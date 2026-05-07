"""CLI entry point, signal handling, test mode, and event loop."""

import argparse
import logging
import os
import signal
import struct
import sys
from datetime import datetime

from .config import (
    load_config, is_permitted, _matching_entries,
    _classify_token, _expand_name_list, _MONTH_NAMES,
)
from .fanotify import (
    make_fan_fd, setup_watches,
    FAN_OPEN_EXEC_PERM, FAN_ALLOW, FAN_DENY,
    EVENT_FMT, EVENT_SIZE, RESP_FMT,
)

DEFAULT_CONFIG_PATH = "/etc/execguard.ini"

log = logging.getLogger("execguard")

reload_flag = False


def handle_sighup(sig, frame) -> None:
    global reload_flag
    reload_flag = True


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Block executables outside allowed hours via fanotify")
    p.add_argument("--config", "-c", default=DEFAULT_CONFIG_PATH, metavar="PATH",
                   help=f"config file (default: {DEFAULT_CONFIG_PATH})")
    p.add_argument("--verbose", "-v", action="count", default=0,
                   help="increase verbosity (-v: DEBUG)")
    p.add_argument("--dry-run", "-n", action="store_true",
                   help="log would-deny decisions but always allow (overrides per-rule log-only)")
    p.add_argument("--test", metavar="DATETIME",
                   help="evaluate config at given datetime and print results; no daemon, no root required. "
                        "Formats: 'YYYY-MM-DD HH:MM' or 'YYYY Mon DD HH:MM'")
    return p.parse_args()


def parse_test_datetime(s: str) -> datetime:
    """Parse a datetime string in ISO or config syntax format.

    Accepted formats:
    - ISO: YYYY-MM-DD HH:MM
    - Config syntax: YYYY Mon DD HH:MM (same tokens as range entries, no weekday)
    """
    try:
        return datetime.strptime(s.strip(), "%Y-%m-%d %H:%M")
    except ValueError:
        pass

    tokens = s.strip().split()
    if len(tokens) != 4:
        raise ValueError(
            f"invalid datetime '{s}': expected 'YYYY-MM-DD HH:MM' or 'YYYY Mon DD HH:MM'"
        )

    year_tok, month_tok, dom_tok, time_tok = tokens
    try:
        kinds = [_classify_token(t) for t in tokens]
    except ValueError as exc:
        raise ValueError(f"invalid datetime '{s}': {exc}") from exc

    if "weekday" in kinds:
        raise ValueError(
            f"invalid datetime '{s}': weekday names are not allowed in --test datetime"
        )

    expected = ["year", "month", "dom", "time"]
    if kinds != expected:
        raise ValueError(
            f"invalid datetime '{s}': expected tokens year month day time, "
            f"got {' '.join(kinds)}"
        )

    try:
        year = int(year_tok)
        month = next(iter(_expand_name_list(month_tok, _MONTH_NAMES, "month")))
        day = int(dom_tok)
    except ValueError as exc:
        raise ValueError(f"invalid datetime '{s}': {exc}") from exc

    try:
        t = datetime.strptime(time_tok, "%H:%M").time()
    except ValueError as exc:
        raise ValueError(f"invalid datetime '{s}': bad time '{time_tok}'") from exc

    try:
        return datetime(year, month, day, t.hour, t.minute)
    except ValueError as exc:
        raise ValueError(f"invalid datetime '{s}': {exc}") from exc


def run_test_mode(config_path: str, dt: datetime) -> None:
    """Evaluate all rules against dt and print a decision table to stdout."""
    rules = load_config(config_path)

    header_dt = dt.strftime("%Y-%m-%d %H:%M")
    print(f"Test datetime: {header_dt}\n")

    col_group    = "Group"
    col_binary   = "Binary"
    col_decision = "Decision"
    col_mode     = "Mode"
    col_matched  = "Matched Rules"

    rows: list[tuple[str, str, str, str, str]] = []
    for binary, rule in rules.items():
        matched = _matching_entries(rule, dt)

        if rule.mode == "allowed":
            decision = "ALLOWED" if matched else "BLOCKED"
        else:
            decision = "BLOCKED" if matched else "ALLOWED"

        decision_col = f"{decision} [log-only]" if rule.log_only else decision
        matched_col = ", ".join(e.raw for e in matched) if matched else "(no match)"
        rows.append((rule.name, binary, decision_col, rule.mode, matched_col))

    w_group    = max(len(col_group),    max((len(r[0]) for r in rows), default=0))
    w_binary   = max(len(col_binary),   max((len(r[1]) for r in rows), default=0))
    w_decision = max(len(col_decision), max((len(r[2]) for r in rows), default=0))
    w_mode     = max(len(col_mode),     max((len(r[3]) for r in rows), default=0))
    w_matched  = max(len(col_matched),  max((len(r[4]) for r in rows), default=0))

    fmt = f"{{:<{w_group}}}  {{:<{w_binary}}}  {{:<{w_decision}}}  {{:<{w_mode}}}  {{}}"
    sep = (f"{'─' * w_group}  {'─' * w_binary}  {'─' * w_decision}  "
           f"{'─' * w_mode}  {'─' * w_matched}")

    print(fmt.format(col_group, col_binary, col_decision, col_mode, col_matched))
    print(sep)
    for group, binary, decision_col, mode, matched_col in rows:
        print(fmt.format(group, binary, decision_col, mode, matched_col))


def main() -> None:
    global reload_flag

    args = parse_args()

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(message)s",
                        stream=sys.stderr)

    if args.test:
        try:
            dt = parse_test_datetime(args.test)
        except ValueError as exc:
            sys.exit(f"error: {exc}")
        try:
            run_test_mode(args.config, dt)
        except FileNotFoundError as exc:
            sys.exit(f"error: {exc}")
        return

    if args.dry_run:
        log.info("dry-run mode: all denials will be logged but not enforced")

    if os.geteuid() != 0:
        sys.exit("error: must run as root")

    try:
        rules = load_config(args.config)
    except FileNotFoundError as exc:
        sys.exit(f"error: {exc}")
    fan_fd = make_fan_fd()
    setup_watches(fan_fd, list(rules.keys()))
    signal.signal(signal.SIGHUP, handle_sighup)
    log.info(f"watching {len(rules)} binaries from {args.config}")

    while True:
        if reload_flag:
            reload_flag = False
            try:
                new_rules = load_config(args.config)
            except (FileNotFoundError, ValueError) as exc:
                log.error(f"config reload failed, keeping current rules: {exc}")
            else:
                os.close(fan_fd)
                rules = new_rules
                fan_fd = make_fan_fd()
                setup_watches(fan_fd, list(rules.keys()))
                log.info(f"config reloaded, watching {len(rules)} binaries")

        try:
            data = os.read(fan_fd, 4096)
        except InterruptedError:
            continue

        offset = 0
        while offset + EVENT_SIZE <= len(data):
            ev = struct.unpack_from(EVENT_FMT, data, offset)
            event_len, _, _, _, mask, ev_fd, pid = ev
            offset += event_len

            if not (mask & FAN_OPEN_EXEC_PERM):
                if ev_fd >= 0:
                    os.close(ev_fd)
                continue

            try:
                path = os.readlink(f"/proc/self/fd/{ev_fd}")
            except OSError:
                path = ""

            rule = rules.get(path)
            now = datetime.now()
            permitted = is_permitted(rule, now) if rule else True
            soft = args.dry_run or (rule is not None and rule.log_only)
            ts = now.strftime("%H:%M")
            matched = _matching_entries(rule, now) if rule else []
            if matched:
                verb = "allow" if rule.mode == "allowed" else "deny"
                rule_suffix = f" [{verb} rule: {matched[0].raw}]"
            elif rule is not None:
                rule_suffix = f" [{rule.mode} ranges: {', '.join(e.raw for e in rule.ranges)}]"
            else:
                rule_suffix = ""

            if permitted:
                log.debug(f"allowed {path} (pid={pid}){rule_suffix}")
            elif soft:
                tag = "dry-run" if args.dry_run else "log-only"
                log.warning(f"would deny {path} (pid={pid}) at {ts} [{tag}]{rule_suffix}")
            else:
                log.info(f"DENIED {path} (pid={pid}) at {ts}{rule_suffix}")

            decision = FAN_ALLOW if (permitted or soft) else FAN_DENY
            # respond before closing — kernel matches response by fd value
            os.write(fan_fd, struct.pack(RESP_FMT, ev_fd, decision))
            os.close(ev_fd)
