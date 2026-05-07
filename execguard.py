#!/usr/bin/env python3
"""execguard-fanotify: block executable launches outside allowed hours using fanotify"""
import argparse, os, sys, signal, struct, ctypes, configparser, logging
from dataclasses import dataclass
from datetime import datetime, time as Time
from typing import Literal

DEFAULT_CONFIG_PATH = "/etc/execguard.ini"

FAN_CLASS_CONTENT  = 0x00000004
FAN_CLOEXEC        = 0x00000001
FAN_OPEN_EXEC_PERM = 0x00040000
FAN_MARK_ADD       = 0x00000001
FAN_MARK_INODE     = 0x00000000
FAN_ALLOW          = 0x01
FAN_DENY           = 0x02
AT_FDCWD           = -100
O_RDONLY           = 0
O_LARGEFILE        = 0x8000

# struct fanotify_event_metadata { u32, u8, u8, u16, u64, s32, s32 } = 24 bytes
EVENT_FMT  = "=IBBHQii"
EVENT_SIZE = struct.calcsize(EVENT_FMT)
# struct fanotify_response { s32 fd, u32 response } = 8 bytes
RESP_FMT   = "=iI"

libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.fanotify_init.restype  = ctypes.c_int
libc.fanotify_init.argtypes = [ctypes.c_uint, ctypes.c_uint]
libc.fanotify_mark.restype  = ctypes.c_int
libc.fanotify_mark.argtypes = [ctypes.c_int, ctypes.c_uint, ctypes.c_uint64,
                                ctypes.c_int, ctypes.c_char_p]

log = logging.getLogger("execguard")

# Month and weekday name → index mappings
_MONTH_NAMES = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}
_WEEKDAY_NAMES = {
    "mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6,
}


@dataclass
class RangeEntry:
    months: set[int] | None         # None = all months; 1-12
    days_of_month: set[int] | None  # None = wildcard; mutually exclusive with weekdays
    weekdays: set[int] | None       # None = wildcard; 0=Mon..6=Sun
    year: int | None                # None = any year
    time_start: Time
    time_end: Time                  # if time_end < time_start → overnight range
    raw: str                        # original text for display


@dataclass
class Rule:
    ranges: list[RangeEntry]
    mode: Literal["allowed", "denied"]
    log_only: bool


def _expand_name_list(s: str, table: dict[str, int], field: str) -> set[int]:
    """Expand a comma/range expression of 3-letter names to a set of ints."""
    result: set[int] = set()
    for part in s.split(","):
        part = part.strip()
        if "-" in part:
            a, _, b = part.partition("-")
            ai = table.get(a.lower())
            bi = table.get(b.lower())
            if ai is None or bi is None:
                raise ValueError(f"unknown {field} name in '{part}'")
            # ranges wrap-around not needed for months/weekdays in practice,
            # but handle ascending order only; spec doesn't require wrap
            if ai > bi:
                raise ValueError(f"{field} range '{part}' must be ascending")
            result.update(range(ai, bi + 1))
        else:
            v = table.get(part.lower())
            if v is None:
                raise ValueError(f"unknown {field} name '{part}'")
            result.add(v)
    return result


def _expand_int_list(s: str, field: str) -> set[int]:
    """Expand a comma/range expression of integers to a set."""
    result: set[int] = set()
    for part in s.split(","):
        part = part.strip()
        if "-" in part:
            a, _, b = part.partition("-")
            try:
                ai, bi = int(a), int(b)
            except ValueError as exc:
                raise ValueError(f"invalid {field} range '{part}'") from exc
            if ai > bi:
                raise ValueError(f"{field} range '{part}' must be ascending")
            result.update(range(ai, bi + 1))
        else:
            try:
                result.add(int(part))
            except ValueError as exc:
                raise ValueError(f"invalid {field} value '{part}'") from exc
    return result


def _parse_time_range(token: str) -> tuple[Time, Time]:
    """Parse HH:MM-HH:MM token into (start, end) times."""
    # token looks like "08:00-16:00" — split on last '-' that follows ':'
    # simple approach: find the '-' that isn't part of HH:MM
    idx = token.index("-", 3)  # first '-' after position 3 (past HH:M)
    a, b = token[:idx], token[idx + 1:]
    try:
        return (
            datetime.strptime(a, "%H:%M").time(),
            datetime.strptime(b, "%H:%M").time(),
        )
    except ValueError as exc:
        raise ValueError(f"invalid time range '{token}'") from exc


def _classify_token(token: str) -> str:
    """Return token type: 'year', 'month', 'weekday', 'dom', 'time'."""
    lower = token.lower()
    # Time: contains ':' (e.g. 08:00-16:00)
    if ":" in token:
        return "time"
    # Year: exactly 4 digits
    if token.isdigit() and len(token) == 4:
        return "year"
    # Weekday: starts with a known 3-letter day name
    first_name = lower.split(",")[0].split("-")[0]
    if first_name in _WEEKDAY_NAMES:
        return "weekday"
    # Month: starts with a known 3-letter month name
    if first_name in _MONTH_NAMES:
        return "month"
    # Day-of-month: digits only (1-2 digit values, with possible comma/range separators)
    dom_clean = token.replace(",", "").replace("-", "")
    if dom_clean.isdigit():
        return "dom"
    raise ValueError(f"unrecognized token '{token}'")


def _parse_entry(line: str) -> RangeEntry:
    """Parse one range entry line into a RangeEntry."""
    tokens = line.split()
    if not tokens:
        raise ValueError("empty range entry")

    year: int | None = None
    months: set[int] | None = None
    days_of_month: set[int] | None = None
    weekdays: set[int] | None = None
    time_start: Time | None = None
    time_end: Time | None = None

    for token in tokens:
        kind = _classify_token(token)
        if kind == "time":
            time_start, time_end = _parse_time_range(token)
        elif kind == "year":
            year = int(token)
        elif kind == "month":
            months = _expand_name_list(token, _MONTH_NAMES, "month")
        elif kind == "weekday":
            weekdays = _expand_name_list(token, _WEEKDAY_NAMES, "weekday")
        elif kind == "dom":
            days_of_month = _expand_int_list(token, "day-of-month")

    if time_start is None or time_end is None:
        raise ValueError(f"no time range found in entry '{line}'")
    if days_of_month is not None and weekdays is not None:
        raise ValueError(f"cannot specify both day-of-month and weekday in '{line}'")

    return RangeEntry(
        months=months,
        days_of_month=days_of_month,
        weekdays=weekdays,
        year=year,
        time_start=time_start,
        time_end=time_end,
        raw=line,
    )


def parse_ranges(s: str) -> list[RangeEntry]:
    entries: list[RangeEntry] = []
    for line in s.splitlines():
        line = line.strip()
        if not line:
            continue
        entries.append(_parse_entry(line))
    return entries


def _in_time_range(start: Time, end: Time, t: Time) -> bool:
    if start <= end:
        return start <= t <= end
    # overnight: wraps midnight
    return t >= start or t <= end


def is_permitted(rule: Rule, dt: datetime) -> bool:
    t = dt.time()
    in_range = False
    for entry in rule.ranges:
        if entry.year is not None and entry.year != dt.year:
            continue
        if entry.months is not None and dt.month not in entry.months:
            continue
        if entry.days_of_month is not None and dt.day not in entry.days_of_month:
            continue
        if entry.weekdays is not None and dt.weekday() not in entry.weekdays:
            continue
        if _in_time_range(entry.time_start, entry.time_end, t):
            in_range = True
            break
    return in_range if rule.mode == "allowed" else not in_range


def load_config(config_path: str) -> dict[str, Rule]:
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"config file not found: {config_path}")
    cfg = configparser.ConfigParser()
    cfg.read(config_path)
    rules: dict[str, Rule] = {}
    for section in cfg.sections():
        path = os.path.realpath(section)
        has_allowed = "allowed" in cfg[section]
        has_denied = "denied" in cfg[section]
        if has_allowed and has_denied:
            raise ValueError(f"{section}: cannot specify both 'allowed' and 'denied'")
        if not has_allowed and not has_denied:
            raise ValueError(f"{section}: must specify either 'allowed' or 'denied'")
        if has_allowed:
            ranges = parse_ranges(cfg[section]["allowed"])
            mode: Literal["allowed", "denied"] = "allowed"
        else:
            ranges = parse_ranges(cfg[section]["denied"])
            mode = "denied"
        log_only = cfg[section].getboolean("log-only", fallback=False)
        rules[path] = Rule(ranges=ranges, mode=mode, log_only=log_only)
    return rules


def setup_watches(fan_fd: int, paths: list[str]) -> None:
    for path in paths:
        ret = libc.fanotify_mark(fan_fd, FAN_MARK_ADD | FAN_MARK_INODE,
                                  FAN_OPEN_EXEC_PERM, AT_FDCWD, path.encode())
        if ret < 0:
            log.warning(f"fanotify_mark failed for {path}: {os.strerror(ctypes.get_errno())}")


def make_fan_fd() -> int:
    fd = libc.fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC, O_RDONLY | O_LARGEFILE)
    if fd < 0:
        sys.exit(f"fanotify_init: {os.strerror(ctypes.get_errno())}")
    return fd


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
    # Try ISO format first
    try:
        return datetime.strptime(s.strip(), "%Y-%m-%d %H:%M")
    except ValueError:
        pass

    # Try config syntax: tokenize and classify
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
        t_start, _ = _parse_time_range(f"{time_tok}-00:00")
    except ValueError as exc:
        raise ValueError(f"invalid datetime '{s}': {exc}") from exc

    # _parse_time_range needs a range; extract just the time we want
    try:
        t = datetime.strptime(time_tok, "%H:%M").time()
    except ValueError as exc:
        raise ValueError(f"invalid datetime '{s}': bad time '{time_tok}'") from exc

    try:
        return datetime(year, month, day, t.hour, t.minute)
    except ValueError as exc:
        raise ValueError(f"invalid datetime '{s}': {exc}") from exc


def _matching_entries(rule: Rule, dt: datetime) -> list[RangeEntry]:
    """Return RangeEntry items whose time window covers dt (mode-independent)."""
    t = dt.time()
    matched = []
    for entry in rule.ranges:
        if entry.year is not None and entry.year != dt.year:
            continue
        if entry.months is not None and dt.month not in entry.months:
            continue
        if entry.days_of_month is not None and dt.day not in entry.days_of_month:
            continue
        if entry.weekdays is not None and dt.weekday() not in entry.weekdays:
            continue
        if _in_time_range(entry.time_start, entry.time_end, t):
            matched.append(entry)
    return matched


def run_test_mode(config_path: str, dt: datetime) -> None:
    """Evaluate all rules against dt and print a decision table to stdout."""
    rules = load_config(config_path)

    header_dt = dt.strftime("%Y-%m-%d %H:%M")
    print(f"Test datetime: {header_dt}\n")

    col_binary  = "Binary"
    col_decision = "Decision"
    col_mode    = "Mode"
    col_matched = "Matched Rules"

    rows: list[tuple[str, str, str, str]] = []
    for binary, rule in rules.items():
        matched = _matching_entries(rule, dt)

        if rule.mode == "allowed":
            decision = "ALLOWED" if matched else "BLOCKED"
        else:
            decision = "BLOCKED" if matched else "ALLOWED"

        if rule.log_only:
            decision_col = f"{decision} [log-only]"
        else:
            decision_col = decision

        matched_col = ", ".join(e.raw for e in matched) if matched else "(no match)"
        rows.append((binary, decision_col, rule.mode, matched_col))

    # compute column widths
    w_binary   = max(len(col_binary),   max((len(r[0]) for r in rows), default=0))
    w_decision = max(len(col_decision), max((len(r[1]) for r in rows), default=0))
    w_mode     = max(len(col_mode),     max((len(r[2]) for r in rows), default=0))
    w_matched  = max(len(col_matched),  max((len(r[3]) for r in rows), default=0))

    fmt = f"{{:<{w_binary}}}  {{:<{w_decision}}}  {{:<{w_mode}}}  {{}}"
    sep = f"{'─' * w_binary}  {'─' * w_decision}  {'─' * w_mode}  {'─' * w_matched}"

    print(fmt.format(col_binary, col_decision, col_mode, col_matched))
    print(sep)
    for binary, decision_col, mode, matched_col in rows:
        print(fmt.format(binary, decision_col, mode, matched_col))


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


if __name__ == "__main__":
    main()
