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


@dataclass
class Rule:
    ranges: list[tuple[Time, Time]]
    mode: Literal["allowed", "denied"]
    log_only: bool


def parse_ranges(s: str) -> list[tuple[Time, Time]]:
    ranges = []
    for part in s.split(","):
        a, b = part.strip().split("-")
        ranges.append((
            datetime.strptime(a.strip(), "%H:%M").time(),
            datetime.strptime(b.strip(), "%H:%M").time(),
        ))
    return ranges


def is_permitted(rule: Rule) -> bool:
    now = datetime.now().time()
    in_range = any(s <= now <= e for s, e in rule.ranges)
    return in_range if rule.mode == "allowed" else not in_range


def load_config(config_path: str) -> dict[str, Rule]:
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
    return p.parse_args()


def main() -> None:
    global reload_flag

    args = parse_args()

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(message)s",
                        stream=sys.stderr)

    if args.dry_run:
        log.info("dry-run mode: all denials will be logged but not enforced")

    if os.geteuid() != 0:
        sys.exit("error: must run as root")

    rules = load_config(args.config)
    fan_fd = make_fan_fd()
    setup_watches(fan_fd, list(rules.keys()))
    signal.signal(signal.SIGHUP, handle_sighup)
    log.info(f"watching {len(rules)} binaries from {args.config}")

    while True:
        if reload_flag:
            reload_flag = False
            os.close(fan_fd)
            rules = load_config(args.config)
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
            permitted = is_permitted(rule) if rule else True
            soft = args.dry_run or (rule is not None and rule.log_only)
            ts = datetime.now().strftime("%H:%M")

            if permitted:
                log.debug(f"allowed {path} (pid={pid})")
            elif soft:
                tag = "dry-run" if args.dry_run else "log-only"
                log.warning(f"would deny {path} (pid={pid}) at {ts} [{tag}]")
            else:
                log.info(f"DENIED {path} (pid={pid}) at {ts}")

            decision = FAN_ALLOW if (permitted or soft) else FAN_DENY
            # respond before closing — kernel matches response by fd value
            os.write(fan_fd, struct.pack(RESP_FMT, ev_fd, decision))
            os.close(ev_fd)


if __name__ == "__main__":
    main()
