"""Fanotify exec-blocking: process a batch of FAN_OPEN_EXEC_PERM events."""

import logging
import os
import struct
from datetime import datetime

from .config import Rule, is_permitted, _matching_entries
from .fanotify import FAN_OPEN_EXEC_PERM, FAN_ALLOW, FAN_DENY, EVENT_FMT, EVENT_SIZE, RESP_FMT

__all__ = ["handle_exec_events"]

log = logging.getLogger("execguard")


def handle_exec_events(
    data: bytes,
    rules: dict[str, Rule],
    fan_fd: int,
    dry_run: bool,
) -> None:
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
        soft = dry_run or (rule is not None and rule.log_only)
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
            tag = "dry-run" if dry_run else "log-only"
            log.warning(f"would deny {path} (pid={pid}) at {ts} [{tag}]{rule_suffix}")
        else:
            log.info(f"DENIED {path} (pid={pid}) at {ts}{rule_suffix}")

        decision = FAN_ALLOW if (permitted or soft) else FAN_DENY
        # respond before closing — kernel matches response by fd value
        os.write(fan_fd, struct.pack(RESP_FMT, ev_fd, decision))
        os.close(ev_fd)
