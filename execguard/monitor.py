"""Process monitor: scan /proc for denied running executables and kill them."""

import logging
import os
import signal
from datetime import datetime

from .config import Rule, is_permitted

__all__ = ["scan_and_kill"]

log = logging.getLogger("execguard")


def scan_and_kill(
    rules: dict[str, Rule],
    tracked: dict[int, tuple[str, float | None]],
    now: datetime,
    dry_run: bool,
) -> None:
    """Scan /proc for denied non-root processes; SIGTERM new ones, SIGKILL after grace."""
    ts = now.strftime("%H:%M:%S")
    now_ts = now.timestamp()

    dead: list[int] = []
    for pid, (exe_path, sigkill_at) in list(tracked.items()):
        try:
            alive = os.path.realpath(f"/proc/{pid}/exe") == exe_path
        except OSError:
            alive = False
        if not alive:
            dead.append(pid)
            continue
        if sigkill_at is not None and now_ts >= sigkill_at:
            log.info(f"SIGKILL {exe_path} (pid={pid}) at {ts} [grace expired]")
            if not dry_run:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            dead.append(pid)
    for pid in dead:
        tracked.pop(pid, None)

    try:
        proc_entries = list(os.scandir("/proc"))
    except OSError:
        return

    for entry in proc_entries:
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        if pid in tracked:
            continue
        try:
            exe_path = os.path.realpath(f"/proc/{pid}/exe")
        except OSError:
            continue
        rule = rules.get(exe_path)
        if rule is None or not rule.kill:
            continue
        try:
            uid = os.stat(f"/proc/{pid}").st_uid
        except OSError:
            continue
        if uid == 0:
            continue
        if is_permitted(rule, now):
            continue

        soft = dry_run or rule.log_only
        grace_note = f", SIGKILL in {rule.kill_grace}s" if rule.kill_grace is not None else ""
        sigkill_at = (now_ts + rule.kill_grace) if (rule.kill_grace is not None and not soft) else None

        if soft:
            tag = "dry-run" if dry_run else "log-only"
            log.warning(f"would SIGTERM {exe_path} (pid={pid}) at {ts} [{tag}]{grace_note}")
        else:
            log.info(f"SIGTERM {exe_path} (pid={pid}) at {ts}{grace_note}")
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                continue

        tracked[pid] = (exe_path, sigkill_at)
