"""Config parsing, rule dataclasses, and permission evaluation."""

import configparser
import os
from dataclasses import dataclass
from datetime import datetime, time as Time
from typing import Literal

__all__ = [
    "RangeEntry", "Rule",
    "parse_ranges", "load_config", "is_permitted",
]

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
    name: str                          # section label or path for single-path sections
    ranges: list[RangeEntry]
    mode: Literal["allowed", "denied"]
    log_only: bool
    kill: bool = True                  # send SIGTERM to running denied processes
    kill_grace: int | None = None      # seconds before SIGKILL; None = never SIGKILL


def _expand_name_list(s: str, table: dict[str, int], field: str) -> set[int]:
    result: set[int] = set()
    for part in s.split(","):
        part = part.strip()
        if "-" in part:
            a, _, b = part.partition("-")
            ai = table.get(a.lower())
            bi = table.get(b.lower())
            if ai is None or bi is None:
                raise ValueError(f"unknown {field} name in '{part}'")
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
    lower = token.lower()
    if ":" in token:
        return "time"
    if token.isdigit() and len(token) == 4:
        return "year"
    first_name = lower.split(",")[0].split("-")[0]
    if first_name in _WEEKDAY_NAMES:
        return "weekday"
    if first_name in _MONTH_NAMES:
        return "month"
    dom_clean = token.replace(",", "").replace("-", "")
    if dom_clean.isdigit():
        return "dom"
    raise ValueError(f"unrecognized token '{token}'")


def _parse_entry(line: str) -> RangeEntry:
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


def _matching_entries(rule: Rule, dt: datetime) -> list[RangeEntry]:
    """Return RangeEntry items whose window covers dt (mode-independent)."""
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


def is_permitted(rule: Rule, dt: datetime) -> bool:
    matched = _matching_entries(rule, dt)
    return bool(matched) if rule.mode == "allowed" else not bool(matched)


def load_config(config_path: str) -> dict[str, Rule]:
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"config file not found: {config_path}")
    cfg = configparser.ConfigParser()
    cfg.read(config_path)
    rules: dict[str, Rule] = {}
    seen_paths: dict[str, str] = {}  # resolved path → section name, for duplicate detection
    for section in cfg.sections():
        has_paths_key = "paths" in cfg[section]

        if has_paths_key and os.path.isabs(section):
            raise ValueError(
                f"[{section}]: section name is an absolute path but 'paths' key is also present. "
                f"When 'paths' is specified the section name must be a group label, not a path. "
                f"Either remove 'paths' (single-binary section) or rename the section to a group label."
            )

        if has_paths_key:
            raw_paths = [p.strip() for p in cfg[section]["paths"].splitlines() if p.strip()]
            if not raw_paths:
                raise ValueError(f"[{section}]: 'paths' key is present but empty")
        else:
            raw_paths = [section]

        has_allowed = "allowed" in cfg[section]
        has_denied = "denied" in cfg[section]
        if has_allowed and has_denied:
            raise ValueError(f"[{section}]: cannot specify both 'allowed' and 'denied'")
        if not has_allowed and not has_denied:
            raise ValueError(f"[{section}]: must specify either 'allowed' or 'denied'")
        if has_allowed:
            ranges = parse_ranges(cfg[section]["allowed"])
            mode: Literal["allowed", "denied"] = "allowed"
        else:
            ranges = parse_ranges(cfg[section]["denied"])
            mode = "denied"
        log_only = cfg[section].getboolean("log-only", fallback=False)
        kill = cfg[section].getboolean("kill", fallback=True)
        kill_grace: int | None = None
        if raw_grace := cfg[section].get("kill-grace"):
            try:
                kill_grace = int(raw_grace.strip())
            except ValueError as exc:
                raise ValueError(f"[{section}]: invalid kill-grace value '{raw_grace.strip()}'") from exc
            if kill_grace <= 0:
                raise ValueError(f"[{section}]: kill-grace must be a positive integer")
        rule = Rule(name=section, ranges=ranges, mode=mode, log_only=log_only, kill=kill, kill_grace=kill_grace)

        for raw_path in raw_paths:
            resolved = os.path.realpath(raw_path)
            if resolved in seen_paths:
                raise ValueError(
                    f"[{section}]: path '{raw_path}' (resolved: '{resolved}') is already "
                    f"registered by section [{seen_paths[resolved]}]"
                )
            seen_paths[resolved] = section
            rules[resolved] = rule

    return rules
