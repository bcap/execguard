# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Time-based executable guard — blocks configured binaries from launching outside allowed hours. Uses `fanotify(7)` `FAN_OPEN_EXEC_PERM` to intercept at the kernel exec path without modifying the blocked app's environment.

**Requires:** Linux 5.0+, root

## Deployment

```sh
sudo ./install.sh    # installs binary, service unit, example config
sudo ./uninstall.sh  # removes binary and service unit (preserves /etc/execguard.ini)
```

## Running (development)

Reload config without restart (SIGHUP):
```sh
sudo kill -HUP <pid>
# or
sudo systemctl reload execguard
```

Test config at a specific datetime (no root required):
```sh
uv run execguard --test "2027 Jan 10 09:15"
uv run execguard --test "2026-05-07 14:30"
```

## Config format

Each section is an absolute path to a binary. Use either `allowed` or `denied` (not both). `log-only` is optional.

```ini
[/absolute/path/to/binary]
allowed =
    HH:MM-HH:MM                        ; permit during range, block outside
    Mon-Fri 08:00-16:00                ; weekday-scoped range
    Jan-Jun Mon-Fri 08:00-16:00        ; month + weekday
    2027 Jan 10 09:00-10:00            ; one-time (year + month + dom)
# -- or --
denied = HH:MM-HH:MM                   ; block during range, permit outside
log-only = true                         ; log would-deny but never actually block (default: false)
```

Range entry syntax (all fields except `HH:MM-HH:MM` are optional wildcards):
```
[Year] [Month[-Month]|Month,...] [DayOfMonth[-Dom]|Dom,... | Weekday[-Weekday]|Weekday,...] HH:MM-HH:MM
```

- `allowed` and `denied` are mutually exclusive — error on both present
- Paths resolved via `realpath` at load time
- Each line under `allowed`/`denied` is one range entry (configparser multi-line value)
- Overnight ranges (`22:00-06:00`, start > end) wrap midnight automatically
- `DayOfMonth` and `Weekday` are mutually exclusive per entry
- `log-only` is per-rule; `--dry-run` CLI flag applies globally

## Architecture

- Uses `ctypes` to call `fanotify_init` / `fanotify_mark` from libc (no Python fanotify bindings support `FAN_OPEN_EXEC_PERM`)
- Marks specific inodes with `FAN_MARK_INODE | FAN_OPEN_EXEC_PERM`
- Event loop: `os.read(fan_fd)` blocks until exec event → resolve path via `/proc/self/fd/<ev_fd>` → write `fanotify_response` → close event fd
- On SIGHUP: closes and recreates the fanotify fd (cleanest way to flush all marks)
- Enforcement is **synchronous and exact** — the calling process blocks in kernel until the daemon responds
- `load_config()` — parses INI, resolves paths, returns `dict[str, Rule]`
- `parse_ranges()` — splits on newlines, tokenizes each entry, returns `list[RangeEntry]`
- `is_permitted(rule, dt)` — evaluates all `RangeEntry` items against `dt`; union match; handles both `allowed` and `denied` modes and overnight ranges
- `RangeEntry` dataclass: `months`, `days_of_month`, `weekdays`, `year`, `time_start`, `time_end`, `raw`
- `Rule` dataclass: `ranges: list[RangeEntry]`, `mode: Literal["allowed","denied"]`, `log_only: bool`
- `--test DATETIME`: loads config, evaluates all rules at the given datetime, prints table, exits — no fanotify, no root required
- `parse_test_datetime()` — accepts ISO (`YYYY-MM-DD HH:MM`) or config syntax (`YYYY Mon DD HH:MM`)
- SIGHUP handler sets a flag; main loop checks and reloads

## Python conventions

Follow the project-wide Python rules (type annotations on public functions, `dataclass`/`TypedDict` for structured data, pytest for tests, specific exceptions with `raise X from Y`).
