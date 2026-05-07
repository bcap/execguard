# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Time-based executable guard — blocks configured binaries from launching outside allowed hours. Uses `fanotify(7)` `FAN_OPEN_EXEC_PERM` to intercept at the kernel exec path without modifying the blocked app's environment.

**Requires:** Linux 5.0+, root

## Running

```sh
sudo python execguard.py
```

Reload config without restart (SIGHUP):
```sh
sudo kill -HUP <pid>
# or
sudo systemctl reload execguard
```

## Config format

Each section is an absolute path to a binary. Use either `allowed` or `denied` (not both). `log-only` is optional.

```ini
[/absolute/path/to/binary]
allowed = HH:MM-HH:MM, HH:MM-HH:MM   ; permit during ranges, block outside
# -- or --
denied = HH:MM-HH:MM                  ; block during ranges, permit outside
log-only = true                        ; log would-deny but never actually block (default: false)
```

- `allowed` and `denied` are mutually exclusive — error on both present
- Paths resolved via `realpath` at load time
- Multiple comma-separated ranges supported
- `log-only` is per-rule; `--dry-run` CLI flag applies globally

## Architecture

- Uses `ctypes` to call `fanotify_init` / `fanotify_mark` from libc (no Python fanotify bindings support `FAN_OPEN_EXEC_PERM`)
- Marks specific inodes with `FAN_MARK_INODE | FAN_OPEN_EXEC_PERM`
- Event loop: `os.read(fan_fd)` blocks until exec event → resolve path via `/proc/self/fd/<ev_fd>` → write `fanotify_response` → close event fd
- On SIGHUP: closes and recreates the fanotify fd (cleanest way to flush all marks)
- Enforcement is **synchronous and exact** — the calling process blocks in kernel until the daemon responds
- `load_config()` — parses INI, resolves paths, returns `dict[str, Rule]`
- `parse_ranges()` / `is_permitted(rule)` — time window evaluation; `is_permitted` handles both `allowed` and `denied` modes
- `Rule` dataclass: `ranges`, `mode: Literal["allowed","denied"]`, `log_only: bool`
- SIGHUP handler sets a flag; main loop checks and reloads

## Python conventions

Follow the project-wide Python rules (type annotations on public functions, `dataclass`/`TypedDict` for structured data, pytest for tests, specific exceptions with `raise X from Y`).
