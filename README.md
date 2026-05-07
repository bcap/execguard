# execguard

Blocks executable launches outside configured time windows using `fanotify(7)` `FAN_OPEN_EXEC_PERM`. No PATH manipulation or app environment modification — intercepts at the kernel exec path.

## Requirements

- Linux 5.0+ (for `FAN_OPEN_EXEC_PERM`)
- Root / `CAP_SYS_ADMIN`
- Python 3.10+, [uv](https://docs.astral.sh/uv/)

## Install

```sh
# install entry point into a uv-managed venv
uv sync

# run directly
sudo uv run execguard

# or install system-wide
uv tool install .
sudo execguard
```

### Systemd

```sh
cp execguard.ini /etc/execguard.ini   # edit as needed

cp execguard.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now execguard
```

## Config (`/etc/execguard.ini`)

Section header is the absolute path to the binary (resolved via `realpath`).  
Each section requires either `allowed` or `denied` (mutually exclusive). Each line under the key is one range entry. See `execguard.example.ini` for full examples.

Range entry syntax (all fields except `HH:MM-HH:MM` are optional wildcards):

```
[Year] [Month[-Month]|Month,Month,...] [DayOfMonth[-Day]|Day,Day,... | Weekday[-Weekday]|Weekday,...] HH:MM-HH:MM
```

```ini
[/usr/bin/steam]
allowed = 18:00-22:00           ; permit only 18:00–22:00 daily

[/usr/bin/discord]
denied = 09:00-17:00            ; block during school hours
log-only = true                 ; log would-deny but don't actually block

[/usr/games/minecraft]
denied =
    Jan-Jun Mon-Fri 08:00-16:00
    Aug-Dec Mon-Fri 08:00-16:00
    22:00-06:00                 ; overnight every day
```

Overnight ranges (`22:00-06:00`) wrap midnight automatically.

Global log-only mode (never blocks, just logs):
```sh
uv run execguard --dry-run
```

Test config against a specific datetime (no root required):
```sh
uv run execguard --test "2027 Jan 10 09:15"
uv run execguard --test "2026-05-07 14:30"
```

Reload config without restart:
```sh
systemctl reload execguard
```
