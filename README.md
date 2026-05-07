# execguard

Blocks executable launches outside configured time windows using `fanotify(7)` `FAN_OPEN_EXEC_PERM`. No PATH manipulation or app environment modification — intercepts at the kernel exec path.

## Requirements

- Linux 5.0+ (for `FAN_OPEN_EXEC_PERM`)
- Root / `CAP_SYS_ADMIN`
- Python 3 (stdlib only, no extra packages)

## Install

```sh
cp execguard.py /usr/local/bin/execguard
chmod +x /usr/local/bin/execguard

cp execguard.ini /etc/execguard.ini   # edit as needed

cp execguard.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now execguard
```

## Config (`/etc/execguard.ini`)

Section header is the absolute path to the binary (resolved via `realpath`).  
Each section requires either `allowed` or `denied` (mutually exclusive), with comma-separated `HH:MM-HH:MM` ranges (24h).

```ini
[/usr/bin/steam]
allowed = 18:00-22:00          ; block outside this range

[/usr/bin/discord]
denied = 09:00-17:00           ; block during this range
log-only = true                ; log would-deny but don't actually block

[/usr/games/minecraft]
allowed = 15:00-20:00, 10:00-12:00
```

Global log-only mode (never blocks, just logs):
```sh
execguard --dry-run
```

Reload config without restart:
```sh
systemctl reload execguard
```
