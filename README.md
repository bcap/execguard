# execguard

Prevents specific programs from launching outside the hours you allow. Useful for parental controls, focus tools, or enforcing schedules on shared machines.

Works transparently — no changes to the blocked app, no PATH tricks. The program simply doesn't start if it's outside the allowed window.

**Requires:** Linux, root access

## Install

```sh
git clone <repo>
cd execguard
sudo ./install.sh
```

Edit `/etc/execguard.ini` to configure which programs to block and when (see [Config](#config) below), then start the service:

```sh
sudo systemctl start execguard
sudo systemctl enable execguard   # start automatically on boot
```

To uninstall:

```sh
sudo ./uninstall.sh
```

## Config (`/etc/execguard.ini`)

Each section is the full path to a program. Use `allowed` to permit only during certain hours, or `denied` to block during certain hours. Add `log-only = true` to log without actually blocking (useful for testing your config).

```ini
[/usr/bin/steam]
allowed = 18:00-22:00           ; only allowed 6pm–10pm daily

[/usr/bin/discord]
denied = 09:00-17:00            ; blocked during school hours
log-only = true                 ; log would-deny but don't actually block

[/usr/games/minecraft]
denied =
    Mon-Fri 08:00-16:00         ; blocked on weekdays during the day
    22:00-06:00                 ; blocked overnight every day

[/usr/bin/firefox]
allowed =
    Mon-Fri 18:00-22:00         ; weeknights
    Sat-Sun 08:00-22:00         ; weekends all day
```

Overnight ranges like `22:00-06:00` wrap midnight automatically.

You can scope rules to specific months, days of the month, or even a single date:

```ini
[/usr/bin/steam]
allowed =
    Jan-Jun Mon-Fri 08:00-16:00 ; Jan through June, weekdays only
    2027 Jan 10 09:00-10:00     ; one specific date and time
```

Reload config without restarting the service:

```sh
sudo systemctl reload execguard
```

## Logs

When running as a service, decisions are written to the system journal:

```sh
journalctl -u execguard -f
```

To see only blocked attempts:

```sh
journalctl -u execguard | grep DENIED
```

## Development

```sh
cp execguard.example.ini execguard.dev.ini
# edit execguard.dev.ini as needed
make run-dev
make test
```

Test your config against a specific date/time without needing root:

```sh
uv run execguard --test "2027 Jan 10 09:15"
uv run execguard --test "2026-05-07 14:30"
```

Run in log-only mode globally (never blocks, just logs):

```sh
uv run execguard --dry-run
```

Show allowed events in addition to denials:

```sh
uv run execguard --verbose
```

Full range entry syntax (all fields except `HH:MM-HH:MM` are optional wildcards):

```
[Year] [Month[-Month]|Month,Month,...] [DayOfMonth[-Day]|Day,Day,... | Weekday[-Weekday]|Weekday,...] HH:MM-HH:MM
```

**Technical notes:**
- Uses `fanotify(7)` `FAN_OPEN_EXEC_PERM` — intercepts at the kernel exec path
- Requires Linux 5.0+, `CAP_SYS_ADMIN`, Python 3.10+, [uv](https://docs.astral.sh/uv/)
- SIGHUP reloads config (`systemctl reload execguard`)
- Enforcement is synchronous — the process blocks in kernel until the daemon responds
