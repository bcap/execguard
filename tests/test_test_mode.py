"""Tests for --test mode: parse_test_datetime and run_test_mode."""
import pytest
from datetime import datetime
from io import StringIO
from unittest.mock import patch

from execguard import parse_test_datetime, run_test_mode, load_config, Rule, parse_ranges


# --- parse_test_datetime ---

@pytest.mark.parametrize("s,expected", [
    ("2026-05-07 14:30", datetime(2026, 5, 7, 14, 30)),
    ("2027-01-10 09:15", datetime(2027, 1, 10, 9, 15)),
    ("2027 Jan 10 09:15", datetime(2027, 1, 10, 9, 15)),
    ("2026 Dec 31 23:59", datetime(2026, 12, 31, 23, 59)),
    ("2026 Feb 28 00:00", datetime(2026, 2, 28, 0, 0)),
])
def test_parse_test_datetime_valid(s: str, expected: datetime) -> None:
    assert parse_test_datetime(s) == expected


@pytest.mark.parametrize("s", [
    "not-a-date",
    "2027-01-10",            # missing time
    "09:15",                 # time only
    "2027 Jan 09:15",        # missing day
    "Jan 10 09:15",          # missing year
    "2027-01-10T09:15",      # ISO with T separator
    "2027 Jan 10 09:15 extra",  # extra token
    "",
])
def test_parse_test_datetime_invalid_format(s: str) -> None:
    with pytest.raises(ValueError, match="invalid datetime"):
        parse_test_datetime(s)


def test_parse_test_datetime_rejects_weekday() -> None:
    with pytest.raises(ValueError, match="weekday"):
        parse_test_datetime("2027 Mon 10 09:15")


def test_parse_test_datetime_invalid_date_values() -> None:
    # Feb 30 doesn't exist
    with pytest.raises(ValueError, match="invalid datetime"):
        parse_test_datetime("2026 Feb 30 12:00")


# --- run_test_mode helpers ---

def _write_config(tmp_path, content: str) -> str:
    p = tmp_path / "test.ini"
    p.write_text(content)
    return str(p)


# --- run_test_mode output ---

def test_run_test_mode_allowed_mode_match(tmp_path, capsys) -> None:
    cfg = _write_config(tmp_path, """
[/usr/bin/steam]
allowed = 08:00-18:00
""")
    run_test_mode(cfg, datetime(2026, 5, 7, 12, 0))
    out = capsys.readouterr().out
    assert "ALLOWED" in out
    assert "allowed" in out
    assert "08:00-18:00" in out


def test_run_test_mode_allowed_mode_no_match(tmp_path, capsys) -> None:
    cfg = _write_config(tmp_path, """
[/usr/bin/steam]
allowed = 08:00-18:00
""")
    run_test_mode(cfg, datetime(2026, 5, 7, 20, 0))
    out = capsys.readouterr().out
    assert "BLOCKED" in out
    assert "(no match)" in out


def test_run_test_mode_denied_mode_match(tmp_path, capsys) -> None:
    cfg = _write_config(tmp_path, """
[/usr/bin/discord]
denied = 09:00-17:00
""")
    run_test_mode(cfg, datetime(2026, 5, 7, 12, 0))
    out = capsys.readouterr().out
    assert "BLOCKED" in out
    assert "denied" in out
    assert "09:00-17:00" in out


def test_run_test_mode_denied_mode_no_match(tmp_path, capsys) -> None:
    cfg = _write_config(tmp_path, """
[/usr/bin/discord]
denied = 09:00-17:00
""")
    run_test_mode(cfg, datetime(2026, 5, 7, 20, 0))
    out = capsys.readouterr().out
    assert "ALLOWED" in out
    assert "(no match)" in out


def test_run_test_mode_log_only_indicator(tmp_path, capsys) -> None:
    cfg = _write_config(tmp_path, """
[/usr/bin/steam]
allowed = 08:00-18:00
log-only = true
""")
    # outside allowed window → BLOCKED, but log-only
    run_test_mode(cfg, datetime(2026, 5, 7, 20, 0))
    out = capsys.readouterr().out
    assert "BLOCKED" in out
    assert "[log-only]" in out


def test_run_test_mode_header_shows_datetime(tmp_path, capsys) -> None:
    cfg = _write_config(tmp_path, """
[/usr/bin/steam]
allowed = 08:00-18:00
""")
    run_test_mode(cfg, datetime(2027, 1, 10, 9, 15))
    out = capsys.readouterr().out
    assert "Test datetime: 2027-01-10 09:15" in out


def test_run_test_mode_multiple_rules(tmp_path, capsys) -> None:
    import os
    steam_path = os.path.realpath("/usr/bin/steam") if os.path.exists("/usr/bin/steam") else "/usr/bin/steam"
    discord_path = os.path.realpath("/usr/bin/discord") if os.path.exists("/usr/bin/discord") else "/usr/bin/discord"
    cfg = _write_config(tmp_path, f"""
[{steam_path}]
allowed = 08:00-18:00

[{discord_path}]
denied = 09:00-17:00
""")
    run_test_mode(cfg, datetime(2026, 5, 7, 12, 0))
    out = capsys.readouterr().out
    assert steam_path in out
    assert discord_path in out


def test_run_test_mode_shows_group_column(tmp_path, capsys) -> None:
    cfg = _write_config(tmp_path, """
[/usr/bin/steam]
allowed = 08:00-18:00
""")
    run_test_mode(cfg, datetime(2026, 5, 7, 12, 0))
    out = capsys.readouterr().out
    assert "Group" in out


def test_run_test_mode_named_group_shows_group_name(tmp_path, capsys) -> None:
    cfg = _write_config(tmp_path, """
[my-games]
paths =
    /bin/true
    /bin/false
allowed = 08:00-18:00
""")
    run_test_mode(cfg, datetime(2026, 5, 7, 12, 0))
    out = capsys.readouterr().out
    assert "my-games" in out
    assert "/bin/true" in out
    assert "/bin/false" in out
