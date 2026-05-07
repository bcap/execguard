"""Tests for kill config fields and scan_and_kill logic."""

import os
import signal
from datetime import datetime
from unittest.mock import MagicMock, call, patch

import pytest

from execguard import Rule, parse_ranges, load_config
from execguard.monitor import scan_and_kill


def _rule(spec: str = "08:00-22:00", mode: str = "allowed", **kwargs) -> Rule:
    return Rule(name="test", ranges=parse_ranges(spec), mode=mode, log_only=False, **kwargs)


def _denied_rule(**kwargs) -> Rule:
    """Rule that denies at 12:00 on a weekday."""
    return _rule("08:00-22:00", mode="allowed", **kwargs)


_NOON = datetime(2026, 5, 7, 12, 0)   # Thu, inside 08:00-22:00 → allowed
_MIDNIGHT = datetime(2026, 5, 7, 0, 30)  # Thu, outside 08:00-22:00 → blocked


# --- config parsing ---

def test_kill_default(tmp_path):
    cfg = tmp_path / "e.ini"
    cfg.write_text("[/usr/bin/foo]\nallowed = 08:00-22:00\n")
    rules = load_config(str(cfg))
    assert rules["/usr/bin/foo"].kill is True
    assert rules["/usr/bin/foo"].kill_grace is None


def test_kill_false(tmp_path):
    cfg = tmp_path / "e.ini"
    cfg.write_text("[/usr/bin/foo]\nallowed = 08:00-22:00\nkill = false\n")
    rules = load_config(str(cfg))
    assert rules["/usr/bin/foo"].kill is False


def test_kill_grace_parsed(tmp_path):
    cfg = tmp_path / "e.ini"
    cfg.write_text("[/usr/bin/foo]\nallowed = 08:00-22:00\nkill-grace = 30\n")
    rules = load_config(str(cfg))
    assert rules["/usr/bin/foo"].kill_grace == 30


def test_kill_grace_invalid(tmp_path):
    cfg = tmp_path / "e.ini"
    cfg.write_text("[/usr/bin/foo]\nallowed = 08:00-22:00\nkill-grace = abc\n")
    with pytest.raises(ValueError, match="invalid kill-grace"):
        load_config(str(cfg))


def test_kill_grace_zero(tmp_path):
    cfg = tmp_path / "e.ini"
    cfg.write_text("[/usr/bin/foo]\nallowed = 08:00-22:00\nkill-grace = 0\n")
    with pytest.raises(ValueError, match="positive integer"):
        load_config(str(cfg))


# --- scan_and_kill ---

def _make_proc_entry(name: str) -> MagicMock:
    e = MagicMock()
    e.name = name
    return e


def _mock_proc(pid: int, exe: str, uid: int):
    """Return side_effect callables for realpath and stat for one process."""
    def realpath(path):
        if path == f"/proc/{pid}/exe":
            return exe
        return path
    stat_result = MagicMock()
    stat_result.st_uid = uid
    def stat(path):
        if path == f"/proc/{pid}":
            return stat_result
        raise OSError(f"unexpected stat: {path}")
    return realpath, stat


def test_sigterm_denied_process():
    exe = "/usr/bin/foo"
    rule = _denied_rule()  # allowed 08:00-22:00; at midnight → denied
    rules = {exe: rule}
    tracked: dict = {}

    rp, st = _mock_proc(42, exe, uid=1000)
    with patch("os.scandir", return_value=[_make_proc_entry("42")]), \
         patch("os.path.realpath", side_effect=rp), \
         patch("os.stat", side_effect=st), \
         patch("os.kill") as mock_kill:
        scan_and_kill(rules, tracked, _MIDNIGHT, dry_run=False)

    mock_kill.assert_called_once_with(42, signal.SIGTERM)
    assert 42 in tracked
    assert tracked[42][0] == exe
    assert tracked[42][1] is None  # no kill_grace


def test_no_sigterm_when_permitted():
    exe = "/usr/bin/foo"
    rule = _denied_rule()  # allowed 08:00-22:00; at noon → allowed
    rules = {exe: rule}
    tracked: dict = {}

    rp, st = _mock_proc(42, exe, uid=1000)
    with patch("os.scandir", return_value=[_make_proc_entry("42")]), \
         patch("os.path.realpath", side_effect=rp), \
         patch("os.stat", side_effect=st), \
         patch("os.kill") as mock_kill:
        scan_and_kill(rules, tracked, _NOON, dry_run=False)

    mock_kill.assert_not_called()
    assert 42 not in tracked


def test_skip_root_process():
    exe = "/usr/bin/foo"
    rule = _denied_rule()
    rules = {exe: rule}
    tracked: dict = {}

    rp, st = _mock_proc(42, exe, uid=0)  # root
    with patch("os.scandir", return_value=[_make_proc_entry("42")]), \
         patch("os.path.realpath", side_effect=rp), \
         patch("os.stat", side_effect=st), \
         patch("os.kill") as mock_kill:
        scan_and_kill(rules, tracked, _MIDNIGHT, dry_run=False)

    mock_kill.assert_not_called()


def test_skip_kill_false():
    exe = "/usr/bin/foo"
    rule = _denied_rule(kill=False)
    rules = {exe: rule}
    tracked: dict = {}

    rp, st = _mock_proc(42, exe, uid=1000)
    with patch("os.scandir", return_value=[_make_proc_entry("42")]), \
         patch("os.path.realpath", side_effect=rp), \
         patch("os.stat", side_effect=st), \
         patch("os.kill") as mock_kill:
        scan_and_kill(rules, tracked, _MIDNIGHT, dry_run=False)

    mock_kill.assert_not_called()


def test_no_resigterm_already_tracked():
    exe = "/usr/bin/foo"
    rule = _denied_rule()
    rules = {exe: rule}
    tracked = {42: (exe, None)}  # already tracked

    with patch("os.path.realpath", return_value=exe), \
         patch("os.scandir", return_value=[_make_proc_entry("42")]), \
         patch("os.kill") as mock_kill:
        scan_and_kill(rules, tracked, _MIDNIGHT, dry_run=False)

    mock_kill.assert_not_called()


def test_sigkill_after_grace_expires():
    exe = "/usr/bin/foo"
    rule = _denied_rule(kill_grace=10)
    rules = {exe: rule}
    past_deadline = _MIDNIGHT.timestamp() - 1  # already expired
    tracked = {42: (exe, past_deadline)}

    with patch("os.path.realpath", return_value=exe), \
         patch("os.scandir", return_value=[]), \
         patch("os.kill") as mock_kill:
        scan_and_kill(rules, tracked, _MIDNIGHT, dry_run=False)

    mock_kill.assert_called_once_with(42, signal.SIGKILL)
    assert 42 not in tracked


def test_no_sigkill_before_grace_expires():
    exe = "/usr/bin/foo"
    rule = _denied_rule(kill_grace=10)
    rules = {exe: rule}
    future_deadline = _MIDNIGHT.timestamp() + 5  # not yet expired
    tracked = {42: (exe, future_deadline)}

    with patch("os.path.realpath", return_value=exe), \
         patch("os.scandir", return_value=[]), \
         patch("os.kill") as mock_kill:
        scan_and_kill(rules, tracked, _MIDNIGHT, dry_run=False)

    mock_kill.assert_not_called()
    assert 42 in tracked


def test_prune_dead_process():
    exe = "/usr/bin/foo"
    tracked = {42: (exe, None)}

    with patch("os.path.realpath", side_effect=OSError("no such process")), \
         patch("os.scandir", return_value=[]), \
         patch("os.kill") as mock_kill:
        scan_and_kill({}, tracked, _MIDNIGHT, dry_run=False)

    mock_kill.assert_not_called()
    assert 42 not in tracked


def test_prune_pid_exe_changed():
    exe = "/usr/bin/foo"
    tracked = {42: (exe, None)}

    with patch("os.path.realpath", return_value="/usr/bin/other"), \
         patch("os.scandir", return_value=[]), \
         patch("os.kill") as mock_kill:
        scan_and_kill({}, tracked, _MIDNIGHT, dry_run=False)

    mock_kill.assert_not_called()
    assert 42 not in tracked


def test_dry_run_no_kill():
    exe = "/usr/bin/foo"
    rule = _denied_rule()
    rules = {exe: rule}
    tracked: dict = {}

    rp, st = _mock_proc(42, exe, uid=1000)
    with patch("os.scandir", return_value=[_make_proc_entry("42")]), \
         patch("os.path.realpath", side_effect=rp), \
         patch("os.stat", side_effect=st), \
         patch("os.kill") as mock_kill:
        scan_and_kill(rules, tracked, _MIDNIGHT, dry_run=True)

    mock_kill.assert_not_called()
    assert 42 in tracked  # still tracked to suppress repeated log lines


def test_dry_run_no_sigkill_on_grace_expiry():
    exe = "/usr/bin/foo"
    tracked = {42: (exe, _MIDNIGHT.timestamp() - 1)}  # expired, but dry-run set sigkill_at=None

    with patch("os.path.realpath", return_value=exe), \
         patch("os.scandir", return_value=[]), \
         patch("os.kill") as mock_kill:
        # sigkill_at is None so this branch shouldn't fire anyway
        scan_and_kill({}, tracked, _MIDNIGHT, dry_run=True)

    mock_kill.assert_not_called()


def test_sigterm_sets_sigkill_deadline():
    exe = "/usr/bin/foo"
    rule = _denied_rule(kill_grace=30)
    rules = {exe: rule}
    tracked: dict = {}

    rp, st = _mock_proc(42, exe, uid=1000)
    with patch("os.scandir", return_value=[_make_proc_entry("42")]), \
         patch("os.path.realpath", side_effect=rp), \
         patch("os.stat", side_effect=st), \
         patch("os.kill"):
        scan_and_kill(rules, tracked, _MIDNIGHT, dry_run=False)

    assert 42 in tracked
    _, sigkill_at = tracked[42]
    assert sigkill_at is not None
    assert abs(sigkill_at - (_MIDNIGHT.timestamp() + 30)) < 1.0
