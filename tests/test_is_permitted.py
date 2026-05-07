import pytest
from datetime import datetime
from execguard import Rule, RangeEntry, is_permitted, parse_ranges
from datetime import time as Time


def _rule(spec: str, mode: str = "allowed") -> Rule:
    return Rule(ranges=parse_ranges(spec), mode=mode, log_only=False)


def _dt(year: int, month: int, day: int, hour: int, minute: int) -> datetime:
    return datetime(year, month, day, hour, minute)


# --- allowed mode ---

def test_plain_time_in_range_allowed():
    rule = _rule("08:00-16:00", "allowed")
    assert is_permitted(rule, _dt(2026, 5, 7, 12, 0)) is True


def test_plain_time_out_of_range_denied_by_allowed():
    rule = _rule("08:00-16:00", "allowed")
    assert is_permitted(rule, _dt(2026, 5, 7, 17, 0)) is False


# --- denied mode ---

def test_denied_mode_in_range():
    rule = _rule("09:00-17:00", "denied")
    assert is_permitted(rule, _dt(2026, 5, 7, 12, 0)) is False


def test_denied_mode_out_of_range():
    rule = _rule("09:00-17:00", "denied")
    assert is_permitted(rule, _dt(2026, 5, 7, 18, 0)) is True


# --- overnight ---

def test_overnight_in_range_after_midnight():
    rule = _rule("22:00-06:00", "denied")
    assert is_permitted(rule, _dt(2026, 5, 7, 2, 0)) is False


def test_overnight_in_range_before_midnight():
    rule = _rule("22:00-06:00", "denied")
    assert is_permitted(rule, _dt(2026, 5, 7, 23, 0)) is False


def test_overnight_out_of_range():
    rule = _rule("22:00-06:00", "denied")
    assert is_permitted(rule, _dt(2026, 5, 7, 12, 0)) is True


# --- month filtering ---

def test_month_match():
    rule = _rule("Jan-Jun 08:00-16:00", "allowed")
    assert is_permitted(rule, _dt(2026, 3, 15, 10, 0)) is True


def test_month_no_match():
    rule = _rule("Jan-Jun 08:00-16:00", "allowed")
    assert is_permitted(rule, _dt(2026, 8, 15, 10, 0)) is False


def test_month_list_match():
    rule = _rule("Jan,Jul 08:00-16:00", "allowed")
    assert is_permitted(rule, _dt(2026, 7, 5, 10, 0)) is True
    assert is_permitted(rule, _dt(2026, 3, 5, 10, 0)) is False


# --- weekday filtering ---

def test_weekday_match():
    # 2026-05-04 is a Monday (weekday=0)
    rule = _rule("Mon-Fri 09:00-17:00", "denied")
    assert is_permitted(rule, _dt(2026, 5, 4, 12, 0)) is False


def test_weekday_no_match():
    # 2026-05-09 is a Saturday (weekday=5)
    rule = _rule("Mon-Fri 09:00-17:00", "denied")
    assert is_permitted(rule, _dt(2026, 5, 9, 12, 0)) is True


# --- day-of-month filtering ---

def test_dom_match():
    rule = _rule("15 10:00-12:00", "allowed")
    assert is_permitted(rule, _dt(2026, 5, 15, 11, 0)) is True


def test_dom_no_match():
    rule = _rule("15 10:00-12:00", "allowed")
    assert is_permitted(rule, _dt(2026, 5, 14, 11, 0)) is False


# --- year filtering ---

def test_year_match():
    rule = _rule("2027 Jan 10 09:00-10:00", "allowed")
    assert is_permitted(rule, _dt(2027, 1, 10, 9, 30)) is True


def test_year_no_match():
    rule = _rule("2027 Jan 10 09:00-10:00", "allowed")
    assert is_permitted(rule, _dt(2026, 1, 10, 9, 30)) is False


# --- multiple entries (union) ---

def test_union_first_entry_matches():
    rule = _rule("Jan-Jun Mon-Fri 08:00-16:00\nAug-Dec Mon-Fri 08:00-16:00", "denied")
    # May Monday in range
    assert is_permitted(rule, _dt(2026, 5, 4, 10, 0)) is False


def test_union_second_entry_matches():
    rule = _rule("Jan-Jun Mon-Fri 08:00-16:00\nAug-Dec Mon-Fri 08:00-16:00", "denied")
    # October Monday in range
    assert is_permitted(rule, _dt(2026, 10, 5, 10, 0)) is False


def test_union_no_entry_matches():
    rule = _rule("Jan-Jun Mon-Fri 08:00-16:00\nAug-Dec Mon-Fri 08:00-16:00", "denied")
    # July (not covered) → out of range → permitted
    assert is_permitted(rule, _dt(2026, 7, 6, 10, 0)) is True


# --- combined fields ---

def test_combined_month_weekday_time():
    rule = _rule("Jan,Jul Sat 00:00-23:59", "allowed")
    # July Saturday
    assert is_permitted(rule, _dt(2026, 7, 4, 12, 0)) is True
    # July Sunday
    assert is_permitted(rule, _dt(2026, 7, 5, 12, 0)) is False
    # March Saturday
    assert is_permitted(rule, _dt(2026, 3, 7, 12, 0)) is False


# --- load_config error: both allowed and denied ---

def test_load_config_both_allowed_denied(tmp_path):
    from execguard import load_config
    cfg = tmp_path / "bad.ini"
    cfg.write_text("[/bin/true]\nallowed = 08:00-16:00\ndenied = 20:00-22:00\n")
    with pytest.raises(ValueError, match="cannot specify both"):
        load_config(str(cfg))
