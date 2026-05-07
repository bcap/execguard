import pytest
from datetime import time as Time
from execguard import parse_ranges, RangeEntry


def test_plain_time_range_backward_compat():
    entries = parse_ranges("08:00-16:00")
    assert len(entries) == 1
    e = entries[0]
    assert e.time_start == Time(8, 0)
    assert e.time_end == Time(16, 0)
    assert e.months is None
    assert e.weekdays is None
    assert e.days_of_month is None
    assert e.year is None


def test_multiline_two_entries():
    entries = parse_ranges("\nMon-Fri 08:00-16:00\nSat 10:00-12:00")
    assert len(entries) == 2
    assert entries[0].weekdays == {0, 1, 2, 3, 4}
    assert entries[1].weekdays == {5}


def test_month_range():
    entries = parse_ranges("Jan-Jun 08:00-16:00")
    assert len(entries) == 1
    assert entries[0].months == {1, 2, 3, 4, 5, 6}


def test_month_list():
    entries = parse_ranges("Jan,Jul 08:00-16:00")
    assert len(entries) == 1
    assert entries[0].months == {1, 7}


def test_weekday_range():
    entries = parse_ranges("Mon-Fri 09:00-17:00")
    assert entries[0].weekdays == {0, 1, 2, 3, 4}


def test_weekday_list():
    entries = parse_ranges("Mon,Wed,Fri 09:00-17:00")
    assert entries[0].weekdays == {0, 2, 4}


def test_single_weekday():
    entries = parse_ranges("Sat 10:00-12:00")
    assert entries[0].weekdays == {5}


def test_day_of_month_single():
    entries = parse_ranges("15 10:00-12:00")
    assert entries[0].days_of_month == {15}
    assert entries[0].weekdays is None


def test_day_of_month_range():
    entries = parse_ranges("1-15 10:00-12:00")
    assert entries[0].days_of_month == set(range(1, 16))


def test_day_of_month_list():
    entries = parse_ranges("1,15,20 10:00-12:00")
    assert entries[0].days_of_month == {1, 15, 20}


def test_year():
    entries = parse_ranges("2027 Jan 10 09:00-10:00")
    e = entries[0]
    assert e.year == 2027
    assert e.months == {1}
    assert e.days_of_month == {10}


def test_overnight_range():
    entries = parse_ranges("22:00-06:00")
    e = entries[0]
    assert e.time_start == Time(22, 0)
    assert e.time_end == Time(6, 0)
    # time_end < time_start signals overnight
    assert e.time_end < e.time_start


def test_combined_month_weekday():
    entries = parse_ranges("Jan-Jun Mon-Fri 08:00-16:00")
    e = entries[0]
    assert e.months == {1, 2, 3, 4, 5, 6}
    assert e.weekdays == {0, 1, 2, 3, 4}
    assert e.days_of_month is None


def test_raw_preserved():
    line = "Jan-Jun Mon-Fri 08:00-16:00"
    entries = parse_ranges(line)
    assert entries[0].raw == line


def test_blank_lines_skipped():
    entries = parse_ranges("\n\n08:00-16:00\n\n")
    assert len(entries) == 1


def test_error_dom_and_weekday_together():
    with pytest.raises(ValueError, match="cannot specify both"):
        parse_ranges("15 Mon 08:00-16:00")


def test_error_unknown_token():
    with pytest.raises(ValueError, match="unrecognized token"):
        parse_ranges("Xyz 08:00-16:00")


def test_error_no_time_range():
    with pytest.raises(ValueError, match="no time range"):
        parse_ranges("Mon-Fri")


def test_error_month_range_descending():
    with pytest.raises(ValueError, match="ascending"):
        parse_ranges("Jun-Jan 08:00-16:00")
