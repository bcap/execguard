"""execguard — block executables outside allowed hours via fanotify."""

from .config import RangeEntry, Rule, is_permitted, load_config, parse_ranges
from .main import DEFAULT_CONFIG_PATH, main, parse_test_datetime, run_test_mode

__all__ = [
    "RangeEntry", "Rule",
    "is_permitted", "load_config", "parse_ranges",
    "main", "parse_test_datetime", "run_test_mode",
    "DEFAULT_CONFIG_PATH",
]
