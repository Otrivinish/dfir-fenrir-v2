"""R129: CSV formula-injection guard (OWASP "CSV Injection").

Spreadsheets evaluate a cell that starts with = + - @ TAB or CR as a formula. Many exported fields are
attacker-influenced (user agents in the audit trail, IOC values, email subjects, imported log lines), so
every CSV writer passes its cells through csv_safe() before the csv module quotes them.

Only the CSV form is escaped. JSON exports, hashes and signatures keep the raw value; recompute any hash
from the JSON, never from a CSV cell.
"""
import re

_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")
_PLAIN_NUMBER = re.compile(r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?")


def csv_safe(value):
    """A string starting with = + - @ TAB or CR gets a leading ' so a spreadsheet shows it as text.
    Plain numbers ("-12.5", "+3") and non-strings are returned unchanged."""
    if isinstance(value, str) and value[:1] in _FORMULA_START and not _PLAIN_NUMBER.fullmatch(value):
        return "'" + value
    return value
