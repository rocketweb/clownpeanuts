"""Spreadsheet formula-injection neutralization for CSV/TSV exports.

CSV quoting protects the parser, not the spreadsheet: a cell whose first
character is ``= + - @`` (or a leading tab/carriage-return) is interpreted as a
formula when the file is opened in Excel, Google Sheets, or LibreOffice. Because
honeypot exports carry attacker-derived strings (source IPs, session ids,
technique names, free-text fields), those cells must be neutralized before they
are written so an analyst opening the export cannot trigger
``=WEBSERVICE(...)`` / ``=HYPERLINK(...)`` data exfiltration or DDE execution.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

# Leading characters that a spreadsheet may interpret as the start of a formula.
_FORMULA_TRIGGERS = ("=", "+", "-", "@", "\t", "\r")


def neutralize_cell(value: Any) -> Any:
    """Prefix a leading apostrophe if a string cell could trigger a formula.

    Non-string values are returned unchanged (numbers cannot carry a trigger
    once rendered by the csv module).
    """

    if not isinstance(value, str):
        return value
    if value and value[0] in _FORMULA_TRIGGERS:
        return "'" + value
    return value


def safe_row(row: Mapping[str, Any]) -> dict[str, Any]:
    """Return a copy of ``row`` with every string cell formula-neutralized."""

    return {key: neutralize_cell(value) for key, value in row.items()}


class SafeDictWriter:
    """Thin wrapper over ``csv.DictWriter`` that neutralizes every data row.

    Header names are written verbatim (they are fixed, trusted field names);
    only row values are neutralized.
    """

    def __init__(self, writer: Any) -> None:
        self._writer = writer

    def writeheader(self) -> Any:
        return self._writer.writeheader()

    def writerow(self, row: Mapping[str, Any]) -> Any:
        return self._writer.writerow(safe_row(row))

    def writerows(self, rows: Any) -> None:
        for row in rows:
            self.writerow(row)
