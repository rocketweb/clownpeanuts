"""Active payload markers for optional toxicity-level workflows."""

from __future__ import annotations

from typing import Any


def apply_active_payload_markers(payload: dict[str, Any]) -> dict[str, Any]:
    """Attach inert marker strings used by downstream forensic tooling."""

    transformed = dict(payload)
    markers = list(transformed.get("active_payload_markers", []))
    markers.extend(
        [
            "csv_formula_marker",
            "archive_traversal_marker",
            "deserialization_marker",
        ]
    )
    transformed["active_payload_markers"] = markers
    transformed["active_payload_markers_applied"] = True
    return transformed

