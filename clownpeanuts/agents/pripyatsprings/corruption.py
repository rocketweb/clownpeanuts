"""Deterministic corruption markers for optional toxic-data workflows."""

from __future__ import annotations

from typing import Any


def apply_corruption(payload: dict[str, Any]) -> dict[str, Any]:
    """Apply non-destructive corruption markers to a generated payload."""

    transformed = dict(payload)
    warnings = list(transformed.get("integrity_warnings", []))
    warnings.extend(
        [
            "statistical skew markers inserted",
            "referential integrity hints degraded",
        ]
    )
    transformed["integrity_warnings"] = warnings
    transformed["corruption_applied"] = True
    return transformed

