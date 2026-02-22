"""Data generation middleware scaffolding."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .corruption import apply_corruption
from .payloads import apply_active_payload_markers


@dataclass(slots=True)
class MiddlewareConfig:
    enabled: bool = False
    default_toxicity: int = 2


class ToxicDataMiddleware:
    """Optional no-op-by-default middleware for generated artifacts."""

    def __init__(self, config: MiddlewareConfig | None = None) -> None:
        self.config = config or MiddlewareConfig()

    def transform(
        self,
        payload: dict[str, Any],
        *,
        toxicity_level: int | None = None,
    ) -> dict[str, Any]:
        if not self.config.enabled:
            return dict(payload)
        level = toxicity_level if toxicity_level is not None else self.config.default_toxicity
        safe_level = max(1, min(3, int(level)))
        transformed = dict(payload)
        transformed["tracking_enabled"] = True
        if safe_level >= 2:
            transformed = apply_corruption(transformed)
        if safe_level >= 3:
            transformed = apply_active_payload_markers(transformed)
        transformed["toxicity_level"] = safe_level
        return transformed
