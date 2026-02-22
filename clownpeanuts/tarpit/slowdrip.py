"""Slow-drip pacing helpers for tarpit streams."""

from __future__ import annotations

from dataclasses import dataclass
import random


@dataclass(slots=True)
class SlowDripProfile:
    min_delay_ms: int = 80
    max_delay_ms: int = 250
    jitter_ratio: float = 0.0

    def next_delay_seconds(self) -> float:
        min_delay = max(0, int(self.min_delay_ms))
        max_delay = max(min_delay, int(self.max_delay_ms))
        if max_delay <= 0:
            return 0.0
        delay_ms = random.uniform(min_delay, max_delay)
        jitter = max(0.0, float(self.jitter_ratio))
        if jitter > 0:
            delay_ms *= random.uniform(1.0 - jitter, 1.0 + jitter)
        return max(0.0, float(delay_ms) / 1000.0)
