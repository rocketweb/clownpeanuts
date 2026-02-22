"""Adaptive throttling primitives for high-friction tarpit flows."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import random
import time
from typing import Any


@dataclass(slots=True)
class AdaptiveThrottleConfig:
    enabled: bool = True
    min_delay_ms: int = 15
    max_delay_ms: int = 250
    ramp_events: int = 10
    jitter_ratio: float = 0.2


class AdaptiveThrottle:
    def __init__(self, service_name: str, config: AdaptiveThrottleConfig | None = None) -> None:
        self.service_name = service_name
        self.config = config or AdaptiveThrottleConfig()

    def configure(self, *, config: dict[str, Any]) -> None:
        self.config = AdaptiveThrottleConfig(
            enabled=bool(config.get("adaptive_tarpit_enabled", self.config.enabled)),
            min_delay_ms=max(0, int(config.get("tarpit_min_delay_ms", self.config.min_delay_ms))),
            max_delay_ms=max(0, int(config.get("tarpit_max_delay_ms", self.config.max_delay_ms))),
            ramp_events=max(1, int(config.get("tarpit_ramp_events", self.config.ramp_events))),
            jitter_ratio=max(0.0, float(config.get("tarpit_jitter_ratio", self.config.jitter_ratio))),
        )
        if self.config.max_delay_ms < self.config.min_delay_ms:
            self.config.max_delay_ms = self.config.min_delay_ms

    def maybe_delay(
        self,
        *,
        runtime: Any,
        session_id: str,
        source_ip: str,
        source_port: int,
        trigger: str,
    ) -> float:
        if not self.config.enabled:
            return 0.0

        event_count = 0
        if runtime:
            try:
                event_count = int(runtime.session_manager.session_event_count(session_id))
            except Exception:
                event_count = 0

        ratio = min(1.0, float(event_count) / float(max(1, self.config.ramp_events)))
        span = max(0, self.config.max_delay_ms - self.config.min_delay_ms)
        delay_ms = float(self.config.min_delay_ms) + (span * ratio)
        if self.config.jitter_ratio > 0:
            jitter_scale = random.uniform(1.0 - self.config.jitter_ratio, 1.0 + self.config.jitter_ratio)
            delay_ms *= jitter_scale
        delay_ms = max(float(self.config.min_delay_ms), min(float(self.config.max_delay_ms), delay_ms))
        configured_delay_seconds = delay_ms / 1000.0
        applied_delay_seconds = configured_delay_seconds
        skipped_in_async_context = False
        if configured_delay_seconds > 0:
            if self._running_in_async_context():
                applied_delay_seconds = 0.0
                skipped_in_async_context = True
            else:
                time.sleep(configured_delay_seconds)

        if runtime:
            runtime.event_logger.emit(
                message="adaptive tarpit delay",
                service=self.service_name,
                action="tarpit_delay",
                session_id=session_id,
                source_ip=source_ip,
                source_port=source_port,
                event_type="info",
                outcome="success",
                payload={
                    "trigger": trigger,
                    "event_count": event_count,
                    "delay_ms": round(applied_delay_seconds * 1000.0, 3),
                    "configured_delay_ms": round(delay_ms, 3),
                    "skipped_in_async_context": skipped_in_async_context,
                },
            )
        return applied_delay_seconds

    @staticmethod
    def _running_in_async_context() -> bool:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return False
        return loop.is_running()
