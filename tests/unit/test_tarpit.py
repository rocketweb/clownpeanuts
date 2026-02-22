import asyncio

from clownpeanuts.tarpit.infinite_exfil import InfiniteExfilConfig, InfiniteExfilStream
from clownpeanuts.tarpit.slowdrip import SlowDripProfile
from clownpeanuts.tarpit.throttle import AdaptiveThrottle


class _FakeSessionManager:
    def __init__(self, events: int) -> None:
        self.events = events

    def session_event_count(self, _session_id: str) -> int:
        return self.events


class _FakeEventLogger:
    def __init__(self) -> None:
        self.last_payload: dict | None = None

    def emit(self, **kwargs: object) -> None:
        payload = kwargs.get("payload")
        if isinstance(payload, dict):
            self.last_payload = payload


class _FakeRuntime:
    def __init__(self, events: int) -> None:
        self.session_manager = _FakeSessionManager(events)
        self.event_logger = _FakeEventLogger()


def test_adaptive_tarpit_delay_can_be_disabled() -> None:
    throttle = AdaptiveThrottle(service_name="ssh")
    throttle.configure(
        config={
            "adaptive_tarpit_enabled": False,
            "tarpit_min_delay_ms": 25,
            "tarpit_max_delay_ms": 50,
        }
    )
    delay = throttle.maybe_delay(
        runtime=_FakeRuntime(events=50),
        session_id="s1",
        source_ip="127.0.0.1",
        source_port=22,
        trigger="test",
    )
    assert delay == 0.0


def test_adaptive_tarpit_delay_uses_session_depth() -> None:
    throttle = AdaptiveThrottle(service_name="redis_db")
    throttle.configure(
        config={
            "adaptive_tarpit_enabled": True,
            "tarpit_min_delay_ms": 0,
            "tarpit_max_delay_ms": 0,
            "tarpit_ramp_events": 5,
        }
    )
    runtime = _FakeRuntime(events=10)
    delay = throttle.maybe_delay(
        runtime=runtime,
        session_id="s2",
        source_ip="127.0.0.1",
        source_port=6380,
        trigger="command",
    )
    assert delay == 0.0
    assert runtime.event_logger.last_payload is not None
    assert runtime.event_logger.last_payload["event_count"] == 10


def test_adaptive_tarpit_delay_skips_blocking_sleep_in_async_context() -> None:
    throttle = AdaptiveThrottle(service_name="http_admin")
    throttle.configure(
        config={
            "adaptive_tarpit_enabled": True,
            "tarpit_min_delay_ms": 25,
            "tarpit_max_delay_ms": 25,
            "tarpit_ramp_events": 1,
            "tarpit_jitter_ratio": 0.0,
        }
    )
    runtime = _FakeRuntime(events=10)

    async def _call_delay() -> float:
        return throttle.maybe_delay(
            runtime=runtime,
            session_id="async-s1",
            source_ip="127.0.0.1",
            source_port=8080,
            trigger="http_get",
        )

    delay = asyncio.run(_call_delay())
    assert delay == 0.0
    assert runtime.event_logger.last_payload is not None
    assert runtime.event_logger.last_payload["skipped_in_async_context"] is True
    assert runtime.event_logger.last_payload["configured_delay_ms"] == 25.0
    assert runtime.event_logger.last_payload["delay_ms"] == 0.0


def test_slowdrip_profile_returns_non_negative_delay() -> None:
    profile = SlowDripProfile(min_delay_ms=0, max_delay_ms=0, jitter_ratio=0.5)
    assert profile.next_delay_seconds() == 0.0


def test_infinite_exfil_stream_honors_chunk_size_and_max_chunks() -> None:
    stream = InfiniteExfilStream(InfiniteExfilConfig(chunk_size_bytes=128, max_chunks=3))
    chunks = list(stream.iter_chunks())
    assert len(chunks) == 3
    assert all(len(chunk) == 128 for chunk in chunks)
