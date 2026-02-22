from clownpeanuts.config.schema import EventBusConfig
from clownpeanuts.core.event_bus import EventBus
import pytest


def test_event_bus_memory_publish_subscribe() -> None:
    bus = EventBus(EventBusConfig(backend="memory"))
    received: list[dict] = []
    bus.subscribe("service.ssh", received.append)
    bus.publish("service.ssh", {"action": "command", "value": "whoami"})
    snap = bus.snapshot()
    assert received
    assert received[0]["payload"]["value"] == "whoami"
    assert snap["backend"] == "memory"
    assert snap["published"] >= 1
    assert snap["delivered"] >= 1
    bus.close()


def test_event_bus_cursor_read_respects_limits_and_rollover() -> None:
    bus = EventBus(EventBusConfig(backend="memory"))
    for index in range(5):
        bus.publish("events", {"message": f"seed-{index}"})

    batch_one, cursor = bus.recent_events_since(cursor=0, limit=2)
    assert [item["payload"]["message"] for item in batch_one] == ["seed-0", "seed-1"]
    assert cursor == int(batch_one[-1]["event_id"])

    batch_two, cursor = bus.recent_events_since(cursor=cursor, limit=10)
    assert [item["payload"]["message"] for item in batch_two] == ["seed-2", "seed-3", "seed-4"]
    assert cursor == int(batch_two[-1]["event_id"])

    for index in range(250):
        bus.publish("events", {"message": f"rollover-{index}"})

    recent = bus.recent_events()
    first_retained_id = int(recent[0]["event_id"])
    rollover_batch, rollover_cursor = bus.recent_events_since(cursor=0, limit=1000)
    assert rollover_batch
    assert int(rollover_batch[0]["event_id"]) == first_retained_id
    assert rollover_cursor == int(rollover_batch[-1]["event_id"])
    bus.close()


def test_event_bus_redis_falls_back_when_unavailable() -> None:
    bus = EventBus(
        EventBusConfig(
            backend="redis",
            redis_url="redis://127.0.0.1:0/1",
            connect_timeout_seconds=0.05,
            required=False,
        )
    )
    assert bus.backend == "memory"
    bus.close()


def test_event_bus_required_redis_raises() -> None:
    with pytest.raises(RuntimeError):
        EventBus(
            EventBusConfig(
                backend="redis",
                redis_url="redis://127.0.0.1:0/1",
                connect_timeout_seconds=0.05,
                required=True,
            )
        )


def test_event_bus_redis_url_credential_detection() -> None:
    assert EventBus._redis_url_has_credentials("redis://:strong-password@redis:6379/1")
    assert EventBus._redis_url_has_credentials("rediss://user:strong-password@redis:6379/1")
    assert not EventBus._redis_url_has_credentials("redis://redis:6379/1")
    assert not EventBus._redis_url_has_credentials("redis://user@redis:6379/1")


def test_event_bus_redacts_redis_url_passwords() -> None:
    assert EventBus._redact_redis_url("redis://:strong-password@redis:6379/1") == "redis://:***@redis:6379/1"
    assert EventBus._redact_redis_url("rediss://user:strong-password@redis:6379/1") == "rediss://user:***@redis:6379/1"
    assert EventBus._redact_redis_url("redis://redis:6379/1") == "redis://redis:6379/1"
