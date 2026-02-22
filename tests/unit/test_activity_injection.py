from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from clownpeanuts.services.base import ServiceRuntime
from clownpeanuts.services.database.memcached_emulator import Emulator as MemcachedEmulator
from clownpeanuts.services.database.mongo_emulator import Emulator as MongoEmulator
from clownpeanuts.services.database.mysql_emulator import Emulator as MySQLEmulator
from clownpeanuts.services.database.postgres_emulator import Emulator as PostgresEmulator
from clownpeanuts.services.database.redis_emulator import Emulator as RedisEmulator
from clownpeanuts.services.http.emulator import Emulator as HTTPEmulator
from clownpeanuts.services.ssh.emulator import Emulator as SSHEmulator


@dataclass
class _FakeSessionManager:
    events_by_session: dict[str, list[dict[str, Any]]] = field(default_factory=dict)

    def get_or_create(self, session_id: str, source_ip: str, fingerprint: str | None = None) -> dict[str, Any]:
        _ = fingerprint
        self.events_by_session.setdefault(session_id, [])
        return {"session_id": session_id, "source_ip": source_ip}

    def record_event(self, session_id: str, service: str, action: str, payload: dict[str, Any]) -> dict[str, Any]:
        event = {
            "session_id": session_id,
            "service": service,
            "action": action,
            "payload": payload,
        }
        self.events_by_session.setdefault(session_id, []).append(event)
        return event

    def session_event_count(self, session_id: str) -> int:
        return len(self.events_by_session.get(session_id, []))


@dataclass
class _FakeEventLogger:
    emitted: list[dict[str, Any]] = field(default_factory=list)

    def emit(self, **kwargs: Any) -> None:
        self.emitted.append(dict(kwargs))


def _runtime() -> ServiceRuntime:
    return ServiceRuntime(
        session_manager=_FakeSessionManager(),
        event_logger=_FakeEventLogger(),
        event_bus=object(),
    )


@pytest.mark.parametrize(
    ("emulator", "payload"),
    [
        (SSHEmulator(), {"type": "ssh_session", "commands": ["whoami", "id"], "session_id": "s-ssh"}),
        (HTTPEmulator(), {"type": "http_request", "method": "GET", "path": "/admin", "session_id": "s-http"}),
        (
            MySQLEmulator(),
            {"type": "database_query", "query": "SELECT 1", "username": "app", "session_id": "s-mysql"},
        ),
        (
            PostgresEmulator(),
            {"type": "database_query", "query": "SELECT 1", "username": "app", "session_id": "s-postgres"},
        ),
        (RedisEmulator(), {"type": "redis_command", "command": "PING", "session_id": "s-redis"}),
        (
            MongoEmulator(),
            {"type": "mongo_command", "command": "find", "document": {"find": "users"}, "session_id": "s-mongo"},
        ),
        (MemcachedEmulator(), {"type": "cache_command", "command": "get", "session_id": "s-memcached"}),
    ],
)
def test_emulators_accept_supported_activity_payloads(emulator: Any, payload: dict[str, Any]) -> None:
    emulator.set_runtime(_runtime())
    result = emulator.inject_activity(payload)
    assert result["accepted"] is True
    assert result["service"] == emulator.name
    assert result["session_id"] == payload["session_id"]


def test_emulator_rejects_unsupported_activity_type() -> None:
    emulator = SSHEmulator()
    emulator.set_runtime(_runtime())
    result = emulator.inject_activity({"type": "http_request"})
    assert result["accepted"] is False
    assert "unsupported activity type" in str(result["reason"]).lower()
