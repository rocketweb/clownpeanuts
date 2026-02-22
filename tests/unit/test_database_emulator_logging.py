from clownpeanuts.services.base import ServiceRuntime
from clownpeanuts.services.database.mysql_emulator import Emulator as MySQLEmulator
from clownpeanuts.services.database.postgres_emulator import Emulator as PostgresEmulator


class _StubSessionManager:
    def __init__(self) -> None:
        self.events: list[dict[str, object]] = []

    def record_event(self, session_id: str, service: str, action: str, payload: dict[str, object]) -> None:
        self.events.append(
            {
                "session_id": session_id,
                "service": service,
                "action": action,
                "payload": payload,
            }
        )


class _StubEventLogger:
    def __init__(self) -> None:
        self.emits: list[dict[str, object]] = []

    def emit(self, **kwargs: object) -> None:
        self.emits.append(kwargs)


def _runtime() -> ServiceRuntime:
    return ServiceRuntime(
        session_manager=_StubSessionManager(),
        event_logger=_StubEventLogger(),
        event_bus=None,
    )


def test_mysql_record_query_emits_event_log_and_session_event() -> None:
    emulator = MySQLEmulator()
    runtime = _runtime()
    emulator.set_runtime(runtime)

    emulator._record_query(  # type: ignore[attr-defined]
        session_id="mysql-query-log",
        source_ip="198.51.100.10",
        source_port=33060,
        query="SELECT 1",
    )

    assert len(runtime.session_manager.events) == 1
    assert runtime.session_manager.events[0]["action"] == "command"
    assert len(runtime.event_logger.emits) == 1
    assert runtime.event_logger.emits[0]["message"] == "mysql query"
    assert runtime.event_logger.emits[0]["source_port"] == 33060


def test_postgres_record_query_emits_event_log_and_session_event() -> None:
    emulator = PostgresEmulator()
    runtime = _runtime()
    emulator.set_runtime(runtime)

    emulator._record_query(  # type: ignore[attr-defined]
        session_id="postgres-query-log",
        source_ip="198.51.100.11",
        source_port=54320,
        query="SELECT 1",
    )

    assert len(runtime.session_manager.events) == 1
    assert runtime.session_manager.events[0]["action"] == "command"
    assert len(runtime.event_logger.emits) == 1
    assert runtime.event_logger.emits[0]["message"] == "postgres query"
    assert runtime.event_logger.emits[0]["source_port"] == 54320
