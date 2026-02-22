"""Minimal service emulator used for bootstrap and smoke tests."""

from __future__ import annotations

from typing import Any

from clownpeanuts.config.schema import ServiceConfig
from clownpeanuts.core.logging import get_logger
from clownpeanuts.services.base import ServiceEmulator


class Emulator(ServiceEmulator):
    def __init__(self) -> None:
        super().__init__()
        self.logger = get_logger("clownpeanuts.services.dummy")
        self._config: ServiceConfig | None = None

    @property
    def name(self) -> str:
        return "dummy"

    @property
    def default_ports(self) -> list[int]:
        return [2222]

    @property
    def config_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "greeting": {"type": "string"},
            },
        }

    async def start(self, config: ServiceConfig) -> None:
        self._config = config
        self.running = True
        self.logger.info(
            "service started",
            extra={
                "service": self.name,
            },
        )
        if self.runtime:
            self.runtime.event_logger.emit(
                message="dummy service started",
                service=self.name,
                action="service_start",
                event_type="start",
                payload={"ports": config.ports or self.default_ports},
            )

    async def stop(self) -> None:
        self.running = False
        self.logger.info("service stopped", extra={"service": self.name})
        if self.runtime:
            self.runtime.event_logger.emit(
                message="dummy service stopped",
                service=self.name,
                action="service_stop",
                event_type="end",
            )

    async def handle_connection(self, conn: dict[str, Any]) -> dict[str, Any]:
        greeting = (self._config.config if self._config else {}).get("greeting", "hello")
        result = {
            "service": self.name,
            "message": greeting,
            "echo": conn.get("payload"),
        }
        if self.runtime:
            session_id = str(conn.get("session_id", "dummy-session"))
            source_ip = str(conn.get("source_ip", "127.0.0.1"))
            self.runtime.session_manager.get_or_create(session_id=session_id, source_ip=source_ip)
            self.runtime.session_manager.record_event(
                session_id=session_id,
                service=self.name,
                action="dummy_connection",
                payload={"source_ip": source_ip, "payload": conn.get("payload")},
            )
            self.runtime.event_logger.emit(
                message="dummy connection handled",
                service=self.name,
                action="dummy_connection",
                session_id=session_id,
                source_ip=source_ip,
                event_type="access",
                outcome="success",
                payload=result,
            )
        return result

    def inject_activity(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.runtime is None:
            return {
                "accepted": False,
                "service": self.name,
                "reason": "runtime not initialized",
            }
        activity_type = str(payload.get("type", "generic")).strip() or "generic"
        session_id = str(payload.get("session_id", f"injected-{activity_type}")).strip() or f"injected-{activity_type}"
        source_ip = str(payload.get("source_ip", "127.0.0.1")).strip() or "127.0.0.1"
        details = payload.get("payload")
        if not isinstance(details, dict):
            details = {}
        self.runtime.session_manager.get_or_create(session_id=session_id, source_ip=source_ip)
        self.runtime.session_manager.record_event(
            session_id=session_id,
            service=self.name,
            action=f"injected_{activity_type}",
            payload={
                "source_ip": source_ip,
                "injected": True,
                "activity_type": activity_type,
                **details,
            },
        )
        self.runtime.event_logger.emit(
            message="dummy activity injected",
            service=self.name,
            action=f"injected_{activity_type}",
            session_id=session_id,
            source_ip=source_ip,
            event_type="activity",
            outcome="success",
            payload={
                "injected": True,
                "activity_type": activity_type,
                "details": details,
            },
        )
        return {
            "accepted": True,
            "service": self.name,
            "session_id": session_id,
            "activity_type": activity_type,
        }
