"""Service emulator interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from clownpeanuts.config.schema import ServiceConfig


@dataclass(slots=True)
class ServiceRuntime:
    session_manager: Any
    event_logger: Any
    event_bus: Any
    rabbit_hole: Any = None
    bandit_select: Any = None
    alert_router: Any = None
    tenant_id: str = "default"
    red_team: Any = None


class ServiceEmulator(ABC):
    def __init__(self) -> None:
        self.running = False
        self.runtime: ServiceRuntime | None = None

    def set_runtime(self, runtime: ServiceRuntime) -> None:
        self.runtime = runtime

    def apply_runtime_config(self, config: ServiceConfig) -> None:
        """Apply mutable runtime config updates without a full restart."""
        _ = config

    def inject_activity(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Inject synthetic activity into a running emulator instance."""
        _ = payload
        return {
            "accepted": False,
            "service": self.name,
            "reason": "activity injection not supported by this emulator",
        }

    @abstractmethod
    async def start(self, config: ServiceConfig) -> None: ...

    @abstractmethod
    async def stop(self) -> None: ...

    @abstractmethod
    async def handle_connection(self, conn: dict[str, Any]) -> dict[str, Any]: ...

    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    @abstractmethod
    def default_ports(self) -> list[int]: ...

    @property
    @abstractmethod
    def config_schema(self) -> dict[str, Any]: ...
