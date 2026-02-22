import pytest
import types
import sys

from clownpeanuts.config.schema import ServiceConfig
from clownpeanuts.core.plugin import PluginError, PluginRegistry
from clownpeanuts.services.base import ServiceEmulator


def test_plugin_registry_loads_dummy() -> None:
    registry = PluginRegistry()
    service = ServiceConfig(
        name="dummy",
        module="clownpeanuts.services.dummy.emulator",
        ports=[2222],
    )
    emulator = registry.instantiate(service)
    assert emulator.name == "dummy"


def test_plugin_registry_loads_redis_db() -> None:
    registry = PluginRegistry()
    service = ServiceConfig(
        name="redis-db",
        module="clownpeanuts.services.database.redis_emulator",
        ports=[6380],
    )
    emulator = registry.instantiate(service)
    assert emulator.name == "redis_db"


def test_plugin_registry_loads_mysql_db() -> None:
    registry = PluginRegistry()
    service = ServiceConfig(
        name="mysql-db",
        module="clownpeanuts.services.database.mysql_emulator",
        ports=[13306],
    )
    emulator = registry.instantiate(service)
    assert emulator.name == "mysql_db"


def test_plugin_registry_loads_postgres_db() -> None:
    registry = PluginRegistry()
    service = ServiceConfig(
        name="postgres-db",
        module="clownpeanuts.services.database.postgres_emulator",
        ports=[15432],
    )
    emulator = registry.instantiate(service)
    assert emulator.name == "postgres_db"


def test_plugin_registry_loads_mongo_db() -> None:
    registry = PluginRegistry()
    service = ServiceConfig(
        name="mongo-db",
        module="clownpeanuts.services.database.mongo_emulator",
        ports=[27018],
    )
    emulator = registry.instantiate(service)
    assert emulator.name == "mongo_db"


def test_plugin_registry_loads_memcached_db() -> None:
    registry = PluginRegistry()
    service = ServiceConfig(
        name="memcached-db",
        module="clownpeanuts.services.database.memcached_emulator",
        ports=[11212],
    )
    emulator = registry.instantiate(service)
    assert emulator.name == "memcached_db"


def test_plugin_registry_rejects_disallowed_module() -> None:
    registry = PluginRegistry()
    service = ServiceConfig(
        name="bad",
        module="builtins",
        ports=[1],
    )
    with pytest.raises(PluginError, match="allowed module list"):
        registry.instantiate(service)


def test_plugin_registry_allows_explicit_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeEmulator(ServiceEmulator):
        @property
        def name(self) -> str:
            return "fake"

        @property
        def default_ports(self) -> list[int]:
            return [1]

        @property
        def config_schema(self) -> dict[str, object]:
            return {"type": "object"}

        async def start(self, config: ServiceConfig) -> None:
            self.running = True

        async def stop(self) -> None:
            self.running = False

        async def handle_connection(self, conn: dict[str, object]) -> dict[str, object]:
            return {"ok": True}

    module_name = "fake_emulator_module"
    fake_module = types.ModuleType(module_name)
    fake_module.Emulator = _FakeEmulator
    monkeypatch.setitem(sys.modules, module_name, fake_module)

    registry = PluginRegistry()
    monkeypatch.setenv("CLOWNPEANUTS_EXTRA_ALLOWED_MODULES", module_name)
    service = ServiceConfig(
        name="fake",
        module=module_name,
        ports=[2222],
    )
    emulator = registry.instantiate(service)
    assert emulator.name == "fake"
