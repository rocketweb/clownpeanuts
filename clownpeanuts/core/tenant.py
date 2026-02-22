"""Multi-tenant configuration helpers."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from clownpeanuts.config.schema import MultiTenantConfig, ServiceConfig, TenantConfig


class TenantManager:
    def __init__(self, config: MultiTenantConfig | None = None) -> None:
        self.config = config or MultiTenantConfig()

    def resolve_tenant(self, requested_tenant: str | None = None) -> TenantConfig:
        requested = (requested_tenant or self.config.default_tenant).strip() or self.config.default_tenant
        if not self.config.enabled:
            return TenantConfig(tenant_id=requested, display_name=requested, enabled=True, tags=[], service_overrides={})
        for tenant in self.config.tenants:
            if tenant.tenant_id == requested and tenant.enabled:
                return tenant
        for tenant in self.config.tenants:
            if tenant.tenant_id == self.config.default_tenant and tenant.enabled:
                return tenant
        return TenantConfig(
            tenant_id=self.config.default_tenant,
            display_name=self.config.default_tenant,
            enabled=True,
            tags=[],
            service_overrides={},
        )

    def apply_service_overrides(self, services: list[ServiceConfig], tenant: TenantConfig) -> list[ServiceConfig]:
        updated: list[ServiceConfig] = []
        for service in services:
            override = tenant.service_overrides.get(service.name)
            if not override:
                updated.append(replace(service))
                continue
            config_update = dict(service.config)
            nested = override.get("config", {})
            if isinstance(nested, dict):
                config_update.update(nested)
            ports = service.ports
            override_ports = override.get("ports")
            if isinstance(override_ports, list) and all(isinstance(item, int) for item in override_ports):
                ports = [int(item) for item in override_ports]
            updated.append(
                ServiceConfig(
                    name=service.name,
                    module=str(override.get("module", service.module)),
                    enabled=bool(override.get("enabled", service.enabled)),
                    listen_host=str(override.get("listen_host", service.listen_host)),
                    ports=list(ports),
                    config=config_update,
                )
            )
        return updated

    def snapshot(self) -> dict[str, Any]:
        return {
            "enabled": self.config.enabled,
            "default_tenant": self.config.default_tenant,
            "tenants": [
                {
                    "id": tenant.tenant_id,
                    "display_name": tenant.display_name,
                    "enabled": tenant.enabled,
                    "tags": tenant.tags,
                }
                for tenant in self.config.tenants
            ],
        }
