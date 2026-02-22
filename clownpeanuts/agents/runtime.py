"""Agent module status and gating runtime."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from clownpeanuts.config.schema import AgentsConfig


@dataclass(slots=True)
class _ModuleStatus:
    name: str
    enabled: bool
    state: str
    reason: str
    blockers: list[str]
    config: dict[str, Any]


class AgentRuntime:
    """Evaluates optional agent-module readiness without forcing activation."""

    def __init__(self, *, config: AgentsConfig, ecosystem_enabled: bool) -> None:
        self._config = config
        self._ecosystem_enabled = bool(ecosystem_enabled)

    def snapshot(self) -> dict[str, Any]:
        modules = [
            self._module_status(
                name="pripyatsprings",
                enabled=self._config.pripyatsprings.enabled,
                blockers=self._pripyatsprings_blockers(),
                config=self._pripyatsprings_config(),
            ),
            self._module_status(
                name="adlibs",
                enabled=self._config.adlibs.enabled,
                blockers=self._adlibs_blockers(),
                config=self._adlibs_config(),
            ),
            self._module_status(
                name="dirtylaundry",
                enabled=self._config.dirtylaundry.enabled,
                blockers=self._dirtylaundry_blockers(),
                config=self._dirtylaundry_config(),
            ),
        ]
        enabled_count = sum(1 for module in modules if module.enabled)
        ready_count = sum(1 for module in modules if module.state == "ready")
        blocked_count = sum(1 for module in modules if module.state == "blocked")
        return {
            "ecosystem_enabled": self._ecosystem_enabled,
            "enabled_count": enabled_count,
            "ready_count": ready_count,
            "blocked_count": blocked_count,
            "modules": [
                {
                    "name": module.name,
                    "enabled": module.enabled,
                    "state": module.state,
                    "reason": module.reason,
                    "blockers": list(module.blockers),
                    "config": module.config,
                }
                for module in modules
            ],
        }

    def _module_status(
        self,
        *,
        name: str,
        enabled: bool,
        blockers: list[str],
        config: dict[str, Any],
    ) -> _ModuleStatus:
        if not enabled:
            return _ModuleStatus(
                name=name,
                enabled=False,
                state="disabled",
                reason="module disabled by config",
                blockers=[],
                config=config,
            )
        if not self._ecosystem_enabled:
            return _ModuleStatus(
                name=name,
                enabled=True,
                state="blocked",
                reason="ecosystem.enabled must be true",
                blockers=["ecosystem.enabled must be true"],
                config=config,
            )
        if blockers:
            return _ModuleStatus(
                name=name,
                enabled=True,
                state="blocked",
                reason="module configuration incomplete",
                blockers=blockers,
                config=config,
            )
        return _ModuleStatus(
            name=name,
            enabled=True,
            state="ready",
            reason="module ready",
            blockers=[],
            config=config,
        )

    def _pripyatsprings_config(self) -> dict[str, Any]:
        cfg = self._config.pripyatsprings
        return {
            "backend_configured": bool(cfg.backend.strip()),
            "default_toxicity": cfg.default_toxicity,
            "tracking_domain": cfg.tracking_domain,
            "canary_dns_domain": cfg.canary_dns_domain,
            "tracking_server_port": cfg.tracking_server_port,
            "level3_acknowledgment": bool(cfg.level3_acknowledgment.strip()),
            "per_emulator_overrides": dict(cfg.per_emulator_overrides),
            "store_path": cfg.store_path,
        }

    def _adlibs_config(self) -> dict[str, Any]:
        cfg = self._config.adlibs
        return {
            "backend_configured": bool(cfg.backend.strip()),
            "ldap_uri": cfg.ldap_uri,
            "base_dn": cfg.base_dn,
            "target_ou": cfg.target_ou,
            "event_log_source": cfg.event_log_source,
            "fake_users": cfg.fake_users,
            "fake_service_accounts": cfg.fake_service_accounts,
            "fake_groups": cfg.fake_groups,
            "bloodhound_paths": cfg.bloodhound_paths,
            "witchbait_integration": cfg.witchbait_integration,
            "store_path": cfg.store_path,
        }

    def _dirtylaundry_config(self) -> dict[str, Any]:
        cfg = self._config.dirtylaundry
        return {
            "backend_configured": bool(cfg.backend.strip()),
            "matching_window_seconds": cfg.matching_window_seconds,
            "match_threshold": cfg.match_threshold,
            "skill_adaptive": cfg.skill_adaptive,
            "auto_theater_on_apt": cfg.auto_theater_on_apt,
            "profile_store_path": cfg.profile_store_path,
            "max_profiles": cfg.max_profiles,
            "max_sessions_per_profile": cfg.max_sessions_per_profile,
            "max_notes_per_profile": cfg.max_notes_per_profile,
            "sharing_enabled": cfg.sharing.enabled,
            "sharing_endpoint": cfg.sharing.endpoint,
            "sharing_export_interval_hours": cfg.sharing.export_interval_hours,
        }

    def _pripyatsprings_blockers(self) -> list[str]:
        cfg = self._config.pripyatsprings
        blockers: list[str] = []
        requires_level3_ack = cfg.default_toxicity >= 3 or any(
            int(value) >= 3 for value in cfg.per_emulator_overrides.values()
        )
        if requires_level3_ack and not cfg.level3_acknowledgment.strip():
            blockers.append(
                "level3_acknowledgment must be set when default_toxicity is 3 "
                "or per_emulator_overrides include level 3"
            )
        return blockers

    def _adlibs_blockers(self) -> list[str]:
        cfg = self._config.adlibs
        blockers: list[str] = []
        if not cfg.ldap_uri.strip():
            blockers.append("ldap_uri is required")
        if not cfg.ldap_bind_dn.strip():
            blockers.append("ldap_bind_dn is required")
        if not cfg.ldap_bind_password_env.strip():
            blockers.append("ldap_bind_password_env is required")
        if not cfg.base_dn.strip():
            blockers.append("base_dn is required")
        if not cfg.target_ou.strip():
            blockers.append("target_ou is required")
        return blockers

    def _dirtylaundry_blockers(self) -> list[str]:
        cfg = self._config.dirtylaundry
        blockers: list[str] = []
        if cfg.sharing.enabled and not cfg.sharing.endpoint.strip():
            blockers.append("sharing.endpoint is required when sharing.enabled is true")
        return blockers
