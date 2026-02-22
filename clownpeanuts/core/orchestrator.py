"""Service lifecycle orchestration for configured emulators."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
import ipaddress
import threading
from typing import Any
from urllib.parse import urlparse

from clownpeanuts.alerts.router import AlertRouter
from clownpeanuts.agents import AgentRuntime
from clownpeanuts.config.schema import AppConfig, ServiceConfig
from clownpeanuts.core.tenant import TenantManager
from clownpeanuts.engine.rabbit_hole import RabbitHoleEngine
from clownpeanuts.core.event_bus import EventBus
from clownpeanuts.core.logging import EventLogger, configure_logging, get_logger
from clownpeanuts.core.network import IsolationReport, NetworkIsolationManager
from clownpeanuts.core.plugin import PluginRegistry
from clownpeanuts.core.session import SessionManager
from clownpeanuts.intel.collector import build_intelligence_report
from clownpeanuts.intel.canary import generate_canary_token as build_canary_token
from clownpeanuts.intel.canary import summarize_canary_hits
from clownpeanuts.intel.canary import token_identifier
from clownpeanuts.intel.classifier import classify_session
from clownpeanuts.intel.lure_bandit import LureBandit
from clownpeanuts.intel.mitre import summarize_techniques
from clownpeanuts.intel.rotation import ThreatFeedRotator
from clownpeanuts.intel.scoring import score_narrative_coherence, score_session
from clownpeanuts.intel.store import IntelligenceStore
from clownpeanuts.services.base import ServiceEmulator, ServiceRuntime
from clownpeanuts.templates.deception import DeceptionTemplateLoader


@dataclass(slots=True)
class LoadedService:
    config: ServiceConfig
    emulator: ServiceEmulator
    source: str = "baseline"
    deployment_id: str | None = None


@dataclass(slots=True)
class RuntimeDeployment:
    deployment_id: str
    services: list[LoadedService]
    manifest_source: str
    activated_at: str


class Orchestrator:
    _DISALLOWED_DEFAULT_REDIS_PASSWORDS = {
        "clownpeanuts-dev-redis",
        "replace-with-strong-redis-password",
    }
    _DISALLOWED_DEFAULT_API_TOKENS = {
        "clownpeanuts-ops-operator-token-2026",
        "replace-with-long-operator-token-0123456789",
    }

    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self._validate_non_development_credentials()
        configure_logging(config.logging)
        self.logger = get_logger("clownpeanuts.orchestrator", level=config.logging.level)
        self.event_bus = EventBus(config.event_bus)
        self.event_logger = EventLogger(
            logger=get_logger("clownpeanuts.events", level=config.logging.level),
            service_name=config.logging.service_name,
            publish_hook=self._publish_event,
        )
        self.plugin_registry = PluginRegistry()
        self.network = NetworkIsolationManager()
        self.session_manager = SessionManager(config.session)
        self.tenant_manager = TenantManager(config.multi_tenant)
        self.template_loader = DeceptionTemplateLoader(config.templates)
        self.threat_rotator = ThreatFeedRotator(config.threat_intel)
        self.intel_store = IntelligenceStore()
        self.rabbit_hole = RabbitHoleEngine(config.engine, narrative_config=config.narrative)
        self.lure_bandit = LureBandit(config.bandit)
        self.alert_router = AlertRouter(config.alerts, config.red_team)
        self.agent_runtime = AgentRuntime(
            config=config.agents,
            ecosystem_enabled=config.ecosystem.enabled,
        )
        from clownpeanuts.dashboard.theater import TheaterService

        self.theater = TheaterService(config.theater)
        self.loaded_services: list[LoadedService] = []
        self._runtime_deployments: dict[str, RuntimeDeployment] = {}
        self._bootstrapped = False
        self._active_tenant = config.multi_tenant.default_tenant
        self._services_lock = threading.RLock()
        self._rotation_source_services: list[ServiceConfig] = []
        self._rotation_scheduler_thread: threading.Thread | None = None
        self._rotation_scheduler_stop = threading.Event()
        self._red_team_networks = [
            ipaddress.ip_network(cidr, strict=False) for cidr in config.red_team.internal_cidrs if cidr.strip()
        ]
        self._alert_subscription_initialized = False
        self._network_report = IsolationReport(outbound_blocked=not config.network.allow_outbound)

    def _validate_non_development_credentials(self) -> None:
        environment = str(getattr(self.config, "environment", "")).strip().lower()
        if environment == "development":
            return

        violations: list[str] = []
        if self.config.session.backend == "redis":
            password = self._redis_password(self.config.session.redis_url)
            if password in self._DISALLOWED_DEFAULT_REDIS_PASSWORDS:
                violations.append("session.redis_url uses a known default credential")
        if self.config.event_bus.backend == "redis":
            password = self._redis_password(self.config.event_bus.redis_url)
            if password in self._DISALLOWED_DEFAULT_REDIS_PASSWORDS:
                violations.append("event_bus.redis_url uses a known default credential")
        if self.config.api.auth_enabled:
            for token in [*self.config.api.auth_operator_tokens, *self.config.api.auth_viewer_tokens]:
                normalized = str(token).strip()
                if normalized in self._DISALLOWED_DEFAULT_API_TOKENS:
                    violations.append("api auth token uses a known default credential")
                    break

        if violations:
            detail = "; ".join(violations)
            raise RuntimeError(
                "refusing startup outside development with default credentials configured: "
                f"{detail}"
            )

    @staticmethod
    def _redis_password(redis_url: str) -> str:
        try:
            parsed = urlparse(redis_url)
        except Exception:
            return ""
        return str(parsed.password or "").strip()

    def bootstrap(self, *, tenant_id: str | None = None) -> None:
        self._stop_rotation_scheduler()
        tenant = self.tenant_manager.resolve_tenant(tenant_id)
        self._active_tenant = tenant.tenant_id
        report = self.network.enforce(self.config.network)
        self._network_report = report
        for violation in report.violations:
            self.logger.error(violation)
        for warning in report.warnings:
            self.logger.warning(warning)

        self._ensure_alert_subscription()

        services = self.tenant_manager.apply_service_overrides(self.config.services, tenant)
        services = self.template_loader.apply(services)
        self._rotation_source_services = self._clone_services(services)
        rotated_services = self.threat_rotator.apply(self._clone_services(self._rotation_source_services))
        loaded: list[LoadedService] = []
        for service_config in rotated_services:
            if not service_config.enabled:
                continue
            loaded.append(self._build_loaded_service(service_config))
        with self._services_lock:
            self.loaded_services = loaded
        self._bootstrapped = True

    async def start_all_async(self) -> None:
        if not self._bootstrapped:
            raise RuntimeError("orchestrator must be bootstrapped before start")
        with self._services_lock:
            loaded_snapshot = list(self.loaded_services)
        await asyncio.gather(*(loaded.emulator.start(loaded.config) for loaded in loaded_snapshot))
        self._start_rotation_scheduler()

    async def stop_all_async(self) -> None:
        self._stop_rotation_scheduler()
        with self._services_lock:
            loaded_snapshot = list(self.loaded_services)
        await asyncio.gather(*(loaded.emulator.stop() for loaded in loaded_snapshot))
        self.event_bus.close()

    def start_all(self) -> None:
        asyncio.run(self.start_all_async())

    def stop_all(self) -> None:
        asyncio.run(self.stop_all_async())

    def status(self) -> dict:
        report = self._network_report if self._bootstrapped else self.network.validate(self.config.network)
        with self._services_lock:
            loaded_snapshot = list(self.loaded_services)
        threat_snapshot = self.threat_rotator.snapshot()
        threat_snapshot["rotation_interval_seconds"] = self.config.threat_intel.rotation_interval_seconds
        threat_snapshot["scheduler_running"] = bool(
            self._rotation_scheduler_thread and self._rotation_scheduler_thread.is_alive()
        )
        return {
            "environment": self.config.environment,
            "bootstrapped": self._bootstrapped,
            "network": {
                "segmentation_mode": self.config.network.segmentation_mode,
                "outbound_blocked": report.outbound_blocked,
                "enforced": report.enforced,
                "compliant": report.compliant,
                "violations": report.violations,
                "warnings": report.warnings,
                "applied_rules": report.applied_rules,
            },
            "tenant": self._active_tenant,
            "services": [
                {
                    "name": loaded.config.name,
                    "module": loaded.config.module,
                    "ports": loaded.config.ports or loaded.emulator.default_ports,
                    "running": loaded.emulator.running,
                    "source": loaded.source,
                    "deployment_id": loaded.deployment_id,
                }
                for loaded in loaded_snapshot
            ],
            "sessions": self.session_manager.snapshot(),
            "event_bus": self.event_bus.snapshot(),
            "rabbit_hole": self.rabbit_hole.snapshot(),
            "narrative": {
                "enabled": self.config.narrative.enabled,
                "world_seed": self.config.narrative.world_seed,
                "entity_count": self.config.narrative.entity_count,
                "per_tenant_worlds": self.config.narrative.per_tenant_worlds,
            },
            "bandit": self.lure_bandit.snapshot(),
            "theater": self.theater.snapshot(),
            "alerts": self.alert_router.snapshot(),
            "intel_store": self.intel_store.snapshot(),
            "threat_intel": threat_snapshot,
            "multi_tenant": self.tenant_manager.snapshot(),
            "agents": self.agent_runtime.snapshot(),
        }

    def agents_status(self) -> dict[str, Any]:
        return self.agent_runtime.snapshot()

    def template_inventory(self) -> dict[str, Any]:
        return self.template_loader.inventory()

    def template_validation(self, *, tenant_id: str | None = None, all_tenants: bool = False) -> dict[str, Any]:
        if not all_tenants:
            tenant = self.tenant_manager.resolve_tenant(tenant_id)
            services = self.tenant_manager.apply_service_overrides(self.config.services, tenant)
            payload = self.template_loader.validate(services)
            payload["all_tenants"] = False
            payload["tenant"] = tenant.tenant_id
            payload["service_count"] = len(services)
            return payload

        tenant_reports: list[dict[str, Any]] = []
        for target in self._tenant_targets(tenant_id=tenant_id, all_tenants=True):
            tenant = self.tenant_manager.resolve_tenant(target)
            services = self.tenant_manager.apply_service_overrides(self.config.services, tenant)
            payload = self.template_loader.validate(services)
            payload["all_tenants"] = False
            payload["tenant"] = tenant.tenant_id
            payload["service_count"] = len(services)
            tenant_reports.append(payload)

        error_count = sum(max(0, int(item.get("error_count", 0))) for item in tenant_reports)
        warning_count = sum(max(0, int(item.get("warning_count", 0))) for item in tenant_reports)
        return {
            "all_tenants": True,
            "enabled": self.template_loader.config.enabled,
            "paths": [str(path) for path in self.template_loader.config.paths],
            "tenant_count": len(tenant_reports),
            "tenants": tenant_reports,
            "error_count": error_count,
            "warning_count": warning_count,
            "ok": all(bool(item.get("ok")) for item in tenant_reports),
        }

    def service_plan(
        self,
        *,
        tenant_id: str | None = None,
        apply_threat_rotation: bool = True,
        all_tenants: bool = False,
    ) -> dict[str, Any]:
        if all_tenants:
            plans: list[dict[str, Any]] = []
            for target in self._tenant_targets(tenant_id=tenant_id, all_tenants=True):
                tenant = self.tenant_manager.resolve_tenant(target)
                services = self.tenant_manager.apply_service_overrides(self.config.services, tenant)
                services = self.template_loader.apply(services)
                if apply_threat_rotation:
                    services = self.threat_rotator.apply(self._clone_services(services))
                plan = {
                    "all_tenants": False,
                    "tenant": tenant.tenant_id,
                    "apply_threat_rotation": bool(apply_threat_rotation),
                    "services": [
                        {
                            "name": service.name,
                            "module": service.module,
                            "enabled": service.enabled,
                            "listen_host": service.listen_host,
                            "ports": list(service.ports),
                            "config": dict(service.config),
                        }
                        for service in services
                    ],
                    "count": len(services),
                }
                plans.append(plan)
            return {
                "all_tenants": True,
                "tenant_count": len(plans),
                "apply_threat_rotation": bool(apply_threat_rotation),
                "count": sum(max(0, int(item.get("count", 0))) for item in plans),
                "plans": plans,
            }

        tenant = self.tenant_manager.resolve_tenant(tenant_id)
        services = self.tenant_manager.apply_service_overrides(self.config.services, tenant)
        services = self.template_loader.apply(services)
        if apply_threat_rotation:
            services = self.threat_rotator.apply(self._clone_services(services))
        return {
            "all_tenants": False,
            "tenant": tenant.tenant_id,
            "apply_threat_rotation": bool(apply_threat_rotation),
            "services": [
                {
                    "name": service.name,
                    "module": service.module,
                    "enabled": service.enabled,
                    "listen_host": service.listen_host,
                    "ports": list(service.ports),
                    "config": dict(service.config),
                }
                for service in services
            ],
            "count": len(services),
        }

    def service_plan_diff(
        self,
        *,
        left_tenant_id: str | None = None,
        right_tenant_id: str | None = None,
        apply_threat_rotation: bool = True,
    ) -> dict[str, Any]:
        left_tenant, right_tenant = self._comparison_tenants(
            left_tenant_id=left_tenant_id,
            right_tenant_id=right_tenant_id,
        )
        left_plan = self.service_plan(
            tenant_id=left_tenant,
            apply_threat_rotation=apply_threat_rotation,
            all_tenants=False,
        )
        right_plan = self.service_plan(
            tenant_id=right_tenant,
            apply_threat_rotation=apply_threat_rotation,
            all_tenants=False,
        )

        left_services = left_plan.get("services", [])
        right_services = right_plan.get("services", [])
        if not isinstance(left_services, list):
            left_services = []
        if not isinstance(right_services, list):
            right_services = []

        left_by_name = {
            str(service.get("name", "")): service
            for service in left_services
            if isinstance(service, dict) and str(service.get("name", "")).strip()
        }
        right_by_name = {
            str(service.get("name", "")): service
            for service in right_services
            if isinstance(service, dict) and str(service.get("name", "")).strip()
        }

        left_names = set(left_by_name.keys())
        right_names = set(right_by_name.keys())
        shared_names = sorted(left_names.intersection(right_names))
        left_only = sorted(left_names.difference(right_names))
        right_only = sorted(right_names.difference(left_names))

        changed: list[dict[str, Any]] = []
        for name in shared_names:
            left_service = left_by_name.get(name, {})
            right_service = right_by_name.get(name, {})
            fields_changed: list[str] = []
            for field in ("module", "enabled", "listen_host", "ports", "config"):
                if left_service.get(field) != right_service.get(field):
                    fields_changed.append(field)
            if fields_changed:
                changed.append(
                    {
                        "service": name,
                        "fields_changed": fields_changed,
                        "left": left_service,
                        "right": right_service,
                    }
                )

        different = bool(left_only or right_only or changed)
        return {
            "left_tenant": left_tenant,
            "right_tenant": right_tenant,
            "apply_threat_rotation": bool(apply_threat_rotation),
            "left_count": len(left_by_name),
            "right_count": len(right_by_name),
            "shared_count": len(shared_names),
            "left_only": left_only,
            "right_only": right_only,
            "changed": changed,
            "changed_count": len(changed),
            "different": different,
        }

    def service_plan_diff_matrix(
        self,
        *,
        tenant_id: str | None = None,
        apply_threat_rotation: bool = True,
    ) -> dict[str, Any]:
        targets = self._tenant_targets(tenant_id=tenant_id, all_tenants=True)
        comparisons: list[dict[str, Any]] = []
        for left_index, left in enumerate(targets):
            for right in targets[left_index + 1 :]:
                comparisons.append(
                    self.service_plan_diff(
                        left_tenant_id=left,
                        right_tenant_id=right,
                        apply_threat_rotation=apply_threat_rotation,
                    )
                )

        different_count = sum(1 for item in comparisons if bool(item.get("different")))
        return {
            "apply_threat_rotation": bool(apply_threat_rotation),
            "tenants": targets,
            "tenant_count": len(targets),
            "comparisons": comparisons,
            "comparison_count": len(comparisons),
            "different_count": different_count,
            "all_same": different_count == 0,
        }

    def intelligence_report(self, *, limit: int = 200, events_per_session: int = 200) -> dict:
        sessions_payload = self.session_manager.export_sessions(
            limit=max(1, int(limit)),
            events_per_session=max(0, int(events_per_session)),
        )
        sessions_payload = self._attach_runtime_narrative(sessions_payload)
        report = build_intelligence_report(sessions_payload, bandit_reward_weights=self.config.bandit.reward_weights)
        report_id = self.intel_store.record_report(report)
        if report_id is not None:
            report["report_id"] = report_id
        performance = self.bandit_performance(limit=500)
        self.alert_router.send_intel_alert(
            report=report,
            bandit_metrics={
                "exploration_ratio": float(performance.get("exploration_ratio", 0.0) or 0.0),
                "reward_avg": float(performance.get("reward_avg", report.get("totals", {}).get("bandit_reward_avg", 0.0)) or 0.0),
                "decision_count": int(performance.get("decision_count", 0) or 0),
                "reward_count": int(performance.get("reward_count", 0) or 0),
            },
        )
        return report

    def narrative_world(self, *, tenant_id: str | None = None) -> dict[str, Any]:
        tenant = self.tenant_manager.resolve_tenant(tenant_id)
        return self.rabbit_hole.narrative.world_snapshot(tenant_id=tenant.tenant_id)

    def narrative_session(self, *, session_id: str, events_limit: int = 500) -> dict[str, Any] | None:
        normalized_session_id = session_id.strip()
        if not normalized_session_id:
            return None
        session_payload = self.session_manager.export_session(
            normalized_session_id,
            events_limit=max(0, int(events_limit)),
        )
        narrative_view = self.rabbit_hole.narrative.session_view(normalized_session_id)
        if narrative_view is None and isinstance(session_payload, dict):
            narrative_raw = session_payload.get("narrative", {})
            if isinstance(narrative_raw, dict) and str(narrative_raw.get("context_id", "")).strip():
                narrative_view = dict(narrative_raw)
                narrative_view["session_id"] = normalized_session_id
                narrative_view["revealed_entity_ids"] = []
                narrative_view["revealed_entities"] = []
                narrative_view["revealed_entity_count"] = 0
                narrative_view["source_ip"] = str(session_payload.get("source_ip", ""))
                narrative_view["world_id"] = str(narrative_view.get("world_id", ""))
        if narrative_view is None:
            return None

        session_for_score: dict[str, Any] = {"session_id": normalized_session_id, "narrative": narrative_view, "events": []}
        if isinstance(session_payload, dict):
            session_for_score.update(session_payload)
            session_for_score["narrative"] = narrative_view
        coherence = score_narrative_coherence(session_for_score)
        return {
            "session_id": normalized_session_id,
            "narrative": narrative_view,
            "coherence_score": float(coherence.get("score", 0.0) or 0.0),
            "coherence_violations": coherence.get("violations", []),
            "coherence_signals": coherence.get("signals", {}),
            "session": session_payload,
        }

    def theater_live(self, *, limit: int = 100, events_per_session: int = 200) -> dict[str, Any]:
        sessions = self.session_manager.export_sessions(
            limit=max(1, int(limit)),
            events_per_session=max(0, int(events_per_session)),
        )
        sessions = self._attach_runtime_narrative(sessions)
        return self.theater.build_live_view(sessions=sessions, bandit_metrics=self.bandit_performance(limit=200))

    def theater_session(self, *, session_id: str, events_limit: int = 500) -> dict[str, Any] | None:
        normalized_session_id = session_id.strip()
        if not normalized_session_id:
            return None
        session_payload = self.session_manager.export_session(
            normalized_session_id,
            events_limit=max(0, int(events_limit)),
        )
        if session_payload is None:
            return None
        sessions = self._attach_runtime_narrative([session_payload])
        if not sessions:
            return None
        return self.theater.build_session_view(
            session=sessions[0],
            bandit_metrics=self.bandit_performance(limit=200),
        )

    def theater_recommendations(
        self,
        *,
        limit: int = 20,
        session_limit: int = 100,
        events_per_session: int = 200,
    ) -> dict[str, Any]:
        sessions = self.session_manager.export_sessions(
            limit=max(1, int(session_limit)),
            events_per_session=max(0, int(events_per_session)),
        )
        sessions = self._attach_runtime_narrative(sessions)
        return self.theater.build_recommendations(
            sessions=sessions,
            limit=max(1, int(limit)),
            bandit_metrics=self.bandit_performance(limit=200),
        )

    def theater_apply_lure(
        self,
        *,
        session_id: str,
        lure_arm: str,
        actor: str,
        context_key: str | None = None,
        duration_seconds: float = 300.0,
        recommendation_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        normalized_session_id = session_id.strip()
        normalized_lure_arm = lure_arm.strip()
        normalized_context_key = (context_key or "*").strip() or "*"
        override = self.bandit_override(
            context_key=normalized_context_key,
            arm=normalized_lure_arm,
            duration_seconds=max(1.0, float(duration_seconds)),
        )
        stored = self.intel_store.record_theater_action(
            action_type="apply_lure",
            session_id=normalized_session_id,
            actor=actor,
            recommendation_id=recommendation_id,
            payload={
                "lure_arm": normalized_lure_arm,
                "context_key": normalized_context_key,
                "duration_seconds": max(1.0, float(duration_seconds)),
                "override_applied": bool(override.get("override", {}).get("applied")),
            },
            metadata={
                "rollout_mode": self.config.theater.rollout_mode,
                "tenant_id": self._active_tenant,
                **(metadata or {}),
            },
        )
        return {
            "applied": bool(override.get("override", {}).get("applied")),
            "session_id": normalized_session_id,
            "lure_arm": normalized_lure_arm,
            "override": override,
            "recorded": stored is not None,
            "action": stored,
        }

    def theater_label(
        self,
        *,
        session_id: str,
        label: str,
        actor: str,
        recommendation_id: str | None = None,
        confidence: float | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        normalized_session_id = session_id.strip()
        normalized_label = label.strip().lower().replace(" ", "_")
        bounded_confidence = max(0.0, min(1.0, float(confidence if confidence is not None else 0.0)))
        stored = self.intel_store.record_theater_action(
            action_type="label",
            session_id=normalized_session_id,
            actor=actor,
            recommendation_id=recommendation_id,
            payload={
                "label": normalized_label,
                "confidence": round(bounded_confidence, 6),
            },
            metadata={
                "rollout_mode": self.config.theater.rollout_mode,
                "tenant_id": self._active_tenant,
                **(metadata or {}),
            },
        )
        return {
            "accepted": stored is not None,
            "session_id": normalized_session_id,
            "label": normalized_label,
            "confidence": round(bounded_confidence, 6),
            "recorded": stored is not None,
            "action": stored,
        }

    def theater_actions(
        self,
        *,
        limit: int = 200,
        session_id: str | None = None,
        action_type: str | None = None,
    ) -> dict[str, Any]:
        items = self.intel_store.recent_theater_actions(
            limit=max(1, int(limit)),
            session_id=session_id,
            action_type=action_type,
        )
        return {
            "actions": items,
            "count": len(items),
            "store": self.intel_store.snapshot(),
        }

    def campaign_graphs(
        self,
        *,
        limit: int = 100,
        status: str | None = None,
        campaign_id_prefix: str = "",
        name_prefix: str = "",
        min_nodes: int = 0,
        min_edges: int = 0,
        query: str = "",
        sort_by: str = "updated_at",
        sort_order: str = "desc",
        compact: bool = False,
    ) -> dict[str, Any]:
        safe_limit = max(1, min(2000, int(limit)))
        items = self.intel_store.recent_campaign_graphs(limit=5000, status=status)
        normalized_campaign_prefix = campaign_id_prefix.strip().lower()
        normalized_name_prefix = name_prefix.strip().lower()
        minimum_nodes = max(0, int(min_nodes))
        minimum_edges = max(0, int(min_edges))
        normalized_query = query.strip().lower()
        filtered: list[dict[str, Any]] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            campaign_id = str(item.get("campaign_id", "")).strip()
            name = str(item.get("name", "")).strip()
            normalized_campaign_id = campaign_id.lower()
            normalized_name = name.lower()
            nodes = item.get("nodes")
            edges = item.get("edges")
            node_count = len(nodes) if isinstance(nodes, list) else 0
            edge_count = len(edges) if isinstance(edges, list) else 0
            if normalized_campaign_prefix and not normalized_campaign_id.startswith(normalized_campaign_prefix):
                continue
            if normalized_name_prefix and not normalized_name.startswith(normalized_name_prefix):
                continue
            if node_count < minimum_nodes:
                continue
            if edge_count < minimum_edges:
                continue
            if normalized_query:
                metadata = item.get("metadata")
                metadata_text = str(metadata).lower() if isinstance(metadata, dict) else ""
                searchable = " ".join(
                    [
                        normalized_campaign_id,
                        normalized_name,
                        str(item.get("status", "")).strip().lower(),
                        metadata_text,
                    ]
                )
                if normalized_query not in searchable:
                    continue
            payload = dict(item)
            payload["_node_count"] = node_count
            payload["_edge_count"] = edge_count
            filtered.append(payload)

        allowed_sort_by = {
            "updated_at",
            "created_at",
            "name",
            "status",
            "campaign_id",
            "version",
            "node_count",
            "edge_count",
        }
        normalized_sort_by = sort_by.strip().lower() if sort_by else "updated_at"
        if normalized_sort_by not in allowed_sort_by:
            raise ValueError(
                "sort_by must be one of: updated_at, created_at, name, status, campaign_id, version, node_count, edge_count"
            )
        normalized_sort_order = sort_order.strip().lower() if sort_order else "desc"
        if normalized_sort_order not in {"asc", "desc"}:
            raise ValueError("sort_order must be one of: asc, desc")
        reverse = normalized_sort_order == "desc"

        if normalized_sort_by in {"node_count", "edge_count"}:
            filtered.sort(
                key=lambda item: (
                    int(item.get(f"_{normalized_sort_by}", 0) or 0),
                    str(item.get("updated_at", "")),
                    str(item.get("campaign_id", "")),
                ),
                reverse=reverse,
            )
        elif normalized_sort_by == "version":
            filtered.sort(
                key=lambda item: (
                    int(item.get("version", 0) or 0),
                    str(item.get("updated_at", "")),
                    str(item.get("campaign_id", "")),
                ),
                reverse=reverse,
            )
        else:
            filtered.sort(
                key=lambda item: (
                    str(item.get(normalized_sort_by, "")),
                    str(item.get("campaign_id", "")),
                ),
                reverse=reverse,
            )

        limited: list[dict[str, Any]] = []
        for item in filtered[:safe_limit]:
            payload = dict(item)
            node_count = int(payload.pop("_node_count", 0) or 0)
            edge_count = int(payload.pop("_edge_count", 0) or 0)
            payload["node_count"] = node_count
            payload["edge_count"] = edge_count
            if compact:
                payload.pop("nodes", None)
                payload.pop("edges", None)
            limited.append(payload)
        return {
            "campaigns": limited,
            "count": len(limited),
            "total_filtered": len(filtered),
            "filters": {
                "status": str(status or "").strip().lower() or None,
                "campaign_id_prefix": normalized_campaign_prefix or None,
                "name_prefix": normalized_name_prefix or None,
                "min_nodes": minimum_nodes,
                "min_edges": minimum_edges,
                "query": normalized_query or None,
                "compact": bool(compact),
            },
            "sort": {
                "by": normalized_sort_by,
                "order": normalized_sort_order,
            },
            "store": self.intel_store.snapshot(),
        }

    def campaign_graph(self, *, campaign_id: str) -> dict[str, Any]:
        item = self.intel_store.campaign_graph(campaign_id=campaign_id)
        return {
            "campaign": item,
            "found": item is not None,
            "store": self.intel_store.snapshot(),
        }

    def campaign_upsert(
        self,
        *,
        campaign_id: str,
        name: str,
        status: str = "draft",
        nodes: list[dict[str, Any]] | None = None,
        edges: list[dict[str, Any]] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        item = self.intel_store.upsert_campaign_graph(
            campaign_id=campaign_id,
            name=name,
            status=status,
            nodes=nodes or [],
            edges=edges or [],
            metadata={
                "tenant_id": self._active_tenant,
                **(metadata or {}),
            },
        )
        return {
            "campaign": item,
            "saved": item is not None,
            "store": self.intel_store.snapshot(),
        }

    def campaign_delete(self, *, campaign_id: str) -> dict[str, Any]:
        deleted = self.intel_store.delete_campaign_graph(campaign_id=campaign_id)
        return {
            "campaign_id": campaign_id.strip(),
            "deleted": bool(deleted),
            "store": self.intel_store.snapshot(),
        }

    def campaign_versions(
        self,
        *,
        campaign_id: str,
        limit: int = 100,
        event_type: str = "",
        min_version: int = 0,
        max_version: int = 0,
        query: str = "",
        sort_by: str = "version",
        sort_order: str = "desc",
        compact: bool = False,
    ) -> dict[str, Any]:
        safe_limit = max(1, min(2000, int(limit)))
        normalized_event_type = event_type.strip().lower()
        minimum_version = max(0, int(min_version))
        maximum_version = max(0, int(max_version))
        if minimum_version and maximum_version and minimum_version > maximum_version:
            raise ValueError("min_version must be less than or equal to max_version")
        normalized_query = query.strip().lower()
        normalized_sort_by = sort_by.strip().lower() if sort_by else "version"
        allowed_sort_by = {"version", "created_at", "event_type", "status", "node_count", "edge_count"}
        if normalized_sort_by not in allowed_sort_by:
            raise ValueError("sort_by must be one of: version, created_at, event_type, status, node_count, edge_count")
        normalized_sort_order = sort_order.strip().lower() if sort_order else "desc"
        if normalized_sort_order not in {"asc", "desc"}:
            raise ValueError("sort_order must be one of: asc, desc")

        item = self.intel_store.campaign_graph(campaign_id=campaign_id)
        if item is None:
            return {
                "campaign_id": campaign_id.strip(),
                "found": False,
                "versions": [],
                "count": 0,
                "total_filtered": 0,
                "filters": {
                    "event_type": normalized_event_type or None,
                    "min_version": minimum_version if minimum_version else None,
                    "max_version": maximum_version if maximum_version else None,
                    "query": normalized_query or None,
                    "compact": bool(compact),
                },
                "sort": {
                    "by": normalized_sort_by,
                    "order": normalized_sort_order,
                },
                "store": self.intel_store.snapshot(),
            }
        versions_raw = self.intel_store.campaign_graph_versions(
            campaign_id=campaign_id,
            limit=5000,
        )
        filtered: list[dict[str, Any]] = []
        for version in versions_raw:
            if not isinstance(version, dict):
                continue
            row_event_type = str(version.get("event_type", "")).strip().lower()
            row_version = int(version.get("version", 0) or 0)
            if normalized_event_type and row_event_type != normalized_event_type:
                continue
            if minimum_version and row_version < minimum_version:
                continue
            if maximum_version and row_version > maximum_version:
                continue
            nodes = version.get("nodes")
            edges = version.get("edges")
            node_count = len(nodes) if isinstance(nodes, list) else 0
            edge_count = len(edges) if isinstance(edges, list) else 0
            if normalized_query:
                metadata = version.get("metadata")
                metadata_text = str(metadata).lower() if isinstance(metadata, dict) else ""
                searchable = " ".join(
                    [
                        str(version.get("version", "")),
                        str(version.get("status", "")).strip().lower(),
                        row_event_type,
                        metadata_text,
                    ]
                )
                if normalized_query not in searchable:
                    continue
            payload = dict(version)
            payload["_node_count"] = node_count
            payload["_edge_count"] = edge_count
            filtered.append(payload)

        reverse = normalized_sort_order == "desc"
        if normalized_sort_by == "node_count":
            filtered.sort(
                key=lambda item: (
                    int(item.get("_node_count", 0) or 0),
                    int(item.get("version", 0) or 0),
                ),
                reverse=reverse,
            )
        elif normalized_sort_by == "edge_count":
            filtered.sort(
                key=lambda item: (
                    int(item.get("_edge_count", 0) or 0),
                    int(item.get("version", 0) or 0),
                ),
                reverse=reverse,
            )
        elif normalized_sort_by == "version":
            filtered.sort(key=lambda item: int(item.get("version", 0) or 0), reverse=reverse)
        else:
            filtered.sort(
                key=lambda item: (
                    str(item.get(normalized_sort_by, "")),
                    int(item.get("version", 0) or 0),
                ),
                reverse=reverse,
            )

        limited: list[dict[str, Any]] = []
        for version in filtered[:safe_limit]:
            payload = dict(version)
            node_count = int(payload.pop("_node_count", 0) or 0)
            edge_count = int(payload.pop("_edge_count", 0) or 0)
            payload["node_count"] = node_count
            payload["edge_count"] = edge_count
            if compact:
                payload.pop("nodes", None)
                payload.pop("edges", None)
            limited.append(payload)
        return {
            "campaign_id": campaign_id.strip(),
            "found": True,
            "campaign": item,
            "versions": limited,
            "count": len(limited),
            "total_filtered": len(filtered),
            "filters": {
                "event_type": normalized_event_type or None,
                "min_version": minimum_version if minimum_version else None,
                "max_version": maximum_version if maximum_version else None,
                "query": normalized_query or None,
                "compact": bool(compact),
            },
            "sort": {
                "by": normalized_sort_by,
                "order": normalized_sort_order,
            },
            "store": self.intel_store.snapshot(),
        }

    def campaign_set_status(
        self,
        *,
        campaign_id: str,
        status: str,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        previous = self.intel_store.campaign_graph(campaign_id=campaign_id)
        if previous is None:
            return {
                "campaign_id": campaign_id.strip(),
                "updated": False,
                "changed": False,
                "campaign": None,
                "store": self.intel_store.snapshot(),
            }
        previous_status = str(previous.get("status", "")).strip().lower()
        item = self.intel_store.set_campaign_graph_status(
            campaign_id=campaign_id,
            status=status,
            metadata={
                "tenant_id": self._active_tenant,
                **(metadata or {}),
            },
        )
        changed = bool(item is not None and previous_status != str(item.get("status", "")).strip().lower())
        return {
            "campaign_id": campaign_id.strip(),
            "updated": item is not None,
            "changed": changed,
            "campaign": item,
            "store": self.intel_store.snapshot(),
        }

    def intelligence_history(self, *, limit: int = 20) -> dict[str, Any]:
        items = self.intel_store.recent_reports(limit=max(1, int(limit)))
        return {
            "reports": items,
            "count": len(items),
            "store": self.intel_store.snapshot(),
        }

    def intelligence_session_history(self, *, limit: int = 100) -> dict[str, Any]:
        items = self.intel_store.recent_sessions(limit=max(1, int(limit)))
        return {
            "sessions": items,
            "count": len(items),
            "store": self.intel_store.snapshot(),
        }

    def intelligence_history_report(self, *, report_id: int) -> dict[str, Any]:
        item = self.intel_store.get_report(report_id=max(1, int(report_id)))
        return {
            "report": item,
            "found": item is not None,
            "store": self.intel_store.snapshot(),
        }

    def intelligence_history_report_sessions(self, *, report_id: int, limit: int = 1000) -> dict[str, Any]:
        report_id_value = max(1, int(report_id))
        items = self.intel_store.report_sessions(report_id=report_id_value, limit=max(1, int(limit)))
        return {
            "report_id": report_id_value,
            "sessions": items,
            "count": len(items),
            "store": self.intel_store.snapshot(),
        }

    def intelligence_history_report_payload(self, *, report_id: int) -> dict[str, Any] | None:
        item = self.intel_store.get_report(report_id=max(1, int(report_id)))
        if item is None:
            return None
        payload = item.get("report")
        if isinstance(payload, dict):
            return payload
        return None

    def bandit_select(self, *, context_key: str, candidates: list[str]) -> dict[str, Any]:
        decision = self.lure_bandit.select_arm(context_key=context_key, candidates=candidates)
        stored = self.intel_store.record_bandit_decision(
            context_key=decision.context_key,
            selected_arm=decision.selected_arm,
            algorithm=decision.algorithm,
            candidates=list(candidates),
            exploration_applied=decision.exploration_applied,
            blocked_arms=decision.blocked_arms,
            arm_scores=decision.arm_scores,
            metadata={
                "override_applied": decision.override_applied,
                "override_expires_at": decision.override_expires_at,
                "tenant_id": self._active_tenant,
            },
        )
        payload: dict[str, Any] = {
            "context_key": decision.context_key,
            "selected_arm": decision.selected_arm,
            "algorithm": decision.algorithm,
            "exploration_floor": decision.exploration_floor,
            "exploration_applied": decision.exploration_applied,
            "override_applied": decision.override_applied,
            "override_expires_at": decision.override_expires_at,
            "eligible_arms": decision.eligible_arms,
            "blocked_arms": decision.blocked_arms,
            "arm_scores": decision.arm_scores,
            "total_selections": decision.total_selections,
            "recorded": stored is not None,
        }
        if stored is not None:
            payload["decision_id"] = stored.get("decision_id")
        return payload

    def bandit_arms(self) -> dict[str, Any]:
        snapshot = self.lure_bandit.snapshot()
        return {
            "bandit": snapshot,
            "store": self.intel_store.snapshot(),
        }

    def bandit_performance(self, *, limit: int = 200) -> dict[str, Any]:
        decision_rows = self.intel_store.recent_bandit_decisions(limit=max(1, int(limit)))
        reward_rows = self.intel_store.recent_bandit_rewards(limit=max(1, int(limit)))
        decisions_by_id = {int(item.get("decision_id", 0)): item for item in decision_rows}

        arm_metrics: dict[str, dict[str, Any]] = {}
        for decision in decision_rows:
            arm = str(decision.get("selected_arm", "")).strip()
            if not arm:
                continue
            item = arm_metrics.setdefault(
                arm,
                {
                    "arm": arm,
                    "selections": 0,
                    "exploration_selections": 0,
                    "reward_updates": 0,
                    "reward_sum": 0.0,
                    "reward_avg": 0.0,
                    "avg_delay_seconds": 0.0,
                    "last_selected_at": "",
                    "last_reward_at": "",
                },
            )
            item["selections"] = int(item["selections"]) + 1
            if bool(decision.get("exploration_applied")):
                item["exploration_selections"] = int(item["exploration_selections"]) + 1
            if not item["last_selected_at"]:
                item["last_selected_at"] = str(decision.get("created_at", ""))

        for reward in reward_rows:
            decision_id = int(reward.get("decision_id", 0) or 0)
            decision = decisions_by_id.get(decision_id, {})
            arm = str(decision.get("selected_arm", "")).strip()
            if not arm:
                continue
            item = arm_metrics.setdefault(
                arm,
                {
                    "arm": arm,
                    "selections": 0,
                    "exploration_selections": 0,
                    "reward_updates": 0,
                    "reward_sum": 0.0,
                    "reward_avg": 0.0,
                    "avg_delay_seconds": 0.0,
                    "last_selected_at": "",
                    "last_reward_at": "",
                },
            )
            reward_value = float(reward.get("reward", 0.0) or 0.0)
            item["reward_updates"] = int(item["reward_updates"]) + 1
            item["reward_sum"] = float(item["reward_sum"]) + reward_value
            reward_updates = max(1, int(item["reward_updates"]))
            item["reward_avg"] = float(item["reward_sum"]) / float(reward_updates)
            delay_seconds = float(reward.get("delay_seconds", 0.0) or 0.0)
            item["avg_delay_seconds"] = (
                float(item["avg_delay_seconds"]) * float(reward_updates - 1) + delay_seconds
            ) / float(reward_updates)
            if not item["last_reward_at"]:
                item["last_reward_at"] = str(reward.get("created_at", ""))

        ordered_arms = sorted(
            arm_metrics.values(),
            key=lambda item: (-float(item.get("reward_avg", 0.0)), -int(item.get("selections", 0)), str(item.get("arm", ""))),
        )
        selected_decision_count = sum(
            1 for item in decision_rows if str(item.get("selected_arm", "")).strip()
        )
        exploration_selection_count = sum(
            1
            for item in decision_rows
            if str(item.get("selected_arm", "")).strip() and bool(item.get("exploration_applied"))
        )
        exploration_ratio = (
            float(exploration_selection_count) / float(selected_decision_count)
            if selected_decision_count > 0
            else 0.0
        )
        reward_series = [float(item.get("reward", 0.0) or 0.0) for item in reversed(reward_rows)]
        reward_avg = round(sum(reward_series) / len(reward_series), 6) if reward_series else 0.0
        if len(reward_series) >= 2:
            midpoint = max(1, len(reward_series) // 2)
            baseline_slice = reward_series[:midpoint]
            recent_slice = reward_series[midpoint:] if midpoint < len(reward_series) else reward_series[-1:]
            baseline_avg = sum(baseline_slice) / len(baseline_slice) if baseline_slice else reward_avg
            recent_avg = sum(recent_slice) / len(recent_slice) if recent_slice else reward_avg
            trend_delta = recent_avg - baseline_avg
            direction = "flat"
            if trend_delta > 0.01:
                direction = "up"
            elif trend_delta < -0.01:
                direction = "down"
            trend_pct = (trend_delta / baseline_avg * 100.0) if baseline_avg > 0 else 0.0
            reward_trend = {
                "baseline_avg": round(baseline_avg, 6),
                "recent_avg": round(recent_avg, 6),
                "delta": round(trend_delta, 6),
                "percent_change": round(trend_pct, 3),
                "direction": direction,
            }
        else:
            reward_trend = {
                "baseline_avg": reward_avg,
                "recent_avg": reward_avg,
                "delta": 0.0,
                "percent_change": 0.0,
                "direction": "flat",
            }
        return {
            "arms": ordered_arms,
            "count": len(ordered_arms),
            "decision_count": len(decision_rows),
            "reward_count": len(reward_rows),
            "selected_decision_count": selected_decision_count,
            "exploration_selection_count": exploration_selection_count,
            "exploration_ratio": round(exploration_ratio, 6),
            "reward_avg": reward_avg,
            "reward_trend": reward_trend,
            "recent_decisions": decision_rows[:20],
            "recent_rewards": reward_rows[:20],
            "store": self.intel_store.snapshot(),
        }

    def bandit_observability(self, *, limit: int = 30) -> dict[str, Any]:
        performance = self.bandit_performance(limit=max(50, int(limit) * 5))
        observability = self.alert_router.bandit_observability(limit=max(1, int(limit)))
        observability["computed"] = {
            "exploration_ratio": float(performance.get("exploration_ratio", 0.0) or 0.0),
            "reward_avg": float(performance.get("reward_avg", 0.0) or 0.0),
            "reward_trend": performance.get("reward_trend", {}),
            "decision_count": int(performance.get("decision_count", 0) or 0),
            "reward_count": int(performance.get("reward_count", 0) or 0),
        }
        observability["store"] = self.intel_store.snapshot()
        return observability

    def bandit_override(self, *, context_key: str, arm: str, duration_seconds: float) -> dict[str, Any]:
        payload = self.lure_bandit.set_override(context_key=context_key, arm=arm, duration_seconds=duration_seconds)
        stored = None
        if bool(payload.get("applied")):
            stored = self.intel_store.record_bandit_decision(
                context_key=f"override:{str(payload.get('context_key', ''))}",
                selected_arm=str(payload.get("arm", "")),
                algorithm=self.config.bandit.algorithm,
                candidates=[str(payload.get("arm", ""))],
                exploration_applied=False,
                metadata={
                    "action": "manual_override",
                    "duration_seconds": float(payload.get("duration_seconds", 0.0) or 0.0),
                    "expires_at": str(payload.get("expires_at", "")),
                    "tenant_id": self._active_tenant,
                },
            )
        return {
            "override": payload,
            "recorded": stored is not None,
            "decision_id": stored.get("decision_id") if isinstance(stored, dict) else None,
            "bandit": self.lure_bandit.snapshot(),
        }

    def bandit_reset(self, *, reason: str = "manual") -> dict[str, Any]:
        payload = self.lure_bandit.reset(reason=reason)
        stored = self.intel_store.record_bandit_decision(
            context_key="bandit:reset",
            selected_arm=None,
            algorithm=self.config.bandit.algorithm,
            candidates=[],
            exploration_applied=False,
            metadata={
                "action": "manual_reset",
                "reason": str(payload.get("reason", "manual")),
                "cleared_arms": int(payload.get("cleared_arms", 0) or 0),
                "cleared_overrides": int(payload.get("cleared_overrides", 0) or 0),
                "previous_total_selections": int(payload.get("previous_total_selections", 0) or 0),
                "tenant_id": self._active_tenant,
            },
        )
        return {
            "reset": payload,
            "recorded": stored is not None,
            "decision_id": stored.get("decision_id") if isinstance(stored, dict) else None,
            "bandit": self.lure_bandit.snapshot(),
        }

    def generate_canary_token(
        self,
        *,
        namespace: str,
        token_type: str,
        metadata: dict[str, object] | None = None,
    ) -> dict[str, Any]:
        token = build_canary_token(namespace=namespace, token_type=token_type)
        stored = self.intel_store.record_canary_token(
            token_id=str(token.get("token_id", "")),
            token=str(token.get("token", "")),
            token_type=str(token.get("token_type", "")),
            namespace=str(token.get("namespace", "")),
            metadata=metadata,
        )
        payload: dict[str, Any] = dict(token)
        payload["stored"] = stored is not None
        if stored is not None:
            payload["record"] = stored
        return payload

    def canary_tokens(
        self,
        *,
        limit: int = 100,
        namespace: str | None = None,
        token_type: str | None = None,
    ) -> dict[str, Any]:
        items = self.intel_store.recent_canary_tokens(
            limit=max(1, int(limit)),
            namespace=namespace,
            token_type=token_type,
        )
        return {
            "tokens": items,
            "count": len(items),
            "store": self.intel_store.snapshot(),
        }

    def canary_token(self, *, token_id: str) -> dict[str, Any]:
        item = self.intel_store.canary_token(token_id=token_id)
        return {
            "token": item,
            "found": item is not None,
            "store": self.intel_store.snapshot(),
        }

    def canary_hits(self, *, limit: int = 200, token_id: str | None = None) -> dict[str, Any]:
        items = self.intel_store.recent_canary_hits(limit=max(1, int(limit)), token_id=token_id)
        return {
            "hits": items,
            "count": len(items),
            "store": self.intel_store.snapshot(),
        }

    def rotate_threat_intel(self) -> dict[str, Any]:
        if not self._bootstrapped:
            snapshot = self.threat_rotator.snapshot()
            snapshot["rotation_interval_seconds"] = self.config.threat_intel.rotation_interval_seconds
            snapshot["scheduler_running"] = bool(
                self._rotation_scheduler_thread and self._rotation_scheduler_thread.is_alive()
            )
            snapshot["rotation_trigger"] = "manual-skipped-unbootstrapped"
            return snapshot
        if not self.config.threat_intel.enabled:
            snapshot = self.threat_rotator.snapshot()
            snapshot["rotation_interval_seconds"] = self.config.threat_intel.rotation_interval_seconds
            snapshot["scheduler_running"] = bool(
                self._rotation_scheduler_thread and self._rotation_scheduler_thread.is_alive()
            )
            snapshot["rotation_trigger"] = "manual-skipped-disabled"
            return snapshot
        self._rotate_services_from_threat_feed()
        snapshot = self.threat_rotator.snapshot()
        snapshot["rotation_interval_seconds"] = self.config.threat_intel.rotation_interval_seconds
        snapshot["scheduler_running"] = bool(
            self._rotation_scheduler_thread and self._rotation_scheduler_thread.is_alive()
        )
        snapshot["rotation_trigger"] = "manual"
        return snapshot

    def threat_intel_preview(self) -> dict[str, Any]:
        preview = self.threat_rotator.preview()
        preview["rotation_interval_seconds"] = self.config.threat_intel.rotation_interval_seconds
        preview["scheduler_running"] = bool(
            self._rotation_scheduler_thread and self._rotation_scheduler_thread.is_alive()
        )
        return preview

    def alert_test(
        self,
        *,
        severity: str,
        title: str,
        summary: str,
        service: str = "ops",
        action: str = "alert_test",
        metadata: dict[str, object] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"source": "manual_alert_test"}
        if metadata:
            payload.update({str(key): value for key, value in metadata.items() if str(key).strip()})
        event = self.alert_router.send_alert(
            severity=severity,
            title=title,
            summary=summary,
            service=service,
            action=action,
            payload=payload,
        )
        snapshot = self.alert_router.snapshot()
        recent = snapshot.get("recent", [])
        if not isinstance(recent, list):
            recent = []
        return {
            "queued": event is not None,
            "alerts_enabled": self.config.alerts.enabled,
            "severity": severity,
            "title": title,
            "summary": summary,
            "service": service,
            "action": action,
            "sent_to": list(event.sent_to) if event is not None else [],
            "recent_count": len(recent),
        }

    def alert_routes(
        self,
        *,
        severity: str = "medium",
        service: str = "ops",
        action: str = "alert_test",
        title: str = "manual_alert_test",
        apply_throttle: bool = False,
    ) -> dict[str, Any]:
        return self.alert_router.route_preview(
            severity=severity,
            service=service,
            action=action,
            title=title,
            apply_throttle=apply_throttle,
        )

    def session_replay(self, *, session_id: str, events_limit: int = 500) -> dict[str, Any]:
        replay = self.session_manager.export_session(session_id, events_limit=max(0, int(events_limit)))
        if replay is None:
            return {
                "found": False,
                "session_id": session_id,
                "session": None,
            }
        events = replay.get("events", [])
        if not isinstance(events, list):
            events = []
        session_for_score = dict(replay)
        runtime_narrative = self.rabbit_hole.narrative.session_snapshot(session_id)
        if isinstance(runtime_narrative, dict):
            session_for_score["narrative"] = runtime_narrative
            replay["narrative"] = runtime_narrative
        coherence = score_narrative_coherence(session_for_score)
        return {
            "found": True,
            "session_id": session_id,
            "session": replay,
            "classification": classify_session(replay),
            "engagement_score": score_session(replay),
            "coherence_score": float(coherence.get("score", 0.0) or 0.0),
            "coherence_violations": coherence.get("violations", []),
            "techniques": summarize_techniques(events),
            "canaries": summarize_canary_hits(events),
        }

    def session_replay_compare(
        self,
        *,
        left_session_id: str,
        right_session_id: str,
        events_limit: int = 500,
    ) -> dict[str, Any]:
        normalized_left = left_session_id.strip()
        normalized_right = right_session_id.strip()
        if not normalized_left or not normalized_right:
            return {
                "found": False,
                "left_session_id": normalized_left,
                "right_session_id": normalized_right,
                "missing_sessions": [item for item in (normalized_left, normalized_right) if not item],
                "left": None,
                "right": None,
            }

        left = self.session_replay(session_id=normalized_left, events_limit=events_limit)
        right = self.session_replay(session_id=normalized_right, events_limit=events_limit)

        missing_sessions: list[str] = []
        if not bool(left.get("found")):
            missing_sessions.append(normalized_left)
        if not bool(right.get("found")):
            missing_sessions.append(normalized_right)
        if missing_sessions:
            return {
                "found": False,
                "left_session_id": normalized_left,
                "right_session_id": normalized_right,
                "missing_sessions": missing_sessions,
                "left": left if bool(left.get("found")) else None,
                "right": right if bool(right.get("found")) else None,
            }

        left_session = left.get("session", {})
        right_session = right.get("session", {})
        left_events = self._normalized_replay_events(left_session)
        right_events = self._normalized_replay_events(right_session)

        left_services = self._normalized_service_set(left_events)
        right_services = self._normalized_service_set(right_events)
        shared_services = sorted(left_services.intersection(right_services))
        left_only_services = sorted(left_services.difference(right_services))
        right_only_services = sorted(right_services.difference(left_services))

        left_techniques = self._normalized_technique_set(left.get("techniques", []))
        right_techniques = self._normalized_technique_set(right.get("techniques", []))
        shared_techniques = sorted(left_techniques.intersection(right_techniques))
        left_only_techniques = sorted(left_techniques.difference(right_techniques))
        right_only_techniques = sorted(right_techniques.difference(left_techniques))

        left_engagement = self._score_value(left, key="engagement_score")
        right_engagement = self._score_value(right, key="engagement_score")
        left_coherence = float(left.get("coherence_score", 0.0) or 0.0)
        right_coherence = float(right.get("coherence_score", 0.0) or 0.0)
        left_event_count = max(0, int(left_session.get("event_count", len(left_events)) or 0))
        right_event_count = max(0, int(right_session.get("event_count", len(right_events)) or 0))
        left_canary_hits = self._canary_hits(left)
        right_canary_hits = self._canary_hits(right)

        technique_union = left_techniques.union(right_techniques)
        service_union = left_services.union(right_services)
        technique_overlap_ratio = (
            float(len(shared_techniques)) / float(len(technique_union)) if technique_union else 1.0
        )
        service_overlap_ratio = float(len(shared_services)) / float(len(service_union)) if service_union else 1.0
        engagement_gap_ratio = min(1.0, abs(right_engagement - left_engagement) / 100.0)
        similarity_score = (
            0.45 * technique_overlap_ratio + 0.35 * service_overlap_ratio + 0.2 * (1.0 - engagement_gap_ratio)
        )

        left_label = self._classification_label(left)
        right_label = self._classification_label(right)
        classification_changed = left_label != right_label
        risk_shift = self._comparison_risk_shift(
            left_engagement=left_engagement,
            right_engagement=right_engagement,
            left_canary_hits=left_canary_hits,
            right_canary_hits=right_canary_hits,
            right_only_techniques=right_only_techniques,
            left_only_techniques=left_only_techniques,
        )
        summary = {
            "similarity_band": self._similarity_band(similarity_score),
            "risk_shift": risk_shift,
            "classification_changed": classification_changed,
            "primary_change": self._comparison_primary_change(
                classification_changed=classification_changed,
                right_only_techniques=right_only_techniques,
                right_only_services=right_only_services,
                event_delta=right_event_count - left_event_count,
            ),
            "new_techniques": right_only_techniques[:5],
            "new_services": right_only_services[:5],
        }
        operator_actions = self._comparison_operator_actions(
            similarity_score=similarity_score,
            risk_shift=risk_shift,
            classification_changed=classification_changed,
            right_only_techniques=right_only_techniques,
            right_only_services=right_only_services,
            canary_delta=right_canary_hits - left_canary_hits,
        )
        return {
            "found": True,
            "left_session_id": normalized_left,
            "right_session_id": normalized_right,
            "left": left,
            "right": right,
            "comparison": {
                "shared_services": shared_services,
                "left_only_services": left_only_services,
                "right_only_services": right_only_services,
                "shared_techniques": shared_techniques,
                "left_only_techniques": left_only_techniques,
                "right_only_techniques": right_only_techniques,
                "classification": {
                    "left": left_label,
                    "right": right_label,
                    "changed": classification_changed,
                },
                "score_delta": {
                    "engagement": round(right_engagement - left_engagement, 3),
                    "coherence": round(right_coherence - left_coherence, 3),
                    "event_count": right_event_count - left_event_count,
                    "canary_hits": right_canary_hits - left_canary_hits,
                },
                "similarity": {
                    "score": round(similarity_score, 3),
                    "technique_overlap_ratio": round(technique_overlap_ratio, 3),
                    "service_overlap_ratio": round(service_overlap_ratio, 3),
                },
                "summary": summary,
                "operator_actions": operator_actions,
            },
        }

    @staticmethod
    def _normalized_replay_events(session_payload: Any) -> list[dict[str, Any]]:
        if not isinstance(session_payload, dict):
            return []
        events = session_payload.get("events", [])
        if not isinstance(events, list):
            return []
        return [item for item in events if isinstance(item, dict)]

    @staticmethod
    def _normalized_service_set(events: list[dict[str, Any]]) -> set[str]:
        services: set[str] = set()
        for event in events:
            normalized = str(event.get("service", "")).strip().lower()
            if normalized:
                services.add(normalized)
        return services

    @staticmethod
    def _normalized_technique_set(techniques_raw: Any) -> set[str]:
        if not isinstance(techniques_raw, list):
            return set()
        techniques: set[str] = set()
        for item in techniques_raw:
            if not isinstance(item, dict):
                continue
            technique_id = str(item.get("technique_id", "")).strip().upper()
            if technique_id.startswith("T"):
                techniques.add(technique_id)
        return techniques

    @staticmethod
    def _score_value(payload: dict[str, Any], *, key: str) -> float:
        raw = payload.get(key, {})
        if not isinstance(raw, dict):
            return 0.0
        return float(raw.get("score", 0.0) or 0.0)

    @staticmethod
    def _classification_label(payload: dict[str, Any]) -> str:
        raw = payload.get("classification", {})
        if not isinstance(raw, dict):
            return "Unknown"
        return str(raw.get("label", "Unknown")).strip() or "Unknown"

    @staticmethod
    def _canary_hits(payload: dict[str, Any]) -> int:
        raw = payload.get("canaries", {})
        if not isinstance(raw, dict):
            return 0
        return max(0, int(raw.get("total_hits", 0) or 0))

    @staticmethod
    def _similarity_band(similarity_score: float) -> str:
        if similarity_score >= 0.8:
            return "high"
        if similarity_score >= 0.5:
            return "moderate"
        return "low"

    @staticmethod
    def _comparison_risk_shift(
        *,
        left_engagement: float,
        right_engagement: float,
        left_canary_hits: int,
        right_canary_hits: int,
        right_only_techniques: list[str],
        left_only_techniques: list[str],
    ) -> str:
        if (
            (right_engagement - left_engagement) >= 8.0
            or right_canary_hits > left_canary_hits
            or bool(right_only_techniques)
        ):
            return "higher"
        if (
            (left_engagement - right_engagement) >= 8.0
            and right_canary_hits <= left_canary_hits
            and not right_only_techniques
            and bool(left_only_techniques)
        ):
            return "lower"
        return "stable"

    @staticmethod
    def _comparison_primary_change(
        *,
        classification_changed: bool,
        right_only_techniques: list[str],
        right_only_services: list[str],
        event_delta: int,
    ) -> str:
        if classification_changed:
            return "classification_shift"
        if right_only_techniques:
            return "new_techniques"
        if right_only_services:
            return "service_expansion"
        if event_delta > 0:
            return "activity_increase"
        if event_delta < 0:
            return "activity_decrease"
        return "minimal_change"

    @staticmethod
    def _comparison_operator_actions(
        *,
        similarity_score: float,
        risk_shift: str,
        classification_changed: bool,
        right_only_techniques: list[str],
        right_only_services: list[str],
        canary_delta: int,
    ) -> list[str]:
        actions: list[str] = []
        if risk_shift == "higher":
            actions.append("Escalate this session pair for analyst triage due to increased risk signals.")
        if classification_changed:
            actions.append("Revalidate attacker profile labeling because classification changed between sessions.")
        if right_only_techniques:
            preview = ", ".join(right_only_techniques[:3])
            actions.append(f"Prioritize detections and lures for newly observed ATT&CK techniques ({preview}).")
        if right_only_services:
            preview = ", ".join(right_only_services[:3])
            actions.append(f"Expand protocol-focused monitoring for newly touched services ({preview}).")
        if canary_delta > 0:
            actions.append("Investigate canary token drift because the right session shows additional canary hits.")
        if similarity_score < 0.4:
            actions.append("Treat sessions as potentially distinct toolchains or operators due to low similarity.")
        if not actions:
            actions.append("Maintain current deception profile; no major divergence detected across the compared sessions.")
        return actions

    def _attach_runtime_narrative(self, sessions: list[dict[str, Any]]) -> list[dict[str, Any]]:
        payload: list[dict[str, Any]] = []
        for session in sessions:
            if not isinstance(session, dict):
                continue
            item = dict(session)
            session_id = str(item.get("session_id", "")).strip()
            if session_id:
                narrative = self.rabbit_hole.narrative.session_snapshot(session_id)
                if isinstance(narrative, dict):
                    item["narrative"] = narrative
            payload.append(item)
        return payload

    def ingest_canary_hit(
        self,
        *,
        token: str,
        source_ip: str,
        service: str = "canary",
        session_id: str | None = None,
        tenant_id: str | None = None,
        metadata: dict[str, object] | None = None,
    ) -> dict[str, Any]:
        token = token.strip()
        source_ip = source_ip.strip()
        if not token:
            raise ValueError("token must be non-empty")
        if not source_ip:
            raise ValueError("source_ip must be non-empty")
        if tenant_id is not None:
            tenant = self.tenant_manager.resolve_tenant(tenant_id)
            self._active_tenant = tenant.tenant_id
        self._ensure_alert_subscription()
        if not session_id:
            digest = hashlib.sha1(f"{source_ip}:{token}".encode("utf-8"), usedforsecurity=False).hexdigest()[:16]
            session_id = f"canary-{digest}"
        payload: dict[str, object] = {
            "source_ip": source_ip,
            "indicator_type": "canary_token",
            "token": token,
            "tenant_id": self._active_tenant,
        }
        if metadata:
            for key, value in metadata.items():
                if str(key).strip():
                    payload[str(key)] = value
        self.session_manager.get_or_create(session_id=session_id, source_ip=source_ip)
        self.session_manager.record_event(
            session_id=session_id,
            service=service,
            action="canary_hit",
            payload=payload,
        )
        self.event_logger.emit(
            message="canary token hit ingested",
            service=service,
            action="canary_hit",
            session_id=session_id,
            source_ip=source_ip,
            event_type="alert",
            outcome="success",
            payload=payload,
            level="WARNING",
        )
        token_id = token_identifier(token=token)
        persisted_hit = self.intel_store.record_canary_hit(
            token=token,
            source_ip=source_ip,
            service=service,
            session_id=session_id,
            tenant_id=self._active_tenant,
            metadata=metadata,
        )
        return {
            "session_id": session_id,
            "source_ip": source_ip,
            "token": token,
            "token_id": token_id,
            "tenant": self._active_tenant,
            "persisted": persisted_hit is not None,
            "hit": persisted_hit,
        }

    def _publish_event(self, payload: dict[str, object]) -> None:
        session_id = str(payload.get("session_id", "")).strip()
        if session_id:
            tags = self.session_manager.session_tags(session_id)
            if tags:
                payload["session_tags"] = tags
                nested = payload.get("payload")
                if isinstance(nested, dict):
                    if "session_tags" not in nested:
                        nested_payload = dict(nested)
                        nested_payload["session_tags"] = tags
                        payload["payload"] = nested_payload
                else:
                    payload["payload"] = {"session_tags": tags}
        source_ip = str(payload.get("source_ip", ""))
        if self._is_red_team_source(source_ip):
            nested = payload.get("payload")
            if isinstance(nested, dict):
                nested[self.config.red_team.label] = True
                payload["payload"] = nested
            payload[self.config.red_team.label] = True
        service = str(payload.get("service", "unknown"))
        action = str(payload.get("action", "unknown"))
        self.event_bus.publish("events", payload)
        self.event_bus.publish(f"service.{service}", payload)
        self.event_bus.publish(f"action.{action}", payload)

    def _is_red_team_source(self, source_ip: str) -> bool:
        if not self.config.red_team.enabled:
            return False
        if not source_ip:
            return False
        try:
            ip_obj = ipaddress.ip_address(source_ip)
        except ValueError:
            return False
        return any(ip_obj in network for network in self._red_team_networks)

    def _build_loaded_service(self, service_config: ServiceConfig) -> LoadedService:
        cfg = self._clone_service(service_config)
        emulator = self.plugin_registry.instantiate(cfg)
        emulator.set_runtime(
            ServiceRuntime(
                session_manager=self.session_manager,
                event_logger=self.event_logger,
                event_bus=self.event_bus,
                rabbit_hole=self.rabbit_hole,
                bandit_select=self.bandit_select,
                alert_router=self.alert_router,
                tenant_id=self._active_tenant,
                red_team=self.config.red_team,
            )
        )
        return LoadedService(config=cfg, emulator=emulator)

    def _ensure_alert_subscription(self) -> None:
        if self._alert_subscription_initialized:
            return
        self.event_bus.subscribe("events", self.alert_router.handle_event)
        self._alert_subscription_initialized = True

    def _start_rotation_scheduler(self) -> None:
        if not self.config.threat_intel.enabled:
            return
        interval_seconds = max(1, int(self.config.threat_intel.rotation_interval_seconds))
        if self._rotation_scheduler_thread and self._rotation_scheduler_thread.is_alive():
            return
        self._rotation_scheduler_stop.clear()
        self._rotation_scheduler_thread = threading.Thread(
            target=self._rotation_scheduler_loop,
            kwargs={"interval_seconds": interval_seconds},
            name="threat-feed-rotation",
            daemon=True,
        )
        self._rotation_scheduler_thread.start()
        self.logger.info(
            "threat-intel rotation scheduler started",
            extra={"service": "intel_rotation", "payload": {"interval_seconds": interval_seconds}},
        )

    def _stop_rotation_scheduler(self) -> None:
        self._rotation_scheduler_stop.set()
        if self._rotation_scheduler_thread and self._rotation_scheduler_thread.is_alive():
            self._rotation_scheduler_thread.join(timeout=2.0)
        self._rotation_scheduler_thread = None

    def _rotation_scheduler_loop(self, *, interval_seconds: int) -> None:
        while not self._rotation_scheduler_stop.wait(interval_seconds):
            try:
                self._rotate_services_from_threat_feed()
            except Exception:
                self.logger.exception("periodic threat-intel rotation failed", extra={"service": "intel_rotation"})

    def _rotate_services_from_threat_feed(self) -> None:
        if not self._rotation_source_services:
            return
        rotated_services = self.threat_rotator.apply(self._clone_services(self._rotation_source_services))
        self._reconcile_rotated_services(rotated_services)

    def _reconcile_rotated_services(self, rotated_services: list[ServiceConfig]) -> None:
        enabled_configs = {
            service.name: self._clone_service(service)
            for service in rotated_services
            if service.enabled
        }
        with self._services_lock:
            loaded_by_name = {
                loaded.config.name: loaded
                for loaded in self.loaded_services
                if loaded.source == "baseline"
            }

        # Runtime-tunable services are hot-updated in place.
        for name, updated_config in enabled_configs.items():
            loaded = loaded_by_name.get(name)
            if loaded is None:
                continue
            loaded.config = updated_config
            try:
                loaded.emulator.apply_runtime_config(updated_config)
            except Exception:
                self.logger.exception(
                    "failed to apply runtime service config update",
                    extra={"service": "intel_rotation", "payload": {"service_name": name}},
                )

        to_stop = [loaded for name, loaded in loaded_by_name.items() if name not in enabled_configs]
        stop_results: list[Any] = []
        if to_stop:
            stop_results = self._run_coroutines_sync([loaded.emulator.stop() for loaded in to_stop])
        for loaded, result in zip(to_stop, stop_results, strict=False):
            if isinstance(result, Exception):
                self.logger.error(
                    "failed to stop service during threat-intel rotation",
                    extra={
                        "service": "intel_rotation",
                        "payload": {"service_name": loaded.config.name, "error": str(result)},
                    },
                )
            with self._services_lock:
                self.loaded_services = [item for item in self.loaded_services if item is not loaded]

        to_start = [config for name, config in enabled_configs.items() if name not in loaded_by_name]
        loaded_to_start = [self._build_loaded_service(service_config) for service_config in to_start]
        start_results: list[Any] = []
        if loaded_to_start:
            start_results = self._run_coroutines_sync(
                [loaded.emulator.start(loaded.config) for loaded in loaded_to_start]
            )
        for loaded, result in zip(loaded_to_start, start_results, strict=False):
            if isinstance(result, Exception):
                self.logger.error(
                    "failed to start service during threat-intel rotation",
                    extra={
                        "service": "intel_rotation",
                        "payload": {"service_name": loaded.config.name, "error": str(result)},
                    },
                )
                continue
            with self._services_lock:
                self.loaded_services.append(loaded)

    @staticmethod
    def _utc_now() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    def active_service_bindings(self) -> list[dict[str, Any]]:
        with self._services_lock:
            loaded_snapshot = list(self.loaded_services)
        bindings: list[dict[str, Any]] = []
        for loaded in loaded_snapshot:
            ports = loaded.config.ports or loaded.emulator.default_ports
            for port in ports:
                bindings.append(
                    {
                        "service": loaded.config.name,
                        "module": loaded.config.module,
                        "listen_host": loaded.config.listen_host,
                        "port": int(port),
                        "source": loaded.source,
                        "deployment_id": loaded.deployment_id,
                        "running": bool(loaded.emulator.running),
                    }
                )
        return bindings

    def active_services_detail(self) -> list[dict[str, Any]]:
        with self._services_lock:
            loaded_snapshot = list(self.loaded_services)
            runtime_snapshot = dict(self._runtime_deployments)
        details: list[dict[str, Any]] = []
        for loaded in loaded_snapshot:
            runtime_deployment = (
                runtime_snapshot.get(loaded.deployment_id)
                if loaded.deployment_id
                else None
            )
            details.append(
                {
                    "name": loaded.config.name,
                    "module": loaded.config.module,
                    "enabled": loaded.config.enabled,
                    "listen_host": loaded.config.listen_host,
                    "ports": list(loaded.config.ports or loaded.emulator.default_ports),
                    "config": dict(loaded.config.config),
                    "running": bool(loaded.emulator.running),
                    "source": loaded.source,
                    "deployment_id": loaded.deployment_id,
                    "deployment_manifest_source": (
                        runtime_deployment.manifest_source if runtime_deployment is not None else None
                    ),
                    "deployment_activated_at": (
                        runtime_deployment.activated_at if runtime_deployment is not None else None
                    ),
                }
            )
        return details

    def validate_runtime_services(
        self,
        services: list[ServiceConfig],
        *,
        ignore_deployment_id: str | None = None,
    ) -> None:
        if not services:
            raise ValueError("runtime deployment requires at least one service")

        seen_names: set[str] = set()
        requested_bindings: set[tuple[str, int]] = set()
        for service in services:
            name = service.name.strip()
            if not name:
                raise ValueError("runtime service name cannot be empty")
            if name in seen_names:
                raise ValueError(f"duplicate runtime service name '{name}' in deployment manifest")
            seen_names.add(name)
            ports = service.ports
            if not ports:
                raise ValueError(f"runtime service '{name}' must declare at least one listen port")
            host = service.listen_host.strip() or "0.0.0.0"
            for port in ports:
                port_value = int(port)
                if port_value < 1 or port_value > 65535:
                    raise ValueError(f"runtime service '{name}' has invalid port '{port_value}'")
                key = (host, port_value)
                if key in requested_bindings:
                    raise ValueError(
                        f"runtime deployment manifest contains duplicate binding {host}:{port_value}"
                    )
                requested_bindings.add(key)

        with self._services_lock:
            existing_bindings = [
                (loaded.config.listen_host.strip() or "0.0.0.0", int(port), loaded.config.name, loaded.deployment_id)
                for loaded in self.loaded_services
                for port in (loaded.config.ports or loaded.emulator.default_ports)
            ]
        for host, port, name, deployment_id in existing_bindings:
            if ignore_deployment_id and deployment_id == ignore_deployment_id:
                continue
            if (host, port) in requested_bindings:
                raise ValueError(
                    f"runtime deployment binding conflict: {host}:{port} is already in use by service '{name}'"
                )

    def activate_runtime_deployment(
        self,
        *,
        deployment_id: str,
        services: list[ServiceConfig],
        manifest_source: str = "api",
    ) -> dict[str, Any]:
        normalized_id = deployment_id.strip()
        if not normalized_id:
            raise ValueError("deployment_id cannot be empty")
        if not self._bootstrapped:
            self.bootstrap()
        with self._services_lock:
            if normalized_id in self._runtime_deployments:
                raise ValueError(f"runtime deployment '{normalized_id}' is already active")
        cloned_services = self._clone_services(services)
        self.validate_runtime_services(cloned_services)
        loaded_to_start: list[LoadedService] = []
        for service_config in cloned_services:
            loaded = self._build_loaded_service(service_config)
            loaded.source = "runtime"
            loaded.deployment_id = normalized_id
            loaded_to_start.append(loaded)

        start_results = self._run_coroutines_sync(
            [loaded.emulator.start(loaded.config) for loaded in loaded_to_start]
        )
        failed: list[tuple[LoadedService, Exception]] = []
        started: list[LoadedService] = []
        for loaded, result in zip(loaded_to_start, start_results, strict=False):
            if isinstance(result, Exception):
                failed.append((loaded, result))
            else:
                started.append(loaded)

        if failed:
            self._run_coroutines_sync([loaded.emulator.stop() for loaded in started])
            detail = "; ".join(
                f"{loaded.config.name}: {type(exc).__name__}: {exc}" for loaded, exc in failed
            )
            raise RuntimeError(f"failed to activate runtime deployment '{normalized_id}': {detail}")

        deployment = RuntimeDeployment(
            deployment_id=normalized_id,
            services=loaded_to_start,
            manifest_source=manifest_source.strip() or "api",
            activated_at=self._utc_now(),
        )
        with self._services_lock:
            self.loaded_services.extend(loaded_to_start)
            self._runtime_deployments[normalized_id] = deployment
        return {
            "deployment_id": normalized_id,
            "status": "active",
            "manifest_source": deployment.manifest_source,
            "activated_at": deployment.activated_at,
            "service_count": len(loaded_to_start),
            "services": [loaded.config.name for loaded in loaded_to_start],
        }

    def deactivate_runtime_deployment(self, *, deployment_id: str) -> dict[str, Any]:
        normalized_id = deployment_id.strip()
        if not normalized_id:
            raise ValueError("deployment_id cannot be empty")
        with self._services_lock:
            deployment = self._runtime_deployments.get(normalized_id)
        if deployment is None:
            raise KeyError(normalized_id)

        stop_results = self._run_coroutines_sync([loaded.emulator.stop() for loaded in deployment.services])
        errors: list[str] = []
        for loaded, result in zip(deployment.services, stop_results, strict=False):
            if isinstance(result, Exception):
                errors.append(f"{loaded.config.name}: {type(result).__name__}: {result}")

        with self._services_lock:
            self.loaded_services = [
                item for item in self.loaded_services if item.deployment_id != normalized_id
            ]
            self._runtime_deployments.pop(normalized_id, None)

        return {
            "deployment_id": normalized_id,
            "status": "deleted",
            "service_count": len(deployment.services),
            "errors": errors,
            "deleted_at": self._utc_now(),
        }

    def runtime_deployments(self) -> list[dict[str, Any]]:
        with self._services_lock:
            deployments = list(self._runtime_deployments.values())
        return [
            {
                "deployment_id": deployment.deployment_id,
                "status": "active",
                "manifest_source": deployment.manifest_source,
                "activated_at": deployment.activated_at,
                "service_count": len(deployment.services),
                "services": [loaded.config.name for loaded in deployment.services],
            }
            for deployment in deployments
        ]

    def runtime_deployment(self, *, deployment_id: str) -> dict[str, Any] | None:
        normalized_id = deployment_id.strip()
        if not normalized_id:
            return None
        with self._services_lock:
            deployment = self._runtime_deployments.get(normalized_id)
        if deployment is None:
            return None
        return {
            "deployment_id": deployment.deployment_id,
            "status": "active",
            "manifest_source": deployment.manifest_source,
            "activated_at": deployment.activated_at,
            "service_count": len(deployment.services),
            "services": [loaded.config.name for loaded in deployment.services],
        }

    def inject_runtime_activity(self, *, deployment_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        normalized_id = deployment_id.strip()
        if not normalized_id:
            raise ValueError("deployment_id cannot be empty")
        if not isinstance(payload, dict):
            raise ValueError("activity payload must be an object")

        with self._services_lock:
            deployment = self._runtime_deployments.get(normalized_id)
        if deployment is None:
            raise KeyError(normalized_id)

        requested_service = str(payload.get("service", "")).strip().lower()
        candidates = deployment.services
        if requested_service:
            candidates = [
                loaded
                for loaded in deployment.services
                if loaded.config.name.strip().lower() == requested_service
            ]
            if not candidates:
                raise ValueError(
                    f"runtime deployment '{normalized_id}' does not include service '{requested_service}'"
                )

        results: list[dict[str, Any]] = []
        errors: list[str] = []
        for loaded in candidates:
            try:
                response = loaded.emulator.inject_activity(dict(payload))
            except Exception as exc:  # pragma: no cover - defensive safety
                errors.append(f"{loaded.config.name}: {type(exc).__name__}: {exc}")
                continue
            if not isinstance(response, dict):
                response = {
                    "accepted": False,
                    "service": loaded.config.name,
                    "reason": "invalid injection response",
                }
            if "service" not in response:
                response["service"] = loaded.config.name
            results.append(response)

        accepted = [item for item in results if bool(item.get("accepted"))]
        if not accepted:
            reason = "; ".join(errors) if errors else "no service accepted the activity payload"
            raise ValueError(reason)

        return {
            "deployment_id": normalized_id,
            "accepted_count": len(accepted),
            "attempted_count": len(candidates),
            "results": results,
            "errors": errors,
        }

    @staticmethod
    def _clone_service(service: ServiceConfig) -> ServiceConfig:
        return replace(service, config=dict(service.config), ports=list(service.ports))

    def _clone_services(self, services: list[ServiceConfig]) -> list[ServiceConfig]:
        return [self._clone_service(service) for service in services]

    def _tenant_targets(self, *, tenant_id: str | None, all_tenants: bool) -> list[str]:
        if not all_tenants:
            return [self.tenant_manager.resolve_tenant(tenant_id).tenant_id]

        tenant_targets: list[str] = []
        if self.config.multi_tenant.enabled:
            tenant_targets.extend(
                [tenant.tenant_id for tenant in self.config.multi_tenant.tenants if tenant.enabled and tenant.tenant_id]
            )
            default_tenant = self.config.multi_tenant.default_tenant.strip()
            if default_tenant:
                tenant_targets.append(default_tenant)
        elif tenant_id:
            tenant_targets.append(tenant_id)
        if not tenant_targets:
            tenant_targets.append(self.config.multi_tenant.default_tenant)

        unique_targets: list[str] = []
        seen_targets: set[str] = set()
        for target in tenant_targets:
            normalized = target.strip()
            if not normalized or normalized in seen_targets:
                continue
            seen_targets.add(normalized)
            unique_targets.append(normalized)
        return unique_targets

    def _comparison_tenants(self, *, left_tenant_id: str | None, right_tenant_id: str | None) -> tuple[str, str]:
        if left_tenant_id:
            left = self.tenant_manager.resolve_tenant(left_tenant_id).tenant_id
        else:
            targets = self._tenant_targets(tenant_id=None, all_tenants=True)
            left = targets[0] if targets else self.config.multi_tenant.default_tenant

        if right_tenant_id:
            right = self.tenant_manager.resolve_tenant(right_tenant_id).tenant_id
        else:
            targets = [target for target in self._tenant_targets(tenant_id=None, all_tenants=True) if target != left]
            right = targets[0] if targets else left

        return left, right

    @staticmethod
    def _run_coroutine_sync(coro: Any) -> Any:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(coro)
        raise RuntimeError("cannot run coroutine synchronously while an event loop is active")

    @staticmethod
    def _run_coroutines_sync(coros: list[Any]) -> list[Any]:
        if not coros:
            return []
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            async def _runner() -> list[Any]:
                return list(await asyncio.gather(*coros, return_exceptions=True))

            return asyncio.run(_runner())
        raise RuntimeError("cannot run coroutine synchronously while an event loop is active")
