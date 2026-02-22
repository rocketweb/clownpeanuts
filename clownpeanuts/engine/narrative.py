"""Deterministic narrative world model and session context resolver."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
import hashlib
import random
from typing import Any

from clownpeanuts.config.schema import NarrativeConfig


@dataclass(slots=True)
class NarrativeEntity:
    entity_id: str
    kind: str
    label: str
    attributes: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class NarrativeEdge:
    source_id: str
    target_id: str
    relation: str


@dataclass(slots=True)
class NarrativeWorld:
    tenant_id: str
    world_id: str
    world_seed: str
    entity_count: int
    entities: dict[str, NarrativeEntity]
    edges: list[NarrativeEdge]
    indexes: dict[str, list[str]]


@dataclass(slots=True)
class NarrativeSessionState:
    session_id: str
    source_ip: str
    tenant_id: str
    world_id: str
    context_id: str
    discovery_depth: int = 0
    touched_services: list[str] = field(default_factory=list)
    revealed_entities: list[str] = field(default_factory=list)
    anchor_entities: dict[str, str] = field(default_factory=dict)
    last_action: str = ""
    last_service: str = ""


class NarrativeEngine:
    """Deterministic world graph plus per-session narrative progression."""

    _USER_POOL = [
        "alex",
        "sam",
        "jordan",
        "morgan",
        "casey",
        "drew",
        "riley",
        "quinn",
        "blake",
        "hayden",
        "taylor",
        "devon",
        "parker",
        "kai",
        "rowan",
        "adrian",
    ]
    _SERVICE_POOL = [
        "jira",
        "confluence",
        "grafana",
        "gitlab",
        "jenkins",
        "vault",
        "kibana",
        "airflow",
        "vault-sync",
        "artifact-proxy",
    ]
    _PROJECT_POOL = [
        "beacon",
        "avalon",
        "northstar",
        "harbor",
        "solstice",
        "ledger",
        "pulse",
        "supplyline",
        "quartz",
        "nightshift",
    ]
    _DATASET_POOL = [
        "customer_orders",
        "invoice_events",
        "billing_rollups",
        "auth_audit",
        "deploy_metrics",
        "shipment_ledger",
        "incident_timeline",
        "analytics_snapshot",
    ]
    _HOST_ROLES = ["web", "api", "db", "cache", "worker", "backup", "bastion", "ci"]
    _TICKET_PREFIX = ["OPS", "SEC", "INC", "PLAT"]

    def __init__(self, config: NarrativeConfig) -> None:
        self.config = config
        self._max_worlds = 512
        self._max_sessions = 10_000
        self._worlds: OrderedDict[str, NarrativeWorld] = OrderedDict()
        self._sessions: OrderedDict[str, NarrativeSessionState] = OrderedDict()

    def world_for_tenant(self, tenant_id: str) -> NarrativeWorld:
        normalized_tenant = tenant_id.strip() or "default"
        world_key = normalized_tenant if self.config.per_tenant_worlds else "global"
        world = self._worlds.get(world_key)
        if world is not None:
            self._worlds.move_to_end(world_key)
            return world
        if len(self._worlds) >= self._max_worlds:
            self._worlds.popitem(last=False)
        built = self._build_world(tenant_id=normalized_tenant, world_key=world_key)
        self._worlds[world_key] = built
        return built

    def resolve_session_context(
        self,
        *,
        session_id: str,
        source_ip: str,
        tenant_id: str = "default",
        service: str = "",
        action: str = "",
        hints: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        world = self.world_for_tenant(tenant_id)
        session = self._sessions.get(session_id)
        if session is None:
            if len(self._sessions) >= self._max_sessions:
                self._sessions.popitem(last=False)
            context_hash = hashlib.sha1(
                f"{world.world_id}:{session_id}:{source_ip}".encode("utf-8"),
                usedforsecurity=False,
            ).hexdigest()[:16]
            session = NarrativeSessionState(
                session_id=session_id,
                source_ip=source_ip,
                tenant_id=tenant_id.strip() or "default",
                world_id=world.world_id,
                context_id=f"ctx-{context_hash}",
            )
            self._sessions[session_id] = session
        else:
            self._sessions.move_to_end(session_id)

        normalized_service = service.strip().lower()
        normalized_action = action.strip().lower()
        if normalized_service and normalized_service not in session.touched_services:
            session.touched_services.append(normalized_service)
        if normalized_action:
            session.discovery_depth = min(10_000, session.discovery_depth + 1)
            session.last_action = normalized_action
        if normalized_service:
            session.last_service = normalized_service

        focus = self._focus_entities(
            world=world,
            context_key=f"{session.context_id}:{normalized_service}:{normalized_action}:{session.discovery_depth}",
        )
        if not session.anchor_entities:
            session.anchor_entities = {key: entity_id for key, entity_id in focus.items() if entity_id}
        for key, entity_id in session.anchor_entities.items():
            if entity_id:
                focus[key] = entity_id
        for entity_id in focus.values():
            if entity_id and entity_id not in session.revealed_entities:
                session.revealed_entities.append(entity_id)

        hint_payload = self._sanitize_hints(hints)
        return {
            "context_id": session.context_id,
            "tenant_id": session.tenant_id,
            "world_id": session.world_id,
            "source_ip": session.source_ip,
            "discovery_depth": session.discovery_depth,
            "touched_services": list(session.touched_services),
            "revealed_entities": len(session.revealed_entities),
            "last_action": session.last_action,
            "last_service": session.last_service,
            "focus": {
                key: self._entity_payload(world, entity_id)
                for key, entity_id in focus.items()
                if entity_id
            },
            "hints": hint_payload,
        }

    def session_snapshot(self, session_id: str) -> dict[str, Any] | None:
        session = self._sessions.get(session_id)
        if session is None:
            return None
        return {
            "session_id": session.session_id,
            "tenant_id": session.tenant_id,
            "world_id": session.world_id,
            "context_id": session.context_id,
            "discovery_depth": session.discovery_depth,
            "touched_services": list(session.touched_services),
            "revealed_entities": len(session.revealed_entities),
            "anchor_entities": dict(session.anchor_entities),
            "last_action": session.last_action,
            "last_service": session.last_service,
        }

    def session_view(self, session_id: str) -> dict[str, Any] | None:
        session = self._sessions.get(session_id)
        if session is None:
            return None
        world = self.world_for_tenant(session.tenant_id)
        revealed = [
            self._entity_payload(world, entity_id)
            for entity_id in session.revealed_entities
            if entity_id in world.entities
        ]
        return {
            "session_id": session.session_id,
            "source_ip": session.source_ip,
            "tenant_id": session.tenant_id,
            "world_id": session.world_id,
            "context_id": session.context_id,
            "discovery_depth": session.discovery_depth,
            "touched_services": list(session.touched_services),
            "revealed_entity_ids": list(session.revealed_entities),
            "revealed_entities": revealed,
            "revealed_entity_count": len(session.revealed_entities),
            "anchor_entities": {
                key: self._entity_payload(world, entity_id)
                for key, entity_id in sorted(session.anchor_entities.items())
                if entity_id in world.entities
            },
            "last_action": session.last_action,
            "last_service": session.last_service,
        }

    def world_snapshot(self, *, tenant_id: str) -> dict[str, Any]:
        world = self.world_for_tenant(tenant_id)
        entities = [
            self._entity_payload(world, entity_id)
            for entity_id in sorted(world.entities.keys())
        ]
        edges = [
            {
                "source_id": edge.source_id,
                "target_id": edge.target_id,
                "relation": edge.relation,
            }
            for edge in sorted(world.edges, key=lambda item: (item.source_id, item.relation, item.target_id))
        ]
        return {
            "enabled": self.config.enabled,
            "tenant_id": world.tenant_id,
            "world_id": world.world_id,
            "world_seed": world.world_seed,
            "entity_count": len(world.entities),
            "edge_count": len(world.edges),
            "indexes": {key: list(value) for key, value in sorted(world.indexes.items())},
            "entities": entities,
            "edges": edges,
        }

    def snapshot(self) -> dict[str, Any]:
        return {
            "enabled": self.config.enabled,
            "world_seed": self.config.world_seed,
            "entity_count": self.config.entity_count,
            "per_tenant_worlds": self.config.per_tenant_worlds,
            "world_count": len(self._worlds),
            "session_count": len(self._sessions),
            "worlds": [
                {
                    "tenant_id": world.tenant_id,
                    "world_id": world.world_id,
                    "entity_count": len(world.entities),
                    "edge_count": len(world.edges),
                }
                for world in self._worlds.values()
            ],
        }

    def _build_world(self, *, tenant_id: str, world_key: str) -> NarrativeWorld:
        seed_material = f"{self.config.world_seed}:{world_key}".encode("utf-8")
        world_hash = hashlib.sha1(seed_material, usedforsecurity=False).hexdigest()
        rng = random.Random(int(world_hash[:16], 16))

        entity_target = max(20, int(self.config.entity_count))
        host_count = min(24, max(8, entity_target // 12))
        user_count = min(80, max(10, entity_target // 8))
        service_count = min(40, max(6, entity_target // 14))
        dataset_count = min(30, max(5, entity_target // 18))
        credential_count = min(60, max(6, entity_target // 20))
        ticket_count = min(60, max(6, entity_target // 16))

        entities: dict[str, NarrativeEntity] = {}
        edges: list[NarrativeEdge] = []
        indexes: dict[str, list[str]] = {
            "host": [],
            "user": [],
            "service": [],
            "dataset": [],
            "credential": [],
            "ticket": [],
            "project": [],
        }

        org_id = "org-001"
        entities[org_id] = NarrativeEntity(
            entity_id=org_id,
            kind="organization",
            label=f"{tenant_id}-systems",
            attributes={"tenant": tenant_id},
        )

        for idx in range(service_count):
            name = self._pick(self._SERVICE_POOL, rng, idx)
            project = self._pick(self._PROJECT_POOL, rng, idx)
            entity_id = f"svc-{idx + 1:03d}"
            label = f"{name}-{project}"
            entities[entity_id] = NarrativeEntity(
                entity_id=entity_id,
                kind="service",
                label=label,
                attributes={"project": project, "tier": str((idx % 3) + 1)},
            )
            indexes["service"].append(entity_id)
            edges.append(NarrativeEdge(source_id=org_id, target_id=entity_id, relation="operates"))

        for idx in range(host_count):
            role = self._pick(self._HOST_ROLES, rng, idx)
            service_id = indexes["service"][idx % len(indexes["service"])]
            suffix = world_hash[idx * 2 : idx * 2 + 2]
            entity_id = f"hst-{idx + 1:03d}"
            label = f"{role}{idx + 1:02d}-{suffix}"
            entities[entity_id] = NarrativeEntity(
                entity_id=entity_id,
                kind="host",
                label=label,
                attributes={
                    "role": role,
                    "ip": f"10.{40 + (idx % 8)}.{(idx * 7) % 200 + 10}.{(idx * 13) % 220 + 20}",
                },
            )
            indexes["host"].append(entity_id)
            edges.append(NarrativeEdge(source_id=service_id, target_id=entity_id, relation="runs_on"))

        for idx in range(user_count):
            username = self._pick(self._USER_POOL, rng, idx)
            project = self._pick(self._PROJECT_POOL, rng, idx + 3)
            entity_id = f"usr-{idx + 1:03d}"
            label = f"{username}.{project}"
            entities[entity_id] = NarrativeEntity(
                entity_id=entity_id,
                kind="user",
                label=label,
                attributes={"department": project, "title": f"engineer-{(idx % 4) + 1}"},
            )
            indexes["user"].append(entity_id)
            target_host = indexes["host"][idx % len(indexes["host"])]
            edges.append(NarrativeEdge(source_id=entity_id, target_id=target_host, relation="has_access"))

        for idx in range(dataset_count):
            name = self._pick(self._DATASET_POOL, rng, idx)
            entity_id = f"dat-{idx + 1:03d}"
            label = f"{name}_{idx + 1:02d}"
            entities[entity_id] = NarrativeEntity(
                entity_id=entity_id,
                kind="dataset",
                label=label,
                attributes={"classification": "internal", "format": "sql"},
            )
            indexes["dataset"].append(entity_id)
            service_id = indexes["service"][idx % len(indexes["service"])]
            edges.append(NarrativeEdge(source_id=service_id, target_id=entity_id, relation="reads"))

        for idx in range(credential_count):
            user_id = indexes["user"][idx % len(indexes["user"])]
            service_id = indexes["service"][idx % len(indexes["service"])]
            entity_id = f"cre-{idx + 1:03d}"
            pass_suffix = world_hash[(idx * 3) % 30 : ((idx * 3) % 30) + 6]
            entities[entity_id] = NarrativeEntity(
                entity_id=entity_id,
                kind="credential",
                label=f"cred-{idx + 1:03d}",
                attributes={"username_ref": user_id, "password_hint": f"{pass_suffix}!"},
            )
            indexes["credential"].append(entity_id)
            edges.append(NarrativeEdge(source_id=entity_id, target_id=service_id, relation="grants_access"))

        for idx in range(ticket_count):
            prefix = self._pick(self._TICKET_PREFIX, rng, idx)
            entity_id = f"tkt-{idx + 1:03d}"
            label = f"{prefix}-{1000 + idx}"
            entities[entity_id] = NarrativeEntity(
                entity_id=entity_id,
                kind="ticket",
                label=label,
                attributes={"priority": str((idx % 4) + 1)},
            )
            indexes["ticket"].append(entity_id)
            service_id = indexes["service"][idx % len(indexes["service"])]
            edges.append(NarrativeEdge(source_id=entity_id, target_id=service_id, relation="references"))

        for idx in range(max(4, len(indexes["service"]) // 3)):
            project_name = self._pick(self._PROJECT_POOL, rng, idx + 11)
            entity_id = f"prj-{idx + 1:03d}"
            entities[entity_id] = NarrativeEntity(
                entity_id=entity_id,
                kind="project",
                label=project_name,
                attributes={"owner": indexes["user"][idx % len(indexes["user"])]},
            )
            indexes["project"].append(entity_id)
            svc_id = indexes["service"][idx % len(indexes["service"])]
            edges.append(NarrativeEdge(source_id=entity_id, target_id=svc_id, relation="contains"))

        return NarrativeWorld(
            tenant_id=tenant_id,
            world_id=f"world-{world_hash[:12]}",
            world_seed=self.config.world_seed,
            entity_count=self.config.entity_count,
            entities=entities,
            edges=edges,
            indexes=indexes,
        )

    def _focus_entities(self, *, world: NarrativeWorld, context_key: str) -> dict[str, str]:
        focus: dict[str, str] = {}
        for kind, label in (
            ("user", "user"),
            ("host", "host"),
            ("service", "service"),
            ("dataset", "dataset"),
            ("ticket", "ticket"),
        ):
            pool = world.indexes.get(kind, [])
            if not pool:
                continue
            digest = hashlib.sha1(f"{context_key}:{kind}".encode("utf-8"), usedforsecurity=False).hexdigest()
            pick = int(digest[:8], 16) % len(pool)
            focus[label] = pool[pick]
        return focus

    @staticmethod
    def _entity_payload(world: NarrativeWorld, entity_id: str) -> dict[str, Any]:
        entity = world.entities.get(entity_id)
        if entity is None:
            return {}
        return {
            "entity_id": entity.entity_id,
            "kind": entity.kind,
            "label": entity.label,
            "attributes": dict(entity.attributes),
        }

    @staticmethod
    def _sanitize_hints(hints: dict[str, str] | None) -> dict[str, str]:
        if not hints:
            return {}
        payload: dict[str, str] = {}
        for key, value in hints.items():
            normalized_key = str(key).strip()
            if not normalized_key:
                continue
            payload[normalized_key] = str(value).strip()[:120]
            if len(payload) >= 10:
                break
        return payload

    @staticmethod
    def _pick(pool: list[str], rng: random.Random, index: int) -> str:
        if not pool:
            return "unknown"
        offset = rng.randint(0, len(pool) - 1)
        return pool[(index + offset) % len(pool)]
