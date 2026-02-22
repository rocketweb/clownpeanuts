"""Credential cascade graph for fake pivoting."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from typing import Any

from clownpeanuts.engine.context import SessionWorld


@dataclass(slots=True)
class CredentialNode:
    source_host: str
    username: str
    password: str
    target_service: str
    target_host: str


class CredentialCascade:
    def __init__(self, *, max_graphs: int = 10_000) -> None:
        self._max_graphs = max(1, int(max_graphs))
        self._graphs: OrderedDict[str, list[CredentialNode]] = OrderedDict()
        self._revealed_index: dict[str, int] = {}

    def ensure_graph(self, world: SessionWorld) -> list[CredentialNode]:
        existing = self._graphs.get(world.session_id)
        if existing is not None:
            self._graphs.move_to_end(world.session_id)
            return existing
        if len(self._graphs) >= self._max_graphs:
            evicted_session_id, _ = self._graphs.popitem(last=False)
            self._revealed_index.pop(evicted_session_id, None)
        seed = world.seed
        entropy = (seed * 3)[:96]
        host = world.hosts
        graph = [
            CredentialNode(
                source_host="web01",
                username="app_user",
                password=entropy[0:10],
                target_service="postgresql",
                target_host=host["db01"].hostname,
            ),
            CredentialNode(
                source_host="db01",
                username="cache_sync",
                password=f"cache-{entropy[10:18]}",
                target_service="redis",
                target_host=host["cache01"].hostname,
            ),
            CredentialNode(
                source_host="cache01",
                username="ops",
                password=f"ops-{entropy[18:26]}",
                target_service="ssh",
                target_host=host["api01"].hostname,
            ),
            CredentialNode(
                source_host="api01",
                username="worker_bot",
                password=f"wrk-{entropy[26:34]}",
                target_service="rabbitmq",
                target_host=host["worker01"].hostname,
            ),
            CredentialNode(
                source_host="worker01",
                username="backup_agent",
                password=f"bkp-{entropy[34:42]}",
                target_service="sftp",
                target_host=host["backup01"].hostname,
            ),
            CredentialNode(
                source_host="backup01",
                username="ops",
                password=f"ops-{entropy[42:50]}",
                target_service="ssh",
                target_host=host["bastion01"].hostname,
            ),
            CredentialNode(
                source_host="bastion01",
                username="ci_runner",
                password=f"ci-{entropy[50:58]}",
                target_service="https",
                target_host=host["ci01"].hostname,
            ),
            CredentialNode(
                source_host="ci01",
                username="root",
                password=f"root-{entropy[58:66]}",
                target_service="kubernetes",
                target_host="k8s-admin.internal",
            ),
        ]
        self._graphs[world.session_id] = graph
        self._revealed_index[world.session_id] = -1
        return graph

    def reveal_next(self, world: SessionWorld) -> dict[str, str] | None:
        graph = self.ensure_graph(world)
        current_index = self._revealed_index.get(world.session_id, -1)
        next_index = current_index + 1
        if next_index >= len(graph):
            return None
        self._revealed_index[world.session_id] = next_index
        node = graph[next_index]
        payload = {
            "username": node.username,
            "password": node.password,
            "source_host": node.source_host,
            "target_host": node.target_host,
            "target_service": node.target_service,
        }
        world.discovered_credentials.append(payload)
        return payload

    def all_revealed(self, session_id: str) -> list[dict[str, str]]:
        graph = self._graphs.get(session_id, [])
        max_index = self._revealed_index.get(session_id, -1)
        payload: list[dict[str, str]] = []
        for node in graph[: max_index + 1]:
            payload.append(
                {
                    "username": node.username,
                    "password": node.password,
                    "source_host": node.source_host,
                    "target_host": node.target_host,
                    "target_service": node.target_service,
                }
            )
        return payload

    def snapshot(self) -> dict[str, list[dict[str, Any]]]:
        payload: dict[str, list[dict[str, Any]]] = {}
        for session_id, nodes in self._graphs.items():
            payload[session_id] = [
                {
                    "source_host": node.source_host,
                    "username": node.username,
                    "password": node.password,
                    "target_service": node.target_service,
                    "target_host": node.target_host,
                }
                for node in nodes
            ]
        return payload
