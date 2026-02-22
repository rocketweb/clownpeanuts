"""Phantom lateral movement artifact generation."""

from __future__ import annotations

from typing import Any

from clownpeanuts.engine.context import SessionWorld


class PhantomLateralMovement:
    def attempt_pivot(self, world: SessionWorld, *, target_hint: str) -> dict[str, Any]:
        candidates = []
        for key, host in world.hosts.items():
            candidates.append((key, host.hostname, host.ip))

        source_key = world.current_host
        selected_key = world.current_host
        hint = target_hint.lower().strip()
        for key, hostname, _ip in candidates:
            if hint in {key.lower(), hostname.lower()}:
                selected_key = key
                break
            if hint and hint in hostname.lower():
                selected_key = key
                break
            if hint and hint == world.hosts[key].role.lower():
                selected_key = key
                break

        if hint in {"next", "pivot-next"}:
            ordered = list(world.hosts.keys())
            idx = ordered.index(source_key)
            selected_key = ordered[(idx + 1) % len(ordered)]

        world.current_host = selected_key
        selected = world.hosts[selected_key]
        pivot_event = {
            "from": source_key,
            "to": selected_key,
            "hostname": selected.hostname,
            "ip": selected.ip,
        }
        world.pivots.append(pivot_event)
        return {
            "success": True,
            "target_key": selected_key,
            "hostname": selected.hostname,
            "ip": selected.ip,
            "users": selected.users,
            "note": "Connection established to internal host via bastion",
        }

    def enumerate_internal_hosts(self, world: SessionWorld) -> list[dict[str, str]]:
        return [
            {"name": key, "hostname": host.hostname, "ip": host.ip, "role": host.role}
            for key, host in world.hosts.items()
        ]
