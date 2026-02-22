"""Relationship fabrication helpers for optional AD graph baiting."""

from __future__ import annotations

from typing import Any


def fabricate_relationships(objects: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Build simple deterministic relationship chains from seeded objects."""

    users = [row for row in objects if str(row.get("object_type", "")) == "user"]
    service_accounts = [row for row in objects if str(row.get("object_type", "")) == "service_account"]
    groups = [row for row in objects if str(row.get("object_type", "")) == "group"]

    relationships: list[dict[str, str]] = []
    for index, user in enumerate(users):
        if service_accounts:
            svc = service_accounts[index % len(service_accounts)]
            relationships.append(
                {
                    "source": str(user.get("name", "")),
                    "relation": "GenericAll",
                    "target": str(svc.get("name", "")),
                }
            )
        if groups:
            grp = groups[index % len(groups)]
            relationships.append(
                {
                    "source": str(user.get("name", "")),
                    "relation": "MemberOf",
                    "target": str(grp.get("name", "")),
                }
            )
    return relationships

