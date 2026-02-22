"""Canary token helpers."""

from __future__ import annotations

import hashlib
import re
import secrets
from typing import Any

_NAMESPACE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")


def canary_type_catalog() -> list[dict[str, str]]:
    return [
        {"token_type": "dns", "description": "DNS beacon hostname canary"},
        {"token_type": "http", "description": "HTTP callback URL canary"},
        {"token_type": "email", "description": "Email-address canary"},
        {"token_type": "aws", "description": "Fake AWS credential canary"},
        {"token_type": "code", "description": "Unique code-marker canary"},
    ]


def token_identifier(*, token: str) -> str:
    return hashlib.sha1(token.encode("utf-8"), usedforsecurity=False).hexdigest()[:16]


def generate_canary_token(*, namespace: str, token_type: str) -> dict[str, Any]:
    namespace_clean = namespace.strip().lower() or "cp"
    if not _NAMESPACE_RE.fullmatch(namespace_clean):
        raise ValueError("namespace must match ^[a-z0-9][a-z0-9-]{0,62}$")
    token_type_clean = token_type.strip().lower() or "http"
    seed = secrets.token_hex(12)
    token = f"{namespace_clean}-{token_type_clean}-{seed}"
    token_id = token_identifier(token=token)
    artifact = _canary_artifact(
        token=token,
        token_type=token_type_clean,
        namespace=namespace_clean,
        seed=seed,
    )
    return {
        "token_id": token_id,
        "token": token,
        "token_type": token_type_clean,
        "namespace": namespace_clean,
        "artifact_type": str(artifact.get("artifact_type", "generic")),
        "artifact": artifact,
    }


def _canary_artifact(*, token: str, token_type: str, namespace: str, seed: str) -> dict[str, Any]:
    if token_type == "dns":
        return {
            "artifact_type": "dns",
            "hostname": f"{seed}.{namespace}.canary.cp.local",
            "record_type": "A",
            "lookup_hint": f"nslookup {seed}.{namespace}.canary.cp.local",
        }
    if token_type == "http":
        return {
            "artifact_type": "http",
            "url": f"https://collector-{namespace}.cp.local/canary/{token}",
            "method": "GET",
            "header_hint": f"X-Canary-Token: {token}",
        }
    if token_type == "email":
        return {
            "artifact_type": "email",
            "address": f"{seed}@alerts-{namespace}.cp.local",
            "subject_hint": f"[{namespace.upper()}] Credential health check",
        }
    if token_type == "aws":
        access_key_id = "AKIA" + secrets.token_hex(8).upper()[:16]
        secret_access_key = secrets.token_urlsafe(32).replace("-", "A").replace("_", "B")[:40]
        return {
            "artifact_type": "aws",
            "access_key_id": access_key_id,
            "secret_access_key": secret_access_key,
            "session_token": token,
            "env_lines": [
                f"AWS_ACCESS_KEY_ID={access_key_id}",
                f"AWS_SECRET_ACCESS_KEY={secret_access_key}",
                f"AWS_SESSION_TOKEN={token}",
            ],
        }
    if token_type == "code":
        marker = f"CANARY_{seed[:12].upper()}"
        return {
            "artifact_type": "code",
            "marker": marker,
            "snippet": f"// {marker}:{token}",
        }
    return {
        "artifact_type": "generic",
        "marker": token,
    }


def detect_canary_hit(*, token: str, text: str) -> dict[str, Any]:
    hit = bool(token and token in text)
    return {
        "hit": hit,
        "token": token,
        "indicator_type": "canary_token",
    }


def summarize_canary_hits(events: list[dict[str, Any]]) -> dict[str, Any]:
    tokens: dict[str, dict[str, Any]] = {}
    for event in events:
        payload = event.get("payload", {})
        if not isinstance(payload, dict):
            continue
        indicator = str(payload.get("indicator_type", "")).lower()
        token = str(payload.get("token", "")).strip()
        if not token and indicator != "canary_token":
            continue
        key = token or "unknown-token"
        record = tokens.get(key)
        if record is None:
            record = {
                "token": key,
                "first_seen": str(event.get("timestamp", "")),
                "last_seen": str(event.get("timestamp", "")),
                "hits": 0,
                "services": set(),
            }
            tokens[key] = record
        record["last_seen"] = str(event.get("timestamp", ""))
        record["hits"] = int(record["hits"]) + 1
        record["services"].add(str(event.get("service", "")))

    rows: list[dict[str, Any]] = []
    for token, record in tokens.items():
        rows.append(
            {
                "token": token,
                "first_seen": record["first_seen"],
                "last_seen": record["last_seen"],
                "hits": int(record["hits"]),
                "services": sorted(str(item) for item in record["services"]),
            }
        )
    rows.sort(key=lambda item: int(item.get("hits", 0)), reverse=True)
    return {"tokens": rows, "total_tokens": len(rows), "total_hits": sum(int(item["hits"]) for item in rows)}
