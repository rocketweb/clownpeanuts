"""Tool fingerprint detection heuristics."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import json
import re
from typing import Any


@dataclass(frozen=True, slots=True)
class ToolSignature:
    tool: str
    category: str
    confidence: float
    patterns: tuple[re.Pattern[str], ...]


_SIGNATURES: tuple[ToolSignature, ...] = (
    ToolSignature(
        tool="nmap",
        category="recon",
        confidence=0.9,
        patterns=(
            re.compile(r"\bnmap\b", re.IGNORECASE),
            re.compile(r"\b-s[suv]\b", re.IGNORECASE),
            re.compile(r"--script", re.IGNORECASE),
        ),
    ),
    ToolSignature(
        tool="masscan",
        category="recon",
        confidence=0.9,
        patterns=(re.compile(r"\bmasscan\b", re.IGNORECASE),),
    ),
    ToolSignature(
        tool="sqlmap",
        category="exploitation",
        confidence=0.92,
        patterns=(re.compile(r"\bsqlmap\b", re.IGNORECASE),),
    ),
    ToolSignature(
        tool="hydra",
        category="credential_access",
        confidence=0.86,
        patterns=(
            re.compile(r"\bhydra\b", re.IGNORECASE),
            re.compile(r"\bmedusa\b", re.IGNORECASE),
        ),
    ),
    ToolSignature(
        tool="gobuster",
        category="recon",
        confidence=0.82,
        patterns=(
            re.compile(r"\bgobuster\b", re.IGNORECASE),
            re.compile(r"\bdirb\b", re.IGNORECASE),
            re.compile(r"\bffuf\b", re.IGNORECASE),
        ),
    ),
    ToolSignature(
        tool="mimikatz",
        category="credential_access",
        confidence=0.95,
        patterns=(
            re.compile(r"\bmimikatz\b", re.IGNORECASE),
            re.compile(r"\bsekurlsa::", re.IGNORECASE),
        ),
    ),
    ToolSignature(
        tool="powershell-download-cradle",
        category="execution",
        confidence=0.8,
        patterns=(
            re.compile(r"invoke-webrequest", re.IGNORECASE),
            re.compile(r"new-object\s+net\.webclient", re.IGNORECASE),
            re.compile(r"iwr\s+http", re.IGNORECASE),
        ),
    ),
    ToolSignature(
        tool="reverse-shell",
        category="command_and_control",
        confidence=0.88,
        patterns=(
            re.compile(r"/dev/tcp/", re.IGNORECASE),
            re.compile(r"\bnc\s+.*\s-e\s", re.IGNORECASE),
            re.compile(r"bash\s+-i", re.IGNORECASE),
        ),
    ),
)


def fingerprint_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    evidence_counts: dict[str, int] = defaultdict(int)
    signature_by_tool = {signature.tool: signature for signature in _SIGNATURES}
    for event in events:
        text = _event_text(event)
        if not text:
            continue
        for signature in _SIGNATURES:
            if any(pattern.search(text) for pattern in signature.patterns):
                evidence_counts[signature.tool] += 1

    payload: list[dict[str, Any]] = []
    for tool, evidence_count in evidence_counts.items():
        signature = signature_by_tool[tool]
        payload.append(
            {
                "tool": signature.tool,
                "category": signature.category,
                "confidence": signature.confidence,
                "evidence_count": evidence_count,
            }
        )
    payload.sort(key=lambda item: (-int(item.get("evidence_count", 0)), str(item.get("tool", ""))))
    return payload


def summarize_fingerprints(session_fingerprints: list[list[dict[str, Any]]]) -> list[dict[str, Any]]:
    totals: dict[str, dict[str, Any]] = {}
    for fingerprints in session_fingerprints:
        seen_tools: set[str] = set()
        for item in fingerprints:
            tool = str(item.get("tool", "")).strip()
            if not tool:
                continue
            record = totals.setdefault(
                tool,
                {
                    "tool": tool,
                    "category": str(item.get("category", "")).strip(),
                    "confidence": float(item.get("confidence", 0.0) or 0.0),
                    "sessions": 0,
                    "evidence_count": 0,
                },
            )
            record["evidence_count"] = int(record["evidence_count"]) + int(item.get("evidence_count", 0) or 0)
            if tool not in seen_tools:
                record["sessions"] = int(record["sessions"]) + 1
                seen_tools.add(tool)

    payload = list(totals.values())
    payload.sort(
        key=lambda item: (
            -int(item.get("sessions", 0)),
            -int(item.get("evidence_count", 0)),
            str(item.get("tool", "")),
        )
    )
    return payload


def _event_text(event: dict[str, Any]) -> str:
    chunks: list[str] = []
    chunks.append(str(event.get("service", "")))
    chunks.append(str(event.get("action", "")))
    payload = event.get("payload", {})
    if isinstance(payload, dict):
        for key in ("command", "query", "path", "user_agent", "message", "request", "body"):
            value = payload.get(key)
            if value is not None:
                chunks.append(str(value))
        for key, value in payload.items():
            if key in {"command", "query", "path", "user_agent", "message", "request", "body"}:
                continue
            if isinstance(value, (dict, list, tuple)):
                chunks.append(json.dumps(value, default=str))
            elif value is not None:
                chunks.append(str(value))
    return " ".join(part for part in chunks if part).strip()
