"""Drift snapshot and comparison helpers for ecosystem mode."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _coerce_port_values(raw: Any) -> list[int]:
    if raw is None:
        return []
    if isinstance(raw, int):
        return [int(raw)]
    if isinstance(raw, list):
        values: list[int] = []
        for item in raw:
            try:
                values.append(int(item))
            except (TypeError, ValueError):
                continue
        return values
    return []


def _extract_timing(config: dict[str, Any]) -> dict[str, Any]:
    timing: dict[str, Any] = {}
    for key, value in config.items():
        normalized = str(key).strip().lower()
        if not normalized:
            continue
        if any(token in normalized for token in ("delay", "tarpit", "throttle", "timeout", "cooldown", "jitter")):
            timing[str(key)] = value
    return timing


def _service_protocol(name: str, module: str) -> str:
    normalized_name = name.strip().lower()
    if normalized_name:
        return normalized_name
    normalized_module = module.strip().lower()
    if normalized_module:
        return normalized_module.rsplit(".", 2)[-2] if "." in normalized_module else normalized_module
    return "unknown"


class EcosystemDriftEngine:
    """Builds drift snapshots and performs server-side drift comparisons."""

    def __init__(self, *, orchestrator: Any, alert_threshold: float = 0.7) -> None:
        self._orchestrator = orchestrator
        self._alert_threshold = max(0.0, min(1.0, float(alert_threshold)))

    def snapshot(self) -> dict[str, Any]:
        return self.snapshot_filtered()

    def snapshot_filtered(
        self,
        *,
        limit: int = 2000,
        protocol: str = "",
        source: str = "",
        deployment_id_prefix: str = "",
        service_prefix: str = "",
        running: str = "",
        query: str = "",
        sort_by: str = "deployment_activated_at",
        sort_order: str = "desc",
    ) -> dict[str, Any]:
        safe_limit = max(1, min(2000, int(limit)))
        normalized_protocol = protocol.strip().lower()
        normalized_source = source.strip().lower()
        normalized_deployment_id_prefix = deployment_id_prefix.strip().lower()
        normalized_service_prefix = service_prefix.strip().lower()
        normalized_query = query.strip().lower()
        running_filter = self._parse_running_filter(running)
        normalized_sort_by = sort_by.strip().lower() if sort_by else "deployment_activated_at"
        allowed_sort_by = {
            "service",
            "protocol",
            "source",
            "deployment_id",
            "listen_host",
            "deployment_activated_at",
        }
        if normalized_sort_by not in allowed_sort_by:
            raise ValueError(
                "sort_by must be one of: service, protocol, source, deployment_id, listen_host, deployment_activated_at"
            )
        normalized_sort_order = sort_order.strip().lower() if sort_order else "desc"
        if normalized_sort_order not in {"asc", "desc"}:
            raise ValueError("sort_order must be one of: asc, desc")

        instances = self._snapshot_instances()
        filtered: list[dict[str, Any]] = []
        for row in instances:
            row_protocol = str(row.get("protocol", "")).strip().lower()
            row_source = str(row.get("source", "")).strip().lower()
            row_metadata = row.get("metadata")
            metadata_source = ""
            if isinstance(row_metadata, dict):
                metadata_source = str(row_metadata.get("deployment_source", "")).strip().lower()
            if normalized_protocol and row_protocol != normalized_protocol:
                continue
            if normalized_source and normalized_source not in {row_source, metadata_source}:
                continue
            row_deployment_id = str(row.get("deployment_id", "")).strip().lower()
            row_service = str(row.get("service", "")).strip().lower()
            if normalized_deployment_id_prefix and not row_deployment_id.startswith(normalized_deployment_id_prefix):
                continue
            if normalized_service_prefix and not row_service.startswith(normalized_service_prefix):
                continue
            row_running = bool(row.get("running", False))
            if running_filter is not None and row_running is not running_filter:
                continue
            if normalized_query:
                searchable = " ".join(
                    [
                        row_service,
                        row_protocol,
                        row_source,
                        metadata_source,
                        row_deployment_id,
                        str(row.get("listen_host", "")).strip().lower(),
                        str(row.get("banner", "")).strip().lower(),
                        str(row.get("hostname", "")).strip().lower(),
                        str(row.get("os_fingerprint", "")).strip().lower(),
                    ]
                )
                if normalized_query not in searchable:
                    continue
            filtered.append(row)

        reverse = normalized_sort_order == "desc"
        filtered.sort(
            key=lambda item: self._snapshot_sort_value(item=item, sort_by=normalized_sort_by),
            reverse=reverse,
        )
        limited = filtered[:safe_limit]
        return {
            "generated_at": _utc_now(),
            "count": len(limited),
            "total_filtered": len(filtered),
            "instances": limited,
            "filters": {
                "protocol": normalized_protocol or None,
                "source": normalized_source or None,
                "deployment_id_prefix": normalized_deployment_id_prefix or None,
                "service_prefix": normalized_service_prefix or None,
                "running": running_filter,
                "query": normalized_query or None,
            },
            "sort": {
                "by": normalized_sort_by,
                "order": normalized_sort_order,
            },
        }

    def _snapshot_instances(self) -> list[dict[str, Any]]:
        services = self._orchestrator.active_services_detail()
        instances: list[dict[str, Any]] = []
        for service in services:
            config = dict(service.get("config", {}))
            name = str(service.get("name", ""))
            module = str(service.get("module", ""))
            instances.append(
                {
                    "service": name,
                    "protocol": _service_protocol(name, module),
                    "module": module,
                    "source": str(service.get("source", "baseline")),
                    "deployment_id": service.get("deployment_id"),
                    "listen_host": str(service.get("listen_host", "")),
                    "ports": list(service.get("ports", [])),
                    "running": bool(service.get("running", False)),
                    "banner": str(config.get("banner", "")),
                    "hostname": str(config.get("hostname", "")),
                    "os_fingerprint": str(config.get("os_fingerprint", "")),
                    "ssl_fingerprint": str(config.get("ssl_fingerprint", "")),
                    "timing": _extract_timing(config),
                    "deployment_activated_at": service.get("deployment_activated_at"),
                    "configuration_updated_at": service.get("deployment_activated_at"),
                    "metadata": {
                        "manifest_source": str(service.get("source", "baseline")),
                        "deployment_source": str(
                            service.get("deployment_manifest_source")
                            or service.get("source", "baseline")
                        ),
                        "deployment_id": service.get("deployment_id"),
                        "deployment_activated_at": service.get("deployment_activated_at"),
                        "configuration_updated_at": service.get("deployment_activated_at"),
                    },
                }
            )
        return instances

    @staticmethod
    def _snapshot_sort_value(*, item: dict[str, Any], sort_by: str) -> tuple[int, str]:
        if sort_by == "source":
            metadata = item.get("metadata")
            if isinstance(metadata, dict):
                value = str(metadata.get("deployment_source", "") or item.get("source", "") or "")
            else:
                value = str(item.get("source", "") or "")
        else:
            value = str(item.get(sort_by, "") or "")
        return (0 if value else 1, value)

    @staticmethod
    def _parse_running_filter(raw: str) -> bool | None:
        normalized = raw.strip().lower()
        if not normalized:
            return None
        if normalized in {"1", "true", "yes", "y", "on"}:
            return True
        if normalized in {"0", "false", "no", "n", "off"}:
            return False
        raise ValueError("running must be one of: true, false")

    def compare(self, fingerprint: dict[str, Any]) -> dict[str, Any]:
        targets_raw = fingerprint.get("services")
        if not isinstance(targets_raw, list):
            targets_raw = fingerprint.get("instances")
        if not isinstance(targets_raw, list):
            raise ValueError("drift compare payload must include 'services' or 'instances' list")

        snapshot = self.snapshot()
        instances = snapshot.get("instances", [])
        if not isinstance(instances, list):
            instances = []

        by_name: dict[str, dict[str, Any]] = {}
        by_port: dict[int, list[dict[str, Any]]] = {}
        for item in instances:
            name = str(item.get("service", "")).strip().lower()
            if name:
                by_name[name] = item
            for port in _coerce_port_values(item.get("ports")):
                by_port.setdefault(port, []).append(item)

        results: list[dict[str, Any]] = []
        for target_raw in targets_raw:
            if not isinstance(target_raw, dict):
                continue
            target = dict(target_raw)
            expected_name = str(target.get("service") or target.get("name") or "").strip().lower()
            expected_ports = _coerce_port_values(target.get("ports"))
            if not expected_ports:
                expected_ports = _coerce_port_values(target.get("port"))

            matched = by_name.get(expected_name) if expected_name else None
            if matched is None and expected_ports:
                for port in expected_ports:
                    candidates = by_port.get(port, [])
                    if candidates:
                        matched = candidates[0]
                        break

            scores: dict[str, float] = {}

            expected_protocol = str(target.get("protocol", "")).strip().lower()
            if expected_protocol:
                actual_protocol = str((matched or {}).get("protocol", "")).strip().lower()
                scores["protocol_match"] = 1.0 if actual_protocol == expected_protocol else 0.0

            expected_banner = str(target.get("banner", "")).strip()
            if expected_banner:
                actual_banner = str((matched or {}).get("banner", "")).strip()
                scores["banner_match"] = 1.0 if actual_banner == expected_banner else 0.0

            if expected_ports:
                actual_ports = set(_coerce_port_values((matched or {}).get("ports")))
                scores["port_match"] = 1.0 if set(expected_ports).issubset(actual_ports) else 0.0

            expected_hostname = str(target.get("hostname", "")).strip().lower()
            if expected_hostname:
                actual_hostname = str((matched or {}).get("hostname", "")).strip().lower()
                scores["hostname_match"] = 1.0 if actual_hostname == expected_hostname else 0.0

            expected_os = str(target.get("os_fingerprint", "")).strip().lower()
            if expected_os:
                actual_os = str((matched or {}).get("os_fingerprint", "")).strip().lower()
                scores["os_match"] = 1.0 if actual_os == expected_os else 0.0

            expected_ssl = str(target.get("ssl_fingerprint", "")).strip().lower()
            if expected_ssl:
                actual_ssl = str((matched or {}).get("ssl_fingerprint", "")).strip().lower()
                scores["ssl_match"] = 1.0 if actual_ssl == expected_ssl else 0.0

            expected_timing = target.get("timing")
            if isinstance(expected_timing, dict) and expected_timing:
                actual_timing = dict((matched or {}).get("timing", {}))
                if all(actual_timing.get(key) == value for key, value in expected_timing.items()):
                    scores["timing_match"] = 1.0
                else:
                    scores["timing_match"] = 0.0

            if scores:
                believability_score = round(sum(scores.values()) / len(scores), 6)
            else:
                believability_score = 0.0

            results.append(
                {
                    "target": target,
                    "matched": matched is not None,
                    "matched_service": (matched or {}).get("service"),
                    "scores": scores,
                    "believability_score": believability_score,
                }
            )

        aggregate_score = (
            round(sum(item["believability_score"] for item in results) / len(results), 6) if results else 0.0
        )
        below_threshold = aggregate_score < self._alert_threshold
        return {
            "generated_at": _utc_now(),
            "threshold": self._alert_threshold,
            "believability_score": aggregate_score,
            "below_threshold": below_threshold,
            "count": len(results),
            "matches": results,
            "snapshot_count": int(snapshot.get("count", 0) or 0),
        }
