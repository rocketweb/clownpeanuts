"""Alert routing with delivery adapters and throttling."""

from __future__ import annotations

from collections import deque
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
import ipaddress
import re
import time
from typing import Any

from clownpeanuts.alerts.discord import send_discord
from clownpeanuts.alerts.email import send_email
from clownpeanuts.alerts.pagerduty import send_pagerduty
from clownpeanuts.alerts.slack import send_slack
from clownpeanuts.alerts.syslog import send_syslog
from clownpeanuts.alerts.webhook import send_webhook
from clownpeanuts.config.schema import AlertDestinationConfig, AlertsConfig, RedTeamConfig
from clownpeanuts.core.logging import emit_metric, get_logger


_SEVERITY_ORDER = {"low": 10, "medium": 20, "high": 30, "critical": 40}
_BANDIT_DEGRADATION_WINDOW = 3
_BANDIT_DEGRADATION_DROP = 0.2
_BANDIT_COLLAPSE_THRESHOLD = 0.2
_MAX_THROTTLE_KEYS = 5000


def _normalize_filter(value: str) -> str:
    normalized = value.strip().lower().replace("-", "_").replace(" ", "_")
    return "_".join(part for part in normalized.split("_") if part)


@dataclass(slots=True)
class AlertEvent:
    timestamp: str
    severity: str
    title: str
    summary: str
    service: str
    action: str
    payload: dict[str, Any]
    sent_to: list[str]


class AlertRouter:
    def __init__(self, config: AlertsConfig | None = None, red_team: RedTeamConfig | None = None) -> None:
        self.config = config or AlertsConfig()
        self.red_team = red_team or RedTeamConfig()
        self.logger = get_logger("clownpeanuts.alerts")
        self._recent: deque[AlertEvent] = deque(maxlen=200)
        self._bandit_observations: deque[dict[str, Any]] = deque(maxlen=200)
        self._last_sent: dict[str, float] = {}
        self._executor = ThreadPoolExecutor(max_workers=8, thread_name_prefix="cp-alert")

    def close(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            return

    def handle_event(self, envelope: dict[str, Any]) -> None:
        payload = envelope.get("payload", {})
        if not isinstance(payload, dict):
            return
        severity = self._severity_from_payload(payload)
        if _SEVERITY_ORDER.get(severity, 0) < _SEVERITY_ORDER.get(self.config.min_severity, 20):
            return
        title = f"{payload.get('service','unknown')}:{payload.get('action','event')}"
        summary = self._summary_from_payload(payload)
        self.send_alert(
            severity=severity,
            title=title,
            summary=summary,
            service=str(payload.get("service", "unknown")),
            action=str(payload.get("action", "event")),
            payload=payload,
        )

    def send_intel_alert(
        self,
        *,
        report: dict[str, Any],
        bandit_metrics: dict[str, Any] | None = None,
    ) -> None:
        totals = report.get("totals", {})
        if not isinstance(totals, dict):
            return
        sessions = int(totals.get("sessions", 0) or 0)
        events = int(totals.get("events", 0) or 0)
        techniques = report.get("techniques", [])
        if not isinstance(techniques, list):
            techniques = []
        if sessions < 1:
            return
        severity = "medium"
        if events > 40 or len(techniques) > 5:
            severity = "high"
        if events > 100:
            severity = "critical"
        if _SEVERITY_ORDER.get(severity, 0) < _SEVERITY_ORDER.get(self.config.min_severity, 20):
            severity = "low"
        if _SEVERITY_ORDER.get(severity, 0) >= _SEVERITY_ORDER.get(self.config.min_severity, 20):
            self.send_alert(
                severity=severity,
                title="intelligence_summary",
                summary=f"sessions={sessions} events={events} techniques={len(techniques)}",
                service="intel",
                action="summary",
                payload={"totals": totals, "technique_count": len(techniques)},
            )
        self.record_bandit_metrics(report=report, metrics=bandit_metrics)

    def send_alert(
        self,
        *,
        severity: str,
        title: str,
        summary: str,
        service: str,
        action: str,
        payload: dict[str, Any],
    ) -> AlertEvent | None:
        if not self.config.enabled:
            return None
        if self.red_team.enabled and self.red_team.suppress_external_alerts and self._is_red_team_payload(payload):
            self.logger.info("suppressed red-team alert", extra={"service": "alerts", "payload": payload})
            return None

        severity = severity.strip().lower() or "low"
        alert_payload = {
            "timestamp": datetime.now(UTC).isoformat(timespec="microseconds"),
            "severity": severity,
            "title": title,
            "summary": summary,
            "service": service,
            "action": action,
            "payload": payload,
        }
        delivered: list[str] = []
        eligible_destinations: list[tuple[AlertDestinationConfig, str]] = []
        for destination in self.config.destinations:
            throttle_key = f"{destination.name}:{title}:{severity}"
            blocked = self._route_block_reason(
                destination=destination,
                severity=severity,
                service=service,
                action=action,
                throttle_key=throttle_key,
                apply_throttle=True,
            )
            if blocked is not None:
                continue
            eligible_destinations.append((destination, throttle_key))

        if eligible_destinations:
            submitted: list[tuple[AlertDestinationConfig, str, Future[None]]] = []
            for destination, throttle_key in eligible_destinations:
                future = self._executor.submit(self._deliver, destination=destination, alert=alert_payload)
                submitted.append((destination, throttle_key, future))
            for destination, throttle_key, future in submitted:
                try:
                    future.result()
                    delivered.append(destination.name)
                    self._last_sent[throttle_key] = time.monotonic()
                    self._prune_throttle_cache()
                except Exception as exc:
                    self.logger.warning(
                        "alert delivery failed",
                        extra={
                            "service": "alerts",
                            "payload": {
                                "destination": destination.name,
                                "type": destination.destination_type,
                                "error": str(exc),
                            },
                        },
                    )
        event = AlertEvent(
            timestamp=str(alert_payload["timestamp"]),
            severity=severity,
            title=title,
            summary=summary,
            service=service,
            action=action,
            payload=dict(payload),
            sent_to=delivered,
        )
        self._recent.append(event)
        return event

    def route_preview(
        self,
        *,
        severity: str = "medium",
        service: str = "ops",
        action: str = "alert_test",
        title: str = "manual_alert_test",
        apply_throttle: bool = False,
    ) -> dict[str, Any]:
        severity = severity.strip().lower() or "low"
        routes: list[dict[str, Any]] = []
        for destination in self.config.destinations:
            throttle_key = f"{destination.name}:{title}:{severity}"
            blocked: str | None = None
            if not self.config.enabled:
                blocked = "alerts_disabled"
            else:
                blocked = self._route_block_reason(
                    destination=destination,
                    severity=severity,
                    service=service,
                    action=action,
                    throttle_key=throttle_key,
                    apply_throttle=apply_throttle,
                )
            routes.append(
                {
                    "name": destination.name,
                    "type": destination.destination_type,
                    "enabled": destination.enabled,
                    "deliver": blocked is None,
                    "reason": blocked or "",
                    "effective_min_severity": self._effective_min_severity(destination),
                    "include_services": list(destination.include_services),
                    "include_actions": list(destination.include_actions),
                    "exclude_actions": list(destination.exclude_actions),
                }
            )
        deliver_count = sum(1 for route in routes if route["deliver"])
        return {
            "alerts_enabled": self.config.enabled,
            "severity": severity,
            "service": service,
            "action": action,
            "title": title,
            "apply_throttle": apply_throttle,
            "destination_count": len(routes),
            "deliver_count": deliver_count,
            "blocked_count": len(routes) - deliver_count,
            "routes": routes,
        }

    def snapshot(self) -> dict[str, Any]:
        return {
            "enabled": self.config.enabled,
            "destinations": [
                {
                    "name": destination.name,
                    "type": destination.destination_type,
                    "enabled": destination.enabled,
                    "endpoint_set": bool(destination.endpoint),
                    "effective_min_severity": self._effective_min_severity(destination),
                    "include_services": list(destination.include_services),
                    "include_actions": list(destination.include_actions),
                    "exclude_actions": list(destination.exclude_actions),
                }
                for destination in self.config.destinations
            ],
            "recent": [
                {
                    "timestamp": item.timestamp,
                    "severity": item.severity,
                    "title": item.title,
                    "summary": item.summary,
                    "service": item.service,
                    "action": item.action,
                    "sent_to": item.sent_to,
                }
                for item in list(self._recent)
            ],
            "bandit_observability": self.bandit_observability(limit=20),
        }

    def bandit_observability(self, *, limit: int = 30) -> dict[str, Any]:
        window = max(1, int(limit))
        history = list(self._bandit_observations)[-window:]
        current = history[-1] if history else {}
        degraded_count = sum(1 for item in history if bool(item.get("sustained_degradation")))
        collapse_count = sum(1 for item in history if bool(item.get("reward_collapse")))
        return {
            "sample_count": len(history),
            "degraded_count": degraded_count,
            "collapse_count": collapse_count,
            "current": current,
            "history": history,
        }

    def record_bandit_metrics(
        self,
        *,
        report: dict[str, Any],
        metrics: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        totals = report.get("totals", {})
        if not isinstance(totals, dict):
            return None
        sessions = int(totals.get("sessions", 0) or 0)
        metrics_payload = metrics if isinstance(metrics, dict) else {}
        if sessions < 1 and not metrics_payload:
            return None

        reward_avg = self._bounded_unit_value(
            metrics_payload.get("reward_avg"),
            default=float(totals.get("bandit_reward_avg", 0.0) or 0.0),
        )
        exploration_ratio = self._bounded_unit_value(metrics_payload.get("exploration_ratio"), default=0.0)
        decision_count = max(0, int(metrics_payload.get("decision_count", 0) or 0))
        reward_count = max(0, int(metrics_payload.get("reward_count", 0) or 0))

        previous = self._bandit_observations[-1] if self._bandit_observations else {}
        previous_reward = float(previous.get("reward_avg", reward_avg) or reward_avg)
        reward_delta = round(reward_avg - previous_reward, 6)
        trend_direction = "flat"
        if reward_delta > 0.01:
            trend_direction = "up"
        elif reward_delta < -0.01:
            trend_direction = "down"

        reward_window = [
            float(item.get("reward_avg", 0.0) or 0.0)
            for item in list(self._bandit_observations)[-(_BANDIT_DEGRADATION_WINDOW - 1) :]
        ]
        reward_window.append(reward_avg)
        rolling_avg = round(sum(reward_window) / len(reward_window), 6) if reward_window else 0.0
        sustained_degradation, degradation_percent = self._reward_degradation_state(reward_window)
        reward_collapse = reward_avg <= _BANDIT_COLLAPSE_THRESHOLD and reward_count >= _BANDIT_DEGRADATION_WINDOW

        observation = {
            "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
            "exploration_ratio": round(exploration_ratio, 6),
            "reward_avg": round(reward_avg, 6),
            "reward_delta": reward_delta,
            "reward_trend": trend_direction,
            "reward_rolling_avg": rolling_avg,
            "decision_count": decision_count,
            "reward_count": reward_count,
            "sustained_degradation": sustained_degradation,
            "degradation_percent": degradation_percent,
            "reward_collapse": reward_collapse,
        }
        self._bandit_observations.append(observation)

        emit_metric(
            self.logger,
            name="bandit_exploration_ratio",
            value=exploration_ratio,
            service="intel",
            payload={"decision_count": decision_count},
        )
        emit_metric(
            self.logger,
            name="bandit_reward_avg",
            value=reward_avg,
            service="intel",
            payload={"reward_count": reward_count},
        )
        emit_metric(
            self.logger,
            name="bandit_reward_delta",
            value=reward_delta,
            service="intel",
            payload={"trend": trend_direction},
        )

        if sustained_degradation or reward_collapse:
            severity = "critical" if reward_collapse else "high"
            summary = (
                "bandit reward degraded "
                f"reward_avg={reward_avg:.3f} "
                f"exploration_ratio={exploration_ratio:.3f} "
                f"drop={degradation_percent:.1f}%"
            )
            self.send_alert(
                severity=severity,
                title="bandit_reward_degradation",
                summary=summary,
                service="intel",
                action="bandit_degradation",
                payload={"bandit": observation},
            )
        return observation

    @staticmethod
    def _bounded_unit_value(value: Any, *, default: float = 0.0) -> float:
        try:
            candidate = float(value)
        except (TypeError, ValueError):
            candidate = float(default)
        return max(0.0, min(1.0, candidate))

    @staticmethod
    def _reward_degradation_state(reward_window: list[float]) -> tuple[bool, float]:
        if len(reward_window) < _BANDIT_DEGRADATION_WINDOW:
            return (False, 0.0)
        baseline = (float(reward_window[0]) + float(reward_window[1])) / 2.0
        latest = float(reward_window[-1])
        if baseline <= 0.0:
            return (False, 0.0)
        degradation = max(0.0, (baseline - latest) / baseline)
        descending = latest < float(reward_window[-2]) <= float(reward_window[-3])
        sustained = descending and degradation >= _BANDIT_DEGRADATION_DROP
        return (sustained, round(degradation * 100.0, 3))

    def _route_block_reason(
        self,
        *,
        destination: AlertDestinationConfig,
        severity: str,
        service: str,
        action: str,
        throttle_key: str,
        apply_throttle: bool,
    ) -> str | None:
        if not destination.enabled:
            return "disabled"

        effective_min = self._effective_min_severity(destination)
        if _SEVERITY_ORDER.get(severity, 0) < _SEVERITY_ORDER.get(effective_min, 20):
            return f"severity_below_{effective_min}"

        normalized_service = _normalize_filter(service)
        include_services = set(destination.include_services)
        if include_services and normalized_service not in include_services:
            return "service_not_included"

        normalized_action = _normalize_filter(action)
        include_actions = set(destination.include_actions)
        exclude_actions = set(destination.exclude_actions)
        if include_actions and normalized_action not in include_actions:
            return "action_not_included"
        if exclude_actions and normalized_action in exclude_actions:
            return "action_excluded"

        if apply_throttle and self._is_throttled(throttle_key):
            return "throttled"
        return None

    def _effective_min_severity(self, destination: AlertDestinationConfig) -> str:
        candidate = destination.min_severity.strip().lower()
        if candidate in _SEVERITY_ORDER:
            return candidate
        fallback = self.config.min_severity.strip().lower()
        if fallback in _SEVERITY_ORDER:
            return fallback
        return "medium"

    def _is_throttled(self, key: str) -> bool:
        if self.config.throttle_seconds <= 0:
            return False
        last = self._last_sent.get(key)
        if last is None:
            return False
        return (time.monotonic() - last) < float(self.config.throttle_seconds)

    def _prune_throttle_cache(self) -> None:
        if len(self._last_sent) <= _MAX_THROTTLE_KEYS:
            return
        now = time.monotonic()
        stale_after_seconds = max(600.0, float(self.config.throttle_seconds) * 4.0)
        stale_keys = [key for key, stamp in self._last_sent.items() if (now - stamp) >= stale_after_seconds]
        for key in stale_keys:
            self._last_sent.pop(key, None)
        while len(self._last_sent) > _MAX_THROTTLE_KEYS:
            oldest_key = next(iter(self._last_sent))
            self._last_sent.pop(oldest_key, None)

    def _deliver(self, *, destination: AlertDestinationConfig, alert: dict[str, Any]) -> None:
        if not destination.endpoint and destination.destination_type not in {"pagerduty"}:
            return
        if destination.destination_type == "webhook":
            send_webhook(endpoint=destination.endpoint, payload=alert)
            return
        if destination.destination_type == "slack":
            send_slack(endpoint=destination.endpoint, payload=alert)
            return
        if destination.destination_type == "discord":
            send_discord(endpoint=destination.endpoint, payload=alert)
            return
        if destination.destination_type == "syslog":
            send_syslog(endpoint=destination.endpoint, payload=alert)
            return
        if destination.destination_type == "email":
            send_email(endpoint=destination.endpoint, payload=alert, metadata=destination.metadata)
            return
        if destination.destination_type == "pagerduty":
            send_pagerduty(
                endpoint=destination.endpoint,
                payload=alert,
                token=destination.token,
                metadata=destination.metadata,
            )
            return
        raise RuntimeError(f"unsupported destination type '{destination.destination_type}'")

    @staticmethod
    def _severity_from_payload(payload: dict[str, Any]) -> str:
        action = str(payload.get("action", "")).lower()
        message = str(payload.get("message", "")).lower()
        service = str(payload.get("service", "")).lower()
        details = payload.get("payload", {})
        text = ""
        if isinstance(details, dict):
            text = " ".join(str(v).lower() for v in details.values())

        if action in {"credential_capture", "auth_attempt"}:
            return "high"
        if action == "service_stop" and "error" in message:
            return "high"
        if re.search(r"(drop table|union select|/etc/passwd|xmrig|curl)", text):
            return "critical"
        if service in {"ssh", "http_admin"} and action in {"command", "http_request"}:
            return "medium"
        return "low"

    @staticmethod
    def _summary_from_payload(payload: dict[str, Any]) -> str:
        service = str(payload.get("service", "unknown"))
        action = str(payload.get("action", "event"))
        details = payload.get("payload", {})
        if isinstance(details, dict):
            command = details.get("command") or details.get("query") or details.get("path")
            if command:
                return f"{service} {action}: {command}"
        return f"{service} {action}"

    def _is_red_team_payload(self, payload: dict[str, Any]) -> bool:
        nested = payload.get("payload", {})
        if isinstance(nested, dict):
            value = nested.get(self.red_team.label)
            if isinstance(value, bool):
                return value
            nested_source_ip = nested.get("source_ip")
            if isinstance(nested_source_ip, str) and self._is_internal_red_team_source(nested_source_ip):
                return True
        payload_source_ip = payload.get("source_ip")
        if isinstance(payload_source_ip, str) and self._is_internal_red_team_source(payload_source_ip):
            return True
        return bool(payload.get(self.red_team.label, False))

    def _is_internal_red_team_source(self, source_ip: str) -> bool:
        candidate = source_ip.strip()
        if not candidate:
            return False
        try:
            ip = ipaddress.ip_address(candidate)
        except ValueError:
            return False
        for cidr in self.red_team.internal_cidrs:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            if ip in network:
                return True
        return False
