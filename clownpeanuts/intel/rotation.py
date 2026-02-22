"""Threat-intel-driven bait rotation."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
import ipaddress
import socket
from typing import Any
from urllib import parse
from urllib import request

from clownpeanuts.config.schema import ServiceConfig, ThreatIntelConfig
from clownpeanuts.core.logging import get_logger


class ThreatFeedRotator:
    _PROFILE_BY_DOMAIN = {"ssh": "ssh-heavy", "web": "web-heavy", "db": "db-heavy"}
    _MAX_SOURCE_BYTES = 20_000

    def __init__(self, config: ThreatIntelConfig | None = None) -> None:
        self.config = config or ThreatIntelConfig()
        self.logger = get_logger("clownpeanuts.intel.rotation")
        self._last_profile = "balanced"
        self._last_signal = {"ssh": 0, "web": 0, "db": 0}
        self._last_rotated_at = ""

    @property
    def last_profile(self) -> str:
        return self._last_profile

    def apply(self, services: list[ServiceConfig]) -> list[ServiceConfig]:
        if not self.config.enabled:
            return [replace(service) for service in services]
        signal = self._read_feed_signal()
        self._last_signal = dict(signal)
        profile = self._select_profile(signal)
        self._last_profile = profile
        self._last_rotated_at = datetime.now(UTC).isoformat(timespec="microseconds")
        updated = [replace(service, config=dict(service.config), ports=list(service.ports)) for service in services]

        for service in updated:
            if service.name == "ssh":
                if profile == "ssh-heavy":
                    service.config["auth_failures_before_success"] = 2
                    service.config["banner"] = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
                elif profile == "db-heavy":
                    service.config["auth_failures_before_success"] = 0
            if service.name == "http-admin":
                if profile == "web-heavy":
                    service.config["server_name"] = "nginx/1.22.1"
                elif profile == "db-heavy":
                    service.config["server_name"] = "Apache/2.4.56 (Debian)"
            if service.name in {"mongo-db", "memcached-db"} and profile == "db-heavy":
                service.enabled = True
        self.logger.info(
            "bait profile rotated",
            extra={"service": "intel_rotation", "payload": {"profile": profile, "signal": signal}},
        )
        return updated

    def preview(self) -> dict[str, Any]:
        signal = self._read_feed_signal()
        profile = self._select_profile(signal)
        payload: dict[str, Any] = {
            "enabled": self.config.enabled,
            "strategy": self.config.strategy,
            "feed_sources": len(self.config.feed_urls),
            "selected_profile": profile,
            "signal": signal,
        }
        if self.config.strategy == "seasonal":
            payload["seasonal_profile"] = self._seasonal_profile()
            payload["seasonal_month"] = self.config.seasonal_month_override or datetime.now(UTC).month
        return payload

    def _read_feed_signal(self) -> dict[str, int]:
        signal = {"ssh": 0, "web": 0, "db": 0}
        for source in self.config.feed_urls:
            payload = self._read_source(source)
            lower = payload.lower()
            signal["ssh"] += lower.count("ssh") + lower.count("telnet")
            signal["web"] += lower.count("http") + lower.count("wordpress") + lower.count("phpmyadmin")
            signal["db"] += lower.count("mysql") + lower.count("postgres") + lower.count("redis") + lower.count("mongo")
        return signal

    def _select_profile(self, signal: dict[str, int]) -> str:
        if self.config.strategy == "conservative":
            return "balanced"
        if self.config.strategy == "aggressive":
            winner = max(signal, key=signal.get)
            return self._PROFILE_BY_DOMAIN.get(winner, "balanced")
        if self.config.strategy == "seasonal":
            seasonal_profile = self._seasonal_profile()
            winner = max(signal, key=signal.get)
            winner_score = int(signal.get(winner, 0))
            if winner_score >= 5:
                return self._PROFILE_BY_DOMAIN.get(winner, seasonal_profile)
            return seasonal_profile

        winner = max(signal, key=signal.get)
        if signal[winner] <= 0:
            return "balanced"
        return self._PROFILE_BY_DOMAIN.get(winner, "balanced")

    def _seasonal_profile(self) -> str:
        month = self.config.seasonal_month_override
        if month is None:
            month = datetime.now(UTC).month
        if month in {12, 1, 2}:
            return "ssh-heavy"
        if month in {3, 4, 5}:
            return "web-heavy"
        if month in {6, 7, 8}:
            return "db-heavy"
        return "web-heavy"

    @staticmethod
    def _resolve_public_addresses(host: str, port: int) -> set[str]:
        try:
            addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError:
            return set()
        resolved_public_ips: set[str] = set()
        for resolved in addresses:
            ip_raw = str(resolved[4][0]).strip()
            try:
                ip = ipaddress.ip_address(ip_raw)
            except ValueError:
                return set()
            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_multicast
                or ip.is_reserved
                or ip.is_unspecified
            ):
                return set()
            resolved_public_ips.add(str(ip))
        return resolved_public_ips

    @staticmethod
    def _read_source(source: str) -> str:
        src = source.strip()
        if not src:
            return ""
        if src.startswith("http://") or src.startswith("https://"):
            parsed = parse.urlparse(src)
            if parsed.scheme.lower() != "https":
                return ""
            if parsed.username or parsed.password:
                return ""
            host = (parsed.hostname or "").strip()
            if not host:
                return ""
            port = int(parsed.port or 443)
            initial_addresses = ThreatFeedRotator._resolve_public_addresses(host, port)
            if not initial_addresses:
                return ""
            # Re-resolve immediately before fetch to reduce DNS-rebind drift risk.
            current_addresses = ThreatFeedRotator._resolve_public_addresses(host, port)
            if not current_addresses:
                return ""
            if not current_addresses.issubset(initial_addresses):
                return ""
            try:
                req = request.Request(
                    src,
                    headers={"User-Agent": "clownpeanuts-threat-intel/1.0"},
                    method="GET",
                )
                with request.urlopen(req, timeout=2.0) as response:
                    return response.read(ThreatFeedRotator._MAX_SOURCE_BYTES).decode("utf-8", errors="replace")
            except Exception:
                return ""
        # Local file sources are intentionally rejected to avoid config-driven local file reads.
        return ""

    def snapshot(self) -> dict[str, Any]:
        return {
            "enabled": self.config.enabled,
            "strategy": self.config.strategy,
            "feed_sources": len(self.config.feed_urls),
            "last_profile": self._last_profile,
            "last_signal": self._last_signal,
            "last_rotated_at": self._last_rotated_at,
        }
