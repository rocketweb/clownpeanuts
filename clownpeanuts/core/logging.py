"""Structured ECS logging and optional SIEM forwarding."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import ipaddress
import json
import logging
from pathlib import Path
import queue
import socket
import threading
import time
from typing import Callable
from urllib import request
from urllib import parse

from clownpeanuts.config.schema import LoggingConfig, SIEMConfig


def _strip_empty(value: object) -> object | None:
    if isinstance(value, dict):
        cleaned = {key: _strip_empty(item) for key, item in value.items()}
        return {key: item for key, item in cleaned.items() if item is not None} or None
    if isinstance(value, list):
        cleaned_list = [_strip_empty(item) for item in value]
        return [item for item in cleaned_list if item is not None] or None
    if value in ("", None):
        return None
    return value


class ECSJsonFormatter(logging.Formatter):
    def __init__(self, service_name: str = "clownpeanuts") -> None:
        super().__init__()
        self.service_name = service_name

    def format(self, record: logging.LogRecord) -> str:
        timestamp = datetime.fromtimestamp(record.created, UTC).isoformat(timespec="microseconds")
        payload: dict[str, object] = {
            "@timestamp": timestamp,
            "message": record.getMessage(),
            "log": {
                "level": record.levelname.lower(),
                "logger": record.name,
            },
            "service": {
                "name": getattr(record, "service_name", self.service_name),
            },
            "event": {
                "kind": "event",
                "category": getattr(record, "event_category", "network"),
                "action": getattr(record, "event_action", None),
                "type": getattr(record, "event_type", None),
                "outcome": getattr(record, "event_outcome", None),
            },
            "session": {
                "id": getattr(record, "session_id", None),
            },
            "source": {
                "ip": getattr(record, "source_ip", None),
                "port": getattr(record, "source_port", None),
            },
            "client": {
                "address": getattr(record, "client_address", None),
            },
            "observer": {
                "vendor": "clownpeanuts",
                "product": "clownpeanuts",
            },
            "clownpeanuts": {
                "service": getattr(record, "service", None),
                "payload": getattr(record, "payload", None),
            },
        }
        cleaned = _strip_empty(payload) or {}
        return json.dumps(cleaned, separators=(",", ":"))


class SIEMHandler(logging.Handler):
    _DEAD_LETTER_MAX_BYTES = 50 * 1024 * 1024
    _DEAD_LETTER_MAX_FILES = 3
    _HTTP_ENDPOINT_VALIDATION_TTL_SECONDS = 30.0

    def __init__(self, config: SIEMConfig, formatter: logging.Formatter) -> None:
        super().__init__()
        self.config = config
        self.setFormatter(formatter)
        self._disabled = not bool(config.endpoint)
        self._queue: queue.Queue[str] = queue.Queue(maxsize=config.max_queue_size)
        self._stop_event = threading.Event()
        self._dead_letter_lock = threading.Lock()
        self._worker: threading.Thread | None = None
        self._udp_socket: socket.socket | None = None
        self._udp_target: tuple[str, int] | None = None
        self._http_endpoint_validated_ips: set[str] = set()
        self._http_endpoint_validation_expires_at_monotonic = 0.0

        if not self._disabled and config.transport == "udp":
            host, _, port = config.endpoint.rpartition(":")
            if not host or not port:
                raise ValueError("UDP SIEM endpoint must be host:port")
            self._udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._udp_target = (host, int(port))
        if not self._disabled:
            self._worker = threading.Thread(target=self._run_worker, name="siem-shipper", daemon=True)
            self._worker.start()

    def emit(self, record: logging.LogRecord) -> None:
        if self._disabled:
            return
        try:
            formatted = self.format(record)
            self._queue.put_nowait(formatted)
        except queue.Full:
            self._write_dead_letter(
                payloads=[formatted],
                error_message="siem queue full",
            )
        except Exception:
            self.handleError(record)

    def _run_worker(self) -> None:
        batch: list[str] = []
        deadline = time.monotonic() + self.config.flush_interval_seconds

        while True:
            if self._stop_event.is_set() and self._queue.empty() and not batch:
                return

            timeout = max(0.01, deadline - time.monotonic())
            try:
                payload = self._queue.get(timeout=timeout)
                batch.append(payload)
                if len(batch) >= self.config.batch_size:
                    self._flush_batch(batch)
                    batch.clear()
                    deadline = time.monotonic() + self.config.flush_interval_seconds
            except queue.Empty:
                if batch:
                    self._flush_batch(batch)
                    batch.clear()
                deadline = time.monotonic() + self.config.flush_interval_seconds

    def _flush_batch(self, payloads: list[str]) -> None:
        if not payloads:
            return
        last_error: Exception | None = None
        for attempt in range(self.config.max_retries + 1):
            try:
                self._send_batch(payloads)
                return
            except Exception as exc:
                last_error = exc
                if attempt >= self.config.max_retries:
                    break
                delay = self.config.retry_backoff_seconds * (2**attempt)
                time.sleep(delay)
        self._write_dead_letter(
            payloads=payloads,
            error_message=str(last_error or "unknown SIEM send error"),
        )

    def _send_batch(self, payloads: list[str]) -> None:
        if self.config.transport == "udp":
            self._send_batch_udp(payloads)
            return
        self._send_batch_http(payloads)

    def _send_batch_http(self, payloads: list[str]) -> None:
        self._validate_http_endpoint()
        body = ("\n".join(payloads) + "\n").encode("utf-8")
        headers = {"Content-Type": "application/x-ndjson", **self.config.headers}
        req = request.Request(
            self.config.endpoint,
            data=body,
            headers=headers,
            method="POST",
        )
        with request.urlopen(req, timeout=self.config.timeout_seconds):
            return

    def _validate_http_endpoint(self) -> None:
        if time.monotonic() < self._http_endpoint_validation_expires_at_monotonic:
            return
        parsed = parse.urlparse(self.config.endpoint)
        host = (parsed.hostname or "").strip()
        if not host:
            return
        port = int(parsed.port or (443 if parsed.scheme.lower() == "https" else 80))
        try:
            addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError:
            # Resolve failures are handled by urlopen; do not block here.
            return
        resolved_public_ips: set[str] = set()
        for resolved in addresses:
            ip_raw = str(resolved[4][0]).strip()
            try:
                ip = ipaddress.ip_address(ip_raw)
            except ValueError:
                continue
            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_multicast
                or ip.is_reserved
                or ip.is_unspecified
            ):
                raise ValueError("siem endpoint resolves to a private or non-routable address")
            resolved_public_ips.add(str(ip))
        if (
            self._http_endpoint_validated_ips
            and resolved_public_ips
            and not resolved_public_ips.issubset(self._http_endpoint_validated_ips)
        ):
            raise ValueError("siem endpoint DNS resolution drift detected")
        if resolved_public_ips:
            self._http_endpoint_validated_ips = set(resolved_public_ips)
        self._http_endpoint_validation_expires_at_monotonic = (
            time.monotonic() + self._HTTP_ENDPOINT_VALIDATION_TTL_SECONDS
        )

    def _send_batch_udp(self, payloads: list[str]) -> None:
        if not self._udp_socket or not self._udp_target:
            raise RuntimeError("udp SIEM target is not configured")
        for payload in payloads:
            self._udp_socket.sendto(payload.encode("utf-8"), self._udp_target)

    def _write_dead_letter(self, *, payloads: list[str], error_message: str) -> None:
        if not self.config.dead_letter_path:
            return
        path = Path(self.config.dead_letter_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        failed_at = datetime.now(UTC).isoformat(timespec="microseconds")
        with self._dead_letter_lock:
            self._rotate_dead_letter_locked(path)
            with path.open("a", encoding="utf-8") as handle:
                for payload in payloads:
                    handle.write(
                        json.dumps(
                            {
                                "failed_at": failed_at,
                                "error": error_message,
                                "transport": self.config.transport,
                                "endpoint": self.config.endpoint,
                                "payload": payload,
                            },
                            separators=(",", ":"),
                        )
                    )
                    handle.write("\n")

    def _rotate_dead_letter_locked(self, path: Path) -> None:
        try:
            size_bytes = path.stat().st_size if path.exists() else 0
        except OSError:
            return
        if size_bytes < self._DEAD_LETTER_MAX_BYTES:
            return
        oldest = path.with_name(f"{path.name}.{self._DEAD_LETTER_MAX_FILES}")
        if oldest.exists():
            oldest.unlink(missing_ok=True)
        for index in range(self._DEAD_LETTER_MAX_FILES - 1, 0, -1):
            source = path.with_name(f"{path.name}.{index}")
            destination = path.with_name(f"{path.name}.{index + 1}")
            if source.exists():
                source.replace(destination)
        if path.exists():
            path.replace(path.with_name(f"{path.name}.1"))

    def close(self) -> None:
        if not self._disabled and self._worker:
            self._stop_event.set()
            self._worker.join(timeout=max(1.0, self.config.flush_interval_seconds * 2))
        if self._udp_socket:
            self._udp_socket.close()
            self._udp_socket = None
        super().close()


def _sink_handler(config: LoggingConfig, formatter: logging.Formatter) -> logging.Handler:
    if config.sink == "file":
        file_path = config.file_path or "logs/clownpeanuts.log"
        log_file = Path(file_path)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        handler: logging.Handler = logging.FileHandler(log_file, encoding="utf-8")
    else:
        handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    return handler


def configure_logging(config: LoggingConfig, force: bool = False) -> None:
    root = logging.getLogger("clownpeanuts")
    if getattr(root, "_clownpeanuts_configured", False) and not force:
        return

    formatter = ECSJsonFormatter(service_name=config.service_name)
    root.setLevel(config.level)
    for existing in list(root.handlers):
        existing.close()
    root.handlers.clear()
    root.addHandler(_sink_handler(config, formatter))

    if config.siem.enabled:
        root.addHandler(SIEMHandler(config.siem, formatter))

    root.propagate = False
    setattr(root, "_clownpeanuts_configured", True)


def get_logger(name: str, level: str = "INFO") -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    if name.startswith("clownpeanuts"):
        parent = logging.getLogger("clownpeanuts")
        if parent.handlers:
            logger.setLevel(level)
            logger.propagate = True
            return logger

    handler = logging.StreamHandler()
    handler.setFormatter(ECSJsonFormatter())
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False
    return logger


def emit_metric(
    logger: logging.Logger,
    *,
    name: str,
    value: float,
    service: str = "intel",
    payload: dict[str, object] | None = None,
    level: str = "INFO",
) -> None:
    metric_name = name.strip() or "metric"
    metric_value = float(value)
    metric_payload: dict[str, object] = {"metric_name": metric_name, "metric_value": metric_value}
    if payload:
        metric_payload.update(payload)
    logger.log(
        getattr(logging, level.upper(), logging.INFO),
        f"metric:{metric_name}",
        extra={
            "service": service,
            "event_action": metric_name,
            "event_category": "metric",
            "event_type": "info",
            "event_outcome": "success",
            "payload": metric_payload,
        },
    )


@dataclass(slots=True)
class EventLogger:
    logger: logging.Logger
    service_name: str
    publish_hook: Callable[[dict[str, object]], None] | None = None

    def emit(
        self,
        *,
        message: str,
        service: str,
        action: str,
        session_id: str | None = None,
        source_ip: str | None = None,
        source_port: int | None = None,
        outcome: str | None = None,
        event_type: str | None = None,
        payload: dict[str, object] | None = None,
        level: str = "INFO",
    ) -> None:
        event_payload: dict[str, object] = {
            "service_name": self.service_name,
            "service": service,
            "action": action,
            "event_type": event_type or "",
            "outcome": outcome or "",
            "session_id": session_id or "",
            "source_ip": source_ip or "",
            "source_port": source_port or 0,
            "message": message,
            "payload": payload or {},
            "timestamp": datetime.now(UTC).isoformat(timespec="microseconds"),
            "level": level.upper(),
        }
        self.logger.log(
            getattr(logging, level.upper(), logging.INFO),
            message,
            extra={
                "service_name": event_payload["service_name"],
                "service": event_payload["service"],
                "event_action": event_payload["action"],
                "event_category": "network",
                "event_type": event_payload["event_type"] or None,
                "event_outcome": event_payload["outcome"] or None,
                "session_id": event_payload["session_id"] or None,
                "source_ip": event_payload["source_ip"] or None,
                "source_port": event_payload["source_port"] or None,
                "payload": event_payload["payload"],
            },
        )
        if self.publish_hook:
            try:
                self.publish_hook(event_payload)
            except Exception:
                return
