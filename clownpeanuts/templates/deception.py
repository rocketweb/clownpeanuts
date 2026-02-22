"""Deception-as-Code template loader."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import yaml

from clownpeanuts.config.schema import ServiceConfig, TemplateConfig


class DeceptionTemplateLoader:
    def __init__(self, config: TemplateConfig | None = None) -> None:
        self.config = config or TemplateConfig()

    def apply(self, services: list[ServiceConfig]) -> list[ServiceConfig]:
        if not self.config.enabled or not self.config.paths:
            return [replace(service) for service in services]

        overrides = self._read_overrides()
        updated: list[ServiceConfig] = []
        for service in services:
            override = overrides.get(service.name, {})
            nested_config = dict(service.config)
            extra = override.get("config", {})
            if isinstance(extra, dict):
                nested_config.update(extra)
            ports = service.ports
            override_ports = override.get("ports")
            if isinstance(override_ports, list) and all(isinstance(item, int) for item in override_ports):
                ports = [int(item) for item in override_ports]
            updated.append(
                ServiceConfig(
                    name=service.name,
                    module=str(override.get("module", service.module)),
                    enabled=bool(override.get("enabled", service.enabled)),
                    listen_host=str(override.get("listen_host", service.listen_host)),
                    ports=ports,
                    config=nested_config,
                )
            )
        return updated

    def inventory(self) -> dict[str, Any]:
        files: list[dict[str, Any]] = []
        service_names: set[str] = set()
        template_count = 0

        for path in self.config.paths:
            file_path = Path(path)
            entry: dict[str, Any] = {
                "path": str(file_path),
                "exists": file_path.exists(),
                "template_count": 0,
                "services": [],
            }
            if not file_path.exists():
                files.append(entry)
                continue
            try:
                rows = self._read_template_rows(file_path)
            except Exception as exc:
                entry["error"] = str(exc)
                files.append(entry)
                continue
            services = sorted({str(item.get("service", "")).strip() for item in rows if str(item.get("service", "")).strip()})
            entry["template_count"] = len(rows)
            entry["services"] = services
            template_count += len(rows)
            service_names.update(services)
            files.append(entry)

        return {
            "enabled": self.config.enabled,
            "paths": [str(Path(path)) for path in self.config.paths],
            "files": files,
            "template_count": template_count,
            "services": sorted(service_names),
        }

    def validate(self, services: list[ServiceConfig]) -> dict[str, Any]:
        known_services = {service.name for service in services}
        files: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        warnings: list[dict[str, Any]] = []
        valid_template_keys = {"service", "module", "enabled", "listen_host", "ports", "config"}

        for path in self.config.paths:
            file_path = Path(path)
            file_entry: dict[str, Any] = {
                "path": str(file_path),
                "exists": file_path.exists(),
                "template_count": 0,
                "errors": [],
                "warnings": [],
            }

            def add_error(message: str, *, index: int | None = None, service_name: str | None = None) -> None:
                payload: dict[str, Any] = {"path": str(file_path), "message": message}
                if index is not None:
                    payload["index"] = index
                if service_name:
                    payload["service"] = service_name
                file_entry["errors"].append(message)
                errors.append(payload)

            def add_warning(message: str, *, index: int | None = None, service_name: str | None = None) -> None:
                payload: dict[str, Any] = {"path": str(file_path), "message": message}
                if index is not None:
                    payload["index"] = index
                if service_name:
                    payload["service"] = service_name
                file_entry["warnings"].append(message)
                warnings.append(payload)

            if not file_path.exists():
                add_warning("template file not found")
                files.append(file_entry)
                continue

            try:
                raw = self._read_template_document(file_path)
            except Exception as exc:
                add_error(f"failed to read template file: {exc}")
                files.append(file_entry)
                continue

            if "__invalid_root__" in raw:
                add_error("template file root must be an object")
                files.append(file_entry)
                continue

            templates_raw = raw.get("templates", [])
            if templates_raw is None:
                templates_raw = []
            if not isinstance(templates_raw, list):
                add_error("'templates' must be a list")
                files.append(file_entry)
                continue

            file_entry["template_count"] = len(templates_raw)
            seen_service_rows: dict[str, int] = {}

            for index, row_item in enumerate(templates_raw, start=1):
                if not isinstance(row_item, dict):
                    add_error("template row must be an object", index=index)
                    continue
                row = dict(row_item)
                unknown_fields = sorted({str(key) for key in row if str(key) not in valid_template_keys})
                if unknown_fields:
                    add_warning(
                        f"unknown template fields ignored: {', '.join(unknown_fields)}",
                        index=index,
                    )

                service_name = str(row.get("service", "")).strip()
                if not service_name:
                    add_error("template row requires non-empty 'service'", index=index)
                    continue

                prior_row = seen_service_rows.get(service_name)
                if prior_row is not None:
                    add_warning(
                        f"duplicate service override for '{service_name}' (row {prior_row} overridden by row {index})",
                        index=index,
                        service_name=service_name,
                    )
                else:
                    seen_service_rows[service_name] = index

                if service_name not in known_services:
                    add_warning(
                        f"service '{service_name}' is not present in config.services",
                        index=index,
                        service_name=service_name,
                    )

                module = row.get("module")
                if module is not None and (not isinstance(module, str) or not module.strip()):
                    add_error(
                        "module override must be a non-empty string",
                        index=index,
                        service_name=service_name,
                    )

                enabled = row.get("enabled")
                if enabled is not None and not isinstance(enabled, bool):
                    add_error(
                        "enabled override must be a boolean",
                        index=index,
                        service_name=service_name,
                    )

                listen_host = row.get("listen_host")
                if listen_host is not None and (not isinstance(listen_host, str) or not listen_host.strip()):
                    add_error(
                        "listen_host override must be a non-empty string",
                        index=index,
                        service_name=service_name,
                    )

                ports = row.get("ports")
                if ports is not None:
                    if not isinstance(ports, list):
                        add_error(
                            "ports override must be a list of integers in range 1-65535",
                            index=index,
                            service_name=service_name,
                        )
                    elif any(not isinstance(item, int) or item < 1 or item > 65535 for item in ports):
                        add_error(
                            "ports override must be a list of integers in range 1-65535",
                            index=index,
                            service_name=service_name,
                        )

                nested_config = row.get("config")
                if nested_config is not None and not isinstance(nested_config, dict):
                    add_error(
                        "config override must be an object",
                        index=index,
                        service_name=service_name,
                    )

            files.append(file_entry)

        return {
            "enabled": self.config.enabled,
            "paths": [str(Path(path)) for path in self.config.paths],
            "service_catalog": sorted(known_services),
            "files": files,
            "errors": errors,
            "warnings": warnings,
            "error_count": len(errors),
            "warning_count": len(warnings),
            "ok": len(errors) == 0,
        }

    def _read_overrides(self) -> dict[str, dict[str, Any]]:
        merged: dict[str, dict[str, Any]] = {}
        for path in self.config.paths:
            file_path = Path(path)
            if not file_path.exists():
                continue
            for item in self._read_template_rows(file_path):
                if not isinstance(item, dict):
                    continue
                service = str(item.get("service", "")).strip()
                if not service:
                    continue
                current = merged.get(service, {})
                current.update(item)
                merged[service] = current
        return merged

    @staticmethod
    def _read_template_rows(file_path: Path) -> list[dict[str, Any]]:
        raw = DeceptionTemplateLoader._read_template_document(file_path)
        if "__invalid_root__" in raw:
            return []
        templates = raw.get("templates", [])
        if not isinstance(templates, list):
            return []
        rows: list[dict[str, Any]] = []
        for item in templates:
            if isinstance(item, dict):
                rows.append(dict(item))
        return rows

    @staticmethod
    def _read_template_document(file_path: Path) -> dict[str, Any]:
        with file_path.open("r", encoding="utf-8") as handle:
            raw = yaml.safe_load(handle)
        if raw is None:
            return {}
        if isinstance(raw, dict):
            return dict(raw)
        return {"__invalid_root__": raw}
