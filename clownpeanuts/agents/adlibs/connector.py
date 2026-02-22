"""Connection configuration helpers for optional AD integration."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class ADConnectorConfig:
    ldap_uri: str
    bind_dn: str
    bind_password_env: str
    base_dn: str
    target_ou: str


class ADConnector:
    """Lightweight connector surface used by module readiness and dry-runs."""

    def __init__(self, config: ADConnectorConfig) -> None:
        self._config = config

    def validate(self) -> list[str]:
        issues: list[str] = []
        uri = self._config.ldap_uri.strip().lower()
        if not uri:
            issues.append("ldap_uri is required")
        elif not (uri.startswith("ldap://") or uri.startswith("ldaps://")):
            issues.append("ldap_uri must start with ldap:// or ldaps://")
        if not self._config.bind_dn.strip():
            issues.append("ldap_bind_dn is required")
        if not self._config.bind_password_env.strip():
            issues.append("ldap_bind_password_env is required")
        if not self._config.base_dn.strip():
            issues.append("base_dn is required")
        if not self._config.target_ou.strip():
            issues.append("target_ou is required")
        return issues

    def status(self) -> dict[str, str | bool]:
        issues = self.validate()
        return {
            "ready": not issues,
            "ldap_uri": self._config.ldap_uri.strip(),
            "base_dn": self._config.base_dn.strip(),
            "target_ou": self._config.target_ou.strip(),
            "bind_dn_present": bool(self._config.bind_dn.strip()),
            "bind_password_env_present": bool(self._config.bind_password_env.strip()),
            "issues": "; ".join(issues),
        }
