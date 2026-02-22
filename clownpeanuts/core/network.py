"""Runtime isolation validation and enforcement gates."""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import shutil
import subprocess

from clownpeanuts.config.schema import NetworkConfig


@dataclass(slots=True)
class IsolationReport:
    outbound_blocked: bool
    warnings: list[str] = field(default_factory=list)
    violations: list[str] = field(default_factory=list)
    applied_rules: list[str] = field(default_factory=list)
    enforced: bool = False

    @property
    def compliant(self) -> bool:
        return not self.violations


class NetworkIsolationError(RuntimeError):
    pass


class NetworkIsolationManager:
    _SUPPORTED_SEGMENTATION = {"vxlan", "wireguard", "none"}
    _APPLY_BACKENDS = {"iptables", "nft", "pfctl"}

    def validate(self, config: NetworkConfig) -> IsolationReport:
        warnings: list[str] = []
        violations: list[str] = []

        if config.segmentation_mode not in self._SUPPORTED_SEGMENTATION:
            violations.append(f"Unsupported segmentation mode '{config.segmentation_mode}'.")

        if config.require_segmentation and config.segmentation_mode == "none":
            violations.append("Segmentation mode 'none' is not allowed when segmentation is required.")

        if config.allow_outbound and not config.allowed_egress:
            violations.append("Outbound traffic requires an explicit egress allowlist.")

        if not config.allow_outbound and config.allowed_egress:
            warnings.append("Egress allowlist is set but outbound traffic is globally blocked.")

        for target in config.allowed_egress:
            if target == "redis":
                continue
            if self._is_valid_host_or_network(target):
                continue
            violations.append(f"Invalid egress target '{target}'.")

        if config.enforce_runtime is False:
            warnings.append("Runtime isolation enforcement is disabled.")
        else:
            if config.verify_host_firewall:
                firewall = self._detect_firewall_backend()
                if not firewall:
                    violations.append("No host firewall backend detected (iptables/nft/pfctl).")
                else:
                    warnings.append(f"Host firewall backend detected: {firewall}.")

            if config.verify_docker_network:
                required_name = config.required_docker_network or "clownpeanuts"
                network_found, diagnostic = self._docker_network_exists(required_name)
                if not network_found:
                    violations.append(f"Required Docker network '{required_name}' not found ({diagnostic}).")
                else:
                    warnings.append(f"Docker network verification passed for '{required_name}'.")

            if config.apply_firewall_rules:
                backend = self._detect_firewall_backend()
                if not backend:
                    violations.append("Cannot apply firewall policy: no firewall backend detected.")
                elif backend not in self._APPLY_BACKENDS:
                    violations.append(f"Unsupported firewall backend for apply mode: {backend}.")

        return IsolationReport(
            outbound_blocked=not config.allow_outbound,
            warnings=warnings,
            violations=violations,
            enforced=False,
        )

    def enforce(self, config: NetworkConfig) -> IsolationReport:
        report = self.validate(config)
        report.enforced = config.enforce_runtime
        if config.enforce_runtime and report.violations:
            details = " ".join(report.violations)
            raise NetworkIsolationError(f"network isolation enforcement failed: {details}")
        if config.enforce_runtime and config.apply_firewall_rules:
            backend = self._detect_firewall_backend()
            if not backend:
                raise NetworkIsolationError(
                    "network isolation enforcement failed: firewall apply mode requires a detected backend"
                )
            applied_rules = self._apply_firewall_policy(backend, config)
            report.applied_rules.extend(applied_rules)
            if config.firewall_dry_run:
                report.warnings.append("Firewall policy was evaluated in dry-run mode.")
            else:
                report.warnings.append(f"Firewall policy was applied using {backend}.")
        return report

    @staticmethod
    def _is_valid_host_or_network(value: str) -> bool:
        try:
            ipaddress.ip_network(value, strict=False)
            return True
        except ValueError:
            pass
        return "." in value and " " not in value

    @staticmethod
    def _detect_firewall_backend() -> str | None:
        for candidate in ("iptables", "nft", "pfctl"):
            if shutil.which(candidate):
                return candidate
        return None

    @staticmethod
    def _docker_network_exists(required_name: str) -> tuple[bool, str]:
        if not shutil.which("docker"):
            return (False, "docker CLI unavailable")
        try:
            proc = subprocess.run(
                ["docker", "network", "ls", "--format", "{{.Name}}"],
                check=False,
                capture_output=True,
                text=True,
                timeout=3.0,
            )
        except Exception as exc:
            return (False, str(exc))
        if proc.returncode != 0:
            return (False, proc.stderr.strip() or f"docker exited with {proc.returncode}")
        names = {line.strip() for line in proc.stdout.splitlines() if line.strip()}
        return (required_name in names, "network missing")

    def _apply_firewall_policy(self, backend: str, config: NetworkConfig) -> list[str]:
        if backend == "iptables":
            return self._apply_iptables_policy(config)
        if backend == "nft":
            return self._apply_nft_policy(config)
        if backend == "pfctl":
            return self._apply_pfctl_policy(config)
        raise NetworkIsolationError(f"unsupported firewall backend '{backend}'")

    @staticmethod
    def _run_command(
        command: list[str],
        *,
        timeout_seconds: float = 3.0,
        dry_run: bool,
        stdin_data: str | None = None,
        tolerated_errors: tuple[str, ...] = (),
    ) -> str:
        rendered = " ".join(command)
        if dry_run:
            return rendered
        proc = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            input=stdin_data,
        )
        if proc.returncode == 0:
            return rendered
        details = (proc.stderr or proc.stdout or "").strip()
        if tolerated_errors and any(token in details for token in tolerated_errors):
            return rendered
        raise NetworkIsolationError(f"failed to apply firewall command '{rendered}': {details}")

    def _apply_iptables_policy(self, config: NetworkConfig) -> list[str]:
        chain = "CLOWNPEANUTS_EGRESS"
        commands: list[list[str]] = []
        commands.append(["iptables", "-N", chain])
        commands.append(["iptables", "-F", chain])
        commands.append(["iptables", "-A", chain, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
        commands.append(["iptables", "-A", chain, "-o", "lo", "-j", "ACCEPT"])

        if config.allow_outbound:
            commands.append(["iptables", "-A", chain, "-j", "ACCEPT"])
        else:
            for target in config.allowed_egress:
                if target == "redis":
                    continue
                if self._is_valid_host_or_network(target):
                    commands.append(["iptables", "-A", chain, "-d", target, "-j", "ACCEPT"])
            commands.append(["iptables", "-A", chain, "-j", "DROP"])

        applied: list[str] = []
        for command in commands:
            tolerated = ("Chain already exists",) if "-N" in command else ()
            applied.append(
                self._run_command(
                    command,
                    dry_run=config.firewall_dry_run,
                    tolerated_errors=tolerated,
                )
            )

        if config.firewall_dry_run:
            applied.append(f"iptables -C OUTPUT -j {chain} (dry-run check)")
            applied.append(f"iptables -A OUTPUT -j {chain} (dry-run add if missing)")
            return applied

        check_cmd = ["iptables", "-C", "OUTPUT", "-j", chain]
        check_proc = subprocess.run(check_cmd, check=False, capture_output=True, text=True, timeout=3.0)
        if check_proc.returncode != 0:
            add_cmd = ["iptables", "-A", "OUTPUT", "-j", chain]
            add_proc = subprocess.run(add_cmd, check=False, capture_output=True, text=True, timeout=3.0)
            if add_proc.returncode != 0:
                raise NetworkIsolationError(
                    f"failed to attach firewall chain to OUTPUT: {add_proc.stderr.strip() or add_proc.stdout.strip()}"
                )
            applied.append(" ".join(add_cmd))
        else:
            applied.append(" ".join(check_cmd))
        return applied

    def _apply_nft_policy(self, config: NetworkConfig) -> list[str]:
        table = "clownpeanuts"
        chain = "output"
        commands: list[tuple[list[str], tuple[str, ...]]] = [
            (["nft", "add", "table", "inet", table], ("File exists",)),
            (
                [
                    "nft",
                    "add",
                    "chain",
                    "inet",
                    table,
                    chain,
                    "{ type filter hook output priority 0 ; policy accept ; }",
                ],
                ("File exists",),
            ),
            (["nft", "flush", "chain", "inet", table, chain], ()),
            (["nft", "add", "rule", "inet", table, chain, "ct", "state", "established,related", "accept"], ()),
            (["nft", "add", "rule", "inet", table, chain, "oifname", "lo", "accept"], ()),
        ]

        if config.allow_outbound:
            commands.append((["nft", "add", "rule", "inet", table, chain, "accept"], ()))
        else:
            for target in config.allowed_egress:
                if target == "redis":
                    continue
                if self._is_valid_host_or_network(target):
                    commands.append((["nft", "add", "rule", "inet", table, chain, "ip", "daddr", target, "accept"], ()))
            commands.append((["nft", "add", "rule", "inet", table, chain, "drop"], ()))

        applied: list[str] = []
        for command, tolerated_errors in commands:
            applied.append(
                self._run_command(
                    command,
                    dry_run=config.firewall_dry_run,
                    tolerated_errors=tolerated_errors,
                )
            )
        return applied

    def _apply_pfctl_policy(self, config: NetworkConfig) -> list[str]:
        anchor = "clownpeanuts/egress"
        rules = self._build_pfctl_rules(config)
        load_command = ["pfctl", "-a", anchor, "-f", "-"]
        verify_command = ["pfctl", "-a", anchor, "-sr"]

        applied = [
            self._run_command(
                load_command,
                dry_run=config.firewall_dry_run,
                stdin_data=rules,
            )
        ]
        if config.firewall_dry_run:
            applied.append("pfctl -a clownpeanuts/egress -sr (dry-run verify)")
            return applied

        applied.append(self._run_command(verify_command, dry_run=False))
        return applied

    def _build_pfctl_rules(self, config: NetworkConfig) -> str:
        lines = [
            "pass out quick on lo0 all",
        ]
        if config.allow_outbound:
            lines.append("pass out quick all keep state")
        else:
            for target in config.allowed_egress:
                if target == "redis":
                    continue
                if self._is_valid_host_or_network(target):
                    lines.append(f"pass out quick to {target} keep state")
            lines.append("block drop out quick all")
        return "\n".join(lines) + "\n"
