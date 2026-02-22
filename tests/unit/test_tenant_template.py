from pathlib import Path

from clownpeanuts.config.schema import ServiceConfig, parse_config
from clownpeanuts.core.tenant import TenantManager
from clownpeanuts.templates.deception import DeceptionTemplateLoader


def test_tenant_manager_applies_service_overrides() -> None:
    config = parse_config(
        {
            "multi_tenant": {
                "enabled": True,
                "default_tenant": "tenant-a",
                "tenants": [
                    {
                        "id": "tenant-a",
                        "enabled": True,
                        "service_overrides": {"ssh": {"ports": [2223], "config": {"hostname": "tenant-a-host"}}},
                    }
                ],
            },
            "services": [{"name": "ssh", "module": "clownpeanuts.services.ssh.emulator", "ports": [2222], "config": {}}],
        }
    )
    manager = TenantManager(config.multi_tenant)
    tenant = manager.resolve_tenant("tenant-a")
    result = manager.apply_service_overrides(config.services, tenant)
    assert result[0].ports == [2223]
    assert result[0].config["hostname"] == "tenant-a-host"


def test_template_loader_applies_template_file(tmp_path: Path) -> None:
    template_path = tmp_path / "template.yml"
    template_path.write_text(
        "templates:\n"
        "  - service: ssh\n"
        "    enabled: true\n"
        "    ports: [2299]\n"
        "    config:\n"
        "      banner: SSH-2.0-OpenSSH_9.9\n",
        encoding="utf-8",
    )

    loader = DeceptionTemplateLoader(config=parse_config({"templates": {"enabled": True, "paths": [str(template_path)]}, "services": []}).templates)
    base = [ServiceConfig(name="ssh", module="clownpeanuts.services.ssh.emulator", ports=[2222], config={})]
    updated = loader.apply(base)
    assert updated[0].ports == [2299]
    assert updated[0].config["banner"] == "SSH-2.0-OpenSSH_9.9"

    inventory = loader.inventory()
    assert inventory["enabled"] is True
    assert inventory["template_count"] == 1
    assert "ssh" in inventory["services"]


def test_template_loader_validation_reports_errors_and_warnings(tmp_path: Path) -> None:
    template_path = tmp_path / "template-invalid.yml"
    template_path.write_text(
        "templates:\n"
        "  - service: ssh\n"
        "    ports: [2299]\n"
        "  - service: unknown-service\n"
        "    ports: [70000]\n"
        "  - service: ssh\n"
        "    enabled: \"true\"\n"
        "    listen_host: \"\"\n"
        "    config: []\n"
        "    unused: 1\n"
        "  - not-an-object\n",
        encoding="utf-8",
    )

    loader = DeceptionTemplateLoader(
        config=parse_config({"templates": {"enabled": True, "paths": [str(template_path)]}, "services": []}).templates
    )
    services = [ServiceConfig(name="ssh", module="clownpeanuts.services.ssh.emulator", ports=[2222], config={})]

    report = loader.validate(services)
    assert report["ok"] is False
    assert report["error_count"] >= 4
    assert report["warning_count"] >= 3
    assert report["service_catalog"] == ["ssh"]
    assert any(item["message"] == "ports override must be a list of integers in range 1-65535" for item in report["errors"])
    assert any(item["message"] == "enabled override must be a boolean" for item in report["errors"])
    assert any(item["message"] == "template row must be an object" for item in report["errors"])
    assert any("service 'unknown-service' is not present" in item["message"] for item in report["warnings"])
    assert any("duplicate service override for 'ssh'" in item["message"] for item in report["warnings"])
    assert any("unknown template fields ignored" in item["message"] for item in report["warnings"])


def test_template_loader_validation_flags_non_object_root(tmp_path: Path) -> None:
    template_path = tmp_path / "template-root-invalid.yml"
    template_path.write_text("- invalid-root\n", encoding="utf-8")

    loader = DeceptionTemplateLoader(
        config=parse_config({"templates": {"enabled": True, "paths": [str(template_path)]}, "services": []}).templates
    )
    services = [ServiceConfig(name="ssh", module="clownpeanuts.services.ssh.emulator", ports=[2222], config={})]

    report = loader.validate(services)
    assert report["ok"] is False
    assert report["error_count"] == 1
    assert report["errors"][0]["message"] == "template file root must be an object"
