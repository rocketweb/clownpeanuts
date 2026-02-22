import json
import os
from pathlib import Path

import pytest

from clownpeanuts.cli import main
from clownpeanuts.intel.store import IntelligenceStore


def test_init_command_writes_config(tmp_path: Path) -> None:
    config_path = tmp_path / "clownpeanuts.yml"
    rc = main(["init", "--config", str(config_path)])
    assert rc == 0
    assert config_path.exists()


def test_intel_command_runs_with_defaults() -> None:
    rc = main(["intel", "--config", "clownpeanuts/config/defaults.yml"])
    assert rc == 0


def test_intel_history_command_runs_with_defaults() -> None:
    rc = main(["intel-history", "--config", "clownpeanuts/config/defaults.yml", "--limit", "5"])
    assert rc == 0


def test_intel_history_command_supports_report_id_and_sessions() -> None:
    rc = main(
        [
            "intel-history",
            "--config",
            "clownpeanuts/config/defaults.yml",
            "--report-id",
            "1",
            "--sessions",
        ]
    )
    assert rc == 0


def test_intel_handoff_command_supports_markdown_output(tmp_path: Path) -> None:
    output_path = tmp_path / "handoff.md"
    rc = main(
        [
            "intel-handoff",
            "--config",
            "clownpeanuts/config/defaults.yml",
            "--format",
            "markdown",
            "--output",
            str(output_path),
        ]
    )
    assert rc == 0
    assert output_path.exists()
    markdown = output_path.read_text(encoding="utf-8")
    assert "ClownPeanuts SOC Handoff" in markdown


def test_intel_handoff_command_supports_csv_output(tmp_path: Path) -> None:
    output_path = tmp_path / "handoff.csv"
    rc = main(
        [
            "intel-handoff",
            "--config",
            "clownpeanuts/config/defaults.yml",
            "--format",
            "csv",
            "--output",
            str(output_path),
        ]
    )
    assert rc == 0
    assert output_path.exists()
    csv_payload = output_path.read_text(encoding="utf-8")
    assert "record_type,generated_at" in csv_payload
    assert "summary" in csv_payload


def test_intel_handoff_command_supports_tsv_output(tmp_path: Path) -> None:
    output_path = tmp_path / "handoff.tsv"
    rc = main(
        [
            "intel-handoff",
            "--config",
            "clownpeanuts/config/defaults.yml",
            "--format",
            "tsv",
            "--output",
            str(output_path),
        ]
    )
    assert rc == 0
    assert output_path.exists()
    tsv_payload = output_path.read_text(encoding="utf-8")
    assert "record_type\tgenerated_at" in tsv_payload
    assert "summary\t" in tsv_payload


def test_intel_handoff_command_supports_ndjson_output(tmp_path: Path) -> None:
    output_path = tmp_path / "handoff.ndjson"
    rc = main(
        [
            "intel-handoff",
            "--config",
            "clownpeanuts/config/defaults.yml",
            "--format",
            "ndjson",
            "--output",
            str(output_path),
        ]
    )
    assert rc == 0
    assert output_path.exists()
    ndjson_payload = output_path.read_text(encoding="utf-8")
    lines = [line for line in ndjson_payload.splitlines() if line.strip()]
    assert lines
    assert '"record_type":"summary"' in lines[0]


def test_intel_handoff_command_supports_jsonl_output(tmp_path: Path) -> None:
    output_path = tmp_path / "handoff.jsonl"
    rc = main(
        [
            "intel-handoff",
            "--config",
            "clownpeanuts/config/defaults.yml",
            "--format",
            "jsonl",
            "--output",
            str(output_path),
        ]
    )
    assert rc == 0
    assert output_path.exists()
    jsonl_payload = output_path.read_text(encoding="utf-8")
    lines = [line for line in jsonl_payload.splitlines() if line.strip()]
    assert lines
    assert '"record_type":"summary"' in lines[0]


def test_intel_handoff_command_supports_cef_output(tmp_path: Path) -> None:
    output_path = tmp_path / "handoff.cef"
    rc = main(
        [
            "intel-handoff",
            "--config",
            "clownpeanuts/config/defaults.yml",
            "--format",
            "cef",
            "--output",
            str(output_path),
        ]
    )
    assert rc == 0
    assert output_path.exists()
    cef_payload = output_path.read_text(encoding="utf-8")
    lines = [line for line in cef_payload.splitlines() if line.strip()]
    assert lines
    assert lines[0].startswith("CEF:0|ClownPeanuts|SOC Handoff|0.1.0|")


def test_intel_handoff_command_supports_syslog_output(tmp_path: Path) -> None:
    output_path = tmp_path / "handoff.syslog"
    rc = main(
        [
            "intel-handoff",
            "--config",
            "clownpeanuts/config/defaults.yml",
            "--format",
            "syslog",
            "--output",
            str(output_path),
        ]
    )
    assert rc == 0
    assert output_path.exists()
    syslog_payload = output_path.read_text(encoding="utf-8")
    lines = [line for line in syslog_payload.splitlines() if line.strip()]
    assert lines
    assert lines[0].startswith("<")
    assert "intel-handoff" in lines[0]


def test_intel_handoff_command_supports_logfmt_output(tmp_path: Path) -> None:
    output_path = tmp_path / "handoff.logfmt"
    rc = main(
        [
            "intel-handoff",
            "--config",
            "clownpeanuts/config/defaults.yml",
            "--format",
            "logfmt",
            "--output",
            str(output_path),
        ]
    )
    assert rc == 0
    assert output_path.exists()
    logfmt_payload = output_path.read_text(encoding="utf-8")
    lines = [line for line in logfmt_payload.splitlines() if line.strip()]
    assert lines
    assert lines[0].startswith("record=summary ")


def test_intel_handoff_command_supports_report_id_lookup(tmp_path: Path) -> None:
    db_path = tmp_path / "intel.sqlite3"
    output_path = tmp_path / "handoff-history.json"
    original_db = os.environ.get("CLOWNPEANUTS_INTEL_DB")
    os.environ["CLOWNPEANUTS_INTEL_DB"] = str(db_path)
    try:
        assert main(["intel", "--config", "clownpeanuts/config/defaults.yml"]) == 0
        rc = main(
            [
                "intel-handoff",
                "--config",
                "clownpeanuts/config/defaults.yml",
                "--report-id",
                "1",
                "--output",
                str(output_path),
            ]
        )
        assert rc == 0
        assert output_path.exists()

        missing_rc = main(
            [
                "intel-handoff",
                "--config",
                "clownpeanuts/config/defaults.yml",
                "--report-id",
                "9999",
            ]
        )
        assert missing_rc == 1
    finally:
        if original_db is None:
            os.environ.pop("CLOWNPEANUTS_INTEL_DB", None)
        else:
            os.environ["CLOWNPEANUTS_INTEL_DB"] = original_db


def test_intel_coverage_command_runs_with_defaults() -> None:
    rc = main(["intel-coverage", "--config", "clownpeanuts/config/defaults.yml", "--limit", "5"])
    assert rc == 0


def test_stix_export_command_writes_output_file(tmp_path: Path) -> None:
    output_path = tmp_path / "bundle.json"
    rc = main(
        [
            "stix-export",
            "--config",
            "clownpeanuts/config/defaults.yml",
            "--output",
            str(output_path),
        ]
    )
    assert rc == 0
    assert output_path.exists()


def test_stix_export_command_supports_report_id_lookup(tmp_path: Path) -> None:
    db_path = tmp_path / "intel.sqlite3"
    original_db = os.environ.get("CLOWNPEANUTS_INTEL_DB")
    os.environ["CLOWNPEANUTS_INTEL_DB"] = str(db_path)
    try:
        assert main(["intel", "--config", "clownpeanuts/config/defaults.yml"]) == 0
        output_path = tmp_path / "bundle-history.json"
        rc = main(
            [
                "stix-export",
                "--config",
                "clownpeanuts/config/defaults.yml",
                "--report-id",
                "1",
                "--output",
                str(output_path),
            ]
        )
        assert rc == 0
        assert output_path.exists()

        missing_rc = main(
            [
                "stix-export",
                "--config",
                "clownpeanuts/config/defaults.yml",
                "--report-id",
                "9999",
            ]
        )
        assert missing_rc == 1
    finally:
        if original_db is None:
            os.environ.pop("CLOWNPEANUTS_INTEL_DB", None)
        else:
            os.environ["CLOWNPEANUTS_INTEL_DB"] = original_db


def test_taxii_export_command_supports_manifest_and_report_id(tmp_path: Path) -> None:
    db_path = tmp_path / "intel.sqlite3"
    original_db = os.environ.get("CLOWNPEANUTS_INTEL_DB")
    os.environ["CLOWNPEANUTS_INTEL_DB"] = str(db_path)
    try:
        assert main(["intel", "--config", "clownpeanuts/config/defaults.yml"]) == 0
        output_path = tmp_path / "taxii-manifest.json"
        rc = main(
            [
                "taxii-export",
                "--config",
                "clownpeanuts/config/defaults.yml",
                "--manifest",
                "--report-id",
                "1",
                "--output",
                str(output_path),
            ]
        )
        assert rc == 0
        assert output_path.exists()

        missing_collection_rc = main(
            [
                "taxii-export",
                "--config",
                "clownpeanuts/config/defaults.yml",
                "--collection-id",
                "unknown",
            ]
        )
        assert missing_collection_rc == 1

        missing_report_rc = main(
            [
                "taxii-export",
                "--config",
                "clownpeanuts/config/defaults.yml",
                "--report-id",
                "9999",
            ]
        )
        assert missing_report_rc == 1
    finally:
        if original_db is None:
            os.environ.pop("CLOWNPEANUTS_INTEL_DB", None)
        else:
            os.environ["CLOWNPEANUTS_INTEL_DB"] = original_db


def test_navigator_export_command_supports_output_and_report_history(tmp_path: Path) -> None:
    db_path = tmp_path / "intel.sqlite3"
    original_db = os.environ.get("CLOWNPEANUTS_INTEL_DB")
    os.environ["CLOWNPEANUTS_INTEL_DB"] = str(db_path)
    try:
        assert main(["intel", "--config", "clownpeanuts/config/defaults.yml"]) == 0
        output_path = tmp_path / "navigator-layer.json"
        rc = main(
            [
                "navigator-export",
                "--config",
                "clownpeanuts/config/defaults.yml",
                "--report-id",
                "1",
                "--name",
                "SOC ATTACK Coverage",
                "--output",
                str(output_path),
            ]
        )
        assert rc == 0
        assert output_path.exists()

        missing_report_rc = main(
            [
                "navigator-export",
                "--config",
                "clownpeanuts/config/defaults.yml",
                "--report-id",
                "9999",
            ]
        )
        assert missing_report_rc == 1
    finally:
        if original_db is None:
            os.environ.pop("CLOWNPEANUTS_INTEL_DB", None)
        else:
            os.environ["CLOWNPEANUTS_INTEL_DB"] = original_db


def test_theater_history_command_writes_output_file(tmp_path: Path) -> None:
    db_path = tmp_path / "intel.sqlite3"
    output_path = tmp_path / "theater-history.json"
    original_db = os.environ.get("CLOWNPEANUTS_INTEL_DB")
    os.environ["CLOWNPEANUTS_INTEL_DB"] = str(db_path)
    try:
        store = IntelligenceStore(db_path=db_path)
        store.record_theater_action(
            action_type="apply_lure",
            session_id="s-theater-1",
            actor="analyst-1",
            recommendation_id="rec-123",
            payload={"lure_arm": "ssh-credential-bait"},
        )
        rc = main(
            [
                "theater-history",
                "--config",
                "clownpeanuts/config/defaults.yml",
                "--limit",
                "10",
                "--output",
                str(output_path),
            ]
        )
        assert rc == 0
        assert output_path.exists()
    finally:
        if original_db is None:
            os.environ.pop("CLOWNPEANUTS_INTEL_DB", None)
        else:
            os.environ["CLOWNPEANUTS_INTEL_DB"] = original_db


def test_theater_history_command_supports_csv_output(tmp_path: Path) -> None:
    db_path = tmp_path / "intel.sqlite3"
    output_path = tmp_path / "theater-history.csv"
    original_db = os.environ.get("CLOWNPEANUTS_INTEL_DB")
    os.environ["CLOWNPEANUTS_INTEL_DB"] = str(db_path)
    try:
        store = IntelligenceStore(db_path=db_path)
        store.record_theater_action(
            action_type="apply_lure",
            session_id="s-theater-2",
            actor="analyst-2",
            recommendation_id="rec-234",
            payload={"lure_arm": "http-query-bait"},
        )
        rc = main(
            [
                "theater-history",
                "--config",
                "clownpeanuts/config/defaults.yml",
                "--limit",
                "10",
                "--format",
                "csv",
                "--output",
                str(output_path),
            ]
        )
        assert rc == 0
        assert output_path.exists()
        csv_payload = output_path.read_text(encoding="utf-8")
        assert "row_id,created_at,action_type,session_id" in csv_payload
        assert "apply_lure" in csv_payload
    finally:
        if original_db is None:
            os.environ.pop("CLOWNPEANUTS_INTEL_DB", None)
        else:
            os.environ["CLOWNPEANUTS_INTEL_DB"] = original_db


def test_theater_history_command_supports_tsv_output(tmp_path: Path) -> None:
    db_path = tmp_path / "intel.sqlite3"
    output_path = tmp_path / "theater-history.tsv"
    original_db = os.environ.get("CLOWNPEANUTS_INTEL_DB")
    os.environ["CLOWNPEANUTS_INTEL_DB"] = str(db_path)
    try:
        store = IntelligenceStore(db_path=db_path)
        store.record_theater_action(
            action_type="label",
            session_id="s-theater-tsv",
            actor="analyst-tsv",
            recommendation_id="rec-tsv",
            payload={"label": "high_value_actor"},
        )
        rc = main(
            [
                "theater-history",
                "--config",
                "clownpeanuts/config/defaults.yml",
                "--limit",
                "10",
                "--format",
                "tsv",
                "--output",
                str(output_path),
            ]
        )
        assert rc == 0
        assert output_path.exists()
        tsv_payload = output_path.read_text(encoding="utf-8")
        assert "row_id\tcreated_at\taction_type\tsession_id" in tsv_payload
        assert "label" in tsv_payload
    finally:
        if original_db is None:
            os.environ.pop("CLOWNPEANUTS_INTEL_DB", None)
        else:
            os.environ["CLOWNPEANUTS_INTEL_DB"] = original_db


def test_theater_history_command_supports_logfmt_output(tmp_path: Path) -> None:
    db_path = tmp_path / "intel.sqlite3"
    output_path = tmp_path / "theater-history.logfmt"
    original_db = os.environ.get("CLOWNPEANUTS_INTEL_DB")
    os.environ["CLOWNPEANUTS_INTEL_DB"] = str(db_path)
    try:
        store = IntelligenceStore(db_path=db_path)
        store.record_theater_action(
            action_type="apply_lure",
            session_id="s-theater-logfmt",
            actor="analyst-logfmt",
            recommendation_id="rec-logfmt",
            payload={"lure_arm": "ssh-credential-bait"},
        )
        rc = main(
            [
                "theater-history",
                "--config",
                "clownpeanuts/config/defaults.yml",
                "--limit",
                "10",
                "--format",
                "logfmt",
                "--output",
                str(output_path),
            ]
        )
        assert rc == 0
        assert output_path.exists()
        logfmt_payload = output_path.read_text(encoding="utf-8")
        assert "record_type=theater_action" in logfmt_payload
        assert "action_type=\"apply_lure\"" in logfmt_payload
    finally:
        if original_db is None:
            os.environ.pop("CLOWNPEANUTS_INTEL_DB", None)
        else:
            os.environ["CLOWNPEANUTS_INTEL_DB"] = original_db


def test_theater_history_command_supports_cef_output(tmp_path: Path) -> None:
    db_path = tmp_path / "intel.sqlite3"
    output_path = tmp_path / "theater-history.cef"
    original_db = os.environ.get("CLOWNPEANUTS_INTEL_DB")
    os.environ["CLOWNPEANUTS_INTEL_DB"] = str(db_path)
    try:
        store = IntelligenceStore(db_path=db_path)
        store.record_theater_action(
            action_type="apply_lure",
            session_id="s-theater-cef",
            actor="analyst-cef",
            recommendation_id="rec-cef",
            payload={"lure_arm": "ssh-credential-bait"},
        )
        rc = main(
            [
                "theater-history",
                "--config",
                "clownpeanuts/config/defaults.yml",
                "--limit",
                "10",
                "--format",
                "cef",
                "--output",
                str(output_path),
            ]
        )
        assert rc == 0
        assert output_path.exists()
        cef_payload = output_path.read_text(encoding="utf-8")
        lines = [line for line in cef_payload.splitlines() if line.strip()]
        assert lines
        assert lines[0].startswith("CEF:0|ClownPeanuts|Theater Actions|0.1.0|")
    finally:
        if original_db is None:
            os.environ.pop("CLOWNPEANUTS_INTEL_DB", None)
        else:
            os.environ["CLOWNPEANUTS_INTEL_DB"] = original_db


def test_theater_history_command_supports_leef_output(tmp_path: Path) -> None:
    db_path = tmp_path / "intel.sqlite3"
    output_path = tmp_path / "theater-history.leef"
    original_db = os.environ.get("CLOWNPEANUTS_INTEL_DB")
    os.environ["CLOWNPEANUTS_INTEL_DB"] = str(db_path)
    try:
        store = IntelligenceStore(db_path=db_path)
        store.record_theater_action(
            action_type="label",
            session_id="s-theater-leef",
            actor="analyst-leef",
            recommendation_id="rec-leef",
            payload={"label": "high_value_actor"},
        )
        rc = main(
            [
                "theater-history",
                "--config",
                "clownpeanuts/config/defaults.yml",
                "--limit",
                "10",
                "--format",
                "leef",
                "--output",
                str(output_path),
            ]
        )
        assert rc == 0
        assert output_path.exists()
        leef_payload = output_path.read_text(encoding="utf-8")
        lines = [line for line in leef_payload.splitlines() if line.strip()]
        assert lines
        assert lines[0].startswith("LEEF:2.0|ClownPeanuts|Theater Actions|0.1.0|")
    finally:
        if original_db is None:
            os.environ.pop("CLOWNPEANUTS_INTEL_DB", None)
        else:
            os.environ["CLOWNPEANUTS_INTEL_DB"] = original_db


def test_theater_history_command_supports_syslog_output(tmp_path: Path) -> None:
    db_path = tmp_path / "intel.sqlite3"
    output_path = tmp_path / "theater-history.syslog"
    original_db = os.environ.get("CLOWNPEANUTS_INTEL_DB")
    os.environ["CLOWNPEANUTS_INTEL_DB"] = str(db_path)
    try:
        store = IntelligenceStore(db_path=db_path)
        store.record_theater_action(
            action_type="apply_lure",
            session_id="s-theater-syslog",
            actor="analyst-syslog",
            recommendation_id="rec-syslog",
            payload={"lure_arm": "http-query-bait"},
        )
        rc = main(
            [
                "theater-history",
                "--config",
                "clownpeanuts/config/defaults.yml",
                "--limit",
                "10",
                "--format",
                "syslog",
                "--output",
                str(output_path),
            ]
        )
        assert rc == 0
        assert output_path.exists()
        syslog_payload = output_path.read_text(encoding="utf-8")
        lines = [line for line in syslog_payload.splitlines() if line.strip()]
        assert lines
        assert lines[0].startswith("<133>1 ")
        assert " clownpeanuts theater-actions " in lines[0]
    finally:
        if original_db is None:
            os.environ.pop("CLOWNPEANUTS_INTEL_DB", None)
        else:
            os.environ["CLOWNPEANUTS_INTEL_DB"] = original_db


def test_theater_history_command_supports_session_ids_filter(tmp_path: Path) -> None:
    db_path = tmp_path / "intel.sqlite3"
    output_path = tmp_path / "theater-history-session-ids.json"
    original_db = os.environ.get("CLOWNPEANUTS_INTEL_DB")
    os.environ["CLOWNPEANUTS_INTEL_DB"] = str(db_path)
    try:
        store = IntelligenceStore(db_path=db_path)
        store.record_theater_action(
            action_type="label",
            session_id="s-session-a",
            actor="analyst-a",
            recommendation_id="rec-a",
            payload={"label": "high_value_actor"},
        )
        store.record_theater_action(
            action_type="label",
            session_id="s-session-b",
            actor="analyst-b",
            recommendation_id="rec-b",
            payload={"label": "medium_value_actor"},
        )
        rc = main(
            [
                "theater-history",
                "--config",
                "clownpeanuts/config/defaults.yml",
                "--limit",
                "10",
                "--session-ids",
                "s-session-b",
                "--output",
                str(output_path),
            ]
        )
        assert rc == 0
        assert output_path.exists()
        payload = json.loads(output_path.read_text(encoding="utf-8"))
        assert payload["count"] == 1
        assert payload["actions"][0]["session_id"] == "s-session-b"
    finally:
        if original_db is None:
            os.environ.pop("CLOWNPEANUTS_INTEL_DB", None)
        else:
            os.environ["CLOWNPEANUTS_INTEL_DB"] = original_db


def test_theater_history_command_supports_jsonl_output(tmp_path: Path) -> None:
    db_path = tmp_path / "intel.sqlite3"
    output_path = tmp_path / "theater-history.jsonl"
    original_db = os.environ.get("CLOWNPEANUTS_INTEL_DB")
    os.environ["CLOWNPEANUTS_INTEL_DB"] = str(db_path)
    try:
        store = IntelligenceStore(db_path=db_path)
        store.record_theater_action(
            action_type="label",
            session_id="s-theater-3",
            actor="analyst-3",
            recommendation_id="rec-345",
            payload={"label": "high_value_actor"},
        )
        rc = main(
            [
                "theater-history",
                "--config",
                "clownpeanuts/config/defaults.yml",
                "--limit",
                "10",
                "--format",
                "jsonl",
                "--output",
                str(output_path),
            ]
        )
        assert rc == 0
        assert output_path.exists()
        jsonl_payload = output_path.read_text(encoding="utf-8")
        lines = [line for line in jsonl_payload.splitlines() if line.strip()]
        assert lines
        assert '"record_type":"theater_action"' in lines[0]
    finally:
        if original_db is None:
            os.environ.pop("CLOWNPEANUTS_INTEL_DB", None)
        else:
            os.environ["CLOWNPEANUTS_INTEL_DB"] = original_db


def test_rotate_command_runs_with_defaults() -> None:
    rc = main(["rotate", "--config", "clownpeanuts/config/defaults.yml"])
    assert rc == 0


def test_rotate_preview_command_runs_with_defaults() -> None:
    rc = main(["rotate-preview", "--config", "clownpeanuts/config/defaults.yml"])
    assert rc == 0


def test_simulate_bandit_command_runs_with_defaults() -> None:
    rc = main(["simulate-bandit", "--config", "clownpeanuts/config/defaults.yml", "--window-hours", "24"])
    assert rc == 0


def test_templates_command_runs_with_defaults() -> None:
    rc = main(["templates", "--config", "clownpeanuts/config/defaults.yml"])
    assert rc == 0


def test_templates_command_supports_all_tenants(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yml"
    config_path.write_text(
        "environment: test\n"
        "multi_tenant:\n"
        "  enabled: true\n"
        "  default_tenant: tenant-a\n"
        "  tenants:\n"
        "    - id: tenant-a\n"
        "      enabled: true\n"
        "    - id: tenant-b\n"
        "      enabled: true\n"
        "services:\n"
        "  - name: ssh\n"
        "    module: clownpeanuts.services.ssh.emulator\n"
        "    ports: [2222]\n",
        encoding="utf-8",
    )
    rc = main(["templates", "--config", str(config_path), "--all-tenants"])
    assert rc == 0


def test_templates_validate_command_runs_with_defaults() -> None:
    rc = main(["templates-validate", "--config", "clownpeanuts/config/defaults.yml"])
    assert rc == 0


def test_templates_validate_returns_nonzero_for_invalid_templates(tmp_path: Path) -> None:
    template_path = tmp_path / "invalid-template.yml"
    template_path.write_text(
        "templates:\n"
        "  - service: ssh\n"
        "    ports: [\"invalid\"]\n",
        encoding="utf-8",
    )

    config_path = tmp_path / "config.yml"
    config_path.write_text(
        "environment: test\n"
        "services:\n"
        "  - name: ssh\n"
        "    module: clownpeanuts.services.ssh.emulator\n"
        "    ports: [2222]\n"
        "templates:\n"
        "  enabled: true\n"
        f"  paths: ['{template_path}']\n",
        encoding="utf-8",
    )

    rc = main(["templates-validate", "--config", str(config_path)])
    assert rc == 1


def test_templates_validate_supports_all_tenants_and_strict_warnings(tmp_path: Path) -> None:
    template_path = tmp_path / "template.yml"
    template_path.write_text(
        "templates:\n"
        "  - service: ssh\n"
        "    ports: [2222]\n",
        encoding="utf-8",
    )

    config_path = tmp_path / "config-multi.yml"
    config_path.write_text(
        "environment: test\n"
        "multi_tenant:\n"
        "  enabled: true\n"
        "  default_tenant: tenant-a\n"
        "  tenants:\n"
        "    - id: tenant-a\n"
        "      enabled: true\n"
        "    - id: tenant-b\n"
        "      enabled: true\n"
        "services:\n"
        "  - name: ssh\n"
        "    module: clownpeanuts.services.ssh.emulator\n"
        "    ports: [2222]\n"
        "templates:\n"
        "  enabled: true\n"
        f"  paths: ['{template_path}']\n",
        encoding="utf-8",
    )

    rc_all = main(["templates-validate", "--config", str(config_path), "--all-tenants"])
    assert rc_all == 0

    strict_config_path = tmp_path / "config-strict.yml"
    strict_config_path.write_text(
        "environment: test\n"
        "services:\n"
        "  - name: ssh\n"
        "    module: clownpeanuts.services.ssh.emulator\n"
        "    ports: [2222]\n"
        "templates:\n"
        "  enabled: true\n"
        f"  paths: ['{tmp_path / 'missing.yml'}']\n",
        encoding="utf-8",
    )
    rc_strict = main(["templates-validate", "--config", str(strict_config_path), "--strict-warnings"])
    assert rc_strict == 1


def test_templates_diff_command_runs_and_can_fail_on_diff(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yml"
    config_path.write_text(
        "environment: test\n"
        "multi_tenant:\n"
        "  enabled: true\n"
        "  default_tenant: tenant-a\n"
        "  tenants:\n"
        "    - id: tenant-a\n"
        "      enabled: true\n"
        "      service_overrides:\n"
        "        ssh:\n"
        "          ports: [2222]\n"
        "    - id: tenant-b\n"
        "      enabled: true\n"
        "      service_overrides:\n"
        "        ssh:\n"
        "          ports: [2299]\n"
        "services:\n"
        "  - name: ssh\n"
        "    module: clownpeanuts.services.ssh.emulator\n"
        "    ports: [2200]\n",
        encoding="utf-8",
    )

    rc = main(
        [
            "templates-diff",
            "--config",
            str(config_path),
            "--left-tenant",
            "tenant-a",
            "--right-tenant",
            "tenant-b",
            "--no-threat-rotation",
        ]
    )
    assert rc == 0

    fail_rc = main(
        [
            "templates-diff",
            "--config",
            str(config_path),
            "--left-tenant",
            "tenant-a",
            "--right-tenant",
            "tenant-b",
            "--no-threat-rotation",
            "--fail-on-diff",
        ]
    )
    assert fail_rc == 1

    matrix_fail_rc = main(
        [
            "templates-diff",
            "--config",
            str(config_path),
            "--all-pairs",
            "--no-threat-rotation",
            "--fail-on-diff",
        ]
    )
    assert matrix_fail_rc == 1


def test_replay_command_runs_with_defaults() -> None:
    rc = main(
        [
            "replay",
            "--config",
            "clownpeanuts/config/defaults.yml",
            "--session-id",
            "missing-session",
        ]
    )
    assert rc == 0


def test_replay_compare_command_returns_nonzero_when_sessions_missing() -> None:
    rc = main(
        [
            "replay-compare",
            "--config",
            "clownpeanuts/config/defaults.yml",
            "--left-session-id",
            "missing-left",
            "--right-session-id",
            "missing-right",
        ]
    )
    assert rc == 1


def test_canary_hit_command_runs_with_defaults() -> None:
    rc = main(
        [
            "canary-hit",
            "--config",
            "clownpeanuts/config/defaults.yml",
            "--token",
            "ct-cli-001",
            "--source-ip",
            "203.0.113.44",
            "--metadata-json",
            "{\"channel\":\"smtp\"}",
        ]
    )
    assert rc == 0


def test_canary_generate_command_runs_with_defaults() -> None:
    rc = main(["canary-generate", "--namespace", "tenant-a", "--token-type", "dns"])
    assert rc == 0


def test_canary_generate_command_rejects_invalid_namespace() -> None:
    rc = main(["canary-generate", "--namespace", "evil.attacker.com", "--token-type", "dns"])
    assert rc == 1


def test_canary_types_command_runs_with_defaults() -> None:
    rc = main(["canary-types"])
    assert rc == 0


def test_canary_inventory_commands_run_with_defaults() -> None:
    assert (
        main(
            [
                "canary-generate",
                "--config",
                "clownpeanuts/config/defaults.yml",
                "--namespace",
                "tenant-a",
                "--token-type",
                "http",
                "--metadata-json",
                "{\"campaign\":\"q1\"}",
            ]
        )
        == 0
    )
    assert main(["canary-tokens", "--config", "clownpeanuts/config/defaults.yml", "--limit", "5"]) == 0
    assert main(["canary-hits", "--config", "clownpeanuts/config/defaults.yml", "--limit", "5"]) == 0


def test_alerts_test_command_reports_disabled_and_enabled(tmp_path: Path) -> None:
    disabled_config_path = tmp_path / "disabled.yml"
    disabled_config_path.write_text(
        "environment: test\n"
        "alerts:\n"
        "  enabled: false\n"
        "services: []\n",
        encoding="utf-8",
    )
    assert main(["alerts-test", "--config", str(disabled_config_path)]) == 1

    enabled_config_path = tmp_path / "enabled.yml"
    enabled_config_path.write_text(
        "environment: test\n"
        "alerts:\n"
        "  enabled: true\n"
        "  min_severity: low\n"
        "  throttle_seconds: 0\n"
        "  destinations: []\n"
        "services: []\n",
        encoding="utf-8",
    )
    assert (
        main(
            [
                "alerts-test",
                "--config",
                str(enabled_config_path),
                "--severity",
                "high",
                "--metadata-json",
                "{\"channel\":\"smoke\"}",
            ]
        )
        == 0
    )


def test_alerts_routes_command_runs_with_defaults(tmp_path: Path) -> None:
    config_path = tmp_path / "alerts-routes.yml"
    config_path.write_text(
        "environment: test\n"
        "alerts:\n"
        "  enabled: true\n"
        "  min_severity: low\n"
        "  throttle_seconds: 0\n"
        "  destinations:\n"
        "    - name: webhook\n"
        "      type: webhook\n"
        "      endpoint: https://example.test/webhook\n"
        "      include_services: [ssh]\n"
        "services: []\n",
        encoding="utf-8",
    )
    assert (
        main(
            [
                "alerts-routes",
                "--config",
                str(config_path),
                "--severity",
                "high",
                "--service",
                "ssh",
                "--action",
                "command",
            ]
        )
        == 0
    )


def test_doctor_command_runs_with_defaults() -> None:
    rc = main(["doctor", "--config", "clownpeanuts/config/defaults.yml"])
    assert rc == 0


def test_doctor_command_returns_nonzero_for_invalid_templates(tmp_path: Path) -> None:
    template_path = tmp_path / "invalid-template.yml"
    template_path.write_text(
        "templates:\n"
        "  - service: ssh\n"
        "    ports: [\"invalid\"]\n",
        encoding="utf-8",
    )

    config_path = tmp_path / "config.yml"
    config_path.write_text(
        "environment: test\n"
        "services:\n"
        "  - name: ssh\n"
        "    module: clownpeanuts.services.ssh.emulator\n"
        "    ports: [2222]\n"
        "templates:\n"
        "  enabled: true\n"
        f"  paths: ['{template_path}']\n",
        encoding="utf-8",
    )

    rc = main(["doctor", "--config", str(config_path)])
    assert rc == 1


def test_api_command_requires_websocket_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("clownpeanuts.cli._websocket_runtime_available", lambda: False)

    with pytest.raises(RuntimeError, match="websocket dependencies are missing"):
        main(["api", "--config", "clownpeanuts/config/defaults.yml"])


def test_api_command_rejects_non_loopback_host_without_auth(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yml"
    config_path.write_text(
        "environment: test\n"
        "services: []\n",
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="non-loopback host without auth"):
        main(["api", "--config", str(config_path), "--host", "0.0.0.0"])


def test_api_command_allows_non_loopback_host_with_auth(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("clownpeanuts.cli._websocket_runtime_available", lambda: False)
    config_path = tmp_path / "config.yml"
    config_path.write_text(
        "environment: test\n"
        "api:\n"
        "  auth_enabled: true\n"
        "  auth_operator_tokens:\n"
        "    - operator-token-0123456789abcdef\n"
        "services: []\n",
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="websocket dependencies are missing"):
        main(["api", "--config", str(config_path), "--host", "0.0.0.0"])
