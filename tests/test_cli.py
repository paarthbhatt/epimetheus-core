"""CLI behavior tests (scan, rules validate/list, exit codes)."""

from __future__ import annotations

import json

import pytest

from epimetheus_core import cli

RULES = "rules/secret_rules.json"
SECRET_LINE = 'api_key = "sk-proj-aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ3aB4cD5eF6gH"'


@pytest.fixture()
def target(tmp_path):
    (tmp_path / "config.py").write_text(f"import os\n{SECRET_LINE}\n", encoding="utf-8")
    return tmp_path


def test_cli_scan_summary(capsys, target):
    code = cli.main(["scan", str(target), "--rules", RULES, "--no-llm"])
    out = capsys.readouterr().out
    assert code == 0
    assert "EPI-SEC-001" in out
    assert "sk-proj-aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ3aB4cD5eF6gH" not in out


def test_cli_scan_json(capsys, target):
    code = cli.main(
        ["scan", str(target), "--rules", RULES, "--format", "json", "--no-llm"]
    )
    doc = json.loads(capsys.readouterr().out)
    assert code == 0
    assert doc["schema"] == "epimetheus.findings/v1"
    assert doc["findings"][0]["rule_id"] == "EPI-SEC-001"


def test_cli_scan_sarif(capsys, target):
    code = cli.main(
        ["scan", str(target), "--rules", RULES, "--format", "sarif", "--no-llm"]
    )
    doc = json.loads(capsys.readouterr().out)
    assert code == 0
    assert doc["version"] == "2.1.0"


def test_cli_fail_on_gate(capsys, target):
    code = cli.main(
        ["scan", str(target), "--rules", RULES, "--fail-on", "HIGH", "--no-llm"]
    )
    assert code == 1


def test_cli_clean_scan_exit_zero(capsys, tmp_path):
    (tmp_path / "ok.py").write_text("x = 1\n", encoding="utf-8")
    code = cli.main(["scan", str(tmp_path), "--rules", RULES, "--no-llm"])
    assert code == 0


def test_cli_rules_validate(capsys):
    assert cli.main(["rules", "validate", RULES]) == 0
    assert "20 rules" in capsys.readouterr().out


def test_cli_rules_list(capsys):
    assert cli.main(["rules", "list", RULES]) == 0
    out = capsys.readouterr().out
    assert "EPI-SEC-001" in out and "EPI-SEC-020" in out


def test_cli_bad_rules_file(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text('{"schema_version": "9.0.0", "rules": []}', encoding="utf-8")
    assert cli.main(["rules", "validate", str(bad)]) == 2
    assert "error" in capsys.readouterr().err


def test_cli_missing_path(target, capsys):
    assert cli.main(["scan", "/nonexistent-path-xyz", "--rules", RULES]) == 2
    assert "error" in capsys.readouterr().err


def test_cli_output_file(target, tmp_path, capsys):
    out_file = tmp_path / "report.json"
    code = cli.main(
        [
            "scan", str(target), "--rules", RULES, "--format", "json",
            "--output", str(out_file), "--no-llm",
        ]
    )
    assert code == 0
    assert capsys.readouterr().out == ""
    assert json.loads(out_file.read_text())["schema"] == "epimetheus.findings/v1"
