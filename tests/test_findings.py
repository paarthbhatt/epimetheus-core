"""Findings format (epimetheus.findings/v1) and SARIF export invariants."""

from __future__ import annotations

import json

from epimetheus_core import __version__
from epimetheus_core.findings import (
    FINDINGS_SCHEMA,
    Finding,
    ScanReport,
    fingerprint,
    redact,
    to_sarif,
)

SECRET = "sk-proj-aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ3aB4cD5eF6gH"


def _finding(**overrides) -> Finding:
    fields = dict(
        rule_id="EPI-SEC-001",
        rule_name="OpenAI API Key",
        severity="CRITICAL",
        category="ai_llm_credentials",
        cwe=("CWE-798", "CWE-312"),
        owasp_llm_2025="LLM02:2025 - Sensitive Information Disclosure",
        path="src/config.py",
        line=3,
        column=11,
        secret_preview=redact(SECRET),
        secret_fingerprint=fingerprint(SECRET),
        entropy=4.6,
        ast_context="variable_declarator",
        ast_verified=True,
        classifier="heuristic",
        classifier_verdict="true_positive",
        classifier_confidence=0.95,
        classifier_reasoning="no placeholder markers",
        remediation={"provider_rotation": "1. Rotate..."},
    )
    fields.update(overrides)
    return Finding(**fields)


def _report(findings=None) -> ScanReport:
    return ScanReport(
        root=".",
        started_at="2026-09-15T00:00:00+00:00",
        finished_at="2026-09-15T00:00:01+00:00",
        files_scanned=10,
        files_skipped=2,
        rules_loaded=20,
        findings=findings if findings is not None else [_finding()],
    )


def test_redact_preserves_head_and_tail():
    assert redact(SECRET) == "sk-pro****F6gH"
    assert redact("short") == "sh***"
    assert redact("") == ""
    assert "****" in redact(SECRET)


def test_fingerprint_stable_and_distinct():
    assert fingerprint("abc") == fingerprint("abc")
    assert fingerprint("abc") != fingerprint("abd")
    assert fingerprint("abc").startswith("sha256:")


def test_finding_dict_has_no_raw_secret():
    doc = _finding().to_dict()
    assert SECRET not in json.dumps(doc)
    assert "****" in doc["secret"]["preview"]
    assert doc["secret"]["fingerprint"].startswith("sha256:")


def test_report_schema_is_pinned():
    doc = _report().to_dict(__version__)
    assert doc["schema"] == FINDINGS_SCHEMA == "epimetheus.findings/v1"
    assert doc["tool"]["name"] == "epimetheus-core"
    assert doc["scan"]["files_scanned"] == 10
    assert doc["summary"] == {"CRITICAL": 1}
    assert len(doc["findings"]) == 1


def test_report_with_llm_triage_carries_it():
    doc = _report([_finding(llm_verdict="true_positive", llm_confidence=0.9)]).to_dict(
        __version__
    )
    assert doc["findings"][0]["llm_triage"] == {"verdict": "true_positive", "confidence": 0.9}


def test_summary_orders_by_severity():
    report = _report(
        [_finding(), _finding(severity="HIGH", rule_id="EPI-SEC-005")]
    )
    assert report.summary() == {"CRITICAL": 1, "HIGH": 1}


def test_sarif_structure():
    rules_meta = {
        "EPI-SEC-001": {
            "name": "OpenAI API Key",
            "severity": "CRITICAL",
            "category": "ai_llm_credentials",
            "cwe": ["CWE-798"],
            "owasp_llm_2025": "LLM02:2025",
        }
    }
    sarif = to_sarif(_report(), rules_meta, __version__)
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "epimetheus-core"
    assert run["tool"]["driver"]["rules"][0]["id"] == "EPI-SEC-001"
    result = run["results"][0]
    assert result["ruleId"] == "EPI-SEC-001"
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 3
    assert SECRET not in json.dumps(sarif)


def test_sarif_level_mapping():
    assert _finding(severity="HIGH").severity == "HIGH"
    sarif = to_sarif(
        _report([_finding(severity="HIGH")]), {"EPI-SEC-001": {}}, __version__
    )
    assert sarif["runs"][0]["results"][0]["level"] == "warning"
