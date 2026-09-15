"""Rules format loading/validation and full-pipeline rule conformance.

The conformance tests run every rule's true-positive and true-negative cases
through the ENTIRE pipeline (regex -> allowlist -> entropy -> AST -> heuristic
classifier), which is a strictly stronger guarantee than the original
regex-only harness that shipped with the rules (118/118).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from epimetheus_core.rules import RuleSet, RuleSetError

RULES_FILE = Path(__file__).resolve().parent.parent / "rules" / "secret_rules.json"


def _load_raw() -> dict:
    return json.loads(RULES_FILE.read_text(encoding="utf-8"))


# ---------------------------------------------------------------- loading

def test_ruleset_loads(ruleset):
    assert len(ruleset) == 20
    assert ruleset.schema_version == "1.0.0"
    assert ruleset.by_id["EPI-SEC-001"].severity == "CRITICAL"
    assert "CWE-798" in ruleset.by_id["EPI-SEC-010"].cwe


def test_ruleset_rejects_unsupported_major():
    data = _load_raw()
    data["schema_version"] = "2.0.0"
    with pytest.raises(RuleSetError, match="unsupported"):
        RuleSet.from_dict(data)


def test_ruleset_rejects_missing_fields():
    with pytest.raises(RuleSetError, match="missing required field"):
        RuleSet.from_dict({"schema_version": "1.0.0", "rules": [{"id": "X"}]})


def test_ruleset_rejects_invalid_regex():
    data = _load_raw()
    data["rules"][0]["detection"]["pattern"] = "([unclosed"
    with pytest.raises(RuleSetError, match="invalid detection regex"):
        RuleSet.from_dict(data)


def test_ruleset_rejects_duplicate_ids():
    data = _load_raw()
    data["rules"].append(dict(data["rules"][0]))
    with pytest.raises(RuleSetError, match="duplicate rule id"):
        RuleSet.from_dict(data)


def test_ruleset_rejects_empty_rules():
    with pytest.raises(RuleSetError, match="non-empty"):
        RuleSet.from_dict({"schema_version": "1.0.0", "rules": []})


def test_ruleset_rejects_bad_version_string():
    with pytest.raises(RuleSetError, match="semver"):
        RuleSet.from_dict({"schema_version": "banana", "rules": [{}]})


# ---------------------------------------------------------- conformance

def _cases():
    data = _load_raw()
    for rule in data["rules"]:
        for snippet in rule["test_cases"]["true_positives"]:
            yield pytest.param(rule["id"], snippet, True, id=f"{rule['id']}-tp")
        for snippet in rule["test_cases"]["true_negatives"]:
            yield pytest.param(rule["id"], snippet, False, id=f"{rule['id']}-tn")


@pytest.mark.parametrize("rule_id,snippet,expected_finding", list(_cases()))
def test_rule_conformance_full_pipeline(make_scanner, rule_id, snippet, expected_finding):
    """Every documented test case through the complete scan pipeline."""
    scanner = make_scanner()
    findings = scanner.scan_text(snippet)
    rule_findings = [f for f in findings if f.rule_id == rule_id]
    if expected_finding:
        assert rule_findings, f"{rule_id} should fire on: {snippet!r}"
    else:
        assert not rule_findings, (
            f"{rule_id} should NOT fire on: {snippet!r} "
            f"(matched via {[f.rule_id for f in findings]})"
        )


def test_negative_cases_produce_zero_findings_from_any_rule(make_scanner):
    """Global precision: no rule may fire on any documented negative case."""
    scanner = make_scanner()
    for rule in _load_raw()["rules"]:
        for snippet in rule["test_cases"]["true_negatives"]:
            findings = scanner.scan_text(snippet)
            assert not findings, (
                f"cross-rule false positive on {rule['id']} negative: {snippet!r} "
                f"-> {[f.rule_id for f in findings]}"
            )


def test_positive_case_counts():
    """The rules file carries the full 118-case suite (57 TP + 61 TN)."""
    data = _load_raw()
    tp = sum(len(r["test_cases"]["true_positives"]) for r in data["rules"])
    tn = sum(len(r["test_cases"]["true_negatives"]) for r in data["rules"])
    assert (tp, tn) == (57, 61)
