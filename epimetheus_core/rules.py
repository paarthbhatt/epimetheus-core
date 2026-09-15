"""Rule model and ruleset loading for the Epimetheus rules format (v1.x).

The rules JSON is a public, versioned interface — see docs/FORMAT_SPEC.md.
Loading validates the structure and every regex up front so a malformed rules
file fails loudly at load time instead of silently mid-scan.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SUPPORTED_SCHEMA_MAJOR = 1

_FLAG_MAP = {
    "": 0,
    "IGNORECASE": re.IGNORECASE,
    "I": re.IGNORECASE,
    "MULTILINE": re.MULTILINE,
    "M": re.MULTILINE,
}


class RuleSetError(ValueError):
    """Raised when a rules file violates the Epimetheus rules format."""


@dataclass(frozen=True)
class EntropyPolicy:
    min_shannon: float
    min_length: int


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    description: str
    severity: str
    category: str
    pattern: re.Pattern[str]
    raw_pattern: str
    ast_context: tuple[str, ...]
    allowlist: tuple[re.Pattern[str], ...]
    entropy: EntropyPolicy | None
    cwe: tuple[str, ...] = ()
    owasp_llm_2025: str = ""
    owasp_llm_2023: str = ""
    owasp_llm_secondary: str = ""
    expected_fp_rate: str = ""
    remediation: dict[str, str] = field(default_factory=dict)


def _compile(pattern: str, flags: str, rule_id: str, what: str) -> re.Pattern[str]:
    try:
        return re.compile(pattern, _FLAG_MAP.get(flags.upper(), 0))
    except re.error as exc:
        raise RuleSetError(f"[{rule_id}] invalid {what} regex: {exc}") from exc


def _parse_rule(raw: dict[str, Any], index: int) -> Rule:
    rule_id = raw.get("id") or f"<rule #{index}>"

    for key in ("name", "description", "severity", "category"):
        if not raw.get(key):
            raise RuleSetError(f"[{rule_id}] missing required field: {key}")

    detection = raw.get("detection") or {}
    if not detection.get("pattern"):
        raise RuleSetError(f"[{rule_id}] missing detection.pattern")

    entropy_raw = detection.get("entropy") or None
    entropy = None
    if entropy_raw:
        try:
            entropy = EntropyPolicy(
                min_shannon=float(entropy_raw["min_shannon"]),
                min_length=int(entropy_raw["min_length"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise RuleSetError(f"[{rule_id}] invalid entropy policy: {exc}") from exc

    mappings = raw.get("mappings") or {}
    remediation = raw.get("remediation") or {}

    return Rule(
        id=rule_id,
        name=raw["name"],
        description=raw["description"],
        severity=raw["severity"].upper(),
        category=raw["category"],
        pattern=_compile(detection["pattern"], detection.get("flags", ""), rule_id, "detection"),
        raw_pattern=detection["pattern"],
        ast_context=tuple(detection.get("ast_context") or ()),
        allowlist=tuple(
            _compile(p, "", rule_id, "allowlist") for p in detection.get("allowlist_patterns") or []
        ),
        entropy=entropy,
        cwe=tuple(mappings.get("cwe") or ()),
        owasp_llm_2025=mappings.get("owasp_llm_2025", ""),
        owasp_llm_2023=mappings.get("owasp_llm_2023", ""),
        owasp_llm_secondary=mappings.get("owasp_llm_secondary", ""),
        expected_fp_rate=(raw.get("false_positive_analysis") or {}).get("expected_rate", ""),
        remediation={
            k: str(v) for k, v in remediation.items() if isinstance(v, (str, int, float))
        },
    )


class RuleSet:
    """A validated collection of detection rules."""

    def __init__(self, rules: list[Rule], schema_version: str, source: str = "<memory>"):
        self.rules = rules
        self.schema_version = schema_version
        self.source = source
        self.by_id: dict[str, Rule] = {}
        for rule in rules:
            if rule.id in self.by_id:
                raise RuleSetError(f"duplicate rule id: {rule.id}")
            self.by_id[rule.id] = rule

    def __len__(self) -> int:
        return len(self.rules)

    def __iter__(self):
        return iter(self.rules)

    @classmethod
    def from_file(cls, path: str | Path) -> RuleSet:
        path = Path(path)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuleSetError(f"cannot load rules file {path}: {exc}") from exc
        return cls.from_dict(data, source=str(path))

    @classmethod
    def from_dict(cls, data: dict[str, Any], source: str = "<memory>") -> RuleSet:
        version = str(data.get("schema_version", ""))
        try:
            major = int(version.split(".")[0])
        except ValueError as exc:
            raise RuleSetError(
                f"rules schema_version must be semver, got {version!r}"
            ) from exc
        if major != SUPPORTED_SCHEMA_MAJOR:
            raise RuleSetError(
                f"rules schema_version {version} is unsupported "
                f"(supported major: {SUPPORTED_SCHEMA_MAJOR})"
            )
        raw_rules = data.get("rules")
        if not isinstance(raw_rules, list) or not raw_rules:
            raise RuleSetError("rules file must contain a non-empty 'rules' array")
        rules = [_parse_rule(raw, i) for i, raw in enumerate(raw_rules)]
        return cls(rules, version, source)
