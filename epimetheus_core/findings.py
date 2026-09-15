"""The findings record format (``epimetheus.findings/v1``) and SARIF export.

The findings document is a public, versioned interface — see
docs/FORMAT_SPEC.md for the schema, stability guarantees, and change policy.
Two invariants hold by construction and are enforced by tests:

  * no serialized finding ever contains the raw secret — only a redacted
    preview and a sha256 fingerprint;
  * ``schema`` pins the format version, so consumers can gate on it.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

FINDINGS_SCHEMA = "epimetheus.findings/v1"

SARIF_LEVELS = {"CRITICAL": "error", "HIGH": "warning", "MEDIUM": "note", "LOW": "note"}
SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def redact(secret: str) -> str:
    """Redact a secret, keeping a short identifying head and tail."""
    if not secret:
        return ""
    if len(secret) <= 8:
        return secret[:2] + "***"
    head = secret[:6]
    tail = secret[-4:] if len(secret) >= 14 else ""
    return f"{head}****{tail}"


def fingerprint(secret: str) -> str:
    """Stable non-reversible identifier for a secret (for dedup/tracking)."""
    return "sha256:" + hashlib.sha256(secret.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class Finding:
    rule_id: str
    rule_name: str
    severity: str
    category: str
    cwe: tuple[str, ...]
    owasp_llm_2025: str
    path: str
    line: int
    column: int
    secret_preview: str
    secret_fingerprint: str
    entropy: float | None
    ast_context: str
    ast_verified: bool
    classifier: str
    classifier_verdict: str
    classifier_confidence: float
    classifier_reasoning: str
    llm_verdict: str | None = None
    llm_confidence: float | None = None
    remediation: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        doc: dict[str, Any] = {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "category": self.category,
            "cwe": list(self.cwe),
            "owasp_llm_2025": self.owasp_llm_2025,
            "location": {
                "path": self.path,
                "line": self.line,
                "column": self.column,
            },
            "secret": {
                "preview": self.secret_preview,
                "fingerprint": self.secret_fingerprint,
            },
            "entropy_bits_per_char": self.entropy,
            "ast_context": self.ast_context,
            "ast_verified": self.ast_verified,
            "classifier": {
                "name": self.classifier,
                "verdict": self.classifier_verdict,
                "confidence": self.classifier_confidence,
                "reasoning": self.classifier_reasoning,
            },
            "remediation": self.remediation,
        }
        if self.llm_verdict is not None:
            doc["llm_triage"] = {
                "verdict": self.llm_verdict,
                "confidence": self.llm_confidence,
            }
        return doc


@dataclass
class ScanReport:
    root: str
    started_at: str
    finished_at: str
    files_scanned: int
    files_skipped: int
    rules_loaded: int
    ast_degraded_files: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: -SEVERITY_ORDER.get(kv[0], 0)))

    def to_dict(self, tool_version: str) -> dict[str, Any]:
        return {
            "schema": FINDINGS_SCHEMA,
            "tool": {"name": "epimetheus-core", "version": tool_version},
            "scan": {
                "root": self.root,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "files_scanned": self.files_scanned,
                "files_skipped": self.files_skipped,
                "rules_loaded": self.rules_loaded,
                "ast_degraded_files": sorted(self.ast_degraded_files),
            },
            "summary": self.summary(),
            "findings": [f.to_dict() for f in self.findings],
        }


def to_sarif(report: ScanReport, rules_meta: dict[str, dict[str, Any]], tool_version: str) -> dict:
    """Export a report as a SARIF 2.1.0 log for CI integrations."""
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "epimetheus-core",
                        "version": tool_version,
                        "informationUri": "https://github.com/paarthbhatt/epimetheus-core",
                        "rules": [
                            {
                                "id": rule_id,
                                "shortDescription": {"text": meta.get("name", rule_id)},
                                "properties": {
                                    "severity": meta.get("severity", ""),
                                    "category": meta.get("category", ""),
                                    "cwe": meta.get("cwe", []),
                                    "owasp_llm_2025": meta.get("owasp_llm_2025", ""),
                                },
                            }
                            for rule_id, meta in sorted(rules_meta.items())
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": finding.rule_id,
                        "level": SARIF_LEVELS.get(finding.severity, "note"),
                        "message": {
                            "text": (
                                f"{finding.rule_name}: potential {finding.severity} secret "
                                f"({finding.secret_fingerprint}). "
                                f"AST context: {finding.ast_context or 'unverified'}."
                            )
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": finding.path},
                                    "region": {
                                        "startLine": finding.line,
                                        "startColumn": finding.column,
                                    },
                                }
                            }
                        ],
                        "partialFingerprints": {"epimetheus/secret": finding.secret_fingerprint},
                    }
                    for finding in report.findings
                ],
            }
        ],
    }


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
