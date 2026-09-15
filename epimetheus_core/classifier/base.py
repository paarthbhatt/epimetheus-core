"""Classifier contracts shared by the heuristic and LLM implementations."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol


class Verdict(str, Enum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class Classification:
    verdict: Verdict
    confidence: float  # 0.0 - 1.0
    reasoning: str = ""
    classifier: str = ""
    model: str = ""


@dataclass(frozen=True)
class CandidateEvidence:
    """What a classifier may see about a candidate.

    Data-flow contract (docs/FORMAT_SPEC.md): ``secret`` is the raw value and
    is for IN-PROCESS classifiers only. ``secret_preview`` (redacted) and
    ``secret_fingerprint`` are the only forms permitted to leave the process —
    any external classifier (e.g. the LLM triage stage) must build its request
    exclusively from those. This is a hard security invariant of the core.
    """

    rule_id: str
    rule_name: str
    severity: str
    expected_fp_rate: str
    secret: str  # raw secret — in-process consumers only, never serialized
    secret_preview: str  # redacted, e.g. "sk-proj-ab****cDEF"
    secret_fingerprint: str  # "sha256:<16 hex chars>"
    entropy: float | None
    line_text: str  # the source line, secret redacted
    ast_context: str
    ast_verified: bool
    path: str


class Classifier(Protocol):
    name: str

    def classify(self, evidence: CandidateEvidence) -> Classification: ...
