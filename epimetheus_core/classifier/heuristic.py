"""Deterministic placeholder classifier — the always-on triage stage.

Suppression doctrine: only reject a candidate when the extracted secret itself
looks like documentation/test placeholder material (EXAMPLE runs, repeated
dummy characters, template interpolations). Everything else is reported —
evidence or silence, never silence without evidence.
"""

from __future__ import annotations

import re

from epimetheus_core.classifier.base import CandidateEvidence, Classification, Verdict

_PLACEHOLDER_MARKERS = (
    "example",
    "xxxx",
    "xxx",
    "your_",
    "your-",
    "<your",
    "placeholder",
    "changeme",
    "change_me",
    "replace_me",
    "dummy",
    "sample",
    "not_real",
    "notareal",
    "do_not",
    "redacted",
    "fakekey",
    "test_key",
    "for_testing",
    "for-testing",
)

_TEMPLATE_PATTERNS = (
    re.compile(r"\$\{[^}]*\}"),
    re.compile(r"\{\{[^}]*\}\}"),
    re.compile(r"<[a-z_][a-z0-9_]*>", re.IGNORECASE),
)

_MAX_DOMINANT_RATIO = 0.8  # one character covering >= 80% of the secret


def _is_dominant_char(secret: str) -> bool:
    if not secret:
        return False
    counts: dict[str, int] = {}
    for ch in secret:
        counts[ch] = counts.get(ch, 0) + 1
    return max(counts.values()) / len(secret) >= _MAX_DOMINANT_RATIO


class HeuristicClassifier:
    name = "heuristic"

    def classify(self, evidence: CandidateEvidence) -> Classification:
        secret = evidence.secret
        lowered = secret.lower()

        for marker in _PLACEHOLDER_MARKERS:
            if marker in lowered:
                return Classification(
                    verdict=Verdict.FALSE_POSITIVE,
                    confidence=0.95,
                    reasoning=f"secret preview contains placeholder marker {marker!r}",
                    classifier=self.name,
                )

        for pattern in _TEMPLATE_PATTERNS:
            if pattern.search(secret):
                return Classification(
                    verdict=Verdict.FALSE_POSITIVE,
                    confidence=0.95,
                    reasoning="secret preview contains an unresolved template interpolation",
                    classifier=self.name,
                )

        if _is_dominant_char(secret):
            return Classification(
                verdict=Verdict.FALSE_POSITIVE,
                confidence=0.9,
                reasoning="secret is dominated by a single repeated character",
                classifier=self.name,
            )

        confidence = 0.85
        if evidence.entropy is not None and evidence.entropy >= 4.2:
            confidence = 0.95
        if evidence.ast_verified:
            confidence = min(1.0, confidence + 0.02)

        return Classification(
            verdict=Verdict.TRUE_POSITIVE,
            confidence=confidence,
            reasoning="no placeholder markers, high-entropy secret in an assignment context",
            classifier=self.name,
        )
