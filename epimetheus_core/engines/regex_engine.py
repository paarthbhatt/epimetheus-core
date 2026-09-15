"""Stage 1 — primary pattern matching.

Runs each rule's compiled regex over file text and emits candidates carrying
the extracted secret (first non-None capture group, else the whole match).
"""

from __future__ import annotations

from dataclasses import dataclass

from epimetheus_core.rules import Rule


@dataclass(frozen=True)
class Candidate:
    """A raw regex hit, before filtering and classification."""

    rule: Rule
    secret: str
    line: int  # 1-based
    column: int  # 1-based, in characters
    match_start: int  # character offset of the secret in the file text
    match_end: int


class RegexEngine:
    def scan_text(self, text: str, rule: Rule) -> list[Candidate]:
        candidates: list[Candidate] = []
        for match in rule.pattern.finditer(text):
            secret = match.group(0)
            for group in match.groups():
                if group:
                    secret = group
                    break
            line = text.count("\n", 0, match.start()) + 1
            last_nl = text.rfind("\n", 0, match.start())
            column = match.start() - last_nl
            candidates.append(
                Candidate(
                    rule=rule,
                    secret=secret,
                    line=line,
                    column=column,
                    match_start=match.start(),
                    match_end=match.end(),
                )
            )
        return candidates
