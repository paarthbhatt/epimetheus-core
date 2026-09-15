"""The scan pipeline: regex -> AST context -> entropy -> allowlist -> classifiers.

Stage order matches the detection methodology in docs/FORMAT_SPEC.md:

  1. regex candidates (RegexEngine)
  2. rule allowlist patterns (documented placeholder suppression)
  3. Shannon entropy + min length (Stage 3 validation)
  4. tree-sitter AST context (Stage 2 filtering; rejected matches are dropped
     when verified, reported unverified when the grammar is unavailable)
  5. classifier triage (heuristic always; optional LLM recorded alongside)

Suppression policy: a candidate is dropped only on allowlist, entropy,
verified AST rejection, or heuristic FALSE_POSITIVE. LLM triage is advisory by
default (``llm_suppress=False``): its verdict is recorded on the finding so a
human can triage, but a remote classifier never silently removes a candidate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from epimetheus_core.classifier.base import CandidateEvidence, Classifier, Verdict
from epimetheus_core.classifier.heuristic import HeuristicClassifier
from epimetheus_core.engines.ast_engine import AstEngine, detect_language
from epimetheus_core.engines.regex_engine import RegexEngine
from epimetheus_core.entropy import shannon_entropy
from epimetheus_core.findings import Finding, ScanReport, fingerprint, redact, utc_now
from epimetheus_core.rules import Rule, RuleSet

DEFAULT_EXCLUDED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "dist",
    "build",
    "target",
    ".eggs",
}

DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024


@dataclass
class ScannerConfig:
    strict_ast: bool = False
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    excluded_dirs: frozenset[str] = frozenset(DEFAULT_EXCLUDED_DIRS)
    llm_suppress: bool = False  # LLM false_positive verdicts suppress findings
    llm_suppress_confidence: float = 0.8
    ruleset: RuleSet | None = None
    heuristic: Classifier = field(default_factory=HeuristicClassifier)
    llm: Classifier | None = None


class Scanner:
    def __init__(self, config: ScannerConfig) -> None:
        if config.ruleset is None:
            raise ValueError("ScannerConfig.ruleset is required")
        self.config = config
        self.ruleset = config.ruleset
        self.regex_engine = RegexEngine()
        self.ast_engine = AstEngine()

    # -- file walking ---------------------------------------------------

    def _iter_files(self, root: Path):
        if root.is_file():
            yield root
            return
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            if any(part in self.config.excluded_dirs for part in path.parts):
                continue
            yield path

    @staticmethod
    def _looks_binary(data: bytes) -> bool:
        if b"\x00" in data[:8192]:
            return True
        return False

    # -- pipeline -------------------------------------------------------

    def _evidence_for(
        self, candidate, path: str, line_text: str, secret: str, entropy: float | None,
        ast_context: str, ast_verified: bool,
    ) -> CandidateEvidence:
        redacted_line = line_text.replace(secret, redact(secret))
        return CandidateEvidence(
            rule_id=candidate.rule.id,
            rule_name=candidate.rule.name,
            severity=candidate.rule.severity,
            expected_fp_rate=candidate.rule.expected_fp_rate,
            secret=secret,
            secret_preview=redact(secret),
            secret_fingerprint=fingerprint(secret),
            entropy=entropy,
            line_text=redacted_line,
            ast_context=ast_context,
            ast_verified=ast_verified,
            path=path,
        )

    def _evaluate_candidate(
        self, candidate, text: str, path: str, file_key: str, language
    ) -> Finding | None:
        rule: Rule = candidate.rule
        secret = candidate.secret

        lines = text.splitlines()
        line_text = lines[candidate.line - 1] if candidate.line - 1 < len(lines) else ""

        # Allowlist patterns are line-scoped (they may reference surrounding
        # syntax like `pk_live_` values or `*_KEY=pk_` assignments), so a hit
        # against the secret OR its containing line suppresses the candidate.
        for pattern in rule.allowlist:
            if pattern.search(secret) or pattern.search(line_text):
                return None

        entropy: float | None = None
        if rule.entropy is not None:
            entropy = shannon_entropy(secret)
            if len(secret) < rule.entropy.min_length:
                return None
            if entropy < rule.entropy.min_shannon:
                return None

        if rule.ast_context:
            byte_start = len(text[: candidate.match_start].encode("utf-8"))
            byte_end = max(byte_start + 1, len(text[: candidate.match_end].encode("utf-8")))
            ast = self.ast_engine.check(
                file_key, language, path, byte_start, byte_end, rule.ast_context,
                strict=self.config.strict_ast,
            )
            if not ast.allowed:
                return None
            ast_context, ast_verified = ast.context, ast.verified
        else:
            ast_context, ast_verified = "unfiltered", False

        evidence = self._evidence_for(
            candidate, path, line_text, secret, entropy, ast_context, ast_verified
        )

        heuristic_result = self.config.heuristic.classify(evidence)
        if heuristic_result.verdict is Verdict.FALSE_POSITIVE:
            return None

        llm_verdict = None
        llm_confidence = None
        if self.config.llm is not None:
            llm_result = self.config.llm.classify(evidence)
            llm_verdict = llm_result.verdict.value
            llm_confidence = llm_result.confidence
            if (
                self.config.llm_suppress
                and llm_result.verdict is Verdict.FALSE_POSITIVE
                and llm_result.confidence >= self.config.llm_suppress_confidence
            ):
                return None

        return Finding(
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.severity,
            category=rule.category,
            cwe=rule.cwe,
            owasp_llm_2025=rule.owasp_llm_2025,
            path=path,
            line=candidate.line,
            column=candidate.column,
            secret_preview=redact(secret),
            secret_fingerprint=fingerprint(secret),
            entropy=entropy,
            ast_context=ast_context,
            ast_verified=ast_verified,
            classifier=heuristic_result.classifier,
            classifier_verdict=heuristic_result.verdict.value,
            classifier_confidence=heuristic_result.confidence,
            classifier_reasoning=heuristic_result.reasoning,
            llm_verdict=llm_verdict,
            llm_confidence=llm_confidence,
            remediation=rule.remediation,
        )

    def scan_text(self, text: str, path: str = "snippet.txt") -> list[Finding]:
        """Scan an in-memory string (used by tests and the rule conformance suite)."""
        report = self._scan_single(Path(path).name, text)
        return report.findings

    def _scan_single(self, display_path: str, text: str) -> ScanReport:
        started = utc_now()
        language = detect_language(display_path)
        file_key = display_path
        self.ast_engine.prepare_file(file_key, language, text)

        findings: list[Finding] = []
        for rule in self.ruleset:
            for candidate in self.regex_engine.scan_text(text, rule):
                finding = self._evaluate_candidate(
                    candidate, text, display_path, file_key, language
                )
                if finding is not None:
                    findings.append(finding)
        return ScanReport(
            root=display_path,
            started_at=started,
            finished_at=utc_now(),
            files_scanned=1,
            files_skipped=0,
            rules_loaded=len(self.ruleset),
            findings=findings,
        )

    def scan_path(self, root: str | Path) -> ScanReport:
        root_path = Path(root)
        if not root_path.exists():
            raise FileNotFoundError(f"scan target does not exist: {root_path}")

        started = utc_now()
        findings: list[Finding] = []
        files_scanned = 0
        files_skipped = 0
        ast_degraded: set[str] = set()

        for path in self._iter_files(root_path):
            try:
                data = path.read_bytes()
            except OSError:
                files_skipped += 1
                continue
            if len(data) > self.config.max_file_bytes or self._looks_binary(data):
                files_skipped += 1
                continue
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                files_skipped += 1
                continue

            files_scanned += 1
            rel_path = str(path.relative_to(root_path)) if root_path.is_dir() else path.name
            language = detect_language(rel_path)
            if language and language != "env":
                self.ast_engine.prepare_file(rel_path, language, text)
                if rel_path not in self.ast_engine._trees:
                    ast_degraded.add(rel_path)

            for rule in self.ruleset:
                for candidate in self.regex_engine.scan_text(text, rule):
                    finding = self._evaluate_candidate(
                        candidate, text, rel_path, rel_path, language
                    )
                    if finding is not None:
                        findings.append(finding)

        return ScanReport(
            root=str(root_path),
            started_at=started,
            finished_at=utc_now(),
            files_scanned=files_scanned,
            files_skipped=files_skipped,
            rules_loaded=len(self.ruleset),
            ast_degraded_files=sorted(ast_degraded),
            findings=findings,
        )
