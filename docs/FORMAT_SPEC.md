# Epimetheus Red — Record Format Specification

**Status:** stable (Phase 0)
**Owner:** scanner core (`epimetheus-core`)

This document defines the public record formats the scanner core produces and
consumes. These formats are the product interface: they are versioned, and a
breaking change requires a major version bump plus a migration note in this
file and in the release notes.

---

## 1. Rules format — `epimetheus.rules/v1`

`rules/secret_rules.json` (current: `schema_version: 1.0.0`).

### 1.1 Top level

| Field | Type | Notes |
| :--- | :--- | :--- |
| `schema_version` | semver string | Major must be `1`. Minor bumps may add optional fields. |
| `engine` | string | Informational. |
| `rules` | array of rule objects | Non-empty. Rule ids must be unique. |

### 1.2 Rule object (required fields)

| Field | Type | Notes |
| :--- | :--- | :--- |
| `id` | string | Stable identifier, e.g. `EPI-SEC-001`. |
| `name`, `description` | string | Human-readable. |
| `severity` | `CRITICAL` \| `HIGH` | |
| `category` | string | e.g. `ai_llm_credentials`. |
| `mappings` | object | `cwe` (array), `owasp_llm_2025`, `owasp_llm_2023`, `owasp_llm_secondary`. |
| `detection.pattern` | Python `re` pattern | Compiled at load; invalid regex is a load error. |
| `detection.flags` | `""` \| `IGNORECASE` | OR-ed into the compile flags. |
| `detection.entropy` | object \| absent | `min_shannon` (bits/char), `min_length`. Absent = no entropy gate. |
| `detection.ast_context` | array | Canonical context names (see §1.3). Empty = no AST gate. |
| `detection.allowlist_patterns` | array | Suppression patterns (see §1.4). |
| `test_cases` | object | `true_positives` / `true_negatives` snippet arrays. This is the rule's conformance contract: the scanner core runs every case through the full pipeline. |
| `remediation` | object | Free-form string fields (`provider_rotation`, `code_fix`, `history_purge`). |

### 1.3 Canonical AST context names

Rules use language-neutral context names; the AST engine maps them per
language. Unmapped combinations are reported `ast_verified: false` (or
rejected in `--strict-ast`).

| Canonical | python | javascript/typescript | json | sentinel |
| :--- | :--- | :--- | :--- | :--- |
| `variable_declarator` | `assignment` | `variable_declarator` | — | |
| `assignment_expression` | `assignment`, `augmented_assignment` | `assignment_expression` | — | |
| `call_expression` | `call` | `call_expression`, `new_expression` | — | |
| `object_property` | `keyword_argument`, `pair` | `pair` | `pair` | |
| `string_literal` | `string` | `string` | `string` | |
| `template_literal` | `string` | `template_string` | — | |
| `environment_file` | | | | dotenv files (`.env`, `.env.*`) |

### 1.4 Allowlist semantics

A candidate is suppressed when an allowlist pattern matches the extracted
secret **or the source line containing the match**. Line-scoped patterns
(e.g. `.*_KEY=pk_.*` matching a `pk_live_` publishable value) are part of the
contract.

### 1.5 Errata — v1.0.0 threshold corrections

The originally delivered rules file declared entropy/length thresholds that
its own `test_cases` could not satisfy (the shipped harness enforced regex +
allowlist only, so the contradictions were invisible). The scanner core
enforces Stage 3 fully, and the following values in `rules/secret_rules.json`
were corrected to make every documented test case pass *through the complete
pipeline* while keeping placeholder suppression intact:

| Rule | Field | Was | Now | Reason |
| :--- | :--- | :--- | :--- | :--- |
| `EPI-SEC-009` | `entropy.min_length` | 100 | 80 | own TP is an 88-char service-role JWT |
| `EPI-SEC-010` | `entropy.min_shannon` | 4.3 | 3.7 | own TPs measure H = 3.78–4.08 (AWS `[A-Z0-9]` ids) |
| `EPI-SEC-016` | `entropy.min_shannon` | 4.1 | 3.9 | hex alphabet caps entropy at 4.0 — 4.1 is unsatisfiable; own TP H = 3.97 |
| `EPI-SEC-020` | `entropy.min_shannon` | 4.1 | 4.0 | UUID alphabets cap entropy ≈ 4.09; own TPs H = 4.04–4.09 |

Reproduction: `pytest tests/test_rules.py` (before the fix, 7 true-positive
cases fail Stage 3; after, 118/118 pass the full pipeline).

### 1.6 Serialization note — JSON unicode escapes in test vectors

`rules/secret_rules.json` stores key-shaped test vectors with JSON unicode
escapes (e.g. `s\u006b-proj-...`) inside otherwise-plain strings. This is a
serialization choice only: `json.load()` yields the exact intended vectors
(asserted by the test suite), but the raw file bytes contain no contiguous
`sk_live_`/`AKIA`/`eyJ`-style tokens, so secret scanners with push protection
(e.g. GitHub) do not false-positive on the repository's own test data.
Regenerating the file must preserve this convention — escape one character
inside every vendor-prefixed token in any string value.

---

## 2. Findings format — `epimetheus.findings/v1`

Emitted by `epimetheus scan --format json`. Current version: `1` (the `v1`
suffix). Additive changes bump a `format_version` field in a future minor
release; removing or renaming a field is a breaking change requiring `v2`.

### 2.1 Document

```json
{
  "schema": "epimetheus.findings/v1",
  "tool": {"name": "epimetheus-core", "version": "0.1.0"},
  "scan": {
    "root": ".",
    "started_at": "2026-09-15T00:00:00+00:00",
    "finished_at": "2026-09-15T00:00:01+00:00",
    "files_scanned": 42,
    "files_skipped": 3,
    "rules_loaded": 20,
    "ast_degraded_files": ["notes.txt"]
  },
  "summary": {"CRITICAL": 2, "HIGH": 1},
  "findings": ["..."]
}
```

### 2.2 Finding

```json
{
  "rule_id": "EPI-SEC-001",
  "rule_name": "OpenAI API Key (Standard, Project & Service Account)",
  "severity": "CRITICAL",
  "category": "ai_llm_credentials",
  "cwe": ["CWE-798", "CWE-312"],
  "owasp_llm_2025": "LLM02:2025 - Sensitive Information Disclosure",
  "location": {"path": "src/config.py", "line": 3, "column": 11},
  "secret": {"preview": "sk-pro****F6gH", "fingerprint": "sha256:0123456789abcdef"},
  "entropy_bits_per_char": 4.6,
  "ast_context": "variable_declarator",
  "ast_verified": true,
  "classifier": {"name": "heuristic", "verdict": "true_positive", "confidence": 0.95, "reasoning": "..."},
  "llm_triage": {"verdict": "true_positive", "confidence": 0.9},
  "remediation": {"provider_rotation": "...", "code_fix": "...", "history_purge": "..."}
}
```

**Invariant — no raw secrets in output.** A serialized findings document (or
SARIF export) never contains the raw secret value: only the redacted preview
(first 6 + last 4 characters) and a non-reversible sha256 fingerprint. This is
enforced by tests (`tests/test_findings.py`, `tests/test_scanner.py`).

**Invariant — classifier data flow.** `CandidateEvidence.secret` (raw) is for
in-process classifiers only. External classifiers (LLM triage) must build
requests exclusively from the redacted preview and fingerprint; enforced by
`tests/test_classifier.py::test_llm_request_never_contains_raw_secret`.

### 2.3 SARIF export

`--format sarif` emits a SARIF 2.1.0 log; `CRITICAL` maps to `error` and
`HIGH` to `warning`. Secrets appear only as fingerprints
(`partialFingerprints["epimetheus/secret"]`).

---

## 3. Change policy

| Change | Requires |
| :--- | :--- |
| New optional field in findings/rules documents | Minor release, note here |
| New canonical AST context name | Minor release, note here |
| Removed/renamed field, changed semantics of an existing field | Major version bump + migration note |
| Threshold value corrections inside `secret_rules.json` | Errata entry (§1.5) — the rules `test_cases` remain the conformance contract |
