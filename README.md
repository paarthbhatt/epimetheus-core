# epimetheus-core

Shared scanner core for **Epimetheus Red** — a high-precision secret detector
for AI-native codebases, combining three detection stages:

1. **Regex pattern matching** — vendor-anchored patterns from the versioned
   rules format (`rules/secret_rules.json`, 20 rules mapped to CWE and the
   OWASP Top 10 for LLM Applications 2025/2023).
2. **Tree-sitter AST context filtering** — matches must sit in a syntactic
   location the rule allows (assignments, call arguments, object properties,
   dotenv keys); secrets in comments, docstrings, and documentation files are
   rejected with a verified verdict.
3. **LLM classifier triage** — an optional second opinion from any
   OpenAI-compatible endpoint, with a hard redaction invariant (the raw secret
   never leaves the process) and a deterministic heuristic classifier that is
   always on.

## Install

```bash
pip install epimetheus-core            # core (regex + entropy + heuristic)
pip install "epimetheus-core[grammars]" # + tree-sitter language grammars
```

Without a language grammar the scanner still scans that language's files, in
degraded mode: findings carry `ast_verified: false`.

## Use

```bash
# scan a project (summary to stdout)
epimetheus scan .

# CI gate: fail on CRITICAL/HIGH findings
epimetheus scan . --format sarif --output results.sarif --fail-on HIGH

# custom rules
epimetheus scan . --rules my_rules.json

# validate a rules file
epimetheus rules validate my_rules.json
```

Python API:

```python
from epimetheus_core.rules import RuleSet
from epimetheus_core.scanner import Scanner, ScannerConfig

ruleset = RuleSet.from_file("rules/secret_rules.json")
scanner = Scanner(ScannerConfig(ruleset=ruleset))
report = scanner.scan_path("src/")
for finding in report.findings:
    print(finding.rule_id, finding.path, finding.line, finding.secret_fingerprint)
```

## LLM triage configuration

```bash
export EPI_LLM_BASE_URL=https://api.openai.com/v1   # any OpenAI-compatible API
export EPI_LLM_API_KEY=...
export EPI_LLM_MODEL=gpt-4o-mini
epimetheus scan .            # LLM verdicts recorded on findings
epimetheus scan . --llm-suppress  # ...and high-confidence false_positive verdicts suppress
```

LLM triage is **advisory by default**: its verdict is recorded alongside the
finding for human triage. With `--llm-suppress`, only verdicts with confidence
≥ 0.8 suppress a finding. All LLM failures fail open (the finding is kept and
marked `inconclusive`).

## Verification of releases

All release artifacts are signed with Sigstore cosign and must pass
`cosign verify` before publication:

```bash
scripts/verify_release.sh v0.1.0
```

See [docs/RELEASE.md](docs/RELEASE.md) for manual verification and
[docs/FORMAT_SPEC.md](docs/FORMAT_SPEC.md) for the versioned record formats.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[grammars,dev]"
pytest            # 185 tests incl. the 118-case rule conformance suite
ruff check epimetheus_core tests
```

## License

MIT — see [LICENSE](LICENSE).
