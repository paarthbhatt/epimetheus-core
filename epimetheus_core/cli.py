"""``epimetheus`` command-line interface.

Usage:
    epimetheus scan <path> [--rules FILE] [--format json|sarif|summary]
                     [--output FILE] [--strict-ast] [--no-llm]
                     [--fail-on CRITICAL|HIGH|any|never]
    epimetheus rules validate <file>

Exit codes: 0 = clean / success, 1 = findings matched the --fail-on gate,
2 = operational error (bad rules file, unreadable path, invalid arguments).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from epimetheus_core import __version__
from epimetheus_core.classifier.llm import LLMClassifier
from epimetheus_core.findings import to_sarif
from epimetheus_core.rules import RuleSet, RuleSetError
from epimetheus_core.scanner import Scanner, ScannerConfig

FAIL_ON_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

# Rules shipped with the package repo; also usable via --rules for custom sets.
DEFAULT_RULES = Path(__file__).resolve().parent.parent / "rules" / "secret_rules.json"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="epimetheus",
        description="Epimetheus Red scanner core: regex + tree-sitter + LLM classifier",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a file or directory for exposed secrets")
    scan.add_argument("path", help="file or directory to scan")
    scan.add_argument(
        "--rules", default=str(DEFAULT_RULES), help="rules JSON file (schema v1.x)"
    )
    scan.add_argument(
        "--format", choices=("json", "sarif", "summary"), default="summary"
    )
    scan.add_argument("--output", help="write the report to this file instead of stdout")
    scan.add_argument(
        "--strict-ast",
        action="store_true",
        help="reject matches in files without a usable tree-sitter grammar",
    )
    scan.add_argument(
        "--no-llm", action="store_true", help="disable LLM triage even if configured"
    )
    scan.add_argument(
        "--llm-suppress",
        action="store_true",
        help="let high-confidence LLM false_positive verdicts suppress findings",
    )
    scan.add_argument(
        "--fail-on",
        choices=("CRITICAL", "HIGH", "MEDIUM", "any", "never"),
        default="never",
        help="exit 1 when findings at or above this severity are present",
    )

    rules = sub.add_parser("rules", help="inspect and validate rules files")
    rules_sub = rules.add_subparsers(dest="subcommand", required=True)
    validate = rules_sub.add_parser("validate", help="validate a rules JSON file")
    validate.add_argument("file", help="rules JSON file to validate")
    list_cmd = rules_sub.add_parser("list", help="list rules in a rules file")
    list_cmd.add_argument("file", help="rules JSON file to list")
    return parser


def _load_ruleset(path: str) -> RuleSet:
    rules_file = Path(path)
    if not rules_file.exists():
        raise RuleSetError(f"rules file not found: {rules_file}")
    return RuleSet.from_file(rules_file)


def _render(scanner: Scanner, report, fmt: str) -> str:
    if fmt == "json":
        return json.dumps(report.to_dict(__version__), indent=2)
    if fmt == "sarif":
        rules_meta = {
            rule.id: {
                "name": rule.name,
                "severity": rule.severity,
                "category": rule.category,
                "cwe": list(rule.cwe),
                "owasp_llm_2025": rule.owasp_llm_2025,
            }
            for rule in scanner.ruleset
        }
        return json.dumps(to_sarif(report, rules_meta, __version__), indent=2)
    lines = [
        f"Epimetheus Red scan — {report.root}",
        f"Files scanned: {report.files_scanned}  skipped: {report.files_skipped}"
        f"  rules: {report.rules_loaded}",
        f"Findings: {len(report.findings)}  {report.summary() or '(clean)'}",
    ]
    if report.ast_degraded_files:
        lines.append(f"AST degraded (no grammar): {len(report.ast_degraded_files)} file(s)")
    for finding in report.findings:
        loc = f"{finding.path}:{finding.line}:{finding.column}"
        lines.append(
            f"  [{finding.severity}] {finding.rule_id} {finding.rule_name} @ {loc} "
            f"({finding.secret_fingerprint}, ast={finding.ast_context or 'unverified'})"
        )
    return "\n".join(lines)


def _gate_failed(report, fail_on: str) -> bool:
    if fail_on == "never":
        return False
    if fail_on == "any":
        return bool(report.findings)
    threshold = FAIL_ON_ORDER[fail_on]
    return any(
        FAIL_ON_ORDER.get(f.severity, 0) >= threshold for f in report.findings
    )


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "rules":
            ruleset = _load_ruleset(args.file)
            if args.subcommand == "validate":
                print(
                    f"OK: {len(ruleset)} rules, schema {ruleset.schema_version} "
                    f"({ruleset.source})"
                )
                return 0
            if args.subcommand == "list":
                for rule in ruleset:
                    print(f"{rule.id}\t{rule.severity}\t{rule.name}")
                return 0

        if args.command == "scan":
            ruleset = _load_ruleset(args.rules)
            llm = None if args.no_llm else LLMClassifier()
            scanner = Scanner(
                ScannerConfig(
                    ruleset=ruleset,
                    strict_ast=args.strict_ast,
                    llm_suppress=args.llm_suppress,
                    llm=llm,
                )
            )
            report = scanner.scan_path(args.path)
            rendered = _render(scanner, report, args.format)
            if args.output:
                Path(args.output).write_text(rendered + "\n", encoding="utf-8")
            else:
                print(rendered)
            return 1 if _gate_failed(report, args.fail_on) else 0

    except (RuleSetError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    sys.exit(main())
