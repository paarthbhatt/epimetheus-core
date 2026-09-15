"""Scanner integration tests over a realistic fixture tree."""

from __future__ import annotations

import pytest

pytest.importorskip("tree_sitter_python")
pytest.importorskip("tree_sitter_javascript")

from synth import SYNTH_OPENAI_KEY, SYNTH_SVCACCT_KEY  # noqa: E402

OPENAI_KEY = SYNTH_OPENAI_KEY
SVCACCT_KEY = SYNTH_SVCACCT_KEY


@pytest.fixture()
def tree(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "config.py").write_text(
        f'import os\n\napi_key = "{OPENAI_KEY}"\nclient_key = os.environ["OPENAI_API_KEY"]\n',
        encoding="utf-8",
    )
    (tmp_path / "src" / "app.js").write_text(
        f'const apiKey = "{OPENAI_KEY}";\n'
        'const safe = process.env.OPENAI_API_KEY;\n',
        encoding="utf-8",
    )
    (tmp_path / ".env").write_text(
        f"OPENAI_API_KEY={SVCACCT_KEY}\n", encoding="utf-8"
    )
    (tmp_path / "docs.md").write_text(
        "Set `OPENAI_API_KEY` in `.env`. Example: sk-proj-EXAMPLE_KEY_NOT_REAL_12345.\n",
        encoding="utf-8",
    )
    (tmp_path / "commented.py").write_text(
        f'# legacy: api_key = "{OPENAI_KEY}"\n', encoding="utf-8"
    )
    (tmp_path / "binary.dat").write_bytes(b"\x00\x01\x02sk-proj-binary")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "dep.js").write_text(
        f'const leaked = "{OPENAI_KEY}";\n', encoding="utf-8"
    )
    return tmp_path


def test_scan_tree_finds_expected_secrets(make_scanner, tree):
    report = make_scanner().scan_path(tree)

    assert report.files_scanned == 5  # 4 text files + binary skipped below
    assert report.files_skipped == 1  # binary.dat
    assert len(report.findings) == 3  # config.py, app.js, .env

    by_path = {f.path: f for f in report.findings}
    assert set(by_path) == {"src/config.py", "src/app.js", ".env"}

    assert by_path["src/config.py"].ast_verified is True
    assert by_path["src/config.py"].ast_context == "variable_declarator"
    assert by_path["src/app.js"].ast_verified is True
    assert by_path[".env"].ast_context == "environment_file"
    assert by_path[".env"].ast_verified is True

    # node_modules excluded, docs placeholder allowlisted, comment AST-filtered
    assert all("node_modules" not in f.path for f in report.findings)
    assert not any("docs.md" in f.path for f in report.findings)
    assert not any("commented.py" in f.path for f in report.findings)


def test_scan_summary_counts(make_scanner, tree):
    report = make_scanner().scan_path(tree)
    assert report.summary() == {"CRITICAL": 3}
    assert report.rules_loaded == 20


def test_report_json_has_no_raw_secrets(make_scanner, tree):
    import json

    report = make_scanner().scan_path(tree)
    blob = json.dumps(report.to_dict("0.1.0"))
    assert OPENAI_KEY not in blob
    assert SVCACCT_KEY not in blob


def test_ast_comment_filtering_is_verified_rejection(make_scanner):
    scanner = make_scanner()
    findings = scanner.scan_text(f'# key = "{OPENAI_KEY}"\n', path="x.py")
    assert not findings


def test_ast_docstring_filtered(make_scanner):
    scanner = make_scanner()
    text = f'def f():\n    """api_key = {OPENAI_KEY}"""\n    return 1\n'
    assert not scanner.scan_text(text, path="x.py")


def test_strict_ast_rejects_unparsed_files(make_scanner, tmp_path):
    (tmp_path / "notes.txt").write_text(f"key = {OPENAI_KEY}\n", encoding="utf-8")
    strict = make_scanner(strict_ast=True)
    assert not strict.scan_path(tmp_path).findings
    lax = make_scanner()
    assert len(lax.scan_path(tmp_path).findings) == 1


def test_scan_single_file(make_scanner, tree):
    report = make_scanner().scan_path(tree / "src" / "config.py")
    assert report.files_scanned == 1
    assert [f.rule_id for f in report.findings] == ["EPI-SEC-001"]


def test_missing_path_raises(make_scanner, tmp_path):
    import pytest as _pytest

    with _pytest.raises(FileNotFoundError):
        make_scanner().scan_path(tmp_path / "nope")


def test_max_file_size_skips(make_scanner, tmp_path):
    (tmp_path / "big.py").write_text(
        f'x = "{OPENAI_KEY}"\n' + "# padding\n" * 500000, encoding="utf-8"
    )
    from epimetheus_core.scanner import ScannerConfig

    config = ScannerConfig(ruleset=make_scanner().ruleset, max_file_bytes=1024)
    from epimetheus_core.scanner import Scanner

    report = Scanner(config).scan_path(tmp_path)
    assert report.files_skipped == 1
    assert not report.findings
