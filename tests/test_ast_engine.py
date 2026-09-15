"""Tree-sitter AST context engine tests (requires grammar extras)."""

from __future__ import annotations

import pytest

pytest.importorskip("tree_sitter_python")
pytest.importorskip("tree_sitter_javascript")

from epimetheus_core.engines.ast_engine import (  # noqa: E402
    AstEngine,
    detect_language,
    is_environment_file,
)

PY_CONTEXTS = (
    "variable_declarator",
    "assignment_expression",
    "call_expression",
    "environment_file",
)
JS_CONTEXTS = (
    "variable_declarator",
    "assignment_expression",
    "call_expression",
    "object_property",
    "environment_file",
)


@pytest.fixture()
def engine():
    return AstEngine()


def test_detect_language():
    assert detect_language("app.py") == "python"
    assert detect_language("app.js") == "javascript"
    assert detect_language("config.json") == "json"
    assert detect_language(".env") == "env"
    assert detect_language(".env.local") == "env"
    assert detect_language("notes.txt") is None


def test_is_environment_file():
    assert is_environment_file(".env")
    assert is_environment_file(".env.production")
    assert not is_environment_file("env.txt")
    assert not is_environment_file("settings.py")


def test_python_assignment_context(engine):
    text = 'api_key = "sk-proj-aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ3aB4cD5eF6gH"'
    engine.prepare_file("f", "python", text)
    start = text.index('"') + 1
    result = engine.check("f", "python", "f.py", start, start + 10, PY_CONTEXTS)
    assert result.allowed and result.verified
    assert result.context in ("assignment_expression", "variable_declarator")


def test_python_call_context(engine):
    text = "client = OpenAI(api_key='sk-proj-aB1cD2eF3gH4iJ5kL')"
    engine.prepare_file("f", "python", text)
    start = text.index("sk-proj")
    result = engine.check("f", "python", "f.py", start, start + 10, PY_CONTEXTS)
    assert result.allowed and result.verified
    assert result.context == "call_expression"


def test_python_comment_rejected(engine):
    text = '# todo: replace api_key = "sk-proj-aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV"'
    engine.prepare_file("f", "python", text)
    start = text.index("sk-proj")
    result = engine.check("f", "python", "f.py", start, start + 10, PY_CONTEXTS)
    assert not result.allowed and result.verified


def test_python_docstring_rejected(engine):
    text = '"""Docs: api_key = "sk-proj-aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV"\n"""'
    engine.prepare_file("f", "python", text)
    start = text.index("sk-proj")
    result = engine.check("f", "python", "f.py", start, start + 10, PY_CONTEXTS)
    assert not result.allowed and result.verified


def test_js_variable_declarator(engine):
    text = 'const apiKey = "sk-proj-aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ3aB4cD5eF6gH";'
    engine.prepare_file("f", "javascript", text)
    start = text.index('"') + 1
    result = engine.check("f", "javascript", "f.js", start, start + 10, JS_CONTEXTS)
    assert result.allowed and result.verified
    assert result.context == "variable_declarator"


def test_js_object_property(engine):
    text = 'config = { openai: "sk-proj-aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ3aB4cD5eF6gH" };'
    engine.prepare_file("f", "javascript", text)
    start = text.index('"', text.index("openai"))
    result = engine.check("f", "javascript", "f.js", start, start + 10, JS_CONTEXTS)
    assert result.allowed and result.verified
    assert result.context == "object_property"


def test_degraded_language_allowed_unverified(engine):
    result = engine.check("f", None, "notes.txt", 0, 5, PY_CONTEXTS)
    assert result.allowed and not result.verified


def test_strict_mode_rejects_unparseable(engine):
    result = engine.check("f", None, "notes.txt", 0, 5, PY_CONTEXTS, strict=True)
    assert not result.allowed and not result.verified


def test_environment_file_sentinel(engine):
    result = engine.check("f", "env", ".env", 0, 5, ("environment_file",))
    assert result.allowed and result.verified
    assert result.context == "environment_file"


def test_env_file_without_sentinel_context(engine):
    result = engine.check("f", "env", ".env", 0, 5, ("variable_declarator",))
    # No AST for env files: non-strict allows (unverified), strict rejects.
    assert result.allowed and not result.verified
    assert not engine.check(
        "f", "env", ".env", 0, 5, ("variable_declarator",), strict=True
    ).allowed
