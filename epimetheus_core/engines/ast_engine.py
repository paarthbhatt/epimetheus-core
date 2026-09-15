"""Stage 2 — tree-sitter syntactic context filtering.

Validates that a candidate sits in a syntactic location the rule allows
(``variable_declarator``, ``assignment_expression``, ``call_expression``,
``object_property``, ``string_literal``, ``template_literal``, or the
``environment_file`` sentinel for dotenv-style files).

The rule format uses canonical (JavaScript-flavoured) context names; this
engine maps them to per-language tree-sitter node types. Grammars are optional:
when a language has no installed grammar the file is scanned in degraded mode —
matches are reported with ``ast_verified=false`` instead of being dropped
(or rejected in strict mode), so the core never silently loses coverage.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

ENVIRONMENT_FILE = "environment_file"

EXTENSION_LANGUAGES: dict[str, str] = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".json": "json",
    ".jsonc": "json",
}

# Canonical context name -> tree-sitter node types per language.
CONTEXT_NODE_TYPES: dict[str, dict[str, tuple[str, ...]]] = {
    "variable_declarator": {
        "javascript": ("variable_declarator",),
        "typescript": ("variable_declarator",),
        "python": ("assignment",),
        "json": (),
    },
    "assignment_expression": {
        "javascript": ("assignment_expression",),
        "typescript": ("assignment_expression",),
        "python": ("assignment", "augmented_assignment"),
        "json": (),
    },
    "call_expression": {
        "javascript": ("call_expression", "new_expression"),
        "typescript": ("call_expression", "new_expression"),
        "python": ("call",),
        "json": (),
    },
    "object_property": {
        "javascript": ("pair",),
        "typescript": ("pair",),
        "python": ("keyword_argument", "pair"),
        "json": ("pair",),
    },
    "string_literal": {
        "javascript": ("string",),
        "typescript": ("string",),
        "python": ("string",),
        "json": ("string",),
    },
    "template_literal": {
        "javascript": ("template_string",),
        "typescript": ("template_string",),
        "python": ("string",),
        "json": (),
    },
}

_ROOT_NODE_TYPES = {"module", "program", "expression_statement", "statement_block"}

# Files treated as dotenv-style environment files for the
# ``environment_file`` context sentinel.
ENV_FILE_SUFFIXES = (".env",)
ENV_FILE_NAMES = (".env",)
ENV_FILE_PREFIXES = (".env.",)


def detect_language(path: str | Path) -> str | None:
    name = Path(path).name
    if name in ENV_FILE_NAMES or name.startswith(ENV_FILE_PREFIXES):
        return "env"
    return EXTENSION_LANGUAGES.get(Path(path).suffix.lower())


def is_environment_file(path: str | Path) -> bool:
    name = Path(path).name
    return detect_language(path) == "env" and (
        name.endswith(ENV_FILE_SUFFIXES) or name.startswith(ENV_FILE_PREFIXES)
    )


@dataclass(frozen=True)
class AstContextResult:
    allowed: bool
    verified: bool  # False when no grammar was available / parse failed
    context: str  # canonical context name that matched, "" when rejected


class AstEngine:
    """Parses files once and answers AST-context questions for candidates."""

    def __init__(self) -> None:
        self._parsers: dict[str, object] = {}
        self._trees: dict[str, object] = {}

    def _language_for(self, language: str):
        if language == "javascript":
            import tree_sitter_javascript

            return tree_sitter_javascript.language()
        if language == "typescript":
            import tree_sitter_typescript

            return tree_sitter_typescript.language_typescript()
        if language == "python":
            import tree_sitter_python

            return tree_sitter_python.language()
        if language == "json":
            import tree_sitter_json

            return tree_sitter_json.language()
        return None

    def _parser_for(self, language: str):
        if language in self._parsers:
            return self._parsers[language]
        try:
            lang_def = self._language_for(language)
            if lang_def is None:
                return None
            from tree_sitter import Language, Parser

            parser = Parser(Language(lang_def))
        except Exception:  # grammar not installed or ABI mismatch
            return None
        self._parsers[language] = parser
        return parser

    def prepare_file(self, key: str, language: str | None, text: str) -> None:
        """Parse ``text`` once so subsequent context checks are cheap."""
        self._trees.pop(key, None)
        if not language:
            return
        parser = self._parser_for(language)
        if parser is None:
            return
        try:
            self._trees[key] = parser.parse(text.encode("utf-8"))
        except Exception:
            self._trees.pop(key, None)

    def _node_types_for(self, language: str, contexts: tuple[str, ...]) -> set[str]:
        types: set[str] = set()
        for context in contexts:
            if context == ENVIRONMENT_FILE:
                continue
            types.update(CONTEXT_NODE_TYPES.get(context, {}).get(language, ()))
        return types

    def check(
        self,
        key: str,
        language: str | None,
        path: str | Path,
        byte_start: int,
        byte_end: int,
        contexts: tuple[str, ...],
        strict: bool = False,
    ) -> AstContextResult:
        """Check whether a match at ``byte_start`` sits in an allowed context."""
        if ENVIRONMENT_FILE in contexts and is_environment_file(path):
            return AstContextResult(allowed=True, verified=True, context=ENVIRONMENT_FILE)

        if not contexts:
            return AstContextResult(allowed=True, verified=False, context="unfiltered")

        tree = self._trees.get(key)
        if tree is None or language is None:
            if strict:
                return AstContextResult(allowed=False, verified=False, context="")
            return AstContextResult(allowed=True, verified=False, context="unverified")

        allowed_types = self._node_types_for(language, contexts)
        if not allowed_types:
            if strict:
                return AstContextResult(allowed=False, verified=False, context="")
            return AstContextResult(allowed=True, verified=False, context="unverified")

        node = tree.root_node.descendant_for_byte_range(byte_start, byte_end)
        while node is not None:
            if node.type in allowed_types and node.type not in _ROOT_NODE_TYPES:
                for context in contexts:
                    if node.type in self._node_types_for(language, (context,)):
                        return AstContextResult(
                            allowed=True, verified=True, context=context
                        )
            node = node.parent

        if strict:
            return AstContextResult(allowed=False, verified=True, context="")
        # Verified out-of-context: the AST is authoritative for rejection —
        # this is the precision guarantee of Stage 2, so we reject even in
        # non-strict mode.
        return AstContextResult(allowed=False, verified=True, context="")
