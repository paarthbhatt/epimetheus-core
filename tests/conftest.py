"""Shared fixtures: ruleset and scanner factory."""

from __future__ import annotations

from pathlib import Path

import pytest

from epimetheus_core.rules import RuleSet
from epimetheus_core.scanner import Scanner, ScannerConfig

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_FILE = REPO_ROOT / "rules" / "secret_rules.json"


@pytest.fixture()
def ruleset() -> RuleSet:
    return RuleSet.from_file(RULES_FILE)


@pytest.fixture()
def make_scanner(ruleset):
    def _make(**overrides) -> Scanner:
        config = ScannerConfig(ruleset=ruleset)
        for key, value in overrides.items():
            setattr(config, key, value)
        return Scanner(config)

    return _make
