"""Shape assertions for the synthetic secret constants (tests/synth.py).

The constants are unicode-escaped at source; these tests pin what the
decoded bytes must look like so a typo in any escape fails loudly.
"""

from __future__ import annotations

from synth import SYNTH_OPENAI_KEY, SYNTH_OPENAI_KEY_SHORT, SYNTH_SVCACCT_KEY


def test_constants_fully_decoded():
    for value in (SYNTH_OPENAI_KEY, SYNTH_OPENAI_KEY_SHORT, SYNTH_SVCACCT_KEY):
        assert "\\" not in value
        assert "u00" not in value.lower()


def test_constants_prefixes_and_lengths():
    assert SYNTH_OPENAI_KEY.startswith("sk-proj-")
    assert SYNTH_OPENAI_KEY_SHORT.startswith("sk-proj-")
    assert SYNTH_SVCACCT_KEY.startswith("sk-svcacct-")
    assert len(SYNTH_OPENAI_KEY) == 58
    assert len(SYNTH_OPENAI_KEY_SHORT) == 40
    assert len(SYNTH_SVCACCT_KEY) == 61


def test_constants_share_the_documented_bodies():
    assert SYNTH_OPENAI_KEY.startswith(SYNTH_OPENAI_KEY_SHORT)
    assert SYNTH_SVCACCT_KEY == "sk-svcacct-" + SYNTH_OPENAI_KEY[len("sk-proj-") :]
    body = SYNTH_OPENAI_KEY[len("sk-proj-") :]
    assert body != body.upper() and body != body.lower()
    assert body.isalnum()
