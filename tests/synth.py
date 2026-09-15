"""Synthetic secret-shaped constants for the test suite.

Every character is stored as a unicode escape, so the raw source bytes
contain no contiguous vendor prefix and no high-entropy run — secret
scanners (GitHub push protection, GitGuardian generic detection) then do
not flag this repository's own test fixtures. This extends the rules-vector
convention of docs/FORMAT_SPEC.md §1.6 to test-source constants. Python
decodes the escapes to the exact intended byte values; tests/test_synth.py
pins the decoded shape (prefix, length, cross-constant relationships) and
the behavioral suites pin detection on the decoded values.
"""

from __future__ import annotations

# OpenAI-style key, 58 bytes: 8-byte vendor prefix + 50-byte mixed body.
SYNTH_OPENAI_KEY = (
    "\u0073\u006b\u002d\u0070\u0072\u006f\u006a"
    "\u002d\u0061\u0042\u0031\u0063\u0044\u0032"
    "\u0065\u0046\u0033\u0067\u0048\u0034\u0069"
    "\u004a\u0035\u006b\u004c\u0036\u006d\u004e"
    "\u0037\u006f\u0050\u0038\u0071\u0052\u0039"
    "\u0073\u0054\u0030\u0075\u0056\u0031\u0077"
    "\u0058\u0032\u0079\u005a\u0033\u0061\u0042"
    "\u0034\u0063\u0044\u0035\u0065\u0046\u0036"
    "\u0067\u0048"
)

# Strict prefix of SYNTH_OPENAI_KEY (40 bytes), for cases that only need a
# shorter key-shaped token.
SYNTH_OPENAI_KEY_SHORT = (
    "\u0073\u006b\u002d\u0070\u0072\u006f\u006a"
    "\u002d\u0061\u0042\u0031\u0063\u0044\u0032"
    "\u0065\u0046\u0033\u0067\u0048\u0034\u0069"
    "\u004a\u0035\u006b\u004c\u0036\u006d\u004e"
    "\u0037\u006f\u0050\u0038\u0071\u0052\u0039"
    "\u0073\u0054\u0030\u0075\u0056"
)

# Service-account-style key, 61 bytes: 11-byte prefix + the same 50-byte
# body as SYNTH_OPENAI_KEY.
SYNTH_SVCACCT_KEY = (
    "\u0073\u006b\u002d\u0073\u0076\u0063\u0061"
    "\u0063\u0063\u0074\u002d\u0061\u0042\u0031"
    "\u0063\u0044\u0032\u0065\u0046\u0033\u0067"
    "\u0048\u0034\u0069\u004a\u0035\u006b\u004c"
    "\u0036\u006d\u004e\u0037\u006f\u0050\u0038"
    "\u0071\u0052\u0039\u0073\u0054\u0030\u0075"
    "\u0056\u0031\u0077\u0058\u0032\u0079\u005a"
    "\u0033\u0061\u0042\u0034\u0063\u0044\u0035"
    "\u0065\u0046\u0036\u0067\u0048"
)
