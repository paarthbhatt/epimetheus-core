"""Classifier tests: heuristic triage and LLM triage (mocked transport).

The LLM tests pin the security invariant: the raw secret never appears in the
request payload, and every failure mode is fail-open (INCONCLUSIVE).
"""

from __future__ import annotations

import json
import urllib.error

from epimetheus_core.classifier.base import CandidateEvidence, Verdict
from epimetheus_core.classifier.heuristic import HeuristicClassifier
from epimetheus_core.classifier.llm import LLMClassifier

SECRET = "sk-proj-aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ3aB4cD5eF6gH"


def _evidence(secret: str, **overrides) -> CandidateEvidence:
    fields = dict(
        rule_id="EPI-SEC-001",
        rule_name="OpenAI API Key",
        severity="CRITICAL",
        expected_fp_rate="< 0.05%",
        secret=secret,
        secret_preview=secret[:6] + "****" + secret[-4:],
        secret_fingerprint="sha256:0123456789abcdef",
        entropy=4.6,
        line_text='api_key = "sk-proj-****F6gH"',
        ast_context="assignment_expression",
        ast_verified=True,
        path="config.py",
    )
    fields.update(overrides)
    return CandidateEvidence(**fields)


# ------------------------------------------------------------ heuristic

def test_heuristic_true_positive():
    result = HeuristicClassifier().classify(_evidence(SECRET))
    assert result.verdict is Verdict.TRUE_POSITIVE
    assert result.confidence >= 0.85


def test_heuristic_placeholder_example():
    result = HeuristicClassifier().classify(
        _evidence("sk-proj-EXAMPLE_KEY_NOT_REAL_12345678901234567890")
    )
    assert result.verdict is Verdict.FALSE_POSITIVE


def test_heuristic_placeholder_template():
    result = HeuristicClassifier().classify(_evidence("${OPENAI_KEY}"))
    assert result.verdict is Verdict.FALSE_POSITIVE


def test_heuristic_dominant_char():
    result = HeuristicClassifier().classify(_evidence("sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxx"))
    assert result.verdict is Verdict.FALSE_POSITIVE


def test_heuristic_your_key_marker():
    result = HeuristicClassifier().classify(_evidence("YOUR_OPENAI_KEY_HERE_00000000"))
    assert result.verdict is Verdict.FALSE_POSITIVE


# ------------------------------------------------------------------ llm

class _FakeResponse:
    def __init__(self, payload: bytes):
        self._payload = payload

    def read(self) -> bytes:
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _llm_response(verdict: str, confidence: float = 0.9) -> bytes:
    return json.dumps(
        {
            "choices": [
                {
                    "message": {
                        "content": json.dumps(
                            {
                                "verdict": verdict,
                                "confidence": confidence,
                                "reasoning": "looks real",
                            }
                        )
                    }
                }
            ]
        }
    ).encode()


def test_llm_unconfigured_is_inconclusive():
    classifier = LLMClassifier(api_key="")
    result = classifier.classify(_evidence(SECRET))
    assert result.verdict is Verdict.INCONCLUSIVE


def test_llm_request_never_contains_raw_secret(monkeypatch):
    captured = {}

    def fake_urlopen(request, timeout=None):
        captured["body"] = request.data.decode()
        captured["url"] = request.full_url
        captured["auth"] = request.headers.get("Authorization")
        return _FakeResponse(_llm_response("true_positive"))

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    result = LLMClassifier(api_key="test-key").classify(_evidence(SECRET))

    assert result.verdict is Verdict.TRUE_POSITIVE
    assert captured["auth"] == "Bearer test-key"  # auth token sent as header
    assert SECRET not in captured["body"], "raw secret leaked into LLM request"
    payload = json.loads(captured["body"])
    assert "test-key" not in payload  # ...but never inside the JSON body
    assert payload["messages"][1]["content"]  # user content present


def test_llm_parses_fenced_json(monkeypatch):
    content = (
        "```json\n"
        '{"verdict": "false_positive", "confidence": 0.95, "reasoning": "x"}\n'
        "```"
    )
    fenced = json.dumps({"choices": [{"message": {"content": content}}]}).encode()
    monkeypatch.setattr(
        "urllib.request.urlopen", lambda req, timeout=None: _FakeResponse(fenced)
    )
    result = LLMClassifier(api_key="k").classify(_evidence(SECRET))
    assert result.verdict is Verdict.FALSE_POSITIVE
    assert result.confidence == 0.95


def test_llm_malformed_response_fails_open(monkeypatch):
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda req, timeout=None: _FakeResponse(b'{"choices": []}'),
    )
    result = LLMClassifier(api_key="k").classify(_evidence(SECRET))
    assert result.verdict is Verdict.INCONCLUSIVE
    assert "fail-open" in result.reasoning


def test_llm_network_error_fails_open(monkeypatch):
    def boom(req, timeout=None):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr("urllib.request.urlopen", boom)
    result = LLMClassifier(api_key="k").classify(_evidence(SECRET))
    assert result.verdict is Verdict.INCONCLUSIVE
    assert "fail-open" in result.reasoning


def test_llm_invalid_verdict_fails_open(monkeypatch):
    bad = json.dumps({"choices": [{"message": {"content": "not json at all"}}]}).encode()
    monkeypatch.setattr(
        "urllib.request.urlopen", lambda req, timeout=None: _FakeResponse(bad)
    )
    result = LLMClassifier(api_key="k").classify(_evidence(SECRET))
    assert result.verdict is Verdict.INCONCLUSIVE
