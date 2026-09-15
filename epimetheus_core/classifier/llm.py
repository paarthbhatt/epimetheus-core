"""LLM triage classifier over any OpenAI-compatible chat-completions endpoint.

Security invariants (tested):
  * the request payload is built exclusively from redacted fields
    (preview + fingerprint) — the raw secret never leaves the process;
  * transport uses only the Python standard library (urllib), so the core
    adds no HTTP dependency;
  * failures are fail-open: an unreachable or malformed endpoint yields
    ``INCONCLUSIVE`` (candidate is kept, marked for human triage), never a
    silent drop and never a crash of the scan.

Configuration (environment):
  EPI_LLM_BASE_URL   base URL of an OpenAI-compatible API
                     (default: https://api.openai.com/v1)
  EPI_LLM_API_KEY    bearer token for the endpoint
  EPI_LLM_MODEL      model name (default: gpt-4o-mini)
  EPI_LLM_TIMEOUT    request timeout in seconds (default: 10)
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from collections.abc import Mapping

from epimetheus_core.classifier.base import CandidateEvidence, Classification, Verdict

_JSON_FENCE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)

_SYSTEM_PROMPT = (
    "You are a secret-detection triage classifier for a security scanner. "
    "You receive a candidate finding whose secret value is redacted: only a "
    "short preview and a sha256 fingerprint are provided. Judge whether the "
    "candidate is a genuine exposed credential or a placeholder/documentation "
    "artifact, using the rule metadata, entropy, and source line. Respond "
    "with ONLY a JSON object: "
    '{"verdict": "true_positive" | "false_positive" | "inconclusive", '
    '"confidence": <0.0-1.0>, "reasoning": "<one sentence>"}. '
    "When in doubt, answer inconclusive; never invent key material."
)


class LLMClassifier:
    name = "llm"

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        timeout: float | None = None,
    ) -> None:
        self.base_url = (
            base_url
            or os.environ.get("EPI_LLM_BASE_URL", "https://api.openai.com/v1")
        ).rstrip("/")
        self.api_key = api_key if api_key is not None else os.environ.get("EPI_LLM_API_KEY", "")
        self.model = model or os.environ.get("EPI_LLM_MODEL", "gpt-4o-mini")
        self.timeout = float(
            timeout if timeout is not None else os.environ.get("EPI_LLM_TIMEOUT", 10)
        )

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    def _build_user_message(self, evidence: CandidateEvidence) -> str:
        """Redacted-fields-only payload. Must never reference ``evidence.secret``."""
        payload = {
            "rule_id": evidence.rule_id,
            "rule_name": evidence.rule_name,
            "severity": evidence.severity,
            "expected_fp_rate": evidence.expected_fp_rate,
            "secret_preview": evidence.secret_preview,
            "secret_fingerprint": evidence.secret_fingerprint,
            "entropy_bits_per_char": evidence.entropy,
            "ast_context": evidence.ast_context,
            "ast_verified": evidence.ast_verified,
            "path": evidence.path,
            "source_line_redacted": evidence.line_text,
        }
        return json.dumps(payload, indent=2)

    def _request(self, user_message: str) -> dict:
        body = json.dumps(
            {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user", "content": user_message},
                ],
                "temperature": 0,
                "max_tokens": 200,
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            return json.loads(response.read().decode("utf-8"))

    @staticmethod
    def _extract_json(text: str) -> dict:
        fenced = _JSON_FENCE.search(text)
        raw = fenced.group(1) if fenced else text
        start, end = raw.find("{"), raw.rfind("}")
        if start == -1 or end == -1:
            raise ValueError("no JSON object in response")
        return json.loads(raw[start : end + 1])

    def _parse(self, data: Mapping) -> Classification:
        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ValueError(f"unexpected response shape: {exc}") from exc
        parsed = self._extract_json(content)
        verdict = Verdict(str(parsed.get("verdict", "")).strip().lower())
        if verdict not in (Verdict.TRUE_POSITIVE, Verdict.FALSE_POSITIVE, Verdict.INCONCLUSIVE):
            raise ValueError(f"invalid verdict: {parsed.get('verdict')!r}")
        try:
            confidence = max(0.0, min(1.0, float(parsed.get("confidence", 0.5))))
        except (TypeError, ValueError):
            confidence = 0.5
        return Classification(
            verdict=verdict,
            confidence=confidence,
            reasoning=str(parsed.get("reasoning", ""))[:500],
            classifier=self.name,
            model=self.model,
        )

    def classify(self, evidence: CandidateEvidence) -> Classification:
        if not self.configured:
            return Classification(
                verdict=Verdict.INCONCLUSIVE,
                confidence=0.0,
                reasoning="EPI_LLM_API_KEY not set; LLM triage unavailable",
                classifier=self.name,
                model=self.model,
            )
        user_message = self._build_user_message(evidence)
        try:
            return self._parse(self._request(user_message))
        except (urllib.error.URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
            return Classification(
                verdict=Verdict.INCONCLUSIVE,
                confidence=0.0,
                reasoning=f"LLM triage failed (fail-open): {exc}",
                classifier=self.name,
                model=self.model,
            )
