"""
orion.ai.coanalyst
=================

Pillar 3 — the AI as a **Co-Analyst**, not an oracle.

Skilled operators don't trust a black-box "Vulnerable: yes". So the model is
constrained to output a structured verdict that a human can audit in seconds:

* ``confidence``      — calibrated 0..1, never a bare boolean;
* ``raw_evidence``    — the *specific* response snippets (headers/body) the model
  based its call on, each tagged with where it came from, so you can eyeball the
  actual bytes rather than the model's summary of them;
* ``verification_step`` — a concrete, manual reproduction the operator can run to
  confirm independently (the model proposes the check; the human makes the call);
* ``assessment``      — ``likely_true`` | ``needs_verification`` | ``likely_false``,
  deliberately *not* a definitive "vulnerable" claim.

Evidence snippets are truncated and the model is instructed to quote verbatim
from supplied data only — if it can't ground a claim in the provided response,
it must lower confidence rather than invent support.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Optional

from ..core.config import AIConfig
from .mcp_bridge import LLMProvider, build_provider

logger = logging.getLogger("orion.coanalyst")

ASSESSMENTS = ("likely_true", "needs_verification", "likely_false")


@dataclass(slots=True)
class Evidence:
    """A grounded snippet the model cited, with provenance."""

    source: str          # e.g. "response_headers", "response_body", "status_line"
    snippet: str         # verbatim, truncated
    why_it_matters: str


@dataclass(slots=True)
class CoAnalystVerdict:
    """Auditable, non-binary triage output."""

    assessment: str                       # one of ASSESSMENTS
    confidence: float                     # 0..1
    raw_evidence: list[Evidence]
    verification_step: str                # concrete manual repro
    reasoning: str
    suggested_severity: Optional[str] = None
    model_grounded: bool = True           # False if evidence couldn't be tied to input
    raw_reply: str = field(default="", repr=False)

    def is_actionable(self, min_confidence: float) -> bool:
        return (
            self.assessment in ("likely_true", "needs_verification")
            and self.confidence >= min_confidence
            and bool(self.raw_evidence)
        )


_SYSTEM = (
    "You are a security co-analyst embedded in an authorized testing pipeline. "
    "You are given ONE scanner finding plus the raw HTTP evidence that produced "
    "it. You do NOT issue a final 'vulnerable' verdict — a human operator decides. "
    "Your job is to make that human fast and correct. Rules:\n"
    "1. Ground every claim ONLY in the provided evidence. If the evidence does "
    "not support the finding, say so and lower confidence.\n"
    "2. Quote evidence VERBATIM from the supplied data; never fabricate bytes.\n"
    "3. Always provide a concrete manual verification step the operator can run.\n"
    "Respond with a single JSON object, no prose, matching exactly:\n"
    "{\n"
    '  "assessment": "likely_true|needs_verification|likely_false",\n'
    '  "confidence": 0.0,\n'
    '  "suggested_severity": "info|low|medium|high|critical",\n'
    '  "reasoning": "<=70 words grounded in the evidence",\n'
    '  "verification_step": "a concrete manual check (curl/browser/etc.)",\n'
    '  "raw_evidence": [\n'
    '    {"source": "response_headers|response_body|status_line",\n'
    '     "snippet": "verbatim excerpt", "why_it_matters": "short"}\n'
    "  ]\n"
    "}"
)


class CoAnalyst:
    """Runs the transparent triage and parses it defensively."""

    def __init__(self, cfg: AIConfig, provider: Optional[LLMProvider] = None) -> None:
        self._cfg = cfg
        self._provider = provider or build_provider(cfg)

    def _user_prompt(self, finding: dict[str, Any], evidence: dict[str, str]) -> str:
        clip = self._cfg.max_log_chars
        return (
            f"FINDING: {json.dumps(finding)[:2000]}\n\n"
            f"STATUS_LINE:\n{evidence.get('status_line','')[:200]}\n\n"
            f"RESPONSE_HEADERS:\n{evidence.get('response_headers','')[:clip//2]}\n\n"
            f"RESPONSE_BODY (truncated):\n{evidence.get('response_body','')[:clip//2]}\n"
        )

    async def analyze(
        self, finding: dict[str, Any], evidence: dict[str, str]
    ) -> CoAnalystVerdict:
        prompt = self._user_prompt(finding, evidence)
        try:
            reply = await self._provider.complete(_SYSTEM, prompt)
            return self._parse(reply, evidence)
        except Exception as e:  # noqa: BLE001
            logger.warning("Co-analyst call failed (%s); returning needs_verification", e)
            return CoAnalystVerdict(
                assessment="needs_verification", confidence=0.0, raw_evidence=[],
                verification_step="AI unavailable — verify the finding manually.",
                reasoning=f"co-analyst error: {e}", model_grounded=False,
            )

    @staticmethod
    def _parse(reply: str, evidence: dict[str, str]) -> CoAnalystVerdict:
        cleaned = reply.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.strip("`")
            cleaned = cleaned[cleaned.find("{"):]
        start, end = cleaned.find("{"), cleaned.rfind("}")
        obj = json.loads(cleaned[start:end + 1]) if start != -1 else {}

        assessment = str(obj.get("assessment", "needs_verification"))
        if assessment not in ASSESSMENTS:
            assessment = "needs_verification"

        evid: list[Evidence] = []
        haystack = " ".join(evidence.values())
        grounded = True
        for e in obj.get("raw_evidence", [])[:6]:
            snip = str(e.get("snippet", ""))[:400]
            # Verify the model's quote actually appears in the supplied evidence.
            if snip and snip[:40] not in haystack:
                grounded = False
            evid.append(Evidence(
                source=str(e.get("source", "unknown")),
                snippet=snip,
                why_it_matters=str(e.get("why_it_matters", ""))[:200],
            ))

        conf = float(obj.get("confidence", 0.0) or 0.0)
        if not grounded:
            conf = min(conf, 0.4)   # penalize ungrounded evidence

        return CoAnalystVerdict(
            assessment=assessment,
            confidence=max(0.0, min(1.0, conf)),
            raw_evidence=evid,
            verification_step=str(obj.get("verification_step", ""))[:500],
            reasoning=str(obj.get("reasoning", ""))[:600],
            suggested_severity=obj.get("suggested_severity"),
            model_grounded=grounded,
            raw_reply=reply[:4000],
        )
