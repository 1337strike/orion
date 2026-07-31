"""
orion.ai.mcp_bridge
===================

The seam between Orion's raw tool output and AI reasoning. It has two halves,
because HexStrike and Orion make *different* architectural choices about where
the model lives, and a serious framework should support both:

* ``HexStrikeToolClient`` — an **async re-implementation of HexStrike's
  ``HexStrikeClient``** (``safe_get`` / ``safe_post`` / ``execute_command`` over
  ``/health`` and ``/api/...``). This lets Orion drive an existing
  ``hexstrike_server.py`` instance, or an external MCP host, unchanged. In that
  model the *host* LLM does the reasoning.

* ``AITriageBridge`` — Orion's own programmatic path. It ships raw Nuclei /
  Httpx logs to a local or remote LLM and gets back a **strict-JSON verdict**
  (true-positive? confidence? suggested attack vectors?). This is what powers
  false-positive filtering inside the pipeline without a human in the loop.

The LLM layer is provider-agnostic (Ollama for local/private on 16 GB, plus any
OpenAI-compatible or Anthropic endpoint) so the same triage code runs offline.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Optional, Protocol

import aiohttp

from ..core.config import AIConfig
from ..core.models import Finding, Severity

logger = logging.getLogger("orion.ai")


# ===========================================================================
# 1. HexStrike-compatible async tool client
# ===========================================================================
class HexStrikeToolClient:
    """
    Async port of HexStrike's ``HexStrikeClient``.

    Talks to a ``hexstrike_server.py``-style Flask API. Every method degrades
    gracefully to ``{"success": False, "error": ...}`` instead of raising, so a
    flaky tool server can never take down the orchestrator's event loop.
    """

    def __init__(self, server_url: str, timeout_s: float = 300.0) -> None:
        self._base = server_url.rstrip("/")
        self._timeout = aiohttp.ClientTimeout(total=timeout_s)
        self._session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self) -> "HexStrikeToolClient":
        self._session = aiohttp.ClientSession(timeout=self._timeout)
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._session:
            await self._session.close()

    def _s(self) -> aiohttp.ClientSession:
        if self._session is None:
            raise RuntimeError("HexStrikeToolClient used outside its context")
        return self._session

    async def check_health(self) -> dict[str, Any]:
        return await self.safe_get("health")

    async def safe_get(
        self, endpoint: str, params: Optional[dict[str, Any]] = None
    ) -> dict[str, Any]:
        url = f"{self._base}/{endpoint}"
        try:
            async with self._s().get(url, params=params or {}) as r:
                r.raise_for_status()
                return await r.json()
        except Exception as e:  # noqa: BLE001 - mirror HexStrike's safe wrapper
            logger.error("GET %s failed: %s", url, e)
            return {"success": False, "error": str(e)}

    async def safe_post(self, endpoint: str, json_data: dict[str, Any]) -> dict[str, Any]:
        url = f"{self._base}/{endpoint}"
        try:
            async with self._s().post(url, json=json_data) as r:
                r.raise_for_status()
                return await r.json()
        except Exception as e:  # noqa: BLE001
            logger.error("POST %s failed: %s", url, e)
            return {"success": False, "error": str(e)}

    async def execute_command(self, command: str, use_cache: bool = True) -> dict[str, Any]:
        """Generic passthrough to HexStrike's ``/api/command`` endpoint."""
        return await self.safe_post(
            "api/command", {"command": command, "use_cache": use_cache}
        )

    async def run_tool(self, tool: str, params: dict[str, Any]) -> dict[str, Any]:
        """Invoke a specific ``/api/tools/<tool>`` endpoint (nuclei, httpx, ...)."""
        return await self.safe_post(f"api/tools/{tool}", params)


# ===========================================================================
# 2. LLM providers
# ===========================================================================
class LLMProvider(Protocol):
    """Minimal async chat interface every backend implements."""

    async def complete(self, system: str, user: str) -> str: ...


class OllamaProvider:
    """Local, private inference via Ollama's ``/api/chat``. No data egress."""

    def __init__(self, cfg: AIConfig) -> None:
        self._cfg = cfg

    async def complete(self, system: str, user: str) -> str:
        payload = {
            "model": self._cfg.model,
            "stream": False,
            "format": "json",  # ask Ollama to constrain output to JSON
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        timeout = aiohttp.ClientTimeout(total=self._cfg.request_timeout_s)
        async with aiohttp.ClientSession(timeout=timeout) as s:
            async with s.post(f"{self._cfg.base_url}/api/chat", json=payload) as r:
                r.raise_for_status()
                data = await r.json()
        return data.get("message", {}).get("content", "")


class OpenAICompatProvider:
    """Any OpenAI-compatible ``/v1/chat/completions`` endpoint."""

    def __init__(self, cfg: AIConfig) -> None:
        self._cfg = cfg

    async def complete(self, system: str, user: str) -> str:
        headers = {"Content-Type": "application/json"}
        if self._cfg.api_key:
            headers["Authorization"] = f"Bearer {self._cfg.api_key}"
        payload = {
            "model": self._cfg.model,
            "temperature": 0,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        timeout = aiohttp.ClientTimeout(total=self._cfg.request_timeout_s)
        async with aiohttp.ClientSession(timeout=timeout) as s:
            url = f"{self._cfg.base_url.rstrip('/')}/v1/chat/completions"
            async with s.post(url, headers=headers, json=payload) as r:
                r.raise_for_status()
                data = await r.json()
        return data["choices"][0]["message"]["content"]


class AnthropicProvider:
    """Anthropic Messages API backend."""

    def __init__(self, cfg: AIConfig) -> None:
        self._cfg = cfg

    async def complete(self, system: str, user: str) -> str:
        headers = {
            "content-type": "application/json",
            "anthropic-version": "2023-06-01",
            "x-api-key": self._cfg.api_key or "",
        }
        payload = {
            "model": self._cfg.model,
            "max_tokens": 1024,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        timeout = aiohttp.ClientTimeout(total=self._cfg.request_timeout_s)
        base = self._cfg.base_url.rstrip("/")
        if not base.endswith("anthropic.com"):
            base = "https://api.anthropic.com"
        async with aiohttp.ClientSession(timeout=timeout) as s:
            async with s.post(f"{base}/v1/messages", headers=headers, json=payload) as r:
                r.raise_for_status()
                data = await r.json()
        # Messages API returns a list of content blocks.
        return "".join(
            b.get("text", "") for b in data.get("content", []) if b.get("type") == "text"
        )


def build_provider(cfg: AIConfig) -> LLMProvider:
    mapping = {
        "ollama": OllamaProvider,
        "openai": OpenAICompatProvider,
        "anthropic": AnthropicProvider,
    }
    factory = mapping.get(cfg.provider)
    if factory is None:
        raise ValueError(f"Unknown AI provider: {cfg.provider!r}")
    return factory(cfg)


# ===========================================================================
# 3. AI triage bridge
# ===========================================================================
_TRIAGE_SYSTEM = (
    "You are a senior application-security triage analyst embedded in an "
    "automated bug-bounty pipeline. You assess ONE candidate finding produced "
    "by a scanner against an AUTHORIZED, in-scope target. Decide whether it is "
    "a genuine issue or a false positive, and if genuine, propose concrete "
    "follow-up validation vectors. You never fabricate evidence. Respond with a "
    "single JSON object and nothing else, matching exactly this schema:\n"
    "{\n"
    '  "is_true_positive": boolean,\n'
    '  "confidence": number,            // 0.0 - 1.0\n'
    '  "adjusted_severity": string,     // info|low|medium|high|critical\n'
    '  "rationale": string,             // <= 60 words, why\n'
    '  "suggested_vectors": [string]    // concrete next validation steps\n'
    "}"
)


class TriageVerdict:
    """Parsed, validated LLM verdict for a single finding."""

    __slots__ = (
        "is_true_positive", "confidence", "adjusted_severity",
        "rationale", "suggested_vectors",
    )

    def __init__(
        self,
        is_true_positive: bool,
        confidence: float,
        adjusted_severity: Severity,
        rationale: str,
        suggested_vectors: list[str],
    ) -> None:
        self.is_true_positive = is_true_positive
        self.confidence = confidence
        self.adjusted_severity = adjusted_severity
        self.rationale = rationale
        self.suggested_vectors = suggested_vectors


class AITriageBridge:
    """
    Converts raw scanner logs into structured, model-reasoned verdicts.

    ``triage_finding`` is the hot path called by the orchestrator's TRIAGE phase.
    It is defensive by construction: any provider/parse failure yields a
    conservative "unknown" verdict (kept, low confidence) rather than silently
    dropping a possibly-real High/Critical.
    """

    def __init__(self, cfg: AIConfig, provider: Optional[LLMProvider] = None) -> None:
        self._cfg = cfg
        self._provider = provider or build_provider(cfg)

    def _build_user_prompt(self, finding: Finding, context: dict[str, Any]) -> str:
        raw = json.dumps(finding.raw, indent=2)[: self._cfg.max_log_chars]
        tech = context.get("technologies") or context.get("tech") or []
        return (
            f"TARGET: {finding.target}\n"
            f"TOOL: {finding.tool}\n"
            f"SCANNER_NAME: {finding.name}\n"
            f"SCANNER_SEVERITY: {finding.severity.value}\n"
            f"DETECTED_STACK: {', '.join(tech) if tech else 'unknown'}\n"
            f"RAW_SCANNER_OUTPUT (truncated):\n{raw}\n"
        )

    async def triage_finding(
        self, finding: Finding, context: Optional[dict[str, Any]] = None
    ) -> TriageVerdict:
        context = context or {}
        user = self._build_user_prompt(finding, context)
        try:
            raw_reply = await self._provider.complete(_TRIAGE_SYSTEM, user)
            return self._parse(raw_reply, finding.severity)
        except Exception as e:  # noqa: BLE001
            logger.warning("Triage failed for %s (%s); keeping as unknown.",
                           finding.name, e)
            return TriageVerdict(
                is_true_positive=True,       # fail safe: don't drop it
                confidence=0.0,
                adjusted_severity=finding.severity,
                rationale=f"AI triage unavailable: {e}",
                suggested_vectors=[],
            )

    @staticmethod
    def _parse(reply: str, fallback_sev: Severity) -> TriageVerdict:
        # Strip accidental markdown fences before parsing.
        cleaned = reply.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.split("```", 2)[1] if "```" in cleaned[3:] else cleaned
            cleaned = cleaned.replace("json", "", 1).strip("` \n")
        # Grab the outermost JSON object defensively.
        start, end = cleaned.find("{"), cleaned.rfind("}")
        obj = json.loads(cleaned[start : end + 1]) if start != -1 else {}

        try:
            sev = Severity(str(obj.get("adjusted_severity", fallback_sev.value)).lower())
        except ValueError:
            sev = fallback_sev

        return TriageVerdict(
            is_true_positive=bool(obj.get("is_true_positive", True)),
            confidence=float(obj.get("confidence", 0.0) or 0.0),
            adjusted_severity=sev,
            rationale=str(obj.get("rationale", ""))[:500],
            suggested_vectors=[str(v) for v in obj.get("suggested_vectors", [])][:8],
        )

    def apply_verdict(self, finding: Finding, verdict: TriageVerdict) -> Finding:
        """Fold a verdict back onto the Finding record for persistence."""
        finding.ai_verdict = verdict.is_true_positive
        finding.ai_confidence = verdict.confidence
        finding.ai_rationale = verdict.rationale
        finding.severity = verdict.adjusted_severity
        finding.suggested_vectors = verdict.suggested_vectors
        return finding
