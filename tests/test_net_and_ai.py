"""
Tests for the request-profile (attribution, not evasion) and the co-analyst
(grounded evidence, non-binary verdicts).
"""
from __future__ import annotations

import asyncio

from orion.ai.coanalyst import CoAnalyst
from orion.core.config import AIConfig
from orion.net.proxy_pool import ProxyPool
from orion.net.request_profile import DEFAULT_USER_AGENT, RequestProfileManager


# --------------------------------------------------------------------------- #
# Request profile: identity is intentional and attributable.                  #
# --------------------------------------------------------------------------- #
def test_profile_sends_identifiable_ua_and_attribution() -> None:
    mgr = RequestProfileManager(contact="sec@tester.example", engagement_id="ENG-42")
    headers = mgr.build_headers()
    assert headers["User-Agent"] == DEFAULT_USER_AGENT
    assert "Orion" in headers["User-Agent"]                 # not a browser disguise
    assert headers["From"] == "sec@tester.example"          # reachable/attributable
    assert headers["X-Orion-Engagement"] == "ENG-42"


def test_profile_ua_is_stable_across_proxies() -> None:
    """Distributing over proxies must not change who the traffic says it is."""
    pool = ProxyPool(proxies=["http://p1:8080", "http://p2:8080", "http://p3:8080"])
    mgr = RequestProfileManager(proxies=pool)
    uas = {mgr.next_profile().headers["User-Agent"] for _ in range(6)}
    assert uas == {DEFAULT_USER_AGENT}                       # one identity, many egresses


def test_proxy_pool_health_cooldown() -> None:
    pool = ProxyPool(proxies=["http://p1:8080", "http://p2:8080"], cooldown_s=999)
    first = pool.acquire()
    pool.mark_bad(first)
    # After marking one bad, subsequent acquisitions avoid it while it cools down.
    nxt = {pool.acquire() for _ in range(4)}
    assert first not in nxt or nxt == {None}


def test_tool_flags_pin_identity() -> None:
    mgr = RequestProfileManager(engagement_id="ENG-9")
    flags = mgr.as_tool_flags("nuclei")
    assert "-H" in flags
    assert any("User-Agent:" in f for f in flags)
    assert any("X-Orion-Engagement: ENG-9" in f for f in flags)


# --------------------------------------------------------------------------- #
# Co-analyst: grounded, auditable, non-binary.                                #
# --------------------------------------------------------------------------- #
class _StubProvider:
    """Returns a canned model reply so parsing/grounding can be tested offline."""

    def __init__(self, reply: str) -> None:
        self._reply = reply

    async def complete(self, system: str, user: str) -> str:
        return self._reply


def test_coanalyst_grounded_evidence_kept() -> None:
    evidence = {
        "status_line": "HTTP/1.1 200 OK",
        "response_headers": "Server: nginx\nX-Powered-By: Express",
        "response_body": "DB_PASSWORD=supersecret\nAWS_KEY=AKIA...",
    }
    reply = (
        '{"assessment":"needs_verification","confidence":0.8,'
        '"suggested_severity":"high","reasoning":"env file exposed",'
        '"verification_step":"curl https://target/.env and inspect",'
        '"raw_evidence":[{"source":"response_body","snippet":"DB_PASSWORD=supersecret",'
        '"why_it_matters":"secret in body"}]}'
    )
    ca = CoAnalyst(AIConfig(), provider=_StubProvider(reply))
    v = asyncio.run(ca.analyze({"name": "exposed .env"}, evidence))
    assert v.assessment == "needs_verification"       # not a binary "vulnerable"
    assert v.confidence == 0.8
    assert v.model_grounded is True                    # quote appears in evidence
    assert v.raw_evidence[0].source == "response_body"
    assert v.verification_step.startswith("curl")


def test_coanalyst_penalizes_ungrounded_quote() -> None:
    evidence = {"response_body": "totally benign homepage"}
    reply = (
        '{"assessment":"likely_true","confidence":0.95,'
        '"verification_step":"n/a","reasoning":"made up",'
        '"raw_evidence":[{"source":"response_body",'
        '"snippet":"THIS STRING IS NOT IN THE RESPONSE AT ALL","why_it_matters":"x"}]}'
    )
    ca = CoAnalyst(AIConfig(), provider=_StubProvider(reply))
    v = asyncio.run(ca.analyze({"name": "hallucinated"}, evidence))
    assert v.model_grounded is False
    assert v.confidence <= 0.4          # confidence capped when evidence isn't grounded


def test_coanalyst_survives_garbage_reply() -> None:
    ca = CoAnalyst(AIConfig(), provider=_StubProvider("not json at all"))
    v = asyncio.run(ca.analyze({"name": "x"}, {"response_body": "y"}))
    assert v.assessment == "needs_verification"    # fails safe, never crashes
