"""
orion.net.request_profile
=========================

Pillar 1, reframed for authorized testing.

The original brief asked for signature *obfuscation* — masking tool traffic as
organic user activity and randomizing JA3/JA4 TLS fingerprints. Two of those
techniques exist only to defeat a defender's ability to detect scanning, so they
are deliberately **not** implemented here. What this module does provide is the
legitimate core that authorized engagements actually need:

* an **identifiable, intentional** outbound identity (so you don't leak a default
  ``Nuclei``/``httpx`` User-Agent by accident, *and* the target's blue team can
  still attribute the traffic to your authorized test — many bug-bounty programs
  require this);
* **well-formed, consistent** request headers (not order-shuffled to evade);
* **humane, jittered pacing** so you stay within rate limits and are a good
  citizen on the target;
* optional **proxy selection** for throughput and resilience (see ``proxy_pool``).

This keeps the footprint clean and professional without crossing into
detection-evasion. If your engagement genuinely requires evasion testing, do it
with an identifiable footprint and coordinate detection expectations with the
defenders in scope.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Optional

from .proxy_pool import ProxyPool

__version__ = "2.0"

# A single, honest default UA. Not a rotating pool of browser disguises.
DEFAULT_USER_AGENT = f"Orion-Security-Scanner/{__version__} (+authorized-testing)"

# Standard, well-formed header template. Static and consistent on purpose.
_BASE_HEADERS: dict[str, str] = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
}


@dataclass(slots=True)
class PacingConfig:
    """Humane request pacing (politeness / rate-limit friendliness)."""

    base_delay_s: float = 0.4
    jitter_s: float = 0.6          # uniform jitter added on top of base
    max_delay_s: float = 8.0

    def next_delay(self, backoff_mult: float = 1.0) -> float:
        d = self.base_delay_s * backoff_mult + random.uniform(0.0, self.jitter_s)
        return min(d, self.max_delay_s)


@dataclass(slots=True)
class RequestProfile:
    """A concrete, attributable outbound identity for one request/batch."""

    headers: dict[str, str]
    proxy: Optional[str]
    delay_s: float
    engagement_id: Optional[str]


@dataclass(slots=True)
class RequestProfileManager:
    """
    Produces attributable, well-formed request profiles.

    Parameters
    ----------
    user_agent:
        The identifiable UA to send. Defaults to an honest Orion UA. Override it
        with your own program-specific string if the target requires one.
    contact:
        Optional contact address. When set, an ``X-Bug-Bounty-Contact`` / ``From``
        header is added so the defender can reach the tester — attribution, not
        disguise.
    engagement_id:
        Optional per-engagement identifier echoed in ``X-Orion-Engagement`` so all
        traffic from a campaign is traceable to its authorization record.
    """

    user_agent: str = DEFAULT_USER_AGENT
    contact: Optional[str] = None
    engagement_id: Optional[str] = None
    pacing: PacingConfig = field(default_factory=PacingConfig)
    proxies: Optional[ProxyPool] = None
    extra_headers: dict[str, str] = field(default_factory=dict)

    def build_headers(self) -> dict[str, str]:
        """Assemble the consistent, identifiable header set."""
        headers = dict(_BASE_HEADERS)
        headers["User-Agent"] = self.user_agent
        if self.contact:
            headers["From"] = self.contact
            headers["X-Bug-Bounty-Contact"] = self.contact
        if self.engagement_id:
            headers["X-Orion-Engagement"] = self.engagement_id
        headers.update(self.extra_headers)
        return headers

    def next_profile(self, backoff_mult: float = 1.0) -> RequestProfile:
        """Return a ready-to-use profile for the next request/batch."""
        proxy = self.proxies.acquire() if self.proxies else None
        return RequestProfile(
            headers=self.build_headers(),
            proxy=proxy,
            delay_s=self.pacing.next_delay(backoff_mult),
            engagement_id=self.engagement_id,
        )

    def as_tool_flags(self, tool: str) -> list[str]:
        """
        Emit CLI flags that pin the identifiable identity onto a supported tool,
        so external binaries don't fall back to their default fingerprints.
        """
        ua = self.user_agent
        if tool in ("httpx", "nuclei"):
            flags = ["-H", f"User-Agent: {ua}"]
            if self.engagement_id:
                flags += ["-H", f"X-Orion-Engagement: {self.engagement_id}"]
            return flags
        if tool == "ffuf":
            flags = ["-H", f"User-Agent: {ua}"]
            if self.engagement_id:
                flags += ["-H", f"X-Orion-Engagement: {self.engagement_id}"]
            return flags
        return []
