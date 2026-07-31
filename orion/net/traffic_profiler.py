"""
orion.net.traffic_profiler
=========================

Pillar 1 — dynamic traffic profiling for **authorized WAF-resilience / CTEM
testing**.

What this does: shapes Orion's outbound requests to resemble realistic browser
traffic, so an appsec/purple team can test whether a WAF's brittle
tool-signature rules (default ``nuclei``/``httpx`` User-Agents, robotic fixed
timing) are the only thing standing between them and a real adversary. If a scan
that looks like a normal browser sails through, that's a finding about the WAF.

Deliberate design choices (so this stays a testing tool, not an evasion kit):

* Profiles are **coherent and realistic** (a Chrome-on-Windows UA ships with the
  matching Accept / Accept-Language / Sec-CH-UA headers) rather than randomly
  order-shuffled headers whose only purpose is defeating signature order checks.
* An **attribution tag** (``X-Orion-Engagement``) can be pinned to every request
  so the target's blue team can still tie the traffic to your authorized test —
  recommended, and required by many programs.
* No TLS/JA3/JA4 fingerprint manipulation. That's out of scope by design.

Use it only against assets you're authorized to test.
"""
from __future__ import annotations

import enum
import logging
import random
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("orion.traffic")


# --------------------------------------------------------------------------- #
# Realistic, coherent browser profiles                                        #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class TrafficProfile:
    """A coherent set of headers representing one plausible client."""

    name: str
    user_agent: str
    headers: dict[str, str]


# A small pool of common, publicly-known client profiles. Each header set is
# internally consistent with its User-Agent.
BUILTIN_PROFILES: tuple[TrafficProfile, ...] = (
    TrafficProfile(
        name="chrome_windows",
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
        ),
        headers={
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Sec-CH-UA": '"Chromium";v="125", "Google Chrome";v="125", "Not.A/Brand";v="24"',
            "Sec-CH-UA-Platform": '"Windows"',
            "Upgrade-Insecure-Requests": "1",
        },
    ),
    TrafficProfile(
        name="firefox_linux",
        user_agent=(
            "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0"
        ),
        headers={
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
        },
    ),
    TrafficProfile(
        name="safari_mac",
        user_agent=(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
            "(KHTML, like Gecko) Version/17.4 Safari/605.1.15"
        ),
        headers={
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
        },
    ),
    TrafficProfile(
        name="chrome_android",
        user_agent=(
            "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36"
        ),
        headers={
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Sec-CH-UA-Mobile": "?1",
        },
    ),
)


class RotationStrategy(str, enum.Enum):
    RANDOM = "random"            # pick a profile at random per call
    ROUND_ROBIN = "round_robin"  # cycle through profiles in order
    STICKY_HOST = "sticky_host"  # one stable profile per host (most realistic)


class TimingMode(str, enum.Enum):
    UNIFORM = "uniform"          # base + U(0, jitter)
    GAUSSIAN = "gaussian"        # N(mean, stddev), clamped
    HUMAN = "human"              # short gaps with occasional longer "read" pauses


@dataclass(slots=True)
class TimingModel:
    """Polymorphic inter-request timing (spacing, not concurrency)."""

    mode: TimingMode = TimingMode.HUMAN
    base_delay_s: float = 0.6
    jitter_s: float = 0.8
    stddev_s: float = 0.4
    long_pause_prob: float = 0.15     # HUMAN mode: chance of a longer pause
    long_pause_s: float = 3.5
    max_delay_s: float = 10.0

    def next_delay(self, backoff_mult: float = 1.0) -> float:
        if self.mode is TimingMode.UNIFORM:
            d = self.base_delay_s + random.uniform(0.0, self.jitter_s)
        elif self.mode is TimingMode.GAUSSIAN:
            d = random.gauss(self.base_delay_s, self.stddev_s)
        else:  # HUMAN
            if random.random() < self.long_pause_prob:
                d = self.long_pause_s + random.uniform(0.0, self.jitter_s)
            else:
                d = self.base_delay_s + random.uniform(0.0, self.jitter_s)
        return max(0.0, min(d * backoff_mult, self.max_delay_s))


# --------------------------------------------------------------------------- #
# TrafficProfiler                                                             #
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class ShapedRequest:
    """The concrete shaping to apply to one request/batch."""

    profile_name: str
    headers: dict[str, str]
    delay_s: float


class TrafficProfiler:
    """
    Produces realistic, attributable request shaping for authorized testing.

    Parameters
    ----------
    profiles:
        Client profiles to rotate through (defaults to the built-in pool).
    strategy:
        How profiles are selected. ``STICKY_HOST`` keeps one identity per host,
        which is both the most realistic and the least noisy.
    timing:
        The inter-request timing model.
    engagement_id:
        Optional authorization tag echoed as ``X-Orion-Engagement`` on every
        request so authorized traffic stays attributable. Strongly recommended.
    extra_headers:
        Static headers merged into every profile (e.g. a program-required token).
    """

    def __init__(
        self,
        profiles: Optional[list[TrafficProfile]] = None,
        strategy: RotationStrategy = RotationStrategy.STICKY_HOST,
        timing: Optional[TimingModel] = None,
        engagement_id: Optional[str] = None,
        extra_headers: Optional[dict[str, str]] = None,
    ) -> None:
        self._profiles: list[TrafficProfile] = list(profiles or BUILTIN_PROFILES)
        if not self._profiles:
            raise ValueError("TrafficProfiler needs at least one profile")
        self._strategy = strategy
        self._timing = timing or TimingModel()
        self._engagement_id = engagement_id
        self._extra_headers = dict(extra_headers or {})
        self._rr_index = 0
        self._host_map: dict[str, TrafficProfile] = {}
        logger.info(
            "TrafficProfiler ready: %d profile(s), strategy=%s, timing=%s, "
            "attribution=%s",
            len(self._profiles), strategy.value, self._timing.mode.value,
            "on" if engagement_id else "off",
        )

    # -- profile selection -------------------------------------------------- #
    def _select(self, host: str) -> TrafficProfile:
        if self._strategy is RotationStrategy.RANDOM:
            return random.choice(self._profiles)
        if self._strategy is RotationStrategy.ROUND_ROBIN:
            prof = self._profiles[self._rr_index % len(self._profiles)]
            self._rr_index += 1
            return prof
        # STICKY_HOST
        prof = self._host_map.get(host)
        if prof is None:
            prof = random.choice(self._profiles)
            self._host_map[host] = prof
            logger.debug("Assigned profile '%s' to host %s", prof.name, host)
        return prof

    def _headers_for(self, profile: TrafficProfile) -> dict[str, str]:
        headers = {"User-Agent": profile.user_agent, **profile.headers}
        if self._engagement_id:
            headers["X-Orion-Engagement"] = self._engagement_id  # attribution
        headers.update(self._extra_headers)
        return headers

    # -- public API --------------------------------------------------------- #
    def shape(self, host: str, backoff_mult: float = 1.0) -> ShapedRequest:
        """Return the headers + pre-request delay for the next request to ``host``."""
        profile = self._select(host)
        return ShapedRequest(
            profile_name=profile.name,
            headers=self._headers_for(profile),
            delay_s=self._timing.next_delay(backoff_mult),
        )

    def headers_for_host(self, host: str) -> dict[str, str]:
        return self._headers_for(self._select(host))

    def as_tool_flags(self, tool: str, host: str) -> list[str]:
        """
        Emit CLI header flags so external binaries (httpx/nuclei/ffuf) send the
        chosen profile instead of their default tool signature.
        """
        headers = self.headers_for_host(host)
        if tool not in ("httpx", "nuclei", "ffuf"):
            return []
        flags: list[str] = []
        for key in ("User-Agent", "Accept", "Accept-Language", "X-Orion-Engagement"):
            if key in headers:
                flags += ["-H", f"{key}: {headers[key]}"]
        return flags

    def profile_names(self) -> list[str]:
        return [p.name for p in self._profiles]
