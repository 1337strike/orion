"""
orion.core.governor
====================

Two independent back-pressure mechanisms the orchestrator consults before it
lets a worker actually spawn a binary:

1. ``ResourceGovernor`` — a global gate that keeps Orion inside its RAM budget.
   It combines a memory-weighted semaphore (so ten concurrent Nuclei runs can't
   each assume they have the whole box) with a live psutil check that stalls new
   dispatches when free memory dips under the configured floor. This is what
   keeps a 16 GB machine responsive.

2. ``WAFRateLimiter`` — a *per-host* token-bucket pacer with randomized jitter,
   plus adaptive escalation. When a tool result shows WAF/rate-limit fingerprints
   (HTTP 429/403, "rate limit", Retry-After, ...), the host is bumped to a slower
   timing profile (normal -> conservative -> stealth), mirroring HexStrike's
   ``RateLimitDetector`` ladder. Escalation is sticky for the rest of the scan so
   we don't oscillate back into a ban.
"""
from __future__ import annotations

import asyncio
import random
import re
import time
from dataclasses import dataclass, field
from typing import Optional

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None  # type: ignore

from .config import RateProfile, ResourceConfig


# --------------------------------------------------------------------------- #
# Resource governor                                                            #
# --------------------------------------------------------------------------- #
class ResourceGovernor:
    """
    Global admission control for tool execution.

    Usage::

        async with governor.slot(task.est_mem_mb):
            await run_tool(...)

    The context manager will not return until (a) a concurrency slot is free and
    (b) the machine has at least ``min_free_gb_to_dispatch`` available.
    """

    def __init__(self, cfg: ResourceConfig) -> None:
        self._cfg = cfg
        self._max = cfg.derived_concurrency()
        self._sem = asyncio.Semaphore(self._max)
        # Weighted budget in MB, so memory-heavy tasks consume more headroom.
        self._budget_mb = int(cfg.budget_gb() * 1024)
        self._in_use_mb = 0
        self._lock = asyncio.Lock()
        self._mem_free = asyncio.Event()
        self._mem_free.set()

    @property
    def max_concurrency(self) -> int:
        return self._max

    def _memory_ok(self) -> bool:
        if psutil is None:
            return True
        free_gb = psutil.virtual_memory().available / (1024 ** 3)
        return free_gb >= self._cfg.min_free_gb_to_dispatch

    async def _await_memory(self) -> None:
        # Poll psutil with backoff until the machine has breathing room again.
        while not self._memory_ok():
            await asyncio.sleep(0.75)

    def slot(self, est_mem_mb: int) -> "_Slot":
        return _Slot(self, est_mem_mb)

    async def _acquire(self, est_mem_mb: int) -> None:
        await self._sem.acquire()
        await self._await_memory()
        async with self._lock:
            self._in_use_mb += est_mem_mb

    async def _release(self, est_mem_mb: int) -> None:
        async with self._lock:
            self._in_use_mb = max(0, self._in_use_mb - est_mem_mb)
        self._sem.release()

    def snapshot(self) -> dict[str, float]:
        avail = (
            psutil.virtual_memory().available / (1024 ** 3) if psutil else -1.0
        )
        return {
            "max_concurrency": self._max,
            "budget_mb": self._budget_mb,
            "in_use_mb": self._in_use_mb,
            "available_gb": round(avail, 2),
        }


@dataclass
class _Slot:
    _gov: ResourceGovernor
    _mem: int

    async def __aenter__(self) -> "_Slot":
        await self._gov._acquire(self._mem)
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self._gov._release(self._mem)


# --------------------------------------------------------------------------- #
# WAF-aware rate limiter                                                       #
# --------------------------------------------------------------------------- #
_ESCALATION = ["aggressive", "normal", "conservative", "stealth"]

_WAF_SIGNATURES = re.compile(
    r"(rate.?limit|too many requests|retry.?after|forbidden|"
    r"access denied|cloudflare|akamai|\bwaf\b|blocked)",
    re.IGNORECASE,
)


@dataclass
class _HostState:
    profile_name: str
    next_allowed: float = 0.0
    sem: asyncio.Semaphore = field(default=None)  # type: ignore
    consecutive_blocks: int = 0


class WAFRateLimiter:
    """
    Per-host pacing with jitter and adaptive slowdown.

    ``await acquire(host)`` blocks until the host's token bucket permits another
    request, then applies base_delay + uniform jitter. ``observe(...)`` inspects
    a tool's HTTP status / output and escalates the host's profile if it smells
    like a WAF is pushing back.
    """

    def __init__(
        self,
        profiles: dict[str, RateProfile],
        default_profile: str = "normal",
    ) -> None:
        self._profiles = profiles
        self._default = default_profile
        self._hosts: dict[str, _HostState] = {}
        self._lock = asyncio.Lock()

    def _profile(self, name: str) -> RateProfile:
        return self._profiles.get(name, self._profiles[self._default])

    async def _host_state(self, host: str) -> _HostState:
        async with self._lock:
            st = self._hosts.get(host)
            if st is None:
                prof = self._profile(self._default)
                st = _HostState(
                    profile_name=self._default,
                    sem=asyncio.Semaphore(prof.max_concurrency_per_host),
                )
                self._hosts[host] = st
            return st

    async def acquire(self, host: str) -> None:
        st = await self._host_state(host)
        await st.sem.acquire()
        prof = self._profile(st.profile_name)

        # Serialize the "next allowed" computation so jitter is honored globally.
        async with self._lock:
            now = time.monotonic()
            wait = max(0.0, st.next_allowed - now)
            delay = prof.base_delay_s + random.uniform(0.0, prof.jitter_s)
            st.next_allowed = max(now, st.next_allowed) + delay
        if wait > 0:
            await asyncio.sleep(wait)

    async def release(self, host: str) -> None:
        st = await self._host_state(host)
        st.sem.release()

    async def observe(
        self,
        host: str,
        status_code: Optional[int],
        sample_text: str = "",
    ) -> Optional[str]:
        """
        Feed a tool's HTTP status / output back in. Returns the new profile name
        if the host was escalated, else None.
        """
        looks_blocked = (
            status_code in (403, 429)
            or bool(_WAF_SIGNATURES.search(sample_text or ""))
        )
        if not looks_blocked:
            return None

        async with self._lock:
            st = self._hosts.get(host)
            if st is None:
                return None
            st.consecutive_blocks += 1
            idx = _ESCALATION.index(st.profile_name)
            if idx < len(_ESCALATION) - 1:
                st.profile_name = _ESCALATION[idx + 1]
                # Rebuild the per-host semaphore to the tighter concurrency.
                new_prof = self._profile(st.profile_name)
                st.sem = asyncio.Semaphore(new_prof.max_concurrency_per_host)
                return st.profile_name
            return st.profile_name  # already at stealth

    def profile_of(self, host: str) -> str:
        st = self._hosts.get(host)
        return st.profile_name if st else self._default
