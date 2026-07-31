"""
orion.net.proxy_pool
===================

A proxy pool for **throughput and resilience** during authorized, distributed
scanning — not for anti-attribution. Paired with ``RequestProfileManager``, the
same identifiable User-Agent is sent regardless of which egress proxy is used,
so distributing load never means hiding who is testing.

Health tracking sidelines proxies that error or get rate-limited, with a cooldown
before they're retried.
"""
from __future__ import annotations

import itertools
import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass(slots=True)
class _ProxyState:
    url: str
    healthy: bool = True
    cooldown_until: float = 0.0
    failures: int = 0


@dataclass
class ProxyPool:
    """
    Round-robin proxy selection with per-proxy health + cooldown.

    Parameters
    ----------
    proxies:
        List of proxy URLs (e.g. ``http://user:pass@host:port``). An empty pool
        means "direct connection" — ``acquire`` returns ``None``.
    cooldown_s:
        How long an unhealthy proxy is skipped before being retried.
    """

    proxies: list[str] = field(default_factory=list)
    cooldown_s: float = 120.0
    _states: dict[str, _ProxyState] = field(default_factory=dict, init=False)
    _cycle: "itertools.cycle[str]" = field(init=False, default=None)  # type: ignore

    def __post_init__(self) -> None:
        self._states = {p: _ProxyState(p) for p in self.proxies}
        self._cycle = itertools.cycle(self.proxies) if self.proxies else itertools.cycle([""])

    def acquire(self) -> Optional[str]:
        """Return the next healthy proxy URL, or None for a direct connection."""
        if not self.proxies:
            return None
        now = time.monotonic()
        for _ in range(len(self.proxies)):
            candidate = next(self._cycle)
            st = self._states[candidate]
            if st.healthy or now >= st.cooldown_until:
                st.healthy = True
                return candidate
        return None  # everything is cooling down -> fall back to direct

    def mark_bad(self, proxy: Optional[str]) -> None:
        if proxy and proxy in self._states:
            st = self._states[proxy]
            st.failures += 1
            st.healthy = False
            st.cooldown_until = time.monotonic() + self.cooldown_s

    def mark_good(self, proxy: Optional[str]) -> None:
        if proxy and proxy in self._states:
            st = self._states[proxy]
            st.healthy = True
            st.failures = 0

    def stats(self) -> dict[str, dict[str, object]]:
        return {
            p: {"healthy": s.healthy, "failures": s.failures}
            for p, s in self._states.items()
        }
