"""
orion.enrich.leaks
=================

OSINT enrichment against breach-intelligence APIs (the "LeaksAPI" concept from
HexStrike's Email-Intelligence workflow, which references ``haveibeenpwned`` /
``hunter_io`` keyed on the target domain).

Responsible-use design decisions (these are deliberate, not incidental):

* **Authorization-gated.** Every lookup is checked against the same ScopeConfig
  the orchestrator uses. Identities whose domain is not in scope are dropped.
* **Metadata only.** This client returns *which* breaches an identity appears in
  and *what data classes* were exposed (email, dates, "passwords exposed: yes")
  — exactly what HIBP-style APIs return. It does not retrieve, crack, or store
  plaintext credentials, and it is not a credential-stuffing tool. Its purpose is
  to tell an authorized tester "these in-scope accounts have prior exposure,
  prioritize them for the program's password-reset / MFA findings."
* **Provider-agnostic.** Point ``BreachClientConfig.base_url`` at any
  HIBP-compatible endpoint; supply the key via env, never in code.
"""
from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Optional

import aiohttp

from ..core.config import ScopeConfig
from ..core.models import Asset

logger = logging.getLogger("orion.enrich")


@dataclass(slots=True)
class BreachClientConfig:
    base_url: str = "https://haveibeenpwned.com/api/v3"
    api_key_env: str = "ORION_BREACH_API_KEY"
    user_agent: str = "Orion-OSINT/0.1 (authorized-bug-bounty)"
    request_timeout_s: float = 30.0
    per_request_delay_s: float = 1.6      # respect provider rate limits
    max_concurrency: int = 1              # HIBP is strictly serial

    @property
    def api_key(self) -> Optional[str]:
        return os.environ.get(self.api_key_env)


@dataclass(slots=True)
class BreachRecord:
    identity: str
    breaches: list[str] = field(default_factory=list)
    data_classes: list[str] = field(default_factory=list)
    passwords_exposed: bool = False
    raw: dict[str, Any] = field(default_factory=dict)


class BreachEnricher:
    """
    Queries a breach-intel API for in-scope identities discovered during recon.

    Typical wiring: the orchestrator extracts emails/usernames (see
    ``recon.planner.extract_identities``), persists them as ``Asset`` rows, then
    this enricher processes the in-scope subset.
    """

    def __init__(self, cfg: BreachClientConfig, scope: ScopeConfig) -> None:
        self._cfg = cfg
        self._scope = scope
        self._sem = asyncio.Semaphore(cfg.max_concurrency)

    def _headers(self) -> dict[str, str]:
        headers = {"user-agent": self._cfg.user_agent, "accept": "application/json"}
        if self._cfg.api_key:
            headers["hibp-api-key"] = self._cfg.api_key
        return headers

    def _in_scope(self, identity: str) -> bool:
        # For emails, authorize on the domain part; usernames alone can't be
        # scoped, so they are skipped unless they carry a domain.
        if "@" not in identity:
            return False
        domain = identity.rsplit("@", 1)[1].lower()
        return self._scope.is_authorized(domain)

    async def enrich_identity(self, identity: str) -> Optional[BreachRecord]:
        """Look up a single email. Returns None if out-of-scope or clean."""
        if not self._in_scope(identity):
            logger.debug("Skipping out-of-scope identity: %s", identity)
            return None

        url = f"{self._cfg.base_url}/breachedaccount/{identity}?truncateResponse=false"
        timeout = aiohttp.ClientTimeout(total=self._cfg.request_timeout_s)

        async with self._sem:
            await asyncio.sleep(self._cfg.per_request_delay_s)  # gentle pacing
            async with aiohttp.ClientSession(timeout=timeout) as s:
                try:
                    async with s.get(url, headers=self._headers()) as r:
                        if r.status == 404:
                            return None                      # no breaches: clean
                        r.raise_for_status()
                        breaches = await r.json()
                except Exception as e:  # noqa: BLE001
                    logger.warning("Breach lookup failed for %s: %s", identity, e)
                    return None

        return self._summarize(identity, breaches)

    @staticmethod
    def _summarize(identity: str, breaches: list[dict[str, Any]]) -> BreachRecord:
        names, classes = [], set()
        for b in breaches:
            names.append(b.get("Name", "unknown"))
            classes.update(b.get("DataClasses", []))
        return BreachRecord(
            identity=identity,
            breaches=names,
            data_classes=sorted(classes),
            passwords_exposed=any("password" in c.lower() for c in classes),
            raw={"count": len(breaches)},
        )

    async def enrich_assets(self, identities: list[str]) -> list[BreachRecord]:
        """Enrich a batch; only in-scope, previously-breached identities return."""
        results = await asyncio.gather(
            *(self.enrich_identity(i) for i in identities)
        )
        return [r for r in results if r is not None]

    @staticmethod
    def to_asset(scan_id: str, record: BreachRecord) -> Asset:
        return Asset(
            scan_id=scan_id,
            kind="email",
            value=record.identity,
            meta={
                "breaches": record.breaches,
                "data_classes": record.data_classes,
                "passwords_exposed": record.passwords_exposed,
            },
        )
