"""
orion.notify.webhook
===================

Async notifiers for daemon mode. The orchestrator calls a ``NotifyHook`` only
after the AI triage bridge confirms a High/Critical finding, so these fire on
*validated* signal, not raw scanner noise.
"""
from __future__ import annotations

import logging
import os
from typing import Optional

import aiohttp

from ..core.config import NotifyConfig
from ..core.models import Finding, Severity

logger = logging.getLogger("orion.notify")


def _format(finding: Finding) -> str:
    vectors = "\n".join(f"  - {v}" for v in finding.suggested_vectors[:5])
    conf = f"{finding.ai_confidence:.0%}" if finding.ai_confidence is not None else "n/a"
    return (
        f"🚨 **{finding.severity.value.upper()}** — {finding.name}\n"
        f"Target: {finding.target}\n"
        f"Tool: {finding.tool} | AI confidence: {conf}\n"
        f"Why: {finding.ai_rationale or 'n/a'}\n"
        + (f"Suggested vectors:\n{vectors}" if vectors else "")
    )


class WebhookNotifier:
    """Fan-out to Discord and/or Telegram based on env-configured secrets."""

    def __init__(self, cfg: NotifyConfig) -> None:
        self._cfg = cfg
        self._min_rank = Severity(cfg.notify_min_severity).rank

    async def notify(self, finding: Finding) -> None:
        if finding.severity.rank < self._min_rank:
            return
        message = _format(finding)
        await self._discord(message)
        await self._telegram(message)

    async def _discord(self, message: str) -> None:
        url = os.environ.get(self._cfg.discord_webhook_env)
        if not url:
            return
        await self._post_json(url, {"content": message})

    async def _telegram(self, message: str) -> None:
        token = os.environ.get(self._cfg.telegram_bot_token_env)
        chat = os.environ.get(self._cfg.telegram_chat_id_env)
        if not (token and chat):
            return
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        await self._post_json(url, {"chat_id": chat, "text": message,
                                    "parse_mode": "Markdown"})

    @staticmethod
    async def _post_json(url: str, payload: dict) -> None:
        timeout = aiohttp.ClientTimeout(total=15)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as s:
                async with s.post(url, json=payload) as r:
                    if r.status >= 300:
                        logger.warning("Notifier %s -> HTTP %s", url[:40], r.status)
        except Exception as e:  # noqa: BLE001
            logger.warning("Notifier post failed: %s", e)
