"""
orion.main
=========

Thin CLI entrypoint. Builds the seed task graph and hands control to the
Orchestrator. Daemon mode simply keeps the same event loop alive under a
process supervisor (systemd/pm2/tmux); the orchestrator already persists all
state, so a restart resumes cleanly.

Example
-------
    export ORION_DISCORD_WEBHOOK=https://discord.com/api/webhooks/...
    python -m orion.main --target example.com --scope scope.json
"""
from __future__ import annotations

import argparse
import asyncio
import logging

from .core.config import OrionConfig, ScopeConfig
from .core.models import Phase, Task
from .core.orchestrator import Orchestrator
from .notify.webhook import WebhookNotifier
from .ui.banner import print_banner


def _seed_tasks(scan_id: str, target: str) -> list[Task]:
    """
    Initial recon graph. Follow-on tasks (nuclei, scoped by tech) are generated
    dynamically by the orchestrator as httpx results arrive.
    """
    return [
        Task(scan_id=scan_id, tool="subfinder", target=target,
             phase=Phase.RECON, priority=10, est_mem_mb=128),
        Task(scan_id=scan_id, tool="httpx", target=f"https://{target}",
             phase=Phase.PROBE, priority=20, est_mem_mb=256),
    ]


def _build_config(args: argparse.Namespace) -> OrionConfig:
    cfg = OrionConfig()
    if args.scope:
        cfg.scope = ScopeConfig.from_file(args.scope)
    else:
        # Minimal safe default: only the exact target + its subdomains.
        cfg.scope = ScopeConfig(in_scope=[args.target, f"*.{args.target}"])
    if args.ai_provider:
        cfg.ai.provider = args.ai_provider
    if args.ai_model:
        cfg.ai.model = args.ai_model
    return cfg


async def _run(args: argparse.Namespace) -> None:
    cfg = _build_config(args)
    if not cfg.scope.is_authorized(args.target):
        raise SystemExit(
            f"Refusing to start: '{args.target}' is not authorized by the scope "
            f"file. Add it to in_scope or supply --scope."
        )

    notifier = WebhookNotifier(cfg.notify)
    orch = Orchestrator(cfg, notify_hook=notifier.notify)
    import uuid
    scan_id = args.resume or uuid.uuid4().hex
    seeds = _seed_tasks(scan_id, args.target)
    await orch.run(args.target, seeds, scan_id=scan_id)


def main() -> None:
    parser = argparse.ArgumentParser(prog="orion", description="AI-driven bug hunter")
    parser.add_argument("--target", required=True, help="root domain in scope")
    parser.add_argument("--scope", help="path to scope JSON (rules of engagement)")
    parser.add_argument("--resume", help="existing scan_id to resume")
    parser.add_argument("--ai-provider", choices=["ollama", "openai", "anthropic"])
    parser.add_argument("--ai-model")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--no-banner", action="store_true", help="suppress the ASCII banner")
    args = parser.parse_args()

    if not args.no_banner:
        print_banner()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    asyncio.run(_run(args))


if __name__ == "__main__":
    main()
