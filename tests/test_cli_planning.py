"""Master planning: recon → probe → context-aware vuln, with scope filtering."""
from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from orion.core.config import ScopeConfig
from orion.core.state import StateStore
from orion.dist.broker import InMemoryBroker
from orion.dist.cli import _plan_followups
from orion.dist.dispatcher import MasterDispatcher
from orion.dist.tasks import TaskResult


def _db():
    return Path(tempfile.mkdtemp()) / "t.db"


def _result(tool: str, stdout: str) -> TaskResult:
    return TaskResult(task_id="t", scan_id="s", tool=tool, target="acme.com",
                      worker_id="w", returncode=0, stdout=stdout, stderr="",
                      duration_s=0.0, ok=True)


async def _drain(broker):
    out = []
    while True:
        lease = await broker.lease("w", 5)
        if lease is None:
            break
        out.append(lease.task)
    return out


def test_subfinder_plans_httpx_and_drops_out_of_scope() -> None:
    async def scenario() -> None:
        scope = ScopeConfig(in_scope=["acme.com", "*.acme.com"])
        broker = InMemoryBroker()
        disp = MasterDispatcher(broker)
        state = await StateStore(_db()).open()
        await state.create_scan("s", "acme.com", "{}")
        await _plan_followups(
            disp, scope, _result("subfinder", "api.acme.com\nwww.acme.com\nevil.com"),
            state, None, None, None, 0.65, 3,
        )
        tasks = await _drain(broker)
        targets = {t.target for t in tasks}
        assert all(t.tool == "httpx" for t in tasks)
        assert "https://evil.com" not in targets
        assert "https://api.acme.com" in targets
        await state.close()
    asyncio.run(scenario())


def test_httpx_plans_context_scoped_nuclei() -> None:
    async def scenario() -> None:
        scope = ScopeConfig(in_scope=["*.acme.com", "acme.com"])
        broker = InMemoryBroker()
        disp = MasterDispatcher(broker)
        state = await StateStore(_db()).open()
        await state.create_scan("s", "acme.com", "{}")
        await _plan_followups(
            disp, scope, _result(
                "httpx",
                '{"url":"https://api.acme.com","status_code":200,"tech":["React","Express"]}',
            ),
            state, None, None, None, 0.65, 3,
        )
        tasks = await _drain(broker)
        assert len(tasks) == 1 and tasks[0].tool == "nuclei"
        joined = " ".join(tasks[0].args)
        assert "node" in joined and "javascript" in joined
        assert "wordpress" not in joined
        await state.close()
    asyncio.run(scenario())
