"""
Tests for MetricsServer health/metrics and the full integrated master pipeline
(state store + planning + AI triage wiring).

HTTP endpoint tests run a real aiohttp server on a random port.
"""
from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path

from orion.core.config import ScopeConfig
from orion.core.models import Severity
from orion.dist.broker import InMemoryBroker
from orion.dist.cli import _ingest_nuclei, _plan_followups
from orion.dist.dispatcher import MasterDispatcher
from orion.dist.metrics import MetricsServer
from orion.dist.tasks import TaskResult
from orion.core.state import StateStore


def _db_path() -> Path:
    return Path(tempfile.mkdtemp()) / "test.db"


def _result(tool: str, stdout: str, ok: bool = True) -> TaskResult:
    return TaskResult(
        task_id="t1", scan_id="scan1", tool=tool, target="acme.com",
        worker_id="w", returncode=0 if ok else 1, stdout=stdout,
        stderr="", duration_s=0.1, ok=ok,
    )


# --------------------------------------------------------------------------- #
# Metrics server                                                               #
# --------------------------------------------------------------------------- #
def test_metrics_health_and_counters() -> None:
    async def scenario() -> None:
        import aiohttp
        broker = InMemoryBroker()
        srv = MetricsServer(broker, port=19876)
        await srv.start()
        try:
            srv.inc("findings_total", 5)
            srv.inc("findings_high_critical", 2)
            async with aiohttp.ClientSession() as s:
                async with s.get("http://127.0.0.1:19876/health") as r:
                    h = await r.json()
                    assert h["status"] == "ok"
                    assert h["uptime_s"] >= 0
                async with s.get("http://127.0.0.1:19876/metrics") as r:
                    m = await r.json()
                    assert m["findings_total"] == 5
                    assert m["findings_high_critical"] == 2
                    assert "queue" in m
        finally:
            await srv.stop()

    asyncio.run(scenario())


# --------------------------------------------------------------------------- #
# Integrated master pipeline                                                  #
# --------------------------------------------------------------------------- #
def test_subfinder_plans_httpx_drops_out_of_scope() -> None:
    async def scenario() -> None:
        scope = ScopeConfig(in_scope=["acme.com", "*.acme.com"])
        broker = InMemoryBroker()
        disp = MasterDispatcher(broker)
        state = await StateStore(_db_path()).open()
        await state.create_scan("scan1", "acme.com", "{}")

        await _plan_followups(
            disp, scope,
            _result("subfinder", "api.acme.com\nwww.acme.com\nevil.com"),
            state, None, None, None, 0.65, 3,
        )

        leased = []
        while True:
            l = await broker.lease("w", 5)
            if l is None:
                break
            leased.append(l.task)

        targets = {t.target for t in leased}
        assert "https://evil.com" not in targets     # out-of-scope dropped
        assert "https://api.acme.com" in targets
        assert all(t.tool == "httpx" for t in leased)
        await state.close()

    asyncio.run(scenario())


def test_nuclei_findings_persisted_to_state() -> None:
    nuclei_jsonl = json.dumps({
        "template-id": "exposed-env",
        "info": {"name": "Exposed .env file", "severity": "high"},
        "matched-at": "https://api.acme.com/.env",
        "response": {"body": "DB_PASSWORD=s3cr3t", "header": {}},
    })

    async def scenario() -> None:
        db = _db_path()
        state = await StateStore(db).open()
        await state.create_scan("scan1", "acme.com", "{}")

        await _ingest_nuclei(
            _result("nuclei", nuclei_jsonl),
            state, None, None, None, 0.65,
        )
        # Findings saved to SQLite — verify via assets_of_kind is not directly
        # applicable; instead open the db and query directly.
        import aiosqlite
        async with aiosqlite.connect(str(db)) as db_conn:
            db_conn.row_factory = aiosqlite.Row
            cur = await db_conn.execute("SELECT name, severity FROM findings")
            rows = await cur.fetchall()
        assert len(rows) == 1
        assert rows[0]["name"] == "Exposed .env file"
        assert rows[0]["severity"] == "high"
        await state.close()

    asyncio.run(scenario())


def test_failed_results_counted_in_metrics() -> None:
    async def scenario() -> None:
        scope = ScopeConfig(in_scope=["acme.com"])
        broker = InMemoryBroker()
        disp = MasterDispatcher(broker)
        state = await StateStore(_db_path()).open()
        await state.create_scan("scan1", "acme.com", "{}")
        srv = MetricsServer(broker, port=19877)
        await srv.start()
        try:
            await _plan_followups(
                disp, scope, _result("subfinder", "", ok=False),
                state, None, None, srv, 0.65, 3,
            )
            m = srv._counters
            assert m["tasks_failed"] == 1
            assert m["tasks_completed"] == 0
        finally:
            await srv.stop()
            await state.close()

    asyncio.run(scenario())
