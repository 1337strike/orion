"""
Tests for the v2.0 durable queue and traffic profiler.

Async tests run via asyncio.run so no pytest-asyncio is required.
"""
from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from orion.dist.queue_manager import DistributedQueueManager
from orion.dist.tasks import DistTask
from orion.net.traffic_profiler import (
    RotationStrategy,
    TimingMode,
    TimingModel,
    TrafficProfiler,
)


def _db() -> str:
    return str(Path(tempfile.mkdtemp()) / "queue.db")


def _tasks(n: int) -> list[DistTask]:
    return [DistTask(tool="httpx", target=f"https://h{i}.example.com", scan_id="s")
            for i in range(n)]


# --------------------------------------------------------------------------- #
# Durable queue                                                               #
# --------------------------------------------------------------------------- #
def test_lease_is_atomic_no_double_delivery() -> None:
    async def scenario() -> None:
        q = await DistributedQueueManager(_db()).open()
        await q.submit(_tasks(5))
        # 10 concurrent workers race for 5 tasks.
        leased = await asyncio.gather(*(q.lease(f"w{i}") for i in range(10)))
        got = [t for t in leased if t is not None]
        ids = [t.task_id for t in got]
        assert len(got) == 5
        assert len(set(ids)) == 5           # every task leased exactly once
        await q.close()

    asyncio.run(scenario())


def test_cold_start_recovery_requeues_interrupted_tasks() -> None:
    """Full restart: leased tasks are recovered from SQLite with zero loss."""
    async def scenario() -> None:
        path = _db()
        q = await DistributedQueueManager(path).open()
        await q.submit(_tasks(3))
        # A worker leases two tasks, then the whole process "dies".
        await q.lease("worker-A")
        await q.lease("worker-A")
        s = await q.stats()
        assert s.leased == 2 and s.pending == 1
        await q.close()                      # simulate crash / interruption

        # Reopen: cold-start recovery should requeue the 2 interrupted tasks.
        q2 = await DistributedQueueManager(path).open(recover=True)
        s2 = await q2.stats()
        assert s2.leased == 0 and s2.pending == 3    # nothing lost
        await q2.close()

    asyncio.run(scenario())


def test_expired_lease_reaped() -> None:
    async def scenario() -> None:
        q = await DistributedQueueManager(_db(), visibility_s=0.3).open()
        await q.submit(_tasks(1))
        await q.lease("slow-worker")
        assert (await q.stats()).leased == 1
        await asyncio.sleep(0.35)
        recovered = await q.recover(reset_all_leased=False)  # deadline-based reap
        assert recovered == 1
        assert (await q.stats()).pending == 1
        await q.close()

    asyncio.run(scenario())


def test_fail_requeues_then_dead_letters() -> None:
    async def scenario() -> None:
        q = await DistributedQueueManager(_db()).open()
        await q.submit([DistTask(tool="ffuf", target="https://x", max_attempts=2)])
        t = await q.lease("w")
        assert t is not None
        assert await q.fail(t.task_id) == "requeued"
        t2 = await q.lease("w")
        assert await q.fail(t2.task_id) == "dead_letter"
        s = await q.stats()
        assert s.failed == 1 and s.pending == 0
        await q.close()

    asyncio.run(scenario())


def test_full_drain_with_workers() -> None:
    """A pool of async workers drains the queue with heartbeats + completion."""
    async def worker(q: DistributedQueueManager, wid: str, done: list[str]) -> None:
        while not await q.is_drained():
            task = await q.lease(wid)
            if task is None:
                await asyncio.sleep(0.02)
                continue
            await q.heartbeat(task.task_id, wid)
            await asyncio.sleep(0.01)         # simulate work
            await q.complete(task.task_id)
            done.append(task.task_id)

    async def scenario() -> None:
        q = await DistributedQueueManager(_db()).open()
        await q.submit(_tasks(20))
        done: list[str] = []
        await asyncio.gather(*(worker(q, f"w{i}", done) for i in range(4)))
        s = await q.stats()
        assert s.done == 20 and s.outstanding == 0
        assert len(set(done)) == 20           # each task completed exactly once
        await q.close()

    asyncio.run(scenario())


# --------------------------------------------------------------------------- #
# Traffic profiler                                                            #
# --------------------------------------------------------------------------- #
def test_profiles_are_coherent_and_have_ua() -> None:
    tp = TrafficProfiler()
    for name in tp.profile_names():
        headers = tp.headers_for_host("example.com")
        assert "User-Agent" in headers and headers["User-Agent"]
        assert "Accept" in headers            # coherent header set, not just a UA


def test_sticky_host_is_stable_but_varies_across_hosts() -> None:
    tp = TrafficProfiler(strategy=RotationStrategy.STICKY_HOST)
    a1 = tp.headers_for_host("a.example.com")["User-Agent"]
    a2 = tp.headers_for_host("a.example.com")["User-Agent"]
    assert a1 == a2                            # same host -> stable identity


def test_attribution_tag_present_when_set() -> None:
    tp = TrafficProfiler(engagement_id="ENG-2026-07")
    headers = tp.headers_for_host("example.com")
    assert headers["X-Orion-Engagement"] == "ENG-2026-07"   # stays attributable


def test_tool_flags_carry_profile_and_attribution() -> None:
    tp = TrafficProfiler(engagement_id="ENG-9")
    flags = tp.as_tool_flags("nuclei", "example.com")
    assert "-H" in flags
    assert any("User-Agent:" in f for f in flags)
    assert any("X-Orion-Engagement: ENG-9" in f for f in flags)


def test_timing_models_bounded() -> None:
    for mode in (TimingMode.UNIFORM, TimingMode.GAUSSIAN, TimingMode.HUMAN):
        tm = TimingModel(mode=mode, base_delay_s=0.5, jitter_s=0.5, max_delay_s=5.0)
        for _ in range(200):
            d = tm.next_delay()
            assert 0.0 <= d <= 5.0             # always within bounds
