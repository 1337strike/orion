"""
Reliability tests for the distributed queue — the core guarantee that no task is
silently lost even when a worker dies mid-flight.

Async tests are driven via ``asyncio.run`` so the suite needs no pytest-asyncio.
"""
from __future__ import annotations

import asyncio

from orion.dist.broker import InMemoryBroker
from orion.dist.dispatcher import DispatcherConfig, MasterDispatcher
from orion.dist.tasks import DistTask, TaskResult
from orion.dist.worker import Worker


def _mk_tasks(n: int) -> list[DistTask]:
    return [DistTask(tool="httpx", target=f"https://h{i}.example.com", scan_id="s")
            for i in range(n)]


def _ok_result(dt: DistTask, worker_id: str = "w") -> TaskResult:
    return TaskResult(task_id=dt.task_id, scan_id=dt.scan_id, tool=dt.tool,
                      target=dt.target, worker_id=worker_id, returncode=0,
                      stdout="{}", stderr="", duration_s=0.01, ok=True)


# --------------------------------------------------------------------------- #
def test_lease_reap_requeues_dead_worker_task() -> None:
    """A leased-but-unacked task returns to pending after its deadline lapses."""
    async def scenario() -> None:
        broker = InMemoryBroker()
        await broker.put(DistTask(tool="httpx", target="https://x.example.com"))

        lease = await broker.lease("dying-worker", visibility_s=0.3)
        assert lease is not None
        assert (await broker.stats())["inflight"] == 1

        # Worker "dies": no heartbeat, no ack. Wait past the deadline.
        await asyncio.sleep(0.35)
        recovered = await broker.reap()
        assert recovered == 1

        stats = await broker.stats()
        assert stats["inflight"] == 0 and stats["pending"] == 1

        # The requeued task is available again and carries an incremented attempt.
        lease2 = await broker.lease("healthy-worker", visibility_s=5)
        assert lease2 is not None and lease2.task.attempts == 1

    asyncio.run(scenario())


def test_heartbeat_prevents_reap() -> None:
    """A worker that heartbeats keeps its lease past the base visibility window."""
    async def scenario() -> None:
        broker = InMemoryBroker()
        await broker.put(DistTask(tool="nuclei", target="https://x.example.com"))
        lease = await broker.lease("w", visibility_s=0.3)
        assert lease is not None

        await asyncio.sleep(0.2)
        assert await broker.heartbeat(lease, extend_s=1.0) is True
        await asyncio.sleep(0.2)                 # past original deadline, not extended one
        assert await broker.reap() == 0          # still owned
        assert (await broker.stats())["inflight"] == 1

    asyncio.run(scenario())


def test_dead_letter_after_max_attempts() -> None:
    """A task that keeps failing is dead-lettered, never lost or infinitely looped."""
    async def scenario() -> None:
        broker = InMemoryBroker()
        await broker.put(DistTask(tool="ffuf", target="https://x.example.com",
                                  max_attempts=2))
        for _ in range(3):
            lease = await broker.lease("w", visibility_s=5)
            if lease is None:
                break
            await broker.nack(lease, requeue=True)
        stats = await broker.stats()
        assert stats["dead_letter"] == 1 and stats["pending"] == 0

    asyncio.run(scenario())


def test_end_to_end_worker_death_recovered_by_dispatcher() -> None:
    """
    Full path: 3 tasks, one worker dies mid-task, the dispatcher's reaper recovers
    it, and a healthy worker completes everything. All 3 results, zero loss.
    """
    async def scenario() -> None:
        broker = InMemoryBroker()
        dispatcher = MasterDispatcher(broker, DispatcherConfig(reap_interval_s=0.2))
        tasks = _mk_tasks(3)
        await dispatcher.submit(tasks)
        await dispatcher.start_reaper()

        # A worker that "dies" on its first task: sleeps forever, then gets cancelled.
        async def dying_executor(dt: DistTask) -> TaskResult:
            await asyncio.sleep(60)  # never completes
            return _ok_result(dt)

        dying = Worker(broker, dying_executor, worker_id="dying",
                       visibility_s=0.4, heartbeat_s=10)
        dying_run = asyncio.create_task(dying.run())
        await asyncio.sleep(0.15)      # let it lease one task
        dying_run.cancel()             # kill it mid-flight
        try:
            await dying_run
        except asyncio.CancelledError:
            pass

        # Healthy worker finishes the rest (reaper will return the orphaned task).
        healthy = Worker(broker, lambda dt: _complete(dt), worker_id="healthy",
                         visibility_s=5, heartbeat_s=1, idle_sleep_s=0.05)
        healthy_run = asyncio.create_task(healthy.run())

        collected: list[TaskResult] = []
        async for res in dispatcher.results(expected=3):
            collected.append(res)

        healthy.stop()
        await healthy_run
        await dispatcher.stop_reaper()

        assert len(collected) == 3
        assert {r.target for r in collected} == {t.target for t in tasks}
        assert (await broker.stats())["dead_letter"] == 0

    async def _complete(dt: DistTask) -> TaskResult:
        await asyncio.sleep(0.02)
        return _ok_result(dt, "healthy")

    asyncio.run(scenario())


def test_retry_on_transient_failure() -> None:
    """A task that fails once is retried and then succeeds — surfaced exactly once."""
    async def scenario() -> None:
        broker = InMemoryBroker()
        dispatcher = MasterDispatcher(broker, DispatcherConfig(reap_interval_s=0.2))
        attempts: dict[str, int] = {}

        async def flaky(dt: DistTask) -> TaskResult:
            attempts[dt.task_id] = attempts.get(dt.task_id, 0) + 1
            if attempts[dt.task_id] == 1:
                raise RuntimeError("transient network error")
            return _ok_result(dt)

        worker = Worker(broker, flaky, worker_id="w", visibility_s=5,
                        heartbeat_s=1, idle_sleep_s=0.05)
        run = asyncio.create_task(worker.run())

        results = await dispatcher.run_until_complete(_mk_tasks(1))

        worker.stop()
        await run
        assert len(results) == 1
        assert results[0].ok is True
        assert list(attempts.values())[0] == 2      # failed once, then succeeded

    asyncio.run(scenario())
