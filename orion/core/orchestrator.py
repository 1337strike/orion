"""
orion.core.orchestrator
=======================

Orion's beating heart: an asyncio event loop that drives a priority execution
queue of external-tool tasks through the recon -> probe -> fuzz -> vuln -> triage
pipeline, entirely non-blocking.

What this module owns
---------------------
* **The event loop & worker pool.** N workers pull from an ``asyncio`` priority
  queue. N is *derived from RAM* by the ResourceGovernor, so the same code is
  safe on a 16 GB laptop.
* **Durable state (SQLite).** Every transition is written through ``StateStore``.
  On startup it recovers interrupted tasks, so a crash/Ctrl-C resumes exactly
  where it stopped.
* **Admission control.** Before any binary spawns, a task passes the scope guard
  (authorized host?), the ResourceGovernor (memory slot?), and the
  WAFRateLimiter (per-host pace + jitter).
* **Context-aware follow-ups.** Httpx tech output is fed to the planner to emit
  a Nuclei task scoped to the detected stack.
* **AI triage + notify.** High/Critical findings are sent to the AITriageBridge;
  confirmed true-positives fire a webhook.

External binaries are wrapped with ``asyncio.create_subprocess_exec`` (argv, no
shell) and hard-capped with ``wait_for``; on timeout the whole process group is
killed so no Go binary is left orphaned.
"""
from __future__ import annotations

import asyncio
import contextlib
import itertools
import json
import logging
import os
import signal
import time
import uuid
from typing import Awaitable, Callable, Optional

from ..ai.mcp_bridge import AITriageBridge
from ..recon.planner import (
    nuclei_tags_for_tech,
    parse_httpx_jsonl,
    parse_nuclei_jsonl,
)
from .config import OrionConfig
from .governor import ResourceGovernor, WAFRateLimiter
from .models import (
    Finding,
    Phase,
    ScanState,
    Severity,
    Task,
    TaskState,
    ToolResult,
)
from .state import StateStore

logger = logging.getLogger("orion.orchestrator")

# Callback fired for a confirmed high/critical finding (wired to notifiers).
NotifyHook = Callable[[Finding], Awaitable[None]]


# --------------------------------------------------------------------------- #
# Async tool runner                                                            #
# --------------------------------------------------------------------------- #
class ToolRunner:
    """Wraps a single external binary as an awaitable, with a hard timeout."""

    def __init__(self, timeout_s: float) -> None:
        self._timeout = timeout_s

    async def run(self, tool: str, argv: list[str]) -> ToolResult:
        start = time.monotonic()
        # New session so we can kill the whole process group on timeout.
        try:
            proc = await asyncio.create_subprocess_exec(
                tool,
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
        except FileNotFoundError:
            return ToolResult(
                task_id="", tool=tool, returncode=127, stdout="",
                stderr=f"binary not found: {tool}", duration_s=0.0,
            )

        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(), timeout=self._timeout
            )
            return ToolResult(
                task_id="",
                tool=tool,
                returncode=proc.returncode if proc.returncode is not None else -1,
                stdout=stdout_b.decode("utf-8", "replace"),
                stderr=stderr_b.decode("utf-8", "replace"),
                duration_s=time.monotonic() - start,
            )
        except asyncio.TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            with contextlib.suppress(Exception):
                await proc.wait()
            return ToolResult(
                task_id="", tool=tool, returncode=-1, stdout="",
                stderr=f"timeout after {self._timeout}s", duration_s=time.monotonic() - start,
                timed_out=True,
            )


# --------------------------------------------------------------------------- #
# Command builders                                                             #
# --------------------------------------------------------------------------- #
def build_argv(task: Task, extra: Optional[list[str]] = None) -> list[str]:
    """
    Translate a Task into concrete argv for the supported Go binaries.

    Kept declarative and central so scope/rate policy can't be bypassed by an
    ad-hoc command string. Add new tools here.
    """
    t = task.target
    base: dict[str, list[str]] = {
        "subfinder": ["-silent", "-d", t],
        "httpx":     ["-json", "-silent", "-tech-detect", "-status-code", "-u", t],
        "masscan":   ["-p1-65535", "--rate", "1000", t],
        "nuclei":    ["-json", "-silent", "-severity", "low,medium,high,critical", "-u", t],
        "ffuf":      ["-of", "json", "-u", f"{t}/FUZZ"],
        "dalfox":    ["url", t, "--format", "json", "--silence"],
    }
    argv = list(base.get(task.tool, [t]))
    argv.extend(task.args)
    if extra:
        argv.extend(extra)
    return argv


# --------------------------------------------------------------------------- #
# Orchestrator                                                                 #
# --------------------------------------------------------------------------- #
class Orchestrator:
    """Coordinates the whole scan lifecycle on a single asyncio event loop."""

    def __init__(
        self,
        config: OrionConfig,
        notify_hook: Optional[NotifyHook] = None,
    ) -> None:
        self.cfg = config
        self.cfg.ensure_dirs()
        self.state = StateStore(self.cfg.db_path)
        self.governor = ResourceGovernor(self.cfg.resources)
        self.limiter = WAFRateLimiter(self.cfg.profiles, self.cfg.default_profile)
        self.runner = ToolRunner(self.cfg.tool_timeout_s)
        self.triage = AITriageBridge(self.cfg.ai)
        self._notify = notify_hook

        # (priority, seq, Task) — seq breaks ties and keeps FIFO within priority.
        self._queue: asyncio.PriorityQueue = asyncio.PriorityQueue()
        self._seq = itertools.count()
        self._inflight = 0
        self._inflight_lock = asyncio.Lock()
        self._shutdown = asyncio.Event()
        self._scan_id = ""

    # -- public API --------------------------------------------------------- #
    async def run(self, target: str, seed_tasks: list[Task], scan_id: Optional[str] = None) -> str:
        """
        Launch (or resume) a scan. Returns the scan_id.

        ``seed_tasks`` are only enqueued the first time; on resume the queue is
        rebuilt from persisted state so nothing runs twice.
        """
        self._scan_id = scan_id or uuid.uuid4().hex
        await self.state.open()
        await self.state.create_scan(
            self._scan_id, target, json.dumps({"target": target})
        )
        await self.state.set_scan_state(self._scan_id, ScanState.RUNNING)
        self._install_signal_handlers()

        # Resume: reset interrupted RUNNING tasks and reload the backlog.
        recovered = await self.state.recover_interrupted(self._scan_id)
        if recovered:
            logger.info("Resuming scan %s: %d task(s) recovered",
                        self._scan_id, len(recovered))
            for task in recovered:
                await self._enqueue(task, persist=False)
        else:
            for task in seed_tasks:
                await self._enqueue(task)

        snap = self.governor.snapshot()
        logger.info("Governor: %d workers, %.1f GB free, budget %d MB",
                    snap["max_concurrency"], snap["available_gb"], snap["budget_mb"])

        workers = [
            asyncio.create_task(self._worker(i), name=f"orion-worker-{i}")
            for i in range(self.governor.max_concurrency)
        ]
        try:
            await self._drain(workers)
        finally:
            for w in workers:
                w.cancel()
            await asyncio.gather(*workers, return_exceptions=True)
            final = ScanState.PAUSED if self._shutdown.is_set() else ScanState.COMPLETED
            await self.state.set_scan_state(self._scan_id, final)
            await self.state.close()
            logger.info("Scan %s ended: %s", self._scan_id, final.value)
        return self._scan_id

    # -- queue plumbing ----------------------------------------------------- #
    async def _enqueue(self, task: Task, persist: bool = True) -> None:
        if persist:
            is_new = await self.state.add_task(task)
            if not is_new:
                return  # dedup: already tracked/completed
        await self._queue.put((task.priority, next(self._seq), task))

    async def _drain(self, workers: list[asyncio.Task]) -> None:
        """Wait until the queue empties and no task is in-flight, or shutdown."""
        while not self._shutdown.is_set():
            await asyncio.sleep(0.3)
            async with self._inflight_lock:
                idle = self._queue.empty() and self._inflight == 0
            if idle:
                return

    # -- worker ------------------------------------------------------------- #
    async def _worker(self, worker_id: int) -> None:
        while not self._shutdown.is_set():
            try:
                _, _, task = await asyncio.wait_for(self._queue.get(), timeout=0.5)
            except asyncio.TimeoutError:
                continue

            async with self._inflight_lock:
                self._inflight += 1
            try:
                await self._execute(task)
            except Exception:  # noqa: BLE001 - never let one task kill a worker
                logger.exception("Worker %d crashed on task %s", worker_id, task.task_id)
                await self.state.set_task_state(task.task_id, TaskState.FAILED)
            finally:
                self._queue.task_done()
                async with self._inflight_lock:
                    self._inflight -= 1

    async def _execute(self, task: Task) -> None:
        # 1) Scope guard — the one gate nothing bypasses.
        if not self.cfg.scope.is_authorized(task.host):
            logger.warning("SKIP out-of-scope host %s (task %s)", task.host, task.tool)
            await self.state.set_task_state(task.task_id, TaskState.SKIPPED)
            return

        await self.state.set_task_state(task.task_id, TaskState.RUNNING, task.attempts + 1)

        # 2) Admission control: memory slot + per-host WAF pacing.
        async with self.governor.slot(task.est_mem_mb):
            await self.limiter.acquire(task.host)
            try:
                argv = build_argv(task)
                result = await self.runner.run(task.tool, argv)
                result.task_id = task.task_id
            finally:
                await self.limiter.release(task.host)

        await self.state.save_result(
            task.task_id, task.tool, result.returncode, result.stdout,
            result.stderr, result.duration_s, result.timed_out,
        )

        # 3) WAF feedback: escalate this host's timing profile if pushed back.
        escalated = await self.limiter.observe(
            task.host, _first_status(result.stdout), result.stderr + result.stdout[:2000]
        )
        if escalated:
            logger.info("WAF pressure on %s -> profile now '%s'", task.host, escalated)

        if not result.ok:
            await self._maybe_retry(task, result)
            return

        await self.state.set_task_state(task.task_id, TaskState.DONE)
        await self._on_success(task, result)

    async def _maybe_retry(self, task: Task, result: ToolResult) -> None:
        if task.attempts + 1 < task.max_attempts:
            task.attempts += 1
            task.state = TaskState.PENDING
            logger.info("Retry %d/%d for %s on %s",
                        task.attempts, task.max_attempts, task.tool, task.host)
            await self.state.set_task_state(task.task_id, TaskState.PENDING, task.attempts)
            await self._queue.put((task.priority + 5, next(self._seq), task))
        else:
            logger.warning("Task %s (%s) failed permanently: %s",
                           task.task_id, task.tool, result.stderr[:200])
            await self.state.set_task_state(task.task_id, TaskState.FAILED)

    # -- pipeline transitions ---------------------------------------------- #
    async def _on_success(self, task: Task, result: ToolResult) -> None:
        """Fan out follow-on tasks based on what this phase produced."""
        if task.phase is Phase.PROBE and task.tool == "httpx":
            await self._plan_from_httpx(task, result)
        elif task.phase is Phase.VULN and task.tool == "nuclei":
            await self._ingest_nuclei(task, result)

    async def _plan_from_httpx(self, task: Task, result: ToolResult) -> None:
        """Context-aware step: scope Nuclei to the detected stack."""
        for probe in parse_httpx_jsonl(result.stdout):
            url = probe.get("url")
            tech = [str(x).lower() for x in (probe.get("tech") or [])]
            if not url:
                continue
            tags = nuclei_tags_for_tech(tech)
            logger.info("httpx %s -> stack=%s -> nuclei tags=%s",
                        url, tech or "unknown", tags)
            follow = Task(
                scan_id=self._scan_id,
                tool="nuclei",
                target=url,
                phase=Phase.VULN,
                args=["-tags", ",".join(tags)],
                priority=40,
                est_mem_mb=768,           # nuclei is heavier -> bigger governor slot
            )
            await self._enqueue(follow)

    async def _ingest_nuclei(self, task: Task, result: ToolResult) -> None:
        """Turn Nuclei JSONL into Findings, then AI-triage the serious ones."""
        for item in parse_nuclei_jsonl(result.stdout):
            finding = Finding(
                scan_id=self._scan_id,
                task_id=task.task_id,
                tool="nuclei",
                target=item.get("matched_at") or task.target,
                name=item["name"],
                severity=item["severity"],
                raw=item["raw"],
            )
            await self.state.add_finding(finding)
            if finding.severity.rank >= Severity.HIGH.rank:
                await self._triage_and_notify(finding, context={"tech": task.args})

    async def _triage_and_notify(self, finding: Finding, context: dict) -> None:
        verdict = await self.triage.triage_finding(finding, context)
        finding = self.triage.apply_verdict(finding, verdict)
        await self.state.add_finding(finding)

        if (
            verdict.is_true_positive
            and verdict.confidence >= self.cfg.ai.min_confidence_to_report
            and finding.severity.rank >= Severity.HIGH.rank
            and self._notify is not None
        ):
            try:
                await self._notify(finding)
                await self.state.mark_notified(finding.finding_id)
            except Exception:  # noqa: BLE001
                logger.exception("Notification failed for %s", finding.finding_id)

    # -- signals ------------------------------------------------------------ #
    def _install_signal_handlers(self) -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            with contextlib.suppress(NotImplementedError):  # Windows
                loop.add_signal_handler(sig, self._request_shutdown, sig)

    def _request_shutdown(self, sig: signal.Signals) -> None:
        if not self._shutdown.is_set():
            logger.warning("Signal %s received — draining and persisting state...",
                           sig.name)
            self._shutdown.set()


def _first_status(stdout: str) -> Optional[int]:
    """Best-effort HTTP status extraction from httpx-style JSONL for WAF checks."""
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                obj = json.loads(line)
                sc = obj.get("status_code") or obj.get("status-code")
                if isinstance(sc, int):
                    return sc
            except json.JSONDecodeError:
                continue
    return None
