"""
orion.core.state
================

Async, crash-safe state store backed by SQLite (via ``aiosqlite``).

Design goals
------------
* **Resume-exactly-where-you-left-off.** Every task transition is persisted
  synchronously with the in-memory change. On startup ``recover_interrupted``
  flips any ``RUNNING`` task (a worker that died mid-flight) back to ``PENDING``
  and returns the full set of not-yet-DONE tasks so the orchestrator can re-fill
  its queue.
* **Idempotency.** ``dedup_key`` has a UNIQUE index; enqueuing a task that has
  already completed is a cheap no-op.
* **WAL mode** so a crash never corrupts the DB and reads don't block writes.

The store is deliberately thin: it holds no business logic, only durable state.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

import aiosqlite

from .models import Asset, Finding, ScanState, Task, TaskState

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id     TEXT PRIMARY KEY,
    target      TEXT NOT NULL,
    state       TEXT NOT NULL,
    config      TEXT,
    created_at  REAL NOT NULL,
    updated_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS tasks (
    task_id      TEXT PRIMARY KEY,
    scan_id      TEXT NOT NULL,
    dedup_key    TEXT NOT NULL,
    tool         TEXT NOT NULL,
    target       TEXT NOT NULL,
    phase        TEXT NOT NULL,
    args         TEXT,
    priority     INTEGER NOT NULL,
    est_mem_mb   INTEGER NOT NULL,
    attempts     INTEGER NOT NULL,
    max_attempts INTEGER NOT NULL,
    state        TEXT NOT NULL,
    depends_on   TEXT,
    created_at   REAL NOT NULL,
    UNIQUE(scan_id, dedup_key)
);

CREATE TABLE IF NOT EXISTS results (
    task_id     TEXT PRIMARY KEY,
    tool        TEXT NOT NULL,
    returncode  INTEGER,
    stdout      TEXT,
    stderr      TEXT,
    duration_s  REAL,
    timed_out   INTEGER,
    created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id        TEXT PRIMARY KEY,
    scan_id           TEXT NOT NULL,
    task_id           TEXT,
    tool              TEXT,
    target            TEXT,
    name              TEXT,
    severity          TEXT,
    raw               TEXT,
    ai_verdict        INTEGER,
    ai_confidence     REAL,
    ai_rationale      TEXT,
    suggested_vectors TEXT,
    notified          INTEGER,
    created_at        REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS assets (
    dedup_key  TEXT NOT NULL,
    scan_id    TEXT NOT NULL,
    kind       TEXT NOT NULL,
    value      TEXT NOT NULL,
    meta       TEXT,
    created_at REAL NOT NULL,
    PRIMARY KEY (scan_id, dedup_key)
);

CREATE INDEX IF NOT EXISTS idx_tasks_scan_state ON tasks(scan_id, state);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
"""


class StateStore:
    """Durable, async state for scans, tasks, results, findings, and assets."""

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = str(db_path)
        self._db: Optional[aiosqlite.Connection] = None

    # -- lifecycle ---------------------------------------------------------- #
    async def open(self) -> "StateStore":
        self._db = await aiosqlite.connect(self._db_path)
        self._db.row_factory = aiosqlite.Row
        await self._db.execute("PRAGMA journal_mode=WAL;")
        await self._db.execute("PRAGMA synchronous=NORMAL;")
        await self._db.executescript(_SCHEMA)
        await self._db.commit()
        return self

    async def close(self) -> None:
        if self._db is not None:
            await self._db.commit()
            await self._db.close()
            self._db = None

    async def __aenter__(self) -> "StateStore":
        return await self.open()

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    @property
    def db(self) -> aiosqlite.Connection:
        if self._db is None:
            raise RuntimeError("StateStore is not open()'d")
        return self._db

    # -- scans -------------------------------------------------------------- #
    async def create_scan(self, scan_id: str, target: str, config_json: str) -> None:
        now = time.time()
        await self.db.execute(
            "INSERT OR IGNORE INTO scans VALUES (?,?,?,?,?,?)",
            (scan_id, target, ScanState.CREATED.value, config_json, now, now),
        )
        await self.db.commit()

    async def set_scan_state(self, scan_id: str, state: ScanState) -> None:
        await self.db.execute(
            "UPDATE scans SET state=?, updated_at=? WHERE scan_id=?",
            (state.value, time.time(), scan_id),
        )
        await self.db.commit()

    # -- tasks -------------------------------------------------------------- #
    async def add_task(self, task: Task) -> bool:
        """
        Insert a task. Returns False if it already exists (dedup), True if new.
        Never resurrects a completed task.
        """
        row = task.to_row()
        try:
            await self.db.execute(
                """INSERT INTO tasks
                   (task_id, scan_id, dedup_key, tool, target, phase, args,
                    priority, est_mem_mb, attempts, max_attempts, state,
                    depends_on, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    row["task_id"], row["scan_id"], task.dedup_key, row["tool"],
                    row["target"], row["phase"], row["args"], row["priority"],
                    row["est_mem_mb"], row["attempts"], row["max_attempts"],
                    row["state"], row["depends_on"], row["created_at"],
                ),
            )
            await self.db.commit()
            return True
        except aiosqlite.IntegrityError:
            return False  # dedup_key collision -> already tracked

    async def set_task_state(
        self, task_id: str, state: TaskState, attempts: Optional[int] = None
    ) -> None:
        if attempts is None:
            await self.db.execute(
                "UPDATE tasks SET state=? WHERE task_id=?", (state.value, task_id)
            )
        else:
            await self.db.execute(
                "UPDATE tasks SET state=?, attempts=? WHERE task_id=?",
                (state.value, attempts, task_id),
            )
        await self.db.commit()

    async def recover_interrupted(self, scan_id: str) -> list[Task]:
        """
        Crash-resume entry point.

        Any task left ``RUNNING`` when the process died is reset to ``PENDING``.
        Returns all tasks that are not yet ``DONE``/``SKIPPED`` so the
        orchestrator can rebuild its queue.
        """
        await self.db.execute(
            "UPDATE tasks SET state=? WHERE scan_id=? AND state=?",
            (TaskState.PENDING.value, scan_id, TaskState.RUNNING.value),
        )
        await self.db.commit()

        cur = await self.db.execute(
            "SELECT * FROM tasks WHERE scan_id=? AND state IN (?,?) "
            "ORDER BY priority ASC, created_at ASC",
            (scan_id, TaskState.PENDING.value, TaskState.FAILED.value),
        )
        rows = await cur.fetchall()
        return [Task.from_row(dict(r)) for r in rows]

    async def pending_count(self, scan_id: str) -> int:
        cur = await self.db.execute(
            "SELECT COUNT(*) AS n FROM tasks WHERE scan_id=? AND state=?",
            (scan_id, TaskState.PENDING.value),
        )
        row = await cur.fetchone()
        return int(row["n"]) if row else 0

    # -- results ------------------------------------------------------------ #
    async def save_result(
        self, task_id: str, tool: str, returncode: int, stdout: str,
        stderr: str, duration_s: float, timed_out: bool,
    ) -> None:
        await self.db.execute(
            "INSERT OR REPLACE INTO results VALUES (?,?,?,?,?,?,?,?)",
            (task_id, tool, returncode, stdout, stderr, duration_s,
             int(timed_out), time.time()),
        )
        await self.db.commit()

    # -- findings ----------------------------------------------------------- #
    async def add_finding(self, finding: Finding) -> None:
        r = finding.to_row()
        await self.db.execute(
            """INSERT OR REPLACE INTO findings
               (finding_id, scan_id, task_id, tool, target, name, severity,
                raw, ai_verdict, ai_confidence, ai_rationale, suggested_vectors,
                notified, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (r["finding_id"], r["scan_id"], r["task_id"], r["tool"], r["target"],
             r["name"], r["severity"], r["raw"], r["ai_verdict"],
             r["ai_confidence"], r["ai_rationale"], r["suggested_vectors"],
             r["notified"], r["created_at"]),
        )
        await self.db.commit()

    async def mark_notified(self, finding_id: str) -> None:
        await self.db.execute(
            "UPDATE findings SET notified=1 WHERE finding_id=?", (finding_id,)
        )
        await self.db.commit()

    # -- assets ------------------------------------------------------------- #
    async def add_asset(self, asset: Asset) -> bool:
        import json

        try:
            await self.db.execute(
                "INSERT INTO assets VALUES (?,?,?,?,?,?)",
                (asset.dedup_key, asset.scan_id, asset.kind, asset.value,
                 json.dumps(asset.meta), time.time()),
            )
            await self.db.commit()
            return True
        except aiosqlite.IntegrityError:
            return False

    async def assets_of_kind(self, scan_id: str, kind: str) -> list[str]:
        cur = await self.db.execute(
            "SELECT value FROM assets WHERE scan_id=? AND kind=?", (scan_id, kind)
        )
        rows = await cur.fetchall()
        return [r["value"] for r in rows]
