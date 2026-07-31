"""
orion.core.models
=================

Domain models shared across the orchestrator, state store, and AI bridge.

Everything here is intentionally dependency-free (stdlib only) so it can be
imported from any layer without creating import cycles. State transitions for
tasks are explicit enums because they are persisted to SQLite and used to drive
crash-resume logic.
"""
from __future__ import annotations

import enum
import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Optional


# --------------------------------------------------------------------------- #
# Enums                                                                        #
# --------------------------------------------------------------------------- #
class TaskState(str, enum.Enum):
    """Lifecycle of a single tool invocation. Persisted verbatim to SQLite."""

    PENDING = "pending"      # queued, never started
    RUNNING = "running"      # dispatched to a worker (reset -> PENDING on resume)
    DONE = "done"            # completed successfully
    FAILED = "failed"        # exhausted retries
    SKIPPED = "skipped"      # pruned by the planner / scope guard


class ScanState(str, enum.Enum):
    """Lifecycle of an overall scan campaign."""

    CREATED = "created"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


class Severity(str, enum.Enum):
    """Normalized severity ladder. Mirrors Nuclei's taxonomy."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        return order[self.value]


class Phase(str, enum.Enum):
    """Pipeline phase a task belongs to. Drives scheduling priority."""

    RECON = "recon"          # subfinder, masscan
    PROBE = "probe"          # httpx (tech fingerprinting)
    ENRICH = "enrich"        # osint / breach lookups
    FUZZ = "fuzz"            # ffuf, dalfox (WAF-sensitive)
    VULN = "vuln"            # nuclei
    TRIAGE = "triage"        # AI false-positive filtering


# --------------------------------------------------------------------------- #
# Core records                                                                 #
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class Task:
    """
    A single external-tool invocation.

    ``dedup_key`` is a deterministic hash of (tool, target, args). It is the
    primary idempotency mechanism: on resume we never re-enqueue a task whose
    dedup_key already reached DONE.
    """

    scan_id: str
    tool: str
    target: str
    phase: Phase
    args: list[str] = field(default_factory=list)
    priority: int = 100                     # lower = scheduled sooner
    est_mem_mb: int = 256                    # memory hint for the governor
    attempts: int = 0
    max_attempts: int = 2
    state: TaskState = TaskState.PENDING
    task_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    created_at: float = field(default_factory=time.time)
    depends_on: Optional[str] = None         # task_id this one waits on

    @property
    def dedup_key(self) -> str:
        payload = json.dumps(
            {"tool": self.tool, "target": self.target, "args": self.args},
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode()).hexdigest()[:32]

    @property
    def host(self) -> str:
        """Bare host used by the per-host WAF rate limiter."""
        t = self.target
        for scheme in ("https://", "http://"):
            if t.startswith(scheme):
                t = t[len(scheme):]
                break
        return t.split("/", 1)[0].split(":", 1)[0]

    def to_row(self) -> dict[str, Any]:
        row = asdict(self)
        row["phase"] = self.phase.value
        row["state"] = self.state.value
        row["args"] = json.dumps(self.args)
        return row

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> "Task":
        return cls(
            scan_id=row["scan_id"],
            tool=row["tool"],
            target=row["target"],
            phase=Phase(row["phase"]),
            args=json.loads(row["args"]) if row["args"] else [],
            priority=row["priority"],
            est_mem_mb=row["est_mem_mb"],
            attempts=row["attempts"],
            max_attempts=row["max_attempts"],
            state=TaskState(row["state"]),
            task_id=row["task_id"],
            created_at=row["created_at"],
            depends_on=row["depends_on"],
        )


@dataclass(slots=True)
class ToolResult:
    """Raw output captured from an external binary."""

    task_id: str
    tool: str
    returncode: int
    stdout: str
    stderr: str
    duration_s: float
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


@dataclass(slots=True)
class Finding:
    """
    A candidate vulnerability, pre- or post-AI triage.

    ``ai_verdict`` is populated by the triage bridge:
    True  -> AI believes it is a genuine finding,
    False -> AI believes it is a false positive,
    None  -> not yet triaged.
    """

    scan_id: str
    task_id: str
    tool: str
    target: str
    name: str
    severity: Severity
    raw: dict[str, Any]
    finding_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    ai_verdict: Optional[bool] = None
    ai_confidence: Optional[float] = None
    ai_rationale: Optional[str] = None
    suggested_vectors: list[str] = field(default_factory=list)
    notified: bool = False
    created_at: float = field(default_factory=time.time)

    def to_row(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "scan_id": self.scan_id,
            "task_id": self.task_id,
            "tool": self.tool,
            "target": self.target,
            "name": self.name,
            "severity": self.severity.value,
            "raw": json.dumps(self.raw),
            "ai_verdict": None if self.ai_verdict is None else int(self.ai_verdict),
            "ai_confidence": self.ai_confidence,
            "ai_rationale": self.ai_rationale,
            "suggested_vectors": json.dumps(self.suggested_vectors),
            "notified": int(self.notified),
            "created_at": self.created_at,
        }


@dataclass(slots=True)
class Asset:
    """A discovered asset (host, url, or identity) fed back into the pipeline."""

    scan_id: str
    kind: str                # "host" | "url" | "email" | "username"
    value: str
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def dedup_key(self) -> str:
        return hashlib.sha256(f"{self.kind}:{self.value}".encode()).hexdigest()[:32]
