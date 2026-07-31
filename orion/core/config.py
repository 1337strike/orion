"""
orion.core.config
=================

Single source of truth for runtime configuration.

Two things here are load-bearing for a *responsible* framework and are not
optional niceties:

* ``ScopeConfig`` — Orion refuses to launch a tool against any host that is not
  explicitly in scope (or that matches an out-of-scope rule). Staying in-scope
  is a hard requirement of every bug-bounty program's rules of engagement; the
  guard is enforced centrally so no code path can bypass it.
* ``ResourceConfig`` — the concurrency envelope is *derived from real available
  RAM* (psutil) rather than hard-coded, so the same code behaves on a 16 GB
  laptop and a larger box without edits.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import psutil
except ImportError:  # pragma: no cover - psutil is a hard runtime dep
    psutil = None  # type: ignore


# --------------------------------------------------------------------------- #
# Scope                                                                        #
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class ScopeConfig:
    """
    Rules of engagement. Loaded from a scope file the operator controls.

    ``in_scope`` / ``out_of_scope`` accept glob patterns (``*.example.com``) and
    CIDR ranges (``10.0.0.0/8``). Out-of-scope always wins over in-scope.
    """

    in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    allow_private_ranges: bool = False
    authorized_by: Optional[str] = None      # free-text: program name / ticket
    authorized_at: Optional[str] = None

    def is_authorized(self, host: str) -> bool:
        """Return True only if ``host`` is explicitly permitted."""
        host = host.strip().lower()
        if not host:
            return False

        # Refuse RFC1918 / loopback unless explicitly allowed.
        ip = self._as_ip(host)
        if ip is not None and (ip.is_private or ip.is_loopback):
            if not self.allow_private_ranges:
                return False

        if any(self._match(host, rule, ip) for rule in self.out_of_scope):
            return False
        return any(self._match(host, rule, ip) for rule in self.in_scope)

    @staticmethod
    def _as_ip(host: str) -> Optional[ipaddress._BaseAddress]:
        try:
            return ipaddress.ip_address(host)
        except ValueError:
            return None

    @staticmethod
    def _match(host: str, rule: str, ip: Optional[ipaddress._BaseAddress]) -> bool:
        rule = rule.strip().lower()
        if "/" in rule and ip is not None:      # CIDR rule
            try:
                return ip in ipaddress.ip_network(rule, strict=False)
            except ValueError:
                return False
        return fnmatch.fnmatch(host, rule)

    @classmethod
    def from_file(cls, path: str | os.PathLike[str]) -> "ScopeConfig":
        import json

        data = json.loads(Path(path).read_text())
        return cls(
            in_scope=data.get("in_scope", []),
            out_of_scope=data.get("out_of_scope", []),
            allow_private_ranges=data.get("allow_private_ranges", False),
            authorized_by=data.get("authorized_by"),
            authorized_at=data.get("authorized_at"),
        )


# --------------------------------------------------------------------------- #
# Resource envelope (tuned for 16 GB)                                          #
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class ResourceConfig:
    """
    Derives a safe concurrency envelope from the host's real memory/CPU.

    Defaults reserve headroom for the OS and the LLM (if running Ollama locally,
    a 7B model alone can hold ~5-6 GB resident), so on a 16 GB box Orion will
    not starve the machine.
    """

    reserved_os_gb: float = 3.0              # never allocate into this
    reserved_llm_gb: float = 6.0             # headroom for a local model
    min_free_gb_to_dispatch: float = 1.5     # backpressure threshold
    max_concurrency_cap: int = 24            # absolute ceiling regardless of RAM
    per_task_default_mem_mb: int = 256

    def total_ram_gb(self) -> float:
        if psutil is None:
            return 16.0
        return psutil.virtual_memory().total / (1024 ** 3)

    def available_ram_gb(self) -> float:
        if psutil is None:
            return 8.0
        return psutil.virtual_memory().available / (1024 ** 3)

    def budget_gb(self) -> float:
        """RAM Orion is allowed to schedule work into."""
        return max(1.0, self.total_ram_gb() - self.reserved_os_gb - self.reserved_llm_gb)

    def derived_concurrency(self) -> int:
        """
        Concurrency = min(cap, budget / per-task footprint, cpu-based ceiling).

        On 16 GB: budget ~= 7 GB; at 256 MB/task that is ~28 slots, clamped to
        the CPU-based ceiling and the hard cap.
        """
        budget_mb = self.budget_gb() * 1024
        by_mem = int(budget_mb // self.per_task_default_mem_mb)
        by_cpu = (os.cpu_count() or 4) * 2
        return max(2, min(self.max_concurrency_cap, by_mem, by_cpu))


# --------------------------------------------------------------------------- #
# WAF / rate-limiting                                                          #
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class RateProfile:
    """A timing profile. Ported from HexStrike's RateLimitDetector ladder."""

    name: str
    base_delay_s: float
    jitter_s: float                          # +/- random jitter added per request
    max_concurrency_per_host: int


DEFAULT_PROFILES: dict[str, RateProfile] = {
    "aggressive":   RateProfile("aggressive", 0.05, 0.05, 12),
    "normal":       RateProfile("normal", 0.30, 0.20, 6),
    "conservative": RateProfile("conservative", 1.00, 0.50, 3),
    "stealth":      RateProfile("stealth", 2.50, 1.50, 1),
}


# --------------------------------------------------------------------------- #
# LLM / AI bridge                                                              #
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class AIConfig:
    """
    Provider-agnostic LLM configuration for the triage bridge.

    ``provider`` is one of {"ollama", "openai", "anthropic", "mcp"}:
      * ollama    -> local, private, no data egress (recommended on 16 GB).
      * openai    -> any OpenAI-compatible /v1/chat/completions endpoint.
      * anthropic -> Anthropic Messages API.
      * mcp       -> defer triage to an external MCP host (HexStrike-style).
    """

    provider: str = "ollama"
    base_url: str = "http://127.0.0.1:11434"
    model: str = "llama3.1:8b"
    api_key_env: str = "ORION_LLM_API_KEY"
    request_timeout_s: float = 120.0
    max_log_chars: int = 12_000              # truncate raw logs before sending
    min_confidence_to_report: float = 0.6

    @property
    def api_key(self) -> Optional[str]:
        return os.environ.get(self.api_key_env)


# --------------------------------------------------------------------------- #
# Notifications                                                                #
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class NotifyConfig:
    discord_webhook_env: str = "ORION_DISCORD_WEBHOOK"
    telegram_bot_token_env: str = "ORION_TELEGRAM_TOKEN"
    telegram_chat_id_env: str = "ORION_TELEGRAM_CHAT"
    notify_min_severity: str = "high"        # only ping on high/critical


# --------------------------------------------------------------------------- #
# Top-level config                                                             #
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class OrionConfig:
    work_dir: Path = field(default_factory=lambda: Path.home() / ".orion")
    db_path: Path = field(default_factory=lambda: Path.home() / ".orion" / "orion.db")
    scope: ScopeConfig = field(default_factory=ScopeConfig)
    resources: ResourceConfig = field(default_factory=ResourceConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    notify: NotifyConfig = field(default_factory=NotifyConfig)
    profiles: dict[str, RateProfile] = field(
        default_factory=lambda: dict(DEFAULT_PROFILES)
    )
    default_profile: str = "normal"
    tool_timeout_s: float = 900.0            # hard wall-clock cap per tool

    def ensure_dirs(self) -> None:
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
