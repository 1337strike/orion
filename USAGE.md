# Using ORION — start to finish

A practical, honest walkthrough: from a clean machine to reading validated
findings. Read the maturity note first so you know what actually runs today.

> **Authorized use only.** ORION refuses to launch against any host not listed in
> your `scope.json`. Only test assets you own or are explicitly authorized to
> assess (e.g. an in-scope bug-bounty program). This is enforced in code, and
> it's on you to keep it that way.

---

## 0. Maturity note (what works today)

| Area | Status |
|------|--------|
| Recon → probe → context-aware vuln → AI triage pipeline | ✅ works with real binaries |
| Crash-safe SQLite state + resume | ✅ works |
| Resource governor (16 GB aware) + WAF-aware pacing | ✅ works |
| Identifiable request profile (UA/headers) | ✅ works |
| Distributed master/worker + reliability suite | ✅ works (wired programmatically) |
| AI co-analyst (transparent verdicts) | ✅ works (needs an LLM endpoint) |
| Fuzzing (ffuf/dalfox) auto-scheduling, rich `plugins/` parsers | ⚠️ foundational — argv supported, not auto-seeded yet |

So: a real recon-to-triage run works end to end. Deep fuzzing orchestration is
the next build-out.

---

## 1. Prerequisites

- **Arch Linux** (native, VM, or ArchWSL). ORION uses Unix process APIs
  (`os.killpg`) and masscan that don't behave on native Windows.
- Python **3.11+**, Git, and the Go toolchain (the installer handles these).

---

## 2. Install

```bash
git clone https://github.com/1337strike/orion.git
cd orion
chmod +x install.sh && ./install.sh
```

The installer sets up Go tools (subfinder, httpx, nuclei, ffuf, dalfox), masscan,
nuclei-templates, and a Python `.venv`, then prints a ✓/✗ summary. Re-runnable.

Then, in every new shell:

```bash
source ~/.bashrc            # load PATH for the Go tools
cd orion
source .venv/bin/activate   # activate the Python environment
```

Verify:

```bash
which subfinder httpx nuclei
python -m orion.ui.banner
```

---

## 3. Define your scope (required)

```bash
cp scope.example.json scope.json
nano scope.json
```

```json
{
  "authorized_by": "HackerOne: acme (public program)",
  "authorized_at": "2026-07-31",
  "in_scope":  ["acme.com", "*.acme.com"],
  "out_of_scope": ["blog.acme.com", "*.corp.acme.com", "10.0.0.0/8"],
  "allow_private_ranges": false
}
```

Rules: globs (`*.acme.com`) and CIDRs (`10.0.0.0/8`) both work; out-of-scope
always wins; private ranges are refused unless you opt in. `scope.json` is
git-ignored so you never leak targets.

---

## 4. Optional: local AI triage (recommended)

Run the co-analyst fully offline with Ollama:

```bash
# install ollama (Arch): pacman -S ollama  OR the official script
ollama pull llama3.1:8b
ollama serve &            # exposes http://127.0.0.1:11434
```

ORION will use it when you pass `--ai-provider ollama`. Without an LLM, findings
are still recorded — they just won't get an AI verdict.

## 4b. Optional: notifications

```bash
export ORION_DISCORD_WEBHOOK="https://discord.com/api/webhooks/..."
# or Telegram:
export ORION_TELEGRAM_TOKEN="..."
export ORION_TELEGRAM_CHAT="..."
```

You'll only get pinged on **AI-validated High/Critical** findings.

---

## 5. Run your first scan (single node)

```bash
python -m orion.main --target acme.com --scope scope.json --ai-provider ollama
```

Useful flags:

| Flag | Meaning |
|------|---------|
| `--target <domain>` | root domain (must be in scope) |
| `--scope scope.json` | rules-of-engagement file |
| `--ai-provider ollama\|openai\|anthropic` | LLM backend for triage |
| `--resume <scan_id>` | resume an interrupted run |
| `--verbose` | debug logging |
| `--no-banner` | skip the ASCII banner |

---

## 6. What happens under the hood

1. **Recon** — `subfinder` enumerates subdomains; seeds are queued.
2. **Probe** — `httpx` fingerprints live hosts (status, tech stack).
3. **Context-aware planning** — the detected stack picks Nuclei `-tags`
   (React/Node → `javascript,node,express`; never the WordPress corpus).
4. **Vuln** — `nuclei` runs the scoped templates.
5. **Triage** — High/Critical findings go to the AI co-analyst, which returns a
   confidence score, verbatim evidence, and a manual verification step.
6. **Notify** — validated High/Critical fire your webhook.

Throughout: every host passes the **scope guard**, the **memory governor**
(concurrency scaled to free RAM), and the **WAF-aware limiter** (per-host jitter,
auto-slowdown on 429/403).

---

## 7. Watch progress

Logs stream to the console. For more detail add `--verbose`. State is written
live to `~/.orion/orion.db`.

---

## 8. Read the results

Everything persists in SQLite. Query it directly:

```bash
sqlite3 ~/.orion/orion.db
```

```sql
-- all findings, worst first
SELECT severity, name, target, ai_confidence
FROM findings
ORDER BY CASE severity
  WHEN 'critical' THEN 4 WHEN 'high' THEN 3
  WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC;

-- only AI-confirmed high/critical
SELECT name, target, ai_confidence, ai_rationale
FROM findings
WHERE ai_verdict = 1 AND severity IN ('high','critical');

-- discovered hosts / assets
SELECT kind, value FROM assets;

-- scan + task status
SELECT state, COUNT(*) FROM tasks GROUP BY state;
```

---

## 9. Resume an interrupted scan

Interrupt any run with `Ctrl-C` — state is flushed. Grab the `scan_id` from the
logs (or the `scans` table) and continue exactly where it stopped:

```bash
python -m orion.main --target acme.com --scope scope.json --resume <scan_id>
```

In-flight tasks are reset to pending; completed ones are never re-run.

---

## 10. Distributed mode (v2.0)

For large campaigns you split the light **master** (coordination, 16 GB-friendly)
from **workers** (heavy network I/O). Wired programmatically today:

```python
import asyncio
from orion.dist.broker import RedisBroker          # pip install redis; run redis
from orion.dist.dispatcher import MasterDispatcher
from orion.dist.worker import Worker, build_tool_executor
from orion.dist.tasks import DistTask
from orion.net.request_profile import RequestProfileManager

async def master():
    broker = RedisBroker("redis://127.0.0.1:6379/0")
    d = MasterDispatcher(broker)
    tasks = [DistTask(tool="httpx", target="https://acme.com", scan_id="camp1")]
    print(await d.run_until_complete(tasks))

async def worker():
    broker = RedisBroker("redis://127.0.0.1:6379/0")
    profile = RequestProfileManager(engagement_id="camp1")
    await Worker(broker, build_tool_executor(profile)).run()

# run master() on your box; run worker() on each node pointed at the same Redis
```

If a worker dies mid-task, the master's reaper returns the task to the queue —
nothing is lost. (A ready-made `orion-master` / `orion-worker` CLI is the next
convenience layer; not shipped yet.)

---

## 11. Run the test suite

```bash
pip install pytest
pytest tests/ -q          # reliability + profile + co-analyst tests
```

---

## 12. Troubleshooting

| Symptom | Fix |
|---------|-----|
| `binary not found: subfinder` | `source ~/.bashrc`; re-run `./install.sh` |
| Scan refuses to start | target isn't in `scope.json` `in_scope` |
| No AI verdicts | start Ollama (`ollama serve`) and pass `--ai-provider ollama` |
| `masscan` permission error | needs raw sockets: run that phase with `sudo`, or drop masscan |
| Import errors in editor | select the `.venv` interpreter; reload window |

---

## 13. Ground rules

- Only in-scope, authorized targets. The scope guard is a safety net, not a
  substitute for having permission.
- Keep your footprint identifiable (the request profile sends an attributable
  User-Agent) — don't repurpose ORION for stealth against systems you don't own.
- Pace responsibly; the WAF-aware limiter is there so you're a good citizen.
