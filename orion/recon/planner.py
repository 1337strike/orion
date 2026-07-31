"""
orion.recon.planner
==================

Context-aware planning + output parsing.

The planner is what makes Orion *not* fire every Nuclei template at every host.
It ports HexStrike's technology-signature idea: read Httpx's tech fingerprint,
then emit a Nuclei task whose ``-tags`` are scoped to the detected stack. A
React/Node target gets ``javascript,node,express`` templates, not the WordPress
or PHP corpus. This cuts scan time and — more importantly — WAF exposure.

Parsers here are line-oriented because both Httpx and Nuclei emit JSONL
(one JSON object per line) with ``-json``.
"""
from __future__ import annotations

import json
from typing import Any, Iterable

from ..core.models import Severity

# Technology signature -> Nuclei tag set. Extends HexStrike's signature table.
_TECH_TO_TAGS: dict[str, list[str]] = {
    "react":      ["javascript", "node", "exposure"],
    "next.js":    ["javascript", "node", "nextjs", "ssrf"],
    "vue.js":     ["javascript", "exposure"],
    "angular":    ["javascript", "exposure"],
    "express":    ["node", "express", "javascript"],
    "node.js":    ["node", "javascript"],
    "php":        ["php", "lfi", "rce"],
    "wordpress":  ["wordpress", "wp-plugin", "cve"],
    "drupal":     ["drupal", "cve"],
    "joomla":     ["joomla", "cve"],
    "django":     ["python", "django", "debug"],
    "flask":      ["python", "flask", "debug"],
    "tomcat":     ["java", "tomcat", "cve"],
    "spring":     ["java", "spring", "cve", "actuator"],
    "nginx":      ["nginx", "misconfig"],
    "apache":     ["apache", "misconfig"],
    "iis":        ["iis", "windows", "misconfig"],
    "graphql":    ["graphql", "api"],
}

# Tags that are always worth running regardless of detected stack.
_BASELINE_TAGS = ["misconfig", "exposure", "default-login", "takeover"]


def nuclei_tags_for_tech(technologies: Iterable[str]) -> list[str]:
    """
    Map a set of detected technologies to a deduplicated Nuclei tag list.

    Falls back to a conservative baseline (never an empty tag set, which would
    make Nuclei run *everything*) when nothing is recognized.
    """
    tags: list[str] = list(_BASELINE_TAGS)
    for tech in technologies:
        key = tech.strip().lower()
        for sig, mapped in _TECH_TO_TAGS.items():
            if sig in key:
                tags.extend(mapped)
    # Preserve order, drop dups.
    seen: set[str] = set()
    ordered = [t for t in tags if not (t in seen or seen.add(t))]
    return ordered


# --------------------------------------------------------------------------- #
# Parsers                                                                      #
# --------------------------------------------------------------------------- #
def parse_httpx_jsonl(stdout: str) -> list[dict[str, Any]]:
    """
    Parse ``httpx -json`` output into probe records.

    Each record surfaces the live URL, status, and detected ``tech`` list, which
    the planner consumes to scope the follow-on Nuclei run.
    """
    out: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        out.append(
            {
                "url": obj.get("url") or obj.get("input"),
                "status_code": obj.get("status_code") or obj.get("status-code"),
                "title": obj.get("title"),
                "tech": obj.get("tech") or obj.get("technologies") or [],
                "webserver": obj.get("webserver"),
            }
        )
    return out


def parse_nuclei_jsonl(stdout: str) -> list[dict[str, Any]]:
    """Parse ``nuclei -json`` findings into normalized dicts."""
    findings: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = obj.get("info", {})
        sev_raw = str(info.get("severity", "info")).lower()
        try:
            severity = Severity(sev_raw)
        except ValueError:
            severity = Severity.INFO
        findings.append(
            {
                "template_id": obj.get("template-id") or obj.get("templateID"),
                "name": info.get("name", obj.get("template-id", "unknown")),
                "severity": severity,
                "matched_at": obj.get("matched-at") or obj.get("host"),
                "raw": obj,
            }
        )
    return findings


def extract_identities(stdout: str) -> tuple[set[str], set[str]]:
    """
    Pull emails and usernames out of arbitrary recon text for OSINT enrichment.

    Returns ``(emails, usernames)``. Usernames are the local-part of emails plus
    obvious ``@handle`` mentions — a pragmatic seed set the enrichment module
    then validates against a breach API.
    """
    import re

    emails = set(
        re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", stdout)
    )
    usernames = {e.split("@", 1)[0] for e in emails}
    usernames |= set(re.findall(r"(?<![\w])@([A-Za-z0-9_]{3,30})", stdout))
    return emails, usernames
