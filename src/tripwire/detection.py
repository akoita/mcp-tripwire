"""Deterministic detection: schema fingerprinting + tool-poisoning/injection scanning.

This is the load-bearing spine of MCP-Tripwire and is intentionally **stdlib-only**
(Hard Rule #2). Everything here is deterministic so the demo and CI can never flake.

Two responsibilities:
  1. `fingerprint()` — a stable content hash of a tool's schema, so post-approval
     mutation (rug pull) is detectable by comparison.
  2. `scan_tool()` — pattern + structural checks for injection / poisoning markers
     hidden in a tool's name, description, or input schema.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from enum import IntEnum


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return self.name.lower()


@dataclass(frozen=True)
class Finding:
    """A single detection result, tagged to the OWASP MCP Top 10."""

    rule: str
    title: str
    severity: Severity
    owasp: str
    evidence: str
    tool: str = ""

    def as_dict(self) -> dict:
        return {
            "rule": self.rule,
            "title": self.title,
            "severity": str(self.severity),
            "owasp": self.owasp,
            "evidence": self.evidence,
            "tool": self.tool,
        }


# --- Schema fingerprinting -------------------------------------------------

# Only the trust-relevant fields participate in the fingerprint. Cosmetic fields
# (titles, examples) are excluded so benign edits don't trip false rug-pull alarms.
_FINGERPRINT_FIELDS = ("name", "description", "inputSchema")


def canonicalize(tool: dict) -> str:
    """Deterministic JSON projection of the trust-relevant parts of a tool schema."""
    projection = {k: tool.get(k) for k in _FINGERPRINT_FIELDS}
    return json.dumps(projection, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def fingerprint(tool: dict) -> str:
    """SHA-256 hex digest of a tool's canonical schema. Stable across reorderings."""
    return hashlib.sha256(canonicalize(tool).encode("utf-8")).hexdigest()


# --- Injection / poisoning rules ------------------------------------------

# (rule_id, compiled_pattern, title, severity, owasp_id). Patterns are deliberately
# conservative & explainable — the LLM classifier is an additive P1 layer, not this.
_RULES: list[tuple[str, re.Pattern, str, Severity, str]] = [
    (
        "INJ-IGNORE",
        re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions", re.I),
        "Instruction-override phrase in tool metadata",
        Severity.HIGH,
        "MCP-01",
    ),
    (
        "INJ-SYSPROMPT",
        re.compile(r"\b(system\s+prompt|developer\s+message)\b", re.I),
        "References the system/developer prompt",
        Severity.MEDIUM,
        "MCP-01",
    ),
    (
        "INJ-HIDE",
        re.compile(r"do\s+not\s+(tell|inform|mention\s+to)\s+the\s+user", re.I),
        "Instructs the agent to hide actions from the user",
        Severity.HIGH,
        "MCP-01",
    ),
    (
        "EXF-SECRET",
        re.compile(
            r"(exfiltrat|leak|send|upload|post)\b.{0,40}\b" r"(secret|token|key|credential|canary)",
            re.I,
        ),
        "Describes exfiltrating secrets/credentials",
        Severity.CRITICAL,
        "MCP-06",
    ),
    (
        "EXF-SSHENV",
        re.compile(r"(~/?\.ssh|id_rsa|\.env\b|BEGIN [A-Z ]*PRIVATE KEY)", re.I),
        "References credential material (ssh/env/private key)",
        Severity.CRITICAL,
        "MCP-06",
    ),
    (
        "EXF-URL",
        re.compile(r"(curl|wget|fetch|http[s]?://)\S*", re.I),
        "Embeds an outbound network call in tool metadata",
        Severity.MEDIUM,
        "MCP-06",
    ),
]

# Zero-width / invisible characters used to smuggle hidden instructions.
# Explicit escapes (not literal glyphs) so the rule is readable and robust:
# U+200B ZWSP, U+200C ZWNJ, U+200D ZWJ, U+2060 WORD JOINER, U+FEFF BOM.
_INVISIBLE_CODEPOINTS = frozenset({0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF})


def _has_invisible(text: str) -> bool:
    return any(ord(c) in _INVISIBLE_CODEPOINTS for c in text)


def _texts(tool: dict) -> list[tuple[str, str]]:
    """(location, text) pairs to scan."""
    out = [("name", str(tool.get("name", ""))), ("description", str(tool.get("description", "")))]
    schema = tool.get("inputSchema")
    if schema is not None:
        out.append(("inputSchema", json.dumps(schema, ensure_ascii=False)))
    return out


def scan_tool(tool: dict) -> list[Finding]:
    """Return all findings for a single tool descriptor. Empty list == clean."""
    name = str(tool.get("name", "<unnamed>"))
    findings: list[Finding] = []
    for where, text in _texts(tool):
        for rule_id, pat, ftitle, sev, owasp in _RULES:
            m = pat.search(text)
            if m:
                findings.append(
                    Finding(
                        rule_id, ftitle, sev, owasp, f"{where}: …{_snippet(text, m.start())}…", name
                    )
                )
        if _has_invisible(text):
            findings.append(
                Finding(
                    "INJ-INVISIBLE",
                    "Invisible/zero-width characters in metadata",
                    Severity.HIGH,
                    "MCP-01",
                    f"{where}: <zero-width chars>",
                    name,
                )
            )
        # Homoglyph smell: mixed scripts in a tool name (shadowing).
        if where == "name" and _has_mixed_scripts(text):
            findings.append(
                Finding(
                    "SHADOW-HOMOGLYPH",
                    "Mixed-script (homoglyph) tool name",
                    Severity.MEDIUM,
                    "MCP-05",
                    f"name: {text!r}",
                    name,
                )
            )
    return findings


def max_severity(findings: list[Finding]) -> Severity | None:
    return max((f.severity for f in findings), default=None)


def detect_drift(old_fingerprint: str, tool: dict) -> bool:
    """True if the tool's current schema no longer matches its approved fingerprint."""
    return fingerprint(tool) != old_fingerprint


# --- helpers ---------------------------------------------------------------


def _snippet(text: str, at: int, width: int = 32) -> str:
    start = max(0, at - 4)
    return text[start : start + width].replace("\n", " ")


def _has_mixed_scripts(text: str) -> bool:
    scripts = set()
    for ch in text:
        if ch.isalpha():
            try:
                name = unicodedata.name(ch)
            except ValueError:
                continue
            scripts.add(name.split(" ")[0])  # e.g. LATIN, CYRILLIC, GREEK
    return len({s for s in scripts if s in {"LATIN", "CYRILLIC", "GREEK"}}) > 1
