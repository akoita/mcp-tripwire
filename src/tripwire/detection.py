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
# OWASP ids follow the official MCP Top 10 (2025); the rule→category rationale
# lives in docs/OWASP_MCP_COVERAGE.md.
_RULES: list[tuple[str, re.Pattern, str, Severity, str]] = [
    (
        "INJ-IGNORE",
        re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions", re.I),
        "Instruction-override phrase in tool metadata",
        Severity.HIGH,
        "MCP06:2025",
    ),
    (
        "INJ-SYSPROMPT",
        re.compile(r"\b(system\s+prompt|developer\s+message)\b", re.I),
        "References the system/developer prompt",
        Severity.MEDIUM,
        "MCP06:2025",
    ),
    (
        "INJ-HIDE",
        re.compile(r"do\s+not\s+(tell|inform|mention\s+to)\s+the\s+user", re.I),
        "Instructs the agent to hide actions from the user",
        Severity.HIGH,
        "MCP06:2025",
    ),
    (
        "EXF-SECRET",
        re.compile(
            r"(exfiltrat\w*|leak|send|upload|post)\b.{0,40}\b"
            r"(secret|token|key|credential|canary)",
            re.I,
        ),
        "Describes exfiltrating secrets/credentials",
        Severity.CRITICAL,
        "MCP01:2025",
    ),
    (
        "EXF-SSHENV",
        re.compile(r"(~/?\.ssh|id_rsa|\.env\b|BEGIN [A-Z ]*PRIVATE KEY)", re.I),
        "References credential material (ssh/env/private key)",
        Severity.CRITICAL,
        "MCP01:2025",
    ),
    (
        "EXF-URL",
        re.compile(r"(curl|wget|http[s]?://)\S*", re.I),
        "Embeds an outbound network call in tool metadata",
        Severity.MEDIUM,
        "MCP06:2025",
    ),
]

# Zero-width / invisible characters used to smuggle hidden instructions.
# Explicit escapes (not literal glyphs) so the rule is readable and robust:
# U+200B ZWSP, U+200C ZWNJ, U+200D ZWJ, U+2060 WORD JOINER, U+FEFF BOM.
_INVISIBLE_CODEPOINTS = frozenset({0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF})
_HOMOGLYPH_SCRIPTS = frozenset({"LATIN", "CYRILLIC", "GREEK"})


def _has_invisible(text: str) -> bool:
    return any(ord(c) in _INVISIBLE_CODEPOINTS for c in text)


# Rule ids for the two structural (non-regex) checks in scan_tool below, named
# so scan_tool() and the registry share one source of truth.
INJ_INVISIBLE = "INJ-INVISIBLE"
SHADOW_HOMOGLYPH = "SHADOW-HOMOGLYPH"

# Canonical registry of every rule id scan_tool() can emit: the regex rules
# (from _RULES) plus the two structural checks. Single source of truth that the
# per-rule matrix test (#61) asserts completeness against, so a new rule can't
# ship without a dedicated test. New structural checks MUST add their id here.
RULE_IDS: tuple[str, ...] = tuple(r[0] for r in _RULES) + (INJ_INVISIBLE, SHADOW_HOMOGLYPH)

_SCHEMA_META_KEYS = frozenset({"$schema", "$id"})


def _scannable_schema(value: object) -> object:
    """Copy a JSON Schema without dialect metadata that is irrelevant to scanning."""
    if isinstance(value, dict):
        return {
            key: _scannable_schema(item)
            for key, item in value.items()
            if key not in _SCHEMA_META_KEYS
        }
    if isinstance(value, list):
        return [_scannable_schema(item) for item in value]
    return value


def _texts(tool: dict) -> list[tuple[str, str]]:
    """(location, text) pairs to scan."""
    out = [("name", str(tool.get("name", ""))), ("description", str(tool.get("description", "")))]
    schema = tool.get("inputSchema")
    if schema is not None:
        out.append(("inputSchema", json.dumps(_scannable_schema(schema), ensure_ascii=False)))
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
                    INJ_INVISIBLE,
                    "Invisible/zero-width characters in metadata",
                    Severity.HIGH,
                    "MCP03:2025",
                    f"{where}: <zero-width chars>",
                    name,
                )
            )
        # Names are identifiers, so separators should not let shadowing hide.
        identifier_like = where == "name"
        if where in {"name", "description"} and _has_intraword_mixed_scripts(
            text, identifier_like=identifier_like
        ):
            findings.append(
                Finding(
                    SHADOW_HOMOGLYPH,
                    "Mixed-script (homoglyph) shadowing in tool metadata",
                    Severity.MEDIUM,
                    "MCP03:2025",
                    f"{where}: {text!r}",
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


def _has_intraword_mixed_scripts(text: str, *, identifier_like: bool = False) -> bool:
    tokens = [_letters_only(text)] if identifier_like else _alpha_tokens(text)
    return any(_token_has_mixed_scripts(token) for token in tokens)


def _alpha_tokens(text: str) -> list[str]:
    tokens = []
    token = []
    for ch in text:
        if ch.isalpha():
            token.append(ch)
        elif token:
            tokens.append("".join(token))
            token = []
    if token:
        tokens.append("".join(token))
    return tokens


def _letters_only(text: str) -> str:
    return "".join(ch for ch in text if ch.isalpha())


def _token_has_mixed_scripts(text: str) -> bool:
    scripts = set()
    for ch in text:
        script = _script(ch)
        if script is not None:
            scripts.add(script)
    return len(scripts) > 1


def _script(ch: str) -> str | None:
    try:
        script = unicodedata.name(ch).split(" ", maxsplit=1)[0]
    except ValueError:
        return None
    if script in _HOMOGLYPH_SCRIPTS:
        return script
    return None
