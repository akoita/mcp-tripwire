"""SARIF 2.1.0 emission for Tripwire findings (RFC-0003).

Stdlib-only — emits plain JSON, no third-party dep in the deterministic core.
The schema validator used in tests (`jsonschema`) lives in the `[dev]` extra.

Public API: `SarifInput` (one logical input being reported on) and `to_sarif`
(emits one SARIF document covering many inputs). Callers serialise the dict
themselves (stdout / file / HTTP body).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from . import __version__
from .detection import Finding, Severity
from .owasp import title as owasp_title

SARIF_VERSION = "2.1.0"
# Stable, canonical SARIF 2.1.0 schema URL. Avoid raw.githubusercontent.com/...master/...
# because oasis-tcs may rename the default branch or move the schema file.
SARIF_SCHEMA_URL = "https://json.schemastore.org/sarif-2.1.0.json"
OWASP_MCP_HELP_URI = "https://owasp.org/www-project-mcp-top-10/"

# Severity → SARIF level (RFC-0003 §Severity mapping).
_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}


@dataclass(frozen=True)
class SarifInput:
    """One logical 'thing we ran the scanner against' — a manifest, a single
    tool descriptor, or a corpus case. The emitter produces one SARIF `result`
    per `Finding` inside the input, all attributed back to this record.

    Per RFC-0003:
      findings    list of Finding objects (may be empty for clean inputs)
      input_uri   absolute path, urn:tripwire:..., or http URL
      case_id     corpus case id, or None for ad-hoc scans
      badge       signed trust badge dict (None until RFC-0002 impl lands)
      properties  arbitrary extra context attached as `properties` on results
    """

    findings: tuple[Finding, ...]
    input_uri: str
    case_id: str | None = None
    badge: dict | None = None
    properties: dict[str, Any] = field(default_factory=dict)


def _rule_for(rule_id: str, owasp_id: str, title: str) -> dict:
    """Build the `tool.driver.rules[]` entry for a Tripwire detection rule."""
    owasp_label = owasp_title(owasp_id)
    full = f"Tripwire rule {rule_id}: {title}. Mapped to OWASP {owasp_id} ({owasp_label})."
    return {
        "id": rule_id,
        "name": title,
        "shortDescription": {"text": title},
        "fullDescription": {"text": full},
        "helpUri": OWASP_MCP_HELP_URI,
        "properties": {
            "owasp_mcp": owasp_id,
            "owasp_title": owasp_label,
        },
    }


def _result_for(finding: Finding, inp: SarifInput) -> dict:
    """Build one SARIF `result` from a Finding + its source SarifInput."""
    props: dict[str, Any] = {"tripwire": finding.as_dict()}
    if inp.case_id is not None:
        # Per-case attribution so a downstream reader navigates from a SARIF
        # result back to the originating corpus case (RFC-0003 §"ci" example).
        props["tripwire_case"] = {
            "id": inp.case_id,
            **inp.properties,
        }
    elif inp.properties:
        props["tripwire_context"] = dict(inp.properties)
    if inp.badge is not None:
        props["tripwire_badge"] = inp.badge

    return {
        "ruleId": finding.rule,
        "level": _LEVEL.get(finding.severity, "warning"),
        "message": {"text": f"{finding.tool or '<unknown>'}: {finding.evidence}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": inp.input_uri},
                }
            }
        ],
        "properties": props,
    }


def to_sarif(
    inputs: Iterable[SarifInput],
    *,
    tool_version: str | None = None,
) -> dict:
    """Emit one SARIF 2.1.0 document covering every input.

    One combined `runs[]` entry per call (matches "one tool invocation = one
    run" SARIF guidance). `tool.driver.rules[]` is built from the *actually-
    fired* rules across all inputs, deduplicated by `rule` id.

    Clean inputs (empty `findings`) contribute nothing to `results[]` — SARIF
    conventionally surfaces issues, not scan completions. Downstream readers
    cannot distinguish "case ran and was clean" from "case never ran" from
    the SARIF document alone; combine with `--json` / `CorpusResult.rows` if
    that distinction matters. A fully-clean run yields `rules: []` and
    `results: []`.
    """
    inputs_list: list[SarifInput] = list(inputs)
    results: list[dict] = []
    rules_seen: dict[str, dict] = {}

    for inp in inputs_list:
        for finding in inp.findings:
            results.append(_result_for(finding, inp))
            if finding.rule not in rules_seen:
                rules_seen[finding.rule] = _rule_for(finding.rule, finding.owasp, finding.title)

    version = tool_version or __version__
    return {
        "$schema": SARIF_SCHEMA_URL,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "MCP-Tripwire",
                        "version": version,
                        "organization": "akoita",
                        "informationUri": "https://github.com/akoita/mcp-tripwire",
                        "rules": list(rules_seen.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def from_corpus_rows(rows: Iterable[dict]) -> list[SarifInput]:
    """Adapter: build SarifInputs from `CorpusResult.rows` (RFC-0003 enrichment).

    Each row carries `findings` (list of dicts), `source_uri`, and `id`. The
    per-case `properties` bag mirrors the row's metadata that the SARIF layer
    surfaces under `result.properties.tripwire_case`.
    """
    inputs: list[SarifInput] = []
    for row in rows:
        finding_dicts = row.get("findings") or []
        findings = tuple(
            Finding(
                rule=d["rule"],
                title=d["title"],
                severity=_severity_from_str(d["severity"]),
                owasp=d["owasp"],
                evidence=d["evidence"],
                tool=d.get("tool", ""),
            )
            for d in finding_dicts
        )
        props = {
            "category": row.get("category"),
            "decision_action": row.get("action"),
            "source_uri": row.get("source_uri", "urn:tripwire:corpus:?"),
        }
        if row.get("drift_from"):
            props["drift_from"] = row["drift_from"]
        inputs.append(
            SarifInput(
                findings=findings,
                input_uri=row.get("source_uri", f"urn:tripwire:corpus:{row.get('id', '?')}"),
                case_id=str(row.get("id", "")),
                properties=props,
            )
        )
    return inputs


# Inverse of `Severity.__str__` (which lower-cases the name).
_SEV_BY_STR: dict[str, Severity] = {str(s): s for s in Severity}


def _severity_from_str(s: str) -> Severity:
    """Parse the lowercase severity name produced by `Finding.as_dict()`.

    Strict: any unknown string is a producer bug (corpus.py → sarif.py round-
    trip), so raise rather than silently downgrading to MEDIUM and masking
    a CRITICAL/HIGH finding in downstream SARIF.
    """
    try:
        return _SEV_BY_STR[s]
    except KeyError as exc:
        raise ValueError(
            f"unknown severity string {s!r}; expected one of {sorted(_SEV_BY_STR)}"
        ) from exc


__all__ = ["SARIF_VERSION", "SarifInput", "from_corpus_rows", "to_sarif"]
