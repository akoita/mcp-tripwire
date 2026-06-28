"""SARIF emitter tests (RFC-0003).

Schema validation runs against the vendored OASIS schema in
tests/fixtures/sarif-2.1.0-schema.json — skipped when `jsonschema` isn't
installed, so the default `[dev]` venv that has it runs the full suite
and a minimal venv just skips cleanly.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from tripwire.corpus import load_corpus, run_corpus
from tripwire.detection import Finding, Severity
from tripwire.sarif import (
    SARIF_VERSION,
    SarifInput,
    from_corpus_rows,
    to_sarif,
)

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "sarif-2.1.0-schema.json"


def _f(rule: str, owasp: str, severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        rule=rule,
        title=f"{rule} title",
        severity=severity,
        owasp=owasp,
        evidence=f"evidence for {rule}",
        tool="get_weather",
    )


# --- shape contract --------------------------------------------------------


def test_to_sarif_empty_inputs_yields_valid_skeleton():
    doc = to_sarif([])
    assert doc["version"] == SARIF_VERSION
    assert isinstance(doc["runs"], list) and len(doc["runs"]) == 1
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "MCP-Tripwire"
    assert run["tool"]["driver"]["rules"] == []
    assert run["results"] == []


def test_to_sarif_one_finding_creates_one_rule_one_result():
    inp = SarifInput(findings=(_f("INJ-IGNORE", "MCP-01"),), input_uri="/tmp/x.json")
    doc = to_sarif([inp])
    run = doc["runs"][0]
    assert len(run["tool"]["driver"]["rules"]) == 1
    assert run["tool"]["driver"]["rules"][0]["id"] == "INJ-IGNORE"
    assert run["tool"]["driver"]["rules"][0]["properties"]["owasp_mcp"] == "MCP-01"
    assert len(run["results"]) == 1
    assert run["results"][0]["ruleId"] == "INJ-IGNORE"
    assert run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == (
        "/tmp/x.json"
    )


def test_to_sarif_dedupes_rule_across_results():
    inp = SarifInput(
        findings=(
            _f("EXFIL-SECRET", "MCP-06"),
            _f("EXFIL-SECRET", "MCP-06"),
        ),
        input_uri="/tmp/two.json",
    )
    doc = to_sarif([inp])
    run = doc["runs"][0]
    assert len(run["tool"]["driver"]["rules"]) == 1  # deduped
    assert len(run["results"]) == 2  # both fired


def test_to_sarif_per_result_tripwire_props_carry_finding_dict():
    inp = SarifInput(findings=(_f("INJ-IGNORE", "MCP-01"),), input_uri="/tmp/x.json")
    doc = to_sarif([inp])
    props = doc["runs"][0]["results"][0]["properties"]
    assert props["tripwire"]["rule"] == "INJ-IGNORE"
    assert props["tripwire"]["severity"] == "high"


# --- severity mapping ------------------------------------------------------


@pytest.mark.parametrize(
    ("severity", "expected_level"),
    [
        (Severity.CRITICAL, "error"),
        (Severity.HIGH, "error"),
        (Severity.MEDIUM, "warning"),
        (Severity.LOW, "note"),
    ],
)
def test_severity_maps_to_sarif_level(severity: Severity, expected_level: str):
    inp = SarifInput(
        findings=(_f(f"R-{severity.name}", "MCP-01", severity=severity),),
        input_uri="urn:tripwire:input:stdin",
    )
    doc = to_sarif([inp])
    assert doc["runs"][0]["results"][0]["level"] == expected_level


# --- ci-input attribution --------------------------------------------------


def test_ci_inputs_carry_tripwire_case_props_on_results():
    """Per-case attribution — RFC-0003 Codex finding #1."""
    inp = SarifInput(
        findings=(_f("INJ-IGNORE", "MCP-01"),),
        input_uri="urn:tripwire:corpus:a3",
        case_id="a3",
        properties={"category": "instruction-override", "decision_action": "block"},
    )
    doc = to_sarif([inp])
    props = doc["runs"][0]["results"][0]["properties"]
    assert props["tripwire_case"]["id"] == "a3"
    assert props["tripwire_case"]["category"] == "instruction-override"
    assert props["tripwire_case"]["decision_action"] == "block"


def test_from_corpus_rows_includes_drift_case_with_synthetic_finding():
    """End-to-end: run the real corpus, build SarifInputs, the d1 drift case
    must produce a result with ruleId == 'MCP04-DRIFT'."""
    rows = run_corpus(load_corpus()).rows
    inputs = from_corpus_rows(rows)
    doc = to_sarif(inputs)
    rule_ids = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert "MCP04-DRIFT" in rule_ids, (
        f"d1 drift case didn't produce a synthetic MCP04-DRIFT rule. Rule IDs: {rule_ids}"
    )
    drift_results = [r for r in doc["runs"][0]["results"] if r["ruleId"] == "MCP04-DRIFT"]
    assert len(drift_results) == 1
    assert drift_results[0]["properties"]["tripwire_case"]["id"] == "d1"


# --- schema validation (skipif on jsonschema absence) ----------------------


_HAS_JSONSCHEMA = importlib.util.find_spec("jsonschema") is not None


@pytest.mark.skipif(not _HAS_JSONSCHEMA, reason="jsonschema not installed")
def test_to_sarif_output_validates_against_official_schema():
    """Vendored OASIS SARIF 2.1.0 schema validation — catches any field-shape
    drift in our emitter (missing required fields, wrong type, etc.)."""
    import jsonschema

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    # Realistic mixed input: clean, poisoned, ci-style with case_id.
    inputs = [
        SarifInput(findings=(), input_uri="/tmp/clean.json"),
        SarifInput(
            findings=(_f("INJ-IGNORE", "MCP-01"), _f("EXFIL-SECRET", "MCP-06")),
            input_uri="/tmp/poisoned.json",
        ),
        SarifInput(
            findings=(_f("MCP04-DRIFT", "MCP-04"),),
            input_uri="urn:tripwire:corpus:d1",
            case_id="d1",
            properties={"category": "rug-pull-exfil", "decision_action": "quarantine"},
        ),
    ]
    doc = to_sarif(inputs)
    # Will raise jsonschema.ValidationError on any shape regression — assert
    # implicit via no-exception.
    jsonschema.validate(instance=doc, schema=schema)


# --- corpus enrichment (RFC-0003 prerequisite) ----------------------------


def test_from_corpus_rows_raises_on_unknown_severity():
    """Unknown severity strings are a producer bug — must raise rather than
    silently downgrade to MEDIUM and mask a CRITICAL/HIGH finding."""
    bogus_row = {
        "id": "x1",
        "category": "test",
        "expected": "block",
        "action": "block",
        "ok": True,
        "findings": [
            {
                "rule": "BOGUS",
                "title": "bogus",
                "severity": "catastrophic",  # not a real Severity name
                "owasp": "MCP-01",
                "evidence": "...",
                "tool": "t",
            }
        ],
        "source_uri": "urn:tripwire:corpus:x1",
        "drift_from": None,
    }
    with pytest.raises(ValueError, match="unknown severity"):
        from_corpus_rows([bogus_row])


def test_corpus_rows_carry_findings_source_uri_drift_from():
    rows = run_corpus(load_corpus()).rows
    for row in rows:
        assert "findings" in row, f"row {row.get('id')} missing 'findings'"
        assert "source_uri" in row, f"row {row.get('id')} missing 'source_uri'"
        assert "drift_from" in row, f"row {row.get('id')} missing 'drift_from'"
        assert row["source_uri"].startswith("urn:tripwire:corpus:")
        assert isinstance(row["findings"], list)
    # Drift case d1 should have drift_from populated.
    d1 = next(r for r in rows if r["id"] == "d1")
    assert d1["drift_from"] is not None
    # Approval cases should have drift_from == None.
    a1 = next(r for r in rows if r["id"] == "a1")
    assert a1["drift_from"] is None
