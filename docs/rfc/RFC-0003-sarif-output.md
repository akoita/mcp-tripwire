# RFC-0003 — SARIF 2.1.0 output for `scan` and `ci`

**Status:** **accepted (v2 — Codex round-2 sign-off, 2026-06-28)**
**Author:** Aboubakar Koita (with Claude)
**Issue:** [#32](https://github.com/akoita/mcp-tripwire/issues/32)
**Relates to:** [RFC-0002 Ed25519 signing](RFC-0002-ed25519-signing.md), [`src/tripwire/cli.py`](../../src/tripwire/cli.py), [`src/tripwire/corpus.py`](../../src/tripwire/corpus.py), [`app/fast_api_app.py`](../../app/fast_api_app.py), [`src/tripwire/owasp.py`](../../src/tripwire/owasp.py)
**Targets:** v0.2 — **first piece** per the SARIF-first ordering. Lands before RFC-0002 implementation; #31 (Ed25519) extends the badge metadata SARIF will already be carrying.

## Why this exists

Tripwire findings live in three places today: stderr lines from the proxy, the `tripwire ci --json` shape, and human CLI output. **None** of those flow into the systems security teams already use without custom integration code.

[SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) is the standard format that GitHub Code Scanning, GitLab SAST, Sonatype Lift, and every modern SAST/DAST tool consumes. Emitting SARIF means a Tripwire run drops into a real security pipeline with **six lines of GitHub Actions YAML** and zero further glue.

This is the **first** piece of v0.2 because Codex was right in the PR #34 review: SARIF is the fastest usefulness jump for the audience that matters. The badge alg upgrade (#31) and the SSE transport (#33) follow.

## Goals (in scope for v0.2 #32)

1. `tripwire scan --sarif` emits a valid SARIF 2.1.0 document on stdout for any manifest input.
2. `tripwire ci --sarif` does the same for a corpus run — one SARIF document covering every case, **with per-case attribution** (case id, source URI, decision action) so a downstream reader can navigate from a SARIF result back to the specific corpus entry that produced it.
3. The HTTP gateway switches `/scan` and `/eval` to SARIF when the client sends `Accept: application/sarif+json`.
4. Each Tripwire detection rule maps to a SARIF `rule` with the OWASP MCP id, the human category title, and a `helpUri` pointing at the OWASP MCP Top 10 project page.
5. Each finding maps to a SARIF `result` with the right `level` (mapped from `Severity`), the evidence snippet, a `locations[]` entry pointing at the input source (manifest path, or a synthetic URN for streamed inputs), and a `properties.tripwire` bag carrying the original finding dict + per-case context for downstream consumers.
6. A documented operator path lands findings in **real** GitHub Code Scanning on a test repo — that's the v0.2 acceptance gate, not just "the validator passes."

## Non-goals (cuts for v0.2)

- **Line-/column-level annotations.** Code Scanning will render Tripwire findings at file granularity. Adding `physicalLocation.region.startLine/startColumn` requires preserving JSON-path / byte-offset metadata from the scanner all the way through `Finding`, which is a wider refactor than this RFC should swallow. Tracked as v0.3 polish in the table below.
- A custom GitHub App / dashboard — use the built-in Code Scanning surface.
- A SARIF "sarif-pretty" CLI mode. Pipe through `jq` if you want pretty.
- SARIF 2.0 (older) or pre-release 2.2 support. 2.1.0 is what GitHub and GitLab consume.
- Multi-tool SARIF (combining Tripwire output with other scanners' SARIF). Out-of-band concern; consumers do that themselves.
- A new "fix suggestion" / `result.fixes[]` field. Tripwire findings are about descriptors, not source code that can be auto-patched.

## Prerequisite — corpus row enrichment

> **This was Codex's #1 finding on v1 of the RFC.** `CorpusResult.rows` today carries only `id / category / expected / action / ok` — no findings, no source URI, and no drift fingerprint for the MCP-04 (rug-pull) cases that fire `evaluate_call` without producing any `scan_tool()` findings.

The implementation PR for #32 MUST extend `CorpusResult.rows` to carry per-case context the SARIF layer can consume. Concretely, each row gains:

- `findings: list[dict]` — the scanner output (`scan_tool(case["tool"]).as_dict()`-style). Empty for drift cases that the scanner doesn't detect.
- `source_uri: str` — for shipped-corpus cases, the URI form `urn:tripwire:corpus:<case_id>` (so each case is its own bucket in Code Scanning); the existing default corpus path `corpus/attacks.jsonl` is recorded once on the `CorpusResult` itself.
- `drift_from: str | None` — for MCP-04 cases (those with `mutate_to`), the approved fingerprint string the engine compared against. Otherwise `None`.

The runner builds a **synthetic drift finding** for any case whose decision was QUARANTINE and whose scanner findings list is empty:

```python
Finding(
    rule="MCP04-DRIFT",
    title="Rug pull — schema drift since approval",
    severity=Severity.HIGH,
    owasp="MCP-04",
    evidence=f"fingerprint mismatch (approved={drift_from[:16]}…, observed={fingerprint(case['mutate_to'])[:16]}…)",
    tool=case["tool"].get("name", "<unnamed>"),
)
```

so the SARIF layer always has at least one `Finding` to map per caught attack, regardless of which engine path fired. The synthetic rule is owned by Tripwire (not a `scan_tool` rule), so it sits in `tool.driver.rules[]` alongside the regular rules whenever the corpus catches a drift case.

The richer rows do **not** change the existing `tripwire ci` human / JSON output shape — both gracefully ignore the new fields. Only the SARIF emitter consumes them.

## Architecture

### Emission stays in the deterministic core

SARIF 2.1.0 is a JSON shape. Emitting it needs only `json.dumps` — no new dependency in the core. That keeps Hard Rule #2 intact: the SARIF emitter lives in `src/tripwire/sarif.py` (new module, stdlib-only). The schema-validator dependency (`sarif-tools`) lives in `[dev]` for tests only.

```
                ┌──────────────────────────────┐
   scan / ci    │  SarifInput (one per logical  │
   pipelines    │   case being reported on)     │
                └──────────┬────────────────────┘
                           │
                ┌──────────▼────────────────────┐
                │  sarif.py — stdlib-only        │
                │  to_sarif(inputs) → dict       │
                │  builds one runs[] entry       │
                │  with all results              │
                └──────────┬────────────────────┘
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
        cli.py         fast_api_app.py  any future caller
        (--sarif)      (Accept header)
```

### Public API — `SarifInput` wrapper

> **This was Codex's #2 finding on v1 of the RFC.** `to_sarif(findings, input_uri)` was too narrow for `ci`, where N corpus cases each have their own URI, their own case id, and their own (eventual) badge. The signature now takes a list of input records.

```python
# src/tripwire/sarif.py
from dataclasses import dataclass, field

@dataclass(frozen=True)
class SarifInput:
    """One logical 'thing we ran the scanner against' — a manifest, a single
    tool descriptor, or a single corpus case. The SARIF emitter produces one
    `result` per finding inside the input, all attributed back to this record.
    """
    findings: list[Finding]
    input_uri: str                       # absolute path, urn:tripwire:..., or http URL
    case_id: str | None = None           # corpus case id, or None for ad-hoc scans
    badge: dict | None = None            # signed trust badge (post-RFC-0002 impl)
    properties: dict = field(default_factory=dict)  # arbitrary extra context

def to_sarif(
    inputs: list[SarifInput],
    *,
    tool_version: str | None = None,     # defaults to tripwire.__version__
) -> dict:
    """Emit one SARIF 2.1.0 document with one runs[] covering every input."""
```

Callers wrap their own findings into one or more `SarifInput`s, then call `to_sarif`. They serialise the returned dict themselves (stdout, file, HTTP body).

### SARIF document shape (concrete `scan` example)

For `tripwire scan --sarif /tmp/poisoned.json` with one poisoned tool that fires both an injection rule and an exfil rule:

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "MCP-Tripwire",
          "version": "0.2.0",
          "organization": "akoita",
          "informationUri": "https://github.com/akoita/mcp-tripwire",
          "rules": [
            {
              "id": "INJ-IGNORE",
              "name": "Instruction-override phrase in tool metadata",
              "shortDescription": { "text": "Instruction-override phrase in tool metadata" },
              "fullDescription": { "text": "Detects 'ignore previous instructions'-class hijack phrases in an MCP tool descriptor. Mapped to OWASP MCP-01 (Prompt / Tool-Description Injection)." },
              "helpUri": "https://owasp.org/www-project-mcp-top-10/",
              "properties": { "owasp_mcp": "MCP-01", "owasp_title": "Prompt / Tool-Description Injection" }
            },
            {
              "id": "EXFIL-SECRET",
              "name": "Describes exfiltrating secrets/credentials",
              "shortDescription": { "text": "Describes exfiltrating secrets/credentials" },
              "fullDescription": { "text": "Detects descriptors that instruct the agent to send secrets out-of-band. Mapped to OWASP MCP-06 (Sensitive Data & Secret Exfiltration)." },
              "helpUri": "https://owasp.org/www-project-mcp-top-10/",
              "properties": { "owasp_mcp": "MCP-06", "owasp_title": "Sensitive Data & Secret Exfiltration" }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "INJ-IGNORE",
          "level": "error",
          "message": { "text": "summarize_notes: …NT: ignore previous instructions…" },
          "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "/tmp/poisoned.json" } } }],
          "properties": {
            "tripwire": { "rule": "INJ-IGNORE", "title": "...", "severity": "high", "owasp": "MCP-01", "evidence": "...", "tool": "summarize_notes" }
          }
        }
      ]
    }
  ]
}
```

### SARIF document shape (concrete `ci` example)

For `tripwire ci --sarif` against the shipped corpus, one combined `runs[]`. Each result carries `properties.tripwire_case = {id, category, decision_action, source_uri}` so a reader navigates result → case:

```json
{
  "results": [
    {
      "ruleId": "EXFIL-SECRET",
      "level": "error",
      "message": { "text": "summarize_text: …send the secret token to http://evil…" },
      "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "urn:tripwire:corpus:a1" } } }],
      "properties": {
        "tripwire": { "rule": "EXFIL-SECRET", "title": "...", "severity": "critical", "owasp": "MCP-06", "evidence": "...", "tool": "summarize_text" },
        "tripwire_case": { "id": "a1", "category": "secret-exfiltration", "decision_action": "block", "source_uri": "corpus/attacks.jsonl" }
      }
    },
    {
      "ruleId": "MCP04-DRIFT",
      "level": "error",
      "message": { "text": "weather: fingerprint mismatch (approved=a8cbde7f6ea1380a…, observed=412e0c1a8d…)" },
      "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "urn:tripwire:corpus:d1" } } }],
      "properties": {
        "tripwire": { "rule": "MCP04-DRIFT", "title": "Rug pull — schema drift since approval", "severity": "high", "owasp": "MCP-04", "evidence": "fingerprint mismatch (approved=a8cbde7f…, observed=412e0c1a…)", "tool": "weather" },
        "tripwire_case": { "id": "d1", "category": "rug-pull-exfil", "decision_action": "quarantine", "source_uri": "corpus/attacks.jsonl" }
      }
    }
  ]
}
```

### Severity → SARIF level mapping

| Tripwire `Severity` | SARIF `level` | Why |
|---|---|---|
| `CRITICAL` | `error` | Drives PR-blocking annotations in GitHub Code Scanning. |
| `HIGH` | `error` | Same — anything HIGH+ should block. Matches the existing `tripwire ci` exit-1 threshold. |
| `MEDIUM` | `warning` | Visible in the Code Scanning UI but doesn't block by default. |
| `LOW` | `note` | Informational. |

SARIF also has `none`; we don't emit it.

### Rule registry

The `to_sarif()` function builds the `tool.driver.rules[]` list **from the actual rules referenced by emitted findings**, deduplicated. Clean inputs emit `rules: []` and `results: []`. A drift case contributes the synthetic `MCP04-DRIFT` rule to the registry whenever it fires.

### `locations[]` URI policy (Codex sign-off)

| Input source | `artifactLocation.uri` |
|---|---|
| File path (`tripwire scan /tmp/x.json`) | absolute or repo-relative path of the file |
| stdin (`cat manifest.json | tripwire scan -`) | `urn:tripwire:input:stdin` |
| HTTP body (POST /scan) | `urn:tripwire:input:http-body` |
| Corpus case (per-case for `ci`) | `urn:tripwire:corpus:<case_id>` |

Real file URIs render as clickable file-level annotations in GitHub Code Scanning. URNs render as the source label without a clickable link, which is the correct UX for streamed input. **Line/column region info is v0.3 polish** — see Codex finding #3, addressed by §Non-goals.

### Where the trust badge goes

Per-result, on the `properties.tripwire_badge` slot (added when RFC-0002 implementation lands). The `SarifInput.badge` field exists in v0.2 but is `None` until #31 ships; emitter writes it through unchanged.

## CLI surface

```
tripwire scan <manifest.json> [--sarif]
    Default unchanged — human output, exit 0/1.
    With --sarif: same exit code, but stdout is a SARIF 2.1.0 document.

tripwire ci [--corpus PATH] [--json | --sarif]
    --json and --sarif are mutually exclusive. --sarif emits one SARIF
    document for the whole corpus run with per-case attribution.
```

Exit codes are **unchanged** when `--sarif` is passed.

## HTTP surface

```
POST /scan      Content-Type: application/json   Body: {"tool": {...}}
                Accept: application/sarif+json   → SARIF response
                Accept: anything else (default)  → existing JSON shape

GET /eval       Accept: application/sarif+json   → SARIF response
                Accept: anything else (default)  → existing JSON shape
```

Response content-type is `application/sarif+json` for SARIF responses (the spec-registered MIME type), `application/json` otherwise.

## Operator path (the v0.2 acceptance gate)

`docs/runbooks/sarif-in-gh-actions.md` (new) walks through running Tripwire in a GitHub Actions job and uploading findings to Code Scanning:

```yaml
- name: Scan MCP tool manifest with Tripwire
  run: |
    pip install mcp-tripwire
    tripwire scan ./tools.json --sarif > tripwire.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: tripwire.sarif
    category: tripwire
```

The runbook documents:
- What permissions the workflow needs (`security-events: write`).
- How to read the findings in the Security tab.
- How to gate a PR on no-new-Tripwire-findings using Code Scanning rules.
- How to combine multiple Tripwire runs (one per server) into one upload.

**Acceptance criterion (revised after Codex finding #3):** in a test repo, run the workflow above against a known-poisoned manifest, then verify the findings render in the Code Scanning UI **at file granularity** with the right OWASP categories, the right severity, and a clickable link to the manifest file. Screenshot or recording lives in the runbook. Line-/column-level navigation is explicitly deferred to v0.3.

## Decisions table (Codex round-1 calls folded in)

| # | Decision | Rationale |
|---|---|---|
| 1 | `sarif-tools` **pinned** in `[dev]` only | Schema-aware validation in tests; the emitter itself stays stdlib-only. |
| 2 | **Per-result** `tripwire_badge` (not separate artifact attachment) | Self-describing results; payload size not yet a concern. |
| 3 | **Synthetic URN** for stdin/HTTP body / corpus cases; **real file URI** for file-path scans | Real URI renders as clickable file-level annotation; URN keeps streamed/synthetic input groupable. |
| 4 | **One combined `runs[]`** for `ci` — with per-result `tripwire_case` context (new) | Matches "one tool invocation = one run" SARIF guidance; the per-result context (Codex finding #1) keeps each result navigable back to its corpus case. |
| 5 | **Stdout** is the SARIF output destination | Unix-friendly; runbook example pipes to file. |
| 6 | Version source = `tripwire.__version__`; bumps at **milestone-tag time**, not per RFC | Stable cadence; current value `0.1.0`, will be `0.2.0` at the v0.2.0 tag. |

All previously-open questions resolved.

## Test plan

1. **Shape contract** — `to_sarif([])` returns a valid empty-result SARIF; `to_sarif([SarifInput([finding], uri="/x")])` includes the rule + result; two inputs that share a rule dedupe it.
2. **Schema validation** — every emitted SARIF passes a SARIF 2.1.0 schema validation via `sarif-tools` (new `[dev]` dep, pinned).
3. **Severity mapping** — each of `LOW/MEDIUM/HIGH/CRITICAL` produces the documented `level` value.
4. **CLI scan** — `tripwire scan --sarif clean.json` → exit 0, valid SARIF with `results: []`. `tripwire scan --sarif poisoned.json` → exit 1, valid SARIF with ≥1 result whose `artifactLocation.uri` is the file path.
5. **CLI ci** — `tripwire ci --sarif` → one SARIF doc; each result has `properties.tripwire_case.id` matching the producing corpus case; the d1 (drift) case produces a result with `ruleId == "MCP04-DRIFT"` and the synthetic finding's evidence.
6. **Mutually exclusive flags** — `tripwire ci --json --sarif` fails with a clear argparse error.
7. **HTTP content negotiation** — `POST /scan` with `Accept: application/sarif+json` returns a SARIF response with the right content-type; default Accept returns the existing JSON shape.
8. **Round-trip** — parse the emitted SARIF; assert `len(results)` equals the human-mode finding count (plus synthetic drift findings for any d-case in `ci`); assert each `result.properties.tripwire.severity` matches its source Finding.
9. **Corpus enrichment** — `run_corpus(...).rows[i]` now carries `findings`, `source_uri`, and `drift_from` (None except for d-cases). Tests for `--json` mode confirm the new fields are present but the human-mode output is unchanged.
10. **Operator-path proof** — the runbook's GitHub Actions workflow runs in a test repo; the Code Scanning UI shows the finding at file granularity. Manual verification step; screenshot in the runbook.

## Day-N implementation plan (post-RFC merge)

| Slot | Step | Exit signal |
|---|---|---|
| 0.5h | Add `[dev]` dependency: `sarif-tools` (pinned to a specific minor) | `uv sync --extra dev` resolves |
| 1.5h | Extend `CorpusResult.rows` with `findings`, `source_uri`, `drift_from`; emit synthetic `MCP04-DRIFT` Finding for quarantined cases with no scanner findings | Test 9 passes; existing `--json` callers still work |
| 2h | New `src/tripwire/sarif.py` with `SarifInput` + `to_sarif()` — stdlib-only, builds rules registry from the inputs, severity mapping, URI policy | Unit tests 1, 3, 8 pass against the function in isolation |
| 0.5h | Schema validator self-test using `sarif-tools` on fixture outputs | Test 2 passes |
| 1h | `tripwire scan --sarif` + `tripwire ci --sarif` wiring; mutually-exclusive flag check in argparse | Tests 4, 5, 6 pass |
| 1h | HTTP `/scan` + `/eval` content-negotiation; `application/sarif+json` content-type | Test 7 passes |
| 1h | `docs/runbooks/sarif-in-gh-actions.md` written | Runbook is judge-readable in 90s, GitHub Actions snippet copy-pasteable |
| 0.5h | README implementation-status row "SARIF output for scan + eval" flips to ✅ implemented | `make eval` + `make demo*` still green from a fresh clone |
| 0.5h | Operator-path proof: run the GH Actions workflow on a test repo, capture the Code Scanning screenshot, paste into the runbook | v0.2 acceptance gate visibly met |
| 0.5h | Buffer | (use it or bank it) |

≈ 9h total (up 1h from v1 to absorb the corpus enrichment).

## Dependencies and ordering

- **Blocks**: nothing in v0.2.
- **Blocked by**: nothing.
- **Lands first** in v0.2 per the SARIF-first ordering decision.
- RFC-0002 (Ed25519) follows; once that lands, §"Where the trust badge goes" is a no-op update (the `SarifInput.badge` slot already exists; the emitter writes whatever shape the badge happens to be).
- v0.3 polish: line-/column-level regions for `physicalLocation`. Requires `scan_tool()` to preserve byte offsets, which is a wider Finding refactor.
