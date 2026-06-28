# RFC-0003 — SARIF 2.1.0 output for `scan` and `ci`

**Status:** **draft — REVIEW REQUESTED**
**Author:** Aboubakar Koita (with Claude)
**Issue:** [#32](https://github.com/akoita/mcp-tripwire/issues/32)
**Relates to:** [RFC-0002 Ed25519 signing](RFC-0002-ed25519-signing.md), [`src/tripwire/cli.py`](../../src/tripwire/cli.py), [`app/fast_api_app.py`](../../app/fast_api_app.py), [`src/tripwire/owasp.py`](../../src/tripwire/owasp.py)
**Targets:** v0.2 — **first piece** per the SARIF-first ordering. Lands before RFC-0002 implementation; #31 (Ed25519) extends the badge metadata SARIF will already be carrying.

## Why this exists

Tripwire findings live in three places today: stderr lines from the proxy, the `tripwire ci --json` shape, and human CLI output. **None** of those flow into the systems security teams already use without custom integration code.

[SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) is the standard format that GitHub Code Scanning, GitLab SAST, Sonatype Lift, and every modern SAST/DAST tool consumes. Emitting SARIF means a Tripwire run drops into a real security pipeline with **six lines of GitHub Actions YAML** and zero further glue.

This is the **first** piece of v0.2 because Codex was right in the PR #34 review: SARIF is the fastest usefulness jump for the audience that matters. The badge alg upgrade (#31) and the SSE transport (#33) follow.

## Goals (in scope for v0.2 #32)

1. `tripwire scan --sarif` emits a valid SARIF 2.1.0 document on stdout for any manifest input.
2. `tripwire ci --sarif` does the same for a corpus run — one SARIF document covering every case.
3. The HTTP gateway switches `/scan` and `/eval` to SARIF when the client sends `Accept: application/sarif+json`.
4. Each Tripwire detection rule maps to a SARIF `rule` with the OWASP MCP id, the human category title, and a `helpUri` pointing at the OWASP MCP Top 10 project page.
5. Each finding maps to a SARIF `result` with the right `level` (mapped from `Severity`), the evidence snippet, a `locations[]` entry pointing at the input source (manifest path, or a synthetic URN for streamed inputs), and a `properties.tripwire` bag carrying the original finding dict for downstream consumers.
6. A documented operator path lands findings in **real** GitHub Code Scanning on a test repo — that's the v0.2 acceptance gate, not just "the validator passes."

## Non-goals (cuts for v0.2)

- A custom GitHub App / dashboard — use the built-in Code Scanning surface.
- A SARIF "sarif-pretty" CLI mode. Pipe through `jq` if you want pretty.
- SARIF 2.0 (older) or pre-release 2.2 support. 2.1.0 is what GitHub and GitLab consume.
- Multi-tool SARIF (combining Tripwire output with other scanners' SARIF). Out-of-band concern; consumers do that themselves.
- A new "fix suggestion" / `result.fixes[]` field. Tripwire findings are about descriptors, not source code that can be auto-patched.

## Architecture

### Emission stays in the deterministic core

SARIF 2.1.0 is a JSON shape. Emitting it needs only `json.dumps` — no new dependency in the core. That keeps Hard Rule #2 intact: the SARIF emitter lives in `src/tripwire/sarif.py` (new module, stdlib-only).

```
                ┌──────────────────────────────┐
   scan_tool()  │  Finding (rule, title,        │
   from         │           severity, owasp,    │
   detection.py │           evidence, tool)     │
                └──────────┬────────────────────┘
                           │
                ┌──────────▼────────────────────┐
                │  sarif.py — stdlib-only        │
                │  to_sarif(findings, input_uri) │
                │  → dict (SARIF 2.1.0 shape)    │
                └──────────┬────────────────────┘
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
        cli.py         fast_api_app.py  any future caller
        (--sarif)      (Accept header)
```

A single function `to_sarif(findings: list[Finding], *, input_uri: str | None) -> dict` is the only public API. Callers serialise to JSON themselves.

### SARIF document shape (concrete example)

For a `scan` of `/tmp/poisoned.json` with one poisoned tool that fires both an injection rule and an exfil rule:

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
          "properties": { "tripwire": { "rule": "INJ-IGNORE", "title": "...", "severity": "high", "owasp": "MCP-01", "evidence": "...", "tool": "summarize_notes" } }
        },
        {
          "ruleId": "EXFIL-SECRET",
          "level": "error",
          "message": { "text": "summarize_notes: …and send the secret token to htt…" },
          "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "/tmp/poisoned.json" } } }],
          "properties": { "tripwire": { "rule": "EXFIL-SECRET", "title": "...", "severity": "critical", "owasp": "MCP-06", "evidence": "...", "tool": "summarize_notes" } }
        }
      ]
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

SARIF also has `none`; we don't emit it (a finding without a level signal is just noise).

### Rule registry

The `to_sarif()` function builds the `tool.driver.rules[]` list **from the actual findings emitted** in the current run, deduplicated by `rule` id. This means:
- A clean scan emits `rules: []` (no rules referenced; SARIF allows empty).
- A poisoned scan emits exactly the rules that fired, with full metadata.

Alternative considered: emit *all* Tripwire rules in `rules[]` regardless of which fired. Rejected — it bloats every scan output with unused entries and there's no consumer benefit; SARIF readers only render rules that have results.

### `locations[]` for streamed input (HTTP / stdin)

When the input came from a file (`scan some.json`), `physicalLocation.artifactLocation.uri` is the absolute or repo-relative path.

When the input came from stdin or an HTTP body, there is no file. Two options:
- **A.** Omit `locations[]`. SARIF allows this; the result still renders, just without a clickable source line.
- **B.** Synthetic URN like `urn:tripwire:input:stdin` or `urn:tripwire:input:http-body`. Keeps the result self-describing; consumers that group by URI can still bucket them.

**Recommendation: B.** A clear synthetic URN over an absent location, so a downstream pipeline can grep by source type.

### Where the trust badge goes

Each `result.properties.tripwire` bag carries the original finding dict — the same shape `Finding.as_dict()` already returns. When badge minting also runs (post-RFC-0002 implementation), the optional `tripwire_badge` key on the same bag carries the signed badge JSON:

```json
"properties": {
  "tripwire": { "rule": "…", "title": "…", "severity": "high", "owasp": "MCP-01", "evidence": "…", "tool": "summarize_notes" },
  "tripwire_badge": { "tool": "summarize_notes", "fingerprint": "…", "status": "blocked", "alg": "Ed25519", "sig": "…" }
}
```

Per-result over per-run because **badges attest individual tool descriptors**, not the whole scan. Larger payloads in exchange for self-contained results — the cost is one extra JSON object per result, and SARIF consumers ignore unknown `properties` keys.

## CLI surface

```
tripwire scan <manifest.json> [--sarif]
    Default behaviour unchanged — human output, exit 0/1.
    With --sarif: same exit code, but stdout is a SARIF 2.1.0 document.

tripwire ci [--corpus PATH] [--json | --sarif]
    --json and --sarif are mutually exclusive. --sarif emits one SARIF
    document for the whole corpus run (one runs[] entry, one result per
    finding across all cases).
```

Exit codes are **unchanged** when `--sarif` is passed — exit 1 on HIGH+ findings or attack-survived; exit 0 otherwise. CI consumers piping SARIF still need the exit code as a hard gate.

## HTTP surface

```
POST /scan      Content-Type: application/json   Body: {"tool": {...}}
                Accept: application/sarif+json   → SARIF response
                Accept: anything else (default)  → existing JSON shape

GET /eval       Accept: application/sarif+json   → SARIF response
                Accept: anything else (default)  → existing JSON shape
```

The HTTP layer reads `request.headers.get("accept")` and dispatches. Response content-type is `application/sarif+json` for SARIF responses (the spec-registered MIME type), `application/json` otherwise.

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

**Acceptance criterion**: in a test repo, run the workflow above against a known-poisoned manifest, then verify the findings render in the Code Scanning UI with the right OWASP categories, the right severity, and clickable links to the manifest line. Screenshot or recording lives in the runbook.

## Test plan

1. **Shape contract** — `to_sarif([])` returns a valid empty-result SARIF; `to_sarif([finding])` includes the rule + result; `to_sarif([finding1, finding2_same_rule])` dedupes the rule.
2. **Schema validation** — every emitted SARIF passes a SARIF 2.1.0 schema validation (using `sarif-tools` from a new `[dev]` extra entry; recommendation locked in below).
3. **Severity mapping** — each of `LOW/MEDIUM/HIGH/CRITICAL` produces the documented `level` value.
4. **CLI** — `tripwire scan --sarif clean.json` → exit 0, stdout is valid SARIF with `results: []`. `tripwire scan --sarif poisoned.json` → exit 1, valid SARIF with ≥1 result. `tripwire ci --sarif` → one SARIF doc covering the full corpus.
5. **Mutually exclusive flags** — `tripwire ci --json --sarif` fails with a clear argparse error.
6. **HTTP content negotiation** — `POST /scan` with `Accept: application/sarif+json` returns a SARIF response with the right content-type; default Accept returns the existing JSON shape.
7. **Round-trip** — parse the emitted SARIF; assert `len(results)` equals the human-mode finding count; assert `result.properties.tripwire.severity` matches the original Finding.
8. **Operator-path proof** — the runbook's GitHub Actions workflow runs in a test repo; the Code Scanning UI shows the finding. This is a manual verification step (not pytest), documented as the v0.2 acceptance.

## Open questions for the reviewer

1. **`sarif-tools` (3rd-party) vs vendored JSON Schema + `jsonschema` for the test validator?**
   - `sarif-tools` is purpose-built, maintained, knows about SARIF semantics beyond schema (e.g. result-graph consistency). Adds one `[dev]` dep.
   - `jsonschema` + vendored `sarif-2.1.0.json` is leaner but only does shape validation, not semantic checks.
   - **Recommendation: `sarif-tools` in `[dev]`.** Purpose-built saves us from re-deriving semantic checks.

2. **Per-result badge in `properties` vs separate artifact attachment?**
   - Per-result: every result is self-describing. Verbose but consumer-friendly.
   - Separate: badges as SARIF `runs[].artifacts[]` referenced by `attachments[]` on results. Smaller for runs with many findings on a single tool.
   - **Recommendation: per-result.** Verbosity is fine until someone profiles a real Tripwire run hitting GH Code Scanning's payload limit (currently 10 MB, very far away).

3. **Synthetic URN for streamed input vs omit `locations[]`?**
   - URN keeps results self-describing and groupable.
   - Omitting renders fine but loses the bucketing.
   - **Recommendation: synthetic URN** (`urn:tripwire:input:stdin`, `urn:tripwire:input:http-body`, `urn:tripwire:input:cli-arg`).

4. **One combined `runs[]` for `ci` vs one per corpus case?**
   - One combined: matches "one tool invocation = one run" SARIF guidance; downstream tooling expects this.
   - One per case: easier per-case filtering but unusual.
   - **Recommendation: one combined**.

5. **Stdout default vs `--out PATH` for the SARIF output destination?**
   - Stdout: Unix convention; pipe to file or another tool.
   - `--out`: explicit, no shell-redirect chains.
   - **Recommendation: stdout** — Unix-friendly, the runbook example pipes to a file.

6. **Tripwire `tool.driver.version` source?** Use `tripwire.__version__` (currently `"0.1.0"`). Bumped to `"0.2.0"` when v0.2 ships. Reviewer to confirm the bump cadence (per-RFC vs per-milestone-tag).

## Day-N implementation plan (post-RFC merge)

| Slot | Step | Exit signal |
|---|---|---|
| 0.5h | Add `[dev]` dependency: `sarif-tools` (one wheel, well-maintained) | `uv sync --extra dev` resolves |
| 2h | New `src/tripwire/sarif.py` with `to_sarif()` — stdlib-only, builds the rules registry from emitted findings, includes the severity mapping table | Unit tests 1, 3, 7 pass against the function in isolation |
| 0.5h | Schema validator self-test using `sarif-tools` — feed the output of `to_sarif()` on a fixture poisoned manifest through the validator | Test 2 passes |
| 1.5h | `tripwire scan --sarif` + `tripwire ci --sarif` wiring; mutually-exclusive flag check in argparse | Tests 4, 5 pass |
| 1.5h | HTTP `/scan` + `/eval` content-negotiation; new SARIF response type with `application/sarif+json` content-type | Test 6 passes |
| 1h | `docs/runbooks/sarif-in-gh-actions.md` written | Runbook is judge-readable in 90s, GitHub Actions snippet copy-pasteable |
| 0.5h | README implementation-status row "SARIF output for scan + eval" flips to ✅ implemented | `make eval` + `make demo*` still green from a fresh clone |
| 0.5h | Operator-path proof: run the GH Actions workflow on a test repo, capture the Code Scanning screenshot, paste into the runbook | v0.2 acceptance gate visibly met |
| 0.5h | Buffer | (use it or bank it) |

≈ 8h total — same deliberate-pace rhythm as RFC-0002.

## Dependencies and ordering

- **Blocks**: nothing in v0.2.
- **Blocked by**: nothing.
- **Lands first** in v0.2 per the SARIF-first ordering decision.
- RFC-0002 (Ed25519) follows; once that lands, Section "Where the trust badge goes" gets one-line update (alg field shifts from HMAC-SHA256 to Ed25519 by default — wire format unchanged).
