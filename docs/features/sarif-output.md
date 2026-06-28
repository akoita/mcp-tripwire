# SARIF output for `scan` and `ci`

> **Status:** 📝 design-locked · **Owner:** akoita · **Indexed by:** [docs/features/README.md](README.md)
> **Design:** [RFC-0003 (accepted)](../rfc/RFC-0003-sarif-output.md) · **Implementation:** [#32](https://github.com/akoita/mcp-tripwire/issues/32)

## Value (what this gives the agent / operator / security team)

Findings flow into the systems security teams already use, with **zero integration code**. SARIF 2.1.0 is the format consumed by GitHub Code Scanning, GitLab SAST, Sonatype Lift, and every modern SAST/DAST tool.

After this lands, a 6-line GitHub Actions workflow turns Tripwire into a PR-blocking gate in the Code Scanning UI — annotated findings with OWASP categories, severity, and `helpUri`s pointing at the OWASP MCP Top 10.

This is the **first piece** of v0.2 by ordering: SARIF is the fastest usefulness jump because it meets security teams where they already work, regardless of which alg Tripwire signs badges with.

## Audience

- **Security team** consuming Tripwire output through their existing SAST pipeline.
- **CI operator** wanting one-line PR gating without writing custom scripts.
- **Downstream auditor** consuming SARIF from sibling teams' Tripwire runs.

## When this lands

| Surface | What changes |
|---|---|
| `tripwire scan --sarif` | Same exit code; stdout is a SARIF 2.1.0 document. |
| `tripwire ci --sarif` | Mutually exclusive with `--json`; one combined `runs[]` covering every corpus case, with per-case `properties.tripwire_case` attribution. |
| `POST /scan` and `GET /eval` | `Accept: application/sarif+json` switches the response shape; default Accept keeps the existing JSON. |
| `docs/runbooks/sarif-in-gh-actions.md` | New runbook with the 6-line GH Actions snippet. |

## Acceptance gate (the v0.2 operator path)

Per the [v0.2 acceptance criterion](../ROADMAP.md#exit-criteria-for-the-v020-tag): a documented session of `fresh clone → configure a real MCP server → run Tripwire → SARIF in GH Code Scanning → badge verified externally`. The runbook isn't done until findings render in the Code Scanning UI on a real test repo — **validator-passes is necessary but not sufficient**.

## Design highlights (full spec in the RFC)

- **Emitter is stdlib-only.** `src/tripwire/sarif.py` writes SARIF as plain JSON — no third-party dep in the deterministic core. The schema validator (`sarif-tools`) lives in `[dev]` for tests only.
- **`SarifInput` wrapper** so `ci` can pass many corpus cases through one `to_sarif(inputs: list[SarifInput])` call — addresses [Codex round-1 finding #2](../rfc/RFC-0003-sarif-output.md#decisions-table-codex-round-1-calls-folded-in).
- **Corpus row enrichment** is a prerequisite — `CorpusResult.rows` gains `findings`, `source_uri`, `drift_from`. The drift case (`d1`) emits a synthetic `MCP04-DRIFT` Finding so caught rug-pulls show up as SARIF results.
- **Per-result `properties.tripwire`** carries the original finding dict; future `properties.tripwire_badge` slot reserved for post-[Ed25519](ed25519-signing.md) consumption.
- **Severity mapping**: CRITICAL/HIGH → `error` (PR-blocking), MEDIUM → `warning`, LOW → `note`.
- **Location URI policy**: real file path for file scans; `urn:tripwire:input:stdin|http-body|corpus:<id>` for streamed/synthetic inputs.
- **Line-/column-level annotations explicitly deferred to v0.3** — current `Finding` has no JSON-path / byte-offset metadata; adding it is a wider refactor.

The full architecture, severity table, JSON examples, decisions table, and Day-N (~9h) implementation plan are in [RFC-0003](../rfc/RFC-0003-sarif-output.md).

## Status & next step

The Day-N plan inside the RFC is the canonical to-do list. First work item is the corpus row enrichment (the rest depends on it); then the `sarif.py` module; then CLI / HTTP wiring; then the runbook + operator-path acceptance screenshot.

When the implementation PR merges, this page flips to ✅ implemented and the [README implementation-status table](../../README.md#implementation-status) gets a new row.

## Cross-references

- Design: [RFC-0003](../rfc/RFC-0003-sarif-output.md).
- Tracking: [#32](https://github.com/akoita/mcp-tripwire/issues/32), [milestone v0.2.0](https://github.com/akoita/mcp-tripwire/milestone/1).
- Companion (badge metadata SARIF will carry): [signed-trust-badges.md](signed-trust-badges.md), [ed25519-signing.md](ed25519-signing.md).
- Companion (corpus that feeds `ci --sarif`): [attack-corpus-runner.md](attack-corpus-runner.md).
