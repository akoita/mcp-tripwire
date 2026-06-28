# SARIF output for `scan` and `ci`

> **Status:** ✅ implemented · **Owner:** akoita · **Indexed by:** [docs/features/README.md](README.md)
> **Design:** [RFC-0003 (accepted)](../rfc/RFC-0003-sarif-output.md) · **Closed:** [#32](https://github.com/akoita/mcp-tripwire/issues/32)

## Value (what this gives the security team / CI / auditor)

Findings flow into the systems security teams already use, with **zero integration code**. SARIF 2.1.0 is the format consumed by GitHub Code Scanning, GitLab SAST, Sonatype Lift, and every modern SAST/DAST tool. Six lines of GitHub Actions YAML turn Tripwire into a PR-blocking gate in the Code Scanning UI — annotated findings with OWASP categories, severity, and `helpUri`s pointing at the OWASP MCP Top 10.

This was the first piece of v0.2 by ordering: SARIF is the fastest usefulness jump because it meets security teams where they already work, regardless of which alg Tripwire signs badges with.

## Audience

- **Security team** consuming Tripwire output through their existing SAST pipeline.
- **CI operator** wanting one-line PR gating without writing custom scripts.
- **Downstream auditor** consuming SARIF from sibling teams' Tripwire runs.

## How it works today

| Surface | How |
|---|---|
| CLI | `tripwire scan <manifest.json> --sarif` emits SARIF on stdout. Exit code unchanged (0 clean, 1 on HIGH+). |
| CLI (corpus) | `tripwire ci --sarif` — one combined `runs[]` covering every corpus case with per-case `properties.tripwire_case` attribution. Mutually exclusive with `--json`. |
| HTTP | `POST /scan` with `Accept: application/sarif+json` returns SARIF; default Accept keeps the existing JSON shape. Content-type response header is the spec-registered MIME. Same for `GET /eval`. |
| Python | `from tripwire.sarif import SarifInput, to_sarif, from_corpus_rows` |

## Contract

```python
# src/tripwire/sarif.py
@dataclass(frozen=True)
class SarifInput:
    findings: tuple[Finding, ...]
    input_uri: str               # real path or urn:tripwire:input:*
    case_id: str | None = None   # for corpus / batch attribution
    badge: dict | None = None    # carries signed badge once #31 lands
    properties: dict = {}        # extra context → properties.tripwire_case

def to_sarif(inputs: Iterable[SarifInput], *,
             tool_version: str | None = None) -> dict: ...

def from_corpus_rows(rows: Iterable[dict]) -> list[SarifInput]: ...
```

The SARIF document follows the OASIS 2.1.0 schema. One combined `runs[]`. `tool.driver.rules[]` deduplicated by `rule` id, each carrying the OWASP MCP id + title + a `helpUri` pointing at the OWASP project page. One `result` per finding; severity mapped CRITICAL/HIGH → `error`, MEDIUM → `warning`, LOW → `note`.

### Locations URI policy

| Input source | `artifactLocation.uri` |
|---|---|
| File path (`tripwire scan /tmp/x.json`) | absolute or repo-relative file path |
| stdin | `urn:tripwire:input:stdin` |
| HTTP body (`POST /scan`) | `urn:tripwire:input:http-body` |
| Corpus case (per-case for `ci`) | `urn:tripwire:corpus:<case_id>` |

### Corpus row enrichment (RFC-0003 prerequisite, landed with this feature)

`CorpusResult.rows` gained three fields so the SARIF layer can attribute every result back to its originating case:

- `findings: list[dict]` — scanner output for the decision-driving descriptor.
- `source_uri: str` — `urn:tripwire:corpus:<id>` (one bucket per case in downstream tooling).
- `drift_from: str | None` — the approved fingerprint for drift cases (None otherwise).

For drift cases (where `engine.evaluate_call` catches the rug-pull but `scan_tool` returns nothing), the runner emits a **synthetic `MCP04-DRIFT` Finding** so the SARIF layer always has ≥1 result per caught attack.

The human / `--json` output silently ignores the new fields — backward compatible.

## Verification

- **Unit (emitter):** [`tests/unit/test_sarif.py`](../../tests/unit/test_sarif.py) — 12 tests covering shape contract, severity mapping, per-result attribution, deduped rule registry, corpus-row adapter end-to-end. The vendored OASIS SARIF 2.1.0 schema validates every emitted document (skipped when `jsonschema` not in the `[dev]` venv).
- **Unit (CLI):** [`tests/unit/test_cli.py`](../../tests/unit/test_cli.py) — `scan --sarif` clean/poisoned paths + file-uri attribution; `ci --sarif` attribution + d1 drift case appearing; `--json` / `--sarif` mutually-exclusive flags refused by argparse.
- **Integration (HTTP):** [`tests/integration/test_http_endpoints.py`](../../tests/integration/test_http_endpoints.py) — `Accept: application/sarif+json` flips both `/scan` and `/eval`; default Accept preserves the existing JSON shape; URN is set on HTTP body inputs.
- **Operator path:** [`docs/runbooks/sarif-in-gh-actions.md`](../runbooks/sarif-in-gh-actions.md) — the 6-line GH Actions workflow that uploads to Code Scanning. The v0.2 acceptance gate is satisfied once findings render in the Code Scanning UI on a real test repo (manual verification — screenshot lives in the runbook once recorded).

## Guarantees and limitations

- **Stdlib-only emitter** — `src/tripwire/sarif.py` uses only `json` + project-local imports. Hard Rule #2 intact; no widening needed.
- **Schema-validated in CI** — every PR's tests run the vendored OASIS schema validator (when `jsonschema` is installed); shape regressions fail the build.
- **No line-/column-level annotations** in v0.2 — `Finding` doesn't preserve JSON-path / byte-offset metadata yet. Annotations render at file granularity in Code Scanning. v0.3 polish (would need a `Finding.region` field and a JSON-source parser).
- **No `result.fixes[]`** — Tripwire findings are about descriptors, not patchable source. The `properties.tripwire` bag carries the original finding dict so downstream tooling can render any remediation guidance it has.
- **Per-result badge slot is reserved** — `properties.tripwire_badge` will start carrying signed badges once [Ed25519 (#31)](ed25519-signing.md) lands. The SarifInput.badge field exists today but is `None` in the v0.2 path.
- **`jsonschema` chosen over `sarif-tools`** (deviation from RFC-0003's recommendation) — `sarif-tools` pulled 18 packages including matplotlib + python-docx for chart and Word-doc export of SARIF, features we don't use; `jsonschema` + vendored OASIS schema is 5 deps and does shape validation cleanly. Called out in the implementation PR's body.

## Cross-references

- **Design:** [RFC-0003](../rfc/RFC-0003-sarif-output.md) — full architecture, decisions table, day-N plan that produced this feature.
- **Companion (the badge metadata SARIF will carry):** [signed-trust-badges.md](signed-trust-badges.md), [ed25519-signing.md](ed25519-signing.md).
- **Companion (the corpus that feeds `ci --sarif`):** [attack-corpus-runner.md](attack-corpus-runner.md).
- **Operator runbook:** [docs/runbooks/sarif-in-gh-actions.md](../runbooks/sarif-in-gh-actions.md).
