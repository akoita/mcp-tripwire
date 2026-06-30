# `tripwire` CLI — scan / verify / ci

> **Status:** ✅ implemented · **Owner:** akoita · **Indexed by:** [docs/features/README.md](README.md)

## Value (what this gives the agent / LLM / operator)

A scriptable command-line surface for the trust loop:

- **`tripwire scan <manifest.json>`** — read a tool descriptor (or a `{"tools": [...]}` manifest), emit findings grouped by OWASP MCP category, exit 1 on HIGH+ findings so CI can gate on it.
- **`tripwire verify <badge.json>`** — re-check a stored badge. Three distinct exit codes (0 valid / 2 tampered / 3 malformed) so wrapping scripts can tell *"this badge says NO"* from *"you gave me garbage"*.
- **`tripwire ci [--corpus PATH] [--json|--sarif]`** — run the full attack corpus, print the headline (`N/M attacks blocked · 0 FP on 4 clean tools`), exit 1 if anything regressed.

CI pipelines plug it in with one line; humans get readable output; agents get machine-parseable `--json`, and security tools get SARIF via `--sarif`.

## Audience

- **CI** running scan/eval against committed manifests.
- **Operator** doing ad-hoc verification (open a badge, confirm it still validates).
- **LLM agent** shelling out to `tripwire scan --json` to vet a tool before calling it.

## How it works today

The CLI is `src/tripwire/cli.py` (entrypoint registered as `tripwire` in `pyproject.toml`'s `[project.scripts]`). Each subcommand is a thin handler over the deterministic core:

| Subcommand | Calls into | Output mode | Exit code |
|---|---|---|---|
| `scan` | `tripwire.detection.scan_tool` | OWASP-grouped human text (colored if TTY) or SARIF | 0 clean / 1 HIGH+ findings |
| `verify` | `tripwire.attestation.verify_badge` | one-line VALID / TAMPERED / INVALID | 0 / 2 / 3 |
| `ci` | `tripwire.corpus.run_corpus` | per-case ✓/✗ + summary, `--json`, or `--sarif` | 0 pass / 1 fail |

ANSI colors are gated on `_use_color()` — silenced when `NO_COLOR` env is set or stdout isn't a TTY (per [no-color.org](https://no-color.org/)). No new dep; stdlib ANSI only.

`tripwire verify` requires `TRIPWIRE_SIGNING_KEY`; if the env var is missing, the command exits malformed/invalid (`3`) instead of verifying against a placeholder key. `tripwire ci` is measurement-only and uses the inert `ci-only` key unless the env var is provided.

## Contract

```bash
tripwire scan <manifest.json>
# stdout: grouped findings; exit 0 (clean) or 1 (HIGH+ found)

tripwire verify <badge.json>
# stdout: one-line VALID / TAMPERED / INVALID + reason
# exit:   0 valid · 2 signature mismatch · 3 malformed (cannot even check)

tripwire ci [--corpus PATH] [--json]
# default: per-case lines + summary, exit 0/1
# --json:  one JSON document with attacks_total / attacks_blocked /
#          clean_total / false_positives / passed / rows[]
# --sarif: one SARIF 2.1.0 document with findings attributed per corpus case
```

Exit-code constants are exported (`EXIT_OK`, `EXIT_FAIL`, `EXIT_BADGE_VALID`, `EXIT_BADGE_TAMPERED`, `EXIT_BADGE_INVALID`) so callers can `from tripwire.cli import EXIT_BADGE_TAMPERED` instead of hard-coding `2`.

## Surfaces

| Surface | How |
|---|---|
| Installed | `pip install mcp-tripwire` → `tripwire …` on PATH |
| In-repo | `uv run python -m tripwire.cli …` (Makefile demo targets use this form) |
| CI snippet | `tripwire ci --json > result.json` then `jq` / consumer parses |

## Verification

- Unit: [`tests/unit/test_cli.py`](../../tests/unit/test_cli.py) — covers scan (clean / poisoned / NO_COLOR / SARIF), verify (valid / tampered / malformed / missing key), and ci (`--json`, `--sarif`, human mode).
- Manual: `make eval` calls `tripwire.cli.ci` end-to-end.

## Guarantees and limitations

- **Deterministic** — same input, same output, same exit code.
- **Stdlib-only handlers** — no third-party dep in the CLI path. `argparse` only.
- **No stateful session** — `scan` and `verify` are one-shot. Drift detection (which is stateful) lives in the proxy bridge or the corpus runner, not the CLI.
- **No `tripwire key gen` yet** — Ed25519 key-management subcommands land with [#31](https://github.com/akoita/mcp-tripwire/issues/31) per [RFC-0002 §CLI](../rfc/RFC-0002-ed25519-signing.md#cli-surface).
- **`--sarif` emits findings, not clean-run proof.** Fully clean scans produce `results: []`; use `ci --json` when consumers need the complete pass/fail row set.

## Cross-references

- Companions: [descriptor-scanning.md](descriptor-scanning.md), [signed-trust-badges.md](signed-trust-badges.md), [attack-corpus-runner.md](attack-corpus-runner.md).
- Companion: [sarif-output.md](sarif-output.md) documents the SARIF contract for `scan` and `ci`.
