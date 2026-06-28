# Runbook — SARIF in GitHub Actions

> Per [RFC-0003](../rfc/RFC-0003-sarif-output.md). Enables the v0.2 operator path: Tripwire findings land in **real** GitHub Code Scanning on a target repo, annotated with OWASP MCP categories, severity, and `helpUri`s. The operator-path proof closes only once a real Code Scanning screenshot is recorded — see the feature page for the manual-verification checkbox.

## The whole thing in six lines of YAML

In any GitHub repo whose CI you want gated by Tripwire:

```yaml
# .github/workflows/tripwire-scan.yml
name: Tripwire scan
on:
  pull_request:
    paths: ['**/tools.json', '**/mcp-tools/**.json']
permissions:
  contents: read
  security-events: write          # required to upload SARIF to Code Scanning
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - run: pip install mcp-tripwire
      - run: tripwire scan ./tools.json --sarif > tripwire.sarif
        continue-on-error: true   # so the upload step still runs on findings
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: tripwire.sarif
          category: tripwire
```

That's it. After the workflow runs:

- Findings appear in the repo's **Security → Code Scanning** tab.
- The Code Scanning tab links each finding to its OWASP MCP category via the `helpUri`.
- Re-running the workflow with a passing manifest auto-dismisses the alerts (Code Scanning closes stale findings).
- Repo admins can gate PRs on no-new-Tripwire-findings via the standard Code Scanning ruleset.

## Permissions

The workflow's `security-events: write` permission is the one non-default knob. Without it, `upload-sarif` fails with `Resource not accessible by integration`. Set it at the job level (above) or at the workflow level — either works.

If your repo uses a fine-grained PAT (instead of `GITHUB_TOKEN`), the PAT needs `security_events: write` on the target repo.

## Reading the results in the UI

In the **Security → Code Scanning** tab, each Tripwire result shows:

- **Rule** — the Tripwire rule that fired (e.g. `INJ-IGNORE`, `EXFIL-SECRET`, `MCP04-DRIFT`).
- **Severity** — Error (HIGH+) / Warning (MEDIUM) / Note (LOW). HIGH+ blocks merges if the repo enables that rule.
- **File** — the `tools.json` path that was scanned.
- **Description** — the rule's full description, mapped to the OWASP MCP Top 10.
- **Help** — clickable link to <https://owasp.org/www-project-mcp-top-10/>.

Each result also carries `properties.tripwire` with the original finding dict (the OWASP id, the rule name, the evidence snippet, the tool name) — visible via the **JSON** view on each alert. Downstream tooling can rehydrate the full Tripwire context from there.

## Gating PRs on no-new findings

Use the repo's built-in **Code Scanning** ruleset:

1. Repo → Settings → Code security → Code Scanning → Default rules.
2. Set "Required" for the category named `tripwire` (matches the `category:` in the workflow above).
3. Choose your threshold — typically *"Block on Error severity"* (= Tripwire HIGH+).

Now any PR that introduces a new Tripwire `error` is blocked until either the finding is fixed or a repo admin explicitly dismisses it.

## Running against the corpus instead of a manifest

For a baseline / regression CI run:

```yaml
- run: tripwire ci --sarif > tripwire-corpus.sarif
  continue-on-error: true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: tripwire-corpus.sarif
    category: tripwire-corpus
```

This emits one SARIF document covering every corpus case (8 poisoning + 1 drift), with per-case `properties.tripwire_case.id` attribution so a reader can navigate from a Code Scanning alert back to the originating attack case.

## Multiple scans in one upload

If your repo has multiple MCP manifests, scan them all then `cat` the SARIFs into one upload:

```yaml
- run: |
    tripwire scan ./team-a/tools.json --sarif > a.sarif
    tripwire scan ./team-b/tools.json --sarif > b.sarif
    # Or, simpler: one combined manifest:
    jq -s '{"tools": (map(.tools) | add)}' \
      team-a/tools.json team-b/tools.json > all.json
    tripwire scan all.json --sarif > tripwire.sarif
```

The `upload-sarif` action accepts an array of files via `sarif_file: '*.sarif'` too.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `upload-sarif` fails with 403 | Missing `security-events: write` permission. | Add the `permissions:` block as above. |
| Code Scanning shows nothing | The workflow ran but found no HIGH+ findings, OR the SARIF was malformed. | `gh run view --log` and check the SARIF locally with `cat tripwire.sarif | jq .`. |
| Findings re-appear every PR even after fixing | The `category:` value drifts between runs. | Pin a stable `category:` (e.g. `tripwire`) — Code Scanning dedupes within a category. |
| `tripwire ci --sarif` empty `results[]` despite the corpus catching attacks | Corpus row enrichment didn't run. | Check the Tripwire version is ≥ the implementation of [#32](https://github.com/akoita/mcp-tripwire/issues/32); older versions emit only the human/`--json` shape. |

## Local validation before pushing

```bash
# Validate the SARIF you're about to upload against the official schema.
pip install jsonschema
tripwire scan ./tools.json --sarif > tripwire.sarif
python3 -c "
import json, jsonschema, urllib.request
schema_url = 'https://json.schemastore.org/sarif-2.1.0.json'
schema = json.loads(urllib.request.urlopen(schema_url).read())
jsonschema.validate(json.load(open('tripwire.sarif')), schema)
print('valid SARIF 2.1.0')
"
```

(The same check runs in Tripwire's own test suite — see `tests/unit/test_sarif.py::test_to_sarif_output_validates_against_official_schema`.)
