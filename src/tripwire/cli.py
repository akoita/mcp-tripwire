"""`tripwire` CLI — scan / verify / ci.

    tripwire scan <manifest.json>     # scan a tool or manifest for poisoning
    tripwire verify <badge.json>      # verify a signed trust badge
    tripwire ci [--corpus PATH]       # run the attack corpus; non-zero exit if any survive

The CLI is the agents-cli "Agent skill"-style entrypoint and the CI gate.
Signing key comes from $TRIPWIRE_SIGNING_KEY (Hard Rule #3 — never hardcoded).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import attestation
from .corpus import DEFAULT_CORPUS, load_corpus, run_corpus
from .detection import Severity, scan_tool

_KEY_ENV = "TRIPWIRE_SIGNING_KEY"


def _key() -> str:
    return os.environ.get(_KEY_ENV, "dev-only-change-me")


def _tools_from(manifest: dict) -> list[dict]:
    if isinstance(manifest, dict) and "tools" in manifest:
        return list(manifest["tools"])
    return [manifest]  # treat as a single tool descriptor


def cmd_scan(args: argparse.Namespace) -> int:
    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    worst = Severity.LOW
    any_finding = False
    for tool in _tools_from(manifest):
        findings = scan_tool(tool)
        name = tool.get("name", "<unnamed>")
        if not findings:
            print(f"  ✓ {name}: clean")
            continue
        any_finding = True
        for f in findings:
            worst = max(worst, f.severity)
            print(f"  ✗ {name}: [{f.severity}] {f.owasp} {f.title} — {f.evidence}")
    if any_finding and worst >= Severity.HIGH:
        print(f"\nFAIL: high-severity finding(s) detected (worst={worst}).")
        return 1
    print("\nOK: no high-severity findings.")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    badge = json.loads(Path(args.badge).read_text(encoding="utf-8"))
    valid, reason = attestation.verify_badge(badge, _key())
    print(("✓ VALID" if valid else "✗ INVALID") + f": {reason}")
    return 0 if valid else 1


def cmd_ci(args: argparse.Namespace) -> int:
    cases = load_corpus(args.corpus)
    result = run_corpus(cases, signing_key=_key())
    print(result.summary())
    for row in result.rows:
        mark = "✓" if row["ok"] else "✗"
        print(
            f"  {mark} {row['id']} ({row['category']}): "
            f"expected {row['expected']}, got {row['action']}"
        )
    if not result.all_attacks_blocked or result.false_positives:
        print("\nCI FAIL: an attack survived or a clean tool was wrongly blocked.")
        return 1
    print("\nCI PASS.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="tripwire", description="MCP trust gateway")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan", help="scan a tool/manifest for poisoning")
    p_scan.add_argument("manifest")
    p_scan.set_defaults(func=cmd_scan)

    p_verify = sub.add_parser("verify", help="verify a signed trust badge")
    p_verify.add_argument("badge")
    p_verify.set_defaults(func=cmd_verify)

    p_ci = sub.add_parser("ci", help="run the attack corpus")
    p_ci.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    p_ci.set_defaults(func=cmd_ci)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
