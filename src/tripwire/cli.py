"""`tripwire` CLI — scan / verify / ci.

    tripwire scan <manifest.json> [--sarif]              # scan; SARIF on stdout with --sarif
    tripwire verify <badge.json>                          # verify a signed trust badge
    tripwire ci [--corpus PATH] [--json | --sarif]        # run the attack corpus

The CLI is the agents-cli "Agent skill"-style entrypoint and the CI gate.
Signing key comes from $TRIPWIRE_SIGNING_KEY (Hard Rule #3 — never hardcoded).

Exit codes:
    0  success / all clear
    1  CI saw a surviving attack or false-positive; scan saw a high-severity finding
    2  verify: badge signature mismatch (tamper-evident)
    3  verify: badge structurally invalid (missing fields, can't even check)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict
from pathlib import Path

from . import attestation
from .corpus import DEFAULT_CORPUS, load_corpus, run_corpus
from .detection import Finding, Severity, scan_tool
from .owasp import title as owasp_title

_KEY_ENV = "TRIPWIRE_SIGNING_KEY"

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_BADGE_VALID = 0
EXIT_BADGE_TAMPERED = 2
EXIT_BADGE_INVALID = 3

# ANSI color helpers — silenced when stdout isn't a TTY or NO_COLOR is set.
_C_RESET = "\x1b[0m"
_C_RED = "\x1b[31m"
_C_YELLOW = "\x1b[33m"
_C_GREEN = "\x1b[32m"
_C_DIM = "\x1b[2m"


def _use_color(force: bool | None = None) -> bool:
    """Decide whether ANSI colors should be emitted.

    Honors (in order): explicit override, NO_COLOR env (per https://no-color.org/),
    stdout TTY status.
    """
    if force is not None:
        return force
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def _paint(text: str, code: str, *, on: bool) -> str:
    return f"{code}{text}{_C_RESET}" if on else text


def _key() -> str:
    return os.environ.get(_KEY_ENV, "dev-only-change-me")


def _tools_from(manifest: dict) -> list[dict]:
    if isinstance(manifest, dict) and "tools" in manifest:
        return list(manifest["tools"])
    return [manifest]  # treat as a single tool descriptor


# --- scan -----------------------------------------------------------------


def _group_by_owasp(findings: list[Finding]) -> dict[str, list[Finding]]:
    """Group findings by OWASP MCP category id, preserving stable order."""
    grouped: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        grouped[f.owasp].append(f)
    return dict(sorted(grouped.items()))


def cmd_scan(args: argparse.Namespace) -> int:
    color = _use_color()
    manifest_path = Path(args.manifest)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    all_findings: list[Finding] = []
    worst: Severity | None = None
    clean: list[str] = []
    for tool in _tools_from(manifest):
        name = str(tool.get("name", "<unnamed>"))
        findings = scan_tool(tool)
        if not findings:
            clean.append(name)
            continue
        for f in findings:
            all_findings.append(f)
            worst = f.severity if worst is None else max(worst, f.severity)

    if getattr(args, "sarif", False):
        # SARIF 2.1.0 on stdout — exit code semantics unchanged.
        from .sarif import SarifInput, to_sarif  # noqa: PLC0415 — optional output path

        sarif_doc = to_sarif(
            [SarifInput(findings=tuple(all_findings), input_uri=str(manifest_path.resolve()))]
        )
        json.dump(sarif_doc, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return EXIT_FAIL if (worst is not None and worst >= Severity.HIGH) else EXIT_OK

    for name in clean:
        print(f"  {_paint('✓', _C_GREEN, on=color)} {name}: clean")

    if all_findings:
        for owasp_id, group in _group_by_owasp(all_findings).items():
            heading = f"{owasp_id} — {owasp_title(owasp_id)}"
            print(f"\n  {_paint(heading, _C_YELLOW, on=color)}")
            for f in group:
                sev_color = _C_RED if f.severity >= Severity.HIGH else _C_YELLOW
                sev = _paint(str(f.severity), sev_color, on=color)
                print(f"    {_paint('✗', _C_RED, on=color)} {f.tool}: [{sev}] {f.title}")
                print(f"        {_paint(f.evidence, _C_DIM, on=color)}")

    if worst is not None and worst >= Severity.HIGH:
        fail = _paint("FAIL", _C_RED, on=color)
        print(f"\n{fail}: high-severity finding(s) detected (worst={worst}).")
        return EXIT_FAIL
    print(f"\n{_paint('OK', _C_GREEN, on=color)}: no high-severity findings.")
    return EXIT_OK


# --- verify ---------------------------------------------------------------

_REQUIRED_BADGE_FIELDS = ("tool", "fingerprint", "sig")


def cmd_verify(args: argparse.Namespace) -> int:
    color = _use_color()
    invalid = _paint("✗ INVALID", _C_RED, on=color)
    try:
        badge = json.loads(Path(args.badge).read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        print(f"{invalid}: cannot read badge ({e.__class__.__name__})")
        return EXIT_BADGE_INVALID

    if not isinstance(badge, dict) or any(k not in badge for k in _REQUIRED_BADGE_FIELDS):
        missing = [
            k for k in _REQUIRED_BADGE_FIELDS if not isinstance(badge, dict) or k not in badge
        ]
        print(f"{invalid}: malformed badge (missing {missing})")
        return EXIT_BADGE_INVALID

    # --pub PATH overrides the legacy HMAC path with Ed25519 verification.
    if getattr(args, "pub", None):
        from .signing.ed25519_backend import Ed25519Backend

        try:
            pub_pem = Path(args.pub).read_bytes()
        except OSError as e:
            print(f"{invalid}: cannot read public key {args.pub} ({e.__class__.__name__})")
            return EXIT_BADGE_INVALID
        verifier = Ed25519Backend(public_key_pem=pub_pem)
    else:
        verifier = _key()
    valid, reason = attestation.verify_badge(badge, verifier)
    if valid:
        print(f"{_paint('✓ VALID', _C_GREEN, on=color)}: {reason} (tool={badge.get('tool')!r})")
        return EXIT_BADGE_VALID
    print(f"{_paint('✗ TAMPERED', _C_RED, on=color)}: {reason} (tool={badge.get('tool')!r})")
    return EXIT_BADGE_TAMPERED


# --- key (Ed25519 lifecycle) ---------------------------------------------


def cmd_key_gen(args: argparse.Namespace) -> int:
    """Generate a fresh Ed25519 keypair. Writes the private key to disk with
    mode 0600 and prints the matching public key PEM on stdout (so it can be
    piped into a pubkey deploy step). RFC-0002 / #31 slot 5."""
    from .signing.ed25519_backend import Ed25519Backend

    backend = Ed25519Backend.generate()
    out = Path(args.out)
    if out.exists() and not args.force:
        print(f"✗ {out} already exists (re-run with --force to overwrite)", file=sys.stderr)
        return EXIT_FAIL
    out.write_bytes(backend.private_key_pem())
    out.chmod(0o600)
    sys.stdout.write(backend.public_key_pem().decode("ascii"))
    print(f"✓ private key written to {out} (mode 0600)", file=sys.stderr)
    return EXIT_OK


def cmd_key_pub(args: argparse.Namespace) -> int:
    """Print the public key PEM for a given private key. Read-only — useful
    for derive-once-deploy-many workflows."""
    from .signing.ed25519_backend import Ed25519Backend

    try:
        priv_pem = Path(args.input).read_bytes()
    except OSError as e:
        print(f"✗ cannot read {args.input}: {e.__class__.__name__}", file=sys.stderr)
        return EXIT_FAIL
    backend = Ed25519Backend(private_key_pem=priv_pem)
    sys.stdout.write(backend.public_key_pem().decode("ascii"))
    return EXIT_OK


# --- ci -------------------------------------------------------------------


def cmd_ci(args: argparse.Namespace) -> int:
    cases = load_corpus(args.corpus)
    result = run_corpus(cases, signing_key=_key())
    passed = result.all_attacks_blocked and not result.false_positives

    if getattr(args, "sarif", False):
        # One combined SARIF document covering every corpus case.
        from .sarif import from_corpus_rows, to_sarif  # noqa: PLC0415

        sarif_doc = to_sarif(from_corpus_rows(result.rows))
        json.dump(sarif_doc, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return EXIT_OK if passed else EXIT_FAIL

    if args.json:
        # Machine-parseable single JSON document (Rule #6 — no invented numbers).
        payload = {
            "attacks_total": result.attacks_total,
            "attacks_blocked": result.attacks_blocked,
            "clean_total": result.clean_total,
            "false_positives": result.false_positives,
            "passed": passed,
            "rows": result.rows,
        }
        json.dump(payload, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return EXIT_OK if passed else EXIT_FAIL

    color = _use_color()
    print(result.summary())
    for row in result.rows:
        mark = _paint("✓", _C_GREEN, on=color) if row["ok"] else _paint("✗", _C_RED, on=color)
        print(
            f"  {mark} {row['id']} ({row['category']}): "
            f"expected {row['expected']}, got {row['action']}"
        )
    if not passed:
        ci_fail = _paint("CI FAIL", _C_RED, on=color)
        print(f"\n{ci_fail}: an attack survived or a clean tool was wrongly blocked.")
        return EXIT_FAIL
    print(f"\n{_paint('CI PASS', _C_GREEN, on=color)}.")
    return EXIT_OK


# --- entrypoint -----------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="tripwire", description="MCP trust gateway")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan", help="scan a tool/manifest for poisoning")
    p_scan.add_argument("manifest")
    p_scan.add_argument(
        "--sarif",
        action="store_true",
        help="emit SARIF 2.1.0 on stdout (for GitHub Code Scanning et al.)",
    )
    p_scan.set_defaults(func=cmd_scan)

    p_verify = sub.add_parser("verify", help="verify a signed trust badge")
    p_verify.add_argument("badge")
    p_verify.add_argument(
        "--pub",
        help="path to an Ed25519 public-key PEM; overrides HMAC verification",
    )
    p_verify.set_defaults(func=cmd_verify)

    p_key = sub.add_parser("key", help="Ed25519 key lifecycle (gen / pub)")
    key_sub = p_key.add_subparsers(dest="key_cmd", required=True)
    p_key_gen = key_sub.add_parser("gen", help="generate an Ed25519 keypair")
    p_key_gen.add_argument(
        "--out", default="tripwire-private.pem", help="output path for the private key PEM"
    )
    p_key_gen.add_argument("--force", action="store_true", help="overwrite an existing --out file")
    p_key_gen.set_defaults(func=cmd_key_gen)
    p_key_pub = key_sub.add_parser("pub", help="print the public-key PEM for a private key")
    p_key_pub.add_argument("--in", dest="input", required=True, help="private-key PEM path")
    p_key_pub.set_defaults(func=cmd_key_pub)

    p_ci = sub.add_parser("ci", help="run the attack corpus")
    p_ci.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    # `--json` and `--sarif` are mutually exclusive output modes.
    ci_out = p_ci.add_mutually_exclusive_group()
    ci_out.add_argument("--json", action="store_true", help="emit machine-parseable JSON")
    ci_out.add_argument(
        "--sarif",
        action="store_true",
        help="emit SARIF 2.1.0 on stdout (one combined runs[] for the whole corpus)",
    )
    p_ci.set_defaults(func=cmd_ci)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
