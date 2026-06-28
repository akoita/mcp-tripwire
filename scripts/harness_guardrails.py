#!/usr/bin/env python3
"""Deterministic enforcement of AGENTS.md hard rules (mirrors resonate-agentic).

These are checks, not vibes: each hard rule that *can* be machine-verified is encoded
here so it can never regress silently. Wired into `make check`, pre-commit, and CI.
Exit 0 = clean, 1 = violation(s).
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "src" / "tripwire"
violations: list[str] = []


def fail(msg: str) -> None:
    violations.append(msg)


def _py_files(base: Path, exclude: tuple[str, ...] = ()) -> list[Path]:
    return [
        p
        for p in base.rglob("*.py")
        if not any(part in exclude for part in p.parts) and "__pycache__" not in p.parts
    ]


# Rule #2: the deterministic core stays dependency-free.
# agents/ and signing/ are the only exceptions (pluggable adapters gated by extras).
def check_core_dependency_free() -> None:
    allowed = set(sys.stdlib_module_names) | {"tripwire"}
    for path in _py_files(CORE, exclude=("agents", "signing")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        rel = path.relative_to(ROOT)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    if top not in allowed:
                        fail(f"[#2] third-party import '{top}' in core file {rel}")
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                top = node.module.split(".")[0]
                if top not in allowed:
                    fail(f"[#2] third-party import '{top}' in core file {rel}")


# Rule #3: no hardcoded secrets in code (tests/examples excluded; examples use the canary).
_SECRET = re.compile(r"(?i)(password|secret|api_key|apikey|token)\s*=\s*['\"][^'\"]{8,}['\"]")
_PRIV_KEY = re.compile(r"BEGIN [A-Z ]*PRIVATE KEY")


def check_no_hardcoded_secrets() -> None:
    targets = _py_files(ROOT / "src") + _py_files(ROOT / "app") + _py_files(ROOT / "scripts")
    for path in targets:
        text = path.read_text(encoding="utf-8")
        # The detection ruleset legitimately *names* these patterns; skip the rules file.
        if path.name == "detection.py":
            continue
        if _SECRET.search(text) or _PRIV_KEY.search(text):
            fail(f"[#3] possible hardcoded secret in {path.relative_to(ROOT)}")


# Rule #4: demos never touch real credential material (canary + fake sink only).
def check_demo_safety() -> None:
    for path in _py_files(ROOT / "examples"):
        text = path.read_text(encoding="utf-8")
        if "expanduser" in text and ".ssh" in text:
            fail(f"[#4] example reads real credential path in {path.relative_to(ROOT)}")
        if "CANARY" not in text and "canary" not in text:
            continue  # not a secret-handling example


# Rule #9: stubs must self-flag so nothing ships silently incomplete.
def check_stubs_flagged() -> None:
    for path in _py_files(ROOT / "src"):
        text = path.read_text(encoding="utf-8")
        if "NotImplementedError" in text and "STUB(" not in text:
            rel = path.relative_to(ROOT)
            fail(f"[#9] unflagged stub (no STUB marker) in {rel}")


# Convention: the repo root stays uncluttered. Anything at the root must be on
# the allowlist below, which is the curated set of files with a tooling or
# ecosystem reason to live there (README/LICENSE for GitHub, pyproject for
# packaging, AGENTS.md for AI agents that read it at the project root, etc.).
# Working memory (STATUS, ROADMAP, BACKLOG, TECH_DEBT, SPEC) lives in docs/.
#
# To add a new root file: append it here AND add a one-line justification
# next to it explaining why a docs/ or scripts/ home is wrong.
ROOT_FILE_ALLOWLIST: dict[str, str] = {
    # GitHub-recognised
    "README.md": "GitHub renders this as the project front page.",
    "LICENSE": "GitHub recognises this for the license badge.",
    "CONTRIBUTING.md": "GitHub surfaces this in the PR sidebar.",
    "SECURITY.md": "GitHub surfaces this in the Security tab.",
    "CHANGELOG.md": "Convention for release tooling (npm, cargo, GitHub Releases).",
    # AI-agent conventions (loaded at the project root by each tool)
    "AGENTS.md": "Single source of truth; every coding agent loads it from the root.",
    "CLAUDE.md": "Symlink to AGENTS.md; Claude Code loads it from the root.",
    "GEMINI.md": "Symlink to AGENTS.md; Gemini Antigravity loads it from the root.",
    ".agents-cli-spec.md": "agents-cli reads it at the project root (Phase 0 spec).",
    # Python / build tooling
    "pyproject.toml": "PEP 621 project manifest; must be at the root.",
    "uv.lock": "Lockfile sits next to pyproject.toml.",
    "Makefile": "Convention: `make <target>` from the project root.",
    "Dockerfile": "Convention: `docker build .` from the project root.",
    # agents-cli
    "agents-cli-manifest.yaml": "agents-cli reads it at the project root.",
    # Dotfiles
    ".env.example": "Convention: sample env at the root, next to where users copy it.",
    ".gitignore": "Git looks here.",
    ".pre-commit-config.yaml": "pre-commit looks here.",
    ".dockerignore": "Docker looks here (allowed even if absent today).",
    ".gitattributes": "Git looks here (allowed even if absent today).",
    ".git": "Git worktree: `.git` is a FILE (not a dir); git-owned, must be at root.",
}


def check_root_clean() -> None:
    """Refuse new files at the repo root unless they're on the allowlist.

    Why: clutter makes the project look unfinished and pushes legitimate
    working-memory docs into the same visual space as load-bearing
    conventions. The allowlist documents the "why is this at the root"
    answer for every survivor — a deliberate signal to future contributors.
    """
    for entry in ROOT.iterdir():
        if not entry.is_file():
            continue  # directories are unconstrained
        if entry.name in ROOT_FILE_ALLOWLIST:
            continue
        fail(
            f"[root-clean] '{entry.name}' is not on the root allowlist. "
            f"Move it into docs/ (or scripts/, examples/, etc.) — or, if it "
            f"genuinely belongs at the root, add it to ROOT_FILE_ALLOWLIST "
            f"in scripts/harness_guardrails.py with a one-line justification."
        )


# Convention: docs/features/ is the canonical per-feature reference. Every
# .md file in that directory must be linked from the index README; every
# link in the index must resolve. Catches drift in both directions —
# orphan pages no one links to, and dead links to deleted pages.
_FEATURE_LINK = re.compile(r"\(([\w_\-/]+\.md)\)")


def check_features_catalog_consistent() -> None:
    """Index ↔ page consistency for docs/features/.

    Why: the feature catalog is only useful if contributors trust it
    reflects reality. A page that exists but isn't indexed is invisible;
    a link in the index that points at a deleted file is a stale
    promise. Both fail the build with a clear remediation.
    """
    features_dir = ROOT / "docs" / "features"
    if not features_dir.exists():
        return  # catalog not adopted in this project yet
    index = features_dir / "README.md"
    if not index.exists():
        fail("[features-catalog] docs/features/ exists but has no README.md index.")
        return

    pages_on_disk = {p.name for p in features_dir.glob("*.md") if p.name != "README.md"}
    index_text = index.read_text(encoding="utf-8")
    # Pull all relative .md links from the index; restrict to entries that
    # resolve to a sibling file (no `../` or absolute paths).
    linked = {match for match in _FEATURE_LINK.findall(index_text) if "/" not in match}

    for orphan in sorted(pages_on_disk - linked):
        fail(
            f"[features-catalog] docs/features/{orphan} exists but is not "
            f"linked from docs/features/README.md. Either link it from the "
            f"index or delete the page."
        )
    for missing in sorted(linked - pages_on_disk):
        fail(
            f"[features-catalog] docs/features/README.md links to "
            f"docs/features/{missing}, but the file doesn't exist. "
            f"Create the page or fix the link."
        )


# Curated list of backend module names that pull a third-party import (e.g.
# `cryptography`). Eager-importing any of these at module scope in
# `attestation.py` would crash a base install without the relevant extra.
# The HMAC backend is stdlib-only and is NOT on this list.
_EXTRAS_GATED_BACKENDS = {"ed25519_backend"}


# Rule #2 corollary: backends in agents/ and signing/ are pluggable adapters gated by
# extras (`[agent]` / `[signing]`). The engine must NEVER eagerly import them at
# module level — a base install with neither extra would crash on `import tripwire`.
# This check parses src/tripwire/attestation.py and fails if it does
# `from .signing import ...` or `import tripwire.signing[.x]` at module scope.
def check_pluggable_backends_lazy_imported() -> None:
    target = CORE / "attestation.py"
    if not target.exists():
        return  # engine moved/renamed; bigger problem than this check
    tree = ast.parse(target.read_text(encoding="utf-8"), filename=str(target))

    def _touches_lazy(dotted: str) -> bool:
        return any(part in _EXTRAS_GATED_BACKENDS for part in dotted.split("."))

    for node in tree.body:  # module-level only — function-body imports are fine
        offending: str | None = None
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if _touches_lazy(module):
                offending = ("." * node.level) + module
            else:
                # e.g. `from .signing import ed25519_backend`
                for alias in node.names:
                    if alias.name in _EXTRAS_GATED_BACKENDS:
                        prefix = ("." * node.level) + (module + "." if module else "")
                        offending = prefix + alias.name
                        break
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if _touches_lazy(alias.name):
                    offending = alias.name
                    break
        if offending:
            fail(
                f"[#2-lazy] attestation.py eagerly imports '{offending}' at module "
                f"scope. Move it inside the function body — a base install without "
                f"the relevant extra (e.g. `[signing]`) must still `import tripwire` "
                f"cleanly."
            )


def main() -> int:
    for check in (
        check_core_dependency_free,
        check_pluggable_backends_lazy_imported,
        check_no_hardcoded_secrets,
        check_demo_safety,
        check_stubs_flagged,
        check_root_clean,
        check_features_catalog_consistent,
    ):
        check()
    if violations:
        print("✗ harness guardrails FAILED:")
        for v in violations:
            print(f"  - {v}")
        return 1
    print(
        "✓ harness guardrails passed "
        "(hard rules #2, #3, #4, #9 + root-clean + feature-catalog conventions verified)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
