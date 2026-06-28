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


# Rule #2: the deterministic core stays dependency-free (agents/ is the only exception).
def check_core_dependency_free() -> None:
    allowed = set(sys.stdlib_module_names) | {"tripwire"}
    for path in _py_files(CORE, exclude=("agents",)):
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


def main() -> int:
    for check in (
        check_core_dependency_free,
        check_no_hardcoded_secrets,
        check_demo_safety,
        check_stubs_flagged,
        check_root_clean,
    ):
        check()
    if violations:
        print("✗ harness guardrails FAILED:")
        for v in violations:
            print(f"  - {v}")
        return 1
    print(
        "✓ harness guardrails passed (hard rules #2, #3, #4, #9 + root-clean convention verified)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
