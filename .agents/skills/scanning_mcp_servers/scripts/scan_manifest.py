#!/usr/bin/env python3
"""Thin wrapper around `tripwire scan` for the scanning-mcp-servers skill."""

from __future__ import annotations

import sys

from tripwire.cli import main

if __name__ == "__main__":
    raise SystemExit(main(["scan", *sys.argv[1:]]))
