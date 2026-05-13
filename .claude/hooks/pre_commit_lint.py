#!/usr/bin/env python3
"""Pre-commit hook: runs `make lint` in Rust repositories before
allowing `git commit`. Exit 0 = allow, exit 2 = block (with reason on
stderr).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _classify import matches  # noqa: E402
from _hookutils import makefile_has_target, repo_root  # noqa: E402

# Imported by tests to verify the hook routes correctly.
TARGET = ("git", ["commit"])


def main() -> None:
    try:
        payload = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, ValueError):
        sys.exit(0)
    command = payload.get("tool_input", {}).get("command", "") or ""
    if not matches(command, *TARGET):
        sys.exit(0)

    root = repo_root()
    if root is None:
        sys.exit(0)
    if not (root / "Cargo.toml").is_file():
        sys.exit(0)
    if not makefile_has_target(root / "Makefile", "lint"):
        sys.exit(0)

    result = subprocess.run(
        ["make", "-C", str(root), "lint"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        sys.stderr.write("make lint failed - fix issues before committing:\n")
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
