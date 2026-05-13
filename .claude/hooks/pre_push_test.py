#!/usr/bin/env python3
"""Pre-push hook: runs `make test` in Rust repositories before allowing
`git push`. Exit 0 = allow, exit 2 = block (with reason on stderr).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _classify import matches  # noqa: E402

TARGET = ("git", ["push"])


def main() -> None:
    try:
        payload = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, ValueError):
        sys.exit(0)
    command = payload.get("tool_input", {}).get("command", "") or ""
    if not matches(command, *TARGET):
        sys.exit(0)

    repo_root = _repo_root()
    if repo_root is None:
        sys.exit(0)
    if not (repo_root / "Cargo.toml").is_file():
        sys.exit(0)
    if not _makefile_has_target(repo_root / "Makefile", "test"):
        sys.exit(0)

    sys.stderr.write("Running make test...\n")
    result = subprocess.run(
        ["make", "-C", str(repo_root), "test"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        sys.stderr.write("make test failed - fix failing tests before pushing:\n")
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        sys.exit(2)
    sys.stderr.write("All tests passed.\n")
    sys.exit(0)


def _repo_root() -> Path | None:
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None
    return Path(result.stdout.strip())


def _makefile_has_target(makefile: Path, target: str) -> bool:
    try:
        text = makefile.read_text()
    except OSError:
        return False
    return any(line.startswith(f"{target}:") for line in text.splitlines())


if __name__ == "__main__":
    main()
