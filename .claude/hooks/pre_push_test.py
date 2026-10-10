#!/usr/bin/env python3
"""Pre-push hook: runs `make test` in Rust repositories before allowing
`git push`. Exit 0 = allow, exit 2 = block (with reason on stderr).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _classify import iter_match_global_args  # noqa: E402
from _hookutils import makefile_has_target, read_command, repo_root  # noqa: E402

TARGET = ("git", ["push"])


def main() -> None:
    command = read_command()
    if command is None:
        sys.exit(0)

    for global_args in iter_match_global_args(command, *TARGET):
        root = repo_root(global_args)
        if root is None:
            continue
        if not (root / "Cargo.toml").is_file():
            continue
        if not makefile_has_target(root / "Makefile", "test"):
            continue

        sys.stderr.write("Running make test...\n")
        result = subprocess.run(
            ["make", "-C", str(root), "test"],
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


if __name__ == "__main__":
    main()
