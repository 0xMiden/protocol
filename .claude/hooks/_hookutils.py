"""Shared filesystem / git helpers used by multiple hook scripts.

Kept separate from `_classify.py` because the concerns are different:
`_classify` parses Bash commands; this module wraps the bits of the
repository that hooks need to inspect (git toplevel, Makefile target
presence). Both modules live alongside the hook scripts so they're
importable via the `sys.path` shim in each hook.
"""

from __future__ import annotations

import subprocess
from pathlib import Path


def repo_root() -> Path | None:
    """Return the absolute path of the current git worktree's top
    level, or None if we're not inside a git worktree.
    """
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None
    out = result.stdout.strip()
    if not out:
        return None
    return Path(out)


def makefile_has_target(makefile: Path, target: str) -> bool:
    """Return True if `makefile` declares a recipe for `target` (i.e.
    any line starts with `target:`). False if the file is missing or
    no matching recipe is found.
    """
    try:
        text = makefile.read_text()
    except OSError:
        return False
    needle = f"{target}:"
    return any(line.startswith(needle) for line in text.splitlines())
