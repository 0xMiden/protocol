"""Shared filesystem / git helpers used by multiple hook scripts.

Kept separate from `_classify.py` because the concerns are different:
`_classify` parses Bash commands; this module wraps the bits of the
repository that hooks need to inspect (git toplevel, Makefile target
presence). Both modules live alongside the hook scripts so they're
importable via the `sys.path` shim in each hook.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any


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


def read_payload(stdin: Any = None) -> dict | None:
    """Parse the Claude Code hook payload from stdin and return the
    top-level dict, or None on any malformed input. `stdin` defaults
    to `sys.stdin`; pass a file-like object to make this unit-testable.
    """
    source = stdin if stdin is not None else sys.stdin
    try:
        payload = json.loads(source.read())
    except (json.JSONDecodeError, ValueError, OSError):
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def command_from_payload(payload: Any) -> str | None:
    """Return `payload["tool_input"]["command"]` as a string, or None
    on any unexpected shape. Defensive against missing keys, non-dict
    `tool_input`, non-string `command`.
    """
    if not isinstance(payload, dict):
        return None
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return None
    command = tool_input.get("command", "")
    if not isinstance(command, str):
        return None
    return command


def read_command(stdin: Any = None) -> str | None:
    """Read the hook payload from stdin and return its
    `tool_input.command` field as a string, or None on any malformed
    input (so the hook can fail open with `sys.exit(0)`).
    """
    return command_from_payload(read_payload(stdin))
