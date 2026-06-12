"""Shared filesystem / git helpers used by multiple hook scripts.

Kept separate from `_classify.py` because the concerns are different:
`_classify` parses Bash commands; this module wraps the bits of the
repository that hooks need to inspect (git toplevel, Makefile target
presence). Both modules live alongside the hook scripts so they're
importable via the `sys.path` shim in each hook.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

# Strips harness-injected <system-reminder> blocks from user message text so
# only what the human actually typed is surfaced to the reviewers.
_SYSTEM_REMINDER = re.compile(r"<system-reminder>.*?</system-reminder>", re.DOTALL)


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


def recent_user_prompts(
    transcript_path: Any,
    max_messages: int = 12,
    max_chars: int = 3000,
) -> str | None:
    """Return the human-typed prompts from a session transcript as a
    bulleted, most-recent-first string, or None if unavailable/empty.

    Reads the JSONL transcript named by a hook payload's `transcript_path`,
    keeps only genuine user turns (dropping tool results, tool calls, and
    harness-injected `<system-reminder>` content), and caps the output so the
    reviewers get the user's intent without the whole conversation.
    """
    if not isinstance(transcript_path, str) or not transcript_path:
        return None
    try:
        lines = Path(transcript_path).read_text().splitlines()
    except OSError:
        return None

    prompts: list[str] = []
    for line in lines:
        try:
            entry = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(entry, dict) or entry.get("type") != "user" or entry.get("isMeta"):
            continue
        message = entry.get("message")
        if not isinstance(message, dict):
            continue
        text = _user_text(message.get("content"))
        if text:
            prompts.append(text)
    if not prompts:
        return None

    out: list[str] = []
    total = 0
    for prompt in reversed(prompts):  # most recent first
        if len(prompt) > 500:
            prompt = prompt[:500].rstrip() + "..."
        bullet = f"- {prompt}"
        if out and total + len(bullet) > max_chars:
            break
        out.append(bullet)
        total += len(bullet)
        if len(out) >= max_messages:
            break
    return "\n".join(out)


def _user_text(content: Any) -> str | None:
    """Extract human text from a user message's `content`, dropping
    tool_result/tool_use blocks and `<system-reminder>` noise. Returns None
    if nothing human-authored remains."""
    if isinstance(content, str):
        parts = [content]
    elif isinstance(content, list):
        parts = [
            block["text"]
            for block in content
            if isinstance(block, dict) and block.get("type") == "text" and isinstance(block.get("text"), str)
        ]
    else:
        return None
    cleaned = _SYSTEM_REMINDER.sub("", "\n".join(parts)).strip()
    return cleaned or None
