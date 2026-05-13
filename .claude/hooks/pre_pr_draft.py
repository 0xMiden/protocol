#!/usr/bin/env python3
"""PreToolUse hook for the Bash tool: blocks `gh pr create` invocations
that do not pass `--draft`. PRs must be created as drafts; a human
promotes them to ready-for-review when appropriate.

Routes via `_classify.iter_match_args` (segment-scoped, per-invocation)
so detection only looks at the args of the actual `gh pr create`
segments — not anywhere in the raw command string. This avoids the
false positives the earlier substring-based check had (`echo gh pr
create`, `gh pr create --title "--draft"`) and enforces the rule on
EVERY matching segment, not just the first (so chained creates can't
slip past).

`--draft=true`/`--draft=1`/etc. count; `--draft=false`/`--draft=0`
do NOT (Cobra/pflag accept the explicit-false form to disable a
boolean flag).

Output protocol: writes JSON to stdout per the Claude Code PreToolUse
hook contract. Exit code is always 0; the deny signal is carried in
the JSON payload's `permissionDecision` field.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _classify import iter_match_args  # noqa: E402
from _hookutils import read_command  # noqa: E402

TARGET = ("gh", ["pr", "create"])

# `gh pr create` flags that take a separate-token argument. Mirrored
# from `gh pr create --help` as of gh 2.x (Nov 2026). If gh adds new
# arg-taking flags, an invocation like `gh pr create --new-flag --draft`
# would otherwise misread `--draft` as a flag rather than the value of
# `--new-flag`. The unknown-flag branch below catches that case
# conservatively: any unknown `-...` token consumes the next token as
# its value.
_ARG_TAKING_FLAGS = frozenset(
    {
        "--base", "-B",
        "--body", "-b",
        "--body-file", "-F",
        "--head", "-H",
        "--label", "-l",
        "--assignee", "-a",
        "--reviewer", "-r",
        "--milestone", "-m",
        "--project", "-p",
        "--template", "-T",
        "--title", "-t",
    }
)

# `gh pr create` flags that are boolean (no arg). Used so the
# unknown-flag conservative branch doesn't accidentally swallow a real
# subsequent `--draft` when a known boolean appears before it.
_BOOLEAN_FLAGS = frozenset(
    {
        "--draft", "-d",
        "--web", "-w",
        "--fill", "-f",
        "--fill-first",
        "--fill-verbose",
        "--dry-run",
        "--editor", "-e",
        "--no-maintainer-edit",
    }
)

# pflag-style truthy values for `--draft=<value>`. Anything not in this
# set is treated as falsy (draft NOT requested).
_TRUTHY_VALUES = frozenset({"1", "t", "T", "true", "TRUE", "True"})


def has_draft_flag(args: list[str]) -> bool:
    """Walk `gh pr create` args left-to-right and return True iff
    `--draft` (or `-d`, or `--draft=<truthy>`) appears in a flag
    position — not as the value of another flag.

    Walking rules:
      - `--draft` / `-d` alone → True.
      - `--draft=<v>` / `-d=<v>` → True if `<v>` is pflag-truthy.
      - `--<name>=<v>` (single-token) consumes one token; never the
        next.
      - Known arg-taking flag → consumes the next token.
      - Known boolean flag → does NOT consume the next token.
      - Unknown `-...` token → consumes the next token (conservative;
        a hypothetical new arg-taking gh flag would otherwise let
        `--draft` be misread).
      - Anything else (positional arg) → advance one.
    """
    i = 0
    while i < len(args):
        tok = args[i]
        # The flag itself.
        if tok == "--draft" or tok == "-d":
            return True
        if tok.startswith("--draft=") or tok.startswith("-d="):
            value = tok.split("=", 1)[1]
            return value in _TRUTHY_VALUES
        # `--flag=value` style: single token, consumes nothing extra.
        if tok.startswith("--") and "=" in tok:
            i += 1
            continue
        # Known boolean flag: stand-alone, doesn't consume next.
        if tok in _BOOLEAN_FLAGS:
            i += 1
            continue
        # Known arg-taking flag: consume the next token as the value.
        if tok in _ARG_TAKING_FLAGS:
            i += 2
            continue
        # Unknown `-...` token: conservatively assume arg-taking.
        if tok.startswith("-"):
            i += 2
            continue
        # Positional arg.
        i += 1
    return False


def main() -> None:
    command = read_command()
    if command is None:
        sys.exit(0)

    # Inspect EVERY matching `gh pr create` segment. The hook's
    # invariant is per-invocation: none of them may be non-draft.
    for args in iter_match_args(command, *TARGET):
        if not has_draft_flag(args):
            _emit_deny(command)
            break
    # Hook exits 0 either way; the deny is carried in the JSON payload.
    sys.exit(0)


def _emit_deny(command: str) -> None:
    reason = (
        "PRs must be created as drafts. Re-run with --draft:\n\n"
        f"  {command} --draft"
    )
    output = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }
    sys.stdout.write(json.dumps(output) + "\n")


if __name__ == "__main__":
    main()
