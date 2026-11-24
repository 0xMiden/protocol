"""Shared command classifier for the `.claude/hooks/*.py` scripts.

Claude Code wires each hook in settings.json under
`if: Bash(*<pattern>*)`, but that matcher does not reliably filter:
unrelated Bash calls have been observed triggering hooks because they
happen to contain a literal substring (e.g. `echo gh pr create`),
while real invocations with intermediate global flags
(`git -C . push`, `gh -R repo pr create`) bypass the strict patterns.

This module classifies a Bash command string by *parsing* it rather
than matching substrings. Each hook calls `matches(command, binary,
subcommand)` and exits 0 if it returns False — meaning the command is
not actually a real invocation of the binary+subcommand the hook
cares about.

Parsing rules:
  1. Split the command on top-level shell separators
     (`&&`, `||`, `;`, `|`, `&`, newlines).
  2. For each segment, tokenize with `shlex.split(posix=True)` so
     quoted arguments are treated as single tokens.
  3. Strip leading env-var assignments (`FOO=bar git ...`).
  4. The first remaining token must equal the target binary.
  5. Walk forward through known global flags (and their separated
     args) until the first non-flag token. That token must equal
     the first subcommand component.
  6. Continue with the remaining subcommand components (e.g. `gh pr
     create` is binary=`gh`, subcommand=[`pr`, `create`]).

Fires (returns True) iff ANY pipeline segment matches. That preserves
the intent of the original `Bash(*<binary> <sub>*)` matcher when the
user runs `cd repo && git push`, while still excluding
`echo "git push"` (first token of the only segment is `echo`).

`invocation_dir` walks the same segments, plus the separators between
them, to find the directory a matched invocation runs in (following
`cd <dir>` segments and `git -C <dir>`).
"""

from __future__ import annotations

import os
import re
import shlex
from typing import Iterator

# Used for env-var assignment detection in strip_assignments.

# Global flags that take a separate-token argument. Flags with `=`-form
# arguments (`--repo=value`, `-c k=v`) tokenize as a single shlex token
# and are skipped naturally by the loop below; they don't need to appear
# in this table.
_GLOBAL_FLAGS_WITH_ARG: dict[str, set[str]] = {
    "git": {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path"},
    "gh": {"-R", "--repo", "--hostname"},
}

# Pattern for `NAME=value` env-var assignments that may precede a command.
# Must start with a letter or underscore, then any [A-Za-z0-9_] chars,
# then `=`, then anything. Matches POSIX identifier rules.
_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

# Two-character separators (longest first so `;;` matches before `;`,
# `&&` before `&`, `||` before `|`).
_TWO_CHAR_SEPARATORS = ("&&", "||", ";;")
# Single-character separators. `\n` belongs here so unquoted newlines
# split commands the way bash does.
_SINGLE_CHAR_SEPARATORS = frozenset(";|&\n")

# Global flag that makes the binary change directory before running the
# subcommand. Git applies several in order, each relative to the previous.
_DIR_FLAGS: dict[str, str] = {"git": "-C"}

# A `cd` is followed only with one of these on both sides (`""` is either
# end of the command): it then runs in the current shell, after the segment
# before it. Next to `|`, `&` or `||` it may run in a subshell or not at
# all.
_SEQUENTIAL_SEPARATORS = frozenset({"", "&&", ";", "\n"})

# Characters that shlex leaves in a token but bash would expand or
# reinterpret first (variables, command substitution, `~`, globs, brace
# expansion, subshells, redirections), so the path is not known.
_SHELL_SYNTAX = re.compile(r"^~|[$`*?\[{()<>]")


def _split_unquoted_separators(command: str) -> list[tuple[str, str]]:
    """Split `command` into raw segments on unquoted shell separators,
    each paired with the separator that ends it (`""` for the last one).
    Walks the string char-by-char, tracking quote state so that
    separators inside `"..."` or `'...'` are preserved as part of the
    segment, and so backslash-newline outside quotes collapses to a
    space (line continuation).
    """
    segments: list[tuple[str, str]] = []
    current: list[str] = []
    quote_char: str | None = None
    i = 0
    n = len(command)
    while i < n:
        c = command[i]
        # Inside a quoted region: copy verbatim until the matching quote.
        if quote_char is not None:
            current.append(c)
            if c == "\\" and i + 1 < n:
                # Inside double quotes, backslash escapes the next char;
                # inside single quotes, it's literal. Either way, copy
                # the next char verbatim so we don't mistake an escaped
                # quote for a closer.
                current.append(command[i + 1])
                i += 2
                continue
            if c == quote_char:
                quote_char = None
            i += 1
            continue
        # Outside quotes: detect opening quote, line continuation, or
        # separator. Otherwise copy verbatim.
        if c in ('"', "'"):
            quote_char = c
            current.append(c)
            i += 1
            continue
        if c == "\\" and i + 1 < n and command[i + 1] == "\n":
            current.append(" ")
            i += 2
            continue
        # Longest separator first.
        if i + 1 < n and command[i : i + 2] in _TWO_CHAR_SEPARATORS:
            segments.append(("".join(current), command[i : i + 2]))
            current = []
            i += 2
            continue
        if c in _SINGLE_CHAR_SEPARATORS:
            segments.append(("".join(current), c))
            current = []
            i += 1
            continue
        current.append(c)
        i += 1
    segments.append(("".join(current), ""))
    return segments


def _segments(command: str) -> Iterator[tuple[list[str], str, str]]:
    """Yield `(tokens, before, after)` for each top-level segment of
    `command`: its shlex tokens and the separators that precede and
    follow it (`""` at either end of the command). Blank segments and
    segments that fail to tokenize are skipped.
    """
    if not command or not command.strip():
        return
    before = ""
    for raw, after in _split_unquoted_separators(command):
        raw = raw.strip()
        try:
            tokens = shlex.split(raw, posix=True)
        except ValueError:
            # Unbalanced quotes or similar — skip this segment.
            tokens = []
        if tokens:
            yield tokens, before, after
        before = after


def pipeline_segments(command: str) -> list[list[str]]:
    """Split `command` on top-level shell separators and tokenize each
    segment. Separators inside quotes are preserved as part of the
    segment text. Backslash-newline outside quotes collapses to a
    space (line continuation). Segments that fail to tokenize
    (unbalanced quotes, etc.) are silently dropped — they could not
    have been a real invocation of any target anyway.
    """
    return [tokens for tokens, _before, _after in _segments(command)]


def strip_assignments(tokens: list[str]) -> list[str]:
    """Drop leading `FOO=bar` env-var assignments from `tokens`."""
    i = 0
    while i < len(tokens) and _ASSIGNMENT_RE.match(tokens[i]):
        i += 1
    return tokens[i:]


def _flag_width(token: str, binary: str) -> int:
    """Return the number of tokens the global flag `token` of `binary`
    occupies. Multi-token flags listed in _GLOBAL_FLAGS_WITH_ARG[binary]
    consume the next token as their argument (2). `--flag=value` style
    flags occupy a single token (the `=` is inside) and consume nothing
    extra. Unknown `-...` tokens are conservatively treated as flag-only
    (single-token, no argument) — if we guess wrong we'll miss the
    subcommand, which is the safer failure mode.
    """
    if "=" not in token and token in _GLOBAL_FLAGS_WITH_ARG.get(binary, set()):
        return 2
    return 1


def _walk_past_global_flags(tokens: list[str], binary: str, start: int) -> int:
    """Given `tokens` and an index `start` pointing at the position just
    after `binary`, return the index of the first non-flag token.
    """
    i = start
    while i < len(tokens) and tokens[i].startswith("-"):
        i += _flag_width(tokens[i], binary)
    return i


def _subcommand_start(tokens: list[str], binary: str, subcommand: list[str]) -> int | None:
    """Return the index of the first `subcommand` token if the segment
    `tokens` (env assignments already stripped) invokes `binary` with
    `subcommand`, otherwise None.
    """
    if not subcommand or not tokens or tokens[0] != binary:
        return None
    i = _walk_past_global_flags(tokens, binary, 1)
    # Subcommand chain must appear contiguously starting at `i`.
    if tokens[i : i + len(subcommand)] == list(subcommand):
        return i
    return None


def matches(command: str, binary: str, subcommand: list[str]) -> bool:
    """Return True iff any pipeline segment in `command` invokes
    `binary` with the given `subcommand` path, accounting for env-var
    assignments and known global flags between `binary` and the first
    subcommand component.

    Thin wrapper around `iter_match_args` — see also `match_args`
    (first segment only) for callers that need to inspect args.

    >>> matches("git push", "git", ["push"])
    True
    >>> matches("git -C . push", "git", ["push"])
    True
    >>> matches("echo git push", "git", ["push"])
    False
    >>> matches("gh -R foo/bar pr create", "gh", ["pr", "create"])
    True
    >>> matches("gh pr list", "gh", ["pr", "create"])
    False
    """
    return next(iter_match_args(command, binary, subcommand), None) is not None


def iter_match_args(
    command: str, binary: str, subcommand: list[str]
) -> Iterator[list[str]]:
    """Yield the args of EVERY pipeline segment in `command` that
    invokes `binary` with `subcommand`. Each yielded list is the
    tokens that follow the subcommand chain in one matching segment.

    Use this when the hook's invariant is per-invocation (e.g.
    "no `gh pr create` should be non-draft") rather than per-command.
    `gh pr create --draft && gh pr create` has two matching segments;
    iterating lets the hook inspect both and deny if any lacks the
    required flag.

    >>> list(iter_match_args("gh pr create --draft && gh pr create", "gh", ["pr", "create"]))
    [['--draft'], []]
    >>> list(iter_match_args("git status", "git", ["push"]))
    []
    """
    for tokens in pipeline_segments(command):
        tokens = strip_assignments(tokens)
        i = _subcommand_start(tokens, binary, subcommand)
        if i is not None:
            yield tokens[i + len(subcommand) :]


def match_args(command: str, binary: str, subcommand: list[str]) -> list[str] | None:
    """Return the args of the FIRST matching pipeline segment, or None
    if no segment matches. Convenience for callers that don't care
    about chained invocations; prefer `iter_match_args` if the hook's
    invariant is per-invocation.

    >>> match_args("gh pr create --draft", "gh", ["pr", "create"])
    ['--draft']
    >>> match_args("gh -R foo/bar pr create --title x", "gh", ["pr", "create"])
    ['--title', 'x']
    >>> match_args("gh pr create && echo --draft", "gh", ["pr", "create"])
    []
    >>> match_args("echo gh pr create --draft", "gh", ["pr", "create"]) is None
    True
    """
    return next(iter_match_args(command, binary, subcommand), None)


def invocation_dir(
    command: str, binary: str, subcommand: list[str], cwd: str | None
) -> str | None:
    """Return the directory that the LAST segment of `command` invoking
    `binary` with `subcommand` runs in, or None when no segment matches
    or its directory cannot be determined with confidence.

    Starts from `cwd`, applies each top-level `cd <dir>` before that
    segment in order, then the segment's own `-C <dir>` flags (git).
    Relative paths resolve against the directory so far. The last
    matching segment wins because a hook that runs after the command
    sees the state it left behind: after `git commit -m a && cd ../b &&
    git commit -m b`, HEAD is the commit made in `../b`.

    The directory becomes unknown after a `cd` that cannot be followed
    (no argument, `cd -`, options, unexpanded shell syntax such as `$VAR`,
    or a `cd` joined by `||`, `|` or `&`), after `pushd`/`popd`, and
    after a subshell or group; a later absolute `cd` makes it known
    again.

    >>> invocation_dir("cd /wt && git commit -m x", "git", ["commit"], "/repo")
    '/wt'
    >>> invocation_dir("git -C ../wt commit -m x", "git", ["commit"], "/repo/main")
    '/repo/wt'
    >>> invocation_dir("cd $WT && git commit -m x", "git", ["commit"], "/repo") is None
    True
    """
    dir_flag = _DIR_FLAGS.get(binary)
    directory = cwd
    found: str | None = None
    for tokens, before, after in _segments(command):
        tokens = strip_assignments(tokens)
        if not tokens:
            continue
        start = _subcommand_start(tokens, binary, subcommand)
        if start is not None:
            found = directory
            i = 1
            while i < start:
                if tokens[i] == dir_flag:
                    found = _change_dir(found, tokens[i + 1])
                i += _flag_width(tokens[i], binary)
        elif tokens[0] == "cd":
            followable = (
                before in _SEQUENTIAL_SEPARATORS
                and after in _SEQUENTIAL_SEPARATORS
                and len(tokens) == 2
                and not tokens[1].startswith("-")
            )
            directory = _change_dir(directory, tokens[1]) if followable else None
        elif tokens[0] in ("pushd", "popd") or tokens[0].startswith(("(", "{")):
            directory = None
    return found


def _change_dir(directory: str | None, path: str) -> str | None:
    """Return `directory` after changing into `path`, or None when that
    is unknown: `path` has shell syntax bash would expand first, or is
    relative to an unknown `directory`.
    """
    if _SHELL_SYNTAX.search(path):
        return None
    if not os.path.isabs(path):
        if directory is None:
            return None
        path = os.path.join(directory, path)
    return os.path.normpath(path)
