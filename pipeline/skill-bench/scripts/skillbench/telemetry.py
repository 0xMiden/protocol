"""Extract skill exposure and loading from Claude Code session transcripts.

Claude Code writes each session to `<config dir>/projects/<project>/<id>.jsonl`
and subagent sessions to `<id>/subagents/*.jsonl`. This module reads:

* listed   - skill names in `skill_listing` attachments: what the model was shown
* invoked  - `Skill` tool calls: skills the model loaded on purpose
* read     - reads of files under the skills directory through `Read` or `Bash`
* searched - `Grep`/`Glob` calls aimed at the skills directory
* outside_paths - absolute paths outside the workspace that the reviewer
  read or named in a shell command (a leak audit; Claude Code's own
  session files under `internal_dirs` are not counted)

The record format is internal to Claude Code and can change between
versions; the version is recorded with every run for that reason.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .util import read_jsonl


def parse_session(
    transcript: Path,
    workspace: Path,
    skills_dir: str = ".claude/skills",
    ignore_files: tuple[str, ...] = (),
    internal_dirs: tuple[Path, ...] = (),
) -> dict[str, Any]:
    """Summarise one session and its subagent sessions."""
    acc = _Accumulator(workspace.resolve(), skills_dir.strip("/"), set(ignore_files), internal_dirs)
    acc.feed(read_jsonl(transcript))
    subagent_dir = transcript.with_suffix("") / "subagents"
    subagent_files = sorted(subagent_dir.glob("*.jsonl")) if subagent_dir.is_dir() else []
    for path in subagent_files:
        acc.feed(read_jsonl(path))
    summary = acc.summary()
    summary["subagent_transcripts"] = len(subagent_files)
    return summary


class _Accumulator:
    def __init__(self, workspace: Path, skills_dir: str, ignore: set[str], internal_dirs: tuple[Path, ...] = ()):
        self.workspace = workspace
        self.skills_dir = skills_dir
        self.ignore = ignore
        self.internal_dirs = tuple(Path(d).resolve() for d in internal_dirs)
        self.listed: list[str] = []
        self.invoked: list[str] = []
        self.read: set[str] = set()
        self.searched: set[str] = set()
        self.outside_paths: set[str] = set()
        self.tool_counts: dict[str, int] = {}
        self.skill_calls: dict[str, str] = {}  # tool_use id -> skill
        self.body_chars: dict[str, int] = {}
        self._mention = re.compile(re.escape(skills_dir) + r"/([^/\s'\"`]+)")

    def feed(self, records: list[Any]) -> None:
        for record in records:
            if not isinstance(record, dict):
                continue
            kind = record.get("type")
            if kind == "attachment":
                self._attachment(record.get("attachment") or {})
            elif kind == "assistant":
                for block in _content(record):
                    if block.get("type") == "tool_use":
                        self._tool_use(block)
            elif kind == "user" and record.get("isMeta") and record.get("sourceToolUseID") in self.skill_calls:
                skill = self.skill_calls[record["sourceToolUseID"]]
                text = "".join(b.get("text", "") for b in _content(record) if isinstance(b, dict))
                self.body_chars[skill] = max(self.body_chars.get(skill, 0), len(text))

    def _attachment(self, attachment: dict[str, Any]) -> None:
        if attachment.get("type") == "skill_listing":
            for name in attachment.get("names") or []:
                if name not in self.listed:
                    self.listed.append(name)

    def _tool_use(self, block: dict[str, Any]) -> None:
        name = block.get("name", "")
        params = block.get("input") or {}
        self.tool_counts[name] = self.tool_counts.get(name, 0) + 1
        if name == "Skill":
            skill = str(params.get("skill") or params.get("name") or "").lstrip("/")
            if skill:
                self.invoked.append(skill)
                if block.get("id"):
                    self.skill_calls[block["id"]] = skill
        elif name == "Read":
            self._path(str(params.get("file_path") or ""), self.read)
        elif name in ("Grep", "Glob"):
            self._path(str(params.get("path") or ""), self.searched)
            for mention in self._mention.findall(str(params.get("pattern") or "")):
                self.searched.add(mention)
        elif name == "Bash":
            command = str(params.get("command") or "")
            for mention in self._mention.findall(command):
                if not self._ignored(f"{self.skills_dir}/{mention}"):
                    self.read.add(mention)
            for token in _ABSOLUTE_PATH.findall(command):
                if token not in _HARMLESS_PATHS:
                    self._outside(Path(token), token)

    def _path(self, raw: str, bucket: set[str]) -> None:
        if not raw:
            return
        path = Path(raw)
        if not path.is_absolute():
            path = self.workspace / path
        try:
            rel = path.resolve().relative_to(self.workspace).as_posix()
        except ValueError:
            self._outside(path, raw)
            return
        prefix = self.skills_dir + "/"
        if rel.startswith(prefix) and not self._ignored(rel):
            bucket.add(rel[len(prefix) :].split("/", 1)[0])

    def _outside(self, path: Path, raw: str) -> None:
        resolved = path.resolve()
        if resolved == self.workspace or self.workspace in resolved.parents:
            return
        if any(resolved == d or d in resolved.parents for d in self.internal_dirs):
            return
        self.outside_paths.add(raw)

    def _ignored(self, rel: str) -> bool:
        """True for an ignored file itself, or a skill directory that contains one."""
        rel = rel.rstrip("/")
        return any(rel == f or f.startswith(rel + "/") for f in self.ignore)

    def summary(self) -> dict[str, Any]:
        return {
            "listed": self.listed,
            "invoked": sorted(set(self.invoked)),
            "invocations": len(self.invoked),
            "read": sorted(self.read),
            "searched": sorted(self.searched),
            "outside_paths": sorted(self.outside_paths),
            "tool_counts": dict(sorted(self.tool_counts.items())),
            "body_chars": dict(sorted(self.body_chars.items())),
        }


# An absolute path: a slash not preceded by a path, glob, variable or ref character.
_ABSOLUTE_PATH = re.compile(r"(?<![\w.~$/*:-])/(?:[\w.@+-]+/)*[\w.@+-]+")
_HARMLESS_PATHS = {"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/stdin"}


def _content(record: dict[str, Any]) -> list[dict[str, Any]]:
    content = (record.get("message") or {}).get("content")
    return [b for b in content if isinstance(b, dict)] if isinstance(content, list) else []


def check_exposure(
    listed: list[str], builtins: list[str], expected: list[str], has_skill_tool: bool
) -> dict[str, Any]:
    """Compare what the model was shown with what the arm should show.

    `builtins` are the skills Claude Code lists in an empty project; they are
    the same in every arm. Anything else that is listed but not expected
    leaked in from outside the snapshot and makes the run invalid. Expected
    skills missing from the listing were dropped (for example by the listing
    budget); they are reported, but do not invalidate the run.
    """
    expected_set = set(expected)
    if not has_skill_tool:
        leaked = sorted(listed)
        return {
            "valid": not leaked,
            "leaked": leaked,
            "missing": [],
            "problems": [f"skills were listed although the reviewer has no Skill tool: {', '.join(leaked)}"] if leaked else [],
        }
    project = set(listed) - (set(builtins) - expected_set)
    leaked = sorted(project - expected_set)
    missing = sorted(expected_set - project)
    return {
        "valid": not leaked,
        "leaked": leaked,
        "missing": missing,
        "problems": [f"skills from outside the snapshot were listed: {', '.join(leaked)}"] if leaked else [],
    }
