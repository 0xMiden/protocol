"""Shared helpers: subprocess calls, JSON files and the tool's error type."""

from __future__ import annotations

import json
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

# The plugin root: scripts/skillbench/util.py -> scripts -> plugin root.
PLUGIN_ROOT = Path(__file__).resolve().parents[2]


class BenchError(RuntimeError):
    """A failure the user can act on. The CLI prints it without a traceback."""


def run(
    cmd: Sequence[str],
    *,
    cwd: str | Path | None = None,
    input: str | None = None,
    env: Mapping[str, str] | None = None,
    timeout: float | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run a command and capture its output as text.

    Raises `BenchError` when the command is missing, times out, or (with
    `check`) exits non-zero.
    """
    try:
        proc = subprocess.run(
            list(cmd),
            cwd=cwd,
            input=input,
            env=dict(env) if env is not None else None,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise BenchError(f"command not found: {cmd[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise BenchError(f"command timed out after {timeout}s: {_short(cmd)}") from exc
    if check and proc.returncode != 0:
        raise BenchError(
            f"command failed with exit code {proc.returncode}: {_short(cmd)}\n"
            f"{proc.stderr.strip()[:2000]}"
        )
    return proc


def _short(cmd: Sequence[str]) -> str:
    head = " ".join(cmd[:4])
    return head + (" ..." if len(cmd) > 4 else "")


def read_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path: str | Path, obj: Any) -> None:
    """Write JSON deterministically: sorted keys, two-space indent, trailing newline."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def read_jsonl(path: str | Path) -> list[Any]:
    """Read a JSON Lines file, skipping blank and malformed lines."""
    records = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records
