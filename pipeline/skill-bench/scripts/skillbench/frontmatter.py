"""Parse the YAML frontmatter of SKILL.md and agent files.

Covers the subset these files use: `key: value` scalars (quoted or bare),
booleans, inline `[a, b]` lists, `- item` lists, and `>` / `|` block scalars.
Anything else is kept as a plain string.
"""

from __future__ import annotations

from typing import Any

_BLOCK_MARKERS = (">", "|", ">-", "|-", ">+", "|+")


def parse(text: str) -> tuple[dict[str, Any], str]:
    """Split a document into (frontmatter, body). Without frontmatter the dict is empty."""
    lines = text.splitlines(keepends=True)
    if not lines or lines[0].strip() != "---":
        return {}, text
    end = next((i for i in range(1, len(lines)) if lines[i].strip() == "---"), None)
    if end is None:
        return {}, text
    return _parse_header([line.rstrip("\n") for line in lines[1:end]]), "".join(lines[end + 1 :])


def _parse_header(lines: list[str]) -> dict[str, Any]:
    data: dict[str, Any] = {}
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line.strip() or line.lstrip().startswith("#") or line[0] in " \t":
            i += 1
            continue
        key, sep, value = line.partition(":")
        if not sep:
            i += 1
            continue
        key, value = key.strip(), value.strip()
        i += 1
        if value in _BLOCK_MARKERS:
            block = []
            while i < len(lines) and (not lines[i].strip() or lines[i][0] in " \t"):
                block.append(lines[i].strip())
                i += 1
            joiner = " " if value.startswith(">") else "\n"
            data[key] = joiner.join(part for part in block if part)
        elif value == "":
            items = []
            while i < len(lines) and lines[i].lstrip().startswith("- "):
                items.append(_scalar(lines[i].lstrip()[2:].strip()))
                i += 1
            data[key] = items if items else ""
        else:
            data[key] = _scalar(value)
    return data


def _scalar(value: str) -> Any:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    lowered = value.lower()
    if lowered in ("true", "yes"):
        return True
    if lowered in ("false", "no"):
        return False
    if value.startswith("[") and value.endswith("]"):
        return [_scalar(part.strip()) for part in value[1:-1].split(",") if part.strip()]
    return value


def as_list(value: Any) -> list[str]:
    """Normalise a tools-style field (`Read, Grep`, `[Read, Grep]` or a list) to a list."""
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    return []
