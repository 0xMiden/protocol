"""Role definitions and output schemas.

Each LLM step runs as its own headless Claude Code session. A role is an
agent definition file (frontmatter plus prompt) under `roles/`; it is passed
to `claude` as `--agents` JSON rather than by loading this plugin, so the
plugin's own skill can never appear in a replay's skill listing.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from . import frontmatter
from .util import PLUGIN_ROOT, BenchError

ROLES_DIR = PLUGIN_ROOT / "roles"
SCHEMAS_DIR = PLUGIN_ROOT / "schemas"


@dataclass
class Role:
    name: str
    description: str
    prompt: str
    tools: list[str] | None = None  # None: the agent inherits the session's tools
    model: str | None = None


def load_agent_file(path: Path) -> Role:
    if not path.is_file():
        raise BenchError(f"agent definition not found: {path}")
    meta, body = frontmatter.parse(path.read_text(encoding="utf-8"))
    tools = frontmatter.as_list(meta["tools"]) if "tools" in meta else None
    model = meta.get("model")
    return Role(
        name=str(meta.get("name") or path.stem),
        description=str(meta.get("description") or path.stem),
        prompt=body.strip(),
        tools=tools,
        model=str(model) if model else None,
    )


def load_role(name: str) -> Role:
    return load_agent_file(ROLES_DIR / f"{name}.md")


def agents_json(role: Role, *, name: str | None = None, add_tools: tuple[str, ...] = ()) -> str:
    """Render a role as the JSON object `claude --agents` expects."""
    spec: dict[str, object] = {"description": role.description, "prompt": role.prompt}
    if role.tools is not None:
        spec["tools"] = role.tools + [t for t in add_tools if t not in role.tools]
    return json.dumps({name or role.name: spec})


def load_schema(name: str) -> str:
    path = SCHEMAS_DIR / f"{name}.json"
    if not path.is_file():
        raise BenchError(f"schema not found: {path}")
    return json.dumps(json.loads(path.read_text(encoding="utf-8")), separators=(",", ":"))
