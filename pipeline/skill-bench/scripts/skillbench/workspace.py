"""Build sealed replay workspaces.

A workspace is a fresh git repository with exactly two commits: the base of
the change and the reviewed state. It has no remotes and no other history,
so a reviewer cannot see how the pull request continued. The project's
agent configuration (`.claude/`) is left out of both commits and placed back
untracked as the *snapshot* for one arm:

* `at-pr`     - `.claude/` as it was at the base commit
* `none`      - the same, without the skills directory (the control arm)
* `ref:<sha>` - the base `.claude/`, with the skills directory taken from <sha>

Settings that would run project code, load extra skills or widen what the
reviewer may do (hooks, plugins, credential and header helpers, environment
variables, MCP opt-ins, and every permission rule except `deny`) are removed
from the workspace settings.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tarfile
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import frontmatter
from .util import BenchError, read_json, run, write_json

BASE_MESSAGE = "Base of the change under review"
REVIEW_MESSAGE = "Change under review"
_FIXED_DATE = "2000-01-01T00:00:00+0000"
_SETTINGS_FILES = ("settings.json", "settings.local.json")
# Top-level settings that run commands, load extensions or change the environment.
_STRIPPED_SETTINGS = (
    "hooks",
    "statusLine",
    "enabledPlugins",
    "extraKnownMarketplaces",
    "apiKeyHelper",
    "awsAuthRefresh",
    "awsCredentialExport",
    "otelHeadersHelper",
    "env",
    "enableAllProjectMcpServers",
    "enabledMcpjsonServers",
)


def hermetic_git_env() -> dict[str, str]:
    """Environment for git commands on workspaces: no user or system config, fixed identity."""
    env = dict(os.environ)
    env.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_NAME": "skill-bench",
            "GIT_AUTHOR_EMAIL": "skill-bench@localhost",
            "GIT_COMMITTER_NAME": "skill-bench",
            "GIT_COMMITTER_EMAIL": "skill-bench@localhost",
            "GIT_AUTHOR_DATE": _FIXED_DATE,
            "GIT_COMMITTER_DATE": _FIXED_DATE,
        }
    )
    return env


def _git(*args: str, cwd: Path | None = None, env: dict[str, str] | None = None, check: bool = True) -> str:
    return run(["git", *args], cwd=cwd, env=env, timeout=600, check=check).stdout


@dataclass
class Arm:
    name: str
    kind: str  # "at-pr" | "none" | "ref"
    ref: str | None = None

    @property
    def slug(self) -> str:
        return f"ref-{self.ref[:12]}" if self.kind == "ref" and self.ref else self.kind

    @property
    def has_skills(self) -> bool:
        return self.kind != "none"


def parse_arm(text: str) -> Arm:
    text = text.strip()
    if text in ("at-pr", "none"):
        return Arm(name=text, kind=text)
    if text.startswith("ref:") and len(text) > 4:
        return Arm(name=text, kind="ref", ref=text[4:])
    raise BenchError(f"unknown arm '{text}' (expected at-pr, none or ref:<sha>)")


@dataclass
class Workspace:
    path: Path
    arm: Arm
    skills: list[dict[str, Any]] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    agents: dict[str, str] = field(default_factory=dict)
    deviations: list[str] = field(default_factory=list)

    def describe(self) -> dict[str, Any]:
        return {
            "arm": self.arm.name,
            "skills": [{k: v for k, v in s.items() if k != "body"} for s in self.skills],
            "commands": self.commands,
            "agents": sorted(self.agents),
            "deviations": self.deviations,
        }


# --- source repositories -------------------------------------------------


def has_commit(git_dir: Path, sha: str) -> bool:
    proc = run(["git", "-C", str(git_dir), "cat-file", "-e", f"{sha}^{{commit}}"], check=False, timeout=60)
    return proc.returncode == 0


def resolve_source(repo: str, shas: list[str], source_repo: str | None, cache_dir: Path) -> Path:
    """Find (or fetch) a git repository that contains every commit in `shas`.

    Tries an explicit `source_repo`, then the current checkout, then a bare
    mirror in `cache_dir` that fetches only the needed commits from GitHub.
    """
    candidates: list[Path] = []
    if source_repo:
        candidates.append(Path(source_repo))
    top = run(["git", "rev-parse", "--show-toplevel"], check=False, timeout=60)
    if top.returncode == 0 and top.stdout.strip():
        candidates.append(Path(top.stdout.strip()))
    for candidate in candidates:
        if all(has_commit(candidate, sha) for sha in shas):
            return candidate

    mirror = cache_dir / f"{repo.replace('/', '__')}.git"
    if not mirror.exists():
        mirror.parent.mkdir(parents=True, exist_ok=True)
        _git("init", "--bare", "-q", str(mirror))
    for sha in shas:
        if not has_commit(mirror, sha):
            _git("-C", str(mirror), "fetch", "--depth=1", "--no-tags", "-q", f"https://github.com/{repo}.git", sha)
    return mirror


def extract_tree(git_dir: Path, sha: str, dest: Path, path: str | None = None) -> bool:
    """Extract a commit's tree (or one path of it) into `dest`. Returns False if `path` is absent."""
    if path is not None:
        listed = run(["git", "-C", str(git_dir), "ls-tree", "--name-only", sha, path], timeout=60).stdout
        if not listed.strip():
            return False
    dest.mkdir(parents=True, exist_ok=True)
    cmd = ["git", "-C", str(git_dir), "archive", "--format=tar", sha] + ([path] if path else [])
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:
        assert proc.stdout is not None
        with tarfile.open(fileobj=proc.stdout, mode="r|") as archive:
            if hasattr(tarfile, "data_filter"):
                archive.extractall(dest, filter="data")
            else:  # Python < 3.12
                archive.extractall(dest)
        stderr = proc.stderr.read().decode() if proc.stderr else ""
    if proc.returncode != 0:
        raise BenchError(f"git archive {sha[:12]} failed: {stderr.strip()[:500]}")
    return True


def export_attribute_deviation(git_dir: Path, shas: list[str]) -> str | None:
    """`git archive` applies export-ignore and export-subst; say so when a tree uses them."""
    for sha in shas:
        proc = run(
            ["git", "-C", str(git_dir), "grep", "-l", "-E", "export-(ignore|subst)", sha, "--", ".gitattributes", "*/.gitattributes"],
            check=False,
            timeout=60,
        )
        if proc.stdout.strip():
            return "the repository sets export-ignore or export-subst attributes, so some files may be missing or rewritten in the replay"
    return None


# --- isolation -----------------------------------------------------------


def assert_isolated(path: Path) -> None:
    """Refuse a location where Claude Code would pick up context from a parent directory."""
    home = Path.home().resolve()
    for parent in path.resolve().parents:
        for marker in ("CLAUDE.md", "CLAUDE.local.md", ".git"):
            if (parent / marker).exists():
                raise BenchError(f"{path} is inside {parent}, which has {marker}; choose a work directory outside any project")
        if (parent / ".claude").is_dir() and parent != home:
            raise BenchError(f"{path} is inside {parent}, which has .claude/; choose a work directory outside any project")


def new_work_root(base: str | None = None) -> Path:
    root = Path(tempfile.mkdtemp(prefix="skill-bench-", dir=base))
    assert_isolated(root)
    return root


# --- building ------------------------------------------------------------


def build_template(source: Path, base_sha: str, review_sha: str, work_root: Path) -> Path:
    """Commit the base and review trees, without `.claude/`, into a fresh repository."""
    env = hermetic_git_env()
    base_dir = work_root / "base"
    template = work_root / "template"
    extract_tree(source, base_sha, base_dir)
    shutil.rmtree(base_dir / ".claude", ignore_errors=True)
    _git("init", "-q", "-b", "main", str(base_dir), env=env)
    # --force: every file came from a commit, so ignore rules must not drop any of them
    _git("add", "-A", "--force", cwd=base_dir, env=env)
    _git("commit", "-q", "--allow-empty", "--no-verify", "-m", BASE_MESSAGE, cwd=base_dir, env=env)

    extract_tree(source, review_sha, template)
    shutil.rmtree(template / ".claude", ignore_errors=True)
    shutil.move(str(base_dir / ".git"), str(template / ".git"))
    shutil.rmtree(base_dir)
    _git("add", "-A", "--force", cwd=template, env=env)
    _git("commit", "-q", "--allow-empty", "--no-verify", "-m", REVIEW_MESSAGE, cwd=template, env=env)
    with (template / ".git" / "info" / "exclude").open("a", encoding="utf-8") as exclude:
        exclude.write("/.claude/\n")
    return template


def materialize(
    template: Path,
    arm: Arm,
    source: Path,
    base_sha: str,
    work_root: Path,
    skills_dir: str = ".claude/skills",
) -> Workspace:
    """Copy the template for one arm and place that arm's `.claude/` snapshot in it."""
    dest = work_root / f"ws-{arm.slug}"
    shutil.copytree(template, dest, symlinks=True)
    ws = Workspace(path=dest, arm=arm)
    extract_tree(source, base_sha, dest, ".claude")
    skills_path = dest / skills_dir
    if arm.kind == "none":
        shutil.rmtree(skills_path, ignore_errors=True)
    elif arm.kind == "ref":
        assert arm.ref is not None
        shutil.rmtree(skills_path, ignore_errors=True)
        staging = work_root / f"ref-{arm.ref[:12]}"
        if not extract_tree(source, arm.ref, staging, skills_dir):
            raise BenchError(f"{arm.ref[:12]} has no {skills_dir}")
        shutil.move(str(staging / skills_dir), str(skills_path))
        shutil.rmtree(staging)
    ws.deviations.extend(strip_settings(dest))
    ws.skills = skill_catalog(dest, skills_dir)
    ws.commands = command_names(dest)
    ws.agents = agent_files(dest)
    return ws


def strip_settings(workspace: Path) -> list[str]:
    """Remove settings that could run code or widen permissions; keep `deny` rules."""
    deviations = []
    for name in _SETTINGS_FILES:
        path = workspace / ".claude" / name
        if not path.is_file():
            continue
        try:
            settings = read_json(path)
        except ValueError:
            path.unlink()
            deviations.append(f".claude/{name} was not valid JSON and was removed")
            continue
        removed = [key for key in _STRIPPED_SETTINGS if key in settings]
        for key in removed:
            settings.pop(key)
        permissions = settings.get("permissions")
        if isinstance(permissions, dict) and set(permissions) - {"deny"}:
            removed.append("permissions other than deny")
            kept = {"deny": permissions["deny"]} if "deny" in permissions else {}
            if kept:
                settings["permissions"] = kept
            else:
                settings.pop("permissions")
        elif "permissions" in settings and not isinstance(permissions, dict):
            settings.pop("permissions")
            removed.append("permissions")
        if removed:
            write_json(path, settings)
            deviations.append(f"removed {', '.join(removed)} from .claude/{name}")
    return deviations


def skill_catalog(workspace: Path, skills_dir: str = ".claude/skills") -> list[dict[str, Any]]:
    """The skills in a workspace: name, description, whether the model may invoke it, and body."""
    root = workspace / skills_dir
    skills = []
    if not root.is_dir():
        return skills
    for skill_file in sorted(root.glob("*/SKILL.md")):
        meta, body = frontmatter.parse(skill_file.read_text(encoding="utf-8"))
        skills.append(
            {
                "name": str(meta.get("name") or skill_file.parent.name),
                "dir": skill_file.parent.name,
                "description": str(meta.get("description") or ""),
                "model_invocable": meta.get("disable-model-invocation") is not True,
                "body": body.strip(),
                "body_chars": len(body.strip()),
            }
        )
    return skills


def command_names(workspace: Path) -> list[str]:
    """Project slash commands; Claude Code lists them to the model alongside skills."""
    root = workspace / ".claude" / "commands"
    if not root.is_dir():
        return []
    return sorted(str(p.relative_to(root).with_suffix("")).replace(os.sep, ":") for p in root.rglob("*.md"))


def agent_files(workspace: Path) -> dict[str, str]:
    """Project agents by name -> path relative to the workspace."""
    root = workspace / ".claude" / "agents"
    agents: dict[str, str] = {}
    if not root.is_dir():
        return agents
    for path in sorted(root.glob("*.md")):
        meta, _ = frontmatter.parse(path.read_text(encoding="utf-8"))
        agents[str(meta.get("name") or path.stem)] = str(path.relative_to(workspace))
    return agents
