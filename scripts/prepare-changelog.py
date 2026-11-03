#!/usr/bin/env python3
"""Moves the `.changelog/unreleased/` entries into `.changelog/<tag>/<PR>.md`, adding their PR links. The PR of
an entry is its file name if that is a number, and otherwise the `(#N)` that GitHub appends to the subject of
the squash commit that added the file. A file holding just the name of another entry adds its PR to the links
of that entry instead.
"""

import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

SRC = Path(".changelog/unreleased")
PR_URL = "https://github.com/0xMiden/protocol/pull"


def pr_of(path: Path) -> int:
    if path.stem.isdigit():
        return int(path.stem)
    log = ["git", "log", "--no-renames", "--diff-filter=A", "--format=%s", "--", str(path)]
    subject = subprocess.run(log, capture_output=True, text=True, check=True).stdout.partition("\n")[0]
    match = re.search(r"\(#(\d+)\)$", subject)
    if not match:
        sys.exit(f'No PR number in "{subject}", the commit that added {path}. Rename it to <PR number>.md.')
    return int(match[1])


def main() -> None:
    nested = [str(p) for p in SRC.rglob("*.md") if p.parent != SRC]
    if nested:
        sys.exit(f"Entries must be directly in {SRC}/, move or remove: {', '.join(nested)}")
    files = sorted(SRC.glob("*.md"))
    if not files:
        sys.exit(f"No changelog entries found in {SRC}/")
    prs = {f.stem: pr_of(f) for f in files}

    # Every entry collects its own PR and the PRs of the files referencing it.
    links = defaultdict(set)
    entries = []
    for f in files:
        target = f.read_text().strip()
        if target not in prs:
            target = f.stem
            entries.append(f)
        links[target].add(prs[f.stem])

    dst = Path(".changelog") / sys.argv[1]
    dst.mkdir(exist_ok=True)
    for f in entries:
        refs = ", ".join(f"[#{n}]({PR_URL}/{n})" for n in sorted(links[f.stem]))
        with open(dst / f"{prs[f.stem]}.md", "a") as out:
            for line in filter(None, f.read_text().splitlines()):
                out.write(f"- {line.removesuffix('.')} ({refs}).\n")

    subprocess.run(["git", "rm", "-q", *map(str, files)], check=True)
    subprocess.run(["git", "add", str(dst)], check=True)


if __name__ == "__main__":
    main()
