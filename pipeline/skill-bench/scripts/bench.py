#!/usr/bin/env python3
"""Command-line entry point for skill-bench. See `bench.py --help`."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from skillbench.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
