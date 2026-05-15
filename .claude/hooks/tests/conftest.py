"""Make the hook scripts importable from tests."""

import sys
from pathlib import Path

# Tests live in .claude/hooks/tests/; the modules under test live in
# .claude/hooks/. Add the parent dir to sys.path so `import _classify`
# and `import pre_push_review` work.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
