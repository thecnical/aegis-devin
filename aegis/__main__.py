"""Aegis CLI entry point for installed package."""
from __future__ import annotations

import os
import sys
from pathlib import Path

# ── Source-tree shim ──────────────────────────────────────────────────────────
# When running from the cloned repo (python -m aegis or .venv/bin/aegis),
# main.py lives one level up from this file.  Insert that directory so the
# bare `from main import cli` below keeps working.
_repo_root = Path(__file__).parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

# ── Install-location config resolution ───────────────────────────────────────
# When aegis is installed (pip / install.sh) and the user runs it from any
# directory, we inject AEGIS_PROJECT_DIR so ConfigManager can find the
# config/config.yaml that lives next to the original source tree.
# Priority: env-var override > script-parent heuristic > CWD
if not os.environ.get("AEGIS_PROJECT_DIR"):
    # __file__ is .../site-packages/aegis/__main__.py  OR  .../aegis/__main__.py
    # Walk up until we find a directory that has config/config.yaml
    _candidate = Path(__file__).resolve().parent.parent  # repo root when in-tree
    if (_candidate / "config" / "config.yaml").exists():
        os.environ["AEGIS_PROJECT_DIR"] = str(_candidate)
    else:
        # Installed package: look for the project dir adjacent to the venv
        # e.g. /home/user/Desktop/test_tool/aegis/.venv -> /home/user/Desktop/test_tool/aegis
        for _parent in Path(__file__).resolve().parents:
            if (_parent / "config" / "config.yaml").exists():
                os.environ["AEGIS_PROJECT_DIR"] = str(_parent)
                break

from main import cli  # noqa: E402

if __name__ == "__main__":
    cli()
