"""Aegis CLI entry point for installed package."""
from __future__ import annotations

import os
import sys
from pathlib import Path

# ── Source-tree / Docker path injection ──────────────────────────────────────
# When running from a git clone OR Docker WORKDIR /app, main.py lives at the
# project root. We must add that directory to sys.path so `from main import cli`
# works regardless of how the package was installed.
#
# Candidate roots in priority order:
#   1. AEGIS_PROJECT_DIR env-var (set by install.sh wrapper)
#   2. Parent of THIS file's parent (aegis/__main__.py → project root)
#   3. /app (Docker standard WORKDIR)
#   4. CWD

def _find_project_root() -> Path:
    """Return the directory that contains main.py."""
    # 1. Explicit env override
    env = os.environ.get("AEGIS_PROJECT_DIR", "")
    if env and (Path(env) / "main.py").exists():
        return Path(env)

    # 2. Relative to this file: aegis/__main__.py → go up two levels
    candidate = Path(__file__).resolve().parent.parent
    if (candidate / "main.py").exists():
        return candidate

    # 3. Docker /app
    if Path("/app/main.py").exists():
        return Path("/app")

    # 4. CWD
    if (Path.cwd() / "main.py").exists():
        return Path.cwd()

    return candidate  # best guess


_root = _find_project_root()

# Inject into sys.path (idempotent)
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

# ── Set AEGIS_PROJECT_DIR so ConfigManager + log paths resolve correctly ─────
if not os.environ.get("AEGIS_PROJECT_DIR"):
    # Walk up from __file__ to find where config/config.yaml lives
    for _parent in [_root] + list(Path(__file__).resolve().parents):
        if (_parent / "config" / "config.yaml").exists():
            os.environ["AEGIS_PROJECT_DIR"] = str(_parent)
            break
    else:
        os.environ["AEGIS_PROJECT_DIR"] = str(_root)

# ── Import and expose cli ─────────────────────────────────────────────────────
from main import cli  # noqa: E402

if __name__ == "__main__":
    cli()
