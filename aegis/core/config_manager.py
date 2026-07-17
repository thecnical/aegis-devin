from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict

import yaml
from aegis.core.ui import console

# Default config bundled with the package (used when no file exists yet)
_BUILTIN_CONFIG = Path(__file__).resolve().parent.parent.parent / "config" / "config.yaml"


class ConfigManager:
    """Loads and stores YAML configuration.

    Path resolution order for a relative config_path:
    1. As-is (respects CWD — legacy behaviour)
    2. Relative to AEGIS_PROJECT_DIR env-var (set by __main__.py)
    3. Relative to the directory that contains this file's package root
    """

    def __init__(self, config_path: str) -> None:
        raw = Path(config_path)
        if raw.is_absolute():
            self.config_path = raw
        else:
            # Try AEGIS_PROJECT_DIR first (injected by __main__.py at startup)
            env_dir = os.environ.get("AEGIS_PROJECT_DIR", "")
            if env_dir and (Path(env_dir) / config_path).exists():
                self.config_path = Path(env_dir) / config_path
            elif raw.exists():
                self.config_path = raw.resolve()
            elif _BUILTIN_CONFIG.exists():
                # Installed package: config lives next to pyproject.toml
                self.config_path = _BUILTIN_CONFIG
            else:
                # Last resort: keep relative (will print "not found" on load)
                self.config_path = raw
        self._config: Dict[str, Any] = {}

    def load(self) -> Dict[str, Any]:
        if not self.config_path.exists():
            # Only warn once to avoid spamming the console on every get() call
            if not getattr(self, "_missing_warned", False):
                console.print(
                    f"[bold yellow]Config not found:[/bold yellow] {self.config_path}\n"
                    "  Run [cyan]aegis setup --wizard[/cyan] or [cyan]aegis configure-keys --interactive[/cyan] to create one."
                )
                object.__setattr__(self, "_missing_warned", True)
            self._config = {}
            return self._config
        try:
            with self.config_path.open("r", encoding="utf-8") as handle:
                self._config = yaml.safe_load(handle) or {}
        except (OSError, yaml.YAMLError) as exc:
            console.print(f"[bold red]Failed to load config:[/bold red] {exc}")
            self._config = {}
        return self._config

    def get(self, path: str, default: Any = None) -> Any:
        if not self._config and not getattr(self, "_missing_warned", False):
            self.load()
        current: Any = self._config
        for key in path.split("."):
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return default
        return current

    def save(self, data: Dict[str, Any] | None = None) -> None:
        payload = data if data is not None else self._config
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self.config_path.with_suffix(f"{self.config_path.suffix}.tmp")
        with tmp_path.open("w", encoding="utf-8") as handle:
            yaml.safe_dump(payload, handle, sort_keys=False)
        tmp_path.replace(self.config_path)
        self._config = payload

    def set(self, path: str, value: Any) -> None:
        """Set a dotted-path config value, creating intermediate dicts."""
        if not self._config:
            self.load()
        keys = path.split(".")
        current: Dict[str, Any] = self._config
        for key in keys[:-1]:
            child = current.get(key)
            if not isinstance(child, dict):
                child = {}
                current[key] = child
            current = child
        current[keys[-1]] = value
