"""Integration tests for Phase 1 setup/profile/ai UX."""
from __future__ import annotations

from click.testing import CliRunner
import yaml

from main import cli


def test_setup_wizard_adds_profiles_and_ai_defaults(tmp_path) -> None:
    runner = CliRunner()
    db_path = str(tmp_path / "test.db")
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        (
            "general:\n"
            f"  db_path: {db_path}\n"
            "  safe_mode: true\n"
            "api_keys:\n"
            "  bytez: CHANGE_ME\n"
            "  openrouter: CHANGE_ME\n"
            "profiles:\n"
            "  default:\n"
            "    timeout: 30\n"
        ),
        encoding="utf-8",
    )

    user_input = "\n".join(
        [
            "y",           # safe_mode
            "45",          # default timeout
            "team-one",    # workspace
            "web-fast",    # default profile
            "n",           # run AI onboarding now?
        ]
    ) + "\n"
    result = runner.invoke(cli, ["--config", str(cfg), "setup", "--wizard"], input=user_input)
    assert result.exit_code == 0, result.output

    loaded = yaml.safe_load(cfg.read_text(encoding="utf-8"))
    assert "web-fast" in loaded["profiles"]
    assert "web-deep" in loaded["profiles"]
    assert "api-deep" in loaded["profiles"]
    assert loaded["general"]["workspace"] == "team-one"
    assert loaded["ai"]["default_profile"] == "web-fast"


def test_ai_doctor_strict_fails_without_providers(tmp_path) -> None:
    runner = CliRunner()
    db_path = str(tmp_path / "test.db")
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        (
            "general:\n"
            f"  db_path: {db_path}\n"
            "  safe_mode: false\n"
            "api_keys:\n"
            "  bytez: CHANGE_ME\n"
            "  openrouter: CHANGE_ME\n"
            "profiles:\n"
            "  default:\n"
            "    timeout: 30\n"
        ),
        encoding="utf-8",
    )
    result = runner.invoke(cli, ["--config", str(cfg), "ai", "doctor", "--strict"])
    assert result.exit_code != 0

