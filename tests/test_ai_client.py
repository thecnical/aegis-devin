"""Unit tests for AIClient — multi-provider edition."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from aegis.core.ai_client import AIClient
from aegis.core.config_manager import ConfigManager
from aegis.core.db_manager import DatabaseManager


def _make_client(
    db: DatabaseManager,
    groq_key: str = "CHANGE_ME",
    nvidia_key: str = "CHANGE_ME",
    bytez_key: str = "CHANGE_ME",
    openrouter_key: str = "CHANGE_ME",
    cloudflare_key: str = "CHANGE_ME",
    cloudflare_account: str = "CHANGE_ME",
) -> AIClient:
    cfg = MagicMock(spec=ConfigManager)
    cfg.get.side_effect = lambda path, default=None: {
        "api_keys.groq": groq_key,
        "api_keys.nvidia": nvidia_key,
        "api_keys.bytez": bytez_key,
        "api_keys.openrouter": openrouter_key,
        "api_keys.cloudflare": cloudflare_key,
        "api_keys.cloudflare_account_id": cloudflare_account,
    }.get(path, default)
    return AIClient(cfg, db)


def _mock_http_ok(content: str = "ok") -> MagicMock:
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"choices": [{"message": {"content": content}}]}
    mock_resp.raise_for_status = MagicMock()
    mock_http = MagicMock()
    mock_http.__enter__ = MagicMock(return_value=mock_http)
    mock_http.__exit__ = MagicMock(return_value=False)
    mock_http.post.return_value = mock_resp
    return mock_http


def test_all_models_fail_raises_runtime_error(db: DatabaseManager) -> None:
    """When no keys are configured, llm7 (no-key provider) is tried first.
    Force it to fail so we verify the error is propagated correctly."""
    client = _make_client(db)  # all CHANGE_ME

    with patch("httpx.Client") as mock_cls:
        mock_http = MagicMock()
        mock_http.__enter__ = MagicMock(return_value=mock_http)
        mock_http.__exit__ = MagicMock(return_value=False)
        mock_http.post.side_effect = Exception("connection refused")
        mock_cls.return_value = mock_http

        with pytest.raises(RuntimeError, match="All AI models exhausted"):
            client.complete("test prompt", "triage")


def test_groq_called_first_when_key_set(db: DatabaseManager) -> None:
    """Groq is highest priority when its key is configured."""
    client = _make_client(db, groq_key="gsk_real-groq-key")

    with patch("httpx.Client") as mock_cls:
        mock_http = _mock_http_ok("groq response")
        mock_cls.return_value = mock_http
        result = client.complete("hello", "triage")

    assert result == "groq response"
    call_url = mock_http.post.call_args[0][0]
    assert "groq.com" in call_url


def test_llm7_used_without_key(db: DatabaseManager) -> None:
    """llm7 works without any API key — should be tried even with all CHANGE_ME."""
    client = _make_client(db)  # all CHANGE_ME, but llm7 doesn't need a key

    with patch("httpx.Client") as mock_cls:
        mock_http = _mock_http_ok("llm7 response")
        mock_cls.return_value = mock_http
        result = client.complete("hello", "triage")

    assert result == "llm7 response"
    call_url = mock_http.post.call_args[0][0]
    assert "llm7.io" in call_url


def test_nvidia_called_when_key_set(db: DatabaseManager) -> None:
    """Nvidia is tried before llm7 when its key is configured."""
    client = _make_client(db, nvidia_key="nvapi-real-key")

    with patch("httpx.Client") as mock_cls:
        mock_http = _mock_http_ok("nvidia response")
        mock_cls.return_value = mock_http
        result = client.complete("hello", "triage")

    assert result == "nvidia response"
    call_url = mock_http.post.call_args[0][0]
    assert "nvidia.com" in call_url


def test_select_model_returns_groq_when_configured(db: DatabaseManager) -> None:
    client = _make_client(db, groq_key="gsk_real")
    model = client.select_model("triage")
    assert model.startswith("groq/")


def test_select_model_falls_back_to_llm7_no_keys(db: DatabaseManager) -> None:
    """Without any keys, llm7 (no-key) should be selected."""
    client = _make_client(db)
    model = client.select_model("triage")
    assert model.startswith("llm7/")


def test_prompt_does_not_contain_api_key(db: DatabaseManager) -> None:
    """The API key must never appear in the request body."""
    client = _make_client(db, groq_key="super-secret-groq-key-12345")

    with patch("httpx.Client") as mock_cls:
        mock_http = _mock_http_ok("response")
        mock_cls.return_value = mock_http
        client.complete("user prompt", "chat")

    call_kwargs = mock_http.post.call_args[1]
    body_str = str(call_kwargs.get("json", ""))
    assert "super-secret-groq-key-12345" not in body_str


def test_provider_status_reflects_configured_keys(db: DatabaseManager) -> None:
    client = _make_client(db, groq_key="gsk_real", nvidia_key="nvapi_real")
    status = client.provider_status()
    assert status["groq"]["key_set"] is True
    assert status["nvidia"]["key_set"] is True
    assert status["llm7"]["key_set"] is True   # always True (no key needed)
    assert status["bytez"]["key_set"] is False  # CHANGE_ME
