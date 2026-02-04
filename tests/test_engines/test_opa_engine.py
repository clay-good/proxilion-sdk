"""Tests for OPAPolicyEngine."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from proxilion.engines.base import PolicyEvaluationError
from proxilion.engines.opa_engine import OPAPolicyEngine
from proxilion.types import UserContext


@pytest.fixture()
def user() -> UserContext:
    return UserContext(
        user_id="alice",
        roles=["analyst"],
        session_id="sess-1",
        attributes={"department": "engineering"},
    )


@pytest.fixture()
def engine() -> OPAPolicyEngine:
    return OPAPolicyEngine({
        "opa_url": "http://localhost:8181",
        "policy_path": "v1/data/proxilion/authz",
        "retry_count": 1,
        "retry_delay": 0.0,
    })


class TestOPAEngineInit:
    """Test OPA engine initialization."""

    def test_default_config(self):
        eng = OPAPolicyEngine()
        assert eng.opa_url == "http://localhost:8181"
        assert eng.policy_path == "v1/data/proxilion/authz"
        assert eng.timeout == 5.0
        assert eng.retry_count == 3
        assert eng.fallback_allow is False
        assert eng.is_initialized()

    def test_custom_config(self):
        eng = OPAPolicyEngine({
            "opa_url": "http://opa:9999",
            "policy_path": "v1/data/myapp",
            "timeout": 10.0,
            "fallback_allow": True,
        })
        assert eng.opa_url == "http://opa:9999"
        assert eng.timeout == 10.0
        assert eng.fallback_allow is True

    def test_capabilities(self, engine: OPAPolicyEngine):
        caps = engine.capabilities
        assert caps.supports_async is True
        assert caps.supports_explain is True
        assert caps.supports_partial_eval is True
        assert caps.supports_hot_reload is True


class TestOPAEngineBuildInput:
    """Test OPA input document construction."""

    def test_build_input(self, engine: OPAPolicyEngine, user: UserContext):
        input_doc = engine._build_input(user, "read", "document", None)
        assert "input" in input_doc
        inp = input_doc["input"]
        assert inp["user"]["user_id"] == "alice"
        assert inp["user"]["roles"] == ["analyst"]
        assert inp["action"] == "read"
        assert inp["resource"] == "document"
        assert inp["context"] == {}

    def test_build_input_with_context(
        self, engine: OPAPolicyEngine, user: UserContext
    ):
        ctx = {"ip": "10.0.0.1"}
        input_doc = engine._build_input(user, "write", "db", ctx)
        assert input_doc["input"]["context"] == {"ip": "10.0.0.1"}


class TestOPAEngineParseResponse:
    """Test OPA response parsing."""

    def test_boolean_true(self, engine: OPAPolicyEngine, user: UserContext):
        result = engine._parse_opa_response(
            {"result": True}, user, "read", "doc"
        )
        assert result.allowed is True
        assert "allowed" in result.reason

    def test_boolean_false(self, engine: OPAPolicyEngine, user: UserContext):
        result = engine._parse_opa_response(
            {"result": False}, user, "write", "doc"
        )
        assert result.allowed is False

    def test_dict_allow(self, engine: OPAPolicyEngine, user: UserContext):
        result = engine._parse_opa_response(
            {"result": {"allow": True, "reason": "Role match"}},
            user, "read", "doc",
        )
        assert result.allowed is True
        assert result.reason == "Role match"

    def test_dict_deny_with_reasons(
        self, engine: OPAPolicyEngine, user: UserContext
    ):
        result = engine._parse_opa_response(
            {"result": {"allow": False, "deny": ["no role", "no scope"]}},
            user, "write", "doc",
        )
        assert result.allowed is False
        assert "no role" in result.reason
        assert "no scope" in result.reason

    def test_none_result(self, engine: OPAPolicyEngine, user: UserContext):
        result = engine._parse_opa_response(
            {}, user, "read", "doc"
        )
        assert result.allowed is False
        assert "undefined" in result.reason

    def test_unexpected_format(
        self, engine: OPAPolicyEngine, user: UserContext
    ):
        result = engine._parse_opa_response(
            {"result": 42}, user, "read", "doc"
        )
        assert result.allowed is False
        assert "Unexpected" in result.reason


class TestOPAEngineEvaluate:
    """Test OPA evaluation with mocked HTTP."""

    def test_evaluate_success(
        self, engine: OPAPolicyEngine, user: UserContext
    ):
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(
            {"result": True}
        ).encode()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_response.status = 200

        with patch("urllib.request.urlopen", return_value=mock_response):
            result = engine.evaluate(user, "read", "document")
        assert result.allowed is True

    def test_evaluate_failure_raises(
        self, engine: OPAPolicyEngine, user: UserContext
    ):
        import urllib.error

        error = urllib.error.URLError("Connection refused")

        with (
            patch("urllib.request.urlopen", side_effect=error),
            pytest.raises(PolicyEvaluationError, match="failed"),
        ):
            engine.evaluate(user, "read", "document")

    def test_evaluate_fallback_allow(self, user: UserContext):
        eng = OPAPolicyEngine({
            "fallback_allow": True,
            "retry_count": 1,
            "retry_delay": 0.0,
        })
        import urllib.error
        error = urllib.error.URLError("Connection refused")

        with patch("urllib.request.urlopen", side_effect=error):
            result = eng.evaluate(user, "read", "document")
        assert result.allowed is True
        assert "fallback" in result.reason

    def test_health_check_success(self, engine: OPAPolicyEngine):
        mock_response = MagicMock()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_response.status = 200

        with patch("urllib.request.urlopen", return_value=mock_response):
            assert engine.health_check() is True

    def test_health_check_failure(self, engine: OPAPolicyEngine):
        with patch("urllib.request.urlopen", side_effect=Exception("fail")):
            assert engine.health_check() is False

    def test_get_decision_id(self, engine: OPAPolicyEngine):
        assert engine.get_decision_id(
            {"decision_id": "abc-123"}
        ) == "abc-123"
        assert engine.get_decision_id({}) is None
