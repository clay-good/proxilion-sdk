"""
Mock-based tests for policy engines.

This test suite covers:
- OPAEngine: mock urllib.request.urlopen to return successful response, error response, health check
- CasbinEngine: mock casbin import to test behavior when casbin is and isn't available
"""

from __future__ import annotations

import json
from typing import Any
from unittest import mock

import pytest

from proxilion.engines.base import EngineNotAvailableError, PolicyEvaluationError
from proxilion.engines.casbin_engine import CasbinPolicyEngine
from proxilion.engines.opa_engine import OPAPolicyEngine
from proxilion.types import UserContext

# ============================================================================
# OPAEngine Tests with Mocked urllib
# ============================================================================


class TestOPAEngineMocked:
    """Test OPAPolicyEngine with mocked HTTP requests."""

    def test_successful_response_boolean_true(self) -> None:
        """OPA returning boolean true should allow."""
        user = UserContext(user_id="user_123", roles=["admin"])

        # Mock response
        mock_response = mock.MagicMock()
        mock_response.read.return_value = json.dumps({"result": True}).encode()
        mock_response.__enter__.return_value = mock_response

        with mock.patch("urllib.request.urlopen", return_value=mock_response):
            engine = OPAPolicyEngine(
                {
                    "opa_url": "http://localhost:8181",
                    "policy_path": "v1/data/proxilion/authz",
                }
            )

            result = engine.evaluate(user, "read", "document")

            assert result.allowed is True
            assert "allowed" in result.reason.lower()

    def test_successful_response_boolean_false(self) -> None:
        """OPA returning boolean false should deny."""
        user = UserContext(user_id="user_123", roles=["user"])

        # Mock response
        mock_response = mock.MagicMock()
        mock_response.read.return_value = json.dumps({"result": False}).encode()
        mock_response.__enter__.return_value = mock_response

        with mock.patch("urllib.request.urlopen", return_value=mock_response):
            engine = OPAPolicyEngine(
                {
                    "opa_url": "http://localhost:8181",
                }
            )

            result = engine.evaluate(user, "delete", "document")

            assert result.allowed is False
            assert "denied" in result.reason.lower()

    def test_successful_response_object_with_allow(self) -> None:
        """OPA returning object with allow field should parse correctly."""
        user = UserContext(user_id="user_123", roles=["editor"])

        # Mock response
        mock_response = mock.MagicMock()
        mock_response.read.return_value = json.dumps(
            {"result": {"allow": True, "reason": "User has editor role"}}
        ).encode()
        mock_response.__enter__.return_value = mock_response

        with mock.patch("urllib.request.urlopen", return_value=mock_response):
            engine = OPAPolicyEngine()

            result = engine.evaluate(user, "write", "document")

            assert result.allowed is True
            assert result.reason == "User has editor role"

    def test_successful_response_no_result(self) -> None:
        """OPA returning no result should deny."""
        user = UserContext(user_id="user_123", roles=[])

        # Mock response with no result field
        mock_response = mock.MagicMock()
        mock_response.read.return_value = json.dumps({}).encode()
        mock_response.__enter__.return_value = mock_response

        with mock.patch("urllib.request.urlopen", return_value=mock_response):
            engine = OPAPolicyEngine()

            result = engine.evaluate(user, "read", "document")

            assert result.allowed is False
            assert "no result" in result.reason.lower()

    def test_http_error_response(self) -> None:
        """HTTP error should raise PolicyEvaluationError."""
        user = UserContext(user_id="user_123", roles=[])

        import urllib.error

        # Mock HTTP error
        with mock.patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = urllib.error.HTTPError(
                url="http://localhost:8181",
                code=500,
                msg="Internal Server Error",
                hdrs={},
                fp=None,
            )

            engine = OPAPolicyEngine(
                {
                    "retry_count": 1,  # Reduce retries for faster test
                }
            )

            with pytest.raises(PolicyEvaluationError, match="OPA query failed"):
                engine.evaluate(user, "read", "document")

    def test_connection_error_response(self) -> None:
        """Connection error should raise PolicyEvaluationError."""
        user = UserContext(user_id="user_123", roles=[])

        import urllib.error

        # Mock URL error (connection failed)
        with mock.patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = urllib.error.URLError(reason="Connection refused")

            engine = OPAPolicyEngine(
                {
                    "retry_count": 1,
                }
            )

            with pytest.raises(PolicyEvaluationError, match="OPA query failed"):
                engine.evaluate(user, "read", "document")

    def test_fallback_allow_on_error(self) -> None:
        """With fallback_allow=True, errors should allow."""
        user = UserContext(user_id="user_123", roles=[])

        import urllib.error

        with mock.patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = urllib.error.URLError(reason="Connection refused")

            engine = OPAPolicyEngine(
                {
                    "retry_count": 1,
                    "fallback_allow": True,
                }
            )

            result = engine.evaluate(user, "read", "document")

            assert result.allowed is True
            assert "fallback" in result.reason.lower()

    def test_health_check_success(self) -> None:
        """Health check should return True when OPA is healthy."""
        mock_response = mock.MagicMock()
        mock_response.status = 200
        mock_response.__enter__.return_value = mock_response

        with mock.patch("urllib.request.urlopen", return_value=mock_response):
            engine = OPAPolicyEngine()
            assert engine.health_check() is True

    def test_health_check_failure(self) -> None:
        """Health check should return False when OPA is unreachable."""
        import urllib.error

        with mock.patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = urllib.error.URLError(reason="Connection refused")

            engine = OPAPolicyEngine()
            assert engine.health_check() is False

    def test_retry_mechanism(self) -> None:
        """Engine should retry on failures."""
        user = UserContext(user_id="user_123", roles=[])

        import urllib.error

        # Mock that fails twice then succeeds
        call_count = 0

        def side_effect(*args: Any, **kwargs: Any) -> Any:
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise urllib.error.URLError(reason="Temporary failure")

            mock_response = mock.MagicMock()
            mock_response.read.return_value = json.dumps({"result": True}).encode()
            mock_response.__enter__.return_value = mock_response
            return mock_response

        with mock.patch("urllib.request.urlopen", side_effect=side_effect):
            engine = OPAPolicyEngine(
                {
                    "retry_count": 3,
                    "retry_delay": 0.01,  # Fast retry for testing
                }
            )

            result = engine.evaluate(user, "read", "document")

            assert result.allowed is True
            assert call_count == 3


# ============================================================================
# CasbinEngine Tests with Mocked casbin Module
# ============================================================================


class TestCasbinEngineMocked:
    """Test CasbinPolicyEngine with mocked casbin import."""

    def test_casbin_not_available_raises(self) -> None:
        """When casbin is not installed, should raise EngineNotAvailableError."""
        # Temporarily set HAS_CASBIN to False
        from proxilion.engines import casbin_engine

        original_has_casbin = casbin_engine.HAS_CASBIN
        casbin_engine.HAS_CASBIN = False

        try:
            with pytest.raises(EngineNotAvailableError, match="Casbin is not installed"):
                CasbinPolicyEngine()
        finally:
            casbin_engine.HAS_CASBIN = original_has_casbin

    def test_casbin_available_initializes(self, tmp_path: Any) -> None:
        """When casbin is available, engine should initialize."""
        # This test requires casbin to be installed (optional dependency)
        try:
            import casbin  # noqa: F401
        except ImportError:
            pytest.skip("casbin not installed")

        # Create minimal model and policy files
        model_path = tmp_path / "model.conf"
        policy_path = tmp_path / "policy.csv"

        model_path.write_text("""
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
""")

        policy_path.write_text("""
p, alice, document, read
p, bob, document, write
""")

        engine = CasbinPolicyEngine(
            {
                "model_path": str(model_path),
                "policy_path": str(policy_path),
            }
        )

        assert engine._initialized is True
        assert engine.enforcer is not None

    def test_casbin_evaluate_with_mocked_enforcer(self) -> None:
        """Test evaluate with mocked casbin enforcer."""
        try:
            import casbin  # noqa: F401
        except ImportError:
            pytest.skip("casbin not installed")

        user = UserContext(user_id="alice", roles=["user"])

        # Create engine with mocked enforcer
        engine = CasbinPolicyEngine.__new__(CasbinPolicyEngine)
        engine._initialized = True
        engine._enforcer = mock.MagicMock()
        engine._enforcer.enforce.return_value = True

        result = engine.evaluate(user, "read", "document")

        assert result.allowed is True
        engine._enforcer.enforce.assert_called_once_with("alice", "document", "read")

    def test_casbin_evaluate_denied(self) -> None:
        """Test evaluate when casbin denies."""
        try:
            import casbin  # noqa: F401
        except ImportError:
            pytest.skip("casbin not installed")

        user = UserContext(user_id="bob", roles=["user"])

        # Create engine with mocked enforcer
        engine = CasbinPolicyEngine.__new__(CasbinPolicyEngine)
        engine._initialized = True
        engine._enforcer = mock.MagicMock()
        engine._enforcer.enforce.return_value = False

        result = engine.evaluate(user, "delete", "document")

        assert result.allowed is False
        assert "denied" in result.reason.lower()

    def test_casbin_add_policy(self) -> None:
        """Test adding policy dynamically."""
        try:
            import casbin  # noqa: F401
        except ImportError:
            pytest.skip("casbin not installed")

        engine = CasbinPolicyEngine.__new__(CasbinPolicyEngine)
        engine._initialized = True
        engine._enforcer = mock.MagicMock()
        engine._enforcer.add_policy.return_value = True

        result = engine.add_policy("alice", "resource", "action")

        assert result is True
        engine._enforcer.add_policy.assert_called_once_with("alice", "resource", "action")

    def test_casbin_get_roles_for_user(self) -> None:
        """Test getting roles for user."""
        try:
            import casbin  # noqa: F401
        except ImportError:
            pytest.skip("casbin not installed")

        engine = CasbinPolicyEngine.__new__(CasbinPolicyEngine)
        engine._initialized = True
        engine._enforcer = mock.MagicMock()
        engine._enforcer.get_roles_for_user.return_value = ["admin", "user"]

        roles = engine.get_roles_for_user("alice")

        assert roles == ["admin", "user"]
        engine._enforcer.get_roles_for_user.assert_called_once_with("alice")
