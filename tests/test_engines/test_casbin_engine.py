"""Tests for CasbinPolicyEngine."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from proxilion.engines.base import (
    EngineNotAvailableError,
    PolicyEvaluationError,
    PolicyLoadError,
)
from proxilion.types import AuthorizationResult, UserContext


@pytest.fixture()
def user() -> UserContext:
    return UserContext(
        user_id="alice",
        roles=["admin", "viewer"],
        session_id="sess-1",
        attributes={"department": "engineering"},
    )


@pytest.fixture()
def user_no_roles() -> UserContext:
    return UserContext(user_id="bob", roles=[])


@pytest.fixture()
def mock_casbin_module():
    mock_mod = MagicMock()
    mock_mod.Enforcer = MagicMock()
    return mock_mod


@pytest.fixture()
def engine(mock_casbin_module, tmp_path):
    model_file = tmp_path / "model.conf"
    policy_file = tmp_path / "policy.csv"
    model_file.write_text("[request_definition]\nr = sub, obj, act\n")
    policy_file.write_text("p, alice, document, read\n")

    with (
        patch.dict("sys.modules", {"casbin": mock_casbin_module}),
        patch("proxilion.engines.casbin_engine.HAS_CASBIN", True),
        patch("proxilion.engines.casbin_engine.casbin", mock_casbin_module),
    ):
        from proxilion.engines.casbin_engine import CasbinPolicyEngine

        eng = CasbinPolicyEngine(
            {
                "model_path": str(model_file),
                "policy_path": str(policy_file),
            }
        )
        yield eng


class TestHasCasbinFlag:
    """Test behavior when casbin is not installed."""

    def test_engine_raises_when_casbin_not_installed(self):
        with patch("proxilion.engines.casbin_engine.HAS_CASBIN", False):
            from proxilion.engines.casbin_engine import CasbinPolicyEngine

            with pytest.raises(EngineNotAvailableError, match="Casbin is not installed"):
                CasbinPolicyEngine()

    def test_error_message_includes_install_hint(self):
        with patch("proxilion.engines.casbin_engine.HAS_CASBIN", False):
            from proxilion.engines.casbin_engine import CasbinPolicyEngine

            with pytest.raises(EngineNotAvailableError, match="pip install proxilion"):
                CasbinPolicyEngine()


class TestCasbinEngineInit:
    """Test engine initialization."""

    def test_init_without_config_paths(self, mock_casbin_module):
        with (
            patch("proxilion.engines.casbin_engine.HAS_CASBIN", True),
            patch("proxilion.engines.casbin_engine.casbin", mock_casbin_module),
        ):
            from proxilion.engines.casbin_engine import CasbinPolicyEngine

            eng = CasbinPolicyEngine()
            assert eng._enforcer is None
            assert eng._model_path is None
            assert eng._policy_path is None

    def test_init_with_config_paths(self, mock_casbin_module, tmp_path):
        model_file = tmp_path / "model.conf"
        policy_file = tmp_path / "policy.csv"
        model_file.write_text("[request_definition]\n")
        policy_file.write_text("p, alice, doc, read\n")

        with (
            patch("proxilion.engines.casbin_engine.HAS_CASBIN", True),
            patch("proxilion.engines.casbin_engine.casbin", mock_casbin_module),
        ):
            from proxilion.engines.casbin_engine import CasbinPolicyEngine

            eng = CasbinPolicyEngine(
                {
                    "model_path": str(model_file),
                    "policy_path": str(policy_file),
                }
            )
            assert eng._enforcer is not None
            assert eng._initialized is True
            mock_casbin_module.Enforcer.assert_called_once_with(str(model_file), str(policy_file))

    def test_init_with_only_model_path_does_not_load(self, mock_casbin_module, tmp_path):
        model_file = tmp_path / "model.conf"
        model_file.write_text("[request_definition]\n")

        with (
            patch("proxilion.engines.casbin_engine.HAS_CASBIN", True),
            patch("proxilion.engines.casbin_engine.casbin", mock_casbin_module),
        ):
            from proxilion.engines.casbin_engine import CasbinPolicyEngine

            eng = CasbinPolicyEngine({"model_path": str(model_file)})
            assert eng._enforcer is None

    def test_name_attribute(self, engine):
        assert engine.name == "casbin"


class TestCapabilities:
    """Test engine capabilities."""

    def test_capabilities_values(self, engine):
        caps = engine.capabilities
        assert caps.supports_async is False
        assert caps.supports_caching is True
        assert caps.supports_explain is False
        assert caps.supports_partial_eval is False
        assert caps.supports_hot_reload is True
        assert caps.max_batch_size == 100


class TestEnforcerProperty:
    """Test the enforcer property."""

    def test_enforcer_returns_instance_when_set(self, engine):
        assert engine.enforcer is not None

    def test_enforcer_raises_when_not_initialized(self, mock_casbin_module):
        with (
            patch("proxilion.engines.casbin_engine.HAS_CASBIN", True),
            patch("proxilion.engines.casbin_engine.casbin", mock_casbin_module),
        ):
            from proxilion.engines.casbin_engine import CasbinPolicyEngine

            eng = CasbinPolicyEngine()
            with pytest.raises(PolicyLoadError, match="not initialized"):
                _ = eng.enforcer


class TestLoadPolicies:
    """Test the load_policies method."""

    def test_load_from_directory(self, mock_casbin_module, tmp_path):
        model_file = tmp_path / "model.conf"
        policy_file = tmp_path / "policy.csv"
        model_file.write_text("[request_definition]\n")
        policy_file.write_text("p, alice, doc, read\n")

        with (
            patch("proxilion.engines.casbin_engine.HAS_CASBIN", True),
            patch("proxilion.engines.casbin_engine.casbin", mock_casbin_module),
        ):
            from proxilion.engines.casbin_engine import CasbinPolicyEngine

            eng = CasbinPolicyEngine()
            eng.load_policies(tmp_path)
            assert eng._initialized is True

    def test_load_from_conf_file(self, mock_casbin_module, tmp_path):
        model_file = tmp_path / "model.conf"
        policy_file = tmp_path / "model.csv"
        model_file.write_text("[request_definition]\n")
        policy_file.write_text("p, alice, doc, read\n")

        with (
            patch("proxilion.engines.casbin_engine.HAS_CASBIN", True),
            patch("proxilion.engines.casbin_engine.casbin", mock_casbin_module),
        ):
            from proxilion.engines.casbin_engine import CasbinPolicyEngine

            eng = CasbinPolicyEngine()
            eng.load_policies(model_file)
            mock_casbin_module.Enforcer.assert_called_with(str(model_file), str(policy_file))

    def test_load_from_invalid_extension_raises(self, mock_casbin_module, tmp_path):
        bad_file = tmp_path / "policy.txt"
        bad_file.write_text("something")

        with (
            patch("proxilion.engines.casbin_engine.HAS_CASBIN", True),
            patch("proxilion.engines.casbin_engine.casbin", mock_casbin_module),
        ):
            from proxilion.engines.casbin_engine import CasbinPolicyEngine

            eng = CasbinPolicyEngine()
            with pytest.raises(PolicyLoadError, match="Invalid source"):
                eng.load_policies(bad_file)

    def test_load_from_string_path(self, mock_casbin_module, tmp_path):
        model_file = tmp_path / "model.conf"
        policy_file = tmp_path / "model.csv"
        model_file.write_text("[request_definition]\n")
        policy_file.write_text("p, alice, doc, read\n")

        with (
            patch("proxilion.engines.casbin_engine.HAS_CASBIN", True),
            patch("proxilion.engines.casbin_engine.casbin", mock_casbin_module),
        ):
            from proxilion.engines.casbin_engine import CasbinPolicyEngine

            eng = CasbinPolicyEngine()
            eng.load_policies(str(model_file))
            assert eng._initialized is True


class TestLoadPoliciesFromFiles:
    """Test the load_policies_from_files method."""

    def test_missing_model_file_raises(self, mock_casbin_module, tmp_path):
        policy_file = tmp_path / "policy.csv"
        policy_file.write_text("p, alice, doc, read\n")

        with (
            patch("proxilion.engines.casbin_engine.HAS_CASBIN", True),
            patch("proxilion.engines.casbin_engine.casbin", mock_casbin_module),
        ):
            from proxilion.engines.casbin_engine import CasbinPolicyEngine

            eng = CasbinPolicyEngine()
            with pytest.raises(PolicyLoadError, match="Model file not found"):
                eng.load_policies_from_files(tmp_path / "missing.conf", policy_file)

    def test_missing_policy_file_raises(self, mock_casbin_module, tmp_path):
        model_file = tmp_path / "model.conf"
        model_file.write_text("[request_definition]\n")

        with (
            patch("proxilion.engines.casbin_engine.HAS_CASBIN", True),
            patch("proxilion.engines.casbin_engine.casbin", mock_casbin_module),
        ):
            from proxilion.engines.casbin_engine import CasbinPolicyEngine

            eng = CasbinPolicyEngine()
            with pytest.raises(PolicyLoadError, match="Policy file not found"):
                eng.load_policies_from_files(model_file, tmp_path / "missing.csv")

    def test_enforcer_creation_failure_raises(self, mock_casbin_module, tmp_path):
        model_file = tmp_path / "model.conf"
        policy_file = tmp_path / "policy.csv"
        model_file.write_text("[request_definition]\n")
        policy_file.write_text("p, alice, doc, read\n")
        mock_casbin_module.Enforcer.side_effect = RuntimeError("bad model")

        with (
            patch("proxilion.engines.casbin_engine.HAS_CASBIN", True),
            patch("proxilion.engines.casbin_engine.casbin", mock_casbin_module),
        ):
            from proxilion.engines.casbin_engine import CasbinPolicyEngine

            eng = CasbinPolicyEngine()
            with pytest.raises(PolicyLoadError, match="Failed to initialize Casbin enforcer"):
                eng.load_policies_from_files(model_file, policy_file)

    def test_accepts_string_paths(self, mock_casbin_module, tmp_path):
        model_file = tmp_path / "model.conf"
        policy_file = tmp_path / "policy.csv"
        model_file.write_text("[request_definition]\n")
        policy_file.write_text("p, alice, doc, read\n")

        with (
            patch("proxilion.engines.casbin_engine.HAS_CASBIN", True),
            patch("proxilion.engines.casbin_engine.casbin", mock_casbin_module),
        ):
            from proxilion.engines.casbin_engine import CasbinPolicyEngine

            eng = CasbinPolicyEngine()
            eng.load_policies_from_files(str(model_file), str(policy_file))
            assert eng._model_path == model_file
            assert eng._policy_path == policy_file


class TestLoadPoliciesFromAdapter:
    """Test adapter-based policy loading."""

    def test_load_with_adapter(self, mock_casbin_module, tmp_path):
        model_file = tmp_path / "model.conf"
        model_file.write_text("[request_definition]\n")
        adapter = MagicMock()

        with (
            patch("proxilion.engines.casbin_engine.HAS_CASBIN", True),
            patch("proxilion.engines.casbin_engine.casbin", mock_casbin_module),
        ):
            from proxilion.engines.casbin_engine import CasbinPolicyEngine

            eng = CasbinPolicyEngine({"model_path": str(model_file)})
            mock_casbin_module.Enforcer.reset_mock()
            eng.load_policies_from_adapter(adapter)
            mock_casbin_module.Enforcer.assert_called_once_with(str(model_file), adapter)
            assert eng._initialized is True

    def test_load_adapter_without_model_path_raises(self, mock_casbin_module):
        with (
            patch("proxilion.engines.casbin_engine.HAS_CASBIN", True),
            patch("proxilion.engines.casbin_engine.casbin", mock_casbin_module),
        ):
            from proxilion.engines.casbin_engine import CasbinPolicyEngine

            eng = CasbinPolicyEngine()
            with pytest.raises(PolicyLoadError, match="model_path is required"):
                eng.load_policies_from_adapter(MagicMock())

    def test_adapter_enforcer_failure_raises(self, mock_casbin_module, tmp_path):
        model_file = tmp_path / "model.conf"
        model_file.write_text("[request_definition]\n")
        mock_casbin_module.Enforcer.side_effect = RuntimeError("adapter error")

        with (
            patch("proxilion.engines.casbin_engine.HAS_CASBIN", True),
            patch("proxilion.engines.casbin_engine.casbin", mock_casbin_module),
        ):
            from proxilion.engines.casbin_engine import CasbinPolicyEngine

            eng = CasbinPolicyEngine({"model_path": str(model_file)})
            match_msg = "Failed to initialize Casbin with adapter"
            with pytest.raises(PolicyLoadError, match=match_msg):
                eng.load_policies_from_adapter(MagicMock())


class TestEvaluate:
    """Test the evaluate method."""

    def test_allowed_result(self, engine, user):
        engine._enforcer.enforce.return_value = True
        result = engine.evaluate(user, "read", "document")

        assert isinstance(result, AuthorizationResult)
        assert result.allowed is True
        assert "allowed" in result.reason
        assert "alice" in result.reason
        assert "read" in result.reason
        assert "document" in result.reason
        assert result.policies_evaluated == ["casbin"]

    def test_denied_result(self, engine, user):
        engine._enforcer.enforce.return_value = False
        result = engine.evaluate(user, "write", "secret")

        assert result.allowed is False
        assert "denied" in result.reason
        assert "alice" in result.reason

    def test_enforce_called_with_correct_args(self, engine, user):
        engine._enforcer.enforce.return_value = True
        engine.evaluate(user, "delete", "record")
        engine._enforcer.enforce.assert_called_once_with("alice", "record", "delete")

    def test_context_parameter_accepted(self, engine, user):
        engine._enforcer.enforce.return_value = True
        result = engine.evaluate(user, "read", "doc", context={"extra": "data"})
        assert result.allowed is True

    def test_enforce_exception_raises_evaluation_error(self, engine, user):
        engine._enforcer.enforce.side_effect = Exception("casbin internal error")
        with pytest.raises(PolicyEvaluationError, match="Casbin evaluation failed"):
            engine.evaluate(user, "read", "doc")

    def test_enforcer_not_initialized_raises(self, mock_casbin_module, user):
        with (
            patch("proxilion.engines.casbin_engine.HAS_CASBIN", True),
            patch("proxilion.engines.casbin_engine.casbin", mock_casbin_module),
        ):
            from proxilion.engines.casbin_engine import CasbinPolicyEngine

            eng = CasbinPolicyEngine()
            with pytest.raises(PolicyEvaluationError, match="not initialized"):
                eng.evaluate(user, "read", "doc")


class TestEvaluateAsync:
    """Test async evaluation."""

    @pytest.mark.asyncio
    async def test_evaluate_async_delegates_to_sync(self, engine, user):
        engine._enforcer.enforce.return_value = True
        result = await engine.evaluate_async(user, "read", "document")
        assert result.allowed is True
        engine._enforcer.enforce.assert_called_once_with("alice", "document", "read")

    @pytest.mark.asyncio
    async def test_evaluate_async_denied(self, engine, user):
        engine._enforcer.enforce.return_value = False
        result = await engine.evaluate_async(user, "write", "secret")
        assert result.allowed is False


class TestEvaluateWithRoles:
    """Test role-based evaluation."""

    def test_allowed_by_user_id(self, engine, user):
        engine._enforcer.enforce.return_value = True
        result = engine.evaluate_with_roles(user, "read", "document")

        assert result.allowed is True
        assert "alice" in result.reason

    def test_denied_by_user_allowed_by_role(self, engine, user):
        engine._enforcer.enforce.side_effect = [False, True]
        result = engine.evaluate_with_roles(user, "read", "document")

        assert result.allowed is True
        assert "admin" in result.reason
        assert engine._enforcer.enforce.call_count == 2

    def test_denied_by_user_allowed_by_second_role(self, engine, user):
        engine._enforcer.enforce.side_effect = [False, False, True]
        result = engine.evaluate_with_roles(user, "read", "document")

        assert result.allowed is True
        assert "viewer" in result.reason

    def test_denied_by_all(self, engine, user):
        engine._enforcer.enforce.return_value = False
        result = engine.evaluate_with_roles(user, "write", "secret")

        assert result.allowed is False
        assert "denied" in result.reason
        assert "all roles" in result.reason

    def test_user_with_no_roles_denied(self, engine, user_no_roles):
        engine._enforcer.enforce.return_value = False
        result = engine.evaluate_with_roles(user_no_roles, "read", "doc")

        assert result.allowed is False
        assert "bob" in result.reason

    def test_role_enforce_exception_skips_role(self, engine, user):
        engine._enforcer.enforce.side_effect = [
            False,
            RuntimeError("role check failed"),
            True,
        ]
        result = engine.evaluate_with_roles(user, "read", "document")

        assert result.allowed is True
        assert "viewer" in result.reason

    def test_all_role_checks_fail_with_exceptions(self, engine, user):
        engine._enforcer.enforce.side_effect = [
            False,
            RuntimeError("error1"),
            RuntimeError("error2"),
        ]
        result = engine.evaluate_with_roles(user, "read", "document")

        assert result.allowed is False
        assert "all roles" in result.reason

    def test_user_evaluate_raises_propagates(self, engine, user):
        engine._enforcer.enforce.side_effect = Exception("fatal")
        with pytest.raises(PolicyEvaluationError):
            engine.evaluate_with_roles(user, "read", "doc")


class TestAddPolicy:
    """Test dynamic policy addition."""

    def test_add_policy_success(self, engine):
        engine._enforcer.add_policy.return_value = True
        assert engine.add_policy("bob", "document", "read") is True
        engine._enforcer.add_policy.assert_called_once_with("bob", "document", "read")

    def test_add_policy_already_exists(self, engine):
        engine._enforcer.add_policy.return_value = False
        assert engine.add_policy("bob", "document", "read") is False

    def test_add_policy_coerces_to_bool(self, engine):
        engine._enforcer.add_policy.return_value = 1
        result = engine.add_policy("bob", "document", "read")
        assert result is True
        assert isinstance(result, bool)


class TestRemovePolicy:
    """Test dynamic policy removal."""

    def test_remove_policy_success(self, engine):
        engine._enforcer.remove_policy.return_value = True
        assert engine.remove_policy("bob", "document", "read") is True
        engine._enforcer.remove_policy.assert_called_once_with("bob", "document", "read")

    def test_remove_nonexistent_policy(self, engine):
        engine._enforcer.remove_policy.return_value = False
        assert engine.remove_policy("bob", "document", "read") is False


class TestRoleManagement:
    """Test user-role management methods."""

    def test_add_role_for_user(self, engine):
        engine._enforcer.add_role_for_user.return_value = True
        assert engine.add_role_for_user("alice", "admin") is True
        engine._enforcer.add_role_for_user.assert_called_once_with("alice", "admin")

    def test_remove_role_for_user(self, engine):
        engine._enforcer.delete_role_for_user.return_value = True
        assert engine.remove_role_for_user("alice", "admin") is True
        engine._enforcer.delete_role_for_user.assert_called_once_with("alice", "admin")

    def test_get_roles_for_user(self, engine):
        engine._enforcer.get_roles_for_user.return_value = ["admin", "viewer"]
        roles = engine.get_roles_for_user("alice")
        assert roles == ["admin", "viewer"]
        assert isinstance(roles, list)
        engine._enforcer.get_roles_for_user.assert_called_once_with("alice")

    def test_get_roles_empty(self, engine):
        engine._enforcer.get_roles_for_user.return_value = []
        assert engine.get_roles_for_user("nobody") == []

    def test_add_role_coerces_to_bool(self, engine):
        engine._enforcer.add_role_for_user.return_value = 1
        result = engine.add_role_for_user("alice", "admin")
        assert result is True
        assert isinstance(result, bool)

    def test_remove_role_coerces_to_bool(self, engine):
        engine._enforcer.delete_role_for_user.return_value = 0
        result = engine.remove_role_for_user("alice", "admin")
        assert result is False
        assert isinstance(result, bool)


class TestReloadAndSavePolicies:
    """Test policy reload and save."""

    def test_reload_policies(self, engine):
        engine.reload_policies()
        engine._enforcer.load_policy.assert_called_once()

    def test_reload_policies_no_enforcer(self, mock_casbin_module):
        with (
            patch("proxilion.engines.casbin_engine.HAS_CASBIN", True),
            patch("proxilion.engines.casbin_engine.casbin", mock_casbin_module),
        ):
            from proxilion.engines.casbin_engine import CasbinPolicyEngine

            eng = CasbinPolicyEngine()
            eng.reload_policies()

    def test_save_policies(self, engine):
        engine.save_policies()
        engine._enforcer.save_policy.assert_called_once()

    def test_save_policies_no_enforcer(self, mock_casbin_module):
        with (
            patch("proxilion.engines.casbin_engine.HAS_CASBIN", True),
            patch("proxilion.engines.casbin_engine.casbin", mock_casbin_module),
        ):
            from proxilion.engines.casbin_engine import CasbinPolicyEngine

            eng = CasbinPolicyEngine()
            eng.save_policies()


class TestInheritedBehavior:
    """Test behavior inherited from BasePolicyEngine."""

    def test_is_initialized_false_by_default(self, mock_casbin_module):
        with (
            patch("proxilion.engines.casbin_engine.HAS_CASBIN", True),
            patch("proxilion.engines.casbin_engine.casbin", mock_casbin_module),
        ):
            from proxilion.engines.casbin_engine import CasbinPolicyEngine

            eng = CasbinPolicyEngine()
            assert eng.is_initialized() is False

    def test_is_initialized_true_after_load(self, engine):
        assert engine.is_initialized() is True

    def test_get_config(self, engine):
        assert engine.get_config("model_path") is not None
        assert engine.get_config("nonexistent") is None
        assert engine.get_config("nonexistent", "default") == "default"

    def test_config_defaults_to_empty_dict(self, mock_casbin_module):
        with (
            patch("proxilion.engines.casbin_engine.HAS_CASBIN", True),
            patch("proxilion.engines.casbin_engine.casbin", mock_casbin_module),
        ):
            from proxilion.engines.casbin_engine import CasbinPolicyEngine

            eng = CasbinPolicyEngine()
            assert eng.config == {}
