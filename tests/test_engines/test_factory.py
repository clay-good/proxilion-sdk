"""Tests for EngineFactory and base classes."""

from __future__ import annotations

import pytest

from proxilion.engines import (
    BasePolicyEngine,
    EngineCapabilities,
    EngineFactory,
    EngineNotAvailableError,
    PolicyEngine,
    PolicyEngineError,
    PolicyEvaluationError,
    PolicyLoadError,
    SimplePolicyEngine,
    create_engine,
)
from proxilion.types import AuthorizationResult


class TestEngineFactory:
    """Test EngineFactory."""

    def test_create_simple(self):
        engine = EngineFactory.create("simple")
        assert isinstance(engine, SimplePolicyEngine)
        assert engine.name == "simple"

    def test_create_simple_case_insensitive(self):
        engine = EngineFactory.create("SIMPLE")
        assert isinstance(engine, SimplePolicyEngine)

    def test_create_unknown_raises(self):
        with pytest.raises(EngineNotAvailableError, match="Unknown"):
            EngineFactory.create("nonexistent")

    def test_create_with_config(self):
        engine = EngineFactory.create(
            "simple",
            {"allow_missing_policies": False},
        )
        assert isinstance(engine, SimplePolicyEngine)
        assert engine.allow_missing_policies is False

    def test_get_available_engines(self):
        available = EngineFactory.get_available_engines()
        assert "simple" in available
        assert "opa" in available  # OPA is always listed

    def test_is_available(self):
        assert EngineFactory.is_available("simple") is True
        assert EngineFactory.is_available("opa") is True
        assert EngineFactory.is_available("nonexistent") is False

    def test_register_and_unregister(self):
        class DummyEngine(BasePolicyEngine):
            name = "dummy"

            def evaluate(
                self, user, action, resource, context=None
            ) -> AuthorizationResult:
                return AuthorizationResult(allowed=True, reason="dummy")

        EngineFactory.register("dummy", DummyEngine)
        assert EngineFactory.is_available("dummy") is True
        engine = EngineFactory.create("dummy")
        assert isinstance(engine, DummyEngine)

        assert EngineFactory.unregister("dummy") is True
        assert EngineFactory.is_available("dummy") is False

    def test_cannot_unregister_simple(self):
        assert EngineFactory.unregister("simple") is False


class TestCreateEngineConvenience:
    """Test create_engine convenience function."""

    def test_create_engine(self):
        engine = create_engine("simple")
        assert isinstance(engine, SimplePolicyEngine)

    def test_create_engine_default(self):
        engine = create_engine()
        assert isinstance(engine, SimplePolicyEngine)


class TestEngineCapabilities:
    """Test EngineCapabilities."""

    def test_defaults(self):
        caps = EngineCapabilities()
        assert caps.supports_async is True
        assert caps.supports_caching is False
        assert caps.supports_explain is False
        assert caps.max_batch_size == 1

    def test_custom(self):
        caps = EngineCapabilities(
            supports_async=False,
            supports_caching=True,
            max_batch_size=50,
        )
        assert caps.supports_async is False
        assert caps.supports_caching is True
        assert caps.max_batch_size == 50


class TestExceptions:
    """Test engine exceptions."""

    def test_policy_engine_error(self):
        err = PolicyEngineError("test error", engine_name="simple")
        assert "simple" in str(err)
        assert err.engine_name == "simple"

    def test_policy_load_error(self):
        err = PolicyLoadError("file not found", engine_name="casbin")
        assert isinstance(err, PolicyEngineError)
        assert "casbin" in str(err)

    def test_policy_evaluation_error(self):
        err = PolicyEvaluationError("timeout", engine_name="opa")
        assert isinstance(err, PolicyEngineError)

    def test_engine_not_available_error(self):
        err = EngineNotAvailableError("not installed", engine_name="casbin")
        assert isinstance(err, PolicyEngineError)


class TestBasePolicyEngine:
    """Test BasePolicyEngine abstract class."""

    def test_abstract_cannot_instantiate(self):
        with pytest.raises(TypeError):
            BasePolicyEngine()

    def test_get_config(self):
        class TestEngine(BasePolicyEngine):
            def evaluate(self, user, action, resource, context=None):
                return AuthorizationResult(allowed=True, reason="test")

        engine = TestEngine({"key": "value"})
        assert engine.get_config("key") == "value"
        assert engine.get_config("missing", "default") == "default"

    def test_load_policies_default(self):
        class TestEngine(BasePolicyEngine):
            def evaluate(self, user, action, resource, context=None):
                return AuthorizationResult(allowed=True, reason="test")

        engine = TestEngine()
        # Default does nothing, should not raise
        engine.load_policies("some/path")


class TestPolicyEngineProtocol:
    """Test PolicyEngine protocol."""

    def test_simple_engine_satisfies_protocol(self):
        engine = SimplePolicyEngine()
        assert isinstance(engine, PolicyEngine)
