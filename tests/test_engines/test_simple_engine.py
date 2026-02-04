"""Tests for SimplePolicyEngine."""

from __future__ import annotations

import pytest

from proxilion.engines.simple import SimplePolicyEngine
from proxilion.policies.base import Policy
from proxilion.policies.registry import PolicyRegistry
from proxilion.types import UserContext


@pytest.fixture()
def engine() -> SimplePolicyEngine:
    """Create a SimplePolicyEngine for testing."""
    return SimplePolicyEngine()


@pytest.fixture()
def admin_user() -> UserContext:
    return UserContext(user_id="admin_1", roles=["admin"])


@pytest.fixture()
def basic_user() -> UserContext:
    return UserContext(user_id="user_1", roles=["user"])


@pytest.fixture()
def analyst_user() -> UserContext:
    return UserContext(user_id="analyst_1", roles=["analyst"])


class TestSimplePolicyEngineInit:
    """Test SimplePolicyEngine initialization."""

    def test_default_init(self):
        engine = SimplePolicyEngine()
        assert engine.name == "simple"
        assert engine.is_initialized()
        assert engine.allow_missing_policies is True
        assert isinstance(engine.registry, PolicyRegistry)

    def test_init_with_config(self):
        engine = SimplePolicyEngine(
            config={"allow_missing_policies": False}
        )
        assert engine.allow_missing_policies is False

    def test_init_with_registry(self):
        registry = PolicyRegistry()
        engine = SimplePolicyEngine(registry=registry)
        assert engine.registry is registry

    def test_capabilities(self, engine: SimplePolicyEngine):
        caps = engine.capabilities
        assert caps.supports_async is True
        assert caps.supports_explain is True
        assert caps.supports_hot_reload is True
        assert caps.max_batch_size == 100


class TestSimplePolicyEngineEvaluate:
    """Test SimplePolicyEngine evaluation."""

    def test_deny_when_no_policy(
        self, engine: SimplePolicyEngine, basic_user: UserContext
    ):
        result = engine.evaluate(basic_user, "read", "unknown_resource")
        assert result.allowed is False
        # Default DenyAllPolicy is used for unregistered resources
        assert "denied" in result.reason.lower()

    def test_policy_class_evaluation(
        self,
        engine: SimplePolicyEngine,
        admin_user: UserContext,
        basic_user: UserContext,
    ):
        @engine.policy("document")
        class DocumentPolicy(Policy):
            def can_read(self, context: dict) -> bool:
                return True

            def can_write(self, context: dict) -> bool:
                return "admin" in self.user.roles

        # Both users can read
        assert engine.evaluate(admin_user, "read", "document").allowed is True
        assert engine.evaluate(basic_user, "read", "document").allowed is True

        # Only admin can write
        assert engine.evaluate(admin_user, "write", "document").allowed is True
        assert engine.evaluate(basic_user, "write", "document").allowed is False

    def test_dict_rules_override(
        self, engine: SimplePolicyEngine, basic_user: UserContext
    ):
        engine.add_rule("api", "execute", ["user", "admin"])
        result = engine.evaluate(basic_user, "execute", "api")
        assert result.allowed is True
        assert "Dictionary rule" in result.reason

    def test_dict_rules_deny(
        self, engine: SimplePolicyEngine, basic_user: UserContext
    ):
        engine.add_rule("api", "configure", ["admin"])
        result = engine.evaluate(basic_user, "configure", "api")
        assert result.allowed is False

    def test_dict_rules_no_match_falls_to_policy(
        self,
        engine: SimplePolicyEngine,
        basic_user: UserContext,
    ):
        engine.add_rule("api", "configure", ["admin"])

        @engine.policy("api")
        class APIPolicy(Policy):
            def can_read(self, context: dict) -> bool:
                return True

        # "read" not in dict rules, falls through to policy
        result = engine.evaluate(basic_user, "read", "api")
        assert result.allowed is True


class TestSimplePolicyEngineDictRules:
    """Test dictionary-based rules."""

    def test_add_rule(self, engine: SimplePolicyEngine):
        engine.add_rule("calc", "execute", ["user"])
        assert "calc" in engine._dict_rules
        assert engine._dict_rules["calc"]["execute"] == ["user"]

    def test_add_rules_batch(self, engine: SimplePolicyEngine):
        engine.add_rules({
            "calc": {"execute": ["user"], "configure": ["admin"]},
            "db": {"query": ["analyst"]},
        })
        assert "calc" in engine._dict_rules
        assert "db" in engine._dict_rules
        assert engine._dict_rules["calc"]["configure"] == ["admin"]

    def test_remove_rule_action(self, engine: SimplePolicyEngine):
        engine.add_rule("calc", "execute", ["user"])
        engine.add_rule("calc", "configure", ["admin"])
        assert engine.remove_rule("calc", "execute") is True
        assert "execute" not in engine._dict_rules.get("calc", {})
        assert "configure" in engine._dict_rules["calc"]

    def test_remove_rule_resource(self, engine: SimplePolicyEngine):
        engine.add_rule("calc", "execute", ["user"])
        assert engine.remove_rule("calc") is True
        assert "calc" not in engine._dict_rules

    def test_remove_nonexistent(self, engine: SimplePolicyEngine):
        assert engine.remove_rule("nonexistent") is False
        assert engine.remove_rule("nonexistent", "action") is False

    def test_clear_rules(self, engine: SimplePolicyEngine):
        engine.add_rule("a", "x", ["r1"])
        engine.add_rule("b", "y", ["r2"])
        engine.clear_rules()
        assert len(engine._dict_rules) == 0


class TestSimplePolicyEngineExplain:
    """Test explain functionality."""

    def test_explain_with_policy(
        self,
        engine: SimplePolicyEngine,
        basic_user: UserContext,
    ):
        @engine.policy("file")
        class FilePolicy(Policy):
            def can_read(self, context: dict) -> bool:
                return True

        explanation = engine.explain(basic_user, "read", "file")
        assert explanation["decision"] == "ALLOW"
        assert explanation["user"]["user_id"] == "user_1"
        assert explanation["request"]["action"] == "read"
        assert "policy_class" in explanation
        assert explanation["policy_class"] == "FilePolicy"

    def test_explain_with_dict_rules(
        self,
        engine: SimplePolicyEngine,
        basic_user: UserContext,
    ):
        engine.add_rule("api", "call", ["user"])
        explanation = engine.explain(basic_user, "call", "api")
        assert explanation["decision"] == "ALLOW"
        assert "dict_rules" in explanation


class TestSimplePolicyEngineAsync:
    """Test async evaluation."""

    @pytest.mark.asyncio()
    async def test_evaluate_async(
        self,
        engine: SimplePolicyEngine,
        basic_user: UserContext,
    ):
        engine.add_rule("api", "call", ["user"])
        result = await engine.evaluate_async(basic_user, "call", "api")
        assert result.allowed is True
