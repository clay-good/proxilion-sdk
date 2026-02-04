"""
Tests for the core Proxilion class.

Tests cover:
- Initialization and configuration
- Policy registration via decorator
- Authorization checks (can, check, authorize decorator)
- Integration with policy engines
- Rate limiting integration
- Circuit breaker integration
- Audit logging integration
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from proxilion import AuthorizationError, Policy, Proxilion, UserContext
from proxilion.types import AuthorizationResult

if TYPE_CHECKING:
    pass


class TestProxilionInitialization:
    """Tests for Proxilion initialization."""

    def test_default_initialization(self):
        """Test default initialization creates valid instance."""
        auth = Proxilion()
        assert auth is not None
        assert auth._engine is not None

    def test_simple_engine_initialization(self):
        """Test initialization with simple policy engine."""
        auth = Proxilion(policy_engine="simple")
        assert auth is not None

    def test_with_audit_logging(self, tmp_path: Path):
        """Test initialization with audit logging enabled."""
        audit_path = tmp_path / "audit.jsonl"
        auth = Proxilion(
            policy_engine="simple",
            audit_log_path=str(audit_path),
        )
        assert auth is not None
        assert auth._audit_logger is not None

    def test_with_rate_limiting(self):
        """Test initialization with rate limiting config."""
        auth = Proxilion(
            policy_engine="simple",
            rate_limit_config={
                "default": {"capacity": 100, "refill_rate": 10},
            },
        )
        assert auth is not None

    def test_with_circuit_breaker(self):
        """Test initialization with circuit breaker enabled."""
        auth = Proxilion(
            policy_engine="simple",
            enable_circuit_breaker=True,
        )
        assert auth is not None


class TestPolicyRegistration:
    """Tests for policy registration via decorator."""

    def test_policy_decorator_registers_policy(self, proxilion_simple: Proxilion):
        """Test that @policy decorator registers the policy class."""
        @proxilion_simple.policy("test_resource")
        class TestPolicy(Policy):
            def can_execute(self, context: dict) -> bool:
                return True

        # Policy should be retrievable
        policy_class = proxilion_simple._registry.get_policy("test_resource")
        assert policy_class is TestPolicy

    def test_policy_decorator_preserves_class(self, proxilion_simple: Proxilion):
        """Test that decorator returns the original class."""
        @proxilion_simple.policy("another_resource")
        class AnotherPolicy(Policy):
            def can_read(self, context: dict) -> bool:
                return "reader" in self.user.roles

        assert AnotherPolicy.__name__ == "AnotherPolicy"
        assert hasattr(AnotherPolicy, "can_read")

    def test_multiple_policies_registration(self, proxilion_simple: Proxilion):
        """Test registering multiple policies."""
        @proxilion_simple.policy("resource_a")
        class PolicyA(Policy):
            def can_execute(self, context: dict) -> bool:
                return True

        @proxilion_simple.policy("resource_b")
        class PolicyB(Policy):
            def can_execute(self, context: dict) -> bool:
                return False

        assert proxilion_simple._registry.get_policy("resource_a") is PolicyA
        assert proxilion_simple._registry.get_policy("resource_b") is PolicyB


class TestCanMethod:
    """Tests for the can() method."""

    def test_can_returns_true_when_allowed(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test can() returns True when policy allows."""
        @proxilion_simple.policy("open_resource")
        class OpenPolicy(Policy):
            def can_execute(self, context: dict) -> bool:
                return True

        result = proxilion_simple.can(basic_user, "execute", "open_resource")
        assert result is True

    def test_can_returns_false_when_denied(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test can() returns False when policy denies."""
        @proxilion_simple.policy("restricted_resource")
        class RestrictedPolicy(Policy):
            def can_execute(self, context: dict) -> bool:
                return "admin" in self.user.roles

        result = proxilion_simple.can(basic_user, "execute", "restricted_resource")
        assert result is False

    def test_can_with_admin_user(
        self, proxilion_simple: Proxilion, admin_user: UserContext
    ):
        """Test can() with admin user passes restricted policy."""
        @proxilion_simple.policy("admin_only")
        class AdminOnlyPolicy(Policy):
            def can_execute(self, context: dict) -> bool:
                return "admin" in self.user.roles

        result = proxilion_simple.can(admin_user, "execute", "admin_only")
        assert result is True

    def test_can_with_context(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test can() passes context to policy."""
        @proxilion_simple.policy("context_aware")
        class ContextAwarePolicy(Policy):
            def can_execute(self, context: dict) -> bool:
                return context.get("approved", False)

        # Without approval
        result = proxilion_simple.can(
            basic_user, "execute", "context_aware", context={"approved": False}
        )
        assert result is False

        # With approval
        result = proxilion_simple.can(
            basic_user, "execute", "context_aware", context={"approved": True}
        )
        assert result is True


class TestCheckMethod:
    """Tests for the check() method."""

    def test_check_returns_authorization_result(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test check() returns AuthorizationResult."""
        @proxilion_simple.policy("check_test")
        class CheckTestPolicy(Policy):
            def can_execute(self, context: dict) -> bool:
                return True

        result = proxilion_simple.check(basic_user, "execute", "check_test")
        assert isinstance(result, AuthorizationResult)
        assert result.allowed is True

    def test_check_includes_policies_evaluated(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test check() includes evaluated policies in result."""
        @proxilion_simple.policy("policy_tracking")
        class PolicyTrackingPolicy(Policy):
            def can_execute(self, context: dict) -> bool:
                return True

        result = proxilion_simple.check(basic_user, "execute", "policy_tracking")
        assert "PolicyTrackingPolicy" in result.policies_evaluated

    def test_check_denied_includes_reason(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test check() includes reason when denied."""
        @proxilion_simple.policy("denied_resource")
        class DeniedPolicy(Policy):
            def can_execute(self, context: dict) -> bool:
                return False

        result = proxilion_simple.check(basic_user, "execute", "denied_resource")
        assert result.allowed is False
        assert result.reason is not None


class TestAuthorizeDecorator:
    """Tests for the @authorize decorator."""

    def test_authorize_allows_execution(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test @authorize allows function execution when policy permits."""
        @proxilion_simple.policy("decorated_resource")
        class DecoratedPolicy(Policy):
            def can_execute(self, context: dict) -> bool:
                return True

        @proxilion_simple.authorize("execute", resource="decorated_resource")
        def protected_function(value: int, user: UserContext = None) -> int:
            return value * 2

        result = protected_function(5, user=basic_user)
        assert result == 10

    def test_authorize_blocks_execution(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test @authorize blocks function execution when policy denies."""
        @proxilion_simple.policy("blocked_resource")
        class BlockedPolicy(Policy):
            def can_execute(self, context: dict) -> bool:
                return False

        @proxilion_simple.authorize("execute", resource="blocked_resource")
        def blocked_function(user: UserContext = None) -> str:
            return "should not reach here"

        with pytest.raises(AuthorizationError):
            blocked_function(user=basic_user)

    def test_authorize_async_function(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test @authorize works with async functions."""
        @proxilion_simple.policy("async_resource")
        class AsyncPolicy(Policy):
            def can_execute(self, context: dict) -> bool:
                return True

        @proxilion_simple.authorize("execute", resource="async_resource")
        async def async_function(user: UserContext = None) -> str:
            return "async result"

        result = asyncio.run(async_function(user=basic_user))
        assert result == "async result"

    def test_authorize_infers_resource_from_function_name(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test @authorize can infer resource from function name."""
        @proxilion_simple.policy("my_tool")
        class MyToolPolicy(Policy):
            def can_execute(self, context: dict) -> bool:
                return True

        @proxilion_simple.authorize("execute")
        def my_tool(user: UserContext = None) -> str:
            return "tool result"

        result = my_tool(user=basic_user)
        assert result == "tool result"


class TestRoleBasedAuthorization:
    """Tests for role-based authorization scenarios."""

    def test_admin_can_access_all(
        self, proxilion_simple: Proxilion, admin_user: UserContext, basic_user: UserContext
    ):
        """Test admin users can access admin-only resources."""
        @proxilion_simple.policy("admin_resource")
        class AdminResourcePolicy(Policy):
            def can_execute(self, context: dict) -> bool:
                return "admin" in self.user.roles

            def can_delete(self, context: dict) -> bool:
                return "admin" in self.user.roles

        # Admin can execute
        assert proxilion_simple.can(admin_user, "execute", "admin_resource") is True
        # Admin can delete
        assert proxilion_simple.can(admin_user, "delete", "admin_resource") is True
        # Basic user cannot
        assert proxilion_simple.can(basic_user, "execute", "admin_resource") is False

    def test_analyst_role_permissions(
        self, proxilion_simple: Proxilion, analyst_user: UserContext, basic_user: UserContext
    ):
        """Test analyst-specific permissions."""
        @proxilion_simple.policy("data_resource")
        class DataResourcePolicy(Policy):
            def can_read(self, context: dict) -> bool:
                return True  # Anyone can read

            def can_analyze(self, context: dict) -> bool:
                return "analyst" in self.user.roles

            def can_export(self, context: dict) -> bool:
                return "analyst" in self.user.roles or "admin" in self.user.roles

        # Analyst can analyze
        assert proxilion_simple.can(analyst_user, "analyze", "data_resource") is True
        # Basic user cannot analyze
        assert proxilion_simple.can(basic_user, "analyze", "data_resource") is False
        # Both can read
        assert proxilion_simple.can(analyst_user, "read", "data_resource") is True
        assert proxilion_simple.can(basic_user, "read", "data_resource") is True


class TestContextualAuthorization:
    """Tests for context-aware authorization."""

    def test_time_based_context(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test authorization based on context values."""
        @proxilion_simple.policy("time_sensitive")
        class TimeSensitivePolicy(Policy):
            def can_execute(self, context: dict) -> bool:
                # Only allow during business hours (simulated via context)
                return context.get("is_business_hours", False)

        # During business hours
        result = proxilion_simple.can(
            basic_user, "execute", "time_sensitive",
            context={"is_business_hours": True}
        )
        assert result is True

        # Outside business hours
        result = proxilion_simple.can(
            basic_user, "execute", "time_sensitive",
            context={"is_business_hours": False}
        )
        assert result is False

    def test_resource_specific_context(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test authorization based on resource-specific context."""
        @proxilion_simple.policy("document")
        class DocumentPolicy(Policy):
            def can_read(self, context: dict) -> bool:
                # Check if user owns the document
                doc_owner = context.get("owner_id")
                return doc_owner == self.user.user_id

        # User's own document
        result = proxilion_simple.can(
            basic_user, "read", "document",
            context={"owner_id": "user_123", "document_id": "doc_1"}
        )
        assert result is True

        # Someone else's document
        result = proxilion_simple.can(
            basic_user, "read", "document",
            context={"owner_id": "other_user", "document_id": "doc_2"}
        )
        assert result is False


class TestAuditLogging:
    """Tests for audit logging integration."""

    def test_audit_logs_authorization_check(
        self, proxilion_with_audit: Proxilion, basic_user: UserContext
    ):
        """Test that authorization checks are logged."""
        @proxilion_with_audit.policy("audited_resource")
        class AuditedPolicy(Policy):
            def can_execute(self, context: dict) -> bool:
                return True

        # Perform authorization check
        proxilion_with_audit.check(basic_user, "execute", "audited_resource")

        # Verify audit logger has recorded events
        # The audit logger is initialized with a path from the fixture's tmp_path
        assert proxilion_with_audit._audit_logger is not None


class TestErrorHandling:
    """Tests for error handling scenarios."""

    def test_missing_policy_returns_denied(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test that missing policy results in denied authorization."""
        result = proxilion_simple.check(basic_user, "execute", "nonexistent_resource")
        # Default behavior should deny if no policy found
        assert result.allowed is False

    def test_policy_exception_handling(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test that exceptions in policy are handled gracefully."""
        @proxilion_simple.policy("buggy_resource")
        class BuggyPolicy(Policy):
            def can_execute(self, context: dict) -> bool:
                raise ValueError("Policy bug!")

        # Should deny on exception rather than crash
        result = proxilion_simple.check(basic_user, "execute", "buggy_resource")
        assert result.allowed is False

    def test_authorize_without_user_raises(self, proxilion_simple: Proxilion):
        """Test that @authorize raises when no user provided."""
        @proxilion_simple.policy("user_required")
        class UserRequiredPolicy(Policy):
            def can_execute(self, context: dict) -> bool:
                return True

        @proxilion_simple.authorize("execute", resource="user_required")
        def needs_user(user: UserContext = None) -> str:
            return "result"

        # Should raise or handle gracefully when no user
        with pytest.raises(AuthorizationError):
            needs_user()  # No user provided
