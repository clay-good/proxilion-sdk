"""
Tests for built-in policy implementations.

This test suite covers:
- DenyAllPolicy: denies all actions
- AllowAllPolicy: allows all actions
- RoleBasedPolicy: with correct roles, without roles, edge cases
- OwnershipPolicy: owner can act, non-owner blocked, non-owner allowed actions
- CompositePolicy: AND logic, OR logic
- AttributeBasedPolicy: custom rules
"""

from __future__ import annotations

from dataclasses import dataclass

from proxilion.policies.builtin import (
    AllowAllPolicy,
    AttributeBasedPolicy,
    CompositePolicy,
    DenyAllPolicy,
    OwnershipPolicy,
    RoleBasedPolicy,
)
from proxilion.types import UserContext

# ============================================================================
# Test Helpers
# ============================================================================


@dataclass
class MockResource:
    """Mock resource for testing ownership policies."""

    owner_id: str
    name: str


# ============================================================================
# DenyAllPolicy Tests
# ============================================================================


class TestDenyAllPolicy:
    """Test DenyAllPolicy denies all actions."""

    def test_denies_execute(self) -> None:
        """DenyAllPolicy should deny execute action."""
        user = UserContext(user_id="user_123", roles=["admin"])
        policy = DenyAllPolicy(user)

        assert policy.can_execute({}) is False

    def test_denies_read(self) -> None:
        """DenyAllPolicy should deny read action."""
        user = UserContext(user_id="user_123", roles=["admin"])
        policy = DenyAllPolicy(user)

        assert policy.can_read({}) is False

    def test_denies_write(self) -> None:
        """DenyAllPolicy should deny write action."""
        user = UserContext(user_id="user_123", roles=["admin"])
        policy = DenyAllPolicy(user)

        assert policy.can_write({}) is False

    def test_denies_delete(self) -> None:
        """DenyAllPolicy should deny delete action."""
        user = UserContext(user_id="user_123", roles=["admin"])
        policy = DenyAllPolicy(user)

        assert policy.can_delete({}) is False

    def test_denies_arbitrary_action(self) -> None:
        """DenyAllPolicy should deny any arbitrary action."""
        user = UserContext(user_id="user_123", roles=["admin"])
        policy = DenyAllPolicy(user)

        assert policy.authorize("custom_action") is False
        assert policy.authorize("another_action") is False

    def test_denies_for_any_user(self) -> None:
        """DenyAllPolicy should deny for any user, regardless of roles."""
        admin = UserContext(user_id="admin", roles=["admin", "superuser"])
        guest = UserContext(user_id="guest", roles=[])

        admin_policy = DenyAllPolicy(admin)
        guest_policy = DenyAllPolicy(guest)

        assert admin_policy.can_read({}) is False
        assert guest_policy.can_read({}) is False


# ============================================================================
# AllowAllPolicy Tests
# ============================================================================


class TestAllowAllPolicy:
    """Test AllowAllPolicy allows all actions."""

    def test_allows_execute(self) -> None:
        """AllowAllPolicy should allow execute action."""
        user = UserContext(user_id="user_123", roles=[])
        policy = AllowAllPolicy(user)

        assert policy.can_execute({}) is True

    def test_allows_read(self) -> None:
        """AllowAllPolicy should allow read action."""
        user = UserContext(user_id="user_123", roles=[])
        policy = AllowAllPolicy(user)

        assert policy.can_read({}) is True

    def test_allows_write(self) -> None:
        """AllowAllPolicy should allow write action."""
        user = UserContext(user_id="user_123", roles=[])
        policy = AllowAllPolicy(user)

        assert policy.can_write({}) is True

    def test_allows_delete(self) -> None:
        """AllowAllPolicy should allow delete action."""
        user = UserContext(user_id="user_123", roles=[])
        policy = AllowAllPolicy(user)

        assert policy.can_delete({}) is True

    def test_allows_arbitrary_action(self) -> None:
        """AllowAllPolicy should allow any arbitrary action."""
        user = UserContext(user_id="user_123", roles=[])
        policy = AllowAllPolicy(user)

        assert policy.authorize("custom_action") is True
        assert policy.authorize("another_action") is True

    def test_allows_for_any_user(self) -> None:
        """AllowAllPolicy should allow for any user."""
        guest = UserContext(user_id="guest", roles=[])
        guest_policy = AllowAllPolicy(guest)

        assert guest_policy.can_read({}) is True


# ============================================================================
# RoleBasedPolicy Tests
# ============================================================================


class TestRoleBasedPolicy:
    """Test RoleBasedPolicy with various role configurations."""

    def test_with_correct_role(self) -> None:
        """User with correct role should be allowed."""

        class DocumentPolicy(RoleBasedPolicy):
            allowed_roles = {
                "read": ["viewer", "editor", "admin"],
                "write": ["editor", "admin"],
                "delete": ["admin"],
            }

        user = UserContext(user_id="user_123", roles=["editor"])
        policy = DocumentPolicy(user)

        assert policy.authorize("read") is True
        assert policy.authorize("write") is True
        assert policy.authorize("delete") is False

    def test_without_required_role(self) -> None:
        """User without required role should be denied."""

        class DocumentPolicy(RoleBasedPolicy):
            allowed_roles = {
                "read": ["viewer", "editor"],
                "write": ["editor"],
            }

        user = UserContext(user_id="user_123", roles=["guest"])
        policy = DocumentPolicy(user)

        assert policy.authorize("read") is False
        assert policy.authorize("write") is False

    def test_user_without_any_roles(self) -> None:
        """User with no roles should be denied."""

        class DocumentPolicy(RoleBasedPolicy):
            allowed_roles = {
                "read": ["viewer"],
            }

        user = UserContext(user_id="user_123", roles=[])
        policy = DocumentPolicy(user)

        assert policy.authorize("read") is False

    def test_action_not_in_allowed_roles(self) -> None:
        """Action not in allowed_roles should be denied by default."""

        class DocumentPolicy(RoleBasedPolicy):
            allowed_roles = {
                "read": ["viewer"],
            }

        user = UserContext(user_id="user_123", roles=["viewer"])
        policy = DocumentPolicy(user)

        assert policy.authorize("read") is True
        assert policy.authorize("unknown_action") is False

    def test_default_allowed_true(self) -> None:
        """When default_allowed=True, unknown actions should be allowed."""

        class PermissivePolicy(RoleBasedPolicy):
            allowed_roles = {
                "read": ["viewer"],
            }
            default_allowed = True

        user = UserContext(user_id="user_123", roles=[])
        policy = PermissivePolicy(user)

        assert policy.authorize("unknown_action") is True

    def test_with_roles_factory_method(self) -> None:
        """with_roles factory method should create policy dynamically."""
        api_policy_cls = RoleBasedPolicy.with_roles(
            {
                "read": ["user", "admin"],
                "write": ["admin"],
            }
        )

        user = UserContext(user_id="user_123", roles=["user"])
        admin = UserContext(user_id="admin_456", roles=["admin"])

        user_policy = api_policy_cls(user)
        admin_policy = api_policy_cls(admin)

        assert user_policy.authorize("read") is True
        assert user_policy.authorize("write") is False
        assert admin_policy.authorize("read") is True
        assert admin_policy.authorize("write") is True

    def test_multiple_roles_any_match(self) -> None:
        """User with multiple roles should be allowed if any role matches."""

        class DocumentPolicy(RoleBasedPolicy):
            allowed_roles = {
                "read": ["viewer"],
                "write": ["editor"],
            }

        user = UserContext(user_id="user_123", roles=["viewer", "editor", "other"])
        policy = DocumentPolicy(user)

        assert policy.authorize("read") is True
        assert policy.authorize("write") is True


# ============================================================================
# OwnershipPolicy Tests
# ============================================================================


class TestOwnershipPolicy:
    """Test OwnershipPolicy for resource ownership."""

    def test_owner_can_write(self) -> None:
        """Owner should be allowed to write."""
        user = UserContext(user_id="user_123", roles=[])
        resource = MockResource(owner_id="user_123", name="document")
        policy = OwnershipPolicy(user, resource)

        assert policy.authorize("write") is True

    def test_owner_can_delete(self) -> None:
        """Owner should be allowed to delete."""
        user = UserContext(user_id="user_123", roles=[])
        resource = MockResource(owner_id="user_123", name="document")
        policy = OwnershipPolicy(user, resource)

        assert policy.authorize("delete") is True

    def test_non_owner_denied_write(self) -> None:
        """Non-owner should be denied write."""
        user = UserContext(user_id="user_456", roles=[])
        resource = MockResource(owner_id="user_123", name="document")
        policy = OwnershipPolicy(user, resource)

        assert policy.authorize("write") is False

    def test_non_owner_denied_delete(self) -> None:
        """Non-owner should be denied delete."""
        user = UserContext(user_id="user_456", roles=[])
        resource = MockResource(owner_id="user_123", name="document")
        policy = OwnershipPolicy(user, resource)

        assert policy.authorize("delete") is False

    def test_non_owner_allowed_actions(self) -> None:
        """Non-owner should be allowed actions in allow_non_owner_actions."""

        class DocumentPolicy(OwnershipPolicy):
            allow_non_owner_actions = ["read", "list"]

        user = UserContext(user_id="user_456", roles=[])
        resource = MockResource(owner_id="user_123", name="document")
        policy = DocumentPolicy(user, resource)

        assert policy.authorize("read") is True
        assert policy.authorize("list") is True
        assert policy.authorize("write") is False

    def test_is_owner_method(self) -> None:
        """is_owner should correctly identify ownership."""
        owner = UserContext(user_id="user_123", roles=[])
        non_owner = UserContext(user_id="user_456", roles=[])
        resource = MockResource(owner_id="user_123", name="document")

        owner_policy = OwnershipPolicy(owner, resource)
        non_owner_policy = OwnershipPolicy(non_owner, resource)

        assert owner_policy.is_owner() is True
        assert non_owner_policy.is_owner() is False

    def test_no_resource_returns_false(self) -> None:
        """is_owner should return False when resource is None."""
        user = UserContext(user_id="user_123", roles=[])
        policy = OwnershipPolicy(user, None)

        assert policy.is_owner() is False


# ============================================================================
# CompositePolicy Tests
# ============================================================================


class TestCompositePolicy:
    """Test CompositePolicy for combining multiple policies."""

    def test_and_logic_both_allow(self) -> None:
        """With AND logic, both policies must allow."""

        class AlwaysAllowPolicy(RoleBasedPolicy):
            allowed_roles = {
                "read": ["user"],
            }

        class DocumentOwnershipPolicy(OwnershipPolicy):
            pass

        class StrictPolicy(CompositePolicy):
            policies = [AlwaysAllowPolicy, DocumentOwnershipPolicy]
            require_all = True

        user = UserContext(user_id="user_123", roles=["user"])
        resource = MockResource(owner_id="user_123", name="doc")
        policy = StrictPolicy(user, resource)

        # User has role and is owner - both allow
        assert policy.authorize("read") is True

    def test_and_logic_one_denies(self) -> None:
        """With AND logic, if one policy denies, result is deny."""

        class AlwaysAllowPolicy(RoleBasedPolicy):
            allowed_roles = {
                "read": ["user"],
            }

        class DocumentOwnershipPolicy(OwnershipPolicy):
            pass

        class StrictPolicy(CompositePolicy):
            policies = [AlwaysAllowPolicy, DocumentOwnershipPolicy]
            require_all = True

        user = UserContext(user_id="user_123", roles=["user"])
        resource = MockResource(owner_id="different_user", name="doc")
        policy = StrictPolicy(user, resource)

        # User has role but is not owner - ownership policy denies
        assert policy.authorize("write") is False

    def test_or_logic_one_allows(self) -> None:
        """With OR logic, if any policy allows, result is allow."""

        class RolePolicy(RoleBasedPolicy):
            allowed_roles = {
                "read": ["admin"],
            }

        class DocumentOwnershipPolicy(OwnershipPolicy):
            pass

        class PermissivePolicy(CompositePolicy):
            policies = [RolePolicy, DocumentOwnershipPolicy]
            require_all = False

        # User is not admin but is owner
        user = UserContext(user_id="user_123", roles=["user"])
        resource = MockResource(owner_id="user_123", name="doc")
        policy = PermissivePolicy(user, resource)

        # Ownership policy allows write
        assert policy.authorize("write") is True

    def test_or_logic_all_deny(self) -> None:
        """With OR logic, if all policies deny, result is deny."""

        class RolePolicy(RoleBasedPolicy):
            allowed_roles = {
                "read": ["admin"],
            }

        class DocumentOwnershipPolicy(OwnershipPolicy):
            pass

        class PermissivePolicy(CompositePolicy):
            policies = [RolePolicy, DocumentOwnershipPolicy]
            require_all = False

        # User is not admin and not owner
        user = UserContext(user_id="user_123", roles=["user"])
        resource = MockResource(owner_id="different_user", name="doc")
        policy = PermissivePolicy(user, resource)

        assert policy.authorize("write") is False

    def test_combine_factory_method(self) -> None:
        """combine factory method should create composite policy."""

        class RolePolicy(RoleBasedPolicy):
            allowed_roles = {"read": ["user"]}

        class OwnerPolicy(OwnershipPolicy):
            pass

        combined_policy_cls = CompositePolicy.combine(RolePolicy, OwnerPolicy, require_all=True)

        user = UserContext(user_id="user_123", roles=["user"])
        resource = MockResource(owner_id="user_123", name="doc")
        policy = combined_policy_cls(user, resource)

        assert policy.authorize("read") is True

    def test_empty_policies_denies(self) -> None:
        """CompositePolicy with no policies should deny."""

        class EmptyPolicy(CompositePolicy):
            policies = []

        user = UserContext(user_id="user_123", roles=[])
        policy = EmptyPolicy(user, None)

        assert policy.authorize("read") is False


# ============================================================================
# AttributeBasedPolicy Tests
# ============================================================================


class TestAttributeBasedPolicy:
    """Test AttributeBasedPolicy with custom rules."""

    def test_default_denies(self) -> None:
        """Default AttributeBasedPolicy should deny all actions."""

        class DefaultPolicy(AttributeBasedPolicy):
            pass

        user = UserContext(user_id="user_123", roles=[])
        policy = DefaultPolicy(user, None)

        assert policy.authorize("read") is False

    def test_custom_rule_allows(self) -> None:
        """Custom rule can allow based on attributes."""

        class DepartmentPolicy(AttributeBasedPolicy):
            def evaluate_rules(self, action: str, context: dict) -> bool:
                if action == "read":
                    # Allow if user is in engineering department
                    return context.get("user_attributes", {}).get("department") == "engineering"
                return False

        user = UserContext(user_id="user_123", roles=[], attributes={"department": "engineering"})
        policy = DepartmentPolicy(user, None)

        assert policy.authorize("read") is True
        assert policy.authorize("write") is False

    def test_custom_rule_denies(self) -> None:
        """Custom rule can deny based on attributes."""

        class DepartmentPolicy(AttributeBasedPolicy):
            def evaluate_rules(self, action: str, context: dict) -> bool:
                if action == "read":
                    return context.get("user_attributes", {}).get("department") == "engineering"
                return False

        user = UserContext(user_id="user_123", roles=[], attributes={"department": "sales"})
        policy = DepartmentPolicy(user, None)

        assert policy.authorize("read") is False

    def test_context_enrichment(self) -> None:
        """AttributeBasedPolicy should enrich context with user data."""

        class InspectContextPolicy(AttributeBasedPolicy):
            def evaluate_rules(self, action: str, context: dict) -> bool:
                # Context should include user_id, user_roles, user_attributes
                assert "user_id" in context
                assert "user_roles" in context
                assert "user_attributes" in context
                return context["user_id"] == "user_123"

        user = UserContext(
            user_id="user_123", roles=["admin"], attributes={"department": "engineering"}
        )
        policy = InspectContextPolicy(user, None)

        assert policy.authorize("read") is True

    def test_resource_based_rule(self) -> None:
        """AttributeBasedPolicy can use resource attributes."""

        class ResourcePolicy(AttributeBasedPolicy):
            def evaluate_rules(self, action: str, context: dict) -> bool:
                # Check if user department matches resource department
                user_dept = context.get("user_attributes", {}).get("department")
                if hasattr(self.resource, "department"):
                    return user_dept == self.resource.department
                return False

        @dataclass
        class DepartmentResource:
            department: str

        user = UserContext(user_id="user_123", roles=[], attributes={"department": "engineering"})
        resource = DepartmentResource(department="engineering")
        policy = ResourcePolicy(user, resource)

        assert policy.authorize("read") is True

        # Different department should deny
        other_resource = DepartmentResource(department="sales")
        other_policy = ResourcePolicy(user, other_resource)
        assert other_policy.authorize("read") is False
