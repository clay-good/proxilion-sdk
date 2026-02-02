"""
Tests for the policy system.

Tests cover:
- Policy base class
- Policy registry
- Built-in policies (DenyAllPolicy, AllowAllPolicy, RoleBasedPolicy)
- Policy auto-discovery
- Policy caching
"""

from __future__ import annotations

import pytest

from proxilion import Policy, UserContext
from proxilion.policies.base import Policy as BasePolicy
from proxilion.policies.registry import PolicyRegistry
from proxilion.policies.builtin import DenyAllPolicy, AllowAllPolicy, RoleBasedPolicy
from proxilion.exceptions import PolicyNotFoundError


class TestPolicyBaseClass:
    """Tests for the Policy base class."""

    def test_policy_initialization(self, basic_user: UserContext):
        """Test Policy base class initialization."""
        resource = {"id": "123", "type": "document"}
        policy = BasePolicy(basic_user, resource)

        assert policy.user == basic_user
        assert policy.resource == resource

    def test_policy_default_denies_all(self, basic_user: UserContext):
        """Test that default Policy implementation denies all actions."""
        policy = BasePolicy(basic_user, None)

        # Default implementation should return False (using authorize/can methods)
        assert policy.can("execute") is False
        assert policy.can("read") is False
        assert policy.can("write") is False
        assert policy.can("delete") is False

    def test_custom_policy_methods(self, basic_user: UserContext):
        """Test custom policy method implementation."""
        class CustomPolicy(BasePolicy):
            def can_custom_action(self, context: dict) -> bool:
                return context.get("allow_custom", False)

        policy = CustomPolicy(basic_user, None)
        assert policy.can_custom_action({"allow_custom": True}) is True
        assert policy.can_custom_action({"allow_custom": False}) is False
        assert policy.can_custom_action({}) is False

    def test_policy_accesses_user_attributes(self, admin_user: UserContext):
        """Test that policy can access user attributes."""
        class AttributePolicy(BasePolicy):
            def can_execute(self, context: dict) -> bool:
                return self.user.attributes.get("clearance") == "high"

        policy = AttributePolicy(admin_user, None)
        assert policy.can_execute({}) is True

    def test_policy_accesses_resource(self, basic_user: UserContext):
        """Test that policy can access resource object."""
        class ResourcePolicy(BasePolicy):
            def can_read(self, context: dict) -> bool:
                if self.resource is None:
                    return False
                return self.resource.get("public", False)

        policy = ResourcePolicy(basic_user, {"public": True, "id": "123"})
        assert policy.can_read({}) is True

        policy2 = ResourcePolicy(basic_user, {"public": False, "id": "456"})
        assert policy2.can_read({}) is False


class TestPolicyRegistry:
    """Tests for the PolicyRegistry class."""

    def test_registry_initialization(self):
        """Test PolicyRegistry initialization."""
        registry = PolicyRegistry()
        assert registry is not None

    def test_register_policy(self, policy_registry: PolicyRegistry):
        """Test registering a policy class."""
        class TestPolicy(BasePolicy):
            def can_execute(self, context: dict) -> bool:
                return True

        policy_registry.register("test_resource", TestPolicy)
        retrieved = policy_registry.get_policy("test_resource")
        assert retrieved is TestPolicy

    def test_register_policy_decorator(self, policy_registry: PolicyRegistry):
        """Test registering policy via decorator."""
        @policy_registry.policy("decorated_resource")
        class DecoratedPolicy(BasePolicy):
            def can_execute(self, context: dict) -> bool:
                return True

        retrieved = policy_registry.get_policy("decorated_resource")
        assert retrieved is DecoratedPolicy

    def test_get_nonexistent_policy_raises(self, policy_registry: PolicyRegistry):
        """Test that getting nonexistent policy raises error."""
        with pytest.raises(PolicyNotFoundError):
            policy_registry.get_policy("nonexistent")

    def test_policy_overwrite(self, policy_registry: PolicyRegistry):
        """Test that registering same resource overwrites previous policy."""
        class PolicyV1(BasePolicy):
            version = 1

        class PolicyV2(BasePolicy):
            version = 2

        policy_registry.register("versioned", PolicyV1)
        policy_registry.register("versioned", PolicyV2)

        retrieved = policy_registry.get_policy("versioned")
        assert retrieved.version == 2

    def test_list_policies(self, policy_registry: PolicyRegistry):
        """Test listing all registered policies."""
        class PolicyA(BasePolicy):
            pass

        class PolicyB(BasePolicy):
            pass

        policy_registry.register("resource_a", PolicyA)
        policy_registry.register("resource_b", PolicyB)

        policies = policy_registry.list_policies()
        assert "resource_a" in policies
        assert "resource_b" in policies

    def test_has_policy(self, policy_registry: PolicyRegistry):
        """Test checking if policy exists."""
        class ExistingPolicy(BasePolicy):
            pass

        policy_registry.register("existing", ExistingPolicy)

        assert policy_registry.has_policy("existing") is True
        assert policy_registry.has_policy("nonexistent") is False

    def test_unregister_policy(self, policy_registry: PolicyRegistry):
        """Test unregistering a policy."""
        class RemovablePolicy(BasePolicy):
            pass

        policy_registry.register("removable", RemovablePolicy)
        assert policy_registry.has_policy("removable") is True

        policy_registry.unregister("removable")
        assert policy_registry.has_policy("removable") is False


class TestDenyAllPolicy:
    """Tests for DenyAllPolicy."""

    def test_deny_all_denies_execute(self, basic_user: UserContext):
        """Test DenyAllPolicy denies execute."""
        policy = DenyAllPolicy(basic_user, None)
        assert policy.can_execute({}) is False

    def test_deny_all_denies_read(self, basic_user: UserContext):
        """Test DenyAllPolicy denies read."""
        policy = DenyAllPolicy(basic_user, None)
        assert policy.can_read({}) is False

    def test_deny_all_denies_write(self, basic_user: UserContext):
        """Test DenyAllPolicy denies write."""
        policy = DenyAllPolicy(basic_user, None)
        assert policy.can_write({}) is False

    def test_deny_all_denies_delete(self, basic_user: UserContext):
        """Test DenyAllPolicy denies delete."""
        policy = DenyAllPolicy(basic_user, None)
        assert policy.can_delete({}) is False

    def test_deny_all_denies_admin(self, admin_user: UserContext):
        """Test DenyAllPolicy denies even admin users."""
        policy = DenyAllPolicy(admin_user, None)
        assert policy.can_execute({}) is False


class TestAllowAllPolicy:
    """Tests for AllowAllPolicy."""

    def test_allow_all_allows_execute(self, basic_user: UserContext):
        """Test AllowAllPolicy allows execute."""
        policy = AllowAllPolicy(basic_user, None)
        assert policy.can_execute({}) is True

    def test_allow_all_allows_read(self, basic_user: UserContext):
        """Test AllowAllPolicy allows read."""
        policy = AllowAllPolicy(basic_user, None)
        assert policy.can_read({}) is True

    def test_allow_all_allows_write(self, basic_user: UserContext):
        """Test AllowAllPolicy allows write."""
        policy = AllowAllPolicy(basic_user, None)
        assert policy.can_write({}) is True

    def test_allow_all_allows_delete(self, basic_user: UserContext):
        """Test AllowAllPolicy allows delete."""
        policy = AllowAllPolicy(basic_user, None)
        assert policy.can_delete({}) is True


class TestRoleBasedPolicy:
    """Tests for RoleBasedPolicy."""

    def test_role_based_with_matching_role(self, admin_user: UserContext):
        """Test RoleBasedPolicy allows when role matches."""
        class AdminPolicy(RoleBasedPolicy):
            allowed_roles = {
                "execute": ["admin"],
                "read": ["admin", "user"],
            }

        policy = AdminPolicy(admin_user, None)
        assert policy.can("execute") is True
        assert policy.can("read") is True

    def test_role_based_without_matching_role(self, basic_user: UserContext):
        """Test RoleBasedPolicy denies when role doesn't match."""
        class AdminPolicy(RoleBasedPolicy):
            allowed_roles = {
                "execute": ["admin"],
                "delete": ["admin"],
            }

        policy = AdminPolicy(basic_user, None)
        assert policy.can("execute") is False
        assert policy.can("delete") is False

    def test_role_based_multiple_roles(self, analyst_user: UserContext):
        """Test RoleBasedPolicy with multiple allowed roles."""
        class DataPolicy(RoleBasedPolicy):
            allowed_roles = {
                "read": ["user", "analyst", "admin"],
                "analyze": ["analyst", "admin"],
                "delete": ["admin"],
            }

        policy = DataPolicy(analyst_user, None)
        assert policy.can("read") is True
        assert policy.can("analyze") is True
        assert policy.can("delete") is False

    def test_role_based_undefined_action(self, admin_user: UserContext):
        """Test RoleBasedPolicy denies undefined actions."""
        class LimitedPolicy(RoleBasedPolicy):
            allowed_roles = {
                "read": ["admin"],
            }

        policy = LimitedPolicy(admin_user, None)
        assert policy.can("read") is True
        # Undefined action should be denied
        assert policy.can("write") is False

    def test_role_based_empty_roles(self, guest_user: UserContext):
        """Test RoleBasedPolicy with user having no matching roles."""
        class StrictPolicy(RoleBasedPolicy):
            allowed_roles = {
                "execute": ["admin", "user"],
            }

        policy = StrictPolicy(guest_user, None)
        # Guest doesn't have admin or user role
        assert policy.can("execute") is False


class TestPolicyInheritance:
    """Tests for policy class inheritance patterns."""

    def test_policy_inheritance(self, basic_user: UserContext):
        """Test that policy classes can be inherited."""
        class BaseResourcePolicy(BasePolicy):
            def can_read(self, context: dict) -> bool:
                return True

        class ExtendedPolicy(BaseResourcePolicy):
            def can_write(self, context: dict) -> bool:
                return "editor" in self.user.roles

        policy = ExtendedPolicy(basic_user, None)
        assert policy.can_read({}) is True
        assert policy.can_write({}) is False

    def test_policy_method_override(self, basic_user: UserContext):
        """Test that policy methods can be overridden."""
        class ParentPolicy(BasePolicy):
            def can_execute(self, context: dict) -> bool:
                return False

        class ChildPolicy(ParentPolicy):
            def can_execute(self, context: dict) -> bool:
                return True  # Override parent

        parent = ParentPolicy(basic_user, None)
        child = ChildPolicy(basic_user, None)

        assert parent.can_execute({}) is False
        assert child.can_execute({}) is True

    def test_policy_super_call(self, admin_user: UserContext):
        """Test calling super() in policy methods."""
        class BaseResourcePolicy(BasePolicy):
            def can_execute(self, context: dict) -> bool:
                return "user" in self.user.roles

        class EnhancedPolicy(BaseResourcePolicy):
            def can_execute(self, context: dict) -> bool:
                # Must have base permission AND be admin
                base_allowed = super().can_execute(context)
                return base_allowed and "admin" in self.user.roles

        policy = EnhancedPolicy(admin_user, None)
        assert policy.can_execute({}) is True


class TestPolicyScope:
    """Tests for Policy Scope inner class pattern."""

    def test_scope_class_filters_resources(self, basic_user: UserContext):
        """Test that Scope class can filter resource collections."""
        class DocumentPolicy(BasePolicy):
            class Scope:
                def __init__(self, user: UserContext, resources: list):
                    self.user = user
                    self.resources = resources

                def resolve(self) -> list:
                    # Filter to only user's documents
                    return [
                        r for r in self.resources
                        if r.get("owner_id") == self.user.user_id
                    ]

        documents = [
            {"id": "1", "owner_id": "user_123"},
            {"id": "2", "owner_id": "other_user"},
            {"id": "3", "owner_id": "user_123"},
        ]

        scope = DocumentPolicy.Scope(basic_user, documents)
        filtered = scope.resolve()

        assert len(filtered) == 2
        assert all(d["owner_id"] == "user_123" for d in filtered)

    def test_scope_with_admin_sees_all(self, admin_user: UserContext):
        """Test that admin Scope sees all resources."""
        class DocumentPolicy(BasePolicy):
            class Scope:
                def __init__(self, user: UserContext, resources: list):
                    self.user = user
                    self.resources = resources

                def resolve(self) -> list:
                    if "admin" in self.user.roles:
                        return self.resources
                    return [
                        r for r in self.resources
                        if r.get("owner_id") == self.user.user_id
                    ]

        documents = [
            {"id": "1", "owner_id": "user_123"},
            {"id": "2", "owner_id": "other_user"},
            {"id": "3", "owner_id": "user_123"},
        ]

        scope = DocumentPolicy.Scope(admin_user, documents)
        filtered = scope.resolve()

        assert len(filtered) == 3  # Admin sees all
