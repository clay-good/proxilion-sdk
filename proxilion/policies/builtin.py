"""
Built-in policies for Proxilion.

This module provides commonly used policy implementations that can be
used directly or extended for custom authorization logic.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from proxilion.policies.base import Policy

if TYPE_CHECKING:
    from proxilion.types import UserContext

logger = logging.getLogger(__name__)


class DenyAllPolicy(Policy[Any]):
    """
    Policy that denies all actions.

    This is the safest default policy - it denies everything unless
    explicitly allowed. Use this as a base class or as the default
    policy in the registry to ensure secure-by-default behavior.

    Example:
        >>> registry = PolicyRegistry(default_policy=DenyAllPolicy)
        >>> # Any unregistered resource will be denied
    """

    def can_execute(self, context: dict[str, Any]) -> bool:
        """Deny execution."""
        return False

    def can_read(self, context: dict[str, Any]) -> bool:
        """Deny read access."""
        return False

    def can_write(self, context: dict[str, Any]) -> bool:
        """Deny write access."""
        return False

    def can_delete(self, context: dict[str, Any]) -> bool:
        """Deny delete access."""
        return False

    def can_create(self, context: dict[str, Any]) -> bool:
        """Deny create access."""
        return False

    def can_update(self, context: dict[str, Any]) -> bool:
        """Deny update access."""
        return False

    def can_list(self, context: dict[str, Any]) -> bool:
        """Deny list access."""
        return False

    def authorize(self, action: str, context: dict[str, Any] | None = None) -> bool:
        """
        Override authorize to deny all actions.

        Even actions without explicit can_<action> methods are denied.
        """
        logger.debug(
            f"DenyAllPolicy: Denying action '{action}' for user '{self.user.user_id}'"
        )
        return False


class AllowAllPolicy(Policy[Any]):
    """
    Policy that allows all actions.

    WARNING: This policy should ONLY be used for testing or in
    development environments. Using it in production is a security risk.

    A warning is logged every time this policy is instantiated to
    help catch accidental production usage.

    Example:
        >>> # For testing only!
        >>> @registry.policy("test_resource")
        >>> class TestPolicy(AllowAllPolicy):
        ...     pass
    """

    def __init__(self, user: UserContext, resource: Any = None) -> None:
        """Initialize with a security warning."""
        super().__init__(user, resource)
        logger.warning(
            f"AllowAllPolicy instantiated for user '{user.user_id}'. "
            "This policy allows ALL actions and should NOT be used in production!"
        )

    def can_execute(self, context: dict[str, Any]) -> bool:
        """Allow execution."""
        return True

    def can_read(self, context: dict[str, Any]) -> bool:
        """Allow read access."""
        return True

    def can_write(self, context: dict[str, Any]) -> bool:
        """Allow write access."""
        return True

    def can_delete(self, context: dict[str, Any]) -> bool:
        """Allow delete access."""
        return True

    def can_create(self, context: dict[str, Any]) -> bool:
        """Allow create access."""
        return True

    def can_update(self, context: dict[str, Any]) -> bool:
        """Allow update access."""
        return True

    def can_list(self, context: dict[str, Any]) -> bool:
        """Allow list access."""
        return True

    def authorize(self, action: str, context: dict[str, Any] | None = None) -> bool:
        """
        Override authorize to allow all actions.

        Even actions without explicit can_<action> methods are allowed.
        """
        logger.debug(
            f"AllowAllPolicy: Allowing action '{action}' for user '{self.user.user_id}'"
        )
        return True


class RoleBasedPolicy(Policy[Any]):
    """
    Base class for role-based authorization policies.

    This policy checks if the user has any of the required roles
    for a given action. Subclasses define the role requirements
    by setting the `allowed_roles` class attribute.

    Attributes:
        allowed_roles: Dictionary mapping action names to lists of
            roles that are allowed to perform that action.
        default_allowed: Whether to allow actions not in allowed_roles.

    Example:
        >>> class DocumentPolicy(RoleBasedPolicy):
        ...     allowed_roles = {
        ...         "read": ["viewer", "editor", "admin"],
        ...         "write": ["editor", "admin"],
        ...         "delete": ["admin"],
        ...     }
        >>>
        >>> # User with "editor" role can read and write, but not delete
        >>> policy = DocumentPolicy(user_with_editor_role, document)
        >>> policy.can("read")   # True
        >>> policy.can("write")  # True
        >>> policy.can("delete") # False
    """

    # Subclasses should override this
    allowed_roles: dict[str, list[str]] = {}

    # Whether to allow actions not explicitly listed in allowed_roles
    default_allowed: bool = False

    def authorize(self, action: str, context: dict[str, Any] | None = None) -> bool:
        """
        Check if user has a required role for the action.

        Args:
            action: The action to check.
            context: Additional context (unused in basic role check).

        Returns:
            True if user has a required role, False otherwise.
        """
        if action not in self.allowed_roles:
            if self.default_allowed:
                logger.debug(
                    f"RoleBasedPolicy: Action '{action}' not in allowed_roles, "
                    f"allowing by default"
                )
                return True
            logger.debug(
                f"RoleBasedPolicy: Action '{action}' not in allowed_roles, "
                f"denying by default"
            )
            return False

        required_roles = self.allowed_roles[action]
        user_roles = set(self.user.roles)
        allowed_role_set = set(required_roles)

        has_role = bool(user_roles & allowed_role_set)

        if has_role:
            matching = user_roles & allowed_role_set
            logger.debug(
                f"RoleBasedPolicy: User '{self.user.user_id}' has role(s) "
                f"{matching} for action '{action}'"
            )
        else:
            logger.debug(
                f"RoleBasedPolicy: User '{self.user.user_id}' lacks required "
                f"role(s) {required_roles} for action '{action}'"
            )

        return has_role

    @classmethod
    def with_roles(
        cls,
        roles: dict[str, list[str]],
        default_allowed: bool = False,
    ) -> type[RoleBasedPolicy]:
        """
        Create a RoleBasedPolicy subclass with specific roles.

        Factory method for creating role-based policies dynamically.

        Args:
            roles: Dictionary mapping actions to allowed roles.
            default_allowed: Whether to allow unlisted actions.

        Returns:
            A new RoleBasedPolicy subclass.

        Example:
            >>> ApiPolicy = RoleBasedPolicy.with_roles({
            ...     "read": ["user", "admin"],
            ...     "write": ["admin"],
            ... })
            >>> policy = ApiPolicy(user, api_resource)
        """
        class DynamicRolePolicy(cls):  # type: ignore[valid-type, misc]
            pass

        DynamicRolePolicy.allowed_roles = roles
        DynamicRolePolicy.default_allowed = default_allowed
        return DynamicRolePolicy


class AttributeBasedPolicy(Policy[Any]):
    """
    Base class for attribute-based authorization policies.

    This policy allows defining rules based on user attributes,
    resource attributes, and environmental conditions. More flexible
    than role-based policies but more complex to configure.

    Subclasses should override the `evaluate_rules` method or
    set the `rules` class attribute.

    Example:
        >>> class DocumentPolicy(AttributeBasedPolicy):
        ...     def evaluate_rules(
        ...         self, action: str, context: dict
        ...     ) -> bool:
        ...         # Allow if user is owner
        ...         if self.resource.owner_id == self.user.user_id:
        ...             return True
        ...         # Allow if user is in same department
        ...         if self.user.get_attribute("department") == \
        ...            self.resource.department:
        ...             return action == "read"
        ...         return False
    """

    def evaluate_rules(
        self,
        action: str,
        context: dict[str, Any],
    ) -> bool:
        """
        Evaluate authorization rules.

        Override this method to implement custom attribute-based logic.

        Args:
            action: The action being checked.
            context: Additional context for the decision.

        Returns:
            True if authorized, False otherwise.
        """
        # Default implementation denies all
        return False

    def authorize(self, action: str, context: dict[str, Any] | None = None) -> bool:
        """
        Check authorization using attribute-based rules.

        Args:
            action: The action to check.
            context: Additional context for the decision.

        Returns:
            True if authorized, False otherwise.
        """
        # Copy to avoid mutating caller's dict
        ctx = dict(context) if context else {}

        # Add user attributes to context for convenience
        ctx["user_id"] = self.user.user_id
        ctx["user_roles"] = self.user.roles
        ctx["user_attributes"] = self.user.attributes

        result = self.evaluate_rules(action, ctx)

        logger.debug(
            f"AttributeBasedPolicy: Action '{action}' for user "
            f"'{self.user.user_id}' -> {'allowed' if result else 'denied'}"
        )

        return result


class OwnershipPolicy(Policy[Any]):
    """
    Policy that allows actions only if the user owns the resource.

    This policy checks if the resource has an owner_id or user_id
    attribute that matches the user's ID.

    Attributes:
        owner_field: Name of the attribute on the resource that contains
            the owner's user ID. Defaults to "owner_id".
        owner_actions: Actions that require ownership. Other actions
            may be allowed based on `allow_non_owner_actions`.
        allow_non_owner_actions: List of actions allowed for non-owners.

    Example:
        >>> class DocumentPolicy(OwnershipPolicy):
        ...     owner_field = "created_by"
        ...     allow_non_owner_actions = ["read"]  # Anyone can read
    """

    owner_field: str = "owner_id"
    owner_actions: list[str] = ["write", "delete", "update"]
    allow_non_owner_actions: list[str] = []

    def is_owner(self) -> bool:
        """Check if the user owns the resource."""
        if self.resource is None:
            return False

        owner_id = getattr(self.resource, self.owner_field, None)
        if owner_id is None:
            # Try alternative field names
            owner_id = getattr(self.resource, "user_id", None)

        return owner_id == self.user.user_id

    def authorize(self, action: str, context: dict[str, Any] | None = None) -> bool:
        """
        Check if user is authorized based on ownership.

        Args:
            action: The action to check.
            context: Additional context (unused).

        Returns:
            True if user is owner or action is in allow_non_owner_actions.
        """
        if action in self.allow_non_owner_actions:
            logger.debug(
                f"OwnershipPolicy: Action '{action}' allowed for non-owners"
            )
            return True

        is_owner = self.is_owner()

        if is_owner:
            logger.debug(
                f"OwnershipPolicy: User '{self.user.user_id}' is owner, "
                f"allowing action '{action}'"
            )
        else:
            logger.debug(
                f"OwnershipPolicy: User '{self.user.user_id}' is not owner, "
                f"denying action '{action}'"
            )

        return is_owner


class CompositePolicy(Policy[Any]):
    """
    Policy that combines multiple policies with AND/OR logic.

    Use this to create complex authorization rules from simpler policies.

    Attributes:
        policies: List of policy classes to combine.
        require_all: If True, all policies must allow (AND).
            If False, any policy can allow (OR).

    Example:
        >>> class SecureDocumentPolicy(CompositePolicy):
        ...     policies = [RoleBasedPolicy, OwnershipPolicy]
        ...     require_all = True  # Must have role AND be owner
    """

    policies: list[type[Policy[Any]]] = []
    require_all: bool = True

    def authorize(self, action: str, context: dict[str, Any] | None = None) -> bool:
        """
        Check authorization using all configured policies.

        Args:
            action: The action to check.
            context: Additional context passed to each policy.

        Returns:
            True if authorized according to combination logic.
        """
        if not self.policies:
            logger.warning("CompositePolicy has no policies configured")
            return False

        results = []
        for policy_class in self.policies:
            policy = policy_class(self.user, self.resource)
            result = policy.authorize(action, context)
            results.append(result)

            # Short-circuit evaluation
            if self.require_all and not result:
                logger.debug(
                    f"CompositePolicy: {policy_class.__name__} denied "
                    f"action '{action}' (require_all=True)"
                )
                return False
            if not self.require_all and result:
                logger.debug(
                    f"CompositePolicy: {policy_class.__name__} allowed "
                    f"action '{action}' (require_all=False)"
                )
                return True

        # If we get here with require_all=True, all passed
        # If we get here with require_all=False, all failed
        final_result = self.require_all
        logger.debug(
            f"CompositePolicy: Final result for action '{action}': "
            f"{'allowed' if final_result else 'denied'}"
        )
        return final_result

    @classmethod
    def combine(
        cls,
        *policy_classes: type[Policy[Any]],
        require_all: bool = True,
    ) -> type[CompositePolicy]:
        """
        Create a CompositePolicy combining multiple policies.

        Factory method for creating composite policies dynamically.

        Args:
            *policy_classes: Policy classes to combine.
            require_all: Whether all must allow (AND) or any (OR).

        Returns:
            A new CompositePolicy subclass.

        Example:
            >>> CombinedPolicy = CompositePolicy.combine(
            ...     RolePolicy, OwnerPolicy,
            ...     require_all=True
            ... )
        """
        class DynamicCompositePolicy(cls):
            pass

        DynamicCompositePolicy.policies = list(policy_classes)
        DynamicCompositePolicy.require_all = require_all
        return DynamicCompositePolicy
