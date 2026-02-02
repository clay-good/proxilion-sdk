"""
Policy system for Proxilion.

This module provides the Pundit-inspired policy pattern for defining
authorization rules. Policies are classes that define what actions
a user can perform on a resource.

Quick Start:
    >>> from proxilion.policies import Policy, PolicyRegistry
    >>>
    >>> registry = PolicyRegistry()
    >>>
    >>> @registry.policy("document")
    >>> class DocumentPolicy(Policy):
    ...     def can_read(self, context: dict) -> bool:
    ...         return True  # All users can read
    ...
    ...     def can_write(self, context: dict) -> bool:
    ...         return "editor" in self.user.roles
    ...
    ...     def can_delete(self, context: dict) -> bool:
    ...         return "admin" in self.user.roles
    >>>
    >>> # Check permissions
    >>> policy = registry.get_policy_instance("document", user, document)
    >>> if policy.can("write"):
    ...     document.save()
"""

from proxilion.policies.base import (
    ActionContext,
    Policy,
    PolicyWithScope,
    Scope,
)
from proxilion.policies.builtin import (
    AllowAllPolicy,
    AttributeBasedPolicy,
    CompositePolicy,
    DenyAllPolicy,
    OwnershipPolicy,
    RoleBasedPolicy,
)
from proxilion.policies.registry import (
    PolicyRegistry,
    get_global_registry,
    reset_global_registry,
)

__all__ = [
    # Base classes
    "Policy",
    "PolicyWithScope",
    "Scope",
    "ActionContext",
    # Registry
    "PolicyRegistry",
    "get_global_registry",
    "reset_global_registry",
    # Built-in policies
    "DenyAllPolicy",
    "AllowAllPolicy",
    "RoleBasedPolicy",
    "AttributeBasedPolicy",
    "OwnershipPolicy",
    "CompositePolicy",
]
