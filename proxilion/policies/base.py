"""
Policy base classes for Proxilion.

This module implements a Pundit-inspired policy pattern for Python,
allowing developers to define authorization rules in a clean,
object-oriented manner.

The Policy pattern separates authorization logic from business logic,
making it easier to understand, test, and maintain security rules.
"""

from __future__ import annotations

import re
from abc import ABC
from typing import TYPE_CHECKING, Any, Generic, TypeVar

if TYPE_CHECKING:
    from proxilion.types import UserContext

# Type variable for the resource being authorized
T = TypeVar("T")


class Policy(ABC, Generic[T]):
    """
    Abstract base class for all Proxilion policies.

    Policies define what actions a user can perform on a resource.
    Following the Pundit pattern, each policy class corresponds to
    a resource type, and methods named `can_<action>` define
    permissions for specific actions.

    Attributes:
        user: The user context for authorization decisions.
        resource: The resource being accessed (can be an instance,
            class, or any object representing the resource).

    Example:
        >>> class DocumentPolicy(Policy):
        ...     def can_read(self, context: dict) -> bool:
        ...         # All authenticated users can read
        ...         return True
        ...
        ...     def can_write(self, context: dict) -> bool:
        ...         # Only owners can write
        ...         return self.resource.owner_id == self.user.user_id
        ...
        ...     def can_delete(self, context: dict) -> bool:
        ...         # Only admins can delete
        ...         return "admin" in self.user.roles

    The `context` parameter allows passing additional runtime
    information for authorization decisions (e.g., IP address,
    time of day, request metadata).
    """

    # Class-level attribute to store the resource name this policy handles
    # Set automatically by the @registry.policy decorator
    _resource_name: str | None = None

    def __init__(self, user: UserContext, resource: T | None = None) -> None:
        """
        Initialize a policy instance.

        Args:
            user: The authenticated user making the request.
            resource: The resource being accessed. Can be None for
                resource-type level checks (e.g., "can user create documents?").
        """
        self.user = user
        self.resource = resource

    def authorize(self, action: str, context: dict[str, Any] | None = None) -> bool:
        """
        Check if the user is authorized to perform an action.

        This method looks up the corresponding `can_<action>` method
        and calls it with the provided context.

        Args:
            action: The action to check (e.g., "read", "write", "execute").
            context: Additional context for the authorization decision.

        Returns:
            True if authorized, False otherwise.

        Raises:
            AttributeError: If no `can_<action>` method is defined.

        Example:
            >>> policy = DocumentPolicy(user, document)
            >>> if policy.authorize("write", {"ip": "192.168.1.1"}):
            ...     document.save()
        """
        method_name = f"can_{action}"
        method = getattr(self, method_name, None)

        if method is None:
            # Default deny if action method doesn't exist
            return False

        return method(context or {})

    def can(self, action: str, context: dict[str, Any] | None = None) -> bool:
        """
        Alias for authorize() for a more fluent API.

        Example:
            >>> if policy.can("delete"):
            ...     resource.delete()
        """
        return self.authorize(action, context)

    @classmethod
    def get_resource_name(cls) -> str:
        """
        Get the resource name this policy handles.

        By default, derives from the class name following the convention
        `ResourcePolicy` -> `resource`. Can be overridden by setting
        `_resource_name` or using the @registry.policy decorator.

        Returns:
            The resource name as a lowercase string.

        Example:
            >>> class DatabaseQueryPolicy(Policy):
            ...     pass
            >>> DatabaseQueryPolicy.get_resource_name()
            'database_query'
        """
        if cls._resource_name:
            return cls._resource_name

        # Convert CamelCase to snake_case and remove 'Policy' suffix
        name = cls.__name__
        if name.endswith("Policy"):
            name = name[:-6]  # Remove 'Policy' suffix

        # Convert CamelCase to snake_case
        # Insert underscore before uppercase letters (except first)
        snake_case = re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()
        return snake_case

    @classmethod
    def get_available_actions(cls) -> list[str]:
        """
        Get all actions defined by this policy.

        Scans the class for methods matching the `can_<action>` pattern.

        Returns:
            List of action names (without the `can_` prefix).

        Example:
            >>> class MyPolicy(Policy):
            ...     def can_read(self, ctx): return True
            ...     def can_write(self, ctx): return False
            >>> MyPolicy.get_available_actions()
            ['read', 'write']
        """
        actions = []
        for name in dir(cls):
            if name.startswith("can_") and callable(getattr(cls, name)):
                action = name[4:]  # Remove 'can_' prefix
                actions.append(action)
        return sorted(actions)


class Scope(Generic[T]):
    """
    Base class for filtering collections based on user permissions.

    The Scope pattern allows filtering a collection of resources
    to only those the user is authorized to access. This is useful
    for listing operations.

    Example:
        >>> class DocumentScope(Scope[Document]):
        ...     def resolve(self) -> list[Document]:
        ...         if "admin" in self.user.roles:
        ...             return self.scope  # Admins see all
        ...         return [doc for doc in self.scope
        ...                 if doc.owner_id == self.user.user_id]
        >>>
        >>> # Usage
        >>> visible_docs = DocumentScope(user, all_documents).resolve()
    """

    def __init__(self, user: UserContext, scope: list[T]) -> None:
        """
        Initialize a scope instance.

        Args:
            user: The authenticated user.
            scope: The initial collection to filter.
        """
        self.user = user
        self.scope = scope

    def resolve(self) -> list[T]:
        """
        Filter the scope to authorized items.

        Subclasses should override this method to implement
        their filtering logic.

        Returns:
            Filtered list of items the user can access.
        """
        # Default implementation returns empty list (safe default)
        return []


class PolicyWithScope(Policy[T]):
    """
    Policy class that includes a Scope inner class.

    This combines the Policy and Scope patterns, following
    the Pundit convention where each Policy can have an
    associated Scope class.

    Example:
        >>> class DocumentPolicy(PolicyWithScope[Document]):
        ...     def can_read(self, context: dict) -> bool:
        ...         return True
        ...
        ...     class Scope(Scope[Document]):
        ...         def resolve(self) -> list[Document]:
        ...             if "admin" in self.user.roles:
        ...                 return self.scope
        ...             return [d for d in self.scope
        ...                     if d.owner_id == self.user.user_id]
        >>>
        >>> # Check permission for single resource
        >>> policy = DocumentPolicy(user, document)
        >>> can_read = policy.can("read")
        >>>
        >>> # Filter collection
        >>> visible = DocumentPolicy.Scope(user, all_docs).resolve()
    """

    # Nested Scope class - subclasses should override
    class Scope(Scope[T]):
        """Default scope that returns empty list."""
        pass


class ActionContext:
    """
    Context object passed to policy methods.

    Provides a structured way to pass runtime context to
    authorization decisions. Can be extended with additional
    attributes as needed.

    Attributes:
        request_id: Unique identifier for the request.
        ip_address: Client IP address.
        timestamp: Request timestamp.
        metadata: Additional key-value metadata.

    Example:
        >>> context = ActionContext(
        ...     ip_address="192.168.1.1",
        ...     metadata={"user_agent": "Claude/1.0"}
        ... )
        >>> policy.authorize("read", context.to_dict())
    """

    def __init__(
        self,
        request_id: str | None = None,
        ip_address: str | None = None,
        timestamp: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.request_id = request_id
        self.ip_address = ip_address
        self.timestamp = timestamp
        self.metadata = metadata or {}

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for passing to policy methods."""
        result: dict[str, Any] = {}
        if self.request_id:
            result["request_id"] = self.request_id
        if self.ip_address:
            result["ip_address"] = self.ip_address
        if self.timestamp:
            result["timestamp"] = self.timestamp
        result.update(self.metadata)
        return result

    def with_metadata(self, **kwargs: Any) -> ActionContext:
        """Create a new context with additional metadata."""
        new_metadata = {**self.metadata, **kwargs}
        return ActionContext(
            request_id=self.request_id,
            ip_address=self.ip_address,
            timestamp=self.timestamp,
            metadata=new_metadata,
        )
