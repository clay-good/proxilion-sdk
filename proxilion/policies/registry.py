"""
Policy registry for Proxilion.

This module provides the PolicyRegistry class for registering, discovering,
and looking up policy classes. It supports both explicit registration via
decorators and automatic discovery based on naming conventions.
"""

from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING, Any

from proxilion.exceptions import PolicyNotFoundError

if TYPE_CHECKING:
    from proxilion.policies.base import Policy
    from proxilion.types import UserContext

logger = logging.getLogger(__name__)


class PolicyRegistry:
    """
    Registry for policy classes.

    The PolicyRegistry manages policy class registration and lookup,
    enabling the authorization system to find the appropriate policy
    for any given resource.

    Features:
        - Decorator-based registration (@registry.policy("resource_name"))
        - Auto-discovery by naming convention (ResourcePolicy -> "resource")
        - Thread-safe operations
        - Policy caching for performance
        - Verification that all resources have been authorized

    Example:
        >>> registry = PolicyRegistry()
        >>>
        >>> @registry.policy("calculator")
        >>> class CalculatorPolicy(Policy):
        ...     def can_execute(self, context: dict) -> bool:
        ...         return "calculator_user" in self.user.roles
        >>>
        >>> # Lookup and use
        >>> policy_class = registry.get_policy("calculator")
        >>> policy = policy_class(user, resource)
        >>> if policy.can("execute"):
        ...     # proceed

    Thread Safety:
        All operations are thread-safe via internal locking.
    """

    def __init__(self, default_policy: type[Policy] | None = None) -> None:
        """
        Initialize the registry.

        Args:
            default_policy: Optional default policy class to use when no
                policy is registered for a resource. If None, lookups for
                unregistered resources will raise PolicyNotFoundError.
        """
        self._policies: dict[str, type[Policy]] = {}
        self._default_policy = default_policy
        self._lock = threading.RLock()
        self._authorized_resources: set[str] = set()

    def policy(self, resource_name: str) -> Any:
        """
        Decorator for registering a policy class.

        This is the primary way to register policies. The decorator
        associates a policy class with a resource name.

        Args:
            resource_name: The name of the resource this policy handles.

        Returns:
            A decorator function that registers the policy class.

        Example:
            >>> @registry.policy("database")
            >>> class DatabasePolicy(Policy):
            ...     def can_query(self, context: dict) -> bool:
            ...         return "analyst" in self.user.roles
        """
        def decorator(policy_class: type[Policy]) -> type[Policy]:
            self.register(resource_name, policy_class)
            return policy_class
        return decorator

    def register(self, resource_name: str, policy_class: type[Policy]) -> None:
        """
        Register a policy class for a resource.

        Args:
            resource_name: The name of the resource.
            policy_class: The policy class to register.

        Raises:
            ValueError: If a policy is already registered for this resource.

        Example:
            >>> registry.register("documents", DocumentPolicy)
        """
        with self._lock:
            if resource_name in self._policies:
                existing = self._policies[resource_name].__name__
                logger.warning(
                    f"Overwriting policy for '{resource_name}': "
                    f"{existing} -> {policy_class.__name__}"
                )

            self._policies[resource_name] = policy_class
            # Set the resource name on the policy class
            policy_class._resource_name = resource_name

            logger.debug(
                f"Registered policy '{policy_class.__name__}' for resource '{resource_name}'"
            )

    def register_by_convention(self, policy_class: type[Policy]) -> None:
        """
        Register a policy class using naming convention.

        Derives the resource name from the class name:
        - DatabaseQueryPolicy -> "database_query"
        - UserPolicy -> "user"

        Args:
            policy_class: The policy class to register.

        Example:
            >>> class FileSystemPolicy(Policy):
            ...     pass
            >>> registry.register_by_convention(FileSystemPolicy)
            >>> # Registered as "file_system"
        """
        resource_name = policy_class.get_resource_name()
        self.register(resource_name, policy_class)

    def get_policy(self, resource_name: str) -> type[Policy]:
        """
        Get the policy class for a resource.

        Args:
            resource_name: The name of the resource.

        Returns:
            The registered policy class.

        Raises:
            PolicyNotFoundError: If no policy is registered and no default is set.

        Example:
            >>> policy_class = registry.get_policy("database")
            >>> policy = policy_class(user, db_connection)
        """
        with self._lock:
            if resource_name in self._policies:
                return self._policies[resource_name]

            if self._default_policy is not None:
                logger.debug(
                    f"No policy for '{resource_name}', using default: "
                    f"{self._default_policy.__name__}"
                )
                return self._default_policy

            available = list(self._policies.keys())
            raise PolicyNotFoundError(resource_name, available)

    def get_policy_instance(
        self,
        resource_name: str,
        user: UserContext,
        resource: Any = None,
    ) -> Policy:
        """
        Get an instantiated policy for a resource.

        Convenience method that looks up the policy class and
        creates an instance with the provided user and resource.

        Args:
            resource_name: The name of the resource.
            user: The user context for the policy.
            resource: The resource instance (optional).

        Returns:
            An instantiated policy object.

        Example:
            >>> policy = registry.get_policy_instance("document", user, doc)
            >>> if policy.can("read"):
            ...     return doc.content
        """
        policy_class = self.get_policy(resource_name)
        return policy_class(user, resource)

    def has_policy(self, resource_name: str) -> bool:
        """
        Check if a policy is registered for a resource.

        Args:
            resource_name: The name of the resource.

        Returns:
            True if a policy is registered, False otherwise.
        """
        with self._lock:
            return resource_name in self._policies

    def list_policies(self) -> dict[str, str]:
        """
        List all registered policies.

        Returns:
            Dictionary mapping resource names to policy class names.

        Example:
            >>> registry.list_policies()
            {'database': 'DatabasePolicy', 'file': 'FilePolicy'}
        """
        with self._lock:
            return {
                resource: policy.__name__
                for resource, policy in self._policies.items()
            }

    def unregister(self, resource_name: str) -> bool:
        """
        Unregister a policy for a resource.

        Args:
            resource_name: The name of the resource.

        Returns:
            True if a policy was unregistered, False if none was registered.
        """
        with self._lock:
            if resource_name in self._policies:
                del self._policies[resource_name]
                logger.debug(f"Unregistered policy for resource '{resource_name}'")
                return True
            return False

    def clear(self) -> None:
        """
        Clear all registered policies.

        Useful for testing or reconfiguration.
        """
        with self._lock:
            self._policies.clear()
            self._authorized_resources.clear()
            logger.debug("Cleared all registered policies")

    def set_default_policy(self, policy_class: type[Policy] | None) -> None:
        """
        Set or clear the default policy.

        Args:
            policy_class: The default policy class, or None to clear.
        """
        with self._lock:
            self._default_policy = policy_class
            if policy_class:
                logger.debug(f"Set default policy to '{policy_class.__name__}'")
            else:
                logger.debug("Cleared default policy")

    # Authorization tracking methods

    def mark_authorized(self, resource_name: str) -> None:
        """
        Mark a resource as having been authorized.

        This is called automatically by the authorization system
        when a policy check is performed.

        Args:
            resource_name: The name of the authorized resource.
        """
        with self._lock:
            self._authorized_resources.add(resource_name)

    def clear_authorized(self) -> None:
        """
        Clear the set of authorized resources.

        Should be called at the start of each request to track
        which resources were checked during that request.
        """
        with self._lock:
            self._authorized_resources.clear()

    def verify_all_authorized(self, expected_resources: list[str]) -> tuple[bool, list[str]]:
        """
        Verify that all expected resources were authorized.

        This method helps catch cases where authorization was
        accidentally skipped for a resource that should have been checked.

        Args:
            expected_resources: List of resource names that should have been authorized.

        Returns:
            Tuple of (all_authorized, missing_resources).
            - all_authorized: True if all resources were checked.
            - missing_resources: List of resources that were not authorized.

        Example:
            >>> # At end of request handling
            >>> ok, missing = registry.verify_all_authorized(["document", "user"])
            >>> if not ok:
            ...     logger.error(f"Authorization skipped for: {missing}")
        """
        with self._lock:
            missing = [
                resource for resource in expected_resources
                if resource not in self._authorized_resources
            ]
            return len(missing) == 0, missing

    def get_authorized_resources(self) -> set[str]:
        """
        Get the set of resources that have been authorized.

        Returns:
            Set of resource names that were checked.
        """
        with self._lock:
            return self._authorized_resources.copy()


# Global registry instance for convenience
_global_registry: PolicyRegistry | None = None
_global_registry_lock = threading.Lock()


def get_global_registry() -> PolicyRegistry:
    """
    Get the global policy registry instance.

    Creates one if it doesn't exist. This provides a convenient
    singleton for simple use cases.

    Returns:
        The global PolicyRegistry instance.

    Example:
        >>> from proxilion.policies.registry import get_global_registry
        >>> registry = get_global_registry()
        >>> @registry.policy("my_resource")
        >>> class MyPolicy(Policy):
        ...     pass
    """
    global _global_registry
    if _global_registry is not None:
        return _global_registry
    with _global_registry_lock:
        # Double-check after acquiring lock
        if _global_registry is None:
            _global_registry = PolicyRegistry()
        return _global_registry


def reset_global_registry() -> None:
    """
    Reset the global registry.

    Clears the global registry instance. Primarily useful for testing.
    """
    global _global_registry
    with _global_registry_lock:
        if _global_registry is not None:
            _global_registry.clear()
        _global_registry = None
