"""
Policy engine base classes and protocols for Proxilion.

This module defines the PolicyEngine protocol that all policy engines
must implement, enabling pluggable authorization backends like
Casbin, OPA, or custom implementations.
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from proxilion.types import AuthorizationResult, UserContext


@runtime_checkable
class PolicyEngine(Protocol):
    """
    Protocol defining the interface for policy engines.

    All policy engines must implement this protocol to be compatible
    with Proxilion. This includes the built-in SimplePolicyEngine,
    as well as optional integrations like Casbin and OPA.

    The protocol requires both synchronous and asynchronous evaluation
    methods to support different application architectures.

    Example:
        >>> class CustomEngine:
        ...     def evaluate(
        ...         self, user: UserContext, action: str,
        ...         resource: str, context: dict
        ...     ) -> AuthorizationResult:
        ...         # Custom authorization logic
        ...         return AuthorizationResult(allowed=True, reason="Custom check passed")
        ...
        ...     async def evaluate_async(
        ...         self, user: UserContext, action: str,
        ...         resource: str, context: dict
        ...     ) -> AuthorizationResult:
        ...         return self.evaluate(user, action, resource, context)
        ...
        ...     def load_policies(self, source: str | Path) -> None:
        ...         pass
    """

    def evaluate(
        self,
        user: UserContext,
        action: str,
        resource: str,
        context: dict[str, Any] | None = None,
    ) -> AuthorizationResult:
        """
        Evaluate an authorization request synchronously.

        Args:
            user: The user context containing identity and roles.
            action: The action being attempted (e.g., "read", "execute").
            resource: The resource being accessed (e.g., "database_query").
            context: Additional context for the authorization decision.

        Returns:
            AuthorizationResult indicating whether the action is allowed.
        """
        ...

    async def evaluate_async(
        self,
        user: UserContext,
        action: str,
        resource: str,
        context: dict[str, Any] | None = None,
    ) -> AuthorizationResult:
        """
        Evaluate an authorization request asynchronously.

        This method is useful for engines that need to make external
        calls (e.g., OPA server) or perform I/O operations.

        Args:
            user: The user context containing identity and roles.
            action: The action being attempted.
            resource: The resource being accessed.
            context: Additional context for the authorization decision.

        Returns:
            AuthorizationResult indicating whether the action is allowed.
        """
        ...

    def load_policies(self, source: str | Path) -> None:
        """
        Load policies from a source.

        The source format depends on the engine:
        - SimplePolicyEngine: Python module path or directory
        - CasbinPolicyEngine: Path to policy.csv file
        - OPAPolicyEngine: Path to Rego files or OPA bundle

        Args:
            source: Path or identifier for the policy source.
        """
        ...


class BasePolicyEngine(ABC):
    """
    Abstract base class for policy engines.

    Provides common functionality and default implementations
    for policy engines. Engines can extend this class instead
    of implementing the Protocol directly.

    Attributes:
        name: Human-readable name for the engine.
        config: Configuration dictionary passed during initialization.
    """

    name: str = "base"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """
        Initialize the policy engine.

        Args:
            config: Engine-specific configuration options.
        """
        self.config = config or {}
        self._initialized = False

    @abstractmethod
    def evaluate(
        self,
        user: UserContext,
        action: str,
        resource: str,
        context: dict[str, Any] | None = None,
    ) -> AuthorizationResult:
        """
        Evaluate an authorization request.

        Subclasses must implement this method.

        Args:
            user: The user context.
            action: The action being attempted.
            resource: The resource being accessed.
            context: Additional context.

        Returns:
            AuthorizationResult with the decision.
        """
        pass

    async def evaluate_async(
        self,
        user: UserContext,
        action: str,
        resource: str,
        context: dict[str, Any] | None = None,
    ) -> AuthorizationResult:
        """
        Async version of evaluate.

        Default implementation wraps the sync version.
        Override for truly async implementations.

        Args:
            user: The user context.
            action: The action being attempted.
            resource: The resource being accessed.
            context: Additional context.

        Returns:
            AuthorizationResult with the decision.
        """
        # Run sync version in thread pool for non-blocking behavior
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self.evaluate, user, action, resource, context
        )

    def load_policies(self, source: str | Path) -> None:
        """
        Load policies from a source.

        Default implementation does nothing. Override in subclasses
        that support external policy loading.

        Args:
            source: Path or identifier for policy source.
        """
        pass

    def is_initialized(self) -> bool:
        """Check if the engine has been initialized."""
        return self._initialized

    def get_config(self, key: str, default: Any = None) -> Any:
        """Get a configuration value."""
        return self.config.get(key, default)


class EngineCapabilities:
    """
    Describes the capabilities of a policy engine.

    This class helps the Proxilion core understand what features
    an engine supports, enabling graceful degradation when features
    are unavailable.
    """

    def __init__(
        self,
        supports_async: bool = True,
        supports_caching: bool = False,
        supports_explain: bool = False,
        supports_partial_eval: bool = False,
        supports_hot_reload: bool = False,
        max_batch_size: int = 1,
    ) -> None:
        """
        Initialize engine capabilities.

        Args:
            supports_async: Whether async evaluation is truly async.
            supports_caching: Whether the engine caches decisions.
            supports_explain: Whether the engine can explain decisions.
            supports_partial_eval: Whether partial evaluation is supported.
            supports_hot_reload: Whether policies can be reloaded at runtime.
            max_batch_size: Maximum number of requests in batch evaluation.
        """
        self.supports_async = supports_async
        self.supports_caching = supports_caching
        self.supports_explain = supports_explain
        self.supports_partial_eval = supports_partial_eval
        self.supports_hot_reload = supports_hot_reload
        self.max_batch_size = max_batch_size


class PolicyEngineError(Exception):
    """Base exception for policy engine errors."""

    def __init__(self, message: str, engine_name: str | None = None) -> None:
        self.engine_name = engine_name
        super().__init__(f"[{engine_name or 'unknown'}] {message}")


class PolicyLoadError(PolicyEngineError):
    """Raised when policies fail to load."""
    pass


class PolicyEvaluationError(PolicyEngineError):
    """Raised when policy evaluation fails."""
    pass


class EngineNotAvailableError(PolicyEngineError):
    """Raised when a required engine is not available."""
    pass
