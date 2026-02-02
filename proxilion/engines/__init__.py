"""
Policy engines for Proxilion.

This module provides the policy engine abstraction layer, enabling
pluggable authorization backends. Available engines:

- SimplePolicyEngine: Built-in engine using Policy classes (no dependencies)
- CasbinPolicyEngine: Integration with Casbin (requires casbin package)
- OPAPolicyEngine: Integration with Open Policy Agent (requires OPA server)

Quick Start:
    >>> from proxilion.engines import EngineFactory
    >>>
    >>> # Create a simple engine
    >>> engine = EngineFactory.create("simple")
    >>>
    >>> # Or create with configuration
    >>> engine = EngineFactory.create("casbin", {
    ...     "model_path": "model.conf",
    ...     "policy_path": "policy.csv",
    ... })
"""

from __future__ import annotations

import logging
from typing import Any

from proxilion.engines.base import (
    BasePolicyEngine,
    EngineCapabilities,
    EngineNotAvailableError,
    PolicyEngine,
    PolicyEngineError,
    PolicyEvaluationError,
    PolicyLoadError,
)
from proxilion.engines.simple import SimplePolicyEngine

logger = logging.getLogger(__name__)

# Type alias for engine types
EngineType = str  # "simple", "casbin", "opa"


class EngineFactory:
    """
    Factory for creating policy engine instances.

    The EngineFactory provides a unified interface for creating
    policy engines based on configuration. It handles dependency
    checking and provides helpful error messages when optional
    engines are not available.

    Example:
        >>> # Create with default configuration
        >>> engine = EngineFactory.create("simple")
        >>>
        >>> # Create with custom configuration
        >>> engine = EngineFactory.create("casbin", {
        ...     "model_path": "model.conf",
        ...     "policy_path": "policy.csv",
        ... })
        >>>
        >>> # Create OPA engine
        >>> engine = EngineFactory.create("opa", {
        ...     "opa_url": "http://localhost:8181",
        ...     "policy_path": "v1/data/myapp/authz",
        ... })

    Available Engine Types:
        - "simple": Built-in SimplePolicyEngine (always available)
        - "casbin": CasbinPolicyEngine (requires casbin package)
        - "opa": OPAPolicyEngine (requires OPA server)
    """

    # Registry of available engine types
    _engines: dict[str, type[BasePolicyEngine]] = {
        "simple": SimplePolicyEngine,
    }

    @classmethod
    def create(
        cls,
        engine_type: str = "simple",
        config: dict[str, Any] | None = None,
    ) -> BasePolicyEngine:
        """
        Create a policy engine instance.

        Args:
            engine_type: The type of engine to create.
            config: Engine-specific configuration.

        Returns:
            An initialized policy engine instance.

        Raises:
            EngineNotAvailableError: If the engine type is not available.
            PolicyEngineError: If engine initialization fails.

        Example:
            >>> engine = EngineFactory.create("simple")
            >>> engine = EngineFactory.create("casbin", {
            ...     "model_path": "model.conf",
            ...     "policy_path": "policy.csv",
            ... })
        """
        engine_type = engine_type.lower()

        # Handle casbin engine (lazy import due to optional dependency)
        if engine_type == "casbin":
            return cls._create_casbin_engine(config)

        # Handle OPA engine
        if engine_type == "opa":
            return cls._create_opa_engine(config)

        # Check built-in engines
        if engine_type not in cls._engines:
            available = cls.get_available_engines()
            raise EngineNotAvailableError(
                f"Unknown engine type: '{engine_type}'. "
                f"Available engines: {', '.join(available)}",
                engine_name=engine_type,
            )

        engine_class = cls._engines[engine_type]
        return engine_class(config)

    @classmethod
    def _create_casbin_engine(
        cls,
        config: dict[str, Any] | None,
    ) -> BasePolicyEngine:
        """Create a Casbin engine instance."""
        try:
            from proxilion.engines.casbin_engine import CasbinPolicyEngine
            return CasbinPolicyEngine(config)
        except ImportError:
            raise EngineNotAvailableError(
                "Casbin engine requires the 'casbin' package. "
                "Install with: pip install proxilion[casbin]",
                engine_name="casbin",
            ) from None

    @classmethod
    def _create_opa_engine(
        cls,
        config: dict[str, Any] | None,
    ) -> BasePolicyEngine:
        """Create an OPA engine instance."""
        from proxilion.engines.opa_engine import OPAPolicyEngine
        return OPAPolicyEngine(config)

    @classmethod
    def register(
        cls,
        engine_type: str,
        engine_class: type[BasePolicyEngine],
    ) -> None:
        """
        Register a custom engine type.

        This allows extending Proxilion with custom policy engines.

        Args:
            engine_type: The name for this engine type.
            engine_class: The engine class to register.

        Example:
            >>> class MyCustomEngine(BasePolicyEngine):
            ...     def evaluate(self, user, action, resource, context=None):
            ...         # Custom logic
            ...         pass
            >>>
            >>> EngineFactory.register("custom", MyCustomEngine)
            >>> engine = EngineFactory.create("custom")
        """
        cls._engines[engine_type.lower()] = engine_class
        logger.debug(f"Registered engine type: {engine_type}")

    @classmethod
    def unregister(cls, engine_type: str) -> bool:
        """
        Unregister an engine type.

        Args:
            engine_type: The engine type to remove.

        Returns:
            True if the engine was unregistered.
        """
        engine_type = engine_type.lower()
        if engine_type in cls._engines and engine_type != "simple":
            del cls._engines[engine_type]
            return True
        return False

    @classmethod
    def get_available_engines(cls) -> list[str]:
        """
        Get a list of available engine types.

        Returns:
            List of engine type names that can be created.
        """
        engines = list(cls._engines.keys())

        # Check if casbin is available
        try:
            import casbin  # noqa: F401
            engines.append("casbin")
        except ImportError:
            pass

        # OPA is always "available" (it just needs a server)
        engines.append("opa")

        return sorted(set(engines))

    @classmethod
    def is_available(cls, engine_type: str) -> bool:
        """
        Check if an engine type is available.

        Args:
            engine_type: The engine type to check.

        Returns:
            True if the engine can be created.
        """
        engine_type = engine_type.lower()

        if engine_type in cls._engines:
            return True

        if engine_type == "casbin":
            try:
                import casbin  # noqa: F401
                return True
            except ImportError:
                return False

        return engine_type == "opa"


# Convenience function for creating engines
def create_engine(
    engine_type: str = "simple",
    config: dict[str, Any] | None = None,
) -> BasePolicyEngine:
    """
    Create a policy engine instance.

    Convenience function that delegates to EngineFactory.create().

    Args:
        engine_type: The type of engine to create.
        config: Engine-specific configuration.

    Returns:
        An initialized policy engine instance.

    Example:
        >>> from proxilion.engines import create_engine
        >>> engine = create_engine("simple")
    """
    return EngineFactory.create(engine_type, config)


__all__ = [
    # Protocol and base classes
    "PolicyEngine",
    "BasePolicyEngine",
    "EngineCapabilities",
    # Engines
    "SimplePolicyEngine",
    # Factory
    "EngineFactory",
    "create_engine",
    # Exceptions
    "PolicyEngineError",
    "PolicyLoadError",
    "PolicyEvaluationError",
    "EngineNotAvailableError",
]
