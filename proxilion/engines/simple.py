"""
Simple policy engine for Proxilion.

This module provides the SimplePolicyEngine, a zero-dependency
policy engine that uses the Pundit-style Policy classes for
authorization decisions.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from proxilion.engines.base import BasePolicyEngine, EngineCapabilities
from proxilion.policies.base import Policy
from proxilion.policies.builtin import DenyAllPolicy
from proxilion.policies.registry import PolicyRegistry
from proxilion.types import AuthorizationResult

if TYPE_CHECKING:
    from proxilion.types import UserContext

logger = logging.getLogger(__name__)


class SimplePolicyEngine(BasePolicyEngine):
    """
    Simple policy engine using Pundit-style Policy classes.

    This is the default policy engine for Proxilion. It uses the
    PolicyRegistry to look up policy classes and evaluates them
    against user context and resources.

    Features:
        - Class-based policies (Pundit-style)
        - Dictionary-based rules for simple cases
        - Default deny behavior
        - Integration with PolicyRegistry
        - No external dependencies

    Example:
        >>> engine = SimplePolicyEngine()
        >>>
        >>> # Register a policy
        >>> @engine.registry.policy("calculator")
        >>> class CalculatorPolicy(Policy):
        ...     def can_execute(self, context: dict) -> bool:
        ...         return "calculator_user" in self.user.roles
        >>>
        >>> # Evaluate
        >>> result = engine.evaluate(user, "execute", "calculator")
        >>> print(result.allowed)  # True or False

    Configuration:
        - default_policy: Policy class to use when no policy is registered.
            Defaults to DenyAllPolicy.
        - allow_missing_policies: If True, missing policies return deny
            instead of raising an error. Defaults to True.
    """

    name = "simple"

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        registry: PolicyRegistry | None = None,
    ) -> None:
        """
        Initialize the SimplePolicyEngine.

        Args:
            config: Engine configuration options.
            registry: Optional PolicyRegistry to use. If not provided,
                a new registry is created.
        """
        super().__init__(config)

        # Get default policy from config or use DenyAllPolicy
        default_policy = self.get_config("default_policy", DenyAllPolicy)
        self.allow_missing_policies = self.get_config("allow_missing_policies", True)

        # Use provided registry or create new one
        self.registry = registry or PolicyRegistry(default_policy=default_policy)

        # Dictionary-based rules for simple authorization
        self._dict_rules: dict[str, dict[str, list[str]]] = {}

        self._initialized = True
        logger.debug(f"SimplePolicyEngine initialized with registry: {self.registry}")

    @property
    def capabilities(self) -> EngineCapabilities:
        """Get engine capabilities."""
        return EngineCapabilities(
            supports_async=True,
            supports_caching=False,
            supports_explain=True,
            supports_partial_eval=False,
            supports_hot_reload=True,
            max_batch_size=100,
        )

    def evaluate(
        self,
        user: UserContext,
        action: str,
        resource: str,
        context: dict[str, Any] | None = None,
    ) -> AuthorizationResult:
        """
        Evaluate an authorization request.

        The evaluation process:
        1. Check dictionary-based rules first (if configured)
        2. Look up policy class from registry
        3. Instantiate policy with user and resource
        4. Call the can_<action> method
        5. Return AuthorizationResult

        Args:
            user: The user context.
            action: The action being attempted.
            resource: The resource being accessed.
            context: Additional context for the decision.

        Returns:
            AuthorizationResult with the decision.
        """
        ctx = context or {}
        policies_evaluated: list[str] = []

        logger.debug(
            f"Evaluating: user={user.user_id}, action={action}, "
            f"resource={resource}"
        )

        # Check dictionary rules first
        if resource in self._dict_rules:
            dict_result = self._evaluate_dict_rules(user, action, resource)
            if dict_result is not None:
                policies_evaluated.append(f"dict_rules:{resource}")
                return AuthorizationResult(
                    allowed=dict_result,
                    reason=f"Dictionary rule for {resource}:{action}",
                    policies_evaluated=policies_evaluated,
                )

        # Get policy class from registry
        try:
            policy_class = self.registry.get_policy(resource)
            policies_evaluated.append(policy_class.__name__)
        except Exception as e:
            if self.allow_missing_policies:
                logger.debug(f"No policy for '{resource}', denying: {e}")
                return AuthorizationResult(
                    allowed=False,
                    reason=f"No policy registered for resource '{resource}'",
                    policies_evaluated=policies_evaluated,
                )
            raise

        # Get the resource object from context if provided
        resource_obj = ctx.get("resource_object")

        # Instantiate policy
        policy = policy_class(user, resource_obj)

        # Evaluate the action
        allowed = policy.authorize(action, ctx)

        # Mark as authorized in registry for tracking
        self.registry.mark_authorized(resource)

        # Build result
        if allowed:
            reason = f"Policy {policy_class.__name__} allowed action '{action}'"
        else:
            reason = f"Policy {policy_class.__name__} denied action '{action}'"

        logger.debug(f"Result: allowed={allowed}, reason={reason}")

        return AuthorizationResult(
            allowed=allowed,
            reason=reason,
            policies_evaluated=policies_evaluated,
        )

    def _evaluate_dict_rules(
        self,
        user: UserContext,
        action: str,
        resource: str,
    ) -> bool | None:
        """
        Evaluate dictionary-based rules.

        Args:
            user: The user context.
            action: The action being attempted.
            resource: The resource being accessed.

        Returns:
            True if allowed, False if denied, None if no rule matches.
        """
        rules = self._dict_rules.get(resource, {})
        required_roles = rules.get(action)

        if required_roles is None:
            return None  # No rule for this action

        user_roles = set(user.roles)
        allowed_roles = set(required_roles)

        return bool(user_roles & allowed_roles)

    def add_rule(
        self,
        resource: str,
        action: str,
        allowed_roles: list[str],
    ) -> None:
        """
        Add a dictionary-based authorization rule.

        This is a simpler alternative to defining a full Policy class.
        Dictionary rules are checked before policy classes.

        Args:
            resource: The resource name.
            action: The action name.
            allowed_roles: List of roles that are allowed.

        Example:
            >>> engine.add_rule("calculator", "execute", ["user", "admin"])
            >>> engine.add_rule("calculator", "configure", ["admin"])
        """
        if resource not in self._dict_rules:
            self._dict_rules[resource] = {}

        self._dict_rules[resource][action] = allowed_roles
        logger.debug(
            f"Added rule: {resource}:{action} -> {allowed_roles}"
        )

    def add_rules(self, rules: dict[str, dict[str, list[str]]]) -> None:
        """
        Add multiple dictionary-based rules at once.

        Args:
            rules: Nested dict of resource -> action -> roles.

        Example:
            >>> engine.add_rules({
            ...     "calculator": {
            ...         "execute": ["user", "admin"],
            ...         "configure": ["admin"],
            ...     },
            ...     "database": {
            ...         "query": ["analyst", "admin"],
            ...         "write": ["admin"],
            ...     },
            ... })
        """
        for resource, actions in rules.items():
            for action, roles in actions.items():
                self.add_rule(resource, action, roles)

    def remove_rule(self, resource: str, action: str | None = None) -> bool:
        """
        Remove a dictionary-based rule.

        Args:
            resource: The resource name.
            action: The action to remove, or None to remove all actions.

        Returns:
            True if a rule was removed, False otherwise.
        """
        if resource not in self._dict_rules:
            return False

        if action is None:
            del self._dict_rules[resource]
            return True

        if action in self._dict_rules[resource]:
            del self._dict_rules[resource][action]
            if not self._dict_rules[resource]:
                del self._dict_rules[resource]
            return True

        return False

    def clear_rules(self) -> None:
        """Clear all dictionary-based rules."""
        self._dict_rules.clear()
        logger.debug("Cleared all dictionary rules")

    def load_policies(self, source: str | Path) -> None:
        """
        Load policies from a Python module or directory.

        This method imports Policy classes from the specified source
        and registers them with the registry.

        Args:
            source: Path to a Python module or directory containing
                Policy class definitions.

        Note:
            Policy classes must use the naming convention *Policy
            (e.g., DatabasePolicy) to be auto-discovered.
        """
        path = Path(source)

        if path.is_file() and path.suffix == ".py":
            self._load_from_file(path)
        elif path.is_dir():
            self._load_from_directory(path)
        else:
            # Assume it's a module path
            self._load_from_module(str(source))

    def _load_from_file(self, path: Path) -> None:
        """Load policies from a Python file."""
        import importlib.util

        spec = importlib.util.spec_from_file_location("policies", path)
        if spec is None or spec.loader is None:
            logger.warning(f"Could not load policies from {path}")
            return

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        self._register_policies_from_module(module)

    def _load_from_directory(self, path: Path) -> None:
        """Load policies from all Python files in a directory."""
        for py_file in path.glob("*.py"):
            if py_file.name.startswith("_"):
                continue
            self._load_from_file(py_file)

    def _load_from_module(self, module_path: str) -> None:
        """Load policies from a module path."""
        import importlib

        try:
            module = importlib.import_module(module_path)
            self._register_policies_from_module(module)
        except ImportError as e:
            logger.warning(f"Could not import module {module_path}: {e}")

    def _register_policies_from_module(self, module: Any) -> None:
        """Register all Policy subclasses from a module."""
        for name in dir(module):
            obj = getattr(module, name)
            if (
                isinstance(obj, type)
                and issubclass(obj, Policy)
                and obj is not Policy
                and name.endswith("Policy")
            ):
                self.registry.register_by_convention(obj)
                logger.debug(f"Registered policy: {name}")

    def policy(self, resource_name: str) -> Any:
        """
        Decorator for registering a policy class.

        Convenience method that delegates to the registry.

        Args:
            resource_name: The resource this policy handles.

        Returns:
            A decorator function.

        Example:
            >>> @engine.policy("database")
            >>> class DatabasePolicy(Policy):
            ...     def can_query(self, context: dict) -> bool:
            ...         return True
        """
        return self.registry.policy(resource_name)

    def explain(
        self,
        user: UserContext,
        action: str,
        resource: str,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Explain an authorization decision.

        Provides detailed information about how a decision was made,
        useful for debugging and auditing.

        Args:
            user: The user context.
            action: The action being attempted.
            resource: The resource being accessed.
            context: Additional context.

        Returns:
            Dictionary containing explanation details.
        """
        result = self.evaluate(user, action, resource, context)

        explanation = {
            "decision": "ALLOW" if result.allowed else "DENY",
            "reason": result.reason,
            "policies_evaluated": result.policies_evaluated,
            "user": {
                "user_id": user.user_id,
                "roles": user.roles,
            },
            "request": {
                "action": action,
                "resource": resource,
            },
        }

        # Check for dict rules
        if resource in self._dict_rules:
            explanation["dict_rules"] = self._dict_rules[resource]

        # Check for policy class
        if self.registry.has_policy(resource):
            policy_class = self.registry.get_policy(resource)
            explanation["policy_class"] = policy_class.__name__
            explanation["available_actions"] = policy_class.get_available_actions()

        return explanation
