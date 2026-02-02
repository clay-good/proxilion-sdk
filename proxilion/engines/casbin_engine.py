"""
Casbin policy engine integration for Proxilion.

This module provides integration with Casbin, an authorization library
that supports various access control models including RBAC, ABAC, and ACL.

Casbin is an optional dependency. If not installed, attempting to use
this engine will raise an informative error.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from proxilion.engines.base import (
    BasePolicyEngine,
    EngineCapabilities,
    EngineNotAvailableError,
    PolicyEvaluationError,
    PolicyLoadError,
)
from proxilion.types import AuthorizationResult

if TYPE_CHECKING:
    from proxilion.types import UserContext

logger = logging.getLogger(__name__)

# Check if casbin is available
try:
    import casbin
    HAS_CASBIN = True
except ImportError:
    casbin = None  # type: ignore
    HAS_CASBIN = False


class CasbinPolicyEngine(BasePolicyEngine):
    """
    Policy engine using Casbin for authorization.

    Casbin is a powerful authorization library that supports:
    - RBAC (Role-Based Access Control)
    - ABAC (Attribute-Based Access Control)
    - ACL (Access Control List)
    - And more through its flexible model system

    This engine wraps Casbin's enforcer and maps Proxilion's
    user context and authorization requests to Casbin's format.

    Requirements:
        Install with: pip install proxilion[casbin]

    Configuration:
        - model_path: Path to the Casbin model file (model.conf)
        - policy_path: Path to the policy file (policy.csv)
        - adapter: Optional Casbin adapter for database storage

    Example:
        >>> engine = CasbinPolicyEngine({
        ...     "model_path": "model.conf",
        ...     "policy_path": "policy.csv",
        ... })
        >>> result = engine.evaluate(user, "read", "document")

    Model Example (RBAC):
        [request_definition]
        r = sub, obj, act

        [policy_definition]
        p = sub, obj, act

        [role_definition]
        g = _, _

        [policy_effect]
        e = some(where (p.eft == allow))

        [matchers]
        m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act

    Policy Example:
        p, admin, document, read
        p, admin, document, write
        p, user, document, read
        g, alice, admin
        g, bob, user
    """

    name = "casbin"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """
        Initialize the Casbin policy engine.

        Args:
            config: Configuration with model_path and policy_path.

        Raises:
            EngineNotAvailableError: If casbin is not installed.
        """
        if not HAS_CASBIN:
            raise EngineNotAvailableError(
                "Casbin is not installed. Install with: pip install proxilion[casbin]",
                engine_name=self.name,
            )

        super().__init__(config)

        self._enforcer: Any = None
        self._model_path: Path | None = None
        self._policy_path: Path | None = None

        # Initialize from config if paths provided
        model_path = self.get_config("model_path")
        policy_path = self.get_config("policy_path")

        if model_path and policy_path:
            self.load_policies_from_files(model_path, policy_path)

    @property
    def capabilities(self) -> EngineCapabilities:
        """Get engine capabilities."""
        return EngineCapabilities(
            supports_async=False,  # Casbin is synchronous
            supports_caching=True,
            supports_explain=False,
            supports_partial_eval=False,
            supports_hot_reload=True,
            max_batch_size=100,
        )

    @property
    def enforcer(self) -> Any:
        """Get the Casbin enforcer instance."""
        if self._enforcer is None:
            raise PolicyLoadError(
                "Casbin enforcer not initialized. Call load_policies() first.",
                engine_name=self.name,
            )
        return self._enforcer

    def load_policies(self, source: str | Path) -> None:
        """
        Load policies from a source.

        For Casbin, this expects a directory containing model.conf
        and policy.csv files, or a path to the model file with
        the policy file inferred.

        Args:
            source: Path to model file or directory with model and policy.
        """
        path = Path(source)

        if path.is_dir():
            model_path = path / "model.conf"
            policy_path = path / "policy.csv"
        elif path.suffix == ".conf":
            model_path = path
            policy_path = path.with_suffix(".csv")
        else:
            raise PolicyLoadError(
                f"Invalid source for Casbin: {source}. "
                "Provide a directory with model.conf and policy.csv, "
                "or a path to model.conf file.",
                engine_name=self.name,
            )

        self.load_policies_from_files(model_path, policy_path)

    def load_policies_from_files(
        self,
        model_path: str | Path,
        policy_path: str | Path,
    ) -> None:
        """
        Load Casbin model and policy from specific files.

        Args:
            model_path: Path to the model configuration file.
            policy_path: Path to the policy file.

        Raises:
            PolicyLoadError: If files cannot be loaded.
        """
        self._model_path = Path(model_path)
        self._policy_path = Path(policy_path)

        if not self._model_path.exists():
            raise PolicyLoadError(
                f"Model file not found: {self._model_path}",
                engine_name=self.name,
            )

        if not self._policy_path.exists():
            raise PolicyLoadError(
                f"Policy file not found: {self._policy_path}",
                engine_name=self.name,
            )

        try:
            self._enforcer = casbin.Enforcer(
                str(self._model_path),
                str(self._policy_path),
            )
            self._initialized = True
            logger.info(
                f"Casbin enforcer initialized with model={self._model_path}, "
                f"policy={self._policy_path}"
            )
        except Exception as e:
            raise PolicyLoadError(
                f"Failed to initialize Casbin enforcer: {e}",
                engine_name=self.name,
            ) from e

    def load_policies_from_adapter(self, adapter: Any) -> None:
        """
        Load policies using a Casbin adapter.

        Adapters allow storing policies in databases like
        PostgreSQL, MySQL, Redis, etc.

        Args:
            adapter: A Casbin adapter instance.
        """
        model_path = self.get_config("model_path")
        if not model_path:
            raise PolicyLoadError(
                "model_path is required when using an adapter",
                engine_name=self.name,
            )

        try:
            self._enforcer = casbin.Enforcer(str(model_path), adapter)
            self._initialized = True
            logger.info(f"Casbin enforcer initialized with adapter: {type(adapter)}")
        except Exception as e:
            raise PolicyLoadError(
                f"Failed to initialize Casbin with adapter: {e}",
                engine_name=self.name,
            ) from e

    def evaluate(
        self,
        user: UserContext,
        action: str,
        resource: str,
        context: dict[str, Any] | None = None,
    ) -> AuthorizationResult:
        """
        Evaluate an authorization request using Casbin.

        The user_id is passed as the subject (sub), the resource
        as the object (obj), and the action as the action (act).

        Args:
            user: The user context.
            action: The action being attempted.
            resource: The resource being accessed.
            context: Additional context (not used by basic Casbin models).

        Returns:
            AuthorizationResult with the decision.
        """
        try:
            # Basic enforcement: (sub, obj, act)
            allowed = self.enforcer.enforce(user.user_id, resource, action)

            if allowed:
                reason = f"Casbin allowed {user.user_id} to {action} on {resource}"
            else:
                reason = f"Casbin denied {user.user_id} to {action} on {resource}"

            logger.debug(f"Casbin evaluation: {reason}")

            return AuthorizationResult(
                allowed=allowed,
                reason=reason,
                policies_evaluated=["casbin"],
            )
        except Exception as e:
            raise PolicyEvaluationError(
                f"Casbin evaluation failed: {e}",
                engine_name=self.name,
            ) from e

    def evaluate_with_roles(
        self,
        user: UserContext,
        action: str,
        resource: str,
        context: dict[str, Any] | None = None,
    ) -> AuthorizationResult:
        """
        Evaluate using user's roles in addition to user_id.

        This method checks if any of the user's roles would allow
        the action, which is useful for RBAC models.

        Args:
            user: The user context.
            action: The action being attempted.
            resource: The resource being accessed.
            context: Additional context.

        Returns:
            AuthorizationResult with the decision.
        """
        # First check user_id directly
        result = self.evaluate(user, action, resource, context)
        if result.allowed:
            return result

        # Then check each role
        for role in user.roles:
            try:
                if self.enforcer.enforce(role, resource, action):
                    return AuthorizationResult(
                        allowed=True,
                        reason=f"Casbin allowed role '{role}' to {action} on {resource}",
                        policies_evaluated=["casbin"],
                    )
            except Exception:
                continue

        return AuthorizationResult(
            allowed=False,
            reason=f"Casbin denied {user.user_id} (and all roles) to {action} on {resource}",
            policies_evaluated=["casbin"],
        )

    def add_policy(self, subject: str, resource: str, action: str) -> bool:
        """
        Add a policy rule dynamically.

        Args:
            subject: The subject (user or role).
            resource: The resource.
            action: The action.

        Returns:
            True if the policy was added, False if it already exists.
        """
        return self.enforcer.add_policy(subject, resource, action)

    def remove_policy(self, subject: str, resource: str, action: str) -> bool:
        """
        Remove a policy rule.

        Args:
            subject: The subject (user or role).
            resource: The resource.
            action: The action.

        Returns:
            True if the policy was removed, False if it didn't exist.
        """
        return self.enforcer.remove_policy(subject, resource, action)

    def add_role_for_user(self, user: str, role: str) -> bool:
        """
        Add a role for a user.

        Args:
            user: The user identifier.
            role: The role to add.

        Returns:
            True if the role was added.
        """
        return self.enforcer.add_role_for_user(user, role)

    def remove_role_for_user(self, user: str, role: str) -> bool:
        """
        Remove a role from a user.

        Args:
            user: The user identifier.
            role: The role to remove.

        Returns:
            True if the role was removed.
        """
        return self.enforcer.delete_role_for_user(user, role)

    def get_roles_for_user(self, user: str) -> list[str]:
        """
        Get all roles for a user.

        Args:
            user: The user identifier.

        Returns:
            List of role names.
        """
        return self.enforcer.get_roles_for_user(user)

    def reload_policies(self) -> None:
        """Reload policies from the policy file."""
        if self._enforcer is not None:
            self._enforcer.load_policy()
            logger.info("Casbin policies reloaded")

    def save_policies(self) -> None:
        """Save current policies to the policy file."""
        if self._enforcer is not None:
            self._enforcer.save_policy()
            logger.info("Casbin policies saved")
