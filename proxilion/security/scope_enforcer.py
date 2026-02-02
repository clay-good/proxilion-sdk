"""
Semantic scope enforcement for Proxilion.

Binds tool calls to execution scopes (read_only, read_write, admin) so that
even if an agent has access to a tool, it can only use it within the scope
of the current operation.

Addresses:
- OWASP ASI02 (Tool Misuse)
- Principle of Least Privilege

Example:
    >>> from proxilion.security.scope_enforcer import (
    ...     ScopeEnforcer, ExecutionScope, scoped_execution
    ... )
    >>> from proxilion import UserContext
    >>>
    >>> enforcer = ScopeEnforcer()
    >>>
    >>> # In a read-only scope, only read operations are allowed
    >>> user = UserContext(user_id="user_123", roles=["viewer"])
    >>> with scoped_execution(enforcer, "read_only", user) as ctx:
    ...     ctx.validate_tool("get_user")  # OK
    ...     ctx.validate_tool("delete_user")  # Raises ScopeViolationError
"""

from __future__ import annotations

import fnmatch
import logging
import re
import threading
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class ExecutionScope(Enum):
    """
    Predefined execution scopes for tool calls.

    Scopes define what categories of operations are permitted.
    """

    READ_ONLY = "read_only"
    """Only read operations (get, list, search, query)."""

    READ_WRITE = "read_write"
    """Read and write operations (create, update, modify)."""

    ADMIN = "admin"
    """All operations including delete and execute."""

    CUSTOM = "custom"
    """Custom scope with explicit allow/deny lists."""


@dataclass
class ScopeBinding:
    """
    Binding between a scope and its allowed/denied operations.

    Attributes:
        scope: The execution scope this binding represents.
        allowed_tools: Set of tool name patterns that are allowed.
        denied_tools: Set of tool name patterns that are denied.
        allowed_actions: Set of action names that are allowed.
        denied_actions: Set of action names that are denied.
        name: Optional name for the scope binding.
        description: Optional description.
    """

    scope: ExecutionScope
    allowed_tools: set[str] = field(default_factory=set)
    denied_tools: set[str] = field(default_factory=set)
    allowed_actions: set[str] = field(default_factory=set)
    denied_actions: set[str] = field(default_factory=set)
    name: str = ""
    description: str = ""

    def allows_action(self, action: str) -> bool:
        """Check if an action is allowed in this scope."""
        # If wildcard allowed, everything is allowed
        if "*" in self.allowed_actions:
            return action.lower() not in {a.lower() for a in self.denied_actions}

        # Check if explicitly denied
        if action.lower() in {a.lower() for a in self.denied_actions}:
            return False

        # Check if explicitly allowed
        if action.lower() in {a.lower() for a in self.allowed_actions}:
            return True

        # If allowed_actions is non-empty and action not in it, deny
        if self.allowed_actions:
            return False

        # Default to allow if no restrictions specified
        return True

    def allows_tool(self, tool_name: str) -> bool:
        """Check if a tool is allowed in this scope."""
        tool_lower = tool_name.lower()

        # Check if explicitly denied by pattern
        for pattern in self.denied_tools:
            if fnmatch.fnmatch(tool_lower, pattern.lower()):
                return False

        # Check if explicitly allowed by pattern
        if self.allowed_tools:
            for pattern in self.allowed_tools:
                if pattern == "*" or fnmatch.fnmatch(tool_lower, pattern.lower()):
                    return True
            return False  # Not in allowed list

        # Default to allow if no tool restrictions
        return True


@dataclass
class ToolClassification:
    """
    Classification of a tool's default scope and actions.

    Attributes:
        tool_name: Name of the tool.
        default_scope: Default scope the tool belongs to.
        actions: Set of actions the tool can perform.
    """

    tool_name: str
    default_scope: ExecutionScope
    actions: set[str] = field(default_factory=set)


# Built-in scope bindings
BUILTIN_SCOPES: dict[str, ScopeBinding] = {
    "read_only": ScopeBinding(
        scope=ExecutionScope.READ_ONLY,
        allowed_actions={"read", "list", "get", "search", "query", "fetch", "find"},
        denied_actions={
            "write", "delete", "execute", "modify", "create", "update", "remove", "drop",
        },
        name="read_only",
        description="Read-only operations only",
    ),
    "read_write": ScopeBinding(
        scope=ExecutionScope.READ_WRITE,
        allowed_actions={
            "read", "list", "get", "search", "query", "fetch", "find",
            "write", "create", "modify", "update", "add", "set",
        },
        denied_actions={"delete", "execute", "remove", "drop", "destroy", "run"},
        name="read_write",
        description="Read and write operations, no delete or execute",
    ),
    "admin": ScopeBinding(
        scope=ExecutionScope.ADMIN,
        allowed_actions={"*"},
        denied_actions=set(),
        name="admin",
        description="All operations allowed",
    ),
}


# Default tool classification patterns
DEFAULT_TOOL_CLASSIFICATIONS: dict[str, ExecutionScope] = {
    r"^(get|read|list|search|query|fetch|find|check|view|show)_": ExecutionScope.READ_ONLY,
    r"^(create|write|update|modify|set|add|put|insert|save)_": ExecutionScope.READ_WRITE,
    r"^(delete|remove|drop|destroy|execute|run|kill|terminate|purge)_": ExecutionScope.ADMIN,
}


class ScopeEnforcer:
    """
    Enforces execution scopes on tool calls.

    The ScopeEnforcer validates that tool calls are permitted within
    the current execution scope based on tool names, actions, and
    explicit allow/deny rules.

    Example:
        >>> enforcer = ScopeEnforcer()
        >>>
        >>> # Validate a tool in read_only scope
        >>> scope = enforcer.get_scope("read_only")
        >>> allowed, reason = enforcer.validate_in_scope("get_user", "read", scope)
        >>> print(allowed)  # True
        >>>
        >>> # Try write operation in read_only scope
        >>> allowed, reason = enforcer.validate_in_scope("update_user", "write", scope)
        >>> print(allowed)  # False
    """

    def __init__(
        self,
        default_scope: ExecutionScope = ExecutionScope.READ_ONLY,
        custom_scopes: dict[str, ScopeBinding] | None = None,
        tool_classifications: dict[str, ExecutionScope] | None = None,
    ) -> None:
        """
        Initialize the scope enforcer.

        Args:
            default_scope: Default scope when no scope is specified.
            custom_scopes: Additional custom scope bindings.
            tool_classifications: Custom tool name patterns to scope mappings.
        """
        self._default_scope = default_scope
        self._lock = threading.RLock()

        # Initialize scopes with built-ins
        self._scopes: dict[str, ScopeBinding] = dict(BUILTIN_SCOPES)
        if custom_scopes:
            self._scopes.update(custom_scopes)

        # Initialize tool classifications
        self._tool_classifications: dict[str, ExecutionScope] = dict(DEFAULT_TOOL_CLASSIFICATIONS)
        if tool_classifications:
            self._tool_classifications.update(tool_classifications)

        # Cache for classified tools
        self._tool_scope_cache: dict[str, ExecutionScope] = {}

    def get_scope(self, scope: str | ExecutionScope) -> ScopeBinding:
        """
        Get a scope binding by name or enum.

        Args:
            scope: Scope name string or ExecutionScope enum.

        Returns:
            The ScopeBinding for the requested scope.

        Raises:
            ValueError: If scope is not found.
        """
        with self._lock:
            if isinstance(scope, ExecutionScope):
                # Return built-in scope for enum
                scope_name = scope.value
            else:
                scope_name = scope.lower()

            if scope_name in self._scopes:
                return self._scopes[scope_name]

            raise ValueError(f"Unknown scope: {scope}")

    def create_scope(
        self,
        name: str,
        allowed_tools: set[str] | None = None,
        denied_tools: set[str] | None = None,
        allowed_actions: set[str] | None = None,
        denied_actions: set[str] | None = None,
        base_scope: ExecutionScope = ExecutionScope.CUSTOM,
        description: str = "",
    ) -> ScopeBinding:
        """
        Create a custom scope binding.

        Args:
            name: Unique name for the scope.
            allowed_tools: Set of tool patterns allowed.
            denied_tools: Set of tool patterns denied.
            allowed_actions: Set of actions allowed.
            denied_actions: Set of actions denied.
            base_scope: Base scope type.
            description: Human-readable description.

        Returns:
            The created ScopeBinding.
        """
        binding = ScopeBinding(
            scope=base_scope,
            allowed_tools=allowed_tools or set(),
            denied_tools=denied_tools or set(),
            allowed_actions=allowed_actions or set(),
            denied_actions=denied_actions or set(),
            name=name,
            description=description,
        )

        with self._lock:
            self._scopes[name.lower()] = binding

        return binding

    def create_scope_from_enum(self, scope: ExecutionScope) -> ScopeBinding:
        """
        Create a scope binding from an ExecutionScope enum.

        Args:
            scope: The ExecutionScope enum value.

        Returns:
            A ScopeBinding matching the enum.
        """
        return self.get_scope(scope.value)

    def classify_tool(
        self,
        tool_name: str,
        scope: ExecutionScope | None = None,
        actions: set[str] | None = None,
    ) -> ToolClassification:
        """
        Classify a tool by name pattern or explicit assignment.

        Args:
            tool_name: Name of the tool.
            scope: Explicit scope assignment (overrides pattern matching).
            actions: Set of actions the tool performs.

        Returns:
            ToolClassification for the tool.
        """
        with self._lock:
            if scope is not None:
                # Explicit scope assignment
                self._tool_scope_cache[tool_name.lower()] = scope
                return ToolClassification(
                    tool_name=tool_name,
                    default_scope=scope,
                    actions=actions or set(),
                )

            # Check cache first
            if tool_name.lower() in self._tool_scope_cache:
                return ToolClassification(
                    tool_name=tool_name,
                    default_scope=self._tool_scope_cache[tool_name.lower()],
                    actions=actions or set(),
                )

            # Pattern matching
            for pattern, pattern_scope in self._tool_classifications.items():
                if re.match(pattern, tool_name, re.IGNORECASE):
                    self._tool_scope_cache[tool_name.lower()] = pattern_scope
                    return ToolClassification(
                        tool_name=tool_name,
                        default_scope=pattern_scope,
                        actions=actions or self._infer_actions(tool_name),
                    )

            # Default to read_only for unknown tools
            return ToolClassification(
                tool_name=tool_name,
                default_scope=self._default_scope,
                actions=actions or set(),
            )

    def _infer_actions(self, tool_name: str) -> set[str]:
        """Infer actions from tool name prefix."""
        tool_lower = tool_name.lower()
        actions = set()

        read_prefixes = ("get_", "read_", "list_", "search_", "query_", "fetch_", "find_")
        if any(tool_lower.startswith(p) for p in read_prefixes):
            actions.add("read")
        if any(tool_lower.startswith(p) for p in ("create_", "write_", "add_", "insert_", "save_")):
            actions.add("write")
            actions.add("create")
        if any(tool_lower.startswith(p) for p in ("update_", "modify_", "set_", "put_")):
            actions.add("write")
            actions.add("modify")
        delete_prefixes = ("delete_", "remove_", "drop_", "destroy_", "purge_")
        if any(tool_lower.startswith(p) for p in delete_prefixes):
            actions.add("delete")
        if any(tool_lower.startswith(p) for p in ("execute_", "run_", "kill_", "terminate_")):
            actions.add("execute")

        return actions or {"execute"}  # Default to execute if unknown

    def validate_in_scope(
        self,
        tool_name: str,
        action: str,
        scope: ScopeBinding,
    ) -> tuple[bool, str | None]:
        """
        Validate if a tool call is allowed in the given scope.

        Args:
            tool_name: Name of the tool to validate.
            action: The action being performed.
            scope: The scope binding to validate against.

        Returns:
            Tuple of (allowed, reason). If not allowed, reason explains why.
        """
        # Check if tool is explicitly denied
        if not scope.allows_tool(tool_name):
            scope_id = scope.name or scope.scope.value
            return False, f"Tool '{tool_name}' is not allowed in scope '{scope_id}'"

        # Check if action is allowed
        if not scope.allows_action(action):
            scope_id = scope.name or scope.scope.value
            return False, f"Action '{action}' is not allowed in scope '{scope_id}'"

        # Check tool classification against scope
        classification = self.classify_tool(tool_name)
        tool_scope = classification.default_scope

        # Scope hierarchy: READ_ONLY < READ_WRITE < ADMIN
        scope_levels = {
            ExecutionScope.READ_ONLY: 1,
            ExecutionScope.READ_WRITE: 2,
            ExecutionScope.ADMIN: 3,
            ExecutionScope.CUSTOM: 0,  # Custom scopes use explicit rules
        }

        current_level = scope_levels.get(scope.scope, 0)
        required_level = scope_levels.get(tool_scope, 0)

        # Custom scopes only use explicit allow/deny rules
        if scope.scope == ExecutionScope.CUSTOM:
            return True, None

        # Check if current scope level is sufficient
        if required_level > current_level:
            return False, (
                f"Tool '{tool_name}' requires '{tool_scope.value}' scope, "
                f"but current scope is '{scope.scope.value}'"
            )

        return True, None

    def get_allowed_tools(self, scope: ScopeBinding) -> set[str]:
        """
        Get the set of allowed tool patterns for a scope.

        Args:
            scope: The scope binding.

        Returns:
            Set of allowed tool patterns.
        """
        if scope.allowed_tools:
            return set(scope.allowed_tools)

        # If no explicit allowed tools, return patterns based on scope level
        if scope.scope == ExecutionScope.READ_ONLY:
            return {"get_*", "read_*", "list_*", "search_*", "query_*", "fetch_*", "find_*"}
        elif scope.scope == ExecutionScope.READ_WRITE:
            return {
                "get_*", "read_*", "list_*", "search_*", "query_*", "fetch_*", "find_*",
                "create_*", "write_*", "update_*", "modify_*", "set_*", "add_*",
            }
        elif scope.scope == ExecutionScope.ADMIN:
            return {"*"}

        return set()

    def add_scope(self, name: str, binding: ScopeBinding) -> None:
        """
        Add a scope binding.

        Args:
            name: Name for the scope.
            binding: The ScopeBinding to add.
        """
        with self._lock:
            self._scopes[name.lower()] = binding

    def remove_scope(self, name: str) -> bool:
        """
        Remove a custom scope.

        Args:
            name: Name of the scope to remove.

        Returns:
            True if removed, False if not found or built-in.
        """
        name_lower = name.lower()
        if name_lower in BUILTIN_SCOPES:
            return False  # Cannot remove built-in scopes

        with self._lock:
            if name_lower in self._scopes:
                del self._scopes[name_lower]
                return True
            return False

    def get_scopes(self) -> dict[str, ScopeBinding]:
        """Get all registered scopes."""
        with self._lock:
            return dict(self._scopes)

    def add_tool_classification(self, pattern: str, scope: ExecutionScope) -> None:
        """
        Add a tool classification pattern.

        Args:
            pattern: Regex pattern to match tool names.
            scope: Scope to assign to matching tools.
        """
        with self._lock:
            self._tool_classifications[pattern] = scope
            # Clear cache as classifications changed
            self._tool_scope_cache.clear()


class ScopeContext:
    """
    Context for scoped execution.

    Tracks tool calls within a scope and validates them against
    the scope's rules.

    Example:
        >>> ctx = ScopeContext(enforcer, scope, user)
        >>> ctx.validate_tool("get_user")  # Returns True
        >>> ctx.validate_tool("delete_user")  # Raises ScopeViolationError
        >>> print(ctx.get_calls())  # ["get_user"]
    """

    def __init__(
        self,
        enforcer: ScopeEnforcer,
        scope: ScopeBinding,
        user: Any,
    ) -> None:
        """
        Initialize scope context.

        Args:
            enforcer: The ScopeEnforcer instance.
            scope: The scope binding for this context.
            user: The user context.
        """
        self.enforcer = enforcer
        self.scope = scope
        self.user = user
        self._calls: list[tuple[str, str]] = []  # (tool_name, action)
        self._closed = False

    def validate_tool(self, tool_name: str, action: str = "execute") -> bool:
        """
        Validate a tool call within this scope.

        Args:
            tool_name: Name of the tool.
            action: Action being performed.

        Returns:
            True if allowed.

        Raises:
            ScopeViolationError: If the tool call is not allowed.
        """
        if self._closed:
            raise RuntimeError("ScopeContext is closed")

        # Import here to avoid circular import
        from proxilion.exceptions import ScopeViolationError

        allowed, reason = self.enforcer.validate_in_scope(tool_name, action, self.scope)
        if not allowed:
            raise ScopeViolationError(
                tool_name=tool_name,
                scope_name=self.scope.name or self.scope.scope.value,
                reason=reason,
            )

        self._calls.append((tool_name, action))
        logger.debug(
            f"Tool '{tool_name}' (action: {action}) validated in scope '{self.scope.name}'"
        )
        return True

    def is_tool_allowed(self, tool_name: str, action: str = "execute") -> bool:
        """
        Check if a tool is allowed without raising an exception.

        Args:
            tool_name: Name of the tool.
            action: Action being performed.

        Returns:
            True if allowed, False otherwise.
        """
        if self._closed:
            return False

        allowed, _ = self.enforcer.validate_in_scope(tool_name, action, self.scope)
        return allowed

    def get_calls(self) -> list[tuple[str, str]]:
        """Get all validated tool calls in this context."""
        return list(self._calls)

    def get_tool_names(self) -> list[str]:
        """Get just the tool names from validated calls."""
        return [call[0] for call in self._calls]

    def close(self) -> None:
        """Close the scope context."""
        self._closed = True
        logger.debug(
            f"ScopeContext closed. Total calls: {len(self._calls)}"
        )

    @property
    def is_closed(self) -> bool:
        """Check if context is closed."""
        return self._closed


@contextmanager
def scoped_execution(
    enforcer: ScopeEnforcer,
    scope: ExecutionScope | str,
    user: Any,
) -> Generator[ScopeContext, None, None]:
    """
    Context manager for scoped tool execution.

    Creates a scope context that validates all tool calls against
    the specified scope's rules.

    Args:
        enforcer: The ScopeEnforcer instance.
        scope: Scope name or ExecutionScope enum.
        user: The user context for this execution.

    Yields:
        ScopeContext for validating tool calls.

    Example:
        >>> with scoped_execution(enforcer, "read_only", user) as ctx:
        ...     ctx.validate_tool("get_user")  # OK
        ...     ctx.validate_tool("delete_user")  # Raises ScopeViolationError
    """
    if isinstance(scope, str):
        scope_binding = enforcer.get_scope(scope)
    else:
        scope_binding = enforcer.create_scope_from_enum(scope)

    ctx = ScopeContext(enforcer, scope_binding, user)
    logger.debug(f"Entering scope '{scope_binding.name or scope_binding.scope.value}'")

    try:
        yield ctx
    finally:
        ctx.close()
        logger.debug(
            f"Exited scope '{scope_binding.name or scope_binding.scope.value}' "
            f"with {len(ctx.get_calls())} tool calls"
        )


def create_scope_enforcer(
    default_scope: ExecutionScope = ExecutionScope.READ_ONLY,
    custom_scopes: dict[str, ScopeBinding] | None = None,
) -> ScopeEnforcer:
    """
    Factory function to create a ScopeEnforcer.

    Args:
        default_scope: Default scope for unknown tools.
        custom_scopes: Additional custom scope bindings.

    Returns:
        Configured ScopeEnforcer instance.
    """
    return ScopeEnforcer(
        default_scope=default_scope,
        custom_scopes=custom_scopes,
    )
