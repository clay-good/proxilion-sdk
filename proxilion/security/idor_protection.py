"""
IDOR (Insecure Direct Object Reference) protection for Proxilion.

This module provides protection against IDOR attacks, where attackers
attempt to access resources by manipulating object IDs in tool calls.
"""

from __future__ import annotations

import logging
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from proxilion.exceptions import IDORViolationError

logger = logging.getLogger(__name__)


@dataclass
class ResourceScope:
    """Defines the scope of resources a user can access."""
    allowed_ids: set[str] = field(default_factory=set)
    allowed_patterns: list[str] = field(default_factory=list)
    scope_loader: Callable[[str], set[str]] | None = None


@dataclass
class IDPattern:
    """Pattern for identifying object IDs in parameters."""
    parameter_name: str
    resource_type: str
    pattern: str = r".*"  # Regex to validate ID format
    extractor: Callable[[Any], list[str]] | None = None


class IDORProtector:
    """
    Protects against Insecure Direct Object Reference attacks.

    IDOR attacks occur when a user manipulates object IDs to access
    resources they shouldn't have access to. This class validates
    that object IDs in tool call arguments are within the user's
    authorized scope.

    Features:
        - Register allowed resource scopes per user
        - Define patterns to extract object IDs from arguments
        - Validate access before tool execution
        - Support for dynamic scope loading

    Example:
        >>> protector = IDORProtector()
        >>>
        >>> # Register user's allowed documents
        >>> protector.register_scope(
        ...     user_id="user_123",
        ...     resource_type="document",
        ...     allowed_ids={"doc_1", "doc_2", "doc_3"},
        ... )
        >>>
        >>> # Define where IDs appear in arguments
        >>> protector.register_id_pattern(
        ...     parameter_name="document_id",
        ...     resource_type="document",
        ... )
        >>>
        >>> # Validate access
        >>> protector.validate_access("user_123", "document", "doc_1")  # True
        >>> protector.validate_access("user_123", "document", "doc_999")  # False
    """

    # Common ID patterns for auto-detection
    UUID_PATTERN = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        re.IGNORECASE,
    )
    NUMERIC_PATTERN = re.compile(r"^\d+$")
    ALPHANUMERIC_PATTERN = re.compile(r"^[a-zA-Z0-9_-]+$")

    def __init__(self) -> None:
        """Initialize the IDOR protector."""
        self._scopes: dict[str, dict[str, ResourceScope]] = {}
        self._patterns: dict[str, IDPattern] = {}
        self._resource_patterns: dict[str, list[IDPattern]] = {}
        self._lock = threading.RLock()

        # Global scope loaders by resource type
        self._scope_loaders: dict[str, Callable[[str], set[str]]] = {}

    def register_scope(
        self,
        user_id: str,
        resource_type: str,
        allowed_ids: set[str] | None = None,
        allowed_patterns: list[str] | None = None,
        scope_loader: Callable[[str], set[str]] | None = None,
    ) -> None:
        """
        Register a resource scope for a user.

        Args:
            user_id: The user's ID.
            resource_type: Type of resource (e.g., "document", "account").
            allowed_ids: Set of allowed object IDs.
            allowed_patterns: Regex patterns for allowed IDs.
            scope_loader: Function to dynamically load allowed IDs.

        Example:
            >>> protector.register_scope(
            ...     user_id="user_123",
            ...     resource_type="document",
            ...     allowed_ids={"doc_1", "doc_2"},
            ... )
        """
        with self._lock:
            if user_id not in self._scopes:
                self._scopes[user_id] = {}

            self._scopes[user_id][resource_type] = ResourceScope(
                allowed_ids=allowed_ids or set(),
                allowed_patterns=allowed_patterns or [],
                scope_loader=scope_loader,
            )

            logger.debug(
                f"Registered scope for user={user_id}, "
                f"resource_type={resource_type}, ids={len(allowed_ids or set())}"
            )

    def register_scope_loader(
        self,
        resource_type: str,
        loader: Callable[[str], set[str]],
    ) -> None:
        """
        Register a global scope loader for a resource type.

        The loader is called with a user_id and should return
        the set of allowed IDs for that user.

        Args:
            resource_type: The resource type.
            loader: Function that takes user_id and returns allowed IDs.

        Example:
            >>> def load_user_documents(user_id: str) -> set[str]:
            ...     return db.get_user_document_ids(user_id)
            >>>
            >>> protector.register_scope_loader("document", load_user_documents)
        """
        with self._lock:
            self._scope_loaders[resource_type] = loader
            logger.debug(f"Registered scope loader for resource_type={resource_type}")

    def register_id_pattern(
        self,
        parameter_name: str,
        resource_type: str,
        pattern: str = r".*",
        extractor: Callable[[Any], list[str]] | None = None,
    ) -> None:
        """
        Register a pattern for extracting object IDs from arguments.

        Args:
            parameter_name: The parameter name that contains the ID.
            resource_type: The type of resource the ID refers to.
            pattern: Regex pattern to validate the ID format.
            extractor: Custom function to extract IDs from the parameter value.

        Example:
            >>> # Simple ID parameter
            >>> protector.register_id_pattern("document_id", "document")
            >>>
            >>> # Parameter with list of IDs
            >>> protector.register_id_pattern(
            ...     "document_ids",
            ...     "document",
            ...     extractor=lambda v: v if isinstance(v, list) else [v],
            ... )
        """
        with self._lock:
            id_pattern = IDPattern(
                parameter_name=parameter_name,
                resource_type=resource_type,
                pattern=pattern,
                extractor=extractor,
            )

            self._patterns[parameter_name] = id_pattern

            if resource_type not in self._resource_patterns:
                self._resource_patterns[resource_type] = []
            self._resource_patterns[resource_type].append(id_pattern)

            logger.debug(
                f"Registered ID pattern: {parameter_name} -> {resource_type}"
            )

    def validate_access(
        self,
        user_id: str,
        resource_type: str,
        object_id: str,
    ) -> bool:
        """
        Validate that a user can access a specific object.

        Args:
            user_id: The user's ID.
            resource_type: The type of resource.
            object_id: The object ID being accessed.

        Returns:
            True if access is allowed, False otherwise.
        """
        with self._lock:
            # Get user's scope for this resource type
            user_scopes = self._scopes.get(user_id, {})
            scope = user_scopes.get(resource_type)

            # Try global scope loader if no user-specific scope
            if scope is None and resource_type in self._scope_loaders:
                loader = self._scope_loaders[resource_type]
                try:
                    allowed_ids = loader(user_id)
                    return object_id in allowed_ids
                except Exception as e:
                    logger.error(f"Scope loader failed: {e}")
                    return False

            if scope is None:
                # No scope defined - default deny
                logger.debug(
                    f"No scope for user={user_id}, resource_type={resource_type}"
                )
                return False

            # Check allowed IDs
            if object_id in scope.allowed_ids:
                return True

            # Check patterns
            for pattern in scope.allowed_patterns:
                if re.match(pattern, object_id):
                    return True

            # Try scope loader
            if scope.scope_loader:
                try:
                    dynamic_ids = scope.scope_loader(user_id)
                    if object_id in dynamic_ids:
                        return True
                except Exception as e:
                    logger.error(f"Dynamic scope loader failed: {e}")

            return False

    def validate_arguments(
        self,
        user_id: str,
        arguments: dict[str, Any],
    ) -> list[tuple[str, str, str]]:
        """
        Validate all object IDs in tool arguments.

        Scans the arguments for registered ID patterns and validates
        each found ID against the user's scope.

        Args:
            user_id: The user's ID.
            arguments: The tool call arguments.

        Returns:
            List of (parameter_name, resource_type, object_id) tuples
            for IDs that failed validation.
        """
        violations: list[tuple[str, str, str]] = []

        with self._lock:
            for param_name, value in arguments.items():
                pattern = self._patterns.get(param_name)
                if pattern is None:
                    continue

                # Extract IDs from the value
                ids = self._extract_ids(value, pattern)

                # Validate each ID
                for object_id in ids:
                    if not self.validate_access(
                        user_id, pattern.resource_type, object_id
                    ):
                        violations.append(
                            (param_name, pattern.resource_type, object_id)
                        )

        return violations

    def check_arguments(
        self,
        user_id: str,
        arguments: dict[str, Any],
    ) -> None:
        """
        Check arguments and raise if any IDOR violations found.

        Args:
            user_id: The user's ID.
            arguments: The tool call arguments.

        Raises:
            IDORViolationError: If any object ID is not in user's scope.
        """
        violations = self.validate_arguments(user_id, arguments)

        if violations:
            # Report first violation
            param_name, resource_type, object_id = violations[0]
            raise IDORViolationError(
                user_id=user_id,
                resource_type=resource_type,
                object_id=object_id,
            )

    def _extract_ids(
        self,
        value: Any,
        pattern: IDPattern,
    ) -> list[str]:
        """Extract object IDs from a parameter value."""
        if pattern.extractor:
            try:
                return pattern.extractor(value)
            except Exception:
                return []

        # Default extraction logic
        if isinstance(value, str):
            return [value]
        elif isinstance(value, list):
            return [str(v) for v in value if v is not None]
        elif isinstance(value, dict):
            # Look for common ID field names
            for key in ("id", "ID", "_id", "object_id"):
                if key in value:
                    return [str(value[key])]
            return []
        else:
            return [str(value)] if value is not None else []

    def auto_detect_ids(
        self,
        arguments: dict[str, Any],
    ) -> dict[str, str]:
        """
        Auto-detect potential object IDs in arguments.

        Scans arguments for values that look like object IDs
        (UUIDs, numeric IDs, etc.).

        Args:
            arguments: The tool call arguments.

        Returns:
            Dictionary mapping parameter names to detected ID types.
        """
        detected: dict[str, str] = {}

        for param_name, value in arguments.items():
            if not isinstance(value, str):
                continue

            # Skip known non-ID parameters
            if param_name in ("query", "content", "message", "text"):
                continue

            # Check for common ID patterns
            if self.UUID_PATTERN.match(value):
                detected[param_name] = "uuid"
            elif self.NUMERIC_PATTERN.match(value) and len(value) <= 20:
                detected[param_name] = "numeric"
            elif (
                self.ALPHANUMERIC_PATTERN.match(value) and
                len(value) <= 50 and
                any(c.isdigit() for c in value)
            ):
                detected[param_name] = "alphanumeric"

        return detected

    def clear_scope(
        self,
        user_id: str,
        resource_type: str | None = None,
    ) -> None:
        """
        Clear scope for a user.

        Args:
            user_id: The user's ID.
            resource_type: Specific resource type to clear, or None for all.
        """
        with self._lock:
            if user_id not in self._scopes:
                return

            if resource_type:
                self._scopes[user_id].pop(resource_type, None)
            else:
                del self._scopes[user_id]

    def add_to_scope(
        self,
        user_id: str,
        resource_type: str,
        object_ids: set[str],
    ) -> None:
        """
        Add object IDs to a user's scope.

        Args:
            user_id: The user's ID.
            resource_type: The resource type.
            object_ids: IDs to add.
        """
        with self._lock:
            if user_id not in self._scopes:
                self._scopes[user_id] = {}

            if resource_type not in self._scopes[user_id]:
                self._scopes[user_id][resource_type] = ResourceScope()

            self._scopes[user_id][resource_type].allowed_ids.update(object_ids)

    def remove_from_scope(
        self,
        user_id: str,
        resource_type: str,
        object_ids: set[str],
    ) -> None:
        """
        Remove object IDs from a user's scope.

        Args:
            user_id: The user's ID.
            resource_type: The resource type.
            object_ids: IDs to remove.
        """
        with self._lock:
            if user_id not in self._scopes:
                return

            if resource_type not in self._scopes[user_id]:
                return

            self._scopes[user_id][resource_type].allowed_ids -= object_ids
