"""
Tool sequence validation for Proxilion.

Prevents dangerous tool call sequences by defining allowed/disallowed
patterns. For example, prevent "delete" from being called without a
prior "confirm" step.

Addresses:
- OWASP ASI01 (Agent Goal Hijack)
- OWASP ASI02 (Tool Misuse)

Example:
    >>> from proxilion.security.sequence_validator import (
    ...     SequenceValidator, SequenceRule, SequenceAction
    ... )
    >>>
    >>> validator = SequenceValidator()
    >>>
    >>> # Add rule requiring confirmation before deletion
    >>> validator.add_rule(SequenceRule(
    ...     name="require_confirm",
    ...     action=SequenceAction.REQUIRE_BEFORE,
    ...     target_pattern="delete_*",
    ...     required_pattern="confirm_*",
    ... ))
    >>>
    >>> # Validate a tool call
    >>> allowed, violation = validator.validate_call("delete_file", "user_123")
    >>> if not allowed:
    ...     print(f"Blocked: {violation.message}")
"""

from __future__ import annotations

import fnmatch
import logging
import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

logger = logging.getLogger(__name__)


class SequenceAction(Enum):
    """Type of sequence rule."""

    REQUIRE_BEFORE = "require_before"
    """Tool X requires tool Y to have been called first."""

    FORBID_AFTER = "forbid_after"
    """Tool X cannot be called after tool Y within a time window."""

    REQUIRE_SEQUENCE = "require_sequence"
    """Tools must be called in exact order."""

    MAX_CONSECUTIVE = "max_consecutive"
    """Maximum times a tool can be called consecutively."""

    COOLDOWN = "cooldown"
    """Minimum time between calls to the same tool."""


@dataclass
class SequenceRule:
    """
    Rule for validating tool call sequences.

    Attributes:
        name: Unique identifier for the rule.
        action: Type of sequence validation.
        target_pattern: Tool name pattern this rule applies to (supports wildcards).
        required_pattern: For REQUIRE_BEFORE, the pattern that must precede.
        forbidden_pattern: For FORBID_AFTER, the pattern that triggers block.
        sequence_patterns: For REQUIRE_SEQUENCE, ordered list of patterns.
        max_count: For MAX_CONSECUTIVE, maximum consecutive calls.
        cooldown_seconds: For COOLDOWN, minimum seconds between calls.
        window_seconds: Time window for FORBID_AFTER and lookback.
        description: Human-readable description of the rule.
        enabled: Whether the rule is active.
    """

    name: str
    action: SequenceAction
    target_pattern: str = "*"
    required_pattern: str | None = None
    forbidden_pattern: str | None = None
    sequence_patterns: list[str] = field(default_factory=list)
    max_count: int = 5
    cooldown_seconds: float = 60.0
    window_seconds: float = 300.0
    description: str = ""
    enabled: bool = True

    def matches_target(self, tool_name: str) -> bool:
        """Check if tool name matches the target pattern."""
        return fnmatch.fnmatch(tool_name.lower(), self.target_pattern.lower())

    def matches_pattern(self, tool_name: str, pattern: str) -> bool:
        """Check if tool name matches a pattern."""
        return fnmatch.fnmatch(tool_name.lower(), pattern.lower())


@dataclass
class SequenceViolation:
    """
    Details about a sequence rule violation.

    Attributes:
        rule_name: Name of the violated rule.
        violation_type: Type of violation (from SequenceAction).
        tool_name: Tool that triggered the violation.
        tool_sequence: Recent tool call sequence.
        message: Human-readable violation message.
        required_prior: For REQUIRE_BEFORE, what tool was required.
        forbidden_prior: For FORBID_AFTER, what tool was forbidden before.
        consecutive_count: For MAX_CONSECUTIVE, how many calls were made.
        last_call_seconds_ago: For COOLDOWN, seconds since last call.
    """

    rule_name: str
    violation_type: SequenceAction
    tool_name: str
    tool_sequence: list[str] = field(default_factory=list)
    message: str = ""
    required_prior: str | None = None
    forbidden_prior: str | None = None
    consecutive_count: int = 0
    last_call_seconds_ago: float = 0.0


@dataclass
class ToolCallRecord:
    """Record of a tool call for sequence tracking."""

    tool_name: str
    timestamp: datetime
    user_id: str


# Default security rules
DEFAULT_SEQUENCE_RULES: list[SequenceRule] = [
    SequenceRule(
        name="require_confirm_before_delete",
        action=SequenceAction.REQUIRE_BEFORE,
        target_pattern="delete_*",
        required_pattern="confirm_*",
        description="Deletion requires confirmation first",
    ),
    SequenceRule(
        name="max_consecutive_calls",
        action=SequenceAction.MAX_CONSECUTIVE,
        target_pattern="*",
        max_count=10,
        description="Prevent runaway tool loops",
    ),
    SequenceRule(
        name="forbid_download_execute",
        action=SequenceAction.FORBID_AFTER,
        target_pattern="execute_*",
        forbidden_pattern="download_*",
        window_seconds=300.0,
        description="Prevent download-and-execute attacks",
    ),
    SequenceRule(
        name="forbid_download_run",
        action=SequenceAction.FORBID_AFTER,
        target_pattern="run_*",
        forbidden_pattern="download_*",
        window_seconds=300.0,
        description="Prevent download-and-run attacks",
    ),
]


class SequenceValidator:
    """
    Validates tool call sequences against defined rules.

    Tracks per-user tool call history and validates each call against
    rules for dangerous patterns like delete without confirm, download
    followed by execute, or rapid consecutive calls.

    Example:
        >>> validator = SequenceValidator()
        >>>
        >>> # Try to delete without confirming
        >>> allowed, violation = validator.validate_call("delete_file", "user_1")
        >>> print(allowed)  # False - needs confirm first
        >>>
        >>> # Confirm first, then delete
        >>> validator.record_call("confirm_delete", "user_1")
        >>> allowed, violation = validator.validate_call("delete_file", "user_1")
        >>> print(allowed)  # True
    """

    def __init__(
        self,
        rules: list[SequenceRule] | None = None,
        history_size: int = 100,
        include_defaults: bool = True,
    ) -> None:
        """
        Initialize the sequence validator.

        Args:
            rules: Custom rules to use.
            history_size: Maximum history entries per user.
            include_defaults: Whether to include default security rules.
        """
        self._rules: list[SequenceRule] = []
        self._history_size = history_size
        self._user_history: dict[str, deque[ToolCallRecord]] = {}
        self._lock = threading.RLock()

        # Index rules by target pattern for efficient lookup
        self._rule_index: dict[str, list[SequenceRule]] = {}

        # Add default rules if requested
        if include_defaults:
            for rule in DEFAULT_SEQUENCE_RULES:
                self.add_rule(rule)

        # Add custom rules
        if rules:
            for rule in rules:
                self.add_rule(rule)

    def add_rule(self, rule: SequenceRule) -> None:
        """
        Add a sequence rule.

        Args:
            rule: The rule to add.
        """
        with self._lock:
            self._rules.append(rule)
            # Index by target pattern
            if rule.target_pattern not in self._rule_index:
                self._rule_index[rule.target_pattern] = []
            self._rule_index[rule.target_pattern].append(rule)

    def remove_rule(self, name: str) -> bool:
        """
        Remove a rule by name.

        Args:
            name: The rule name to remove.

        Returns:
            True if rule was removed, False if not found.
        """
        with self._lock:
            for i, rule in enumerate(self._rules):
                if rule.name == name:
                    self._rules.pop(i)
                    # Remove from index
                    if rule.target_pattern in self._rule_index:
                        self._rule_index[rule.target_pattern] = [
                            r for r in self._rule_index[rule.target_pattern]
                            if r.name != name
                        ]
                    return True
            return False

    def get_rules(self) -> list[SequenceRule]:
        """Get all registered rules."""
        with self._lock:
            return list(self._rules)

    def get_rule(self, name: str) -> SequenceRule | None:
        """Get a rule by name."""
        with self._lock:
            for rule in self._rules:
                if rule.name == name:
                    return rule
            return None

    def enable_rule(self, name: str) -> bool:
        """Enable a rule by name."""
        rule = self.get_rule(name)
        if rule:
            rule.enabled = True
            return True
        return False

    def disable_rule(self, name: str) -> bool:
        """Disable a rule by name."""
        rule = self.get_rule(name)
        if rule:
            rule.enabled = False
            return True
        return False

    def record_call(
        self,
        tool_name: str,
        user_id: str,
        timestamp: datetime | None = None,
    ) -> None:
        """
        Record a tool call for sequence tracking.

        Args:
            tool_name: Name of the tool called.
            user_id: ID of the user making the call.
            timestamp: Optional timestamp (defaults to now).
        """
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)

        record = ToolCallRecord(
            tool_name=tool_name,
            timestamp=timestamp,
            user_id=user_id,
        )

        with self._lock:
            if user_id not in self._user_history:
                self._user_history[user_id] = deque(maxlen=self._history_size)
            self._user_history[user_id].append(record)

    def validate_call(
        self,
        tool_name: str,
        user_id: str,
    ) -> tuple[bool, SequenceViolation | None]:
        """
        Validate a tool call against sequence rules.

        Args:
            tool_name: Name of the tool to validate.
            user_id: ID of the user making the call.

        Returns:
            Tuple of (allowed, violation). If allowed is False,
            violation contains details about what rule was violated.
        """
        with self._lock:
            history = self._get_user_history(user_id)

            # Check all rules that might apply
            for rule in self._rules:
                if not rule.enabled:
                    continue

                if not rule.matches_target(tool_name):
                    continue

                violation = self._check_rule(rule, tool_name, history)
                if violation:
                    logger.warning(
                        f"Sequence violation for user {user_id}: "
                        f"{violation.rule_name} - {violation.message}"
                    )
                    return False, violation

            return True, None

    def _get_user_history(self, user_id: str) -> list[ToolCallRecord]:
        """Get history for a user."""
        if user_id not in self._user_history:
            return []
        return list(self._user_history[user_id])

    def _check_rule(
        self,
        rule: SequenceRule,
        tool_name: str,
        history: list[ToolCallRecord],
    ) -> SequenceViolation | None:
        """Check a single rule against the tool call."""
        if rule.action == SequenceAction.REQUIRE_BEFORE:
            return self._check_require_before(rule, tool_name, history)
        elif rule.action == SequenceAction.FORBID_AFTER:
            return self._check_forbid_after(rule, tool_name, history)
        elif rule.action == SequenceAction.REQUIRE_SEQUENCE:
            return self._check_require_sequence(rule, tool_name, history)
        elif rule.action == SequenceAction.MAX_CONSECUTIVE:
            return self._check_max_consecutive(rule, tool_name, history)
        elif rule.action == SequenceAction.COOLDOWN:
            return self._check_cooldown(rule, tool_name, history)
        return None

    def _check_require_before(
        self,
        rule: SequenceRule,
        tool_name: str,
        history: list[ToolCallRecord],
    ) -> SequenceViolation | None:
        """Check REQUIRE_BEFORE rule."""
        if not rule.required_pattern:
            return None

        # Look for required pattern in history
        for record in reversed(history):
            if rule.matches_pattern(record.tool_name, rule.required_pattern):
                return None  # Found required predecessor

        return SequenceViolation(
            rule_name=rule.name,
            violation_type=SequenceAction.REQUIRE_BEFORE,
            tool_name=tool_name,
            tool_sequence=[r.tool_name for r in history[-5:]],
            message=f"Tool '{tool_name}' requires '{rule.required_pattern}' to be called first",
            required_prior=rule.required_pattern,
        )

    def _check_forbid_after(
        self,
        rule: SequenceRule,
        tool_name: str,
        history: list[ToolCallRecord],
    ) -> SequenceViolation | None:
        """Check FORBID_AFTER rule."""
        if not rule.forbidden_pattern:
            return None

        now = datetime.now(timezone.utc)
        window_seconds = rule.window_seconds

        # Look for forbidden pattern within time window
        for record in reversed(history):
            age = (now - record.timestamp).total_seconds()
            if age > window_seconds:
                break  # Beyond time window

            if rule.matches_pattern(record.tool_name, rule.forbidden_pattern):
                return SequenceViolation(
                    rule_name=rule.name,
                    violation_type=SequenceAction.FORBID_AFTER,
                    tool_name=tool_name,
                    tool_sequence=[r.tool_name for r in history[-5:]],
                    message=(
                        f"Tool '{tool_name}' cannot be called within "
                        f"{window_seconds}s after '{rule.forbidden_pattern}' "
                        f"('{record.tool_name}' was called {age:.1f}s ago)"
                    ),
                    forbidden_prior=record.tool_name,
                )

        return None

    def _check_require_sequence(
        self,
        rule: SequenceRule,
        tool_name: str,
        history: list[ToolCallRecord],
    ) -> SequenceViolation | None:
        """Check REQUIRE_SEQUENCE rule."""
        if not rule.sequence_patterns:
            return None

        sequence = rule.sequence_patterns

        # Find which step we're on
        step_index = -1
        for i, pattern in enumerate(sequence):
            if rule.matches_pattern(tool_name, pattern):
                step_index = i
                break

        if step_index == -1:
            return None  # Tool not in sequence

        if step_index == 0:
            return None  # First step is always allowed

        # Check that previous steps were completed in order
        expected_prior = sequence[step_index - 1]

        # Look for the expected prior step
        found_prior = False
        for record in reversed(history):
            if rule.matches_pattern(record.tool_name, expected_prior):
                found_prior = True
                break
            # If we find any other step from the sequence that's not the expected one
            for i, pattern in enumerate(sequence):
                if i != step_index - 1 and rule.matches_pattern(record.tool_name, pattern):
                    # Found a different step - sequence may be broken
                    pass

        if not found_prior:
            return SequenceViolation(
                rule_name=rule.name,
                violation_type=SequenceAction.REQUIRE_SEQUENCE,
                tool_name=tool_name,
                tool_sequence=[r.tool_name for r in history[-5:]],
                message=(
                    f"Tool '{tool_name}' requires '{expected_prior}' to be called first "
                    f"(sequence: {' -> '.join(sequence)})"
                ),
                required_prior=expected_prior,
            )

        return None

    def _check_max_consecutive(
        self,
        rule: SequenceRule,
        tool_name: str,
        history: list[ToolCallRecord],
    ) -> SequenceViolation | None:
        """Check MAX_CONSECUTIVE rule."""
        consecutive_count = 0

        for record in reversed(history):
            if record.tool_name == tool_name:
                consecutive_count += 1
            else:
                break

        if consecutive_count >= rule.max_count:
            return SequenceViolation(
                rule_name=rule.name,
                violation_type=SequenceAction.MAX_CONSECUTIVE,
                tool_name=tool_name,
                tool_sequence=[r.tool_name for r in history[-5:]],
                message=(
                    f"Tool '{tool_name}' has been called {consecutive_count} times "
                    f"consecutively (max allowed: {rule.max_count})"
                ),
                consecutive_count=consecutive_count,
            )

        return None

    def _check_cooldown(
        self,
        rule: SequenceRule,
        tool_name: str,
        history: list[ToolCallRecord],
    ) -> SequenceViolation | None:
        """Check COOLDOWN rule."""
        now = datetime.now(timezone.utc)

        # Find last call to this tool
        for record in reversed(history):
            if record.tool_name == tool_name:
                age = (now - record.timestamp).total_seconds()
                if age < rule.cooldown_seconds:
                    return SequenceViolation(
                        rule_name=rule.name,
                        violation_type=SequenceAction.COOLDOWN,
                        tool_name=tool_name,
                        tool_sequence=[r.tool_name for r in history[-5:]],
                        message=(
                            f"Tool '{tool_name}' requires {rule.cooldown_seconds}s cooldown "
                            f"(last called {age:.1f}s ago)"
                        ),
                        last_call_seconds_ago=age,
                    )
                break

        return None

    def get_history(
        self,
        user_id: str,
        limit: int | None = None,
    ) -> list[tuple[str, datetime]]:
        """
        Get tool call history for a user.

        Args:
            user_id: The user ID.
            limit: Maximum entries to return (None for all).

        Returns:
            List of (tool_name, timestamp) tuples, most recent first.
        """
        with self._lock:
            history = self._get_user_history(user_id)
            result = [(r.tool_name, r.timestamp) for r in reversed(history)]
            if limit:
                result = result[:limit]
            return result

    def clear_history(self, user_id: str | None = None) -> None:
        """
        Clear tool call history.

        Args:
            user_id: User ID to clear (None to clear all).
        """
        with self._lock:
            if user_id is None:
                self._user_history.clear()
            elif user_id in self._user_history:
                del self._user_history[user_id]

    def configure(
        self,
        history_size: int | None = None,
    ) -> None:
        """
        Update validator configuration.

        Args:
            history_size: New maximum history size per user.
        """
        with self._lock:
            if history_size is not None:
                self._history_size = history_size
                # Resize existing histories
                for user_id in self._user_history:
                    old_history = list(self._user_history[user_id])
                    self._user_history[user_id] = deque(
                        old_history[-history_size:],
                        maxlen=history_size,
                    )


def create_sequence_validator(
    include_defaults: bool = True,
    custom_rules: list[SequenceRule] | None = None,
    history_size: int = 100,
) -> SequenceValidator:
    """
    Factory function to create a SequenceValidator.

    Args:
        include_defaults: Whether to include default security rules.
        custom_rules: Additional custom rules.
        history_size: Maximum history entries per user.

    Returns:
        Configured SequenceValidator instance.
    """
    return SequenceValidator(
        rules=custom_rules,
        history_size=history_size,
        include_defaults=include_defaults,
    )
