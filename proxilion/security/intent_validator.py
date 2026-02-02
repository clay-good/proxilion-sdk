"""
Intent validation for Proxilion.

This module provides deterministic intent validation to detect
anomalous patterns in tool calls without relying on LLM analysis.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class ValidationResult(Enum):
    """Result of intent validation."""
    VALID = "valid"
    SUSPICIOUS = "suspicious"
    BLOCKED = "blocked"


@dataclass
class ValidationOutcome:
    """Outcome of intent validation."""
    result: ValidationResult
    reason: str | None = None
    risk_score: float = 0.0
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def is_valid(self) -> bool:
        """Check if the validation passed."""
        return self.result == ValidationResult.VALID

    @property
    def should_block(self) -> bool:
        """Check if the request should be blocked."""
        return self.result == ValidationResult.BLOCKED


@dataclass
class WorkflowState:
    """State of a user's workflow."""
    current_state: str = "initial"
    allowed_transitions: set[str] = field(default_factory=set)
    history: list[str] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)


@dataclass
class AnomalyThresholds:
    """Thresholds for anomaly detection."""
    max_calls_per_minute: int = 60
    max_unique_resources_per_minute: int = 20
    max_consecutive_failures: int = 5
    max_data_volume_mb: float = 10.0
    suspicious_hour_start: int = 2  # 2 AM
    suspicious_hour_end: int = 5    # 5 AM


class IntentValidator:
    """
    Validates the intent of tool calls using deterministic rules.

    This validator checks for anomalous patterns that might indicate
    malicious use, without relying on LLM-based analysis.

    Features:
        - Workflow state validation
        - Parameter consistency checking
        - Anomaly detection (mass operations, unusual patterns)
        - Time-based suspicion (unusual hours)
        - Resource access pattern analysis

    Example:
        >>> validator = IntentValidator()
        >>>
        >>> # Register workflow
        >>> validator.register_workflow("document_workflow", {
        ...     "initial": ["search"],
        ...     "search": ["view", "search"],
        ...     "view": ["edit", "download", "search"],
        ...     "edit": ["save", "view"],
        ... })
        >>>
        >>> # Validate a tool call
        >>> outcome = validator.validate(
        ...     user_id="user_123",
        ...     tool_name="view_document",
        ...     arguments={"doc_id": "doc_456"},
        ...     workflow_name="document_workflow",
        ... )
    """

    def __init__(
        self,
        thresholds: AnomalyThresholds | None = None,
    ) -> None:
        """
        Initialize the intent validator.

        Args:
            thresholds: Custom anomaly detection thresholds.
        """
        self.thresholds = thresholds or AnomalyThresholds()

        # Workflows: workflow_name -> {state -> allowed_next_states}
        self._workflows: dict[str, dict[str, set[str]]] = {}

        # User workflow states: user_id -> workflow_name -> WorkflowState
        self._user_states: dict[str, dict[str, WorkflowState]] = defaultdict(dict)

        # Call history for anomaly detection: user_id -> list of (timestamp, tool_name, arguments)
        self._call_history: dict[str, list[tuple[float, str, dict[str, Any]]]] = defaultdict(list)

        # Failure tracking
        self._failure_counts: dict[str, int] = defaultdict(int)

        # Custom validators
        self._validators: list[Callable[[str, str, dict[str, Any]], ValidationOutcome | None]] = []

        self._lock = threading.RLock()

    def register_workflow(
        self,
        workflow_name: str,
        transitions: dict[str, list[str]],
    ) -> None:
        """
        Register a workflow state machine.

        Args:
            workflow_name: Name of the workflow.
            transitions: Dictionary mapping states to allowed next states.

        Example:
            >>> validator.register_workflow("order_flow", {
            ...     "initial": ["browse"],
            ...     "browse": ["add_to_cart", "browse"],
            ...     "add_to_cart": ["checkout", "browse", "remove_from_cart"],
            ...     "checkout": ["pay", "cancel"],
            ...     "pay": ["complete"],
            ... })
        """
        with self._lock:
            self._workflows[workflow_name] = {
                state: set(next_states)
                for state, next_states in transitions.items()
            }
            logger.debug(f"Registered workflow: {workflow_name}")

    def register_validator(
        self,
        validator: Callable[[str, str, dict[str, Any]], ValidationOutcome | None],
    ) -> None:
        """
        Register a custom validation function.

        The function should return a ValidationOutcome if it has a decision,
        or None to defer to other validators.

        Args:
            validator: Function(user_id, tool_name, arguments) -> ValidationOutcome | None
        """
        with self._lock:
            self._validators.append(validator)

    def validate(
        self,
        user_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        workflow_name: str | None = None,
        tool_to_state: Callable[[str], str] | None = None,
    ) -> ValidationOutcome:
        """
        Validate a tool call intent.

        Args:
            user_id: The user's ID.
            tool_name: The tool being called.
            arguments: The tool arguments.
            workflow_name: Optional workflow to validate against.
            tool_to_state: Optional function to map tool name to workflow state.

        Returns:
            ValidationOutcome with the validation result.
        """
        with self._lock:
            # Run custom validators first
            for validator in self._validators:
                try:
                    outcome = validator(user_id, tool_name, arguments)
                    if outcome is not None:
                        return outcome
                except Exception as e:
                    logger.error(f"Custom validator failed: {e}")

            # Record call for history
            self._record_call(user_id, tool_name, arguments)

            # Run built-in checks
            outcomes: list[ValidationOutcome] = []

            # Workflow validation
            if workflow_name:
                state_name = tool_to_state(tool_name) if tool_to_state else tool_name
                workflow_outcome = self._validate_workflow(
                    user_id, workflow_name, state_name
                )
                outcomes.append(workflow_outcome)

            # Anomaly detection
            anomaly_outcome = self._detect_anomalies(user_id, tool_name, arguments)
            outcomes.append(anomaly_outcome)

            # Parameter consistency
            consistency_outcome = self._check_parameter_consistency(
                tool_name, arguments
            )
            outcomes.append(consistency_outcome)

            # Combine outcomes
            return self._combine_outcomes(outcomes)

    def _record_call(
        self,
        user_id: str,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> None:
        """Record a tool call for history analysis."""
        now = time.time()
        self._call_history[user_id].append((now, tool_name, arguments))

        # Cleanup old entries (keep last hour)
        cutoff = now - 3600
        self._call_history[user_id] = [
            entry for entry in self._call_history[user_id]
            if entry[0] > cutoff
        ]

    def _validate_workflow(
        self,
        user_id: str,
        workflow_name: str,
        state_name: str,
    ) -> ValidationOutcome:
        """Validate against workflow state machine."""
        if workflow_name not in self._workflows:
            return ValidationOutcome(
                result=ValidationResult.VALID,
                reason="Unknown workflow, skipping validation",
            )

        workflow = self._workflows[workflow_name]

        # Get or create user's workflow state
        if workflow_name not in self._user_states[user_id]:
            self._user_states[user_id][workflow_name] = WorkflowState(
                current_state="initial",
                allowed_transitions=workflow.get("initial", set()),
            )

        user_state = self._user_states[user_id][workflow_name]

        # Check if transition is allowed
        not_allowed = state_name not in user_state.allowed_transitions
        not_initial = user_state.current_state != "initial"
        if not_allowed and not_initial:
            return ValidationOutcome(
                result=ValidationResult.SUSPICIOUS,
                reason=(
                    f"Unexpected workflow transition: "
                    f"{user_state.current_state} -> {state_name}"
                ),
                risk_score=0.5,
                details={
                    "current_state": user_state.current_state,
                    "attempted_state": state_name,
                    "allowed": list(user_state.allowed_transitions),
                },
            )

        # Update state
        user_state.current_state = state_name
        user_state.allowed_transitions = workflow.get(state_name, set())
        user_state.history.append(state_name)

        return ValidationOutcome(
            result=ValidationResult.VALID,
            reason="Workflow transition valid",
        )

    def _detect_anomalies(
        self,
        user_id: str,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> ValidationOutcome:
        """Detect anomalous patterns in tool usage."""
        now = time.time()
        minute_ago = now - 60

        # Get recent calls
        recent_calls = [
            entry for entry in self._call_history[user_id]
            if entry[0] > minute_ago
        ]

        # Check call rate
        if len(recent_calls) > self.thresholds.max_calls_per_minute:
            return ValidationOutcome(
                result=ValidationResult.SUSPICIOUS,
                reason=f"High call rate: {len(recent_calls)} calls in last minute",
                risk_score=0.7,
                details={"calls_per_minute": len(recent_calls)},
            )

        # Check unique resources accessed
        unique_resources: set[str] = set()
        for _, _, args in recent_calls:
            for key, value in args.items():
                if key.endswith("_id") and isinstance(value, str):
                    unique_resources.add(f"{key}:{value}")

        if len(unique_resources) > self.thresholds.max_unique_resources_per_minute:
            return ValidationOutcome(
                result=ValidationResult.SUSPICIOUS,
                reason=f"Mass resource access: {len(unique_resources)} unique resources",
                risk_score=0.8,
                details={"unique_resources": len(unique_resources)},
            )

        # Check for unusual hours (local time check would require timezone)
        hour = time.localtime(now).tm_hour
        if self.thresholds.suspicious_hour_start <= hour < self.thresholds.suspicious_hour_end:
            return ValidationOutcome(
                result=ValidationResult.SUSPICIOUS,
                reason=f"Access during unusual hours ({hour}:00)",
                risk_score=0.3,
                details={"hour": hour},
            )

        # Check for mass operations (same tool, different IDs)
        same_tool_calls = [c for c in recent_calls if c[1] == tool_name]
        if len(same_tool_calls) > 10:
            different_ids = len({
                str(c[2].get("id") or c[2].get("document_id") or c[2].get("user_id"))
                for c in same_tool_calls
            })
            if different_ids > 5:
                return ValidationOutcome(
                    result=ValidationResult.SUSPICIOUS,
                    reason=(
                        f"Mass operation detected: {tool_name} "
                        f"on {different_ids} different resources"
                    ),
                    risk_score=0.6,
                    details={
                        "tool": tool_name,
                        "call_count": len(same_tool_calls),
                        "unique_targets": different_ids,
                    },
                )

        return ValidationOutcome(result=ValidationResult.VALID)

    def _check_parameter_consistency(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> ValidationOutcome:
        """Check for inconsistent or suspicious parameters."""
        # Check for suspiciously long strings (potential injection)
        for key, value in arguments.items():
            if isinstance(value, str) and len(value) > 10000:
                return ValidationOutcome(
                    result=ValidationResult.SUSPICIOUS,
                    reason=f"Unusually long parameter: {key} ({len(value)} chars)",
                    risk_score=0.4,
                    details={"parameter": key, "length": len(value)},
                )

        # Check for null bytes (potential injection)
        for key, value in arguments.items():
            if isinstance(value, str) and "\x00" in value:
                return ValidationOutcome(
                    result=ValidationResult.BLOCKED,
                    reason=f"Null byte in parameter: {key}",
                    risk_score=1.0,
                    details={"parameter": key},
                )

        # Check for excessive nesting in dicts/lists
        def check_depth(obj: Any, depth: int = 0) -> int:
            if depth > 10:
                return depth
            if isinstance(obj, dict):
                return max(
                    (check_depth(v, depth + 1) for v in obj.values()),
                    default=depth,
                )
            elif isinstance(obj, list):
                return max(
                    (check_depth(v, depth + 1) for v in obj),
                    default=depth,
                )
            return depth

        max_depth = check_depth(arguments)
        if max_depth > 10:
            return ValidationOutcome(
                result=ValidationResult.SUSPICIOUS,
                reason=f"Deeply nested parameters (depth: {max_depth})",
                risk_score=0.5,
                details={"max_depth": max_depth},
            )

        return ValidationOutcome(result=ValidationResult.VALID)

    def _combine_outcomes(
        self,
        outcomes: list[ValidationOutcome],
    ) -> ValidationOutcome:
        """Combine multiple validation outcomes."""
        # Any BLOCKED result blocks
        blocked = [o for o in outcomes if o.result == ValidationResult.BLOCKED]
        if blocked:
            return blocked[0]

        # Aggregate suspicious results
        suspicious = [o for o in outcomes if o.result == ValidationResult.SUSPICIOUS]
        if suspicious:
            total_risk = sum(o.risk_score for o in suspicious) / len(suspicious)

            # If combined risk is high enough, block
            if total_risk > 0.8:
                return ValidationOutcome(
                    result=ValidationResult.BLOCKED,
                    reason="Multiple suspicious indicators",
                    risk_score=total_risk,
                    details={"indicators": [o.reason for o in suspicious]},
                )

            # Return the highest risk suspicious result
            return max(suspicious, key=lambda o: o.risk_score)

        return ValidationOutcome(result=ValidationResult.VALID)

    def record_failure(self, user_id: str) -> None:
        """Record a tool call failure for the user."""
        with self._lock:
            self._failure_counts[user_id] += 1

    def record_success(self, user_id: str) -> None:
        """Record a tool call success (resets failure count)."""
        with self._lock:
            self._failure_counts[user_id] = 0

    def get_failure_count(self, user_id: str) -> int:
        """Get consecutive failure count for a user."""
        with self._lock:
            return self._failure_counts.get(user_id, 0)

    def reset_user_state(
        self,
        user_id: str,
        workflow_name: str | None = None,
    ) -> None:
        """Reset a user's workflow state."""
        with self._lock:
            if workflow_name:
                if workflow_name in self._user_states.get(user_id, {}):
                    del self._user_states[user_id][workflow_name]
            else:
                self._user_states.pop(user_id, None)
                self._call_history.pop(user_id, None)
                self._failure_counts.pop(user_id, None)

    def get_user_state(
        self,
        user_id: str,
        workflow_name: str,
    ) -> WorkflowState | None:
        """Get a user's current workflow state."""
        with self._lock:
            return self._user_states.get(user_id, {}).get(workflow_name)
