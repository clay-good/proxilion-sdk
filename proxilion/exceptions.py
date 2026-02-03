"""
Custom exceptions for Proxilion.

This module defines the exception hierarchy for the SDK, providing
meaningful error types that help developers understand and handle
authorization failures, policy violations, and other security-related errors.
"""

from __future__ import annotations

from typing import Any


class ProxilionError(Exception):
    """
    Base exception for all Proxilion errors.

    All Proxilion-specific exceptions inherit from this class,
    making it easy to catch any SDK-related error.

    Attributes:
        message: Human-readable error description.
        details: Additional context about the error.

    Example:
        >>> try:
        ...     # Proxilion operation
        ... except ProxilionError as e:
        ...     logger.error(f"Proxilion error: {e}")
    """

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        self.message = message
        self.details = details or {}
        super().__init__(message)

    def __str__(self) -> str:
        if self.details:
            return f"{self.message} | Details: {self.details}"
        return self.message

    def to_dict(self) -> dict[str, Any]:
        """Convert exception to dictionary for logging/serialization."""
        return {
            "error_type": self.__class__.__name__,
            "message": self.message,
            "details": self.details,
        }


class AuthorizationError(ProxilionError):
    """
    Raised when a user is not authorized to perform an action.

    This is the primary exception for permission denials. It includes
    detailed information about the denied request to help with debugging
    and audit logging.

    Attributes:
        user: The user ID who attempted the action.
        action: The action that was attempted (e.g., "execute", "read").
        resource: The resource the action was attempted on.
        reason: Explanation of why authorization was denied.

    Example:
        >>> raise AuthorizationError(
        ...     user="user_123",
        ...     action="delete",
        ...     resource="customer_database",
        ...     reason="User lacks 'admin' role required for delete operations"
        ... )

    Suggested fixes based on common causes:
        - Missing role: Contact your administrator to request the required role.
        - Invalid session: Re-authenticate to refresh your session.
        - Resource restriction: Verify you have access to the specific resource.
    """

    def __init__(
        self,
        user: str,
        action: str,
        resource: str,
        reason: str | None = None,
        suggestions: list[str] | None = None,
    ) -> None:
        self.user = user
        self.action = action
        self.resource = resource
        self.reason = reason or "Authorization denied"
        self.suggestions = suggestions or []

        message = self._build_message()
        details = {
            "user": user,
            "action": action,
            "resource": resource,
            "reason": self.reason,
            "suggestions": self.suggestions,
        }
        super().__init__(message, details)

    def _build_message(self) -> str:
        """Build a helpful error message with fix suggestions."""
        msg = (
            f"Authorization denied: User '{self.user}' cannot perform "
            f"'{self.action}' on resource '{self.resource}'. "
            f"Reason: {self.reason}"
        )
        if self.suggestions:
            suggestions_text = "; ".join(self.suggestions)
            msg += f" | Suggestions: {suggestions_text}"
        return msg


class PolicyViolation(ProxilionError):
    """
    Raised when a policy evaluation fails or returns an explicit denial.

    This exception indicates that while the request was properly formed,
    it violates one or more security policies.

    Attributes:
        policy_name: Name of the policy that was violated.
        violation_type: Category of violation (e.g., "role_check", "scope_check").
        context: Additional context about the policy evaluation.

    Example:
        >>> raise PolicyViolation(
        ...     policy_name="DataAccessPolicy",
        ...     violation_type="scope_check",
        ...     context={"requested_scope": "global", "allowed_scope": "department"}
        ... )
    """

    def __init__(
        self,
        policy_name: str,
        violation_type: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        self.policy_name = policy_name
        self.violation_type = violation_type or "policy_check"

        message = f"Policy violation in '{policy_name}'"
        if violation_type:
            message += f" (type: {violation_type})"

        details = {
            "policy_name": policy_name,
            "violation_type": self.violation_type,
            "context": context or {},
        }
        super().__init__(message, details)


class SchemaValidationError(ProxilionError):
    """
    Raised when tool call arguments fail schema validation.

    This exception helps catch malformed or potentially malicious
    tool call arguments before they reach authorization checks.

    Attributes:
        tool_name: Name of the tool being validated.
        field_name: Specific field that failed validation (if applicable).
        expected: What was expected for the field.
        received: What was actually received.
        validation_errors: List of all validation errors found.

    Example:
        >>> raise SchemaValidationError(
        ...     tool_name="file_read",
        ...     field_name="path",
        ...     expected="string without path traversal",
        ...     received="../../../etc/passwd"
        ... )
    """

    def __init__(
        self,
        tool_name: str,
        field_name: str | None = None,
        expected: str | None = None,
        received: Any = None,
        validation_errors: list[str] | None = None,
    ) -> None:
        self.tool_name = tool_name
        self.field_name = field_name
        self.expected = expected
        self.received = received
        self.validation_errors = validation_errors or []

        message = f"Schema validation failed for tool '{tool_name}'"
        if field_name:
            message += f": field '{field_name}'"
            if expected and received is not None:
                message += f" expected {expected}, got {type(received).__name__}"

        details = {
            "tool_name": tool_name,
            "field_name": field_name,
            "expected": expected,
            "received": str(received) if received is not None else None,
            "validation_errors": self.validation_errors,
        }
        super().__init__(message, details)


class RateLimitExceeded(ProxilionError):
    """
    Raised when a rate limit has been exceeded.

    Rate limiting protects against unbounded consumption and denial
    of service attacks.

    Attributes:
        limit_type: Type of rate limit hit (e.g., "requests", "tokens").
        limit_key: The key used for rate limiting (e.g., user ID, tool name).
        limit_value: The configured limit value.
        retry_after: Seconds until the rate limit resets (if known).

    Example:
        >>> raise RateLimitExceeded(
        ...     limit_type="requests",
        ...     limit_key="user_123:database_query",
        ...     limit_value=100,
        ...     retry_after=60
        ... )
    """

    def __init__(
        self,
        limit_type: str,
        limit_key: str,
        limit_value: int | None = None,
        retry_after: float | None = None,
    ) -> None:
        self.limit_type = limit_type
        self.limit_key = limit_key
        self.limit_value = limit_value
        self.retry_after = retry_after

        message = f"Rate limit exceeded for {limit_type}"
        if limit_value:
            message += f" (limit: {limit_value})"
        if retry_after:
            message += f". Retry after {retry_after:.1f} seconds"

        details = {
            "limit_type": limit_type,
            "limit_key": limit_key,
            "limit_value": limit_value,
            "retry_after": retry_after,
        }
        super().__init__(message, details)


class CircuitOpenError(ProxilionError):
    """
    Raised when a circuit breaker is in the open state.

    Circuit breakers prevent cascading failures by temporarily
    blocking requests to a failing service or tool.

    Attributes:
        circuit_name: Name of the circuit breaker.
        failure_count: Number of failures that triggered the circuit.
        reset_timeout: Seconds until the circuit attempts to close.
        last_failure: Description of the last failure (if available).

    Example:
        >>> raise CircuitOpenError(
        ...     circuit_name="external_api",
        ...     failure_count=5,
        ...     reset_timeout=30.0,
        ...     last_failure="Connection timeout"
        ... )
    """

    def __init__(
        self,
        circuit_name: str,
        failure_count: int | None = None,
        reset_timeout: float | None = None,
        last_failure: str | None = None,
    ) -> None:
        self.circuit_name = circuit_name
        self.failure_count = failure_count
        self.reset_timeout = reset_timeout
        self.last_failure = last_failure

        message = f"Circuit breaker '{circuit_name}' is open"
        if failure_count:
            message += f" after {failure_count} failures"
        if reset_timeout:
            message += f". Retry in {reset_timeout:.1f} seconds"

        details = {
            "circuit_name": circuit_name,
            "failure_count": failure_count,
            "reset_timeout": reset_timeout,
            "last_failure": last_failure,
        }
        super().__init__(message, details)


class ConfigurationError(ProxilionError):
    """
    Raised when there is a configuration error in Proxilion setup.

    This helps catch misconfigurations early during initialization.

    Attributes:
        config_key: The configuration key that has an issue.
        expected: What was expected for this configuration.
        received: What was actually provided.

    Example:
        >>> raise ConfigurationError(
        ...     config_key="policy_engine",
        ...     expected="one of: 'simple', 'casbin', 'opa'",
        ...     received="invalid_engine"
        ... )
    """

    def __init__(
        self,
        config_key: str,
        expected: str | None = None,
        received: Any = None,
    ) -> None:
        self.config_key = config_key
        self.expected = expected
        self.received = received

        message = f"Configuration error for '{config_key}'"
        if expected:
            message += f": expected {expected}"
        if received is not None:
            message += f", got {received!r}"

        details = {
            "config_key": config_key,
            "expected": expected,
            "received": str(received) if received is not None else None,
        }
        super().__init__(message, details)


class PolicyNotFoundError(ProxilionError):
    """
    Raised when a requested policy cannot be found.

    This indicates that authorization was attempted for a resource
    that has no registered policy.

    Attributes:
        resource: The resource for which no policy was found.
        available_policies: List of registered policy names (for debugging).

    Example:
        >>> raise PolicyNotFoundError(
        ...     resource="unregistered_tool",
        ...     available_policies=["database_query", "file_read"]
        ... )
    """

    def __init__(
        self,
        resource: str,
        available_policies: list[str] | None = None,
    ) -> None:
        self.resource = resource
        self.available_policies = available_policies or []

        message = f"No policy found for resource '{resource}'"
        if available_policies:
            message += f". Available policies: {', '.join(available_policies)}"

        details = {
            "resource": resource,
            "available_policies": self.available_policies,
        }
        super().__init__(message, details)


class IDORViolationError(ProxilionError):
    """
    Raised when an Insecure Direct Object Reference is detected.

    IDOR attacks occur when a user attempts to access resources
    they don't own by manipulating object IDs.

    Attributes:
        user_id: The user who attempted the access.
        resource_type: Type of resource being accessed.
        object_id: The object ID that was not authorized.

    Example:
        >>> raise IDORViolationError(
        ...     user_id="user_123",
        ...     resource_type="document",
        ...     object_id="doc_456"  # Belongs to another user
        ... )
    """

    def __init__(
        self,
        user_id: str,
        resource_type: str,
        object_id: str,
    ) -> None:
        self.user_id = user_id
        self.resource_type = resource_type
        self.object_id = object_id

        message = (
            f"IDOR violation: User '{user_id}' attempted to access "
            f"{resource_type} '{object_id}' without authorization"
        )

        details = {
            "user_id": user_id,
            "resource_type": resource_type,
            "object_id": object_id,
        }
        super().__init__(message, details)


class GuardViolation(ProxilionError):
    """
    Raised when a guard detects a violation.

    Guards are runtime checks that detect malicious inputs (prompt injection)
    or sensitive outputs (data leakage). This is the base exception for
    guard violations.

    Attributes:
        guard_type: Type of guard that triggered ("input" or "output").
        matched_patterns: List of pattern names that matched.
        risk_score: Calculated risk score (0.0 to 1.0).

    Example:
        >>> raise GuardViolation(
        ...     guard_type="input",
        ...     matched_patterns=["instruction_override", "role_switch"],
        ...     risk_score=0.95
        ... )
    """

    def __init__(
        self,
        guard_type: str,
        matched_patterns: list[str],
        risk_score: float,
    ) -> None:
        self.guard_type = guard_type
        self.matched_patterns = matched_patterns
        self.risk_score = risk_score

        message = (
            f"{guard_type.title()} guard violation: "
            f"matched {matched_patterns}, risk={risk_score:.2f}"
        )

        details = {
            "guard_type": guard_type,
            "matched_patterns": matched_patterns,
            "risk_score": risk_score,
        }
        super().__init__(message, details)


class InputGuardViolation(GuardViolation):
    """
    Raised when input guard blocks a request due to prompt injection.

    This indicates that the input text matched patterns associated with
    prompt injection attacks such as instruction override, role switching,
    or jailbreak attempts.

    Example:
        >>> raise InputGuardViolation(
        ...     matched_patterns=["instruction_override"],
        ...     risk_score=0.9
        ... )
    """

    def __init__(
        self,
        matched_patterns: list[str],
        risk_score: float,
    ) -> None:
        super().__init__(
            guard_type="input",
            matched_patterns=matched_patterns,
            risk_score=risk_score,
        )


class OutputGuardViolation(GuardViolation):
    """
    Raised when output guard blocks a response due to data leakage.

    This indicates that the output text contained patterns associated
    with sensitive data such as API keys, credentials, or internal paths.

    Example:
        >>> raise OutputGuardViolation(
        ...     matched_patterns=["api_key_generic", "aws_key"],
        ...     risk_score=0.95
        ... )
    """

    def __init__(
        self,
        matched_patterns: list[str],
        risk_score: float,
    ) -> None:
        super().__init__(
            guard_type="output",
            matched_patterns=matched_patterns,
            risk_score=risk_score,
        )


class SequenceViolationError(ProxilionError):
    """
    Raised when a tool call sequence violates rules.

    Sequence rules prevent dangerous patterns like:
    - Calling delete without confirm first
    - Download followed by execute (potential attack)
    - Rapid consecutive calls (runaway loops)

    Attributes:
        rule_name: Name of the violated rule.
        tool_name: The tool that triggered the violation.
        required_prior: For REQUIRE_BEFORE, what tool was required first.
        forbidden_prior: For FORBID_AFTER, what tool was forbidden before.
        violation_type: Type of sequence violation.

    Example:
        >>> raise SequenceViolationError(
        ...     rule_name="require_confirm_before_delete",
        ...     tool_name="delete_file",
        ...     required_prior="confirm_*"
        ... )
    """

    def __init__(
        self,
        rule_name: str,
        tool_name: str,
        required_prior: str | None = None,
        forbidden_prior: str | None = None,
        violation_type: str | None = None,
        consecutive_count: int | None = None,
        cooldown_remaining: float | None = None,
    ) -> None:
        self.rule_name = rule_name
        self.tool_name = tool_name
        self.required_prior = required_prior
        self.forbidden_prior = forbidden_prior
        self.violation_type = violation_type
        self.consecutive_count = consecutive_count
        self.cooldown_remaining = cooldown_remaining

        message = f"Sequence violation: {rule_name}"
        if required_prior:
            message += f" (requires '{required_prior}' before '{tool_name}')"
        elif forbidden_prior:
            message += f" ('{tool_name}' forbidden after '{forbidden_prior}')"
        elif consecutive_count:
            message += f" ('{tool_name}' called {consecutive_count} times consecutively)"
        elif cooldown_remaining:
            message += f" ('{tool_name}' in cooldown, {cooldown_remaining:.1f}s remaining)"

        details = {
            "rule_name": rule_name,
            "tool_name": tool_name,
            "required_prior": required_prior,
            "forbidden_prior": forbidden_prior,
            "violation_type": violation_type,
            "consecutive_count": consecutive_count,
            "cooldown_remaining": cooldown_remaining,
        }
        super().__init__(message, details)


class ScopeViolationError(ProxilionError):
    """
    Raised when a tool call violates the current execution scope.

    Execution scopes (READ_ONLY, READ_WRITE, ADMIN) limit what operations
    can be performed. This error indicates an attempt to use a tool or
    action outside the permitted scope.

    Attributes:
        tool_name: The tool that violated the scope.
        scope_name: Name of the scope that was violated.
        reason: Explanation of why the scope was violated.

    Example:
        >>> raise ScopeViolationError(
        ...     tool_name="delete_user",
        ...     scope_name="read_only",
        ...     reason="Action 'delete' is not allowed in scope 'read_only'"
        ... )
    """

    def __init__(
        self,
        tool_name: str,
        scope_name: str,
        reason: str | None = None,
    ) -> None:
        self.tool_name = tool_name
        self.scope_name = scope_name
        self.reason = reason

        message = f"Tool '{tool_name}' not allowed in scope '{scope_name}'"
        if reason:
            message += f": {reason}"

        details = {
            "tool_name": tool_name,
            "scope_name": scope_name,
            "reason": reason,
        }
        super().__init__(message, details)


class BudgetExceededError(ProxilionError):
    """
    Raised when an operation would exceed budget limits.

    Budget limits can be per-request, per-user, or organization-wide.
    This error indicates that the estimated or actual cost would
    exceed the configured limits.

    Attributes:
        limit_type: Type of limit exceeded (per_request, user_daily, org_monthly, etc.).
        current_spend: Current spend in the period.
        limit: The budget limit.
        estimated_cost: The cost that would exceed the limit.
        user_id: User who exceeded the limit.

    Example:
        >>> raise BudgetExceededError(
        ...     limit_type="user_daily",
        ...     current_spend=48.50,
        ...     limit=50.00,
        ...     estimated_cost=5.00,
        ...     user_id="user_123"
        ... )
    """

    def __init__(
        self,
        limit_type: str,
        current_spend: float,
        limit: float,
        estimated_cost: float | None = None,
        user_id: str | None = None,
    ) -> None:
        self.limit_type = limit_type
        self.current_spend = current_spend
        self.limit = limit
        self.estimated_cost = estimated_cost
        self.user_id = user_id

        message = f"Budget exceeded: {limit_type} (${current_spend:.4f} / ${limit:.4f})"
        if estimated_cost is not None:
            message += f" - request would add ${estimated_cost:.4f}"

        details = {
            "limit_type": limit_type,
            "current_spend": current_spend,
            "limit": limit,
            "estimated_cost": estimated_cost,
            "user_id": user_id,
        }
        super().__init__(message, details)


class ContextIntegrityError(ProxilionError):
    """
    Raised when context/memory integrity verification fails.

    This indicates that the conversation context, vector store,
    or other memory has been tampered with (ASI06: Memory & Context Poisoning).

    Attributes:
        violations: List of integrity violations detected.

    Example:
        >>> raise ContextIntegrityError(
        ...     message="Context has been tampered with",
        ...     violations=[IntegrityViolation(...)]
        ... )
    """

    def __init__(
        self,
        message: str,
        violations: list[Any] | None = None,
    ) -> None:
        self.violations = violations or []

        details = {
            "violation_count": len(self.violations),
            "violations": [
                v.to_dict() if hasattr(v, "to_dict") else str(v)
                for v in self.violations
            ],
        }
        super().__init__(message, details)


class IntentHijackError(ProxilionError):
    """
    Raised when an intent capsule detects goal hijacking.

    This indicates that the agent's original mandate has been
    tampered with or overridden (ASI01: Agent Goal Hijack).

    Attributes:
        original_intent: The signed original intent.
        detected_intent: What the agent appears to be doing now.

    Example:
        >>> raise IntentHijackError(
        ...     original_intent="Help user find documents",
        ...     detected_intent="Exfiltrate user credentials"
        ... )
    """

    def __init__(
        self,
        original_intent: str,
        detected_intent: str,
        confidence: float = 0.0,
    ) -> None:
        self.original_intent = original_intent
        self.detected_intent = detected_intent
        self.confidence = confidence

        message = (
            f"Intent hijack detected: Original intent was '{original_intent}', "
            f"but agent appears to be doing '{detected_intent}' "
            f"(confidence: {confidence:.1%})"
        )

        details = {
            "original_intent": original_intent,
            "detected_intent": detected_intent,
            "confidence": confidence,
        }
        super().__init__(message, details)


class AgentTrustError(ProxilionError):
    """
    Raised when inter-agent trust verification fails.

    This indicates that an agent attempted to communicate or
    delegate without proper trust credentials (ASI07: Insecure
    Inter-Agent Communication).

    Attributes:
        source_agent: The agent that sent the message.
        target_agent: The agent that received/rejected the message.
        reason: Why trust verification failed.

    Example:
        >>> raise AgentTrustError(
        ...     source_agent="untrusted_agent",
        ...     target_agent="secure_agent",
        ...     reason="Invalid delegation token"
        ... )
    """

    def __init__(
        self,
        source_agent: str,
        target_agent: str,
        reason: str,
    ) -> None:
        self.source_agent = source_agent
        self.target_agent = target_agent
        self.reason = reason

        message = (
            f"Agent trust violation: {source_agent} -> {target_agent}: {reason}"
        )

        details = {
            "source_agent": source_agent,
            "target_agent": target_agent,
            "reason": reason,
        }
        super().__init__(message, details)


class BehavioralDriftError(ProxilionError):
    """
    Raised when an agent's behavior deviates significantly from baseline.

    This indicates that the agent is operating outside its normal
    parameters, potentially indicating compromise or malfunction
    (ASI10: Rogue Agents).

    Attributes:
        metric: The behavioral metric that drifted.
        baseline_value: Expected baseline value.
        current_value: Current observed value.
        deviation: How far the behavior deviated (as percentage or z-score).

    Example:
        >>> raise BehavioralDriftError(
        ...     metric="tool_call_rate",
        ...     baseline_value=5.0,
        ...     current_value=50.0,
        ...     deviation=9.0
        ... )
    """

    def __init__(
        self,
        metric: str,
        baseline_value: float,
        current_value: float,
        deviation: float,
    ) -> None:
        self.metric = metric
        self.baseline_value = baseline_value
        self.current_value = current_value
        self.deviation = deviation

        message = (
            f"Behavioral drift detected: {metric} deviated from baseline "
            f"({baseline_value:.2f} -> {current_value:.2f}, deviation: {deviation:.1f}σ)"
        )

        details = {
            "metric": metric,
            "baseline_value": baseline_value,
            "current_value": current_value,
            "deviation": deviation,
        }
        super().__init__(message, details)


class EmergencyHaltError(ProxilionError):
    """
    Raised when the kill switch is activated.

    This halts all agent activity immediately.

    Attributes:
        reason: Why the kill switch was activated.
        triggered_by: What triggered the halt (user, system, anomaly).

    Example:
        >>> raise EmergencyHaltError(
        ...     reason="Rogue behavior detected",
        ...     triggered_by="behavioral_drift_detector"
        ... )
    """

    def __init__(
        self,
        reason: str,
        triggered_by: str = "system",
    ) -> None:
        self.reason = reason
        self.triggered_by = triggered_by

        message = f"EMERGENCY HALT: {reason} (triggered by: {triggered_by})"

        details = {
            "reason": reason,
            "triggered_by": triggered_by,
        }
        super().__init__(message, details)


class ApprovalRequiredError(ProxilionError):
    """
    Raised when a tool requires approval before execution.

    Tools marked with requires_approval=True must have approval granted
    before they can be executed. This exception blocks execution until
    the approval workflow is completed.

    Attributes:
        tool_name: Name of the tool that requires approval.
        user: The user who attempted to execute the tool.
        reason: Why approval is required.

    Example:
        >>> raise ApprovalRequiredError(
        ...     tool_name="delete_database",
        ...     user="user_123",
        ...     reason="Tool is marked as high-risk and requires manager approval"
        ... )
    """

    def __init__(
        self,
        tool_name: str,
        user: str,
        reason: str | None = None,
    ) -> None:
        self.tool_name = tool_name
        self.user = user
        self.reason = reason or "Tool requires approval before execution"

        message = f"Approval required: Tool '{tool_name}' requires approval. {self.reason}"

        details = {
            "tool_name": tool_name,
            "user": user,
            "reason": self.reason,
        }
        super().__init__(message, details)


class ScopeLoaderError(ProxilionError):
    """
    Raised when a scope loader encounters a temporary failure.

    This exception distinguishes between permanent configuration errors
    (which should be logged and denied) and temporary failures (network
    issues, database timeouts) that callers may want to retry.

    Attributes:
        resource_type: Type of resource being loaded.
        user_id: User for whom scope was being loaded.
        original_error: The underlying error that caused the failure.

    Example:
        >>> raise ScopeLoaderError(
        ...     resource_type="document",
        ...     user_id="user_123",
        ...     original_error=TimeoutError("Database connection timed out")
        ... )
    """

    def __init__(
        self,
        resource_type: str,
        user_id: str,
        original_error: Exception | None = None,
    ) -> None:
        self.resource_type = resource_type
        self.user_id = user_id
        self.original_error = original_error

        message = f"Scope loader failed for {resource_type} (user: {user_id})"
        if original_error:
            message += f": {original_error}"

        details = {
            "resource_type": resource_type,
            "user_id": user_id,
            "original_error": str(original_error) if original_error else None,
        }
        super().__init__(message, details)
