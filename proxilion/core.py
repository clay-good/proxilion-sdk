"""
Core Proxilion class and authorization logic.

This module provides the main entry point for the Proxilion SDK,
integrating policy evaluation, schema validation, rate limiting,
circuit breaking, and audit logging into a unified API.
"""

from __future__ import annotations

import asyncio
import contextvars
import functools
import inspect
import logging
import threading
from collections.abc import Callable
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, ParamSpec, TypeVar

from proxilion.audit.events import AuditEventV2
from proxilion.audit.logger import AuditLogger, InMemoryAuditLogger, LoggerConfig
from proxilion.context.context_window import (
    ContextStrategy,
    ContextWindow,
)
from proxilion.context.session import (
    Session,
    SessionConfig,
    SessionManager,
)
from proxilion.engines import EngineFactory
from proxilion.exceptions import (
    AuthorizationError,
    CircuitOpenError,
    IDORViolationError,
    InputGuardViolation,
    OutputGuardViolation,
    PolicyNotFoundError,
    PolicyViolation,
    RateLimitExceeded,
    SchemaValidationError,
)
from proxilion.guards import GuardAction, GuardResult, InputGuard, OutputGuard
from proxilion.observability.cost_tracker import (
    CostSummary,
    CostTracker,
    UsageRecord,
)
from proxilion.policies.base import Policy
from proxilion.policies.registry import PolicyRegistry
from proxilion.providers import (
    Provider,
    ProviderAdapter,
    UnifiedResponse,
    UnifiedToolCall,
    get_adapter,
)
from proxilion.resilience.degradation import (
    DegradationTier,
    GracefulDegradation,
)
from proxilion.resilience.fallback import (
    FallbackChain,
    FallbackOption,
    ModelFallback,
    ToolFallback,
)
from proxilion.resilience.retry import (
    DEFAULT_RETRY_POLICY,
    RetryPolicy,
    retry_async,
    retry_with_backoff,
)
from proxilion.security.circuit_breaker import (
    CircuitBreakerRegistry,
)
from proxilion.security.cost_limiter import (
    CostLimiter,
    CostLimitResult,
)
from proxilion.security.idor_protection import IDORProtector
from proxilion.security.rate_limiter import (
    RateLimiterMiddleware,
    TokenBucketRateLimiter,
)
from proxilion.security.scope_enforcer import (
    ExecutionScope,
    ScopeBinding,
    ScopeContext,
    ScopeEnforcer,
)
from proxilion.security.sequence_validator import (
    SequenceRule,
    SequenceValidator,
    SequenceViolation,
)
from proxilion.streaming.detector import (
    DetectedToolCall,
    StreamEventType,
    StreamingToolCallDetector,
)
from proxilion.streaming.transformer import (
    StreamTransformer,
    create_authorization_stream,
    create_guarded_stream,
)
from proxilion.timeouts.manager import (
    DeadlineContext,
    TimeoutConfig,
    TimeoutManager,
)
from proxilion.timeouts.manager import (
    TimeoutError as ProxilionTimeoutError,
)
from proxilion.tools.decorators import (
    tool,
)
from proxilion.tools.registry import (
    RiskLevel,
    ToolCategory,
    ToolDefinition,
    ToolExecutionResult,
    ToolRegistry,
)
from proxilion.types import (
    AgentContext,
    AuthorizationResult,
    ToolCallRequest,
    UserContext,
)
from proxilion.validation.schema import SchemaValidator, ToolSchema

logger = logging.getLogger(__name__)

P = ParamSpec("P")
T = TypeVar("T")

# Context variable for current user context
_current_user: contextvars.ContextVar[UserContext | None] = contextvars.ContextVar(
    "proxilion_user", default=None
)

# Context variable for current agent context
_current_agent: contextvars.ContextVar[AgentContext | None] = contextvars.ContextVar(
    "proxilion_agent", default=None
)


def get_current_user() -> UserContext | None:
    """Get the current user from context."""
    return _current_user.get()


def get_current_agent() -> AgentContext | None:
    """Get the current agent from context."""
    return _current_agent.get()


class Proxilion:
    """
    Main entry point for the Proxilion authorization SDK.

    Proxilion provides application-layer security for LLM tool calls,
    combining policy-based authorization, schema validation, rate limiting,
    circuit breaking, and tamper-evident audit logging.

    Features:
        - Pundit-style policy definitions
        - Multiple policy engine backends (simple, Casbin, OPA)
        - Schema validation with security checks
        - Token bucket rate limiting
        - Circuit breaker pattern
        - Hash-chained audit logs

    Example:
        >>> from proxilion import Proxilion, Policy, UserContext
        >>>
        >>> auth = Proxilion(
        ...     policy_engine="simple",
        ...     audit_log_path="./logs/audit.jsonl"
        ... )
        >>>
        >>> @auth.policy("search")
        ... class SearchPolicy(Policy):
        ...     def can_execute(self, context):
        ...         return True  # All authenticated users
        ...
        ...     def can_search_private(self, context):
        ...         return "admin" in self.user.roles
        >>>
        >>> @auth.authorize("execute", resource="search")
        ... async def search_tool(query: str, user: UserContext = None):
        ...     return await perform_search(query)
        >>>
        >>> user = UserContext(user_id="alice", roles=["analyst"])
        >>> result = await search_tool("find documents", user=user)
    """

    def __init__(
        self,
        policy_engine: str = "simple",
        engine_config: dict[str, Any] | None = None,
        audit_log_path: Path | str | None = None,
        rate_limit_config: dict[str, Any] | None = None,
        enable_circuit_breaker: bool = True,
        circuit_breaker_config: dict[str, Any] | None = None,
        enable_idor_protection: bool = True,
        default_deny: bool = True,
        input_guard: InputGuard | None = None,
        output_guard: OutputGuard | None = None,
        sequence_validator: SequenceValidator | None = None,
        scope_enforcer: ScopeEnforcer | None = None,
        cost_tracker: CostTracker | None = None,
        cost_limiter: CostLimiter | None = None,
        session_manager: SessionManager | None = None,
        session_config: SessionConfig | None = None,
        timeout_manager: TimeoutManager | None = None,
        timeout_config: TimeoutConfig | None = None,
        retry_policy: RetryPolicy | None = None,
        graceful_degradation: GracefulDegradation | None = None,
        enable_degradation: bool = False,
        tool_registry: ToolRegistry | None = None,
    ) -> None:
        """
        Initialize Proxilion.

        Args:
            policy_engine: Policy engine type ("simple", "casbin", "opa").
            engine_config: Configuration for the policy engine.
            audit_log_path: Path for audit log file (None for in-memory).
            rate_limit_config: Rate limiting configuration.
            enable_circuit_breaker: Whether to enable circuit breaker.
            circuit_breaker_config: Circuit breaker configuration.
            enable_idor_protection: Whether to enable IDOR protection.
            default_deny: If True, deny requests with no matching policy.
            input_guard: Optional InputGuard for prompt injection detection.
            output_guard: Optional OutputGuard for data leakage detection.
            sequence_validator: Optional SequenceValidator for tool sequence rules.
            scope_enforcer: Optional ScopeEnforcer for semantic scope enforcement.
            cost_tracker: Optional CostTracker for usage and cost tracking.
            cost_limiter: Optional CostLimiter for cost-based rate limiting.
            session_manager: Optional SessionManager for session tracking.
            session_config: Optional SessionConfig for session defaults.
            timeout_manager: Optional TimeoutManager for timeout handling.
            timeout_config: Optional TimeoutConfig for timeout defaults.
            retry_policy: Optional RetryPolicy for retry behavior.
            graceful_degradation: Optional GracefulDegradation for tier management.
            enable_degradation: Whether to enable graceful degradation.
            tool_registry: Optional ToolRegistry for tool management.
        """
        self._lock = threading.RLock()
        self._default_deny = default_deny

        # Initialize policy registry
        self._registry = PolicyRegistry()

        # Initialize policy engine
        self._engine = EngineFactory.create(
            engine_type=policy_engine,
            config=engine_config or {},
        )

        # Initialize schema validator
        self._schema_validator = SchemaValidator()

        # Initialize rate limiter
        self._rate_limiter: RateLimiterMiddleware | None = None
        if rate_limit_config:
            self._setup_rate_limiter(rate_limit_config)

        # Initialize circuit breaker registry
        self._circuit_breakers: CircuitBreakerRegistry | None = None
        if enable_circuit_breaker:
            cb_config = circuit_breaker_config or {}
            self._circuit_breakers = CircuitBreakerRegistry(
                default_config={
                    "failure_threshold": cb_config.get("failure_threshold", 5),
                    "reset_timeout": cb_config.get("reset_timeout", 30.0),
                }
            )

        # Initialize IDOR protector
        self._idor_protector: IDORProtector | None = None
        if enable_idor_protection:
            self._idor_protector = IDORProtector()

        # Initialize guards
        self._input_guard = input_guard
        self._output_guard = output_guard

        # Initialize sequence validator
        self._sequence_validator = sequence_validator

        # Initialize scope enforcer
        self._scope_enforcer = scope_enforcer
        self._current_scope: ScopeBinding | None = None

        # Initialize cost tracking
        self._cost_tracker = cost_tracker
        self._cost_limiter = cost_limiter
        if cost_limiter and cost_tracker:
            cost_limiter.set_cost_tracker(cost_tracker)

        # Initialize session management
        self._session_config = session_config or SessionConfig()
        self._session_manager = session_manager or SessionManager(self._session_config)

        # Initialize timeout management
        self._timeout_config = timeout_config or TimeoutConfig()
        self._timeout_manager = timeout_manager or TimeoutManager(self._timeout_config)

        # Initialize resilience components
        self._retry_policy = retry_policy or DEFAULT_RETRY_POLICY
        self._graceful_degradation: GracefulDegradation | None = None
        if enable_degradation:
            self._graceful_degradation = graceful_degradation or GracefulDegradation()

        # Initialize tool registry
        self._tool_registry = tool_registry or ToolRegistry()

        # Initialize audit logger
        self._audit_logger: AuditLogger | InMemoryAuditLogger
        if audit_log_path:
            config = LoggerConfig.default(Path(audit_log_path))
            self._audit_logger = AuditLogger(config)
        else:
            self._audit_logger = InMemoryAuditLogger()

    def _setup_rate_limiter(self, config: dict[str, Any]) -> None:
        """Set up rate limiter from configuration."""
        user_limit = None
        if "user" in config:
            user_cfg = config["user"]
            user_limit = TokenBucketRateLimiter(
                capacity=user_cfg.get("capacity", 100),
                refill_rate=user_cfg.get("refill_rate", 10.0),
            )

        global_limit = None
        if "global" in config:
            global_cfg = config["global"]
            global_limit = TokenBucketRateLimiter(
                capacity=global_cfg.get("capacity", 1000),
                refill_rate=global_cfg.get("refill_rate", 100.0),
            )

        tool_limits: dict[str, TokenBucketRateLimiter] = {}
        if "tools" in config:
            for tool_name, tool_cfg in config["tools"].items():
                tool_limits[tool_name] = TokenBucketRateLimiter(
                    capacity=tool_cfg.get("capacity", 50),
                    refill_rate=tool_cfg.get("refill_rate", 5.0),
                )

        self._rate_limiter = RateLimiterMiddleware(
            user_limit=user_limit,
            tool_limits=tool_limits,
            global_limit=global_limit,
        )

    # ==================== Policy Registration ====================

    def policy(self, resource_name: str) -> Callable[[type[Policy]], type[Policy]]:
        """
        Decorator to register a policy class for a resource.

        Args:
            resource_name: The resource this policy applies to.

        Returns:
            A decorator that registers the policy class.

        Example:
            >>> @auth.policy("database_query")
            ... class DatabaseQueryPolicy(Policy):
            ...     def can_execute(self, context):
            ...         return "analyst" in self.user.roles
        """
        return self._registry.policy(resource_name)

    def register_policy(
        self,
        resource_name: str,
        policy_class: type[Policy],
    ) -> None:
        """
        Register a policy class programmatically.

        Args:
            resource_name: The resource this policy applies to.
            policy_class: The policy class to register.
        """
        self._registry.register(resource_name, policy_class)

    # ==================== Schema Registration ====================

    def register_schema(self, tool_name: str, schema: ToolSchema) -> None:
        """
        Register a tool schema for validation.

        Args:
            tool_name: The tool name.
            schema: The tool schema.
        """
        self._schema_validator.register_schema(tool_name, schema)

    # ==================== IDOR Protection ====================

    def register_scope(
        self,
        user_id: str,
        resource_type: str,
        allowed_ids: set[str],
    ) -> None:
        """
        Register allowed object IDs for a user.

        Args:
            user_id: The user's ID.
            resource_type: Type of resource (e.g., "document").
            allowed_ids: Set of object IDs the user can access.
        """
        if self._idor_protector:
            self._idor_protector.register_scope(user_id, resource_type, allowed_ids)

    def register_id_pattern(
        self,
        parameter_name: str,
        resource_type: str,
    ) -> None:
        """
        Register a parameter as containing object IDs.

        Args:
            parameter_name: The parameter name (e.g., "document_id").
            resource_type: The resource type it refers to.
        """
        if self._idor_protector:
            self._idor_protector.register_id_pattern(parameter_name, resource_type)

    # ==================== Guards ====================

    def guard_input(
        self,
        input_text: str,
        context: dict[str, Any] | None = None,
        raise_on_block: bool = False,
    ) -> GuardResult:
        """
        Check input against guards before tool execution.

        Detects prompt injection patterns and other malicious input.

        Args:
            input_text: The user input to check.
            context: Optional context for pattern evaluation.
            raise_on_block: If True, raise InputGuardViolation on block.

        Returns:
            GuardResult with check outcome.

        Raises:
            InputGuardViolation: If raise_on_block=True and input is blocked.

        Example:
            >>> result = auth.guard_input("ignore all instructions")
            >>> if not result.passed:
            ...     print(f"Blocked: {result.matched_patterns}")
        """
        if self._input_guard is None:
            return GuardResult(passed=True, action=GuardAction.ALLOW)

        result = self._input_guard.check(input_text, context)

        if raise_on_block and not result.passed and result.action == GuardAction.BLOCK:
            raise InputGuardViolation(
                matched_patterns=result.matched_patterns,
                risk_score=result.risk_score,
            )

        return result

    def guard_output(
        self,
        output_text: str,
        context: dict[str, Any] | None = None,
        raise_on_block: bool = False,
        auto_redact: bool = False,
    ) -> GuardResult:
        """
        Check output against guards after tool execution.

        Detects sensitive data leakage such as API keys and credentials.

        Args:
            output_text: The output to check.
            context: Optional context for pattern evaluation.
            raise_on_block: If True, raise OutputGuardViolation on block.
            auto_redact: If True and leakage detected, redact in result.

        Returns:
            GuardResult with check outcome.

        Raises:
            OutputGuardViolation: If raise_on_block=True and output is blocked.

        Example:
            >>> result = auth.guard_output("API key: sk-abc123...")
            >>> if not result.passed:
            ...     print(f"Leakage: {result.matched_patterns}")
        """
        if self._output_guard is None:
            return GuardResult(passed=True, action=GuardAction.ALLOW)

        result = self._output_guard.check(output_text, context)

        if auto_redact and not result.passed:
            result.sanitized_input = self._output_guard.redact(output_text)

        if raise_on_block and not result.passed and result.action == GuardAction.BLOCK:
            raise OutputGuardViolation(
                matched_patterns=result.matched_patterns,
                risk_score=result.risk_score,
            )

        return result

    def redact_output(self, output_text: str) -> str:
        """
        Redact sensitive data from output text.

        Args:
            output_text: Text to redact.

        Returns:
            Text with sensitive data redacted.
        """
        if self._output_guard is None:
            return output_text
        return self._output_guard.redact(output_text)

    def set_input_guard(self, guard: InputGuard | None) -> None:
        """
        Set or replace the input guard.

        Args:
            guard: The input guard to use, or None to disable.
        """
        self._input_guard = guard

    def set_output_guard(self, guard: OutputGuard | None) -> None:
        """
        Set or replace the output guard.

        Args:
            guard: The output guard to use, or None to disable.
        """
        self._output_guard = guard

    # ==================== Sequence Validation ====================

    def validate_sequence(
        self,
        tool_name: str,
        user: UserContext,
    ) -> tuple[bool, SequenceViolation | None]:
        """
        Validate a tool call against sequence rules.

        Checks if the tool call is allowed given the user's recent
        tool call history. Prevents dangerous patterns like:
        - Calling delete without confirm first
        - Download followed by execute
        - Rapid consecutive calls

        Args:
            tool_name: Name of the tool to validate.
            user: The user context.

        Returns:
            Tuple of (allowed, violation). If allowed is False,
            violation contains details about what rule was violated.

        Example:
            >>> allowed, violation = auth.validate_sequence("delete_file", user)
            >>> if not allowed:
            ...     print(f"Blocked: {violation.message}")
        """
        if self._sequence_validator is None:
            return True, None
        return self._sequence_validator.validate_call(tool_name, user.user_id)

    def record_tool_call(
        self,
        tool_name: str,
        user: UserContext,
    ) -> None:
        """
        Record a tool call for sequence tracking.

        Should be called after a tool call completes successfully
        to maintain accurate history for sequence validation.

        Args:
            tool_name: Name of the tool called.
            user: The user context.

        Example:
            >>> auth.record_tool_call("confirm_delete", user)
            >>> auth.record_tool_call("delete_file", user)
        """
        if self._sequence_validator:
            self._sequence_validator.record_call(tool_name, user.user_id)

    def add_sequence_rule(self, rule: SequenceRule) -> None:
        """
        Add a sequence validation rule.

        Args:
            rule: The rule to add.

        Example:
            >>> auth.add_sequence_rule(SequenceRule(
            ...     name="require_auth",
            ...     action=SequenceAction.REQUIRE_BEFORE,
            ...     target_pattern="access_*",
            ...     required_pattern="authenticate",
            ... ))
        """
        if self._sequence_validator:
            self._sequence_validator.add_rule(rule)

    def remove_sequence_rule(self, name: str) -> bool:
        """
        Remove a sequence rule by name.

        Args:
            name: The rule name to remove.

        Returns:
            True if rule was removed, False if not found.
        """
        if self._sequence_validator:
            return self._sequence_validator.remove_rule(name)
        return False

    def get_tool_history(
        self,
        user: UserContext,
        limit: int | None = None,
    ) -> list[tuple[str, Any]]:
        """
        Get tool call history for a user.

        Args:
            user: The user context.
            limit: Maximum entries to return.

        Returns:
            List of (tool_name, timestamp) tuples, most recent first.
        """
        if self._sequence_validator:
            return self._sequence_validator.get_history(user.user_id, limit)
        return []

    def clear_tool_history(self, user: UserContext | None = None) -> None:
        """
        Clear tool call history.

        Args:
            user: User to clear history for (None to clear all).
        """
        if self._sequence_validator:
            user_id = user.user_id if user else None
            self._sequence_validator.clear_history(user_id)

    def set_sequence_validator(
        self,
        validator: SequenceValidator | None,
    ) -> None:
        """
        Set or replace the sequence validator.

        Args:
            validator: The validator to use, or None to disable.
        """
        self._sequence_validator = validator

    # ==================== Scope Enforcement Methods ====================

    def enter_scope(
        self,
        scope: ExecutionScope | str,
        user: UserContext,
    ) -> ScopeContext:
        """
        Enter a scoped execution context.

        Creates a ScopeContext that validates tool calls against the
        specified scope's restrictions.

        Args:
            scope: Scope name or ExecutionScope enum.
            user: The user context for this execution.

        Returns:
            ScopeContext for validating tool calls.

        Raises:
            ProxilionError: If scope enforcer is not configured.

        Example:
            >>> ctx = auth.enter_scope("read_only", user)
            >>> try:
            ...     ctx.validate_tool("get_user")  # OK
            ...     ctx.validate_tool("delete_user")  # Raises ScopeViolationError
            ... finally:
            ...     ctx.close()
        """
        if self._scope_enforcer is None:
            from proxilion.exceptions import ProxilionError
            raise ProxilionError("Scope enforcer not configured")

        if isinstance(scope, str):
            scope_binding = self._scope_enforcer.get_scope(scope)
        else:
            scope_binding = self._scope_enforcer.create_scope_from_enum(scope)

        return ScopeContext(self._scope_enforcer, scope_binding, user)

    def validate_scope(
        self,
        tool_name: str,
        action: str = "execute",
    ) -> tuple[bool, str | None]:
        """
        Validate a tool against the current scope.

        Args:
            tool_name: Name of the tool to validate.
            action: Action being performed.

        Returns:
            Tuple of (allowed, reason). If allowed is False, reason explains why.
        """
        if self._current_scope is None or self._scope_enforcer is None:
            return True, None  # No scope enforcement

        return self._scope_enforcer.validate_in_scope(
            tool_name, action, self._current_scope
        )

    def set_scope_enforcer(
        self,
        enforcer: ScopeEnforcer | None,
    ) -> None:
        """
        Set or replace the scope enforcer.

        Args:
            enforcer: The enforcer to use, or None to disable.
        """
        self._scope_enforcer = enforcer

    def get_scope_enforcer(self) -> ScopeEnforcer | None:
        """Get the current scope enforcer."""
        return self._scope_enforcer

    def create_scope(
        self,
        name: str,
        allowed_tools: set[str] | None = None,
        denied_tools: set[str] | None = None,
        allowed_actions: set[str] | None = None,
        denied_actions: set[str] | None = None,
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
            description: Human-readable description.

        Returns:
            The created ScopeBinding.

        Raises:
            ProxilionError: If scope enforcer is not configured.

        Example:
            >>> scope = auth.create_scope(
            ...     name="user_data",
            ...     allowed_tools={"get_user_*", "search_users"},
            ...     denied_tools={"delete_*"},
            ...     allowed_actions={"read", "list"},
            ... )
        """
        if self._scope_enforcer is None:
            from proxilion.exceptions import ProxilionError
            raise ProxilionError("Scope enforcer not configured")

        return self._scope_enforcer.create_scope(
            name=name,
            allowed_tools=allowed_tools,
            denied_tools=denied_tools,
            allowed_actions=allowed_actions,
            denied_actions=denied_actions,
            description=description,
        )

    def classify_tool(
        self,
        tool_name: str,
        scope: ExecutionScope | None = None,
        actions: set[str] | None = None,
    ) -> None:
        """
        Classify a tool with a specific scope.

        Args:
            tool_name: Name of the tool.
            scope: Scope to assign (or None for pattern-based classification).
            actions: Actions the tool performs.

        Raises:
            ProxilionError: If scope enforcer is not configured.
        """
        if self._scope_enforcer is None:
            from proxilion.exceptions import ProxilionError
            raise ProxilionError("Scope enforcer not configured")

        self._scope_enforcer.classify_tool(tool_name, scope, actions)

    # ==================== Cost Tracking Methods ====================

    def record_usage(
        self,
        model: str,
        input_tokens: int,
        output_tokens: int,
        cache_read_tokens: int = 0,
        cache_write_tokens: int = 0,
        tool_name: str | None = None,
        user: UserContext | None = None,
        request_id: str | None = None,
    ) -> UsageRecord | None:
        """
        Record token usage and calculate cost.

        Args:
            model: Model identifier.
            input_tokens: Number of input tokens.
            output_tokens: Number of output tokens.
            cache_read_tokens: Number of cached tokens read.
            cache_write_tokens: Number of tokens written to cache.
            tool_name: Tool that triggered the usage.
            user: User who incurred the usage.
            request_id: Request identifier.

        Returns:
            UsageRecord if cost tracker is configured, None otherwise.

        Example:
            >>> record = auth.record_usage(
            ...     model="claude-sonnet-4-20250514",
            ...     input_tokens=1000,
            ...     output_tokens=500,
            ...     user=user,
            ... )
            >>> print(f"Cost: ${record.cost_usd:.4f}")
        """
        if self._cost_tracker is None:
            return None

        return self._cost_tracker.record_usage(
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cache_read_tokens=cache_read_tokens,
            cache_write_tokens=cache_write_tokens,
            tool_name=tool_name,
            user_id=user.user_id if user else None,
            request_id=request_id,
        )

    def check_budget(
        self,
        user: UserContext,
        estimated_cost: float = 0.0,
        estimated_tokens: int = 0,
    ) -> tuple[bool, str | None]:
        """
        Check if a request would exceed budget limits.

        Args:
            user: User making the request.
            estimated_cost: Estimated cost of the request.
            estimated_tokens: Estimated tokens for the request.

        Returns:
            Tuple of (allowed, reason). If not allowed, reason explains why.

        Example:
            >>> allowed, reason = auth.check_budget(user, estimated_tokens=10000)
            >>> if not allowed:
            ...     print(f"Budget issue: {reason}")
        """
        if self._cost_tracker is None:
            return True, None

        return self._cost_tracker.check_budget(
            user_id=user.user_id,
            estimated_cost=estimated_cost,
            estimated_tokens=estimated_tokens,
        )

    def check_cost_limit(
        self,
        user: UserContext,
        estimated_cost: float,
    ) -> CostLimitResult | None:
        """
        Check cost-based rate limits.

        Args:
            user: User making the request.
            estimated_cost: Estimated cost of the request.

        Returns:
            CostLimitResult if cost limiter is configured, None otherwise.
        """
        if self._cost_limiter is None:
            return None

        return self._cost_limiter.check_limit(user.user_id, estimated_cost)

    def get_cost_summary(
        self,
        user: UserContext | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> CostSummary | None:
        """
        Get a cost summary for the specified period.

        Args:
            user: Filter by user (or None for all users).
            start: Start of period.
            end: End of period.

        Returns:
            CostSummary if cost tracker is configured, None otherwise.
        """
        if self._cost_tracker is None:
            return None

        return self._cost_tracker.get_summary(
            start=start,
            end=end,
            user_id=user.user_id if user else None,
        )

    def get_budget_status(self, user: UserContext) -> dict[str, Any]:
        """
        Get current budget status for a user.

        Args:
            user: User to check.

        Returns:
            Dictionary with budget status information.
        """
        if self._cost_tracker is None:
            return {"cost_tracking_enabled": False}

        return self._cost_tracker.get_budget_status(user.user_id)

    def set_cost_tracker(self, tracker: CostTracker | None) -> None:
        """
        Set or replace the cost tracker.

        Args:
            tracker: The tracker to use, or None to disable.
        """
        self._cost_tracker = tracker
        if self._cost_limiter and tracker:
            self._cost_limiter.set_cost_tracker(tracker)

    def set_cost_limiter(self, limiter: CostLimiter | None) -> None:
        """
        Set or replace the cost limiter.

        Args:
            limiter: The limiter to use, or None to disable.
        """
        self._cost_limiter = limiter
        if limiter and self._cost_tracker:
            limiter.set_cost_tracker(self._cost_tracker)

    def get_cost_tracker(self) -> CostTracker | None:
        """Get the current cost tracker."""
        return self._cost_tracker

    def get_cost_limiter(self) -> CostLimiter | None:
        """Get the current cost limiter."""
        return self._cost_limiter

    # ==================== Session Management Methods ====================

    def create_session(
        self,
        user: UserContext,
        session_id: str | None = None,
        config: SessionConfig | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Session:
        """
        Create a new session for a user.

        Args:
            user: The user context.
            session_id: Optional session ID (auto-generated if not provided).
            config: Optional session-specific configuration.
            metadata: Optional initial metadata.

        Returns:
            The created session.

        Example:
            >>> session = auth.create_session(user)
            >>> session.add_message(MessageRole.USER, "Hello!")
        """
        return self._session_manager.create_session(
            user=user,
            session_id=session_id,
            config=config,
            metadata=metadata,
        )

    def get_session(self, session_id: str) -> Session | None:
        """
        Get a session by ID.

        Args:
            session_id: The session ID.

        Returns:
            The session if found and not expired, None otherwise.
        """
        return self._session_manager.get_session(session_id)

    def get_or_create_session(
        self,
        user: UserContext,
        session_id: str | None = None,
        config: SessionConfig | None = None,
    ) -> tuple[Session, bool]:
        """
        Get an existing session or create a new one.

        Args:
            user: The user context.
            session_id: Optional session ID to look up.
            config: Optional session configuration for creation.

        Returns:
            Tuple of (session, created) where created is True if new.

        Example:
            >>> session, is_new = auth.get_or_create_session(user, "sess_123")
            >>> if is_new:
            ...     print("Created new session")
        """
        return self._session_manager.get_or_create_session(
            user=user,
            session_id=session_id,
            config=config,
        )

    def get_user_sessions(
        self,
        user: UserContext,
        include_expired: bool = False,
    ) -> list[Session]:
        """
        Get all sessions for a user.

        Args:
            user: The user context.
            include_expired: Whether to include expired sessions.

        Returns:
            List of sessions for the user.
        """
        return self._session_manager.get_user_sessions(
            user_id=user.user_id,
            include_expired=include_expired,
        )

    def terminate_session(
        self,
        session_id: str,
        reason: str | None = None,
    ) -> bool:
        """
        Terminate a session.

        Args:
            session_id: The session ID.
            reason: Optional reason for termination.

        Returns:
            True if session was found and terminated.
        """
        return self._session_manager.terminate_session(session_id, reason)

    def terminate_user_sessions(
        self,
        user: UserContext,
        reason: str | None = None,
    ) -> int:
        """
        Terminate all sessions for a user.

        Args:
            user: The user context.
            reason: Optional reason for termination.

        Returns:
            Number of sessions terminated.
        """
        return self._session_manager.terminate_user_sessions(user.user_id, reason)

    def cleanup_expired_sessions(self) -> int:
        """
        Remove expired and terminated sessions.

        Returns:
            Number of sessions removed.
        """
        return self._session_manager.cleanup_expired()

    def get_session_stats(self) -> dict[str, Any]:
        """
        Get session statistics.

        Returns:
            Dictionary with session statistics.

        Example:
            >>> stats = auth.get_session_stats()
            >>> print(f"Active: {stats['active']}, Expired: {stats['expired']}")
        """
        return self._session_manager.get_stats()

    def get_active_session_count(self) -> int:
        """
        Get count of active (non-expired) sessions.

        Returns:
            Number of active sessions.
        """
        return self._session_manager.get_active_count()

    def set_session_manager(self, manager: SessionManager | None) -> None:
        """
        Set or replace the session manager.

        Args:
            manager: The manager to use. If None, creates a new default manager.
        """
        if manager is None:
            self._session_manager = SessionManager(self._session_config)
        else:
            self._session_manager = manager

    def get_session_manager(self) -> SessionManager:
        """Get the current session manager."""
        return self._session_manager

    def create_context_window(
        self,
        max_tokens: int,
        strategy: ContextStrategy = ContextStrategy.KEEP_SYSTEM_RECENT,
        reserve_output: int = 1000,
    ) -> ContextWindow:
        """
        Create a context window for managing LLM context.

        Args:
            max_tokens: Maximum tokens for context.
            strategy: Strategy for fitting messages.
            reserve_output: Tokens to reserve for output.

        Returns:
            Configured ContextWindow.

        Example:
            >>> window = auth.create_context_window(8000)
            >>> messages = session.history.get_messages()
            >>> fitted = window.fit_messages(messages)
        """
        return ContextWindow(
            max_tokens=max_tokens,
            strategy=strategy,
            reserve_output=reserve_output,
        )

    # ==================== Timeout Management Methods ====================

    def get_timeout(self, operation: str) -> float:
        """
        Get timeout for a specific operation.

        Args:
            operation: Name of the operation or tool.

        Returns:
            Timeout value in seconds.

        Example:
            >>> timeout = auth.get_timeout("web_search")
        """
        return self._timeout_manager.get_timeout(operation)

    def get_llm_timeout(self) -> float:
        """
        Get timeout for LLM operations.

        Returns:
            LLM timeout in seconds.
        """
        return self._timeout_manager.get_llm_timeout()

    def set_tool_timeout(self, tool_name: str, timeout: float) -> None:
        """
        Set timeout for a specific tool.

        Args:
            tool_name: Name of the tool.
            timeout: Timeout value in seconds.
        """
        self._timeout_manager.set_tool_timeout(tool_name, timeout)

    def create_deadline(
        self,
        timeout: float | None = None,
        operation: str | None = None,
    ) -> DeadlineContext:
        """
        Create a deadline context for tracking time budget.

        Args:
            timeout: Explicit timeout (uses total_request_timeout if None).
            operation: Optional operation name.

        Returns:
            DeadlineContext for tracking the deadline.

        Example:
            >>> async with auth.create_deadline(30.0) as deadline:
            ...     result1 = await tool1(timeout=deadline.remaining())
            ...     result2 = await tool2(timeout=deadline.remaining())
        """
        return self._timeout_manager.create_deadline(timeout, operation)

    def create_tool_deadline(self, tool_name: str) -> DeadlineContext:
        """
        Create a deadline context for a specific tool.

        Args:
            tool_name: Name of the tool.

        Returns:
            DeadlineContext with tool-specific timeout.
        """
        return self._timeout_manager.create_tool_deadline(tool_name)

    def get_effective_timeout(
        self,
        operation: str,
        requested_timeout: float | None = None,
    ) -> float:
        """
        Get effective timeout considering current deadline.

        If there's an active deadline context, returns the minimum
        of the requested timeout and remaining deadline time.

        Args:
            operation: Name of the operation.
            requested_timeout: Requested timeout (uses config if None).

        Returns:
            Effective timeout in seconds.
        """
        return self._timeout_manager.get_effective_timeout(operation, requested_timeout)

    def set_timeout_manager(self, manager: TimeoutManager | None) -> None:
        """
        Set or replace the timeout manager.

        Args:
            manager: The manager to use. If None, creates a new default manager.
        """
        if manager is None:
            self._timeout_manager = TimeoutManager(self._timeout_config)
        else:
            self._timeout_manager = manager

    def get_timeout_manager(self) -> TimeoutManager:
        """Get the current timeout manager."""
        return self._timeout_manager

    async def authorize_with_timeout(
        self,
        user: UserContext,
        action: str,
        resource: str,
        timeout: float | None = None,
        context: dict[str, Any] | None = None,
    ) -> AuthorizationResult:
        """
        Authorize with a timeout.

        Args:
            user: The user context.
            action: The action to perform.
            resource: The resource name.
            timeout: Explicit timeout (uses default if None).
            context: Additional context for the policy.

        Returns:
            AuthorizationResult if authorized within timeout.

        Raises:
            ProxilionTimeoutError: If authorization times out.

        Example:
            >>> result = await auth.authorize_with_timeout(
            ...     user, "execute", "search", timeout=5.0
            ... )
        """
        effective_timeout = timeout or self._timeout_config.default_timeout
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(self.check, user, action, resource, context),
                timeout=effective_timeout,
            )
        except asyncio.TimeoutError as e:
            raise ProxilionTimeoutError(
                message="Authorization check timed out",
                operation=f"authorize:{action}:{resource}",
                timeout=effective_timeout,
            ) from e

    # ==================== Authorization Methods ====================

    def can(
        self,
        user: UserContext,
        action: str,
        resource: str,
        context: dict[str, Any] | None = None,
    ) -> bool:
        """
        Check if a user can perform an action on a resource.

        This is a simple boolean check that returns True/False
        without raising exceptions.

        Args:
            user: The user context.
            action: The action to perform (e.g., "execute", "read").
            resource: The resource name.
            context: Additional context for the policy.

        Returns:
            True if authorized, False otherwise.

        Example:
            >>> if auth.can(user, "execute", "database_query"):
            ...     result = await database_query(query)
        """
        result = self.check(user, action, resource, context)
        return result.allowed

    def check(
        self,
        user: UserContext,
        action: str,
        resource: str,
        context: dict[str, Any] | None = None,
    ) -> AuthorizationResult:
        """
        Check authorization and return detailed result.

        Unlike `can()`, this method returns an AuthorizationResult
        with the reason for the decision and policies evaluated.

        Args:
            user: The user context.
            action: The action to perform.
            resource: The resource name.
            context: Additional context for the policy.

        Returns:
            AuthorizationResult with allowed status and details.

        Example:
            >>> result = auth.check(user, "execute", "database_query")
            >>> if not result.allowed:
            ...     print(f"Denied: {result.reason}")
        """
        context = context or {}

        # Try policy registry first (Pundit-style)
        try:
            policy_class = self._registry.get_policy(resource)
        except PolicyNotFoundError:
            policy_class = None

        if policy_class:
            policy = policy_class(user, resource)
            method_name = f"can_{action}"

            if hasattr(policy, method_name):
                method = getattr(policy, method_name)
                try:
                    allowed = method(context)
                    return AuthorizationResult(
                        allowed=bool(allowed),
                        reason=f"Policy {policy_class.__name__}.{method_name} returned {allowed}",
                        policies_evaluated=[policy_class.__name__],
                    )
                except Exception as e:
                    logger.error(f"Policy {policy_class.__name__}.{method_name} raised: {e}")
                    return AuthorizationResult.deny(
                        reason=f"Policy evaluation failed: {e}",
                        policies=[policy_class.__name__],
                    )

        # Fall back to policy engine
        result = self._engine.evaluate(user, action, resource, context)
        return result

    def authorize_or_raise(
        self,
        user: UserContext,
        action: str,
        resource: str,
        context: dict[str, Any] | None = None,
    ) -> AuthorizationResult:
        """
        Check authorization and raise if denied.

        Args:
            user: The user context.
            action: The action to perform.
            resource: The resource name.
            context: Additional context.

        Returns:
            AuthorizationResult if authorized.

        Raises:
            AuthorizationError: If authorization is denied.
        """
        result = self.check(user, action, resource, context)

        if not result.allowed:
            raise AuthorizationError(
                user=user.user_id,
                action=action,
                resource=resource,
                reason=result.reason,
            )

        return result

    # ==================== Decorator ====================

    def authorize(
        self,
        action: str,
        resource: str | None = None,
        user_param: str = "user",
        agent_param: str = "agent",
        validate_schema: bool = True,
        apply_rate_limit: bool = True,
        check_circuit_breaker: bool = True,
        log_audit: bool = True,
    ) -> Callable[[Callable[P, T]], Callable[P, T]]:
        """
        Decorator to protect a function with authorization.

        Wraps the function with:
        1. Schema validation (if registered)
        2. Authorization check
        3. Rate limiting
        4. Circuit breaker
        5. Audit logging

        Works with both sync and async functions.

        Args:
            action: The action being performed (e.g., "execute").
            resource: The resource name (defaults to function name).
            user_param: Parameter name containing UserContext.
            agent_param: Parameter name containing AgentContext.
            validate_schema: Whether to validate against registered schema.
            apply_rate_limit: Whether to apply rate limiting.
            check_circuit_breaker: Whether to check circuit breaker.
            log_audit: Whether to log audit events.

        Returns:
            A decorator function.

        Example:
            >>> @auth.authorize("execute", resource="search")
            ... async def search_tool(query: str, user: UserContext = None):
            ...     return await perform_search(query)
        """
        def decorator(func: Callable[P, T]) -> Callable[P, T]:
            # Determine resource name
            nonlocal resource
            if resource is None:
                resource = func.__name__

            # Check if function is async
            is_async = inspect.iscoroutinefunction(func)

            if is_async:
                @functools.wraps(func)
                async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
                    return await self._execute_with_auth(
                        func=func,
                        args=args,
                        kwargs=kwargs,
                        action=action,
                        resource=resource,
                        user_param=user_param,
                        agent_param=agent_param,
                        validate_schema=validate_schema,
                        apply_rate_limit=apply_rate_limit,
                        check_circuit_breaker=check_circuit_breaker,
                        log_audit=log_audit,
                        is_async=True,
                    )
                return async_wrapper  # type: ignore
            else:
                @functools.wraps(func)
                def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
                    # Run in event loop if one exists, otherwise synchronously
                    return self._execute_with_auth_sync(
                        func=func,
                        args=args,
                        kwargs=kwargs,
                        action=action,
                        resource=resource,
                        user_param=user_param,
                        agent_param=agent_param,
                        validate_schema=validate_schema,
                        apply_rate_limit=apply_rate_limit,
                        check_circuit_breaker=check_circuit_breaker,
                        log_audit=log_audit,
                    )
                return sync_wrapper  # type: ignore

        return decorator

    async def _execute_with_auth(
        self,
        func: Callable[..., Any],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        action: str,
        resource: str,
        user_param: str,
        agent_param: str,
        validate_schema: bool,
        apply_rate_limit: bool,
        check_circuit_breaker: bool,
        log_audit: bool,
        is_async: bool,
    ) -> Any:
        """Execute function with all authorization checks (async version)."""
        # Extract user and agent from kwargs or context
        user = kwargs.get(user_param) or get_current_user()
        agent = kwargs.get(agent_param) or get_current_agent()

        if user is None:
            raise AuthorizationError(
                user="unknown",
                action=action,
                resource=resource,
                reason="No user context provided",
            )

        # Build context from arguments
        context = dict(kwargs)
        context["_args"] = args

        tool_request = ToolCallRequest(
            tool_name=resource,
            arguments=context,
        )

        auth_result: AuthorizationResult | None = None
        execution_result: dict[str, Any] | None = None
        error_message: str | None = None

        try:
            # 1. Schema validation
            if validate_schema:
                self._validate_schema(resource, context)

            # 2. IDOR protection
            if self._idor_protector:
                violations = self._idor_protector.validate_arguments(user.user_id, context)
                if violations:
                    param, res_type, obj_id = violations[0]
                    raise IDORViolationError(
                        user_id=user.user_id,
                        resource_type=res_type,
                        object_id=obj_id,
                    )

            # 3. Authorization check
            auth_result = self.authorize_or_raise(user, action, resource, context)

            # 4. Rate limiting
            if apply_rate_limit and self._rate_limiter:
                self._apply_rate_limit(user, resource)

            # 5. Circuit breaker
            if check_circuit_breaker and self._circuit_breakers:
                breaker = self._circuit_breakers.get(resource)
                if not breaker.is_available():
                    stats = breaker.stats
                    raise CircuitOpenError(
                        circuit_name=resource,
                        failure_count=stats.consecutive_failures,
                        reset_timeout=breaker.reset_timeout,
                        last_failure=stats.last_failure_error,
                    )

            # 6. Execute function
            if is_async:
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)

            # Record success for circuit breaker
            if self._circuit_breakers:
                breaker = self._circuit_breakers.get(resource)
                breaker._record_success()

            execution_result = {"success": True, "result_type": type(result).__name__}
            return result

        except (AuthorizationError, PolicyViolation, SchemaValidationError,
                RateLimitExceeded, CircuitOpenError, IDORViolationError):
            # Re-raise Proxilion exceptions
            raise

        except Exception as e:
            # Record failure for circuit breaker
            if self._circuit_breakers:
                breaker = self._circuit_breakers.get(resource)
                breaker._record_failure(e)

            error_message = str(e)
            raise

        finally:
            # 7. Audit logging
            if log_audit:
                self._log_audit_event(
                    user=user,
                    agent=agent,
                    tool_request=tool_request,
                    auth_result=auth_result,
                    execution_result=execution_result,
                    error_message=error_message,
                )

    def _execute_with_auth_sync(
        self,
        func: Callable[..., Any],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        action: str,
        resource: str,
        user_param: str,
        agent_param: str,
        validate_schema: bool,
        apply_rate_limit: bool,
        check_circuit_breaker: bool,
        log_audit: bool,
    ) -> Any:
        """Execute function with all authorization checks (sync version)."""
        # Extract user and agent from kwargs or context
        user = kwargs.get(user_param) or get_current_user()
        agent = kwargs.get(agent_param) or get_current_agent()

        if user is None:
            raise AuthorizationError(
                user="unknown",
                action=action,
                resource=resource,
                reason="No user context provided",
            )

        # Build context from arguments
        context = dict(kwargs)
        context["_args"] = args

        tool_request = ToolCallRequest(
            tool_name=resource,
            arguments=context,
        )

        auth_result: AuthorizationResult | None = None
        execution_result: dict[str, Any] | None = None
        error_message: str | None = None

        try:
            # 1. Schema validation
            if validate_schema:
                self._validate_schema(resource, context)

            # 2. IDOR protection
            if self._idor_protector:
                violations = self._idor_protector.validate_arguments(user.user_id, context)
                if violations:
                    param, res_type, obj_id = violations[0]
                    raise IDORViolationError(
                        user_id=user.user_id,
                        resource_type=res_type,
                        object_id=obj_id,
                    )

            # 3. Authorization check
            auth_result = self.authorize_or_raise(user, action, resource, context)

            # 4. Rate limiting
            if apply_rate_limit and self._rate_limiter:
                self._apply_rate_limit(user, resource)

            # 5. Circuit breaker
            if check_circuit_breaker and self._circuit_breakers:
                breaker = self._circuit_breakers.get(resource)
                if not breaker.is_available():
                    stats = breaker.stats
                    raise CircuitOpenError(
                        circuit_name=resource,
                        failure_count=stats.consecutive_failures,
                        reset_timeout=breaker.reset_timeout,
                        last_failure=stats.last_failure_error,
                    )

            # 6. Execute function
            result = func(*args, **kwargs)

            # Record success for circuit breaker
            if self._circuit_breakers:
                breaker = self._circuit_breakers.get(resource)
                breaker._record_success()

            execution_result = {"success": True, "result_type": type(result).__name__}
            return result

        except (AuthorizationError, PolicyViolation, SchemaValidationError,
                RateLimitExceeded, CircuitOpenError, IDORViolationError):
            raise

        except Exception as e:
            if self._circuit_breakers:
                breaker = self._circuit_breakers.get(resource)
                breaker._record_failure(e)

            error_message = str(e)
            raise

        finally:
            if log_audit:
                self._log_audit_event(
                    user=user,
                    agent=agent,
                    tool_request=tool_request,
                    auth_result=auth_result,
                    execution_result=execution_result,
                    error_message=error_message,
                )

    def _validate_schema(self, tool_name: str, arguments: dict[str, Any]) -> None:
        """Validate arguments against registered schema."""
        result = self._schema_validator.validate(tool_name, arguments)
        if not result.valid:
            raise SchemaValidationError(
                tool_name=tool_name,
                errors=result.errors,
            )

    def _apply_rate_limit(self, user: UserContext, tool_name: str) -> None:
        """Apply rate limiting for the user and tool."""
        if self._rate_limiter:
            self._rate_limiter.check_rate_limit(user.user_id, tool_name)

    def _log_audit_event(
        self,
        user: UserContext,
        agent: AgentContext | None,
        tool_request: ToolCallRequest,
        auth_result: AuthorizationResult | None,
        execution_result: dict[str, Any] | None,
        error_message: str | None,
    ) -> None:
        """Log an audit event."""
        # Note: event_type is determined internally by log_authorization based on allowed flag

        # Filter out non-serializable arguments
        filtered_args = {}
        for key, value in tool_request.arguments.items():
            if key.startswith("_"):
                continue
            if isinstance(value, (str, int, float, bool, list, dict, type(None))):
                filtered_args[key] = value
            else:
                filtered_args[key] = f"<{type(value).__name__}>"

        self._audit_logger.log_authorization(
            user_id=user.user_id,
            user_roles=list(user.roles),
            tool_name=tool_request.tool_name,
            tool_arguments=filtered_args,
            allowed=auth_result.allowed if auth_result else False,
            reason=auth_result.reason if auth_result else None,
            policies_evaluated=auth_result.policies_evaluated if auth_result else [],
            session_id=user.session_id,
            user_attributes=dict(user.attributes),
            agent_id=agent.agent_id if agent else None,
            agent_capabilities=list(agent.capabilities) if agent else [],
            agent_trust_score=agent.trust_score if agent else None,
            execution_result=execution_result,
        )

    # ==================== Context Managers ====================

    @contextmanager
    def user_context(self, user: UserContext):
        """
        Context manager to set the current user for authorization.

        All authorization checks within this context will use
        the provided user unless overridden.

        Args:
            user: The user context to set.

        Yields:
            The user context.

        Example:
            >>> with auth.user_context(user) as ctx:
            ...     result = await tool_function(args)
        """
        token = _current_user.set(user)
        try:
            yield user
        finally:
            _current_user.reset(token)

    @contextmanager
    def agent_context(self, agent: AgentContext):
        """
        Context manager to set the current agent.

        Args:
            agent: The agent context to set.

        Yields:
            The agent context.
        """
        token = _current_agent.set(agent)
        try:
            yield agent
        finally:
            _current_agent.reset(token)

    @contextmanager
    def session(self, user: UserContext, agent: AgentContext | None = None):
        """
        Context manager to set both user and agent context.

        Args:
            user: The user context.
            agent: Optional agent context.

        Yields:
            Tuple of (user, agent).

        Example:
            >>> with auth.session(user, agent) as (u, a):
            ...     result = await tool_function(args)
        """
        user_token = _current_user.set(user)
        agent_token = _current_agent.set(agent) if agent else None
        try:
            yield (user, agent)
        finally:
            _current_user.reset(user_token)
            if agent_token:
                _current_agent.reset(agent_token)

    # ==================== Resilience Methods ====================

    def get_retry_policy(self) -> RetryPolicy:
        """Get the current retry policy."""
        return self._retry_policy

    def set_retry_policy(self, policy: RetryPolicy) -> None:
        """
        Set the retry policy.

        Args:
            policy: The retry policy to use.
        """
        self._retry_policy = policy

    def get_graceful_degradation(self) -> GracefulDegradation | None:
        """Get the graceful degradation instance."""
        return self._graceful_degradation

    def set_graceful_degradation(
        self, degradation: GracefulDegradation | None
    ) -> None:
        """
        Set the graceful degradation instance.

        Args:
            degradation: The degradation instance, or None to disable.
        """
        self._graceful_degradation = degradation

    def get_current_tier(self) -> DegradationTier:
        """
        Get the current degradation tier.

        Returns:
            Current tier, or FULL if degradation is disabled.
        """
        if self._graceful_degradation:
            return self._graceful_degradation.get_current_tier()
        return DegradationTier.FULL

    def is_tool_available_at_tier(self, tool_name: str) -> bool:
        """
        Check if a tool is available at the current degradation tier.

        Args:
            tool_name: Name of the tool to check.

        Returns:
            True if available (or degradation is disabled).
        """
        if self._graceful_degradation:
            return self._graceful_degradation.is_tool_available(tool_name)
        return True

    def is_model_available_at_tier(self, model_name: str) -> bool:
        """
        Check if a model is available at the current degradation tier.

        Args:
            model_name: Name of the model to check.

        Returns:
            True if available (or degradation is disabled).
        """
        if self._graceful_degradation:
            return self._graceful_degradation.is_model_available(model_name)
        return True

    def record_operation_failure(self, component: str) -> None:
        """
        Record an operation failure for degradation tracking.

        May trigger automatic tier degradation if threshold is reached.

        Args:
            component: Name of the component that failed.
        """
        if self._graceful_degradation:
            self._graceful_degradation.record_failure(component)

    def record_operation_success(self, component: str) -> None:
        """
        Record an operation success for degradation tracking.

        May trigger automatic tier recovery if threshold is reached.

        Args:
            component: Name of the component that succeeded.
        """
        if self._graceful_degradation:
            self._graceful_degradation.record_success(component)

    def create_retry_decorator(
        self,
        policy: RetryPolicy | None = None,
        on_retry: Any | None = None,
    ) -> Any:
        """
        Create a retry decorator with the configured or specified policy.

        Args:
            policy: Override retry policy (uses default if None).
            on_retry: Optional callback for retry events.

        Returns:
            Decorator function.

        Example:
            >>> @auth.create_retry_decorator()
            ... async def call_llm():
            ...     return await client.chat.completions.create(...)
        """
        effective_policy = policy or self._retry_policy
        return retry_with_backoff(policy=effective_policy, on_retry=on_retry)

    def create_fallback_chain(
        self,
        options: list[FallbackOption] | None = None,
    ) -> FallbackChain[Any]:
        """
        Create a fallback chain.

        Args:
            options: Initial fallback options.

        Returns:
            FallbackChain instance.

        Example:
            >>> chain = auth.create_fallback_chain()
            >>> chain.add_option(FallbackOption("primary", primary_handler))
            >>> chain.add_option(FallbackOption("backup", backup_handler))
            >>> result = await chain.execute_async()
        """
        return FallbackChain(options=options)

    def create_model_fallback(self) -> ModelFallback:
        """
        Create a model fallback chain.

        Returns:
            ModelFallback instance.

        Example:
            >>> fallback = auth.create_model_fallback()
            >>> fallback.add_model("claude-opus", call_claude)
            >>> fallback.add_model("gpt-4o", call_gpt)
            >>> result = await fallback.complete(prompt="Hello")
        """
        return ModelFallback()

    def create_tool_fallback(self) -> ToolFallback:
        """
        Create a tool fallback chain.

        Returns:
            ToolFallback instance.

        Example:
            >>> fallback = auth.create_tool_fallback()
            >>> fallback.add_tool("google_search", google_search)
            >>> fallback.add_tool("bing_search", bing_search)
            >>> result = await fallback.invoke(query="test")
        """
        return ToolFallback()

    async def execute_with_retry(
        self,
        func: Any,
        *args: Any,
        policy: RetryPolicy | None = None,
        **kwargs: Any,
    ) -> Any:
        """
        Execute a function with retry logic.

        Args:
            func: Async function to execute.
            *args: Positional arguments for the function.
            policy: Override retry policy.
            **kwargs: Keyword arguments for the function.

        Returns:
            Function result on success.

        Raises:
            Exception: The last exception if all retries fail.

        Example:
            >>> result = await auth.execute_with_retry(
            ...     call_llm_api,
            ...     prompt="Hello",
            ... )
        """
        effective_policy = policy or self._retry_policy
        return await retry_async(func, *args, policy=effective_policy, **kwargs)

    # ==================== Streaming Methods ====================

    def create_tool_call_detector(
        self,
        provider: str = "auto",
    ) -> StreamingToolCallDetector:
        """
        Create a streaming tool call detector.

        Args:
            provider: LLM provider ("openai", "anthropic", "google", or "auto").

        Returns:
            StreamingToolCallDetector instance.

        Example:
            >>> detector = auth.create_tool_call_detector()
            >>> async for chunk in llm_stream:
            ...     events = detector.process_chunk(chunk)
            ...     for event in events:
            ...         if event.type == StreamEventType.TOOL_CALL_END:
            ...             tool_call = event.tool_call
            ...             auth.authorize_tool_call(user, tool_call)
        """
        return StreamingToolCallDetector(provider=provider)

    def create_stream_transformer(self) -> StreamTransformer:
        """
        Create a stream transformer with optional output guard integration.

        Returns:
            StreamTransformer instance.

        Example:
            >>> transformer = auth.create_stream_transformer()
            >>> transformer.add_filter(my_filter)
            >>> async for chunk in transformer.transform(stream):
            ...     yield chunk
        """
        transformer = StreamTransformer()

        # If output guard is configured, add it as a filter
        if self._output_guard:
            def guard_filter(content: str) -> str | None:
                result = self._output_guard.check(content)
                if result.action == GuardAction.BLOCK:
                    return None
                elif result.action == GuardAction.SANITIZE:
                    return self._output_guard.redact(content)
                return content

            transformer.add_filter(guard_filter)

        return transformer

    def create_guarded_stream(
        self,
        stream: Any,  # AsyncIterator[str]
    ) -> Any:  # AsyncIterator[str]
        """
        Create a stream filtered by the configured output guard.

        Args:
            stream: Source async iterator of strings.

        Returns:
            Filtered async iterator.

        Example:
            >>> async for chunk in auth.create_guarded_stream(llm_stream):
            ...     ws.send(chunk)  # Filtered content
        """
        if self._output_guard:
            return create_guarded_stream(stream, self._output_guard)
        return stream

    def create_authorized_stream(
        self,
        stream: Any,  # AsyncIterator[Any]
        user: UserContext,
        detector: StreamingToolCallDetector | None = None,
    ) -> Any:  # AsyncIterator[StreamEvent]
        """
        Create a stream that authorizes tool calls.

        Tool calls detected in the stream are authorized before
        the TOOL_CALL_END event is emitted.

        Args:
            stream: Raw LLM streaming chunks.
            user: User context for authorization.
            detector: Optional detector instance.

        Returns:
            Async iterator of StreamEvents with authorized tool calls.

        Example:
            >>> async for event in auth.create_authorized_stream(llm_stream, user):
            ...     if event.type == StreamEventType.TOOL_CALL_END:
            ...         # Tool call is authorized
            ...         result = execute_tool(event.tool_call)
            ...     elif event.type == StreamEventType.ERROR:
            ...         # Tool call was not authorized
            ...         handle_unauthorized(event.error)
        """

        def authorizer(tool_call: DetectedToolCall) -> bool:
            return self.can(user, "execute", tool_call.name)

        return create_authorization_stream(stream, authorizer, detector)

    async def process_stream_with_authorization(
        self,
        stream: Any,  # AsyncIterator[Any]
        user: UserContext,
        provider: str = "auto",
        on_text: Any | None = None,  # Callable[[str], None] | Callable[[str], Awaitable[None]]
        # Callable[[DetectedToolCall], None] | Callable[[DetectedToolCall], Awaitable[None]]
        on_tool_call: Any | None = None,
        # Callable[[DetectedToolCall, str], None] |
        # Callable[[DetectedToolCall, str], Awaitable[None]]
        on_unauthorized: Any | None = None,
    ) -> dict[str, Any]:
        """
        Process a stream with authorization and callbacks.

        A high-level method that handles stream processing with
        callbacks for text, authorized tool calls, and unauthorized attempts.

        Args:
            stream: Raw LLM streaming chunks.
            user: User context for authorization.
            provider: LLM provider for detection.
            on_text: Callback for text chunks.
            on_tool_call: Callback for authorized tool calls.
            on_unauthorized: Callback for unauthorized tool calls.

        Returns:
            Dictionary with processing results including:
            - text: Full accumulated text
            - tool_calls: List of authorized tool calls
            - unauthorized_calls: List of unauthorized tool calls
            - stats: Processing statistics

        Example:
            >>> async def handle_text(text):
            ...     await ws.send(text)
            >>>
            >>> async def handle_tool_call(tool_call):
            ...     result = await execute_tool(tool_call)
            ...     await ws.send(f"Tool result: {result}")
            >>>
            >>> result = await auth.process_stream_with_authorization(
            ...     stream, user,
            ...     on_text=handle_text,
            ...     on_tool_call=handle_tool_call,
            ... )
        """
        import inspect

        detector = self.create_tool_call_detector(provider)
        text_buffer = []
        authorized_calls: list[DetectedToolCall] = []
        unauthorized_calls: list[tuple[DetectedToolCall, str]] = []

        async def _call_handler(handler: Any, *args: Any) -> None:
            if handler is None:
                return
            result = handler(*args)
            if inspect.iscoroutine(result):
                await result

        async for chunk in stream:
            events = detector.process_chunk(chunk)

            for event in events:
                if event.type == StreamEventType.TEXT and event.content:
                    # Apply output guard if configured
                    content = event.content
                    if self._output_guard:
                        guard_result = self._output_guard.check(content)
                        if guard_result.action == GuardAction.BLOCK:
                            continue
                        elif guard_result.action == GuardAction.SANITIZE:
                            content = self._output_guard.redact(content)

                    text_buffer.append(content)
                    await _call_handler(on_text, content)

                elif event.type == StreamEventType.TOOL_CALL_END and event.tool_call:
                    tool_call = event.tool_call
                    # Check authorization
                    if self.can(user, "execute", tool_call.name):
                        authorized_calls.append(tool_call)
                        await _call_handler(on_tool_call, tool_call)
                    else:
                        reason = f"User {user.user_id} not authorized to execute {tool_call.name}"
                        unauthorized_calls.append((tool_call, reason))
                        await _call_handler(on_unauthorized, tool_call, reason)

        return {
            "text": "".join(text_buffer),
            "tool_calls": authorized_calls,
            "unauthorized_calls": unauthorized_calls,
            "stats": detector.get_stats(),
        }

    def authorize_detected_tool_call(
        self,
        user: UserContext,
        tool_call: DetectedToolCall,
        context: dict[str, Any] | None = None,
    ) -> AuthorizationResult:
        """
        Authorize a detected tool call.

        Args:
            user: The user context.
            tool_call: The detected tool call from streaming.
            context: Additional context for the policy.

        Returns:
            AuthorizationResult.

        Raises:
            AuthorizationError: If not authorized.

        Example:
            >>> for event in events:
            ...     if event.type == StreamEventType.TOOL_CALL_END:
            ...         result = auth.authorize_detected_tool_call(user, event.tool_call)
            ...         if result.allowed:
            ...             execute_tool(event.tool_call)
        """
        # Merge tool call arguments into context
        merged_context = dict(context or {})
        merged_context["tool_call_id"] = tool_call.id
        merged_context["tool_call_arguments"] = tool_call.arguments

        return self.check(user, "execute", tool_call.name, merged_context)

    # ==================== Tool Registry Methods ====================

    def get_tool_registry(self) -> ToolRegistry:
        """
        Get the tool registry.

        Returns:
            The ToolRegistry instance.
        """
        return self._tool_registry

    def set_tool_registry(self, registry: ToolRegistry | None) -> None:
        """
        Set or replace the tool registry.

        Args:
            registry: The registry to use. If None, creates a new default registry.
        """
        if registry is None:
            self._tool_registry = ToolRegistry()
        else:
            self._tool_registry = registry

    def register_tool(
        self,
        tool_def: ToolDefinition,
    ) -> None:
        """
        Register a tool with the registry.

        Args:
            tool_def: The tool definition to register.

        Example:
            >>> auth.register_tool(ToolDefinition(
            ...     name="search_web",
            ...     description="Search the web",
            ...     parameters={"type": "object", "properties": {...}},
            ...     category=ToolCategory.SEARCH,
            ... ))
        """
        self._tool_registry.register(tool_def)

    def unregister_tool(self, name: str) -> bool:
        """
        Unregister a tool by name.

        Args:
            name: The tool name to unregister.

        Returns:
            True if the tool was found and unregistered.
        """
        return self._tool_registry.unregister(name)

    def get_tool(self, name: str) -> ToolDefinition | None:
        """
        Get a tool definition by name.

        Args:
            name: The tool name.

        Returns:
            The ToolDefinition or None if not found.
        """
        return self._tool_registry.get(name)

    def list_tools(
        self,
        category: ToolCategory | None = None,
        max_risk_level: RiskLevel | None = None,
        enabled_only: bool = True,
    ) -> list[ToolDefinition]:
        """
        List registered tools with optional filtering.

        Args:
            category: Filter by category.
            max_risk_level: Filter by maximum risk level.
            enabled_only: Only include enabled tools.

        Returns:
            List of matching tool definitions.

        Example:
            >>> tools = auth.list_tools(category=ToolCategory.SEARCH)
            >>> for tool in tools:
            ...     print(f"{tool.name}: {tool.description}")
        """
        tools = self._tool_registry.list_all()

        if category is not None:
            tools = [t for t in tools if t.category == category]

        if max_risk_level is not None:
            tools = [t for t in tools if t.risk_level.value <= max_risk_level.value]

        if enabled_only:
            tools = [t for t in tools if t.enabled]

        return tools

    def export_tools(
        self,
        format: str = "openai",
        category: ToolCategory | None = None,
        max_risk_level: RiskLevel | None = None,
    ) -> list[dict[str, Any]]:
        """
        Export tools to LLM provider format.

        Args:
            format: Target format ("openai", "anthropic", or "gemini").
            category: Filter by category.
            max_risk_level: Filter by maximum risk level.

        Returns:
            List of tools in the specified format.

        Example:
            >>> tools = auth.export_tools(format="openai")
            >>> response = client.chat.completions.create(
            ...     model="gpt-4o",
            ...     messages=[...],
            ...     tools=tools,
            ... )
        """
        # Get filtered tools
        if category is not None:
            tools = self._tool_registry.list_by_category(category)
        elif max_risk_level is not None:
            tools = self._tool_registry.list_by_risk_level(max_risk_level)
        else:
            tools = self._tool_registry.list_enabled()

        # Export each tool manually
        if format == "openai":
            return [t.to_openai_format() for t in tools]
        elif format == "anthropic":
            return [t.to_anthropic_format() for t in tools]
        elif format == "gemini":
            return [t.to_gemini_format() for t in tools]
        else:
            return [t.to_dict() for t in tools]

    def execute_tool(
        self,
        name: str,
        user: UserContext,
        authorize: bool = True,
        **kwargs: Any,
    ) -> ToolExecutionResult:
        """
        Execute a registered tool synchronously.

        Args:
            name: The tool name.
            user: The user context for authorization.
            authorize: Whether to check authorization.
            **kwargs: Arguments to pass to the tool.

        Returns:
            ToolExecutionResult with execution details.

        Raises:
            AuthorizationError: If not authorized and authorize=True.

        Example:
            >>> result = auth.execute_tool(
            ...     "search_web",
            ...     user,
            ...     query="python async",
            ... )
            >>> if result.success:
            ...     print(result.result)
        """
        if authorize:
            tool_def = self._tool_registry.get(name)
            if tool_def:
                # Check authorization
                auth_result = self.check(user, "execute", name, kwargs)
                if not auth_result.allowed:
                    raise AuthorizationError(
                        user=user.user_id,
                        action="execute",
                        resource=name,
                        reason=auth_result.reason,
                    )

                # Check risk level requires approval
                if tool_def.requires_approval:
                    # In a real implementation, this would trigger an approval workflow
                    logger.warning(
                        f"Tool {name} requires approval but automatic approval is not implemented"
                    )

        return self._tool_registry.execute(name, **kwargs)

    async def execute_tool_async(
        self,
        name: str,
        user: UserContext,
        authorize: bool = True,
        **kwargs: Any,
    ) -> ToolExecutionResult:
        """
        Execute a registered tool asynchronously.

        Args:
            name: The tool name.
            user: The user context for authorization.
            authorize: Whether to check authorization.
            **kwargs: Arguments to pass to the tool.

        Returns:
            ToolExecutionResult with execution details.

        Raises:
            AuthorizationError: If not authorized and authorize=True.

        Example:
            >>> result = await auth.execute_tool_async(
            ...     "search_web",
            ...     user,
            ...     query="python async",
            ... )
            >>> if result.success:
            ...     print(result.result)
        """
        if authorize:
            tool_def = self._tool_registry.get(name)
            if tool_def:
                # Check authorization
                auth_result = self.check(user, "execute", name, kwargs)
                if not auth_result.allowed:
                    raise AuthorizationError(
                        user=user.user_id,
                        action="execute",
                        resource=name,
                        reason=auth_result.reason,
                    )

                if tool_def.requires_approval:
                    logger.warning(
                        f"Tool {name} requires approval but automatic approval is not implemented"
                    )

        return await self._tool_registry.execute_async(name, **kwargs)

    def tool(
        self,
        name: str | None = None,
        description: str | None = None,
        category: ToolCategory = ToolCategory.CUSTOM,
        risk_level: RiskLevel = RiskLevel.LOW,
        requires_approval: bool = False,
        timeout: float | None = None,
        enabled: bool = True,
        **metadata: Any,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """
        Decorator to register a function as a tool.

        Registers the function with this Proxilion instance's tool registry.

        Args:
            name: Tool name (defaults to function name).
            description: Tool description (defaults to docstring).
            category: Tool category for organization.
            risk_level: Risk level for authorization decisions.
            requires_approval: Whether tool requires explicit approval.
            timeout: Execution timeout in seconds.
            enabled: Whether tool is enabled by default.
            **metadata: Additional metadata.

        Returns:
            Decorator function.

        Example:
            >>> @auth.tool(
            ...     name="search_web",
            ...     category=ToolCategory.SEARCH,
            ... )
            ... def search_web(query: str, max_results: int = 10) -> list[dict]:
            ...     return perform_search(query, max_results)
        """
        return tool(
            name=name,
            description=description,
            category=category,
            risk_level=risk_level,
            requires_approval=requires_approval,
            timeout=timeout,
            registry=self._tool_registry,
            enabled=enabled,
            **metadata,
        )

    def enable_tool(self, name: str) -> bool:
        """
        Enable a registered tool.

        Args:
            name: The tool name.

        Returns:
            True if tool was found and enabled.
        """
        return self._tool_registry.enable(name)

    def disable_tool(self, name: str) -> bool:
        """
        Disable a registered tool.

        Args:
            name: The tool name.

        Returns:
            True if tool was found and disabled.
        """
        return self._tool_registry.disable(name)

    def get_tool_stats(self) -> dict[str, Any]:
        """
        Get statistics about registered tools.

        Returns:
            Dictionary with tool statistics.

        Example:
            >>> stats = auth.get_tool_stats()
            >>> print(f"Total tools: {stats['total']}")
            >>> print(f"Enabled: {stats['enabled']}")
        """
        tools = self._tool_registry.list_all()

        # Count by category
        by_category: dict[str, int] = {}
        for tool_def in tools:
            cat_name = tool_def.category.name
            by_category[cat_name] = by_category.get(cat_name, 0) + 1

        # Count by risk level
        by_risk: dict[str, int] = {}
        for tool_def in tools:
            risk_name = tool_def.risk_level.name
            by_risk[risk_name] = by_risk.get(risk_name, 0) + 1

        return {
            "total": len(tools),
            "enabled": sum(1 for t in tools if t.enabled),
            "disabled": sum(1 for t in tools if not t.enabled),
            "requires_approval": sum(1 for t in tools if t.requires_approval),
            "by_category": by_category,
            "by_risk_level": by_risk,
        }

    # ==================== Provider Adapter Methods ====================

    def get_provider_adapter(
        self,
        provider: str | Provider | None = None,
        response: Any = None,
    ) -> ProviderAdapter:
        """
        Get a provider adapter.

        Can auto-detect from response or use explicit provider name.

        Args:
            provider: Provider name or enum.
            response: Optional response for auto-detection.

        Returns:
            Appropriate ProviderAdapter instance.

        Example:
            >>> adapter = auth.get_provider_adapter("openai")
            >>> tools = adapter.format_tools(auth.list_tools())
        """
        return get_adapter(provider=provider, response=response)

    def extract_tool_calls_from_response(
        self,
        response: Any,
        provider: str | Provider | None = None,
    ) -> list[UnifiedToolCall]:
        """
        Extract tool calls from an LLM response.

        Args:
            response: LLM response object.
            provider: Optional provider hint (auto-detected if None).

        Returns:
            List of unified tool calls.

        Example:
            >>> tool_calls = auth.extract_tool_calls_from_response(llm_response)
            >>> for call in tool_calls:
            ...     result = auth.authorize_and_execute(user, call)
        """
        adapter = get_adapter(provider=provider, response=response)
        return adapter.extract_tool_calls(response)

    def extract_unified_response(
        self,
        response: Any,
        provider: str | Provider | None = None,
    ) -> UnifiedResponse:
        """
        Extract a unified response from an LLM response.

        Args:
            response: LLM response object.
            provider: Optional provider hint (auto-detected if None).

        Returns:
            UnifiedResponse instance.

        Example:
            >>> unified = auth.extract_unified_response(llm_response)
            >>> print(f"Content: {unified.content}")
            >>> print(f"Tool calls: {len(unified.tool_calls)}")
        """
        adapter = get_adapter(provider=provider, response=response)
        return adapter.extract_response(response)

    def authorize_tool_calls(
        self,
        user: UserContext,
        tool_calls: list[UnifiedToolCall],
        context: dict[str, Any] | None = None,
    ) -> list[tuple[UnifiedToolCall, AuthorizationResult]]:
        """
        Authorize a list of tool calls.

        Args:
            user: The user context.
            tool_calls: List of tool calls to authorize.
            context: Additional context for policies.

        Returns:
            List of (tool_call, authorization_result) tuples.

        Example:
            >>> tool_calls = auth.extract_tool_calls_from_response(response)
            >>> results = auth.authorize_tool_calls(user, tool_calls)
            >>> for call, result in results:
            ...     if result.allowed:
            ...         execute_tool(call)
        """
        results = []
        for call in tool_calls:
            merged_context = dict(context or {})
            merged_context["tool_call_id"] = call.id
            merged_context.update(call.arguments)

            auth_result = self.check(user, "execute", call.name, merged_context)
            results.append((call, auth_result))

        return results

    def authorize_and_execute_tool_calls(
        self,
        user: UserContext,
        tool_calls: list[UnifiedToolCall],
        context: dict[str, Any] | None = None,
    ) -> list[tuple[UnifiedToolCall, ToolExecutionResult | AuthorizationResult]]:
        """
        Authorize and execute a list of tool calls.

        For each tool call:
        1. Check authorization
        2. If authorized and tool is registered, execute it
        3. Return results

        Args:
            user: The user context.
            tool_calls: List of tool calls to process.
            context: Additional context for policies.

        Returns:
            List of (tool_call, result) tuples where result is either
            ToolExecutionResult (if executed) or AuthorizationResult (if denied).

        Example:
            >>> tool_calls = auth.extract_tool_calls_from_response(response)
            >>> results = auth.authorize_and_execute_tool_calls(user, tool_calls)
            >>> for call, result in results:
            ...     if isinstance(result, ToolExecutionResult):
            ...         print(f"{call.name}: {result.result}")
            ...     else:
            ...         print(f"{call.name}: DENIED - {result.reason}")
        """
        results = []
        for call in tool_calls:
            merged_context = dict(context or {})
            merged_context["tool_call_id"] = call.id
            merged_context.update(call.arguments)

            # Check authorization
            auth_result = self.check(user, "execute", call.name, merged_context)
            if not auth_result.allowed:
                results.append((call, auth_result))
                continue

            # Try to execute if tool is registered
            tool_def = self._tool_registry.get(call.name)
            if tool_def:
                exec_result = self._tool_registry.execute(call.name, **call.arguments)
                results.append((call, exec_result))
            else:
                # Tool not registered, return auth result indicating it's allowed
                # but caller must handle execution
                results.append((call, auth_result))

        return results

    def format_tool_results(
        self,
        results: list[tuple[UnifiedToolCall, Any, bool]],
        provider: str | Provider,
    ) -> list[Any]:
        """
        Format tool results for a specific provider.

        Args:
            results: List of (tool_call, result, is_error) tuples.
            provider: Target provider.

        Returns:
            List of provider-formatted tool result messages.

        Example:
            >>> results = [
            ...     (call1, {"temp": 72}, False),
            ...     (call2, "Error message", True),
            ... ]
            >>> formatted = auth.format_tool_results(results, "openai")
            >>> messages.extend(formatted)
        """
        adapter = get_adapter(provider=provider)
        return [
            adapter.format_tool_result(call, result, is_error)
            for call, result, is_error in results
        ]

    def export_tools_for_provider(
        self,
        provider: str | Provider,
        category: ToolCategory | None = None,
        max_risk_level: RiskLevel | None = None,
    ) -> list[dict[str, Any]]:
        """
        Export tools formatted for a specific provider.

        Args:
            provider: Target provider.
            category: Optional category filter.
            max_risk_level: Optional risk level filter.

        Returns:
            List of tools in provider-specific format.

        Example:
            >>> openai_tools = auth.export_tools_for_provider("openai")
            >>> response = client.chat.completions.create(
            ...     model="gpt-4o",
            ...     messages=[...],
            ...     tools=openai_tools,
            ... )
        """
        # Get filtered tools
        if category is not None:
            tools = self._tool_registry.list_by_category(category)
        elif max_risk_level is not None:
            tools = self._tool_registry.list_by_risk_level(max_risk_level)
        else:
            tools = self._tool_registry.list_enabled()

        adapter = get_adapter(provider=provider)
        return adapter.format_tools(tools)

    async def process_response_with_authorization(
        self,
        response: Any,
        user: UserContext,
        provider: str | Provider | None = None,
        execute_tools: bool = True,
    ) -> dict[str, Any]:
        """
        Process an LLM response with authorization and optional execution.

        High-level method that:
        1. Extracts tool calls from response
        2. Authorizes each tool call
        3. Optionally executes authorized tools
        4. Returns comprehensive results

        Args:
            response: LLM response object.
            user: User context for authorization.
            provider: Optional provider hint.
            execute_tools: Whether to execute authorized tools.

        Returns:
            Dictionary with:
            - unified_response: The unified response
            - authorized_calls: List of authorized tool calls
            - denied_calls: List of (call, reason) for denied calls
            - execution_results: List of (call, result) if execute_tools=True

        Example:
            >>> result = await auth.process_response_with_authorization(
            ...     llm_response,
            ...     user,
            ... )
            >>> for call in result["authorized_calls"]:
            ...     print(f"Authorized: {call.name}")
            >>> for call, reason in result["denied_calls"]:
            ...     print(f"Denied: {call.name} - {reason}")
        """
        # Extract response
        adapter = get_adapter(provider=provider, response=response)
        unified_response = adapter.extract_response(response)

        authorized_calls = []
        denied_calls = []
        execution_results = []

        # Process each tool call
        for call in unified_response.tool_calls:
            # Check authorization
            auth_result = self.check(
                user, "execute", call.name,
                {"tool_call_id": call.id, **call.arguments}
            )

            if not auth_result.allowed:
                denied_calls.append((call, auth_result.reason))
                continue

            authorized_calls.append(call)

            # Execute if requested and tool is registered
            if execute_tools:
                tool_def = self._tool_registry.get(call.name)
                if tool_def:
                    exec_result = await self._tool_registry.execute_async(
                        call.name, **call.arguments
                    )
                    execution_results.append((call, exec_result))

        return {
            "unified_response": unified_response,
            "authorized_calls": authorized_calls,
            "denied_calls": denied_calls,
            "execution_results": execution_results,
        }

    # ==================== Utility Methods ====================

    def get_audit_events(self) -> list[AuditEventV2]:
        """
        Get all audit events (for in-memory logger).

        Returns:
            List of audit events.
        """
        if isinstance(self._audit_logger, InMemoryAuditLogger):
            return self._audit_logger.events
        return []

    def verify_audit_chain(self) -> Any:
        """
        Verify the integrity of the audit log.

        Returns:
            ChainVerificationResult.
        """
        return self._audit_logger.verify()

    def close(self) -> None:
        """Close the Proxilion instance and flush audit logs."""
        if hasattr(self._audit_logger, "close"):
            self._audit_logger.close()

    def __enter__(self) -> Proxilion:
        """Context manager entry."""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit."""
        self.close()
