"""
Decorators for Proxilion authorization.

This module provides standalone decorators that can be used
independently of the main Proxilion class for more flexibility.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import logging
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any, ParamSpec, TypeVar

from proxilion.exceptions import AuthorizationError, SequenceViolationError
from proxilion.types import UserContext

logger = logging.getLogger(__name__)

P = ParamSpec("P")
T = TypeVar("T")


class ApprovalStrategy(ABC):
    """
    Abstract base class for approval strategies.

    Approval strategies determine how high-risk operations
    are approved before execution.
    """

    @abstractmethod
    def request_approval(
        self,
        user: UserContext,
        action: str,
        resource: str,
        context: dict[str, Any],
    ) -> bool:
        """
        Request approval for an action.

        Args:
            user: The user requesting the action.
            action: The action to perform.
            resource: The resource being acted upon.
            context: Additional context.

        Returns:
            True if approved, False otherwise.
        """
        pass

    @abstractmethod
    async def request_approval_async(
        self,
        user: UserContext,
        action: str,
        resource: str,
        context: dict[str, Any],
    ) -> bool:
        """Async version of request_approval."""
        pass


class AlwaysApproveStrategy(ApprovalStrategy):
    """
    Strategy that always approves requests.

    WARNING: Only use for testing or development.
    """

    def request_approval(
        self,
        user: UserContext,
        action: str,
        resource: str,
        context: dict[str, Any],
    ) -> bool:
        logger.warning(
            f"AlwaysApproveStrategy: Auto-approving {action} on {resource} for {user.user_id}"
        )
        return True

    async def request_approval_async(
        self,
        user: UserContext,
        action: str,
        resource: str,
        context: dict[str, Any],
    ) -> bool:
        return self.request_approval(user, action, resource, context)


class AlwaysDenyStrategy(ApprovalStrategy):
    """Strategy that always denies requests."""

    def request_approval(
        self,
        user: UserContext,
        action: str,
        resource: str,
        context: dict[str, Any],
    ) -> bool:
        logger.info(
            f"AlwaysDenyStrategy: Denying {action} on {resource} for {user.user_id}"
        )
        return False

    async def request_approval_async(
        self,
        user: UserContext,
        action: str,
        resource: str,
        context: dict[str, Any],
    ) -> bool:
        return self.request_approval(user, action, resource, context)


class CallbackApprovalStrategy(ApprovalStrategy):
    """
    Strategy that uses a callback function for approval.

    Example:
        >>> def my_approval_callback(user, action, resource, context):
        ...     # Custom approval logic
        ...     return user.has_role("approver")
        >>>
        >>> strategy = CallbackApprovalStrategy(my_approval_callback)
    """

    def __init__(
        self,
        callback: Callable[[UserContext, str, str, dict[str, Any]], bool],
        async_callback: Callable[[UserContext, str, str, dict[str, Any]], Any] | None = None,
    ) -> None:
        """
        Initialize with callback functions.

        Args:
            callback: Sync callback for approval.
            async_callback: Optional async callback.
        """
        self._callback = callback
        self._async_callback = async_callback

    def request_approval(
        self,
        user: UserContext,
        action: str,
        resource: str,
        context: dict[str, Any],
    ) -> bool:
        return self._callback(user, action, resource, context)

    async def request_approval_async(
        self,
        user: UserContext,
        action: str,
        resource: str,
        context: dict[str, Any],
    ) -> bool:
        if self._async_callback:
            return await self._async_callback(user, action, resource, context)
        return self._callback(user, action, resource, context)


class QueueApprovalStrategy(ApprovalStrategy):
    """
    Strategy that queues requests for later approval.

    Useful for asynchronous approval workflows where
    a human reviews pending requests.

    Example:
        >>> strategy = QueueApprovalStrategy()
        >>>
        >>> # Request gets queued
        >>> @require_approval(strategy=strategy)
        ... async def delete_database(db_name, user=None):
        ...     pass
        >>>
        >>> # Admin reviews queue
        >>> for request in strategy.pending_requests:
        ...     if should_approve(request):
        ...         strategy.approve(request["id"])
    """

    def __init__(self, timeout: float = 300.0) -> None:
        """
        Initialize the queue strategy.

        Args:
            timeout: Seconds to wait for approval (default 5 minutes).
        """
        self.timeout = timeout
        self._pending: dict[str, dict[str, Any]] = {}
        self._approved: set[str] = set()
        self._denied: set[str] = set()
        self._request_counter = 0

    @property
    def pending_requests(self) -> list[dict[str, Any]]:
        """Get list of pending approval requests."""
        return list(self._pending.values())

    def approve(self, request_id: str) -> None:
        """Approve a pending request."""
        if request_id in self._pending:
            self._approved.add(request_id)
            del self._pending[request_id]

    def deny(self, request_id: str) -> None:
        """Deny a pending request."""
        if request_id in self._pending:
            self._denied.add(request_id)
            del self._pending[request_id]

    def request_approval(
        self,
        user: UserContext,
        action: str,
        resource: str,
        context: dict[str, Any],
    ) -> bool:
        """Queue request and wait for approval (blocking)."""
        import time

        self._request_counter += 1
        request_id = f"req_{self._request_counter}"

        self._pending[request_id] = {
            "id": request_id,
            "user_id": user.user_id,
            "action": action,
            "resource": resource,
            "context": context,
        }

        logger.info(f"Approval request queued: {request_id}")

        # Poll for approval
        start_time = time.time()
        while time.time() - start_time < self.timeout:
            if request_id in self._approved:
                self._approved.discard(request_id)
                return True
            if request_id in self._denied:
                self._denied.discard(request_id)
                return False
            time.sleep(0.1)

        # Timeout - clean up and deny
        self._pending.pop(request_id, None)
        logger.warning(f"Approval request timed out: {request_id}")
        return False

    async def request_approval_async(
        self,
        user: UserContext,
        action: str,
        resource: str,
        context: dict[str, Any],
    ) -> bool:
        """Queue request and wait for approval (async)."""
        self._request_counter += 1
        request_id = f"req_{self._request_counter}"

        self._pending[request_id] = {
            "id": request_id,
            "user_id": user.user_id,
            "action": action,
            "resource": resource,
            "context": context,
        }

        logger.info(f"Approval request queued: {request_id}")

        # Poll for approval
        elapsed = 0.0
        while elapsed < self.timeout:
            if request_id in self._approved:
                self._approved.discard(request_id)
                return True
            if request_id in self._denied:
                self._denied.discard(request_id)
                return False
            await asyncio.sleep(0.1)
            elapsed += 0.1

        # Timeout
        self._pending.pop(request_id, None)
        logger.warning(f"Approval request timed out: {request_id}")
        return False


def require_approval(
    strategy: ApprovalStrategy | None = None,
    reason_param: str = "approval_reason",
    user_param: str = "user",
) -> Callable[[Callable[P, T]], Callable[P, T]]:
    """
    Decorator that requires approval before executing a function.

    For high-risk operations that need human-in-the-loop approval.

    Args:
        strategy: The approval strategy to use (default: AlwaysDenyStrategy).
        reason_param: Parameter name to pass approval reason.
        user_param: Parameter name containing UserContext.

    Returns:
        A decorator function.

    Example:
        >>> @require_approval(strategy=QueueApprovalStrategy())
        ... async def delete_all_data(user: UserContext = None):
        ...     # Only runs if approved
        ...     await perform_deletion()
    """
    if strategy is None:
        strategy = AlwaysDenyStrategy()

    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        is_async = inspect.iscoroutinefunction(func)
        resource = func.__name__

        if is_async:
            @functools.wraps(func)
            async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
                user = kwargs.get(user_param)
                if user is None:
                    raise AuthorizationError(
                        user="unknown",
                        action="execute",
                        resource=resource,
                        reason="No user context provided for approval",
                    )

                context = dict(kwargs)

                approved = await strategy.request_approval_async(
                    user, "execute", resource, context
                )

                if not approved:
                    raise AuthorizationError(
                        user=user.user_id,
                        action="execute",
                        resource=resource,
                        reason="Approval denied or timed out",
                    )

                return await func(*args, **kwargs)

            return async_wrapper  # type: ignore
        else:
            @functools.wraps(func)
            def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
                user = kwargs.get(user_param)
                if user is None:
                    raise AuthorizationError(
                        user="unknown",
                        action="execute",
                        resource=resource,
                        reason="No user context provided for approval",
                    )

                context = dict(kwargs)

                approved = strategy.request_approval(
                    user, "execute", resource, context
                )

                if not approved:
                    raise AuthorizationError(
                        user=user.user_id,
                        action="execute",
                        resource=resource,
                        reason="Approval denied or timed out",
                    )

                return func(*args, **kwargs)

            return sync_wrapper  # type: ignore

    return decorator


def authorize_tool_call(
    proxilion: Any,
    action: str = "execute",
    resource: str | None = None,
    user_param: str = "user",
) -> Callable[[Callable[P, T]], Callable[P, T]]:
    """
    Standalone decorator for authorizing tool calls.

    This is an alternative to using the `@auth.authorize()` method
    when you need to decorate functions without having a reference
    to the Proxilion instance at decoration time.

    Args:
        proxilion: The Proxilion instance to use for authorization.
        action: The action being performed.
        resource: The resource name (defaults to function name).
        user_param: Parameter name containing UserContext.

    Returns:
        A decorator function.

    Example:
        >>> from proxilion import Proxilion
        >>> from proxilion.decorators import authorize_tool_call
        >>>
        >>> auth = Proxilion()
        >>>
        >>> @authorize_tool_call(auth, action="execute", resource="search")
        ... async def search(query: str, user: UserContext = None):
        ...     return await perform_search(query)
    """
    return proxilion.authorize(
        action=action,
        resource=resource,
        user_param=user_param,
    )


def rate_limited(
    capacity: int = 100,
    refill_rate: float = 10.0,
    user_param: str = "user",
    key_func: Callable[[dict[str, Any]], str] | None = None,
) -> Callable[[Callable[P, T]], Callable[P, T]]:
    """
    Standalone rate limiting decorator.

    Apply rate limiting to a function without using the full
    Proxilion authorization flow.

    Args:
        capacity: Maximum tokens in bucket.
        refill_rate: Tokens added per second.
        user_param: Parameter name containing UserContext.
        key_func: Custom function to extract rate limit key.

    Returns:
        A decorator function.

    Example:
        >>> @rate_limited(capacity=10, refill_rate=1.0)
        ... async def expensive_operation(user: UserContext = None):
        ...     return await perform_operation()
    """
    from proxilion.exceptions import RateLimitExceeded
    from proxilion.security.rate_limiter import TokenBucketRateLimiter

    limiter = TokenBucketRateLimiter(capacity=capacity, refill_rate=refill_rate)

    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        is_async = inspect.iscoroutinefunction(func)

        if is_async:
            @functools.wraps(func)
            async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
                if key_func:
                    key = key_func(dict(kwargs))
                else:
                    user = kwargs.get(user_param)
                    key = user.user_id if user else "anonymous"

                if not limiter.allow_request(key):
                    retry_after = limiter.get_retry_after(key)
                    raise RateLimitExceeded(
                        limit_type="function",
                        limit_key=key,
                        limit_value=capacity,
                        retry_after=retry_after,
                    )

                return await func(*args, **kwargs)

            return async_wrapper  # type: ignore
        else:
            @functools.wraps(func)
            def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
                if key_func:
                    key = key_func(dict(kwargs))
                else:
                    user = kwargs.get(user_param)
                    key = user.user_id if user else "anonymous"

                if not limiter.allow_request(key):
                    retry_after = limiter.get_retry_after(key)
                    raise RateLimitExceeded(
                        limit_type="function",
                        limit_key=key,
                        limit_value=capacity,
                        retry_after=retry_after,
                    )

                return func(*args, **kwargs)

            return sync_wrapper  # type: ignore

    return decorator


def circuit_protected(
    failure_threshold: int = 5,
    reset_timeout: float = 30.0,
) -> Callable[[Callable[P, T]], Callable[P, T]]:
    """
    Standalone circuit breaker decorator.

    Wrap a function with circuit breaker protection to prevent
    cascading failures.

    Args:
        failure_threshold: Failures before opening circuit.
        reset_timeout: Seconds before attempting reset.

    Returns:
        A decorator function.

    Example:
        >>> @circuit_protected(failure_threshold=3, reset_timeout=60.0)
        ... async def external_api_call():
        ...     return await call_external_api()
    """
    from proxilion.security.circuit_breaker import CircuitBreaker

    breaker = CircuitBreaker(
        failure_threshold=failure_threshold,
        reset_timeout=reset_timeout,
    )

    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        is_async = inspect.iscoroutinefunction(func)

        if is_async:
            @functools.wraps(func)
            async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
                return await breaker.call_async(func, *args, **kwargs)

            return async_wrapper  # type: ignore
        else:
            @functools.wraps(func)
            def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
                return breaker.call(func, *args, **kwargs)

            return sync_wrapper  # type: ignore

    return decorator


def sequence_validated(
    proxilion: Any,
    tool_name: str | None = None,
    user_param: str = "user",
    record_on_success: bool = True,
) -> Callable[[Callable[P, T]], Callable[P, T]]:
    """
    Decorator that validates tool call sequence before execution.

    Validates the tool call against sequence rules configured in the
    Proxilion instance. If validation fails, raises SequenceViolationError.

    Args:
        proxilion: The Proxilion instance with sequence validator.
        tool_name: Tool name to use (defaults to function name).
        user_param: Parameter name containing UserContext.
        record_on_success: Whether to record the call after successful execution.

    Returns:
        A decorator function.

    Example:
        >>> from proxilion import Proxilion
        >>> from proxilion.decorators import sequence_validated
        >>>
        >>> auth = Proxilion()
        >>>
        >>> @sequence_validated(auth, tool_name="delete_file")
        ... def delete_file(path: str, user: UserContext = None):
        ...     os.remove(path)
        ...
        >>> # Will fail if confirm_* wasn't called first
        >>> delete_file("/path/to/file", user=user)
    """
    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        name = tool_name or func.__name__
        is_async = inspect.iscoroutinefunction(func)

        if is_async:
            @functools.wraps(func)
            async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
                user = kwargs.get(user_param)
                if user is None:
                    raise AuthorizationError(
                        user="unknown",
                        action="execute",
                        resource=name,
                        reason="No user context provided for sequence validation",
                    )

                # Validate sequence
                allowed, violation = proxilion.validate_sequence(name, user)
                if not allowed and violation:
                    raise SequenceViolationError(
                        rule_name=violation.rule_name,
                        tool_name=name,
                        required_prior=violation.required_prior,
                        forbidden_prior=violation.forbidden_prior,
                        violation_type=(
                            violation.violation_type.value if violation.violation_type else None
                        ),
                        consecutive_count=(
                            violation.consecutive_count if violation.consecutive_count else None
                        ),
                    )

                # Execute function
                result = await func(*args, **kwargs)

                # Record successful call
                if record_on_success:
                    proxilion.record_tool_call(name, user)

                return result

            return async_wrapper  # type: ignore
        else:
            @functools.wraps(func)
            def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
                user = kwargs.get(user_param)
                if user is None:
                    raise AuthorizationError(
                        user="unknown",
                        action="execute",
                        resource=name,
                        reason="No user context provided for sequence validation",
                    )

                # Validate sequence
                allowed, violation = proxilion.validate_sequence(name, user)
                if not allowed and violation:
                    raise SequenceViolationError(
                        rule_name=violation.rule_name,
                        tool_name=name,
                        required_prior=violation.required_prior,
                        forbidden_prior=violation.forbidden_prior,
                        violation_type=(
                            violation.violation_type.value if violation.violation_type else None
                        ),
                        consecutive_count=(
                            violation.consecutive_count if violation.consecutive_count else None
                        ),
                    )

                # Execute function
                result = func(*args, **kwargs)

                # Record successful call
                if record_on_success:
                    proxilion.record_tool_call(name, user)

                return result

            return sync_wrapper  # type: ignore

    return decorator


def enforce_scope(
    proxilion: Any,
    scope: Any,  # ExecutionScope | str
    user_param: str = "user",
    action: str = "execute",
) -> Callable[[Callable[P, T]], Callable[P, T]]:
    """
    Decorator that enforces execution scope on a function.

    All tool calls within the decorated function must comply with
    the specified scope's restrictions (read_only, read_write, admin).

    Args:
        proxilion: The Proxilion instance with scope enforcer.
        scope: Scope name or ExecutionScope enum.
        user_param: Parameter name containing UserContext.
        action: Default action to validate against.

    Returns:
        A decorator function.

    Example:
        >>> from proxilion import Proxilion
        >>> from proxilion.decorators import enforce_scope
        >>> from proxilion.security.scope_enforcer import ExecutionScope
        >>>
        >>> auth = Proxilion()
        >>>
        >>> @enforce_scope(auth, "read_only")
        ... def handle_user_query(query: str, user: UserContext = None):
        ...     # Any tool calls here must be read-only
        ...     return get_user_data(query)
        ...
        >>> # If this function calls delete_user, it will raise ScopeViolationError
    """

    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        is_async = inspect.iscoroutinefunction(func)

        if is_async:
            @functools.wraps(func)
            async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
                user = kwargs.get(user_param)
                if user is None:
                    raise AuthorizationError(
                        user="unknown",
                        action="execute",
                        resource=func.__name__,
                        reason="No user context provided for scope enforcement",
                    )

                # Enter scope context
                ctx = proxilion.enter_scope(scope, user)
                try:
                    # Store scope context in kwargs so nested calls can validate
                    kwargs["_scope_context"] = ctx
                    result = await func(*args, **kwargs)
                    return result
                finally:
                    ctx.close()

            return async_wrapper  # type: ignore
        else:
            @functools.wraps(func)
            def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
                user = kwargs.get(user_param)
                if user is None:
                    raise AuthorizationError(
                        user="unknown",
                        action="execute",
                        resource=func.__name__,
                        reason="No user context provided for scope enforcement",
                    )

                # Enter scope context
                ctx = proxilion.enter_scope(scope, user)
                try:
                    # Store scope context in kwargs so nested calls can validate
                    kwargs["_scope_context"] = ctx
                    result = func(*args, **kwargs)
                    return result
                finally:
                    ctx.close()

            return sync_wrapper  # type: ignore

    return decorator


def scoped_tool(
    proxilion: Any,
    tool_name: str | None = None,
    action: str = "execute",
    user_param: str = "user",
    scope_context_param: str = "_scope_context",
) -> Callable[[Callable[P, T]], Callable[P, T]]:
    """
    Decorator that validates a tool call against the current scope context.

    Use this decorator on individual tool functions to validate them
    against the scope established by @enforce_scope.

    Args:
        proxilion: The Proxilion instance with scope enforcer.
        tool_name: Tool name (defaults to function name).
        action: Action being performed.
        user_param: Parameter name containing UserContext.
        scope_context_param: Parameter name for scope context.

    Returns:
        A decorator function.

    Example:
        >>> @scoped_tool(auth, action="delete")
        ... def delete_user(user_id: str, user: UserContext = None, _scope_context=None):
        ...     # Will be validated against current scope
        ...     ...
    """

    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        name = tool_name or func.__name__
        is_async = inspect.iscoroutinefunction(func)

        if is_async:
            @functools.wraps(func)
            async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
                # Get scope context if available
                scope_ctx = kwargs.get(scope_context_param)

                if scope_ctx is not None:
                    # Validate against scope
                    scope_ctx.validate_tool(name, action)

                # Remove internal param before calling function
                clean_kwargs = {k: v for k, v in kwargs.items() if k != scope_context_param}
                return await func(*args, **clean_kwargs)

            return async_wrapper  # type: ignore
        else:
            @functools.wraps(func)
            def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
                # Get scope context if available
                scope_ctx = kwargs.get(scope_context_param)

                if scope_ctx is not None:
                    # Validate against scope
                    scope_ctx.validate_tool(name, action)

                # Remove internal param before calling function
                clean_kwargs = {k: v for k, v in kwargs.items() if k != scope_context_param}
                return func(*args, **clean_kwargs)

            return sync_wrapper  # type: ignore

    return decorator


def cost_limited(
    limiter: Any,  # CostLimiter or HybridRateLimiter
    estimate_cost: Callable[..., float] | float = 0.01,
    user_param: str = "user",
    record_actual: bool = True,
) -> Callable[[Callable[P, T]], Callable[P, T]]:
    """
    Decorator that enforces cost limits on a function.

    Checks cost limits before execution and optionally records
    actual cost after execution.

    Args:
        limiter: CostLimiter or HybridRateLimiter instance.
        estimate_cost: Fixed cost estimate or callable to estimate cost from args.
        user_param: Parameter name containing UserContext.
        record_actual: Whether to record actual cost after execution.

    Returns:
        A decorator function.

    Example:
        >>> from proxilion.security.cost_limiter import CostLimiter
        >>> from proxilion.decorators import cost_limited
        >>>
        >>> limiter = CostLimiter(limits=[...])
        >>>
        >>> @cost_limited(limiter, estimate_cost=0.05)
        ... def call_llm(prompt: str, user: UserContext = None):
        ...     return client.chat(prompt)
        ...
        >>> # Or with dynamic estimation
        >>> @cost_limited(limiter, estimate_cost=lambda model, **kw: MODEL_COSTS[model])
        ... def call_model(model: str, prompt: str, user: UserContext = None):
        ...     return client.chat(model, prompt)
    """
    from proxilion.exceptions import BudgetExceededError

    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        is_async = inspect.iscoroutinefunction(func)

        def get_estimated_cost(*args: Any, **kwargs: Any) -> float:
            if callable(estimate_cost):
                return estimate_cost(*args, **kwargs)
            return float(estimate_cost)

        def get_user_id(kwargs: dict[str, Any]) -> str:
            user = kwargs.get(user_param)
            if user is None:
                return "anonymous"
            if hasattr(user, "user_id"):
                return user.user_id
            return str(user)

        if is_async:
            @functools.wraps(func)
            async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
                user_id = get_user_id(kwargs)
                cost_estimate = get_estimated_cost(*args, **kwargs)

                # Check limit
                if hasattr(limiter, "allow_request"):
                    # HybridRateLimiter
                    allowed, reason = limiter.allow_request(user_id, cost_estimate)
                else:
                    # CostLimiter
                    result = limiter.check_limit(user_id, cost_estimate)
                    allowed = result.allowed
                    # reason available in result.limit_name if not allowed

                if not allowed:
                    raise BudgetExceededError(
                        limit_type="cost_limit",
                        current_spend=0.0,  # Could get from limiter status
                        limit=0.0,
                        estimated_cost=cost_estimate,
                        user_id=user_id,
                    )

                # Execute function
                result = await func(*args, **kwargs)

                # Record actual cost
                if record_actual:
                    if hasattr(limiter, "record_usage"):
                        limiter.record_usage(user_id, cost_estimate, func.__name__)
                    elif hasattr(limiter, "record_spend"):
                        limiter.record_spend(user_id, cost_estimate, func.__name__)

                return result

            return async_wrapper  # type: ignore
        else:
            @functools.wraps(func)
            def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
                user_id = get_user_id(kwargs)
                cost_estimate = get_estimated_cost(*args, **kwargs)

                # Check limit
                if hasattr(limiter, "allow_request"):
                    # HybridRateLimiter
                    allowed, reason = limiter.allow_request(user_id, cost_estimate)
                else:
                    # CostLimiter
                    result = limiter.check_limit(user_id, cost_estimate)
                    allowed = result.allowed
                    # reason available in result.limit_name if not allowed

                if not allowed:
                    raise BudgetExceededError(
                        limit_type="cost_limit",
                        current_spend=0.0,
                        limit=0.0,
                        estimated_cost=cost_estimate,
                        user_id=user_id,
                    )

                # Execute function
                result = func(*args, **kwargs)

                # Record actual cost
                if record_actual:
                    if hasattr(limiter, "record_usage"):
                        limiter.record_usage(user_id, cost_estimate, func.__name__)
                    elif hasattr(limiter, "record_spend"):
                        limiter.record_spend(user_id, cost_estimate, func.__name__)

                return result

            return sync_wrapper  # type: ignore

    return decorator
