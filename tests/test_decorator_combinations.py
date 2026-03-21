"""
Tests for decorator stacking/combinations.

Tests common patterns where multiple decorators are applied
to the same function (e.g., @authorize_tool_call + @rate_limited).
Ensures decorators work together without interfering with each
other's argument passing, wrapping order, or async behavior.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from proxilion.decorators import (
    AlwaysApproveStrategy,
    AlwaysDenyStrategy,
    circuit_protected,
    cost_limited,
    rate_limited,
    require_approval,
    sequence_validated,
)
from proxilion.exceptions import (
    AuthorizationError,
    BudgetExceededError,
    CircuitOpenError,
    RateLimitExceeded,
    SequenceViolationError,
)
from proxilion.types import UserContext

# =============================================================================
# Helpers
# =============================================================================


def make_user(user_id: str = "alice", roles: list[str] | None = None) -> UserContext:
    return UserContext(user_id=user_id, roles=roles or ["user"])


def make_cost_limiter(allowed: bool = True, current_spend: float = 0.50, limit: float = 1.00):
    """Create a mock CostLimiter."""
    limiter = MagicMock()
    result_mock = MagicMock()
    result_mock.allowed = allowed
    result_mock.current_spend = current_spend
    result_mock.limit = limit
    limiter.check_limit.return_value = result_mock
    limiter.record_spend = MagicMock()
    # Remove allow_request to use CostLimiter path
    del limiter.allow_request
    del limiter.record_usage
    return limiter


def make_proxilion_mock(allowed: bool = True, violation=None):
    """Create a mock Proxilion for sequence validation."""
    mock = MagicMock()
    mock.validate_sequence.return_value = (allowed, violation)
    mock.record_tool_call.return_value = None
    return mock


# =============================================================================
# TestApprovalPlusRateLimit
# =============================================================================


class TestApprovalPlusRateLimit:
    """Tests combining @require_approval with @rate_limited."""

    def test_sync_both_pass(self) -> None:
        """Authorized user within rate limit succeeds."""

        @require_approval(strategy=AlwaysApproveStrategy())
        @rate_limited(capacity=5, refill_rate=0.001)
        def do_thing(user=None):
            return "done"

        result = do_thing(user=make_user())
        assert result == "done"

    def test_sync_approval_first_checked(self) -> None:
        """Unauthorized user is rejected before rate limit is checked."""
        rate_limit_checked = False

        @require_approval(strategy=AlwaysDenyStrategy())
        @rate_limited(capacity=100, refill_rate=1.0)
        def do_thing(user=None):
            nonlocal rate_limit_checked
            rate_limit_checked = True
            return "done"

        with pytest.raises(AuthorizationError):
            do_thing(user=make_user())

        # Function was never called, so rate limit logic wasn't reached
        assert not rate_limit_checked

    def test_sync_rate_limit_after_approval(self) -> None:
        """Authorized user exceeding rate limit gets RateLimitExceeded."""

        @require_approval(strategy=AlwaysApproveStrategy())
        @rate_limited(capacity=2, refill_rate=0.001)
        def do_thing(user=None):
            return "done"

        user = make_user()
        assert do_thing(user=user) == "done"
        assert do_thing(user=user) == "done"
        with pytest.raises(RateLimitExceeded):
            do_thing(user=user)

    def test_sync_reversed_order(self) -> None:
        """Rate limit checked first when decorators are reversed."""
        # When @rate_limited is the outer decorator, it runs first

        @rate_limited(capacity=2, refill_rate=0.001)
        @require_approval(strategy=AlwaysApproveStrategy())
        def do_thing(user=None):
            return "done"

        user = make_user()
        assert do_thing(user=user) == "done"
        assert do_thing(user=user) == "done"
        # Rate limit kicks in before approval is even checked
        with pytest.raises(RateLimitExceeded):
            do_thing(user=user)

    @pytest.mark.asyncio
    async def test_async_both_pass(self) -> None:
        """Async: authorized user within rate limit succeeds."""

        @require_approval(strategy=AlwaysApproveStrategy())
        @rate_limited(capacity=5, refill_rate=0.001)
        async def do_thing(user=None):
            return "done"

        result = await do_thing(user=make_user())
        assert result == "done"

    @pytest.mark.asyncio
    async def test_async_approval_denied(self) -> None:
        """Async: unauthorized user rejected."""

        @require_approval(strategy=AlwaysDenyStrategy())
        @rate_limited(capacity=100, refill_rate=1.0)
        async def do_thing(user=None):
            return "done"

        with pytest.raises(AuthorizationError):
            await do_thing(user=make_user())

    @pytest.mark.asyncio
    async def test_async_rate_limit_exceeded(self) -> None:
        """Async: authorized user exceeding rate limit."""

        @require_approval(strategy=AlwaysApproveStrategy())
        @rate_limited(capacity=1, refill_rate=0.001)
        async def do_thing(user=None):
            return "done"

        user = make_user()
        await do_thing(user=user)
        with pytest.raises(RateLimitExceeded):
            await do_thing(user=user)


# =============================================================================
# TestApprovalPlusCircuitBreaker
# =============================================================================


class TestApprovalPlusCircuitBreaker:
    """Tests combining @require_approval with @circuit_protected."""

    def test_sync_both_pass(self) -> None:
        """Function works normally when circuit is closed."""

        @require_approval(strategy=AlwaysApproveStrategy())
        @circuit_protected(failure_threshold=3, reset_timeout=60.0)
        def do_thing(user=None):
            return "ok"

        result = do_thing(user=make_user())
        assert result == "ok"

    def test_sync_circuit_opens_after_failures(self) -> None:
        """After enough failures, circuit opens and raises CircuitOpenError."""

        @require_approval(strategy=AlwaysApproveStrategy())
        @circuit_protected(failure_threshold=3, reset_timeout=60.0)
        def do_thing(user=None):
            raise ValueError("fail")

        user = make_user()
        for _ in range(3):
            with pytest.raises(ValueError):
                do_thing(user=user)

        # Circuit should now be open
        with pytest.raises(CircuitOpenError):
            do_thing(user=user)

    def test_sync_approval_checked_even_with_open_circuit(self) -> None:
        """Approval is checked before circuit breaker when approval is outer."""
        # When circuit is open but approval fails, approval error is raised first

        @require_approval(strategy=AlwaysDenyStrategy())
        @circuit_protected(failure_threshold=1, reset_timeout=60.0)
        def do_thing(user=None):
            return "ok"

        with pytest.raises(AuthorizationError):
            do_thing(user=make_user())

    @pytest.mark.asyncio
    async def test_async_both_pass(self) -> None:
        """Async: function works normally when circuit is closed."""

        @require_approval(strategy=AlwaysApproveStrategy())
        @circuit_protected(failure_threshold=3, reset_timeout=60.0)
        async def do_thing(user=None):
            return "ok"

        result = await do_thing(user=make_user())
        assert result == "ok"

    @pytest.mark.asyncio
    async def test_async_circuit_opens(self) -> None:
        """Async: circuit opens after failures."""

        @require_approval(strategy=AlwaysApproveStrategy())
        @circuit_protected(failure_threshold=2, reset_timeout=60.0)
        async def do_thing(user=None):
            raise ValueError("fail")

        user = make_user()
        for _ in range(2):
            with pytest.raises(ValueError):
                await do_thing(user=user)

        with pytest.raises(CircuitOpenError):
            await do_thing(user=user)


# =============================================================================
# TestTripleStack
# =============================================================================


class TestTripleStack:
    """Tests combining @require_approval, @rate_limited, and @circuit_protected."""

    def test_sync_all_three_pass(self) -> None:
        """All three layers work together successfully."""

        @require_approval(strategy=AlwaysApproveStrategy())
        @rate_limited(capacity=10, refill_rate=0.001)
        @circuit_protected(failure_threshold=5, reset_timeout=60.0)
        def do_thing(user=None):
            return "done"

        result = do_thing(user=make_user())
        assert result == "done"

    def test_sync_outermost_checked_first(self) -> None:
        """The outermost decorator is checked first."""
        # Order: require_approval -> rate_limited -> circuit_protected
        # So approval is checked first

        @require_approval(strategy=AlwaysDenyStrategy())
        @rate_limited(capacity=100, refill_rate=1.0)
        @circuit_protected(failure_threshold=100, reset_timeout=60.0)
        def do_thing(user=None):
            return "done"

        # Approval fails first, others never checked
        with pytest.raises(AuthorizationError):
            do_thing(user=make_user())

    def test_sync_rate_limit_before_circuit(self) -> None:
        """Rate limit is checked before circuit breaker."""

        @require_approval(strategy=AlwaysApproveStrategy())
        @rate_limited(capacity=2, refill_rate=0.001)
        @circuit_protected(failure_threshold=100, reset_timeout=60.0)
        def do_thing(user=None):
            return "done"

        user = make_user()
        do_thing(user=user)
        do_thing(user=user)

        # Rate limit exceeded, circuit never considered
        with pytest.raises(RateLimitExceeded):
            do_thing(user=user)

    def test_sync_circuit_after_rate(self) -> None:
        """Circuit opens after failures pass through rate limit."""

        @require_approval(strategy=AlwaysApproveStrategy())
        @rate_limited(capacity=100, refill_rate=1.0)
        @circuit_protected(failure_threshold=2, reset_timeout=60.0)
        def do_thing(user=None):
            raise ValueError("fail")

        user = make_user()
        for _ in range(2):
            with pytest.raises(ValueError):
                do_thing(user=user)

        # Circuit should now be open
        with pytest.raises(CircuitOpenError):
            do_thing(user=user)

    @pytest.mark.asyncio
    async def test_async_all_three_pass(self) -> None:
        """Async: all three layers work together."""

        @require_approval(strategy=AlwaysApproveStrategy())
        @rate_limited(capacity=10, refill_rate=0.001)
        @circuit_protected(failure_threshold=5, reset_timeout=60.0)
        async def do_thing(user=None):
            return "done"

        result = await do_thing(user=make_user())
        assert result == "done"

    @pytest.mark.asyncio
    async def test_async_outermost_checked_first(self) -> None:
        """Async: outermost decorator checked first."""

        @require_approval(strategy=AlwaysDenyStrategy())
        @rate_limited(capacity=100, refill_rate=1.0)
        @circuit_protected(failure_threshold=100, reset_timeout=60.0)
        async def do_thing(user=None):
            return "done"

        with pytest.raises(AuthorizationError):
            await do_thing(user=make_user())


# =============================================================================
# TestAsyncDecoratorStacking
# =============================================================================


class TestAsyncDecoratorStacking:
    """Tests verifying async functions work correctly through decorator chains."""

    @pytest.mark.asyncio
    async def test_async_approval_plus_rate_plus_circuit(self) -> None:
        """Async function with all decorators awaits correctly."""
        import asyncio

        @require_approval(strategy=AlwaysApproveStrategy())
        @rate_limited(capacity=10, refill_rate=0.001)
        @circuit_protected(failure_threshold=5, reset_timeout=60.0)
        async def async_operation(user=None):
            await asyncio.sleep(0.001)
            return "async done"

        result = await async_operation(user=make_user())
        assert result == "async done"

    @pytest.mark.asyncio
    async def test_async_with_sequence_validation(self) -> None:
        """Async function with sequence validation works correctly."""
        mock_px = make_proxilion_mock(allowed=True)

        @rate_limited(capacity=10, refill_rate=0.001)
        @sequence_validated(mock_px)
        async def async_tool(user=None):
            return "tool done"

        result = await async_tool(user=make_user())
        assert result == "tool done"
        mock_px.validate_sequence.assert_called_once()
        mock_px.record_tool_call.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_sequence_violation_stops_chain(self) -> None:
        """Sequence violation stops execution even in async chain."""
        violation = MagicMock()
        violation.rule_name = "test_rule"
        violation.required_prior = ["prereq"]
        violation.forbidden_prior = None
        violation.violation_type = MagicMock(value="missing_prerequisite")
        violation.consecutive_count = None
        mock_px = make_proxilion_mock(allowed=False, violation=violation)

        @rate_limited(capacity=100, refill_rate=1.0)
        @sequence_validated(mock_px)
        async def async_tool(user=None):
            return "tool done"

        with pytest.raises(SequenceViolationError):
            await async_tool(user=make_user())

    @pytest.mark.asyncio
    async def test_async_cost_plus_rate(self) -> None:
        """Async function with both cost and rate limiting."""
        limiter = make_cost_limiter(allowed=True)

        @cost_limited(limiter, estimate_cost=0.05)
        @rate_limited(capacity=10, refill_rate=0.001)
        async def expensive_operation(user=None):
            return "expensive done"

        result = await expensive_operation(user=make_user())
        assert result == "expensive done"
        limiter.check_limit.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_cost_denied_before_rate(self) -> None:
        """Cost limit checked before rate limit when outer."""
        limiter = make_cost_limiter(allowed=False)

        @cost_limited(limiter, estimate_cost=0.05)
        @rate_limited(capacity=100, refill_rate=1.0)
        async def expensive_operation(user=None):
            return "expensive done"

        with pytest.raises(BudgetExceededError):
            await expensive_operation(user=make_user())


# =============================================================================
# TestDecoratorPreservesMetadata
# =============================================================================


class TestDecoratorPreservesMetadata:
    """Tests that stacked decorators preserve __name__, __doc__, __module__."""

    def test_single_decorator_preserves_name(self) -> None:
        @rate_limited(capacity=10)
        def my_function(user=None):
            """My docstring."""
            return "done"

        assert my_function.__name__ == "my_function"
        assert my_function.__doc__ == "My docstring."

    def test_double_stack_preserves_name(self) -> None:
        @require_approval(strategy=AlwaysApproveStrategy())
        @rate_limited(capacity=10)
        def my_function(user=None):
            """My docstring."""
            return "done"

        assert my_function.__name__ == "my_function"
        assert my_function.__doc__ == "My docstring."

    def test_triple_stack_preserves_name(self) -> None:
        @require_approval(strategy=AlwaysApproveStrategy())
        @rate_limited(capacity=10)
        @circuit_protected(failure_threshold=5)
        def my_function(user=None):
            """My docstring."""
            return "done"

        assert my_function.__name__ == "my_function"
        assert my_function.__doc__ == "My docstring."

    def test_quadruple_stack_preserves_name(self) -> None:
        limiter = make_cost_limiter()

        @cost_limited(limiter, estimate_cost=0.01)
        @require_approval(strategy=AlwaysApproveStrategy())
        @rate_limited(capacity=10)
        @circuit_protected(failure_threshold=5)
        def my_function(user=None):
            """My docstring."""
            return "done"

        assert my_function.__name__ == "my_function"
        assert my_function.__doc__ == "My docstring."

    @pytest.mark.asyncio
    async def test_async_stack_preserves_name(self) -> None:
        @require_approval(strategy=AlwaysApproveStrategy())
        @rate_limited(capacity=10)
        @circuit_protected(failure_threshold=5)
        async def my_async_function(user=None):
            """Async docstring."""
            return "done"

        assert my_async_function.__name__ == "my_async_function"
        assert my_async_function.__doc__ == "Async docstring."


# =============================================================================
# TestRateLimitPlusCircuit
# =============================================================================


class TestRateLimitPlusCircuit:
    """Tests combining @rate_limited with @circuit_protected."""

    def test_sync_both_pass(self) -> None:
        """Both rate limit and circuit breaker pass."""

        @rate_limited(capacity=10, refill_rate=0.001)
        @circuit_protected(failure_threshold=5, reset_timeout=60.0)
        def do_thing(user=None):
            return "done"

        assert do_thing(user=make_user()) == "done"

    def test_sync_rate_limit_independent_of_circuit(self) -> None:
        """Rate limit is checked independently per user, circuit is per function."""

        @rate_limited(capacity=2, refill_rate=0.001)
        @circuit_protected(failure_threshold=5, reset_timeout=60.0)
        def do_thing(user=None):
            return "done"

        alice = make_user("alice")
        bob = make_user("bob")

        # Alice hits her limit
        do_thing(user=alice)
        do_thing(user=alice)
        with pytest.raises(RateLimitExceeded):
            do_thing(user=alice)

        # Bob can still call
        assert do_thing(user=bob) == "done"

    def test_sync_circuit_shares_across_users(self) -> None:
        """Circuit breaker state is shared across all users."""

        @rate_limited(capacity=100, refill_rate=1.0)
        @circuit_protected(failure_threshold=3, reset_timeout=60.0)
        def do_thing(user=None):
            raise ValueError("fail")

        alice = make_user("alice")
        bob = make_user("bob")
        charlie = make_user("charlie")

        # Each user causes one failure
        with pytest.raises(ValueError):
            do_thing(user=alice)
        with pytest.raises(ValueError):
            do_thing(user=bob)
        with pytest.raises(ValueError):
            do_thing(user=charlie)

        # Circuit should now be open for everyone
        with pytest.raises(CircuitOpenError):
            do_thing(user=alice)
        with pytest.raises(CircuitOpenError):
            do_thing(user=bob)


# =============================================================================
# TestSequencePlusCost
# =============================================================================


class TestSequencePlusCost:
    """Tests combining @sequence_validated with @cost_limited."""

    def test_sync_both_pass(self) -> None:
        """Sequence validation and cost limit both pass."""
        mock_px = make_proxilion_mock(allowed=True)
        limiter = make_cost_limiter(allowed=True)

        @sequence_validated(mock_px)
        @cost_limited(limiter, estimate_cost=0.05)
        def do_thing(user=None):
            return "done"

        result = do_thing(user=make_user())
        assert result == "done"
        mock_px.validate_sequence.assert_called_once()
        limiter.check_limit.assert_called_once()

    def test_sync_sequence_fails_first(self) -> None:
        """Sequence validation fails before cost is checked."""
        violation = MagicMock()
        violation.rule_name = "order_rule"
        violation.required_prior = ["step_a"]
        violation.forbidden_prior = None
        violation.violation_type = MagicMock(value="wrong_order")
        violation.consecutive_count = None
        mock_px = make_proxilion_mock(allowed=False, violation=violation)
        limiter = make_cost_limiter(allowed=True)

        @sequence_validated(mock_px)
        @cost_limited(limiter, estimate_cost=0.05)
        def do_thing(user=None):
            return "done"

        with pytest.raises(SequenceViolationError):
            do_thing(user=make_user())

        # Cost was never checked
        limiter.check_limit.assert_not_called()

    def test_sync_cost_fails_after_sequence(self) -> None:
        """Cost limit fails after sequence passes."""
        mock_px = make_proxilion_mock(allowed=True)
        limiter = make_cost_limiter(allowed=False)

        @sequence_validated(mock_px)
        @cost_limited(limiter, estimate_cost=0.05)
        def do_thing(user=None):
            return "done"

        with pytest.raises(BudgetExceededError):
            do_thing(user=make_user())

        # Sequence was validated first
        mock_px.validate_sequence.assert_called_once()


# =============================================================================
# TestMultipleUsersSameDecorators
# =============================================================================


class TestMultipleUsersSameDecorators:
    """Tests that decorator state is correctly isolated or shared."""

    def test_rate_limit_per_user(self) -> None:
        """Each user has their own rate limit bucket."""

        @rate_limited(capacity=2, refill_rate=0.001)
        def do_thing(user=None):
            return "done"

        alice = make_user("alice")
        bob = make_user("bob")

        # Alice uses her quota
        do_thing(user=alice)
        do_thing(user=alice)

        # Bob still has full quota
        assert do_thing(user=bob) == "done"
        assert do_thing(user=bob) == "done"

        # Both are now rate limited
        with pytest.raises(RateLimitExceeded):
            do_thing(user=alice)
        with pytest.raises(RateLimitExceeded):
            do_thing(user=bob)

    def test_circuit_breaker_shared(self) -> None:
        """Circuit breaker is shared across all callers."""

        @circuit_protected(failure_threshold=2, reset_timeout=60.0)
        def do_thing(user=None):
            raise ValueError("fail")

        alice = make_user("alice")
        bob = make_user("bob")

        # One failure from each user
        with pytest.raises(ValueError):
            do_thing(user=alice)
        with pytest.raises(ValueError):
            do_thing(user=bob)

        # Circuit is now open for everyone
        with pytest.raises(CircuitOpenError):
            do_thing(user=alice)
        with pytest.raises(CircuitOpenError):
            do_thing(user=bob)


# =============================================================================
# TestDecoratorArgumentPassing
# =============================================================================


class TestDecoratorArgumentPassing:
    """Tests that decorator chains correctly pass arguments through."""

    def test_positional_args_passed_through(self) -> None:
        """Positional arguments are correctly passed through decorator chain."""

        @require_approval(strategy=AlwaysApproveStrategy())
        @rate_limited(capacity=10)
        def do_thing(a, b, user=None):
            return a + b

        result = do_thing(1, 2, user=make_user())
        assert result == 3

    def test_keyword_args_passed_through(self) -> None:
        """Keyword arguments are correctly passed through decorator chain."""

        @require_approval(strategy=AlwaysApproveStrategy())
        @rate_limited(capacity=10)
        def do_thing(a=0, b=0, user=None):
            return a * b

        result = do_thing(a=3, b=4, user=make_user())
        assert result == 12

    def test_mixed_args_passed_through(self) -> None:
        """Mixed positional and keyword arguments work correctly."""

        @require_approval(strategy=AlwaysApproveStrategy())
        @rate_limited(capacity=10)
        @circuit_protected(failure_threshold=5)
        def do_thing(a, b, c=10, user=None):
            return a + b + c

        result = do_thing(1, 2, c=5, user=make_user())
        assert result == 8

    def test_varargs_passed_through(self) -> None:
        """*args and **kwargs are correctly passed through."""

        @require_approval(strategy=AlwaysApproveStrategy())
        @rate_limited(capacity=10)
        def do_thing(*args, user=None, **kwargs):
            return sum(args) + sum(kwargs.values())

        result = do_thing(1, 2, 3, user=make_user(), x=10, y=20)
        assert result == 36

    @pytest.mark.asyncio
    async def test_async_args_passed_through(self) -> None:
        """Arguments are correctly passed through in async chain."""

        @require_approval(strategy=AlwaysApproveStrategy())
        @rate_limited(capacity=10)
        async def do_thing(a, b, user=None):
            return a - b

        result = await do_thing(10, 3, user=make_user())
        assert result == 7
