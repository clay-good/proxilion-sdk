"""
Tests for proxilion.decorators module.

Covers require_approval, rate_limited, circuit_protected,
sequence_validated, enforce_scope, scoped_tool, and cost_limited decorators
with both sync and async functions.
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from proxilion.decorators import (
    AlwaysApproveStrategy,
    AlwaysDenyStrategy,
    CallbackApprovalStrategy,
    QueueApprovalStrategy,
    circuit_protected,
    cost_limited,
    enforce_scope,
    rate_limited,
    require_approval,
    scoped_tool,
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


# =============================================================================
# ApprovalStrategy Tests
# =============================================================================


class TestAlwaysApproveStrategy:
    def test_sync_approve(self) -> None:
        strategy = AlwaysApproveStrategy()
        assert strategy.request_approval(make_user(), "execute", "tool", {}) is True

    @pytest.mark.asyncio
    async def test_async_approve(self) -> None:
        strategy = AlwaysApproveStrategy()
        result = await strategy.request_approval_async(make_user(), "execute", "tool", {})
        assert result is True


class TestAlwaysDenyStrategy:
    def test_sync_deny(self) -> None:
        strategy = AlwaysDenyStrategy()
        assert strategy.request_approval(make_user(), "execute", "tool", {}) is False

    @pytest.mark.asyncio
    async def test_async_deny(self) -> None:
        strategy = AlwaysDenyStrategy()
        result = await strategy.request_approval_async(make_user(), "execute", "tool", {})
        assert result is False


class TestCallbackApprovalStrategy:
    def test_sync_callback(self) -> None:
        cb = lambda u, a, r, c: u.user_id == "admin"
        strategy = CallbackApprovalStrategy(cb)
        assert strategy.request_approval(make_user("admin"), "execute", "tool", {}) is True
        assert strategy.request_approval(make_user("alice"), "execute", "tool", {}) is False

    @pytest.mark.asyncio
    async def test_async_callback_fallback(self) -> None:
        """Async falls back to sync callback when no async_callback provided."""
        cb = lambda u, a, r, c: True
        strategy = CallbackApprovalStrategy(cb)
        result = await strategy.request_approval_async(make_user(), "execute", "tool", {})
        assert result is True

    @pytest.mark.asyncio
    async def test_async_callback_explicit(self) -> None:
        """Uses explicit async callback when provided."""
        async def async_cb(u, a, r, c):
            return u.user_id == "bob"

        strategy = CallbackApprovalStrategy(lambda u, a, r, c: False, async_callback=async_cb)
        assert await strategy.request_approval_async(make_user("bob"), "execute", "tool", {}) is True
        assert await strategy.request_approval_async(make_user("alice"), "execute", "tool", {}) is False


class TestQueueApprovalStrategy:
    def test_pending_requests(self) -> None:
        strategy = QueueApprovalStrategy(timeout=0.2)
        assert strategy.pending_requests == []

    def test_approve_removes_from_pending(self) -> None:
        strategy = QueueApprovalStrategy(timeout=0.2)
        # Manually add a request
        strategy._pending["req_1"] = {"id": "req_1", "user_id": "alice"}
        strategy.approve("req_1")
        assert "req_1" not in strategy._pending
        assert "req_1" in strategy._approved

    def test_deny_removes_from_pending(self) -> None:
        strategy = QueueApprovalStrategy(timeout=0.2)
        strategy._pending["req_1"] = {"id": "req_1", "user_id": "alice"}
        strategy.deny("req_1")
        assert "req_1" not in strategy._pending
        assert "req_1" in strategy._denied

    def test_sync_timeout_denies(self) -> None:
        strategy = QueueApprovalStrategy(timeout=0.1)
        result = strategy.request_approval(make_user(), "execute", "tool", {})
        assert result is False

    @pytest.mark.asyncio
    async def test_async_timeout_denies(self) -> None:
        strategy = QueueApprovalStrategy(timeout=0.1)
        result = await strategy.request_approval_async(make_user(), "execute", "tool", {})
        assert result is False

    @pytest.mark.asyncio
    async def test_async_approve_before_timeout(self) -> None:
        strategy = QueueApprovalStrategy(timeout=2.0)

        async def approve_later():
            await asyncio.sleep(0.05)
            for req in strategy.pending_requests:
                strategy.approve(req["id"])

        asyncio.create_task(approve_later())
        result = await strategy.request_approval_async(make_user(), "execute", "tool", {})
        assert result is True

    @pytest.mark.asyncio
    async def test_async_deny_before_timeout(self) -> None:
        strategy = QueueApprovalStrategy(timeout=2.0)

        async def deny_later():
            await asyncio.sleep(0.05)
            for req in strategy.pending_requests:
                strategy.deny(req["id"])

        asyncio.create_task(deny_later())
        result = await strategy.request_approval_async(make_user(), "execute", "tool", {})
        assert result is False


# =============================================================================
# require_approval Tests
# =============================================================================


class TestRequireApproval:
    def test_sync_approved(self) -> None:
        @require_approval(strategy=AlwaysApproveStrategy())
        def do_thing(user=None):
            return "done"

        result = do_thing(user=make_user())
        assert result == "done"

    def test_sync_denied(self) -> None:
        @require_approval(strategy=AlwaysDenyStrategy())
        def do_thing(user=None):
            return "done"

        with pytest.raises(AuthorizationError):
            do_thing(user=make_user())

    def test_sync_no_user_raises(self) -> None:
        @require_approval(strategy=AlwaysApproveStrategy())
        def do_thing(user=None):
            return "done"

        with pytest.raises(AuthorizationError, match="No user context"):
            do_thing()

    @pytest.mark.asyncio
    async def test_async_approved(self) -> None:
        @require_approval(strategy=AlwaysApproveStrategy())
        async def do_thing(user=None):
            return "done"

        result = await do_thing(user=make_user())
        assert result == "done"

    @pytest.mark.asyncio
    async def test_async_denied(self) -> None:
        @require_approval(strategy=AlwaysDenyStrategy())
        async def do_thing(user=None):
            return "done"

        with pytest.raises(AuthorizationError):
            await do_thing(user=make_user())

    @pytest.mark.asyncio
    async def test_async_no_user_raises(self) -> None:
        @require_approval(strategy=AlwaysApproveStrategy())
        async def do_thing(user=None):
            return "done"

        with pytest.raises(AuthorizationError, match="No user context"):
            await do_thing()

    def test_default_strategy_denies(self) -> None:
        """Default strategy (AlwaysDenyStrategy) should deny."""
        @require_approval()
        def do_thing(user=None):
            return "done"

        with pytest.raises(AuthorizationError):
            do_thing(user=make_user())

    def test_preserves_function_name(self) -> None:
        @require_approval(strategy=AlwaysApproveStrategy())
        def my_function(user=None):
            return "done"

        assert my_function.__name__ == "my_function"

    def test_callback_strategy(self) -> None:
        strategy = CallbackApprovalStrategy(
            lambda u, a, r, c: u.user_id == "admin"
        )

        @require_approval(strategy=strategy)
        def do_thing(user=None):
            return "done"

        assert do_thing(user=make_user("admin")) == "done"
        with pytest.raises(AuthorizationError):
            do_thing(user=make_user("alice"))


# =============================================================================
# rate_limited Tests
# =============================================================================


class TestRateLimited:
    def test_sync_allows_within_limit(self) -> None:
        @rate_limited(capacity=5, refill_rate=0.001)
        def do_thing(user=None):
            return "done"

        user = make_user()
        for _ in range(5):
            assert do_thing(user=user) == "done"

    def test_sync_blocks_over_limit(self) -> None:
        @rate_limited(capacity=2, refill_rate=0.001)
        def do_thing(user=None):
            return "done"

        user = make_user()
        do_thing(user=user)
        do_thing(user=user)
        with pytest.raises(RateLimitExceeded):
            do_thing(user=user)

    @pytest.mark.asyncio
    async def test_async_allows_within_limit(self) -> None:
        @rate_limited(capacity=3, refill_rate=0.001)
        async def do_thing(user=None):
            return "done"

        user = make_user()
        for _ in range(3):
            assert await do_thing(user=user) == "done"

    @pytest.mark.asyncio
    async def test_async_blocks_over_limit(self) -> None:
        @rate_limited(capacity=1, refill_rate=0.001)
        async def do_thing(user=None):
            return "done"

        user = make_user()
        await do_thing(user=user)
        with pytest.raises(RateLimitExceeded):
            await do_thing(user=user)

    def test_per_user_limiting(self) -> None:
        @rate_limited(capacity=1, refill_rate=0.001)
        def do_thing(user=None):
            return "done"

        alice = make_user("alice")
        bob = make_user("bob")
        do_thing(user=alice)
        # Bob should still be able to call
        assert do_thing(user=bob) == "done"
        # Alice should be blocked
        with pytest.raises(RateLimitExceeded):
            do_thing(user=alice)

    def test_anonymous_user(self) -> None:
        @rate_limited(capacity=1, refill_rate=0.001)
        def do_thing():
            return "done"

        assert do_thing() == "done"
        with pytest.raises(RateLimitExceeded):
            do_thing()

    def test_custom_key_func(self) -> None:
        @rate_limited(capacity=1, refill_rate=0.001, key_func=lambda kw: "shared")
        def do_thing(user=None):
            return "done"

        do_thing(user=make_user("alice"))
        with pytest.raises(RateLimitExceeded):
            do_thing(user=make_user("bob"))  # Same key, blocked

    def test_preserves_function_name(self) -> None:
        @rate_limited(capacity=10)
        def my_function(user=None):
            return "done"

        assert my_function.__name__ == "my_function"


# =============================================================================
# circuit_protected Tests
# =============================================================================


class TestCircuitProtected:
    def test_sync_success(self) -> None:
        @circuit_protected(failure_threshold=3)
        def do_thing():
            return "ok"

        assert do_thing() == "ok"

    def test_sync_opens_after_failures(self) -> None:
        call_count = 0

        @circuit_protected(failure_threshold=3, reset_timeout=60.0)
        def do_thing():
            nonlocal call_count
            call_count += 1
            raise ValueError("fail")

        for _ in range(3):
            with pytest.raises(ValueError):
                do_thing()

        # Circuit should now be open
        with pytest.raises(CircuitOpenError):
            do_thing()

    @pytest.mark.asyncio
    async def test_async_success(self) -> None:
        @circuit_protected(failure_threshold=3)
        async def do_thing():
            return "ok"

        assert await do_thing() == "ok"

    @pytest.mark.asyncio
    async def test_async_opens_after_failures(self) -> None:
        @circuit_protected(failure_threshold=2, reset_timeout=60.0)
        async def do_thing():
            raise ValueError("fail")

        for _ in range(2):
            with pytest.raises(ValueError):
                await do_thing()

        with pytest.raises(CircuitOpenError):
            await do_thing()

    def test_preserves_function_name(self) -> None:
        @circuit_protected()
        def my_function():
            return "done"

        assert my_function.__name__ == "my_function"


# =============================================================================
# sequence_validated Tests
# =============================================================================


class TestSequenceValidated:
    def _make_proxilion_mock(self, allowed=True, violation=None):
        mock = MagicMock()
        mock.validate_sequence.return_value = (allowed, violation)
        mock.record_tool_call.return_value = None
        return mock

    def test_sync_allowed(self) -> None:
        mock_px = self._make_proxilion_mock(allowed=True)

        @sequence_validated(mock_px)
        def do_thing(user=None):
            return "done"

        result = do_thing(user=make_user())
        assert result == "done"
        mock_px.validate_sequence.assert_called_once_with("do_thing", make_user())
        mock_px.record_tool_call.assert_called_once_with("do_thing", make_user())

    def test_sync_violation(self) -> None:
        violation = MagicMock()
        violation.rule_name = "require_confirm"
        violation.required_prior = ["confirm"]
        violation.forbidden_prior = None
        violation.violation_type = MagicMock(value="missing_prerequisite")
        violation.consecutive_count = None
        mock_px = self._make_proxilion_mock(allowed=False, violation=violation)

        @sequence_validated(mock_px)
        def do_thing(user=None):
            return "done"

        with pytest.raises(SequenceViolationError):
            do_thing(user=make_user())

    def test_sync_no_user_raises(self) -> None:
        mock_px = self._make_proxilion_mock()

        @sequence_validated(mock_px)
        def do_thing(user=None):
            return "done"

        with pytest.raises(AuthorizationError, match="No user context"):
            do_thing()

    def test_custom_tool_name(self) -> None:
        mock_px = self._make_proxilion_mock()

        @sequence_validated(mock_px, tool_name="custom_name")
        def do_thing(user=None):
            return "done"

        do_thing(user=make_user())
        mock_px.validate_sequence.assert_called_once_with("custom_name", make_user())

    def test_no_record_on_success(self) -> None:
        mock_px = self._make_proxilion_mock()

        @sequence_validated(mock_px, record_on_success=False)
        def do_thing(user=None):
            return "done"

        do_thing(user=make_user())
        mock_px.record_tool_call.assert_not_called()

    @pytest.mark.asyncio
    async def test_async_allowed(self) -> None:
        mock_px = self._make_proxilion_mock()

        @sequence_validated(mock_px)
        async def do_thing(user=None):
            return "done"

        result = await do_thing(user=make_user())
        assert result == "done"
        mock_px.validate_sequence.assert_called_once()
        mock_px.record_tool_call.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_violation(self) -> None:
        violation = MagicMock()
        violation.rule_name = "order_rule"
        violation.required_prior = ["step_a"]
        violation.forbidden_prior = None
        violation.violation_type = MagicMock(value="wrong_order")
        violation.consecutive_count = None
        mock_px = self._make_proxilion_mock(allowed=False, violation=violation)

        @sequence_validated(mock_px)
        async def do_thing(user=None):
            return "done"

        with pytest.raises(SequenceViolationError):
            await do_thing(user=make_user())

    @pytest.mark.asyncio
    async def test_async_no_user_raises(self) -> None:
        mock_px = self._make_proxilion_mock()

        @sequence_validated(mock_px)
        async def do_thing(user=None):
            return "done"

        with pytest.raises(AuthorizationError):
            await do_thing()


# =============================================================================
# enforce_scope Tests
# =============================================================================


class TestEnforceScope:
    def _make_proxilion_mock(self):
        mock = MagicMock()
        scope_ctx = MagicMock()
        scope_ctx.close.return_value = None
        mock.enter_scope.return_value = scope_ctx
        return mock, scope_ctx

    def test_sync_enters_and_closes_scope(self) -> None:
        mock_px, scope_ctx = self._make_proxilion_mock()

        @enforce_scope(mock_px, "read_only")
        def do_thing(user=None, **kwargs):
            return "done"

        result = do_thing(user=make_user())
        assert result == "done"
        mock_px.enter_scope.assert_called_once_with("read_only", make_user())
        scope_ctx.close.assert_called_once()

    def test_sync_no_user_raises(self) -> None:
        mock_px, _ = self._make_proxilion_mock()

        @enforce_scope(mock_px, "read_only")
        def do_thing(user=None, **kwargs):
            return "done"

        with pytest.raises(AuthorizationError, match="No user context"):
            do_thing()

    def test_sync_closes_scope_on_error(self) -> None:
        mock_px, scope_ctx = self._make_proxilion_mock()

        @enforce_scope(mock_px, "read_only")
        def do_thing(user=None, **kwargs):
            raise RuntimeError("boom")

        with pytest.raises(RuntimeError):
            do_thing(user=make_user())
        scope_ctx.close.assert_called_once()

    def test_scope_context_passed_to_function(self) -> None:
        mock_px, scope_ctx = self._make_proxilion_mock()
        received_ctx = None

        @enforce_scope(mock_px, "read_write")
        def do_thing(user=None, **kwargs):
            nonlocal received_ctx
            received_ctx = kwargs.get("_scope_context")
            return "done"

        do_thing(user=make_user())
        assert received_ctx is scope_ctx

    @pytest.mark.asyncio
    async def test_async_enters_and_closes_scope(self) -> None:
        mock_px, scope_ctx = self._make_proxilion_mock()

        @enforce_scope(mock_px, "read_only")
        async def do_thing(user=None, **kwargs):
            return "done"

        result = await do_thing(user=make_user())
        assert result == "done"
        mock_px.enter_scope.assert_called_once()
        scope_ctx.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_no_user_raises(self) -> None:
        mock_px, _ = self._make_proxilion_mock()

        @enforce_scope(mock_px, "admin")
        async def do_thing(user=None, **kwargs):
            return "done"

        with pytest.raises(AuthorizationError):
            await do_thing()

    @pytest.mark.asyncio
    async def test_async_closes_scope_on_error(self) -> None:
        mock_px, scope_ctx = self._make_proxilion_mock()

        @enforce_scope(mock_px, "read_only")
        async def do_thing(user=None, **kwargs):
            raise RuntimeError("boom")

        with pytest.raises(RuntimeError):
            await do_thing(user=make_user())
        scope_ctx.close.assert_called_once()


# =============================================================================
# scoped_tool Tests
# =============================================================================


class TestScopedTool:
    def test_sync_validates_scope(self) -> None:
        mock_px = MagicMock()
        scope_ctx = MagicMock()

        @scoped_tool(mock_px, action="delete")
        def delete_item(item_id, user=None, **kwargs):
            return f"deleted {item_id}"

        result = delete_item("123", user=make_user(), _scope_context=scope_ctx)
        assert result == "deleted 123"
        scope_ctx.validate_tool.assert_called_once_with("delete_item", "delete")

    def test_sync_no_scope_context_skips_validation(self) -> None:
        mock_px = MagicMock()

        @scoped_tool(mock_px)
        def do_thing(user=None, **kwargs):
            return "done"

        result = do_thing(user=make_user())
        assert result == "done"

    def test_sync_custom_tool_name(self) -> None:
        mock_px = MagicMock()
        scope_ctx = MagicMock()

        @scoped_tool(mock_px, tool_name="custom_tool", action="read")
        def do_thing(user=None, **kwargs):
            return "done"

        do_thing(user=make_user(), _scope_context=scope_ctx)
        scope_ctx.validate_tool.assert_called_once_with("custom_tool", "read")

    def test_scope_context_not_passed_to_function(self) -> None:
        """The _scope_context param should be stripped before calling the function."""
        mock_px = MagicMock()
        scope_ctx = MagicMock()

        @scoped_tool(mock_px)
        def do_thing(**kwargs):
            assert "_scope_context" not in kwargs
            return "done"

        do_thing(_scope_context=scope_ctx)

    @pytest.mark.asyncio
    async def test_async_validates_scope(self) -> None:
        mock_px = MagicMock()
        scope_ctx = MagicMock()

        @scoped_tool(mock_px, action="write")
        async def write_item(data, user=None, **kwargs):
            return f"wrote {data}"

        result = await write_item("hello", user=make_user(), _scope_context=scope_ctx)
        assert result == "wrote hello"
        scope_ctx.validate_tool.assert_called_once_with("write_item", "write")

    @pytest.mark.asyncio
    async def test_async_no_scope_context(self) -> None:
        mock_px = MagicMock()

        @scoped_tool(mock_px)
        async def do_thing(user=None, **kwargs):
            return "done"

        result = await do_thing(user=make_user())
        assert result == "done"


# =============================================================================
# cost_limited Tests
# =============================================================================


class TestCostLimited:
    def _make_cost_limiter(self, allowed=True):
        limiter = MagicMock()
        result_mock = MagicMock()
        result_mock.allowed = allowed
        limiter.check_limit.return_value = result_mock
        limiter.record_spend = MagicMock()
        # Remove allow_request to use CostLimiter path
        del limiter.allow_request
        del limiter.record_usage
        return limiter

    def _make_hybrid_limiter(self, allowed=True):
        limiter = MagicMock()
        limiter.allow_request.return_value = (allowed, "reason")
        limiter.record_usage = MagicMock()
        return limiter

    def test_sync_allowed(self) -> None:
        limiter = self._make_cost_limiter(allowed=True)

        @cost_limited(limiter, estimate_cost=0.05)
        def do_thing(user=None):
            return "done"

        result = do_thing(user=make_user())
        assert result == "done"
        limiter.check_limit.assert_called_once()
        limiter.record_spend.assert_called_once()

    def test_sync_denied(self) -> None:
        limiter = self._make_cost_limiter(allowed=False)

        @cost_limited(limiter, estimate_cost=0.05)
        def do_thing(user=None):
            return "done"

        with pytest.raises(BudgetExceededError):
            do_thing(user=make_user())

    def test_sync_callable_estimate(self) -> None:
        limiter = self._make_cost_limiter(allowed=True)

        def estimate(model="gpt-4", **kw):
            return 0.10 if model == "gpt-4" else 0.01

        @cost_limited(limiter, estimate_cost=estimate)
        def do_thing(model="gpt-4", user=None):
            return "done"

        do_thing(model="gpt-4", user=make_user())
        limiter.check_limit.assert_called_once()

    def test_sync_no_record(self) -> None:
        limiter = self._make_cost_limiter(allowed=True)

        @cost_limited(limiter, estimate_cost=0.01, record_actual=False)
        def do_thing(user=None):
            return "done"

        do_thing(user=make_user())
        limiter.record_spend.assert_not_called()

    def test_sync_anonymous_user(self) -> None:
        limiter = self._make_cost_limiter(allowed=True)

        @cost_limited(limiter, estimate_cost=0.01)
        def do_thing():
            return "done"

        result = do_thing()
        assert result == "done"

    def test_sync_hybrid_limiter(self) -> None:
        limiter = self._make_hybrid_limiter(allowed=True)

        @cost_limited(limiter, estimate_cost=0.05)
        def do_thing(user=None):
            return "done"

        result = do_thing(user=make_user())
        assert result == "done"
        limiter.allow_request.assert_called_once()
        limiter.record_usage.assert_called_once()

    def test_sync_hybrid_limiter_denied(self) -> None:
        limiter = self._make_hybrid_limiter(allowed=False)

        @cost_limited(limiter, estimate_cost=0.05)
        def do_thing(user=None):
            return "done"

        with pytest.raises(BudgetExceededError):
            do_thing(user=make_user())

    @pytest.mark.asyncio
    async def test_async_allowed(self) -> None:
        limiter = self._make_cost_limiter(allowed=True)

        @cost_limited(limiter, estimate_cost=0.05)
        async def do_thing(user=None):
            return "done"

        result = await do_thing(user=make_user())
        assert result == "done"
        limiter.check_limit.assert_called_once()
        limiter.record_spend.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_denied(self) -> None:
        limiter = self._make_cost_limiter(allowed=False)

        @cost_limited(limiter, estimate_cost=0.05)
        async def do_thing(user=None):
            return "done"

        with pytest.raises(BudgetExceededError):
            await do_thing(user=make_user())

    @pytest.mark.asyncio
    async def test_async_hybrid_limiter(self) -> None:
        limiter = self._make_hybrid_limiter(allowed=True)

        @cost_limited(limiter, estimate_cost=0.02)
        async def do_thing(user=None):
            return "done"

        result = await do_thing(user=make_user())
        assert result == "done"
        limiter.allow_request.assert_called_once()

    def test_preserves_function_name(self) -> None:
        limiter = self._make_cost_limiter()

        @cost_limited(limiter, estimate_cost=0.01)
        def my_function(user=None):
            return "done"

        assert my_function.__name__ == "my_function"
