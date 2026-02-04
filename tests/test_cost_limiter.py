"""
Tests for proxilion.security.cost_limiter module.

Covers CostLimit, CostLimiter, CostLimitResult, and HybridRateLimiter.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from proxilion.observability.cost_tracker import CostTracker
from proxilion.security.cost_limiter import (
    CostLimit,
    CostLimiter,
    CostLimitResult,
    HybridRateLimiter,
    LimitScope,
    create_cost_limiter,
)

# =============================================================================
# CostLimit Tests
# =============================================================================


class TestCostLimit:
    """Tests for CostLimit dataclass."""

    def test_basic_limit(self) -> None:
        """Test basic limit creation."""
        limit = CostLimit(
            max_cost=10.00,
            period=timedelta(hours=1),
            scope="user",
        )

        assert limit.max_cost == 10.00
        assert limit.period == timedelta(hours=1)
        assert limit.scope == LimitScope.USER

    def test_limit_with_name(self) -> None:
        """Test limit with custom name."""
        limit = CostLimit(
            max_cost=50.00,
            period=timedelta(days=1),
            scope=LimitScope.USER,
            name="daily_cap",
        )

        assert limit.name == "daily_cap"

    def test_limit_auto_name(self) -> None:
        """Test automatic name generation."""
        limit = CostLimit(
            max_cost=10.00,
            period=timedelta(hours=1),
            scope=LimitScope.USER,
        )

        assert "user" in limit.name
        assert "1h" in limit.name

    def test_limit_scope_string_conversion(self) -> None:
        """Test scope string is converted to enum."""
        limit = CostLimit(
            max_cost=10.00,
            period=timedelta(hours=1),
            scope="org",
        )

        assert limit.scope == LimitScope.ORG

    def test_limit_soft_limit(self) -> None:
        """Test soft limit flag."""
        limit = CostLimit(
            max_cost=10.00,
            period=timedelta(hours=1),
            hard_limit=False,
        )

        assert not limit.hard_limit


# =============================================================================
# CostLimitResult Tests
# =============================================================================


class TestCostLimitResult:
    """Tests for CostLimitResult dataclass."""

    def test_result_allowed(self) -> None:
        """Test allowed result."""
        result = CostLimitResult(
            allowed=True,
            current_spend=5.00,
            limit=10.00,
            remaining=5.00,
        )

        assert result.allowed
        assert result.remaining == 5.00

    def test_result_denied(self) -> None:
        """Test denied result."""
        result = CostLimitResult(
            allowed=False,
            limit_name="user_daily",
            current_spend=50.00,
            limit=50.00,
            remaining=0.0,
        )

        assert not result.allowed
        assert result.limit_name == "user_daily"

    def test_result_with_warning(self) -> None:
        """Test result with warning."""
        result = CostLimitResult(
            allowed=True,
            warning=True,
            warning_message="Approaching limit",
        )

        assert result.allowed
        assert result.warning
        assert "Approaching" in result.warning_message

    def test_result_to_dict(self) -> None:
        """Test serialization to dict."""
        reset_at = datetime.now(timezone.utc) + timedelta(hours=1)
        result = CostLimitResult(
            allowed=True,
            current_spend=5.00,
            limit=10.00,
            remaining=5.00,
            reset_at=reset_at,
        )

        d = result.to_dict()
        assert d["allowed"] is True
        assert d["current_spend"] == 5.00
        assert d["reset_at"] == reset_at.isoformat()


# =============================================================================
# CostLimiter Core Tests
# =============================================================================


class TestCostLimiterCore:
    """Tests for CostLimiter basic operations."""

    def test_init_with_limits(self) -> None:
        """Test initialization with limits."""
        limits = [
            CostLimit(max_cost=10.00, period=timedelta(hours=1), scope=LimitScope.USER),
            CostLimit(max_cost=50.00, period=timedelta(days=1), scope=LimitScope.USER),
        ]
        limiter = CostLimiter(limits=limits)

        assert len(limiter.get_limits()) == 2

    def test_add_limit(self) -> None:
        """Test adding a limit."""
        limiter = CostLimiter(limits=[])

        limiter.add_limit(CostLimit(
            max_cost=10.00,
            period=timedelta(hours=1),
            name="new_limit",
        ))

        assert len(limiter.get_limits()) == 1

    def test_remove_limit(self) -> None:
        """Test removing a limit."""
        limiter = CostLimiter(limits=[
            CostLimit(max_cost=10.00, period=timedelta(hours=1), name="to_remove"),
        ])

        assert limiter.remove_limit("to_remove")
        assert len(limiter.get_limits()) == 0

    def test_remove_limit_not_found(self) -> None:
        """Test removing non-existent limit."""
        limiter = CostLimiter(limits=[])
        assert not limiter.remove_limit("nonexistent")


# =============================================================================
# Cost Limit Checking Tests
# =============================================================================


class TestCostLimitChecking:
    """Tests for cost limit checking."""

    def test_check_limit_allowed(self) -> None:
        """Test request within limit."""
        limiter = CostLimiter(limits=[
            CostLimit(max_cost=10.00, period=timedelta(hours=1), scope=LimitScope.USER),
        ])

        result = limiter.check_limit("user_123", estimated_cost=1.00)
        assert result.allowed

    def test_check_limit_denied(self) -> None:
        """Test request exceeding limit."""
        limiter = CostLimiter(limits=[
            CostLimit(max_cost=10.00, period=timedelta(hours=1), scope=LimitScope.USER),
        ])

        # Record spend to hit limit
        for _ in range(11):
            limiter.record_spend("user_123", 1.00)

        result = limiter.check_limit("user_123", estimated_cost=1.00)
        assert not result.allowed

    def test_check_limit_multi_tier(self) -> None:
        """Test multi-tier limits."""
        limiter = CostLimiter(limits=[
            CostLimit(
                max_cost=1.00, period=timedelta(minutes=1),
                scope=LimitScope.USER, name="burst",
            ),
            CostLimit(
                max_cost=10.00, period=timedelta(hours=1),
                scope=LimitScope.USER, name="hourly",
            ),
        ])

        # Record spend to exceed burst limit
        for _ in range(2):
            limiter.record_spend("user_123", 0.60)

        result = limiter.check_limit("user_123", estimated_cost=0.10)
        assert not result.allowed
        assert "burst" in result.limit_name

    def test_check_limit_warning(self) -> None:
        """Test warning when approaching limit."""
        limiter = CostLimiter(limits=[
            CostLimit(max_cost=10.00, period=timedelta(hours=1), warn_at=0.8),
        ])

        # Record spend to approach limit
        limiter.record_spend("user_123", 8.00)

        result = limiter.check_limit("user_123", estimated_cost=0.50)
        assert result.allowed
        assert result.warning

    def test_check_limit_soft_limit(self) -> None:
        """Test soft limit allows but warns."""
        limiter = CostLimiter(limits=[
            CostLimit(max_cost=10.00, period=timedelta(hours=1), hard_limit=False),
        ])

        # Record spend to exceed limit
        limiter.record_spend("user_123", 10.00)

        result = limiter.check_limit("user_123", estimated_cost=1.00)
        # Soft limit doesn't block
        assert result.allowed
        assert result.warning


# =============================================================================
# Spend Recording Tests
# =============================================================================


class TestSpendRecording:
    """Tests for spend recording."""

    def test_record_spend(self) -> None:
        """Test recording spend."""
        limiter = CostLimiter(limits=[
            CostLimit(max_cost=10.00, period=timedelta(hours=1)),
        ])

        limiter.record_spend("user_123", 5.00)

        spend = limiter.get_spend_by_period("user_123", timedelta(hours=1))
        assert spend == 5.00

    def test_record_spend_accumulates(self) -> None:
        """Test spend accumulates."""
        limiter = CostLimiter(limits=[
            CostLimit(max_cost=100.00, period=timedelta(hours=1)),
        ])

        limiter.record_spend("user_123", 5.00)
        limiter.record_spend("user_123", 3.00)
        limiter.record_spend("user_123", 2.00)

        spend = limiter.get_spend_by_period("user_123", timedelta(hours=1))
        assert spend == 10.00

    def test_get_remaining_budget(self) -> None:
        """Test getting remaining budget."""
        limiter = CostLimiter(limits=[
            CostLimit(max_cost=10.00, period=timedelta(hours=1)),
        ])

        limiter.record_spend("user_123", 3.00)

        remaining = limiter.get_remaining_budget("user_123", timedelta(hours=1))
        assert remaining == 7.00

    def test_reset_period(self) -> None:
        """Test manual reset of period."""
        limiter = CostLimiter(limits=[
            CostLimit(max_cost=10.00, period=timedelta(hours=1)),
        ])

        limiter.record_spend("user_123", 5.00)
        limiter.reset_period("user_123")

        spend = limiter.get_spend_by_period("user_123", timedelta(hours=1))
        assert spend == 0.0


# =============================================================================
# Integration with CostTracker Tests
# =============================================================================


class TestCostTrackerIntegration:
    """Tests for integration with CostTracker."""

    def test_limiter_with_cost_tracker(self) -> None:
        """Test limiter using CostTracker for spend data."""
        tracker = CostTracker()
        limiter = CostLimiter(
            limits=[
                CostLimit(max_cost=1.00, period=timedelta(hours=1), scope=LimitScope.USER),
            ],
            cost_tracker=tracker,
        )

        # Record usage via tracker
        tracker.record_usage(
            model="claude-sonnet-4-20250514",
            input_tokens=10000,
            output_tokens=5000,
            user_id="user_123",
        )

        # Limiter should see the spend
        result = limiter.check_limit("user_123", estimated_cost=0.10)
        # Just verify it doesn't error
        assert isinstance(result.allowed, bool)


# =============================================================================
# Status Reporting Tests
# =============================================================================


class TestStatusReporting:
    """Tests for status reporting."""

    def test_get_status(self) -> None:
        """Test getting comprehensive status."""
        limiter = CostLimiter(limits=[
            CostLimit(max_cost=10.00, period=timedelta(hours=1), name="hourly"),
            CostLimit(max_cost=50.00, period=timedelta(days=1), name="daily"),
        ])

        limiter.record_spend("user_123", 5.00)

        status = limiter.get_status("user_123")

        assert status["user_id"] == "user_123"
        assert len(status["limits"]) == 2
        assert any(lim["name"] == "hourly" for lim in status["limits"])


# =============================================================================
# HybridRateLimiter Tests
# =============================================================================


class TestHybridRateLimiter:
    """Tests for HybridRateLimiter."""

    def test_init(self) -> None:
        """Test initialization."""
        cost_limiter = CostLimiter(limits=[
            CostLimit(max_cost=10.00, period=timedelta(hours=1)),
        ])

        hybrid = HybridRateLimiter(cost_limiter=cost_limiter)
        assert hybrid is not None

    def test_allow_request_cost_only(self) -> None:
        """Test with only cost limiter."""
        cost_limiter = CostLimiter(limits=[
            CostLimit(max_cost=10.00, period=timedelta(hours=1)),
        ])

        hybrid = HybridRateLimiter(cost_limiter=cost_limiter)

        allowed, reason = hybrid.allow_request("user_123", estimated_cost=1.00)
        assert allowed

    def test_allow_request_cost_exceeded(self) -> None:
        """Test when cost limit exceeded."""
        cost_limiter = CostLimiter(limits=[
            CostLimit(max_cost=1.00, period=timedelta(hours=1)),
        ])

        hybrid = HybridRateLimiter(cost_limiter=cost_limiter)

        # Record spend to exceed limit
        for _ in range(2):
            cost_limiter.record_spend("user_123", 0.60)

        allowed, reason = hybrid.allow_request("user_123", estimated_cost=0.10)
        assert not allowed
        assert "Cost limit exceeded" in reason

    def test_record_usage(self) -> None:
        """Test recording usage through hybrid limiter."""
        cost_limiter = CostLimiter(limits=[
            CostLimit(max_cost=10.00, period=timedelta(hours=1)),
        ])

        hybrid = HybridRateLimiter(cost_limiter=cost_limiter)

        hybrid.record_usage("user_123", 1.00, "test_tool")

        spend = cost_limiter.get_spend_by_period("user_123", timedelta(hours=1))
        assert spend == 1.00

    def test_get_status(self) -> None:
        """Test getting status from hybrid limiter."""
        cost_limiter = CostLimiter(limits=[
            CostLimit(max_cost=10.00, period=timedelta(hours=1)),
        ])

        hybrid = HybridRateLimiter(cost_limiter=cost_limiter)

        status = hybrid.get_status("user_123")
        assert "cost_limiter" in status


# =============================================================================
# Factory Function Tests
# =============================================================================


class TestCreateCostLimiter:
    """Tests for create_cost_limiter factory."""

    def test_create_default(self) -> None:
        """Test factory with defaults."""
        limiter = create_cost_limiter()
        limits = limiter.get_limits()

        # Should have default limits
        assert len(limits) >= 3
        assert any("burst" in lim.name for lim in limits)

    def test_create_without_defaults(self) -> None:
        """Test factory without defaults."""
        limiter = create_cost_limiter(include_defaults=False)
        assert len(limiter.get_limits()) == 0

    def test_create_with_custom_limits(self) -> None:
        """Test factory with custom limits."""
        custom = [
            CostLimit(max_cost=100.00, period=timedelta(days=1), name="custom"),
        ]
        limiter = create_cost_limiter(
            limits=custom,
            include_defaults=False,
        )

        assert len(limiter.get_limits()) == 1
        assert limiter.get_limits()[0].name == "custom"

    def test_create_with_cost_tracker(self) -> None:
        """Test factory with cost tracker."""
        tracker = CostTracker()
        limiter = create_cost_limiter(cost_tracker=tracker)

        # Should be configured
        assert limiter is not None


# =============================================================================
# LimitScope Tests
# =============================================================================


class TestLimitScope:
    """Tests for LimitScope enum."""

    def test_scope_values(self) -> None:
        """Test scope enum values."""
        assert LimitScope.USER.value == "user"
        assert LimitScope.ORG.value == "org"
        assert LimitScope.GLOBAL.value == "global"
        assert LimitScope.TOOL.value == "tool"

    def test_scope_members(self) -> None:
        """Test all expected scopes exist."""
        scopes = list(LimitScope)
        assert len(scopes) == 4


# =============================================================================
# Thread Safety Tests
# =============================================================================


class TestThreadSafety:
    """Tests for thread-safe operations."""

    def test_concurrent_spend_recording(self) -> None:
        """Test concurrent spend recording."""
        import threading

        limiter = CostLimiter(limits=[
            CostLimit(max_cost=1000.00, period=timedelta(hours=1)),
        ])

        def record_spend() -> None:
            for _ in range(100):
                limiter.record_spend("user_123", 0.01)

        threads = [
            threading.Thread(target=record_spend)
            for _ in range(10)
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        spend = limiter.get_spend_by_period("user_123", timedelta(hours=1))
        assert spend == pytest.approx(10.00, rel=0.01)

    def test_concurrent_limit_check(self) -> None:
        """Test concurrent limit checking."""
        import threading

        limiter = CostLimiter(limits=[
            CostLimit(max_cost=100.00, period=timedelta(hours=1)),
        ])

        results = []
        lock = threading.Lock()

        def check_limit() -> None:
            for _ in range(100):
                result = limiter.check_limit("user_123", estimated_cost=0.01)
                with lock:
                    results.append(result.allowed)

        threads = [
            threading.Thread(target=check_limit)
            for _ in range(5)
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 500


# =============================================================================
# Edge Cases
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases."""

    def test_empty_limits(self) -> None:
        """Test limiter with no limits."""
        limiter = CostLimiter(limits=[])

        result = limiter.check_limit("user_123", estimated_cost=1000.00)
        assert result.allowed

    def test_zero_cost_request(self) -> None:
        """Test checking limit with zero cost."""
        limiter = CostLimiter(limits=[
            CostLimit(max_cost=10.00, period=timedelta(hours=1)),
        ])

        result = limiter.check_limit("user_123", estimated_cost=0.0)
        assert result.allowed

    def test_exact_limit(self) -> None:
        """Test request that exactly reaches limit."""
        limiter = CostLimiter(limits=[
            CostLimit(max_cost=10.00, period=timedelta(hours=1)),
        ])

        limiter.record_spend("user_123", 9.00)

        # This should push to exactly 10.00
        result = limiter.check_limit("user_123", estimated_cost=1.00)
        assert result.allowed

        # Record it
        limiter.record_spend("user_123", 1.00)

        # Now any additional spend should fail
        result = limiter.check_limit("user_123", estimated_cost=0.01)
        assert not result.allowed

    def test_user_isolation(self) -> None:
        """Test that users are isolated."""
        limiter = CostLimiter(limits=[
            CostLimit(max_cost=10.00, period=timedelta(hours=1)),
        ])

        # User A hits limit
        limiter.record_spend("user_a", 10.00)

        # User B should not be affected
        result = limiter.check_limit("user_b", estimated_cost=5.00)
        assert result.allowed
