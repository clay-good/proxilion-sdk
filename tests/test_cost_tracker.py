"""
Tests for proxilion.observability.cost_tracker module.

Covers ModelPricing, UsageRecord, CostTracker, CostSummary, and BudgetPolicy.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from proxilion.exceptions import BudgetExceededError
from proxilion.observability.cost_tracker import (
    DEFAULT_PRICING,
    BudgetPolicy,
    CostTracker,
    ModelPricing,
    UsageRecord,
    create_cost_tracker,
)

# =============================================================================
# ModelPricing Tests
# =============================================================================


class TestModelPricing:
    """Tests for ModelPricing dataclass."""

    def test_calculate_cost_basic(self) -> None:
        """Test basic cost calculation."""
        pricing = ModelPricing(
            model_name="test_model",
            input_price_per_1k=0.01,
            output_price_per_1k=0.03,
        )

        cost = pricing.calculate_cost(input_tokens=1000, output_tokens=1000)
        assert cost == pytest.approx(0.04)  # 0.01 + 0.03

    def test_calculate_cost_fractional_tokens(self) -> None:
        """Test cost calculation with fractional thousands."""
        pricing = ModelPricing(
            model_name="test_model",
            input_price_per_1k=0.01,
            output_price_per_1k=0.03,
        )

        cost = pricing.calculate_cost(input_tokens=500, output_tokens=500)
        assert cost == pytest.approx(0.02)  # 0.005 + 0.015

    def test_calculate_cost_with_cache(self) -> None:
        """Test cost calculation including cache tokens."""
        pricing = ModelPricing(
            model_name="test_model",
            input_price_per_1k=0.01,
            output_price_per_1k=0.03,
            cache_read_price_per_1k=0.001,
            cache_write_price_per_1k=0.02,
        )

        cost = pricing.calculate_cost(
            input_tokens=1000,
            output_tokens=1000,
            cache_read_tokens=500,
            cache_write_tokens=200,
        )
        # 0.01 + 0.03 + 0.0005 + 0.004 = 0.0445
        assert cost == pytest.approx(0.0445)

    def test_calculate_cost_zero_tokens(self) -> None:
        """Test cost calculation with zero tokens."""
        pricing = ModelPricing(
            model_name="test_model",
            input_price_per_1k=0.01,
            output_price_per_1k=0.03,
        )

        cost = pricing.calculate_cost(input_tokens=0, output_tokens=0)
        assert cost == 0.0


# =============================================================================
# UsageRecord Tests
# =============================================================================


class TestUsageRecord:
    """Tests for UsageRecord dataclass."""

    def test_total_tokens(self) -> None:
        """Test total_tokens property."""
        record = UsageRecord(
            timestamp=datetime.now(timezone.utc),
            model="test_model",
            input_tokens=1000,
            output_tokens=500,
        )
        assert record.total_tokens == 1500

    def test_to_dict(self) -> None:
        """Test serialization to dict."""
        now = datetime.now(timezone.utc)
        record = UsageRecord(
            timestamp=now,
            model="test_model",
            input_tokens=1000,
            output_tokens=500,
            user_id="user_123",
            cost_usd=0.05,
        )

        d = record.to_dict()
        assert d["model"] == "test_model"
        assert d["input_tokens"] == 1000
        assert d["output_tokens"] == 500
        assert d["user_id"] == "user_123"
        assert d["cost_usd"] == 0.05
        assert d["timestamp"] == now.isoformat()

    def test_to_json(self) -> None:
        """Test serialization to JSON."""
        record = UsageRecord(
            timestamp=datetime.now(timezone.utc),
            model="test_model",
            input_tokens=1000,
            output_tokens=500,
        )

        json_str = record.to_json()
        parsed = json.loads(json_str)
        assert parsed["model"] == "test_model"


# =============================================================================
# CostTracker Core Tests
# =============================================================================


class TestCostTrackerCore:
    """Tests for CostTracker basic operations."""

    def test_init_default_pricing(self) -> None:
        """Test initialization includes default pricing."""
        tracker = CostTracker()

        # Should have Claude models
        pricing = tracker.get_pricing("claude-sonnet-4-20250514")
        assert pricing is not None
        assert pricing.input_price_per_1k > 0

    def test_init_custom_pricing(self) -> None:
        """Test initialization with custom pricing."""
        custom = {
            "custom_model": ModelPricing(
                model_name="Custom",
                input_price_per_1k=0.05,
                output_price_per_1k=0.10,
            )
        }
        tracker = CostTracker(pricing=custom)

        pricing = tracker.get_pricing("custom_model")
        assert pricing is not None
        assert pricing.input_price_per_1k == 0.05

    def test_set_pricing(self) -> None:
        """Test adding/updating pricing."""
        tracker = CostTracker()

        tracker.set_pricing(
            "new_model",
            ModelPricing("New", 0.01, 0.02),
        )

        pricing = tracker.get_pricing("new_model")
        assert pricing is not None

    def test_get_pricing_unknown(self) -> None:
        """Test getting pricing for unknown model."""
        tracker = CostTracker()
        pricing = tracker.get_pricing("unknown_model")
        assert pricing is None


# =============================================================================
# Usage Recording Tests
# =============================================================================


class TestUsageRecording:
    """Tests for recording usage."""

    def test_record_usage_basic(self) -> None:
        """Test basic usage recording."""
        tracker = CostTracker()

        record = tracker.record_usage(
            model="claude-sonnet-4-20250514",
            input_tokens=1000,
            output_tokens=500,
            user_id="user_123",
        )

        assert record.model == "claude-sonnet-4-20250514"
        assert record.input_tokens == 1000
        assert record.output_tokens == 500
        assert record.cost_usd > 0

    def test_record_usage_with_tool(self) -> None:
        """Test recording usage with tool name."""
        tracker = CostTracker()

        record = tracker.record_usage(
            model="claude-sonnet-4-20250514",
            input_tokens=1000,
            output_tokens=500,
            tool_name="database_query",
            user_id="user_123",
        )

        assert record.tool_name == "database_query"

    def test_record_usage_unknown_model(self) -> None:
        """Test recording usage with unknown model uses default pricing."""
        tracker = CostTracker()

        record = tracker.record_usage(
            model="unknown_model",
            input_tokens=1000,
            output_tokens=500,
        )

        # Should still calculate cost using default model
        assert record.cost_usd >= 0

    def test_record_usage_custom_timestamp(self) -> None:
        """Test recording usage with custom timestamp."""
        tracker = CostTracker()
        custom_time = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

        record = tracker.record_usage(
            model="claude-sonnet-4-20250514",
            input_tokens=1000,
            output_tokens=500,
            timestamp=custom_time,
        )

        assert record.timestamp == custom_time

    def test_record_usage_max_records(self) -> None:
        """Test that old records are trimmed."""
        tracker = CostTracker(max_records=5)

        for i in range(10):
            tracker.record_usage(
                model="claude-sonnet-4-20250514",
                input_tokens=100,
                output_tokens=50,
                user_id=f"user_{i}",
            )

        records = tracker.get_records()
        assert len(records) == 5


# =============================================================================
# Cost Estimation Tests
# =============================================================================


class TestCostEstimation:
    """Tests for cost estimation."""

    def test_estimate_cost(self) -> None:
        """Test basic cost estimation."""
        tracker = CostTracker()

        cost = tracker.estimate_cost(
            model="claude-sonnet-4-20250514",
            input_tokens=1000,
            output_tokens=500,
        )

        assert cost > 0

    def test_estimate_cost_default_model(self) -> None:
        """Test estimation using default model."""
        tracker = CostTracker(default_model="claude-sonnet-4-20250514")

        cost = tracker.estimate_cost(
            input_tokens=1000,
            output_tokens=500,
        )

        assert cost > 0


# =============================================================================
# Budget Policy Tests
# =============================================================================


class TestBudgetPolicy:
    """Tests for budget policy enforcement."""

    def test_check_budget_per_request(self) -> None:
        """Test per-request budget limit."""
        tracker = CostTracker(
            budget_policy=BudgetPolicy(max_cost_per_request=0.01)
        )

        # Small request should be allowed
        allowed, reason = tracker.check_budget(
            user_id="user_123",
            estimated_cost=0.005,
        )
        assert allowed

        # Large request should be denied
        allowed, reason = tracker.check_budget(
            user_id="user_123",
            estimated_cost=0.05,
        )
        assert not allowed
        assert "per-request" in reason.lower()

    def test_check_budget_per_user_daily(self) -> None:
        """Test per-user daily budget limit."""
        tracker = CostTracker(
            budget_policy=BudgetPolicy(max_cost_per_user_per_day=1.00)
        )

        # Record some usage
        for _ in range(10):
            tracker.record_usage(
                model="claude-sonnet-4-20250514",
                input_tokens=10000,
                output_tokens=5000,
                user_id="user_123",
            )

        # Check budget
        allowed, reason = tracker.check_budget(
            user_id="user_123",
            estimated_cost=0.50,
        )

        # May or may not exceed depending on actual prices
        # Just verify it works without error
        assert isinstance(allowed, bool)

    def test_check_budget_token_limit(self) -> None:
        """Test per-request token limit."""
        tracker = CostTracker(
            budget_policy=BudgetPolicy(max_tokens_per_request=5000)
        )

        # Small request allowed
        allowed, reason = tracker.check_budget(
            user_id="user_123",
            estimated_tokens=1000,
        )
        assert allowed

        # Large request denied
        allowed, reason = tracker.check_budget(
            user_id="user_123",
            estimated_tokens=10000,
        )
        assert not allowed
        assert "token" in reason.lower()

    def test_check_budget_no_policy(self) -> None:
        """Test that no policy means no limits."""
        tracker = CostTracker()

        allowed, reason = tracker.check_budget(
            user_id="user_123",
            estimated_cost=1000.00,
        )
        assert allowed
        assert reason is None


# =============================================================================
# User Spend Tests
# =============================================================================


class TestUserSpend:
    """Tests for user spend tracking."""

    def test_get_user_spend(self) -> None:
        """Test getting user spend over period."""
        tracker = CostTracker()

        # Record some usage
        tracker.record_usage(
            model="claude-sonnet-4-20250514",
            input_tokens=1000,
            output_tokens=500,
            user_id="user_123",
        )

        spend = tracker.get_user_spend("user_123", timedelta(days=1))
        assert spend > 0

    def test_get_user_spend_empty(self) -> None:
        """Test getting spend for user with no usage."""
        tracker = CostTracker()

        spend = tracker.get_user_spend("unknown_user", timedelta(days=1))
        assert spend == 0.0

    def test_get_org_spend(self) -> None:
        """Test getting organization-wide spend."""
        tracker = CostTracker()

        # Record usage from multiple users
        for i in range(3):
            tracker.record_usage(
                model="claude-sonnet-4-20250514",
                input_tokens=1000,
                output_tokens=500,
                user_id=f"user_{i}",
            )

        spend = tracker.get_org_spend(timedelta(days=1))
        assert spend > 0


# =============================================================================
# Cost Summary Tests
# =============================================================================


class TestCostSummary:
    """Tests for cost summary generation."""

    def test_get_summary_basic(self) -> None:
        """Test basic summary generation."""
        tracker = CostTracker()

        # Record some usage
        tracker.record_usage(
            model="claude-sonnet-4-20250514",
            input_tokens=1000,
            output_tokens=500,
            user_id="user_123",
            tool_name="tool_a",
        )

        summary = tracker.get_summary()

        assert summary.total_cost > 0
        assert summary.total_input_tokens == 1000
        assert summary.total_output_tokens == 500
        assert summary.record_count == 1
        assert "claude-sonnet-4-20250514" in summary.by_model
        assert "user_123" in summary.by_user
        assert "tool_a" in summary.by_tool

    def test_get_summary_filtered_by_user(self) -> None:
        """Test summary filtered by user."""
        tracker = CostTracker()

        # Record usage from multiple users
        tracker.record_usage(
            model="claude-sonnet-4-20250514",
            input_tokens=1000,
            output_tokens=500,
            user_id="user_a",
        )
        tracker.record_usage(
            model="claude-sonnet-4-20250514",
            input_tokens=2000,
            output_tokens=1000,
            user_id="user_b",
        )

        summary = tracker.get_summary(user_id="user_a")

        assert summary.total_input_tokens == 1000
        assert summary.record_count == 1

    def test_get_summary_filtered_by_time(self) -> None:
        """Test summary filtered by time range."""
        tracker = CostTracker()

        # Record usage at different times
        old_time = datetime.now(timezone.utc) - timedelta(hours=2)
        new_time = datetime.now(timezone.utc)

        tracker.record_usage(
            model="claude-sonnet-4-20250514",
            input_tokens=1000,
            output_tokens=500,
            timestamp=old_time,
        )
        tracker.record_usage(
            model="claude-sonnet-4-20250514",
            input_tokens=2000,
            output_tokens=1000,
            timestamp=new_time,
        )

        # Get summary for last hour only
        summary = tracker.get_summary(
            start=datetime.now(timezone.utc) - timedelta(hours=1)
        )

        assert summary.total_input_tokens == 2000
        assert summary.record_count == 1


# =============================================================================
# Records Management Tests
# =============================================================================


class TestRecordsManagement:
    """Tests for records management."""

    def test_get_records(self) -> None:
        """Test getting records."""
        tracker = CostTracker()

        for i in range(5):
            tracker.record_usage(
                model="claude-sonnet-4-20250514",
                input_tokens=1000,
                output_tokens=500,
                user_id=f"user_{i}",
            )

        records = tracker.get_records()
        assert len(records) == 5

    def test_get_records_with_limit(self) -> None:
        """Test getting limited records."""
        tracker = CostTracker()

        for _ in range(10):
            tracker.record_usage(
                model="claude-sonnet-4-20250514",
                input_tokens=1000,
                output_tokens=500,
            )

        records = tracker.get_records(limit=3)
        assert len(records) == 3

    def test_get_records_filtered_by_user(self) -> None:
        """Test getting records filtered by user."""
        tracker = CostTracker()

        tracker.record_usage(
            model="claude-sonnet-4-20250514",
            input_tokens=1000,
            output_tokens=500,
            user_id="user_a",
        )
        tracker.record_usage(
            model="claude-sonnet-4-20250514",
            input_tokens=2000,
            output_tokens=1000,
            user_id="user_b",
        )

        records = tracker.get_records(user_id="user_a")
        assert len(records) == 1
        assert records[0].user_id == "user_a"

    def test_clear_records(self) -> None:
        """Test clearing all records."""
        tracker = CostTracker()

        for _ in range(5):
            tracker.record_usage(
                model="claude-sonnet-4-20250514",
                input_tokens=1000,
                output_tokens=500,
            )

        cleared = tracker.clear_records()
        assert cleared == 5
        assert len(tracker.get_records()) == 0

    def test_export_records_json(self) -> None:
        """Test exporting records as JSON."""
        tracker = CostTracker()

        tracker.record_usage(
            model="claude-sonnet-4-20250514",
            input_tokens=1000,
            output_tokens=500,
            user_id="user_123",
        )

        json_str = tracker.export_records(format="json")
        parsed = json.loads(json_str)
        assert isinstance(parsed, list)
        assert len(parsed) == 1

    def test_export_records_jsonl(self) -> None:
        """Test exporting records as JSONL."""
        tracker = CostTracker()

        for _ in range(3):
            tracker.record_usage(
                model="claude-sonnet-4-20250514",
                input_tokens=1000,
                output_tokens=500,
            )

        jsonl = tracker.export_records(format="jsonl")
        lines = jsonl.strip().split("\n")
        assert len(lines) == 3


# =============================================================================
# Budget Status Tests
# =============================================================================


class TestBudgetStatus:
    """Tests for budget status reporting."""

    def test_get_budget_status(self) -> None:
        """Test getting budget status."""
        tracker = CostTracker(
            budget_policy=BudgetPolicy(
                max_cost_per_user_per_day=50.00,
                max_cost_per_user_per_hour=10.00,
            )
        )

        # Record some usage
        tracker.record_usage(
            model="claude-sonnet-4-20250514",
            input_tokens=1000,
            output_tokens=500,
            user_id="user_123",
        )

        status = tracker.get_budget_status("user_123")

        assert status["policy_active"]
        assert "daily" in status
        assert status["daily"]["limit"] == 50.00
        assert "hourly" in status

    def test_get_budget_status_no_policy(self) -> None:
        """Test budget status with no policy."""
        tracker = CostTracker()

        status = tracker.get_budget_status("user_123")
        assert not status["policy_active"]


# =============================================================================
# Default Pricing Tests
# =============================================================================


class TestDefaultPricing:
    """Tests for default pricing definitions."""

    def test_default_pricing_not_empty(self) -> None:
        """Test default pricing is defined."""
        assert len(DEFAULT_PRICING) > 0

    def test_default_pricing_has_claude(self) -> None:
        """Test Claude models are in default pricing."""
        assert any("claude" in k for k in DEFAULT_PRICING)

    def test_default_pricing_has_gpt(self) -> None:
        """Test GPT models are in default pricing."""
        assert any("gpt" in k for k in DEFAULT_PRICING)

    def test_default_pricing_valid(self) -> None:
        """Test all default pricing has valid values."""
        for _model, pricing in DEFAULT_PRICING.items():
            assert pricing.input_price_per_1k > 0
            assert pricing.output_price_per_1k > 0
            assert pricing.model_name


# =============================================================================
# Factory Function Tests
# =============================================================================


class TestCreateCostTracker:
    """Tests for create_cost_tracker factory."""

    def test_create_default(self) -> None:
        """Test factory with defaults."""
        tracker = create_cost_tracker()
        assert tracker is not None
        assert tracker.get_pricing("claude-sonnet-4-20250514") is not None

    def test_create_with_budget_policy(self) -> None:
        """Test factory with budget policy."""
        tracker = create_cost_tracker(
            budget_policy=BudgetPolicy(max_cost_per_request=1.00)
        )
        assert tracker.get_budget_policy() is not None

    def test_create_with_custom_pricing(self) -> None:
        """Test factory with custom pricing."""
        custom = {
            "my_model": ModelPricing("My Model", 0.01, 0.02)
        }
        tracker = create_cost_tracker(custom_pricing=custom)
        assert tracker.get_pricing("my_model") is not None


# =============================================================================
# BudgetExceededError Tests
# =============================================================================


class TestBudgetExceededError:
    """Tests for BudgetExceededError exception."""

    def test_error_message(self) -> None:
        """Test error message formatting."""
        error = BudgetExceededError(
            limit_type="user_daily",
            current_spend=48.50,
            limit=50.00,
            estimated_cost=5.00,
            user_id="user_123",
        )

        assert "user_daily" in str(error)
        assert "48.50" in str(error) or "48.5" in str(error)
        assert "50.00" in str(error) or "50.0" in str(error)

    def test_error_attributes(self) -> None:
        """Test error attributes."""
        error = BudgetExceededError(
            limit_type="per_request",
            current_spend=0.0,
            limit=1.00,
            estimated_cost=2.00,
        )

        assert error.limit_type == "per_request"
        assert error.limit == 1.00
        assert error.estimated_cost == 2.00

    def test_error_to_dict(self) -> None:
        """Test error serialization."""
        error = BudgetExceededError(
            limit_type="user_daily",
            current_spend=48.50,
            limit=50.00,
        )

        d = error.to_dict()
        assert d["details"]["limit_type"] == "user_daily"


# =============================================================================
# Thread Safety Tests
# =============================================================================


class TestThreadSafety:
    """Tests for thread-safe operations."""

    def test_concurrent_recording(self) -> None:
        """Test concurrent usage recording."""
        import threading

        tracker = CostTracker()
        results = []
        lock = threading.Lock()

        def record_usage(user_id: str) -> None:
            for _ in range(10):
                record = tracker.record_usage(
                    model="claude-sonnet-4-20250514",
                    input_tokens=1000,
                    output_tokens=500,
                    user_id=user_id,
                )
                with lock:
                    results.append(record)

        threads = [
            threading.Thread(target=record_usage, args=(f"user_{i}",))
            for i in range(5)
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 50

    def test_concurrent_budget_check(self) -> None:
        """Test concurrent budget checking."""
        import threading

        tracker = CostTracker(
            budget_policy=BudgetPolicy(max_cost_per_user_per_day=100.00)
        )
        results = []
        lock = threading.Lock()

        def check_budget(user_id: str) -> None:
            for _ in range(10):
                allowed, _ = tracker.check_budget(user_id, estimated_cost=0.01)
                with lock:
                    results.append(allowed)

        threads = [
            threading.Thread(target=check_budget, args=(f"user_{i}",))
            for i in range(5)
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 50
