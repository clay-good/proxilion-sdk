"""
Tests for the resilience module.

Tests cover:
- Retry with exponential backoff
- Max attempts and retry conditions
- Jitter application
- Fallback chain execution
- Model and tool fallbacks
- Degradation tier management
- Auto-degradation and recovery
"""

import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from proxilion.resilience.degradation import (
    DegradationTier,
    GracefulDegradation,
    TierConfig,
)
from proxilion.resilience.fallback import (
    FallbackChain,
    FallbackCondition,
    FallbackOption,
    FallbackResult,
    ModelFallback,
    ToolFallback,
)
from proxilion.resilience.retry import (
    RetryBudget,
    RetryContext,
    RetryPolicy,
    RetryStats,
    retry_with_backoff,
)

# ==================== RetryPolicy Tests ====================


class TestRetryPolicy:
    """Tests for RetryPolicy dataclass."""

    def test_default_policy(self):
        """Test default policy values."""
        policy = RetryPolicy()
        assert policy.max_attempts == 3
        assert policy.base_delay == 1.0
        assert policy.max_delay == 30.0
        assert policy.exponential_base == 2.0
        assert policy.jitter == 0.1

    def test_custom_policy(self):
        """Test creating a custom policy."""
        policy = RetryPolicy(
            max_attempts=5,
            base_delay=0.5,
            max_delay=60.0,
            exponential_base=3.0,
            jitter=0.2,
        )
        assert policy.max_attempts == 5
        assert policy.base_delay == 0.5

    def test_invalid_max_attempts(self):
        """Test validation of max_attempts."""
        with pytest.raises(ValueError, match="max_attempts must be at least 1"):
            RetryPolicy(max_attempts=0)

    def test_invalid_base_delay(self):
        """Test validation of base_delay."""
        with pytest.raises(ValueError, match="base_delay must be non-negative"):
            RetryPolicy(base_delay=-1.0)

    def test_invalid_max_delay(self):
        """Test validation of max_delay."""
        with pytest.raises(ValueError, match="max_delay must be >= base_delay"):
            RetryPolicy(base_delay=10.0, max_delay=5.0)

    def test_invalid_exponential_base(self):
        """Test validation of exponential_base."""
        with pytest.raises(ValueError, match="exponential_base must be >= 1"):
            RetryPolicy(exponential_base=0.5)

    def test_invalid_jitter(self):
        """Test validation of jitter."""
        with pytest.raises(ValueError, match="jitter must be between 0 and 1"):
            RetryPolicy(jitter=1.5)

    def test_calculate_delay_exponential(self):
        """Test exponential delay calculation."""
        policy = RetryPolicy(base_delay=1.0, exponential_base=2.0, jitter=0.0)

        assert policy.calculate_delay(1) == 1.0  # 1 * 2^0
        assert policy.calculate_delay(2) == 2.0  # 1 * 2^1
        assert policy.calculate_delay(3) == 4.0  # 1 * 2^2
        assert policy.calculate_delay(4) == 8.0  # 1 * 2^3

    def test_calculate_delay_capped(self):
        """Test delay is capped at max_delay."""
        policy = RetryPolicy(
            base_delay=1.0, max_delay=5.0, exponential_base=2.0, jitter=0.0
        )

        assert policy.calculate_delay(10) == 5.0  # Capped

    def test_calculate_delay_with_jitter(self):
        """Test jitter is applied to delay."""
        policy = RetryPolicy(base_delay=10.0, jitter=0.1)

        delays = [policy.calculate_delay(1) for _ in range(100)]

        # All delays should be between 9.0 and 11.0
        assert all(9.0 <= d <= 11.0 for d in delays)
        # Should have some variation (not all exactly 10.0)
        assert len(set(delays)) > 1

    def test_should_retry_within_attempts(self):
        """Test should_retry within max_attempts."""
        policy = RetryPolicy(max_attempts=3, retryable_exceptions=(ValueError,))

        assert policy.should_retry(ValueError("test"), attempt=1) is True
        assert policy.should_retry(ValueError("test"), attempt=2) is True
        assert policy.should_retry(ValueError("test"), attempt=3) is False

    def test_should_retry_non_retryable_exception(self):
        """Test should_retry with non-retryable exception."""
        policy = RetryPolicy(max_attempts=3, retryable_exceptions=(ValueError,))

        assert policy.should_retry(TypeError("test"), attempt=1) is False

    def test_should_retry_custom_function(self):
        """Test should_retry with custom retry_on function."""
        policy = RetryPolicy(
            max_attempts=5,
            retry_on=lambda e: "retry" in str(e),
        )

        assert policy.should_retry(Exception("please retry"), attempt=1) is True
        assert policy.should_retry(Exception("no"), attempt=1) is False


# ==================== RetryContext Tests ====================


class TestRetryContext:
    """Tests for RetryContext dataclass."""

    def test_create_context(self):
        """Test creating a retry context."""
        exc = ValueError("test")
        context = RetryContext(
            attempt=2,
            total_delay=1.5,
            last_exception=exc,
            should_retry=True,
        )

        assert context.attempt == 2
        assert context.total_delay == 1.5
        assert context.last_exception == exc
        assert context.should_retry is True

    def test_elapsed(self):
        """Test elapsed time calculation."""
        context = RetryContext(
            attempt=1,
            total_delay=0,
            last_exception=None,
            should_retry=True,
        )

        time.sleep(0.1)
        elapsed = context.elapsed()
        assert elapsed >= 0.1


# ==================== RetryStats Tests ====================


class TestRetryStats:
    """Tests for RetryStats dataclass."""

    def test_initial_stats(self):
        """Test initial stats are zero."""
        stats = RetryStats()
        assert stats.total_attempts == 0
        assert stats.successful_attempts == 0
        assert stats.failed_attempts == 0
        assert stats.total_delay == 0.0

    def test_record_success(self):
        """Test recording a successful attempt."""
        stats = RetryStats()
        stats.record_attempt(success=True, delay=0.5)

        assert stats.total_attempts == 1
        assert stats.successful_attempts == 1
        assert stats.failed_attempts == 0
        assert stats.total_delay == 0.5

    def test_record_failure(self):
        """Test recording a failed attempt."""
        stats = RetryStats()
        exc = ValueError("test")
        stats.record_attempt(success=False, exception=exc)

        assert stats.total_attempts == 1
        assert stats.failed_attempts == 1
        assert exc in stats.exceptions

    def test_success_rate(self):
        """Test success rate calculation."""
        stats = RetryStats()
        stats.record_attempt(success=True)
        stats.record_attempt(success=True)
        stats.record_attempt(success=False)

        assert stats.success_rate == 2 / 3

    def test_success_rate_no_attempts(self):
        """Test success rate with no attempts."""
        stats = RetryStats()
        assert stats.success_rate == 0.0

    def test_to_dict(self):
        """Test conversion to dictionary."""
        stats = RetryStats()
        stats.record_attempt(success=True)
        stats.record_attempt(success=False, exception=ValueError("test"))

        d = stats.to_dict()
        assert d["total_attempts"] == 2
        assert d["successful_attempts"] == 1
        assert d["failed_attempts"] == 1
        assert "ValueError" in d["exception_types"]


# ==================== RetryBudget Tests ====================


class TestRetryBudget:
    """Tests for RetryBudget class."""

    def test_initial_budget(self):
        """Test initial budget allows retries."""
        budget = RetryBudget(max_retries_per_second=10)

        # Should allow several retries
        for _ in range(10):
            assert budget.allow_retry() is True

    def test_budget_exhaustion(self):
        """Test budget exhaustion."""
        budget = RetryBudget(max_retries_per_second=2)

        # Exhaust budget
        assert budget.allow_retry() is True
        assert budget.allow_retry() is True
        assert budget.allow_retry() is False

    def test_budget_refill(self):
        """Test budget refills over time."""
        budget = RetryBudget(max_retries_per_second=10)

        # Exhaust some budget
        for _ in range(5):
            budget.allow_retry()

        # Wait for partial refill
        time.sleep(0.3)

        # Should have refilled some tokens
        assert budget.available_tokens > 5

    def test_reset(self):
        """Test budget reset."""
        budget = RetryBudget(max_retries_per_second=10)

        # Exhaust budget
        for _ in range(10):
            budget.allow_retry()

        budget.reset()
        assert budget.available_tokens == 10.0


# ==================== retry_with_backoff Tests ====================


class TestRetryWithBackoff:
    """Tests for retry_with_backoff decorator."""

    def test_decorator_sync_success(self):
        """Test decorator with sync function that succeeds."""
        call_count = 0

        @retry_with_backoff(RetryPolicy(max_attempts=3))
        def success_func():
            nonlocal call_count
            call_count += 1
            return "success"

        result = success_func()
        assert result == "success"
        assert call_count == 1

    def test_decorator_sync_retry(self):
        """Test decorator with sync function that retries."""
        call_count = 0

        @retry_with_backoff(
            RetryPolicy(max_attempts=3, base_delay=0.01, retryable_exceptions=(ValueError,))
        )
        def retry_func():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("retry")
            return "success"

        result = retry_func()
        assert result == "success"
        assert call_count == 3

    def test_decorator_sync_all_fail(self):
        """Test decorator with sync function that always fails."""

        @retry_with_backoff(
            RetryPolicy(max_attempts=3, base_delay=0.01, retryable_exceptions=(ValueError,))
        )
        def fail_func():
            raise ValueError("always fail")

        with pytest.raises(ValueError, match="always fail"):
            fail_func()

    @pytest.mark.asyncio
    async def test_decorator_async_success(self):
        """Test decorator with async function that succeeds."""
        call_count = 0

        @retry_with_backoff(RetryPolicy(max_attempts=3))
        async def success_func():
            nonlocal call_count
            call_count += 1
            return "success"

        result = await success_func()
        assert result == "success"
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_decorator_async_retry(self):
        """Test decorator with async function that retries."""
        call_count = 0

        @retry_with_backoff(
            RetryPolicy(max_attempts=3, base_delay=0.01, retryable_exceptions=(ValueError,))
        )
        async def retry_func():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("retry")
            return "success"

        result = await retry_func()
        assert result == "success"
        assert call_count == 3

    def test_on_retry_callback(self):
        """Test on_retry callback is called."""
        contexts = []
        call_count = 0

        @retry_with_backoff(
            RetryPolicy(max_attempts=3, base_delay=0.01, retryable_exceptions=(ValueError,)),
            on_retry=lambda ctx: contexts.append(ctx),
        )
        def retry_func():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("retry")
            return "success"

        retry_func()
        assert len(contexts) == 2  # Called before 2nd and 3rd attempts


# ==================== FallbackOption Tests ====================


class TestFallbackOption:
    """Tests for FallbackOption dataclass."""

    def test_create_option(self):
        """Test creating a fallback option."""
        handler = MagicMock()
        option = FallbackOption(
            name="test",
            handler=handler,
            priority=1,
        )

        assert option.name == "test"
        assert option.handler == handler
        assert option.priority == 1
        assert option.enabled is True

    def test_matches_condition_always(self):
        """Test condition matching with ALWAYS."""
        option = FallbackOption(
            name="test",
            handler=MagicMock(),
            conditions={FallbackCondition.ALWAYS},
        )

        assert option.matches_condition(ValueError("any error")) is True

    def test_matches_condition_on_timeout(self):
        """Test condition matching with ON_TIMEOUT."""
        option = FallbackOption(
            name="test",
            handler=MagicMock(),
            conditions={FallbackCondition.ON_TIMEOUT},
        )

        assert option.matches_condition(TimeoutError("timeout")) is True
        assert option.matches_condition(ValueError("other")) is False

    def test_matches_condition_on_rate_limit(self):
        """Test condition matching with ON_RATE_LIMIT."""
        option = FallbackOption(
            name="test",
            handler=MagicMock(),
            conditions={FallbackCondition.ON_RATE_LIMIT},
        )

        assert option.matches_condition(Exception("rate limit exceeded")) is True
        assert option.matches_condition(Exception("429 Too Many Requests")) is True
        assert option.matches_condition(ValueError("other")) is False

    def test_matches_condition_disabled(self):
        """Test condition matching when disabled."""
        option = FallbackOption(
            name="test",
            handler=MagicMock(),
            conditions={FallbackCondition.ALWAYS},
            enabled=False,
        )

        assert option.matches_condition(ValueError("test")) is False


# ==================== FallbackResult Tests ====================


class TestFallbackResult:
    """Tests for FallbackResult dataclass."""

    def test_successful_result(self):
        """Test successful result."""
        result = FallbackResult(
            success=True,
            result="data",
            used_fallback=False,
            fallback_name="primary",
            attempts=1,
        )

        assert result.success is True
        assert result.result == "data"
        assert result.used_fallback is False

    def test_fallback_result(self):
        """Test result from fallback."""
        result = FallbackResult(
            success=True,
            result="data",
            used_fallback=True,
            fallback_name="backup",
            attempts=2,
        )

        assert result.used_fallback is True
        assert result.fallback_name == "backup"

    def test_to_dict(self):
        """Test conversion to dictionary."""
        result = FallbackResult(
            success=True,
            result="data",
            fallback_name="test",
            attempts=1,
            execution_time=0.5,
        )

        d = result.to_dict()
        assert d["success"] is True
        assert d["fallback_name"] == "test"


# ==================== FallbackChain Tests ====================


class TestFallbackChain:
    """Tests for FallbackChain class."""

    def test_create_empty_chain(self):
        """Test creating an empty chain."""
        chain = FallbackChain()
        assert len(chain) == 0

    def test_add_option(self):
        """Test adding options to chain."""
        chain = FallbackChain()
        option = FallbackOption("test", MagicMock(), priority=1)

        chain.add_option(option)
        assert len(chain) == 1

    def test_options_sorted_by_priority(self):
        """Test options are sorted by priority."""
        chain = FallbackChain()
        chain.add_option(FallbackOption("low", MagicMock(), priority=3))
        chain.add_option(FallbackOption("high", MagicMock(), priority=1))
        chain.add_option(FallbackOption("mid", MagicMock(), priority=2))

        options = chain.get_options()
        assert options[0].name == "high"
        assert options[1].name == "mid"
        assert options[2].name == "low"

    def test_remove_option(self):
        """Test removing an option."""
        chain = FallbackChain()
        chain.add_option(FallbackOption("test", MagicMock()))

        assert chain.remove_option("test") is True
        assert len(chain) == 0
        assert chain.remove_option("nonexistent") is False

    def test_enable_disable_option(self):
        """Test enabling/disabling options."""
        chain = FallbackChain()
        chain.add_option(FallbackOption("test", MagicMock()))

        assert chain.disable_option("test") is True
        assert chain.get_options()[0].enabled is False

        assert chain.enable_option("test") is True
        assert chain.get_options()[0].enabled is True

    def test_execute_sync_success(self):
        """Test sync execution success."""
        handler = MagicMock(return_value="result")
        chain = FallbackChain([FallbackOption("test", handler)])

        result = chain.execute()

        assert result.success is True
        assert result.result == "result"
        assert result.fallback_name == "test"

    def test_execute_sync_with_primary(self):
        """Test sync execution with primary handler."""
        primary = MagicMock(return_value="primary_result")
        fallback = MagicMock(return_value="fallback_result")

        chain = FallbackChain([FallbackOption("fallback", fallback)])
        result = chain.execute(primary=primary)

        assert result.success is True
        assert result.result == "primary_result"
        assert result.fallback_name == "primary"
        assert result.used_fallback is False

    def test_execute_sync_fallback_on_failure(self):
        """Test sync execution falls back on failure."""
        primary = MagicMock(side_effect=ValueError("fail"))
        fallback = MagicMock(return_value="fallback_result")

        chain = FallbackChain([FallbackOption("fallback", fallback)])
        result = chain.execute(primary=primary)

        assert result.success is True
        assert result.result == "fallback_result"
        assert result.used_fallback is True

    @pytest.mark.asyncio
    async def test_execute_async_success(self):
        """Test async execution success."""
        handler = AsyncMock(return_value="result")
        chain = FallbackChain([FallbackOption("test", handler)])

        result = await chain.execute_async()

        assert result.success is True
        assert result.result == "result"

    @pytest.mark.asyncio
    async def test_execute_async_fallback(self):
        """Test async execution fallback."""
        primary = AsyncMock(side_effect=ValueError("fail"))
        fallback = AsyncMock(return_value="fallback_result")

        chain = FallbackChain([FallbackOption("fallback", fallback)])
        result = await chain.execute_async(primary=primary)

        assert result.success is True
        assert result.result == "fallback_result"


# ==================== ModelFallback Tests ====================


class TestModelFallback:
    """Tests for ModelFallback class."""

    def test_create_model_fallback(self):
        """Test creating model fallback."""
        fallback = ModelFallback()
        assert len(fallback) == 0

    def test_add_model(self):
        """Test adding models."""
        fallback = ModelFallback()
        handler = AsyncMock(return_value="response")

        fallback.add_model("gpt-4o", handler)
        assert len(fallback) == 1

    @pytest.mark.asyncio
    async def test_complete(self):
        """Test model completion."""
        fallback = ModelFallback()
        handler = AsyncMock(return_value="Hello!")

        fallback.add_model("gpt-4o", handler)
        result = await fallback.complete(prompt="Hi")

        assert result.success is True
        assert result.result == "Hello!"

    @pytest.mark.asyncio
    async def test_get_model_stats(self):
        """Test model statistics."""
        fallback = ModelFallback()
        fallback.add_model("gpt-4o", AsyncMock(return_value="response"))

        await fallback.complete(prompt="test")  # Use complete to update stats

        stats = fallback.get_model_stats()
        assert "gpt-4o" in stats
        assert stats["gpt-4o"]["calls"] == 1


# ==================== ToolFallback Tests ====================


class TestToolFallback:
    """Tests for ToolFallback class."""

    def test_create_tool_fallback(self):
        """Test creating tool fallback."""
        fallback = ToolFallback()
        assert len(fallback) == 0

    def test_add_tool(self):
        """Test adding tools."""
        fallback = ToolFallback()
        handler = MagicMock(return_value={"result": "data"})

        fallback.add_tool("search", handler)
        assert len(fallback) == 1

    @pytest.mark.asyncio
    async def test_invoke(self):
        """Test tool invocation."""
        fallback = ToolFallback()
        handler = AsyncMock(return_value={"results": []})

        fallback.add_tool("search", handler)
        result = await fallback.invoke(query="test")

        assert result.success is True
        assert result.result == {"results": []}

    def test_invoke_sync(self):
        """Test sync tool invocation."""
        fallback = ToolFallback()
        handler = MagicMock(return_value={"results": []})

        fallback.add_tool("search", handler)
        result = fallback.invoke_sync(query="test")

        assert result.success is True


# ==================== DegradationTier Tests ====================


class TestDegradationTier:
    """Tests for DegradationTier enum."""

    def test_tier_comparison(self):
        """Test tier comparison."""
        assert DegradationTier.OFFLINE < DegradationTier.MINIMAL
        assert DegradationTier.MINIMAL < DegradationTier.REDUCED
        assert DegradationTier.REDUCED < DegradationTier.FULL

        assert DegradationTier.FULL > DegradationTier.REDUCED
        assert DegradationTier.FULL >= DegradationTier.FULL


# ==================== TierConfig Tests ====================


class TestTierConfig:
    """Tests for TierConfig dataclass."""

    def test_create_config(self):
        """Test creating tier config."""
        config = TierConfig(
            tier=DegradationTier.REDUCED,
            available_tools={"search", "calculator"},
            available_models=["gpt-4o-mini"],
            max_tokens=32000,
        )

        assert config.tier == DegradationTier.REDUCED
        assert config.max_tokens == 32000

    def test_is_tool_available_wildcard(self):
        """Test tool availability with wildcard."""
        config = TierConfig(
            tier=DegradationTier.FULL,
            available_tools={"*"},
        )

        assert config.is_tool_available("any_tool") is True

    def test_is_tool_available_specific(self):
        """Test tool availability with specific list."""
        config = TierConfig(
            tier=DegradationTier.REDUCED,
            available_tools={"search", "calculator"},
        )

        assert config.is_tool_available("search") is True
        assert config.is_tool_available("file_write") is False

    def test_is_model_available(self):
        """Test model availability."""
        config = TierConfig(
            tier=DegradationTier.REDUCED,
            available_models=["gpt-4o-mini"],
        )

        assert config.is_model_available("gpt-4o-mini") is True
        assert config.is_model_available("gpt-4o") is False

    def test_is_feature_enabled(self):
        """Test feature availability."""
        config = TierConfig(
            tier=DegradationTier.FULL,
            features={"streaming", "vision"},
        )

        assert config.is_feature_enabled("streaming") is True
        assert config.is_feature_enabled("code_execution") is False


# ==================== GracefulDegradation Tests ====================


class TestGracefulDegradation:
    """Tests for GracefulDegradation class."""

    def test_initial_tier(self):
        """Test initial tier is FULL."""
        degradation = GracefulDegradation()
        assert degradation.current_tier == DegradationTier.FULL

    def test_custom_initial_tier(self):
        """Test custom initial tier."""
        degradation = GracefulDegradation(initial_tier=DegradationTier.REDUCED)
        assert degradation.current_tier == DegradationTier.REDUCED

    def test_set_tier(self):
        """Test setting tier manually."""
        degradation = GracefulDegradation()
        degradation.set_tier(DegradationTier.REDUCED, reason="test")

        assert degradation.current_tier == DegradationTier.REDUCED

    def test_degrade(self):
        """Test degrading to next tier."""
        degradation = GracefulDegradation()

        assert degradation.degrade(reason="test") is True
        assert degradation.current_tier == DegradationTier.REDUCED

        assert degradation.degrade(reason="test") is True
        assert degradation.current_tier == DegradationTier.MINIMAL

        assert degradation.degrade(reason="test") is True
        assert degradation.current_tier == DegradationTier.OFFLINE

        # Can't degrade further
        assert degradation.degrade(reason="test") is False

    def test_recover(self):
        """Test recovering to higher tier."""
        degradation = GracefulDegradation(initial_tier=DegradationTier.OFFLINE)

        assert degradation.recover(reason="test") is True
        assert degradation.current_tier == DegradationTier.MINIMAL

        # Continue recovering
        degradation.recover()
        degradation.recover()
        assert degradation.current_tier == DegradationTier.FULL

        # Can't recover further
        assert degradation.recover(reason="test") is False

    def test_record_failure_auto_degrade(self):
        """Test auto-degradation on failures."""
        degradation = GracefulDegradation(failure_threshold=3)

        degradation.record_failure("api")
        assert degradation.current_tier == DegradationTier.FULL

        degradation.record_failure("api")
        assert degradation.current_tier == DegradationTier.FULL

        degradation.record_failure("api")
        assert degradation.current_tier == DegradationTier.REDUCED

    def test_record_success_auto_recover(self):
        """Test auto-recovery on successes."""
        degradation = GracefulDegradation(
            initial_tier=DegradationTier.REDUCED,
            recovery_threshold=3,
            auto_recover=True,
        )

        degradation.record_success("api")
        degradation.record_success("api")
        assert degradation.current_tier == DegradationTier.REDUCED

        degradation.record_success("api")
        assert degradation.current_tier == DegradationTier.FULL

    def test_is_tool_available(self):
        """Test tool availability at different tiers."""
        degradation = GracefulDegradation()

        assert degradation.is_tool_available("any_tool") is True

        degradation.set_tier(DegradationTier.MINIMAL)
        # Minimal tier has limited tools
        assert degradation.is_tool_available("search") is True

    def test_tier_change_callback(self):
        """Test tier change callbacks."""
        events = []
        degradation = GracefulDegradation()
        degradation.add_tier_change_callback(lambda e: events.append(e))

        degradation.degrade(reason="test")

        assert len(events) == 1
        assert events[0].from_tier == DegradationTier.FULL
        assert events[0].to_tier == DegradationTier.REDUCED

    def test_get_history(self):
        """Test getting tier change history."""
        degradation = GracefulDegradation()
        degradation.degrade(reason="reason1")
        degradation.degrade(reason="reason2")

        history = degradation.get_history()
        assert len(history) == 2

    def test_reset(self):
        """Test resetting degradation."""
        degradation = GracefulDegradation(initial_tier=DegradationTier.OFFLINE)
        degradation.record_failure("api")
        degradation.record_failure("api")

        degradation.reset()

        assert degradation.current_tier == DegradationTier.FULL
        assert degradation.get_failure_counts() == {}

    def test_to_dict(self):
        """Test conversion to dictionary."""
        degradation = GracefulDegradation()
        d = degradation.to_dict()

        assert "current_tier" in d
        assert d["current_tier"] == "FULL"


# ==================== Integration Tests ====================


class TestResilienceIntegration:
    """Integration tests for resilience components."""

    @pytest.mark.asyncio
    async def test_retry_with_fallback(self):
        """Test combining retry with fallback."""
        call_count = 0

        async def unreliable_primary():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("temporary failure")
            return "primary_result"

        async def reliable_backup():
            return "backup_result"

        # Create retry-wrapped handlers
        @retry_with_backoff(RetryPolicy(max_attempts=2, base_delay=0.01))
        async def retrying_primary():
            return await unreliable_primary()

        # Create fallback chain
        chain = FallbackChain([
            FallbackOption("backup", reliable_backup, priority=2),
        ])

        # Execute with retrying primary
        result = await chain.execute_async(primary=retrying_primary)

        # Should have used backup (primary failed after retries)
        assert result.success is True
        assert result.result == "backup_result"
        assert result.used_fallback is True

    @pytest.mark.asyncio
    async def test_degradation_with_fallback(self):
        """Test degradation affects fallback availability."""
        degradation = GracefulDegradation()

        # Set to minimal tier
        degradation.set_tier(DegradationTier.MINIMAL)

        # Check which tools are available
        available = degradation.is_tool_available("search")
        _unavailable = degradation.is_tool_available("code_execution")

        assert available is True  # search should be in minimal tier

    def test_full_resilience_pipeline(self):
        """Test complete resilience pipeline."""
        # Setup degradation
        degradation = GracefulDegradation(failure_threshold=2)

        # Simulate failures
        degradation.record_failure("external_api")
        degradation.record_failure("external_api")

        # Should have degraded
        assert degradation.current_tier == DegradationTier.REDUCED

        # Simulate recovery
        for _ in range(5):
            degradation.record_success("external_api")

        # Should have recovered
        assert degradation.current_tier == DegradationTier.FULL
