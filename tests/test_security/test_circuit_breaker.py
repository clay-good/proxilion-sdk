"""
Tests for circuit breaker implementation.

Tests cover:
- CircuitBreaker state transitions
- Failure counting and threshold
- Reset timeout
- Half-open state behavior
- CircuitBreakerRegistry
"""

from __future__ import annotations

import contextlib
import time

import pytest

from proxilion.exceptions import CircuitOpenError
from proxilion.security.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerRegistry,
    CircuitState,
    CircuitStats,
)


class TestCircuitBreakerStates:
    """Tests for circuit breaker state transitions."""

    def test_initial_state_is_closed(self, circuit_breaker: CircuitBreaker):
        """Test that initial state is CLOSED."""
        assert circuit_breaker.state == CircuitState.CLOSED

    def test_stays_closed_on_success(self, circuit_breaker: CircuitBreaker):
        """Test that successful calls keep circuit closed."""
        def success_func():
            return "success"

        for _ in range(10):
            result = circuit_breaker.call(success_func)
            assert result == "success"

        assert circuit_breaker.state == CircuitState.CLOSED

    def test_opens_after_failure_threshold(self):
        """Test that circuit opens after reaching failure threshold."""
        breaker = CircuitBreaker(failure_threshold=3, reset_timeout=10)

        def failing_func():
            raise ValueError("Failure!")

        # Cause 3 failures
        for _ in range(3):
            with pytest.raises(ValueError):
                breaker.call(failing_func)

        assert breaker.state == CircuitState.OPEN

    def test_open_circuit_raises_error(self):
        """Test that open circuit raises CircuitOpenError."""
        breaker = CircuitBreaker(failure_threshold=1, reset_timeout=10)

        def failing_func():
            raise ValueError("Failure!")

        # Open the circuit
        with pytest.raises(ValueError):
            breaker.call(failing_func)

        assert breaker.state == CircuitState.OPEN

        # Next call should raise CircuitOpenError
        with pytest.raises(CircuitOpenError):
            breaker.call(lambda: "should not execute")

    def test_transitions_to_half_open_after_timeout(self):
        """Test that circuit transitions to HALF_OPEN after timeout."""
        breaker = CircuitBreaker(failure_threshold=1, reset_timeout=0.1)

        def failing_func():
            raise ValueError("Failure!")

        # Open the circuit
        with pytest.raises(ValueError):
            breaker.call(failing_func)

        assert breaker.state == CircuitState.OPEN

        # Wait for timeout
        time.sleep(0.2)

        # State should be HALF_OPEN now (checked on next call attempt)
        # The next call will be allowed to test if service recovered
        def success_func():
            return "recovered"

        result = breaker.call(success_func)
        assert result == "recovered"
        assert breaker.state == CircuitState.CLOSED

    def test_half_open_closes_on_success(self):
        """Test that HALF_OPEN state closes on successful call."""
        breaker = CircuitBreaker(failure_threshold=1, reset_timeout=0.1, half_open_max=1)

        call_count = 0

        def sometimes_fails():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise ValueError("First call fails")
            return "success"

        # First call fails, opens circuit
        with pytest.raises(ValueError):
            breaker.call(sometimes_fails)

        assert breaker.state == CircuitState.OPEN

        # Wait for timeout
        time.sleep(0.15)

        # Next call succeeds, should close circuit
        result = breaker.call(sometimes_fails)
        assert result == "success"
        assert breaker.state == CircuitState.CLOSED

    def test_half_open_reopens_on_failure(self):
        """Test that HALF_OPEN state reopens on failure."""
        breaker = CircuitBreaker(failure_threshold=1, reset_timeout=0.1, half_open_max=1)

        def always_fails():
            raise ValueError("Always fails!")

        # Open the circuit
        with pytest.raises(ValueError):
            breaker.call(always_fails)

        # Wait for timeout
        time.sleep(0.15)

        # Try again in half-open state, fails again
        with pytest.raises(ValueError):
            breaker.call(always_fails)

        # Should be back to OPEN
        assert breaker.state == CircuitState.OPEN


class TestCircuitBreakerStats:
    """Tests for circuit breaker statistics."""

    def test_stats_initialization(self, circuit_breaker: CircuitBreaker):
        """Test that stats are initialized to zero."""
        stats = circuit_breaker.stats
        assert isinstance(stats, CircuitStats)
        assert stats.failures == 0
        assert stats.successes == 0

    def test_stats_count_successes(self, circuit_breaker: CircuitBreaker):
        """Test that successful calls are counted."""
        for _ in range(5):
            circuit_breaker.call(lambda: "success")

        stats = circuit_breaker.stats
        assert stats.successes == 5
        assert stats.failures == 0

    def test_stats_count_failures(self):
        """Test that failed calls are counted."""
        breaker = CircuitBreaker(failure_threshold=10, reset_timeout=10)

        for _ in range(3):
            with contextlib.suppress(ValueError):
                breaker.call(lambda: (_ for _ in ()).throw(ValueError("fail")))

        stats = breaker.stats
        assert stats.failures == 3

    def test_stats_reset(self, circuit_breaker: CircuitBreaker):
        """Test resetting statistics."""
        circuit_breaker.call(lambda: "success")
        circuit_breaker.reset()

        stats = circuit_breaker.stats
        assert stats.successes == 0
        assert stats.failures == 0


class TestCircuitBreakerRegistry:
    """Tests for CircuitBreakerRegistry."""

    def test_registry_initialization(self, circuit_breaker_registry: CircuitBreakerRegistry):
        """Test registry initialization."""
        assert circuit_breaker_registry is not None

    def test_get_or_create_breaker(self, circuit_breaker_registry: CircuitBreakerRegistry):
        """Test getting or creating a circuit breaker."""
        breaker = circuit_breaker_registry.get("tool_a")
        assert isinstance(breaker, CircuitBreaker)

        # Getting same name returns same instance
        breaker2 = circuit_breaker_registry.get("tool_a")
        assert breaker is breaker2

    def test_different_tools_different_breakers(
        self, circuit_breaker_registry: CircuitBreakerRegistry,
    ):
        """Test that different tools get different breakers."""
        breaker_a = circuit_breaker_registry.get("tool_a")
        breaker_b = circuit_breaker_registry.get("tool_b")

        assert breaker_a is not breaker_b

    def test_registry_with_custom_config(self):
        """Test registry with custom per-tool configuration."""
        registry = CircuitBreakerRegistry(
            default_config={
                "failure_threshold": 5,
                "reset_timeout": 30,
            }
        )

        breaker = registry.get("custom_tool")
        # Breaker should use default config
        assert breaker.failure_threshold == 5
        assert breaker.reset_timeout == 30

    def test_list_breakers(self, circuit_breaker_registry: CircuitBreakerRegistry):
        """Test listing all circuit breakers."""
        circuit_breaker_registry.get("tool_1")
        circuit_breaker_registry.get("tool_2")
        circuit_breaker_registry.get("tool_3")

        all_stats = circuit_breaker_registry.get_all_stats()
        assert "tool_1" in all_stats
        assert "tool_2" in all_stats
        assert "tool_3" in all_stats

    def test_get_all_stats(self, circuit_breaker_registry: CircuitBreakerRegistry):
        """Test getting stats for all breakers."""
        breaker_a = circuit_breaker_registry.get("tool_a")
        breaker_b = circuit_breaker_registry.get("tool_b")

        breaker_a.call(lambda: "success")
        breaker_b.call(lambda: "success")
        breaker_b.call(lambda: "success")

        all_stats = circuit_breaker_registry.get_all_stats()
        assert "tool_a" in all_stats
        assert "tool_b" in all_stats
        assert all_stats["tool_a"]["successes"] == 1
        assert all_stats["tool_b"]["successes"] == 2


class TestCircuitBreakerAsync:
    """Tests for async circuit breaker functionality."""

    @pytest.mark.asyncio
    async def test_async_call_success(self, circuit_breaker: CircuitBreaker):
        """Test async call with success."""
        async def async_success():
            return "async success"

        result = await circuit_breaker.call_async(async_success)
        assert result == "async success"

    @pytest.mark.asyncio
    async def test_async_call_failure(self):
        """Test async call with failure."""
        breaker = CircuitBreaker(failure_threshold=1, reset_timeout=10)

        async def async_failure():
            raise ValueError("Async failure!")

        with pytest.raises(ValueError):
            await breaker.call_async(async_failure)

        assert breaker.state == CircuitState.OPEN

    @pytest.mark.asyncio
    async def test_async_circuit_open_error(self):
        """Test async raises CircuitOpenError when open."""
        breaker = CircuitBreaker(failure_threshold=1, reset_timeout=10)

        async def async_failure():
            raise ValueError("Failure!")

        # Open the circuit
        with pytest.raises(ValueError):
            await breaker.call_async(async_failure)

        # Next call should raise CircuitOpenError
        with pytest.raises(CircuitOpenError):
            await breaker.call_async(lambda: "should not run")


class TestCircuitBreakerEdgeCases:
    """Tests for edge cases and special scenarios."""

    def test_manual_open(self, circuit_breaker: CircuitBreaker):
        """Test manually opening the circuit."""
        circuit_breaker.force_open()
        assert circuit_breaker.state == CircuitState.OPEN

    def test_manual_close(self):
        """Test manually closing the circuit."""
        breaker = CircuitBreaker(failure_threshold=1, reset_timeout=100)

        # Open it
        with contextlib.suppress(ValueError):
            breaker.call(lambda: (_ for _ in ()).throw(ValueError()))

        assert breaker.state == CircuitState.OPEN

        # Manually close via reset
        breaker.reset()
        assert breaker.state == CircuitState.CLOSED

    def test_reset_clears_failure_count(self):
        """Test that reset clears the failure count."""
        breaker = CircuitBreaker(failure_threshold=3, reset_timeout=10)

        # Cause 2 failures (not enough to open)
        for _ in range(2):
            with contextlib.suppress(ValueError):
                breaker.call(lambda: (_ for _ in ()).throw(ValueError()))

        # Reset
        breaker.reset()

        # Should be able to have 2 more failures without opening
        for _ in range(2):
            with contextlib.suppress(ValueError):
                breaker.call(lambda: (_ for _ in ()).throw(ValueError()))

        # Still closed (only 2 failures since reset)
        assert breaker.state == CircuitState.CLOSED
