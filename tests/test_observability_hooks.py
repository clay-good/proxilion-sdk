"""Tests for proxilion.observability.hooks module."""

from __future__ import annotations

import logging
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from proxilion.observability import (
    MetricType,
    MetricHook,
    ObservabilityHooks,
    HistogramStats,
    LoggingMetricHook,
    InMemoryMetricHook,
    emit_counter,
    emit_gauge,
    emit_histogram,
    emit_timing,
    METRIC_AUTH_REQUESTS,
    METRIC_AUTH_ALLOWED,
    METRIC_AUTH_DENIED,
    METRIC_AUTH_LATENCY,
    METRIC_RATE_LIMIT_REQUESTS,
    METRIC_RATE_LIMIT_EXCEEDED,
    METRIC_TOOL_CALLS,
    METRIC_TOOL_LATENCY,
    METRIC_TOOL_ERRORS,
    METRIC_COST_USD,
    METRIC_TOKENS_INPUT,
    METRIC_TOKENS_OUTPUT,
    METRIC_CIRCUIT_BREAKER_OPEN,
    METRIC_CIRCUIT_BREAKER_HALF_OPEN,
    METRIC_CIRCUIT_BREAKER_CLOSED,
)


@pytest.fixture(autouse=True)
def reset_observability_hooks():
    """Reset the global ObservabilityHooks instance before each test."""
    ObservabilityHooks.reset_instance()
    yield
    ObservabilityHooks.reset_instance()


# =============================================================================
# MetricType Tests
# =============================================================================


class TestMetricType:
    """Tests for MetricType enum."""

    def test_metric_types_exist(self):
        """Test all metric types are defined."""
        assert MetricType.COUNTER.value == "counter"
        assert MetricType.GAUGE.value == "gauge"
        assert MetricType.HISTOGRAM.value == "histogram"
        assert MetricType.SUMMARY.value == "summary"
        assert MetricType.TIMING.value == "timing"

    def test_metric_type_count(self):
        """Test there are exactly 5 metric types."""
        assert len(MetricType) == 5


# =============================================================================
# MetricHook Protocol Tests
# =============================================================================


class TestMetricHookProtocol:
    """Tests for MetricHook protocol."""

    def test_protocol_methods(self):
        """Test that MetricHook defines all required methods."""

        class ValidHook:
            def increment(self, name: str, value: float = 1.0, tags: dict | None = None) -> None:
                pass

            def gauge(self, name: str, value: float, tags: dict | None = None) -> None:
                pass

            def histogram(self, name: str, value: float, tags: dict | None = None) -> None:
                pass

            def timing(self, name: str, duration_ms: float, tags: dict | None = None) -> None:
                pass

        hook = ValidHook()
        assert isinstance(hook, MetricHook)

    def test_protocol_detection(self):
        """Test that protocol detection works correctly."""

        class IncompleteHook:
            def increment(self, name: str, value: float = 1.0, tags: dict | None = None) -> None:
                pass

        # Missing gauge, histogram, timing - should not be a MetricHook
        hook = IncompleteHook()
        assert not isinstance(hook, MetricHook)

    def test_builtin_hooks_satisfy_protocol(self):
        """Test that built-in hooks satisfy the protocol."""
        logging_hook = LoggingMetricHook()
        memory_hook = InMemoryMetricHook()

        assert isinstance(logging_hook, MetricHook)
        assert isinstance(memory_hook, MetricHook)


# =============================================================================
# LoggingMetricHook Tests
# =============================================================================


class TestLoggingMetricHook:
    """Tests for LoggingMetricHook."""

    def test_default_logger(self):
        """Test hook creates default logger."""
        hook = LoggingMetricHook()
        assert hook.logger.name == "proxilion.metrics"

    def test_custom_logger(self):
        """Test hook accepts custom logger."""
        custom_logger = logging.getLogger("custom")
        hook = LoggingMetricHook(logger=custom_logger)
        assert hook.logger.name == "custom"

    def test_custom_level(self):
        """Test hook accepts custom log level."""
        hook = LoggingMetricHook(level=logging.INFO)
        assert hook.level == logging.INFO

    def test_increment_logs(self):
        """Test increment logs correctly."""
        hook = LoggingMetricHook()
        with patch.object(hook.logger, "log") as mock_log:
            hook.increment("requests", 1.0, {"user": "alice"})
            mock_log.assert_called_once_with(
                logging.DEBUG, "COUNTER requests=1.0 tags={'user': 'alice'}"
            )

    def test_increment_default_value(self):
        """Test increment with default value."""
        hook = LoggingMetricHook()
        with patch.object(hook.logger, "log") as mock_log:
            hook.increment("requests")
            mock_log.assert_called_once_with(logging.DEBUG, "COUNTER requests=1.0 tags=None")

    def test_gauge_logs(self):
        """Test gauge logs correctly."""
        hook = LoggingMetricHook()
        with patch.object(hook.logger, "log") as mock_log:
            hook.gauge("connections", 42.0, {"service": "api"})
            mock_log.assert_called_once_with(
                logging.DEBUG, "GAUGE connections=42.0 tags={'service': 'api'}"
            )

    def test_histogram_logs(self):
        """Test histogram logs correctly."""
        hook = LoggingMetricHook()
        with patch.object(hook.logger, "log") as mock_log:
            hook.histogram("response_size", 1024.0)
            mock_log.assert_called_once_with(logging.DEBUG, "HISTOGRAM response_size=1024.0 tags=None")

    def test_timing_logs(self):
        """Test timing logs correctly."""
        hook = LoggingMetricHook()
        with patch.object(hook.logger, "log") as mock_log:
            hook.timing("latency", 45.2, {"endpoint": "/api"})
            mock_log.assert_called_once_with(
                logging.DEBUG, "TIMING latency=45.2ms tags={'endpoint': '/api'}"
            )


# =============================================================================
# InMemoryMetricHook Tests
# =============================================================================


class TestInMemoryMetricHook:
    """Tests for InMemoryMetricHook."""

    def test_counter_increment(self):
        """Test basic counter increment."""
        hook = InMemoryMetricHook()
        hook.increment("requests")
        assert hook.get_counter("requests") == 1.0

    def test_counter_increment_by_value(self):
        """Test counter increment by specific value."""
        hook = InMemoryMetricHook()
        hook.increment("requests", 5.0)
        assert hook.get_counter("requests") == 5.0

    def test_counter_multiple_increments(self):
        """Test multiple counter increments accumulate."""
        hook = InMemoryMetricHook()
        hook.increment("requests", 1.0)
        hook.increment("requests", 2.0)
        hook.increment("requests", 3.0)
        assert hook.get_counter("requests") == 6.0

    def test_counter_with_tags(self):
        """Test counter with tags."""
        hook = InMemoryMetricHook()
        hook.increment("requests", tags={"user": "alice"})
        hook.increment("requests", tags={"user": "alice"})
        hook.increment("requests", tags={"user": "bob"})

        assert hook.get_counter("requests", {"user": "alice"}) == 2.0
        assert hook.get_counter("requests", {"user": "bob"}) == 1.0
        assert hook.get_counter("requests") == 0.0  # No tags

    def test_counter_tag_order_independent(self):
        """Test that tag order doesn't matter."""
        hook = InMemoryMetricHook()
        hook.increment("requests", tags={"user": "alice", "service": "api"})
        hook.increment("requests", tags={"service": "api", "user": "alice"})

        assert hook.get_counter("requests", {"user": "alice", "service": "api"}) == 2.0
        assert hook.get_counter("requests", {"service": "api", "user": "alice"}) == 2.0

    def test_counter_nonexistent(self):
        """Test getting nonexistent counter returns 0."""
        hook = InMemoryMetricHook()
        assert hook.get_counter("nonexistent") == 0.0

    def test_gauge_set(self):
        """Test gauge setting."""
        hook = InMemoryMetricHook()
        hook.gauge("connections", 42.0)
        assert hook.get_gauge("connections") == 42.0

    def test_gauge_overwrite(self):
        """Test gauge overwrites previous value."""
        hook = InMemoryMetricHook()
        hook.gauge("connections", 42.0)
        hook.gauge("connections", 100.0)
        assert hook.get_gauge("connections") == 100.0

    def test_gauge_with_tags(self):
        """Test gauge with tags."""
        hook = InMemoryMetricHook()
        hook.gauge("connections", 42.0, {"service": "api"})
        hook.gauge("connections", 10.0, {"service": "web"})

        assert hook.get_gauge("connections", {"service": "api"}) == 42.0
        assert hook.get_gauge("connections", {"service": "web"}) == 10.0

    def test_gauge_nonexistent(self):
        """Test getting nonexistent gauge returns None."""
        hook = InMemoryMetricHook()
        assert hook.get_gauge("nonexistent") is None

    def test_histogram_single_value(self):
        """Test histogram with single value."""
        hook = InMemoryMetricHook()
        hook.histogram("latency", 100.0)
        stats = hook.get_histogram_stats("latency")

        assert stats is not None
        assert stats.count == 1
        assert stats.total == 100.0
        assert stats.min == 100.0
        assert stats.max == 100.0
        assert stats.avg == 100.0

    def test_histogram_multiple_values(self):
        """Test histogram with multiple values."""
        hook = InMemoryMetricHook()
        hook.histogram("latency", 100.0)
        hook.histogram("latency", 200.0)
        hook.histogram("latency", 300.0)

        stats = hook.get_histogram_stats("latency")
        assert stats is not None
        assert stats.count == 3
        assert stats.total == 600.0
        assert stats.min == 100.0
        assert stats.max == 300.0
        assert stats.avg == 200.0

    def test_histogram_with_tags(self):
        """Test histogram with tags."""
        hook = InMemoryMetricHook()
        hook.histogram("latency", 100.0, {"endpoint": "/api/v1"})
        hook.histogram("latency", 200.0, {"endpoint": "/api/v1"})
        hook.histogram("latency", 50.0, {"endpoint": "/api/v2"})

        v1_stats = hook.get_histogram_stats("latency", {"endpoint": "/api/v1"})
        v2_stats = hook.get_histogram_stats("latency", {"endpoint": "/api/v2"})

        assert v1_stats is not None
        assert v1_stats.count == 2
        assert v1_stats.avg == 150.0

        assert v2_stats is not None
        assert v2_stats.count == 1
        assert v2_stats.avg == 50.0

    def test_histogram_nonexistent(self):
        """Test getting nonexistent histogram returns None."""
        hook = InMemoryMetricHook()
        assert hook.get_histogram_stats("nonexistent") is None

    def test_timing_records_correctly(self):
        """Test timing records correctly."""
        hook = InMemoryMetricHook()
        hook.timing("auth_latency", 45.2)
        hook.timing("auth_latency", 55.8)

        stats = hook.get_timing_stats("auth_latency")
        assert stats is not None
        assert stats.count == 2
        assert stats.min == 45.2
        assert stats.max == 55.8

    def test_timing_nonexistent(self):
        """Test getting nonexistent timing returns None."""
        hook = InMemoryMetricHook()
        assert hook.get_timing_stats("nonexistent") is None

    def test_get_all_counters(self):
        """Test getting all counters."""
        hook = InMemoryMetricHook()
        hook.increment("requests", tags={"user": "alice"})
        hook.increment("errors")

        counters = hook.get_all_counters()
        assert len(counters) == 2
        assert counters["requests[user=alice]"] == 1.0
        assert counters["errors"] == 1.0

    def test_get_all_gauges(self):
        """Test getting all gauges."""
        hook = InMemoryMetricHook()
        hook.gauge("connections", 42.0)
        hook.gauge("memory", 1024.0, {"service": "api"})

        gauges = hook.get_all_gauges()
        assert len(gauges) == 2
        assert gauges["connections"] == 42.0
        assert gauges["memory[service=api]"] == 1024.0

    def test_reset(self):
        """Test reset clears all metrics."""
        hook = InMemoryMetricHook()
        hook.increment("requests")
        hook.gauge("connections", 42.0)
        hook.histogram("latency", 100.0)
        hook.timing("auth_time", 50.0)

        hook.reset()

        assert hook.get_counter("requests") == 0.0
        assert hook.get_gauge("connections") is None
        assert hook.get_histogram_stats("latency") is None
        assert hook.get_timing_stats("auth_time") is None


# =============================================================================
# HistogramStats Tests
# =============================================================================


class TestHistogramStats:
    """Tests for HistogramStats dataclass."""

    def test_to_dict(self):
        """Test to_dict conversion."""
        stats = HistogramStats(count=3, total=600.0, min=100.0, max=300.0, avg=200.0)
        result = stats.to_dict()

        assert result == {
            "count": 3,
            "total": 600.0,
            "min": 100.0,
            "max": 300.0,
            "avg": 200.0,
        }


# =============================================================================
# ObservabilityHooks Tests
# =============================================================================


class TestObservabilityHooks:
    """Tests for ObservabilityHooks singleton."""

    def test_singleton_instance(self):
        """Test that get_instance returns the same instance."""
        hooks1 = ObservabilityHooks.get_instance()
        hooks2 = ObservabilityHooks.get_instance()
        assert hooks1 is hooks2

    def test_reset_instance(self):
        """Test that reset_instance creates new instance."""
        hooks1 = ObservabilityHooks.get_instance()
        ObservabilityHooks.reset_instance()
        hooks2 = ObservabilityHooks.get_instance()
        assert hooks1 is not hooks2

    def test_add_metric_hook(self):
        """Test adding a metric hook."""
        hooks = ObservabilityHooks.get_instance()
        memory_hook = InMemoryMetricHook()
        hooks.add_metric_hook(memory_hook)

        assert memory_hook in hooks.metric_hooks

    def test_remove_metric_hook(self):
        """Test removing a metric hook."""
        hooks = ObservabilityHooks.get_instance()
        memory_hook = InMemoryMetricHook()
        hooks.add_metric_hook(memory_hook)

        assert hooks.remove_metric_hook(memory_hook) is True
        assert memory_hook not in hooks.metric_hooks

    def test_remove_nonexistent_hook(self):
        """Test removing a hook that doesn't exist."""
        hooks = ObservabilityHooks.get_instance()
        memory_hook = InMemoryMetricHook()

        assert hooks.remove_metric_hook(memory_hook) is False

    def test_clear_metric_hooks(self):
        """Test clearing all metric hooks."""
        hooks = ObservabilityHooks.get_instance()
        hooks.add_metric_hook(InMemoryMetricHook())
        hooks.add_metric_hook(InMemoryMetricHook())

        hooks.clear_metric_hooks()
        assert len(hooks.metric_hooks) == 0

    def test_metric_hooks_returns_copy(self):
        """Test metric_hooks returns a copy."""
        hooks = ObservabilityHooks.get_instance()
        memory_hook = InMemoryMetricHook()
        hooks.add_metric_hook(memory_hook)

        returned = hooks.metric_hooks
        returned.clear()

        assert memory_hook in hooks.metric_hooks

    def test_emit_counter(self):
        """Test emitting counter metric."""
        hooks = ObservabilityHooks.get_instance()
        memory_hook = InMemoryMetricHook()
        hooks.add_metric_hook(memory_hook)

        hooks.emit_counter("requests", 1.0, {"user": "alice"})
        assert memory_hook.get_counter("requests", {"user": "alice"}) == 1.0

    def test_emit_gauge(self):
        """Test emitting gauge metric."""
        hooks = ObservabilityHooks.get_instance()
        memory_hook = InMemoryMetricHook()
        hooks.add_metric_hook(memory_hook)

        hooks.emit_gauge("connections", 42.0)
        assert memory_hook.get_gauge("connections") == 42.0

    def test_emit_histogram(self):
        """Test emitting histogram metric."""
        hooks = ObservabilityHooks.get_instance()
        memory_hook = InMemoryMetricHook()
        hooks.add_metric_hook(memory_hook)

        hooks.emit_histogram("latency", 100.0)
        stats = memory_hook.get_histogram_stats("latency")
        assert stats is not None
        assert stats.count == 1
        assert stats.avg == 100.0

    def test_emit_timing(self):
        """Test emitting timing metric."""
        hooks = ObservabilityHooks.get_instance()
        memory_hook = InMemoryMetricHook()
        hooks.add_metric_hook(memory_hook)

        hooks.emit_timing("auth_latency", 45.2)
        stats = memory_hook.get_timing_stats("auth_latency")
        assert stats is not None
        assert stats.count == 1
        assert stats.avg == 45.2

    def test_emit_metric_counter(self):
        """Test emit_metric with counter type."""
        hooks = ObservabilityHooks.get_instance()
        memory_hook = InMemoryMetricHook()
        hooks.add_metric_hook(memory_hook)

        hooks.emit_metric(MetricType.COUNTER, "requests", 1.0)
        assert memory_hook.get_counter("requests") == 1.0

    def test_emit_metric_gauge(self):
        """Test emit_metric with gauge type."""
        hooks = ObservabilityHooks.get_instance()
        memory_hook = InMemoryMetricHook()
        hooks.add_metric_hook(memory_hook)

        hooks.emit_metric(MetricType.GAUGE, "connections", 42.0)
        assert memory_hook.get_gauge("connections") == 42.0

    def test_emit_metric_histogram(self):
        """Test emit_metric with histogram type."""
        hooks = ObservabilityHooks.get_instance()
        memory_hook = InMemoryMetricHook()
        hooks.add_metric_hook(memory_hook)

        hooks.emit_metric(MetricType.HISTOGRAM, "latency", 100.0)
        stats = memory_hook.get_histogram_stats("latency")
        assert stats is not None

    def test_emit_metric_timing(self):
        """Test emit_metric with timing type."""
        hooks = ObservabilityHooks.get_instance()
        memory_hook = InMemoryMetricHook()
        hooks.add_metric_hook(memory_hook)

        hooks.emit_metric(MetricType.TIMING, "auth_time", 50.0)
        stats = memory_hook.get_timing_stats("auth_time")
        assert stats is not None

    def test_emit_metric_summary(self):
        """Test emit_metric with summary type (treated as timing)."""
        hooks = ObservabilityHooks.get_instance()
        memory_hook = InMemoryMetricHook()
        hooks.add_metric_hook(memory_hook)

        hooks.emit_metric(MetricType.SUMMARY, "summary_metric", 50.0)
        stats = memory_hook.get_timing_stats("summary_metric")
        assert stats is not None

    def test_multiple_hooks(self):
        """Test emitting to multiple hooks."""
        hooks = ObservabilityHooks.get_instance()
        hook1 = InMemoryMetricHook()
        hook2 = InMemoryMetricHook()
        hooks.add_metric_hook(hook1)
        hooks.add_metric_hook(hook2)

        hooks.emit_counter("requests")

        assert hook1.get_counter("requests") == 1.0
        assert hook2.get_counter("requests") == 1.0


# =============================================================================
# Convenience Function Tests
# =============================================================================


class TestConvenienceFunctions:
    """Tests for module-level convenience functions."""

    def test_emit_counter(self):
        """Test emit_counter convenience function."""
        hooks = ObservabilityHooks.get_instance()
        memory_hook = InMemoryMetricHook()
        hooks.add_metric_hook(memory_hook)

        emit_counter("requests", 1.0, {"user": "alice"})
        assert memory_hook.get_counter("requests", {"user": "alice"}) == 1.0

    def test_emit_counter_default_value(self):
        """Test emit_counter with default value."""
        hooks = ObservabilityHooks.get_instance()
        memory_hook = InMemoryMetricHook()
        hooks.add_metric_hook(memory_hook)

        emit_counter("requests")
        assert memory_hook.get_counter("requests") == 1.0

    def test_emit_gauge(self):
        """Test emit_gauge convenience function."""
        hooks = ObservabilityHooks.get_instance()
        memory_hook = InMemoryMetricHook()
        hooks.add_metric_hook(memory_hook)

        emit_gauge("connections", 42.0)
        assert memory_hook.get_gauge("connections") == 42.0

    def test_emit_histogram(self):
        """Test emit_histogram convenience function."""
        hooks = ObservabilityHooks.get_instance()
        memory_hook = InMemoryMetricHook()
        hooks.add_metric_hook(memory_hook)

        emit_histogram("response_size", 1024.0)
        stats = memory_hook.get_histogram_stats("response_size")
        assert stats is not None
        assert stats.avg == 1024.0

    def test_emit_timing(self):
        """Test emit_timing convenience function."""
        hooks = ObservabilityHooks.get_instance()
        memory_hook = InMemoryMetricHook()
        hooks.add_metric_hook(memory_hook)

        emit_timing("auth_latency", 45.2)
        stats = memory_hook.get_timing_stats("auth_latency")
        assert stats is not None
        assert stats.avg == 45.2

    def test_emit_with_no_hooks(self):
        """Test emitting with no hooks registered doesn't error."""
        # Should not raise any errors
        emit_counter("requests")
        emit_gauge("connections", 42.0)
        emit_histogram("latency", 100.0)
        emit_timing("auth_time", 50.0)


# =============================================================================
# Standard Metric Names Tests
# =============================================================================


class TestStandardMetricNames:
    """Tests for standard metric name constants."""

    def test_auth_metrics(self):
        """Test authorization metric names."""
        assert METRIC_AUTH_REQUESTS == "proxilion.auth.requests"
        assert METRIC_AUTH_ALLOWED == "proxilion.auth.allowed"
        assert METRIC_AUTH_DENIED == "proxilion.auth.denied"
        assert METRIC_AUTH_LATENCY == "proxilion.auth.latency_ms"

    def test_rate_limit_metrics(self):
        """Test rate limit metric names."""
        assert METRIC_RATE_LIMIT_REQUESTS == "proxilion.rate_limit.requests"
        assert METRIC_RATE_LIMIT_EXCEEDED == "proxilion.rate_limit.exceeded"

    def test_tool_metrics(self):
        """Test tool metric names."""
        assert METRIC_TOOL_CALLS == "proxilion.tool.calls"
        assert METRIC_TOOL_LATENCY == "proxilion.tool.latency_ms"
        assert METRIC_TOOL_ERRORS == "proxilion.tool.errors"

    def test_cost_metrics(self):
        """Test cost metric names."""
        assert METRIC_COST_USD == "proxilion.cost.usd"
        assert METRIC_TOKENS_INPUT == "proxilion.tokens.input"
        assert METRIC_TOKENS_OUTPUT == "proxilion.tokens.output"

    def test_circuit_breaker_metrics(self):
        """Test circuit breaker metric names."""
        assert METRIC_CIRCUIT_BREAKER_OPEN == "proxilion.circuit_breaker.open"
        assert METRIC_CIRCUIT_BREAKER_HALF_OPEN == "proxilion.circuit_breaker.half_open"
        assert METRIC_CIRCUIT_BREAKER_CLOSED == "proxilion.circuit_breaker.closed"

    def test_standard_metrics_usage(self):
        """Test using standard metric names."""
        hooks = ObservabilityHooks.get_instance()
        memory_hook = InMemoryMetricHook()
        hooks.add_metric_hook(memory_hook)

        emit_counter(METRIC_AUTH_REQUESTS, tags={"user": "alice"})
        emit_counter(METRIC_AUTH_ALLOWED, tags={"user": "alice"})
        emit_timing(METRIC_AUTH_LATENCY, 45.2, tags={"tool": "search"})

        assert memory_hook.get_counter(METRIC_AUTH_REQUESTS, {"user": "alice"}) == 1.0
        assert memory_hook.get_counter(METRIC_AUTH_ALLOWED, {"user": "alice"}) == 1.0
        stats = memory_hook.get_timing_stats(METRIC_AUTH_LATENCY, {"tool": "search"})
        assert stats is not None
        assert stats.avg == 45.2


# =============================================================================
# Integration Tests
# =============================================================================


class TestIntegration:
    """Integration tests for observability hooks."""

    def test_complete_auth_workflow(self):
        """Test recording a complete authorization workflow."""
        hooks = ObservabilityHooks.get_instance()
        memory_hook = InMemoryMetricHook()
        hooks.add_metric_hook(memory_hook)

        # Simulate authorization workflow
        user = "alice"
        tool = "search_database"

        # Record request
        emit_counter(METRIC_AUTH_REQUESTS, tags={"user": user, "tool": tool})

        # Record latency
        emit_timing(METRIC_AUTH_LATENCY, 15.3, tags={"user": user, "tool": tool})

        # Record allowed
        emit_counter(METRIC_AUTH_ALLOWED, tags={"user": user, "tool": tool})

        # Record tool call
        emit_counter(METRIC_TOOL_CALLS, tags={"tool": tool})

        # Record tool latency
        emit_timing(METRIC_TOOL_LATENCY, 150.0, tags={"tool": tool})

        # Verify all metrics
        tags = {"user": user, "tool": tool}
        assert memory_hook.get_counter(METRIC_AUTH_REQUESTS, tags) == 1.0
        assert memory_hook.get_counter(METRIC_AUTH_ALLOWED, tags) == 1.0
        assert memory_hook.get_counter(METRIC_AUTH_DENIED, tags) == 0.0

        auth_latency = memory_hook.get_timing_stats(METRIC_AUTH_LATENCY, tags)
        assert auth_latency is not None
        assert auth_latency.avg == 15.3

        tool_latency = memory_hook.get_timing_stats(METRIC_TOOL_LATENCY, {"tool": tool})
        assert tool_latency is not None
        assert tool_latency.avg == 150.0

    def test_denied_auth_workflow(self):
        """Test recording a denied authorization."""
        hooks = ObservabilityHooks.get_instance()
        memory_hook = InMemoryMetricHook()
        hooks.add_metric_hook(memory_hook)

        user = "mallory"
        tool = "delete_database"

        emit_counter(METRIC_AUTH_REQUESTS, tags={"user": user, "tool": tool})
        emit_counter(METRIC_AUTH_DENIED, tags={"user": user, "tool": tool})
        emit_timing(METRIC_AUTH_LATENCY, 5.0, tags={"user": user, "tool": tool})

        tags = {"user": user, "tool": tool}
        assert memory_hook.get_counter(METRIC_AUTH_REQUESTS, tags) == 1.0
        assert memory_hook.get_counter(METRIC_AUTH_DENIED, tags) == 1.0
        assert memory_hook.get_counter(METRIC_AUTH_ALLOWED, tags) == 0.0

    def test_rate_limit_workflow(self):
        """Test recording rate limit events."""
        hooks = ObservabilityHooks.get_instance()
        memory_hook = InMemoryMetricHook()
        hooks.add_metric_hook(memory_hook)

        user = "bob"

        # Simulate 10 requests, 3 rate limited
        for _ in range(10):
            emit_counter(METRIC_RATE_LIMIT_REQUESTS, tags={"user": user})

        for _ in range(3):
            emit_counter(METRIC_RATE_LIMIT_EXCEEDED, tags={"user": user})

        assert memory_hook.get_counter(METRIC_RATE_LIMIT_REQUESTS, {"user": user}) == 10.0
        assert memory_hook.get_counter(METRIC_RATE_LIMIT_EXCEEDED, {"user": user}) == 3.0

    def test_cost_tracking_workflow(self):
        """Test recording cost metrics."""
        hooks = ObservabilityHooks.get_instance()
        memory_hook = InMemoryMetricHook()
        hooks.add_metric_hook(memory_hook)

        model = "claude-sonnet"
        user = "alice"

        # Record token usage
        emit_counter(METRIC_TOKENS_INPUT, 1000, tags={"model": model, "user": user})
        emit_counter(METRIC_TOKENS_OUTPUT, 500, tags={"model": model, "user": user})
        emit_counter(METRIC_COST_USD, 0.015, tags={"model": model, "user": user})

        # Another request
        emit_counter(METRIC_TOKENS_INPUT, 2000, tags={"model": model, "user": user})
        emit_counter(METRIC_TOKENS_OUTPUT, 1000, tags={"model": model, "user": user})
        emit_counter(METRIC_COST_USD, 0.030, tags={"model": model, "user": user})

        tags = {"model": model, "user": user}
        assert memory_hook.get_counter(METRIC_TOKENS_INPUT, tags) == 3000
        assert memory_hook.get_counter(METRIC_TOKENS_OUTPUT, tags) == 1500
        assert memory_hook.get_counter(METRIC_COST_USD, tags) == pytest.approx(0.045)

    def test_multiple_hooks_workflow(self):
        """Test with multiple hooks registered."""
        hooks = ObservabilityHooks.get_instance()
        memory_hook1 = InMemoryMetricHook()
        memory_hook2 = InMemoryMetricHook()
        logging_hook = LoggingMetricHook()

        hooks.add_metric_hook(memory_hook1)
        hooks.add_metric_hook(memory_hook2)
        hooks.add_metric_hook(logging_hook)

        emit_counter(METRIC_AUTH_REQUESTS, tags={"user": "alice"})

        # Both memory hooks should have recorded the metric
        assert memory_hook1.get_counter(METRIC_AUTH_REQUESTS, {"user": "alice"}) == 1.0
        assert memory_hook2.get_counter(METRIC_AUTH_REQUESTS, {"user": "alice"}) == 1.0

    def test_hook_removal(self):
        """Test hook removal stops receiving metrics."""
        hooks = ObservabilityHooks.get_instance()
        memory_hook = InMemoryMetricHook()
        hooks.add_metric_hook(memory_hook)

        emit_counter("before_removal")
        assert memory_hook.get_counter("before_removal") == 1.0

        hooks.remove_metric_hook(memory_hook)

        emit_counter("after_removal")
        assert memory_hook.get_counter("after_removal") == 0.0


# =============================================================================
# Custom Hook Tests
# =============================================================================


class TestCustomHook:
    """Tests for custom hook implementations."""

    def test_custom_hook_implementation(self):
        """Test that custom hooks work correctly."""

        class CustomHook:
            def __init__(self):
                self.metrics: list[dict[str, Any]] = []

            def increment(self, name: str, value: float = 1.0, tags: dict | None = None) -> None:
                self.metrics.append({"type": "counter", "name": name, "value": value, "tags": tags})

            def gauge(self, name: str, value: float, tags: dict | None = None) -> None:
                self.metrics.append({"type": "gauge", "name": name, "value": value, "tags": tags})

            def histogram(self, name: str, value: float, tags: dict | None = None) -> None:
                self.metrics.append({"type": "histogram", "name": name, "value": value, "tags": tags})

            def timing(self, name: str, duration_ms: float, tags: dict | None = None) -> None:
                self.metrics.append({"type": "timing", "name": name, "value": duration_ms, "tags": tags})

        hooks = ObservabilityHooks.get_instance()
        custom_hook = CustomHook()
        hooks.add_metric_hook(custom_hook)

        emit_counter("requests", tags={"service": "api"})
        emit_gauge("connections", 42.0)
        emit_histogram("latency", 100.0)
        emit_timing("auth_time", 50.0)

        assert len(custom_hook.metrics) == 4
        assert custom_hook.metrics[0]["type"] == "counter"
        assert custom_hook.metrics[1]["type"] == "gauge"
        assert custom_hook.metrics[2]["type"] == "histogram"
        assert custom_hook.metrics[3]["type"] == "timing"
