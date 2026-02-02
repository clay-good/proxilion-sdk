"""
Metrics and observability hooks for Proxilion.

Provides hooks for metrics and observability without requiring external
dependencies. Allows integration with Prometheus, OpenTelemetry, StatsD, etc.

Quick Start:
    >>> from proxilion.observability import (
    ...     ObservabilityHooks,
    ...     InMemoryMetricHook,
    ...     emit_counter,
    ...     emit_timing,
    ... )
    >>>
    >>> # Set up metrics hook
    >>> hooks = ObservabilityHooks.get_instance()
    >>> memory_hook = InMemoryMetricHook()
    >>> hooks.add_metric_hook(memory_hook)
    >>>
    >>> # Emit metrics
    >>> emit_counter("proxilion.auth.requests", tags={"user": "alice"})
    >>> emit_timing("proxilion.auth.latency_ms", 45.2, tags={"tool": "search"})
    >>>
    >>> # Check recorded metrics
    >>> memory_hook.get_counter("proxilion.auth.requests", {"user": "alice"})
    1.0

Integration with Prometheus:
    >>> from prometheus_client import Counter, Histogram
    >>>
    >>> class PrometheusMetricHook:
    ...     def __init__(self):
    ...         self.auth_requests = Counter(
    ...             "proxilion_auth_requests_total",
    ...             "Total authorization requests",
    ...             ["user", "tool"]
    ...         )
    ...         self.auth_latency = Histogram(
    ...             "proxilion_auth_latency_seconds",
    ...             "Authorization latency in seconds"
    ...         )
    ...
    ...     def increment(self, name, value=1.0, tags=None):
    ...         if name == "proxilion.auth.requests":
    ...             self.auth_requests.labels(**(tags or {})).inc(value)
    ...
    ...     def histogram(self, name, value, tags=None):
    ...         if name == "proxilion.auth.latency_ms":
    ...             self.auth_latency.observe(value / 1000)  # Convert to seconds
    ...
    ...     def gauge(self, name, value, tags=None): pass
    ...     def timing(self, name, duration_ms, tags=None):
    ...         self.histogram(name, duration_ms, tags)
    >>>
    >>> hooks = ObservabilityHooks.get_instance()
    >>> hooks.add_metric_hook(PrometheusMetricHook())

Integration with OpenTelemetry:
    >>> from opentelemetry import metrics
    >>>
    >>> class OpenTelemetryMetricHook:
    ...     def __init__(self):
    ...         meter = metrics.get_meter("proxilion")
    ...         self._counters = {}
    ...         self._histograms = {}
    ...         self._meter = meter
    ...
    ...     def increment(self, name, value=1.0, tags=None):
    ...         if name not in self._counters:
    ...             self._counters[name] = self._meter.create_counter(name)
    ...         self._counters[name].add(value, tags or {})
    ...
    ...     def histogram(self, name, value, tags=None):
    ...         if name not in self._histograms:
    ...             self._histograms[name] = self._meter.create_histogram(name)
    ...         self._histograms[name].record(value, tags or {})
    ...
    ...     def gauge(self, name, value, tags=None): pass
    ...     def timing(self, name, duration_ms, tags=None):
    ...         self.histogram(name, duration_ms, tags)
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol, runtime_checkable


class MetricType(Enum):
    """Types of metrics that can be emitted."""

    COUNTER = "counter"
    """A monotonically increasing counter."""

    GAUGE = "gauge"
    """A value that can go up or down."""

    HISTOGRAM = "histogram"
    """Distribution of values."""

    SUMMARY = "summary"
    """Similar to histogram but calculates quantiles."""

    TIMING = "timing"
    """Duration measurement (usually milliseconds)."""


@runtime_checkable
class MetricHook(Protocol):
    """
    Protocol for metric backends (Prometheus, StatsD, OpenTelemetry, etc.).

    Implement this protocol to integrate with your metrics infrastructure.
    The hooks will be called by Proxilion whenever metrics are emitted.

    Example:
        >>> class MyMetricHook:
        ...     def increment(self, name, value=1.0, tags=None):
        ...         # Send to your metrics backend
        ...         pass
        ...
        ...     def gauge(self, name, value, tags=None):
        ...         pass
        ...
        ...     def histogram(self, name, value, tags=None):
        ...         pass
        ...
        ...     def timing(self, name, duration_ms, tags=None):
        ...         pass
        >>>
        >>> from proxilion.observability import ObservabilityHooks
        >>> hooks = ObservabilityHooks.get_instance()
        >>> hooks.add_metric_hook(MyMetricHook())
    """

    def increment(self, name: str, value: float = 1.0, tags: dict[str, Any] | None = None) -> None:
        """
        Increment a counter metric.

        Args:
            name: The metric name (e.g., "proxilion.auth.requests").
            value: The amount to increment by (default 1.0).
            tags: Optional tags/labels for the metric.
        """
        ...

    def gauge(self, name: str, value: float, tags: dict[str, Any] | None = None) -> None:
        """
        Set a gauge metric.

        Args:
            name: The metric name.
            value: The gauge value.
            tags: Optional tags/labels for the metric.
        """
        ...

    def histogram(self, name: str, value: float, tags: dict[str, Any] | None = None) -> None:
        """
        Record a value in a histogram.

        Args:
            name: The metric name.
            value: The value to record.
            tags: Optional tags/labels for the metric.
        """
        ...

    def timing(self, name: str, duration_ms: float, tags: dict[str, Any] | None = None) -> None:
        """
        Record a timing/duration measurement.

        Args:
            name: The metric name.
            duration_ms: The duration in milliseconds.
            tags: Optional tags/labels for the metric.
        """
        ...


class LoggingMetricHook:
    """
    Simple hook that logs metrics (for development and debugging).

    Example:
        >>> import logging
        >>> logging.basicConfig(level=logging.DEBUG)
        >>> hook = LoggingMetricHook()
        >>> hook.increment("requests", 1.0, {"service": "api"})
        DEBUG:proxilion.metrics:COUNTER requests=1.0 tags={'service': 'api'}
    """

    def __init__(self, logger: logging.Logger | None = None, level: int = logging.DEBUG):
        """
        Initialize the logging hook.

        Args:
            logger: Logger instance to use. Defaults to "proxilion.metrics".
            level: Logging level for metric messages.
        """
        self.logger = logger or logging.getLogger("proxilion.metrics")
        self.level = level

    def increment(self, name: str, value: float = 1.0, tags: dict[str, Any] | None = None) -> None:
        """Log a counter increment."""
        self.logger.log(self.level, f"COUNTER {name}={value} tags={tags}")

    def gauge(self, name: str, value: float, tags: dict[str, Any] | None = None) -> None:
        """Log a gauge value."""
        self.logger.log(self.level, f"GAUGE {name}={value} tags={tags}")

    def histogram(self, name: str, value: float, tags: dict[str, Any] | None = None) -> None:
        """Log a histogram value."""
        self.logger.log(self.level, f"HISTOGRAM {name}={value} tags={tags}")

    def timing(self, name: str, duration_ms: float, tags: dict[str, Any] | None = None) -> None:
        """Log a timing value."""
        self.logger.log(self.level, f"TIMING {name}={duration_ms}ms tags={tags}")


@dataclass
class HistogramStats:
    """Statistics for a histogram metric."""

    count: int
    """Number of recorded values."""

    total: float
    """Sum of all values."""

    min: float
    """Minimum value."""

    max: float
    """Maximum value."""

    avg: float
    """Average value."""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "count": self.count,
            "total": self.total,
            "min": self.min,
            "max": self.max,
            "avg": self.avg,
        }


class InMemoryMetricHook:
    """
    In-memory metrics for testing and simple use cases.

    Stores all metrics in memory and provides methods to query them.
    Useful for testing that metrics are being emitted correctly.

    Example:
        >>> hook = InMemoryMetricHook()
        >>> hook.increment("requests", tags={"user": "alice"})
        >>> hook.increment("requests", tags={"user": "alice"})
        >>> hook.increment("requests", tags={"user": "bob"})
        >>>
        >>> hook.get_counter("requests", {"user": "alice"})
        2.0
        >>> hook.get_counter("requests", {"user": "bob"})
        1.0
        >>>
        >>> hook.histogram("latency", 100.0)
        >>> hook.histogram("latency", 200.0)
        >>> stats = hook.get_histogram_stats("latency")
        >>> stats.avg
        150.0
    """

    def __init__(self):
        """Initialize the in-memory hook."""
        self.counters: dict[str, float] = defaultdict(float)
        self.gauges: dict[str, float] = {}
        self.histograms: dict[str, list[float]] = defaultdict(list)
        self.timings: dict[str, list[float]] = defaultdict(list)

    def _make_key(self, name: str, tags: dict[str, Any] | None) -> str:
        """Create a unique key from metric name and tags."""
        if not tags:
            return name
        sorted_tags = sorted(tags.items())
        tag_str = ",".join(f"{k}={v}" for k, v in sorted_tags)
        return f"{name}[{tag_str}]"

    def increment(self, name: str, value: float = 1.0, tags: dict[str, Any] | None = None) -> None:
        """Increment a counter."""
        key = self._make_key(name, tags)
        self.counters[key] += value

    def gauge(self, name: str, value: float, tags: dict[str, Any] | None = None) -> None:
        """Set a gauge value."""
        key = self._make_key(name, tags)
        self.gauges[key] = value

    def histogram(self, name: str, value: float, tags: dict[str, Any] | None = None) -> None:
        """Record a histogram value."""
        key = self._make_key(name, tags)
        self.histograms[key].append(value)

    def timing(self, name: str, duration_ms: float, tags: dict[str, Any] | None = None) -> None:
        """Record a timing value."""
        key = self._make_key(name, tags)
        self.timings[key].append(duration_ms)

    def get_counter(self, name: str, tags: dict[str, Any] | None = None) -> float:
        """
        Get the current value of a counter.

        Args:
            name: The metric name.
            tags: Optional tags/labels for the metric.

        Returns:
            The current counter value, or 0.0 if not found.
        """
        key = self._make_key(name, tags)
        return self.counters[key]

    def get_gauge(self, name: str, tags: dict[str, Any] | None = None) -> float | None:
        """
        Get the current value of a gauge.

        Args:
            name: The metric name.
            tags: Optional tags/labels for the metric.

        Returns:
            The current gauge value, or None if not set.
        """
        key = self._make_key(name, tags)
        return self.gauges.get(key)

    def get_histogram_stats(
        self, name: str, tags: dict[str, Any] | None = None
    ) -> HistogramStats | None:
        """
        Get statistics for a histogram.

        Args:
            name: The metric name.
            tags: Optional tags/labels for the metric.

        Returns:
            HistogramStats with count, sum, min, max, avg, or None if empty.
        """
        key = self._make_key(name, tags)
        values = self.histograms.get(key, [])
        if not values:
            return None
        return HistogramStats(
            count=len(values),
            total=sum(values),
            min=min(values),
            max=max(values),
            avg=sum(values) / len(values),
        )

    def get_timing_stats(
        self, name: str, tags: dict[str, Any] | None = None
    ) -> HistogramStats | None:
        """
        Get statistics for timing measurements.

        Args:
            name: The metric name.
            tags: Optional tags/labels for the metric.

        Returns:
            HistogramStats with count, sum, min, max, avg, or None if empty.
        """
        key = self._make_key(name, tags)
        values = self.timings.get(key, [])
        if not values:
            return None
        return HistogramStats(
            count=len(values),
            total=sum(values),
            min=min(values),
            max=max(values),
            avg=sum(values) / len(values),
        )

    def get_all_counters(self) -> dict[str, float]:
        """Get all counter values."""
        return dict(self.counters)

    def get_all_gauges(self) -> dict[str, float]:
        """Get all gauge values."""
        return dict(self.gauges)

    def reset(self) -> None:
        """Reset all metrics to initial state."""
        self.counters.clear()
        self.gauges.clear()
        self.histograms.clear()
        self.timings.clear()


class ObservabilityHooks:
    """
    Central registry for observability hooks.

    This is a singleton that manages all metric hooks. Use `get_instance()`
    to get the global instance.

    Example:
        >>> from proxilion.observability import ObservabilityHooks, InMemoryMetricHook
        >>>
        >>> hooks = ObservabilityHooks.get_instance()
        >>> memory_hook = InMemoryMetricHook()
        >>> hooks.add_metric_hook(memory_hook)
        >>>
        >>> # Emit metrics (these will be sent to all registered hooks)
        >>> hooks.emit_counter("requests", tags={"service": "api"})
        >>> hooks.emit_timing("latency", 45.2)
        >>>
        >>> # Check the recorded metrics
        >>> memory_hook.get_counter("requests", {"service": "api"})
        1.0
    """

    _instance: ObservabilityHooks | None = None

    def __init__(self):
        """Initialize the observability hooks registry."""
        self._metric_hooks: list[MetricHook] = []

    @classmethod
    def get_instance(cls) -> ObservabilityHooks:
        """
        Get the global ObservabilityHooks instance.

        Returns:
            The singleton instance.
        """
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """
        Reset the global instance.

        Useful for testing to ensure a clean state.
        """
        cls._instance = None

    def add_metric_hook(self, hook: MetricHook) -> None:
        """
        Register a metric hook.

        Args:
            hook: The metric hook to register.
        """
        self._metric_hooks.append(hook)

    def remove_metric_hook(self, hook: MetricHook) -> bool:
        """
        Remove a metric hook.

        Args:
            hook: The metric hook to remove.

        Returns:
            True if the hook was removed, False if not found.
        """
        try:
            self._metric_hooks.remove(hook)
            return True
        except ValueError:
            return False

    def clear_metric_hooks(self) -> None:
        """Remove all registered metric hooks."""
        self._metric_hooks.clear()

    @property
    def metric_hooks(self) -> list[MetricHook]:
        """Get a copy of the registered metric hooks."""
        return list(self._metric_hooks)

    def emit_metric(
        self,
        metric_type: MetricType,
        name: str,
        value: float,
        tags: dict[str, Any] | None = None,
    ) -> None:
        """
        Emit a metric to all registered hooks.

        Args:
            metric_type: The type of metric.
            name: The metric name.
            value: The metric value.
            tags: Optional tags/labels for the metric.
        """
        for hook in self._metric_hooks:
            if metric_type == MetricType.COUNTER:
                hook.increment(name, value, tags)
            elif metric_type == MetricType.GAUGE:
                hook.gauge(name, value, tags)
            elif metric_type == MetricType.HISTOGRAM:
                hook.histogram(name, value, tags)
            elif metric_type in (MetricType.TIMING, MetricType.SUMMARY):
                hook.timing(name, value, tags)

    def emit_counter(
        self, name: str, value: float = 1.0, tags: dict[str, Any] | None = None
    ) -> None:
        """
        Emit a counter metric.

        Args:
            name: The metric name.
            value: The amount to increment by (default 1.0).
            tags: Optional tags/labels for the metric.
        """
        self.emit_metric(MetricType.COUNTER, name, value, tags)

    def emit_gauge(self, name: str, value: float, tags: dict[str, Any] | None = None) -> None:
        """
        Emit a gauge metric.

        Args:
            name: The metric name.
            value: The gauge value.
            tags: Optional tags/labels for the metric.
        """
        self.emit_metric(MetricType.GAUGE, name, value, tags)

    def emit_histogram(self, name: str, value: float, tags: dict[str, Any] | None = None) -> None:
        """
        Emit a histogram metric.

        Args:
            name: The metric name.
            value: The value to record.
            tags: Optional tags/labels for the metric.
        """
        self.emit_metric(MetricType.HISTOGRAM, name, value, tags)

    def emit_timing(
        self, name: str, duration_ms: float, tags: dict[str, Any] | None = None
    ) -> None:
        """
        Emit a timing metric.

        Args:
            name: The metric name.
            duration_ms: The duration in milliseconds.
            tags: Optional tags/labels for the metric.
        """
        self.emit_metric(MetricType.TIMING, name, duration_ms, tags)


# Standard metric names emitted by Proxilion
# These are the metric names that Proxilion components emit

# Authorization metrics
METRIC_AUTH_REQUESTS = "proxilion.auth.requests"
"""Counter: Total authorization requests."""

METRIC_AUTH_ALLOWED = "proxilion.auth.allowed"
"""Counter: Authorization requests that were allowed."""

METRIC_AUTH_DENIED = "proxilion.auth.denied"
"""Counter: Authorization requests that were denied."""

METRIC_AUTH_LATENCY = "proxilion.auth.latency_ms"
"""Histogram: Authorization check latency in milliseconds."""

# Rate limiting metrics
METRIC_RATE_LIMIT_REQUESTS = "proxilion.rate_limit.requests"
"""Counter: Total rate limit checks."""

METRIC_RATE_LIMIT_EXCEEDED = "proxilion.rate_limit.exceeded"
"""Counter: Rate limit exceeded events."""

# Tool execution metrics
METRIC_TOOL_CALLS = "proxilion.tool.calls"
"""Counter: Total tool call executions."""

METRIC_TOOL_LATENCY = "proxilion.tool.latency_ms"
"""Histogram: Tool execution latency in milliseconds."""

METRIC_TOOL_ERRORS = "proxilion.tool.errors"
"""Counter: Tool execution errors."""

# Cost metrics
METRIC_COST_USD = "proxilion.cost.usd"
"""Counter: Total cost in USD."""

METRIC_TOKENS_INPUT = "proxilion.tokens.input"
"""Counter: Total input tokens processed."""

METRIC_TOKENS_OUTPUT = "proxilion.tokens.output"
"""Counter: Total output tokens generated."""

# Circuit breaker metrics
METRIC_CIRCUIT_BREAKER_OPEN = "proxilion.circuit_breaker.open"
"""Counter: Circuit breaker open events."""

METRIC_CIRCUIT_BREAKER_HALF_OPEN = "proxilion.circuit_breaker.half_open"
"""Counter: Circuit breaker half-open events."""

METRIC_CIRCUIT_BREAKER_CLOSED = "proxilion.circuit_breaker.closed"
"""Counter: Circuit breaker closed events."""


# Convenience functions for emitting metrics
def emit_counter(name: str, value: float = 1.0, tags: dict[str, Any] | None = None) -> None:
    """
    Emit a counter metric to all registered hooks.

    Args:
        name: The metric name (e.g., "proxilion.auth.requests").
        value: The amount to increment by (default 1.0).
        tags: Optional tags/labels for the metric.

    Example:
        >>> from proxilion.observability import emit_counter
        >>> emit_counter("proxilion.auth.requests", tags={"user": "alice"})
    """
    ObservabilityHooks.get_instance().emit_counter(name, value, tags)


def emit_gauge(name: str, value: float, tags: dict[str, Any] | None = None) -> None:
    """
    Emit a gauge metric to all registered hooks.

    Args:
        name: The metric name.
        value: The gauge value.
        tags: Optional tags/labels for the metric.

    Example:
        >>> from proxilion.observability import emit_gauge
        >>> emit_gauge("proxilion.connections.active", 42)
    """
    ObservabilityHooks.get_instance().emit_gauge(name, value, tags)


def emit_histogram(name: str, value: float, tags: dict[str, Any] | None = None) -> None:
    """
    Emit a histogram metric to all registered hooks.

    Args:
        name: The metric name.
        value: The value to record.
        tags: Optional tags/labels for the metric.

    Example:
        >>> from proxilion.observability import emit_histogram
        >>> emit_histogram("proxilion.response.size_bytes", 1024)
    """
    ObservabilityHooks.get_instance().emit_histogram(name, value, tags)


def emit_timing(name: str, duration_ms: float, tags: dict[str, Any] | None = None) -> None:
    """
    Emit a timing metric to all registered hooks.

    Args:
        name: The metric name.
        duration_ms: The duration in milliseconds.
        tags: Optional tags/labels for the metric.

    Example:
        >>> from proxilion.observability import emit_timing
        >>> emit_timing("proxilion.auth.latency_ms", 45.2, tags={"tool": "search"})
    """
    ObservabilityHooks.get_instance().emit_timing(name, duration_ms, tags)
