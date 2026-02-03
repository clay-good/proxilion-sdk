"""
Observability components for Proxilion.

This module provides visibility into agent operations:
- Token usage and cost tracking
- Budget enforcement and cost-based rate limiting
- Usage analytics and summaries
- Metrics and observability hooks

Cost Tracking Example:
    >>> from proxilion.observability import CostTracker, BudgetPolicy
    >>>
    >>> # Create cost tracker with budget policy
    >>> tracker = CostTracker(
    ...     budget_policy=BudgetPolicy(
    ...         max_cost_per_request=1.00,
    ...         max_cost_per_user_per_day=50.00,
    ...     )
    ... )
    >>>
    >>> # Record usage
    >>> record = tracker.record_usage(
    ...     model="claude-sonnet-4-20250514",
    ...     input_tokens=1000,
    ...     output_tokens=500,
    ...     user_id="user_123",
    ... )
    >>> print(f"Cost: ${record.cost_usd:.4f}")

Metrics Example:
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

Standard Metrics:
    Proxilion emits the following standard metrics:

    Authorization:
    - proxilion.auth.requests: Total authorization requests
    - proxilion.auth.allowed: Allowed requests
    - proxilion.auth.denied: Denied requests
    - proxilion.auth.latency_ms: Authorization check latency

    Rate Limiting:
    - proxilion.rate_limit.requests: Total rate limit checks
    - proxilion.rate_limit.exceeded: Rate limit exceeded events

    Tool Execution:
    - proxilion.tool.calls: Total tool calls
    - proxilion.tool.latency_ms: Tool execution latency
    - proxilion.tool.errors: Tool execution errors

    Cost:
    - proxilion.cost.usd: Total cost in USD
    - proxilion.tokens.input: Input tokens processed
    - proxilion.tokens.output: Output tokens generated
"""

from proxilion.observability.cost_tracker import (
    DEFAULT_PRICING,
    BudgetPolicy,
    CostSummary,
    CostTracker,
    ModelPricing,
    UsageRecord,
    create_cost_tracker,
)
from proxilion.observability.hooks import (
    METRIC_AUTH_ALLOWED,
    METRIC_AUTH_DENIED,
    METRIC_AUTH_LATENCY,
    # Standard metric names
    METRIC_AUTH_REQUESTS,
    METRIC_CIRCUIT_BREAKER_CLOSED,
    METRIC_CIRCUIT_BREAKER_HALF_OPEN,
    METRIC_CIRCUIT_BREAKER_OPEN,
    METRIC_COST_USD,
    METRIC_RATE_LIMIT_EXCEEDED,
    METRIC_RATE_LIMIT_REQUESTS,
    METRIC_TOKENS_INPUT,
    METRIC_TOKENS_OUTPUT,
    METRIC_TOOL_CALLS,
    METRIC_TOOL_ERRORS,
    METRIC_TOOL_LATENCY,
    HistogramStats,
    InMemoryMetricHook,
    # Built-in hooks
    LoggingMetricHook,
    MetricHook,
    # Core classes
    MetricType,
    ObservabilityHooks,
    # Convenience functions
    emit_counter,
    emit_gauge,
    emit_histogram,
    emit_timing,
)

# Real-time metrics and alerts
from proxilion.observability.metrics import (
    Alert,
    AlertManager,
    AlertRule,
    EventType,
    MetricsCollector,
    PrometheusExporter,
    SecurityEvent,
)
from proxilion.observability.metrics import (
    MetricType as SecurityMetricType,
)

# Session-based cost tracking
from proxilion.observability.session_cost_tracker import (
    AgentCostProfile,
    AlertSeverity,
    AlertType,
    CostAlert,
    Session,
    SessionCostTracker,
    SessionState,
    SessionSummary,
    create_session_cost_tracker,
)

__all__ = [
    # Cost tracking
    "BudgetPolicy",
    "CostSummary",
    "CostTracker",
    "ModelPricing",
    "UsageRecord",
    "DEFAULT_PRICING",
    "create_cost_tracker",
    # Metrics - Core classes
    "MetricType",
    "MetricHook",
    "ObservabilityHooks",
    "HistogramStats",
    # Metrics - Built-in hooks
    "LoggingMetricHook",
    "InMemoryMetricHook",
    # Metrics - Convenience functions
    "emit_counter",
    "emit_gauge",
    "emit_histogram",
    "emit_timing",
    # Metrics - Standard metric names
    "METRIC_AUTH_REQUESTS",
    "METRIC_AUTH_ALLOWED",
    "METRIC_AUTH_DENIED",
    "METRIC_AUTH_LATENCY",
    "METRIC_RATE_LIMIT_REQUESTS",
    "METRIC_RATE_LIMIT_EXCEEDED",
    "METRIC_TOOL_CALLS",
    "METRIC_TOOL_LATENCY",
    "METRIC_TOOL_ERRORS",
    "METRIC_COST_USD",
    "METRIC_TOKENS_INPUT",
    "METRIC_TOKENS_OUTPUT",
    "METRIC_CIRCUIT_BREAKER_OPEN",
    "METRIC_CIRCUIT_BREAKER_HALF_OPEN",
    "METRIC_CIRCUIT_BREAKER_CLOSED",
    # Real-time metrics and alerts
    "MetricsCollector",
    "AlertManager",
    "AlertRule",
    "PrometheusExporter",
    "SecurityEvent",
    "Alert",
    "EventType",
    "SecurityMetricType",
    # Session cost tracking
    "AgentCostProfile",
    "AlertSeverity",
    "AlertType",
    "CostAlert",
    "Session",
    "SessionCostTracker",
    "SessionState",
    "SessionSummary",
    "create_session_cost_tracker",
]
