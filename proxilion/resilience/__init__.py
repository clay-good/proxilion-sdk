"""
Resilience components for Proxilion.

This module provides fault tolerance mechanisms for AI agent operations:
- Retry with exponential backoff
- Fallback chains for tools and models
- Graceful degradation tiers

These components help build robust AI applications that can handle
transient failures, provider outages, and degraded service conditions.

Example:
    >>> from proxilion.resilience import (
    ...     RetryPolicy, retry_with_backoff,
    ...     FallbackChain, FallbackOption,
    ...     DegradationTier, GracefulDegradation,
    ... )
    >>>
    >>> # Retry with exponential backoff
    >>> @retry_with_backoff(RetryPolicy(max_attempts=3))
    ... async def call_llm_api():
    ...     return await client.chat.completions.create(...)
    >>>
    >>> # Fallback chain for models
    >>> model_fallback = FallbackChain([
    ...     FallbackOption("claude-opus", call_claude_opus),
    ...     FallbackOption("gpt-4o", call_gpt4o),
    ...     FallbackOption("local-llama", call_local),
    ... ])
    >>> result = await model_fallback.execute_async(prompt="Hello")
    >>>
    >>> # Graceful degradation
    >>> degradation = GracefulDegradation()
    >>> if degradation.is_tool_available("web_search"):
    ...     result = await web_search(query)
"""

from proxilion.resilience.degradation import (
    DEFAULT_TIERS,
    DegradationTier,
    GracefulDegradation,
    TierConfig,
)
from proxilion.resilience.fallback import (
    FallbackChain,
    FallbackOption,
    FallbackResult,
    ModelFallback,
    ToolFallback,
)
from proxilion.resilience.retry import (
    DEFAULT_RETRY_POLICY,
    RetryContext,
    RetryPolicy,
    RetryStats,
    retry_async,
    retry_sync,
    retry_with_backoff,
)

__all__ = [
    # Retry
    "RetryPolicy",
    "RetryContext",
    "RetryStats",
    "retry_with_backoff",
    "retry_async",
    "retry_sync",
    "DEFAULT_RETRY_POLICY",
    # Fallback
    "FallbackOption",
    "FallbackResult",
    "FallbackChain",
    "ModelFallback",
    "ToolFallback",
    # Degradation
    "DegradationTier",
    "TierConfig",
    "GracefulDegradation",
    "DEFAULT_TIERS",
]
