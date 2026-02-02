"""
Caching components for Proxilion.

Provides tool call result caching to improve performance
and reduce costs by avoiding redundant tool executions.

Example:
    >>> from proxilion.caching import (
    ...     ToolCache, CacheConfig, CacheEntry, CacheStats,
    ...     CachePolicy, cached_tool,
    ... )
    >>>
    >>> # Create cache with custom config
    >>> config = CacheConfig(max_size=1000, default_ttl=300)
    >>> cache = ToolCache(config)
    >>>
    >>> # Manual caching
    >>> cache.set("get_weather", {"city": "NYC"}, {"temp": 72})
    >>> result = cache.get("get_weather", {"city": "NYC"})
    >>>
    >>> # Decorator-based caching
    >>> @cached_tool(cache, ttl=300)
    ... def get_weather(city: str) -> dict:
    ...     return weather_api.get(city)
    >>>
    >>> # Check stats
    >>> stats = cache.get_stats()
    >>> print(f"Hit rate: {stats.hit_rate:.2%}")
"""

from proxilion.caching.tool_cache import (
    CacheConfig,
    CacheEntry,
    CachePolicy,
    CacheStats,
    EvictionPolicy,
    ToolCache,
    cached_tool,
)

__all__ = [
    "ToolCache",
    "CacheEntry",
    "CacheConfig",
    "CacheStats",
    "EvictionPolicy",
    "CachePolicy",
    "cached_tool",
]
