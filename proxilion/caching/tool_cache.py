"""
Tool call result caching.

Provides caching for tool call results to avoid redundant
executions and improve performance.
"""

from __future__ import annotations

import fnmatch
import functools
import hashlib
import json
import logging
import sys
import threading
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any, ParamSpec, TypeVar

logger = logging.getLogger(__name__)

# Sentinel object to distinguish cache misses from cached None values
_CACHE_MISS = object()

P = ParamSpec("P")
T = TypeVar("T")


class EvictionPolicy(Enum):
    """Cache eviction policies."""

    LRU = auto()  # Least Recently Used
    LFU = auto()  # Least Frequently Used
    FIFO = auto()  # First In First Out


@dataclass
class CacheConfig:
    """
    Configuration for the tool cache.

    Attributes:
        max_size: Maximum number of entries in cache.
        default_ttl: Default time-to-live in seconds.
        eviction_policy: Policy for evicting entries when full.
        per_user_cache: Whether to maintain separate caches per user.

    Example:
        >>> config = CacheConfig(
        ...     max_size=500,
        ...     default_ttl=600,
        ...     eviction_policy=EvictionPolicy.LRU,
        ... )
    """

    max_size: int = 1000
    default_ttl: int | None = 300  # 5 minutes
    eviction_policy: EvictionPolicy = EvictionPolicy.LRU
    per_user_cache: bool = False


@dataclass
class CacheEntry:
    """
    A single cache entry.

    Attributes:
        key: Cache key (hash).
        value: Cached value.
        created_at: When entry was created.
        expires_at: When entry expires (None = never).
        hits: Number of times this entry was accessed.
        size_bytes: Estimated size in bytes.
        tool_name: Name of the cached tool.
        user_id: User ID if per-user caching.

    Example:
        >>> entry = CacheEntry(
        ...     key="abc123",
        ...     value={"result": "data"},
        ...     tool_name="get_weather",
        ... )
    """

    key: str
    value: Any
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None
    hits: int = 0
    size_bytes: int = 0
    tool_name: str = ""
    user_id: str | None = None

    def __post_init__(self) -> None:
        """Calculate size on creation."""
        if self.size_bytes == 0:
            self.size_bytes = self._estimate_size(self.value)

    def _estimate_size(self, obj: Any) -> int:
        """Estimate object size in bytes."""
        try:
            return sys.getsizeof(json.dumps(obj, default=str))
        except (TypeError, ValueError):
            return sys.getsizeof(str(obj))

    def is_expired(self) -> bool:
        """Check if this entry has expired."""
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) >= self.expires_at

    def access(self) -> None:
        """Record an access to this entry."""
        self.hits += 1

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "key": self.key,
            "tool_name": self.tool_name,
            "user_id": self.user_id,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "hits": self.hits,
            "size_bytes": self.size_bytes,
            "is_expired": self.is_expired(),
        }


@dataclass
class CacheStats:
    """
    Cache statistics.

    Attributes:
        hits: Number of cache hits.
        misses: Number of cache misses.
        evictions: Number of evicted entries.
        size: Current number of entries.
        size_bytes: Estimated total size in bytes.

    Example:
        >>> stats = cache.get_stats()
        >>> print(f"Hit rate: {stats.hit_rate:.2%}")
    """

    hits: int = 0
    misses: int = 0
    evictions: int = 0
    size: int = 0
    size_bytes: int = 0
    expirations: int = 0

    @property
    def hit_rate(self) -> float:
        """Calculate cache hit rate."""
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0

    @property
    def total_requests(self) -> int:
        """Get total number of cache requests."""
        return self.hits + self.misses

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "hits": self.hits,
            "misses": self.misses,
            "evictions": self.evictions,
            "expirations": self.expirations,
            "size": self.size,
            "size_bytes": self.size_bytes,
            "hit_rate": self.hit_rate,
            "total_requests": self.total_requests,
        }


@dataclass
class CachePolicy:
    """
    Policy for selective caching.

    Defines which tools should be cached and their TTL settings.

    Attributes:
        never_cache: Tools that should never be cached (have side effects).
        short_ttl: Tools with short TTL (frequently changing data).
        long_ttl: Tools with long TTL (stable data).
        default_ttl: Default TTL for unlisted tools.

    Example:
        >>> policy = CachePolicy(
        ...     never_cache={"send_email", "create_file"},
        ...     short_ttl={"get_stock_price": 60},
        ...     long_ttl={"get_config": 86400},
        ... )
    """

    never_cache: set[str] = field(default_factory=lambda: {
        "send_email",
        "create_file",
        "delete_*",
        "execute_*",
        "write_*",
        "update_*",
        "insert_*",
    })
    short_ttl: dict[str, int] = field(default_factory=lambda: {
        "get_stock_price": 60,
        "get_weather": 300,
        "get_current_time": 1,
    })
    long_ttl: dict[str, int] = field(default_factory=lambda: {
        "get_user_profile": 3600,
        "get_config": 86400,
        "get_schema": 86400,
    })
    default_ttl: int | None = 300

    def should_cache(self, tool_name: str) -> bool:
        """
        Check if a tool should be cached.

        Args:
            tool_name: Name of the tool.

        Returns:
            True if the tool should be cached.
        """
        return all(not fnmatch.fnmatch(tool_name, pattern) for pattern in self.never_cache)

    def get_ttl(self, tool_name: str) -> int | None:
        """
        Get TTL for a tool.

        Args:
            tool_name: Name of the tool.

        Returns:
            TTL in seconds, or None for no expiration.
        """
        if tool_name in self.short_ttl:
            return self.short_ttl[tool_name]
        if tool_name in self.long_ttl:
            return self.long_ttl[tool_name]
        return self.default_ttl


class ToolCache:
    """
    Tool call result cache.

    Caches tool call results to avoid redundant executions.
    Supports multiple eviction policies and per-user caching.

    Example:
        >>> cache = ToolCache(CacheConfig(max_size=500))
        >>>
        >>> # Store result
        >>> cache.set("get_weather", {"city": "NYC"}, {"temp": 72})
        >>>
        >>> # Retrieve result
        >>> result = cache.get("get_weather", {"city": "NYC"})
        >>>
        >>> # Check stats
        >>> print(cache.get_stats())
    """

    def __init__(
        self,
        config: CacheConfig | None = None,
        policy: CachePolicy | None = None,
    ) -> None:
        """
        Initialize the cache.

        Args:
            config: Cache configuration.
            policy: Caching policy for tool-specific settings.
        """
        self.config = config or CacheConfig()
        self.policy = policy or CachePolicy()

        # Use OrderedDict for LRU/FIFO eviction
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._lock = threading.RLock()
        self._stats = CacheStats()

    def _generate_key(
        self,
        tool_name: str,
        args: dict[str, Any],
        user_id: str | None = None,
    ) -> str:
        """
        Generate deterministic cache key.

        Args:
            tool_name: Name of the tool.
            args: Tool arguments.
            user_id: Optional user ID for per-user caching.

        Returns:
            SHA-256 hash as cache key.
        """
        key_data = {
            "tool": tool_name,
            "args": json.dumps(args, sort_keys=True, default=str),
        }
        if self.config.per_user_cache and user_id:
            key_data["user"] = user_id

        key_str = json.dumps(key_data, sort_keys=True)
        return hashlib.sha256(key_str.encode()).hexdigest()

    def get(
        self,
        tool_name: str,
        args: dict[str, Any],
        user_id: str | None = None,
        default: Any = None,
    ) -> Any:
        """
        Get a cached result.

        Args:
            tool_name: Name of the tool.
            args: Tool arguments.
            user_id: Optional user ID.
            default: Value to return if not found/expired (default: None).
                Use _CACHE_MISS sentinel to distinguish misses from cached None.

        Returns:
            Cached value or default if not found/expired.
        """
        key = self._generate_key(tool_name, args, user_id)

        with self._lock:
            entry = self._cache.get(key)

            if entry is None:
                self._stats.misses += 1
                return default

            if entry.is_expired():
                # Remove expired entry
                del self._cache[key]
                self._stats.misses += 1
                self._stats.expirations += 1
                return default

            # Record hit and move to end (for LRU)
            entry.access()
            self._stats.hits += 1

            if self.config.eviction_policy == EvictionPolicy.LRU:
                self._cache.move_to_end(key)

            return entry.value

    def set(
        self,
        tool_name: str,
        args: dict[str, Any],
        result: Any,
        ttl: int | None = None,
        user_id: str | None = None,
    ) -> bool:
        """
        Cache a tool result.

        Args:
            tool_name: Name of the tool.
            args: Tool arguments.
            result: Result to cache.
            ttl: Time-to-live in seconds (overrides policy).
            user_id: Optional user ID.

        Returns:
            True if cached, False if caching is disabled for this tool.
        """
        # Check policy
        if not self.policy.should_cache(tool_name):
            return False

        # Get TTL
        if ttl is None:
            ttl = self.policy.get_ttl(tool_name)

        key = self._generate_key(tool_name, args, user_id)

        # Calculate expiration
        expires_at = None
        if ttl is not None:
            from datetime import timedelta
            expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl)

        entry = CacheEntry(
            key=key,
            value=result,
            expires_at=expires_at,
            tool_name=tool_name,
            user_id=user_id,
        )

        with self._lock:
            # Evict if necessary
            while len(self._cache) >= self.config.max_size:
                self._evict_one()

            self._cache[key] = entry
            self._stats.size = len(self._cache)
            self._stats.size_bytes += entry.size_bytes

        return True

    def _evict_one(self) -> None:
        """Evict one entry based on policy."""
        if not self._cache:
            return

        if self.config.eviction_policy == EvictionPolicy.LRU:
            # Remove oldest (first) item
            key, entry = self._cache.popitem(last=False)
        elif self.config.eviction_policy == EvictionPolicy.FIFO:
            # Remove first inserted item
            key, entry = self._cache.popitem(last=False)
        elif self.config.eviction_policy == EvictionPolicy.LFU:
            # Remove least frequently used
            min_hits = float("inf")
            min_key = None
            for k, e in self._cache.items():
                if e.hits < min_hits:
                    min_hits = e.hits
                    min_key = k
            if min_key:
                entry = self._cache.pop(min_key)
            else:
                return
        else:
            return

        self._stats.evictions += 1
        self._stats.size_bytes -= entry.size_bytes
        logger.debug(f"Evicted cache entry: {entry.tool_name}")

    def invalidate(
        self,
        tool_name: str,
        args: dict[str, Any] | None = None,
        user_id: str | None = None,
    ) -> int:
        """
        Invalidate cache entries.

        Args:
            tool_name: Name of the tool to invalidate.
            args: Specific arguments (None = all entries for tool).
            user_id: Specific user (None = all users).

        Returns:
            Number of entries invalidated.
        """
        with self._lock:
            if args is not None:
                # Invalidate specific entry
                key = self._generate_key(tool_name, args, user_id)
                if key in self._cache:
                    entry = self._cache.pop(key)
                    self._stats.size_bytes -= entry.size_bytes
                    self._stats.size = len(self._cache)
                    return 1
                return 0

            # Invalidate all entries for this tool
            keys_to_remove = [
                k for k, v in self._cache.items()
                if v.tool_name == tool_name
                and (user_id is None or v.user_id == user_id)
            ]

            for key in keys_to_remove:
                entry = self._cache.pop(key)
                self._stats.size_bytes -= entry.size_bytes

            self._stats.size = len(self._cache)
            return len(keys_to_remove)

    def clear(self) -> int:
        """
        Clear all cache entries.

        Returns:
            Number of entries cleared.
        """
        with self._lock:
            count = len(self._cache)
            self._cache.clear()
            self._stats.size = 0
            self._stats.size_bytes = 0
            return count

    def get_stats(self) -> CacheStats:
        """
        Get cache statistics.

        Returns:
            Current cache statistics.
        """
        with self._lock:
            self._stats.size = len(self._cache)
            return CacheStats(
                hits=self._stats.hits,
                misses=self._stats.misses,
                evictions=self._stats.evictions,
                expirations=self._stats.expirations,
                size=self._stats.size,
                size_bytes=self._stats.size_bytes,
            )

    def get_entries(self, tool_name: str | None = None) -> list[CacheEntry]:
        """
        Get all cache entries.

        Args:
            tool_name: Filter by tool name (optional).

        Returns:
            List of cache entries.
        """
        with self._lock:
            entries = list(self._cache.values())
            if tool_name:
                entries = [e for e in entries if e.tool_name == tool_name]
            return entries

    def cleanup_expired(self) -> int:
        """
        Remove all expired entries.

        Returns:
            Number of entries removed.
        """
        with self._lock:
            expired_keys = [
                k for k, v in self._cache.items()
                if v.is_expired()
            ]

            for key in expired_keys:
                entry = self._cache.pop(key)
                self._stats.size_bytes -= entry.size_bytes
                self._stats.expirations += 1

            self._stats.size = len(self._cache)
            return len(expired_keys)

    def __contains__(self, key: tuple[str, dict[str, Any]]) -> bool:
        """Check if a tool/args combination is cached."""
        tool_name, args = key
        return self.get(tool_name, args, default=_CACHE_MISS) is not _CACHE_MISS

    def __len__(self) -> int:
        """Get number of cached entries."""
        with self._lock:
            return len(self._cache)


def cached_tool(
    cache: ToolCache,
    ttl: int | None = None,
    key_params: list[str] | None = None,
) -> Callable[[Callable[P, T]], Callable[P, T]]:
    """
    Decorator that caches tool call results.

    Args:
        cache: ToolCache instance to use.
        ttl: Time-to-live in seconds (overrides policy).
        key_params: Specific parameters to use for cache key.

    Returns:
        Decorated function.

    Example:
        >>> cache = ToolCache()
        >>>
        >>> @cached_tool(cache, ttl=300)
        ... def get_weather(city: str) -> dict:
        ...     return weather_api.get(city)
        >>>
        >>> # First call - cache miss, executes function
        >>> result1 = get_weather("NYC")
        >>>
        >>> # Second call - cache hit, returns cached value
        >>> result2 = get_weather("NYC")
    """

    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        tool_name = func.__name__

        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            # Build args dict for cache key
            import inspect
            sig = inspect.signature(func)
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
            all_args = dict(bound.arguments)

            # Filter to key_params if specified
            if key_params:
                cache_args = {k: v for k, v in all_args.items() if k in key_params}
            else:
                cache_args = all_args

            # Check cache — use sentinel to handle cached falsy values (None, False, 0)
            cached_result = cache.get(tool_name, cache_args, default=_CACHE_MISS)
            if cached_result is not _CACHE_MISS:
                logger.debug(f"Cache hit for {tool_name}")
                return cached_result

            # Execute function
            result = func(*args, **kwargs)

            # Store in cache
            cache.set(tool_name, cache_args, result, ttl=ttl)
            logger.debug(f"Cached result for {tool_name}")

            return result

        return wrapper

    return decorator
