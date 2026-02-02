"""
Tests for tool call result caching.
"""

import time
import threading
from datetime import datetime, timezone, timedelta

import pytest

from proxilion.caching import (
    ToolCache,
    CacheConfig,
    CacheEntry,
    CacheStats,
    EvictionPolicy,
    CachePolicy,
    cached_tool,
)


class TestCacheEntry:
    """Tests for CacheEntry dataclass."""

    def test_default_creation(self):
        """Test creating entry with defaults."""
        entry = CacheEntry(key="test-key", value="test-value")
        assert entry.key == "test-key"
        assert entry.value == "test-value"
        assert entry.hits == 0
        assert entry.size_bytes > 0

    def test_is_expired_no_expiry(self):
        """Test entry without expiry never expires."""
        entry = CacheEntry(key="test", value="value")
        assert not entry.is_expired()

    def test_is_expired_with_expiry(self):
        """Test entry expiration."""
        past = datetime.now(timezone.utc) - timedelta(seconds=10)
        entry = CacheEntry(key="test", value="value", expires_at=past)
        assert entry.is_expired()

        future = datetime.now(timezone.utc) + timedelta(seconds=10)
        entry = CacheEntry(key="test", value="value", expires_at=future)
        assert not entry.is_expired()

    def test_access(self):
        """Test recording access."""
        entry = CacheEntry(key="test", value="value")
        assert entry.hits == 0
        entry.access()
        assert entry.hits == 1
        entry.access()
        assert entry.hits == 2

    def test_to_dict(self):
        """Test dictionary conversion."""
        entry = CacheEntry(
            key="test-key",
            value="test-value",
            tool_name="my_tool",
        )
        d = entry.to_dict()
        assert d["key"] == "test-key"
        assert d["tool_name"] == "my_tool"
        assert "created_at" in d


class TestCacheStats:
    """Tests for CacheStats dataclass."""

    def test_hit_rate(self):
        """Test hit rate calculation."""
        stats = CacheStats(hits=3, misses=1)
        assert stats.hit_rate == 0.75

        stats = CacheStats(hits=0, misses=0)
        assert stats.hit_rate == 0.0

    def test_total_requests(self):
        """Test total requests calculation."""
        stats = CacheStats(hits=5, misses=3)
        assert stats.total_requests == 8

    def test_to_dict(self):
        """Test dictionary conversion."""
        stats = CacheStats(hits=10, misses=5, evictions=2)
        d = stats.to_dict()
        assert d["hits"] == 10
        assert d["misses"] == 5
        assert d["evictions"] == 2
        assert d["hit_rate"] == pytest.approx(0.667, rel=0.01)


class TestCachePolicy:
    """Tests for CachePolicy."""

    def test_should_cache_allowed(self):
        """Test caching allowed for normal tools."""
        policy = CachePolicy()
        assert policy.should_cache("get_weather")
        assert policy.should_cache("search_docs")

    def test_should_cache_blocked(self):
        """Test caching blocked for side-effect tools."""
        policy = CachePolicy()
        assert not policy.should_cache("send_email")
        assert not policy.should_cache("create_file")
        assert not policy.should_cache("delete_user")  # Matches delete_*
        assert not policy.should_cache("execute_code")  # Matches execute_*

    def test_get_ttl(self):
        """Test getting TTL for different tools."""
        policy = CachePolicy(
            short_ttl={"get_stock_price": 60},
            long_ttl={"get_config": 86400},
            default_ttl=300,
        )
        assert policy.get_ttl("get_stock_price") == 60
        assert policy.get_ttl("get_config") == 86400
        assert policy.get_ttl("unknown_tool") == 300


class TestToolCache:
    """Tests for ToolCache."""

    def test_basic_get_set(self):
        """Test basic cache get/set."""
        cache = ToolCache()

        cache.set("my_tool", {"arg": "value"}, "result")
        result = cache.get("my_tool", {"arg": "value"})
        assert result == "result"

    def test_cache_miss(self):
        """Test cache miss returns None."""
        cache = ToolCache()
        result = cache.get("my_tool", {"arg": "value"})
        assert result is None

    def test_different_args_different_keys(self):
        """Test that different args create different cache entries."""
        cache = ToolCache()

        cache.set("my_tool", {"city": "NYC"}, "nyc-result")
        cache.set("my_tool", {"city": "LA"}, "la-result")

        assert cache.get("my_tool", {"city": "NYC"}) == "nyc-result"
        assert cache.get("my_tool", {"city": "LA"}) == "la-result"

    def test_ttl_expiration(self):
        """Test TTL-based expiration."""
        config = CacheConfig(default_ttl=None)
        cache = ToolCache(config=config)

        # Set with short TTL
        cache.set("my_tool", {"arg": "value"}, "result", ttl=1)

        # Should be available immediately
        assert cache.get("my_tool", {"arg": "value"}) == "result"

        # Wait for expiration
        time.sleep(1.1)

        # Should be expired
        assert cache.get("my_tool", {"arg": "value"}) is None

    def test_lru_eviction(self):
        """Test LRU eviction when cache is full."""
        config = CacheConfig(max_size=2, eviction_policy=EvictionPolicy.LRU)
        cache = ToolCache(config=config)

        cache.set("tool1", {"a": 1}, "result1")
        cache.set("tool2", {"a": 2}, "result2")

        # Access tool1 to make it recently used
        cache.get("tool1", {"a": 1})

        # Add third item, should evict tool2 (least recently used)
        cache.set("tool3", {"a": 3}, "result3")

        assert cache.get("tool1", {"a": 1}) == "result1"
        assert cache.get("tool2", {"a": 2}) is None  # Evicted
        assert cache.get("tool3", {"a": 3}) == "result3"

    def test_lfu_eviction(self):
        """Test LFU eviction when cache is full."""
        config = CacheConfig(max_size=2, eviction_policy=EvictionPolicy.LFU)
        cache = ToolCache(config=config)

        cache.set("tool1", {"a": 1}, "result1")
        cache.set("tool2", {"a": 2}, "result2")

        # Access tool1 multiple times
        cache.get("tool1", {"a": 1})
        cache.get("tool1", {"a": 1})

        # Add third item, should evict tool2 (least frequently used)
        cache.set("tool3", {"a": 3}, "result3")

        assert cache.get("tool1", {"a": 1}) == "result1"
        assert cache.get("tool2", {"a": 2}) is None  # Evicted
        assert cache.get("tool3", {"a": 3}) == "result3"

    def test_invalidate_specific(self):
        """Test invalidating specific cache entry."""
        cache = ToolCache()

        cache.set("tool1", {"a": 1}, "result1")
        cache.set("tool1", {"a": 2}, "result2")

        count = cache.invalidate("tool1", {"a": 1})
        assert count == 1
        assert cache.get("tool1", {"a": 1}) is None
        assert cache.get("tool1", {"a": 2}) == "result2"

    def test_invalidate_all_for_tool(self):
        """Test invalidating all entries for a tool."""
        cache = ToolCache()

        cache.set("tool1", {"a": 1}, "result1")
        cache.set("tool1", {"a": 2}, "result2")
        cache.set("tool2", {"a": 1}, "result3")

        count = cache.invalidate("tool1")
        assert count == 2
        assert cache.get("tool1", {"a": 1}) is None
        assert cache.get("tool1", {"a": 2}) is None
        assert cache.get("tool2", {"a": 1}) == "result3"

    def test_clear(self):
        """Test clearing all cache entries."""
        cache = ToolCache()

        cache.set("tool1", {"a": 1}, "result1")
        cache.set("tool2", {"a": 2}, "result2")

        count = cache.clear()
        assert count == 2
        assert len(cache) == 0

    def test_get_stats(self):
        """Test statistics tracking."""
        cache = ToolCache()

        cache.set("tool1", {"a": 1}, "result1")
        cache.get("tool1", {"a": 1})  # Hit
        cache.get("tool1", {"a": 1})  # Hit
        cache.get("tool2", {"a": 2})  # Miss

        stats = cache.get_stats()
        assert stats.hits == 2
        assert stats.misses == 1
        assert stats.size == 1
        assert stats.hit_rate == pytest.approx(0.667, rel=0.01)

    def test_policy_prevents_caching(self):
        """Test that policy can prevent caching."""
        policy = CachePolicy(never_cache={"no_cache_tool"})
        cache = ToolCache(policy=policy)

        result = cache.set("no_cache_tool", {"a": 1}, "result")
        assert result is False
        assert cache.get("no_cache_tool", {"a": 1}) is None

    def test_policy_ttl_override(self):
        """Test that policy TTL is applied."""
        policy = CachePolicy(short_ttl={"short_tool": 1})
        config = CacheConfig(default_ttl=300)
        cache = ToolCache(config=config, policy=policy)

        cache.set("short_tool", {"a": 1}, "result")

        # Should be available immediately
        assert cache.get("short_tool", {"a": 1}) == "result"

        # Wait for policy TTL
        time.sleep(1.1)

        # Should be expired
        assert cache.get("short_tool", {"a": 1}) is None

    def test_per_user_caching(self):
        """Test per-user cache isolation."""
        config = CacheConfig(per_user_cache=True)
        cache = ToolCache(config=config)

        cache.set("tool1", {"a": 1}, "user1-result", user_id="user1")
        cache.set("tool1", {"a": 1}, "user2-result", user_id="user2")

        assert cache.get("tool1", {"a": 1}, user_id="user1") == "user1-result"
        assert cache.get("tool1", {"a": 1}, user_id="user2") == "user2-result"
        assert cache.get("tool1", {"a": 1}) is None  # No user

    def test_get_entries(self):
        """Test getting cache entries."""
        cache = ToolCache()

        cache.set("tool1", {"a": 1}, "result1")
        cache.set("tool2", {"a": 2}, "result2")

        entries = cache.get_entries()
        assert len(entries) == 2

        entries = cache.get_entries("tool1")
        assert len(entries) == 1
        assert entries[0].tool_name == "tool1"

    def test_cleanup_expired(self):
        """Test cleanup of expired entries."""
        config = CacheConfig(default_ttl=None)
        cache = ToolCache(config=config)

        cache.set("tool1", {"a": 1}, "result1", ttl=1)
        cache.set("tool2", {"a": 2}, "result2", ttl=3600)

        time.sleep(1.1)

        count = cache.cleanup_expired()
        assert count == 1
        assert len(cache) == 1

    def test_contains(self):
        """Test __contains__ method."""
        cache = ToolCache()
        cache.set("tool1", {"a": 1}, "result")

        assert ("tool1", {"a": 1}) in cache
        assert ("tool1", {"a": 2}) not in cache

    def test_thread_safety(self):
        """Test thread-safe operations."""
        cache = ToolCache()
        results = []

        def writer():
            for i in range(100):
                cache.set("tool", {"i": i}, f"result-{i}")

        def reader():
            for i in range(100):
                result = cache.get("tool", {"i": i})
                if result:
                    results.append(result)

        threads = [
            threading.Thread(target=writer),
            threading.Thread(target=reader),
            threading.Thread(target=writer),
            threading.Thread(target=reader),
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # No exceptions and cache is consistent
        assert len(cache) > 0


class TestCachedToolDecorator:
    """Tests for cached_tool decorator."""

    def test_basic_caching(self):
        """Test basic function caching."""
        cache = ToolCache()
        call_count = [0]

        @cached_tool(cache)
        def my_tool(arg1: str, arg2: int = 10) -> str:
            call_count[0] += 1
            return f"{arg1}-{arg2}"

        # First call - miss
        result1 = my_tool("test", 5)
        assert result1 == "test-5"
        assert call_count[0] == 1

        # Second call - hit
        result2 = my_tool("test", 5)
        assert result2 == "test-5"
        assert call_count[0] == 1  # Not called again

        # Different args - miss
        result3 = my_tool("test", 10)
        assert result3 == "test-10"
        assert call_count[0] == 2

    def test_custom_ttl(self):
        """Test custom TTL in decorator."""
        cache = ToolCache(config=CacheConfig(default_ttl=None))
        call_count = [0]

        @cached_tool(cache, ttl=1)
        def my_tool(arg: str) -> str:
            call_count[0] += 1
            return arg

        my_tool("test")
        assert call_count[0] == 1

        my_tool("test")
        assert call_count[0] == 1  # Cached

        time.sleep(1.1)

        my_tool("test")
        assert call_count[0] == 2  # Expired, called again

    def test_key_params(self):
        """Test filtering cache key parameters."""
        cache = ToolCache()
        call_count = [0]

        @cached_tool(cache, key_params=["important"])
        def my_tool(important: str, not_important: str) -> str:
            call_count[0] += 1
            return f"{important}-{not_important}"

        result1 = my_tool("key", "value1")
        assert call_count[0] == 1

        # Same important param, different not_important - should hit cache
        result2 = my_tool("key", "value2")
        assert call_count[0] == 1  # Cached (key_params only considers "important")
        assert result2 == "key-value1"  # Returns cached value

        # Different important param - miss
        result3 = my_tool("different", "value1")
        assert call_count[0] == 2

    def test_preserves_function_metadata(self):
        """Test that decorator preserves function metadata."""
        cache = ToolCache()

        @cached_tool(cache)
        def my_documented_tool(arg: str) -> str:
            """This is my tool's docstring."""
            return arg

        assert my_documented_tool.__name__ == "my_documented_tool"
        assert my_documented_tool.__doc__ == "This is my tool's docstring."

    def test_with_kwargs(self):
        """Test caching with keyword arguments."""
        cache = ToolCache()
        call_count = [0]

        @cached_tool(cache)
        def my_tool(a: str, b: str = "default") -> str:
            call_count[0] += 1
            return f"{a}-{b}"

        # Positional
        my_tool("x", "y")
        assert call_count[0] == 1

        # Keyword - same values
        my_tool(a="x", b="y")
        assert call_count[0] == 1  # Cached

        # Different order keyword - same values
        my_tool(b="y", a="x")
        assert call_count[0] == 1  # Cached
