"""
Tests for rate limiting implementations.

Tests cover:
- TokenBucketRateLimiter
- SlidingWindowRateLimiter
- MultiDimensionalRateLimiter
- Thread safety
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from proxilion.security.rate_limiter import (
    MultiDimensionalRateLimiter,
    RateLimitConfig,
    SlidingWindowRateLimiter,
    TokenBucketRateLimiter,
)


class TestTokenBucketRateLimiter:
    """Tests for TokenBucketRateLimiter."""

    def test_initialization(self):
        """Test rate limiter initialization."""
        limiter = TokenBucketRateLimiter(capacity=100, refill_rate=10)
        assert limiter is not None

    def test_allows_requests_under_limit(self, rate_limiter: TokenBucketRateLimiter):
        """Test that requests under limit are allowed."""
        # Should allow up to capacity
        for i in range(10):
            assert rate_limiter.allow_request(f"user_{i}") is True

    def test_denies_requests_over_limit(self):
        """Test that requests over limit are denied."""
        limiter = TokenBucketRateLimiter(capacity=3, refill_rate=0.1)

        # Exhaust the bucket
        assert limiter.allow_request("user_1") is True
        assert limiter.allow_request("user_1") is True
        assert limiter.allow_request("user_1") is True

        # Next request should be denied
        assert limiter.allow_request("user_1") is False

    def test_tokens_refill_over_time(self):
        """Test that tokens refill over time."""
        limiter = TokenBucketRateLimiter(capacity=2, refill_rate=10)  # 10 tokens/sec

        # Exhaust tokens
        assert limiter.allow_request("user_1") is True
        assert limiter.allow_request("user_1") is True
        assert limiter.allow_request("user_1") is False

        # Wait for refill
        time.sleep(0.2)  # Should refill ~2 tokens

        # Should be allowed again
        assert limiter.allow_request("user_1") is True

    def test_different_users_have_separate_buckets(self, rate_limiter: TokenBucketRateLimiter):
        """Test that different users have separate token buckets."""
        # Exhaust user_1's tokens
        for _ in range(10):
            rate_limiter.allow_request("user_1")

        # user_2 should still have tokens
        assert rate_limiter.allow_request("user_2") is True

    def test_get_remaining_tokens(self):
        """Test getting remaining token count."""
        limiter = TokenBucketRateLimiter(capacity=10, refill_rate=1)

        assert limiter.get_remaining("new_user") == 10

        limiter.allow_request("new_user")
        assert limiter.get_remaining("new_user") == 9

    def test_variable_cost_requests(self):
        """Test requests with variable token cost."""
        limiter = TokenBucketRateLimiter(capacity=10, refill_rate=1)

        # Request with cost of 5
        assert limiter.allow_request("user_1", cost=5) is True
        assert limiter.get_remaining("user_1") == 5

        # Request with cost of 6 should fail
        assert limiter.allow_request("user_1", cost=6) is False

        # Request with cost of 5 should succeed
        assert limiter.allow_request("user_1", cost=5) is True

    def test_thread_safety(self):
        """Test thread safety of rate limiter."""
        # Use a very small refill rate to prevent tokens from refilling during the test
        limiter = TokenBucketRateLimiter(capacity=100, refill_rate=0.001)

        results = []

        def make_request():
            result = limiter.allow_request("user_1")
            results.append(result)

        # Run 150 requests concurrently
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(make_request) for _ in range(150)]
            for f in futures:
                f.result()

        # Exactly 100 should be allowed
        allowed = sum(1 for r in results if r)
        assert allowed == 100


class TestSlidingWindowRateLimiter:
    """Tests for SlidingWindowRateLimiter."""

    def test_initialization(self):
        """Test sliding window limiter initialization."""
        limiter = SlidingWindowRateLimiter(max_requests=10, window_seconds=60)
        assert limiter is not None

    def test_allows_requests_under_limit(self, sliding_window_limiter: SlidingWindowRateLimiter):
        """Test that requests under limit are allowed."""
        for i in range(10):
            assert sliding_window_limiter.allow_request(f"user_{i}") is True

    def test_denies_requests_over_limit(self):
        """Test that requests over limit are denied."""
        limiter = SlidingWindowRateLimiter(max_requests=3, window_seconds=60)

        assert limiter.allow_request("user_1") is True
        assert limiter.allow_request("user_1") is True
        assert limiter.allow_request("user_1") is True
        assert limiter.allow_request("user_1") is False

    def test_window_slides_over_time(self):
        """Test that the window slides and old requests expire."""
        limiter = SlidingWindowRateLimiter(max_requests=2, window_seconds=0.2)

        # Make 2 requests
        assert limiter.allow_request("user_1") is True
        assert limiter.allow_request("user_1") is True
        assert limiter.allow_request("user_1") is False

        # Wait for window to slide
        time.sleep(0.3)

        # Should be allowed again
        assert limiter.allow_request("user_1") is True

    def test_different_users_separate_windows(self):
        """Test that different users have separate windows."""
        limiter = SlidingWindowRateLimiter(max_requests=2, window_seconds=60)

        # Exhaust user_1
        limiter.allow_request("user_1")
        limiter.allow_request("user_1")
        assert limiter.allow_request("user_1") is False

        # user_2 should still work
        assert limiter.allow_request("user_2") is True

    def test_get_remaining(self):
        """Test getting remaining requests in window."""
        limiter = SlidingWindowRateLimiter(max_requests=10, window_seconds=60)

        assert limiter.get_remaining("user_1") == 10

        limiter.allow_request("user_1")
        limiter.allow_request("user_1")

        assert limiter.get_remaining("user_1") == 8


class TestMultiDimensionalRateLimiter:
    """Tests for MultiDimensionalRateLimiter."""

    def test_initialization(self):
        """Test multi-dimensional limiter initialization."""
        config = {
            "user": RateLimitConfig(capacity=100, refill_rate=10),
            "tool": RateLimitConfig(capacity=50, refill_rate=5),
        }
        limiter = MultiDimensionalRateLimiter(config)
        assert limiter is not None

    def test_checks_all_dimensions(self):
        """Test that all dimensions are checked."""
        # Use a very small refill rate to prevent tokens from refilling during the test
        config = {
            "user": RateLimitConfig(capacity=10, refill_rate=0.001),
            "tool": RateLimitConfig(capacity=5, refill_rate=0.001),
        }
        limiter = MultiDimensionalRateLimiter(config)

        # First 5 requests should pass (limited by tool)
        for _ in range(5):
            assert limiter.allow_request(
                keys={"user": "user_1", "tool": "tool_a"}
            ) is True

        # 6th request should fail (tool limit)
        assert limiter.allow_request(
            keys={"user": "user_1", "tool": "tool_a"}
        ) is False

    def test_different_tools_separate_limits(self):
        """Test that different tools have separate limits."""
        # Use a very small refill rate to prevent tokens from refilling during the test
        config = {
            "tool": RateLimitConfig(capacity=2, refill_rate=0.001),
        }
        limiter = MultiDimensionalRateLimiter(config)

        # Exhaust tool_a
        limiter.allow_request(keys={"tool": "tool_a"})
        limiter.allow_request(keys={"tool": "tool_a"})
        assert limiter.allow_request(keys={"tool": "tool_a"}) is False

        # tool_b should still work
        assert limiter.allow_request(keys={"tool": "tool_b"}) is True

    def test_combined_user_and_tool_limits(self):
        """Test combined user and tool rate limiting."""
        # Use a very small refill rate to prevent tokens from refilling during the test
        config = {
            "user": RateLimitConfig(capacity=10, refill_rate=0.001),
            "tool": RateLimitConfig(capacity=3, refill_rate=0.001),
        }
        limiter = MultiDimensionalRateLimiter(config)

        # Use tool_a 3 times
        for _ in range(3):
            limiter.allow_request(keys={"user": "user_1", "tool": "tool_a"})

        # tool_a is exhausted
        assert limiter.allow_request(
            keys={"user": "user_1", "tool": "tool_a"}
        ) is False

        # But user can still use tool_b
        assert limiter.allow_request(
            keys={"user": "user_1", "tool": "tool_b"}
        ) is True


class TestRateLimitConfig:
    """Tests for RateLimitConfig dataclass."""

    def test_config_creation(self):
        """Test creating rate limit config."""
        config = RateLimitConfig(capacity=100, refill_rate=10.0)
        assert config.capacity == 100
        assert config.refill_rate == 10.0

    def test_config_with_defaults(self):
        """Test config with default values."""
        config = RateLimitConfig(capacity=50, refill_rate=5.0)
        assert config.capacity == 50
