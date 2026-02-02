"""
Rate limiting implementations for Proxilion.

This module provides various rate limiting strategies to prevent
unbounded consumption and protect against denial-of-service attacks.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from proxilion.exceptions import RateLimitExceeded

logger = logging.getLogger(__name__)


@dataclass
class RateLimitState:
    """State for a rate limit bucket."""
    tokens: float
    last_update: float
    request_count: int = 0


class TokenBucketRateLimiter:
    """
    Token bucket rate limiter.

    The token bucket algorithm allows bursts up to the bucket capacity
    while maintaining a long-term average rate. Tokens are added at a
    fixed rate and consumed by requests.

    Attributes:
        capacity: Maximum number of tokens in the bucket.
        refill_rate: Tokens added per second.

    Thread Safety:
        All operations are thread-safe using internal locking.

    Example:
        >>> limiter = TokenBucketRateLimiter(capacity=100, refill_rate=10)
        >>> if limiter.allow_request("user_123"):
        ...     # Process request
        ...     pass
        >>> else:
        ...     # Rate limit exceeded
        ...     raise RateLimitExceeded(...)
    """

    def __init__(
        self,
        capacity: int,
        refill_rate: float,
        key_func: Callable[[Any], str] | None = None,
    ) -> None:
        """
        Initialize the token bucket rate limiter.

        Args:
            capacity: Maximum tokens in the bucket.
            refill_rate: Tokens added per second.
            key_func: Optional function to extract rate limit key from requests.
        """
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.key_func = key_func

        self._buckets: dict[str, RateLimitState] = {}
        self._lock = threading.RLock()

    def _get_or_create_bucket(self, key: str) -> RateLimitState:
        """Get or create a bucket for a key."""
        if key not in self._buckets:
            self._buckets[key] = RateLimitState(
                tokens=float(self.capacity),
                last_update=time.monotonic(),
            )
        return self._buckets[key]

    def _refill_bucket(self, bucket: RateLimitState) -> None:
        """Refill tokens based on elapsed time."""
        now = time.monotonic()
        elapsed = now - bucket.last_update
        tokens_to_add = elapsed * self.refill_rate

        bucket.tokens = min(self.capacity, bucket.tokens + tokens_to_add)
        bucket.last_update = now

    def allow_request(self, key: str, cost: int = 1) -> bool:
        """
        Check if a request is allowed and consume tokens.

        Args:
            key: The rate limit key (e.g., user ID, IP address).
            cost: Number of tokens to consume (default 1).

        Returns:
            True if the request is allowed, False if rate limited.

        Example:
            >>> if limiter.allow_request("user_123", cost=5):
            ...     # Expensive operation
            ...     pass
        """
        with self._lock:
            bucket = self._get_or_create_bucket(key)
            self._refill_bucket(bucket)

            if bucket.tokens >= cost:
                bucket.tokens -= cost
                bucket.request_count += 1
                logger.debug(
                    f"Rate limit: key={key}, tokens_remaining={bucket.tokens:.1f}"
                )
                return True

            logger.debug(
                f"Rate limit exceeded: key={key}, "
                f"tokens={bucket.tokens:.1f}, cost={cost}"
            )
            return False

    def get_remaining(self, key: str) -> int:
        """
        Get remaining tokens for a key.

        Args:
            key: The rate limit key.

        Returns:
            Number of available tokens (floored to int).
        """
        with self._lock:
            bucket = self._get_or_create_bucket(key)
            self._refill_bucket(bucket)
            return int(bucket.tokens)

    def get_retry_after(self, key: str, cost: int = 1) -> float:
        """
        Get seconds until enough tokens are available.

        Args:
            key: The rate limit key.
            cost: Number of tokens needed.

        Returns:
            Seconds to wait, or 0 if tokens are available.
        """
        with self._lock:
            bucket = self._get_or_create_bucket(key)
            self._refill_bucket(bucket)

            if bucket.tokens >= cost:
                return 0.0

            tokens_needed = cost - bucket.tokens
            return tokens_needed / self.refill_rate

    def reset(self, key: str) -> None:
        """Reset a bucket to full capacity."""
        with self._lock:
            if key in self._buckets:
                del self._buckets[key]

    def reset_all(self) -> None:
        """Reset all buckets."""
        with self._lock:
            self._buckets.clear()


class SlidingWindowRateLimiter:
    """
    Sliding window rate limiter.

    Unlike token bucket, sliding window provides more consistent
    rate limiting by tracking requests within a time window.
    This prevents bursts at window boundaries.

    Example:
        >>> limiter = SlidingWindowRateLimiter(
        ...     max_requests=100,
        ...     window_seconds=60
        ... )
        >>> if limiter.allow_request("user_123"):
        ...     # Process request
        ...     pass
    """

    def __init__(
        self,
        max_requests: int,
        window_seconds: float,
    ) -> None:
        """
        Initialize the sliding window rate limiter.

        Args:
            max_requests: Maximum requests allowed in the window.
            window_seconds: Window size in seconds.
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds

        self._requests: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.RLock()

    def _cleanup_old_requests(self, key: str) -> None:
        """Remove requests outside the window."""
        cutoff = time.monotonic() - self.window_seconds
        self._requests[key] = [
            t for t in self._requests[key] if t > cutoff
        ]

    def allow_request(self, key: str, cost: int = 1) -> bool:
        """
        Check if a request is allowed.

        Args:
            key: The rate limit key.
            cost: Number of "requests" to count (for weighted limiting).

        Returns:
            True if allowed, False if rate limited.
        """
        with self._lock:
            self._cleanup_old_requests(key)

            current_count = len(self._requests[key])
            if current_count + cost <= self.max_requests:
                now = time.monotonic()
                for _ in range(cost):
                    self._requests[key].append(now)
                return True

            return False

    def get_remaining(self, key: str) -> int:
        """Get remaining requests allowed in current window."""
        with self._lock:
            self._cleanup_old_requests(key)
            return max(0, self.max_requests - len(self._requests[key]))

    def get_retry_after(self, key: str) -> float:
        """Get seconds until the oldest request expires from window."""
        with self._lock:
            self._cleanup_old_requests(key)

            if len(self._requests[key]) < self.max_requests:
                return 0.0

            if not self._requests[key]:
                return 0.0

            oldest = min(self._requests[key])
            expires_at = oldest + self.window_seconds
            return max(0.0, expires_at - time.monotonic())

    def reset(self, key: str) -> None:
        """Reset request history for a key."""
        with self._lock:
            self._requests.pop(key, None)


@dataclass
class RateLimitConfig:
    """Configuration for a rate limit dimension."""
    capacity: int
    refill_rate: float
    window_seconds: float | None = None  # For sliding window


class MultiDimensionalRateLimiter:
    """
    Multi-dimensional rate limiter.

    Applies different rate limits based on multiple dimensions:
    user, tool, action, time of day, etc.

    Example:
        >>> limiter = MultiDimensionalRateLimiter({
        ...     "user": RateLimitConfig(capacity=100, refill_rate=10),
        ...     "tool": RateLimitConfig(capacity=50, refill_rate=5),
        ...     "global": RateLimitConfig(capacity=1000, refill_rate=100),
        ... })
        >>>
        >>> keys = {"user": "user_123", "tool": "database_query"}
        >>> if limiter.allow_request(keys):
        ...     # All limits passed
        ...     pass
    """

    def __init__(
        self,
        limits: dict[str, RateLimitConfig],
        use_sliding_window: bool = False,
    ) -> None:
        """
        Initialize the multi-dimensional rate limiter.

        Args:
            limits: Dictionary of dimension name to RateLimitConfig.
            use_sliding_window: If True, use sliding window instead of token bucket.
        """
        self.limits = limits
        self._limiters: dict[str, TokenBucketRateLimiter | SlidingWindowRateLimiter] = {}

        for dimension, config in limits.items():
            if use_sliding_window and config.window_seconds:
                self._limiters[dimension] = SlidingWindowRateLimiter(
                    max_requests=config.capacity,
                    window_seconds=config.window_seconds,
                )
            else:
                self._limiters[dimension] = TokenBucketRateLimiter(
                    capacity=config.capacity,
                    refill_rate=config.refill_rate,
                )

    def allow_request(
        self,
        keys: dict[str, str],
        costs: dict[str, int] | None = None,
    ) -> bool:
        """
        Check if request is allowed across all dimensions.

        Args:
            keys: Dictionary mapping dimension names to keys.
            costs: Optional per-dimension costs (default 1 for all).

        Returns:
            True if all dimensions allow the request.
        """
        costs = costs or {}

        # Check all dimensions first (don't consume until we know all pass)
        for dimension, key in keys.items():
            if dimension not in self._limiters:
                continue

            limiter = self._limiters[dimension]
            cost = costs.get(dimension, 1)

            # For token bucket, we need to check without consuming
            if isinstance(limiter, TokenBucketRateLimiter):
                if limiter.get_remaining(key) < cost:
                    logger.debug(
                        f"Rate limit failed: dimension={dimension}, key={key}"
                    )
                    return False
            else:
                if limiter.get_remaining(key) < cost:
                    logger.debug(
                        f"Rate limit failed: dimension={dimension}, key={key}"
                    )
                    return False

        # All checks passed, now consume tokens
        for dimension, key in keys.items():
            if dimension not in self._limiters:
                continue

            limiter = self._limiters[dimension]
            cost = costs.get(dimension, 1)
            limiter.allow_request(key, cost)

        return True

    def get_most_restrictive(
        self,
        keys: dict[str, str],
    ) -> tuple[str, int]:
        """
        Get the most restrictive dimension.

        Args:
            keys: Dictionary mapping dimension names to keys.

        Returns:
            Tuple of (dimension_name, remaining_tokens).
        """
        min_remaining = float("inf")
        min_dimension = ""

        for dimension, key in keys.items():
            if dimension not in self._limiters:
                continue

            remaining = self._limiters[dimension].get_remaining(key)
            if remaining < min_remaining:
                min_remaining = remaining
                min_dimension = dimension

        return min_dimension, int(min_remaining)


class RateLimiterMiddleware:
    """
    Rate limiter middleware for tool calls.

    Integrates rate limiting with the authorization flow,
    raising RateLimitExceeded when limits are hit.

    Example:
        >>> middleware = RateLimiterMiddleware(
        ...     user_limit=TokenBucketRateLimiter(100, 10),
        ...     tool_limits={"database_query": TokenBucketRateLimiter(10, 1)},
        ... )
        >>>
        >>> middleware.check_rate_limit(user, "database_query")
    """

    def __init__(
        self,
        user_limit: TokenBucketRateLimiter | None = None,
        tool_limits: dict[str, TokenBucketRateLimiter] | None = None,
        global_limit: TokenBucketRateLimiter | None = None,
    ) -> None:
        """
        Initialize the middleware.

        Args:
            user_limit: Per-user rate limiter.
            tool_limits: Per-tool rate limiters.
            global_limit: Global rate limiter.
        """
        self.user_limit = user_limit
        self.tool_limits = tool_limits or {}
        self.global_limit = global_limit

    def check_rate_limit(
        self,
        user_id: str,
        tool_name: str,
        cost: int = 1,
    ) -> None:
        """
        Check rate limits and raise if exceeded.

        Args:
            user_id: The user's ID.
            tool_name: The tool being called.
            cost: Token cost for this request.

        Raises:
            RateLimitExceeded: If any rate limit is exceeded.
        """
        # Check global limit
        if self.global_limit and not self.global_limit.allow_request("global", cost):
            retry_after = self.global_limit.get_retry_after("global", cost)
            raise RateLimitExceeded(
                limit_type="global",
                limit_key="global",
                limit_value=self.global_limit.capacity,
                retry_after=retry_after,
            )

        # Check user limit
        if self.user_limit and not self.user_limit.allow_request(user_id, cost):
            retry_after = self.user_limit.get_retry_after(user_id, cost)
            raise RateLimitExceeded(
                limit_type="user",
                limit_key=user_id,
                limit_value=self.user_limit.capacity,
                retry_after=retry_after,
            )

        # Check tool-specific limit
        if tool_name in self.tool_limits:
            tool_limiter = self.tool_limits[tool_name]
            key = f"{user_id}:{tool_name}"
            if not tool_limiter.allow_request(key, cost):
                retry_after = tool_limiter.get_retry_after(key, cost)
                raise RateLimitExceeded(
                    limit_type="tool",
                    limit_key=key,
                    limit_value=tool_limiter.capacity,
                    retry_after=retry_after,
                )

    def get_headers(
        self,
        user_id: str,
        tool_name: str,
    ) -> dict[str, str]:
        """
        Get rate limit headers for API responses.

        Args:
            user_id: The user's ID.
            tool_name: The tool name.

        Returns:
            Dictionary of rate limit headers.
        """
        headers: dict[str, str] = {}

        if self.user_limit:
            remaining = self.user_limit.get_remaining(user_id)
            headers["X-RateLimit-Limit"] = str(self.user_limit.capacity)
            headers["X-RateLimit-Remaining"] = str(remaining)

        return headers
