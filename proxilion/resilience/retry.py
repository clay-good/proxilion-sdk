"""
Retry logic with exponential backoff for AI operations.

Provides configurable retry policies with exponential backoff,
jitter, and customizable retry conditions.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import logging
import random
import threading
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, ParamSpec, TypeVar

logger = logging.getLogger(__name__)

P = ParamSpec("P")
T = TypeVar("T")


@dataclass
class RetryPolicy:
    """
    Configuration for retry behavior.

    Attributes:
        max_attempts: Maximum number of attempts (including the first try).
        base_delay: Base delay between retries in seconds.
        max_delay: Maximum delay between retries in seconds.
        exponential_base: Base for exponential backoff calculation.
        jitter: Jitter factor as a fraction (0.1 = +/- 10%).
        retryable_exceptions: Tuple of exception types that trigger retry.
        retry_on: Optional custom function to determine if retry should occur.

    Example:
        >>> policy = RetryPolicy(
        ...     max_attempts=5,
        ...     base_delay=1.0,
        ...     max_delay=60.0,
        ...     exponential_base=2.0,
        ...     jitter=0.1,
        ... )
    """

    max_attempts: int = 3
    base_delay: float = 1.0
    max_delay: float = 30.0
    exponential_base: float = 2.0
    jitter: float = 0.1
    retryable_exceptions: tuple[type[Exception], ...] = (
        TimeoutError,
        ConnectionError,
        OSError,
    )
    retry_on: Callable[[Exception], bool] | None = None

    def __post_init__(self) -> None:
        """Validate policy parameters."""
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        if self.base_delay < 0:
            raise ValueError("base_delay must be non-negative")
        if self.max_delay < self.base_delay:
            raise ValueError("max_delay must be >= base_delay")
        if self.exponential_base < 1:
            raise ValueError("exponential_base must be >= 1")
        if not 0 <= self.jitter <= 1:
            raise ValueError("jitter must be between 0 and 1")

    def calculate_delay(self, attempt: int) -> float:
        """
        Calculate delay for a given attempt number.

        Args:
            attempt: The attempt number (1-indexed).

        Returns:
            Delay in seconds with jitter applied.
        """
        # Exponential backoff: base_delay * (exponential_base ^ (attempt - 1))
        delay = self.base_delay * (self.exponential_base ** (attempt - 1))

        # Cap at max_delay
        delay = min(delay, self.max_delay)

        # Apply jitter
        if self.jitter > 0:
            jitter_range = delay * self.jitter
            delay = delay + random.uniform(-jitter_range, jitter_range)
            delay = max(0, delay)  # Ensure non-negative

        return delay

    def should_retry(self, exception: Exception, attempt: int) -> bool:
        """
        Determine if a retry should be attempted.

        Args:
            exception: The exception that occurred.
            attempt: Current attempt number (1-indexed).

        Returns:
            True if retry should be attempted.
        """
        if attempt >= self.max_attempts:
            return False

        # Check custom retry condition
        if self.retry_on is not None:
            return self.retry_on(exception)

        # Check if exception type is retryable
        return isinstance(exception, self.retryable_exceptions)


@dataclass
class RetryContext:
    """
    Context information for a retry attempt.

    Attributes:
        attempt: Current attempt number (1-indexed).
        total_delay: Total delay accumulated across all retries.
        last_exception: The exception that triggered this retry.
        should_retry: Whether another retry will be attempted.
        started_at: When the retry sequence started.
        policy: The retry policy being used.
    """

    attempt: int
    total_delay: float
    last_exception: Exception | None
    should_retry: bool
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    policy: RetryPolicy | None = None

    def elapsed(self) -> float:
        """Get elapsed time since retry sequence started."""
        return (datetime.now(timezone.utc) - self.started_at).total_seconds()


@dataclass
class RetryStats:
    """
    Statistics for retry operations.

    Attributes:
        total_attempts: Total number of attempts made.
        successful_attempts: Number of successful completions.
        failed_attempts: Number of failed attempts (excluding final failure).
        total_delay: Total time spent in delays.
        exceptions: List of exceptions encountered.
    """

    total_attempts: int = 0
    successful_attempts: int = 0
    failed_attempts: int = 0
    total_delay: float = 0.0
    exceptions: list[Exception] = field(default_factory=list)

    def record_attempt(
        self, success: bool, delay: float = 0.0, exception: Exception | None = None
    ) -> None:
        """Record an attempt."""
        self.total_attempts += 1
        self.total_delay += delay
        if success:
            self.successful_attempts += 1
        else:
            self.failed_attempts += 1
            if exception:
                self.exceptions.append(exception)

    @property
    def success_rate(self) -> float:
        """Calculate success rate."""
        if self.total_attempts == 0:
            return 0.0
        return self.successful_attempts / self.total_attempts

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total_attempts": self.total_attempts,
            "successful_attempts": self.successful_attempts,
            "failed_attempts": self.failed_attempts,
            "total_delay": self.total_delay,
            "success_rate": self.success_rate,
            "exception_types": [type(e).__name__ for e in self.exceptions],
        }


# Default retry policy
DEFAULT_RETRY_POLICY = RetryPolicy(
    max_attempts=3,
    base_delay=1.0,
    max_delay=30.0,
    exponential_base=2.0,
    jitter=0.1,
    retryable_exceptions=(
        TimeoutError,
        ConnectionError,
        OSError,
    ),
)


def retry_with_backoff(
    policy: RetryPolicy | None = None,
    on_retry: Callable[[RetryContext], None] | None = None,
    on_success: Callable[[T, RetryStats], None] | None = None,
    on_failure: Callable[[Exception, RetryStats], None] | None = None,
) -> Callable[[Callable[P, T]], Callable[P, T]]:
    """
    Decorator that retries a function with exponential backoff.

    Works with both synchronous and asynchronous functions.

    Args:
        policy: Retry policy to use. Defaults to DEFAULT_RETRY_POLICY.
        on_retry: Callback invoked before each retry attempt.
        on_success: Callback invoked on successful completion.
        on_failure: Callback invoked on final failure.

    Returns:
        Decorated function with retry behavior.

    Example:
        >>> @retry_with_backoff(RetryPolicy(max_attempts=3))
        ... def call_api():
        ...     return requests.get("https://api.example.com")

        >>> @retry_with_backoff(
        ...     policy=RetryPolicy(max_attempts=5),
        ...     on_retry=lambda ctx: print(f"Retry {ctx.attempt}")
        ... )
        ... async def call_async_api():
        ...     return await client.fetch()
    """
    effective_policy = policy or DEFAULT_RETRY_POLICY

    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        if inspect.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
                return await retry_async(
                    func,
                    *args,
                    policy=effective_policy,
                    on_retry=on_retry,
                    on_success=on_success,
                    on_failure=on_failure,
                    **kwargs,
                )

            return async_wrapper  # type: ignore
        else:

            @functools.wraps(func)
            def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
                return retry_sync(
                    func,
                    *args,
                    policy=effective_policy,
                    on_retry=on_retry,
                    on_success=on_success,
                    on_failure=on_failure,
                    **kwargs,
                )

            return sync_wrapper  # type: ignore

    return decorator


async def retry_async(
    func: Callable[..., Awaitable[T]],
    *args: Any,
    policy: RetryPolicy | None = None,
    on_retry: Callable[[RetryContext], None] | None = None,
    on_success: Callable[[T, RetryStats], None] | None = None,
    on_failure: Callable[[Exception, RetryStats], None] | None = None,
    **kwargs: Any,
) -> T:
    """
    Retry an async function with exponential backoff.

    Args:
        func: Async function to retry.
        *args: Positional arguments for the function.
        policy: Retry policy to use.
        on_retry: Callback invoked before each retry.
        on_success: Callback invoked on success.
        on_failure: Callback invoked on final failure.
        **kwargs: Keyword arguments for the function.

    Returns:
        Function result on success.

    Raises:
        Exception: The last exception if all retries fail.

    Example:
        >>> result = await retry_async(
        ...     fetch_data,
        ...     url="https://api.example.com",
        ...     policy=RetryPolicy(max_attempts=3),
        ... )
    """
    effective_policy = policy or DEFAULT_RETRY_POLICY
    stats = RetryStats()
    started_at = datetime.now(timezone.utc)
    last_exception: Exception | None = None
    total_delay = 0.0

    for attempt in range(1, effective_policy.max_attempts + 1):
        try:
            result = await func(*args, **kwargs)
            stats.record_attempt(success=True)

            if on_success:
                on_success(result, stats)

            logger.debug(
                f"Retry succeeded on attempt {attempt}/{effective_policy.max_attempts}"
            )
            return result

        except Exception as e:
            last_exception = e
            should_retry = effective_policy.should_retry(e, attempt)

            stats.record_attempt(success=False, exception=e)

            if should_retry:
                delay = effective_policy.calculate_delay(attempt)
                total_delay += delay

                context = RetryContext(
                    attempt=attempt,
                    total_delay=total_delay,
                    last_exception=e,
                    should_retry=True,
                    started_at=started_at,
                    policy=effective_policy,
                )

                if on_retry:
                    on_retry(context)

                logger.warning(
                    f"Attempt {attempt}/{effective_policy.max_attempts} failed: {e}. "
                    f"Retrying in {delay:.2f}s"
                )

                await asyncio.sleep(delay)
            else:
                break

    # All retries exhausted
    if on_failure and last_exception:
        on_failure(last_exception, stats)

    logger.error(
        f"All {effective_policy.max_attempts} attempts failed. "
        f"Last error: {last_exception}"
    )

    if last_exception:
        raise last_exception
    raise RuntimeError("Unexpected state: no exception but all retries failed")


def retry_sync(
    func: Callable[..., T],
    *args: Any,
    policy: RetryPolicy | None = None,
    on_retry: Callable[[RetryContext], None] | None = None,
    on_success: Callable[[T, RetryStats], None] | None = None,
    on_failure: Callable[[Exception, RetryStats], None] | None = None,
    **kwargs: Any,
) -> T:
    """
    Retry a sync function with exponential backoff.

    Args:
        func: Function to retry.
        *args: Positional arguments for the function.
        policy: Retry policy to use.
        on_retry: Callback invoked before each retry.
        on_success: Callback invoked on success.
        on_failure: Callback invoked on final failure.
        **kwargs: Keyword arguments for the function.

    Returns:
        Function result on success.

    Raises:
        Exception: The last exception if all retries fail.

    Example:
        >>> result = retry_sync(
        ...     requests.get,
        ...     "https://api.example.com",
        ...     policy=RetryPolicy(max_attempts=3),
        ... )
    """
    effective_policy = policy or DEFAULT_RETRY_POLICY
    stats = RetryStats()
    started_at = datetime.now(timezone.utc)
    last_exception: Exception | None = None
    total_delay = 0.0

    for attempt in range(1, effective_policy.max_attempts + 1):
        try:
            result = func(*args, **kwargs)
            stats.record_attempt(success=True)

            if on_success:
                on_success(result, stats)

            logger.debug(
                f"Retry succeeded on attempt {attempt}/{effective_policy.max_attempts}"
            )
            return result

        except Exception as e:
            last_exception = e
            should_retry = effective_policy.should_retry(e, attempt)

            stats.record_attempt(success=False, exception=e)

            if should_retry:
                delay = effective_policy.calculate_delay(attempt)
                total_delay += delay

                context = RetryContext(
                    attempt=attempt,
                    total_delay=total_delay,
                    last_exception=e,
                    should_retry=True,
                    started_at=started_at,
                    policy=effective_policy,
                )

                if on_retry:
                    on_retry(context)

                logger.warning(
                    f"Attempt {attempt}/{effective_policy.max_attempts} failed: {e}. "
                    f"Retrying in {delay:.2f}s"
                )

                time.sleep(delay)
            else:
                break

    # All retries exhausted
    if on_failure and last_exception:
        on_failure(last_exception, stats)

    logger.error(
        f"All {effective_policy.max_attempts} attempts failed. "
        f"Last error: {last_exception}"
    )

    if last_exception:
        raise last_exception
    raise RuntimeError("Unexpected state: no exception but all retries failed")


class RetryBudget:
    """
    A budget-based retry limiter to prevent retry storms.

    Tracks retry attempts across multiple operations and limits
    the total retry rate to prevent cascading failures.

    Attributes:
        max_retries_per_second: Maximum retries allowed per second.
        window_seconds: Time window for tracking.

    Example:
        >>> budget = RetryBudget(max_retries_per_second=10)
        >>> if budget.allow_retry():
        ...     # Proceed with retry
        ...     pass
    """

    def __init__(
        self,
        max_retries_per_second: float = 10.0,
        window_seconds: float = 1.0,
    ) -> None:
        """
        Initialize the retry budget.

        Args:
            max_retries_per_second: Maximum retries per second.
            window_seconds: Time window for tracking.
        """
        self.max_retries_per_second = max_retries_per_second
        self.window_seconds = window_seconds
        self._tokens = max_retries_per_second
        self._last_update = time.monotonic()
        self._lock = threading.Lock()

    def allow_retry(self) -> bool:
        """
        Check if a retry is allowed within budget.

        Returns:
            True if retry is allowed, False otherwise.
        """
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_update
            self._last_update = now

            # Refill tokens
            self._tokens = min(
                self.max_retries_per_second,
                self._tokens + elapsed * self.max_retries_per_second,
            )

            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True
            return False

    def reset(self) -> None:
        """Reset the budget to full capacity."""
        with self._lock:
            self._tokens = self.max_retries_per_second
            self._last_update = time.monotonic()

    @property
    def available_tokens(self) -> float:
        """Get current available tokens."""
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_update
            return min(
                self.max_retries_per_second,
                self._tokens + elapsed * self.max_retries_per_second,
            )
