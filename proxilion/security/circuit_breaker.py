"""
Circuit breaker implementation for Proxilion.

This module provides the circuit breaker pattern to prevent
cascading failures when external services or tools fail.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, TypeVar

from proxilion.exceptions import CircuitOpenError

logger = logging.getLogger(__name__)

T = TypeVar("T")


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"      # Normal operation, requests pass through
    OPEN = "open"          # Failing, requests rejected
    HALF_OPEN = "half_open"  # Testing if service recovered


@dataclass
class CircuitStats:
    """Statistics for a circuit breaker."""
    failures: int = 0
    successes: int = 0
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    last_failure_time: float | None = None
    last_success_time: float | None = None
    last_failure_error: str | None = None
    state_change_time: float = field(default_factory=time.monotonic)


class CircuitBreaker:
    """
    Circuit breaker for protecting against cascading failures.

    The circuit breaker has three states:
    - CLOSED: Normal operation. Requests pass through and failures are tracked.
    - OPEN: The circuit is tripped. Requests are rejected immediately.
    - HALF_OPEN: Testing recovery. Limited requests are allowed through.

    State Transitions:
    - CLOSED -> OPEN: When failures exceed the threshold.
    - OPEN -> HALF_OPEN: After the reset timeout expires.
    - HALF_OPEN -> CLOSED: When a request succeeds.
    - HALF_OPEN -> OPEN: When a request fails.

    Thread Safety:
        All operations are thread-safe.

    Example:
        >>> breaker = CircuitBreaker(
        ...     failure_threshold=5,
        ...     reset_timeout=30.0,
        ... )
        >>>
        >>> try:
        ...     result = breaker.call(external_api_call, arg1, arg2)
        ... except CircuitOpenError:
        ...     # Circuit is open, use fallback
        ...     result = fallback_response()
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        reset_timeout: float = 30.0,
        half_open_max: int = 1,
        success_threshold: int = 1,
        excluded_exceptions: tuple[type[Exception], ...] | None = None,
        exponential_backoff: bool = True,
        max_backoff: float = 300.0,
    ) -> None:
        """
        Initialize the circuit breaker.

        Args:
            failure_threshold: Number of failures before opening circuit.
            reset_timeout: Seconds to wait before trying half-open.
            half_open_max: Max concurrent requests in half-open state.
            success_threshold: Successes needed to close circuit from half-open.
            excluded_exceptions: Exceptions that don't count as failures.
            exponential_backoff: If True, increase timeout on repeated failures.
            max_backoff: Maximum backoff timeout in seconds.
        """
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self.half_open_max = half_open_max
        self.success_threshold = success_threshold
        self.excluded_exceptions = excluded_exceptions or ()
        self.exponential_backoff = exponential_backoff
        self.max_backoff = max_backoff

        self._state = CircuitState.CLOSED
        self._stats = CircuitStats()
        self._lock = threading.RLock()
        self._half_open_count = 0
        self._backoff_multiplier = 1.0

    @property
    def state(self) -> CircuitState:
        """Get current circuit state."""
        with self._lock:
            self._maybe_transition_to_half_open()
            return self._state

    @property
    def stats(self) -> CircuitStats:
        """Get circuit statistics."""
        with self._lock:
            return CircuitStats(
                failures=self._stats.failures,
                successes=self._stats.successes,
                consecutive_failures=self._stats.consecutive_failures,
                consecutive_successes=self._stats.consecutive_successes,
                last_failure_time=self._stats.last_failure_time,
                last_success_time=self._stats.last_success_time,
                last_failure_error=self._stats.last_failure_error,
                state_change_time=self._stats.state_change_time,
            )

    def _maybe_transition_to_half_open(self) -> None:
        """Check if we should transition from OPEN to HALF_OPEN."""
        if self._state != CircuitState.OPEN:
            return

        current_timeout = self.reset_timeout * self._backoff_multiplier
        elapsed = time.monotonic() - self._stats.state_change_time

        if elapsed >= current_timeout:
            logger.info(
                f"Circuit transitioning from OPEN to HALF_OPEN "
                f"after {elapsed:.1f}s"
            )
            self._state = CircuitState.HALF_OPEN
            self._stats.state_change_time = time.monotonic()
            self._half_open_count = 0

    def _set_state(self, new_state: CircuitState) -> None:
        """Set circuit state and log the transition."""
        old_state = self._state
        if old_state != new_state:
            self._state = new_state
            self._stats.state_change_time = time.monotonic()
            logger.info(f"Circuit state: {old_state.value} -> {new_state.value}")

    def _record_success(self) -> None:
        """Record a successful call."""
        self._stats.successes += 1
        self._stats.consecutive_successes += 1
        self._stats.consecutive_failures = 0
        self._stats.last_success_time = time.monotonic()

        if self._state == CircuitState.HALF_OPEN:
            if self._stats.consecutive_successes >= self.success_threshold:
                self._set_state(CircuitState.CLOSED)
                self._backoff_multiplier = 1.0  # Reset backoff
                self._stats.consecutive_successes = 0

    def _record_failure(self, error: Exception) -> None:
        """Record a failed call."""
        self._stats.failures += 1
        self._stats.consecutive_failures += 1
        self._stats.consecutive_successes = 0
        self._stats.last_failure_time = time.monotonic()
        self._stats.last_failure_error = str(error)

        if self._state == CircuitState.HALF_OPEN:
            # Any failure in half-open opens the circuit again
            self._set_state(CircuitState.OPEN)
            if self.exponential_backoff:
                self._backoff_multiplier = min(
                    self._backoff_multiplier * 2,
                    self.max_backoff / self.reset_timeout,
                )

        elif self._state == CircuitState.CLOSED:
            if self._stats.consecutive_failures >= self.failure_threshold:
                self._set_state(CircuitState.OPEN)

    def call(
        self,
        func: Callable[..., T],
        *args: Any,
        **kwargs: Any,
    ) -> T:
        """
        Execute a function through the circuit breaker.

        Args:
            func: The function to call.
            *args: Positional arguments for the function.
            **kwargs: Keyword arguments for the function.

        Returns:
            The function's return value.

        Raises:
            CircuitOpenError: If the circuit is open.
            Exception: Any exception raised by the function.

        Example:
            >>> result = breaker.call(api.get_data, user_id=123)
        """
        with self._lock:
            self._maybe_transition_to_half_open()
            state = self._state

            if state == CircuitState.OPEN:
                current_timeout = self.reset_timeout * self._backoff_multiplier
                elapsed = time.monotonic() - self._stats.state_change_time
                remaining = current_timeout - elapsed

                raise CircuitOpenError(
                    circuit_name=getattr(func, "__name__", "unknown"),
                    failure_count=self._stats.consecutive_failures,
                    reset_timeout=remaining,
                    last_failure=self._stats.last_failure_error,
                )

            if state == CircuitState.HALF_OPEN:
                if self._half_open_count >= self.half_open_max:
                    raise CircuitOpenError(
                        circuit_name=getattr(func, "__name__", "unknown"),
                        failure_count=self._stats.consecutive_failures,
                        reset_timeout=0.0,
                        last_failure="Half-open limit reached",
                    )
                self._half_open_count += 1

        # Execute outside lock to avoid blocking
        try:
            result = func(*args, **kwargs)
            with self._lock:
                self._record_success()
            return result

        except self.excluded_exceptions:
            # Don't count as failure, but free the half-open slot
            if state == CircuitState.HALF_OPEN:
                with self._lock:
                    self._half_open_count = max(0, self._half_open_count - 1)
            raise

        except Exception as e:
            with self._lock:
                self._record_failure(e)
            raise

    async def call_async(
        self,
        func: Callable[..., Any],
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """
        Execute an async function through the circuit breaker.

        Args:
            func: The async function to call.
            *args: Positional arguments.
            **kwargs: Keyword arguments.

        Returns:
            The function's return value.

        Raises:
            CircuitOpenError: If the circuit is open.
        """
        with self._lock:
            self._maybe_transition_to_half_open()
            state = self._state

            if state == CircuitState.OPEN:
                current_timeout = self.reset_timeout * self._backoff_multiplier
                elapsed = time.monotonic() - self._stats.state_change_time
                remaining = current_timeout - elapsed

                raise CircuitOpenError(
                    circuit_name=getattr(func, "__name__", "unknown"),
                    failure_count=self._stats.consecutive_failures,
                    reset_timeout=remaining,
                    last_failure=self._stats.last_failure_error,
                )

            if state == CircuitState.HALF_OPEN:
                if self._half_open_count >= self.half_open_max:
                    raise CircuitOpenError(
                        circuit_name=getattr(func, "__name__", "unknown"),
                        failure_count=self._stats.consecutive_failures,
                        reset_timeout=0.0,
                        last_failure="Half-open limit reached",
                    )
                self._half_open_count += 1

        try:
            result = await func(*args, **kwargs)
            with self._lock:
                self._record_success()
            return result

        except self.excluded_exceptions:
            # Don't count as failure, but free the half-open slot
            if state == CircuitState.HALF_OPEN:
                with self._lock:
                    self._half_open_count = max(0, self._half_open_count - 1)
            raise

        except Exception as e:
            with self._lock:
                self._record_failure(e)
            raise

    def reset(self) -> None:
        """Reset the circuit breaker to closed state."""
        with self._lock:
            self._set_state(CircuitState.CLOSED)
            self._stats = CircuitStats()
            self._half_open_count = 0
            self._backoff_multiplier = 1.0

    def force_open(self) -> None:
        """Force the circuit to open state (for testing/maintenance)."""
        with self._lock:
            self._set_state(CircuitState.OPEN)

    def is_available(self) -> bool:
        """Check if the circuit will accept requests."""
        return self.state != CircuitState.OPEN


class CircuitBreakerRegistry:
    """
    Registry for managing multiple circuit breakers.

    Provides a central place to manage circuit breakers for
    different tools or services.

    Example:
        >>> registry = CircuitBreakerRegistry()
        >>> registry.register("external_api", CircuitBreaker(failure_threshold=3))
        >>>
        >>> breaker = registry.get("external_api")
        >>> result = breaker.call(api_call)
    """

    def __init__(
        self,
        default_config: dict[str, Any] | None = None,
    ) -> None:
        """
        Initialize the registry.

        Args:
            default_config: Default configuration for auto-created breakers.
        """
        self._breakers: dict[str, CircuitBreaker] = {}
        self._lock = threading.RLock()
        self.default_config = default_config or {
            "failure_threshold": 5,
            "reset_timeout": 30.0,
        }

    def register(
        self,
        name: str,
        breaker: CircuitBreaker | None = None,
    ) -> CircuitBreaker:
        """
        Register a circuit breaker.

        Args:
            name: Name for the circuit breaker.
            breaker: CircuitBreaker instance, or None to create with defaults.

        Returns:
            The registered circuit breaker.
        """
        with self._lock:
            if breaker is None:
                breaker = CircuitBreaker(**self.default_config)
            self._breakers[name] = breaker
            return breaker

    def get(self, name: str, auto_create: bool = True) -> CircuitBreaker:
        """
        Get a circuit breaker by name.

        Args:
            name: The circuit breaker name.
            auto_create: If True, create a new breaker if not found.

        Returns:
            The circuit breaker.

        Raises:
            KeyError: If not found and auto_create is False.
        """
        with self._lock:
            if name not in self._breakers:
                if auto_create:
                    return self.register(name)
                raise KeyError(f"Circuit breaker '{name}' not found")
            return self._breakers[name]

    def get_all_stats(self) -> dict[str, dict[str, Any]]:
        """Get statistics for all circuit breakers."""
        with self._lock:
            return {
                name: {
                    "state": breaker.state.value,
                    "failures": breaker.stats.failures,
                    "successes": breaker.stats.successes,
                    "consecutive_failures": breaker.stats.consecutive_failures,
                }
                for name, breaker in self._breakers.items()
            }

    def reset_all(self) -> None:
        """Reset all circuit breakers."""
        with self._lock:
            for breaker in self._breakers.values():
                breaker.reset()
