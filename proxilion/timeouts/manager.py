"""
Timeout management for AI agent operations.

Provides configurable timeout handling with deadline tracking
for managing time budgets across multiple operations.
"""

from __future__ import annotations

import contextvars
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any


class TimeoutError(Exception):
    """
    Raised when an operation exceeds its timeout.

    Attributes:
        operation: Name of the operation that timed out.
        timeout: The timeout value that was exceeded.
        elapsed: Actual time elapsed before timeout.
        message: Human-readable error message.
    """

    def __init__(
        self,
        message: str = "Operation timed out",
        operation: str | None = None,
        timeout: float | None = None,
        elapsed: float | None = None,
    ) -> None:
        self.operation = operation
        self.timeout = timeout
        self.elapsed = elapsed
        self.message = message
        super().__init__(self._format_message())

    def _format_message(self) -> str:
        """Format the error message with details."""
        parts = [self.message]
        if self.operation:
            parts.append(f"operation={self.operation}")
        if self.timeout is not None:
            parts.append(f"timeout={self.timeout:.2f}s")
        if self.elapsed is not None:
            parts.append(f"elapsed={self.elapsed:.2f}s")
        return " ".join(parts)


@dataclass
class TimeoutConfig:
    """
    Configuration for timeout management.

    Attributes:
        default_timeout: Default timeout for operations in seconds.
        tool_timeouts: Per-tool timeout overrides.
        llm_timeout: Timeout for LLM API calls.
        total_request_timeout: Total request budget timeout.
        warn_at_percent: Percentage of timeout to trigger warning (0-100).

    Example:
        >>> config = TimeoutConfig(
        ...     default_timeout=30.0,
        ...     tool_timeouts={
        ...         "web_search": 60.0,
        ...         "database_query": 10.0,
        ...         "file_read": 5.0,
        ...     },
        ...     llm_timeout=120.0,
        ...     total_request_timeout=300.0,
        ... )
    """

    default_timeout: float = 30.0
    tool_timeouts: dict[str, float] = field(default_factory=dict)
    llm_timeout: float = 120.0
    total_request_timeout: float = 300.0
    warn_at_percent: float = 80.0

    def get_timeout(self, operation: str) -> float:
        """
        Get timeout for a specific operation.

        Args:
            operation: Name of the operation or tool.

        Returns:
            Timeout value in seconds.
        """
        return self.tool_timeouts.get(operation, self.default_timeout)

    def set_tool_timeout(self, tool_name: str, timeout: float) -> None:
        """
        Set timeout for a specific tool.

        Args:
            tool_name: Name of the tool.
            timeout: Timeout value in seconds.
        """
        self.tool_timeouts[tool_name] = timeout

    def to_dict(self) -> dict[str, Any]:
        """Convert config to dictionary."""
        return {
            "default_timeout": self.default_timeout,
            "tool_timeouts": dict(self.tool_timeouts),
            "llm_timeout": self.llm_timeout,
            "total_request_timeout": self.total_request_timeout,
            "warn_at_percent": self.warn_at_percent,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TimeoutConfig:
        """Create config from dictionary."""
        return cls(
            default_timeout=data.get("default_timeout", 30.0),
            tool_timeouts=data.get("tool_timeouts", {}),
            llm_timeout=data.get("llm_timeout", 120.0),
            total_request_timeout=data.get("total_request_timeout", 300.0),
            warn_at_percent=data.get("warn_at_percent", 80.0),
        )


# Context variable for current deadline
_current_deadline: contextvars.ContextVar[DeadlineContext | None] = contextvars.ContextVar(
    "proxilion_deadline", default=None
)


def get_current_deadline() -> DeadlineContext | None:
    """Get the current deadline context if any."""
    return _current_deadline.get()


class DeadlineContext:
    """
    Context manager for tracking remaining time with a hard deadline.

    Tracks the time budget for a request and provides methods to
    check remaining time and whether the deadline has expired.
    Supports nested deadlines (inner deadline cannot exceed outer).

    Attributes:
        timeout: Total timeout for this deadline context.
        deadline: Monotonic timestamp when deadline expires.
        started_at: Monotonic timestamp when context started.
        operation: Optional name of the operation.

    Example:
        >>> async with DeadlineContext(timeout=30.0) as deadline:
        ...     result1 = await call_tool1(timeout=deadline.remaining())
        ...     result2 = await call_tool2(timeout=deadline.remaining())
        ...     # Automatically raises TimeoutError if deadline exceeded

        >>> # With synchronous context manager
        >>> with DeadlineContext(timeout=10.0) as deadline:
        ...     if deadline.remaining() > 5:
        ...         do_slow_operation()
    """

    def __init__(
        self,
        timeout: float,
        operation: str | None = None,
        raise_on_expire: bool = True,
    ) -> None:
        """
        Initialize deadline context.

        Args:
            timeout: Timeout in seconds.
            operation: Optional operation name for error messages.
            raise_on_expire: Whether to raise TimeoutError when expired.
        """
        if timeout <= 0:
            raise ValueError(f"Timeout must be positive, got {timeout}")
        self.timeout = timeout
        self.operation = operation
        self.raise_on_expire = raise_on_expire
        self._started_at: float | None = None
        self._deadline: float | None = None
        self._parent: DeadlineContext | None = None
        self._token: contextvars.Token | None = None
        self._lock = threading.Lock()

    @property
    def started_at(self) -> float:
        """Get the start time (monotonic)."""
        if self._started_at is None:
            raise RuntimeError("DeadlineContext not started")
        return self._started_at

    @property
    def deadline(self) -> float:
        """Get the deadline (monotonic timestamp)."""
        if self._deadline is None:
            raise RuntimeError("DeadlineContext not started")
        return self._deadline

    def _start(self) -> None:
        """Start the deadline tracking."""
        now = time.monotonic()
        self._started_at = now
        self._deadline = now + self.timeout

        # Check for parent deadline
        self._parent = get_current_deadline()
        if self._parent is not None:
            # Inner deadline cannot exceed outer deadline
            parent_deadline = self._parent.deadline
            if self._deadline > parent_deadline:
                self._deadline = parent_deadline

        # Set as current deadline
        self._token = _current_deadline.set(self)

    def _stop(self) -> None:
        """Stop the deadline tracking."""
        if self._token is not None:
            _current_deadline.reset(self._token)
            self._token = None

    def remaining(self) -> float:
        """
        Get remaining time until deadline.

        Returns:
            Remaining time in seconds.

        Raises:
            TimeoutError: If deadline has expired and raise_on_expire is True.
        """
        with self._lock:
            if self._deadline is None:
                raise RuntimeError("DeadlineContext not started")

            remaining = self._deadline - time.monotonic()
            if remaining <= 0:
                if self.raise_on_expire:
                    raise TimeoutError(
                        message="Deadline exceeded",
                        operation=self.operation,
                        timeout=self.timeout,
                        elapsed=self.elapsed(),
                    )
                return 0.0
            return remaining

    def remaining_or_default(self, default: float) -> float:
        """
        Get remaining time or default if expired.

        Args:
            default: Default value to return if deadline expired.

        Returns:
            Remaining time or default.
        """
        try:
            return self.remaining()
        except TimeoutError:
            return default

    def elapsed(self) -> float:
        """
        Get elapsed time since start.

        Returns:
            Elapsed time in seconds.
        """
        if self._started_at is None:
            return 0.0
        return time.monotonic() - self._started_at

    def is_expired(self) -> bool:
        """
        Check if deadline has passed.

        Returns:
            True if deadline has expired.
        """
        if self._deadline is None:
            return False
        return time.monotonic() >= self._deadline

    def check(self) -> None:
        """
        Check if deadline has expired and raise if so.

        Raises:
            TimeoutError: If deadline has expired.
        """
        if self.is_expired():
            raise TimeoutError(
                message="Deadline exceeded",
                operation=self.operation,
                timeout=self.timeout,
                elapsed=self.elapsed(),
            )

    def get_timeout_for_operation(self, operation_timeout: float) -> float:
        """
        Get effective timeout for a sub-operation.

        Returns the minimum of the operation's timeout and
        the remaining deadline time.

        Args:
            operation_timeout: The desired timeout for the operation.

        Returns:
            Effective timeout (minimum of operation_timeout and remaining).
        """
        remaining = self.remaining()
        return min(operation_timeout, remaining)

    def __enter__(self) -> DeadlineContext:
        """Enter context (synchronous)."""
        self._start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Exit context (synchronous)."""
        self._stop()

    async def __aenter__(self) -> DeadlineContext:
        """Enter context (asynchronous)."""
        self._start()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Exit context (asynchronous)."""
        self._stop()


class TimeoutManager:
    """
    Central timeout configuration and management.

    Manages timeout settings for different operations and provides
    methods to create deadline contexts with appropriate timeouts.

    Attributes:
        config: The timeout configuration.

    Example:
        >>> manager = TimeoutManager(TimeoutConfig(
        ...     default_timeout=30.0,
        ...     tool_timeouts={"search": 60.0},
        ... ))
        >>> timeout = manager.get_timeout("search")  # 60.0
        >>> timeout = manager.get_timeout("unknown")  # 30.0 (default)
    """

    def __init__(self, config: TimeoutConfig | None = None) -> None:
        """
        Initialize timeout manager.

        Args:
            config: Timeout configuration. Uses defaults if None.
        """
        self.config = config or TimeoutConfig()
        self._lock = threading.RLock()

    def get_timeout(self, operation: str) -> float:
        """
        Get timeout for a specific operation.

        Args:
            operation: Name of the operation or tool.

        Returns:
            Timeout value in seconds.
        """
        with self._lock:
            return self.config.get_timeout(operation)

    def get_llm_timeout(self) -> float:
        """
        Get timeout for LLM operations.

        Returns:
            LLM timeout in seconds.
        """
        return self.config.llm_timeout

    def get_total_request_timeout(self) -> float:
        """
        Get total request budget timeout.

        Returns:
            Total request timeout in seconds.
        """
        return self.config.total_request_timeout

    def set_tool_timeout(self, tool_name: str, timeout: float) -> None:
        """
        Set timeout for a specific tool.

        Args:
            tool_name: Name of the tool.
            timeout: Timeout value in seconds.
        """
        with self._lock:
            self.config.set_tool_timeout(tool_name, timeout)

    def create_deadline(
        self,
        timeout: float | None = None,
        operation: str | None = None,
    ) -> DeadlineContext:
        """
        Create a deadline context with appropriate timeout.

        Args:
            timeout: Explicit timeout (uses total_request_timeout if None).
            operation: Optional operation name.

        Returns:
            DeadlineContext for tracking the deadline.
        """
        effective_timeout = timeout or self.config.total_request_timeout
        return DeadlineContext(timeout=effective_timeout, operation=operation)

    def create_tool_deadline(self, tool_name: str) -> DeadlineContext:
        """
        Create a deadline context for a specific tool.

        Args:
            tool_name: Name of the tool.

        Returns:
            DeadlineContext with tool-specific timeout.
        """
        timeout = self.get_timeout(tool_name)
        return DeadlineContext(timeout=timeout, operation=tool_name)

    def create_llm_deadline(self) -> DeadlineContext:
        """
        Create a deadline context for LLM operations.

        Returns:
            DeadlineContext with LLM timeout.
        """
        return DeadlineContext(timeout=self.config.llm_timeout, operation="llm_call")

    @contextmanager
    def deadline_context(
        self,
        timeout: float | None = None,
        operation: str | None = None,
    ):
        """
        Context manager for deadline tracking.

        Args:
            timeout: Explicit timeout.
            operation: Optional operation name.

        Yields:
            DeadlineContext instance.
        """
        ctx = self.create_deadline(timeout, operation)
        with ctx:
            yield ctx

    def get_effective_timeout(
        self,
        operation: str,
        requested_timeout: float | None = None,
    ) -> float:
        """
        Get effective timeout considering current deadline.

        If there's an active deadline context, returns the minimum
        of the requested timeout and remaining deadline time.

        Args:
            operation: Name of the operation.
            requested_timeout: Requested timeout (uses config if None).

        Returns:
            Effective timeout in seconds.
        """
        # Get configured timeout
        config_timeout = self.get_timeout(operation)
        timeout = requested_timeout if requested_timeout is not None else config_timeout

        # Check for active deadline
        current_deadline = get_current_deadline()
        if current_deadline is not None:
            try:
                remaining = current_deadline.remaining()
                return min(timeout, remaining)
            except TimeoutError:
                # Deadline already expired
                return 0.0

        return timeout

    def to_dict(self) -> dict[str, Any]:
        """Serialize manager configuration to dictionary."""
        return self.config.to_dict()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TimeoutManager:
        """Create manager from dictionary."""
        config = TimeoutConfig.from_dict(data)
        return cls(config)


# Default timeout manager instance
_default_manager: TimeoutManager | None = None
_manager_lock = threading.Lock()


def get_default_manager() -> TimeoutManager:
    """
    Get the default timeout manager.

    Creates one with default settings if none exists.

    Returns:
        Default TimeoutManager instance.
    """
    global _default_manager
    with _manager_lock:
        if _default_manager is None:
            _default_manager = TimeoutManager()
        return _default_manager


def set_default_manager(manager: TimeoutManager) -> None:
    """
    Set the default timeout manager.

    Args:
        manager: TimeoutManager to use as default.
    """
    global _default_manager
    with _manager_lock:
        _default_manager = manager
