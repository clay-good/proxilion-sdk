"""
Timeout decorators for AI agent operations.

Provides decorators for applying timeouts to sync and async functions,
with support for both explicit timeouts and deadline contexts.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import functools
import inspect
from collections.abc import Callable, Coroutine
from typing import Any, ParamSpec, TypeVar

from proxilion.timeouts.manager import (
    DeadlineContext,
    TimeoutError,
    TimeoutManager,
    get_current_deadline,
    get_default_manager,
)

P = ParamSpec("P")
T = TypeVar("T")


def with_timeout(
    timeout: float | None = None,
    timeout_manager: TimeoutManager | None = None,
    operation_name: str | None = None,
    use_deadline: bool = True,
) -> Callable[[Callable[P, T]], Callable[P, T]]:
    """
    Decorator that applies a timeout to a sync or async function.

    For async functions, uses asyncio.wait_for.
    For sync functions, uses ThreadPoolExecutor.

    Args:
        timeout: Explicit timeout in seconds. If None, uses manager's default.
        timeout_manager: TimeoutManager to use for configuration.
        operation_name: Name of operation (defaults to function name).
        use_deadline: If True, respects active deadline context.

    Returns:
        Decorator function.

    Example:
        >>> @with_timeout(10.0)
        ... async def slow_api_call():
        ...     await asyncio.sleep(20)  # Will raise TimeoutError

        >>> @with_timeout(5.0)
        ... def sync_operation():
        ...     time.sleep(10)  # Will raise TimeoutError
    """
    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        nonlocal operation_name
        if operation_name is None:
            operation_name = func.__name__

        manager = timeout_manager or get_default_manager()

        if inspect.iscoroutinefunction(func):
            @functools.wraps(func)
            async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
                effective_timeout = _get_effective_timeout(
                    timeout, manager, operation_name, use_deadline
                )

                if effective_timeout <= 0:
                    raise TimeoutError(
                        message="Deadline already exceeded",
                        operation=operation_name,
                        timeout=effective_timeout,
                    )

                try:
                    return await asyncio.wait_for(
                        func(*args, **kwargs),
                        timeout=effective_timeout,
                    )
                except asyncio.TimeoutError as e:
                    raise TimeoutError(
                        message="Operation timed out",
                        operation=operation_name,
                        timeout=effective_timeout,
                    ) from e

            return async_wrapper  # type: ignore
        else:
            @functools.wraps(func)
            def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
                effective_timeout = _get_effective_timeout(
                    timeout, manager, operation_name, use_deadline
                )

                if effective_timeout <= 0:
                    raise TimeoutError(
                        message="Deadline already exceeded",
                        operation=operation_name,
                        timeout=effective_timeout,
                    )

                return _run_with_timeout_sync(
                    func, args, kwargs, effective_timeout, operation_name
                )

            return sync_wrapper  # type: ignore

    return decorator


def with_deadline(
    timeout: float,
    operation_name: str | None = None,
    raise_on_expire: bool = True,
) -> Callable[[Callable[P, T]], Callable[P, T]]:
    """
    Decorator that creates a deadline context for the function.

    The entire function execution is wrapped in a DeadlineContext,
    allowing nested calls to check remaining time.

    Args:
        timeout: Total timeout budget for the function.
        operation_name: Name of operation (defaults to function name).
        raise_on_expire: Whether to raise TimeoutError on expiration.

    Returns:
        Decorator function.

    Example:
        >>> @with_deadline(30.0)
        ... async def complex_operation():
        ...     # Nested calls can use get_current_deadline()
        ...     deadline = get_current_deadline()
        ...     await call_api(timeout=deadline.remaining())
    """
    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        nonlocal operation_name
        if operation_name is None:
            operation_name = func.__name__

        if inspect.iscoroutinefunction(func):
            @functools.wraps(func)
            async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
                async with DeadlineContext(
                    timeout=timeout,
                    operation=operation_name,
                    raise_on_expire=raise_on_expire,
                ) as deadline:
                    try:
                        return await asyncio.wait_for(
                            func(*args, **kwargs),
                            timeout=deadline.remaining(),
                        )
                    except asyncio.TimeoutError as e:
                        raise TimeoutError(
                            message="Deadline exceeded",
                            operation=operation_name,
                            timeout=timeout,
                            elapsed=deadline.elapsed(),
                        ) from e

            return async_wrapper  # type: ignore
        else:
            @functools.wraps(func)
            def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
                with DeadlineContext(
                    timeout=timeout,
                    operation=operation_name,
                    raise_on_expire=raise_on_expire,
                ) as deadline:
                    return _run_with_timeout_sync(
                        func, args, kwargs, deadline.remaining(), operation_name
                    )

            return sync_wrapper  # type: ignore

    return decorator


def _get_effective_timeout(
    explicit_timeout: float | None,
    manager: TimeoutManager,
    operation_name: str,
    use_deadline: bool,
) -> float:
    """
    Get effective timeout considering explicit, configured, and deadline.

    Args:
        explicit_timeout: Explicitly specified timeout.
        manager: TimeoutManager for configuration.
        operation_name: Name of the operation.
        use_deadline: Whether to consider active deadline.

    Returns:
        Effective timeout in seconds.
    """
    # Start with explicit or configured timeout
    if explicit_timeout is not None:
        timeout = explicit_timeout
    else:
        timeout = manager.get_timeout(operation_name)

    # Consider active deadline if enabled
    if use_deadline:
        current_deadline = get_current_deadline()
        if current_deadline is not None:
            try:
                remaining = current_deadline.remaining()
                timeout = min(timeout, remaining)
            except TimeoutError:
                return 0.0

    return timeout


def _run_with_timeout_sync(
    func: Callable[..., T],
    args: tuple,
    kwargs: dict,
    timeout: float,
    operation_name: str,
) -> T:
    """
    Run a synchronous function with a timeout.

    Uses ThreadPoolExecutor for cross-platform compatibility.

    Args:
        func: Function to run.
        args: Positional arguments.
        kwargs: Keyword arguments.
        timeout: Timeout in seconds.
        operation_name: Name of operation for error messages.

    Returns:
        Function result.

    Raises:
        TimeoutError: If function exceeds timeout.
    """
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(func, *args, **kwargs)
        try:
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError as e:
            # Cancel the future (may not actually stop the thread)
            future.cancel()
            raise TimeoutError(
                message="Operation timed out",
                operation=operation_name,
                timeout=timeout,
            ) from e


async def run_with_timeout(
    coro: Coroutine[Any, Any, T],
    timeout: float,
    operation_name: str | None = None,
) -> T:
    """
    Run a coroutine with a timeout.

    Convenience function for applying timeout to a coroutine
    without using a decorator.

    Args:
        coro: Coroutine to run.
        timeout: Timeout in seconds.
        operation_name: Name of operation for error messages.

    Returns:
        Coroutine result.

    Raises:
        TimeoutError: If coroutine exceeds timeout.

    Example:
        >>> result = await run_with_timeout(
        ...     fetch_data(),
        ...     timeout=10.0,
        ...     operation_name="fetch_data"
        ... )
    """
    try:
        return await asyncio.wait_for(coro, timeout=timeout)
    except asyncio.TimeoutError as e:
        raise TimeoutError(
            message="Operation timed out",
            operation=operation_name,
            timeout=timeout,
        ) from e


async def run_with_deadline(
    coro: Coroutine[Any, Any, T],
    deadline: DeadlineContext,
    operation_name: str | None = None,
) -> T:
    """
    Run a coroutine respecting an existing deadline context.

    Args:
        coro: Coroutine to run.
        deadline: Active deadline context.
        operation_name: Name of operation for error messages.

    Returns:
        Coroutine result.

    Raises:
        TimeoutError: If deadline is exceeded.

    Example:
        >>> async with DeadlineContext(30.0) as deadline:
        ...     result1 = await run_with_deadline(call1(), deadline)
        ...     result2 = await run_with_deadline(call2(), deadline)
    """
    remaining = deadline.remaining()  # May raise TimeoutError

    try:
        return await asyncio.wait_for(coro, timeout=remaining)
    except asyncio.TimeoutError as e:
        raise TimeoutError(
            message="Deadline exceeded during operation",
            operation=operation_name,
            timeout=deadline.timeout,
            elapsed=deadline.elapsed(),
        ) from e


class TimeoutScope:
    """
    Structured timeout scope for multiple operations.

    Similar to DeadlineContext but designed for grouping
    multiple operations with named checkpoints.

    Example:
        >>> async with TimeoutScope(30.0) as scope:
        ...     result1 = await scope.run("fetch", fetch_data())
        ...     result2 = await scope.run("process", process_data(result1))
        ...     result3 = await scope.run("save", save_result(result2))
    """

    def __init__(
        self,
        timeout: float,
        operation_name: str = "scope",
    ) -> None:
        """
        Initialize timeout scope.

        Args:
            timeout: Total timeout budget.
            operation_name: Name of the scope.
        """
        self.timeout = timeout
        self.operation_name = operation_name
        self._deadline: DeadlineContext | None = None
        self._checkpoints: list[tuple[str, float]] = []

    async def __aenter__(self) -> TimeoutScope:
        """Enter the scope."""
        self._deadline = DeadlineContext(
            timeout=self.timeout,
            operation=self.operation_name,
        )
        await self._deadline.__aenter__()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Exit the scope."""
        if self._deadline is not None:
            await self._deadline.__aexit__(exc_type, exc_val, exc_tb)

    def __enter__(self) -> TimeoutScope:
        """Enter the scope (sync)."""
        self._deadline = DeadlineContext(
            timeout=self.timeout,
            operation=self.operation_name,
        )
        self._deadline.__enter__()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Exit the scope (sync)."""
        if self._deadline is not None:
            self._deadline.__exit__(exc_type, exc_val, exc_tb)

    def remaining(self) -> float:
        """Get remaining time."""
        if self._deadline is None:
            raise RuntimeError("TimeoutScope not started")
        return self._deadline.remaining()

    def elapsed(self) -> float:
        """Get elapsed time."""
        if self._deadline is None:
            return 0.0
        return self._deadline.elapsed()

    def checkpoint(self, name: str) -> None:
        """
        Record a checkpoint.

        Args:
            name: Name of the checkpoint.
        """
        self._checkpoints.append((name, self.elapsed()))

    def get_checkpoints(self) -> list[tuple[str, float]]:
        """Get all recorded checkpoints."""
        return list(self._checkpoints)

    async def run(
        self,
        name: str,
        coro: Coroutine[Any, Any, T],
    ) -> T:
        """
        Run a coroutine with remaining timeout.

        Args:
            name: Name of the operation (for checkpointing).
            coro: Coroutine to run.

        Returns:
            Coroutine result.

        Raises:
            TimeoutError: If deadline is exceeded.
        """
        if self._deadline is None:
            raise RuntimeError("TimeoutScope not started")

        self.checkpoint(f"{name}_start")
        try:
            result = await run_with_deadline(coro, self._deadline, name)
            self.checkpoint(f"{name}_end")
            return result
        except TimeoutError:
            self.checkpoint(f"{name}_timeout")
            raise

    def run_sync(self, name: str, func: Callable[..., T], *args: Any, **kwargs: Any) -> T:
        """
        Run a sync function with remaining timeout.

        Args:
            name: Name of the operation.
            func: Function to run.
            *args: Positional arguments.
            **kwargs: Keyword arguments.

        Returns:
            Function result.
        """
        if self._deadline is None:
            raise RuntimeError("TimeoutScope not started")

        self.checkpoint(f"{name}_start")
        try:
            result = _run_with_timeout_sync(
                func, args, kwargs, self._deadline.remaining(), name
            )
            self.checkpoint(f"{name}_end")
            return result
        except TimeoutError:
            self.checkpoint(f"{name}_timeout")
            raise
