"""
Fallback chains for AI operations.

Provides ordered fallback mechanisms for models and tools,
allowing graceful handling of failures.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import threading
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Generic, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


class FallbackCondition(Enum):
    """Conditions that trigger fallback."""

    ALWAYS = "always"  # Always try this fallback if previous failed
    ON_TIMEOUT = "on_timeout"  # Only on timeout errors
    ON_RATE_LIMIT = "on_rate_limit"  # Only on rate limit errors
    ON_UNAVAILABLE = "on_unavailable"  # Only when service unavailable
    ON_ERROR = "on_error"  # Only on general errors


@dataclass
class FallbackOption:
    """
    A single fallback option in a chain.

    Attributes:
        name: Identifier for this fallback option.
        handler: Callable that handles the request.
        priority: Priority order (lower = higher priority).
        conditions: Conditions under which this fallback applies.
        enabled: Whether this fallback is currently enabled.
        metadata: Additional metadata about this option.

    Example:
        >>> option = FallbackOption(
        ...     name="gpt-4o",
        ...     handler=call_gpt4,
        ...     priority=1,
        ... )
    """

    name: str
    handler: Callable[..., Any]
    priority: int = 0
    conditions: set[FallbackCondition] = field(
        default_factory=lambda: {FallbackCondition.ALWAYS}
    )
    enabled: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    def matches_condition(self, exception: Exception) -> bool:
        """
        Check if exception matches any of the fallback conditions.

        Args:
            exception: The exception that occurred.

        Returns:
            True if this fallback should be attempted.
        """
        if not self.enabled:
            return False

        if FallbackCondition.ALWAYS in self.conditions:
            return True

        # Check specific conditions based on exception type
        exception_type = type(exception).__name__.lower()
        exception_msg = str(exception).lower()

        if FallbackCondition.ON_TIMEOUT in self.conditions:
            if "timeout" in exception_type or "timeout" in exception_msg:
                return True

        if FallbackCondition.ON_RATE_LIMIT in self.conditions:
            if "ratelimit" in exception_type or "rate limit" in exception_msg:
                return True
            if "429" in exception_msg:
                return True

        if FallbackCondition.ON_UNAVAILABLE in self.conditions:
            if "unavailable" in exception_msg or "503" in exception_msg:
                return True

        return FallbackCondition.ON_ERROR in self.conditions


@dataclass
class FallbackResult(Generic[T]):
    """
    Result of a fallback chain execution.

    Attributes:
        success: Whether any option succeeded.
        result: The result value if successful.
        used_fallback: Whether a fallback was used (not the primary).
        fallback_name: Name of the fallback that succeeded.
        attempts: Number of attempts made.
        exceptions: List of exceptions encountered.
        execution_time: Total execution time in seconds.

    Example:
        >>> result = await chain.execute_async(prompt="Hello")
        >>> if result.success:
        ...     print(f"Got result from {result.fallback_name}")
        ...     print(result.result)
    """

    success: bool
    result: T | None = None
    used_fallback: bool = False
    fallback_name: str | None = None
    attempts: int = 0
    exceptions: list[tuple[str, Exception]] = field(default_factory=list)
    execution_time: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "success": self.success,
            "used_fallback": self.used_fallback,
            "fallback_name": self.fallback_name,
            "attempts": self.attempts,
            "execution_time": self.execution_time,
            "exception_types": [
                (name, type(e).__name__) for name, e in self.exceptions
            ],
        }


class FallbackChain(Generic[T]):
    """
    Ordered chain of fallback options.

    Executes options in priority order until one succeeds.
    Supports both synchronous and asynchronous handlers.

    Example:
        >>> chain = FallbackChain([
        ...     FallbackOption("claude-opus", call_claude, priority=1),
        ...     FallbackOption("gpt-4o", call_gpt4, priority=2),
        ...     FallbackOption("local-llama", call_local, priority=3),
        ... ])
        >>>
        >>> # Execute with fallback
        >>> result = await chain.execute_async(prompt="Hello")
        >>> if result.success:
        ...     print(result.result)
    """

    def __init__(
        self,
        options: list[FallbackOption] | None = None,
        stop_on_success: bool = True,
    ) -> None:
        """
        Initialize the fallback chain.

        Args:
            options: List of fallback options.
            stop_on_success: Whether to stop after first success.
        """
        self._options: list[FallbackOption] = []
        self._lock = threading.RLock()
        self.stop_on_success = stop_on_success

        if options:
            for option in options:
                self.add_option(option)

    def add_option(self, option: FallbackOption) -> FallbackChain[T]:
        """
        Add a fallback option.

        Options are kept sorted by priority.

        Args:
            option: The option to add.

        Returns:
            Self for chaining.
        """
        with self._lock:
            self._options.append(option)
            self._options.sort(key=lambda o: o.priority)
        return self

    def remove_option(self, name: str) -> bool:
        """
        Remove a fallback option by name.

        Args:
            name: Name of the option to remove.

        Returns:
            True if option was found and removed.
        """
        with self._lock:
            for i, option in enumerate(self._options):
                if option.name == name:
                    self._options.pop(i)
                    return True
        return False

    def enable_option(self, name: str) -> bool:
        """Enable a fallback option."""
        with self._lock:
            for option in self._options:
                if option.name == name:
                    option.enabled = True
                    return True
        return False

    def disable_option(self, name: str) -> bool:
        """Disable a fallback option."""
        with self._lock:
            for option in self._options:
                if option.name == name:
                    option.enabled = False
                    return True
        return False

    def get_options(self) -> list[FallbackOption]:
        """Get all options (copy)."""
        with self._lock:
            return list(self._options)

    def execute(
        self,
        *args: Any,
        primary: Callable[..., T] | None = None,
        **kwargs: Any,
    ) -> FallbackResult[T]:
        """
        Execute the fallback chain synchronously.

        Args:
            *args: Arguments to pass to handlers.
            primary: Optional primary handler to try first.
            **kwargs: Keyword arguments to pass to handlers.

        Returns:
            FallbackResult with execution details.
        """
        start_time = datetime.now(timezone.utc)
        result = FallbackResult[T](success=False)

        # Build execution order
        handlers: list[tuple[str, Callable[..., Any], bool]] = []
        if primary:
            handlers.append(("primary", primary, False))

        with self._lock:
            for option in self._options:
                if option.enabled:
                    handlers.append((option.name, option.handler, True))

        for name, handler, is_fallback in handlers:
            result.attempts += 1

            try:
                # Check if handler is async
                if inspect.iscoroutinefunction(handler):
                    # Run async handler in event loop
                    loop = asyncio.new_event_loop()
                    try:
                        value = loop.run_until_complete(handler(*args, **kwargs))
                    finally:
                        loop.close()
                else:
                    value = handler(*args, **kwargs)

                result.success = True
                result.result = value
                result.used_fallback = is_fallback
                result.fallback_name = name

                logger.debug(f"Fallback chain: '{name}' succeeded")
                break

            except Exception as e:
                result.exceptions.append((name, e))
                logger.warning(f"Fallback chain: '{name}' failed: {e}")

                # Check if next option matches condition
                # (simplified - in full implementation would check conditions)

        result.execution_time = (
            datetime.now(timezone.utc) - start_time
        ).total_seconds()
        return result

    async def execute_async(
        self,
        *args: Any,
        primary: Callable[..., Awaitable[T]] | None = None,
        **kwargs: Any,
    ) -> FallbackResult[T]:
        """
        Execute the fallback chain asynchronously.

        Args:
            *args: Arguments to pass to handlers.
            primary: Optional primary async handler to try first.
            **kwargs: Keyword arguments to pass to handlers.

        Returns:
            FallbackResult with execution details.
        """
        start_time = datetime.now(timezone.utc)
        result = FallbackResult[T](success=False)

        # Build execution order
        handlers: list[tuple[str, Callable[..., Any], bool]] = []
        if primary:
            handlers.append(("primary", primary, False))

        with self._lock:
            for option in self._options:
                if option.enabled:
                    handlers.append((option.name, option.handler, True))

        for name, handler, is_fallback in handlers:
            result.attempts += 1

            try:
                # Check if handler is async
                if inspect.iscoroutinefunction(handler):
                    value = await handler(*args, **kwargs)
                else:
                    # Run sync handler in thread pool
                    loop = asyncio.get_event_loop()
                    value = await loop.run_in_executor(
                        None, lambda h=handler: h(*args, **kwargs)
                    )

                result.success = True
                result.result = value
                result.used_fallback = is_fallback
                result.fallback_name = name

                logger.debug(f"Fallback chain: '{name}' succeeded")
                break

            except Exception as e:
                result.exceptions.append((name, e))
                logger.warning(f"Fallback chain: '{name}' failed: {e}")

        result.execution_time = (
            datetime.now(timezone.utc) - start_time
        ).total_seconds()
        return result

    def __len__(self) -> int:
        """Get number of options."""
        return len(self._options)


class ModelFallback(FallbackChain[str]):
    """
    Specialized fallback chain for LLM models.

    Provides convenience methods for common model fallback patterns.

    Example:
        >>> fallback = ModelFallback()
        >>> fallback.add_model("claude-opus-4-5", call_claude_opus)
        >>> fallback.add_model("gpt-4o", call_gpt4o)
        >>> result = await fallback.complete(prompt="Hello")
    """

    def __init__(self) -> None:
        """Initialize model fallback chain."""
        super().__init__()
        self._model_stats: dict[str, dict[str, int]] = {}

    def add_model(
        self,
        model_name: str,
        handler: Callable[..., str | Awaitable[str]],
        priority: int | None = None,
        **metadata: Any,
    ) -> ModelFallback:
        """
        Add a model to the fallback chain.

        Args:
            model_name: Name of the model.
            handler: Function to call the model.
            priority: Priority (auto-assigned if None).
            **metadata: Additional model metadata.

        Returns:
            Self for chaining.
        """
        if priority is None:
            priority = len(self._options)

        option = FallbackOption(
            name=model_name,
            handler=handler,
            priority=priority,
            metadata={"model_name": model_name, **metadata},
        )
        self.add_option(option)
        self._model_stats[model_name] = {"calls": 0, "successes": 0, "failures": 0}
        return self

    async def complete(
        self,
        prompt: str,
        **kwargs: Any,
    ) -> FallbackResult[str]:
        """
        Complete a prompt using the model fallback chain.

        Args:
            prompt: The prompt to complete.
            **kwargs: Additional arguments for the model.

        Returns:
            FallbackResult with the completion.
        """
        result = await self.execute_async(prompt=prompt, **kwargs)

        # Update stats
        if result.fallback_name and result.fallback_name in self._model_stats:
            self._model_stats[result.fallback_name]["calls"] += 1
            if result.success:
                self._model_stats[result.fallback_name]["successes"] += 1
            else:
                self._model_stats[result.fallback_name]["failures"] += 1

        return result

    def get_model_stats(self) -> dict[str, dict[str, int]]:
        """Get statistics for each model."""
        return dict(self._model_stats)


class ToolFallback(FallbackChain[Any]):
    """
    Specialized fallback chain for tools.

    Provides convenience methods for tool fallback patterns.

    Example:
        >>> fallback = ToolFallback()
        >>> fallback.add_tool("google_search", google_search)
        >>> fallback.add_tool("bing_search", bing_search)
        >>> fallback.add_tool("cached", get_cached)
        >>> result = await fallback.invoke(query="test")
    """

    def __init__(self) -> None:
        """Initialize tool fallback chain."""
        super().__init__()
        self._tool_stats: dict[str, dict[str, int]] = {}

    def add_tool(
        self,
        tool_name: str,
        handler: Callable[..., Any | Awaitable[Any]],
        priority: int | None = None,
        conditions: set[FallbackCondition] | None = None,
        **metadata: Any,
    ) -> ToolFallback:
        """
        Add a tool to the fallback chain.

        Args:
            tool_name: Name of the tool.
            handler: Function to call the tool.
            priority: Priority (auto-assigned if None).
            conditions: Fallback conditions.
            **metadata: Additional tool metadata.

        Returns:
            Self for chaining.
        """
        if priority is None:
            priority = len(self._options)

        option = FallbackOption(
            name=tool_name,
            handler=handler,
            priority=priority,
            conditions=conditions or {FallbackCondition.ALWAYS},
            metadata={"tool_name": tool_name, **metadata},
        )
        self.add_option(option)
        self._tool_stats[tool_name] = {"calls": 0, "successes": 0, "failures": 0}
        return self

    async def invoke(self, **kwargs: Any) -> FallbackResult[Any]:
        """
        Invoke a tool using the fallback chain.

        Args:
            **kwargs: Arguments for the tool.

        Returns:
            FallbackResult with the tool output.
        """
        result = await self.execute_async(**kwargs)

        # Update stats
        if result.fallback_name and result.fallback_name in self._tool_stats:
            self._tool_stats[result.fallback_name]["calls"] += 1
            if result.success:
                self._tool_stats[result.fallback_name]["successes"] += 1
            else:
                self._tool_stats[result.fallback_name]["failures"] += 1

        return result

    def invoke_sync(self, **kwargs: Any) -> FallbackResult[Any]:
        """
        Invoke a tool synchronously.

        Args:
            **kwargs: Arguments for the tool.

        Returns:
            FallbackResult with the tool output.
        """
        result = self.execute(**kwargs)

        # Update stats
        if result.fallback_name and result.fallback_name in self._tool_stats:
            self._tool_stats[result.fallback_name]["calls"] += 1
            if result.success:
                self._tool_stats[result.fallback_name]["successes"] += 1
            else:
                self._tool_stats[result.fallback_name]["failures"] += 1

        return result

    def get_tool_stats(self) -> dict[str, dict[str, int]]:
        """Get statistics for each tool."""
        return dict(self._tool_stats)
