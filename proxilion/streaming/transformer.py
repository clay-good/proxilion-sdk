"""
Stream transformation and filtering for LLM responses.

Provides utilities for filtering, transforming, and validating
streaming content before it reaches the client.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import AsyncIterator, Callable, Iterator
from dataclasses import dataclass, field
from typing import Any, Generic, Protocol, TypeVar

from proxilion.streaming.detector import (
    DetectedToolCall,
    StreamEvent,
    StreamEventType,
    StreamingToolCallDetector,
)

T = TypeVar("T")


class StreamFilter(Protocol):
    """Protocol for stream content filters."""

    def __call__(self, content: str) -> str | None:
        """
        Filter content.

        Args:
            content: The content to filter.

        Returns:
            Filtered content, or None to drop the chunk.
        """
        ...


class StreamValidator(Protocol):
    """Protocol for stream validators."""

    def __call__(self, content: str) -> bool:
        """
        Validate content.

        Args:
            content: The content to validate.

        Returns:
            True to continue stream, False to stop.
        """
        ...


class ToolCallAuthorizer(Protocol):
    """Protocol for tool call authorization."""

    def __call__(self, tool_call: DetectedToolCall) -> bool:
        """
        Authorize a tool call.

        Args:
            tool_call: The detected tool call.

        Returns:
            True if authorized, False otherwise.
        """
        ...


@dataclass
class FilteredStream(Generic[T]):
    """
    An async iterator wrapper that applies filters to a stream.

    Attributes:
        source: The original async iterator.
        filters: List of filter functions to apply.
        validators: List of validator functions to apply.
        stopped: Whether the stream has been stopped.
    """

    source: AsyncIterator[T]
    filters: list[StreamFilter] = field(default_factory=list)
    validators: list[StreamValidator] = field(default_factory=list)
    stopped: bool = False
    _buffer: list[T] = field(default_factory=list)

    def __aiter__(self) -> AsyncIterator[T]:
        return self

    async def __anext__(self) -> T:
        if self.stopped:
            raise StopAsyncIteration

        while True:
            try:
                chunk = await self.source.__anext__()
            except StopAsyncIteration:
                raise

            # Convert chunk to string for filtering
            if isinstance(chunk, str):
                content = chunk
            elif hasattr(chunk, "content"):
                content = getattr(chunk, "content", "")
            else:
                content = str(chunk)

            # Apply validators
            for validator in self.validators:
                if not validator(content):
                    self.stopped = True
                    raise StopAsyncIteration

            # Apply filters
            result = content
            for filter_fn in self.filters:
                result = filter_fn(result)
                if result is None:
                    break  # Drop this chunk

            if result is not None:
                # Return original chunk type if possible
                if isinstance(chunk, str):
                    return result  # type: ignore
                return chunk

    def stop(self) -> None:
        """Stop the stream."""
        self.stopped = True


class StreamTransformer:
    """
    Transform streaming content with filters and validators.

    Supports both string streams and structured chunk streams,
    applying filters and validators to control content flow.

    Example:
        >>> transformer = StreamTransformer()
        >>> transformer.add_filter(redact_pii)
        >>> transformer.add_filter(block_sensitive_output)
        >>>
        >>> async for chunk in transformer.transform(original_stream):
        ...     yield chunk  # Filtered content

    Example with tool call authorization:
        >>> transformer = StreamTransformer()
        >>> transformer.set_tool_call_authorizer(my_authorizer)
        >>>
        >>> async for event in transformer.transform_events(detector_events):
        ...     if event.type == StreamEventType.TOOL_CALL_END:
        ...         # Tool call was authorized
        ...         execute_tool(event.tool_call)
    """

    def __init__(self) -> None:
        """Initialize the transformer."""
        self._filters: list[StreamFilter] = []
        self._validators: list[StreamValidator] = []
        self._tool_call_authorizer: ToolCallAuthorizer | None = None
        self._event_callbacks: list[Callable[[StreamEvent], None]] = []
        self._lock = threading.Lock()

    def add_filter(self, filter_fn: StreamFilter) -> StreamTransformer:
        """
        Add a content filter.

        Filters are applied in order. Return None to drop a chunk.

        Args:
            filter_fn: Function that takes content and returns filtered content or None.

        Returns:
            Self for chaining.
        """
        with self._lock:
            self._filters.append(filter_fn)
        return self

    def add_validator(self, validator_fn: StreamValidator) -> StreamTransformer:
        """
        Add a validator.

        Validators are checked before filters. Return False to stop the stream.

        Args:
            validator_fn: Function that takes content and returns bool.

        Returns:
            Self for chaining.
        """
        with self._lock:
            self._validators.append(validator_fn)
        return self

    def set_tool_call_authorizer(
        self, authorizer: ToolCallAuthorizer
    ) -> StreamTransformer:
        """
        Set the tool call authorizer.

        Args:
            authorizer: Function that authorizes tool calls.

        Returns:
            Self for chaining.
        """
        self._tool_call_authorizer = authorizer
        return self

    def add_event_callback(
        self, callback: Callable[[StreamEvent], None]
    ) -> StreamTransformer:
        """
        Add an event callback.

        Callbacks are invoked for each stream event.

        Args:
            callback: Function called with each StreamEvent.

        Returns:
            Self for chaining.
        """
        with self._lock:
            self._event_callbacks.append(callback)
        return self

    def clear_filters(self) -> None:
        """Remove all filters."""
        with self._lock:
            self._filters.clear()

    def clear_validators(self) -> None:
        """Remove all validators."""
        with self._lock:
            self._validators.clear()

    async def transform(
        self,
        stream: AsyncIterator[str],
    ) -> AsyncIterator[str]:
        """
        Transform a string stream with all registered filters.

        Args:
            stream: The source async iterator of strings.

        Yields:
            Filtered string chunks.
        """
        async for chunk in stream:
            # Apply validators
            valid = True
            for validator in self._validators:
                if not validator(chunk):
                    valid = False
                    break

            if not valid:
                return  # Stop stream

            # Apply filters
            result: str | None = chunk
            for filter_fn in self._filters:
                if result is None:
                    break
                result = filter_fn(result)

            if result is not None:
                yield result

    def transform_sync(
        self,
        stream: Iterator[str],
    ) -> Iterator[str]:
        """
        Transform a synchronous string stream.

        Args:
            stream: The source iterator of strings.

        Yields:
            Filtered string chunks.
        """
        for chunk in stream:
            # Apply validators
            valid = True
            for validator in self._validators:
                if not validator(chunk):
                    valid = False
                    break

            if not valid:
                return  # Stop stream

            # Apply filters
            result: str | None = chunk
            for filter_fn in self._filters:
                if result is None:
                    break
                result = filter_fn(result)

            if result is not None:
                yield result

    async def transform_events(
        self,
        stream: AsyncIterator[StreamEvent],
    ) -> AsyncIterator[StreamEvent]:
        """
        Transform a stream of StreamEvents.

        Applies filters to TEXT events and authorization to tool calls.

        Args:
            stream: The source async iterator of StreamEvents.

        Yields:
            Transformed StreamEvent objects.
        """
        async for event in stream:
            # Invoke callbacks
            for callback in self._event_callbacks:
                callback(event)

            if event.type == StreamEventType.TEXT:
                # Apply validators and filters to text
                content = event.content or ""

                valid = True
                for validator in self._validators:
                    if not validator(content):
                        valid = False
                        break

                if not valid:
                    return  # Stop stream

                result: str | None = content
                for filter_fn in self._filters:
                    if result is None:
                        break
                    result = filter_fn(result)

                if result is not None:
                    yield StreamEvent.text(result, event.raw_chunk)

            elif event.type == StreamEventType.TOOL_CALL_END:
                # Check authorization for tool calls
                if self._tool_call_authorizer and event.tool_call:
                    if not self._tool_call_authorizer(event.tool_call):
                        # Tool call not authorized - emit error instead
                        yield StreamEvent.error_event(
                            f"Tool call '{event.tool_call.name}' not authorized",
                            event.raw_chunk,
                        )
                        continue

                yield event

            else:
                # Pass through other events
                yield event

    async def transform_chunks(
        self,
        stream: AsyncIterator[Any],
        detector: StreamingToolCallDetector | None = None,
    ) -> AsyncIterator[StreamEvent]:
        """
        Transform raw LLM chunks into StreamEvents.

        Optionally detects tool calls and applies filters.

        Args:
            stream: Raw LLM streaming chunks.
            detector: Optional tool call detector. Creates one if not provided.

        Yields:
            StreamEvent objects.
        """
        if detector is None:
            detector = StreamingToolCallDetector()

        async for chunk in stream:
            events = detector.process_chunk(chunk)

            for event in events:
                # Apply transformations
                async for transformed in self.transform_events(
                    _single_event_iterator(event)
                ):
                    yield transformed

    def wrap(self, stream: AsyncIterator[str]) -> FilteredStream[str]:
        """
        Wrap a stream with the transformer's filters.

        Args:
            stream: The source async iterator.

        Returns:
            A FilteredStream with filters applied.
        """
        return FilteredStream(
            source=stream,
            filters=list(self._filters),
            validators=list(self._validators),
        )


async def _single_event_iterator(event: StreamEvent) -> AsyncIterator[StreamEvent]:
    """Create an async iterator yielding a single event."""
    yield event


def create_guarded_stream(
    stream: AsyncIterator[str],
    output_guard: Any,  # OutputGuard from guards module
) -> AsyncIterator[str]:
    """
    Create a stream that's filtered by output guards.

    Integrates with the OutputGuard from proxilion.guards to
    filter sensitive content from streaming responses.

    Args:
        stream: The source async iterator of strings.
        output_guard: An OutputGuard instance for content filtering.

    Returns:
        Async iterator yielding filtered content.

    Example:
        >>> from proxilion.guards import OutputGuard
        >>> guard = OutputGuard()
        >>> async for chunk in create_guarded_stream(llm_stream, guard):
        ...     # Chunks are checked for sensitive data
        ...     ws.send(chunk)
    """
    # Import here to avoid circular imports
    try:
        from proxilion.guards import GuardAction
    except ImportError:
        # Fallback if guards not available
        class GuardAction:
            ALLOW = "allow"
            BLOCK = "block"
            SANITIZE = "sanitize"

    transformer = StreamTransformer()

    def guard_filter(chunk: str) -> str | None:
        result = output_guard.check(chunk)
        if hasattr(result, "action"):
            if result.action == GuardAction.BLOCK:
                return None
            elif result.action == GuardAction.SANITIZE:
                return output_guard.redact(chunk)
        return chunk

    transformer.add_filter(guard_filter)
    return transformer.transform(stream)


def create_authorization_stream(
    stream: AsyncIterator[Any],
    authorizer: Callable[[DetectedToolCall], bool],
    detector: StreamingToolCallDetector | None = None,
) -> AsyncIterator[StreamEvent]:
    """
    Create a stream that authorizes tool calls.

    Processes raw LLM chunks, detects tool calls, and applies
    authorization before yielding events.

    Args:
        stream: Raw LLM streaming chunks.
        authorizer: Function to authorize tool calls.
        detector: Optional detector instance.

    Returns:
        Async iterator yielding StreamEvents.

    Example:
        >>> def my_authorizer(tool_call):
        ...     return auth.can(user, "execute", tool_call.name)
        >>>
        >>> async for event in create_authorization_stream(llm_stream, my_authorizer):
        ...     if event.type == StreamEventType.TOOL_CALL_END:
        ...         # Tool call is authorized
        ...         result = execute_tool(event.tool_call)
    """
    transformer = StreamTransformer()
    transformer.set_tool_call_authorizer(authorizer)
    return transformer.transform_chunks(stream, detector)


class BufferedStreamTransformer:
    r"""
    Stream transformer that buffers content for pattern matching.

    Useful when you need to detect patterns that may span multiple chunks.

    Example:
        >>> transformer = BufferedStreamTransformer(buffer_size=1000)
        >>> transformer.add_pattern_filter(r"API_KEY_\w+", "[REDACTED]")
        >>>
        >>> async for chunk in transformer.transform(stream):
        ...     yield chunk
    """

    def __init__(self, buffer_size: int = 500) -> None:
        """
        Initialize the buffered transformer.

        Args:
            buffer_size: Maximum buffer size in characters.
        """
        self.buffer_size = buffer_size
        self._buffer: str = ""
        self._patterns: list[tuple[str, str]] = []
        self._lock = threading.Lock()

    def add_pattern_filter(
        self, pattern: str, replacement: str
    ) -> BufferedStreamTransformer:
        """
        Add a regex pattern filter.

        Args:
            pattern: Regex pattern to match.
            replacement: Replacement string.

        Returns:
            Self for chaining.
        """
        import re

        # Validate pattern
        re.compile(pattern)
        with self._lock:
            self._patterns.append((pattern, replacement))
        return self

    async def transform(self, stream: AsyncIterator[str]) -> AsyncIterator[str]:
        """
        Transform stream with buffered pattern matching.

        Args:
            stream: Source async iterator.

        Yields:
            Filtered content.
        """
        import re

        async for chunk in stream:
            self._buffer += chunk

            # If buffer is large enough, process and emit it.
            # The buffer_size acts as the accumulation window: we
            # collect enough data to catch patterns that may span
            # multiple chunks before applying regex and yielding.
            if len(self._buffer) >= self.buffer_size:
                result = self._buffer
                for pattern, replacement in self._patterns:
                    result = re.sub(pattern, replacement, result)
                yield result
                self._buffer = ""

        # Flush remaining buffer
        if self._buffer:
            result = self._buffer
            for pattern, replacement in self._patterns:
                result = re.sub(pattern, replacement, result)
            yield result
            self._buffer = ""

    def reset(self) -> None:
        """Reset the buffer."""
        with self._lock:
            self._buffer = ""


class StreamAggregator:
    """
    Aggregate streaming content for batch processing.

    Collects chunks until a condition is met, then yields
    the aggregated content.

    Example:
        >>> aggregator = StreamAggregator(
        ...     min_chars=100,
        ...     timeout=1.0,
        ... )
        >>> async for batch in aggregator.aggregate(stream):
        ...     process_batch(batch)
    """

    def __init__(
        self,
        min_chars: int = 0,
        max_chars: int = 10000,
        timeout: float = 0.5,
        delimiter: str | None = None,
    ) -> None:
        """
        Initialize the aggregator.

        Args:
            min_chars: Minimum characters before yielding.
            max_chars: Maximum characters to buffer.
            timeout: Timeout in seconds before yielding.
            delimiter: Optional delimiter that triggers yield.
        """
        self.min_chars = min_chars
        self.max_chars = max_chars
        self.timeout = timeout
        self.delimiter = delimiter
        self._buffer: str = ""

    async def aggregate(self, stream: AsyncIterator[str]) -> AsyncIterator[str]:
        """
        Aggregate streaming content.

        Args:
            stream: Source async iterator.

        Yields:
            Aggregated batches.
        """
        last_yield = asyncio.get_event_loop().time()

        async for chunk in stream:
            self._buffer += chunk
            now = asyncio.get_event_loop().time()

            should_yield = False

            # Check delimiter
            if self.delimiter and self.delimiter in self._buffer:
                should_yield = True

            # Check max chars
            if len(self._buffer) >= self.max_chars:
                should_yield = True

            # Check min chars and timeout
            if len(self._buffer) >= self.min_chars and (now - last_yield) >= self.timeout:
                should_yield = True

            if should_yield and self._buffer:
                yield self._buffer
                self._buffer = ""
                last_yield = now

        # Flush remaining
        if self._buffer:
            yield self._buffer
            self._buffer = ""

    def reset(self) -> None:
        """Reset the buffer."""
        self._buffer = ""
