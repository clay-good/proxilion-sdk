"""
Tool call detection in streaming LLM responses.

Provides utilities for detecting and extracting tool calls from
streaming responses across multiple LLM providers (OpenAI, Anthropic, Google).
"""

from __future__ import annotations

import contextlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class StreamEventType(Enum):
    """Types of events that can occur during streaming."""

    TEXT = "text"
    TOOL_CALL_START = "tool_call_start"
    TOOL_CALL_DELTA = "tool_call_delta"
    TOOL_CALL_END = "tool_call_end"
    DONE = "done"
    ERROR = "error"


@dataclass
class PartialToolCall:
    """
    A tool call that is being buffered during streaming.

    Accumulates argument chunks until the tool call is complete.

    Attributes:
        id: Unique identifier for this tool call.
        name: Name of the tool being called.
        arguments_buffer: Accumulated JSON argument string.
        is_complete: Whether the tool call has finished streaming.
        started_at: When the tool call started.
        index: Index in the response (for multiple tool calls).
    """

    id: str
    name: str
    arguments_buffer: str = ""
    is_complete: bool = False
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    index: int = 0

    def append_arguments(self, delta: str) -> None:
        """Append argument delta to the buffer."""
        self.arguments_buffer += delta

    def get_arguments(self) -> dict[str, Any]:
        """
        Parse and return the accumulated arguments.

        Returns:
            Parsed arguments dictionary.

        Raises:
            ValueError: If arguments cannot be parsed as JSON.
        """
        if not self.arguments_buffer:
            return {}
        try:
            return json.loads(self.arguments_buffer)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid tool call arguments: {e}") from e

    def complete(self) -> None:
        """Mark the tool call as complete."""
        self.is_complete = True


@dataclass
class DetectedToolCall:
    """
    A fully detected tool call extracted from streaming.

    Attributes:
        id: Unique identifier for this tool call.
        name: Name of the tool being called.
        arguments: Parsed arguments dictionary.
        raw_arguments: Original JSON string of arguments.
        index: Index in the response (for multiple tool calls).
        detected_at: When the tool call was fully detected.
    """

    id: str
    name: str
    arguments: dict[str, Any]
    raw_arguments: str = ""
    index: int = 0
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @classmethod
    def from_partial(cls, partial: PartialToolCall) -> DetectedToolCall:
        """Create a DetectedToolCall from a completed PartialToolCall."""
        return cls(
            id=partial.id,
            name=partial.name,
            arguments=partial.get_arguments(),
            raw_arguments=partial.arguments_buffer,
            index=partial.index,
        )


@dataclass
class StreamEvent:
    """
    An event emitted during stream processing.

    Attributes:
        type: The type of event.
        content: Text content (for TEXT events).
        tool_call: The tool call (for TOOL_CALL_* events).
        partial_call: The partial tool call (for TOOL_CALL_DELTA events).
        error: Error message (for ERROR events).
        raw_chunk: The original chunk that produced this event.
    """

    type: StreamEventType
    content: str | None = None
    tool_call: DetectedToolCall | None = None
    partial_call: PartialToolCall | None = None
    error: str | None = None
    raw_chunk: Any = None

    @classmethod
    def text(cls, content: str, raw_chunk: Any = None) -> StreamEvent:
        """Create a TEXT event."""
        return cls(type=StreamEventType.TEXT, content=content, raw_chunk=raw_chunk)

    @classmethod
    def tool_call_start(
        cls, partial: PartialToolCall, raw_chunk: Any = None
    ) -> StreamEvent:
        """Create a TOOL_CALL_START event."""
        return cls(
            type=StreamEventType.TOOL_CALL_START,
            partial_call=partial,
            raw_chunk=raw_chunk,
        )

    @classmethod
    def tool_call_delta(
        cls, partial: PartialToolCall, raw_chunk: Any = None
    ) -> StreamEvent:
        """Create a TOOL_CALL_DELTA event."""
        return cls(
            type=StreamEventType.TOOL_CALL_DELTA,
            partial_call=partial,
            raw_chunk=raw_chunk,
        )

    @classmethod
    def tool_call_end(
        cls, tool_call: DetectedToolCall, raw_chunk: Any = None
    ) -> StreamEvent:
        """Create a TOOL_CALL_END event."""
        return cls(
            type=StreamEventType.TOOL_CALL_END,
            tool_call=tool_call,
            raw_chunk=raw_chunk,
        )

    @classmethod
    def done(cls, raw_chunk: Any = None) -> StreamEvent:
        """Create a DONE event."""
        return cls(type=StreamEventType.DONE, raw_chunk=raw_chunk)

    @classmethod
    def error_event(cls, error: str, raw_chunk: Any = None) -> StreamEvent:
        """Create an ERROR event."""
        return cls(type=StreamEventType.ERROR, error=error, raw_chunk=raw_chunk)


class StreamingToolCallDetector:
    """
    Detect and buffer tool calls from streaming LLM responses.

    Works with OpenAI, Anthropic, and Google streaming formats,
    automatically detecting the provider from chunk structure.

    Example:
        >>> detector = StreamingToolCallDetector()
        >>> async for chunk in llm_stream:
        ...     events = detector.process_chunk(chunk)
        ...     for event in events:
        ...         if event.type == StreamEventType.TOOL_CALL_END:
        ...             # Full tool call is now available
        ...             tool_call = event.tool_call
        ...             result = auth.authorize(user, "execute", tool_call.name)
        ...         elif event.type == StreamEventType.TEXT:
        ...             print(event.content, end="")

    Attributes:
        provider: The LLM provider ("openai", "anthropic", "google", or "auto").
    """

    SUPPORTED_PROVIDERS = ("auto", "openai", "anthropic", "google")

    def __init__(self, provider: str = "auto") -> None:
        """
        Initialize the detector.

        Args:
            provider: LLM provider name or "auto" for detection.

        Raises:
            ValueError: If provider is not supported.
        """
        if provider not in self.SUPPORTED_PROVIDERS:
            raise ValueError(
                f"Unsupported provider: {provider}. "
                f"Supported: {self.SUPPORTED_PROVIDERS}"
            )
        self.provider = provider
        self._partial_calls: dict[str, PartialToolCall] = {}
        self._text_buffer: str = ""
        self._detected: bool = False

    def process_chunk(self, chunk: Any) -> list[StreamEvent]:
        """
        Process a streaming chunk and return any events.

        Args:
            chunk: A streaming chunk from an LLM provider.

        Returns:
            List of StreamEvent objects detected in this chunk.

        Raises:
            ValueError: If the provider cannot be determined.
        """
        # Detect provider from chunk structure if auto
        if self.provider == "auto" and not self._detected:
            detected = self._detect_provider(chunk)
            if detected:
                self.provider = detected
                self._detected = True
            else:
                # Try to process without detection
                return self._process_generic_chunk(chunk)

        if self.provider == "openai":
            return self._process_openai_chunk(chunk)
        elif self.provider == "anthropic":
            return self._process_anthropic_chunk(chunk)
        elif self.provider == "google":
            return self._process_google_chunk(chunk)
        else:
            return self._process_generic_chunk(chunk)

    def _detect_provider(self, chunk: Any) -> str | None:
        """
        Detect the provider from chunk structure.

        Args:
            chunk: A streaming chunk to analyze.

        Returns:
            Provider name or None if detection failed.
        """
        # Check if it's a dict-like object
        if isinstance(chunk, dict):
            # OpenAI streaming format
            if "choices" in chunk:
                return "openai"
            # Anthropic streaming format
            if "type" in chunk and chunk.get("type") in (
                "content_block_start",
                "content_block_delta",
                "content_block_stop",
                "message_start",
                "message_delta",
                "message_stop",
            ):
                return "anthropic"
            # Google/Gemini format
            if "candidates" in chunk:
                return "google"

        # Check for object attributes (SDK response objects)
        if hasattr(chunk, "choices"):
            return "openai"
        if hasattr(chunk, "type"):
            chunk_type = getattr(chunk, "type", None)
            if chunk_type in (
                "content_block_start",
                "content_block_delta",
                "content_block_stop",
                "message_start",
                "message_delta",
                "message_stop",
            ):
                return "anthropic"
        if hasattr(chunk, "candidates"):
            return "google"

        return None

    def _process_openai_chunk(self, chunk: Any) -> list[StreamEvent]:
        """Process an OpenAI streaming chunk."""
        events: list[StreamEvent] = []

        # Handle dict or object format
        choices = (
            chunk.get("choices", [])
            if isinstance(chunk, dict)
            else getattr(chunk, "choices", [])
        )

        if not choices:
            return events

        for choice in choices:
            # Get delta from choice
            if isinstance(choice, dict):
                delta = choice.get("delta", {})
                finish_reason = choice.get("finish_reason")
                index = choice.get("index", 0)
            else:
                delta = getattr(choice, "delta", None)
                finish_reason = getattr(choice, "finish_reason", None)
                index = getattr(choice, "index", 0)
                if delta is None:
                    continue

            # Check for content (text)
            content = (
                delta.get("content")
                if isinstance(delta, dict)
                else getattr(delta, "content", None)
            )
            if content:
                self._text_buffer += content
                events.append(StreamEvent.text(content, chunk))

            # Check for tool calls
            tool_calls = (
                delta.get("tool_calls")
                if isinstance(delta, dict)
                else getattr(delta, "tool_calls", None)
            )
            if tool_calls:
                for tc in tool_calls:
                    tc_events = self._process_openai_tool_call(tc, index, chunk)
                    events.extend(tc_events)

            # Check for finish
            if finish_reason == "stop":
                events.append(StreamEvent.done(chunk))
            elif finish_reason == "tool_calls":
                # Mark all pending tool calls as complete
                for _call_id, partial in list(self._partial_calls.items()):
                    if not partial.is_complete:
                        partial.complete()
                        tool_call = DetectedToolCall.from_partial(partial)
                        events.append(StreamEvent.tool_call_end(tool_call, chunk))

        return events

    def _process_openai_tool_call(
        self, tc: Any, choice_index: int, chunk: Any
    ) -> list[StreamEvent]:
        """Process a tool call delta from OpenAI format."""
        events: list[StreamEvent] = []

        # Extract tool call fields
        if isinstance(tc, dict):
            tc_index = tc.get("index", 0)
            tc_id = tc.get("id")
            tc_function = tc.get("function", {})
            tc_name = tc_function.get("name") if isinstance(tc_function, dict) else None
            tc_args = (
                tc_function.get("arguments")
                if isinstance(tc_function, dict)
                else None
            )
        else:
            tc_index = getattr(tc, "index", 0)
            tc_id = getattr(tc, "id", None)
            tc_function = getattr(tc, "function", None)
            tc_name = getattr(tc_function, "name", None) if tc_function else None
            tc_args = getattr(tc_function, "arguments", None) if tc_function else None

        # Create unique key for this tool call
        call_key = f"{choice_index}_{tc_index}"

        # Check if this is a new tool call
        if tc_id and tc_name and call_key not in self._partial_calls:
            partial = PartialToolCall(
                id=tc_id,
                name=tc_name,
                index=tc_index,
            )
            self._partial_calls[call_key] = partial
            events.append(StreamEvent.tool_call_start(partial, chunk))
        elif call_key not in self._partial_calls and tc_id:
            # New tool call without name yet
            partial = PartialToolCall(
                id=tc_id,
                name="",
                index=tc_index,
            )
            self._partial_calls[call_key] = partial
            events.append(StreamEvent.tool_call_start(partial, chunk))

        # Update existing tool call
        if call_key in self._partial_calls:
            partial = self._partial_calls[call_key]
            if tc_name and not partial.name:
                partial.name = tc_name
            if tc_args:
                partial.append_arguments(tc_args)
                events.append(StreamEvent.tool_call_delta(partial, chunk))

        return events

    def _process_anthropic_chunk(self, chunk: Any) -> list[StreamEvent]:
        """Process an Anthropic streaming chunk."""
        events: list[StreamEvent] = []

        # Get chunk type
        chunk_type = (
            chunk.get("type")
            if isinstance(chunk, dict)
            else getattr(chunk, "type", None)
        )

        if chunk_type == "content_block_start":
            events.extend(self._handle_anthropic_block_start(chunk))
        elif chunk_type == "content_block_delta":
            events.extend(self._handle_anthropic_block_delta(chunk))
        elif chunk_type == "content_block_stop":
            events.extend(self._handle_anthropic_block_stop(chunk))
        elif chunk_type == "message_stop":
            events.append(StreamEvent.done(chunk))

        return events

    def _handle_anthropic_block_start(self, chunk: Any) -> list[StreamEvent]:
        """Handle Anthropic content_block_start event."""
        events: list[StreamEvent] = []

        # Get the content block
        content_block = (
            chunk.get("content_block")
            if isinstance(chunk, dict)
            else getattr(chunk, "content_block", None)
        )
        index = (
            chunk.get("index", 0)
            if isinstance(chunk, dict)
            else getattr(chunk, "index", 0)
        )

        if not content_block:
            return events

        block_type = (
            content_block.get("type")
            if isinstance(content_block, dict)
            else getattr(content_block, "type", None)
        )

        if block_type == "tool_use":
            # Start of a tool call
            tc_id = (
                content_block.get("id")
                if isinstance(content_block, dict)
                else getattr(content_block, "id", None)
            )
            tc_name = (
                content_block.get("name")
                if isinstance(content_block, dict)
                else getattr(content_block, "name", None)
            )

            if tc_id:
                partial = PartialToolCall(
                    id=tc_id,
                    name=tc_name or "",
                    index=index,
                )
                self._partial_calls[tc_id] = partial
                events.append(StreamEvent.tool_call_start(partial, chunk))

        return events

    def _handle_anthropic_block_delta(self, chunk: Any) -> list[StreamEvent]:
        """Handle Anthropic content_block_delta event."""
        events: list[StreamEvent] = []

        # Get the delta
        delta = (
            chunk.get("delta")
            if isinstance(chunk, dict)
            else getattr(chunk, "delta", None)
        )
        index = (
            chunk.get("index", 0)
            if isinstance(chunk, dict)
            else getattr(chunk, "index", 0)
        )

        if not delta:
            return events

        delta_type = (
            delta.get("type")
            if isinstance(delta, dict)
            else getattr(delta, "type", None)
        )

        if delta_type == "text_delta":
            # Text content
            text = (
                delta.get("text")
                if isinstance(delta, dict)
                else getattr(delta, "text", None)
            )
            if text:
                self._text_buffer += text
                events.append(StreamEvent.text(text, chunk))

        elif delta_type == "input_json_delta":
            # Tool call arguments
            partial_json = (
                delta.get("partial_json")
                if isinstance(delta, dict)
                else getattr(delta, "partial_json", None)
            )
            if partial_json:
                # Find the partial call for this index
                for partial in self._partial_calls.values():
                    if partial.index == index and not partial.is_complete:
                        partial.append_arguments(partial_json)
                        events.append(StreamEvent.tool_call_delta(partial, chunk))
                        break

        return events

    def _handle_anthropic_block_stop(self, chunk: Any) -> list[StreamEvent]:
        """Handle Anthropic content_block_stop event."""
        events: list[StreamEvent] = []

        index = (
            chunk.get("index", 0)
            if isinstance(chunk, dict)
            else getattr(chunk, "index", 0)
        )

        # Find and complete the partial call at this index
        for _call_id, partial in list(self._partial_calls.items()):
            if partial.index == index and not partial.is_complete:
                partial.complete()
                try:
                    tool_call = DetectedToolCall.from_partial(partial)
                    events.append(StreamEvent.tool_call_end(tool_call, chunk))
                except ValueError as e:
                    events.append(StreamEvent.error_event(str(e), chunk))
                break

        return events

    def _process_google_chunk(self, chunk: Any) -> list[StreamEvent]:
        """Process a Google/Gemini streaming chunk."""
        events: list[StreamEvent] = []

        # Get candidates
        candidates = (
            chunk.get("candidates", [])
            if isinstance(chunk, dict)
            else getattr(chunk, "candidates", [])
        )

        if not candidates:
            return events

        for cand_idx, candidate in enumerate(candidates):
            # Get content from candidate
            content = (
                candidate.get("content")
                if isinstance(candidate, dict)
                else getattr(candidate, "content", None)
            )
            finish_reason = (
                candidate.get("finishReason")
                if isinstance(candidate, dict)
                else getattr(candidate, "finish_reason", None)
            )

            if content:
                parts = (
                    content.get("parts", [])
                    if isinstance(content, dict)
                    else getattr(content, "parts", [])
                )

                for part_idx, part in enumerate(parts):
                    part_events = self._process_google_part(
                        part, cand_idx, part_idx, chunk
                    )
                    events.extend(part_events)

            # Check for finish
            if finish_reason == "STOP":
                # Complete any pending tool calls
                for partial in list(self._partial_calls.values()):
                    if not partial.is_complete:
                        partial.complete()
                        try:
                            tool_call = DetectedToolCall.from_partial(partial)
                            events.append(StreamEvent.tool_call_end(tool_call, chunk))
                        except ValueError:
                            pass
                events.append(StreamEvent.done(chunk))

        return events

    def _process_google_part(
        self, part: Any, cand_idx: int, part_idx: int, chunk: Any
    ) -> list[StreamEvent]:
        """Process a part from a Google response."""
        events: list[StreamEvent] = []

        # Check for text
        text = (
            part.get("text") if isinstance(part, dict) else getattr(part, "text", None)
        )
        if text:
            self._text_buffer += text
            events.append(StreamEvent.text(text, chunk))

        # Check for function call
        function_call = (
            part.get("functionCall")
            if isinstance(part, dict)
            else getattr(part, "function_call", None)
        )
        if function_call:
            # Google sends function calls complete in one chunk
            fc_name = (
                function_call.get("name")
                if isinstance(function_call, dict)
                else getattr(function_call, "name", None)
            )
            fc_args = (
                function_call.get("args")
                if isinstance(function_call, dict)
                else getattr(function_call, "args", None)
            )

            call_id = f"google_{cand_idx}_{part_idx}"
            partial = PartialToolCall(
                id=call_id,
                name=fc_name or "",
                index=part_idx,
            )

            # Google sends args as dict, not JSON string
            if fc_args:
                if isinstance(fc_args, dict):
                    partial.arguments_buffer = json.dumps(fc_args)
                else:
                    partial.arguments_buffer = str(fc_args)

            partial.complete()
            self._partial_calls[call_id] = partial

            events.append(StreamEvent.tool_call_start(partial, chunk))
            tool_call = DetectedToolCall.from_partial(partial)
            events.append(StreamEvent.tool_call_end(tool_call, chunk))

        return events

    def _process_generic_chunk(self, chunk: Any) -> list[StreamEvent]:
        """Process a chunk with unknown format."""
        events: list[StreamEvent] = []

        # Try to extract text content
        if isinstance(chunk, str):
            self._text_buffer += chunk
            events.append(StreamEvent.text(chunk, chunk))
        elif isinstance(chunk, dict):
            # Try common keys
            for key in ("content", "text", "message", "data"):
                if key in chunk and isinstance(chunk[key], str):
                    self._text_buffer += chunk[key]
                    events.append(StreamEvent.text(chunk[key], chunk))
                    break

        return events

    def get_pending_calls(self) -> list[PartialToolCall]:
        """
        Get tool calls that are still being streamed.

        Returns:
            List of incomplete PartialToolCall objects.
        """
        return [c for c in self._partial_calls.values() if not c.is_complete]

    def get_completed_calls(self) -> list[PartialToolCall]:
        """
        Get tool calls that have completed streaming.

        Returns:
            List of complete PartialToolCall objects.
        """
        return [c for c in self._partial_calls.values() if c.is_complete]

    def get_all_detected_calls(self) -> list[DetectedToolCall]:
        """
        Get all completed tool calls as DetectedToolCall objects.

        Returns:
            List of DetectedToolCall objects.
        """
        result = []
        for partial in self._partial_calls.values():
            if partial.is_complete:
                with contextlib.suppress(ValueError):
                    result.append(DetectedToolCall.from_partial(partial))
        return result

    def get_text_buffer(self) -> str:
        """
        Get all accumulated text content.

        Returns:
            Concatenated text from all TEXT events.
        """
        return self._text_buffer

    def reset(self) -> None:
        """Reset detector state for a new stream."""
        self._partial_calls.clear()
        self._text_buffer = ""
        if self.provider == "auto":
            self._detected = False

    def get_stats(self) -> dict[str, Any]:
        """
        Get statistics about the current stream processing.

        Returns:
            Dictionary with processing statistics.
        """
        return {
            "provider": self.provider,
            "pending_calls": len(self.get_pending_calls()),
            "completed_calls": len(self.get_completed_calls()),
            "text_length": len(self._text_buffer),
            "total_calls": len(self._partial_calls),
        }
