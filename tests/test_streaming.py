"""
Tests for the streaming response handling module.

Tests cover:
- Tool call detection in streaming responses
- OpenAI, Anthropic, and Google streaming formats
- Partial tool call buffering
- Complete tool call extraction
- Stream filtering and transformation
- Output guard integration
- Authorization integration
"""

import asyncio
import json
import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock, AsyncMock

from proxilion.streaming.detector import (
    StreamEventType,
    StreamEvent,
    PartialToolCall,
    DetectedToolCall,
    StreamingToolCallDetector,
)
from proxilion.streaming.transformer import (
    StreamTransformer,
    FilteredStream,
    BufferedStreamTransformer,
    StreamAggregator,
    create_guarded_stream,
    create_authorization_stream,
)


# ==================== PartialToolCall Tests ====================


class TestPartialToolCall:
    """Tests for PartialToolCall dataclass."""

    def test_create_partial_tool_call(self):
        """Test creating a partial tool call."""
        partial = PartialToolCall(
            id="call_123",
            name="test_tool",
            index=0,
        )
        assert partial.id == "call_123"
        assert partial.name == "test_tool"
        assert partial.arguments_buffer == ""
        assert partial.is_complete is False
        assert partial.index == 0

    def test_append_arguments(self):
        """Test appending argument chunks."""
        partial = PartialToolCall(id="call_123", name="test_tool")
        partial.append_arguments('{"key":')
        partial.append_arguments(' "value"}')
        assert partial.arguments_buffer == '{"key": "value"}'

    def test_get_arguments_valid_json(self):
        """Test getting arguments with valid JSON."""
        partial = PartialToolCall(id="call_123", name="test_tool")
        partial.arguments_buffer = '{"key": "value", "number": 42}'
        args = partial.get_arguments()
        assert args == {"key": "value", "number": 42}

    def test_get_arguments_empty(self):
        """Test getting arguments when empty."""
        partial = PartialToolCall(id="call_123", name="test_tool")
        args = partial.get_arguments()
        assert args == {}

    def test_get_arguments_invalid_json(self):
        """Test getting arguments with invalid JSON."""
        partial = PartialToolCall(id="call_123", name="test_tool")
        partial.arguments_buffer = '{"key": incomplete'
        with pytest.raises(ValueError, match="Invalid tool call arguments"):
            partial.get_arguments()

    def test_complete(self):
        """Test marking a tool call as complete."""
        partial = PartialToolCall(id="call_123", name="test_tool")
        assert partial.is_complete is False
        partial.complete()
        assert partial.is_complete is True


# ==================== DetectedToolCall Tests ====================


class TestDetectedToolCall:
    """Tests for DetectedToolCall dataclass."""

    def test_create_detected_tool_call(self):
        """Test creating a detected tool call."""
        tool_call = DetectedToolCall(
            id="call_123",
            name="test_tool",
            arguments={"key": "value"},
            raw_arguments='{"key": "value"}',
            index=0,
        )
        assert tool_call.id == "call_123"
        assert tool_call.name == "test_tool"
        assert tool_call.arguments == {"key": "value"}
        assert tool_call.raw_arguments == '{"key": "value"}'

    def test_from_partial(self):
        """Test creating from a partial tool call."""
        partial = PartialToolCall(
            id="call_123",
            name="test_tool",
            index=1,
        )
        partial.arguments_buffer = '{"query": "search term"}'
        partial.complete()

        tool_call = DetectedToolCall.from_partial(partial)
        assert tool_call.id == "call_123"
        assert tool_call.name == "test_tool"
        assert tool_call.arguments == {"query": "search term"}
        assert tool_call.index == 1


# ==================== StreamEvent Tests ====================


class TestStreamEvent:
    """Tests for StreamEvent dataclass."""

    def test_create_text_event(self):
        """Test creating a text event."""
        event = StreamEvent.text("Hello, world!")
        assert event.type == StreamEventType.TEXT
        assert event.content == "Hello, world!"
        assert event.tool_call is None

    def test_create_tool_call_start_event(self):
        """Test creating a tool call start event."""
        partial = PartialToolCall(id="call_123", name="test_tool")
        event = StreamEvent.tool_call_start(partial)
        assert event.type == StreamEventType.TOOL_CALL_START
        assert event.partial_call == partial

    def test_create_tool_call_delta_event(self):
        """Test creating a tool call delta event."""
        partial = PartialToolCall(id="call_123", name="test_tool")
        event = StreamEvent.tool_call_delta(partial)
        assert event.type == StreamEventType.TOOL_CALL_DELTA
        assert event.partial_call == partial

    def test_create_tool_call_end_event(self):
        """Test creating a tool call end event."""
        tool_call = DetectedToolCall(
            id="call_123",
            name="test_tool",
            arguments={},
        )
        event = StreamEvent.tool_call_end(tool_call)
        assert event.type == StreamEventType.TOOL_CALL_END
        assert event.tool_call == tool_call

    def test_create_done_event(self):
        """Test creating a done event."""
        event = StreamEvent.done()
        assert event.type == StreamEventType.DONE

    def test_create_error_event(self):
        """Test creating an error event."""
        event = StreamEvent.error_event("Something went wrong")
        assert event.type == StreamEventType.ERROR
        assert event.error == "Something went wrong"


# ==================== StreamingToolCallDetector Tests ====================


class TestStreamingToolCallDetector:
    """Tests for StreamingToolCallDetector."""

    def test_create_detector_default_provider(self):
        """Test creating a detector with default provider."""
        detector = StreamingToolCallDetector()
        assert detector.provider == "auto"

    def test_create_detector_specific_provider(self):
        """Test creating a detector with specific provider."""
        detector = StreamingToolCallDetector(provider="openai")
        assert detector.provider == "openai"

    def test_create_detector_invalid_provider(self):
        """Test creating a detector with invalid provider."""
        with pytest.raises(ValueError, match="Unsupported provider"):
            StreamingToolCallDetector(provider="invalid")

    def test_reset(self):
        """Test resetting the detector."""
        detector = StreamingToolCallDetector(provider="openai")
        detector._partial_calls["test"] = PartialToolCall(id="test", name="test")
        detector._text_buffer = "some text"

        detector.reset()
        assert detector._partial_calls == {}
        assert detector._text_buffer == ""

    def test_get_stats(self):
        """Test getting detector statistics."""
        detector = StreamingToolCallDetector()
        stats = detector.get_stats()
        assert "provider" in stats
        assert "pending_calls" in stats
        assert "completed_calls" in stats
        assert "text_length" in stats

    # OpenAI format tests

    def test_process_openai_text_chunk(self):
        """Test processing OpenAI text chunk."""
        detector = StreamingToolCallDetector(provider="openai")
        chunk = {
            "choices": [
                {
                    "index": 0,
                    "delta": {"content": "Hello, "},
                    "finish_reason": None,
                }
            ]
        }

        events = detector.process_chunk(chunk)
        assert len(events) == 1
        assert events[0].type == StreamEventType.TEXT
        assert events[0].content == "Hello, "

    def test_process_openai_tool_call_start(self):
        """Test processing OpenAI tool call start."""
        detector = StreamingToolCallDetector(provider="openai")
        chunk = {
            "choices": [
                {
                    "index": 0,
                    "delta": {
                        "tool_calls": [
                            {
                                "index": 0,
                                "id": "call_abc123",
                                "function": {"name": "get_weather", "arguments": ""},
                            }
                        ]
                    },
                    "finish_reason": None,
                }
            ]
        }

        events = detector.process_chunk(chunk)
        assert len(events) == 1
        assert events[0].type == StreamEventType.TOOL_CALL_START
        assert events[0].partial_call.id == "call_abc123"
        assert events[0].partial_call.name == "get_weather"

    def test_process_openai_tool_call_delta(self):
        """Test processing OpenAI tool call argument delta."""
        detector = StreamingToolCallDetector(provider="openai")

        # First chunk - tool call start
        start_chunk = {
            "choices": [
                {
                    "index": 0,
                    "delta": {
                        "tool_calls": [
                            {
                                "index": 0,
                                "id": "call_abc123",
                                "function": {"name": "get_weather", "arguments": ""},
                            }
                        ]
                    },
                }
            ]
        }
        detector.process_chunk(start_chunk)

        # Second chunk - arguments delta
        delta_chunk = {
            "choices": [
                {
                    "index": 0,
                    "delta": {
                        "tool_calls": [{"index": 0, "function": {"arguments": '{"city":'}}]
                    },
                }
            ]
        }

        events = detector.process_chunk(delta_chunk)
        assert len(events) == 1
        assert events[0].type == StreamEventType.TOOL_CALL_DELTA

    def test_process_openai_tool_call_complete(self):
        """Test processing complete OpenAI tool call."""
        detector = StreamingToolCallDetector(provider="openai")

        # Start
        detector.process_chunk(
            {
                "choices": [
                    {
                        "index": 0,
                        "delta": {
                            "tool_calls": [
                                {
                                    "index": 0,
                                    "id": "call_abc123",
                                    "function": {"name": "get_weather", "arguments": ""},
                                }
                            ]
                        },
                    }
                ]
            }
        )

        # Arguments
        detector.process_chunk(
            {
                "choices": [
                    {
                        "index": 0,
                        "delta": {
                            "tool_calls": [
                                {"index": 0, "function": {"arguments": '{"city": "NYC"}'}}
                            ]
                        },
                    }
                ]
            }
        )

        # Finish
        events = detector.process_chunk(
            {"choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]}
        )

        # Should have TOOL_CALL_END
        tool_call_end = [e for e in events if e.type == StreamEventType.TOOL_CALL_END]
        assert len(tool_call_end) == 1
        assert tool_call_end[0].tool_call.name == "get_weather"
        assert tool_call_end[0].tool_call.arguments == {"city": "NYC"}

    def test_process_openai_stop(self):
        """Test processing OpenAI stop."""
        detector = StreamingToolCallDetector(provider="openai")
        chunk = {"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}

        events = detector.process_chunk(chunk)
        assert len(events) == 1
        assert events[0].type == StreamEventType.DONE

    # Anthropic format tests

    def test_process_anthropic_text_delta(self):
        """Test processing Anthropic text delta."""
        detector = StreamingToolCallDetector(provider="anthropic")
        chunk = {
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "text_delta", "text": "Hello, world!"},
        }

        events = detector.process_chunk(chunk)
        assert len(events) == 1
        assert events[0].type == StreamEventType.TEXT
        assert events[0].content == "Hello, world!"

    def test_process_anthropic_tool_use_start(self):
        """Test processing Anthropic tool use start."""
        detector = StreamingToolCallDetector(provider="anthropic")
        chunk = {
            "type": "content_block_start",
            "index": 1,
            "content_block": {
                "type": "tool_use",
                "id": "toolu_01A09q90qw90lq917835lgs8",
                "name": "get_weather",
            },
        }

        events = detector.process_chunk(chunk)
        assert len(events) == 1
        assert events[0].type == StreamEventType.TOOL_CALL_START
        assert events[0].partial_call.id == "toolu_01A09q90qw90lq917835lgs8"
        assert events[0].partial_call.name == "get_weather"

    def test_process_anthropic_tool_use_delta(self):
        """Test processing Anthropic tool use delta."""
        detector = StreamingToolCallDetector(provider="anthropic")

        # Start the tool call
        detector.process_chunk(
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {
                    "type": "tool_use",
                    "id": "toolu_123",
                    "name": "get_weather",
                },
            }
        )

        # Delta with arguments
        chunk = {
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "input_json_delta", "partial_json": '{"city": '},
        }

        events = detector.process_chunk(chunk)
        assert len(events) == 1
        assert events[0].type == StreamEventType.TOOL_CALL_DELTA

    def test_process_anthropic_tool_use_complete(self):
        """Test processing complete Anthropic tool use."""
        detector = StreamingToolCallDetector(provider="anthropic")

        # Start
        detector.process_chunk(
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {
                    "type": "tool_use",
                    "id": "toolu_123",
                    "name": "get_weather",
                },
            }
        )

        # Arguments
        detector.process_chunk(
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "input_json_delta", "partial_json": '{"city": "NYC"}'},
            }
        )

        # Stop
        events = detector.process_chunk({"type": "content_block_stop", "index": 0})

        tool_call_end = [e for e in events if e.type == StreamEventType.TOOL_CALL_END]
        assert len(tool_call_end) == 1
        assert tool_call_end[0].tool_call.name == "get_weather"
        assert tool_call_end[0].tool_call.arguments == {"city": "NYC"}

    def test_process_anthropic_message_stop(self):
        """Test processing Anthropic message stop."""
        detector = StreamingToolCallDetector(provider="anthropic")
        chunk = {"type": "message_stop"}

        events = detector.process_chunk(chunk)
        assert len(events) == 1
        assert events[0].type == StreamEventType.DONE

    # Google format tests

    def test_process_google_text(self):
        """Test processing Google text."""
        detector = StreamingToolCallDetector(provider="google")
        chunk = {"candidates": [{"content": {"parts": [{"text": "Hello from Gemini!"}]}}]}

        events = detector.process_chunk(chunk)
        assert len(events) == 1
        assert events[0].type == StreamEventType.TEXT
        assert events[0].content == "Hello from Gemini!"

    def test_process_google_function_call(self):
        """Test processing Google function call."""
        detector = StreamingToolCallDetector(provider="google")
        chunk = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {
                                "functionCall": {
                                    "name": "get_weather",
                                    "args": {"city": "NYC"},
                                }
                            }
                        ]
                    }
                }
            ]
        }

        events = detector.process_chunk(chunk)
        # Google sends complete function calls, so we get both start and end
        assert len(events) == 2
        assert events[0].type == StreamEventType.TOOL_CALL_START
        assert events[1].type == StreamEventType.TOOL_CALL_END
        assert events[1].tool_call.name == "get_weather"
        assert events[1].tool_call.arguments == {"city": "NYC"}

    def test_process_google_stop(self):
        """Test processing Google stop."""
        detector = StreamingToolCallDetector(provider="google")
        chunk = {"candidates": [{"finishReason": "STOP", "content": {"parts": []}}]}

        events = detector.process_chunk(chunk)
        assert any(e.type == StreamEventType.DONE for e in events)

    # Auto-detection tests

    def test_auto_detect_openai(self):
        """Test auto-detecting OpenAI format."""
        detector = StreamingToolCallDetector(provider="auto")
        chunk = {"choices": [{"index": 0, "delta": {"content": "Hello"}}]}

        events = detector.process_chunk(chunk)
        assert detector.provider == "openai"
        assert len(events) == 1

    def test_auto_detect_anthropic(self):
        """Test auto-detecting Anthropic format."""
        detector = StreamingToolCallDetector(provider="auto")
        chunk = {
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "text_delta", "text": "Hello"},
        }

        events = detector.process_chunk(chunk)
        assert detector.provider == "anthropic"
        assert len(events) == 1

    def test_auto_detect_google(self):
        """Test auto-detecting Google format."""
        detector = StreamingToolCallDetector(provider="auto")
        chunk = {"candidates": [{"content": {"parts": [{"text": "Hello"}]}}]}

        events = detector.process_chunk(chunk)
        assert detector.provider == "google"
        assert len(events) == 1

    # State management tests

    def test_get_pending_calls(self):
        """Test getting pending tool calls."""
        detector = StreamingToolCallDetector(provider="openai")

        # Start a tool call but don't complete it
        detector.process_chunk(
            {
                "choices": [
                    {
                        "index": 0,
                        "delta": {
                            "tool_calls": [
                                {
                                    "index": 0,
                                    "id": "call_123",
                                    "function": {"name": "test", "arguments": ""},
                                }
                            ]
                        },
                    }
                ]
            }
        )

        pending = detector.get_pending_calls()
        assert len(pending) == 1
        assert pending[0].id == "call_123"

    def test_get_completed_calls(self):
        """Test getting completed tool calls."""
        detector = StreamingToolCallDetector(provider="openai")

        # Complete a tool call
        detector.process_chunk(
            {
                "choices": [
                    {
                        "index": 0,
                        "delta": {
                            "tool_calls": [
                                {
                                    "index": 0,
                                    "id": "call_123",
                                    "function": {"name": "test", "arguments": "{}"},
                                }
                            ]
                        },
                    }
                ]
            }
        )
        detector.process_chunk(
            {"choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]}
        )

        completed = detector.get_completed_calls()
        assert len(completed) == 1
        assert completed[0].id == "call_123"

    def test_get_all_detected_calls(self):
        """Test getting all detected tool calls."""
        detector = StreamingToolCallDetector(provider="openai")

        # Complete a tool call
        detector.process_chunk(
            {
                "choices": [
                    {
                        "index": 0,
                        "delta": {
                            "tool_calls": [
                                {
                                    "index": 0,
                                    "id": "call_123",
                                    "function": {"name": "test", "arguments": "{}"},
                                }
                            ]
                        },
                    }
                ]
            }
        )
        detector.process_chunk(
            {"choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]}
        )

        detected = detector.get_all_detected_calls()
        assert len(detected) == 1
        assert isinstance(detected[0], DetectedToolCall)

    def test_get_text_buffer(self):
        """Test getting accumulated text."""
        detector = StreamingToolCallDetector(provider="openai")

        detector.process_chunk(
            {"choices": [{"index": 0, "delta": {"content": "Hello, "}}]}
        )
        detector.process_chunk(
            {"choices": [{"index": 0, "delta": {"content": "world!"}}]}
        )

        assert detector.get_text_buffer() == "Hello, world!"

    # Generic/fallback tests

    def test_process_string_chunk(self):
        """Test processing plain string chunk."""
        detector = StreamingToolCallDetector(provider="auto")
        events = detector.process_chunk("Hello, world!")

        assert len(events) == 1
        assert events[0].type == StreamEventType.TEXT
        assert events[0].content == "Hello, world!"


# ==================== StreamTransformer Tests ====================


class TestStreamTransformer:
    """Tests for StreamTransformer."""

    def test_create_transformer(self):
        """Test creating a transformer."""
        transformer = StreamTransformer()
        assert transformer._filters == []
        assert transformer._validators == []

    def test_add_filter(self):
        """Test adding a filter."""
        transformer = StreamTransformer()

        def my_filter(content: str) -> str:
            return content.upper()

        result = transformer.add_filter(my_filter)
        assert result is transformer  # Check chaining
        assert len(transformer._filters) == 1

    def test_add_validator(self):
        """Test adding a validator."""
        transformer = StreamTransformer()

        def my_validator(content: str) -> bool:
            return len(content) < 100

        result = transformer.add_validator(my_validator)
        assert result is transformer
        assert len(transformer._validators) == 1

    def test_clear_filters(self):
        """Test clearing filters."""
        transformer = StreamTransformer()
        transformer.add_filter(lambda x: x)
        transformer.clear_filters()
        assert transformer._filters == []

    def test_clear_validators(self):
        """Test clearing validators."""
        transformer = StreamTransformer()
        transformer.add_validator(lambda x: True)
        transformer.clear_validators()
        assert transformer._validators == []

    @pytest.mark.asyncio
    async def test_transform_applies_filters(self):
        """Test that transform applies filters."""
        transformer = StreamTransformer()
        transformer.add_filter(lambda x: x.upper())

        async def source():
            yield "hello"
            yield "world"

        results = []
        async for chunk in transformer.transform(source()):
            results.append(chunk)

        assert results == ["HELLO", "WORLD"]

    @pytest.mark.asyncio
    async def test_transform_filter_drops_chunk(self):
        """Test that returning None drops a chunk."""
        transformer = StreamTransformer()
        transformer.add_filter(lambda x: None if x == "drop" else x)

        async def source():
            yield "keep"
            yield "drop"
            yield "keep"

        results = []
        async for chunk in transformer.transform(source()):
            results.append(chunk)

        assert results == ["keep", "keep"]

    @pytest.mark.asyncio
    async def test_transform_validator_stops_stream(self):
        """Test that validator can stop the stream."""
        transformer = StreamTransformer()
        transformer.add_validator(lambda x: x != "stop")

        async def source():
            yield "go"
            yield "go"
            yield "stop"
            yield "should not reach"

        results = []
        async for chunk in transformer.transform(source()):
            results.append(chunk)

        assert results == ["go", "go"]

    @pytest.mark.asyncio
    async def test_transform_multiple_filters(self):
        """Test multiple filters applied in order."""
        transformer = StreamTransformer()
        transformer.add_filter(lambda x: x.strip())
        transformer.add_filter(lambda x: x.upper())
        transformer.add_filter(lambda x: f"[{x}]")

        async def source():
            yield "  hello  "
            yield "  world  "

        results = []
        async for chunk in transformer.transform(source()):
            results.append(chunk)

        assert results == ["[HELLO]", "[WORLD]"]

    def test_transform_sync(self):
        """Test synchronous transform."""
        transformer = StreamTransformer()
        transformer.add_filter(lambda x: x.upper())

        def source():
            yield "hello"
            yield "world"

        results = list(transformer.transform_sync(source()))
        assert results == ["HELLO", "WORLD"]

    @pytest.mark.asyncio
    async def test_transform_events_text(self):
        """Test transforming StreamEvents with text."""
        transformer = StreamTransformer()
        transformer.add_filter(lambda x: x.upper())

        async def source():
            yield StreamEvent.text("hello")
            yield StreamEvent.text("world")

        results = []
        async for event in transformer.transform_events(source()):
            results.append(event)

        assert len(results) == 2
        assert results[0].content == "HELLO"
        assert results[1].content == "WORLD"

    @pytest.mark.asyncio
    async def test_transform_events_passes_non_text(self):
        """Test that non-text events pass through."""
        transformer = StreamTransformer()

        tool_call = DetectedToolCall(id="1", name="test", arguments={})

        async def source():
            yield StreamEvent.text("hello")
            yield StreamEvent.tool_call_end(tool_call)
            yield StreamEvent.done()

        results = []
        async for event in transformer.transform_events(source()):
            results.append(event)

        assert len(results) == 3
        assert results[0].type == StreamEventType.TEXT
        assert results[1].type == StreamEventType.TOOL_CALL_END
        assert results[2].type == StreamEventType.DONE

    @pytest.mark.asyncio
    async def test_transform_events_with_authorization(self):
        """Test tool call authorization in event stream."""
        transformer = StreamTransformer()

        def authorizer(tool_call: DetectedToolCall) -> bool:
            return tool_call.name != "blocked_tool"

        transformer.set_tool_call_authorizer(authorizer)

        allowed_call = DetectedToolCall(id="1", name="allowed_tool", arguments={})
        blocked_call = DetectedToolCall(id="2", name="blocked_tool", arguments={})

        async def source():
            yield StreamEvent.tool_call_end(allowed_call)
            yield StreamEvent.tool_call_end(blocked_call)

        results = []
        async for event in transformer.transform_events(source()):
            results.append(event)

        assert len(results) == 2
        assert results[0].type == StreamEventType.TOOL_CALL_END
        assert results[0].tool_call.name == "allowed_tool"
        assert results[1].type == StreamEventType.ERROR
        assert "not authorized" in results[1].error

    def test_add_event_callback(self):
        """Test adding event callbacks."""
        transformer = StreamTransformer()
        callback = MagicMock()

        result = transformer.add_event_callback(callback)
        assert result is transformer
        assert len(transformer._event_callbacks) == 1

    @pytest.mark.asyncio
    async def test_event_callbacks_called(self):
        """Test that event callbacks are invoked."""
        transformer = StreamTransformer()
        callback = MagicMock()
        transformer.add_event_callback(callback)

        async def source():
            yield StreamEvent.text("hello")
            yield StreamEvent.done()

        results = []
        async for event in transformer.transform_events(source()):
            results.append(event)

        assert callback.call_count == 2


# ==================== FilteredStream Tests ====================


class TestFilteredStream:
    """Tests for FilteredStream."""

    @pytest.mark.asyncio
    async def test_filtered_stream_basic(self):
        """Test basic FilteredStream functionality."""

        async def source():
            yield "hello"
            yield "world"

        stream = FilteredStream(
            source=source(),
            filters=[lambda x: x.upper()],
        )

        results = []
        async for chunk in stream:
            results.append(chunk)

        assert results == ["HELLO", "WORLD"]

    @pytest.mark.asyncio
    async def test_filtered_stream_stop(self):
        """Test stopping a FilteredStream."""

        async def source():
            yield "hello"
            yield "world"

        stream = FilteredStream(source=source())
        stream.stop()

        results = []
        async for chunk in stream:
            results.append(chunk)

        assert results == []


# ==================== BufferedStreamTransformer Tests ====================


class TestBufferedStreamTransformer:
    """Tests for BufferedStreamTransformer."""

    def test_create_buffered_transformer(self):
        """Test creating a buffered transformer."""
        transformer = BufferedStreamTransformer(buffer_size=100)
        assert transformer.buffer_size == 100

    def test_add_pattern_filter(self):
        """Test adding pattern filter."""
        transformer = BufferedStreamTransformer()
        result = transformer.add_pattern_filter(r"secret_\w+", "[REDACTED]")
        assert result is transformer
        assert len(transformer._patterns) == 1

    def test_add_invalid_pattern(self):
        """Test adding invalid regex pattern."""
        transformer = BufferedStreamTransformer()
        with pytest.raises(Exception):  # re.error
            transformer.add_pattern_filter(r"[invalid", "")

    @pytest.mark.asyncio
    async def test_buffered_transform_pattern(self):
        """Test buffered transform with pattern."""
        transformer = BufferedStreamTransformer(buffer_size=50)
        transformer.add_pattern_filter(r"API_KEY_\w+", "[REDACTED]")

        async def source():
            yield "My key is "
            yield "API_KEY_abc123"
            yield " and more text"

        results = []
        async for chunk in transformer.transform(source()):
            results.append(chunk)

        full_output = "".join(results)
        assert "API_KEY_abc123" not in full_output
        assert "[REDACTED]" in full_output

    def test_reset(self):
        """Test resetting the buffer."""
        transformer = BufferedStreamTransformer()
        transformer._buffer = "some content"
        transformer.reset()
        assert transformer._buffer == ""


# ==================== StreamAggregator Tests ====================


class TestStreamAggregator:
    """Tests for StreamAggregator."""

    def test_create_aggregator(self):
        """Test creating an aggregator."""
        aggregator = StreamAggregator(min_chars=10, max_chars=100, timeout=0.5)
        assert aggregator.min_chars == 10
        assert aggregator.max_chars == 100
        assert aggregator.timeout == 0.5

    @pytest.mark.asyncio
    async def test_aggregate_by_max_chars(self):
        """Test aggregation by max chars."""
        aggregator = StreamAggregator(max_chars=10, timeout=10.0)

        async def source():
            for i in range(5):
                yield "12345"  # 5 chars each

        results = []
        async for batch in aggregator.aggregate(source()):
            results.append(batch)

        # Should have batched when reaching 10 chars
        assert len(results) >= 2

    @pytest.mark.asyncio
    async def test_aggregate_by_delimiter(self):
        """Test aggregation by delimiter."""
        aggregator = StreamAggregator(delimiter="\n", timeout=10.0)

        async def source():
            yield "line 1"
            yield "\n"
            yield "line 2"
            yield "\n"

        results = []
        async for batch in aggregator.aggregate(source()):
            results.append(batch)

        # Should batch on newline
        assert len(results) >= 2

    def test_reset(self):
        """Test resetting the aggregator."""
        aggregator = StreamAggregator()
        aggregator._buffer = "some content"
        aggregator.reset()
        assert aggregator._buffer == ""


# ==================== Helper Function Tests ====================


class TestHelperFunctions:
    """Tests for helper functions."""

    @pytest.mark.asyncio
    async def test_create_guarded_stream(self):
        """Test create_guarded_stream function."""
        # Create a mock output guard
        mock_guard = MagicMock()
        mock_result = MagicMock()
        mock_result.action = "allow"  # GuardAction.ALLOW
        mock_guard.check.return_value = mock_result

        async def source():
            yield "hello"
            yield "world"

        # Patch the import
        results = []
        async for chunk in create_guarded_stream(source(), mock_guard):
            results.append(chunk)

        assert results == ["hello", "world"]
        assert mock_guard.check.call_count == 2

    @pytest.mark.asyncio
    async def test_create_authorization_stream(self):
        """Test create_authorization_stream function."""

        def authorizer(tool_call: DetectedToolCall) -> bool:
            return tool_call.name == "allowed"

        # Create raw chunks that will be detected
        async def source():
            yield {
                "choices": [
                    {
                        "index": 0,
                        "delta": {
                            "tool_calls": [
                                {
                                    "index": 0,
                                    "id": "call_1",
                                    "function": {"name": "allowed", "arguments": "{}"},
                                }
                            ]
                        },
                    }
                ]
            }
            yield {"choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]}

        detector = StreamingToolCallDetector(provider="openai")
        results = []
        async for event in create_authorization_stream(source(), authorizer, detector):
            results.append(event)

        # Should have tool call events
        tool_call_ends = [e for e in results if e.type == StreamEventType.TOOL_CALL_END]
        assert len(tool_call_ends) == 1


# ==================== Integration Tests ====================


class TestStreamingIntegration:
    """Integration tests for streaming module."""

    @pytest.mark.asyncio
    async def test_full_openai_stream_processing(self):
        """Test processing a full OpenAI-style stream."""
        detector = StreamingToolCallDetector()

        chunks = [
            {"choices": [{"index": 0, "delta": {"content": "I'll help "}}]},
            {"choices": [{"index": 0, "delta": {"content": "you with that."}}]},
            {
                "choices": [
                    {
                        "index": 0,
                        "delta": {
                            "tool_calls": [
                                {
                                    "index": 0,
                                    "id": "call_123",
                                    "function": {"name": "search", "arguments": ""},
                                }
                            ]
                        },
                    }
                ]
            },
            {
                "choices": [
                    {
                        "index": 0,
                        "delta": {
                            "tool_calls": [
                                {"index": 0, "function": {"arguments": '{"query":'}}
                            ]
                        },
                    }
                ]
            },
            {
                "choices": [
                    {
                        "index": 0,
                        "delta": {
                            "tool_calls": [
                                {"index": 0, "function": {"arguments": ' "test"}'}}
                            ]
                        },
                    }
                ]
            },
            {"choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]},
        ]

        all_events = []
        for chunk in chunks:
            events = detector.process_chunk(chunk)
            all_events.extend(events)

        # Check we got expected events
        text_events = [e for e in all_events if e.type == StreamEventType.TEXT]
        tool_start = [e for e in all_events if e.type == StreamEventType.TOOL_CALL_START]
        tool_end = [e for e in all_events if e.type == StreamEventType.TOOL_CALL_END]

        assert len(text_events) == 2
        assert len(tool_start) == 1
        assert len(tool_end) == 1

        assert tool_end[0].tool_call.name == "search"
        assert tool_end[0].tool_call.arguments == {"query": "test"}

    @pytest.mark.asyncio
    async def test_full_anthropic_stream_processing(self):
        """Test processing a full Anthropic-style stream."""
        detector = StreamingToolCallDetector()

        chunks = [
            {"type": "message_start"},
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text"},
            },
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": "Let me search for that."},
            },
            {"type": "content_block_stop", "index": 0},
            {
                "type": "content_block_start",
                "index": 1,
                "content_block": {
                    "type": "tool_use",
                    "id": "toolu_123",
                    "name": "web_search",
                },
            },
            {
                "type": "content_block_delta",
                "index": 1,
                "delta": {"type": "input_json_delta", "partial_json": '{"query": "test"}'},
            },
            {"type": "content_block_stop", "index": 1},
            {"type": "message_stop"},
        ]

        all_events = []
        for chunk in chunks:
            events = detector.process_chunk(chunk)
            all_events.extend(events)

        text_events = [e for e in all_events if e.type == StreamEventType.TEXT]
        tool_end = [e for e in all_events if e.type == StreamEventType.TOOL_CALL_END]

        assert len(text_events) == 1
        assert text_events[0].content == "Let me search for that."

        assert len(tool_end) == 1
        assert tool_end[0].tool_call.name == "web_search"
        assert tool_end[0].tool_call.arguments == {"query": "test"}

    @pytest.mark.asyncio
    async def test_transformer_with_detector(self):
        """Test transformer with tool call detector integration."""
        transformer = StreamTransformer()
        transformer.add_filter(lambda x: x.replace("sensitive", "[REDACTED]"))

        detector = StreamingToolCallDetector(provider="openai")

        async def source():
            yield {"choices": [{"index": 0, "delta": {"content": "This is sensitive data"}}]}
            yield {"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}

        results = []
        async for event in transformer.transform_chunks(source(), detector):
            results.append(event)

        text_events = [e for e in results if e.type == StreamEventType.TEXT]
        assert len(text_events) == 1
        assert text_events[0].content == "This is [REDACTED] data"


# ==================== Edge Case Tests ====================


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_detector_with_empty_choices(self):
        """Test detector with empty choices."""
        detector = StreamingToolCallDetector(provider="openai")
        events = detector.process_chunk({"choices": []})
        assert events == []

    def test_detector_with_missing_delta(self):
        """Test detector with missing delta."""
        detector = StreamingToolCallDetector(provider="openai")
        events = detector.process_chunk({"choices": [{"index": 0}]})
        assert events == []

    def test_detector_with_none_content(self):
        """Test detector with None content."""
        detector = StreamingToolCallDetector(provider="openai")
        events = detector.process_chunk(
            {"choices": [{"index": 0, "delta": {"content": None}}]}
        )
        assert events == []

    def test_partial_tool_call_with_invalid_json_on_complete(self):
        """Test partial tool call with invalid JSON when completing."""
        detector = StreamingToolCallDetector(provider="anthropic")

        # Start tool call
        detector.process_chunk(
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "tool_use", "id": "test", "name": "test"},
            }
        )

        # Add invalid JSON
        detector.process_chunk(
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "input_json_delta", "partial_json": "{invalid json"},
            }
        )

        # Complete - should emit error
        events = detector.process_chunk({"type": "content_block_stop", "index": 0})
        error_events = [e for e in events if e.type == StreamEventType.ERROR]
        assert len(error_events) == 1

    @pytest.mark.asyncio
    async def test_transformer_with_exception_in_filter(self):
        """Test transformer handles exceptions in filters gracefully."""
        transformer = StreamTransformer()

        def bad_filter(content: str) -> str:
            raise ValueError("Filter error")

        transformer.add_filter(bad_filter)

        async def source():
            yield "test"

        with pytest.raises(ValueError):
            async for _ in transformer.transform(source()):
                pass

    def test_multiple_tool_calls_same_stream(self):
        """Test handling multiple tool calls in same stream."""
        detector = StreamingToolCallDetector(provider="openai")

        # First tool call
        detector.process_chunk(
            {
                "choices": [
                    {
                        "index": 0,
                        "delta": {
                            "tool_calls": [
                                {
                                    "index": 0,
                                    "id": "call_1",
                                    "function": {"name": "tool1", "arguments": "{}"},
                                }
                            ]
                        },
                    }
                ]
            }
        )

        # Second tool call
        detector.process_chunk(
            {
                "choices": [
                    {
                        "index": 0,
                        "delta": {
                            "tool_calls": [
                                {
                                    "index": 1,
                                    "id": "call_2",
                                    "function": {"name": "tool2", "arguments": "{}"},
                                }
                            ]
                        },
                    }
                ]
            }
        )

        # Complete
        detector.process_chunk(
            {"choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]}
        )

        completed = detector.get_completed_calls()
        assert len(completed) == 2
        names = {c.name for c in completed}
        assert names == {"tool1", "tool2"}
