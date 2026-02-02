"""
Streaming response handling for AI agents.

Provides utilities for handling streaming responses from LLMs,
including tool call detection in streams and incremental authorization.
Essential for real-time applications and WebSocket-based chatbots.

Features:
    - Tool call detection in streaming responses
    - Multi-provider support (OpenAI, Anthropic, Google)
    - Incremental authorization during streaming
    - Stream transformation and filtering
    - Output guard integration for content filtering

Example:
    >>> from proxilion.streaming import (
    ...     StreamingToolCallDetector,
    ...     StreamTransformer,
    ...     StreamEvent,
    ...     create_guarded_stream,
    ... )
    >>>
    >>> # Detect tool calls in streaming response
    >>> detector = StreamingToolCallDetector()
    >>> async for chunk in llm_stream:
    ...     events = detector.process_chunk(chunk)
    ...     for event in events:
    ...         if event.type == StreamEvent.TOOL_CALL_END:
    ...             # Full tool call available, authorize it
    ...             tool_call = event.tool_call
    ...             auth.authorize(user, "execute", tool_call.name)
    >>>
    >>> # Filter streaming output
    >>> transformer = StreamTransformer()
    >>> transformer.add_filter(redact_sensitive_data)
    >>> async for chunk in transformer.transform(llm_stream):
    ...     ws.send(chunk)  # Filtered content
"""

from proxilion.streaming.detector import (
    DetectedToolCall,
    PartialToolCall,
    StreamEvent,
    StreamEventType,
    StreamingToolCallDetector,
)
from proxilion.streaming.transformer import (
    FilteredStream,
    StreamFilter,
    StreamTransformer,
    StreamValidator,
    create_authorization_stream,
    create_guarded_stream,
)

__all__ = [
    # Detector classes
    "StreamEvent",
    "StreamEventType",
    "PartialToolCall",
    "StreamingToolCallDetector",
    "DetectedToolCall",
    # Transformer classes
    "StreamTransformer",
    "FilteredStream",
    "StreamFilter",
    "StreamValidator",
    "create_guarded_stream",
    "create_authorization_stream",
]
