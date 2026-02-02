"""Tests for message history management."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

import pytest

from proxilion.context.message_history import (
    Message,
    MessageHistory,
    MessageRole,
    estimate_tokens,
)


class TestEstimateTokens:
    """Tests for token estimation function."""

    def test_empty_string_returns_zero(self):
        """Empty string should return 0 tokens."""
        assert estimate_tokens("") == 0

    def test_single_word(self):
        """Single word should estimate reasonable tokens."""
        result = estimate_tokens("Hello")
        assert 1 <= result <= 3

    def test_short_sentence(self):
        """Short sentence estimation."""
        result = estimate_tokens("Hello, world!")
        assert 2 <= result <= 6

    def test_longer_text(self):
        """Longer text should estimate more tokens."""
        short = estimate_tokens("Hello")
        long_text = estimate_tokens("This is a much longer piece of text with many more words.")
        assert long_text > short

    def test_code_snippet(self):
        """Code should also be tokenized."""
        code = "def hello(): return 'world'"
        result = estimate_tokens(code)
        assert result > 0

    def test_special_characters(self):
        """Special characters should be handled."""
        text = "Hello! @#$%^&*() World!"
        result = estimate_tokens(text)
        assert result > 0

    def test_unicode_text(self):
        """Unicode text should work."""
        text = "こんにちは世界"
        result = estimate_tokens(text)
        assert result > 0


class TestMessage:
    """Tests for Message dataclass."""

    def test_create_basic_message(self):
        """Create a basic message."""
        msg = Message(role=MessageRole.USER, content="Hello!")
        assert msg.role == MessageRole.USER
        assert msg.content == "Hello!"
        assert msg.token_count is not None
        assert msg.token_count > 0
        assert msg.message_id is not None

    def test_message_with_metadata(self):
        """Create message with metadata."""
        metadata = {"tool_name": "search", "arg": "query"}
        msg = Message(
            role=MessageRole.TOOL_CALL,
            content="Searching...",
            metadata=metadata,
        )
        assert msg.metadata == metadata

    def test_message_timestamp(self):
        """Message should have timestamp."""
        before = datetime.now(timezone.utc)
        msg = Message(role=MessageRole.USER, content="Test")
        after = datetime.now(timezone.utc)
        assert before <= msg.timestamp <= after

    def test_custom_token_count(self):
        """Can provide custom token count."""
        msg = Message(role=MessageRole.USER, content="Test", token_count=100)
        assert msg.token_count == 100

    def test_to_dict(self):
        """Message can be serialized to dict."""
        msg = Message(role=MessageRole.USER, content="Hello!")
        data = msg.to_dict()
        assert data["role"] == "user"
        assert data["content"] == "Hello!"
        assert "timestamp" in data
        assert "message_id" in data

    def test_from_dict(self):
        """Message can be deserialized from dict."""
        original = Message(role=MessageRole.ASSISTANT, content="Hi there!")
        data = original.to_dict()
        restored = Message.from_dict(data)
        assert restored.role == original.role
        assert restored.content == original.content
        assert restored.message_id == original.message_id

    def test_all_message_roles(self):
        """Test all message roles work."""
        roles = [
            MessageRole.USER,
            MessageRole.ASSISTANT,
            MessageRole.SYSTEM,
            MessageRole.TOOL_CALL,
            MessageRole.TOOL_RESULT,
        ]
        for role in roles:
            msg = Message(role=role, content="test")
            assert msg.role == role


class TestMessageHistory:
    """Tests for MessageHistory class."""

    def test_create_empty_history(self):
        """Create empty message history."""
        history = MessageHistory()
        assert len(history) == 0

    def test_append_message(self):
        """Append message to history."""
        history = MessageHistory()
        msg = Message(role=MessageRole.USER, content="Hello!")
        history.append(msg)
        assert len(history) == 1

    def test_get_recent(self):
        """Get recent messages."""
        history = MessageHistory()
        for i in range(5):
            history.append(Message(role=MessageRole.USER, content=f"Message {i}"))

        recent = history.get_recent(3)
        assert len(recent) == 3
        assert recent[0].content == "Message 2"
        assert recent[2].content == "Message 4"

    def test_get_by_role(self):
        """Filter messages by role."""
        history = MessageHistory()
        history.append(Message(role=MessageRole.USER, content="User 1"))
        history.append(Message(role=MessageRole.ASSISTANT, content="Assistant 1"))
        history.append(Message(role=MessageRole.USER, content="User 2"))

        user_msgs = history.get_by_role(MessageRole.USER)
        assert len(user_msgs) == 2
        assert all(m.role == MessageRole.USER for m in user_msgs)

    def test_max_messages_limit(self):
        """Enforce max messages limit."""
        history = MessageHistory(max_messages=3)
        for i in range(5):
            history.append(Message(role=MessageRole.USER, content=f"Message {i}"))

        assert len(history) == 3
        # Should have kept the most recent
        messages = history.get_messages()
        assert messages[0].content == "Message 2"
        assert messages[2].content == "Message 4"

    def test_max_tokens_limit(self):
        """Enforce max tokens limit."""
        history = MessageHistory(max_tokens=50)

        # Add messages until limit is exceeded
        for i in range(10):
            history.append(Message(
                role=MessageRole.USER,
                content=f"This is message number {i} with some content",
            ))

        # Should have enforced token limit
        total = history.get_total_tokens()
        assert total <= 50 or len(history) == 1  # At least one message kept

    def test_preserve_system_messages(self):
        """System messages should be preserved when truncating."""
        history = MessageHistory(max_messages=3)
        history.append(Message(role=MessageRole.SYSTEM, content="System prompt"))
        for i in range(5):
            history.append(Message(role=MessageRole.USER, content=f"User {i}"))

        messages = history.get_messages()
        # System message should still be there
        system_msgs = [m for m in messages if m.role == MessageRole.SYSTEM]
        assert len(system_msgs) == 1

    def test_truncate_to_token_limit(self):
        """Truncate history to token limit."""
        history = MessageHistory()
        for i in range(10):
            # Use fixed token count to make test deterministic
            history.append(Message(role=MessageRole.USER, content=f"Message {i}", token_count=10))

        original_count = len(history)
        original_tokens = history.get_total_tokens()
        removed = history.truncate_to_token_limit(25)

        # Should have removed some messages
        assert history.get_total_tokens() < original_tokens
        assert len(removed) > 0
        assert history.get_total_tokens() <= 25 or len(history) == 1

    def test_total_tokens(self):
        """Calculate total tokens."""
        history = MessageHistory()
        history.append(Message(role=MessageRole.USER, content="Hello", token_count=10))
        history.append(Message(role=MessageRole.ASSISTANT, content="Hi", token_count=5))

        assert history.get_total_tokens() == 15

    def test_clear(self):
        """Clear all messages."""
        history = MessageHistory()
        history.append(Message(role=MessageRole.USER, content="Test"))
        history.append(Message(role=MessageRole.ASSISTANT, content="Response"))

        cleared = history.clear()
        assert len(history) == 0
        assert len(cleared) == 2

    def test_clear_except_system(self):
        """Clear non-system messages."""
        history = MessageHistory()
        history.append(Message(role=MessageRole.SYSTEM, content="System"))
        history.append(Message(role=MessageRole.USER, content="User"))
        history.append(Message(role=MessageRole.ASSISTANT, content="Assistant"))

        cleared = history.clear_except_system()
        assert len(history) == 1
        assert history[0].role == MessageRole.SYSTEM
        assert len(cleared) == 2

    def test_find_by_id(self):
        """Find message by ID."""
        history = MessageHistory()
        msg = Message(role=MessageRole.USER, content="Find me")
        history.append(msg)

        found = history.find_by_id(msg.message_id)
        assert found is not None
        assert found.content == "Find me"

    def test_find_by_id_not_found(self):
        """Return None for non-existent ID."""
        history = MessageHistory()
        history.append(Message(role=MessageRole.USER, content="Test"))

        found = history.find_by_id("non-existent-id")
        assert found is None

    def test_remove_by_id(self):
        """Remove message by ID."""
        history = MessageHistory()
        msg = Message(role=MessageRole.USER, content="Remove me")
        history.append(msg)
        history.append(Message(role=MessageRole.ASSISTANT, content="Keep me"))

        removed = history.remove_by_id(msg.message_id)
        assert removed is not None
        assert removed.content == "Remove me"
        assert len(history) == 1

    def test_iteration(self):
        """Iterate over messages."""
        history = MessageHistory()
        history.append(Message(role=MessageRole.USER, content="1"))
        history.append(Message(role=MessageRole.USER, content="2"))

        contents = [m.content for m in history]
        assert contents == ["1", "2"]

    def test_indexing(self):
        """Access messages by index."""
        history = MessageHistory()
        history.append(Message(role=MessageRole.USER, content="First"))
        history.append(Message(role=MessageRole.USER, content="Second"))

        assert history[0].content == "First"
        assert history[1].content == "Second"
        assert history[-1].content == "Second"

    def test_slicing(self):
        """Slice message history."""
        history = MessageHistory()
        for i in range(5):
            history.append(Message(role=MessageRole.USER, content=str(i)))

        sliced = history[1:3]
        assert len(sliced) == 2
        assert sliced[0].content == "1"
        assert sliced[1].content == "2"


class TestMessageHistoryLLMFormat:
    """Tests for LLM format conversion."""

    def test_openai_format_basic(self):
        """Convert to OpenAI format."""
        history = MessageHistory()
        history.append(Message(role=MessageRole.SYSTEM, content="You are helpful."))
        history.append(Message(role=MessageRole.USER, content="Hello"))
        history.append(Message(role=MessageRole.ASSISTANT, content="Hi!"))

        result = history.to_llm_format("openai")
        assert len(result) == 3
        assert result[0]["role"] == "system"
        assert result[1]["role"] == "user"
        assert result[2]["role"] == "assistant"

    def test_openai_format_tool_call(self):
        """OpenAI format with tool calls."""
        history = MessageHistory()
        history.append(Message(
            role=MessageRole.TOOL_CALL,
            content="",
            metadata={"tool_calls": [{"id": "call_1", "function": {"name": "search"}}]},
        ))

        result = history.to_llm_format("openai")
        assert result[0]["role"] == "assistant"
        assert result[0]["tool_calls"] is not None

    def test_openai_format_tool_result(self):
        """OpenAI format with tool results."""
        history = MessageHistory()
        history.append(Message(
            role=MessageRole.TOOL_RESULT,
            content="Search result",
            metadata={"tool_call_id": "call_1"},
        ))

        result = history.to_llm_format("openai")
        assert result[0]["role"] == "tool"
        assert result[0]["tool_call_id"] == "call_1"

    def test_anthropic_format_basic(self):
        """Convert to Anthropic format."""
        history = MessageHistory()
        history.append(Message(role=MessageRole.USER, content="Hello"))
        history.append(Message(role=MessageRole.ASSISTANT, content="Hi!"))

        result = history.to_llm_format("anthropic")
        assert len(result) == 2
        assert result[0]["role"] == "user"
        assert result[1]["role"] == "assistant"

    def test_google_format_basic(self):
        """Convert to Google/Gemini format."""
        history = MessageHistory()
        history.append(Message(role=MessageRole.USER, content="Hello"))
        history.append(Message(role=MessageRole.ASSISTANT, content="Hi!"))

        result = history.to_llm_format("google")
        assert len(result) == 2
        assert result[0]["role"] == "user"
        assert result[1]["role"] == "model"
        assert "parts" in result[0]

    def test_unknown_provider_uses_openai(self):
        """Unknown provider defaults to OpenAI format."""
        history = MessageHistory()
        history.append(Message(role=MessageRole.USER, content="Test"))

        result = history.to_llm_format("unknown_provider")
        assert result[0]["role"] == "user"


class TestMessageHistorySerialization:
    """Tests for serialization/deserialization."""

    def test_to_dict(self):
        """Serialize history to dict."""
        history = MessageHistory(max_messages=100, max_tokens=5000)
        history.append(Message(role=MessageRole.USER, content="Hello"))

        data = history.to_dict()
        assert data["max_messages"] == 100
        assert data["max_tokens"] == 5000
        assert len(data["messages"]) == 1

    def test_from_dict(self):
        """Deserialize history from dict."""
        original = MessageHistory(max_messages=50, max_tokens=2000)
        original.append(Message(role=MessageRole.USER, content="Test 1"))
        original.append(Message(role=MessageRole.ASSISTANT, content="Test 2"))

        data = original.to_dict()
        restored = MessageHistory.from_dict(data)

        assert restored.max_messages == 50
        assert restored.max_tokens == 2000
        assert len(restored) == 2

    def test_round_trip(self):
        """Full round-trip serialization."""
        history = MessageHistory()
        history.append(Message(
            role=MessageRole.USER,
            content="Hello",
            metadata={"key": "value"},
        ))
        history.append(Message(
            role=MessageRole.ASSISTANT,
            content="Hi there!",
        ))

        data = history.to_dict()
        restored = MessageHistory.from_dict(data)

        assert len(restored) == 2
        assert restored[0].content == "Hello"
        assert restored[0].metadata == {"key": "value"}
        assert restored[1].content == "Hi there!"


class TestMessageHistoryThreadSafety:
    """Tests for thread safety."""

    def test_concurrent_appends(self):
        """Concurrent appends should be thread-safe."""
        import threading

        history = MessageHistory()
        append_count = 100
        thread_count = 5

        def append_messages():
            for i in range(append_count):
                history.append(Message(role=MessageRole.USER, content=f"Msg {i}"))

        threads = [threading.Thread(target=append_messages) for _ in range(thread_count)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(history) == append_count * thread_count

    def test_concurrent_read_write(self):
        """Concurrent reads and writes should be thread-safe."""
        import threading

        history = MessageHistory()
        errors = []

        def writer():
            for i in range(50):
                history.append(Message(role=MessageRole.USER, content=f"Msg {i}"))
                time.sleep(0.001)

        def reader():
            for _ in range(50):
                try:
                    _ = len(history)
                    _ = history.get_total_tokens()
                    _ = list(history)
                except Exception as e:
                    errors.append(e)
                time.sleep(0.001)

        writer_thread = threading.Thread(target=writer)
        reader_thread = threading.Thread(target=reader)

        writer_thread.start()
        reader_thread.start()
        writer_thread.join()
        reader_thread.join()

        assert len(errors) == 0
