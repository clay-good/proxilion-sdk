"""Tests for context window management."""

from __future__ import annotations

from proxilion.context.context_window import (
    ContextStrategy,
    ContextWindow,
    KeepFirstLastStrategy,
    KeepSystemRecentStrategy,
    SlidingWindowStrategy,
    SummarizeOldStrategy,
    create_claude_context_window,
    create_gemini_context_window,
    create_gpt4_32k_context_window,
    create_gpt4_context_window,
)
from proxilion.context.message_history import Message, MessageRole


def create_message(
    content: str,
    role: MessageRole = MessageRole.USER,
    tokens: int | None = None,
) -> Message:
    """Helper to create test messages."""
    return Message(
        role=role,
        content=content,
        token_count=tokens or len(content.split()) * 2,
    )


class TestSlidingWindowStrategy:
    """Tests for sliding window strategy."""

    def test_empty_messages(self):
        """Empty messages returns empty list."""
        strategy = SlidingWindowStrategy()
        result = strategy.fit([], 100)
        assert result == []

    def test_all_messages_fit(self):
        """All messages fit within limit."""
        strategy = SlidingWindowStrategy()
        messages = [
            create_message("Hello", tokens=10),
            create_message("World", tokens=10),
        ]
        result = strategy.fit(messages, 100)
        assert len(result) == 2

    def test_truncates_from_start(self):
        """Removes messages from start when over limit."""
        strategy = SlidingWindowStrategy()
        messages = [
            create_message("First", tokens=30),
            create_message("Second", tokens=30),
            create_message("Third", tokens=30),
        ]
        result = strategy.fit(messages, 50)

        # Should keep only most recent that fits
        assert len(result) == 1
        assert result[0].content == "Third"

    def test_keeps_most_recent(self):
        """Keeps the most recent messages."""
        strategy = SlidingWindowStrategy()
        messages = [
            create_message("Msg 1", tokens=10),
            create_message("Msg 2", tokens=10),
            create_message("Msg 3", tokens=10),
            create_message("Msg 4", tokens=10),
        ]
        result = strategy.fit(messages, 25)

        # Should keep last 2 messages (20 tokens)
        assert len(result) == 2
        assert result[0].content == "Msg 3"
        assert result[1].content == "Msg 4"

    def test_single_large_message(self):
        """Single message larger than limit."""
        strategy = SlidingWindowStrategy()
        messages = [create_message("Large message", tokens=100)]
        result = strategy.fit(messages, 50)

        # Cannot fit, returns empty
        assert len(result) == 0


class TestKeepSystemRecentStrategy:
    """Tests for keep system + recent strategy."""

    def test_empty_messages(self):
        """Empty messages returns empty list."""
        strategy = KeepSystemRecentStrategy()
        result = strategy.fit([], 100)
        assert result == []

    def test_all_messages_fit(self):
        """All messages fit within limit."""
        strategy = KeepSystemRecentStrategy()
        messages = [
            create_message("System prompt", role=MessageRole.SYSTEM, tokens=10),
            create_message("User input", role=MessageRole.USER, tokens=10),
        ]
        result = strategy.fit(messages, 100)
        assert len(result) == 2

    def test_preserves_system_messages(self):
        """System messages are preserved."""
        strategy = KeepSystemRecentStrategy()
        messages = [
            create_message("System 1", role=MessageRole.SYSTEM, tokens=10),
            create_message("User 1", role=MessageRole.USER, tokens=10),
            create_message("User 2", role=MessageRole.USER, tokens=10),
            create_message("User 3", role=MessageRole.USER, tokens=10),
        ]
        result = strategy.fit(messages, 25)

        # Should keep system + most recent user messages
        system_msgs = [m for m in result if m.role == MessageRole.SYSTEM]
        assert len(system_msgs) == 1
        assert system_msgs[0].content == "System 1"

    def test_multiple_system_messages(self):
        """Multiple system messages are all preserved."""
        strategy = KeepSystemRecentStrategy()
        messages = [
            create_message("System 1", role=MessageRole.SYSTEM, tokens=10),
            create_message("System 2", role=MessageRole.SYSTEM, tokens=10),
            create_message("User 1", role=MessageRole.USER, tokens=10),
            create_message("User 2", role=MessageRole.USER, tokens=10),
        ]
        result = strategy.fit(messages, 35)

        system_msgs = [m for m in result if m.role == MessageRole.SYSTEM]
        assert len(system_msgs) == 2

    def test_system_messages_exceed_limit(self):
        """When system messages exceed limit, truncate them."""
        strategy = KeepSystemRecentStrategy()
        messages = [
            create_message("System 1", role=MessageRole.SYSTEM, tokens=40),
            create_message("System 2", role=MessageRole.SYSTEM, tokens=40),
        ]
        result = strategy.fit(messages, 50)

        # Should keep only most recent system messages that fit
        assert len(result) == 1
        assert result[0].content == "System 2"

    def test_no_system_messages(self):
        """Works without system messages."""
        strategy = KeepSystemRecentStrategy()
        messages = [
            create_message("User 1", role=MessageRole.USER, tokens=10),
            create_message("User 2", role=MessageRole.USER, tokens=10),
            create_message("User 3", role=MessageRole.USER, tokens=10),
        ]
        result = strategy.fit(messages, 25)

        # Should keep recent messages
        assert len(result) == 2
        assert result[0].content == "User 2"
        assert result[1].content == "User 3"


class TestKeepFirstLastStrategy:
    """Tests for keep first and last strategy."""

    def test_empty_messages(self):
        """Empty messages returns empty list."""
        strategy = KeepFirstLastStrategy()
        result = strategy.fit([], 100)
        assert result == []

    def test_all_messages_fit(self):
        """All messages fit within limit."""
        strategy = KeepFirstLastStrategy()
        messages = [create_message(f"Msg {i}", tokens=5) for i in range(5)]
        result = strategy.fit(messages, 100)
        assert len(result) == 5

    def test_keeps_first_and_last(self):
        """Keeps first and last messages."""
        strategy = KeepFirstLastStrategy(keep_first=1, keep_last=2)
        messages = [
            create_message("First", tokens=10),
            create_message("Middle 1", tokens=10),
            create_message("Middle 2", tokens=10),
            create_message("Second Last", tokens=10),
            create_message("Last", tokens=10),
        ]
        result = strategy.fit(messages, 100)

        assert len(result) == 3
        assert result[0].content == "First"
        assert result[1].content == "Second Last"
        assert result[2].content == "Last"

    def test_fewer_messages_than_keep_regions(self):
        """Fewer messages than keep regions."""
        strategy = KeepFirstLastStrategy(keep_first=2, keep_last=3)
        messages = [create_message(f"Msg {i}", tokens=10) for i in range(4)]
        result = strategy.fit(messages, 100)

        # Should return all messages
        assert len(result) == 4

    def test_exceeds_token_limit(self):
        """First + last exceed token limit."""
        strategy = KeepFirstLastStrategy(keep_first=2, keep_last=2)
        messages = [
            create_message("First 1", tokens=20),
            create_message("First 2", tokens=20),
            create_message("Middle", tokens=10),
            create_message("Last 1", tokens=20),
            create_message("Last 2", tokens=20),
        ]
        result = strategy.fit(messages, 50)

        # Prioritizes last, keeps what fits of first
        assert result[-1].content == "Last 2"


class TestSummarizeOldStrategy:
    """Tests for summarize old strategy."""

    def test_empty_messages(self):
        """Empty messages returns empty list."""
        def summarize(msgs):
            return "Summary"

        strategy = SummarizeOldStrategy(summarize, keep_recent=5)
        result = strategy.fit([], 100)
        assert result == []

    def test_all_messages_fit(self):
        """No summarization needed when all fit."""
        def summarize(msgs):
            return "Should not be called"

        strategy = SummarizeOldStrategy(summarize, keep_recent=5)
        messages = [create_message(f"Msg {i}", tokens=5) for i in range(3)]
        result = strategy.fit(messages, 100)

        # Returns original messages
        assert len(result) == 3

    def test_summarizes_old_messages(self):
        """Old messages are summarized."""
        def summarize(msgs):
            return f"Summary of {len(msgs)} messages"

        strategy = SummarizeOldStrategy(
            summarize,
            summary_prefix="[Summary]",
            keep_recent=2,
        )
        # Use larger token counts to ensure we exceed limit and trigger summarization
        messages = [create_message(f"Msg {i}", tokens=50) for i in range(5)]
        # With 5 messages at 50 tokens each = 250 tokens total
        # Setting max_tokens to 150 should trigger summarization
        result = strategy.fit(messages, 150)

        # First message should be summary
        assert "[Summary]" in result[0].content
        assert "3 messages" in result[0].content
        # Last 2 messages should be kept
        assert result[-1].content == "Msg 4"
        assert result[-2].content == "Msg 3"

    def test_not_enough_messages_to_summarize(self):
        """Fewer messages than keep_recent uses sliding window."""
        def summarize(msgs):
            return "Summary"

        strategy = SummarizeOldStrategy(summarize, keep_recent=10)
        messages = [create_message(f"Msg {i}", tokens=20) for i in range(5)]
        result = strategy.fit(messages, 50)

        # Falls back to sliding window
        assert len(result) <= 2


class TestContextWindow:
    """Tests for ContextWindow class."""

    def test_create_with_enum_strategy(self):
        """Create with ContextStrategy enum."""
        window = ContextWindow(
            max_tokens=8000,
            strategy=ContextStrategy.SLIDING_WINDOW,
        )
        assert window.max_tokens == 8000

    def test_create_with_custom_strategy(self):
        """Create with custom strategy."""
        custom = SlidingWindowStrategy()
        window = ContextWindow(max_tokens=8000, strategy=custom)
        assert window._fit_strategy == custom

    def test_available_tokens(self):
        """Get available tokens after reserve."""
        window = ContextWindow(max_tokens=8000, reserve_output=1000)
        assert window.get_available_tokens() == 7000

    def test_fit_messages(self):
        """Fit messages within token limit."""
        window = ContextWindow(max_tokens=100, reserve_output=20)
        messages = [create_message(f"Msg {i}", tokens=10) for i in range(10)]

        result = window.fit_messages(messages)
        total = sum(m.token_count or 0 for m in result)
        assert total <= 80  # 100 - 20 reserve

    def test_should_truncate(self):
        """Check if truncation needed."""
        window = ContextWindow(max_tokens=50, reserve_output=10)

        small_msgs = [create_message("Small", tokens=10)]
        assert window.should_truncate(small_msgs) is False

        large_msgs = [create_message(f"Msg {i}", tokens=20) for i in range(5)]
        assert window.should_truncate(large_msgs) is True

    def test_get_token_count(self):
        """Get total token count."""
        window = ContextWindow(max_tokens=1000)
        messages = [
            create_message("A", tokens=10),
            create_message("B", tokens=20),
        ]
        assert window.get_token_count(messages) == 30

    def test_get_overflow(self):
        """Get overflow amount."""
        window = ContextWindow(max_tokens=50, reserve_output=10)
        messages = [create_message("Msg", tokens=60)]
        overflow = window.get_overflow(messages)
        assert overflow == 20  # 60 - 40 available

    def test_no_overflow(self):
        """No overflow when under limit."""
        window = ContextWindow(max_tokens=100, reserve_output=10)
        messages = [create_message("Msg", tokens=50)]
        assert window.get_overflow(messages) == 0

    def test_change_strategy(self):
        """Change strategy after creation."""
        window = ContextWindow(max_tokens=1000, strategy=ContextStrategy.SLIDING_WINDOW)
        window.strategy = ContextStrategy.KEEP_SYSTEM_RECENT

        assert window.strategy == ContextStrategy.KEEP_SYSTEM_RECENT

    def test_serialization(self):
        """Serialize and deserialize context window."""
        window = ContextWindow(
            max_tokens=8000,
            strategy=ContextStrategy.KEEP_SYSTEM_RECENT,
            reserve_output=1500,
        )

        data = window.to_dict()
        assert data["max_tokens"] == 8000
        assert data["strategy"] == "keep_system_recent"
        assert data["reserve_output"] == 1500

        restored = ContextWindow.from_dict(data)
        assert restored.max_tokens == 8000
        assert restored.reserve_output == 1500


class TestContextWindowStrategies:
    """Tests for different context window strategies."""

    def test_sliding_window_strategy(self):
        """Sliding window removes oldest messages."""
        window = ContextWindow(
            max_tokens=50,
            strategy=ContextStrategy.SLIDING_WINDOW,
            reserve_output=10,
        )
        messages = [
            create_message("First", tokens=15),
            create_message("Second", tokens=15),
            create_message("Third", tokens=15),
        ]

        result = window.fit_messages(messages)
        # Available: 40 tokens, should fit 2 most recent
        assert len(result) == 2
        assert result[0].content == "Second"
        assert result[1].content == "Third"

    def test_keep_system_recent_strategy(self):
        """Keep system + recent strategy."""
        window = ContextWindow(
            max_tokens=60,
            strategy=ContextStrategy.KEEP_SYSTEM_RECENT,
            reserve_output=10,
        )
        messages = [
            create_message("System prompt", role=MessageRole.SYSTEM, tokens=10),
            create_message("Old user msg", role=MessageRole.USER, tokens=15),
            create_message("Recent user", role=MessageRole.USER, tokens=15),
            create_message("Most recent", role=MessageRole.USER, tokens=15),
        ]

        result = window.fit_messages(messages)
        # Should keep system + most recent that fits
        system_msgs = [m for m in result if m.role == MessageRole.SYSTEM]
        assert len(system_msgs) == 1
        assert result[-1].content == "Most recent"

    def test_keep_first_last_strategy(self):
        """Keep first and last strategy."""
        window = ContextWindow(
            max_tokens=100,
            strategy=ContextStrategy.KEEP_FIRST_LAST,
            reserve_output=10,
        )
        messages = [
            create_message("Opening", tokens=10),
            create_message("Middle 1", tokens=10),
            create_message("Middle 2", tokens=10),
            create_message("Middle 3", tokens=10),
            create_message("Closing", tokens=10),
        ]

        result = window.fit_messages(messages)
        # Should have first and last
        assert result[0].content == "Opening"
        assert result[-1].content == "Closing"


class TestConvenienceFunctions:
    """Tests for convenience context window creators."""

    def test_gpt4_context_window(self):
        """Create GPT-4 context window."""
        window = create_gpt4_context_window()
        assert window.max_tokens == 8192
        assert window.reserve_output == 1024

    def test_gpt4_32k_context_window(self):
        """Create GPT-4-32K context window."""
        window = create_gpt4_32k_context_window()
        assert window.max_tokens == 32768
        assert window.reserve_output == 2048

    def test_claude_context_window(self):
        """Create Claude context window."""
        window = create_claude_context_window()
        assert window.max_tokens == 200000
        assert window.reserve_output == 4096

    def test_gemini_context_window(self):
        """Create Gemini context window."""
        window = create_gemini_context_window()
        assert window.max_tokens == 1000000
        assert window.reserve_output == 8192

    def test_custom_strategy_on_convenience(self):
        """Convenience functions accept custom strategy."""
        window = create_gpt4_context_window(strategy=ContextStrategy.SLIDING_WINDOW)
        assert window.strategy == ContextStrategy.SLIDING_WINDOW


class TestContextWindowIntegration:
    """Integration tests combining context window with message history."""

    def test_realistic_conversation(self):
        """Test with realistic conversation pattern."""
        window = ContextWindow(
            max_tokens=4096,
            strategy=ContextStrategy.KEEP_SYSTEM_RECENT,
            reserve_output=500,
        )

        messages = [
            create_message(
                "You are a helpful assistant that answers coding questions.",
                role=MessageRole.SYSTEM,
                tokens=50,
            ),
        ]

        # Simulate a conversation
        for i in range(20):
            messages.append(create_message(
                f"User question {i} about Python programming",
                role=MessageRole.USER,
                tokens=100,
            ))
            messages.append(create_message(
                f"Here's the answer to question {i} with detailed explanation",
                role=MessageRole.ASSISTANT,
                tokens=150,
            ))

        # Fit to context window
        result = window.fit_messages(messages)

        # System message should be preserved
        system_msgs = [m for m in result if m.role == MessageRole.SYSTEM]
        assert len(system_msgs) == 1

        # Recent messages should be present
        total_tokens = window.get_token_count(result)
        assert total_tokens <= window.get_available_tokens()

    def test_tool_call_conversation(self):
        """Test conversation with tool calls."""
        window = ContextWindow(
            max_tokens=2000,
            strategy=ContextStrategy.SLIDING_WINDOW,
            reserve_output=200,
        )

        messages = [
            create_message("You can use tools", role=MessageRole.SYSTEM, tokens=20),
            create_message("Search for X", role=MessageRole.USER, tokens=30),
            create_message("", role=MessageRole.TOOL_CALL, tokens=50),
            create_message("Results: ...", role=MessageRole.TOOL_RESULT, tokens=100),
            create_message("Based on results...", role=MessageRole.ASSISTANT, tokens=80),
            create_message("What about Y?", role=MessageRole.USER, tokens=30),
        ]

        result = window.fit_messages(messages)

        # All messages should fit
        assert len(result) == len(messages)

        # Order should be preserved
        assert result[0].role == MessageRole.SYSTEM
        assert result[-1].role == MessageRole.USER
