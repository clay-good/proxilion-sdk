"""
Context window management for LLM interactions.

Provides strategies for fitting conversation history within
LLM token limits while preserving important context.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol

from proxilion.context.message_history import Message, MessageRole


class ContextStrategy(Enum):
    """Strategy for fitting messages within token limits."""

    SLIDING_WINDOW = "sliding_window"
    """Keep most recent messages that fit."""

    KEEP_SYSTEM_RECENT = "keep_system_recent"
    """Keep all system messages + most recent other messages."""

    SUMMARIZE_OLD = "summarize_old"
    """Summarize older messages (requires callback)."""

    KEEP_FIRST_LAST = "keep_first_last"
    """Keep first and last messages, remove middle."""


class FitStrategy(Protocol):
    """Protocol for context fitting strategies."""

    def fit(self, messages: list[Message], max_tokens: int) -> list[Message]:
        """
        Fit messages within token limit.

        Args:
            messages: The messages to fit.
            max_tokens: Maximum tokens allowed.

        Returns:
            List of messages that fit within the limit.
        """
        ...


class SlidingWindowStrategy:
    """
    Keep most recent messages that fit within token limit.

    This strategy removes messages from the start of the conversation
    until the remaining messages fit within the token limit.

    Example:
        >>> strategy = SlidingWindowStrategy()
        >>> fitted = strategy.fit(messages, max_tokens=4000)
    """

    def fit(self, messages: list[Message], max_tokens: int) -> list[Message]:
        """
        Fit messages using sliding window approach.

        Args:
            messages: The messages to fit.
            max_tokens: Maximum tokens allowed.

        Returns:
            List of most recent messages that fit.
        """
        if not messages:
            return []

        result: list[Message] = []
        total = 0

        # Process messages in reverse (most recent first)
        for msg in reversed(messages):
            msg_tokens = msg.token_count or 0
            if total + msg_tokens > max_tokens:
                break
            result.append(msg)
            total += msg_tokens

        result.reverse()
        return result


class KeepSystemRecentStrategy:
    """
    Keep all system messages plus most recent user/assistant messages.

    This strategy ensures system prompts are always included,
    then fills remaining space with recent conversation.

    Example:
        >>> strategy = KeepSystemRecentStrategy()
        >>> fitted = strategy.fit(messages, max_tokens=4000)
    """

    def fit(self, messages: list[Message], max_tokens: int) -> list[Message]:
        """
        Fit messages keeping system messages and recent others.

        Args:
            messages: The messages to fit.
            max_tokens: Maximum tokens allowed.

        Returns:
            List of system messages + recent messages that fit.
        """
        if not messages:
            return []

        # Separate system and other messages
        system_msgs = [m for m in messages if m.role == MessageRole.SYSTEM]
        other_msgs = [m for m in messages if m.role != MessageRole.SYSTEM]

        # Calculate tokens used by system messages
        system_tokens = sum(m.token_count or 0 for m in system_msgs)

        # If system messages exceed limit, truncate them
        if system_tokens > max_tokens:
            # Keep only the most recent system message that fits
            result: list[Message] = []
            total = 0
            for msg in reversed(system_msgs):
                msg_tokens = msg.token_count or 0
                if total + msg_tokens > max_tokens:
                    break
                result.append(msg)
                total += msg_tokens
            result.reverse()  # O(n) instead of O(n²) insert(0)
            return result

        # Calculate remaining tokens for other messages
        remaining = max_tokens - system_tokens

        # Fill with recent messages
        recent: list[Message] = []
        recent_tokens = 0
        for msg in reversed(other_msgs):
            msg_tokens = msg.token_count or 0
            if recent_tokens + msg_tokens > remaining:
                break
            recent.append(msg)
            recent_tokens += msg_tokens
        recent.reverse()  # O(n) instead of O(n²) insert(0)

        return system_msgs + recent


class KeepFirstLastStrategy:
    """
    Keep first and last messages, removing middle messages.

    This strategy preserves the beginning context and recent
    conversation while removing intermediate messages.

    Attributes:
        keep_first: Number of messages to keep from start.
        keep_last: Number of messages to keep from end.

    Example:
        >>> strategy = KeepFirstLastStrategy(keep_first=2, keep_last=5)
        >>> fitted = strategy.fit(messages, max_tokens=4000)
    """

    def __init__(self, keep_first: int = 1, keep_last: int = 5) -> None:
        """
        Initialize strategy.

        Args:
            keep_first: Number of messages to keep from start.
            keep_last: Number of messages to keep from end.

        Raises:
            ValueError: If keep_first < 0 or keep_last < 0.
        """
        if keep_first < 0:
            raise ValueError("keep_first must be >= 0")
        if keep_last < 0:
            raise ValueError("keep_last must be >= 0")

        self.keep_first = keep_first
        self.keep_last = keep_last

    def fit(self, messages: list[Message], max_tokens: int) -> list[Message]:
        """
        Fit messages keeping first and last.

        Args:
            messages: The messages to fit.
            max_tokens: Maximum tokens allowed.

        Returns:
            List of first and last messages that fit.
        """
        if not messages:
            return []

        if len(messages) <= self.keep_first + self.keep_last:
            # All messages fit in the keep regions
            total = sum(m.token_count or 0 for m in messages)
            if total <= max_tokens:
                return messages
            # Still need to truncate — keep first and last, trim from middle
            # to maintain the KeepFirstLast contract
            first_msgs = messages[: self.keep_first]
            last_msgs = messages[self.keep_first :]
            first_tokens = sum(m.token_count or 0 for m in first_msgs)
            remaining = max_tokens - first_tokens
            if remaining <= 0:
                # First messages alone exceed budget, trim first messages
                kept: list[Message] = []
                budget = 0
                for msg in first_msgs:
                    msg_tokens = msg.token_count or 0
                    if budget + msg_tokens > max_tokens:
                        break
                    kept.append(msg)
                    budget += msg_tokens
                return kept
            # Fill remaining budget from the end
            kept_last: list[Message] = []
            budget = 0
            for msg in reversed(last_msgs):
                msg_tokens = msg.token_count or 0
                if budget + msg_tokens > remaining:
                    break
                kept_last.insert(0, msg)
                budget += msg_tokens
            return first_msgs + kept_last

        # Get first and last messages
        first_msgs = messages[: self.keep_first]
        last_msgs = messages[-self.keep_last :]

        # Calculate tokens
        first_tokens = sum(m.token_count or 0 for m in first_msgs)
        last_tokens = sum(m.token_count or 0 for m in last_msgs)

        # If first+last exceed limit, prioritize last
        if first_tokens + last_tokens > max_tokens:
            # Try to keep at least some first messages
            available = max_tokens - last_tokens
            if available > 0:
                kept_first: list[Message] = []
                total = 0
                for msg in first_msgs:
                    msg_tokens = msg.token_count or 0
                    if total + msg_tokens > available:
                        break
                    kept_first.append(msg)
                    total += msg_tokens
                return kept_first + last_msgs
            else:
                # Can only fit last messages
                return SlidingWindowStrategy().fit(last_msgs, max_tokens)

        return first_msgs + last_msgs


@dataclass
class SummarizeOldStrategy:
    """
    Summarize older messages to fit within token limit.

    This strategy requires a summarization callback that takes
    messages and returns a summary string. Useful when you want
    to preserve context without keeping all messages.

    Attributes:
        summarize_callback: Function to summarize messages.
        summary_prefix: Prefix for summary message.
        keep_recent: Number of recent messages to keep without summarizing.

    Example:
        >>> def summarize(messages):
        ...     return f"Previously discussed: {len(messages)} messages"
        >>> strategy = SummarizeOldStrategy(summarize, keep_recent=5)
        >>> fitted = strategy.fit(messages, max_tokens=4000)
    """

    summarize_callback: Any  # Callable[[list[Message]], str]
    summary_prefix: str = "[Summary of previous conversation]"
    keep_recent: int = 10

    def fit(self, messages: list[Message], max_tokens: int) -> list[Message]:
        """
        Fit messages by summarizing older ones.

        Args:
            messages: The messages to fit.
            max_tokens: Maximum tokens allowed.

        Returns:
            List of messages with older ones summarized.
        """
        if not messages:
            return []

        # Calculate total tokens
        total_tokens = sum(m.token_count or 0 for m in messages)

        if total_tokens <= max_tokens:
            return messages

        # Split into recent and old
        if len(messages) <= self.keep_recent:
            # Not enough to summarize, use sliding window
            return SlidingWindowStrategy().fit(messages, max_tokens)

        recent = messages[-self.keep_recent :]
        old = messages[: -self.keep_recent]

        # Summarize old messages
        summary_text = self.summarize_callback(old)
        summary_content = f"{self.summary_prefix}\n{summary_text}"

        summary_msg = Message(
            role=MessageRole.SYSTEM,
            content=summary_content,
        )

        # Check if summary + recent fits
        result = [summary_msg] + recent
        result_tokens = sum(m.token_count or 0 for m in result)

        if result_tokens <= max_tokens:
            return result

        # Still too large, reduce recent messages
        available = max_tokens - (summary_msg.token_count or 0)
        fitted_recent = SlidingWindowStrategy().fit(recent, available)
        return [summary_msg] + fitted_recent


class ContextWindow:
    """
    Manages context window for LLM calls.

    Coordinates fitting messages within token limits using
    configurable strategies.

    Attributes:
        max_tokens: Maximum tokens for context.
        strategy: The fitting strategy to use.
        reserve_output: Tokens to reserve for output generation.

    Example:
        >>> window = ContextWindow(
        ...     max_tokens=8000,
        ...     strategy=ContextStrategy.KEEP_SYSTEM_RECENT,
        ...     reserve_output=1000
        ... )
        >>> messages = [...]
        >>> fitted = window.fit_messages(messages)
        >>> available = window.get_available_tokens()
    """

    def __init__(
        self,
        max_tokens: int,
        strategy: ContextStrategy | FitStrategy = ContextStrategy.SLIDING_WINDOW,
        reserve_output: int = 1000,
    ) -> None:
        """
        Initialize context window.

        Args:
            max_tokens: Maximum tokens for context.
            strategy: The fitting strategy to use.
            reserve_output: Tokens to reserve for output generation.

        Raises:
            ValueError: If max_tokens <= 0 or reserve_output < 0.
        """
        if max_tokens <= 0:
            raise ValueError("max_tokens must be greater than 0")
        if reserve_output < 0:
            raise ValueError("reserve_output must be >= 0")

        self.max_tokens = max_tokens
        self.reserve_output = reserve_output
        self._strategy = strategy
        self._fit_strategy = self._get_strategy(strategy)

    def _get_strategy(
        self, strategy: ContextStrategy | FitStrategy
    ) -> FitStrategy:
        """Get the fit strategy implementation."""
        if isinstance(strategy, ContextStrategy):
            if strategy == ContextStrategy.SLIDING_WINDOW:
                return SlidingWindowStrategy()
            elif strategy == ContextStrategy.KEEP_SYSTEM_RECENT:
                return KeepSystemRecentStrategy()
            elif strategy == ContextStrategy.KEEP_FIRST_LAST:
                return KeepFirstLastStrategy()
            else:
                # Default to sliding window for unsupported strategies
                return SlidingWindowStrategy()
        else:
            # Custom strategy implementation
            return strategy

    @property
    def strategy(self) -> ContextStrategy | FitStrategy:
        """Get the current strategy."""
        return self._strategy

    @strategy.setter
    def strategy(self, value: ContextStrategy | FitStrategy) -> None:
        """Set the strategy."""
        self._strategy = value
        self._fit_strategy = self._get_strategy(value)

    def fit_messages(self, messages: list[Message]) -> list[Message]:
        """
        Fit messages within token limit using configured strategy.

        Args:
            messages: The messages to fit.

        Returns:
            List of messages that fit within the limit.
        """
        available = self.get_available_tokens()
        return self._fit_strategy.fit(messages, available)

    def get_available_tokens(self) -> int:
        """
        Get available tokens for context (after reserving output tokens).

        Returns:
            Number of tokens available for context.
        """
        return max(0, self.max_tokens - self.reserve_output)

    def should_truncate(self, messages: list[Message]) -> bool:
        """
        Check if messages need truncation.

        Args:
            messages: The messages to check.

        Returns:
            True if messages exceed available tokens.
        """
        total = sum(m.token_count or 0 for m in messages)
        return total > self.get_available_tokens()

    def get_token_count(self, messages: list[Message]) -> int:
        """
        Get total token count for messages.

        Args:
            messages: The messages to count.

        Returns:
            Total token count.
        """
        return sum(m.token_count or 0 for m in messages)

    def get_overflow(self, messages: list[Message]) -> int:
        """
        Get number of tokens over the limit.

        Args:
            messages: The messages to check.

        Returns:
            Number of tokens over limit (0 if under).
        """
        total = self.get_token_count(messages)
        available = self.get_available_tokens()
        return max(0, total - available)

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize context window to dictionary.

        Returns:
            Dictionary representation.
        """
        strategy_value: str
        if isinstance(self._strategy, ContextStrategy):
            strategy_value = self._strategy.value
        else:
            strategy_value = "custom"

        return {
            "max_tokens": self.max_tokens,
            "strategy": strategy_value,
            "reserve_output": self.reserve_output,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ContextWindow:
        """
        Deserialize context window from dictionary.

        Args:
            data: Dictionary with context window data.

        Returns:
            ContextWindow instance.
        """
        strategy_str = data.get("strategy", "sliding_window")
        try:
            strategy = ContextStrategy(strategy_str)
        except ValueError:
            strategy = ContextStrategy.SLIDING_WINDOW

        return cls(
            max_tokens=data.get("max_tokens", 8000),
            strategy=strategy,
            reserve_output=data.get("reserve_output", 1000),
        )


# Convenience functions for common context window configurations


def create_gpt4_context_window(
    strategy: ContextStrategy = ContextStrategy.KEEP_SYSTEM_RECENT,
) -> ContextWindow:
    """
    Create context window configured for GPT-4 (8K context).

    Args:
        strategy: The fitting strategy to use.

    Returns:
        Configured ContextWindow.
    """
    return ContextWindow(
        max_tokens=8192,
        strategy=strategy,
        reserve_output=1024,
    )


def create_gpt4_32k_context_window(
    strategy: ContextStrategy = ContextStrategy.KEEP_SYSTEM_RECENT,
) -> ContextWindow:
    """
    Create context window configured for GPT-4-32K.

    Args:
        strategy: The fitting strategy to use.

    Returns:
        Configured ContextWindow.
    """
    return ContextWindow(
        max_tokens=32768,
        strategy=strategy,
        reserve_output=2048,
    )


def create_claude_context_window(
    strategy: ContextStrategy = ContextStrategy.KEEP_SYSTEM_RECENT,
) -> ContextWindow:
    """
    Create context window configured for Claude (200K context).

    Args:
        strategy: The fitting strategy to use.

    Returns:
        Configured ContextWindow.
    """
    return ContextWindow(
        max_tokens=200000,
        strategy=strategy,
        reserve_output=4096,
    )


def create_gemini_context_window(
    strategy: ContextStrategy = ContextStrategy.KEEP_SYSTEM_RECENT,
) -> ContextWindow:
    """
    Create context window configured for Gemini 1.5 (1M context).

    Args:
        strategy: The fitting strategy to use.

    Returns:
        Configured ContextWindow.
    """
    return ContextWindow(
        max_tokens=1000000,
        strategy=strategy,
        reserve_output=8192,
    )
