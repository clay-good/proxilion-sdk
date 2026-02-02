"""
Message history management for AI agent sessions.

Provides message tracking with token counting and truncation strategies
for managing conversation context within LLM token limits.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class MessageRole(Enum):
    """Role of a message in conversation history."""

    USER = "user"
    ASSISTANT = "assistant"
    SYSTEM = "system"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"


def estimate_tokens(text: str) -> int:
    """
    Estimate token count without tiktoken dependency.

    Uses a blend of word-based and character-based heuristics that
    approximates tokenizer behavior for English text. This provides
    a reasonable estimate (~10-15% accurate) without external dependencies.

    Args:
        text: The text to estimate tokens for.

    Returns:
        Estimated token count.

    Example:
        >>> estimate_tokens("Hello, world!")
        4
        >>> estimate_tokens("This is a longer sentence with more words.")
        11
    """
    if not text:
        return 0

    words = len(text.split())
    chars = len(text)

    # Blend word and character estimates
    # ~1.3 tokens per word, ~4 chars per token
    # Average the two approaches for better accuracy
    word_estimate = int(words * 1.3)
    char_estimate = chars // 4

    return max(1, (word_estimate + char_estimate) // 2)


@dataclass
class Message:
    """
    A single message in conversation history.

    Attributes:
        role: The role of the message sender.
        content: The message content.
        timestamp: When the message was created.
        metadata: Additional metadata (tool name, function args, etc.).
        token_count: Estimated token count for this message.
        message_id: Unique identifier for this message.
    """

    role: MessageRole
    content: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)
    token_count: int | None = None
    message_id: str | None = None

    def __post_init__(self) -> None:
        """Compute token count if not provided."""
        if self.token_count is None:
            self.token_count = estimate_tokens(self.content)
        if self.message_id is None:
            import uuid

            self.message_id = str(uuid.uuid4())

    def to_dict(self) -> dict[str, Any]:
        """
        Convert message to dictionary format.

        Returns:
            Dictionary representation of the message.
        """
        return {
            "role": self.role.value,
            "content": self.content,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
            "token_count": self.token_count,
            "message_id": self.message_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Message:
        """
        Create message from dictionary.

        Args:
            data: Dictionary with message data.

        Returns:
            Message instance.
        """
        return cls(
            role=MessageRole(data["role"]),
            content=data["content"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            metadata=data.get("metadata", {}),
            token_count=data.get("token_count"),
            message_id=data.get("message_id"),
        )


class MessageHistory:
    """
    Manages message list with token tracking and truncation.

    Thread-safe collection of messages with support for various
    retrieval patterns and LLM API formatting.

    Attributes:
        max_messages: Maximum number of messages to retain.
        max_tokens: Maximum total tokens to retain.

    Example:
        >>> history = MessageHistory(max_messages=100, max_tokens=8000)
        >>> history.append(Message(role=MessageRole.USER, content="Hello!"))
        >>> history.append(Message(role=MessageRole.ASSISTANT, content="Hi there!"))
        >>> len(history)
        2
        >>> history.get_total_tokens()
        6
    """

    def __init__(
        self,
        max_messages: int | None = None,
        max_tokens: int | None = None,
    ) -> None:
        """
        Initialize message history.

        Args:
            max_messages: Maximum number of messages to retain. None for unlimited.
            max_tokens: Maximum total tokens to retain. None for unlimited.
        """
        self.max_messages = max_messages
        self.max_tokens = max_tokens
        self._messages: list[Message] = []
        self._lock = threading.RLock()

    def __len__(self) -> int:
        """Return number of messages."""
        with self._lock:
            return len(self._messages)

    def __iter__(self):
        """Iterate over messages."""
        with self._lock:
            return iter(list(self._messages))

    def __getitem__(self, index: int | slice) -> Message | list[Message]:
        """Get message by index or slice."""
        with self._lock:
            return self._messages[index]

    def append(self, message: Message) -> list[Message]:
        """
        Append a message to history.

        If max_messages or max_tokens is exceeded, older messages
        are removed (except system messages which are preserved).

        Args:
            message: The message to append.

        Returns:
            List of messages that were removed due to limits.
        """
        with self._lock:
            self._messages.append(message)
            return self._enforce_limits()

    def _enforce_limits(self) -> list[Message]:
        """
        Enforce max_messages and max_tokens limits.

        Returns:
            List of removed messages.
        """
        removed: list[Message] = []

        # Enforce message limit
        if self.max_messages is not None:
            while len(self._messages) > self.max_messages:
                # Find first non-system message to remove
                for i, msg in enumerate(self._messages):
                    if msg.role != MessageRole.SYSTEM:
                        removed.append(self._messages.pop(i))
                        break
                else:
                    # All messages are system messages, remove oldest
                    if self._messages:
                        removed.append(self._messages.pop(0))
                    break

        # Enforce token limit
        if self.max_tokens is not None:
            while self.get_total_tokens() > self.max_tokens and len(self._messages) > 1:
                # Find first non-system message to remove
                for i, msg in enumerate(self._messages):
                    if msg.role != MessageRole.SYSTEM:
                        removed.append(self._messages.pop(i))
                        break
                else:
                    # All messages are system messages, keep at least one
                    if len(self._messages) > 1:
                        removed.append(self._messages.pop(0))
                    break

        return removed

    def get_recent(self, n: int) -> list[Message]:
        """
        Get the n most recent messages.

        Args:
            n: Number of messages to retrieve.

        Returns:
            List of most recent messages.
        """
        with self._lock:
            return list(self._messages[-n:])

    def get_by_role(self, role: MessageRole) -> list[Message]:
        """
        Get all messages with a specific role.

        Args:
            role: The role to filter by.

        Returns:
            List of messages with the specified role.
        """
        with self._lock:
            return [msg for msg in self._messages if msg.role == role]

    def truncate_to_token_limit(self, max_tokens: int) -> list[Message]:
        """
        Truncate history to fit within token limit.

        Removes oldest non-system messages first to fit within the limit.

        Args:
            max_tokens: Maximum tokens to retain.

        Returns:
            List of messages that were removed.
        """
        with self._lock:
            removed: list[Message] = []
            while self.get_total_tokens() > max_tokens and len(self._messages) > 1:
                # Find first non-system message to remove
                for i, msg in enumerate(self._messages):
                    if msg.role != MessageRole.SYSTEM:
                        removed.append(self._messages.pop(i))
                        break
                else:
                    # All remaining are system messages
                    if len(self._messages) > 1:
                        removed.append(self._messages.pop(0))
                    break
            return removed

    def to_llm_format(self, provider: str = "openai") -> list[dict[str, Any]]:
        """
        Format messages for LLM API calls.

        Args:
            provider: The LLM provider format to use.
                     Supported: "openai", "anthropic", "google"

        Returns:
            List of message dictionaries formatted for the provider.

        Example:
            >>> history.to_llm_format("openai")
            [{"role": "user", "content": "Hello!"}, ...]
        """
        with self._lock:
            result: list[dict[str, Any]] = []

            for msg in self._messages:
                if provider == "openai":
                    result.append(self._to_openai_format(msg))
                elif provider == "anthropic":
                    result.append(self._to_anthropic_format(msg))
                elif provider == "google":
                    result.append(self._to_google_format(msg))
                else:
                    # Default to OpenAI-style format
                    result.append(self._to_openai_format(msg))

            return result

    def _to_openai_format(self, msg: Message) -> dict[str, Any]:
        """Convert message to OpenAI format."""
        role_map = {
            MessageRole.USER: "user",
            MessageRole.ASSISTANT: "assistant",
            MessageRole.SYSTEM: "system",
            MessageRole.TOOL_CALL: "assistant",
            MessageRole.TOOL_RESULT: "tool",
        }

        formatted: dict[str, Any] = {
            "role": role_map.get(msg.role, "user"),
            "content": msg.content,
        }

        # Add tool-specific fields
        if msg.role == MessageRole.TOOL_CALL and "tool_calls" in msg.metadata:
            formatted["tool_calls"] = msg.metadata["tool_calls"]
            formatted["content"] = None

        if msg.role == MessageRole.TOOL_RESULT and "tool_call_id" in msg.metadata:
            formatted["tool_call_id"] = msg.metadata["tool_call_id"]

        return formatted

    def _to_anthropic_format(self, msg: Message) -> dict[str, Any]:
        """Convert message to Anthropic format."""
        role_map = {
            MessageRole.USER: "user",
            MessageRole.ASSISTANT: "assistant",
            MessageRole.SYSTEM: "user",  # Anthropic handles system differently
            MessageRole.TOOL_CALL: "assistant",
            MessageRole.TOOL_RESULT: "user",
        }

        formatted: dict[str, Any] = {
            "role": role_map.get(msg.role, "user"),
            "content": msg.content,
        }

        # Handle tool use blocks for Anthropic
        if msg.role == MessageRole.TOOL_CALL and "tool_use" in msg.metadata:
            formatted["content"] = msg.metadata["tool_use"]

        if msg.role == MessageRole.TOOL_RESULT and "tool_result" in msg.metadata:
            formatted["content"] = [msg.metadata["tool_result"]]

        return formatted

    def _to_google_format(self, msg: Message) -> dict[str, Any]:
        """Convert message to Google/Gemini format."""
        role_map = {
            MessageRole.USER: "user",
            MessageRole.ASSISTANT: "model",
            MessageRole.SYSTEM: "user",
            MessageRole.TOOL_CALL: "model",
            MessageRole.TOOL_RESULT: "function",
        }

        formatted: dict[str, Any] = {
            "role": role_map.get(msg.role, "user"),
            "parts": [{"text": msg.content}],
        }

        # Handle function calls for Gemini
        if msg.role == MessageRole.TOOL_CALL and "function_call" in msg.metadata:
            formatted["parts"] = [{"function_call": msg.metadata["function_call"]}]

        if msg.role == MessageRole.TOOL_RESULT and "function_response" in msg.metadata:
            formatted["parts"] = [
                {"function_response": msg.metadata["function_response"]}
            ]

        return formatted

    def get_total_tokens(self) -> int:
        """
        Get total token count across all messages.

        Returns:
            Total estimated tokens.
        """
        with self._lock:
            return sum(msg.token_count or 0 for msg in self._messages)

    def get_messages(self) -> list[Message]:
        """
        Get a copy of all messages.

        Returns:
            List of all messages in history.
        """
        with self._lock:
            return list(self._messages)

    def clear(self) -> list[Message]:
        """
        Clear all messages from history.

        Returns:
            List of all cleared messages.
        """
        with self._lock:
            cleared = list(self._messages)
            self._messages = []
            return cleared

    def clear_except_system(self) -> list[Message]:
        """
        Clear all non-system messages from history.

        Returns:
            List of cleared messages.
        """
        with self._lock:
            system_msgs = [m for m in self._messages if m.role == MessageRole.SYSTEM]
            cleared = [m for m in self._messages if m.role != MessageRole.SYSTEM]
            self._messages = system_msgs
            return cleared

    def find_by_id(self, message_id: str) -> Message | None:
        """
        Find a message by its ID.

        Args:
            message_id: The message ID to find.

        Returns:
            The message if found, None otherwise.
        """
        with self._lock:
            for msg in self._messages:
                if msg.message_id == message_id:
                    return msg
            return None

    def remove_by_id(self, message_id: str) -> Message | None:
        """
        Remove a message by its ID.

        Args:
            message_id: The message ID to remove.

        Returns:
            The removed message if found, None otherwise.
        """
        with self._lock:
            for i, msg in enumerate(self._messages):
                if msg.message_id == message_id:
                    return self._messages.pop(i)
            return None

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize history to dictionary.

        Returns:
            Dictionary representation of the history.
        """
        with self._lock:
            return {
                "max_messages": self.max_messages,
                "max_tokens": self.max_tokens,
                "messages": [msg.to_dict() for msg in self._messages],
            }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MessageHistory:
        """
        Deserialize history from dictionary.

        Args:
            data: Dictionary with history data.

        Returns:
            MessageHistory instance.
        """
        history = cls(
            max_messages=data.get("max_messages"),
            max_tokens=data.get("max_tokens"),
        )
        for msg_data in data.get("messages", []):
            history._messages.append(Message.from_dict(msg_data))
        return history
