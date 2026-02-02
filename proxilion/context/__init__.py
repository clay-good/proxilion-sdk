"""
Context management for AI agent sessions.

Provides:
- Session tracking with metadata
- Message history management
- Context window optimization
- Multi-turn conversation state

This module enables stateful agent interactions, including context windows,
message history, and session metadata. Essential for chatbot applications
and multi-turn agent conversations.

Example:
    >>> from proxilion.context import (
    ...     Session, SessionManager, SessionConfig,
    ...     MessageHistory, Message, MessageRole,
    ...     ContextWindow, ContextStrategy,
    ... )
    >>> from proxilion.types import UserContext
    >>>
    >>> # Create a session manager
    >>> config = SessionConfig(max_duration=3600, max_messages=100)
    >>> manager = SessionManager(config)
    >>>
    >>> # Create a session for a user
    >>> user = UserContext(user_id="user_123", roles=["user"])
    >>> session = manager.create_session(user)
    >>>
    >>> # Add messages
    >>> session.add_message(MessageRole.USER, "Hello, how can you help?")
    >>> session.add_message(MessageRole.ASSISTANT, "I can help with many tasks!")
    >>>
    >>> # Get context for LLM
    >>> context = session.get_context_for_llm(max_tokens=4000)
"""

from proxilion.context.context_window import (
    ContextStrategy,
    ContextWindow,
    KeepSystemRecentStrategy,
    SlidingWindowStrategy,
)
from proxilion.context.message_history import (
    Message,
    MessageHistory,
    MessageRole,
    estimate_tokens,
)
from proxilion.context.session import (
    Session,
    SessionConfig,
    SessionManager,
    SessionState,
)

__all__ = [
    # Session management
    "Session",
    "SessionConfig",
    "SessionManager",
    "SessionState",
    # Message history
    "Message",
    "MessageHistory",
    "MessageRole",
    "estimate_tokens",
    # Context window
    "ContextStrategy",
    "ContextWindow",
    "KeepSystemRecentStrategy",
    "SlidingWindowStrategy",
]
