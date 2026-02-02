"""
Session tracking for AI agent conversations.

Provides session management with metadata, expiration, and
multi-turn conversation state.
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from proxilion.context.message_history import Message, MessageHistory, MessageRole
from proxilion.types import UserContext


class SessionState(Enum):
    """State of a session."""

    ACTIVE = "active"
    IDLE = "idle"
    EXPIRED = "expired"
    TERMINATED = "terminated"


@dataclass
class SessionConfig:
    """
    Configuration for session management.

    Attributes:
        max_duration: Maximum session duration in seconds. None for no limit.
        max_idle_time: Maximum idle time before expiration in seconds.
        max_messages: Maximum messages per session.
        max_tokens: Maximum total tokens per session.
        auto_cleanup: Whether to automatically cleanup expired sessions.
        metadata_schema: Optional schema for validating session metadata.
    """

    max_duration: int | None = 3600  # 1 hour default
    max_idle_time: int | None = 900  # 15 minutes default
    max_messages: int | None = 100
    max_tokens: int | None = None
    auto_cleanup: bool = True
    metadata_schema: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert config to dictionary."""
        return {
            "max_duration": self.max_duration,
            "max_idle_time": self.max_idle_time,
            "max_messages": self.max_messages,
            "max_tokens": self.max_tokens,
            "auto_cleanup": self.auto_cleanup,
            "metadata_schema": self.metadata_schema,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SessionConfig:
        """Create config from dictionary."""
        return cls(
            max_duration=data.get("max_duration", 3600),
            max_idle_time=data.get("max_idle_time", 900),
            max_messages=data.get("max_messages", 100),
            max_tokens=data.get("max_tokens"),
            auto_cleanup=data.get("auto_cleanup", True),
            metadata_schema=data.get("metadata_schema"),
        )


@dataclass
class Session:
    """
    Individual session with state and message history.

    Attributes:
        session_id: Unique identifier for this session.
        user: The user context for this session.
        config: Session configuration.
        created_at: When the session was created.
        last_activity: Last activity timestamp.
        state: Current session state.
        metadata: Session metadata (e.g., agent info, preferences).
        history: Message history for this session.
        termination_reason: Reason for termination if terminated.
    """

    session_id: str
    user: UserContext
    config: SessionConfig
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_activity: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    state: SessionState = SessionState.ACTIVE
    metadata: dict[str, Any] = field(default_factory=dict)
    history: MessageHistory = field(default=None)  # type: ignore
    termination_reason: str | None = None
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def __post_init__(self) -> None:
        """Initialize message history if not provided."""
        if self.history is None:
            self.history = MessageHistory(
                max_messages=self.config.max_messages,
                max_tokens=self.config.max_tokens,
            )

    def add_message(
        self,
        role: MessageRole,
        content: str,
        metadata: dict[str, Any] | None = None,
    ) -> Message:
        """
        Add a message to the session history.

        Args:
            role: The role of the message sender.
            content: The message content.
            metadata: Optional metadata for the message.

        Returns:
            The created message.

        Raises:
            ValueError: If session is not active.
        """
        with self._lock:
            if self.state not in (SessionState.ACTIVE, SessionState.IDLE):
                raise ValueError(
                    f"Cannot add message to session in state {self.state.value}"
                )

            message = Message(
                role=role,
                content=content,
                metadata=metadata or {},
            )
            self.history.append(message)
            self.touch()
            return message

    def get_messages(self, limit: int | None = None) -> list[Message]:
        """
        Get messages from the session history.

        Args:
            limit: Maximum number of messages to return (most recent).

        Returns:
            List of messages.
        """
        with self._lock:
            if limit is not None:
                return self.history.get_recent(limit)
            return self.history.get_messages()

    def get_context_for_llm(
        self,
        max_tokens: int | None = None,
        provider: str = "openai",
    ) -> list[dict[str, Any]]:
        """
        Get message history formatted for LLM API calls.

        Args:
            max_tokens: Maximum tokens to include (truncates from start).
            provider: The LLM provider format ("openai", "anthropic", "google").

        Returns:
            List of message dictionaries for the LLM API.
        """
        with self._lock:
            if max_tokens is not None:
                # Create a temporary history to apply truncation
                temp_history = MessageHistory()
                for msg in self.history.get_messages():
                    temp_history.append(
                        Message(
                            role=msg.role,
                            content=msg.content,
                            timestamp=msg.timestamp,
                            metadata=msg.metadata,
                            token_count=msg.token_count,
                            message_id=msg.message_id,
                        )
                    )
                temp_history.truncate_to_token_limit(max_tokens)
                return temp_history.to_llm_format(provider)

            return self.history.to_llm_format(provider)

    def set_metadata(self, key: str, value: Any) -> None:
        """
        Set a metadata value.

        Args:
            key: The metadata key.
            value: The metadata value.
        """
        with self._lock:
            self.metadata[key] = value

    def get_metadata(self, key: str, default: Any = None) -> Any:
        """
        Get a metadata value.

        Args:
            key: The metadata key.
            default: Default value if key not found.

        Returns:
            The metadata value or default.
        """
        with self._lock:
            return self.metadata.get(key, default)

    def touch(self) -> None:
        """Update last activity time and set state to active."""
        with self._lock:
            self.last_activity = datetime.now(timezone.utc)
            if self.state == SessionState.IDLE:
                self.state = SessionState.ACTIVE

    def is_expired(self) -> bool:
        """
        Check if the session has expired.

        Returns:
            True if session is expired, False otherwise.
        """
        with self._lock:
            if self.state in (SessionState.EXPIRED, SessionState.TERMINATED):
                return True

            now = datetime.now(timezone.utc)

            # Check max duration
            if self.config.max_duration is not None:
                duration = (now - self.created_at).total_seconds()
                if duration > self.config.max_duration:
                    self.state = SessionState.EXPIRED
                    return True

            # Check idle time
            if self.config.max_idle_time is not None:
                idle_time = (now - self.last_activity).total_seconds()
                if idle_time > self.config.max_idle_time:
                    self.state = SessionState.EXPIRED
                    return True

            return False

    def check_idle(self) -> bool:
        """
        Check if session should be marked as idle.

        Returns:
            True if session is idle, False otherwise.
        """
        with self._lock:
            if self.state != SessionState.ACTIVE:
                return self.state == SessionState.IDLE

            if self.config.max_idle_time is not None:
                now = datetime.now(timezone.utc)
                idle_time = (now - self.last_activity).total_seconds()
                # Mark as idle after half the max idle time
                if idle_time > self.config.max_idle_time / 2:
                    self.state = SessionState.IDLE
                    return True

            return False

    def terminate(self, reason: str | None = None) -> None:
        """
        Terminate the session.

        Args:
            reason: Optional reason for termination.
        """
        with self._lock:
            self.state = SessionState.TERMINATED
            self.termination_reason = reason

    def get_duration(self) -> float:
        """
        Get session duration in seconds.

        Returns:
            Duration in seconds.
        """
        with self._lock:
            now = datetime.now(timezone.utc)
            return (now - self.created_at).total_seconds()

    def get_idle_time(self) -> float:
        """
        Get time since last activity in seconds.

        Returns:
            Idle time in seconds.
        """
        with self._lock:
            now = datetime.now(timezone.utc)
            return (now - self.last_activity).total_seconds()

    def get_remaining_duration(self) -> float | None:
        """
        Get remaining session duration in seconds.

        Returns:
            Remaining duration in seconds, or None if no limit.
        """
        with self._lock:
            if self.config.max_duration is None:
                return None
            elapsed = self.get_duration()
            return max(0, self.config.max_duration - elapsed)

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize session to dictionary.

        Returns:
            Dictionary representation of the session.
        """
        with self._lock:
            return {
                "session_id": self.session_id,
                "user_id": self.user.user_id,
                "user_roles": self.user.roles,
                "config": self.config.to_dict(),
                "created_at": self.created_at.isoformat(),
                "last_activity": self.last_activity.isoformat(),
                "state": self.state.value,
                "metadata": self.metadata,
                "history": self.history.to_dict(),
                "termination_reason": self.termination_reason,
            }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Session:
        """
        Deserialize session from dictionary.

        Args:
            data: Dictionary with session data.

        Returns:
            Session instance.
        """
        user = UserContext(
            user_id=data["user_id"],
            roles=data.get("user_roles", []),
        )
        config = SessionConfig.from_dict(data.get("config", {}))
        history = MessageHistory.from_dict(data.get("history", {}))

        session = cls(
            session_id=data["session_id"],
            user=user,
            config=config,
            created_at=datetime.fromisoformat(data["created_at"]),
            last_activity=datetime.fromisoformat(data["last_activity"]),
            state=SessionState(data.get("state", "active")),
            metadata=data.get("metadata", {}),
            history=history,
            termination_reason=data.get("termination_reason"),
        )
        return session


class SessionManager:
    """
    Manages multiple sessions with lifecycle management.

    Provides session creation, retrieval, and cleanup for
    multi-user agent applications.

    Attributes:
        config: Default configuration for new sessions.
        cleanup_interval: Interval in seconds for automatic cleanup.

    Example:
        >>> from proxilion.types import UserContext
        >>> config = SessionConfig(max_duration=3600, max_messages=100)
        >>> manager = SessionManager(config)
        >>> user = UserContext(user_id="user_123", roles=["user"])
        >>> session = manager.create_session(user)
        >>> session.add_message(MessageRole.USER, "Hello!")
        >>> manager.get_session(session.session_id)
        <Session ...>
    """

    def __init__(
        self,
        config: SessionConfig | None = None,
        cleanup_interval: int = 300,
    ) -> None:
        """
        Initialize session manager.

        Args:
            config: Default configuration for new sessions.
            cleanup_interval: Interval in seconds for automatic cleanup.
        """
        self.config = config or SessionConfig()
        self.cleanup_interval = cleanup_interval
        self._sessions: dict[str, Session] = {}
        self._user_sessions: dict[str, list[str]] = {}  # user_id -> session_ids
        self._lock = threading.RLock()
        self._last_cleanup = datetime.now(timezone.utc)

    def create_session(
        self,
        user: UserContext,
        session_id: str | None = None,
        config: SessionConfig | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Session:
        """
        Create a new session for a user.

        Args:
            user: The user context.
            session_id: Optional session ID. Auto-generated if not provided.
            config: Optional session-specific configuration.
            metadata: Optional initial metadata.

        Returns:
            The created session.
        """
        with self._lock:
            if session_id is None:
                session_id = str(uuid.uuid4())

            # Use provided config or fall back to default
            session_config = config or self.config

            session = Session(
                session_id=session_id,
                user=user,
                config=session_config,
                metadata=metadata or {},
            )

            self._sessions[session_id] = session

            # Track sessions by user
            if user.user_id not in self._user_sessions:
                self._user_sessions[user.user_id] = []
            self._user_sessions[user.user_id].append(session_id)

            # Run cleanup if needed
            if self.config.auto_cleanup:
                self._maybe_cleanup()

            return session

    def get_session(self, session_id: str) -> Session | None:
        """
        Get a session by ID.

        Args:
            session_id: The session ID.

        Returns:
            The session if found and not expired, None otherwise.
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return None

            # Check expiration
            if session.is_expired():
                return None

            return session

    def get_user_sessions(
        self,
        user_id: str,
        include_expired: bool = False,
    ) -> list[Session]:
        """
        Get all sessions for a user.

        Args:
            user_id: The user ID.
            include_expired: Whether to include expired sessions.

        Returns:
            List of sessions for the user.
        """
        with self._lock:
            session_ids = self._user_sessions.get(user_id, [])
            sessions: list[Session] = []

            for sid in session_ids:
                session = self._sessions.get(sid)
                if session is None:
                    continue
                if not include_expired and session.is_expired():
                    continue
                sessions.append(session)

            return sessions

    def get_or_create_session(
        self,
        user: UserContext,
        session_id: str | None = None,
        config: SessionConfig | None = None,
    ) -> tuple[Session, bool]:
        """
        Get an existing session or create a new one.

        Args:
            user: The user context.
            session_id: Optional session ID to look up.
            config: Optional session configuration for creation.

        Returns:
            Tuple of (session, created) where created is True if new.
        """
        with self._lock:
            if session_id is not None:
                existing = self.get_session(session_id)
                if existing is not None:
                    return existing, False

            session = self.create_session(user, session_id, config)
            return session, True

    def terminate_session(
        self,
        session_id: str,
        reason: str | None = None,
    ) -> bool:
        """
        Terminate a session.

        Args:
            session_id: The session ID.
            reason: Optional reason for termination.

        Returns:
            True if session was found and terminated.
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return False

            session.terminate(reason)
            return True

    def terminate_user_sessions(
        self,
        user_id: str,
        reason: str | None = None,
    ) -> int:
        """
        Terminate all sessions for a user.

        Args:
            user_id: The user ID.
            reason: Optional reason for termination.

        Returns:
            Number of sessions terminated.
        """
        with self._lock:
            sessions = self.get_user_sessions(user_id, include_expired=False)
            count = 0
            for session in sessions:
                session.terminate(reason)
                count += 1
            return count

    def cleanup_expired(self) -> int:
        """
        Remove expired and terminated sessions.

        Returns:
            Number of sessions removed.
        """
        with self._lock:
            to_remove: list[str] = []

            for session_id, session in self._sessions.items():
                if session.is_expired() or session.state == SessionState.TERMINATED:
                    to_remove.append(session_id)

            for session_id in to_remove:
                session = self._sessions.pop(session_id, None)
                if session is not None:
                    # Remove from user sessions list
                    user_id = session.user.user_id
                    if user_id in self._user_sessions:
                        if session_id in self._user_sessions[user_id]:
                            self._user_sessions[user_id].remove(session_id)

            self._last_cleanup = datetime.now(timezone.utc)
            return len(to_remove)

    def _maybe_cleanup(self) -> None:
        """Run cleanup if interval has passed."""
        now = datetime.now(timezone.utc)
        elapsed = (now - self._last_cleanup).total_seconds()
        if elapsed >= self.cleanup_interval:
            self.cleanup_expired()

    def get_active_count(self) -> int:
        """
        Get count of active (non-expired) sessions.

        Returns:
            Number of active sessions.
        """
        with self._lock:
            count = 0
            for session in self._sessions.values():
                if not session.is_expired() and session.state != SessionState.TERMINATED:
                    count += 1
            return count

    def get_total_count(self) -> int:
        """
        Get total count of sessions (including expired).

        Returns:
            Total number of sessions.
        """
        with self._lock:
            return len(self._sessions)

    def get_user_count(self) -> int:
        """
        Get count of unique users with sessions.

        Returns:
            Number of unique users.
        """
        with self._lock:
            return len(self._user_sessions)

    def get_stats(self) -> dict[str, Any]:
        """
        Get session statistics.

        Returns:
            Dictionary with session statistics.
        """
        with self._lock:
            active = 0
            idle = 0
            expired = 0
            terminated = 0

            for session in self._sessions.values():
                session.is_expired()  # Update state
                if session.state == SessionState.ACTIVE:
                    active += 1
                elif session.state == SessionState.IDLE:
                    idle += 1
                elif session.state == SessionState.EXPIRED:
                    expired += 1
                elif session.state == SessionState.TERMINATED:
                    terminated += 1

            return {
                "total": len(self._sessions),
                "active": active,
                "idle": idle,
                "expired": expired,
                "terminated": terminated,
                "unique_users": len(self._user_sessions),
                "last_cleanup": self._last_cleanup.isoformat(),
            }

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize manager state to dictionary.

        Returns:
            Dictionary representation of the manager.
        """
        with self._lock:
            return {
                "config": self.config.to_dict(),
                "cleanup_interval": self.cleanup_interval,
                "sessions": {
                    sid: session.to_dict()
                    for sid, session in self._sessions.items()
                },
                "user_sessions": dict(self._user_sessions),
                "last_cleanup": self._last_cleanup.isoformat(),
            }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SessionManager:
        """
        Deserialize manager from dictionary.

        Args:
            data: Dictionary with manager data.

        Returns:
            SessionManager instance.
        """
        config = SessionConfig.from_dict(data.get("config", {}))
        manager = cls(
            config=config,
            cleanup_interval=data.get("cleanup_interval", 300),
        )
        default_cleanup = datetime.now(timezone.utc).isoformat()
        manager._last_cleanup = datetime.fromisoformat(
            data.get("last_cleanup", default_cleanup)
        )

        # Restore sessions
        for session_data in data.get("sessions", {}).values():
            session = Session.from_dict(session_data)
            manager._sessions[session.session_id] = session

        # Restore user sessions mapping
        manager._user_sessions = data.get("user_sessions", {})

        return manager
