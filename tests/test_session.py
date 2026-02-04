"""Tests for session management."""

from __future__ import annotations

import threading
import time

import pytest

from proxilion.context.message_history import MessageRole
from proxilion.context.session import (
    Session,
    SessionConfig,
    SessionManager,
    SessionState,
)
from proxilion.types import UserContext


class TestSessionConfig:
    """Tests for SessionConfig dataclass."""

    def test_default_config(self):
        """Test default configuration values."""
        config = SessionConfig()
        assert config.max_duration == 3600
        assert config.max_idle_time == 900
        assert config.max_messages == 100
        assert config.max_tokens is None
        assert config.auto_cleanup is True

    def test_custom_config(self):
        """Test custom configuration."""
        config = SessionConfig(
            max_duration=7200,
            max_idle_time=1800,
            max_messages=500,
            max_tokens=10000,
        )
        assert config.max_duration == 7200
        assert config.max_idle_time == 1800
        assert config.max_messages == 500
        assert config.max_tokens == 10000

    def test_to_dict(self):
        """Serialize config to dict."""
        config = SessionConfig(max_duration=1800)
        data = config.to_dict()
        assert data["max_duration"] == 1800

    def test_from_dict(self):
        """Deserialize config from dict."""
        data = {"max_duration": 3600, "max_messages": 200}
        config = SessionConfig.from_dict(data)
        assert config.max_duration == 3600
        assert config.max_messages == 200


class TestSession:
    """Tests for Session class."""

    @pytest.fixture
    def user(self) -> UserContext:
        """Create test user."""
        return UserContext(user_id="test_user", roles=["user"])

    @pytest.fixture
    def config(self) -> SessionConfig:
        """Create test config."""
        return SessionConfig(max_messages=100)

    def test_create_session(self, user: UserContext, config: SessionConfig):
        """Create a basic session."""
        session = Session(
            session_id="sess_123",
            user=user,
            config=config,
        )
        assert session.session_id == "sess_123"
        assert session.user == user
        assert session.state == SessionState.ACTIVE
        assert len(session.history) == 0

    def test_add_message(self, user: UserContext, config: SessionConfig):
        """Add message to session."""
        session = Session(session_id="sess_123", user=user, config=config)

        msg = session.add_message(MessageRole.USER, "Hello!")
        assert msg.content == "Hello!"
        assert len(session.history) == 1

    def test_add_message_with_metadata(self, user: UserContext, config: SessionConfig):
        """Add message with metadata."""
        session = Session(session_id="sess_123", user=user, config=config)

        msg = session.add_message(
            MessageRole.TOOL_CALL,
            "Searching...",
            metadata={"tool": "search"},
        )
        assert msg.metadata["tool"] == "search"

    def test_cannot_add_to_expired_session(self, user: UserContext):
        """Cannot add messages to expired session."""
        config = SessionConfig(max_duration=0)  # Immediately expires
        session = Session(session_id="sess_123", user=user, config=config)
        session.is_expired()  # Force state update

        with pytest.raises(ValueError, match="Cannot add message"):
            session.add_message(MessageRole.USER, "Hello!")

    def test_cannot_add_to_terminated_session(self, user: UserContext, config: SessionConfig):
        """Cannot add messages to terminated session."""
        session = Session(session_id="sess_123", user=user, config=config)
        session.terminate("Test termination")

        with pytest.raises(ValueError, match="Cannot add message"):
            session.add_message(MessageRole.USER, "Hello!")

    def test_get_messages(self, user: UserContext, config: SessionConfig):
        """Get messages from session."""
        session = Session(session_id="sess_123", user=user, config=config)
        session.add_message(MessageRole.USER, "Message 1")
        session.add_message(MessageRole.USER, "Message 2")
        session.add_message(MessageRole.USER, "Message 3")

        all_msgs = session.get_messages()
        assert len(all_msgs) == 3

        limited = session.get_messages(limit=2)
        assert len(limited) == 2
        assert limited[0].content == "Message 2"

    def test_get_context_for_llm(self, user: UserContext, config: SessionConfig):
        """Get LLM context from session."""
        session = Session(session_id="sess_123", user=user, config=config)
        session.add_message(MessageRole.SYSTEM, "You are helpful.")
        session.add_message(MessageRole.USER, "Hello")
        session.add_message(MessageRole.ASSISTANT, "Hi!")

        context = session.get_context_for_llm()
        assert len(context) == 3
        assert context[0]["role"] == "system"

    def test_get_context_for_llm_with_max_tokens(self, user: UserContext, config: SessionConfig):
        """Get truncated LLM context."""
        session = Session(session_id="sess_123", user=user, config=config)
        for i in range(20):
            session.add_message(MessageRole.USER, f"Message {i} with some content")

        # With a small token limit, should get fewer messages
        context = session.get_context_for_llm(max_tokens=50)
        full_context = session.get_context_for_llm()
        assert len(context) <= len(full_context)

    def test_metadata_operations(self, user: UserContext, config: SessionConfig):
        """Test metadata get/set."""
        session = Session(session_id="sess_123", user=user, config=config)

        session.set_metadata("agent", "gpt-4")
        assert session.get_metadata("agent") == "gpt-4"
        assert session.get_metadata("missing") is None
        assert session.get_metadata("missing", "default") == "default"

    def test_touch_updates_activity(self, user: UserContext, config: SessionConfig):
        """Touch updates last activity time."""
        session = Session(session_id="sess_123", user=user, config=config)
        original_time = session.last_activity

        time.sleep(0.01)
        session.touch()

        assert session.last_activity > original_time

    def test_expiration_by_duration(self, user: UserContext):
        """Session expires after max duration."""
        config = SessionConfig(max_duration=0)  # Immediate expiration
        session = Session(session_id="sess_123", user=user, config=config)

        assert session.is_expired() is True
        assert session.state == SessionState.EXPIRED

    def test_expiration_by_idle(self, user: UserContext):
        """Session expires after idle time."""
        config = SessionConfig(max_duration=None, max_idle_time=0)
        session = Session(session_id="sess_123", user=user, config=config)

        assert session.is_expired() is True

    def test_no_expiration_when_unlimited(self, user: UserContext):
        """Session doesn't expire with no limits."""
        config = SessionConfig(max_duration=None, max_idle_time=None)
        session = Session(session_id="sess_123", user=user, config=config)

        assert session.is_expired() is False
        assert session.state == SessionState.ACTIVE

    def test_terminate_session(self, user: UserContext, config: SessionConfig):
        """Terminate session with reason."""
        session = Session(session_id="sess_123", user=user, config=config)
        session.terminate("User logged out")

        assert session.state == SessionState.TERMINATED
        assert session.termination_reason == "User logged out"

    def test_get_duration(self, user: UserContext, config: SessionConfig):
        """Get session duration."""
        session = Session(session_id="sess_123", user=user, config=config)
        time.sleep(0.01)

        duration = session.get_duration()
        assert duration > 0

    def test_get_idle_time(self, user: UserContext, config: SessionConfig):
        """Get idle time."""
        session = Session(session_id="sess_123", user=user, config=config)
        time.sleep(0.01)

        idle_time = session.get_idle_time()
        assert idle_time > 0

    def test_get_remaining_duration(self, user: UserContext):
        """Get remaining duration."""
        config = SessionConfig(max_duration=3600)
        session = Session(session_id="sess_123", user=user, config=config)

        remaining = session.get_remaining_duration()
        assert remaining is not None
        assert remaining <= 3600

    def test_remaining_duration_none_when_unlimited(self, user: UserContext):
        """Remaining duration is None when unlimited."""
        config = SessionConfig(max_duration=None)
        session = Session(session_id="sess_123", user=user, config=config)

        assert session.get_remaining_duration() is None


class TestSessionSerialization:
    """Tests for session serialization."""

    @pytest.fixture
    def user(self) -> UserContext:
        return UserContext(user_id="test_user", roles=["admin"])

    def test_to_dict(self, user: UserContext):
        """Serialize session to dict."""
        config = SessionConfig(max_messages=50)
        session = Session(
            session_id="sess_123",
            user=user,
            config=config,
            metadata={"key": "value"},
        )
        session.add_message(MessageRole.USER, "Hello")

        data = session.to_dict()
        assert data["session_id"] == "sess_123"
        assert data["user_id"] == "test_user"
        assert data["metadata"]["key"] == "value"
        assert len(data["history"]["messages"]) == 1

    def test_from_dict(self, user: UserContext):
        """Deserialize session from dict."""
        config = SessionConfig(max_messages=50)
        original = Session(
            session_id="sess_123",
            user=user,
            config=config,
        )
        original.add_message(MessageRole.USER, "Test message")
        original.set_metadata("agent", "test")

        data = original.to_dict()
        restored = Session.from_dict(data)

        assert restored.session_id == "sess_123"
        assert restored.user.user_id == "test_user"
        assert len(restored.history) == 1
        assert restored.metadata["agent"] == "test"

    def test_round_trip_preserves_state(self, user: UserContext):
        """Full round-trip preserves session state."""
        config = SessionConfig()
        original = Session(session_id="sess_xyz", user=user, config=config)
        original.add_message(MessageRole.SYSTEM, "System prompt")
        original.add_message(MessageRole.USER, "Hello")
        original.add_message(MessageRole.ASSISTANT, "Hi!")

        data = original.to_dict()
        restored = Session.from_dict(data)

        assert len(restored.history) == 3
        messages = restored.get_messages()
        assert messages[0].content == "System prompt"
        assert messages[1].content == "Hello"


class TestSessionManager:
    """Tests for SessionManager class."""

    @pytest.fixture
    def manager(self) -> SessionManager:
        return SessionManager(SessionConfig(max_duration=3600))

    @pytest.fixture
    def user(self) -> UserContext:
        return UserContext(user_id="test_user", roles=["user"])

    def test_create_session(self, manager: SessionManager, user: UserContext):
        """Create a new session."""
        session = manager.create_session(user)
        assert session is not None
        assert session.user == user
        assert session.state == SessionState.ACTIVE

    def test_create_session_with_id(self, manager: SessionManager, user: UserContext):
        """Create session with specific ID."""
        session = manager.create_session(user, session_id="custom_id")
        assert session.session_id == "custom_id"

    def test_create_session_with_metadata(self, manager: SessionManager, user: UserContext):
        """Create session with initial metadata."""
        metadata = {"agent": "gpt-4", "client": "web"}
        session = manager.create_session(user, metadata=metadata)
        assert session.metadata == metadata

    def test_get_session(self, manager: SessionManager, user: UserContext):
        """Get session by ID."""
        session = manager.create_session(user, session_id="sess_123")
        retrieved = manager.get_session("sess_123")
        assert retrieved is not None
        assert retrieved.session_id == session.session_id

    def test_get_session_not_found(self, manager: SessionManager):
        """Get non-existent session returns None."""
        result = manager.get_session("non_existent")
        assert result is None

    def test_get_expired_session_returns_none(self, user: UserContext):
        """Get expired session returns None."""
        config = SessionConfig(max_duration=0)
        manager = SessionManager(config)
        _session = manager.create_session(user, session_id="sess_123")

        # Session immediately expires
        result = manager.get_session("sess_123")
        assert result is None

    def test_get_user_sessions(self, manager: SessionManager, user: UserContext):
        """Get all sessions for a user."""
        manager.create_session(user, session_id="sess_1")
        manager.create_session(user, session_id="sess_2")

        sessions = manager.get_user_sessions(user.user_id)
        assert len(sessions) == 2

    def test_get_user_sessions_filters_expired(self, user: UserContext):
        """Get user sessions filters out expired by default."""
        config = SessionConfig(max_duration=0)
        manager = SessionManager(config)
        manager.create_session(user)

        sessions = manager.get_user_sessions(user.user_id)
        assert len(sessions) == 0

    def test_get_user_sessions_include_expired(self, user: UserContext):
        """Get user sessions can include expired."""
        config = SessionConfig(max_duration=0)
        manager = SessionManager(config)
        manager.create_session(user)

        sessions = manager.get_user_sessions(user.user_id, include_expired=True)
        assert len(sessions) == 1

    def test_get_or_create_session_creates(self, manager: SessionManager, user: UserContext):
        """Get or create creates new session."""
        session, created = manager.get_or_create_session(user, session_id="new_sess")
        assert created is True
        assert session.session_id == "new_sess"

    def test_get_or_create_session_gets_existing(self, manager: SessionManager, user: UserContext):
        """Get or create returns existing session."""
        original = manager.create_session(user, session_id="existing")
        session, created = manager.get_or_create_session(user, session_id="existing")
        assert created is False
        assert session.session_id == original.session_id

    def test_terminate_session(self, manager: SessionManager, user: UserContext):
        """Terminate a session."""
        session = manager.create_session(user, session_id="sess_123")
        result = manager.terminate_session("sess_123", "Manual termination")

        assert result is True
        assert session.state == SessionState.TERMINATED

    def test_terminate_session_not_found(self, manager: SessionManager):
        """Terminate non-existent session returns False."""
        result = manager.terminate_session("non_existent")
        assert result is False

    def test_terminate_user_sessions(self, manager: SessionManager, user: UserContext):
        """Terminate all sessions for a user."""
        manager.create_session(user, session_id="sess_1")
        manager.create_session(user, session_id="sess_2")

        count = manager.terminate_user_sessions(user.user_id)
        assert count == 2

    def test_cleanup_expired(self, user: UserContext):
        """Cleanup removes expired sessions."""
        config = SessionConfig(max_duration=0, auto_cleanup=False)
        manager = SessionManager(config, cleanup_interval=0)

        manager.create_session(user, session_id="sess_1")
        manager.create_session(user, session_id="sess_2")

        count = manager.cleanup_expired()
        assert count == 2
        assert manager.get_total_count() == 0

    def test_get_active_count(self, manager: SessionManager, user: UserContext):
        """Get active session count."""
        manager.create_session(user, session_id="sess_1")
        manager.create_session(user, session_id="sess_2")

        assert manager.get_active_count() == 2

    def test_get_total_count(self, manager: SessionManager, user: UserContext):
        """Get total session count."""
        manager.create_session(user, session_id="sess_1")
        manager.create_session(user, session_id="sess_2")

        assert manager.get_total_count() == 2

    def test_get_user_count(self, manager: SessionManager):
        """Get unique user count."""
        user1 = UserContext(user_id="user_1", roles=[])
        user2 = UserContext(user_id="user_2", roles=[])

        manager.create_session(user1)
        manager.create_session(user1)
        manager.create_session(user2)

        assert manager.get_user_count() == 2

    def test_get_stats(self, manager: SessionManager, user: UserContext):
        """Get session statistics."""
        manager.create_session(user)
        manager.create_session(user)

        stats = manager.get_stats()
        assert stats["total"] == 2
        assert stats["active"] == 2
        assert stats["unique_users"] == 1

    def test_multiple_users(self, manager: SessionManager):
        """Manage sessions for multiple users."""
        user1 = UserContext(user_id="alice", roles=["admin"])
        user2 = UserContext(user_id="bob", roles=["user"])

        _s1 = manager.create_session(user1)
        _s2 = manager.create_session(user2)
        _s3 = manager.create_session(user1)

        alice_sessions = manager.get_user_sessions("alice")
        bob_sessions = manager.get_user_sessions("bob")

        assert len(alice_sessions) == 2
        assert len(bob_sessions) == 1


class TestSessionManagerSerialization:
    """Tests for SessionManager serialization."""

    def test_to_dict(self):
        """Serialize manager to dict."""
        config = SessionConfig(max_duration=1800)
        manager = SessionManager(config)
        user = UserContext(user_id="test", roles=[])

        manager.create_session(user, session_id="sess_1")
        manager.create_session(user, session_id="sess_2")

        data = manager.to_dict()
        assert data["config"]["max_duration"] == 1800
        assert len(data["sessions"]) == 2

    def test_from_dict(self):
        """Deserialize manager from dict."""
        config = SessionConfig(max_duration=1800)
        original = SessionManager(config)
        user = UserContext(user_id="test", roles=[])

        session = original.create_session(user, session_id="sess_1")
        session.add_message(MessageRole.USER, "Hello")

        data = original.to_dict()
        restored = SessionManager.from_dict(data)

        assert restored.config.max_duration == 1800
        assert restored.get_total_count() == 1

        # Note: restored sessions may be expired depending on timing
        restored_session = restored._sessions.get("sess_1")
        assert restored_session is not None
        assert len(restored_session.history) == 1


class TestSessionManagerThreadSafety:
    """Tests for thread safety."""

    def test_concurrent_session_creation(self):
        """Concurrent session creation should be thread-safe."""
        manager = SessionManager()
        user = UserContext(user_id="test", roles=[])
        errors = []

        def create_sessions():
            for _ in range(50):
                try:
                    manager.create_session(user)
                except Exception as e:
                    errors.append(e)

        threads = [threading.Thread(target=create_sessions) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert manager.get_total_count() == 250

    def test_concurrent_session_access(self):
        """Concurrent session access should be thread-safe."""
        manager = SessionManager()
        user = UserContext(user_id="test", roles=[])
        _session = manager.create_session(user, session_id="shared")
        errors = []

        def access_session():
            for i in range(50):
                try:
                    s = manager.get_session("shared")
                    if s:
                        s.add_message(MessageRole.USER, f"Message {i}")
                        _ = s.get_messages()
                except Exception as e:
                    errors.append(e)

        threads = [threading.Thread(target=access_session) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
