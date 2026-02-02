"""
Tests for MCP (Model Context Protocol) integration.

Tests cover:
- MCPSession management and validation
- MCPSessionManager operations
- ToolDefinitionRegistry for shadowing detection
- MCPToolWrapper authorization
- ProxilionMCPServer tool handling
- User context extraction from MCP context
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from proxilion import Proxilion, Policy, UserContext, AgentContext
from proxilion.contrib.mcp import (
    MCPSession,
    MCPSessionManager,
    ToolDefinitionRegistry,
    MCPToolWrapper,
    ProxilionMCPServer,
    extract_user_from_mcp_context,
    create_mcp_tool_handler,
    ToolShadowingError,
    SessionExpiredError,
    InvalidClientError,
)
from proxilion.exceptions import AuthorizationError


class TestMCPSession:
    """Tests for MCPSession dataclass."""

    def test_session_creation(self, basic_user: UserContext):
        """Test creating an MCP session."""
        session = MCPSession(
            session_id="session_123",
            user_context=basic_user,
        )

        assert session.session_id == "session_123"
        assert session.user_context == basic_user
        assert session.agent_context is None
        assert session.created_at is not None
        assert session.expires_at is None

    def test_session_with_expiry(self, basic_user: UserContext):
        """Test session with expiration time."""
        expires = datetime.now(timezone.utc) + timedelta(hours=1)
        session = MCPSession(
            session_id="session_123",
            user_context=basic_user,
            expires_at=expires,
        )

        assert session.expires_at == expires
        assert session.is_expired() is False

    def test_session_expired(self, basic_user: UserContext):
        """Test detecting expired session."""
        expires = datetime.now(timezone.utc) - timedelta(seconds=1)
        session = MCPSession(
            session_id="session_123",
            user_context=basic_user,
            expires_at=expires,
        )

        assert session.is_expired() is True

    def test_session_with_permissions(self, basic_user: UserContext):
        """Test session with specific permissions."""
        session = MCPSession(
            session_id="session_123",
            user_context=basic_user,
            permissions={
                "file_read": ["execute"],
                "file_write": ["execute", "delete"],
            },
        )

        assert session.has_permission("file_read", "execute") is True
        assert session.has_permission("file_write", "delete") is True
        # Permission not in list
        assert session.has_permission("file_read", "delete") is False
        # Resource not restricted
        assert session.has_permission("calculator", "execute") is True

    def test_session_with_agent_context(
        self, basic_user: UserContext, basic_agent: AgentContext
    ):
        """Test session with agent context."""
        session = MCPSession(
            session_id="session_123",
            user_context=basic_user,
            agent_context=basic_agent,
        )

        assert session.agent_context == basic_agent
        assert session.agent_context.agent_id == "agent_001"


class TestMCPSessionManager:
    """Tests for MCPSessionManager class."""

    def test_manager_initialization(self):
        """Test session manager initialization."""
        manager = MCPSessionManager()
        assert manager is not None
        assert manager.default_ttl == 3600.0

    def test_manager_custom_ttl(self):
        """Test session manager with custom TTL."""
        manager = MCPSessionManager(default_ttl=7200.0)
        assert manager.default_ttl == 7200.0

    def test_create_session(self, basic_user: UserContext):
        """Test creating a session."""
        manager = MCPSessionManager()
        session = manager.create_session(basic_user)

        assert session is not None
        assert session.user_context == basic_user
        assert session.session_id is not None

    def test_get_session(self, basic_user: UserContext):
        """Test getting a session by ID."""
        manager = MCPSessionManager()
        created = manager.create_session(basic_user)

        retrieved = manager.get_session(created.session_id)
        assert retrieved is not None
        assert retrieved.session_id == created.session_id

    def test_get_nonexistent_session(self):
        """Test getting a session that doesn't exist."""
        manager = MCPSessionManager()
        session = manager.get_session("nonexistent")
        assert session is None

    def test_validate_session(self, basic_user: UserContext):
        """Test validating a session."""
        manager = MCPSessionManager()
        session = manager.create_session(basic_user)

        assert manager.validate_session(session.session_id) is True
        assert manager.validate_session("nonexistent") is False

    def test_invalidate_session(self, basic_user: UserContext):
        """Test invalidating a session."""
        manager = MCPSessionManager()
        session = manager.create_session(basic_user)

        assert manager.validate_session(session.session_id) is True
        manager.invalidate_session(session.session_id)
        assert manager.validate_session(session.session_id) is False

    def test_session_with_custom_ttl(self, basic_user: UserContext):
        """Test creating session with custom TTL."""
        manager = MCPSessionManager(default_ttl=3600.0)
        session = manager.create_session(basic_user, ttl=60.0)

        assert session.expires_at is not None
        # Should expire in about 60 seconds, not 3600
        time_until_expiry = (session.expires_at - datetime.now(timezone.utc)).total_seconds()
        assert 55 < time_until_expiry < 65

    def test_session_with_no_expiry(self, basic_user: UserContext):
        """Test creating session with no expiry."""
        manager = MCPSessionManager(default_ttl=None)
        session = manager.create_session(basic_user)

        assert session.expires_at is None
        assert session.is_expired() is False


class TestToolDefinitionRegistry:
    """Tests for ToolDefinitionRegistry class."""

    def test_registry_initialization(self):
        """Test registry initialization."""
        registry = ToolDefinitionRegistry()
        assert registry is not None

    def test_register_tool(self):
        """Test registering a tool definition."""
        registry = ToolDefinitionRegistry()
        definition = {
            "name": "file_read",
            "description": "Read a file",
            "input_schema": {"type": "object", "properties": {"path": {"type": "string"}}},
        }

        tool_hash = registry.register_tool("file_read", definition)
        assert tool_hash is not None
        assert len(tool_hash) == 64  # SHA-256 hex

    def test_verify_tool_valid(self):
        """Test verifying a valid tool definition."""
        registry = ToolDefinitionRegistry()
        definition = {
            "name": "file_read",
            "description": "Read a file",
            "input_schema": {"type": "object"},
        }

        registry.register_tool("file_read", definition)

        # Same definition should verify
        assert registry.verify_tool("file_read", definition) is True

    def test_verify_tool_shadowing(self):
        """Test detecting tool shadowing attack."""
        registry = ToolDefinitionRegistry()
        original_def = {
            "name": "file_read",
            "description": "Read a file",
            "input_schema": {"type": "object"},
        }
        malicious_def = {
            "name": "file_read",
            "description": "Read a file (modified)",  # Changed
            "input_schema": {"type": "object"},
        }

        registry.register_tool("file_read", original_def)

        with pytest.raises(ToolShadowingError) as exc:
            registry.verify_tool("file_read", malicious_def)

        assert exc.value.tool_name == "file_read"
        assert exc.value.expected_hash != exc.value.actual_hash

    def test_verify_unregistered_tool(self):
        """Test verifying an unregistered tool."""
        registry = ToolDefinitionRegistry()
        definition = {"name": "unknown_tool"}

        # Unregistered tools are allowed
        assert registry.verify_tool("unknown_tool", definition) is True


class TestMCPToolWrapper:
    """Tests for MCPToolWrapper class."""

    def test_wrapper_initialization(self, proxilion_simple: Proxilion):
        """Test tool wrapper initialization."""
        class MockTool:
            name = "test_tool"
            description = "A test tool"
            input_schema = {"type": "object"}

            async def execute(self, arguments):
                return {"result": "success"}

        wrapper = MCPToolWrapper(
            original_tool=MockTool(),
            proxilion=proxilion_simple,
        )

        assert wrapper.name == "test_tool"
        assert wrapper.description == "A test tool"
        assert wrapper.resource == "test_tool"

    @pytest.mark.asyncio
    async def test_wrapper_execute_with_session(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test executing wrapped tool with session."""
        @proxilion_simple.policy("test_tool")
        class TestToolPolicy(Policy):
            def can_execute(self, context):
                return True

        class MockTool:
            name = "test_tool"
            description = "A test tool"
            input_schema = {"type": "object"}

            async def execute(self, arguments):
                return {"result": arguments.get("input", "default")}

        wrapper = MCPToolWrapper(
            original_tool=MockTool(),
            proxilion=proxilion_simple,
        )

        session = MCPSession(
            session_id="session_123",
            user_context=basic_user,
        )

        result = await wrapper.execute(
            arguments={"input": "test_value"},
            session=session,
        )

        assert result == {"result": "test_value"}

    @pytest.mark.asyncio
    async def test_wrapper_execute_denied(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test that wrapped tool denies unauthorized access."""
        @proxilion_simple.policy("restricted_tool")
        class RestrictedPolicy(Policy):
            def can_execute(self, context):
                return "admin" in self.user.roles

        class MockTool:
            name = "restricted_tool"
            description = "A restricted tool"
            input_schema = {"type": "object"}

            async def execute(self, arguments):
                return {"result": "success"}

        wrapper = MCPToolWrapper(
            original_tool=MockTool(),
            proxilion=proxilion_simple,
            resource="restricted_tool",
        )

        session = MCPSession(
            session_id="session_123",
            user_context=basic_user,  # basic_user doesn't have admin role
        )

        with pytest.raises(AuthorizationError):
            await wrapper.execute(arguments={}, session=session)

    @pytest.mark.asyncio
    async def test_wrapper_execute_expired_session(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test that wrapper rejects expired sessions."""
        class MockTool:
            name = "test_tool"
            async def execute(self, arguments):
                return {"result": "success"}

        wrapper = MCPToolWrapper(
            original_tool=MockTool(),
            proxilion=proxilion_simple,
        )

        expired_session = MCPSession(
            session_id="session_123",
            user_context=basic_user,
            expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        )

        with pytest.raises(SessionExpiredError):
            await wrapper.execute(arguments={}, session=expired_session)

    @pytest.mark.asyncio
    async def test_wrapper_session_permission_check(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test that wrapper checks session-specific permissions."""
        @proxilion_simple.policy("file_write")
        class FileWritePolicy(Policy):
            def can_execute(self, context):
                return True  # Policy allows

        class MockTool:
            name = "file_write"
            async def execute(self, arguments):
                return {"result": "success"}

        wrapper = MCPToolWrapper(
            original_tool=MockTool(),
            proxilion=proxilion_simple,
            resource="file_write",
        )

        # Session restricts to only read permission
        session = MCPSession(
            session_id="session_123",
            user_context=basic_user,
            permissions={"file_write": ["read"]},  # Only read, not execute
        )

        with pytest.raises(AuthorizationError) as exc:
            await wrapper.execute(arguments={}, session=session)

        assert "Session lacks required permission" in str(exc.value)


class TestProxilionMCPServer:
    """Tests for ProxilionMCPServer class."""

    def test_server_initialization(self, proxilion_simple: Proxilion):
        """Test MCP server initialization."""
        class MockServer:
            tools = []

        server = ProxilionMCPServer(
            original_server=MockServer(),
            proxilion=proxilion_simple,
        )

        assert server is not None
        assert server.default_policy == "deny"

    @pytest.mark.asyncio
    async def test_server_handle_tool_call(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test handling a tool call through the server."""
        @proxilion_simple.policy("calculator")
        class CalculatorPolicy(Policy):
            def can_execute(self, context):
                return True

        class CalculatorTool:
            name = "calculator"
            description = "Calculate"
            input_schema = {"type": "object"}

            async def execute(self, arguments):
                a = arguments.get("a", 0)
                b = arguments.get("b", 0)
                return {"result": a + b}

        class MockServer:
            tools = [CalculatorTool()]

        server = ProxilionMCPServer(
            original_server=MockServer(),
            proxilion=proxilion_simple,
            verify_tool_definitions=False,
        )

        session = server.create_session(basic_user)

        result = await server.handle_tool_call(
            tool_name="calculator",
            arguments={"a": 5, "b": 3},
            session=session,
        )

        assert result == {"result": 8}

    @pytest.mark.asyncio
    async def test_server_deny_unknown_tool(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test that server denies unknown tools by default."""
        class MockServer:
            tools = []

        server = ProxilionMCPServer(
            original_server=MockServer(),
            proxilion=proxilion_simple,
            default_policy="deny",
        )

        session = server.create_session(basic_user)

        with pytest.raises(AuthorizationError) as exc:
            await server.handle_tool_call(
                tool_name="unknown_tool",
                arguments={},
                session=session,
            )

        assert "not found" in str(exc.value)

    def test_server_create_session(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test creating a session through the server."""
        class MockServer:
            tools = []

        server = ProxilionMCPServer(
            original_server=MockServer(),
            proxilion=proxilion_simple,
        )

        session = server.create_session(basic_user)
        assert session is not None
        assert session.user_context == basic_user


class TestExtractUserFromMCPContext:
    """Tests for extract_user_from_mcp_context function."""

    def test_extract_basic_user(self):
        """Test extracting basic user context."""
        mcp_context = {
            "user_id": "alice",
            "roles": ["user", "analyst"],
            "session_id": "session_123",
        }

        user = extract_user_from_mcp_context(mcp_context)

        assert user.user_id == "alice"
        assert "user" in user.roles
        assert "analyst" in user.roles
        assert user.session_id == "session_123"

    def test_extract_with_attributes(self):
        """Test extracting user with additional attributes."""
        mcp_context = {
            "user_id": "alice",
            "roles": ["user"],
            "department": "engineering",
            "clearance": "high",
        }

        user = extract_user_from_mcp_context(mcp_context)

        assert user.attributes["department"] == "engineering"
        assert user.attributes["clearance"] == "high"

    def test_extract_roles_as_string(self):
        """Test extracting when roles is a single string."""
        mcp_context = {
            "user_id": "alice",
            "roles": "admin",  # String instead of list
        }

        user = extract_user_from_mcp_context(mcp_context)

        assert user.roles == ["admin"]

    def test_extract_missing_user_id(self):
        """Test that missing user_id raises error."""
        mcp_context = {
            "roles": ["user"],
        }

        with pytest.raises(InvalidClientError) as exc:
            extract_user_from_mcp_context(mcp_context)

        assert "user_id" in str(exc.value)

    def test_extract_custom_field_names(self):
        """Test extracting with custom field names."""
        mcp_context = {
            "uid": "alice",
            "permissions": ["admin"],
            "sid": "session_123",
        }

        user = extract_user_from_mcp_context(
            mcp_context,
            user_id_field="uid",
            roles_field="permissions",
            session_id_field="sid",
        )

        assert user.user_id == "alice"
        assert user.roles == ["admin"]
        assert user.session_id == "session_123"


class TestCreateMCPToolHandler:
    """Tests for create_mcp_tool_handler function."""

    @pytest.mark.asyncio
    async def test_create_handler(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test creating a tool handler function."""
        @proxilion_simple.policy("test_tool")
        class TestToolPolicy(Policy):
            def can_execute(self, context):
                return True

        class TestTool:
            name = "test_tool"
            description = "Test"
            input_schema = {}

            async def execute(self, arguments):
                return {"result": "handled"}

        handler = create_mcp_tool_handler(
            proxilion=proxilion_simple,
            tools=[TestTool()],
        )

        session = MCPSession(
            session_id="session_123",
            user_context=basic_user,
        )

        result = await handler("test_tool", {}, session)
        assert result == {"result": "handled"}

    @pytest.mark.asyncio
    async def test_handler_unknown_tool(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test handler with unknown tool."""
        handler = create_mcp_tool_handler(
            proxilion=proxilion_simple,
            tools=[],
        )

        session = MCPSession(
            session_id="session_123",
            user_context=basic_user,
        )

        with pytest.raises(AuthorizationError) as exc:
            await handler("unknown_tool", {}, session)

        assert "Unknown tool" in str(exc.value)
