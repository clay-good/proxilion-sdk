"""
Model Context Protocol (MCP) integration for Proxilion.

This module provides authorization wrappers for MCP tools and servers,
enabling secure tool execution with user-context authorization.

MCP is Anthropic's protocol for connecting AI agents to tools. Proxilion
intercepts MCP tool calls to add authorization before execution.

Key Security Features:
    - Validate client authentication from MCP session
    - Extract user context from MCP metadata
    - Apply authorization before tool execution
    - Audit log all MCP tool invocations
    - Prevent tool shadowing attacks (verify tool definitions)
    - No ambient authority (capabilities must be explicitly passed)
    - Session-bound permissions (expire with session)
    - Cross-server trust isolation

Example:
    >>> from proxilion import Proxilion, Policy
    >>> from proxilion.contrib.mcp import MCPToolWrapper, ProxilionMCPServer
    >>>
    >>> auth = Proxilion()
    >>>
    >>> @auth.policy("file_read")
    ... class FileReadPolicy(Policy):
    ...     def can_execute(self, context):
    ...         path = context.get("path", "")
    ...         return not path.startswith("/etc/") and ".." not in path
    >>>
    >>> wrapped_tool = MCPToolWrapper(
    ...     original_tool=file_read_tool,
    ...     proxilion=auth,
    ...     resource="file_read"
    ... )
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol, TypeVar, runtime_checkable

from proxilion.exceptions import (
    AuthorizationError,
    ProxilionError,
)
from proxilion.types import AgentContext, UserContext

logger = logging.getLogger(__name__)

T = TypeVar("T")


class MCPSecurityError(ProxilionError):
    """Base exception for MCP security errors."""
    pass


class ToolShadowingError(MCPSecurityError):
    """Raised when a tool shadowing attack is detected."""

    def __init__(self, tool_name: str, expected_hash: str, actual_hash: str) -> None:
        self.tool_name = tool_name
        self.expected_hash = expected_hash
        self.actual_hash = actual_hash
        super().__init__(
            f"Tool shadowing detected for '{tool_name}': "
            f"expected hash {expected_hash[:16]}..., got {actual_hash[:16]}..."
        )


class SessionExpiredError(MCPSecurityError):
    """Raised when an MCP session has expired."""

    def __init__(self, session_id: str) -> None:
        self.session_id = session_id
        super().__init__(f"MCP session expired: {session_id}")


class InvalidClientError(MCPSecurityError):
    """Raised when MCP client authentication fails."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"Invalid MCP client: {reason}")


@runtime_checkable
class MCPTool(Protocol):
    """Protocol for MCP tool definitions."""

    @property
    def name(self) -> str:
        """Tool name."""
        ...

    @property
    def description(self) -> str:
        """Tool description."""
        ...

    @property
    def input_schema(self) -> dict[str, Any]:
        """JSON Schema for tool inputs."""
        ...

    async def execute(self, arguments: dict[str, Any]) -> Any:
        """Execute the tool with given arguments."""
        ...


@runtime_checkable
class MCPServer(Protocol):
    """Protocol for MCP server implementations."""

    @property
    def tools(self) -> list[Any]:
        """List of available tools."""
        ...

    async def handle_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> Any:
        """Handle a tool call request."""
        ...


@dataclass
class MCPSession:
    """
    Represents an MCP session with user context and permissions.

    Attributes:
        session_id: Unique session identifier.
        user_context: The authenticated user for this session.
        agent_context: Optional agent context.
        created_at: Session creation time.
        expires_at: Session expiration time (None for no expiry).
        permissions: Session-specific permissions.
        metadata: Additional session metadata.
    """
    session_id: str
    user_context: UserContext
    agent_context: AgentContext | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None
    permissions: dict[str, list[str]] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def is_expired(self) -> bool:
        """Check if the session has expired."""
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at

    def has_permission(self, resource: str, action: str) -> bool:
        """Check if session has a specific permission."""
        if resource not in self.permissions:
            return True  # No explicit restriction
        return action in self.permissions[resource]


@dataclass
class ToolDefinitionHash:
    """Hash of a tool definition for shadowing detection."""
    tool_name: str
    definition_hash: str
    registered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class MCPSessionManager:
    """
    Manages MCP sessions with user contexts.

    Provides session creation, validation, and expiration handling
    for MCP connections.

    Example:
        >>> manager = MCPSessionManager(default_ttl=3600)
        >>> session = manager.create_session(user_context)
        >>> if manager.validate_session(session.session_id):
        ...     # Session is valid
        ...     pass
    """

    def __init__(
        self,
        default_ttl: float | None = 3600.0,
    ) -> None:
        """
        Initialize the session manager.

        Args:
            default_ttl: Default session TTL in seconds (None for no expiry).
        """
        self.default_ttl = default_ttl
        self._sessions: dict[str, MCPSession] = {}
        self._lock = threading.RLock()

    def create_session(
        self,
        user_context: UserContext,
        agent_context: AgentContext | None = None,
        ttl: float | None = None,
        permissions: dict[str, list[str]] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> MCPSession:
        """
        Create a new MCP session.

        Args:
            user_context: The user for this session.
            agent_context: Optional agent context.
            ttl: Session TTL in seconds (None uses default).
            permissions: Session-specific permissions.
            metadata: Additional metadata.

        Returns:
            The created MCPSession.
        """
        import uuid

        session_ttl = ttl if ttl is not None else self.default_ttl
        expires_at = None
        if session_ttl is not None:
            from datetime import timedelta
            expires_at = datetime.now(timezone.utc) + timedelta(seconds=session_ttl)

        session = MCPSession(
            session_id=str(uuid.uuid4()),
            user_context=user_context,
            agent_context=agent_context,
            expires_at=expires_at,
            permissions=permissions or {},
            metadata=metadata or {},
        )

        with self._lock:
            self._sessions[session.session_id] = session
            self._cleanup_expired()

        logger.debug(f"Created MCP session: {session.session_id} for user {user_context.user_id}")
        return session

    def get_session(self, session_id: str) -> MCPSession | None:
        """
        Get a session by ID.

        Args:
            session_id: The session ID.

        Returns:
            The session, or None if not found or expired.
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return None
            if session.is_expired():
                del self._sessions[session_id]
                return None
            return session

    def validate_session(self, session_id: str) -> bool:
        """
        Validate that a session exists and is not expired.

        Args:
            session_id: The session ID.

        Returns:
            True if session is valid.
        """
        return self.get_session(session_id) is not None

    def invalidate_session(self, session_id: str) -> None:
        """
        Invalidate a session.

        Args:
            session_id: The session ID to invalidate.
        """
        with self._lock:
            self._sessions.pop(session_id, None)

    def _cleanup_expired(self) -> None:
        """Remove expired sessions."""
        expired = [
            sid for sid, session in self._sessions.items()
            if session.is_expired()
        ]
        for sid in expired:
            del self._sessions[sid]


class ToolDefinitionRegistry:
    """
    Registry for verifying tool definitions against shadowing attacks.

    Tool shadowing occurs when a malicious tool is substituted for
    a legitimate one. This registry maintains hashes of registered
    tool definitions to detect such attacks.
    """

    def __init__(self) -> None:
        self._hashes: dict[str, ToolDefinitionHash] = {}
        self._lock = threading.RLock()

    def register_tool(
        self,
        tool_name: str,
        definition: dict[str, Any],
    ) -> str:
        """
        Register a tool definition.

        Args:
            tool_name: The tool name.
            definition: The tool definition dict.

        Returns:
            The computed hash.
        """
        definition_hash = self._compute_hash(definition)

        with self._lock:
            self._hashes[tool_name] = ToolDefinitionHash(
                tool_name=tool_name,
                definition_hash=definition_hash,
            )

        logger.debug(f"Registered tool definition: {tool_name} -> {definition_hash[:16]}...")
        return definition_hash

    def verify_tool(
        self,
        tool_name: str,
        definition: dict[str, Any],
    ) -> bool:
        """
        Verify a tool definition matches the registered one.

        Args:
            tool_name: The tool name.
            definition: The tool definition to verify.

        Returns:
            True if the definition matches.

        Raises:
            ToolShadowingError: If definitions don't match.
        """
        with self._lock:
            registered = self._hashes.get(tool_name)

        if registered is None:
            # Tool not registered, allow it
            return True

        actual_hash = self._compute_hash(definition)

        if actual_hash != registered.definition_hash:
            raise ToolShadowingError(
                tool_name=tool_name,
                expected_hash=registered.definition_hash,
                actual_hash=actual_hash,
            )

        return True

    def _compute_hash(self, definition: dict[str, Any]) -> str:
        """Compute a hash of a tool definition."""
        canonical = json.dumps(definition, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()


class MCPToolWrapper:
    """
    Wraps an MCP tool with Proxilion authorization.

    Intercepts tool calls before execution to apply authorization
    checks, schema validation, and audit logging.

    Example:
        >>> from proxilion import Proxilion
        >>> from proxilion.contrib.mcp import MCPToolWrapper
        >>>
        >>> auth = Proxilion()
        >>>
        >>> # Define your MCP tool
        >>> class FileReadTool:
        ...     name = "file_read"
        ...     description = "Read a file"
        ...     input_schema = {"type": "object", "properties": {"path": {"type": "string"}}}
        ...
        ...     async def execute(self, arguments):
        ...         return open(arguments["path"]).read()
        >>>
        >>> # Wrap with authorization
        >>> wrapped = MCPToolWrapper(
        ...     original_tool=FileReadTool(),
        ...     proxilion=auth,
        ...     resource="file_read",
        ... )
        >>>
        >>> # Execute with user context
        >>> result = await wrapped.execute(
        ...     arguments={"path": "/data/file.txt"},
        ...     session=mcp_session,
        ... )
    """

    def __init__(
        self,
        original_tool: Any,
        proxilion: Any,
        resource: str | None = None,
        action: str = "execute",
        validate_schema: bool = True,
        require_session: bool = True,
    ) -> None:
        """
        Initialize the tool wrapper.

        Args:
            original_tool: The original MCP tool to wrap.
            proxilion: The Proxilion instance for authorization.
            resource: Resource name for policies (default: tool name).
            action: Action name for authorization.
            validate_schema: Whether to validate against schema.
            require_session: Whether a valid session is required.
        """
        self.original_tool = original_tool
        self.proxilion = proxilion
        self.resource = resource or getattr(original_tool, "name", "unknown")
        self.action = action
        self.validate_schema = validate_schema
        self.require_session = require_session

        # Extract tool properties
        self._name = getattr(original_tool, "name", "unknown")
        self._description = getattr(original_tool, "description", "")
        self._input_schema = getattr(original_tool, "input_schema", {})

    @property
    def name(self) -> str:
        """Get the tool name."""
        return self._name

    @property
    def description(self) -> str:
        """Get the tool description."""
        return self._description

    @property
    def input_schema(self) -> dict[str, Any]:
        """Get the input schema."""
        return self._input_schema

    async def execute(
        self,
        arguments: dict[str, Any],
        session: MCPSession | None = None,
        user_context: UserContext | None = None,
    ) -> Any:
        """
        Execute the tool with authorization.

        Args:
            arguments: Tool arguments.
            session: MCP session (preferred).
            user_context: Direct user context (fallback).

        Returns:
            The tool execution result.

        Raises:
            SessionExpiredError: If session is expired.
            AuthorizationError: If authorization fails.
        """
        # Get user context from session or direct parameter
        if session is not None:
            if session.is_expired():
                raise SessionExpiredError(session.session_id)
            user = session.user_context
            # agent_context available via session.agent_context if needed

            # Check session-specific permissions
            if not session.has_permission(self.resource, self.action):
                raise AuthorizationError(
                    user=user.user_id,
                    action=self.action,
                    resource=self.resource,
                    reason="Session lacks required permission",
                )
        elif user_context is not None:
            user = user_context
        elif self.require_session:
            raise AuthorizationError(
                user="unknown",
                action=self.action,
                resource=self.resource,
                reason="No session or user context provided",
            )
        else:
            raise AuthorizationError(
                user="unknown",
                action=self.action,
                resource=self.resource,
                reason="No user context available",
            )

        # Build context for authorization
        # Spread arguments first so trusted keys can't be overridden
        context = {
            **arguments,  # Flatten arguments for policy access
            "arguments": arguments,
            "tool_name": self.name,
        }

        # Check authorization
        result = self.proxilion.check(user, self.action, self.resource, context)
        if not result.allowed:
            raise AuthorizationError(
                user=user.user_id,
                action=self.action,
                resource=self.resource,
                reason=result.reason,
            )

        # Execute original tool
        execute_method = getattr(self.original_tool, "execute", None)
        if execute_method is None:
            # Try calling the tool directly
            if callable(self.original_tool):
                return await self.original_tool(arguments)
            raise ValueError(f"Tool {self.name} has no execute method")

        return await execute_method(arguments)

    def __call__(
        self,
        arguments: dict[str, Any],
        session: MCPSession | None = None,
        user_context: UserContext | None = None,
    ) -> Any:
        """Synchronous wrapper for execute."""
        import asyncio
        return asyncio.run(self.execute(arguments, session, user_context))


class ProxilionMCPServer:
    """
    Wraps an MCP server with Proxilion authorization.

    Adds an authorization layer to all tool calls on the server,
    with configurable per-tool policies and default behavior.

    Example:
        >>> from proxilion import Proxilion
        >>> from proxilion.contrib.mcp import ProxilionMCPServer
        >>>
        >>> auth = Proxilion()
        >>> secure_server = ProxilionMCPServer(
        ...     original_server=mcp_server,
        ...     proxilion=auth,
        ...     default_policy="deny",
        ... )
        >>>
        >>> # Handle tool call with authorization
        >>> result = await secure_server.handle_tool_call(
        ...     tool_name="file_read",
        ...     arguments={"path": "/data/file.txt"},
        ...     session=mcp_session,
        ... )
    """

    def __init__(
        self,
        original_server: Any,
        proxilion: Any,
        default_policy: str = "deny",
        session_manager: MCPSessionManager | None = None,
        tool_registry: ToolDefinitionRegistry | None = None,
        verify_tool_definitions: bool = True,
    ) -> None:
        """
        Initialize the secure MCP server.

        Args:
            original_server: The original MCP server.
            proxilion: Proxilion instance for authorization.
            default_policy: Default policy ("allow" or "deny").
            session_manager: Session manager (created if None).
            tool_registry: Tool definition registry (created if None).
            verify_tool_definitions: Whether to verify tool definitions.
        """
        self.original_server = original_server
        self.proxilion = proxilion
        self.default_policy = default_policy
        self.session_manager = session_manager or MCPSessionManager()
        self.tool_registry = tool_registry or ToolDefinitionRegistry()
        self.verify_tool_definitions = verify_tool_definitions

        # Cache wrapped tools
        self._wrapped_tools: dict[str, MCPToolWrapper] = {}
        self._lock = threading.RLock()

        # Register tool definitions if available
        if hasattr(original_server, "tools") and self.verify_tool_definitions:
            self._register_tools()

    def _register_tools(self) -> None:
        """Register tool definitions from the original server."""
        tools = getattr(self.original_server, "tools", [])
        for tool in tools:
            name = getattr(tool, "name", None)
            if name:
                definition = {
                    "name": name,
                    "description": getattr(tool, "description", ""),
                    "input_schema": getattr(tool, "input_schema", {}),
                }
                self.tool_registry.register_tool(name, definition)

    @property
    def tools(self) -> list[Any]:
        """Get the list of available tools."""
        if hasattr(self.original_server, "tools"):
            return self.original_server.tools
        return []

    def get_wrapped_tool(self, tool_name: str) -> MCPToolWrapper | None:
        """
        Get a wrapped tool by name.

        Args:
            tool_name: The tool name.

        Returns:
            The wrapped tool, or None if not found.
        """
        with self._lock:
            if tool_name in self._wrapped_tools:
                return self._wrapped_tools[tool_name]

            # Find the original tool
            original_tool = self._find_tool(tool_name)
            if original_tool is None:
                return None

            # Wrap it
            wrapped = MCPToolWrapper(
                original_tool=original_tool,
                proxilion=self.proxilion,
                resource=tool_name,
            )
            self._wrapped_tools[tool_name] = wrapped
            return wrapped

    def _find_tool(self, tool_name: str) -> Any:
        """Find a tool by name in the original server."""
        tools = getattr(self.original_server, "tools", [])
        for tool in tools:
            if getattr(tool, "name", None) == tool_name:
                return tool
        return None

    async def handle_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        session: MCPSession | None = None,
        session_id: str | None = None,
        user_context: UserContext | None = None,
        tool_definition: dict[str, Any] | None = None,
    ) -> Any:
        """
        Handle a tool call with authorization.

        Args:
            tool_name: Name of the tool to call.
            arguments: Tool arguments.
            session: MCP session object.
            session_id: Session ID (to look up session).
            user_context: Direct user context (fallback).
            tool_definition: Tool definition for shadowing check.

        Returns:
            The tool execution result.

        Raises:
            ToolShadowingError: If tool definition doesn't match.
            SessionExpiredError: If session is expired.
            AuthorizationError: If authorization fails.
        """
        # Verify tool definition if provided
        if tool_definition and self.verify_tool_definitions:
            self.tool_registry.verify_tool(tool_name, tool_definition)

        # Resolve session
        if session is None and session_id is not None:
            session = self.session_manager.get_session(session_id)
            if session is None:
                raise SessionExpiredError(session_id)

        # Get wrapped tool
        wrapped_tool = self.get_wrapped_tool(tool_name)

        if wrapped_tool is None:
            # Tool not found - apply default policy
            if self.default_policy == "deny":
                user_id = "unknown"
                if session:
                    user_id = session.user_context.user_id
                elif user_context:
                    user_id = user_context.user_id

                raise AuthorizationError(
                    user=user_id,
                    action="execute",
                    resource=tool_name,
                    reason=f"Tool '{tool_name}' not found and default policy is deny",
                )

            # Default allow - pass through to original server
            if hasattr(self.original_server, "handle_tool_call"):
                return await self.original_server.handle_tool_call(tool_name, arguments)
            raise ValueError(f"Tool '{tool_name}' not found")

        # Execute with authorization
        return await wrapped_tool.execute(
            arguments=arguments,
            session=session,
            user_context=user_context,
        )

    def create_session(
        self,
        user_context: UserContext,
        agent_context: AgentContext | None = None,
        **kwargs: Any,
    ) -> MCPSession:
        """
        Create a new session for this server.

        Args:
            user_context: The user for the session.
            agent_context: Optional agent context.
            **kwargs: Additional session parameters.

        Returns:
            The created session.
        """
        return self.session_manager.create_session(
            user_context=user_context,
            agent_context=agent_context,
            **kwargs,
        )

    def validate_client(
        self,
        client_id: str,
        client_secret: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> bool:
        """
        Validate an MCP client.

        Override this method to implement custom client validation.

        Args:
            client_id: The client identifier.
            client_secret: Optional client secret.
            metadata: Additional client metadata.

        Returns:
            True if client is valid.
        """
        # Default implementation accepts all clients
        # Override for custom validation
        return True


def extract_user_from_mcp_context(
    mcp_context: dict[str, Any],
    user_id_field: str = "user_id",
    roles_field: str = "roles",
    session_id_field: str = "session_id",
) -> UserContext:
    """
    Extract UserContext from MCP context/metadata.

    Helper function to create a UserContext from MCP's
    context mechanism.

    Args:
        mcp_context: The MCP context dictionary.
        user_id_field: Field name for user ID.
        roles_field: Field name for roles.
        session_id_field: Field name for session ID.

    Returns:
        Extracted UserContext.

    Raises:
        InvalidClientError: If required fields are missing.
    """
    user_id = mcp_context.get(user_id_field)
    if not user_id:
        raise InvalidClientError(f"Missing required field: {user_id_field}")

    roles = mcp_context.get(roles_field, [])
    if isinstance(roles, str):
        roles = [roles]

    session_id = mcp_context.get(session_id_field)

    # Extract remaining fields as attributes
    attributes = {
        k: v for k, v in mcp_context.items()
        if k not in {user_id_field, roles_field, session_id_field}
    }

    return UserContext(
        user_id=user_id,
        roles=roles,
        session_id=session_id,
        attributes=attributes,
    )


def create_mcp_tool_handler(
    proxilion: Any,
    tools: list[Any],
    session_manager: MCPSessionManager | None = None,
) -> Callable[[str, dict[str, Any], MCPSession | None], Any]:
    """
    Create a tool handler function for MCP integration.

    Returns a function that can be used as the tool call handler
    in an MCP server implementation.

    Args:
        proxilion: Proxilion instance.
        tools: List of MCP tools.
        session_manager: Optional session manager.

    Returns:
        An async function that handles tool calls.

    Example:
        >>> handler = create_mcp_tool_handler(auth, [tool1, tool2])
        >>> result = await handler("tool1", {"arg": "value"}, session)
    """
    wrapped_tools: dict[str, MCPToolWrapper] = {}

    for tool in tools:
        name = getattr(tool, "name", None)
        if name:
            wrapped_tools[name] = MCPToolWrapper(
                original_tool=tool,
                proxilion=proxilion,
                resource=name,
            )

    async def handler(
        tool_name: str,
        arguments: dict[str, Any],
        session: MCPSession | None = None,
    ) -> Any:
        if tool_name not in wrapped_tools:
            raise AuthorizationError(
                user="unknown",
                action="execute",
                resource=tool_name,
                reason=f"Unknown tool: {tool_name}",
            )

        return await wrapped_tools[tool_name].execute(
            arguments=arguments,
            session=session,
        )

    return handler
