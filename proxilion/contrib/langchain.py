"""
LangChain integration for Proxilion.

This module provides authorization wrappers for LangChain tools,
enabling secure tool execution with user-context authorization.

Features:
    - ProxilionTool: Wraps LangChain BaseTool with authorization
    - ProxilionCallbackHandler: Intercepts and logs tool invocations
    - wrap_langchain_tools: Convenience function for bulk wrapping

Note:
    LangChain is an optional dependency. Install with:
    pip install proxilion[langchain]

Example:
    >>> from langchain.tools import Tool
    >>> from proxilion import Proxilion, Policy
    >>> from proxilion.contrib.langchain import ProxilionTool, wrap_langchain_tools
    >>>
    >>> auth = Proxilion()
    >>>
    >>> @auth.policy("search")
    ... class SearchPolicy(Policy):
    ...     def can_execute(self, context):
    ...         return "search_user" in self.user.roles
    >>>
    >>> # Wrap a single tool
    >>> secure_tool = ProxilionTool(
    ...     original_tool=search_tool,
    ...     proxilion=auth,
    ...     resource="search",
    ... )
    >>>
    >>> # Or wrap multiple tools at once
    >>> secure_tools = wrap_langchain_tools(
    ...     tools=[search_tool, calc_tool],
    ...     proxilion=auth,
    ... )
"""

from __future__ import annotations

import asyncio
import contextvars
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from proxilion.exceptions import AuthorizationError, ProxilionError
from proxilion.types import AgentContext, UserContext

logger = logging.getLogger(__name__)

# Context variable for user context in LangChain callbacks
_langchain_user_context: contextvars.ContextVar[UserContext | None] = contextvars.ContextVar(
    "langchain_user_context", default=None
)

_langchain_agent_context: contextvars.ContextVar[AgentContext | None] = contextvars.ContextVar(
    "langchain_agent_context", default=None
)


def set_langchain_user(user: UserContext) -> contextvars.Token[UserContext | None]:
    """Set the current user for LangChain tool execution."""
    return _langchain_user_context.set(user)


def get_langchain_user() -> UserContext | None:
    """Get the current user for LangChain tool execution."""
    return _langchain_user_context.get()


def set_langchain_agent(agent: AgentContext) -> contextvars.Token[AgentContext | None]:
    """Set the current agent for LangChain tool execution."""
    return _langchain_agent_context.set(agent)


def get_langchain_agent() -> AgentContext | None:
    """Get the current agent for LangChain tool execution."""
    return _langchain_agent_context.get()


class LangChainIntegrationError(ProxilionError):
    """Error in LangChain integration."""
    pass


@dataclass
class ToolInvocation:
    """Record of a tool invocation for audit purposes."""
    tool_name: str
    input_str: str
    user_id: str | None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    authorized: bool = False
    output: str | None = None
    error: str | None = None
    duration_ms: float = 0.0


class ProxilionToolMixin:
    """
    Mixin class providing Proxilion authorization for LangChain tools.

    This mixin can be combined with LangChain's BaseTool to create
    authorized tools without requiring LangChain as a dependency
    at import time.
    """

    proxilion: Any
    resource: str
    action: str
    original_tool: Any
    require_user: bool

    def _get_user_context(self) -> UserContext | None:
        """Get user context from context variable or Proxilion."""
        # Try context variable first
        user = get_langchain_user()
        if user is not None:
            return user

        # Try Proxilion's context
        from proxilion.core import get_current_user
        return get_current_user()

    def _authorize(self, tool_input: str) -> None:
        """Check authorization and raise if denied."""
        user = self._get_user_context()

        if user is None:
            if self.require_user:
                raise AuthorizationError(
                    user="unknown",
                    action=self.action,
                    resource=self.resource,
                    reason="No user context available for LangChain tool",
                )
            return  # Allow if user not required

        # Build context from input
        context = {
            "tool_input": tool_input,
            "tool_name": getattr(self.original_tool, "name", self.resource),
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


class ProxilionTool:
    """
    Wraps a LangChain tool with Proxilion authorization.

    This wrapper intercepts tool calls and applies authorization
    checks before delegating to the original tool.

    Works without LangChain installed by duck-typing the BaseTool
    interface. When LangChain is available, the wrapped tool can
    be used anywhere a BaseTool is expected.

    Example:
        >>> from proxilion import Proxilion, Policy, UserContext
        >>> from proxilion.contrib.langchain import ProxilionTool, set_langchain_user
        >>>
        >>> auth = Proxilion()
        >>>
        >>> @auth.policy("calculator")
        ... class CalculatorPolicy(Policy):
        ...     def can_execute(self, context):
        ...         return True
        >>>
        >>> # Create a mock tool
        >>> class CalcTool:
        ...     name = "calculator"
        ...     description = "Perform calculations"
        ...     def _run(self, query):
        ...         return eval(query)
        >>>
        >>> secure_calc = ProxilionTool(
        ...     original_tool=CalcTool(),
        ...     proxilion=auth,
        ...     resource="calculator",
        ... )
        >>>
        >>> # Set user context and run
        >>> set_langchain_user(UserContext(user_id="alice", roles=["user"]))
        >>> result = secure_calc.run("2 + 2")
    """

    def __init__(
        self,
        original_tool: Any,
        proxilion: Any,
        resource: str | None = None,
        action: str = "execute",
        require_user: bool = True,
    ) -> None:
        """
        Initialize the Proxilion-wrapped tool.

        Args:
            original_tool: The original LangChain tool to wrap.
            proxilion: Proxilion instance for authorization.
            resource: Resource name for policies (default: tool name).
            action: Action name for authorization (default: "execute").
            require_user: Whether to require user context (default: True).
        """
        self.original_tool = original_tool
        self.proxilion = proxilion
        self.resource = resource or getattr(original_tool, "name", "unknown_tool")
        self.action = action
        self.require_user = require_user

        # Copy attributes from original tool
        self.name = getattr(original_tool, "name", self.resource)
        self.description = getattr(original_tool, "description", "")

        # Copy other common attributes
        for attr in ["args_schema", "return_direct", "verbose"]:
            if hasattr(original_tool, attr):
                setattr(self, attr, getattr(original_tool, attr))

    def _get_user_context(self) -> UserContext | None:
        """Get user context from context variable or Proxilion."""
        user = get_langchain_user()
        if user is not None:
            return user

        from proxilion.core import get_current_user
        return get_current_user()

    def _authorize(self, tool_input: str | dict[str, Any]) -> None:
        """Check authorization and raise if denied."""
        user = self._get_user_context()

        if user is None:
            if self.require_user:
                raise AuthorizationError(
                    user="unknown",
                    action=self.action,
                    resource=self.resource,
                    reason="No user context available for LangChain tool",
                )
            return

        # Build context from input
        if isinstance(tool_input, dict):
            context = {"tool_input": tool_input, **tool_input}
        else:
            context = {"tool_input": str(tool_input)}

        context["tool_name"] = self.name

        result = self.proxilion.check(user, self.action, self.resource, context)
        if not result.allowed:
            raise AuthorizationError(
                user=user.user_id,
                action=self.action,
                resource=self.resource,
                reason=result.reason,
            )

    def run(self, tool_input: str | dict[str, Any], **kwargs: Any) -> str:
        """
        Run the tool with authorization.

        Args:
            tool_input: Input for the tool.
            **kwargs: Additional arguments.

        Returns:
            Tool output as string.
        """
        self._authorize(tool_input)
        return self.original_tool.run(tool_input, **kwargs)

    async def arun(self, tool_input: str | dict[str, Any], **kwargs: Any) -> str:
        """
        Run the tool asynchronously with authorization.

        Args:
            tool_input: Input for the tool.
            **kwargs: Additional arguments.

        Returns:
            Tool output as string.
        """
        self._authorize(tool_input)

        if hasattr(self.original_tool, "arun"):
            return await self.original_tool.arun(tool_input, **kwargs)
        else:
            # Fall back to sync run in executor
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                None,
                lambda: self.original_tool.run(tool_input, **kwargs),
            )

    def _run(self, *args: Any, **kwargs: Any) -> str:
        """Internal run method for LangChain compatibility."""
        tool_input = args[0] if args else kwargs.get("tool_input", "")
        self._authorize(tool_input)

        if hasattr(self.original_tool, "_run"):
            return self.original_tool._run(*args, **kwargs)
        return self.original_tool.run(tool_input, **kwargs)

    async def _arun(self, *args: Any, **kwargs: Any) -> str:
        """Internal async run method for LangChain compatibility."""
        tool_input = args[0] if args else kwargs.get("tool_input", "")
        self._authorize(tool_input)

        if hasattr(self.original_tool, "_arun"):
            return await self.original_tool._arun(*args, **kwargs)
        elif hasattr(self.original_tool, "arun"):
            return await self.original_tool.arun(tool_input, **kwargs)
        else:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                None,
                lambda: self.original_tool._run(*args, **kwargs)
                if hasattr(self.original_tool, "_run")
                else self.original_tool.run(tool_input, **kwargs),
            )

    def __call__(self, tool_input: str | dict[str, Any], **kwargs: Any) -> str:
        """Call the tool directly."""
        return self.run(tool_input, **kwargs)


class ProxilionCallbackHandler:
    """
    LangChain callback handler for logging and authorization.

    Intercepts tool calls in LangChain agents to:
    - Log all tool invocations to audit trail
    - Apply authorization checks
    - Track execution timing

    Compatible with LangChain's callback system without requiring
    LangChain as a dependency.

    Example:
        >>> from proxilion import Proxilion
        >>> from proxilion.contrib.langchain import ProxilionCallbackHandler
        >>>
        >>> auth = Proxilion()
        >>> handler = ProxilionCallbackHandler(
        ...     proxilion=auth,
        ...     user_context=user,
        ... )
        >>>
        >>> # Use with LangChain agent
        >>> agent.run("query", callbacks=[handler])
    """

    def __init__(
        self,
        proxilion: Any,
        user_context: UserContext | None = None,
        agent_context: AgentContext | None = None,
        log_inputs: bool = True,
        log_outputs: bool = True,
        block_unauthorized: bool = True,
    ) -> None:
        """
        Initialize the callback handler.

        Args:
            proxilion: Proxilion instance.
            user_context: User context for authorization.
            agent_context: Optional agent context.
            log_inputs: Whether to log tool inputs.
            log_outputs: Whether to log tool outputs.
            block_unauthorized: Whether to block unauthorized calls.
        """
        self.proxilion = proxilion
        self.user_context = user_context
        self.agent_context = agent_context
        self.log_inputs = log_inputs
        self.log_outputs = log_outputs
        self.block_unauthorized = block_unauthorized

        self._invocations: list[ToolInvocation] = []
        self._current_invocation: ToolInvocation | None = None
        self._start_time: float | None = None

    @property
    def invocations(self) -> list[ToolInvocation]:
        """Get list of recorded tool invocations."""
        return list(self._invocations)

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        """
        Called when a tool starts execution.

        Args:
            serialized: Serialized tool information.
            input_str: Tool input string.
            **kwargs: Additional arguments.
        """
        import time

        tool_name = serialized.get("name", "unknown")

        # Get user context
        user = self.user_context or get_langchain_user()
        user_id = user.user_id if user else None

        # Create invocation record
        self._current_invocation = ToolInvocation(
            tool_name=tool_name,
            input_str=input_str if self.log_inputs else "[REDACTED]",
            user_id=user_id,
        )
        self._start_time = time.time()

        # Check authorization if blocking is enabled
        if self.block_unauthorized and user is not None:
            context = {"tool_input": input_str}
            result = self.proxilion.check(user, "execute", tool_name, context)

            self._current_invocation.authorized = result.allowed

            if not result.allowed:
                self._current_invocation.error = result.reason
                self._invocations.append(self._current_invocation)
                raise AuthorizationError(
                    user=user.user_id,
                    action="execute",
                    resource=tool_name,
                    reason=result.reason,
                )
        else:
            self._current_invocation.authorized = True

        logger.debug(f"Tool started: {tool_name} for user {user_id}")

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        """
        Called when a tool finishes execution.

        Args:
            output: Tool output string.
            **kwargs: Additional arguments.
        """
        import time

        if self._current_invocation is not None:
            if self._start_time is not None:
                self._current_invocation.duration_ms = (
                    time.time() - self._start_time
                ) * 1000

            self._current_invocation.output = (
                output if self.log_outputs else "[REDACTED]"
            )
            self._invocations.append(self._current_invocation)

            logger.debug(
                f"Tool ended: {self._current_invocation.tool_name} "
                f"({self._current_invocation.duration_ms:.1f}ms)"
            )

        self._current_invocation = None
        self._start_time = None

    def on_tool_error(self, error: Exception, **kwargs: Any) -> None:
        """
        Called when a tool raises an error.

        Args:
            error: The exception raised.
            **kwargs: Additional arguments.
        """
        import time

        if self._current_invocation is not None:
            if self._start_time is not None:
                self._current_invocation.duration_ms = (
                    time.time() - self._start_time
                ) * 1000

            self._current_invocation.error = str(error)
            self._invocations.append(self._current_invocation)

            logger.warning(
                f"Tool error: {self._current_invocation.tool_name} - {error}"
            )

        self._current_invocation = None
        self._start_time = None

    # LangChain callback handler interface methods
    def on_llm_start(self, *args: Any, **kwargs: Any) -> None:
        """Called when LLM starts (no-op)."""
        pass

    def on_llm_end(self, *args: Any, **kwargs: Any) -> None:
        """Called when LLM ends (no-op)."""
        pass

    def on_llm_error(self, *args: Any, **kwargs: Any) -> None:
        """Called on LLM error (no-op)."""
        pass

    def on_chain_start(self, *args: Any, **kwargs: Any) -> None:
        """Called when chain starts (no-op)."""
        pass

    def on_chain_end(self, *args: Any, **kwargs: Any) -> None:
        """Called when chain ends (no-op)."""
        pass

    def on_chain_error(self, *args: Any, **kwargs: Any) -> None:
        """Called on chain error (no-op)."""
        pass

    def on_agent_action(self, *args: Any, **kwargs: Any) -> None:
        """Called on agent action (no-op)."""
        pass

    def on_agent_finish(self, *args: Any, **kwargs: Any) -> None:
        """Called when agent finishes (no-op)."""
        pass


def wrap_langchain_tools(
    tools: list[Any],
    proxilion: Any,
    resource_prefix: str = "",
    action: str = "execute",
    require_user: bool = True,
) -> list[ProxilionTool]:
    """
    Wrap multiple LangChain tools with Proxilion authorization.

    Convenience function for bulk wrapping of tools.

    Args:
        tools: List of LangChain tools to wrap.
        proxilion: Proxilion instance.
        resource_prefix: Optional prefix for resource names.
        action: Action name for authorization.
        require_user: Whether to require user context.

    Returns:
        List of wrapped ProxilionTool instances.

    Example:
        >>> tools = [search_tool, calc_tool, file_tool]
        >>> secure_tools = wrap_langchain_tools(
        ...     tools=tools,
        ...     proxilion=auth,
        ...     resource_prefix="agent_",
        ... )
    """
    wrapped = []

    for tool in tools:
        tool_name = getattr(tool, "name", f"tool_{len(wrapped)}")
        resource = f"{resource_prefix}{tool_name}" if resource_prefix else tool_name

        wrapped.append(
            ProxilionTool(
                original_tool=tool,
                proxilion=proxilion,
                resource=resource,
                action=action,
                require_user=require_user,
            )
        )

    return wrapped


class LangChainUserContextManager:
    """
    Context manager for setting user context in LangChain operations.

    Example:
        >>> with LangChainUserContextManager(user):
        ...     result = agent.run("query")
    """

    def __init__(
        self,
        user: UserContext,
        agent: AgentContext | None = None,
    ) -> None:
        self.user = user
        self.agent = agent
        self._user_token: contextvars.Token[UserContext | None] | None = None
        self._agent_token: contextvars.Token[AgentContext | None] | None = None

    def __enter__(self) -> LangChainUserContextManager:
        self._user_token = set_langchain_user(self.user)
        if self.agent:
            self._agent_token = set_langchain_agent(self.agent)
        return self

    def __exit__(self, *args: Any) -> None:
        if self._user_token is not None:
            _langchain_user_context.reset(self._user_token)
        if self._agent_token is not None:
            _langchain_agent_context.reset(self._agent_token)


def langchain_user_context(user: UserContext, agent: AgentContext | None = None):
    """
    Decorator/context manager for setting user context.

    Can be used as a decorator or context manager.

    Example as decorator:
        >>> @langchain_user_context(user)
        ... def run_agent():
        ...     return agent.run("query")

    Example as context manager:
        >>> with langchain_user_context(user):
        ...     result = agent.run("query")
    """
    return LangChainUserContextManager(user, agent)
