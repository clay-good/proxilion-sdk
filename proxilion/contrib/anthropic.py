"""
Anthropic integration for Proxilion.

This module provides authorization wrappers for Anthropic's tool_use feature,
enabling secure tool execution with user-context authorization.

Features:
    - ProxilionToolHandler: Manages tool registration and execution
    - process_tool_use: Process tool_use blocks from Claude responses
    - Safe error handling for production use

Note:
    Anthropic SDK is an optional dependency. This module works by wrapping
    tool definitions and implementations rather than modifying the
    Anthropic client directly.

Example:
    >>> from anthropic import Anthropic
    >>> from proxilion import Proxilion
    >>> from proxilion.contrib.anthropic import ProxilionToolHandler
    >>>
    >>> auth = Proxilion()
    >>> handler = ProxilionToolHandler(auth)
    >>>
    >>> # Register a tool
    >>> handler.register_tool(
    ...     name="get_weather",
    ...     schema=weather_schema,
    ...     implementation=get_weather_impl,
    ...     resource="weather_api",
    ... )
    >>>
    >>> # Process tool_use from Claude response
    >>> for block in response.content:
    ...     if block.type == "tool_use":
    ...         result = handler.execute(
    ...             tool_use_block=block,
    ...             user=current_user,
    ...         )
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, TypeVar

from proxilion.exceptions import ProxilionError
from proxilion.types import AgentContext, UserContext

logger = logging.getLogger(__name__)

T = TypeVar("T")


class AnthropicIntegrationError(ProxilionError):
    """Error in Anthropic integration."""
    pass


class ToolNotFoundError(AnthropicIntegrationError):
    """Raised when a tool is not registered."""

    def __init__(self, tool_name: str) -> None:
        self.tool_name = tool_name
        super().__init__(f"Tool not registered: {tool_name}")


class ToolExecutionError(AnthropicIntegrationError):
    """Raised when tool execution fails."""

    def __init__(self, tool_name: str, safe_message: str) -> None:
        self.tool_name = tool_name
        self.safe_message = safe_message
        super().__init__(f"Tool execution failed: {safe_message}")


@dataclass
class RegisteredTool:
    """A registered tool with its schema and implementation."""
    name: str
    schema: dict[str, Any]
    implementation: Callable[..., Any]
    resource: str
    action: str
    async_impl: bool
    description: str


@dataclass
class ToolUseResult:
    """Result of a tool use execution."""
    tool_use_id: str
    tool_name: str
    success: bool
    result: Any | None = None
    error: str | None = None
    authorized: bool = True
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_tool_result_block(self) -> dict[str, Any]:
        """
        Convert to Anthropic tool_result format.

        Returns:
            Dictionary suitable for tool_result content block.
        """
        if self.success:
            content = self.result
            if not isinstance(content, str):
                content = json.dumps(content)
            return {
                "type": "tool_result",
                "tool_use_id": self.tool_use_id,
                "content": content,
            }
        else:
            return {
                "type": "tool_result",
                "tool_use_id": self.tool_use_id,
                "content": self.error or "Tool execution failed",
                "is_error": True,
            }


class ProxilionToolHandler:
    """
    Handler for Anthropic tool_use with Proxilion authorization.

    Manages tool registration, authorization, and execution for
    Anthropic's Claude tool_use feature.

    Example:
        >>> from proxilion import Proxilion, Policy, UserContext
        >>> from proxilion.contrib.anthropic import ProxilionToolHandler
        >>>
        >>> auth = Proxilion()
        >>>
        >>> @auth.policy("calculator")
        ... class CalculatorPolicy(Policy):
        ...     def can_execute(self, context):
        ...         return True
        >>>
        >>> handler = ProxilionToolHandler(auth)
        >>>
        >>> def calculate(expression: str) -> str:
        ...     return str(eval(expression))
        >>>
        >>> handler.register_tool(
        ...     name="calculator",
        ...     schema={
        ...         "name": "calculator",
        ...         "description": "Evaluate a math expression",
        ...         "input_schema": {
        ...             "type": "object",
        ...             "properties": {
        ...                 "expression": {"type": "string"}
        ...             },
        ...             "required": ["expression"]
        ...         }
        ...     },
        ...     implementation=calculate,
        ...     resource="calculator",
        ... )
        >>>
        >>> # Execute tool
        >>> result = handler.execute(
        ...     tool_name="calculator",
        ...     tool_use_id="toolu_123",
        ...     input_data={"expression": "2 + 2"},
        ...     user=user,
        ... )
    """

    def __init__(
        self,
        proxilion: Any,
        default_action: str = "execute",
        safe_errors: bool = True,
    ) -> None:
        """
        Initialize the tool handler.

        Args:
            proxilion: Proxilion instance for authorization.
            default_action: Default action for authorization checks.
            safe_errors: If True, return safe error messages.
        """
        self.proxilion = proxilion
        self.default_action = default_action
        self.safe_errors = safe_errors

        self._tools: dict[str, RegisteredTool] = {}
        self._execution_history: list[ToolUseResult] = []

    @property
    def tools(self) -> list[RegisteredTool]:
        """Get list of registered tools."""
        return list(self._tools.values())

    @property
    def tool_schemas(self) -> list[dict[str, Any]]:
        """Get list of tool schemas for Anthropic API."""
        return [t.schema for t in self._tools.values()]

    @property
    def execution_history(self) -> list[ToolUseResult]:
        """Get history of tool executions."""
        return list(self._execution_history)

    def register_tool(
        self,
        name: str,
        schema: dict[str, Any],
        implementation: Callable[..., Any],
        resource: str | None = None,
        action: str | None = None,
        description: str | None = None,
    ) -> None:
        """
        Register a tool for execution.

        Args:
            name: Tool name (must match Anthropic tool_use name).
            schema: Anthropic tool schema with input_schema.
            implementation: Python function to execute.
            resource: Resource name for authorization (default: tool name).
            action: Action for authorization (default: handler default).
            description: Optional description override.
        """
        is_async = inspect.iscoroutinefunction(implementation)

        self._tools[name] = RegisteredTool(
            name=name,
            schema=schema,
            implementation=implementation,
            resource=resource or name,
            action=action or self.default_action,
            async_impl=is_async,
            description=description or schema.get("description", ""),
        )

        logger.debug(f"Registered tool: {name} (resource: {resource or name})")

    def unregister_tool(self, name: str) -> bool:
        """
        Unregister a tool.

        Args:
            name: Tool name to unregister.

        Returns:
            True if tool was registered and removed.
        """
        if name in self._tools:
            del self._tools[name]
            return True
        return False

    def get_tool(self, name: str) -> RegisteredTool | None:
        """Get a registered tool by name."""
        return self._tools.get(name)

    def execute(
        self,
        tool_name: str | None = None,
        tool_use_id: str | None = None,
        input_data: dict[str, Any] | None = None,
        user: UserContext | None = None,
        agent: AgentContext | None = None,
        tool_use_block: Any | None = None,
    ) -> ToolUseResult:
        """
        Execute a tool with authorization.

        Can accept either explicit parameters or an Anthropic
        tool_use block object.

        Args:
            tool_name: Name of the tool to call.
            tool_use_id: Unique ID for this tool use.
            input_data: Tool input data.
            user: User context for authorization.
            agent: Optional agent context.
            tool_use_block: Anthropic tool_use block (alternative).

        Returns:
            ToolUseResult with execution result or error.
        """
        # Extract from tool_use_block if provided
        if tool_use_block is not None:
            tool_name = getattr(tool_use_block, "name", None)
            tool_use_id = getattr(tool_use_block, "id", tool_use_id or "unknown")
            input_data = getattr(tool_use_block, "input", {})

        tool_use_id = tool_use_id or "unknown"

        if tool_name is None:
            return ToolUseResult(
                tool_use_id=tool_use_id,
                tool_name="unknown",
                success=False,
                error="No tool name provided",
            )

        input_data = input_data or {}

        # Get registered tool
        tool = self._tools.get(tool_name)
        if tool is None:
            result = ToolUseResult(
                tool_use_id=tool_use_id,
                tool_name=tool_name,
                success=False,
                error=f"Tool not found: {tool_name}",
            )
            self._execution_history.append(result)
            return result

        # Check authorization
        if user is not None:
            context = {
                **input_data,
                "tool_name": tool_name,
                "input": input_data,
            }

            auth_result = self.proxilion.check(user, tool.action, tool.resource, context)

            if not auth_result.allowed:
                result = ToolUseResult(
                    tool_use_id=tool_use_id,
                    tool_name=tool_name,
                    success=False,
                    error="Not authorized" if self.safe_errors else auth_result.reason,
                    authorized=False,
                )
                self._execution_history.append(result)
                return result

        # Execute tool
        try:
            if tool.async_impl:
                loop = asyncio.new_event_loop()
                try:
                    output = loop.run_until_complete(tool.implementation(**input_data))
                finally:
                    loop.close()
            else:
                output = tool.implementation(**input_data)

            # Convert output to string if needed for Anthropic
            if not isinstance(output, str):
                output = json.dumps(output)

            result = ToolUseResult(
                tool_use_id=tool_use_id,
                tool_name=tool_name,
                success=True,
                result=output,
            )

        except Exception as e:
            logger.error(f"Tool execution error: {tool_name} - {e}")

            error_msg = "Tool execution failed"
            if not self.safe_errors:
                error_msg = str(e)

            result = ToolUseResult(
                tool_use_id=tool_use_id,
                tool_name=tool_name,
                success=False,
                error=error_msg,
            )

        self._execution_history.append(result)
        return result

    async def execute_async(
        self,
        tool_name: str | None = None,
        tool_use_id: str | None = None,
        input_data: dict[str, Any] | None = None,
        user: UserContext | None = None,
        agent: AgentContext | None = None,
        tool_use_block: Any | None = None,
    ) -> ToolUseResult:
        """
        Execute a tool asynchronously with authorization.

        Args:
            tool_name: Name of the tool to call.
            tool_use_id: Unique ID for this tool use.
            input_data: Tool input data.
            user: User context for authorization.
            agent: Optional agent context.
            tool_use_block: Anthropic tool_use block.

        Returns:
            ToolUseResult with execution result or error.
        """
        if tool_use_block is not None:
            tool_name = getattr(tool_use_block, "name", None)
            tool_use_id = getattr(tool_use_block, "id", tool_use_id or "unknown")
            input_data = getattr(tool_use_block, "input", {})

        tool_use_id = tool_use_id or "unknown"

        if tool_name is None:
            return ToolUseResult(
                tool_use_id=tool_use_id,
                tool_name="unknown",
                success=False,
                error="No tool name provided",
            )

        input_data = input_data or {}

        tool = self._tools.get(tool_name)
        if tool is None:
            result = ToolUseResult(
                tool_use_id=tool_use_id,
                tool_name=tool_name,
                success=False,
                error=f"Tool not found: {tool_name}",
            )
            self._execution_history.append(result)
            return result

        # Check authorization
        if user is not None:
            context = {
                **input_data,
                "tool_name": tool_name,
                "input": input_data,
            }

            auth_result = self.proxilion.check(user, tool.action, tool.resource, context)

            if not auth_result.allowed:
                result = ToolUseResult(
                    tool_use_id=tool_use_id,
                    tool_name=tool_name,
                    success=False,
                    error="Not authorized" if self.safe_errors else auth_result.reason,
                    authorized=False,
                )
                self._execution_history.append(result)
                return result

        # Execute tool
        try:
            if tool.async_impl:
                output = await tool.implementation(**input_data)
            else:
                loop = asyncio.get_event_loop()
                output = await loop.run_in_executor(
                    None,
                    lambda: tool.implementation(**input_data),
                )

            if not isinstance(output, str):
                output = json.dumps(output)

            result = ToolUseResult(
                tool_use_id=tool_use_id,
                tool_name=tool_name,
                success=True,
                result=output,
            )

        except Exception as e:
            logger.error(f"Tool execution error: {tool_name} - {e}")

            error_msg = "Tool execution failed"
            if not self.safe_errors:
                error_msg = str(e)

            result = ToolUseResult(
                tool_use_id=tool_use_id,
                tool_name=tool_name,
                success=False,
                error=error_msg,
            )

        self._execution_history.append(result)
        return result

    def to_anthropic_tools(self) -> list[dict[str, Any]]:
        """
        Get tool schemas in Anthropic tools format.

        Returns:
            List of tool definitions for Anthropic API.
        """
        return self.tool_schemas


def process_tool_use(
    response: Any,
    handler: ProxilionToolHandler,
    user: UserContext | None = None,
) -> list[ToolUseResult]:
    """
    Process an Anthropic response and execute any tool_use blocks.

    Args:
        response: Anthropic API response object.
        handler: ProxilionToolHandler for execution.
        user: User context for authorization.

    Returns:
        List of ToolUseResult for each tool_use block.

    Example:
        >>> response = client.messages.create(...)
        >>> results = process_tool_use(response, handler, user)
        >>> tool_results = [r.to_tool_result_block() for r in results]
    """
    results: list[ToolUseResult] = []

    # Get content blocks from response
    content = getattr(response, "content", [])
    if not content:
        return results

    for block in content:
        # Check if this is a tool_use block
        block_type = getattr(block, "type", None)
        if block_type != "tool_use":
            continue

        result = handler.execute(
            tool_use_block=block,
            user=user,
        )
        results.append(result)

    return results


async def process_tool_use_async(
    response: Any,
    handler: ProxilionToolHandler,
    user: UserContext | None = None,
) -> list[ToolUseResult]:
    """
    Process an Anthropic response and execute tool_use blocks asynchronously.

    Args:
        response: Anthropic API response object.
        handler: ProxilionToolHandler for execution.
        user: User context for authorization.

    Returns:
        List of ToolUseResult for each tool_use block.
    """
    results: list[ToolUseResult] = []

    content = getattr(response, "content", [])
    if not content:
        return results

    for block in content:
        block_type = getattr(block, "type", None)
        if block_type != "tool_use":
            continue

        result = await handler.execute_async(
            tool_use_block=block,
            user=user,
        )
        results.append(result)

    return results


def create_tool_result_content(results: list[ToolUseResult]) -> list[dict[str, Any]]:
    """
    Create tool_result content blocks from execution results.

    Convenience function for building the tool_result message
    to send back to Claude.

    Args:
        results: List of ToolUseResult objects.

    Returns:
        List of tool_result content blocks.

    Example:
        >>> results = process_tool_use(response, handler, user)
        >>> tool_results = create_tool_result_content(results)
        >>> next_response = client.messages.create(
        ...     messages=[
        ...         {"role": "user", "content": original_query},
        ...         {"role": "assistant", "content": response.content},
        ...         {"role": "user", "content": tool_results},
        ...     ],
        ...     ...
        ... )
    """
    return [result.to_tool_result_block() for result in results]
