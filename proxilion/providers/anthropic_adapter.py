"""
Anthropic adapter for Proxilion.

Provides translation between Anthropic's tool use format
and Proxilion's unified format.
"""

from __future__ import annotations

import logging
from typing import Any

from proxilion.providers.adapter import (
    BaseAdapter,
    Provider,
    UnifiedResponse,
    UnifiedToolCall,
)

logger = logging.getLogger(__name__)


class AnthropicAdapter(BaseAdapter):
    """
    Adapter for Anthropic Claude API.

    Handles tool use blocks from Anthropic's Messages API,
    including parallel tool calls.

    Example:
        >>> from anthropic import Anthropic
        >>> from proxilion.providers import AnthropicAdapter
        >>>
        >>> adapter = AnthropicAdapter()
        >>> client = Anthropic()
        >>>
        >>> response = client.messages.create(
        ...     model="claude-sonnet-4-20250514",
        ...     messages=[{"role": "user", "content": "Get weather"}],
        ...     tools=[...],
        ... )
        >>>
        >>> # Extract tool calls
        >>> tool_calls = adapter.extract_tool_calls(response)
        >>> for call in tool_calls:
        ...     print(f"Tool: {call.name}, Args: {call.arguments}")
        >>>
        >>> # Format result for continuation
        >>> result_msg = adapter.format_tool_result(tool_calls[0], {"temp": 72})
    """

    @property
    def provider(self) -> Provider:
        """Get the provider type."""
        return Provider.ANTHROPIC

    def extract_tool_calls(self, response: Any) -> list[UnifiedToolCall]:
        """
        Extract tool calls from Anthropic response.

        Anthropic returns tool_use blocks within the content array.

        Args:
            response: Anthropic Message response.

        Returns:
            List of unified tool calls.
        """
        # Handle dictionary form
        if isinstance(response, dict):
            return self._extract_from_dict(response)

        # Handle object form
        content = getattr(response, "content", None)
        if not content:
            return []

        tool_calls = []
        for block in content:
            # Check if it's a tool_use block
            block_type = getattr(block, "type", None)
            is_tool_use = block_type == "tool_use"
            is_dict_tool_use = isinstance(block, dict) and block.get("type") == "tool_use"
            if is_tool_use or is_dict_tool_use:
                tool_calls.append(UnifiedToolCall.from_anthropic(block))

        return tool_calls

    def _extract_from_dict(self, response: dict) -> list[UnifiedToolCall]:
        """Extract tool calls from dictionary response."""
        content = response.get("content", [])
        tool_calls = []

        for block in content:
            if isinstance(block, dict) and block.get("type") == "tool_use":
                tool_calls.append(UnifiedToolCall.from_anthropic(block))

        return tool_calls

    def extract_response(self, response: Any) -> UnifiedResponse:
        """
        Extract full response from Anthropic response.

        Args:
            response: Anthropic Message response.

        Returns:
            UnifiedResponse instance.
        """
        tool_calls = self.extract_tool_calls(response)

        # Handle dictionary form
        if isinstance(response, dict):
            content = response.get("content", [])
            text_content = self._extract_text_content(content)
            stop_reason = response.get("stop_reason")

            usage = response.get("usage", {})
            usage_dict = {
                "input_tokens": usage.get("input_tokens", 0),
                "output_tokens": usage.get("output_tokens", 0),
            }

            return UnifiedResponse(
                content=text_content,
                tool_calls=tool_calls,
                finish_reason=stop_reason,
                provider=Provider.ANTHROPIC,
                usage=usage_dict,
                raw=response,
            )

        # Handle object form
        content_blocks = getattr(response, "content", [])
        text_content = self._extract_text_content_from_objects(content_blocks)
        stop_reason = getattr(response, "stop_reason", None)

        usage_dict = {}
        usage = getattr(response, "usage", None)
        if usage:
            usage_dict = {
                "input_tokens": getattr(usage, "input_tokens", 0),
                "output_tokens": getattr(usage, "output_tokens", 0),
            }

        return UnifiedResponse(
            content=text_content,
            tool_calls=tool_calls,
            finish_reason=stop_reason,
            provider=Provider.ANTHROPIC,
            usage=usage_dict,
            raw=response,
        )

    def _extract_text_content(self, content: list) -> str | None:
        """Extract text content from content blocks (dict form)."""
        text_parts = []
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                text_parts.append(block.get("text", ""))

        return "".join(text_parts) if text_parts else None

    def _extract_text_content_from_objects(self, content: list) -> str | None:
        """Extract text content from content blocks (object form)."""
        text_parts = []
        for block in content:
            block_type = getattr(block, "type", None)
            if block_type == "text":
                text_parts.append(getattr(block, "text", ""))

        return "".join(text_parts) if text_parts else None

    def format_tool_result(
        self,
        tool_call: UnifiedToolCall,
        result: Any,
        is_error: bool = False,
    ) -> dict[str, Any]:
        """
        Format tool result for Anthropic API.

        Creates a tool_result block for the user message.

        Args:
            tool_call: The original tool call.
            result: The result to send back.
            is_error: Whether the result represents an error.

        Returns:
            Dictionary with tool_result block.

        Example:
            >>> result_block = adapter.format_tool_result(
            ...     tool_call,
            ...     {"temperature": 72}
            ... )
            >>> messages.append({
            ...     "role": "user",
            ...     "content": [result_block],
            ... })
        """
        content = self._serialize_result(result)

        return {
            "type": "tool_result",
            "tool_use_id": tool_call.id,
            "content": content,
            "is_error": is_error,
        }

    def format_tools(
        self,
        tools: list[Any],
    ) -> list[dict[str, Any]]:
        """
        Format tool definitions for Anthropic API.

        Converts ToolDefinition objects to Anthropic's tool format.

        Args:
            tools: List of ToolDefinition objects.

        Returns:
            List of tool definitions in Anthropic format.

        Example:
            >>> anthropic_tools = adapter.format_tools(registry.list_enabled())
            >>> response = client.messages.create(
            ...     model="claude-sonnet-4-20250514",
            ...     messages=[...],
            ...     tools=anthropic_tools,
            ... )
        """
        formatted = []
        for tool in tools:
            # Check if it's a ToolDefinition
            if hasattr(tool, "to_anthropic_format"):
                formatted.append(tool.to_anthropic_format())
            elif hasattr(tool, "name") and hasattr(tool, "description"):
                # Manual conversion
                formatted.append({
                    "name": tool.name,
                    "description": tool.description,
                    "input_schema": getattr(tool, "parameters", {
                        "type": "object",
                        "properties": {},
                    }),
                })
            elif isinstance(tool, dict):
                # Already in correct format or needs conversion
                if "input_schema" in tool:
                    formatted.append(tool)
                elif "parameters" in tool:
                    formatted.append({
                        "name": tool.get("name"),
                        "description": tool.get("description", ""),
                        "input_schema": tool.get("parameters"),
                    })

        return formatted

    def format_user_message_with_results(
        self,
        results: list[tuple[UnifiedToolCall, Any, bool]],
    ) -> dict[str, Any]:
        """
        Format a user message containing multiple tool results.

        Args:
            results: List of (tool_call, result, is_error) tuples.

        Returns:
            Dictionary suitable for Anthropic messages list.

        Example:
            >>> results = [
            ...     (call1, {"temp": 72}, False),
            ...     (call2, "Error", True),
            ... ]
            >>> user_msg = adapter.format_user_message_with_results(results)
            >>> messages.append(user_msg)
        """
        content = [
            self.format_tool_result(tc, result, is_error)
            for tc, result, is_error in results
        ]

        return {
            "role": "user",
            "content": content,
        }

    def format_assistant_message(
        self,
        text_content: str | None,
        tool_calls: list[UnifiedToolCall],
    ) -> dict[str, Any]:
        """
        Format an assistant message with tool use blocks.

        Useful for reconstructing conversation history.

        Args:
            text_content: Text content of the message.
            tool_calls: List of tool calls to include.

        Returns:
            Dictionary suitable for Anthropic messages list.
        """
        content = []

        if text_content:
            content.append({
                "type": "text",
                "text": text_content,
            })

        for tc in tool_calls:
            content.append({
                "type": "tool_use",
                "id": tc.id,
                "name": tc.name,
                "input": tc.arguments,
            })

        return {
            "role": "assistant",
            "content": content,
        }
