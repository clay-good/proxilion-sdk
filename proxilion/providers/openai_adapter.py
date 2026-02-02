"""
OpenAI adapter for Proxilion.

Provides translation between OpenAI's tool calling format
and Proxilion's unified format.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from proxilion.providers.adapter import (
    BaseAdapter,
    Provider,
    UnifiedResponse,
    UnifiedToolCall,
)

logger = logging.getLogger(__name__)


class OpenAIAdapter(BaseAdapter):
    """
    Adapter for OpenAI API.

    Handles tool calls from OpenAI's chat completion API,
    including function calling and parallel tool calls.

    Example:
        >>> from openai import OpenAI
        >>> from proxilion.providers import OpenAIAdapter
        >>>
        >>> adapter = OpenAIAdapter()
        >>> client = OpenAI()
        >>>
        >>> response = client.chat.completions.create(
        ...     model="gpt-4o",
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
        return Provider.OPENAI

    def extract_tool_calls(self, response: Any) -> list[UnifiedToolCall]:
        """
        Extract tool calls from OpenAI response.

        Handles both ChatCompletion objects and dictionaries.

        Args:
            response: OpenAI ChatCompletion response.

        Returns:
            List of unified tool calls.
        """
        # Handle dictionary form (e.g., from JSON API response)
        if isinstance(response, dict):
            return self._extract_from_dict(response)

        # Handle object form (e.g., from openai library)
        if not hasattr(response, "choices") or not response.choices:
            return []

        choice = response.choices[0]
        message = getattr(choice, "message", None)
        if message is None:
            return []

        tool_calls = getattr(message, "tool_calls", None)
        if not tool_calls:
            return []

        return [UnifiedToolCall.from_openai(tc) for tc in tool_calls]

    def _extract_from_dict(self, response: dict) -> list[UnifiedToolCall]:
        """Extract tool calls from dictionary response."""
        choices = response.get("choices", [])
        if not choices:
            return []

        message = choices[0].get("message", {})
        tool_calls = message.get("tool_calls") or []

        return [UnifiedToolCall.from_openai(tc) for tc in tool_calls]

    def extract_response(self, response: Any) -> UnifiedResponse:
        """
        Extract full response from OpenAI response.

        Args:
            response: OpenAI ChatCompletion response.

        Returns:
            UnifiedResponse instance.
        """
        tool_calls = self.extract_tool_calls(response)

        # Handle dictionary form
        if isinstance(response, dict):
            choices = response.get("choices", [])
            if choices:
                message = choices[0].get("message", {})
                content = message.get("content")
                finish_reason = choices[0].get("finish_reason")
            else:
                content = None
                finish_reason = None

            usage = response.get("usage", {})
            usage_dict = {
                "input_tokens": usage.get("prompt_tokens", 0),
                "output_tokens": usage.get("completion_tokens", 0),
                "total_tokens": usage.get("total_tokens", 0),
            }

            return UnifiedResponse(
                content=content,
                tool_calls=tool_calls,
                finish_reason=finish_reason,
                provider=Provider.OPENAI,
                usage=usage_dict,
                raw=response,
            )

        # Handle object form
        content = None
        finish_reason = None
        usage_dict = {}

        if hasattr(response, "choices") and response.choices:
            choice = response.choices[0]
            message = getattr(choice, "message", None)
            if message:
                content = getattr(message, "content", None)
            finish_reason = getattr(choice, "finish_reason", None)

        if hasattr(response, "usage") and response.usage:
            usage = response.usage
            usage_dict = {
                "input_tokens": getattr(usage, "prompt_tokens", 0),
                "output_tokens": getattr(usage, "completion_tokens", 0),
                "total_tokens": getattr(usage, "total_tokens", 0),
            }

        return UnifiedResponse(
            content=content,
            tool_calls=tool_calls,
            finish_reason=finish_reason,
            provider=Provider.OPENAI,
            usage=usage_dict,
            raw=response,
        )

    def format_tool_result(
        self,
        tool_call: UnifiedToolCall,
        result: Any,
        is_error: bool = False,
    ) -> dict[str, Any]:
        """
        Format tool result for OpenAI API.

        Creates a message suitable for adding to the messages list
        when continuing a conversation with tool results.

        Args:
            tool_call: The original tool call.
            result: The result to send back.
            is_error: Whether the result represents an error.

        Returns:
            Dictionary with role, tool_call_id, and content.

        Example:
            >>> result_msg = adapter.format_tool_result(
            ...     tool_call,
            ...     {"temperature": 72, "conditions": "sunny"}
            ... )
            >>> messages.append(result_msg)
        """
        content = self._serialize_result(result)

        if is_error:
            content = json.dumps({"error": content})

        return {
            "role": "tool",
            "tool_call_id": tool_call.id,
            "content": content,
        }

    def format_tools(
        self,
        tools: list[Any],
    ) -> list[dict[str, Any]]:
        """
        Format tool definitions for OpenAI API.

        Converts ToolDefinition objects to OpenAI's function format.

        Args:
            tools: List of ToolDefinition objects.

        Returns:
            List of tool definitions in OpenAI format.

        Example:
            >>> openai_tools = adapter.format_tools(registry.list_enabled())
            >>> response = client.chat.completions.create(
            ...     model="gpt-4o",
            ...     messages=[...],
            ...     tools=openai_tools,
            ... )
        """
        formatted = []
        for tool in tools:
            # Check if it's a ToolDefinition
            if hasattr(tool, "to_openai_format"):
                formatted.append(tool.to_openai_format())
            elif hasattr(tool, "name") and hasattr(tool, "description"):
                # Manual conversion
                formatted.append({
                    "type": "function",
                    "function": {
                        "name": tool.name,
                        "description": tool.description,
                        "parameters": getattr(tool, "parameters", {
                            "type": "object",
                            "properties": {},
                        }),
                    },
                })
            elif isinstance(tool, dict):
                # Already in correct format or needs wrapping
                if tool.get("type") == "function":
                    formatted.append(tool)
                else:
                    formatted.append({
                        "type": "function",
                        "function": tool,
                    })

        return formatted

    def format_assistant_message(
        self,
        content: str | None,
        tool_calls: list[UnifiedToolCall],
    ) -> dict[str, Any]:
        """
        Format an assistant message with tool calls.

        Useful for reconstructing conversation history.

        Args:
            content: Text content of the message.
            tool_calls: List of tool calls to include.

        Returns:
            Dictionary suitable for OpenAI messages list.
        """
        message: dict[str, Any] = {"role": "assistant"}

        if content:
            message["content"] = content

        if tool_calls:
            message["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.name,
                        "arguments": json.dumps(tc.arguments),
                    },
                }
                for tc in tool_calls
            ]

        return message
