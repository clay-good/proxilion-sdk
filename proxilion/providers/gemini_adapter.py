"""
Google Gemini adapter for Proxilion.

Provides translation between Google Gemini/Vertex AI's function calling format
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


class GeminiAdapter(BaseAdapter):
    """
    Adapter for Google Gemini / Vertex AI API.

    Handles function calls from Gemini's GenerateContent API,
    including parallel function calls.

    Example:
        >>> from vertexai.generative_models import GenerativeModel
        >>> from proxilion.providers import GeminiAdapter
        >>>
        >>> adapter = GeminiAdapter()
        >>> model = GenerativeModel("gemini-1.5-pro")
        >>>
        >>> response = model.generate_content(
        ...     "Get weather",
        ...     tools=[...],
        ... )
        >>>
        >>> # Extract tool calls
        >>> tool_calls = adapter.extract_tool_calls(response)
        >>> for call in tool_calls:
        ...     print(f"Tool: {call.name}, Args: {call.arguments}")
        >>>
        >>> # Format result for continuation
        >>> result_part = adapter.format_tool_result(tool_calls[0], {"temp": 72})
    """

    @property
    def provider(self) -> Provider:
        """Get the provider type."""
        return Provider.GEMINI

    def extract_tool_calls(self, response: Any) -> list[UnifiedToolCall]:
        """
        Extract tool calls from Gemini response.

        Gemini returns function_call parts within candidates.

        Args:
            response: Gemini GenerateContentResponse.

        Returns:
            List of unified tool calls.
        """
        # Handle dictionary form
        if isinstance(response, dict):
            return self._extract_from_dict(response)

        # Handle object form
        candidates = getattr(response, "candidates", None)
        if not candidates:
            return []

        tool_calls = []
        for candidate in candidates:
            content = getattr(candidate, "content", None)
            if not content:
                continue

            parts = getattr(content, "parts", None)
            if not parts:
                continue

            for part in parts:
                # Check for function_call attribute
                function_call = getattr(part, "function_call", None)
                if function_call:
                    tool_calls.append(UnifiedToolCall.from_gemini(function_call))

        return tool_calls

    def _extract_from_dict(self, response: dict) -> list[UnifiedToolCall]:
        """Extract tool calls from dictionary response."""
        candidates = response.get("candidates", [])
        tool_calls = []

        for candidate in candidates:
            content = candidate.get("content", {})
            parts = content.get("parts", [])

            for part in parts:
                if "functionCall" in part:
                    # Gemini API returns camelCase
                    fc = part["functionCall"]
                    tool_calls.append(UnifiedToolCall.from_gemini({
                        "name": fc.get("name"),
                        "args": fc.get("args", {}),
                    }))
                elif "function_call" in part:
                    # Handle snake_case variant
                    tool_calls.append(UnifiedToolCall.from_gemini(part["function_call"]))

        return tool_calls

    def extract_response(self, response: Any) -> UnifiedResponse:
        """
        Extract full response from Gemini response.

        Args:
            response: Gemini GenerateContentResponse.

        Returns:
            UnifiedResponse instance.
        """
        tool_calls = self.extract_tool_calls(response)

        # Handle dictionary form
        if isinstance(response, dict):
            text_content = self._extract_text_from_dict(response)
            finish_reason = self._extract_finish_reason_from_dict(response)

            usage = response.get("usageMetadata", {})
            usage_dict = {
                "input_tokens": usage.get("promptTokenCount", 0),
                "output_tokens": usage.get("candidatesTokenCount", 0),
                "total_tokens": usage.get("totalTokenCount", 0),
            }

            return UnifiedResponse(
                content=text_content,
                tool_calls=tool_calls,
                finish_reason=finish_reason,
                provider=Provider.GEMINI,
                usage=usage_dict,
                raw=response,
            )

        # Handle object form
        text_content = self._extract_text_from_object(response)
        finish_reason = self._extract_finish_reason_from_object(response)

        usage_dict = {}
        usage_metadata = getattr(response, "usage_metadata", None)
        if usage_metadata:
            usage_dict = {
                "input_tokens": getattr(usage_metadata, "prompt_token_count", 0),
                "output_tokens": getattr(usage_metadata, "candidates_token_count", 0),
                "total_tokens": getattr(usage_metadata, "total_token_count", 0),
            }

        return UnifiedResponse(
            content=text_content,
            tool_calls=tool_calls,
            finish_reason=finish_reason,
            provider=Provider.GEMINI,
            usage=usage_dict,
            raw=response,
        )

    def _extract_text_from_dict(self, response: dict) -> str | None:
        """Extract text content from dictionary response."""
        candidates = response.get("candidates", [])
        text_parts = []

        for candidate in candidates:
            content = candidate.get("content", {})
            parts = content.get("parts", [])

            for part in parts:
                if "text" in part:
                    text_parts.append(part["text"])

        return "".join(text_parts) if text_parts else None

    def _extract_text_from_object(self, response: Any) -> str | None:
        """Extract text content from object response."""
        candidates = getattr(response, "candidates", [])
        text_parts = []

        for candidate in candidates:
            content = getattr(candidate, "content", None)
            if not content:
                continue

            parts = getattr(content, "parts", [])
            for part in parts:
                text = getattr(part, "text", None)
                if text:
                    text_parts.append(text)

        return "".join(text_parts) if text_parts else None

    def _extract_finish_reason_from_dict(self, response: dict) -> str | None:
        """Extract finish reason from dictionary response."""
        candidates = response.get("candidates", [])
        if candidates:
            return candidates[0].get("finishReason")
        return None

    def _extract_finish_reason_from_object(self, response: Any) -> str | None:
        """Extract finish reason from object response."""
        candidates = getattr(response, "candidates", [])
        if candidates:
            return getattr(candidates[0], "finish_reason", None)
        return None

    def format_tool_result(
        self,
        tool_call: UnifiedToolCall,
        result: Any,
        is_error: bool = False,
    ) -> dict[str, Any]:
        """
        Format tool result for Gemini API.

        Creates a function_response part for continuing the conversation.

        Args:
            tool_call: The original tool call.
            result: The result to send back.
            is_error: Whether the result represents an error.

        Returns:
            Dictionary with function_response part.

        Example:
            >>> result_part = adapter.format_tool_result(
            ...     tool_call,
            ...     {"temperature": 72}
            ... )
            >>> # Use with Vertex AI
            >>> from vertexai.generative_models import Part
            >>> response_part = Part.from_function_response(
            ...     name=tool_call.name,
            ...     response=result_part["response"],
            ... )
        """
        if is_error:
            response_data = {"error": self._serialize_result(result)}
        else:
            # Gemini expects dict response
            response_data = result if isinstance(result, dict) else {"result": result}

        return {
            "function_response": {
                "name": tool_call.name,
                "response": response_data,
            }
        }

    def format_tools(
        self,
        tools: list[Any],
    ) -> list[dict[str, Any]]:
        """
        Format tool definitions for Gemini API.

        Converts ToolDefinition objects to Gemini's function declaration format.

        Args:
            tools: List of ToolDefinition objects.

        Returns:
            List of tool definitions in Gemini format.

        Example:
            >>> gemini_tools = adapter.format_tools(registry.list_enabled())
            >>> from vertexai.generative_models import Tool, FunctionDeclaration
            >>> tool = Tool(function_declarations=[
            ...     FunctionDeclaration(**td) for td in gemini_tools
            ... ])
        """
        formatted = []
        for tool in tools:
            # Check if it's a ToolDefinition
            if hasattr(tool, "to_gemini_format"):
                formatted.append(tool.to_gemini_format())
            elif hasattr(tool, "name") and hasattr(tool, "description"):
                # Manual conversion
                formatted.append({
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": getattr(tool, "parameters", {
                        "type": "object",
                        "properties": {},
                    }),
                })
            elif isinstance(tool, dict):
                # Already in correct format
                formatted.append(tool)

        return formatted

    def format_content_with_results(
        self,
        results: list[tuple[UnifiedToolCall, Any, bool]],
    ) -> list[dict[str, Any]]:
        """
        Format multiple tool results as content parts.

        Args:
            results: List of (tool_call, result, is_error) tuples.

        Returns:
            List of function_response parts.

        Example:
            >>> results = [
            ...     (call1, {"temp": 72}, False),
            ...     (call2, "Error", True),
            ... ]
            >>> response_parts = adapter.format_content_with_results(results)
        """
        return [
            self.format_tool_result(tc, result, is_error)
            for tc, result, is_error in results
        ]

    def create_vertex_tool(self, tools: list[Any]) -> Any:
        """
        Create a Vertex AI Tool object from tool definitions.

        Requires vertexai library to be installed.

        Args:
            tools: List of ToolDefinition objects.

        Returns:
            Vertex AI Tool object.

        Raises:
            ImportError: If vertexai is not installed.
        """
        try:
            from vertexai.generative_models import FunctionDeclaration, Tool
        except ImportError:
            raise ImportError(
                "vertexai library required. Install with: pip install google-cloud-aiplatform"
            ) from None

        formatted = self.format_tools(tools)
        declarations = [FunctionDeclaration(**fd) for fd in formatted]
        return Tool(function_declarations=declarations)

    def create_function_response_part(
        self,
        tool_call: UnifiedToolCall,
        result: Any,
        is_error: bool = False,
    ) -> Any:
        """
        Create a Vertex AI Part object for function response.

        Requires vertexai library to be installed.

        Args:
            tool_call: The original tool call.
            result: The result to send back.
            is_error: Whether the result represents an error.

        Returns:
            Vertex AI Part object.

        Raises:
            ImportError: If vertexai is not installed.
        """
        try:
            from vertexai.generative_models import Part
        except ImportError:
            raise ImportError(
                "vertexai library required. Install with: pip install google-cloud-aiplatform"
            ) from None

        formatted = self.format_tool_result(tool_call, result, is_error)
        return Part.from_function_response(
            name=formatted["function_response"]["name"],
            response=formatted["function_response"]["response"],
        )
