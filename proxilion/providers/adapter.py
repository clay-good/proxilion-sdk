"""
Provider-agnostic tool call interface.

Provides a unified representation of tool calls and responses
across different LLM providers (OpenAI, Anthropic, Google Gemini).
"""

from __future__ import annotations

import json
import logging
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger(__name__)


class Provider(Enum):
    """Supported LLM providers."""

    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GEMINI = "gemini"
    BEDROCK = "bedrock"
    OLLAMA = "ollama"
    UNKNOWN = "unknown"


@dataclass
class UnifiedToolCall:
    """
    Provider-agnostic tool call representation.

    Normalizes tool calls from different providers into a common format
    for authorization and execution.

    Attributes:
        id: Unique identifier for the tool call.
        name: Name of the tool being called.
        arguments: Dictionary of arguments passed to the tool.
        provider: The provider that generated this call.
        raw: Original provider-specific object (for debugging).
        timestamp: When the tool call was extracted.

    Example:
        >>> # From OpenAI response
        >>> call = UnifiedToolCall.from_openai(response.choices[0].message.tool_calls[0])
        >>> print(f"Tool: {call.name}, Args: {call.arguments}")
        >>>
        >>> # From Anthropic response
        >>> call = UnifiedToolCall.from_anthropic(tool_use_block)
    """

    id: str
    name: str
    arguments: dict[str, Any]
    provider: Provider = Provider.UNKNOWN
    raw: Any = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @classmethod
    def from_openai(cls, tool_call: Any) -> UnifiedToolCall:
        """
        Create from OpenAI tool call.

        Args:
            tool_call: OpenAI ChatCompletionMessageToolCall object.

        Returns:
            UnifiedToolCall instance.
        """
        # Handle both dict and object forms
        if isinstance(tool_call, dict):
            call_id = tool_call.get("id", str(uuid.uuid4()))
            function = tool_call.get("function", {})
            name = function.get("name", "unknown")
            arguments_str = function.get("arguments", "{}")
        else:
            call_id = getattr(tool_call, "id", str(uuid.uuid4()))
            function = getattr(tool_call, "function", None)
            if function:
                name = getattr(function, "name", "unknown")
                arguments_str = getattr(function, "arguments", "{}")
            else:
                name = "unknown"
                arguments_str = "{}"

        # Parse arguments JSON
        try:
            if isinstance(arguments_str, str):
                arguments = json.loads(arguments_str)
            else:
                arguments = arguments_str or {}
        except json.JSONDecodeError:
            logger.warning(f"Failed to parse tool call arguments: {arguments_str}")
            arguments = {}

        return cls(
            id=call_id,
            name=name,
            arguments=arguments,
            provider=Provider.OPENAI,
            raw=tool_call,
        )

    @classmethod
    def from_anthropic(cls, tool_use: Any) -> UnifiedToolCall:
        """
        Create from Anthropic tool use block.

        Args:
            tool_use: Anthropic ToolUseBlock object.

        Returns:
            UnifiedToolCall instance.
        """
        # Handle both dict and object forms
        if isinstance(tool_use, dict):
            call_id = tool_use.get("id", str(uuid.uuid4()))
            name = tool_use.get("name", "unknown")
            arguments = tool_use.get("input", {})
        else:
            call_id = getattr(tool_use, "id", str(uuid.uuid4()))
            name = getattr(tool_use, "name", "unknown")
            arguments = getattr(tool_use, "input", {})

        return cls(
            id=call_id,
            name=name,
            arguments=arguments if isinstance(arguments, dict) else {},
            provider=Provider.ANTHROPIC,
            raw=tool_use,
        )

    @classmethod
    def from_gemini(cls, function_call: Any) -> UnifiedToolCall:
        """
        Create from Gemini function call.

        Args:
            function_call: Gemini FunctionCall object.

        Returns:
            UnifiedToolCall instance.
        """
        # Handle both dict and object forms
        if isinstance(function_call, dict):
            name = function_call.get("name", "unknown")
            args = function_call.get("args", {})
        else:
            name = getattr(function_call, "name", "unknown")
            # Gemini args can be a Struct protobuf object
            args_raw = getattr(function_call, "args", {})
            if hasattr(args_raw, "items"):
                args = dict(args_raw.items())
            elif isinstance(args_raw, dict):
                args = args_raw
            else:
                # Try to convert Struct to dict
                try:
                    args = dict(args_raw)
                except (TypeError, ValueError):
                    args = {}

        # Gemini doesn't provide call IDs, generate one
        return cls(
            id=str(uuid.uuid4()),
            name=name,
            arguments=args,
            provider=Provider.GEMINI,
            raw=function_call,
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> UnifiedToolCall:
        """
        Create from dictionary.

        Args:
            data: Dictionary with tool call data.

        Returns:
            UnifiedToolCall instance.
        """
        return cls(
            id=data.get("id", str(uuid.uuid4())),
            name=data.get("name", "unknown"),
            arguments=data.get("arguments", {}),
            provider=Provider(data.get("provider", "unknown")),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "id": self.id,
            "name": self.name,
            "arguments": self.arguments,
            "provider": self.provider.value,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class UnifiedToolResult:
    """
    Provider-agnostic tool result representation.

    Attributes:
        tool_call_id: ID of the corresponding tool call.
        result: The result value.
        is_error: Whether the result is an error.
        error_message: Error message if is_error is True.
    """

    tool_call_id: str
    result: Any
    is_error: bool = False
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "tool_call_id": self.tool_call_id,
            "result": self.result,
            "is_error": self.is_error,
            "error_message": self.error_message,
        }


@dataclass
class UnifiedResponse:
    """
    Provider-agnostic response representation.

    Attributes:
        content: Text content of the response.
        tool_calls: List of tool calls in the response.
        finish_reason: Why the response ended.
        provider: The provider that generated this response.
        usage: Token usage information.
        raw: Original provider-specific response.
    """

    content: str | None = None
    tool_calls: list[UnifiedToolCall] = field(default_factory=list)
    finish_reason: str | None = None
    provider: Provider = Provider.UNKNOWN
    usage: dict[str, int] = field(default_factory=dict)
    raw: Any = None

    def has_tool_calls(self) -> bool:
        """Check if response contains tool calls."""
        return len(self.tool_calls) > 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "content": self.content,
            "tool_calls": [tc.to_dict() for tc in self.tool_calls],
            "finish_reason": self.finish_reason,
            "provider": self.provider.value,
            "usage": self.usage,
        }


@runtime_checkable
class ProviderAdapter(Protocol):
    """
    Protocol for provider adapters.

    Each adapter translates between provider-specific formats
    and the unified format used by Proxilion.
    """

    @property
    def provider(self) -> Provider:
        """Get the provider type."""
        ...

    def extract_tool_calls(self, response: Any) -> list[UnifiedToolCall]:
        """
        Extract tool calls from a provider response.

        Args:
            response: Provider-specific response object.

        Returns:
            List of unified tool calls.
        """
        ...

    def extract_response(self, response: Any) -> UnifiedResponse:
        """
        Extract full response including content and tool calls.

        Args:
            response: Provider-specific response object.

        Returns:
            UnifiedResponse instance.
        """
        ...

    def format_tool_result(
        self,
        tool_call: UnifiedToolCall,
        result: Any,
        is_error: bool = False,
    ) -> Any:
        """
        Format tool result for the provider.

        Args:
            tool_call: The original tool call.
            result: The result to format.
            is_error: Whether the result is an error.

        Returns:
            Provider-specific message format.
        """
        ...

    def format_tools(
        self,
        tools: list[Any],  # list[ToolDefinition]
    ) -> list[dict[str, Any]]:
        """
        Format tool definitions for the provider.

        Args:
            tools: List of ToolDefinition objects.

        Returns:
            List of provider-specific tool definitions.
        """
        ...


class BaseAdapter(ABC):
    """
    Base class for provider adapters.

    Provides common functionality and enforces the adapter interface.
    """

    @property
    @abstractmethod
    def provider(self) -> Provider:
        """Get the provider type."""
        ...

    @abstractmethod
    def extract_tool_calls(self, response: Any) -> list[UnifiedToolCall]:
        """Extract tool calls from response."""
        ...

    @abstractmethod
    def extract_response(self, response: Any) -> UnifiedResponse:
        """Extract full response."""
        ...

    @abstractmethod
    def format_tool_result(
        self,
        tool_call: UnifiedToolCall,
        result: Any,
        is_error: bool = False,
    ) -> Any:
        """Format tool result for provider."""
        ...

    @abstractmethod
    def format_tools(
        self,
        tools: list[Any],
    ) -> list[dict[str, Any]]:
        """Format tool definitions for provider."""
        ...

    def _serialize_result(self, result: Any) -> str:
        """Serialize a result to string format."""
        if isinstance(result, str):
            return result
        try:
            return json.dumps(result, default=str)
        except (TypeError, ValueError):
            return str(result)


def detect_provider(response: Any) -> Provider:
    """
    Auto-detect provider from response object.

    Examines the response type and module to determine
    which provider generated it.

    Args:
        response: Provider response object.

    Returns:
        Detected Provider enum value.

    Raises:
        ValueError: If provider cannot be detected.

    Example:
        >>> from openai import OpenAI
        >>> response = client.chat.completions.create(...)
        >>> provider = detect_provider(response)
        >>> assert provider == Provider.OPENAI
    """
    type_name = type(response).__name__
    module = type(response).__module__

    # Check module name
    module_lower = module.lower()

    if "openai" in module_lower:
        return Provider.OPENAI
    elif "anthropic" in module_lower:
        return Provider.ANTHROPIC
    elif (
        "vertexai" in module_lower
        or "google.generativeai" in module_lower
        or ("google" in module_lower and "aiplatform" in module_lower)
    ):
        return Provider.GEMINI

    # Check type name patterns
    if "ChatCompletion" in type_name:
        return Provider.OPENAI
    elif "Message" in type_name and hasattr(response, "content"):
        # Anthropic messages have content attribute that's a list
        content = getattr(response, "content", None)
        if isinstance(content, list):
            return Provider.ANTHROPIC
    elif "GenerateContentResponse" in type_name or "GenerationResponse" in type_name:
        return Provider.GEMINI

    # Check for specific attributes
    if hasattr(response, "choices") and hasattr(response, "model"):
        return Provider.OPENAI
    elif hasattr(response, "candidates"):
        return Provider.GEMINI
    elif hasattr(response, "stop_reason"):
        return Provider.ANTHROPIC

    raise ValueError(f"Unknown provider for response type: {module}.{type_name}")


def detect_provider_safe(response: Any) -> Provider:
    """
    Safely detect provider, returning UNKNOWN if detection fails.

    Args:
        response: Provider response object.

    Returns:
        Detected Provider or Provider.UNKNOWN.
    """
    try:
        return detect_provider(response)
    except ValueError:
        return Provider.UNKNOWN
