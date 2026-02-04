"""
Comprehensive tests for the Provider Adapters module.

Tests cover:
- Provider enum and detection
- UnifiedToolCall and UnifiedResponse dataclasses
- OpenAI adapter
- Anthropic adapter
- Gemini adapter
- Adapter registry and factory functions
- Integration with Proxilion core
"""

import json
from unittest.mock import MagicMock

import pytest

from proxilion import Proxilion
from proxilion.providers import (
    AnthropicAdapter,
    BaseAdapter,
    GeminiAdapter,
    OpenAIAdapter,
    Provider,
    UnifiedResponse,
    UnifiedToolCall,
    detect_provider,
    detect_provider_safe,
    extract_response,
    extract_tool_calls,
    get_adapter,
    list_providers,
    register_adapter,
)
from proxilion.tools.registry import ToolCategory, ToolDefinition
from proxilion.types import UserContext

# =============================================================================
# Provider Enum Tests
# =============================================================================


class TestProvider:
    """Tests for Provider enum."""

    def test_all_providers_exist(self):
        """All expected providers exist."""
        assert Provider.OPENAI.value == "openai"
        assert Provider.ANTHROPIC.value == "anthropic"
        assert Provider.GEMINI.value == "gemini"
        assert Provider.BEDROCK.value == "bedrock"
        assert Provider.OLLAMA.value == "ollama"
        assert Provider.UNKNOWN.value == "unknown"


# =============================================================================
# UnifiedToolCall Tests
# =============================================================================


class TestUnifiedToolCall:
    """Tests for UnifiedToolCall dataclass."""

    def test_create_basic_tool_call(self):
        """Create a basic unified tool call."""
        call = UnifiedToolCall(
            id="call_123",
            name="get_weather",
            arguments={"location": "NYC"},
        )

        assert call.id == "call_123"
        assert call.name == "get_weather"
        assert call.arguments == {"location": "NYC"}
        assert call.provider == Provider.UNKNOWN

    def test_from_openai_dict(self):
        """Create from OpenAI dict format."""
        openai_call = {
            "id": "call_abc123",
            "type": "function",
            "function": {
                "name": "search",
                "arguments": '{"query": "python"}',
            }
        }

        call = UnifiedToolCall.from_openai(openai_call)

        assert call.id == "call_abc123"
        assert call.name == "search"
        assert call.arguments == {"query": "python"}
        assert call.provider == Provider.OPENAI

    def test_from_openai_object(self):
        """Create from OpenAI object format."""
        # Mock OpenAI tool call object
        mock_function = MagicMock()
        mock_function.name = "calculate"
        mock_function.arguments = '{"x": 5, "y": 3}'

        mock_call = MagicMock()
        mock_call.id = "call_xyz"
        mock_call.function = mock_function

        call = UnifiedToolCall.from_openai(mock_call)

        assert call.id == "call_xyz"
        assert call.name == "calculate"
        assert call.arguments == {"x": 5, "y": 3}

    def test_from_openai_invalid_json(self):
        """Handle invalid JSON in OpenAI arguments."""
        openai_call = {
            "id": "call_bad",
            "function": {
                "name": "test",
                "arguments": "not valid json",
            }
        }

        call = UnifiedToolCall.from_openai(openai_call)

        assert call.name == "test"
        assert call.arguments == {}  # Should fallback to empty dict

    def test_from_anthropic_dict(self):
        """Create from Anthropic dict format."""
        anthropic_block = {
            "type": "tool_use",
            "id": "toolu_123",
            "name": "read_file",
            "input": {"path": "/tmp/test.txt"},
        }

        call = UnifiedToolCall.from_anthropic(anthropic_block)

        assert call.id == "toolu_123"
        assert call.name == "read_file"
        assert call.arguments == {"path": "/tmp/test.txt"}
        assert call.provider == Provider.ANTHROPIC

    def test_from_anthropic_object(self):
        """Create from Anthropic object format."""
        mock_block = MagicMock()
        mock_block.id = "toolu_xyz"
        mock_block.name = "write_file"
        mock_block.input = {"path": "/tmp/out.txt", "content": "hello"}

        call = UnifiedToolCall.from_anthropic(mock_block)

        assert call.id == "toolu_xyz"
        assert call.name == "write_file"
        assert call.arguments == {"path": "/tmp/out.txt", "content": "hello"}

    def test_from_gemini_dict(self):
        """Create from Gemini dict format."""
        gemini_call = {
            "name": "search_db",
            "args": {"query": "users", "limit": 10},
        }

        call = UnifiedToolCall.from_gemini(gemini_call)

        assert call.name == "search_db"
        assert call.arguments == {"query": "users", "limit": 10}
        assert call.provider == Provider.GEMINI
        assert call.id is not None  # Generated UUID

    def test_from_dict(self):
        """Create from generic dictionary."""
        data = {
            "id": "call_123",
            "name": "my_tool",
            "arguments": {"key": "value"},
            "provider": "openai",
        }

        call = UnifiedToolCall.from_dict(data)

        assert call.id == "call_123"
        assert call.name == "my_tool"
        assert call.arguments == {"key": "value"}
        assert call.provider == Provider.OPENAI

    def test_to_dict(self):
        """Convert to dictionary."""
        call = UnifiedToolCall(
            id="call_123",
            name="test_tool",
            arguments={"arg": "value"},
            provider=Provider.ANTHROPIC,
        )

        d = call.to_dict()

        assert d["id"] == "call_123"
        assert d["name"] == "test_tool"
        assert d["arguments"] == {"arg": "value"}
        assert d["provider"] == "anthropic"
        assert "timestamp" in d


# =============================================================================
# UnifiedResponse Tests
# =============================================================================


class TestUnifiedResponse:
    """Tests for UnifiedResponse dataclass."""

    def test_create_basic_response(self):
        """Create a basic unified response."""
        response = UnifiedResponse(
            content="Hello, world!",
            provider=Provider.OPENAI,
        )

        assert response.content == "Hello, world!"
        assert response.tool_calls == []
        assert response.has_tool_calls() is False

    def test_response_with_tool_calls(self):
        """Response with tool calls."""
        calls = [
            UnifiedToolCall(id="1", name="tool1", arguments={}),
            UnifiedToolCall(id="2", name="tool2", arguments={}),
        ]

        response = UnifiedResponse(
            content=None,
            tool_calls=calls,
            finish_reason="tool_calls",
        )

        assert response.has_tool_calls() is True
        assert len(response.tool_calls) == 2

    def test_to_dict(self):
        """Convert response to dictionary."""
        response = UnifiedResponse(
            content="Test",
            finish_reason="stop",
            provider=Provider.ANTHROPIC,
            usage={"input_tokens": 100, "output_tokens": 50},
        )

        d = response.to_dict()

        assert d["content"] == "Test"
        assert d["finish_reason"] == "stop"
        assert d["provider"] == "anthropic"
        assert d["usage"]["input_tokens"] == 100


# =============================================================================
# Provider Detection Tests
# =============================================================================


class TestProviderDetection:
    """Tests for provider detection."""

    def test_detect_openai_by_module(self):
        """Detect OpenAI from module name."""
        mock_response = MagicMock()
        mock_response.__class__.__module__ = "openai.types.chat"
        mock_response.__class__.__name__ = "ChatCompletion"

        provider = detect_provider(mock_response)
        assert provider == Provider.OPENAI

    def test_detect_anthropic_by_module(self):
        """Detect Anthropic from module name."""
        mock_response = MagicMock()
        mock_response.__class__.__module__ = "anthropic.types"
        mock_response.__class__.__name__ = "Message"
        mock_response.content = []  # Anthropic messages have list content

        provider = detect_provider(mock_response)
        assert provider == Provider.ANTHROPIC

    def test_detect_gemini_by_module(self):
        """Detect Gemini from module name."""
        mock_response = MagicMock()
        mock_response.__class__.__module__ = "vertexai.generative_models"
        mock_response.__class__.__name__ = "GenerateContentResponse"

        provider = detect_provider(mock_response)
        assert provider == Provider.GEMINI

    def test_detect_by_type_name(self):
        """Detect by type name pattern."""
        mock_response = MagicMock()
        mock_response.__class__.__module__ = "some.module"
        mock_response.__class__.__name__ = "ChatCompletion"

        provider = detect_provider(mock_response)
        assert provider == Provider.OPENAI

    def test_detect_by_attributes(self):
        """Detect by response attributes."""
        mock_response = MagicMock()
        mock_response.__class__.__module__ = "unknown"
        mock_response.__class__.__name__ = "Response"
        mock_response.choices = []
        mock_response.model = "gpt-4"

        provider = detect_provider(mock_response)
        assert provider == Provider.OPENAI

    def test_detect_unknown_raises(self):
        """Unknown response raises ValueError."""
        mock_response = MagicMock()
        mock_response.__class__.__module__ = "unknown"
        mock_response.__class__.__name__ = "UnknownResponse"

        # Remove attributes that would help detection
        del mock_response.choices
        del mock_response.candidates
        del mock_response.content
        del mock_response.stop_reason

        with pytest.raises(ValueError, match="Unknown provider"):
            detect_provider(mock_response)

    def test_detect_provider_safe(self):
        """Safe detection returns UNKNOWN on failure."""
        # Create a simple object that doesn't match any provider heuristics
        # MagicMock has .model and .choices which trigger OpenAI detection
        class UnknownType:
            pass

        mock_response = UnknownType()
        mock_response.__class__.__module__ = "completely_unknown_package"
        mock_response.__class__.__name__ = "UnknownResponse"

        provider = detect_provider_safe(mock_response)
        assert provider == Provider.UNKNOWN


# =============================================================================
# OpenAI Adapter Tests
# =============================================================================


class TestOpenAIAdapter:
    """Tests for OpenAIAdapter."""

    def test_provider_property(self):
        """Adapter has correct provider."""
        adapter = OpenAIAdapter()
        assert adapter.provider == Provider.OPENAI

    def test_extract_tool_calls_from_dict(self):
        """Extract tool calls from dict response."""
        adapter = OpenAIAdapter()

        response = {
            "choices": [{
                "message": {
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {
                                "name": "get_weather",
                                "arguments": '{"city": "NYC"}',
                            }
                        },
                        {
                            "id": "call_2",
                            "type": "function",
                            "function": {
                                "name": "get_time",
                                "arguments": '{"timezone": "EST"}',
                            }
                        }
                    ]
                },
                "finish_reason": "tool_calls"
            }]
        }

        calls = adapter.extract_tool_calls(response)

        assert len(calls) == 2
        assert calls[0].name == "get_weather"
        assert calls[0].arguments == {"city": "NYC"}
        assert calls[1].name == "get_time"

    def test_extract_tool_calls_empty(self):
        """Extract from response with no tool calls."""
        adapter = OpenAIAdapter()

        response = {
            "choices": [{
                "message": {
                    "content": "Hello!",
                    "tool_calls": None
                }
            }]
        }

        calls = adapter.extract_tool_calls(response)
        assert len(calls) == 0

    def test_extract_response(self):
        """Extract full response."""
        adapter = OpenAIAdapter()

        response = {
            "choices": [{
                "message": {
                    "content": "Here's the result",
                    "tool_calls": None
                },
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": 100,
                "completion_tokens": 50,
                "total_tokens": 150
            }
        }

        unified = adapter.extract_response(response)

        assert unified.content == "Here's the result"
        assert unified.finish_reason == "stop"
        assert unified.usage["input_tokens"] == 100
        assert unified.usage["output_tokens"] == 50

    def test_format_tool_result(self):
        """Format tool result for OpenAI."""
        adapter = OpenAIAdapter()
        call = UnifiedToolCall(id="call_123", name="test", arguments={})

        result = adapter.format_tool_result(call, {"key": "value"})

        assert result["role"] == "tool"
        assert result["tool_call_id"] == "call_123"
        assert json.loads(result["content"]) == {"key": "value"}

    def test_format_tool_result_error(self):
        """Format error result for OpenAI."""
        adapter = OpenAIAdapter()
        call = UnifiedToolCall(id="call_err", name="test", arguments={})

        result = adapter.format_tool_result(call, "Something went wrong", is_error=True)

        content = json.loads(result["content"])
        assert "error" in content

    def test_format_tools(self):
        """Format tool definitions for OpenAI."""
        adapter = OpenAIAdapter()

        tools = [
            ToolDefinition(
                name="search",
                description="Search the web",
                parameters={
                    "type": "object",
                    "properties": {"query": {"type": "string"}},
                    "required": ["query"]
                },
                category=ToolCategory.SEARCH,
            )
        ]

        formatted = adapter.format_tools(tools)

        assert len(formatted) == 1
        assert formatted[0]["type"] == "function"
        assert formatted[0]["function"]["name"] == "search"

    def test_format_assistant_message(self):
        """Format assistant message with tool calls."""
        adapter = OpenAIAdapter()
        calls = [
            UnifiedToolCall(id="call_1", name="tool1", arguments={"x": 1}),
        ]

        msg = adapter.format_assistant_message("Thinking...", calls)

        assert msg["role"] == "assistant"
        assert msg["content"] == "Thinking..."
        assert len(msg["tool_calls"]) == 1
        assert msg["tool_calls"][0]["function"]["name"] == "tool1"


# =============================================================================
# Anthropic Adapter Tests
# =============================================================================


class TestAnthropicAdapter:
    """Tests for AnthropicAdapter."""

    def test_provider_property(self):
        """Adapter has correct provider."""
        adapter = AnthropicAdapter()
        assert adapter.provider == Provider.ANTHROPIC

    def test_extract_tool_calls_from_dict(self):
        """Extract tool calls from dict response."""
        adapter = AnthropicAdapter()

        response = {
            "content": [
                {"type": "text", "text": "Let me search for that."},
                {
                    "type": "tool_use",
                    "id": "toolu_123",
                    "name": "search",
                    "input": {"query": "python"},
                }
            ],
            "stop_reason": "tool_use"
        }

        calls = adapter.extract_tool_calls(response)

        assert len(calls) == 1
        assert calls[0].name == "search"
        assert calls[0].arguments == {"query": "python"}

    def test_extract_response(self):
        """Extract full response."""
        adapter = AnthropicAdapter()

        response = {
            "content": [
                {"type": "text", "text": "Here is the answer."},
            ],
            "stop_reason": "end_turn",
            "usage": {
                "input_tokens": 50,
                "output_tokens": 20
            }
        }

        unified = adapter.extract_response(response)

        assert unified.content == "Here is the answer."
        assert unified.finish_reason == "end_turn"
        assert unified.usage["input_tokens"] == 50

    def test_format_tool_result(self):
        """Format tool result for Anthropic."""
        adapter = AnthropicAdapter()
        call = UnifiedToolCall(id="toolu_123", name="test", arguments={})

        result = adapter.format_tool_result(call, {"data": "value"})

        assert result["type"] == "tool_result"
        assert result["tool_use_id"] == "toolu_123"
        assert result["is_error"] is False

    def test_format_tools(self):
        """Format tool definitions for Anthropic."""
        adapter = AnthropicAdapter()

        tools = [
            ToolDefinition(
                name="calculator",
                description="Perform calculations",
                parameters={
                    "type": "object",
                    "properties": {"expression": {"type": "string"}},
                },
                category=ToolCategory.COMPUTE,
            )
        ]

        formatted = adapter.format_tools(tools)

        assert len(formatted) == 1
        assert formatted[0]["name"] == "calculator"
        assert "input_schema" in formatted[0]

    def test_format_user_message_with_results(self):
        """Format user message with multiple results."""
        adapter = AnthropicAdapter()

        results = [
            (UnifiedToolCall(id="1", name="a", arguments={}), {"r": 1}, False),
            (UnifiedToolCall(id="2", name="b", arguments={}), "error", True),
        ]

        msg = adapter.format_user_message_with_results(results)

        assert msg["role"] == "user"
        assert len(msg["content"]) == 2


# =============================================================================
# Gemini Adapter Tests
# =============================================================================


class TestGeminiAdapter:
    """Tests for GeminiAdapter."""

    def test_provider_property(self):
        """Adapter has correct provider."""
        adapter = GeminiAdapter()
        assert adapter.provider == Provider.GEMINI

    def test_extract_tool_calls_from_dict(self):
        """Extract tool calls from dict response."""
        adapter = GeminiAdapter()

        response = {
            "candidates": [{
                "content": {
                    "parts": [
                        {
                            "functionCall": {
                                "name": "search_db",
                                "args": {"query": "users"}
                            }
                        }
                    ]
                }
            }]
        }

        calls = adapter.extract_tool_calls(response)

        assert len(calls) == 1
        assert calls[0].name == "search_db"
        assert calls[0].arguments == {"query": "users"}

    def test_extract_response(self):
        """Extract full response."""
        adapter = GeminiAdapter()

        response = {
            "candidates": [{
                "content": {
                    "parts": [{"text": "The answer is 42."}]
                },
                "finishReason": "STOP"
            }],
            "usageMetadata": {
                "promptTokenCount": 100,
                "candidatesTokenCount": 20,
                "totalTokenCount": 120
            }
        }

        unified = adapter.extract_response(response)

        assert unified.content == "The answer is 42."
        assert unified.usage["input_tokens"] == 100

    def test_format_tool_result(self):
        """Format tool result for Gemini."""
        adapter = GeminiAdapter()
        call = UnifiedToolCall(id="gen_123", name="search", arguments={})

        result = adapter.format_tool_result(call, {"items": [1, 2, 3]})

        assert "function_response" in result
        assert result["function_response"]["name"] == "search"
        assert result["function_response"]["response"]["items"] == [1, 2, 3]

    def test_format_tools(self):
        """Format tool definitions for Gemini."""
        adapter = GeminiAdapter()

        tools = [
            ToolDefinition(
                name="get_data",
                description="Get data from API",
                parameters={
                    "type": "object",
                    "properties": {"id": {"type": "string"}},
                },
                category=ToolCategory.API,
            )
        ]

        formatted = adapter.format_tools(tools)

        assert len(formatted) == 1
        assert formatted[0]["name"] == "get_data"
        assert "parameters" in formatted[0]


# =============================================================================
# Adapter Factory Tests
# =============================================================================


class TestAdapterFactory:
    """Tests for adapter factory functions."""

    def test_get_adapter_by_name(self):
        """Get adapter by provider name."""
        adapter = get_adapter(provider="openai")
        assert isinstance(adapter, OpenAIAdapter)

        adapter = get_adapter(provider="anthropic")
        assert isinstance(adapter, AnthropicAdapter)

        adapter = get_adapter(provider="gemini")
        assert isinstance(adapter, GeminiAdapter)

    def test_get_adapter_by_enum(self):
        """Get adapter by Provider enum."""
        adapter = get_adapter(provider=Provider.OPENAI)
        assert isinstance(adapter, OpenAIAdapter)

    def test_get_adapter_aliases(self):
        """Test provider name aliases."""
        adapter1 = get_adapter(provider="gemini")
        adapter2 = get_adapter(provider="vertexai")
        adapter3 = get_adapter(provider="google")

        assert isinstance(adapter1, GeminiAdapter)
        assert isinstance(adapter2, GeminiAdapter)
        assert isinstance(adapter3, GeminiAdapter)

    def test_get_adapter_unknown_raises(self):
        """Unknown provider raises ValueError."""
        with pytest.raises(ValueError, match="Unknown provider"):
            get_adapter(provider="unknown_provider")

    def test_get_adapter_no_args_raises(self):
        """No arguments raises ValueError."""
        with pytest.raises(ValueError, match="Must specify"):
            get_adapter()

    def test_register_adapter(self):
        """Register a custom adapter."""
        class CustomAdapter(BaseAdapter):
            @property
            def provider(self):
                return Provider.UNKNOWN

            def extract_tool_calls(self, response):
                return []

            def extract_response(self, response):
                return UnifiedResponse()

            def format_tool_result(self, tool_call, result, is_error=False):
                return {}

            def format_tools(self, tools):
                return []

        register_adapter("custom", CustomAdapter)

        adapter = get_adapter(provider="custom")
        assert isinstance(adapter, CustomAdapter)

    def test_list_providers(self):
        """List all registered providers."""
        providers = list_providers()

        assert "openai" in providers
        assert "anthropic" in providers
        assert "gemini" in providers


# =============================================================================
# Convenience Functions Tests
# =============================================================================


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_extract_tool_calls_function(self):
        """Test extract_tool_calls convenience function."""
        # Create mock response with identifiable attributes
        mock_response = MagicMock()
        mock_response.__class__.__module__ = "openai.types"
        mock_response.__class__.__name__ = "ChatCompletion"

        mock_message = MagicMock()
        mock_message.content = "test"
        mock_message.tool_calls = []

        mock_choice = MagicMock()
        mock_choice.message = mock_message

        mock_response.choices = [mock_choice]

        calls = extract_tool_calls(mock_response)
        assert calls == []

    def test_extract_response_function(self):
        """Test extract_response convenience function."""
        mock_response = MagicMock()
        mock_response.__class__.__module__ = "openai.types"
        mock_response.__class__.__name__ = "ChatCompletion"

        mock_message = MagicMock()
        mock_message.content = "Hello"
        mock_message.tool_calls = None

        mock_choice = MagicMock()
        mock_choice.message = mock_message
        mock_choice.finish_reason = "stop"

        mock_response.choices = [mock_choice]
        mock_response.usage = None

        unified = extract_response(mock_response)
        assert unified.content == "Hello"


# =============================================================================
# Proxilion Integration Tests
# =============================================================================


class TestProxilionProviderIntegration:
    """Tests for provider integration with Proxilion core."""

    def test_get_provider_adapter(self):
        """Get provider adapter via Proxilion."""
        auth = Proxilion()
        adapter = auth.get_provider_adapter("openai")
        assert isinstance(adapter, OpenAIAdapter)

    def test_extract_tool_calls_from_response(self):
        """Extract tool calls via Proxilion."""
        auth = Proxilion()

        # Mock OpenAI response
        mock_response = MagicMock()
        mock_response.__class__.__module__ = "openai.types"
        mock_response.__class__.__name__ = "ChatCompletion"

        mock_function = MagicMock()
        mock_function.name = "test_tool"
        mock_function.arguments = '{"arg": "value"}'

        mock_tool_call = MagicMock()
        mock_tool_call.id = "call_123"
        mock_tool_call.function = mock_function

        mock_message = MagicMock()
        mock_message.tool_calls = [mock_tool_call]

        mock_choice = MagicMock()
        mock_choice.message = mock_message

        mock_response.choices = [mock_choice]

        calls = auth.extract_tool_calls_from_response(mock_response)

        assert len(calls) == 1
        assert calls[0].name == "test_tool"
        assert calls[0].arguments == {"arg": "value"}

    def test_authorize_tool_calls(self):
        """Authorize tool calls via Proxilion."""
        auth = Proxilion()

        # Register policy
        from proxilion.policies.base import Policy

        @auth.policy("allowed_tool")
        class AllowedPolicy(Policy):
            def can_execute(self, context):
                return True

        @auth.policy("denied_tool")
        class DeniedPolicy(Policy):
            def can_execute(self, context):
                return False

        user = UserContext(user_id="test_user", roles=["user"])
        tool_calls = [
            UnifiedToolCall(id="1", name="allowed_tool", arguments={}),
            UnifiedToolCall(id="2", name="denied_tool", arguments={}),
        ]

        results = auth.authorize_tool_calls(user, tool_calls)

        assert len(results) == 2
        assert results[0][1].allowed is True
        assert results[1][1].allowed is False

    def test_export_tools_for_provider(self):
        """Export tools for provider via Proxilion."""
        auth = Proxilion()

        @auth.tool(name="my_tool", description="A test tool")
        def my_tool(x: int) -> int:
            return x * 2

        # Export for OpenAI
        openai_tools = auth.export_tools_for_provider("openai")
        assert len(openai_tools) == 1
        assert openai_tools[0]["type"] == "function"
        assert openai_tools[0]["function"]["name"] == "my_tool"

        # Export for Anthropic
        anthropic_tools = auth.export_tools_for_provider("anthropic")
        assert len(anthropic_tools) == 1
        assert "input_schema" in anthropic_tools[0]

        # Export for Gemini
        gemini_tools = auth.export_tools_for_provider("gemini")
        assert len(gemini_tools) == 1
        assert "parameters" in gemini_tools[0]

    def test_format_tool_results(self):
        """Format tool results via Proxilion."""
        auth = Proxilion()

        results = [
            (UnifiedToolCall(id="1", name="tool1", arguments={}), {"data": 42}, False),
            (UnifiedToolCall(id="2", name="tool2", arguments={}), "Error!", True),
        ]

        # Format for OpenAI
        formatted = auth.format_tool_results(results, "openai")
        assert len(formatted) == 2
        assert formatted[0]["role"] == "tool"
        assert formatted[0]["tool_call_id"] == "1"

    @pytest.mark.asyncio
    async def test_process_response_with_authorization(self):
        """Process response with authorization via Proxilion."""
        auth = Proxilion()

        # Register a tool and policy
        @auth.tool(name="test_tool")
        def test_tool(x: int) -> int:
            return x * 2

        from proxilion.policies.base import Policy

        @auth.policy("test_tool")
        class TestToolPolicy(Policy):
            def can_execute(self, context):
                return True

        # Create mock response
        mock_response = {
            "choices": [{
                "message": {
                    "content": None,
                    "tool_calls": [{
                        "id": "call_1",
                        "function": {
                            "name": "test_tool",
                            "arguments": '{"x": 5}',
                        }
                    }]
                },
                "finish_reason": "tool_calls"
            }],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
        }

        user = UserContext(user_id="test_user", roles=["user"])

        result = await auth.process_response_with_authorization(
            mock_response,
            user,
            provider="openai",
            execute_tools=True,
        )

        assert len(result["authorized_calls"]) == 1
        assert len(result["denied_calls"]) == 0
        assert len(result["execution_results"]) == 1
        assert result["execution_results"][0][1].result == 10  # 5 * 2


# =============================================================================
# Edge Cases Tests
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_response(self):
        """Handle empty response."""
        adapter = OpenAIAdapter()
        response = {"choices": []}

        calls = adapter.extract_tool_calls(response)
        assert calls == []

    def test_null_tool_calls(self):
        """Handle null tool_calls field."""
        adapter = OpenAIAdapter()
        response = {
            "choices": [{
                "message": {"content": "Hello", "tool_calls": None}
            }]
        }

        calls = adapter.extract_tool_calls(response)
        assert calls == []

    def test_missing_fields(self):
        """Handle missing fields gracefully."""
        adapter = AnthropicAdapter()
        response = {"content": []}

        calls = adapter.extract_tool_calls(response)
        assert calls == []

    def test_serialization_complex_result(self):
        """Serialize complex result types."""
        adapter = OpenAIAdapter()
        call = UnifiedToolCall(id="1", name="test", arguments={})

        # Test with various types
        result1 = adapter.format_tool_result(call, "string")
        assert result1["content"] == "string"

        result2 = adapter.format_tool_result(call, 42)
        assert result2["content"] == "42"

        result3 = adapter.format_tool_result(call, {"key": "value"})
        assert json.loads(result3["content"]) == {"key": "value"}

    def test_adapter_caching(self):
        """Adapters are cached."""
        adapter1 = get_adapter(provider="openai")
        adapter2 = get_adapter(provider="openai")
        assert adapter1 is adapter2

    def test_tool_definition_formats(self):
        """Test various tool definition input formats."""
        adapter = OpenAIAdapter()

        # Dict format
        tools1 = adapter.format_tools([{
            "type": "function",
            "function": {"name": "test", "description": "Test"},
        }])
        assert len(tools1) == 1

        # Dict without type wrapper
        tools2 = adapter.format_tools([{
            "name": "test",
            "description": "Test",
            "parameters": {"type": "object"},
        }])
        assert len(tools2) == 1

    def test_gemini_protobuf_args(self):
        """Handle Gemini protobuf args format."""
        _adapter = GeminiAdapter()

        # Mock a Struct-like object
        mock_args = MagicMock()
        mock_args.items.return_value = [("key", "value")]

        mock_call = MagicMock()
        mock_call.name = "test"
        mock_call.args = mock_args

        call = UnifiedToolCall.from_gemini(mock_call)
        assert call.arguments == {"key": "value"}
