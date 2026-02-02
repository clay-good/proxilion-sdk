"""
Tests for Google Vertex AI / Gemini integration.

Tests the ProxilionVertexHandler, function call extraction,
authorization flow, and result formatting.
"""

from __future__ import annotations

import pytest
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock, AsyncMock

from proxilion import Proxilion, Policy, UserContext
from proxilion.contrib.google import (
    ProxilionVertexHandler,
    GeminiFunctionCall,
    GeminiToolResult,
    RegisteredGeminiTool,
    GoogleIntegrationError,
    ToolNotFoundError,
    ToolExecutionError,
    extract_function_calls,
    format_tool_response,
    to_gemini_tools,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def proxilion():
    """Create a Proxilion instance with test policies."""
    auth = Proxilion()

    @auth.policy("weather_api")
    class WeatherPolicy(Policy):
        def can_execute(self, context):
            return True

    @auth.policy("database")
    class DatabasePolicy(Policy):
        def can_execute(self, context):
            # Only allow admins to access database
            # self.user is set by Policy.__init__(user, resource)
            return "admin" in self.user.roles

    @auth.policy("public_api")
    class PublicPolicy(Policy):
        def can_execute(self, context):
            return True

    return auth


@pytest.fixture
def handler(proxilion):
    """Create a ProxilionVertexHandler."""
    return ProxilionVertexHandler(proxilion)


@pytest.fixture
def user():
    """Create a test user."""
    return UserContext(user_id="user_123", roles=["user"])


@pytest.fixture
def admin_user():
    """Create an admin user."""
    return UserContext(user_id="admin_456", roles=["admin", "user"])


@pytest.fixture
def weather_tool_declaration():
    """Weather tool declaration."""
    return {
        "name": "get_weather",
        "description": "Get the current weather for a location",
        "parameters": {
            "type": "object",
            "properties": {
                "location": {
                    "type": "string",
                    "description": "City name",
                },
                "units": {
                    "type": "string",
                    "enum": ["celsius", "fahrenheit"],
                },
            },
            "required": ["location"],
        },
    }


@pytest.fixture
def database_tool_declaration():
    """Database tool declaration."""
    return {
        "name": "query_database",
        "description": "Query the database",
        "parameters": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "limit": {"type": "integer"},
            },
            "required": ["query"],
        },
    }


# =============================================================================
# GeminiFunctionCall Tests
# =============================================================================


class TestGeminiFunctionCall:
    """Tests for GeminiFunctionCall dataclass."""

    def test_create_basic_call(self):
        """Create a basic function call."""
        call = GeminiFunctionCall(
            name="get_weather",
            args={"location": "San Francisco"},
        )

        assert call.name == "get_weather"
        assert call.args == {"location": "San Francisco"}
        assert call.raw is None

    def test_create_call_with_raw(self):
        """Create function call with raw object."""
        raw = MagicMock()
        call = GeminiFunctionCall(
            name="search",
            args={"query": "test"},
            raw=raw,
        )

        assert call.raw is raw

    def test_to_dict(self):
        """Convert to dictionary."""
        call = GeminiFunctionCall(
            name="get_weather",
            args={"location": "NYC", "units": "fahrenheit"},
        )

        result = call.to_dict()

        assert result["name"] == "get_weather"
        assert result["args"] == {"location": "NYC", "units": "fahrenheit"}


# =============================================================================
# GeminiToolResult Tests
# =============================================================================


class TestGeminiToolResult:
    """Tests for GeminiToolResult dataclass."""

    def test_create_success_result(self):
        """Create a successful result."""
        result = GeminiToolResult(
            name="get_weather",
            success=True,
            result={"temp": 72, "condition": "sunny"},
        )

        assert result.name == "get_weather"
        assert result.success is True
        assert result.result == {"temp": 72, "condition": "sunny"}
        assert result.error is None
        assert result.authorized is True

    def test_create_error_result(self):
        """Create an error result."""
        result = GeminiToolResult(
            name="get_weather",
            success=False,
            error="Location not found",
        )

        assert result.success is False
        assert result.error == "Location not found"
        assert result.result is None

    def test_create_unauthorized_result(self):
        """Create an unauthorized result."""
        result = GeminiToolResult(
            name="query_database",
            success=False,
            error="Not authorized",
            authorized=False,
        )

        assert result.authorized is False
        assert result.error == "Not authorized"

    def test_timestamp_auto_generated(self):
        """Timestamp is auto-generated."""
        before = datetime.now(timezone.utc)
        result = GeminiToolResult(name="test", success=True)
        after = datetime.now(timezone.utc)

        assert before <= result.timestamp <= after

    def test_to_dict(self):
        """Convert to dictionary."""
        result = GeminiToolResult(
            name="get_weather",
            success=True,
            result={"temp": 72},
        )

        data = result.to_dict()

        assert data["name"] == "get_weather"
        assert data["success"] is True
        assert data["result"] == {"temp": 72}
        assert "timestamp" in data

    def test_to_function_response_success(self):
        """Convert successful result to function response format."""
        result = GeminiToolResult(
            name="get_weather",
            success=True,
            result={"temp": 72, "condition": "sunny"},
        )

        response = result.to_function_response()

        assert response["name"] == "get_weather"
        assert response["response"] == {"temp": 72, "condition": "sunny"}

    def test_to_function_response_with_non_dict_result(self):
        """Convert non-dict result to function response."""
        result = GeminiToolResult(
            name="calculate",
            success=True,
            result="42",
        )

        response = result.to_function_response()

        assert response["name"] == "calculate"
        assert response["response"] == {"result": "42"}

    def test_to_function_response_error(self):
        """Convert error result to function response format."""
        result = GeminiToolResult(
            name="get_weather",
            success=False,
            error="Location not found",
        )

        response = result.to_function_response()

        assert response["name"] == "get_weather"
        assert response["response"] == {"error": "Location not found"}


# =============================================================================
# ProxilionVertexHandler Initialization Tests
# =============================================================================


class TestProxilionVertexHandlerInit:
    """Tests for ProxilionVertexHandler initialization."""

    def test_basic_initialization(self, proxilion):
        """Basic handler initialization."""
        handler = ProxilionVertexHandler(proxilion)

        assert handler.proxilion is proxilion
        assert handler.default_action == "execute"
        assert handler.safe_errors is True
        assert len(handler.tools) == 0

    def test_custom_initialization(self, proxilion):
        """Initialize with custom options."""
        handler = ProxilionVertexHandler(
            proxilion,
            default_action="read",
            safe_errors=False,
        )

        assert handler.default_action == "read"
        assert handler.safe_errors is False

    def test_properties(self, handler, weather_tool_declaration):
        """Test handler properties."""
        def weather_impl(location: str) -> dict:
            return {"temp": 72}

        handler.register_tool(
            name="get_weather",
            declaration=weather_tool_declaration,
            implementation=weather_impl,
            resource="weather_api",
        )

        assert len(handler.tools) == 1
        assert len(handler.tool_declarations) == 1
        assert len(handler.execution_history) == 0


# =============================================================================
# Tool Registration Tests
# =============================================================================


class TestToolRegistration:
    """Tests for tool registration."""

    def test_register_basic_tool(self, handler, weather_tool_declaration):
        """Register a basic tool."""
        def weather_impl(location: str, units: str = "celsius") -> dict:
            return {"temp": 72, "units": units}

        handler.register_tool(
            name="get_weather",
            declaration=weather_tool_declaration,
            implementation=weather_impl,
            resource="weather_api",
        )

        tool = handler.get_tool("get_weather")

        assert tool is not None
        assert tool.name == "get_weather"
        assert tool.resource == "weather_api"
        assert tool.action == "execute"
        assert tool.async_impl is False

    def test_register_async_tool(self, handler, weather_tool_declaration):
        """Register an async tool."""
        async def async_weather(location: str) -> dict:
            return {"temp": 72}

        handler.register_tool(
            name="get_weather",
            declaration=weather_tool_declaration,
            implementation=async_weather,
            resource="weather_api",
        )

        tool = handler.get_tool("get_weather")

        assert tool.async_impl is True

    def test_register_with_custom_action(self, handler, weather_tool_declaration):
        """Register tool with custom action."""
        def impl(location: str) -> dict:
            return {}

        handler.register_tool(
            name="get_weather",
            declaration=weather_tool_declaration,
            implementation=impl,
            resource="weather_api",
            action="read",
        )

        tool = handler.get_tool("get_weather")
        assert tool.action == "read"

    def test_register_default_resource(self, handler, weather_tool_declaration):
        """Resource defaults to tool name."""
        def impl(location: str) -> dict:
            return {}

        handler.register_tool(
            name="get_weather",
            declaration=weather_tool_declaration,
            implementation=impl,
        )

        tool = handler.get_tool("get_weather")
        assert tool.resource == "get_weather"

    def test_unregister_tool(self, handler, weather_tool_declaration):
        """Unregister a tool."""
        handler.register_tool(
            name="get_weather",
            declaration=weather_tool_declaration,
            implementation=lambda x: {},
            resource="weather_api",
        )

        assert handler.get_tool("get_weather") is not None

        result = handler.unregister_tool("get_weather")

        assert result is True
        assert handler.get_tool("get_weather") is None

    def test_unregister_nonexistent_tool(self, handler):
        """Unregister a nonexistent tool."""
        result = handler.unregister_tool("nonexistent")
        assert result is False

    def test_register_tool_from_function(self, handler):
        """Register tool by inferring from function."""
        def search_database(query: str, limit: int = 10) -> list:
            """Search the database for matching records."""
            return [{"id": 1}]

        handler.register_tool_from_function(
            search_database,
            resource="database",
        )

        tool = handler.get_tool("search_database")

        assert tool is not None
        assert tool.resource == "database"
        assert tool.declaration["description"] == "Search the database for matching records."
        assert tool.declaration["parameters"]["properties"]["query"]["type"] == "string"
        assert tool.declaration["parameters"]["properties"]["limit"]["type"] == "integer"
        assert "query" in tool.declaration["parameters"]["required"]
        assert "limit" not in tool.declaration["parameters"]["required"]


# =============================================================================
# Function Call Extraction Tests
# =============================================================================


class TestFunctionCallExtraction:
    """Tests for extracting function calls from responses."""

    def test_extract_from_object_response(self, handler):
        """Extract function calls from object response."""
        # Create mock response
        mock_fc = MagicMock()
        mock_fc.name = "get_weather"
        mock_fc.args = {"location": "NYC"}

        mock_part = MagicMock()
        mock_part.function_call = mock_fc

        mock_content = MagicMock()
        mock_content.parts = [mock_part]

        mock_candidate = MagicMock()
        mock_candidate.content = mock_content

        mock_response = MagicMock()
        mock_response.candidates = [mock_candidate]

        calls = handler.extract_function_calls(mock_response)

        assert len(calls) == 1
        assert calls[0].name == "get_weather"
        assert calls[0].args == {"location": "NYC"}

    def test_extract_from_dict_response(self, handler):
        """Extract function calls from dictionary response."""
        response = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {
                                "functionCall": {
                                    "name": "search_db",
                                    "args": {"query": "test"},
                                }
                            }
                        ]
                    }
                }
            ]
        }

        calls = handler.extract_function_calls(response)

        assert len(calls) == 1
        assert calls[0].name == "search_db"
        assert calls[0].args == {"query": "test"}

    def test_extract_snake_case_dict(self, handler):
        """Extract with snake_case function_call key."""
        response = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {
                                "function_call": {
                                    "name": "get_weather",
                                    "args": {"location": "LA"},
                                }
                            }
                        ]
                    }
                }
            ]
        }

        calls = handler.extract_function_calls(response)

        assert len(calls) == 1
        assert calls[0].name == "get_weather"

    def test_extract_multiple_function_calls(self, handler):
        """Extract multiple function calls."""
        response = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {"functionCall": {"name": "get_weather", "args": {"location": "NYC"}}},
                            {"functionCall": {"name": "get_time", "args": {"timezone": "EST"}}},
                        ]
                    }
                }
            ]
        }

        calls = handler.extract_function_calls(response)

        assert len(calls) == 2
        assert calls[0].name == "get_weather"
        assert calls[1].name == "get_time"

    def test_extract_empty_response(self, handler):
        """Extract from response without function calls."""
        response = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {"text": "Hello, how can I help you?"}
                        ]
                    }
                }
            ]
        }

        calls = handler.extract_function_calls(response)

        assert len(calls) == 0

    def test_extract_no_candidates(self, handler):
        """Extract from response without candidates."""
        response = {"candidates": []}
        calls = handler.extract_function_calls(response)
        assert len(calls) == 0

        response_obj = MagicMock()
        response_obj.candidates = None
        calls = handler.extract_function_calls(response_obj)
        assert len(calls) == 0

    def test_standalone_extract_function(self):
        """Test standalone extract_function_calls function."""
        response = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {"functionCall": {"name": "test", "args": {}}}
                        ]
                    }
                }
            ]
        }

        calls = extract_function_calls(response)

        assert len(calls) == 1
        assert calls[0].name == "test"


# =============================================================================
# Tool Execution Tests
# =============================================================================


class TestToolExecution:
    """Tests for tool execution."""

    def test_execute_authorized_tool(self, handler, user, weather_tool_declaration):
        """Execute a tool that user is authorized for."""
        def get_weather(location: str) -> dict:
            return {"temp": 72, "location": location}

        handler.register_tool(
            name="get_weather",
            declaration=weather_tool_declaration,
            implementation=get_weather,
            resource="weather_api",
        )

        call = GeminiFunctionCall(
            name="get_weather",
            args={"location": "San Francisco"},
        )

        result = handler.execute(call, user=user)

        assert result.success is True
        assert result.authorized is True
        assert result.result == {"temp": 72, "location": "San Francisco"}

    def test_execute_unauthorized_tool(self, handler, user, database_tool_declaration):
        """Execute a tool that user is not authorized for."""
        def query_db(query: str) -> list:
            return [{"id": 1}]

        handler.register_tool(
            name="query_database",
            declaration=database_tool_declaration,
            implementation=query_db,
            resource="database",
        )

        call = GeminiFunctionCall(
            name="query_database",
            args={"query": "SELECT * FROM users"},
        )

        result = handler.execute(call, user=user)

        assert result.success is False
        assert result.authorized is False
        assert result.error == "Not authorized"

    def test_execute_admin_authorized(self, handler, admin_user, database_tool_declaration):
        """Admin can execute restricted tools."""
        def query_db(query: str) -> list:
            return [{"id": 1}]

        handler.register_tool(
            name="query_database",
            declaration=database_tool_declaration,
            implementation=query_db,
            resource="database",
        )

        call = GeminiFunctionCall(
            name="query_database",
            args={"query": "SELECT * FROM users"},
        )

        result = handler.execute(call, user=admin_user)

        assert result.success is True
        assert result.authorized is True

    def test_execute_without_user(self, handler, weather_tool_declaration):
        """Execute tool without user skips authorization."""
        def get_weather(location: str) -> dict:
            return {"temp": 72}

        handler.register_tool(
            name="get_weather",
            declaration=weather_tool_declaration,
            implementation=get_weather,
            resource="weather_api",
        )

        call = GeminiFunctionCall(
            name="get_weather",
            args={"location": "NYC"},
        )

        result = handler.execute(call, user=None)

        assert result.success is True
        assert result.result == {"temp": 72}

    def test_execute_nonexistent_tool(self, handler, user):
        """Execute a tool that doesn't exist."""
        call = GeminiFunctionCall(
            name="nonexistent_tool",
            args={},
        )

        result = handler.execute(call, user=user)

        assert result.success is False
        assert "not found" in result.error.lower()

    def test_execute_tool_with_error(self, handler, weather_tool_declaration):
        """Execute tool that raises exception."""
        def failing_weather(location: str) -> dict:
            raise ValueError("API error")

        handler.register_tool(
            name="get_weather",
            declaration=weather_tool_declaration,
            implementation=failing_weather,
            resource="weather_api",
        )

        call = GeminiFunctionCall(
            name="get_weather",
            args={"location": "NYC"},
        )

        result = handler.execute(call, user=None)

        assert result.success is False
        assert result.error == "Tool execution failed"

    def test_execute_tool_error_with_unsafe_errors(self, proxilion, weather_tool_declaration):
        """Execute tool with safe_errors=False shows real error."""
        handler = ProxilionVertexHandler(proxilion, safe_errors=False)

        def failing_weather(location: str) -> dict:
            raise ValueError("API connection failed")

        handler.register_tool(
            name="get_weather",
            declaration=weather_tool_declaration,
            implementation=failing_weather,
            resource="weather_api",
        )

        call = GeminiFunctionCall(
            name="get_weather",
            args={"location": "NYC"},
        )

        result = handler.execute(call, user=None)

        assert result.success is False
        assert "API connection failed" in result.error

    def test_execution_history(self, handler, weather_tool_declaration):
        """Execution history is maintained."""
        def get_weather(location: str) -> dict:
            return {"temp": 72}

        handler.register_tool(
            name="get_weather",
            declaration=weather_tool_declaration,
            implementation=get_weather,
            resource="weather_api",
        )

        call = GeminiFunctionCall(name="get_weather", args={"location": "NYC"})
        handler.execute(call)

        assert len(handler.execution_history) == 1
        assert handler.execution_history[0].name == "get_weather"

        handler.clear_history()
        assert len(handler.execution_history) == 0


# =============================================================================
# Async Execution Tests
# =============================================================================


class TestAsyncExecution:
    """Tests for async tool execution."""

    @pytest.mark.asyncio
    async def test_execute_async_tool(self, handler, weather_tool_declaration):
        """Execute async tool."""
        async def async_weather(location: str) -> dict:
            return {"temp": 72, "location": location}

        handler.register_tool(
            name="get_weather",
            declaration=weather_tool_declaration,
            implementation=async_weather,
            resource="weather_api",
        )

        call = GeminiFunctionCall(
            name="get_weather",
            args={"location": "NYC"},
        )

        result = await handler.execute_async(call)

        assert result.success is True
        assert result.result == {"temp": 72, "location": "NYC"}

    @pytest.mark.asyncio
    async def test_execute_sync_tool_async(self, handler, weather_tool_declaration):
        """Execute sync tool via async method."""
        def sync_weather(location: str) -> dict:
            return {"temp": 72}

        handler.register_tool(
            name="get_weather",
            declaration=weather_tool_declaration,
            implementation=sync_weather,
            resource="weather_api",
        )

        call = GeminiFunctionCall(
            name="get_weather",
            args={"location": "NYC"},
        )

        result = await handler.execute_async(call)

        assert result.success is True

    @pytest.mark.asyncio
    async def test_execute_async_unauthorized(self, handler, user, database_tool_declaration):
        """Async execution respects authorization."""
        async def query_db(query: str) -> list:
            return []

        handler.register_tool(
            name="query_database",
            declaration=database_tool_declaration,
            implementation=query_db,
            resource="database",
        )

        call = GeminiFunctionCall(
            name="query_database",
            args={"query": "SELECT *"},
        )

        result = await handler.execute_async(call, user=user)

        assert result.success is False
        assert result.authorized is False


# =============================================================================
# Process Response Tests
# =============================================================================


class TestProcessResponse:
    """Tests for processing complete responses."""

    def test_process_response_single_call(self, handler, user, weather_tool_declaration):
        """Process response with single function call."""
        def get_weather(location: str) -> dict:
            return {"temp": 72}

        handler.register_tool(
            name="get_weather",
            declaration=weather_tool_declaration,
            implementation=get_weather,
            resource="weather_api",
        )

        response = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {
                                "functionCall": {
                                    "name": "get_weather",
                                    "args": {"location": "NYC"},
                                }
                            }
                        ]
                    }
                }
            ]
        }

        results = handler.process_response(response, user=user)

        assert len(results) == 1
        assert results[0].success is True
        assert results[0].result == {"temp": 72}

    def test_process_response_multiple_calls(self, handler, weather_tool_declaration):
        """Process response with multiple function calls."""
        def get_weather(location: str) -> dict:
            return {"temp": 72, "location": location}

        handler.register_tool(
            name="get_weather",
            declaration=weather_tool_declaration,
            implementation=get_weather,
            resource="weather_api",
        )

        response = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {"functionCall": {"name": "get_weather", "args": {"location": "NYC"}}},
                            {"functionCall": {"name": "get_weather", "args": {"location": "LA"}}},
                        ]
                    }
                }
            ]
        }

        results = handler.process_response(response)

        assert len(results) == 2
        assert results[0].result["location"] == "NYC"
        assert results[1].result["location"] == "LA"

    def test_process_response_no_function_calls(self, handler):
        """Process response without function calls."""
        response = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {"text": "Hello!"}
                        ]
                    }
                }
            ]
        }

        results = handler.process_response(response)

        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_process_response_async(self, handler, weather_tool_declaration):
        """Process response asynchronously."""
        async def async_weather(location: str) -> dict:
            return {"temp": 72}

        handler.register_tool(
            name="get_weather",
            declaration=weather_tool_declaration,
            implementation=async_weather,
            resource="weather_api",
        )

        response = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {"functionCall": {"name": "get_weather", "args": {"location": "NYC"}}}
                        ]
                    }
                }
            ]
        }

        results = await handler.process_response_async(response)

        assert len(results) == 1
        assert results[0].success is True


# =============================================================================
# Tool Output Formatting Tests
# =============================================================================


class TestToolOutputFormatting:
    """Tests for formatting tool outputs."""

    def test_format_tool_response(self, handler):
        """Format tool results for Gemini."""
        results = [
            GeminiToolResult(
                name="get_weather",
                success=True,
                result={"temp": 72, "condition": "sunny"},
            ),
            GeminiToolResult(
                name="get_time",
                success=True,
                result={"time": "3:00 PM"},
            ),
        ]

        formatted = handler.format_tool_response(results)

        assert len(formatted) == 2
        assert formatted[0]["function_response"]["name"] == "get_weather"
        assert formatted[0]["function_response"]["response"] == {"temp": 72, "condition": "sunny"}
        assert formatted[1]["function_response"]["name"] == "get_time"

    def test_format_error_response(self, handler):
        """Format error result for Gemini."""
        results = [
            GeminiToolResult(
                name="get_weather",
                success=False,
                error="Location not found",
            )
        ]

        formatted = handler.format_tool_response(results)

        assert formatted[0]["function_response"]["response"] == {"error": "Location not found"}

    def test_standalone_format_tool_response(self):
        """Test standalone format_tool_response function."""
        results = [
            GeminiToolResult(name="test", success=True, result={"data": 123})
        ]

        formatted = format_tool_response(results)

        assert len(formatted) == 1
        assert formatted[0]["function_response"]["name"] == "test"


# =============================================================================
# Gemini Tools Export Tests
# =============================================================================


class TestGeminiToolsExport:
    """Tests for exporting tools to Gemini format."""

    def test_to_gemini_tools_without_vertexai(self, handler, weather_tool_declaration):
        """Export tools when vertexai is not installed."""
        handler.register_tool(
            name="get_weather",
            declaration=weather_tool_declaration,
            implementation=lambda x: {},
            resource="weather_api",
        )

        tools = handler.to_gemini_tools()

        # Should return raw format when vertexai not available
        assert isinstance(tools, list)
        assert len(tools) == 1

        # Check structure
        if isinstance(tools[0], dict):
            assert "function_declarations" in tools[0]

    def test_tool_declarations_property(self, handler, weather_tool_declaration, database_tool_declaration):
        """Get tool declarations."""
        handler.register_tool(
            name="get_weather",
            declaration=weather_tool_declaration,
            implementation=lambda x: {},
        )
        handler.register_tool(
            name="query_database",
            declaration=database_tool_declaration,
            implementation=lambda x: {},
        )

        declarations = handler.tool_declarations

        assert len(declarations) == 2
        names = [d["name"] for d in declarations]
        assert "get_weather" in names
        assert "query_database" in names

    def test_standalone_to_gemini_tools(self):
        """Test standalone to_gemini_tools function."""
        declarations = [
            {
                "name": "test_tool",
                "description": "A test tool",
                "parameters": {"type": "object", "properties": {}},
            }
        ]

        tools = to_gemini_tools(declarations)

        assert isinstance(tools, list)
        assert len(tools) == 1

    def test_to_gemini_tool_config(self, handler):
        """Export tool config."""
        config = handler.to_gemini_tool_config(mode="AUTO")

        # When vertexai not installed, returns dict
        if isinstance(config, dict):
            assert config["function_calling_config"]["mode"] == "AUTO"

    def test_to_gemini_tool_config_with_allowed_functions(self, handler, weather_tool_declaration):
        """Export tool config with allowed functions."""
        handler.register_tool(
            name="get_weather",
            declaration=weather_tool_declaration,
            implementation=lambda x: {},
        )

        config = handler.to_gemini_tool_config(
            mode="ANY",
            allowed_functions=["get_weather"],
        )

        if isinstance(config, dict):
            assert config["function_calling_config"]["mode"] == "ANY"
            assert "get_weather" in config["function_calling_config"]["allowed_function_names"]


# =============================================================================
# Integration Tests
# =============================================================================


class TestIntegration:
    """Integration tests for complete workflows."""

    def test_complete_workflow(self, proxilion, user):
        """Test a complete function calling workflow."""
        # Setup handler
        handler = ProxilionVertexHandler(proxilion)

        # Register tools
        def search_kb(query: str) -> list:
            return [{"title": "Result 1", "content": "Some content"}]

        handler.register_tool(
            name="search_knowledge_base",
            declaration={
                "name": "search_knowledge_base",
                "description": "Search the knowledge base",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string"},
                    },
                    "required": ["query"],
                },
            },
            implementation=search_kb,
            resource="public_api",
        )

        # Simulate Gemini response
        response = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {
                                "functionCall": {
                                    "name": "search_knowledge_base",
                                    "args": {"query": "how to use the API"},
                                }
                            }
                        ]
                    }
                }
            ]
        }

        # Process response
        results = handler.process_response(response, user=user)

        assert len(results) == 1
        assert results[0].success is True
        assert results[0].result[0]["title"] == "Result 1"

        # Format for sending back to Gemini
        tool_responses = handler.format_tool_response(results)

        assert len(tool_responses) == 1
        assert tool_responses[0]["function_response"]["name"] == "search_knowledge_base"

    def test_mixed_authorization_workflow(self, proxilion, user):
        """Test workflow with mixed authorized/unauthorized calls."""
        handler = ProxilionVertexHandler(proxilion)

        # Register public tool
        handler.register_tool(
            name="search",
            declaration={
                "name": "search",
                "description": "Search",
                "parameters": {"type": "object", "properties": {}},
            },
            implementation=lambda: [{"id": 1}],
            resource="public_api",
        )

        # Register restricted tool
        handler.register_tool(
            name="query_db",
            declaration={
                "name": "query_db",
                "description": "Query database",
                "parameters": {"type": "object", "properties": {}},
            },
            implementation=lambda: [{"id": 2}],
            resource="database",
        )

        # Simulate response with both calls
        response = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {"functionCall": {"name": "search", "args": {}}},
                            {"functionCall": {"name": "query_db", "args": {}}},
                        ]
                    }
                }
            ]
        }

        results = handler.process_response(response, user=user)

        assert len(results) == 2
        # Public tool should succeed
        assert results[0].success is True
        assert results[0].authorized is True
        # Database tool should fail authorization
        assert results[1].success is False
        assert results[1].authorized is False


# =============================================================================
# Edge Case Tests
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_args(self, handler, weather_tool_declaration):
        """Handle function call with empty args."""
        def no_args_tool() -> str:
            return "result"

        handler.register_tool(
            name="no_args",
            declaration={
                "name": "no_args",
                "description": "No args",
                "parameters": {"type": "object", "properties": {}},
            },
            implementation=no_args_tool,
            resource="public_api",
        )

        call = GeminiFunctionCall(name="no_args", args={})
        result = handler.execute(call)

        assert result.success is True
        assert result.result == "result"

    def test_none_args(self, handler):
        """Handle function call with None args converted to empty dict."""
        call = GeminiFunctionCall(name="test", args=None)  # type: ignore
        result = handler.execute(call)

        # Should handle gracefully (tool not found)
        assert result.success is False

    def test_complex_result_serialization(self, handler):
        """Handle complex result types."""
        def complex_tool() -> dict:
            return {
                "nested": {"key": "value"},
                "list": [1, 2, 3],
                "number": 42,
            }

        handler.register_tool(
            name="complex",
            declaration={"name": "complex", "description": "Complex", "parameters": {}},
            implementation=complex_tool,
            resource="public_api",
        )

        call = GeminiFunctionCall(name="complex", args={})
        result = handler.execute(call)

        assert result.success is True
        assert result.result["nested"]["key"] == "value"

    def test_exception_error_classes(self):
        """Test custom exception classes."""
        error1 = GoogleIntegrationError("Generic error")
        assert str(error1) == "Generic error"

        error2 = ToolNotFoundError("my_tool")
        assert error2.tool_name == "my_tool"
        assert "my_tool" in str(error2)

        error3 = ToolExecutionError("my_tool", "Safe message")
        assert error3.tool_name == "my_tool"
        assert error3.safe_message == "Safe message"

    def test_protobuf_value_conversion(self, handler):
        """Test protobuf value conversion."""
        # Create mock protobuf-like value
        mock_value = MagicMock()
        mock_value.string_value = "test_string"

        result = handler._convert_protobuf_value(mock_value)
        assert result == "test_string"

        # Test number
        mock_num = MagicMock()
        mock_num.string_value = None
        del mock_num.string_value
        mock_num.number_value = 42

        result = handler._convert_protobuf_value(mock_num)
        assert result == 42
