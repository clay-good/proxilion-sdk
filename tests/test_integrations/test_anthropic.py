"""
Tests for Anthropic tool_use integration.

Tests cover:
- ProxilionToolHandler registration and execution
- ToolUseResult handling and conversion
- process_tool_use helper
- create_tool_result_content helper
- Error handling and safe error messages
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from datetime import datetime, timezone

import pytest

from proxilion import Proxilion, Policy, UserContext, AgentContext
from proxilion.contrib.anthropic import (
    ProxilionToolHandler,
    ToolUseResult,
    RegisteredTool,
    process_tool_use,
    process_tool_use_async,
    create_tool_result_content,
    ToolNotFoundError,
    ToolExecutionError,
)
from proxilion.exceptions import AuthorizationError


class TestToolUseResult:
    """Tests for ToolUseResult dataclass."""

    def test_result_creation_success(self):
        """Test creating a successful result."""
        result = ToolUseResult(
            tool_use_id="toolu_123",
            tool_name="get_weather",
            success=True,
            result='{"temperature": 20, "unit": "celsius"}',
        )

        assert result.tool_use_id == "toolu_123"
        assert result.tool_name == "get_weather"
        assert result.success is True
        assert result.error is None
        assert result.authorized is True

    def test_result_creation_failure(self):
        """Test creating a failed result."""
        result = ToolUseResult(
            tool_use_id="toolu_456",
            tool_name="get_weather",
            success=False,
            error="Location not found",
        )

        assert result.success is False
        assert result.error == "Location not found"
        assert result.result is None

    def test_result_unauthorized(self):
        """Test creating an unauthorized result."""
        result = ToolUseResult(
            tool_use_id="toolu_789",
            tool_name="admin_action",
            success=False,
            error="Not authorized",
            authorized=False,
        )

        assert result.authorized is False

    def test_to_tool_result_block_success(self):
        """Test converting successful result to Anthropic format."""
        result = ToolUseResult(
            tool_use_id="toolu_123",
            tool_name="calculator",
            success=True,
            result="42",
        )

        block = result.to_tool_result_block()

        assert block["type"] == "tool_result"
        assert block["tool_use_id"] == "toolu_123"
        assert block["content"] == "42"
        assert "is_error" not in block

    def test_to_tool_result_block_dict_result(self):
        """Test converting dict result to Anthropic format."""
        result = ToolUseResult(
            tool_use_id="toolu_123",
            tool_name="get_data",
            success=True,
            result={"key": "value"},
        )

        block = result.to_tool_result_block()

        assert block["content"] == '{"key": "value"}'

    def test_to_tool_result_block_error(self):
        """Test converting error result to Anthropic format."""
        result = ToolUseResult(
            tool_use_id="toolu_123",
            tool_name="failing_tool",
            success=False,
            error="Something went wrong",
        )

        block = result.to_tool_result_block()

        assert block["type"] == "tool_result"
        assert block["tool_use_id"] == "toolu_123"
        assert block["content"] == "Something went wrong"
        assert block["is_error"] is True


class TestProxilionToolHandler:
    """Tests for ProxilionToolHandler class."""

    def test_handler_initialization(self, proxilion_simple: Proxilion):
        """Test handler initialization."""
        handler = ProxilionToolHandler(proxilion_simple)

        assert handler.proxilion == proxilion_simple
        assert handler.default_action == "execute"
        assert handler.safe_errors is True

    def test_register_tool(self, proxilion_simple: Proxilion):
        """Test registering a tool."""
        handler = ProxilionToolHandler(proxilion_simple)

        def get_weather(location: str) -> str:
            return f"Weather in {location}: sunny"

        schema = {
            "name": "get_weather",
            "description": "Get weather for a location",
            "input_schema": {
                "type": "object",
                "properties": {
                    "location": {"type": "string"}
                },
                "required": ["location"],
            },
        }

        handler.register_tool(
            name="get_weather",
            schema=schema,
            implementation=get_weather,
        )

        assert len(handler.tools) == 1
        assert handler.tools[0].name == "get_weather"

    def test_unregister_tool(self, proxilion_simple: Proxilion):
        """Test unregistering a tool."""
        handler = ProxilionToolHandler(proxilion_simple)

        def func():
            pass

        handler.register_tool(
            name="temp_tool",
            schema={"name": "temp_tool"},
            implementation=func,
        )

        assert handler.unregister_tool("temp_tool") is True
        assert handler.unregister_tool("temp_tool") is False
        assert handler.get_tool("temp_tool") is None

    def test_get_tool(self, proxilion_simple: Proxilion):
        """Test getting a registered tool."""
        handler = ProxilionToolHandler(proxilion_simple)

        def func():
            pass

        handler.register_tool(
            name="my_tool",
            schema={"name": "my_tool"},
            implementation=func,
        )

        registered = handler.get_tool("my_tool")
        assert registered is not None
        assert registered.name == "my_tool"

    def test_execute_tool(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test executing a tool."""
        @proxilion_simple.policy("get_weather")
        class WeatherPolicy(Policy):
            def can_execute(self, context):
                return True

        handler = ProxilionToolHandler(proxilion_simple)

        def get_weather(location: str, unit: str = "celsius") -> dict:
            return {"location": location, "temp": 20, "unit": unit}

        handler.register_tool(
            name="get_weather",
            schema={"name": "get_weather"},
            implementation=get_weather,
        )

        result = handler.execute(
            tool_name="get_weather",
            tool_use_id="toolu_123",
            input_data={"location": "London"},
            user=basic_user,
        )

        assert result.success is True
        assert result.tool_use_id == "toolu_123"
        # Result is JSON stringified
        assert "London" in result.result

    def test_execute_tool_unauthorized(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test that execution is denied for unauthorized users."""
        @proxilion_simple.policy("admin_tool")
        class AdminPolicy(Policy):
            def can_execute(self, context):
                return "admin" in self.user.roles

        handler = ProxilionToolHandler(proxilion_simple)

        def admin_action():
            return "admin result"

        handler.register_tool(
            name="admin_tool",
            schema={"name": "admin_tool"},
            implementation=admin_action,
            resource="admin_tool",
        )

        result = handler.execute(
            tool_name="admin_tool",
            tool_use_id="toolu_456",
            input_data={},
            user=basic_user,
        )

        assert result.success is False
        assert result.authorized is False
        assert result.error == "Not authorized"

    def test_execute_tool_not_found(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test executing a tool that doesn't exist."""
        handler = ProxilionToolHandler(proxilion_simple)

        result = handler.execute(
            tool_name="nonexistent",
            tool_use_id="toolu_789",
            input_data={},
            user=basic_user,
        )

        assert result.success is False
        assert "not found" in result.error.lower()

    def test_execute_with_tool_use_block(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test executing with Anthropic tool_use block object."""
        @proxilion_simple.policy("calculator")
        class CalcPolicy(Policy):
            def can_execute(self, context):
                return True

        handler = ProxilionToolHandler(proxilion_simple)

        def calculate(a: int, b: int) -> int:
            return a + b

        handler.register_tool(
            name="calculator",
            schema={"name": "calculator"},
            implementation=calculate,
        )

        # Mock Anthropic tool_use block
        @dataclass
        class MockToolUseBlock:
            type: str = "tool_use"
            id: str = "toolu_abc"
            name: str = "calculator"
            input: dict = None

            def __post_init__(self):
                self.input = {"a": 5, "b": 3}

        block = MockToolUseBlock()

        result = handler.execute(
            tool_use_block=block,
            user=basic_user,
        )

        assert result.success is True
        assert result.tool_use_id == "toolu_abc"
        assert "8" in result.result

    def test_execute_safe_errors(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test that safe errors hide implementation details."""
        @proxilion_simple.policy("buggy_tool")
        class BuggyPolicy(Policy):
            def can_execute(self, context):
                return True

        handler = ProxilionToolHandler(proxilion_simple, safe_errors=True)

        def buggy_tool():
            raise ValueError("Internal error with sensitive details")

        handler.register_tool(
            name="buggy_tool",
            schema={"name": "buggy_tool"},
            implementation=buggy_tool,
        )

        result = handler.execute(
            tool_name="buggy_tool",
            tool_use_id="toolu_err",
            input_data={},
            user=basic_user,
        )

        assert result.success is False
        assert "sensitive" not in result.error
        assert result.error == "Tool execution failed"

    def test_execute_detailed_errors(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test that detailed errors show implementation details."""
        @proxilion_simple.policy("buggy_tool")
        class BuggyPolicy(Policy):
            def can_execute(self, context):
                return True

        handler = ProxilionToolHandler(proxilion_simple, safe_errors=False)

        def buggy_tool():
            raise ValueError("Detailed error message")

        handler.register_tool(
            name="buggy_tool",
            schema={"name": "buggy_tool"},
            implementation=buggy_tool,
        )

        result = handler.execute(
            tool_name="buggy_tool",
            tool_use_id="toolu_err",
            input_data={},
            user=basic_user,
        )

        assert result.success is False
        assert "Detailed error message" in result.error

    @pytest.mark.asyncio
    async def test_execute_async_tool(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test executing an async tool."""
        @proxilion_simple.policy("async_tool")
        class AsyncPolicy(Policy):
            def can_execute(self, context):
                return True

        handler = ProxilionToolHandler(proxilion_simple)

        async def async_operation(value: int) -> int:
            await asyncio.sleep(0.01)
            return value * 3

        handler.register_tool(
            name="async_tool",
            schema={"name": "async_tool"},
            implementation=async_operation,
        )

        result = await handler.execute_async(
            tool_name="async_tool",
            tool_use_id="toolu_async",
            input_data={"value": 7},
            user=basic_user,
        )

        assert result.success is True
        assert "21" in result.result

    def test_tool_schemas(self, proxilion_simple: Proxilion):
        """Test getting tool schemas for Anthropic API."""
        handler = ProxilionToolHandler(proxilion_simple)

        schema1 = {
            "name": "tool1",
            "description": "First tool",
            "input_schema": {"type": "object"},
        }
        schema2 = {
            "name": "tool2",
            "description": "Second tool",
            "input_schema": {"type": "object"},
        }

        handler.register_tool(name="tool1", schema=schema1, implementation=lambda: None)
        handler.register_tool(name="tool2", schema=schema2, implementation=lambda: None)

        schemas = handler.tool_schemas
        assert len(schemas) == 2
        assert schema1 in schemas
        assert schema2 in schemas

    def test_to_anthropic_tools(self, proxilion_simple: Proxilion):
        """Test getting tools in Anthropic format."""
        handler = ProxilionToolHandler(proxilion_simple)

        schema = {
            "name": "my_tool",
            "description": "My tool",
            "input_schema": {"type": "object"},
        }
        handler.register_tool(name="my_tool", schema=schema, implementation=lambda: None)

        tools = handler.to_anthropic_tools()

        assert len(tools) == 1
        assert tools[0] == schema

    def test_execution_history(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test that execution history is tracked."""
        @proxilion_simple.policy("tracked_tool")
        class TrackedPolicy(Policy):
            def can_execute(self, context):
                return True

        handler = ProxilionToolHandler(proxilion_simple)

        def tracked_tool(x: int) -> int:
            return x

        handler.register_tool(
            name="tracked_tool",
            schema={"name": "tracked_tool"},
            implementation=tracked_tool,
        )

        # Execute multiple times
        handler.execute(tool_name="tracked_tool", tool_use_id="t1", input_data={"x": 1}, user=basic_user)
        handler.execute(tool_name="tracked_tool", tool_use_id="t2", input_data={"x": 2}, user=basic_user)
        handler.execute(tool_name="tracked_tool", tool_use_id="t3", input_data={"x": 3}, user=basic_user)

        history = handler.execution_history
        assert len(history) == 3
        assert all(h.success for h in history)


class TestProcessToolUse:
    """Tests for process_tool_use helper function."""

    def test_process_single_tool_use(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test processing response with single tool_use."""
        @proxilion_simple.policy("get_weather")
        class WeatherPolicy(Policy):
            def can_execute(self, context):
                return True

        handler = ProxilionToolHandler(proxilion_simple)

        def get_weather(location: str) -> str:
            return f"Weather in {location}: sunny"

        handler.register_tool(
            name="get_weather",
            schema={"name": "get_weather"},
            implementation=get_weather,
        )

        # Mock Anthropic response
        @dataclass
        class MockToolUseBlock:
            type: str = "tool_use"
            id: str = "toolu_123"
            name: str = "get_weather"
            input: dict = None

            def __post_init__(self):
                self.input = {"location": "London"}

        @dataclass
        class MockResponse:
            content: list = None

            def __post_init__(self):
                self.content = [MockToolUseBlock()]

        response = MockResponse()
        results = process_tool_use(response, handler, basic_user)

        assert len(results) == 1
        assert results[0].success is True
        assert "London" in results[0].result

    def test_process_multiple_tool_uses(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test processing response with multiple tool_use blocks."""
        @proxilion_simple.policy("tool_a")
        class ToolAPolicy(Policy):
            def can_execute(self, context):
                return True

        @proxilion_simple.policy("tool_b")
        class ToolBPolicy(Policy):
            def can_execute(self, context):
                return True

        handler = ProxilionToolHandler(proxilion_simple)

        handler.register_tool(
            name="tool_a",
            schema={"name": "tool_a"},
            implementation=lambda: "result_a",
        )
        handler.register_tool(
            name="tool_b",
            schema={"name": "tool_b"},
            implementation=lambda: "result_b",
        )

        @dataclass
        class MockToolUseBlockA:
            type: str = "tool_use"
            id: str = "toolu_a"
            name: str = "tool_a"
            input: dict = None

            def __post_init__(self):
                self.input = {}

        @dataclass
        class MockToolUseBlockB:
            type: str = "tool_use"
            id: str = "toolu_b"
            name: str = "tool_b"
            input: dict = None

            def __post_init__(self):
                self.input = {}

        @dataclass
        class MockResponse:
            content: list = None

            def __post_init__(self):
                self.content = [MockToolUseBlockA(), MockToolUseBlockB()]

        response = MockResponse()
        results = process_tool_use(response, handler, basic_user)

        assert len(results) == 2
        assert all(r.success for r in results)

    def test_process_mixed_content(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test processing response with mixed content types."""
        @proxilion_simple.policy("my_tool")
        class MyToolPolicy(Policy):
            def can_execute(self, context):
                return True

        handler = ProxilionToolHandler(proxilion_simple)
        handler.register_tool(
            name="my_tool",
            schema={"name": "my_tool"},
            implementation=lambda: "result",
        )

        @dataclass
        class MockTextBlock:
            type: str = "text"
            text: str = "Some text"

        @dataclass
        class MockToolUseBlock:
            type: str = "tool_use"
            id: str = "toolu_123"
            name: str = "my_tool"
            input: dict = None

            def __post_init__(self):
                self.input = {}

        @dataclass
        class MockResponse:
            content: list = None

            def __post_init__(self):
                self.content = [MockTextBlock(), MockToolUseBlock()]

        response = MockResponse()
        results = process_tool_use(response, handler, basic_user)

        # Should only process tool_use blocks
        assert len(results) == 1
        assert results[0].tool_name == "my_tool"

    def test_process_empty_response(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test processing response with no tool_use blocks."""
        handler = ProxilionToolHandler(proxilion_simple)

        @dataclass
        class MockTextBlock:
            type: str = "text"
            text: str = "Just text"

        @dataclass
        class MockResponse:
            content: list = None

            def __post_init__(self):
                self.content = [MockTextBlock()]

        response = MockResponse()
        results = process_tool_use(response, handler, basic_user)

        assert len(results) == 0


@pytest.mark.asyncio
class TestProcessToolUseAsync:
    """Tests for process_tool_use_async helper function."""

    async def test_process_async(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test async processing of tool_use blocks."""
        @proxilion_simple.policy("async_tool")
        class AsyncPolicy(Policy):
            def can_execute(self, context):
                return True

        handler = ProxilionToolHandler(proxilion_simple)

        async def async_impl() -> str:
            await asyncio.sleep(0.01)
            return "async_result"

        handler.register_tool(
            name="async_tool",
            schema={"name": "async_tool"},
            implementation=async_impl,
        )

        @dataclass
        class MockToolUseBlock:
            type: str = "tool_use"
            id: str = "toolu_async"
            name: str = "async_tool"
            input: dict = None

            def __post_init__(self):
                self.input = {}

        @dataclass
        class MockResponse:
            content: list = None

            def __post_init__(self):
                self.content = [MockToolUseBlock()]

        response = MockResponse()
        results = await process_tool_use_async(response, handler, basic_user)

        assert len(results) == 1
        assert results[0].success is True


class TestCreateToolResultContent:
    """Tests for create_tool_result_content helper."""

    def test_create_from_results(self):
        """Test creating tool_result content from results."""
        results = [
            ToolUseResult(
                tool_use_id="toolu_1",
                tool_name="tool_a",
                success=True,
                result="success_a",
            ),
            ToolUseResult(
                tool_use_id="toolu_2",
                tool_name="tool_b",
                success=False,
                error="Error in tool_b",
            ),
        ]

        content = create_tool_result_content(results)

        assert len(content) == 2

        # First should be success
        assert content[0]["type"] == "tool_result"
        assert content[0]["tool_use_id"] == "toolu_1"
        assert content[0]["content"] == "success_a"
        assert "is_error" not in content[0]

        # Second should be error
        assert content[1]["type"] == "tool_result"
        assert content[1]["tool_use_id"] == "toolu_2"
        assert content[1]["is_error"] is True

    def test_create_empty_list(self):
        """Test creating from empty results list."""
        content = create_tool_result_content([])
        assert len(content) == 0


class TestRegisteredTool:
    """Tests for RegisteredTool dataclass."""

    def test_registered_tool_creation(self):
        """Test creating a registered tool record."""
        def impl(x: int) -> int:
            return x

        tool = RegisteredTool(
            name="test_tool",
            schema={"name": "test_tool", "input_schema": {}},
            implementation=impl,
            resource="test_resource",
            action="execute",
            async_impl=False,
            description="A test tool",
        )

        assert tool.name == "test_tool"
        assert tool.resource == "test_resource"
        assert tool.action == "execute"
        assert tool.async_impl is False
        assert tool.description == "A test tool"
