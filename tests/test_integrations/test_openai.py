"""
Tests for OpenAI function calling integration.

Tests cover:
- ProxilionFunctionHandler registration and execution
- FunctionCallResult handling
- create_secure_function wrapper
- process_openai_response helper
- Error handling and safe error messages
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from datetime import datetime, timezone

import pytest

from proxilion import Proxilion, Policy, UserContext, AgentContext
from proxilion.contrib.openai import (
    ProxilionFunctionHandler,
    FunctionCallResult,
    RegisteredFunction,
    create_secure_function,
    process_openai_response,
    FunctionNotFoundError,
    FunctionExecutionError,
)
from proxilion.exceptions import AuthorizationError


class TestFunctionCallResult:
    """Tests for FunctionCallResult dataclass."""

    def test_result_creation_success(self):
        """Test creating a successful result."""
        result = FunctionCallResult(
            function_name="get_weather",
            success=True,
            result={"temperature": 20, "unit": "celsius"},
        )

        assert result.function_name == "get_weather"
        assert result.success is True
        assert result.result == {"temperature": 20, "unit": "celsius"}
        assert result.error is None
        assert result.authorized is True

    def test_result_creation_failure(self):
        """Test creating a failed result."""
        result = FunctionCallResult(
            function_name="get_weather",
            success=False,
            error="Location not found",
        )

        assert result.success is False
        assert result.error == "Location not found"
        assert result.result is None

    def test_result_unauthorized(self):
        """Test creating an unauthorized result."""
        result = FunctionCallResult(
            function_name="admin_action",
            success=False,
            error="Not authorized",
            authorized=False,
        )

        assert result.authorized is False


class TestProxilionFunctionHandler:
    """Tests for ProxilionFunctionHandler class."""

    def test_handler_initialization(self, proxilion_simple: Proxilion):
        """Test handler initialization."""
        handler = ProxilionFunctionHandler(proxilion_simple)

        assert handler.proxilion == proxilion_simple
        assert handler.default_action == "execute"
        assert handler.safe_errors is True

    def test_register_function(self, proxilion_simple: Proxilion):
        """Test registering a function."""
        handler = ProxilionFunctionHandler(proxilion_simple)

        def get_weather(location: str) -> str:
            return f"Weather in {location}: sunny"

        schema = {
            "name": "get_weather",
            "description": "Get weather for a location",
            "parameters": {
                "type": "object",
                "properties": {
                    "location": {"type": "string"}
                },
                "required": ["location"],
            },
        }

        handler.register_function(
            name="get_weather",
            schema=schema,
            implementation=get_weather,
        )

        assert len(handler.functions) == 1
        assert handler.functions[0].name == "get_weather"

    def test_unregister_function(self, proxilion_simple: Proxilion):
        """Test unregistering a function."""
        handler = ProxilionFunctionHandler(proxilion_simple)

        def func():
            pass

        handler.register_function(
            name="temp_func",
            schema={"name": "temp_func"},
            implementation=func,
        )

        assert handler.unregister_function("temp_func") is True
        assert handler.unregister_function("temp_func") is False  # Already removed
        assert handler.get_function("temp_func") is None

    def test_get_function(self, proxilion_simple: Proxilion):
        """Test getting a registered function."""
        handler = ProxilionFunctionHandler(proxilion_simple)

        def func():
            pass

        handler.register_function(
            name="my_func",
            schema={"name": "my_func"},
            implementation=func,
        )

        registered = handler.get_function("my_func")
        assert registered is not None
        assert registered.name == "my_func"

    def test_execute_function(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test executing a function."""
        @proxilion_simple.policy("get_weather")
        class WeatherPolicy(Policy):
            def can_execute(self, context):
                return True

        handler = ProxilionFunctionHandler(proxilion_simple)

        def get_weather(location: str, unit: str = "celsius") -> dict:
            return {"location": location, "temp": 20, "unit": unit}

        handler.register_function(
            name="get_weather",
            schema={"name": "get_weather"},
            implementation=get_weather,
        )

        result = handler.execute(
            function_name="get_weather",
            arguments={"location": "London"},
            user=basic_user,
        )

        assert result.success is True
        assert result.result["location"] == "London"
        assert result.result["temp"] == 20

    def test_execute_function_unauthorized(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test that execution is denied for unauthorized users."""
        @proxilion_simple.policy("admin_func")
        class AdminPolicy(Policy):
            def can_execute(self, context):
                return "admin" in self.user.roles

        handler = ProxilionFunctionHandler(proxilion_simple)

        def admin_action():
            return "admin result"

        handler.register_function(
            name="admin_func",
            schema={"name": "admin_func"},
            implementation=admin_action,
            resource="admin_func",
        )

        result = handler.execute(
            function_name="admin_func",
            arguments={},
            user=basic_user,
        )

        assert result.success is False
        assert result.authorized is False
        assert result.error == "Not authorized"  # Safe error

    def test_execute_function_not_found(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test executing a function that doesn't exist."""
        handler = ProxilionFunctionHandler(proxilion_simple)

        result = handler.execute(
            function_name="nonexistent",
            arguments={},
            user=basic_user,
        )

        assert result.success is False
        assert "not found" in result.error.lower()

    def test_execute_with_json_arguments(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test executing with JSON string arguments."""
        @proxilion_simple.policy("json_func")
        class JsonPolicy(Policy):
            def can_execute(self, context):
                return True

        handler = ProxilionFunctionHandler(proxilion_simple)

        def process_data(value: int) -> int:
            return value * 2

        handler.register_function(
            name="json_func",
            schema={"name": "json_func"},
            implementation=process_data,
        )

        result = handler.execute(
            function_name="json_func",
            arguments='{"value": 5}',  # JSON string
            user=basic_user,
        )

        assert result.success is True
        assert result.result == 10

    def test_execute_with_function_call_object(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test executing with OpenAI function_call object."""
        @proxilion_simple.policy("calc")
        class CalcPolicy(Policy):
            def can_execute(self, context):
                return True

        handler = ProxilionFunctionHandler(proxilion_simple)

        def calculate(a: int, b: int) -> int:
            return a + b

        handler.register_function(
            name="calc",
            schema={"name": "calc"},
            implementation=calculate,
        )

        # Mock OpenAI function_call object
        @dataclass
        class MockFunctionCall:
            name: str
            arguments: str

        function_call = MockFunctionCall(
            name="calc",
            arguments='{"a": 5, "b": 3}',
        )

        result = handler.execute(
            function_call=function_call,
            user=basic_user,
        )

        assert result.success is True
        assert result.result == 8

    def test_execute_safe_errors(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test that safe errors hide implementation details."""
        @proxilion_simple.policy("buggy_func")
        class BuggyPolicy(Policy):
            def can_execute(self, context):
                return True

        handler = ProxilionFunctionHandler(proxilion_simple, safe_errors=True)

        def buggy_function():
            raise ValueError("Internal error with sensitive details")

        handler.register_function(
            name="buggy_func",
            schema={"name": "buggy_func"},
            implementation=buggy_function,
        )

        result = handler.execute(
            function_name="buggy_func",
            arguments={},
            user=basic_user,
        )

        assert result.success is False
        assert "sensitive" not in result.error
        assert result.error == "Function execution failed"

    def test_execute_detailed_errors(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test that detailed errors show implementation details."""
        @proxilion_simple.policy("buggy_func")
        class BuggyPolicy(Policy):
            def can_execute(self, context):
                return True

        handler = ProxilionFunctionHandler(proxilion_simple, safe_errors=False)

        def buggy_function():
            raise ValueError("Detailed error message")

        handler.register_function(
            name="buggy_func",
            schema={"name": "buggy_func"},
            implementation=buggy_function,
        )

        result = handler.execute(
            function_name="buggy_func",
            arguments={},
            user=basic_user,
        )

        assert result.success is False
        assert "Detailed error message" in result.error

    @pytest.mark.asyncio
    async def test_execute_async_function(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test executing an async function."""
        @proxilion_simple.policy("async_func")
        class AsyncPolicy(Policy):
            def can_execute(self, context):
                return True

        handler = ProxilionFunctionHandler(proxilion_simple)

        async def async_operation(value: int) -> int:
            await asyncio.sleep(0.01)
            return value * 3

        handler.register_function(
            name="async_func",
            schema={"name": "async_func"},
            implementation=async_operation,
        )

        result = await handler.execute_async(
            function_name="async_func",
            arguments={"value": 7},
            user=basic_user,
        )

        assert result.success is True
        assert result.result == 21

    def test_function_schemas(self, proxilion_simple: Proxilion):
        """Test getting function schemas for OpenAI API."""
        handler = ProxilionFunctionHandler(proxilion_simple)

        schema1 = {"name": "func1", "description": "First function"}
        schema2 = {"name": "func2", "description": "Second function"}

        handler.register_function(name="func1", schema=schema1, implementation=lambda: None)
        handler.register_function(name="func2", schema=schema2, implementation=lambda: None)

        schemas = handler.function_schemas
        assert len(schemas) == 2
        assert schema1 in schemas
        assert schema2 in schemas

    def test_to_openai_tools(self, proxilion_simple: Proxilion):
        """Test converting to OpenAI tools format."""
        handler = ProxilionFunctionHandler(proxilion_simple)

        schema = {"name": "my_func", "description": "My function"}
        handler.register_function(name="my_func", schema=schema, implementation=lambda: None)

        tools = handler.to_openai_tools()

        assert len(tools) == 1
        assert tools[0]["type"] == "function"
        assert tools[0]["function"] == schema

    def test_call_history(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test that call history is tracked."""
        @proxilion_simple.policy("tracked_func")
        class TrackedPolicy(Policy):
            def can_execute(self, context):
                return True

        handler = ProxilionFunctionHandler(proxilion_simple)

        def tracked_func(x: int) -> int:
            return x

        handler.register_function(
            name="tracked_func",
            schema={"name": "tracked_func"},
            implementation=tracked_func,
        )

        # Execute multiple times
        handler.execute(function_name="tracked_func", arguments={"x": 1}, user=basic_user)
        handler.execute(function_name="tracked_func", arguments={"x": 2}, user=basic_user)
        handler.execute(function_name="tracked_func", arguments={"x": 3}, user=basic_user)

        history = handler.call_history
        assert len(history) == 3
        assert all(h.success for h in history)


class TestCreateSecureFunction:
    """Tests for create_secure_function helper."""

    def test_create_sync_wrapper(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test creating a sync wrapper."""
        @proxilion_simple.policy("secure_func")
        class SecurePolicy(Policy):
            def can_execute(self, context):
                return True

        def original_func(a: int, b: int) -> int:
            return a + b

        schema = {"name": "secure_func"}

        result_schema, wrapped = create_secure_function(
            function_def=schema,
            implementation=original_func,
            proxilion=proxilion_simple,
            resource="secure_func",
        )

        assert result_schema == schema
        result = wrapped(a=5, b=3, user=basic_user)
        assert result == 8

    def test_create_sync_wrapper_unauthorized(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test that sync wrapper blocks unauthorized access."""
        @proxilion_simple.policy("admin_func")
        class AdminPolicy(Policy):
            def can_execute(self, context):
                return "admin" in self.user.roles

        def original_func() -> str:
            return "secret"

        _, wrapped = create_secure_function(
            function_def={"name": "admin_func"},
            implementation=original_func,
            proxilion=proxilion_simple,
            resource="admin_func",
        )

        with pytest.raises(AuthorizationError):
            wrapped(user=basic_user)

    @pytest.mark.asyncio
    async def test_create_async_wrapper(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test creating an async wrapper."""
        @proxilion_simple.policy("async_func")
        class AsyncPolicy(Policy):
            def can_execute(self, context):
                return True

        async def original_func(value: int) -> int:
            return value * 2

        _, wrapped = create_secure_function(
            function_def={"name": "async_func"},
            implementation=original_func,
            proxilion=proxilion_simple,
            resource="async_func",
        )

        result = await wrapped(value=10, user=basic_user)
        assert result == 20


class TestProcessOpenAIResponse:
    """Tests for process_openai_response helper."""

    def test_process_function_call_response(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test processing response with function_call."""
        @proxilion_simple.policy("get_weather")
        class WeatherPolicy(Policy):
            def can_execute(self, context):
                return True

        handler = ProxilionFunctionHandler(proxilion_simple)

        def get_weather(location: str) -> str:
            return f"Weather in {location}: sunny"

        handler.register_function(
            name="get_weather",
            schema={"name": "get_weather"},
            implementation=get_weather,
        )

        # Mock OpenAI response with function_call
        @dataclass
        class MockFunctionCall:
            name: str = "get_weather"
            arguments: str = '{"location": "London"}'

        @dataclass
        class MockMessage:
            function_call: MockFunctionCall = None
            tool_calls: list = None

            def __post_init__(self):
                self.function_call = MockFunctionCall()

        @dataclass
        class MockChoice:
            message: MockMessage = None

            def __post_init__(self):
                self.message = MockMessage()

        @dataclass
        class MockResponse:
            choices: list = None

            def __post_init__(self):
                self.choices = [MockChoice()]

        response = MockResponse()
        results = process_openai_response(response, handler, basic_user)

        assert len(results) == 1
        assert results[0].success is True
        assert "London" in results[0].result

    def test_process_tool_calls_response(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test processing response with tool_calls format."""
        @proxilion_simple.policy("calculator")
        class CalcPolicy(Policy):
            def can_execute(self, context):
                return True

        handler = ProxilionFunctionHandler(proxilion_simple)

        def calculate(a: int, b: int) -> int:
            return a + b

        handler.register_function(
            name="calculator",
            schema={"name": "calculator"},
            implementation=calculate,
        )

        # Mock OpenAI response with tool_calls
        @dataclass
        class MockFunction:
            name: str = "calculator"
            arguments: str = '{"a": 10, "b": 5}'

        @dataclass
        class MockToolCall:
            type: str = "function"
            function: MockFunction = None

            def __post_init__(self):
                self.function = MockFunction()

        @dataclass
        class MockMessage:
            function_call: None = None
            tool_calls: list = None

            def __post_init__(self):
                self.tool_calls = [MockToolCall()]

        @dataclass
        class MockChoice:
            message: MockMessage = None

            def __post_init__(self):
                self.message = MockMessage()

        @dataclass
        class MockResponse:
            choices: list = None

            def __post_init__(self):
                self.choices = [MockChoice()]

        response = MockResponse()
        results = process_openai_response(response, handler, basic_user)

        assert len(results) == 1
        assert results[0].success is True
        assert results[0].result == 15

    def test_process_empty_response(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test processing response with no function calls."""
        handler = ProxilionFunctionHandler(proxilion_simple)

        @dataclass
        class MockMessage:
            function_call: None = None
            tool_calls: None = None

        @dataclass
        class MockChoice:
            message: MockMessage = None

            def __post_init__(self):
                self.message = MockMessage()

        @dataclass
        class MockResponse:
            choices: list = None

            def __post_init__(self):
                self.choices = [MockChoice()]

        response = MockResponse()
        results = process_openai_response(response, handler, basic_user)

        assert len(results) == 0


class TestRegisteredFunction:
    """Tests for RegisteredFunction dataclass."""

    def test_registered_function_creation(self):
        """Test creating a registered function record."""
        def impl(x: int) -> int:
            return x

        func = RegisteredFunction(
            name="test_func",
            schema={"name": "test_func"},
            implementation=impl,
            resource="test_resource",
            action="execute",
            async_impl=False,
            description="A test function",
        )

        assert func.name == "test_func"
        assert func.resource == "test_resource"
        assert func.action == "execute"
        assert func.async_impl is False
        assert func.description == "A test function"
