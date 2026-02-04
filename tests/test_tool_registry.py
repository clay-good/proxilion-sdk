"""
Comprehensive tests for the Tool Registry and Discovery module.

Tests cover:
- ToolCategory and RiskLevel enums
- ToolDefinition creation and format exports
- ToolRegistry registration and management
- @tool decorator with schema inference
- Integration with Proxilion core
"""

from typing import Any

import pytest

from proxilion import Proxilion
from proxilion.tools.decorators import (
    get_tool_definition,
    infer_schema_from_function,
    register_tool,
    tool,
    unregister_tool,
)
from proxilion.tools.registry import (
    RiskLevel,
    ToolCategory,
    ToolDefinition,
    ToolExecutionResult,
    ToolRegistry,
    get_global_registry,
    set_global_registry,
)
from proxilion.types import UserContext

# =============================================================================
# ToolCategory Tests
# =============================================================================


class TestToolCategory:
    """Tests for ToolCategory enum."""

    def test_all_categories_exist(self):
        """All expected categories exist."""
        expected = [
            "FILE_SYSTEM",
            "DATABASE",
            "API",
            "SEARCH",
            "COMPUTE",
            "COMMUNICATION",
            "CODE_EXECUTION",
            "DATA_PROCESSING",
            "AUTHENTICATION",
            "CUSTOM",
        ]
        for cat in expected:
            assert hasattr(ToolCategory, cat)

    def test_category_values_are_unique(self):
        """All category values are unique."""
        values = [c.value for c in ToolCategory]
        assert len(values) == len(set(values))


# =============================================================================
# RiskLevel Tests
# =============================================================================


class TestRiskLevel:
    """Tests for RiskLevel enum."""

    def test_all_risk_levels_exist(self):
        """All expected risk levels exist."""
        assert RiskLevel.LOW.value == 1
        assert RiskLevel.MEDIUM.value == 2
        assert RiskLevel.HIGH.value == 3
        assert RiskLevel.CRITICAL.value == 4

    def test_risk_levels_are_comparable(self):
        """Risk levels can be compared by value."""
        assert RiskLevel.LOW.value < RiskLevel.MEDIUM.value
        assert RiskLevel.MEDIUM.value < RiskLevel.HIGH.value
        assert RiskLevel.HIGH.value < RiskLevel.CRITICAL.value


# =============================================================================
# ToolDefinition Tests
# =============================================================================


class TestToolDefinition:
    """Tests for ToolDefinition dataclass."""

    def test_create_basic_tool_definition(self):
        """Create a basic tool definition."""
        tool_def = ToolDefinition(
            name="test_tool",
            description="A test tool",
            parameters={
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
            },
            category=ToolCategory.SEARCH,
        )

        assert tool_def.name == "test_tool"
        assert tool_def.description == "A test tool"
        assert tool_def.category == ToolCategory.SEARCH
        assert tool_def.risk_level == RiskLevel.LOW  # default
        assert tool_def.enabled is True  # default
        assert tool_def.requires_approval is False  # default

    def test_create_tool_definition_with_all_fields(self):
        """Create tool definition with all fields specified."""

        def handler(x: int) -> int:
            return x * 2

        tool_def = ToolDefinition(
            name="full_tool",
            description="Full tool description",
            parameters={"type": "object", "properties": {}},
            category=ToolCategory.COMPUTE,
            risk_level=RiskLevel.HIGH,
            requires_approval=True,
            timeout=30.0,
            handler=handler,
            metadata={"author": "test"},
            enabled=False,
        )

        assert tool_def.name == "full_tool"
        assert tool_def.risk_level == RiskLevel.HIGH
        assert tool_def.requires_approval is True
        assert tool_def.timeout == 30.0
        assert tool_def.handler is handler
        assert tool_def.metadata == {"author": "test"}
        assert tool_def.enabled is False

    def test_to_openai_format(self):
        """Export tool to OpenAI format."""
        tool_def = ToolDefinition(
            name="search_web",
            description="Search the web for information",
            parameters={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query"},
                    "max_results": {"type": "integer", "default": 10},
                },
                "required": ["query"],
            },
            category=ToolCategory.SEARCH,
        )

        openai_format = tool_def.to_openai_format()

        assert openai_format["type"] == "function"
        assert openai_format["function"]["name"] == "search_web"
        assert openai_format["function"]["description"] == "Search the web for information"
        assert openai_format["function"]["parameters"]["type"] == "object"
        assert "query" in openai_format["function"]["parameters"]["properties"]

    def test_to_anthropic_format(self):
        """Export tool to Anthropic format."""
        tool_def = ToolDefinition(
            name="read_file",
            description="Read a file from disk",
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                },
                "required": ["path"],
            },
            category=ToolCategory.FILE_SYSTEM,
        )

        anthropic_format = tool_def.to_anthropic_format()

        assert anthropic_format["name"] == "read_file"
        assert anthropic_format["description"] == "Read a file from disk"
        assert anthropic_format["input_schema"]["type"] == "object"
        assert "path" in anthropic_format["input_schema"]["properties"]

    def test_to_gemini_format(self):
        """Export tool to Gemini format."""
        tool_def = ToolDefinition(
            name="execute_sql",
            description="Execute SQL query",
            parameters={
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                },
                "required": ["query"],
            },
            category=ToolCategory.DATABASE,
        )

        gemini_format = tool_def.to_gemini_format()

        assert gemini_format["name"] == "execute_sql"
        assert gemini_format["description"] == "Execute SQL query"
        # Gemini format uses lowercase type in current implementation
        assert gemini_format["parameters"]["type"] == "object"
        assert "query" in gemini_format["parameters"]["properties"]

    def test_to_dict(self):
        """Convert tool definition to dictionary."""
        tool_def = ToolDefinition(
            name="test_tool",
            description="Test",
            parameters={"type": "object"},
            category=ToolCategory.CUSTOM,
            metadata={"key": "value"},
        )

        d = tool_def.to_dict()

        assert d["name"] == "test_tool"
        assert d["description"] == "Test"
        assert d["category"] == "CUSTOM"
        assert d["risk_level"] == "LOW"
        assert d["metadata"] == {"key": "value"}


# =============================================================================
# ToolRegistry Tests
# =============================================================================


class TestToolRegistry:
    """Tests for ToolRegistry class."""

    def test_create_empty_registry(self):
        """Create an empty registry."""
        registry = ToolRegistry()
        assert len(registry.list_all()) == 0

    def test_register_tool(self):
        """Register a tool."""
        registry = ToolRegistry()
        tool_def = ToolDefinition(
            name="test_tool",
            description="Test",
            parameters={"type": "object"},
            category=ToolCategory.CUSTOM,
        )

        registry.register(tool_def)

        assert registry.get("test_tool") == tool_def
        assert len(registry.list_all()) == 1

    def test_register_duplicate_raises(self):
        """Registering duplicate tool raises error."""
        registry = ToolRegistry()
        tool_def = ToolDefinition(
            name="duplicate_tool",
            description="Test",
            parameters={"type": "object"},
            category=ToolCategory.CUSTOM,
        )

        registry.register(tool_def)

        with pytest.raises(ValueError, match="already registered"):
            registry.register(tool_def)

    def test_register_duplicate_allow_override(self):
        """Register duplicate with register_or_replace."""
        registry = ToolRegistry()
        tool_def1 = ToolDefinition(
            name="override_tool",
            description="First version",
            parameters={"type": "object"},
            category=ToolCategory.CUSTOM,
        )
        tool_def2 = ToolDefinition(
            name="override_tool",
            description="Second version",
            parameters={"type": "object"},
            category=ToolCategory.SEARCH,
        )

        registry.register(tool_def1)
        registry.register_or_replace(tool_def2)

        tool = registry.get("override_tool")
        assert tool.description == "Second version"
        assert tool.category == ToolCategory.SEARCH

    def test_unregister_tool(self):
        """Unregister a tool."""
        registry = ToolRegistry()
        tool_def = ToolDefinition(
            name="to_remove",
            description="Test",
            parameters={"type": "object"},
            category=ToolCategory.CUSTOM,
        )

        registry.register(tool_def)
        assert registry.get("to_remove") is not None

        result = registry.unregister("to_remove")

        assert result is True
        assert registry.get("to_remove") is None

    def test_unregister_nonexistent(self):
        """Unregister nonexistent tool returns False."""
        registry = ToolRegistry()
        result = registry.unregister("nonexistent")
        assert result is False

    def test_get_nonexistent(self):
        """Get nonexistent tool returns None."""
        registry = ToolRegistry()
        assert registry.get("nonexistent") is None

    def test_list_all(self):
        """List all tools."""
        registry = ToolRegistry()
        for i in range(5):
            registry.register(
                ToolDefinition(
                    name=f"tool_{i}",
                    description=f"Tool {i}",
                    parameters={"type": "object"},
                    category=ToolCategory.CUSTOM,
                )
            )

        tools = registry.list_all()
        assert len(tools) == 5
        names = [t.name for t in tools]
        assert all(f"tool_{i}" in names for i in range(5))

    def test_list_by_category(self):
        """List tools by category."""
        registry = ToolRegistry()
        registry.register(
            ToolDefinition(
                name="search1",
                description="Search",
                parameters={"type": "object"},
                category=ToolCategory.SEARCH,
            )
        )
        registry.register(
            ToolDefinition(
                name="search2",
                description="Search",
                parameters={"type": "object"},
                category=ToolCategory.SEARCH,
            )
        )
        registry.register(
            ToolDefinition(
                name="db1",
                description="Database",
                parameters={"type": "object"},
                category=ToolCategory.DATABASE,
            )
        )

        search_tools = registry.list_by_category(ToolCategory.SEARCH)
        assert len(search_tools) == 2
        assert all(t.category == ToolCategory.SEARCH for t in search_tools)

    def test_list_by_risk_level(self):
        """List tools by maximum risk level."""
        registry = ToolRegistry()
        registry.register(
            ToolDefinition(
                name="low_risk",
                description="Low",
                parameters={"type": "object"},
                category=ToolCategory.CUSTOM,
                risk_level=RiskLevel.LOW,
            )
        )
        registry.register(
            ToolDefinition(
                name="medium_risk",
                description="Medium",
                parameters={"type": "object"},
                category=ToolCategory.CUSTOM,
                risk_level=RiskLevel.MEDIUM,
            )
        )
        registry.register(
            ToolDefinition(
                name="high_risk",
                description="High",
                parameters={"type": "object"},
                category=ToolCategory.CUSTOM,
                risk_level=RiskLevel.HIGH,
            )
        )

        low_only = registry.list_by_risk_level(RiskLevel.LOW)
        assert len(low_only) == 1
        assert low_only[0].name == "low_risk"

        up_to_medium = registry.list_by_risk_level(RiskLevel.MEDIUM)
        assert len(up_to_medium) == 2

    def test_enable_disable(self):
        """Enable and disable tools."""
        registry = ToolRegistry()
        registry.register(
            ToolDefinition(
                name="toggle_tool",
                description="Toggle",
                parameters={"type": "object"},
                category=ToolCategory.CUSTOM,
            )
        )

        assert registry.get("toggle_tool").enabled is True

        registry.disable("toggle_tool")
        assert registry.get("toggle_tool").enabled is False

        registry.enable("toggle_tool")
        assert registry.get("toggle_tool").enabled is True

    def test_export_all_openai(self):
        """Export all tools to OpenAI format."""
        registry = ToolRegistry()
        registry.register(
            ToolDefinition(
                name="tool1",
                description="Tool 1",
                parameters={"type": "object", "properties": {}},
                category=ToolCategory.CUSTOM,
            )
        )
        registry.register(
            ToolDefinition(
                name="tool2",
                description="Tool 2",
                parameters={"type": "object", "properties": {}},
                category=ToolCategory.CUSTOM,
            )
        )

        exported = registry.export_all(format="openai")

        assert len(exported) == 2
        assert all(e["type"] == "function" for e in exported)

    def test_export_all_anthropic(self):
        """Export all tools to Anthropic format."""
        registry = ToolRegistry()
        registry.register(
            ToolDefinition(
                name="tool1",
                description="Tool 1",
                parameters={"type": "object", "properties": {}},
                category=ToolCategory.CUSTOM,
            )
        )

        exported = registry.export_all(format="anthropic")

        assert len(exported) == 1
        assert "input_schema" in exported[0]

    def test_export_filtered(self):
        """Export filtered tools manually."""
        registry = ToolRegistry()
        registry.register(
            ToolDefinition(
                name="tool1",
                description="Tool 1",
                parameters={"type": "object", "properties": {}},
                category=ToolCategory.SEARCH,
            )
        )
        registry.register(
            ToolDefinition(
                name="tool2",
                description="Tool 2",
                parameters={"type": "object", "properties": {}},
                category=ToolCategory.DATABASE,
            )
        )

        # Filter tools and export individually
        search_tools = registry.list_by_category(ToolCategory.SEARCH)
        exported = [t.to_openai_format() for t in search_tools]

        assert len(exported) == 1
        assert exported[0]["function"]["name"] == "tool1"

    def test_execute_sync_handler(self):
        """Execute tool with sync handler."""
        registry = ToolRegistry()

        def multiply(x: int, y: int) -> int:
            return x * y

        registry.register(
            ToolDefinition(
                name="multiply",
                description="Multiply",
                parameters={"type": "object"},
                category=ToolCategory.COMPUTE,
                handler=multiply,
            )
        )

        result = registry.execute("multiply", x=3, y=4)

        assert result.success is True
        assert result.result == 12
        assert result.tool_name == "multiply"

    def test_execute_no_handler(self):
        """Execute tool without handler raises ValueError."""
        registry = ToolRegistry()
        registry.register(
            ToolDefinition(
                name="no_handler",
                description="No handler",
                parameters={"type": "object"},
                category=ToolCategory.CUSTOM,
            )
        )

        with pytest.raises(ValueError, match="no handler"):
            registry.execute("no_handler")

    def test_execute_nonexistent(self):
        """Execute nonexistent tool raises KeyError."""
        registry = ToolRegistry()

        with pytest.raises(KeyError, match="not found"):
            registry.execute("nonexistent")

    def test_execute_disabled(self):
        """Execute disabled tool raises."""
        registry = ToolRegistry()
        registry.register(
            ToolDefinition(
                name="disabled_tool",
                description="Disabled",
                parameters={"type": "object"},
                category=ToolCategory.CUSTOM,
                handler=lambda: "result",
                enabled=False,
            )
        )

        result = registry.execute("disabled_tool")

        assert result.success is False
        assert "disabled" in result.error.lower()

    @pytest.mark.asyncio
    async def test_execute_async_handler(self):
        """Execute tool with async handler."""
        registry = ToolRegistry()

        async def async_fetch(url: str) -> str:
            return f"fetched: {url}"

        registry.register(
            ToolDefinition(
                name="async_fetch",
                description="Async fetch",
                parameters={"type": "object"},
                category=ToolCategory.API,
                handler=async_fetch,
            )
        )

        result = await registry.execute_async("async_fetch", url="http://example.com")

        assert result.success is True
        assert result.result == "fetched: http://example.com"

    def test_execute_with_timeout(self):
        """Execute tool with timeout (timeout not enforced in basic registry)."""
        import time

        registry = ToolRegistry()

        def slow_function() -> str:
            time.sleep(0.1)
            return "done"

        registry.register(
            ToolDefinition(
                name="slow",
                description="Slow",
                parameters={"type": "object"},
                category=ToolCategory.COMPUTE,
                handler=slow_function,
                timeout=0.1,
            )
        )

        # Basic registry execute doesn't enforce timeout - it completes
        # Timeout enforcement is handled at the Proxilion level
        result = registry.execute("slow")

        assert result.success is True
        assert result.result == "done"

    def test_execute_handler_error(self):
        """Execute tool that raises exception."""
        registry = ToolRegistry()

        def failing_handler() -> None:
            raise ValueError("Handler error")

        registry.register(
            ToolDefinition(
                name="failing",
                description="Failing",
                parameters={"type": "object"},
                category=ToolCategory.CUSTOM,
                handler=failing_handler,
            )
        )

        result = registry.execute("failing")

        assert result.success is False
        assert "Handler error" in result.error


# =============================================================================
# Global Registry Tests
# =============================================================================


class TestGlobalRegistry:
    """Tests for global registry functions."""

    def test_get_global_registry(self):
        """Get global registry returns singleton."""
        registry1 = get_global_registry()
        registry2 = get_global_registry()
        assert registry1 is registry2

    def test_set_global_registry(self):
        """Set global registry."""
        old_registry = get_global_registry()
        new_registry = ToolRegistry()

        try:
            set_global_registry(new_registry)
            assert get_global_registry() is new_registry
        finally:
            # Restore
            set_global_registry(old_registry)


# =============================================================================
# Schema Inference Tests
# =============================================================================


class TestSchemaInference:
    """Tests for schema inference from function signatures."""

    def test_infer_schema_basic_types(self):
        """Infer schema from basic types."""

        def func(a: str, b: int, c: float, d: bool) -> None:
            pass

        schema = infer_schema_from_function(func)

        assert schema["type"] == "object"
        assert schema["properties"]["a"]["type"] == "string"
        assert schema["properties"]["b"]["type"] == "integer"
        assert schema["properties"]["c"]["type"] == "number"
        assert schema["properties"]["d"]["type"] == "boolean"
        assert set(schema["required"]) == {"a", "b", "c", "d"}

    def test_infer_schema_with_defaults(self):
        """Infer schema with default values."""

        def func(required: str, optional: int = 10) -> None:
            pass

        schema = infer_schema_from_function(func)

        assert schema["required"] == ["required"]
        assert schema["properties"]["optional"]["default"] == 10

    def test_infer_schema_optional_type(self):
        """Infer schema with Optional type."""

        def func(value: str | None = None) -> None:
            pass

        schema = infer_schema_from_function(func)

        assert schema["properties"]["value"]["type"] == "string"
        assert "required" not in schema or "value" not in schema.get("required", [])

    def test_infer_schema_list_type(self):
        """Infer schema from list type."""

        def func(items: list[str]) -> None:
            pass

        schema = infer_schema_from_function(func)

        assert schema["properties"]["items"]["type"] == "array"
        assert schema["properties"]["items"]["items"]["type"] == "string"

    def test_infer_schema_dict_type(self):
        """Infer schema from dict type."""

        def func(data: dict[str, int]) -> None:
            pass

        schema = infer_schema_from_function(func)

        assert schema["properties"]["data"]["type"] == "object"
        assert schema["properties"]["data"]["additionalProperties"]["type"] == "integer"

    def test_infer_schema_skip_self_cls(self):
        """Skip self and cls parameters."""

        class MyClass:
            def method(self, value: str) -> None:
                pass

            @classmethod
            def class_method(cls, value: str) -> None:
                pass

        schema1 = infer_schema_from_function(MyClass.method)
        schema2 = infer_schema_from_function(MyClass.class_method)

        assert "self" not in schema1["properties"]
        assert "cls" not in schema2["properties"]

    def test_infer_schema_skip_args_kwargs(self):
        """Skip *args and **kwargs."""

        def func(normal: str, *args: Any, **kwargs: Any) -> None:
            pass

        schema = infer_schema_from_function(func)

        assert "args" not in schema["properties"]
        assert "kwargs" not in schema["properties"]

    def test_infer_schema_no_annotations(self):
        """Handle function with no annotations."""

        def func(a, b):
            pass

        schema = infer_schema_from_function(func)

        assert "a" in schema["properties"]
        assert "b" in schema["properties"]

    def test_infer_schema_from_docstring(self):
        """Extract parameter descriptions from docstring."""

        def func(query: str, limit: int = 10) -> list:
            """
            Search for items.

            Args:
                query: The search query string.
                limit: Maximum number of results.
            """
            pass

        schema = infer_schema_from_function(func)

        assert "description" in schema["properties"]["query"]
        assert "search query" in schema["properties"]["query"]["description"].lower()


# =============================================================================
# @tool Decorator Tests
# =============================================================================


class TestToolDecorator:
    """Tests for @tool decorator."""

    def test_tool_decorator_basic(self):
        """Basic @tool decorator usage."""
        registry = ToolRegistry()

        @tool(registry=registry)
        def search(query: str) -> list:
            """Search for items."""
            return [query]

        assert registry.get("search") is not None
        assert registry.get("search").description == "Search for items."

    def test_tool_decorator_custom_name(self):
        """@tool decorator with custom name."""
        registry = ToolRegistry()

        @tool(name="web_search", registry=registry)
        def search(query: str) -> list:
            return []

        assert registry.get("web_search") is not None
        assert registry.get("search") is None

    def test_tool_decorator_with_options(self):
        """@tool decorator with all options."""
        registry = ToolRegistry()

        @tool(
            name="risky_tool",
            description="A risky operation",
            category=ToolCategory.CODE_EXECUTION,
            risk_level=RiskLevel.CRITICAL,
            requires_approval=True,
            timeout=60.0,
            registry=registry,
            author="test",
        )
        def risky(code: str) -> str:
            return code

        tool_def = registry.get("risky_tool")
        assert tool_def is not None
        assert tool_def.description == "A risky operation"
        assert tool_def.category == ToolCategory.CODE_EXECUTION
        assert tool_def.risk_level == RiskLevel.CRITICAL
        assert tool_def.requires_approval is True
        assert tool_def.timeout == 60.0
        assert tool_def.metadata["author"] == "test"

    def test_tool_decorator_preserves_function(self):
        """@tool decorator preserves function behavior."""
        registry = ToolRegistry()

        @tool(registry=registry)
        def multiply(x: int, y: int) -> int:
            return x * y

        # Function should still work
        assert multiply(3, 4) == 12

    @pytest.mark.asyncio
    async def test_tool_decorator_async_function(self):
        """@tool decorator with async function."""
        registry = ToolRegistry()

        @tool(registry=registry)
        async def async_search(query: str) -> list:
            return [query]

        assert registry.get("async_search") is not None

        # Should be callable
        result = await async_search("test")
        assert result == ["test"]

    def test_tool_decorator_infers_schema(self):
        """@tool decorator infers schema from type hints."""
        registry = ToolRegistry()

        @tool(registry=registry)
        def search(query: str, max_results: int = 10, include_metadata: bool = False) -> list:
            return []

        tool_def = registry.get("search")
        params = tool_def.parameters

        assert params["properties"]["query"]["type"] == "string"
        assert params["properties"]["max_results"]["type"] == "integer"
        assert params["properties"]["include_metadata"]["type"] == "boolean"
        assert params["required"] == ["query"]

    def test_get_tool_definition_from_decorated(self):
        """Get tool definition from decorated function."""
        registry = ToolRegistry()

        @tool(name="my_tool", registry=registry)
        def my_func() -> None:
            pass

        tool_def = get_tool_definition(my_func)
        assert tool_def is not None
        assert tool_def.name == "my_tool"


# =============================================================================
# register_tool Function Tests
# =============================================================================


class TestRegisterTool:
    """Tests for register_tool function."""

    def test_register_tool_basic(self):
        """Basic register_tool usage."""
        registry = ToolRegistry()

        def my_function(x: int) -> int:
            return x * 2

        tool_def = register_tool(my_function, registry=registry)

        assert tool_def.name == "my_function"
        assert registry.get("my_function") is not None

    def test_register_tool_with_options(self):
        """register_tool with all options."""
        registry = ToolRegistry()

        def compute(value: float) -> float:
            return value ** 2

        tool_def = register_tool(
            compute,
            name="square",
            description="Compute square",
            category=ToolCategory.COMPUTE,
            risk_level=RiskLevel.LOW,
            registry=registry,
        )

        assert tool_def.name == "square"
        assert tool_def.description == "Compute square"
        assert tool_def.category == ToolCategory.COMPUTE

    def test_unregister_tool(self):
        """Unregister a tool."""
        registry = ToolRegistry()

        @tool(name="to_remove", registry=registry)
        def func() -> None:
            pass

        assert registry.get("to_remove") is not None

        result = unregister_tool("to_remove", registry=registry)

        assert result is True
        assert registry.get("to_remove") is None


# =============================================================================
# Proxilion Integration Tests
# =============================================================================


class TestProxilionToolIntegration:
    """Tests for tool registry integration with Proxilion core."""

    def test_proxilion_has_tool_registry(self):
        """Proxilion instance has tool registry."""
        auth = Proxilion()
        assert auth.get_tool_registry() is not None

    def test_proxilion_custom_registry(self):
        """Proxilion with custom tool registry."""
        registry = ToolRegistry()
        # Register a tool to identify the registry
        registry.register(
            ToolDefinition(
                name="marker_tool",
                description="Marker",
                parameters={"type": "object"},
                category=ToolCategory.CUSTOM,
            )
        )
        auth = Proxilion(tool_registry=registry)
        # Check registry has marker tool
        assert auth.get_tool("marker_tool") is not None

    def test_register_tool_via_proxilion(self):
        """Register tool via Proxilion."""
        auth = Proxilion()
        tool_def = ToolDefinition(
            name="test_tool",
            description="Test",
            parameters={"type": "object"},
            category=ToolCategory.CUSTOM,
        )

        auth.register_tool(tool_def)

        assert auth.get_tool("test_tool") is not None

    def test_proxilion_tool_decorator(self):
        """Use @auth.tool decorator."""
        auth = Proxilion()

        @auth.tool(name="search", category=ToolCategory.SEARCH)
        def search_web(query: str) -> list:
            return [query]

        tool_def = auth.get_tool("search")
        assert tool_def is not None
        assert tool_def.category == ToolCategory.SEARCH

    def test_list_tools_filtered(self):
        """List tools with filters."""
        auth = Proxilion()

        @auth.tool(category=ToolCategory.SEARCH, risk_level=RiskLevel.LOW)
        def search1() -> None:
            pass

        @auth.tool(category=ToolCategory.SEARCH, risk_level=RiskLevel.HIGH)
        def search2() -> None:
            pass

        @auth.tool(category=ToolCategory.DATABASE, risk_level=RiskLevel.MEDIUM)
        def db1() -> None:
            pass

        # Filter by category
        search_tools = auth.list_tools(category=ToolCategory.SEARCH)
        assert len(search_tools) == 2

        # Filter by risk - LOW only gets search1
        low_risk = auth.list_tools(max_risk_level=RiskLevel.LOW)
        assert len(low_risk) == 1
        assert low_risk[0].name == "search1"

    def test_export_tools(self):
        """Export tools via Proxilion."""
        auth = Proxilion()

        @auth.tool()
        def tool1(x: str) -> str:
            return x

        @auth.tool()
        def tool2(x: int) -> int:
            return x

        openai_tools = auth.export_tools(format="openai")
        assert len(openai_tools) == 2

        anthropic_tools = auth.export_tools(format="anthropic")
        assert len(anthropic_tools) == 2

    def test_execute_tool_with_auth(self):
        """Execute tool with authorization."""
        auth = Proxilion()

        @auth.tool()
        def compute(x: int, y: int) -> int:
            return x * y

        # Register a policy that allows execution
        from proxilion.policies.base import Policy

        @auth.policy("compute")
        class ComputePolicy(Policy):
            def can_execute(self, context):
                return True

        user = UserContext(user_id="test_user", roles=["user"])
        result = auth.execute_tool("compute", user, x=3, y=4)

        assert result.success is True
        assert result.result == 12

    def test_execute_tool_unauthorized(self):
        """Execute tool fails without authorization."""
        auth = Proxilion(default_deny=True)

        @auth.tool()
        def restricted() -> str:
            return "secret"

        user = UserContext(user_id="test_user", roles=["user"])

        from proxilion.exceptions import AuthorizationError

        with pytest.raises(AuthorizationError):
            auth.execute_tool("restricted", user)

    @pytest.mark.asyncio
    async def test_execute_tool_async(self):
        """Execute tool asynchronously."""
        auth = Proxilion()

        @auth.tool()
        async def async_compute(x: int) -> int:
            return x * 2

        from proxilion.policies.base import Policy

        @auth.policy("async_compute")
        class AsyncComputePolicy(Policy):
            def can_execute(self, context):
                return True

        user = UserContext(user_id="test_user", roles=["user"])
        result = await auth.execute_tool_async("async_compute", user, x=5)

        assert result.success is True
        assert result.result == 10

    def test_enable_disable_tool_via_proxilion(self):
        """Enable/disable tools via Proxilion."""
        auth = Proxilion()

        @auth.tool()
        def toggleable() -> None:
            pass

        assert auth.get_tool("toggleable").enabled is True

        auth.disable_tool("toggleable")
        assert auth.get_tool("toggleable").enabled is False

        auth.enable_tool("toggleable")
        assert auth.get_tool("toggleable").enabled is True

    def test_get_tool_stats(self):
        """Get tool statistics."""
        auth = Proxilion()

        @auth.tool(category=ToolCategory.SEARCH, risk_level=RiskLevel.LOW)
        def search() -> None:
            pass

        @auth.tool(
            category=ToolCategory.DATABASE,
            risk_level=RiskLevel.HIGH,
            requires_approval=True,
        )
        def dangerous() -> None:
            pass

        stats = auth.get_tool_stats()

        assert stats["total"] == 2
        assert stats["enabled"] == 2
        assert stats["requires_approval"] == 1
        assert stats["by_category"]["SEARCH"] == 1
        assert stats["by_category"]["DATABASE"] == 1
        assert stats["by_risk_level"]["LOW"] == 1
        assert stats["by_risk_level"]["HIGH"] == 1

    def test_set_tool_registry(self):
        """Set a new tool registry."""
        auth = Proxilion()
        _old_registry = auth.get_tool_registry()

        new_registry = ToolRegistry()
        new_registry.register(
            ToolDefinition(
                name="new_tool",
                description="New",
                parameters={"type": "object"},
                category=ToolCategory.CUSTOM,
            )
        )

        auth.set_tool_registry(new_registry)

        assert auth.get_tool_registry() is new_registry
        assert auth.get_tool("new_tool") is not None

    def test_unregister_tool_via_proxilion(self):
        """Unregister tool via Proxilion."""
        auth = Proxilion()

        @auth.tool()
        def to_remove() -> None:
            pass

        assert auth.get_tool("to_remove") is not None

        result = auth.unregister_tool("to_remove")

        assert result is True
        assert auth.get_tool("to_remove") is None


# =============================================================================
# Thread Safety Tests
# =============================================================================


class TestThreadSafety:
    """Tests for thread safety of tool registry."""

    def test_concurrent_registration(self):
        """Concurrent tool registration is thread-safe."""
        import threading

        registry = ToolRegistry()
        errors = []

        def register_tool_thread(i: int):
            try:
                registry.register(
                    ToolDefinition(
                        name=f"tool_{i}",
                        description=f"Tool {i}",
                        parameters={"type": "object"},
                        category=ToolCategory.CUSTOM,
                    )
                )
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=register_tool_thread, args=(i,)) for i in range(50)]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(registry.list_all()) == 50

    def test_concurrent_execution(self):
        """Concurrent tool execution is thread-safe."""
        import threading

        registry = ToolRegistry()
        counter = {"value": 0}
        lock = threading.Lock()

        def increment() -> int:
            with lock:
                counter["value"] += 1
                return counter["value"]

        registry.register(
            ToolDefinition(
                name="increment",
                description="Increment counter",
                parameters={"type": "object"},
                category=ToolCategory.CUSTOM,
                handler=increment,
            )
        )

        results = []

        def execute_thread():
            result = registry.execute("increment")
            results.append(result)

        threads = [threading.Thread(target=execute_thread) for _ in range(100)]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert all(r.success for r in results)
        assert counter["value"] == 100


# =============================================================================
# Edge Cases and Error Handling Tests
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_parameters_schema(self):
        """Tool with no parameters."""
        registry = ToolRegistry()

        @tool(registry=registry)
        def no_params() -> str:
            return "result"

        tool_def = registry.get("no_params")
        assert tool_def.parameters["type"] == "object"
        assert tool_def.parameters["properties"] == {}

    def test_complex_nested_types(self):
        """Schema inference with complex nested types."""

        def func(data: list[dict[str, list[int]]]) -> None:
            pass

        schema = infer_schema_from_function(func)

        assert schema["properties"]["data"]["type"] == "array"
        assert schema["properties"]["data"]["items"]["type"] == "object"

    def test_tool_with_none_handler(self):
        """Tool definition without handler."""
        tool_def = ToolDefinition(
            name="no_handler",
            description="No handler",
            parameters={"type": "object"},
            category=ToolCategory.CUSTOM,
            handler=None,
        )

        assert tool_def.handler is None

    def test_export_invalid_format(self):
        """Export with invalid format raises."""
        registry = ToolRegistry()
        registry.register(
            ToolDefinition(
                name="tool",
                description="Tool",
                parameters={"type": "object"},
                category=ToolCategory.CUSTOM,
            )
        )

        with pytest.raises(ValueError, match="Unsupported format"):
            registry.export_all(format="invalid")

    def test_tool_decorator_without_registry(self):
        """@tool decorator uses global registry when none specified."""
        global_registry = get_global_registry()
        initial_count = len(global_registry.list_all())

        @tool()
        def global_tool() -> None:
            pass

        assert len(global_registry.list_all()) == initial_count + 1
        global_registry.unregister("global_tool")

    def test_tool_execution_result_to_dict(self):
        """ToolExecutionResult to_dict method."""
        result = ToolExecutionResult(
            success=True,
            result={"data": [1, 2, 3]},
            tool_name="test",
            execution_time=0.5,
        )

        d = result.to_dict()

        assert d["success"] is True
        assert d["tool_name"] == "test"
        assert d["execution_time"] == 0.5
