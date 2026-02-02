"""
Tool registry and management for AI agents.

Provides centralized management of tools with metadata, schemas,
and discovery capabilities. Makes it easy to manage tools across
an application and export them to different LLM provider formats.

Features:
    - Centralized tool registration
    - Schema inference from type hints
    - Export to OpenAI, Anthropic, and Gemini formats
    - Category and risk-level filtering
    - Tool execution with authorization

Example:
    >>> from proxilion.tools import (
    ...     ToolRegistry, ToolDefinition, ToolCategory, RiskLevel,
    ...     tool, get_global_registry,
    ... )
    >>>
    >>> # Create a registry
    >>> registry = ToolRegistry()
    >>>
    >>> # Register tools with decorator
    >>> @tool(
    ...     name="search_web",
    ...     description="Search the web",
    ...     category=ToolCategory.SEARCH,
    ...     registry=registry,
    ... )
    ... def search_web(query: str, max_results: int = 10) -> list[dict]:
    ...     return perform_search(query, max_results)
    >>>
    >>> # Export to OpenAI format
    >>> tools = registry.export_all(format="openai")
    >>>
    >>> # Execute a tool
    >>> result = registry.execute("search_web", query="python async")
"""

from proxilion.tools.decorators import (
    infer_schema_from_function,
    register_tool,
    tool,
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

__all__ = [
    # Registry classes
    "ToolCategory",
    "RiskLevel",
    "ToolDefinition",
    "ToolRegistry",
    "ToolExecutionResult",
    "get_global_registry",
    "set_global_registry",
    # Decorators
    "tool",
    "register_tool",
    "infer_schema_from_function",
]
