"""
Tool registry for centralized tool management.

Provides a registry for tools with metadata, schemas, and
export capabilities for different LLM providers.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any

logger = logging.getLogger(__name__)


class ToolCategory(Enum):
    """Categories of tools for organization and filtering."""

    FILE_SYSTEM = auto()
    DATABASE = auto()
    API = auto()
    SEARCH = auto()
    COMPUTE = auto()
    COMMUNICATION = auto()
    CODE_EXECUTION = auto()
    DATA_PROCESSING = auto()
    AUTHENTICATION = auto()
    CUSTOM = auto()

    def __str__(self) -> str:
        return self.name.lower()


class RiskLevel(Enum):
    """Risk levels for tool operations."""

    LOW = 1  # Read-only, no sensitive data
    MEDIUM = 2  # May modify non-critical data
    HIGH = 3  # May modify critical data or access sensitive info
    CRITICAL = 4  # Destructive operations, requires approval

    def __lt__(self, other: RiskLevel) -> bool:
        if not isinstance(other, RiskLevel):
            return NotImplemented
        return self.value < other.value

    def __le__(self, other: RiskLevel) -> bool:
        return self == other or self < other

    def __gt__(self, other: RiskLevel) -> bool:
        return not self <= other

    def __ge__(self, other: RiskLevel) -> bool:
        return not self < other


@dataclass
class ToolDefinition:
    """
    Definition of a tool that can be called by an AI agent.

    Attributes:
        name: Unique identifier for the tool.
        description: Human-readable description of what the tool does.
        parameters: JSON Schema describing the tool's parameters.
        category: Category for organization and filtering.
        risk_level: Risk level for authorization decisions.
        requires_approval: Whether human approval is required.
        timeout: Timeout for tool execution in seconds.
        handler: The function that implements the tool.
        metadata: Additional metadata about the tool.
        enabled: Whether the tool is currently enabled.

    Example:
        >>> tool_def = ToolDefinition(
        ...     name="search_web",
        ...     description="Search the web for information",
        ...     parameters={
        ...         "type": "object",
        ...         "properties": {
        ...             "query": {"type": "string", "description": "Search query"},
        ...             "max_results": {"type": "integer", "default": 10},
        ...         },
        ...         "required": ["query"],
        ...     },
        ...     category=ToolCategory.SEARCH,
        ...     risk_level=RiskLevel.LOW,
        ...     handler=search_function,
        ... )
    """

    name: str
    description: str
    parameters: dict[str, Any] = field(default_factory=lambda: {
        "type": "object",
        "properties": {},
        "required": [],
    })
    category: ToolCategory = ToolCategory.CUSTOM
    risk_level: RiskLevel = RiskLevel.LOW
    requires_approval: bool = False
    timeout: float | None = None
    handler: Callable[..., Any] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    enabled: bool = True

    def __post_init__(self) -> None:
        """Validate the tool definition."""
        if not self.name:
            raise ValueError("Tool name cannot be empty")
        if not self.description:
            raise ValueError("Tool description cannot be empty")

    def to_openai_format(self) -> dict[str, Any]:
        """
        Export as OpenAI function definition.

        Returns:
            Dictionary in OpenAI tools format.
        """
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }

    def to_anthropic_format(self) -> dict[str, Any]:
        """
        Export as Anthropic tool definition.

        Returns:
            Dictionary in Anthropic tools format.
        """
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.parameters,
        }

    def to_gemini_format(self) -> dict[str, Any]:
        """
        Export as Google Gemini function declaration.

        Returns:
            Dictionary in Gemini function declaration format.
        """
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters,
        }

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters,
            "category": self.category.name,
            "risk_level": self.risk_level.name,
            "requires_approval": self.requires_approval,
            "timeout": self.timeout,
            "enabled": self.enabled,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ToolDefinition:
        """Create from dictionary."""
        return cls(
            name=data["name"],
            description=data["description"],
            parameters=data.get("parameters", {}),
            category=ToolCategory[data.get("category", "CUSTOM")],
            risk_level=RiskLevel[data.get("risk_level", "LOW")],
            requires_approval=data.get("requires_approval", False),
            timeout=data.get("timeout"),
            metadata=data.get("metadata", {}),
            enabled=data.get("enabled", True),
        )


@dataclass
class ToolExecutionResult:
    """
    Result of a tool execution.

    Attributes:
        tool_name: Name of the executed tool.
        success: Whether execution succeeded.
        result: The result value if successful.
        error: Error message if failed.
        execution_time: Time taken to execute in seconds.
        timestamp: When execution occurred.
    """

    tool_name: str
    success: bool
    result: Any = None
    error: str | None = None
    execution_time: float = 0.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "tool_name": self.tool_name,
            "success": self.success,
            "result": self.result if self.success else None,
            "error": self.error,
            "execution_time": self.execution_time,
            "timestamp": self.timestamp.isoformat(),
        }


class ToolRegistry:
    """
    Central registry for tool management.

    Provides registration, discovery, and execution of tools
    with support for different export formats.

    Example:
        >>> registry = ToolRegistry()
        >>> registry.register(ToolDefinition(
        ...     name="calculator",
        ...     description="Perform calculations",
        ...     parameters={"type": "object", "properties": {...}},
        ...     handler=calculate,
        ... ))
        >>>
        >>> # Get tool
        >>> tool = registry.get("calculator")
        >>>
        >>> # Export to OpenAI format
        >>> tools = registry.export_all(format="openai")
        >>>
        >>> # Execute tool
        >>> result = registry.execute("calculator", expression="2+2")
    """

    SUPPORTED_FORMATS = ("openai", "anthropic", "gemini", "dict")

    def __init__(self) -> None:
        """Initialize the registry."""
        self._tools: dict[str, ToolDefinition] = {}
        self._lock = threading.RLock()
        self._execution_hooks: list[Callable[[str, dict[str, Any]], None]] = []

    def register(self, tool: ToolDefinition) -> ToolRegistry:
        """
        Register a tool.

        Args:
            tool: The tool definition to register.

        Returns:
            Self for chaining.

        Raises:
            ValueError: If a tool with the same name already exists.
        """
        with self._lock:
            if tool.name in self._tools:
                raise ValueError(f"Tool '{tool.name}' is already registered")
            self._tools[tool.name] = tool
            logger.debug(f"Registered tool: {tool.name}")
        return self

    def register_or_replace(self, tool: ToolDefinition) -> ToolRegistry:
        """
        Register a tool, replacing if it already exists.

        Args:
            tool: The tool definition to register.

        Returns:
            Self for chaining.
        """
        with self._lock:
            existed = tool.name in self._tools
            self._tools[tool.name] = tool
            action = "Replaced" if existed else "Registered"
            logger.debug(f"{action} tool: {tool.name}")
        return self

    def unregister(self, name: str) -> bool:
        """
        Unregister a tool.

        Args:
            name: Name of the tool to unregister.

        Returns:
            True if tool was found and removed.
        """
        with self._lock:
            if name in self._tools:
                del self._tools[name]
                logger.debug(f"Unregistered tool: {name}")
                return True
            return False

    def get(self, name: str) -> ToolDefinition | None:
        """
        Get a tool by name.

        Args:
            name: Name of the tool.

        Returns:
            ToolDefinition or None if not found.
        """
        return self._tools.get(name)

    def get_required(self, name: str) -> ToolDefinition:
        """
        Get a tool by name, raising if not found.

        Args:
            name: Name of the tool.

        Returns:
            ToolDefinition.

        Raises:
            KeyError: If tool not found.
        """
        tool = self.get(name)
        if tool is None:
            raise KeyError(f"Tool '{name}' not found")
        return tool

    def has(self, name: str) -> bool:
        """Check if a tool is registered."""
        return name in self._tools

    def list_all(self) -> list[ToolDefinition]:
        """
        List all registered tools.

        Returns:
            List of all tool definitions.
        """
        with self._lock:
            return list(self._tools.values())

    def list_enabled(self) -> list[ToolDefinition]:
        """
        List all enabled tools.

        Returns:
            List of enabled tool definitions.
        """
        with self._lock:
            return [t for t in self._tools.values() if t.enabled]

    def list_by_category(self, category: ToolCategory) -> list[ToolDefinition]:
        """
        List tools by category.

        Args:
            category: The category to filter by.

        Returns:
            List of matching tool definitions.
        """
        with self._lock:
            return [t for t in self._tools.values() if t.category == category]

    def list_by_risk_level(
        self, max_risk: RiskLevel, include_higher: bool = False
    ) -> list[ToolDefinition]:
        """
        List tools up to a given risk level.

        Args:
            max_risk: Maximum risk level to include.
            include_higher: If True, include higher risk levels too.

        Returns:
            List of matching tool definitions.
        """
        with self._lock:
            if include_higher:
                return [t for t in self._tools.values() if t.risk_level >= max_risk]
            return [t for t in self._tools.values() if t.risk_level <= max_risk]

    def list_requiring_approval(self) -> list[ToolDefinition]:
        """
        List tools that require approval.

        Returns:
            List of tools requiring human approval.
        """
        with self._lock:
            return [t for t in self._tools.values() if t.requires_approval]

    def list_names(self) -> list[str]:
        """Get list of all tool names."""
        with self._lock:
            return list(self._tools.keys())

    def enable(self, name: str) -> bool:
        """
        Enable a tool.

        Args:
            name: Name of the tool.

        Returns:
            True if tool was found.
        """
        tool = self.get(name)
        if tool:
            tool.enabled = True
            return True
        return False

    def disable(self, name: str) -> bool:
        """
        Disable a tool.

        Args:
            name: Name of the tool.

        Returns:
            True if tool was found.
        """
        tool = self.get(name)
        if tool:
            tool.enabled = False
            return True
        return False

    def export_all(
        self,
        format: str = "openai",
        enabled_only: bool = True,
    ) -> list[dict[str, Any]]:
        """
        Export all tools to a specific format.

        Args:
            format: Export format ("openai", "anthropic", "gemini", "dict").
            enabled_only: Only export enabled tools.

        Returns:
            List of tool definitions in requested format.

        Raises:
            ValueError: If format is not supported.
        """
        if format not in self.SUPPORTED_FORMATS:
            raise ValueError(
                f"Unsupported format: {format}. Supported: {self.SUPPORTED_FORMATS}"
            )

        with self._lock:
            tools = self.list_enabled() if enabled_only else self.list_all()

            if format == "openai":
                return [t.to_openai_format() for t in tools]
            elif format == "anthropic":
                return [t.to_anthropic_format() for t in tools]
            elif format == "gemini":
                return [t.to_gemini_format() for t in tools]
            else:  # dict
                return [t.to_dict() for t in tools]

    def export_one(self, name: str, format: str = "openai") -> dict[str, Any] | None:
        """
        Export a single tool.

        Args:
            name: Name of the tool.
            format: Export format.

        Returns:
            Tool definition in requested format, or None if not found.
        """
        tool = self.get(name)
        if tool is None:
            return None

        if format == "openai":
            return tool.to_openai_format()
        elif format == "anthropic":
            return tool.to_anthropic_format()
        elif format == "gemini":
            return tool.to_gemini_format()
        else:
            return tool.to_dict()

    def execute(
        self,
        name: str,
        **kwargs: Any,
    ) -> ToolExecutionResult:
        """
        Execute a tool by name.

        Args:
            name: Name of the tool to execute.
            **kwargs: Arguments to pass to the tool handler.

        Returns:
            ToolExecutionResult with execution details.

        Raises:
            KeyError: If tool not found.
            ValueError: If tool has no handler.
        """
        tool = self.get_required(name)

        if not tool.enabled:
            return ToolExecutionResult(
                tool_name=name,
                success=False,
                error=f"Tool '{name}' is disabled",
            )

        if tool.handler is None:
            raise ValueError(f"Tool '{name}' has no handler")

        # Invoke execution hooks
        for hook in self._execution_hooks:
            try:
                hook(name, kwargs)
            except Exception as e:
                logger.warning(f"Execution hook error: {e}")

        start_time = datetime.now(timezone.utc)

        try:
            # Check if handler is async
            if inspect.iscoroutinefunction(tool.handler):
                # Run async handler in event loop
                loop = asyncio.new_event_loop()
                try:
                    result = loop.run_until_complete(tool.handler(**kwargs))
                finally:
                    loop.close()
            else:
                result = tool.handler(**kwargs)

            execution_time = (datetime.now(timezone.utc) - start_time).total_seconds()

            return ToolExecutionResult(
                tool_name=name,
                success=True,
                result=result,
                execution_time=execution_time,
            )

        except Exception as e:
            execution_time = (datetime.now(timezone.utc) - start_time).total_seconds()
            logger.error(f"Tool '{name}' execution failed: {e}")

            return ToolExecutionResult(
                tool_name=name,
                success=False,
                error=str(e),
                execution_time=execution_time,
            )

    async def execute_async(
        self,
        name: str,
        **kwargs: Any,
    ) -> ToolExecutionResult:
        """
        Execute a tool by name asynchronously.

        Args:
            name: Name of the tool to execute.
            **kwargs: Arguments to pass to the tool handler.

        Returns:
            ToolExecutionResult with execution details.
        """
        tool = self.get_required(name)

        if not tool.enabled:
            return ToolExecutionResult(
                tool_name=name,
                success=False,
                error=f"Tool '{name}' is disabled",
            )

        if tool.handler is None:
            raise ValueError(f"Tool '{name}' has no handler")

        # Invoke execution hooks
        for hook in self._execution_hooks:
            try:
                hook(name, kwargs)
            except Exception as e:
                logger.warning(f"Execution hook error: {e}")

        start_time = datetime.now(timezone.utc)

        try:
            # Check if handler is async
            if inspect.iscoroutinefunction(tool.handler):
                result = await tool.handler(**kwargs)
            else:
                # Run sync handler in thread pool
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(
                    None, lambda: tool.handler(**kwargs)
                )

            execution_time = (datetime.now(timezone.utc) - start_time).total_seconds()

            return ToolExecutionResult(
                tool_name=name,
                success=True,
                result=result,
                execution_time=execution_time,
            )

        except Exception as e:
            execution_time = (datetime.now(timezone.utc) - start_time).total_seconds()
            logger.error(f"Tool '{name}' execution failed: {e}")

            return ToolExecutionResult(
                tool_name=name,
                success=False,
                error=str(e),
                execution_time=execution_time,
            )

    def add_execution_hook(
        self, hook: Callable[[str, dict[str, Any]], None]
    ) -> ToolRegistry:
        """
        Add a hook to be called before tool execution.

        Args:
            hook: Function called with (tool_name, kwargs).

        Returns:
            Self for chaining.
        """
        self._execution_hooks.append(hook)
        return self

    def remove_execution_hook(
        self, hook: Callable[[str, dict[str, Any]], None]
    ) -> bool:
        """
        Remove an execution hook.

        Args:
            hook: The hook to remove.

        Returns:
            True if hook was found and removed.
        """
        try:
            self._execution_hooks.remove(hook)
            return True
        except ValueError:
            return False

    def clear(self) -> None:
        """Remove all registered tools."""
        with self._lock:
            self._tools.clear()

    def __len__(self) -> int:
        """Get number of registered tools."""
        return len(self._tools)

    def __contains__(self, name: str) -> bool:
        """Check if tool is registered."""
        return name in self._tools

    def __iter__(self):
        """Iterate over tool definitions."""
        return iter(self._tools.values())

    def to_dict(self) -> dict[str, Any]:
        """Convert registry state to dictionary."""
        return {
            "tools": [t.to_dict() for t in self._tools.values()],
            "count": len(self._tools),
        }


# Global registry instance
_global_registry: ToolRegistry | None = None
_global_lock = threading.Lock()


def get_global_registry() -> ToolRegistry:
    """
    Get the global tool registry.

    Creates one if it doesn't exist.

    Returns:
        The global ToolRegistry instance.
    """
    global _global_registry
    with _global_lock:
        if _global_registry is None:
            _global_registry = ToolRegistry()
        return _global_registry


def set_global_registry(registry: ToolRegistry | None) -> None:
    """
    Set the global tool registry.

    Args:
        registry: The registry to use, or None to clear.
    """
    global _global_registry
    with _global_lock:
        _global_registry = registry
