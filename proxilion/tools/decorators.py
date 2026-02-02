"""
Decorators for tool registration.

Provides convenient decorators for registering functions as tools
with automatic schema inference from type hints.
"""

from __future__ import annotations

import functools
import inspect
import logging
from collections.abc import Callable
from typing import Any, TypeVar, Union, get_args, get_origin, get_type_hints

from proxilion.tools.registry import (
    RiskLevel,
    ToolCategory,
    ToolDefinition,
    ToolRegistry,
    get_global_registry,
)

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])


def infer_schema_from_function(func: Callable[..., Any]) -> dict[str, Any]:
    """
    Infer a JSON Schema from function signature and type hints.

    Analyzes the function's parameters and type annotations to generate
    a JSON Schema compatible with OpenAI/Anthropic tool definitions.

    Args:
        func: The function to analyze.

    Returns:
        A JSON Schema dictionary describing the function's parameters.

    Example:
        >>> def search(query: str, max_results: int = 10) -> list[dict]:
        ...     pass
        >>> schema = infer_schema_from_function(search)
        >>> schema["type"]
        'object'
        >>> "query" in schema["properties"]
        True
    """
    schema: dict[str, Any] = {
        "type": "object",
        "properties": {},
        "required": [],
    }

    sig = inspect.signature(func)

    # Try to get type hints, handling potential errors
    try:
        hints = get_type_hints(func)
    except Exception:
        hints = {}

    for param_name, param in sig.parameters.items():
        # Skip self, cls, *args, **kwargs
        if param_name in ("self", "cls"):
            continue
        if param.kind in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        ):
            continue

        # Get type annotation
        type_hint = hints.get(param_name, param.annotation)
        if type_hint is inspect.Parameter.empty:
            type_hint = Any

        # Convert type to JSON Schema
        prop_schema = _type_to_schema(type_hint)

        # Add description from docstring if available
        param_desc = _extract_param_description(func, param_name)
        if param_desc:
            prop_schema["description"] = param_desc

        # Add default value if present
        if param.default is not inspect.Parameter.empty:
            if param.default is not None:
                prop_schema["default"] = param.default
        else:
            # No default means required
            schema["required"].append(param_name)

        schema["properties"][param_name] = prop_schema

    # Remove empty required list
    if not schema["required"]:
        del schema["required"]

    return schema


def _type_to_schema(type_hint: Any) -> dict[str, Any]:
    """
    Convert a Python type hint to JSON Schema.

    Args:
        type_hint: The Python type hint.

    Returns:
        A JSON Schema dictionary for the type.
    """
    # Handle None/NoneType
    if type_hint is None or type_hint is type(None):
        return {"type": "null"}

    # Handle basic types
    if type_hint is str:
        return {"type": "string"}
    if type_hint is int:
        return {"type": "integer"}
    if type_hint is float:
        return {"type": "number"}
    if type_hint is bool:
        return {"type": "boolean"}
    if type_hint is Any:
        return {}  # Any type

    # Handle generic types
    origin = get_origin(type_hint)
    args = get_args(type_hint)

    # Handle Optional (Union[X, None])
    if origin is Union:
        # Filter out NoneType
        non_none_args = [a for a in args if a is not type(None)]
        if len(non_none_args) == 1:
            # Optional[X] -> X with nullable
            schema = _type_to_schema(non_none_args[0])
            # JSON Schema draft 2020-12 uses "type": ["string", "null"]
            # But for compatibility, we'll just return the base type
            return schema
        else:
            # Union of multiple types
            return {"oneOf": [_type_to_schema(a) for a in non_none_args]}

    # Handle list/List
    if origin is list:
        schema: dict[str, Any] = {"type": "array"}
        if args:
            schema["items"] = _type_to_schema(args[0])
        return schema

    # Handle dict/Dict
    if origin is dict:
        schema = {"type": "object"}
        if len(args) >= 2:
            schema["additionalProperties"] = _type_to_schema(args[1])
        return schema

    # Handle tuple/Tuple
    if origin is tuple:
        if args:
            if len(args) == 2 and args[1] is Ellipsis:
                # Tuple[X, ...] is like List[X]
                return {"type": "array", "items": _type_to_schema(args[0])}
            else:
                # Fixed-length tuple
                return {
                    "type": "array",
                    "prefixItems": [_type_to_schema(a) for a in args],
                    "minItems": len(args),
                    "maxItems": len(args),
                }
        return {"type": "array"}

    # Handle set/Set
    if origin is set or origin is frozenset:
        schema = {"type": "array", "uniqueItems": True}
        if args:
            schema["items"] = _type_to_schema(args[0])
        return schema

    # Handle Literal
    try:
        from typing import Literal

        if origin is Literal:
            return {"enum": list(args)}
    except ImportError:
        pass

    # Handle classes with __annotations__ (dataclasses, etc.)
    if hasattr(type_hint, "__annotations__"):
        properties = {}
        required = []
        annotations = getattr(type_hint, "__annotations__", {})
        for field_name, field_type in annotations.items():
            properties[field_name] = _type_to_schema(field_type)
            # For dataclasses, check if field has default
            if hasattr(type_hint, "__dataclass_fields__"):
                field_info = type_hint.__dataclass_fields__.get(field_name)
                if field_info and field_info.default is field_info.default_factory:
                    required.append(field_name)
            else:
                required.append(field_name)

        schema = {"type": "object", "properties": properties}
        if required:
            schema["required"] = required
        return schema

    # Default to string for unknown types
    return {"type": "string"}


def _extract_param_description(func: Callable[..., Any], param_name: str) -> str | None:
    """
    Extract parameter description from function docstring.

    Supports Google, NumPy, and Sphinx docstring formats.

    Args:
        func: The function with docstring.
        param_name: The parameter name to look for.

    Returns:
        The parameter description or None.
    """
    docstring = func.__doc__
    if not docstring:
        return None

    lines = docstring.split("\n")

    # Try Google style: "param_name: description" or "param_name (type): description"
    for i, line in enumerate(lines):
        stripped = line.strip()
        # Google style
        if stripped.startswith(f"{param_name}:") or stripped.startswith(
            f"{param_name} ("
        ):
            # Extract description after colon
            if ":" in stripped:
                desc = stripped.split(":", 1)[1].strip()
                # Check for continuation on next lines
                j = i + 1
                while j < len(lines):
                    next_line = lines[j]
                    if next_line.strip() and not next_line.strip().startswith(
                        tuple("abcdefghijklmnopqrstuvwxyz_")
                    ):
                        # Continuation
                        desc += " " + next_line.strip()
                        j += 1
                    else:
                        break
                return desc

        # Sphinx style: ":param param_name: description"
        if stripped.startswith(f":param {param_name}:"):
            desc = stripped.split(":", 2)[2].strip()
            return desc

        # NumPy style: "param_name : type\n    description"
        if stripped == param_name or stripped.startswith(f"{param_name} :"):
            if i + 1 < len(lines):
                next_line = lines[i + 1].strip()
                if next_line and not next_line.startswith(("-", "=")):
                    return next_line

    return None


def tool(
    name: str | None = None,
    description: str | None = None,
    category: ToolCategory = ToolCategory.CUSTOM,
    risk_level: RiskLevel = RiskLevel.LOW,
    requires_approval: bool = False,
    timeout: float | None = None,
    registry: ToolRegistry | None = None,
    enabled: bool = True,
    **metadata: Any,
) -> Callable[[F], F]:
    """
    Decorator to register a function as a tool.

    Automatically infers the parameter schema from type hints and
    registers the function with the specified registry.

    Args:
        name: Tool name (defaults to function name).
        description: Tool description (defaults to function docstring).
        category: Tool category for organization.
        risk_level: Risk level for authorization decisions.
        requires_approval: Whether tool requires explicit approval.
        timeout: Execution timeout in seconds.
        registry: Registry to register with (defaults to global).
        enabled: Whether tool is enabled by default.
        **metadata: Additional metadata to attach.

    Returns:
        Decorator function.

    Example:
        >>> @tool(
        ...     name="search_web",
        ...     description="Search the web for information",
        ...     category=ToolCategory.SEARCH,
        ...     risk_level=RiskLevel.LOW,
        ... )
        ... def search_web(query: str, max_results: int = 10) -> list[dict]:
        ...     '''
        ...     Search the web.
        ...
        ...     Args:
        ...         query: The search query.
        ...         max_results: Maximum results to return.
        ...     '''
        ...     return perform_search(query, max_results)
    """

    def decorator(func: F) -> F:
        # Determine tool name
        tool_name = name if name is not None else func.__name__

        # Determine description
        tool_description = description
        if tool_description is None:
            # Extract from docstring
            if func.__doc__:
                # Get first paragraph of docstring
                doc_lines = func.__doc__.strip().split("\n\n")[0].split("\n")
                tool_description = " ".join(line.strip() for line in doc_lines)
            else:
                tool_description = f"Execute {tool_name}"

        # Infer parameter schema
        parameters = infer_schema_from_function(func)

        # Create tool definition
        tool_def = ToolDefinition(
            name=tool_name,
            description=tool_description,
            parameters=parameters,
            category=category,
            risk_level=risk_level,
            requires_approval=requires_approval,
            timeout=timeout,
            handler=func,
            metadata=metadata,
            enabled=enabled,
        )

        # Register with registry
        target_registry = registry if registry is not None else get_global_registry()
        target_registry.register(tool_def)

        logger.debug(f"Registered tool: {tool_name}")

        # Preserve function metadata
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return func(*args, **kwargs)

        # Attach tool definition to wrapper
        wrapper._tool_definition = tool_def  # type: ignore
        wrapper._tool_name = tool_name  # type: ignore

        return wrapper  # type: ignore

    return decorator


def register_tool(
    func: Callable[..., Any],
    name: str | None = None,
    description: str | None = None,
    category: ToolCategory = ToolCategory.CUSTOM,
    risk_level: RiskLevel = RiskLevel.LOW,
    requires_approval: bool = False,
    timeout: float | None = None,
    registry: ToolRegistry | None = None,
    enabled: bool = True,
    **metadata: Any,
) -> ToolDefinition:
    """
    Register a function as a tool without using decorator syntax.

    Useful for registering existing functions or lambdas as tools.

    Args:
        func: The function to register.
        name: Tool name (defaults to function name).
        description: Tool description (defaults to function docstring).
        category: Tool category for organization.
        risk_level: Risk level for authorization decisions.
        requires_approval: Whether tool requires explicit approval.
        timeout: Execution timeout in seconds.
        registry: Registry to register with (defaults to global).
        enabled: Whether tool is enabled by default.
        **metadata: Additional metadata to attach.

    Returns:
        The created ToolDefinition.

    Example:
        >>> def my_function(x: int) -> int:
        ...     return x * 2
        >>> tool_def = register_tool(
        ...     my_function,
        ...     name="double",
        ...     description="Double a number",
        ... )
    """
    # Determine tool name
    tool_name = name if name is not None else func.__name__

    # Determine description
    tool_description = description
    if tool_description is None:
        if func.__doc__:
            doc_lines = func.__doc__.strip().split("\n\n")[0].split("\n")
            tool_description = " ".join(line.strip() for line in doc_lines)
        else:
            tool_description = f"Execute {tool_name}"

    # Infer parameter schema
    parameters = infer_schema_from_function(func)

    # Create tool definition
    tool_def = ToolDefinition(
        name=tool_name,
        description=tool_description,
        parameters=parameters,
        category=category,
        risk_level=risk_level,
        requires_approval=requires_approval,
        timeout=timeout,
        handler=func,
        metadata=metadata,
        enabled=enabled,
    )

    # Register with registry
    target_registry = registry if registry is not None else get_global_registry()
    target_registry.register(tool_def)

    logger.debug(f"Registered tool: {tool_name}")

    return tool_def


def unregister_tool(
    name: str,
    registry: ToolRegistry | None = None,
) -> bool:
    """
    Unregister a tool by name.

    Args:
        name: The tool name to unregister.
        registry: Registry to unregister from (defaults to global).

    Returns:
        True if the tool was found and unregistered.
    """
    target_registry = registry if registry is not None else get_global_registry()
    return target_registry.unregister(name)


def get_tool_definition(func: Callable[..., Any]) -> ToolDefinition | None:
    """
    Get the tool definition attached to a decorated function.

    Args:
        func: The decorated function.

    Returns:
        The ToolDefinition or None if not a registered tool.

    Example:
        >>> @tool(name="my_tool")
        ... def my_func():
        ...     pass
        >>> tool_def = get_tool_definition(my_func)
        >>> tool_def.name
        'my_tool'
    """
    return getattr(func, "_tool_definition", None)
