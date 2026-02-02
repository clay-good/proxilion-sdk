"""
Google Vertex AI / Gemini integration for Proxilion.

Provides authorization wrappers for Gemini's function calling feature,
enabling secure tool execution with user-context authorization.

Features:
    - ProxilionVertexHandler: Manages tool registration and execution for Vertex AI
    - GeminiFunctionCall: Represents a function call from Gemini response
    - GeminiToolResult: Result of a tool execution
    - extract_function_calls: Extract function calls from Gemini responses
    - format_tool_response: Format results for sending back to Gemini

Note:
    The vertexai library (google-cloud-aiplatform) is an optional dependency.
    This module works by wrapping tool definitions and implementations rather
    than modifying the Vertex AI client directly.

Example:
    >>> import vertexai
    >>> from vertexai.generative_models import GenerativeModel, Tool
    >>> from proxilion import Proxilion, UserContext
    >>> from proxilion.contrib.google import ProxilionVertexHandler
    >>>
    >>> auth = Proxilion()
    >>> handler = ProxilionVertexHandler(auth)
    >>>
    >>> # Register tools
    >>> handler.register_tool(
    ...     name="search_database",
    ...     declaration={
    ...         "name": "search_database",
    ...         "description": "Search the database",
    ...         "parameters": {
    ...             "type": "object",
    ...             "properties": {
    ...                 "query": {"type": "string"}
    ...             },
    ...             "required": ["query"]
    ...         }
    ...     },
    ...     implementation=search_database_fn,
    ...     resource="database",
    ... )
    >>>
    >>> # Get Gemini-formatted tools
    >>> gemini_tools = handler.to_gemini_tools()
    >>>
    >>> # Create model with tools
    >>> model = GenerativeModel("gemini-1.5-pro", tools=gemini_tools)
    >>> response = model.generate_content("Find users named John")
    >>>
    >>> # Process function calls with authorization
    >>> results = handler.process_response(response, user=current_user)
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, TypeVar

from proxilion.exceptions import ProxilionError
from proxilion.types import AgentContext, UserContext

logger = logging.getLogger(__name__)

T = TypeVar("T")


class GoogleIntegrationError(ProxilionError):
    """Error in Google Vertex AI / Gemini integration."""
    pass


class ToolNotFoundError(GoogleIntegrationError):
    """Raised when a tool is not registered."""

    def __init__(self, tool_name: str) -> None:
        self.tool_name = tool_name
        super().__init__(f"Tool not registered: {tool_name}")


class ToolExecutionError(GoogleIntegrationError):
    """Raised when tool execution fails."""

    def __init__(self, tool_name: str, safe_message: str) -> None:
        self.tool_name = tool_name
        self.safe_message = safe_message
        super().__init__(f"Tool execution failed: {safe_message}")


@dataclass
class GeminiFunctionCall:
    """
    Represents a Gemini function call.

    Attributes:
        name: Name of the function to call.
        args: Arguments passed to the function.
        raw: Original function call object from Gemini.

    Example:
        >>> call = GeminiFunctionCall(
        ...     name="get_weather",
        ...     args={"location": "San Francisco"},
        ...     raw=gemini_function_call,
        ... )
    """
    name: str
    args: dict[str, Any]
    raw: Any = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "args": self.args,
        }


@dataclass
class GeminiToolResult:
    """
    Result of a Gemini tool execution.

    Attributes:
        name: Name of the tool that was executed.
        success: Whether the execution succeeded.
        result: The result value if successful.
        error: Error message if failed.
        authorized: Whether the call was authorized.
        timestamp: When the execution occurred.

    Example:
        >>> result = GeminiToolResult(
        ...     name="get_weather",
        ...     success=True,
        ...     result={"temperature": 72, "condition": "sunny"},
        ... )
    """
    name: str
    success: bool
    result: Any | None = None
    error: str | None = None
    authorized: bool = True
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "success": self.success,
            "result": self.result,
            "error": self.error,
            "authorized": self.authorized,
            "timestamp": self.timestamp.isoformat(),
        }

    def to_function_response(self) -> dict[str, Any]:
        """
        Convert to Gemini function_response format.

        Returns:
            Dictionary suitable for Part.from_function_response().
        """
        if self.success:
            response_data = self.result
            if not isinstance(response_data, dict):
                response_data = {"result": response_data}
        else:
            response_data = {"error": self.error or "Execution failed"}

        return {
            "name": self.name,
            "response": response_data,
        }


@dataclass
class RegisteredGeminiTool:
    """A registered tool with its declaration and implementation."""
    name: str
    declaration: dict[str, Any]
    implementation: Callable[..., Any]
    resource: str
    action: str
    async_impl: bool
    description: str


class ProxilionVertexHandler:
    """
    Handler for Google Vertex AI / Gemini function calling with Proxilion.

    Manages tool registration, authorization, and execution for
    Gemini's function calling feature.

    Example:
        >>> from proxilion import Proxilion, Policy, UserContext
        >>> from proxilion.contrib.google import ProxilionVertexHandler
        >>>
        >>> auth = Proxilion()
        >>>
        >>> @auth.policy("weather_api")
        ... class WeatherPolicy(Policy):
        ...     def can_execute(self, context):
        ...         return True
        >>>
        >>> handler = ProxilionVertexHandler(auth)
        >>>
        >>> def get_weather(location: str) -> dict:
        ...     return {"temp": 72, "condition": "sunny"}
        >>>
        >>> handler.register_tool(
        ...     name="get_weather",
        ...     declaration={
        ...         "name": "get_weather",
        ...         "description": "Get weather for a location",
        ...         "parameters": {
        ...             "type": "object",
        ...             "properties": {
        ...                 "location": {"type": "string", "description": "City name"}
        ...             },
        ...             "required": ["location"]
        ...         }
        ...     },
        ...     implementation=get_weather,
        ...     resource="weather_api",
        ... )
        >>>
        >>> # Get tools for Gemini model
        >>> tools = handler.to_gemini_tools()
        >>> model = GenerativeModel("gemini-1.5-pro", tools=tools)
    """

    def __init__(
        self,
        proxilion: Any,
        default_action: str = "execute",
        safe_errors: bool = True,
    ) -> None:
        """
        Initialize the Vertex AI handler.

        Args:
            proxilion: Proxilion instance for authorization.
            default_action: Default action for authorization checks.
            safe_errors: If True, return safe error messages to the model.
        """
        self.proxilion = proxilion
        self.default_action = default_action
        self.safe_errors = safe_errors

        self._tools: dict[str, RegisteredGeminiTool] = {}
        self._execution_history: list[GeminiToolResult] = []

    @property
    def tools(self) -> list[RegisteredGeminiTool]:
        """Get list of registered tools."""
        return list(self._tools.values())

    @property
    def tool_declarations(self) -> list[dict[str, Any]]:
        """Get list of tool declarations for Gemini."""
        return [t.declaration for t in self._tools.values()]

    @property
    def execution_history(self) -> list[GeminiToolResult]:
        """Get history of tool executions."""
        return list(self._execution_history)

    def register_tool(
        self,
        name: str,
        declaration: dict[str, Any],
        implementation: Callable[..., Any],
        resource: str | None = None,
        action: str | None = None,
        description: str | None = None,
    ) -> None:
        """
        Register a tool for Gemini function calling.

        Args:
            name: Tool name (must match function call name from Gemini).
            declaration: Gemini function declaration dict.
            implementation: Python function to execute.
            resource: Resource name for authorization (default: tool name).
            action: Action for authorization (default: handler default).
            description: Optional description override.

        Example:
            >>> handler.register_tool(
            ...     name="search_db",
            ...     declaration={
            ...         "name": "search_db",
            ...         "description": "Search the database",
            ...         "parameters": {
            ...             "type": "object",
            ...             "properties": {
            ...                 "query": {"type": "string"}
            ...             },
            ...             "required": ["query"]
            ...         }
            ...     },
            ...     implementation=search_database,
            ...     resource="database",
            ... )
        """
        is_async = inspect.iscoroutinefunction(implementation)

        self._tools[name] = RegisteredGeminiTool(
            name=name,
            declaration=declaration,
            implementation=implementation,
            resource=resource or name,
            action=action or self.default_action,
            async_impl=is_async,
            description=description or declaration.get("description", ""),
        )

        logger.debug(f"Registered Gemini tool: {name} (resource: {resource or name})")

    def register_tool_from_function(
        self,
        func: Callable[..., Any],
        name: str | None = None,
        resource: str | None = None,
        action: str | None = None,
    ) -> None:
        """
        Register a tool by inferring the declaration from a function.

        Uses type hints and docstring to build the function declaration.

        Args:
            func: Python function to register.
            name: Optional name override (defaults to function name).
            resource: Resource for authorization.
            action: Action for authorization.

        Example:
            >>> def get_user(user_id: str) -> dict:
            ...     '''Get user by ID.'''
            ...     return {"id": user_id, "name": "John"}
            >>>
            >>> handler.register_tool_from_function(
            ...     get_user,
            ...     resource="users",
            ... )
        """
        tool_name = name or func.__name__

        # Infer description from docstring
        description = ""
        if func.__doc__:
            description = func.__doc__.strip().split("\n")[0]

        # Build parameters schema from type hints
        parameters = self._infer_parameters_from_function(func)

        declaration = {
            "name": tool_name,
            "description": description or f"Execute {tool_name}",
            "parameters": parameters,
        }

        self.register_tool(
            name=tool_name,
            declaration=declaration,
            implementation=func,
            resource=resource,
            action=action,
        )

    def _infer_parameters_from_function(self, func: Callable[..., Any]) -> dict[str, Any]:
        """Infer parameters schema from function signature."""
        from typing import get_type_hints

        sig = inspect.signature(func)
        hints = {}
        try:
            # Use get_type_hints to resolve forward references and string annotations
            all_hints = get_type_hints(func)
            hints = {k: v for k, v in all_hints.items() if k != "return"}
        except Exception:
            # Fall back to raw annotations
            with contextlib.suppress(AttributeError):
                hints = {k: v for k, v in func.__annotations__.items() if k != "return"}

        properties: dict[str, Any] = {}
        required: list[str] = []

        for param_name, param in sig.parameters.items():
            if param_name in ("self", "cls"):
                continue
            if param.kind in (
                inspect.Parameter.VAR_POSITIONAL,
                inspect.Parameter.VAR_KEYWORD,
            ):
                continue

            # Get type hint
            type_hint = hints.get(param_name, Any)

            # Convert to JSON Schema type
            prop_schema = self._type_to_schema(type_hint)
            properties[param_name] = prop_schema

            # Check if required
            if param.default is inspect.Parameter.empty:
                required.append(param_name)

        schema: dict[str, Any] = {
            "type": "object",
            "properties": properties,
        }
        if required:
            schema["required"] = required

        return schema

    def _type_to_schema(self, type_hint: Any) -> dict[str, Any]:
        """Convert Python type hint to JSON Schema."""
        if type_hint is str:
            return {"type": "string"}
        if type_hint is int:
            return {"type": "integer"}
        if type_hint is float:
            return {"type": "number"}
        if type_hint is bool:
            return {"type": "boolean"}
        if type_hint is list or (hasattr(type_hint, "__origin__") and type_hint.__origin__ is list):
            return {"type": "array"}
        if type_hint is dict or (hasattr(type_hint, "__origin__") and type_hint.__origin__ is dict):
            return {"type": "object"}
        # Default to string for unknown types
        return {"type": "string"}

    def unregister_tool(self, name: str) -> bool:
        """
        Unregister a tool.

        Args:
            name: Tool name to unregister.

        Returns:
            True if tool was registered and removed.
        """
        if name in self._tools:
            del self._tools[name]
            return True
        return False

    def get_tool(self, name: str) -> RegisteredGeminiTool | None:
        """Get a registered tool by name."""
        return self._tools.get(name)

    def extract_function_calls(self, response: Any) -> list[GeminiFunctionCall]:
        """
        Extract function calls from a Gemini response.

        Parses the response to find all function_call parts.

        Args:
            response: Gemini GenerateContentResponse object.

        Returns:
            List of GeminiFunctionCall objects.

        Example:
            >>> response = model.generate_content("What's the weather?")
            >>> calls = handler.extract_function_calls(response)
            >>> for call in calls:
            ...     print(f"{call.name}: {call.args}")
        """
        calls: list[GeminiFunctionCall] = []

        # Handle dictionary response
        if isinstance(response, dict):
            return self._extract_from_dict(response)

        # Handle object response
        candidates = getattr(response, "candidates", None)
        if not candidates:
            return calls

        for candidate in candidates:
            content = getattr(candidate, "content", None)
            if not content:
                continue

            parts = getattr(content, "parts", None)
            if not parts:
                continue

            for part in parts:
                function_call = getattr(part, "function_call", None)
                if function_call:
                    # Handle protobuf-style args
                    args = {}
                    raw_args = getattr(function_call, "args", None)
                    if raw_args:
                        # Convert protobuf Struct to dict if needed
                        if hasattr(raw_args, "items"):
                            args = dict(raw_args.items())
                        elif hasattr(raw_args, "__iter__"):
                            args = dict(raw_args)
                        else:
                            try:
                                # Try to iterate as Struct
                                args = {
                                    k: self._convert_protobuf_value(v)
                                    for k, v in raw_args.items()
                                }
                            except (TypeError, AttributeError):
                                args = {}

                    calls.append(GeminiFunctionCall(
                        name=function_call.name,
                        args=args,
                        raw=function_call,
                    ))

        return calls

    def _extract_from_dict(self, response: dict) -> list[GeminiFunctionCall]:
        """Extract function calls from dictionary response."""
        calls: list[GeminiFunctionCall] = []
        candidates = response.get("candidates", [])

        for candidate in candidates:
            content = candidate.get("content", {})
            parts = content.get("parts", [])

            for part in parts:
                # Handle both camelCase and snake_case
                fc = part.get("functionCall") or part.get("function_call")
                if fc:
                    calls.append(GeminiFunctionCall(
                        name=fc.get("name", ""),
                        args=fc.get("args", {}),
                        raw=fc,
                    ))

        return calls

    def _convert_protobuf_value(self, value: Any) -> Any:
        """Convert protobuf Value to Python native type."""
        if hasattr(value, "string_value"):
            return value.string_value
        if hasattr(value, "number_value"):
            return value.number_value
        if hasattr(value, "bool_value"):
            return value.bool_value
        if hasattr(value, "struct_value"):
            return {
                k: self._convert_protobuf_value(v)
                for k, v in value.struct_value.fields.items()
            }
        if hasattr(value, "list_value"):
            return [self._convert_protobuf_value(v) for v in value.list_value.values]
        return value

    def execute(
        self,
        function_call: GeminiFunctionCall,
        user: UserContext | None = None,
        agent: AgentContext | None = None,
    ) -> GeminiToolResult:
        """
        Execute a function call with authorization.

        Args:
            function_call: The function call to execute.
            user: User context for authorization.
            agent: Optional agent context.

        Returns:
            GeminiToolResult with execution result or error.

        Example:
            >>> calls = handler.extract_function_calls(response)
            >>> for call in calls:
            ...     result = handler.execute(call, user=current_user)
            ...     if result.authorized:
            ...         print(f"Result: {result.result}")
            ...     else:
            ...         print("Unauthorized")
        """
        tool_name = function_call.name

        # Get registered tool
        tool = self._tools.get(tool_name)
        if tool is None:
            result = GeminiToolResult(
                name=tool_name,
                success=False,
                error=f"Tool not found: {tool_name}",
            )
            self._execution_history.append(result)
            return result

        # Check authorization
        if user is not None:
            context = {
                "tool_name": tool_name,
                "args": function_call.args,
                **function_call.args,
            }

            auth_result = self.proxilion.check(
                user, tool.action, tool.resource, context
            )

            if not auth_result.allowed:
                result = GeminiToolResult(
                    name=tool_name,
                    success=False,
                    error="Not authorized" if self.safe_errors else auth_result.reason,
                    authorized=False,
                )
                self._execution_history.append(result)
                return result

        # Execute tool
        try:
            if tool.async_impl:
                loop = asyncio.new_event_loop()
                try:
                    output = loop.run_until_complete(
                        tool.implementation(**function_call.args)
                    )
                finally:
                    loop.close()
            else:
                output = tool.implementation(**function_call.args)

            result = GeminiToolResult(
                name=tool_name,
                success=True,
                result=output,
            )

        except Exception as e:
            logger.error(f"Tool execution error: {tool_name} - {e}")

            error_msg = "Tool execution failed"
            if not self.safe_errors:
                error_msg = str(e)

            result = GeminiToolResult(
                name=tool_name,
                success=False,
                error=error_msg,
            )

        self._execution_history.append(result)
        return result

    async def execute_async(
        self,
        function_call: GeminiFunctionCall,
        user: UserContext | None = None,
        agent: AgentContext | None = None,
    ) -> GeminiToolResult:
        """
        Execute a function call asynchronously with authorization.

        Args:
            function_call: The function call to execute.
            user: User context for authorization.
            agent: Optional agent context.

        Returns:
            GeminiToolResult with execution result or error.
        """
        tool_name = function_call.name

        tool = self._tools.get(tool_name)
        if tool is None:
            result = GeminiToolResult(
                name=tool_name,
                success=False,
                error=f"Tool not found: {tool_name}",
            )
            self._execution_history.append(result)
            return result

        # Check authorization
        if user is not None:
            context = {
                "tool_name": tool_name,
                "args": function_call.args,
                **function_call.args,
            }

            auth_result = self.proxilion.check(
                user, tool.action, tool.resource, context
            )

            if not auth_result.allowed:
                result = GeminiToolResult(
                    name=tool_name,
                    success=False,
                    error="Not authorized" if self.safe_errors else auth_result.reason,
                    authorized=False,
                )
                self._execution_history.append(result)
                return result

        # Execute tool
        try:
            if tool.async_impl:
                output = await tool.implementation(**function_call.args)
            else:
                loop = asyncio.get_event_loop()
                output = await loop.run_in_executor(
                    None,
                    lambda: tool.implementation(**function_call.args),
                )

            result = GeminiToolResult(
                name=tool_name,
                success=True,
                result=output,
            )

        except Exception as e:
            logger.error(f"Tool execution error: {tool_name} - {e}")

            error_msg = "Tool execution failed"
            if not self.safe_errors:
                error_msg = str(e)

            result = GeminiToolResult(
                name=tool_name,
                success=False,
                error=error_msg,
            )

        self._execution_history.append(result)
        return result

    def process_response(
        self,
        response: Any,
        user: UserContext | None = None,
        agent: AgentContext | None = None,
    ) -> list[GeminiToolResult]:
        """
        Process all function calls in a Gemini response.

        Extracts and executes all function calls with authorization.

        Args:
            response: Gemini GenerateContentResponse.
            user: User context for authorization.
            agent: Optional agent context.

        Returns:
            List of GeminiToolResult for each function call.

        Example:
            >>> response = model.generate_content("Search for products")
            >>> results = handler.process_response(response, user=current_user)
            >>> for result in results:
            ...     if result.success:
            ...         print(f"{result.name}: {result.result}")
        """
        calls = self.extract_function_calls(response)
        return [self.execute(call, user=user, agent=agent) for call in calls]

    async def process_response_async(
        self,
        response: Any,
        user: UserContext | None = None,
        agent: AgentContext | None = None,
    ) -> list[GeminiToolResult]:
        """
        Process all function calls asynchronously.

        Args:
            response: Gemini GenerateContentResponse.
            user: User context for authorization.
            agent: Optional agent context.

        Returns:
            List of GeminiToolResult for each function call.
        """
        calls = self.extract_function_calls(response)
        results = []
        for call in calls:
            result = await self.execute_async(call, user=user, agent=agent)
            results.append(result)
        return results

    def to_gemini_tools(self) -> list[Any]:
        """
        Get tool declarations in Gemini format.

        Returns tools suitable for GenerativeModel(tools=...).

        Returns:
            List containing a Tool object (if vertexai is available)
            or a list of raw declarations.

        Example:
            >>> tools = handler.to_gemini_tools()
            >>> model = GenerativeModel("gemini-1.5-pro", tools=tools)
        """
        try:
            from vertexai.generative_models import FunctionDeclaration, Tool

            declarations = [
                FunctionDeclaration(**tool.declaration)
                for tool in self._tools.values()
            ]
            return [Tool(function_declarations=declarations)]
        except ImportError:
            # Return raw dicts if vertexai not installed
            logger.debug("vertexai not installed, returning raw declarations")
            return [{"function_declarations": self.tool_declarations}]

    def to_gemini_tool_config(
        self,
        mode: str = "AUTO",
        allowed_functions: list[str] | None = None,
    ) -> Any:
        """
        Create a ToolConfig for Gemini.

        Args:
            mode: Function calling mode - "AUTO", "ANY", or "NONE".
            allowed_functions: List of function names to allow (for "ANY" mode).

        Returns:
            ToolConfig object or dict.
        """
        try:
            from vertexai.generative_models import ToolConfig

            if allowed_functions:
                return ToolConfig(
                    function_calling_config=ToolConfig.FunctionCallingConfig(
                        mode=ToolConfig.FunctionCallingConfig.Mode[mode],
                        allowed_function_names=allowed_functions,
                    )
                )
            else:
                return ToolConfig(
                    function_calling_config=ToolConfig.FunctionCallingConfig(
                        mode=ToolConfig.FunctionCallingConfig.Mode[mode],
                    )
                )
        except ImportError:
            # Return raw dict if vertexai not installed
            config: dict[str, Any] = {
                "function_calling_config": {
                    "mode": mode,
                }
            }
            if allowed_functions:
                config["function_calling_config"]["allowed_function_names"] = allowed_functions
            return config

    def format_tool_response(
        self,
        results: list[GeminiToolResult],
    ) -> list[dict[str, Any]]:
        """
        Format tool results for sending back to Gemini.

        Creates function_response parts for the model.

        Args:
            results: List of GeminiToolResult objects.

        Returns:
            List of function_response dictionaries.

        Example:
            >>> results = handler.process_response(response, user=user)
            >>> tool_responses = handler.format_tool_response(results)
            >>> # Continue conversation
            >>> next_response = chat.send_message(tool_responses)
        """
        return [
            {
                "function_response": r.to_function_response()
            }
            for r in results
        ]

    def create_response_parts(
        self,
        results: list[GeminiToolResult],
    ) -> list[Any]:
        """
        Create Vertex AI Part objects for function responses.

        Requires vertexai library.

        Args:
            results: List of GeminiToolResult objects.

        Returns:
            List of Part objects.

        Raises:
            ImportError: If vertexai is not installed.
        """
        try:
            from vertexai.generative_models import Part
        except ImportError:
            raise ImportError(
                "vertexai library required. Install with: pip install google-cloud-aiplatform"
            ) from None

        parts = []
        for result in results:
            response_data = result.to_function_response()
            parts.append(
                Part.from_function_response(
                    name=response_data["name"],
                    response=response_data["response"],
                )
            )
        return parts

    def clear_history(self) -> None:
        """Clear the execution history."""
        self._execution_history.clear()


def extract_function_calls(response: Any) -> list[GeminiFunctionCall]:
    """
    Extract function calls from a Gemini response.

    Standalone function for quick extraction without handler.

    Args:
        response: Gemini GenerateContentResponse.

    Returns:
        List of GeminiFunctionCall objects.

    Example:
        >>> from proxilion.contrib.google import extract_function_calls
        >>> calls = extract_function_calls(response)
        >>> for call in calls:
        ...     print(f"{call.name}: {call.args}")
    """
    handler = ProxilionVertexHandler(None)  # type: ignore
    return handler.extract_function_calls(response)


def format_tool_response(results: list[GeminiToolResult]) -> list[dict[str, Any]]:
    """
    Format tool results for Gemini.

    Standalone function for formatting results.

    Args:
        results: List of GeminiToolResult objects.

    Returns:
        List of function_response dictionaries.

    Example:
        >>> from proxilion.contrib.google import format_tool_response
        >>> responses = format_tool_response(results)
        >>> next_response = chat.send_message(responses)
    """
    return [
        {
            "function_response": r.to_function_response()
        }
        for r in results
    ]


def to_gemini_tools(declarations: list[dict[str, Any]]) -> list[Any]:
    """
    Convert function declarations to Gemini Tool format.

    Args:
        declarations: List of function declaration dicts.

    Returns:
        List containing a Tool object or raw format.

    Example:
        >>> declarations = [
        ...     {"name": "search", "description": "Search", "parameters": {...}}
        ... ]
        >>> tools = to_gemini_tools(declarations)
        >>> model = GenerativeModel("gemini-1.5-pro", tools=tools)
    """
    try:
        from vertexai.generative_models import FunctionDeclaration, Tool

        func_declarations = [FunctionDeclaration(**d) for d in declarations]
        return [Tool(function_declarations=func_declarations)]
    except ImportError:
        return [{"function_declarations": declarations}]
