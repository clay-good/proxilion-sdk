"""
OpenAI integration for Proxilion.

This module provides authorization wrappers for OpenAI function calling,
enabling secure function execution with user-context authorization.

Features:
    - ProxilionFunctionHandler: Manages function registration and execution
    - create_secure_function: Wraps individual functions with authorization
    - Safe error handling (no internal details exposed)

Note:
    OpenAI SDK is an optional dependency. This module works by wrapping
    function definitions and implementations rather than modifying the
    OpenAI client directly.

Example:
    >>> from openai import OpenAI
    >>> from proxilion import Proxilion
    >>> from proxilion.contrib.openai import ProxilionFunctionHandler
    >>>
    >>> auth = Proxilion()
    >>> handler = ProxilionFunctionHandler(auth)
    >>>
    >>> # Register a function
    >>> handler.register_function(
    ...     name="get_weather",
    ...     schema=weather_schema,
    ...     implementation=get_weather_impl,
    ...     resource="weather_api",
    ... )
    >>>
    >>> # Process function call from OpenAI response
    >>> if response.choices[0].message.function_call:
    ...     result = handler.execute(
    ...         function_call=response.choices[0].message.function_call,
    ...         user=current_user,
    ...     )
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, TypeVar

from proxilion.exceptions import (
    AuthorizationError,
    ProxilionError,
)
from proxilion.types import AgentContext, UserContext

logger = logging.getLogger(__name__)

T = TypeVar("T")


class OpenAIIntegrationError(ProxilionError):
    """Error in OpenAI integration."""
    pass


class FunctionNotFoundError(OpenAIIntegrationError):
    """Raised when a function is not registered."""

    def __init__(self, function_name: str) -> None:
        self.function_name = function_name
        super().__init__(f"Function not registered: {function_name}")


class FunctionExecutionError(OpenAIIntegrationError):
    """Raised when function execution fails."""

    def __init__(self, function_name: str, safe_message: str) -> None:
        self.function_name = function_name
        self.safe_message = safe_message
        super().__init__(f"Function execution failed: {safe_message}")


@dataclass
class RegisteredFunction:
    """A registered function with its schema and implementation."""
    name: str
    schema: dict[str, Any]
    implementation: Callable[..., Any]
    resource: str
    action: str
    async_impl: bool
    description: str


@dataclass
class FunctionCallResult:
    """Result of a function call execution."""
    function_name: str
    success: bool
    result: Any | None = None
    error: str | None = None
    authorized: bool = True
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class ProxilionFunctionHandler:
    """
    Handler for OpenAI function calls with Proxilion authorization.

    Manages function registration, schema validation, authorization,
    and execution for OpenAI's function calling feature.

    Example:
        >>> from proxilion import Proxilion, Policy, UserContext
        >>> from proxilion.contrib.openai import ProxilionFunctionHandler
        >>>
        >>> auth = Proxilion()
        >>>
        >>> @auth.policy("weather_api")
        ... class WeatherPolicy(Policy):
        ...     def can_execute(self, context):
        ...         return "weather_user" in self.user.roles
        >>>
        >>> handler = ProxilionFunctionHandler(auth)
        >>>
        >>> def get_weather(location: str, unit: str = "celsius") -> str:
        ...     return f"Weather in {location}: 20{unit[0].upper()}"
        >>>
        >>> handler.register_function(
        ...     name="get_weather",
        ...     schema={
        ...         "name": "get_weather",
        ...         "description": "Get weather for a location",
        ...         "parameters": {
        ...             "type": "object",
        ...             "properties": {
        ...                 "location": {"type": "string"},
        ...                 "unit": {"type": "string", "enum": ["celsius", "fahrenheit"]}
        ...             },
        ...             "required": ["location"]
        ...         }
        ...     },
        ...     implementation=get_weather,
        ...     resource="weather_api",
        ... )
        >>>
        >>> # Execute function call
        >>> user = UserContext(user_id="alice", roles=["weather_user"])
        >>> result = handler.execute(
        ...     function_name="get_weather",
        ...     arguments={"location": "London"},
        ...     user=user,
        ... )
    """

    def __init__(
        self,
        proxilion: Any,
        default_action: str = "execute",
        safe_errors: bool = True,
    ) -> None:
        """
        Initialize the function handler.

        Args:
            proxilion: Proxilion instance for authorization.
            default_action: Default action for authorization checks.
            safe_errors: If True, return safe error messages without internals.
        """
        self.proxilion = proxilion
        self.default_action = default_action
        self.safe_errors = safe_errors

        self._functions: dict[str, RegisteredFunction] = {}
        self._call_history: list[FunctionCallResult] = []

    @property
    def functions(self) -> list[RegisteredFunction]:
        """Get list of registered functions."""
        return list(self._functions.values())

    @property
    def function_schemas(self) -> list[dict[str, Any]]:
        """Get list of function schemas for OpenAI API."""
        return [f.schema for f in self._functions.values()]

    @property
    def call_history(self) -> list[FunctionCallResult]:
        """Get history of function calls."""
        return list(self._call_history)

    def register_function(
        self,
        name: str,
        schema: dict[str, Any],
        implementation: Callable[..., Any],
        resource: str | None = None,
        action: str | None = None,
        description: str | None = None,
    ) -> None:
        """
        Register a function for execution.

        Args:
            name: Function name (must match OpenAI function call).
            schema: OpenAI function schema.
            implementation: Python function to execute.
            resource: Resource name for authorization (default: function name).
            action: Action for authorization (default: handler default).
            description: Optional description override.
        """
        is_async = inspect.iscoroutinefunction(implementation)

        self._functions[name] = RegisteredFunction(
            name=name,
            schema=schema,
            implementation=implementation,
            resource=resource or name,
            action=action or self.default_action,
            async_impl=is_async,
            description=description or schema.get("description", ""),
        )

        logger.debug(f"Registered function: {name} (resource: {resource or name})")

    def unregister_function(self, name: str) -> bool:
        """
        Unregister a function.

        Args:
            name: Function name to unregister.

        Returns:
            True if function was registered and removed.
        """
        if name in self._functions:
            del self._functions[name]
            return True
        return False

    def get_function(self, name: str) -> RegisteredFunction | None:
        """Get a registered function by name."""
        return self._functions.get(name)

    def execute(
        self,
        function_name: str | None = None,
        arguments: dict[str, Any] | str | None = None,
        user: UserContext | None = None,
        agent: AgentContext | None = None,
        function_call: Any | None = None,
    ) -> FunctionCallResult:
        """
        Execute a function call with authorization.

        Can accept either explicit function_name/arguments or an OpenAI
        function_call object.

        Args:
            function_name: Name of the function to call.
            arguments: Function arguments (dict or JSON string).
            user: User context for authorization.
            agent: Optional agent context.
            function_call: OpenAI function_call object (alternative).

        Returns:
            FunctionCallResult with execution result or error.
        """
        # Extract from function_call object if provided
        if function_call is not None:
            function_name = getattr(function_call, "name", None)
            raw_args = getattr(function_call, "arguments", "{}")
            if isinstance(raw_args, str):
                try:
                    arguments = json.loads(raw_args)
                except json.JSONDecodeError:
                    arguments = {}
            else:
                arguments = raw_args or {}

        if function_name is None:
            return FunctionCallResult(
                function_name="unknown",
                success=False,
                error="No function name provided",
            )

        # Parse arguments if string
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments)
            except json.JSONDecodeError:
                return FunctionCallResult(
                    function_name=function_name,
                    success=False,
                    error="Invalid JSON arguments",
                )

        arguments = arguments or {}

        # Get registered function
        func = self._functions.get(function_name)
        if func is None:
            result = FunctionCallResult(
                function_name=function_name,
                success=False,
                error=f"Function not found: {function_name}",
            )
            self._call_history.append(result)
            return result

        # Check authorization
        if user is not None:
            context = {
                "function_name": function_name,
                "arguments": arguments,
                **arguments,
            }

            auth_result = self.proxilion.check(user, func.action, func.resource, context)

            if not auth_result.allowed:
                result = FunctionCallResult(
                    function_name=function_name,
                    success=False,
                    error="Not authorized" if self.safe_errors else auth_result.reason,
                    authorized=False,
                )
                self._call_history.append(result)
                return result

        # Execute function
        try:
            if func.async_impl:
                # Run async function synchronously
                loop = asyncio.new_event_loop()
                try:
                    output = loop.run_until_complete(func.implementation(**arguments))
                finally:
                    loop.close()
            else:
                output = func.implementation(**arguments)

            result = FunctionCallResult(
                function_name=function_name,
                success=True,
                result=output,
            )

        except Exception as e:
            logger.error(f"Function execution error: {function_name} - {e}")

            error_msg = "Function execution failed"
            if not self.safe_errors:
                error_msg = str(e)

            result = FunctionCallResult(
                function_name=function_name,
                success=False,
                error=error_msg,
            )

        self._call_history.append(result)
        return result

    async def execute_async(
        self,
        function_name: str | None = None,
        arguments: dict[str, Any] | str | None = None,
        user: UserContext | None = None,
        agent: AgentContext | None = None,
        function_call: Any | None = None,
    ) -> FunctionCallResult:
        """
        Execute a function call asynchronously with authorization.

        Args:
            function_name: Name of the function to call.
            arguments: Function arguments.
            user: User context for authorization.
            agent: Optional agent context.
            function_call: OpenAI function_call object.

        Returns:
            FunctionCallResult with execution result or error.
        """
        # Extract from function_call object if provided
        if function_call is not None:
            function_name = getattr(function_call, "name", None)
            raw_args = getattr(function_call, "arguments", "{}")
            if isinstance(raw_args, str):
                try:
                    arguments = json.loads(raw_args)
                except json.JSONDecodeError:
                    arguments = {}
            else:
                arguments = raw_args or {}

        if function_name is None:
            return FunctionCallResult(
                function_name="unknown",
                success=False,
                error="No function name provided",
            )

        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments)
            except json.JSONDecodeError:
                return FunctionCallResult(
                    function_name=function_name,
                    success=False,
                    error="Invalid JSON arguments",
                )

        arguments = arguments or {}

        func = self._functions.get(function_name)
        if func is None:
            result = FunctionCallResult(
                function_name=function_name,
                success=False,
                error=f"Function not found: {function_name}",
            )
            self._call_history.append(result)
            return result

        # Check authorization
        if user is not None:
            context = {
                "function_name": function_name,
                "arguments": arguments,
                **arguments,
            }

            auth_result = self.proxilion.check(user, func.action, func.resource, context)

            if not auth_result.allowed:
                result = FunctionCallResult(
                    function_name=function_name,
                    success=False,
                    error="Not authorized" if self.safe_errors else auth_result.reason,
                    authorized=False,
                )
                self._call_history.append(result)
                return result

        # Execute function
        try:
            if func.async_impl:
                output = await func.implementation(**arguments)
            else:
                loop = asyncio.get_event_loop()
                output = await loop.run_in_executor(
                    None,
                    lambda: func.implementation(**arguments),
                )

            result = FunctionCallResult(
                function_name=function_name,
                success=True,
                result=output,
            )

        except Exception as e:
            logger.error(f"Function execution error: {function_name} - {e}")

            error_msg = "Function execution failed"
            if not self.safe_errors:
                error_msg = str(e)

            result = FunctionCallResult(
                function_name=function_name,
                success=False,
                error=error_msg,
            )

        self._call_history.append(result)
        return result

    def to_openai_tools(self) -> list[dict[str, Any]]:
        """
        Get function schemas in OpenAI tools format.

        Returns:
            List of tool definitions for OpenAI API.
        """
        return [
            {"type": "function", "function": func.schema}
            for func in self._functions.values()
        ]


def create_secure_function(
    function_def: dict[str, Any],
    implementation: Callable[..., Any],
    proxilion: Any,
    resource: str,
    action: str = "execute",
    safe_errors: bool = True,
) -> tuple[dict[str, Any], Callable[..., Any]]:
    """
    Create a secured function wrapper for OpenAI function calling.

    Returns both the function definition and a wrapped implementation
    that includes authorization checks.

    Args:
        function_def: OpenAI function definition schema.
        implementation: The actual function implementation.
        proxilion: Proxilion instance for authorization.
        resource: Resource name for authorization.
        action: Action for authorization checks.
        safe_errors: If True, return safe error messages.

    Returns:
        Tuple of (function_def, wrapped_implementation).

    Example:
        >>> schema = {
        ...     "name": "get_weather",
        ...     "description": "Get weather",
        ...     "parameters": {...}
        ... }
        >>>
        >>> def get_weather_impl(location: str) -> str:
        ...     return f"Weather in {location}: sunny"
        >>>
        >>> schema, secure_impl = create_secure_function(
        ...     function_def=schema,
        ...     implementation=get_weather_impl,
        ...     proxilion=auth,
        ...     resource="weather_api",
        ... )
    """
    is_async = inspect.iscoroutinefunction(implementation)

    if is_async:
        async def async_wrapper(
            user: UserContext | None = None,
            **kwargs: Any,
        ) -> Any:
            if user is not None:
                context = {"function_name": function_def.get("name", resource), **kwargs}
                result = proxilion.check(user, action, resource, context)

                if not result.allowed:
                    if safe_errors:
                        raise AuthorizationError(
                            user=user.user_id,
                            action=action,
                            resource=resource,
                            reason="Not authorized",
                        )
                    raise AuthorizationError(
                        user=user.user_id,
                        action=action,
                        resource=resource,
                        reason=result.reason,
                    )

            return await implementation(**kwargs)

        return function_def, async_wrapper
    else:
        def sync_wrapper(
            user: UserContext | None = None,
            **kwargs: Any,
        ) -> Any:
            if user is not None:
                context = {"function_name": function_def.get("name", resource), **kwargs}
                result = proxilion.check(user, action, resource, context)

                if not result.allowed:
                    if safe_errors:
                        raise AuthorizationError(
                            user=user.user_id,
                            action=action,
                            resource=resource,
                            reason="Not authorized",
                        )
                    raise AuthorizationError(
                        user=user.user_id,
                        action=action,
                        resource=resource,
                        reason=result.reason,
                    )

            return implementation(**kwargs)

        return function_def, sync_wrapper


def process_openai_response(
    response: Any,
    handler: ProxilionFunctionHandler,
    user: UserContext | None = None,
) -> list[FunctionCallResult]:
    """
    Process an OpenAI response and execute any function calls.

    Handles both single function calls and tool_calls format.

    Args:
        response: OpenAI API response object.
        handler: ProxilionFunctionHandler for execution.
        user: User context for authorization.

    Returns:
        List of FunctionCallResult for each function call.
    """
    results: list[FunctionCallResult] = []

    # Handle choices
    if hasattr(response, "choices"):
        for choice in response.choices:
            message = getattr(choice, "message", None)
            if message is None:
                continue

            # Handle function_call format (deprecated but still used)
            function_call = getattr(message, "function_call", None)
            if function_call is not None:
                result = handler.execute(
                    function_call=function_call,
                    user=user,
                )
                results.append(result)

            # Handle tool_calls format (newer)
            tool_calls = getattr(message, "tool_calls", None)
            if tool_calls:
                for tool_call in tool_calls:
                    if getattr(tool_call, "type", None) == "function":
                        func = getattr(tool_call, "function", None)
                        if func:
                            result = handler.execute(
                                function_name=getattr(func, "name", None),
                                arguments=getattr(func, "arguments", "{}"),
                                user=user,
                            )
                            results.append(result)

    return results
