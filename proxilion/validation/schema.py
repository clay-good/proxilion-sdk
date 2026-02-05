"""
Schema validation system for Proxilion.

This module provides dataclass-based schema definitions and validation
for tool call arguments. It validates types, required fields, constraints,
and includes security-focused validations like path traversal detection.
"""

from __future__ import annotations

import logging
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Literal

from proxilion.exceptions import SchemaValidationError

logger = logging.getLogger(__name__)

# Type alias for risk levels
RiskLevel = Literal["low", "medium", "high", "critical"]


@dataclass
class ParameterSchema:
    """
    Schema definition for a single tool parameter.

    Defines the expected type, constraints, and metadata for a parameter.

    Attributes:
        name: Parameter name.
        type: Python type name ("str", "int", "float", "bool", "list", "dict").
        description: Human-readable description.
        constraints: Validation constraints (min, max, pattern, enum, etc.).
        sensitive: Whether this parameter contains sensitive data (for redaction).
        default: Default value if not provided.
        required: Whether the parameter is required (can also be set at ToolSchema level).

    Constraint Options:
        - min: Minimum value (for numbers) or length (for strings/lists).
        - max: Maximum value (for numbers) or length (for strings/lists).
        - pattern: Regex pattern for string validation.
        - enum: List of allowed values.
        - min_length: Minimum string/list length.
        - max_length: Maximum string/list length.
        - allow_path_traversal: If False, reject ".." in paths (default: False).
        - allow_sql_keywords: If False, reject SQL injection patterns (default: True).

    Example:
        >>> param = ParameterSchema(
        ...     name="query",
        ...     type="str",
        ...     description="SQL query to execute",
        ...     constraints={"max_length": 1000, "allow_sql_keywords": False},
        ...     sensitive=True,
        ... )
    """
    name: str
    type: str = "str"
    description: str = ""
    constraints: dict[str, Any] = field(default_factory=dict)
    sensitive: bool = False
    default: Any = None
    required: bool = True

    def __post_init__(self) -> None:
        """Validate the parameter schema itself."""
        valid_types = {"str", "int", "float", "bool", "list", "dict", "any"}
        if self.type not in valid_types:
            logger.warning(
                f"Unknown type '{self.type}' for parameter '{self.name}'. "
                f"Valid types: {valid_types}"
            )


@dataclass
class ToolSchema:
    """
    Schema definition for a tool.

    Defines all parameters, their types, and validation rules for a tool.
    Used to validate tool call arguments before execution.

    Attributes:
        name: Tool name (should match the tool function name).
        description: Human-readable tool description.
        parameters: Dictionary mapping parameter names to ParameterSchema.
        required_parameters: List of required parameter names.
        risk_level: Risk level for audit and approval decisions.
        tags: Optional tags for categorization.
        version: Schema version for compatibility tracking.

    Example:
        >>> schema = ToolSchema(
        ...     name="file_read",
        ...     description="Read contents of a file",
        ...     parameters={
        ...         "path": ParameterSchema(
        ...             name="path",
        ...             type="str",
        ...             constraints={"allow_path_traversal": False},
        ...         ),
        ...         "encoding": ParameterSchema(
        ...             name="encoding",
        ...             type="str",
        ...             default="utf-8",
        ...             required=False,
        ...         ),
        ...     },
        ...     required_parameters=["path"],
        ...     risk_level="medium",
        ... )
    """
    name: str
    description: str = ""
    parameters: dict[str, ParameterSchema] = field(default_factory=dict)
    required_parameters: list[str] = field(default_factory=list)
    risk_level: RiskLevel = "low"
    tags: list[str] = field(default_factory=list)
    version: str = "1.0"

    def get_sensitive_parameters(self) -> list[str]:
        """Get names of parameters marked as sensitive."""
        return [
            name for name, param in self.parameters.items()
            if param.sensitive
        ]

    def get_parameter(self, name: str) -> ParameterSchema | None:
        """Get a parameter schema by name."""
        return self.parameters.get(name)


@dataclass
class ValidationResult:
    """
    Result of schema validation.

    Attributes:
        valid: Whether validation passed.
        errors: List of validation error messages.
        warnings: List of validation warnings.
        sanitized_arguments: Arguments after sanitization (if applicable).
    """
    valid: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    sanitized_arguments: dict[str, Any] | None = None

    @classmethod
    def success(
        cls,
        sanitized: dict[str, Any] | None = None,
        warnings: list[str] | None = None,
    ) -> ValidationResult:
        """Create a successful validation result."""
        return cls(
            valid=True,
            sanitized_arguments=sanitized,
            warnings=warnings or [],
        )

    @classmethod
    def failure(cls, errors: list[str]) -> ValidationResult:
        """Create a failed validation result."""
        return cls(valid=False, errors=errors)

    def raise_if_invalid(self, tool_name: str) -> None:
        """Raise SchemaValidationError if validation failed."""
        if not self.valid:
            raise SchemaValidationError(
                tool_name=tool_name,
                validation_errors=self.errors,
            )


class SchemaValidator:
    """
    Validates tool call arguments against registered schemas.

    The SchemaValidator maintains a registry of tool schemas and
    validates arguments against them. It performs type checking,
    constraint validation, and security checks.

    Features:
        - Type validation (str, int, float, bool, list, dict)
        - Constraint validation (min, max, pattern, enum, etc.)
        - Security validations (path traversal, SQL injection)
        - Required field checking
        - Default value application
        - Thread-safe operations

    Example:
        >>> validator = SchemaValidator()
        >>> validator.register_schema("calculator", calculator_schema)
        >>> result = validator.validate("calculator", {
        ...     "operation": "add",
        ...     "a": 5,
        ...     "b": 3,
        ... })
        >>> if result.valid:
        ...     print("Validation passed!")
    """

    # SQL injection patterns to detect
    SQL_INJECTION_PATTERNS = [
        r"(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\b",
        r"(?i)\b(EXEC|EXECUTE|INTO|FROM|WHERE)\b.*[;'\"]",
        r"--",  # SQL comment
        r"/\*",  # Block comment start
        r";\s*(SELECT|INSERT|UPDATE|DELETE|DROP)",  # Chained statements
    ]

    def __init__(self, strict_mode: bool = False) -> None:
        """
        Initialize the schema validator.

        Args:
            strict_mode: If True, reject unknown parameters.
                If False, unknown parameters are allowed with a warning.
        """
        self._schemas: dict[str, ToolSchema] = {}
        self._lock = threading.RLock()
        self.strict_mode = strict_mode

        # Compile SQL injection patterns
        self._sql_patterns = [
            re.compile(pattern) for pattern in self.SQL_INJECTION_PATTERNS
        ]

    def register_schema(self, tool_name: str, schema: ToolSchema) -> None:
        """
        Register a schema for a tool.

        Args:
            tool_name: The tool name (should match function name).
            schema: The ToolSchema definition.

        Example:
            >>> validator.register_schema("my_tool", my_schema)
        """
        with self._lock:
            if tool_name in self._schemas:
                logger.warning(f"Overwriting schema for tool '{tool_name}'")
            self._schemas[tool_name] = schema
            logger.debug(f"Registered schema for tool '{tool_name}'")

    def unregister_schema(self, tool_name: str) -> bool:
        """
        Unregister a tool schema.

        Args:
            tool_name: The tool name to unregister.

        Returns:
            True if a schema was removed.
        """
        with self._lock:
            if tool_name in self._schemas:
                del self._schemas[tool_name]
                return True
            return False

    def get_schema(self, tool_name: str) -> ToolSchema | None:
        """Get the schema for a tool."""
        with self._lock:
            return self._schemas.get(tool_name)

    def has_schema(self, tool_name: str) -> bool:
        """Check if a schema is registered for a tool."""
        with self._lock:
            return tool_name in self._schemas

    def list_schemas(self) -> list[str]:
        """List all registered tool names."""
        with self._lock:
            return list(self._schemas.keys())

    def validate(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> ValidationResult:
        """
        Validate arguments against a tool's schema.

        Args:
            tool_name: The name of the tool.
            arguments: The arguments to validate.

        Returns:
            ValidationResult with validation status and any errors.

        Example:
            >>> result = validator.validate("calculator", {"op": "add", "a": 5})
            >>> if not result.valid:
            ...     print("Errors:", result.errors)
        """
        with self._lock:
            schema = self._schemas.get(tool_name)

        if schema is None:
            if self.strict_mode:
                return ValidationResult.failure(
                    [f"No schema registered for tool '{tool_name}'"]
                )
            # No schema = allow everything (with warning)
            logger.warning(f"No schema for tool '{tool_name}', skipping validation")
            return ValidationResult.success(
                sanitized=arguments,
                warnings=[f"No schema registered for tool '{tool_name}'"],
            )

        errors: list[str] = []
        warnings: list[str] = []
        sanitized = dict(arguments)

        # Check required parameters
        for param_name in schema.required_parameters:
            if param_name not in arguments:
                param_schema = schema.get_parameter(param_name)
                if param_schema and param_schema.default is not None:
                    sanitized[param_name] = param_schema.default
                else:
                    errors.append(f"Missing required parameter: '{param_name}'")

        # Validate each provided argument
        for arg_name, arg_value in arguments.items():
            param_schema = schema.get_parameter(arg_name)

            if param_schema is None:
                if self.strict_mode:
                    errors.append(f"Unknown parameter: '{arg_name}'")
                else:
                    warnings.append(f"Unknown parameter: '{arg_name}'")
                continue

            # Validate the parameter
            param_errors = self._validate_parameter(
                param_schema, arg_value, arg_name
            )
            errors.extend(param_errors)

        if errors:
            return ValidationResult.failure(errors)

        return ValidationResult.success(sanitized=sanitized, warnings=warnings)

    def _validate_parameter(
        self,
        schema: ParameterSchema,
        value: Any,
        name: str,
    ) -> list[str]:
        """
        Validate a single parameter value.

        Args:
            schema: The parameter schema.
            value: The value to validate.
            name: The parameter name (for error messages).

        Returns:
            List of error messages (empty if valid).
        """
        errors: list[str] = []

        # Type validation
        type_error = self._validate_type(schema.type, value, name)
        if type_error:
            errors.append(type_error)
            return errors  # Skip other validations if type is wrong

        # Constraint validation
        constraint_errors = self._validate_constraints(
            schema.constraints, value, name, schema.type
        )
        errors.extend(constraint_errors)

        return errors

    def _validate_type(
        self,
        expected_type: str,
        value: Any,
        name: str,
    ) -> str | None:
        """
        Validate value type.

        Returns error message if invalid, None if valid.
        """
        if expected_type == "any":
            return None

        type_map = {
            "str": str,
            "int": int,
            "float": (int, float),  # Allow int for float
            "bool": bool,
            "list": list,
            "dict": dict,
        }

        expected = type_map.get(expected_type)
        if expected is None:
            return None  # Unknown type, skip validation

        if not isinstance(value, expected):
            return (
                f"Parameter '{name}' expected type '{expected_type}', "
                f"got '{type(value).__name__}'"
            )

        return None

    def _validate_constraints(
        self,
        constraints: dict[str, Any],
        value: Any,
        name: str,
        value_type: str,
    ) -> list[str]:
        """
        Validate value against constraints.

        Returns list of error messages.
        """
        errors: list[str] = []

        # Numeric constraints
        if value_type in ("int", "float") and isinstance(value, (int, float)):
            if "min" in constraints and value < constraints["min"]:
                errors.append(
                    f"Parameter '{name}' value {value} is less than "
                    f"minimum {constraints['min']}"
                )
            if "max" in constraints and value > constraints["max"]:
                errors.append(
                    f"Parameter '{name}' value {value} is greater than "
                    f"maximum {constraints['max']}"
                )

        # String constraints
        if value_type == "str" and isinstance(value, str):
            # Length constraints
            if "min_length" in constraints and len(value) < constraints["min_length"]:
                errors.append(
                    f"Parameter '{name}' length {len(value)} is less than "
                    f"minimum {constraints['min_length']}"
                )
            if "max_length" in constraints and len(value) > constraints["max_length"]:
                errors.append(
                    f"Parameter '{name}' length {len(value)} exceeds "
                    f"maximum {constraints['max_length']}"
                )

            # Pattern constraint
            if "pattern" in constraints:
                pattern = constraints["pattern"]
                if not re.match(pattern, value):
                    errors.append(
                        f"Parameter '{name}' does not match pattern '{pattern}'"
                    )

            # Path traversal check (default: reject traversal sequences)
            if not constraints.get("allow_path_traversal", False):
                if self._check_path_traversal(value):
                    errors.append(
                        f"Parameter '{name}' contains path traversal sequence"
                    )

            # SQL injection check
            if not constraints.get("allow_sql_keywords", True):
                if self._check_sql_injection(value):
                    errors.append(
                        f"Parameter '{name}' contains potential SQL injection"
                    )

        # Enum constraint
        if "enum" in constraints and value not in constraints["enum"]:
            errors.append(
                f"Parameter '{name}' value '{value}' not in allowed values: "
                f"{constraints['enum']}"
            )

        # List constraints
        if value_type == "list" and isinstance(value, list):
            if "min_length" in constraints and len(value) < constraints["min_length"]:
                errors.append(
                    f"Parameter '{name}' has {len(value)} items, "
                    f"minimum is {constraints['min_length']}"
                )
            if "max_length" in constraints and len(value) > constraints["max_length"]:
                errors.append(
                    f"Parameter '{name}' has {len(value)} items, "
                    f"maximum is {constraints['max_length']}"
                )

        return errors

    def _check_path_traversal(self, value: str) -> bool:
        """
        Check for path traversal attempts.

        Detects patterns like "..", "..\\", encoded variants.

        Args:
            value: The string to check.

        Returns:
            True if path traversal detected.
        """
        # Direct check
        if ".." in value:
            return True

        # URL encoded
        if "%2e%2e" in value.lower():
            return True

        # Double URL encoded
        if "%252e%252e" in value.lower():
            return True

        # Unicode variants
        return ".." in value

    def _check_sql_injection(self, value: str) -> bool:
        """
        Check for SQL injection patterns.

        Args:
            value: The string to check.

        Returns:
            True if potential SQL injection detected.
        """
        return any(pattern.search(value) for pattern in self._sql_patterns)

    def validate_object_id(
        self,
        value: str,
        id_type: str = "uuid",
    ) -> bool:
        """
        Validate object ID format to prevent IDOR attacks.

        Args:
            value: The ID value to validate.
            id_type: Expected ID format ("uuid", "numeric", "alphanumeric").

        Returns:
            True if the ID format is valid.
        """
        if id_type == "uuid":
            # UUID format: 8-4-4-4-12 hex characters
            uuid_pattern = re.compile(
                r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                re.IGNORECASE,
            )
            return bool(uuid_pattern.match(value))

        elif id_type == "numeric":
            return value.isdigit()

        elif id_type == "alphanumeric":
            return value.isalnum()

        return True  # Unknown type, allow

    def create_schema_from_function(
        self,
        func: Any,
        risk_level: RiskLevel = "low",
    ) -> ToolSchema:
        """
        Create a ToolSchema from a function's type hints.

        This provides a convenient way to auto-generate schemas
        from function signatures.

        Args:
            func: The function to analyze.
            risk_level: Risk level for the schema.

        Returns:
            A ToolSchema derived from the function.

        Example:
            >>> def my_tool(query: str, limit: int = 10) -> dict:
            ...     pass
            >>> schema = validator.create_schema_from_function(my_tool)
        """
        import inspect

        sig = inspect.signature(func)
        hints = getattr(func, "__annotations__", {})

        parameters: dict[str, ParameterSchema] = {}
        required: list[str] = []

        for param_name, param in sig.parameters.items():
            if param_name in ("self", "cls", "user", "context"):
                continue  # Skip common non-argument parameters

            # Determine type
            type_hint = hints.get(param_name, Any)
            param_type = self._python_type_to_schema_type(type_hint)

            # Check if required
            has_default = param.default is not inspect.Parameter.empty
            default_value = param.default if has_default else None

            if not has_default:
                required.append(param_name)

            parameters[param_name] = ParameterSchema(
                name=param_name,
                type=param_type,
                description="",
                default=default_value,
                required=not has_default,
            )

        return ToolSchema(
            name=func.__name__,
            description=func.__doc__ or "",
            parameters=parameters,
            required_parameters=required,
            risk_level=risk_level,
        )

    def _python_type_to_schema_type(self, type_hint: Any) -> str:
        """Convert Python type hint to schema type string."""
        if type_hint is str:
            return "str"
        elif type_hint is int:
            return "int"
        elif type_hint is float:
            return "float"
        elif type_hint is bool:
            return "bool"
        elif type_hint is list:
            return "list"
        elif type_hint is dict:
            return "dict"
        else:
            return "any"
