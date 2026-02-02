"""
Pydantic-based schema validation for Proxilion.

This module provides optional Pydantic integration for richer
validation capabilities. It requires the pydantic package to be installed.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from proxilion.validation.schema import (
    ParameterSchema,
    RiskLevel,
    SchemaValidator,
    ToolSchema,
    ValidationResult,
)

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# Check if Pydantic is available
try:
    from pydantic import BaseModel, ValidationError, create_model
    from pydantic.fields import FieldInfo
    from pydantic_core import PydanticUndefined
    HAS_PYDANTIC = True
except ImportError:
    HAS_PYDANTIC = False
    BaseModel = None  # type: ignore
    ValidationError = None  # type: ignore


class PydanticSchemaValidator(SchemaValidator):
    """
    Schema validator using Pydantic for rich validation.

    This validator extends SchemaValidator to use Pydantic models
    for validation, providing:
    - Automatic type coercion
    - Rich validation error messages
    - JSON Schema generation
    - Nested model validation

    Requires: pip install proxilion[pydantic]

    Example:
        >>> from pydantic import BaseModel
        >>>
        >>> class CalculatorInput(BaseModel):
        ...     operation: str
        ...     a: float
        ...     b: float
        >>>
        >>> validator = PydanticSchemaValidator()
        >>> validator.register_pydantic_model("calculator", CalculatorInput)
        >>> result = validator.validate("calculator", {"operation": "add", "a": 5, "b": 3})
    """

    def __init__(self, strict_mode: bool = False) -> None:
        """
        Initialize the Pydantic schema validator.

        Args:
            strict_mode: If True, reject unknown parameters.

        Raises:
            ImportError: If pydantic is not installed.
        """
        if not HAS_PYDANTIC:
            raise ImportError(
                "Pydantic is not installed. Install with: pip install proxilion[pydantic]"
            )

        super().__init__(strict_mode)
        self._pydantic_models: dict[str, type[BaseModel]] = {}

    def register_pydantic_model(
        self,
        tool_name: str,
        model: type[BaseModel],
        risk_level: RiskLevel = "low",
        sensitive_fields: list[str] | None = None,
    ) -> None:
        """
        Register a Pydantic model as the schema for a tool.

        Args:
            tool_name: The tool name.
            model: The Pydantic model class.
            risk_level: Risk level for the tool.
            sensitive_fields: List of field names that contain sensitive data.

        Example:
            >>> class QueryInput(BaseModel):
            ...     query: str
            ...     limit: int = 100
            >>>
            >>> validator.register_pydantic_model("database_query", QueryInput)
        """
        self._pydantic_models[tool_name] = model

        # Also create a ToolSchema for compatibility
        schema = self._pydantic_model_to_tool_schema(
            model, tool_name, risk_level, sensitive_fields or []
        )
        self.register_schema(tool_name, schema)

        logger.debug(f"Registered Pydantic model for tool '{tool_name}'")

    def _pydantic_model_to_tool_schema(
        self,
        model: type[BaseModel],
        tool_name: str,
        risk_level: RiskLevel,
        sensitive_fields: list[str],
    ) -> ToolSchema:
        """Convert a Pydantic model to a ToolSchema."""
        parameters: dict[str, ParameterSchema] = {}
        required_params: list[str] = []

        # Get field information from the model
        for field_name, field_info in model.model_fields.items():
            # Determine type
            annotation = field_info.annotation
            param_type = self._annotation_to_type(annotation)

            # Check if required
            is_required = field_info.is_required()
            if is_required:
                required_params.append(field_name)

            # Get default value
            default = None
            if not is_required and field_info.default is not PydanticUndefined:
                default = field_info.default

            # Build constraints from Pydantic field info
            constraints = self._field_info_to_constraints(field_info)

            parameters[field_name] = ParameterSchema(
                name=field_name,
                type=param_type,
                description=field_info.description or "",
                constraints=constraints,
                sensitive=field_name in sensitive_fields,
                default=default,
                required=is_required,
            )

        return ToolSchema(
            name=tool_name,
            description=model.__doc__ or "",
            parameters=parameters,
            required_parameters=required_params,
            risk_level=risk_level,
        )

    def _annotation_to_type(self, annotation: Any) -> str:
        """Convert a type annotation to a schema type string."""
        if annotation is None:
            return "any"

        # Handle Optional and Union types
        origin = getattr(annotation, "__origin__", None)
        if origin is not None:
            # Get the first non-None type from Union
            args = getattr(annotation, "__args__", ())
            for arg in args:
                if arg is not type(None):
                    return self._annotation_to_type(arg)

        # Simple types
        if annotation is str:
            return "str"
        elif annotation is int:
            return "int"
        elif annotation is float:
            return "float"
        elif annotation is bool:
            return "bool"
        elif annotation is list or origin is list:
            return "list"
        elif annotation is dict or origin is dict:
            return "dict"

        return "any"

    def _field_info_to_constraints(self, field_info: FieldInfo) -> dict[str, Any]:
        """Extract constraints from Pydantic FieldInfo."""
        constraints: dict[str, Any] = {}

        # Get metadata from field_info
        metadata = getattr(field_info, "metadata", [])
        for item in metadata:
            # Handle Pydantic constraints (Gt, Lt, Ge, Le, etc.)
            if hasattr(item, "gt"):
                constraints["min"] = item.gt
            if hasattr(item, "ge"):
                constraints["min"] = item.ge
            if hasattr(item, "lt"):
                constraints["max"] = item.lt
            if hasattr(item, "le"):
                constraints["max"] = item.le
            if hasattr(item, "min_length"):
                constraints["min_length"] = item.min_length
            if hasattr(item, "max_length"):
                constraints["max_length"] = item.max_length
            if hasattr(item, "pattern"):
                constraints["pattern"] = item.pattern

        return constraints

    def validate(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> ValidationResult:
        """
        Validate arguments using Pydantic model if available.

        Args:
            tool_name: The tool name.
            arguments: The arguments to validate.

        Returns:
            ValidationResult with validation status.
        """
        # Check if we have a Pydantic model for this tool
        model = self._pydantic_models.get(tool_name)

        if model is not None:
            return self._validate_with_pydantic(model, tool_name, arguments)

        # Fall back to standard validation
        return super().validate(tool_name, arguments)

    def _validate_with_pydantic(
        self,
        model: type[BaseModel],
        tool_name: str,
        arguments: dict[str, Any],
    ) -> ValidationResult:
        """Validate using a Pydantic model."""
        try:
            # Validate and get the model instance
            validated = model.model_validate(arguments)

            # Convert back to dict for sanitized output
            sanitized = validated.model_dump()

            return ValidationResult.success(sanitized=sanitized)

        except ValidationError as e:
            # Convert Pydantic errors to our format
            errors = []
            for error in e.errors():
                loc = ".".join(str(part) for part in error["loc"])
                msg = error["msg"]
                errors.append(f"Parameter '{loc}': {msg}")

            return ValidationResult.failure(errors)

    def get_json_schema(self, tool_name: str) -> dict[str, Any] | None:
        """
        Get JSON Schema for a tool.

        Pydantic can generate JSON Schema from models, which is useful
        for documentation and OpenAI function calling.

        Args:
            tool_name: The tool name.

        Returns:
            JSON Schema dict or None if no model registered.
        """
        model = self._pydantic_models.get(tool_name)
        if model is None:
            return None

        return model.model_json_schema()

    def create_model_from_schema(
        self,
        schema: ToolSchema,
    ) -> type[BaseModel]:
        """
        Create a Pydantic model from a ToolSchema.

        This is useful when you have a ToolSchema but want to use
        Pydantic's validation.

        Args:
            schema: The ToolSchema to convert.

        Returns:
            A dynamically created Pydantic model class.
        """
        field_definitions: dict[str, Any] = {}

        for param_name, param_schema in schema.parameters.items():
            # Get Python type
            python_type = self._schema_type_to_python(param_schema.type)

            # Build field info
            if param_schema.required:
                field_definitions[param_name] = (python_type, ...)
            else:
                field_definitions[param_name] = (python_type, param_schema.default)

        # Create the model dynamically
        model = create_model(
            f"{schema.name}Input",
            **field_definitions,
        )

        return model

    def _schema_type_to_python(self, type_str: str) -> type:
        """Convert schema type string to Python type."""
        type_map = {
            "str": str,
            "int": int,
            "float": float,
            "bool": bool,
            "list": list,
            "dict": dict,
            "any": Any,
        }
        return type_map.get(type_str, Any)


def create_pydantic_validator() -> PydanticSchemaValidator | None:
    """
    Create a PydanticSchemaValidator if Pydantic is available.

    Returns:
        PydanticSchemaValidator instance or None if Pydantic not installed.
    """
    if not HAS_PYDANTIC:
        logger.warning(
            "Pydantic not installed. Using standard SchemaValidator. "
            "Install with: pip install proxilion[pydantic]"
        )
        return None

    return PydanticSchemaValidator()
