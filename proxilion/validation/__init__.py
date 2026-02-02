"""
Schema validation system for Proxilion.

This module provides tools for validating LLM tool call arguments
against defined schemas. It includes security validations for
path traversal, SQL injection, and IDOR protection.

Quick Start:
    >>> from proxilion.validation import SchemaValidator, ToolSchema, ParameterSchema
    >>>
    >>> validator = SchemaValidator()
    >>> schema = ToolSchema(
    ...     name="file_read",
    ...     description="Read a file",
    ...     parameters={
    ...         "path": ParameterSchema(
    ...             name="path",
    ...             type="str",
    ...             constraints={"allow_path_traversal": False},
    ...         ),
    ...     },
    ...     required_parameters=["path"],
    ...     risk_level="medium",
    ... )
    >>> validator.register_schema("file_read", schema)
    >>> result = validator.validate("file_read", {"path": "/safe/path.txt"})
    >>> print(result.valid)
    True

Security Features:
    - Path traversal detection: Rejects ".." and encoded variants
    - SQL injection detection: Detects common SQL injection patterns
    - Object ID validation: Validates UUID, numeric, and alphanumeric IDs
    - Parameter constraints: min, max, pattern, enum, length limits
"""

from proxilion.validation.schema import (
    ParameterSchema,
    RiskLevel,
    SchemaValidator,
    ToolSchema,
    ValidationResult,
)

# Optional Pydantic support
try:
    from proxilion.validation.pydantic_schema import (
        PydanticSchemaValidator,
        create_pydantic_validator,
    )
    HAS_PYDANTIC = True
except ImportError:
    HAS_PYDANTIC = False
    PydanticSchemaValidator = None  # type: ignore
    create_pydantic_validator = None  # type: ignore


def create_validator(use_pydantic: bool = False) -> SchemaValidator:
    """
    Create a schema validator.

    Args:
        use_pydantic: If True, try to create a PydanticSchemaValidator.
            Falls back to SchemaValidator if Pydantic is not installed.

    Returns:
        A SchemaValidator or PydanticSchemaValidator instance.

    Example:
        >>> validator = create_validator(use_pydantic=True)
    """
    if use_pydantic and HAS_PYDANTIC and create_pydantic_validator is not None:
        pydantic_validator = create_pydantic_validator()
        if pydantic_validator is not None:
            return pydantic_validator

    return SchemaValidator()


__all__ = [
    # Core classes
    "ToolSchema",
    "ParameterSchema",
    "SchemaValidator",
    "ValidationResult",
    "RiskLevel",
    # Factory
    "create_validator",
    # Pydantic (optional)
    "PydanticSchemaValidator",
    "create_pydantic_validator",
    "HAS_PYDANTIC",
]
