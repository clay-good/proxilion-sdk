"""
Tests for proxilion.validation.pydantic_schema module.

Covers PydanticSchemaValidator, model registration, validation,
JSON schema generation, and dynamic model creation.
"""

from __future__ import annotations

import pytest

from proxilion.validation.pydantic_schema import HAS_PYDANTIC

if not HAS_PYDANTIC:
    pytest.skip("pydantic not installed", allow_module_level=True)

from pydantic import BaseModel, Field  # noqa: E402

from proxilion.validation.pydantic_schema import (  # noqa: E402
    PydanticSchemaValidator,
    create_pydantic_validator,
)

# =============================================================================
# Test Models
# =============================================================================


class CalculatorInput(BaseModel):
    """Calculator tool input."""

    operation: str
    a: float
    b: float


class QueryInput(BaseModel):
    """Database query input."""

    query: str = Field(description="SQL query to execute")
    limit: int = Field(default=100, ge=1, le=10000)
    timeout: float = 30.0


class UserInput(BaseModel):
    """User creation input."""

    name: str = Field(min_length=1, max_length=100)
    email: str
    age: int | None = None
    tags: list[str] = Field(default_factory=list)


# =============================================================================
# PydanticSchemaValidator Creation Tests
# =============================================================================


class TestPydanticSchemaValidatorCreation:
    """Tests for PydanticSchemaValidator initialization."""

    def test_creation(self) -> None:
        """Test basic creation."""
        validator = PydanticSchemaValidator()
        assert validator is not None

    def test_creation_strict_mode(self) -> None:
        """Test creation with strict mode."""
        validator = PydanticSchemaValidator(strict_mode=True)
        assert validator is not None

    def test_factory_function(self) -> None:
        """Test create_pydantic_validator factory."""
        validator = create_pydantic_validator()
        assert validator is not None
        assert isinstance(validator, PydanticSchemaValidator)


# =============================================================================
# Model Registration Tests
# =============================================================================


class TestModelRegistration:
    """Tests for registering Pydantic models."""

    def test_register_model(self) -> None:
        """Test registering a Pydantic model."""
        validator = PydanticSchemaValidator()
        validator.register_pydantic_model("calculator", CalculatorInput)

        # Should be able to validate
        result = validator.validate("calculator", {"operation": "add", "a": 5, "b": 3})
        assert result.valid

    def test_register_model_with_risk_level(self) -> None:
        """Test registering with risk level."""
        validator = PydanticSchemaValidator()
        validator.register_pydantic_model("query", QueryInput, risk_level="high")

        result = validator.validate("query", {"query": "SELECT 1"})
        assert result.valid

    def test_register_model_with_sensitive_fields(self) -> None:
        """Test registering with sensitive field marking."""
        validator = PydanticSchemaValidator()
        validator.register_pydantic_model("user", UserInput, sensitive_fields=["email"])

        result = validator.validate("user", {"name": "Alice", "email": "alice@example.com"})
        assert result.valid

    def test_register_multiple_models(self) -> None:
        """Test registering multiple models."""
        validator = PydanticSchemaValidator()
        validator.register_pydantic_model("calculator", CalculatorInput)
        validator.register_pydantic_model("query", QueryInput)
        validator.register_pydantic_model("user", UserInput)

        assert validator.validate("calculator", {"operation": "+", "a": 1, "b": 2}).valid
        assert validator.validate("query", {"query": "SELECT 1"}).valid
        assert validator.validate("user", {"name": "Bob", "email": "b@b.com"}).valid


# =============================================================================
# Validation Tests
# =============================================================================


class TestValidation:
    """Tests for validation with Pydantic models."""

    def test_valid_input(self) -> None:
        """Test valid input passes validation."""
        validator = PydanticSchemaValidator()
        validator.register_pydantic_model("calculator", CalculatorInput)

        result = validator.validate("calculator", {"operation": "multiply", "a": 3.14, "b": 2.0})
        assert result.valid
        assert result.sanitized_arguments is not None
        assert result.sanitized_arguments["operation"] == "multiply"

    def test_invalid_missing_required(self) -> None:
        """Test missing required field fails."""
        validator = PydanticSchemaValidator()
        validator.register_pydantic_model("calculator", CalculatorInput)

        result = validator.validate("calculator", {"operation": "add"})
        assert not result.valid
        assert len(result.errors) > 0

    def test_invalid_wrong_type(self) -> None:
        """Test wrong type fails."""
        validator = PydanticSchemaValidator()
        validator.register_pydantic_model("calculator", CalculatorInput)

        result = validator.validate("calculator", {"operation": "add", "a": "not_a_number", "b": 3})
        assert not result.valid

    def test_type_coercion(self) -> None:
        """Test Pydantic's type coercion (int to float)."""
        validator = PydanticSchemaValidator()
        validator.register_pydantic_model("calculator", CalculatorInput)

        result = validator.validate("calculator", {"operation": "add", "a": 5, "b": 3})
        assert result.valid
        assert result.sanitized_arguments["a"] == 5.0

    def test_default_values(self) -> None:
        """Test default values are applied."""
        validator = PydanticSchemaValidator()
        validator.register_pydantic_model("query", QueryInput)

        result = validator.validate("query", {"query": "SELECT 1"})
        assert result.valid
        assert result.sanitized_arguments["limit"] == 100
        assert result.sanitized_arguments["timeout"] == 30.0

    def test_optional_field_none(self) -> None:
        """Test optional field accepts None."""
        validator = PydanticSchemaValidator()
        validator.register_pydantic_model("user", UserInput)

        result = validator.validate("user", {"name": "Alice", "email": "a@a.com", "age": None})
        assert result.valid
        assert result.sanitized_arguments["age"] is None

    def test_constraint_violation(self) -> None:
        """Test constraint violation detected."""
        validator = PydanticSchemaValidator()
        validator.register_pydantic_model("query", QueryInput)

        # limit must be >= 1
        result = validator.validate("query", {"query": "SELECT 1", "limit": 0})
        assert not result.valid
        assert any("limit" in err for err in result.errors)

    def test_constraint_upper_bound(self) -> None:
        """Test upper bound constraint."""
        validator = PydanticSchemaValidator()
        validator.register_pydantic_model("query", QueryInput)

        result = validator.validate("query", {"query": "SELECT 1", "limit": 99999})
        assert not result.valid

    def test_string_length_constraint(self) -> None:
        """Test string length constraints."""
        validator = PydanticSchemaValidator()
        validator.register_pydantic_model("user", UserInput)

        # Empty name should fail (min_length=1)
        result = validator.validate("user", {"name": "", "email": "a@a.com"})
        assert not result.valid

    def test_list_field(self) -> None:
        """Test list field validation."""
        validator = PydanticSchemaValidator()
        validator.register_pydantic_model("user", UserInput)

        result = validator.validate(
            "user", {"name": "Alice", "email": "a@a.com", "tags": ["admin", "active"]}
        )
        assert result.valid
        assert result.sanitized_arguments["tags"] == ["admin", "active"]

    def test_fallback_to_standard_validation(self) -> None:
        """Test unregistered tool falls back to standard validation."""
        validator = PydanticSchemaValidator()
        validator.register_pydantic_model("calculator", CalculatorInput)

        # "unknown_tool" has no Pydantic model — falls back to parent
        result = validator.validate("unknown_tool", {"anything": "goes"})
        # Standard validator with no schema registered just passes
        assert result.valid

    def test_error_messages_include_field_location(self) -> None:
        """Test error messages include field path."""
        validator = PydanticSchemaValidator()
        validator.register_pydantic_model("calculator", CalculatorInput)

        result = validator.validate("calculator", {"operation": "add"})
        assert not result.valid
        # Errors should mention the field names
        error_text = " ".join(result.errors)
        assert "a" in error_text or "b" in error_text


# =============================================================================
# JSON Schema Generation Tests
# =============================================================================


class TestJsonSchema:
    """Tests for JSON schema generation."""

    def test_get_json_schema(self) -> None:
        """Test getting JSON schema for a registered model."""
        validator = PydanticSchemaValidator()
        validator.register_pydantic_model("calculator", CalculatorInput)

        schema = validator.get_json_schema("calculator")
        assert schema is not None
        assert "properties" in schema
        assert "operation" in schema["properties"]
        assert "a" in schema["properties"]
        assert "b" in schema["properties"]

    def test_get_json_schema_not_registered(self) -> None:
        """Test getting JSON schema for unregistered tool returns None."""
        validator = PydanticSchemaValidator()
        assert validator.get_json_schema("nonexistent") is None

    def test_json_schema_has_required(self) -> None:
        """Test JSON schema includes required fields."""
        validator = PydanticSchemaValidator()
        validator.register_pydantic_model("calculator", CalculatorInput)

        schema = validator.get_json_schema("calculator")
        assert "required" in schema
        assert "operation" in schema["required"]
        assert "a" in schema["required"]
        assert "b" in schema["required"]


# =============================================================================
# Dynamic Model Creation Tests
# =============================================================================


class TestDynamicModelCreation:
    """Tests for creating Pydantic models from ToolSchema."""

    def test_create_model_from_schema(self) -> None:
        """Test creating a Pydantic model from a ToolSchema."""
        from proxilion.validation.schema import ParameterSchema, ToolSchema

        schema = ToolSchema(
            name="test_tool",
            description="A test tool",
            parameters={
                "name": ParameterSchema(name="name", type="str", required=True),
                "count": ParameterSchema(name="count", type="int", required=False, default=10),
            },
            required_parameters=["name"],
        )

        validator = PydanticSchemaValidator()
        model = validator.create_model_from_schema(schema)

        assert model is not None
        assert model.__name__ == "test_toolInput"

        # Validate with the created model
        instance = model(name="test", count=5)
        assert instance.name == "test"
        assert instance.count == 5

    def test_create_model_with_defaults(self) -> None:
        """Test created model respects defaults."""
        from proxilion.validation.schema import ParameterSchema, ToolSchema

        schema = ToolSchema(
            name="search",
            description="Search tool",
            parameters={
                "query": ParameterSchema(name="query", type="str", required=True),
                "max_results": ParameterSchema(
                    name="max_results", type="int", required=False, default=20
                ),
            },
            required_parameters=["query"],
        )

        validator = PydanticSchemaValidator()
        model = validator.create_model_from_schema(schema)

        instance = model(query="hello")
        assert instance.query == "hello"
        assert instance.max_results == 20


# =============================================================================
# Type Annotation Conversion Tests
# =============================================================================


class TestTypeConversion:
    """Tests for type annotation conversion."""

    def test_annotation_to_type_primitives(self) -> None:
        """Test conversion of primitive types."""
        validator = PydanticSchemaValidator()

        assert validator._annotation_to_type(str) == "str"
        assert validator._annotation_to_type(int) == "int"
        assert validator._annotation_to_type(float) == "float"
        assert validator._annotation_to_type(bool) == "bool"
        assert validator._annotation_to_type(list) == "list"
        assert validator._annotation_to_type(dict) == "dict"

    def test_annotation_to_type_none(self) -> None:
        """Test None annotation."""
        validator = PydanticSchemaValidator()
        assert validator._annotation_to_type(None) == "any"

    def test_schema_type_to_python(self) -> None:
        """Test schema type string to Python type mapping."""
        validator = PydanticSchemaValidator()

        assert validator._schema_type_to_python("str") is str
        assert validator._schema_type_to_python("int") is int
        assert validator._schema_type_to_python("float") is float
        assert validator._schema_type_to_python("bool") is bool
        assert validator._schema_type_to_python("list") is list
        assert validator._schema_type_to_python("dict") is dict


# =============================================================================
# Edge Cases
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases."""

    def test_empty_arguments(self) -> None:
        """Test validation with empty arguments for model with all required."""
        validator = PydanticSchemaValidator()
        validator.register_pydantic_model("calculator", CalculatorInput)

        result = validator.validate("calculator", {})
        assert not result.valid

    def test_extra_arguments(self) -> None:
        """Test validation with extra arguments."""
        validator = PydanticSchemaValidator()
        validator.register_pydantic_model("calculator", CalculatorInput)

        result = validator.validate(
            "calculator",
            {"operation": "add", "a": 1, "b": 2, "extra_field": "ignored"},
        )
        # Pydantic by default ignores extra fields
        assert result.valid

    def test_nested_model(self) -> None:
        """Test validation with nested Pydantic model."""

        class Address(BaseModel):
            street: str
            city: str

        class Person(BaseModel):
            name: str
            address: Address

        validator = PydanticSchemaValidator()
        validator.register_pydantic_model("person", Person)

        result = validator.validate(
            "person",
            {"name": "Alice", "address": {"street": "123 Main", "city": "Springfield"}},
        )
        assert result.valid
        assert result.sanitized_arguments["address"]["city"] == "Springfield"

    def test_nested_model_invalid(self) -> None:
        """Test validation fails with invalid nested model."""

        class Address(BaseModel):
            street: str
            city: str

        class Person(BaseModel):
            name: str
            address: Address

        validator = PydanticSchemaValidator()
        validator.register_pydantic_model("person", Person)

        result = validator.validate(
            "person",
            {"name": "Alice", "address": {"street": "123 Main"}},  # missing city
        )
        assert not result.valid

    def test_model_with_all_defaults(self) -> None:
        """Test model where all fields have defaults."""

        class Config(BaseModel):
            debug: bool = False
            verbose: bool = False
            timeout: int = 30

        validator = PydanticSchemaValidator()
        validator.register_pydantic_model("config", Config)

        result = validator.validate("config", {})
        assert result.valid
        assert result.sanitized_arguments["debug"] is False
        assert result.sanitized_arguments["timeout"] == 30
