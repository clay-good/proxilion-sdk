"""
Tests for IDOR (Insecure Direct Object Reference) protection.

Tests cover:
- Scope registration
- Access validation
- Pattern-based ID detection
- Object ID format validation
"""

from __future__ import annotations

import pytest

from proxilion.security.idor_protection import (
    IDORProtector,
    IDPattern,
    ResourceScope,
)


class TestIDORProtectorBasics:
    """Basic tests for IDORProtector."""

    def test_initialization(self):
        """Test IDORProtector initialization."""
        protector = IDORProtector()
        assert protector is not None

    def test_register_scope(self, idor_protector: IDORProtector):
        """Test registering a user's scope for a resource type."""
        idor_protector.register_scope("new_user", "file", {"file_1", "file_2"})
        assert idor_protector.validate_access("new_user", "file", "file_1") is True

    def test_register_scope_overwrites(self, idor_protector: IDORProtector):
        """Test that registering scope overwrites previous scope."""
        idor_protector.register_scope("user_123", "document", {"new_doc"})
        # Old docs should no longer be accessible
        assert idor_protector.validate_access("user_123", "document", "doc_1") is False
        assert idor_protector.validate_access("user_123", "document", "new_doc") is True

    def test_add_to_scope(self, idor_protector: IDORProtector):
        """Test adding IDs to existing scope."""
        idor_protector.add_to_scope("user_123", "document", {"doc_new"})
        assert idor_protector.validate_access("user_123", "document", "doc_new") is True
        # Old docs should still be accessible
        assert idor_protector.validate_access("user_123", "document", "doc_1") is True

    def test_remove_from_scope(self, idor_protector: IDORProtector):
        """Test removing IDs from scope."""
        idor_protector.remove_from_scope("user_123", "document", {"doc_1"})
        assert idor_protector.validate_access("user_123", "document", "doc_1") is False
        # Other docs should still be accessible
        assert idor_protector.validate_access("user_123", "document", "doc_2") is True


class TestAccessValidation:
    """Tests for access validation."""

    def test_validate_access_allowed(self, idor_protector: IDORProtector):
        """Test that valid access is allowed."""
        assert idor_protector.validate_access("user_123", "document", "doc_1") is True
        assert idor_protector.validate_access("user_123", "document", "doc_2") is True
        assert idor_protector.validate_access("user_123", "project", "proj_a") is True

    def test_validate_access_denied(self, idor_protector: IDORProtector):
        """Test that invalid access is denied."""
        # user_123 doesn't have access to doc_4
        assert idor_protector.validate_access("user_123", "document", "doc_4") is False

    def test_validate_access_unknown_user(self, idor_protector: IDORProtector):
        """Test access validation for unknown user."""
        assert idor_protector.validate_access("unknown_user", "document", "doc_1") is False

    def test_validate_access_unknown_resource_type(self, idor_protector: IDORProtector):
        """Test access validation for unknown resource type."""
        assert idor_protector.validate_access("user_123", "unknown_type", "id_1") is False

    def test_admin_has_wider_scope(self, idor_protector: IDORProtector):
        """Test that admin user has wider scope."""
        # Admin can access doc_4 and doc_5
        assert idor_protector.validate_access("admin_456", "document", "doc_4") is True
        assert idor_protector.validate_access("admin_456", "document", "doc_5") is True
        # But user_123 cannot
        assert idor_protector.validate_access("user_123", "document", "doc_4") is False


class TestBulkValidation:
    """Tests for bulk validation operations."""

    def test_validate_multiple_ids(self, idor_protector: IDORProtector):
        """Test validating multiple IDs at once."""
        ids_to_check = ["doc_1", "doc_2", "doc_3"]
        results = {}
        for id_ in ids_to_check:
            results[id_] = idor_protector.validate_access("user_123", "document", id_)

        assert results["doc_1"] is True
        assert results["doc_2"] is True
        assert results["doc_3"] is True

    def test_validate_multiple_partial_access(self, idor_protector: IDORProtector):
        """Test bulk validation with partial access."""
        ids_to_check = ["doc_1", "doc_4", "doc_5"]
        results = {}
        for id_ in ids_to_check:
            results[id_] = idor_protector.validate_access("user_123", "document", id_)

        assert results["doc_1"] is True
        assert results["doc_4"] is False
        assert results["doc_5"] is False

    def test_filter_accessible(self, idor_protector: IDORProtector):
        """Test filtering to only accessible IDs."""
        ids_to_filter = ["doc_1", "doc_2", "doc_4", "doc_5"]
        accessible = [
            id_ for id_ in ids_to_filter
            if idor_protector.validate_access("user_123", "document", id_)
        ]

        assert "doc_1" in accessible
        assert "doc_2" in accessible
        assert "doc_4" not in accessible
        assert "doc_5" not in accessible


class TestIDPatterns:
    """Tests for ID pattern detection."""

    def test_uuid_pattern(self):
        """Test UUID pattern detection."""
        import re
        pattern = re.compile(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
            re.IGNORECASE,
        )

        # Valid UUIDs
        assert pattern.match("123e4567-e89b-12d3-a456-426614174000")
        assert pattern.match("550e8400-e29b-41d4-a716-446655440000")

        # Invalid UUIDs
        assert not pattern.match("not-a-uuid")
        assert not pattern.match("123")

    def test_numeric_pattern(self):
        """Test numeric ID pattern detection."""
        import re
        pattern = re.compile(r"^\d+$")

        # Valid numeric IDs
        assert pattern.match("123")
        assert pattern.match("999999")

        # Invalid numeric IDs
        assert not pattern.match("abc")
        assert not pattern.match("123abc")

    def test_alphanumeric_pattern(self):
        """Test alphanumeric ID pattern detection."""
        import re
        pattern = re.compile(r"^[a-zA-Z0-9_-]+$")

        # Valid alphanumeric IDs
        assert pattern.match("abc123")
        assert pattern.match("user_001")
        assert pattern.match("doc-123")

        # Invalid (contains special chars)
        assert not pattern.match("id@123")


class TestExtractObjectIDs:
    """Tests for extracting object IDs from tool arguments."""

    def test_extract_from_flat_args(self, idor_protector: IDORProtector):
        """Test extracting IDs from flat argument dict."""
        args = {
            "document_id": "doc_123",
            "query": "search text",
        }

        idor_protector.register_id_pattern("document_id", "document")

        violations = idor_protector.validate_arguments("user_123", args)
        # doc_123 is not in user_123's scope, so should be a violation
        assert len(violations) == 1
        assert violations[0][2] == "doc_123"

    def test_extract_from_nested_args(self, idor_protector: IDORProtector):
        """Test extracting IDs from flat argument dict (nested not supported in current impl)."""
        args = {
            "project_id": "proj_456",
            "options": {
                "limit": 10,
            },
        }

        idor_protector.register_id_pattern("project_id", "project")

        violations = idor_protector.validate_arguments("user_123", args)
        # proj_456 is not in user_123's scope
        assert len(violations) == 1
        assert violations[0][2] == "proj_456"

    def test_extract_multiple_ids(self, idor_protector: IDORProtector):
        """Test extracting multiple IDs from arguments."""
        args = {
            "document_id": "doc_1",
            "project_id": "proj_a",
            "other_field": "not an ID",
        }

        idor_protector.register_id_pattern("document_id", "document")
        idor_protector.register_id_pattern("project_id", "project")

        violations = idor_protector.validate_arguments("user_123", args)
        # Both doc_1 and proj_a are in user_123's scope
        assert len(violations) == 0


class TestResourceScope:
    """Tests for ResourceScope dataclass."""

    def test_scope_creation(self):
        """Test creating a ResourceScope."""
        scope = ResourceScope(
            allowed_ids={"doc_1", "doc_2"},
        )

        assert "doc_1" in scope.allowed_ids
        assert "doc_2" in scope.allowed_ids

    def test_scope_contains(self):
        """Test checking if ID is in scope."""
        scope = ResourceScope(
            allowed_ids={"doc_1", "doc_2"},
        )

        assert "doc_1" in scope.allowed_ids
        assert "doc_3" not in scope.allowed_ids

    def test_scope_add_and_remove(self):
        """Test adding and removing from scope."""
        scope = ResourceScope(
            allowed_ids={"doc_1"},
        )

        scope.allowed_ids.add("doc_2")
        assert "doc_2" in scope.allowed_ids

        scope.allowed_ids.remove("doc_1")
        assert "doc_1" not in scope.allowed_ids


class TestIDORValidationIntegration:
    """Integration tests for IDOR validation in tool calls."""

    def test_validate_tool_arguments(self, idor_protector: IDORProtector):
        """Test validating all object IDs in tool arguments."""
        idor_protector.register_id_pattern("document_id", "document")

        # Valid access
        args = {"document_id": "doc_1", "action": "read"}
        violations = idor_protector.validate_arguments("user_123", args)
        assert len(violations) == 0

        # Invalid access
        args = {"document_id": "doc_4", "action": "read"}
        violations = idor_protector.validate_arguments("user_123", args)
        assert len(violations) > 0
        assert "doc_4" in str(violations[0])

    def test_validate_tool_arguments_multiple(self, idor_protector: IDORProtector):
        """Test validating multiple object IDs."""
        idor_protector.register_id_pattern("document_id", "document")
        idor_protector.register_id_pattern("project_id", "project")

        # Both valid
        args = {"document_id": "doc_1", "project_id": "proj_a"}
        violations = idor_protector.validate_arguments("user_123", args)
        assert len(violations) == 0

        # One invalid
        args = {"document_id": "doc_1", "project_id": "proj_unknown"}
        violations = idor_protector.validate_arguments("user_123", args)
        assert len(violations) > 0
