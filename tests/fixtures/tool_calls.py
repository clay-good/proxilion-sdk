"""
Tool call request fixtures for testing.

Provides factory functions for creating various types of tool call requests,
including safe operations, attack attempts, and sequences.
"""

from __future__ import annotations

from datetime import datetime, timezone

from proxilion.types import ToolCallRequest


def make_safe_search(query: str = "weather forecast") -> ToolCallRequest:
    """
    Create a safe search tool call request.

    Args:
        query: Search query string.

    Returns:
        ToolCallRequest for a safe search operation.
    """
    return ToolCallRequest(
        tool_name="search",
        arguments={
            "query": query,
            "limit": 10,
            "safe_mode": True,
        },
        timestamp=datetime.now(timezone.utc),
    )


def make_sql_injection_attempt() -> ToolCallRequest:
    """
    Create a SQL injection attack attempt.

    Returns:
        ToolCallRequest with SQL injection payload.
    """
    return ToolCallRequest(
        tool_name="database_query",
        arguments={
            "query": "SELECT * FROM users WHERE id = '1' OR '1'='1'; DROP TABLE users; --",
            "database": "main",
        },
        timestamp=datetime.now(timezone.utc),
    )


def make_path_traversal_attempt() -> ToolCallRequest:
    """
    Create a path traversal attack attempt.

    Returns:
        ToolCallRequest with path traversal payload.
    """
    return ToolCallRequest(
        tool_name="read_file",
        arguments={
            "path": "../../../etc/passwd",
        },
        timestamp=datetime.now(timezone.utc),
    )


def make_normal_crud_sequence() -> list[ToolCallRequest]:
    """
    Create a sequence of normal CRUD operations.

    Returns:
        List of ToolCallRequest objects representing normal operations.
    """
    return [
        ToolCallRequest(
            tool_name="create_document",
            arguments={
                "title": "Project Plan",
                "content": "Q1 objectives...",
                "owner_id": "user_123",
            },
            timestamp=datetime.now(timezone.utc),
        ),
        ToolCallRequest(
            tool_name="read_document",
            arguments={
                "document_id": "doc_001",
            },
            timestamp=datetime.now(timezone.utc),
        ),
        ToolCallRequest(
            tool_name="update_document",
            arguments={
                "document_id": "doc_001",
                "content": "Updated Q1 objectives...",
            },
            timestamp=datetime.now(timezone.utc),
        ),
        ToolCallRequest(
            tool_name="list_documents",
            arguments={
                "owner_id": "user_123",
                "limit": 50,
            },
            timestamp=datetime.now(timezone.utc),
        ),
        ToolCallRequest(
            tool_name="delete_document",
            arguments={
                "document_id": "doc_001",
            },
            timestamp=datetime.now(timezone.utc),
        ),
    ]


def make_attack_sequence() -> list[ToolCallRequest]:
    """
    Create a sequence of attack attempts for testing detection.

    Returns:
        List of ToolCallRequest objects representing various attacks.
    """
    return [
        # SQL injection attempt
        ToolCallRequest(
            tool_name="database_query",
            arguments={
                "query": "SELECT * FROM users WHERE id = '1' OR '1'='1'",
                "database": "main",
            },
            timestamp=datetime.now(timezone.utc),
        ),
        # Path traversal attempt
        ToolCallRequest(
            tool_name="read_file",
            arguments={
                "path": "../../../../etc/shadow",
            },
            timestamp=datetime.now(timezone.utc),
        ),
        # Command injection attempt
        ToolCallRequest(
            tool_name="system_command",
            arguments={
                "command": "ls; rm -rf /",
            },
            timestamp=datetime.now(timezone.utc),
        ),
        # IDOR attempt (accessing other user's resources)
        ToolCallRequest(
            tool_name="read_document",
            arguments={
                "document_id": "admin_secret_doc_999",
            },
            timestamp=datetime.now(timezone.utc),
        ),
        # Credential harvesting attempt
        ToolCallRequest(
            tool_name="database_query",
            arguments={
                "query": "SELECT username, password FROM users",
                "database": "auth",
            },
            timestamp=datetime.now(timezone.utc),
        ),
    ]
