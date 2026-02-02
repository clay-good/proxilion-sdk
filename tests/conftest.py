"""
Pytest fixtures for Proxilion tests.

Provides common fixtures used across all test modules.
"""

from __future__ import annotations

import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator

import pytest

from proxilion import Proxilion, Policy, UserContext, AgentContext
from proxilion.types import ToolCallRequest, AuthorizationResult
from proxilion.policies.registry import PolicyRegistry
from proxilion.policies.base import Policy as BasePolicy
from proxilion.validation.schema import SchemaValidator, ToolSchema, ParameterSchema
from proxilion.security.rate_limiter import TokenBucketRateLimiter, SlidingWindowRateLimiter
from proxilion.security.circuit_breaker import CircuitBreaker, CircuitBreakerRegistry
from proxilion.security.idor_protection import IDORProtector
from proxilion.audit.logger import AuditLogger, LoggerConfig, RotationPolicy
from proxilion.audit.hash_chain import HashChain, GENESIS_HASH
from proxilion.audit.events import AuditEventV2, AuditEventData, EventType


# ============================================================================
# User Context Fixtures
# ============================================================================


@pytest.fixture
def basic_user() -> UserContext:
    """Create a basic user context for testing."""
    return UserContext(
        user_id="user_123",
        roles=["user"],
        session_id="session_abc",
        attributes={"department": "engineering"},
    )


@pytest.fixture
def admin_user() -> UserContext:
    """Create an admin user context for testing."""
    return UserContext(
        user_id="admin_456",
        roles=["admin", "user"],
        session_id="session_def",
        attributes={"department": "engineering", "clearance": "high"},
    )


@pytest.fixture
def analyst_user() -> UserContext:
    """Create an analyst user context for testing."""
    return UserContext(
        user_id="analyst_789",
        roles=["analyst", "user"],
        session_id="session_ghi",
        attributes={"department": "data_science"},
    )


@pytest.fixture
def guest_user() -> UserContext:
    """Create a guest user context with minimal permissions."""
    return UserContext(
        user_id="guest_000",
        roles=["guest"],
        session_id=None,
        attributes={},
    )


# ============================================================================
# Agent Context Fixtures
# ============================================================================


@pytest.fixture
def basic_agent() -> AgentContext:
    """Create a basic agent context for testing."""
    return AgentContext(
        agent_id="agent_001",
        capabilities=["search", "read"],
        trust_score=0.8,
    )


@pytest.fixture
def high_trust_agent() -> AgentContext:
    """Create a high-trust agent context."""
    return AgentContext(
        agent_id="agent_002",
        capabilities=["search", "read", "write", "execute"],
        trust_score=1.0,
    )


@pytest.fixture
def low_trust_agent() -> AgentContext:
    """Create a low-trust agent context."""
    return AgentContext(
        agent_id="agent_003",
        capabilities=["read"],
        trust_score=0.3,
    )


# ============================================================================
# Tool Call Request Fixtures
# ============================================================================


@pytest.fixture
def search_tool_request() -> ToolCallRequest:
    """Create a search tool call request."""
    return ToolCallRequest(
        tool_name="search",
        arguments={"query": "test query", "limit": 10},
        timestamp=datetime.now(timezone.utc),
    )


@pytest.fixture
def database_query_request() -> ToolCallRequest:
    """Create a database query tool call request."""
    return ToolCallRequest(
        tool_name="database_query",
        arguments={"query": "SELECT * FROM users WHERE id = 1", "database": "main"},
        timestamp=datetime.now(timezone.utc),
    )


@pytest.fixture
def file_read_request() -> ToolCallRequest:
    """Create a file read tool call request."""
    return ToolCallRequest(
        tool_name="file_read",
        arguments={"path": "/safe/path/file.txt"},
        timestamp=datetime.now(timezone.utc),
    )


@pytest.fixture
def dangerous_file_request() -> ToolCallRequest:
    """Create a dangerous file read request with path traversal."""
    return ToolCallRequest(
        tool_name="file_read",
        arguments={"path": "../../../etc/passwd"},
        timestamp=datetime.now(timezone.utc),
    )


# ============================================================================
# Policy Fixtures
# ============================================================================


@pytest.fixture
def policy_registry() -> PolicyRegistry:
    """Create a fresh policy registry."""
    return PolicyRegistry()


@pytest.fixture
def search_policy_class():
    """Create a search policy class."""
    class SearchPolicy(BasePolicy):
        def can_execute(self, context: dict) -> bool:
            return True  # All authenticated users can search

        def can_search_private(self, context: dict) -> bool:
            return "admin" in self.user.roles

    return SearchPolicy


@pytest.fixture
def database_policy_class():
    """Create a database query policy class."""
    class DatabaseQueryPolicy(BasePolicy):
        def can_execute(self, context: dict) -> bool:
            return self.user.roles and any(
                role in ["analyst", "admin"] for role in self.user.roles
            )

        def can_write(self, context: dict) -> bool:
            return "admin" in self.user.roles

        def can_delete(self, context: dict) -> bool:
            return "admin" in self.user.roles and context.get("confirmed", False)

    return DatabaseQueryPolicy


@pytest.fixture
def file_policy_class():
    """Create a file access policy class."""
    class FilePolicy(BasePolicy):
        FORBIDDEN_PATHS = ["/etc/", "/root/", "/var/log/"]

        def can_read(self, context: dict) -> bool:
            path = context.get("path", "")
            # Block path traversal
            if ".." in path:
                return False
            # Block forbidden paths
            for forbidden in self.FORBIDDEN_PATHS:
                if path.startswith(forbidden):
                    return False
            return True

        def can_write(self, context: dict) -> bool:
            if not self.can_read(context):
                return False
            return "admin" in self.user.roles or "writer" in self.user.roles

    return FilePolicy


# ============================================================================
# Proxilion Instance Fixtures
# ============================================================================


@pytest.fixture
def proxilion_simple() -> Proxilion:
    """Create a Proxilion instance with simple engine."""
    return Proxilion(
        policy_engine="simple",
        enable_circuit_breaker=False,
    )


@pytest.fixture
def proxilion_with_audit(tmp_path: Path) -> Proxilion:
    """Create a Proxilion instance with audit logging."""
    audit_path = tmp_path / "audit.jsonl"
    return Proxilion(
        policy_engine="simple",
        audit_log_path=str(audit_path),
        enable_circuit_breaker=False,
    )


@pytest.fixture
def proxilion_full(tmp_path: Path) -> Proxilion:
    """Create a fully configured Proxilion instance."""
    audit_path = tmp_path / "audit.jsonl"
    return Proxilion(
        policy_engine="simple",
        audit_log_path=str(audit_path),
        rate_limit_config={
            "default": {"capacity": 100, "refill_rate": 10},
        },
        enable_circuit_breaker=True,
    )


# ============================================================================
# Schema Validation Fixtures
# ============================================================================


@pytest.fixture
def schema_validator() -> SchemaValidator:
    """Create a schema validator."""
    return SchemaValidator()


@pytest.fixture
def calculator_schema() -> ToolSchema:
    """Create a calculator tool schema."""
    return ToolSchema(
        name="calculator",
        description="Performs mathematical operations",
        parameters={
            "operation": ParameterSchema(
                name="operation",
                type="str",
                description="The operation to perform",
                constraints={"enum": ["add", "subtract", "multiply", "divide"]},
            ),
            "a": ParameterSchema(
                name="a",
                type="float",
                description="First operand",
            ),
            "b": ParameterSchema(
                name="b",
                type="float",
                description="Second operand",
            ),
        },
        required_parameters=["operation", "a", "b"],
        risk_level="low",
    )


@pytest.fixture
def file_read_schema() -> ToolSchema:
    """Create a file read tool schema with path validation."""
    return ToolSchema(
        name="file_read",
        description="Read contents of a file",
        parameters={
            "path": ParameterSchema(
                name="path",
                type="str",
                description="Path to the file",
                constraints={"allow_path_traversal": False},
            ),
        },
        required_parameters=["path"],
        risk_level="medium",
    )


@pytest.fixture
def database_query_schema() -> ToolSchema:
    """Create a database query tool schema."""
    return ToolSchema(
        name="database_query",
        description="Execute a database query",
        parameters={
            "query": ParameterSchema(
                name="query",
                type="str",
                description="SQL query to execute",
                sensitive=True,
            ),
            "database": ParameterSchema(
                name="database",
                type="str",
                description="Target database",
                constraints={"enum": ["main", "analytics", "logs"]},
            ),
        },
        required_parameters=["query"],
        risk_level="high",
    )


# ============================================================================
# Security Control Fixtures
# ============================================================================


@pytest.fixture
def rate_limiter() -> TokenBucketRateLimiter:
    """Create a token bucket rate limiter."""
    return TokenBucketRateLimiter(
        capacity=10,
        refill_rate=1.0,  # 1 token per second
    )


@pytest.fixture
def sliding_window_limiter() -> SlidingWindowRateLimiter:
    """Create a sliding window rate limiter."""
    return SlidingWindowRateLimiter(
        max_requests=10,
        window_seconds=60.0,
    )


@pytest.fixture
def circuit_breaker() -> CircuitBreaker:
    """Create a circuit breaker."""
    return CircuitBreaker(
        failure_threshold=3,
        reset_timeout=5.0,
        half_open_max=1,
    )


@pytest.fixture
def circuit_breaker_registry() -> CircuitBreakerRegistry:
    """Create a circuit breaker registry."""
    return CircuitBreakerRegistry(
        default_config={
            "failure_threshold": 3,
            "reset_timeout": 5.0,
        }
    )


@pytest.fixture
def idor_protector() -> IDORProtector:
    """Create an IDOR protector with sample scopes."""
    protector = IDORProtector()
    # Register some sample scopes
    protector.register_scope("user_123", "document", {"doc_1", "doc_2", "doc_3"})
    protector.register_scope("user_123", "project", {"proj_a", "proj_b"})
    protector.register_scope("admin_456", "document", {"doc_1", "doc_2", "doc_3", "doc_4", "doc_5"})
    return protector


# ============================================================================
# Audit Logging Fixtures
# ============================================================================


@pytest.fixture
def hash_chain() -> HashChain:
    """Create a fresh hash chain."""
    return HashChain()


@pytest.fixture
def temp_audit_dir(tmp_path: Path) -> Path:
    """Create a temporary directory for audit logs."""
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    return audit_dir


@pytest.fixture
def audit_logger(temp_audit_dir: Path) -> AuditLogger:
    """Create an audit logger with temporary directory."""
    config = LoggerConfig(
        log_path=temp_audit_dir / "audit.jsonl",
        rotation=RotationPolicy.NONE,
    )
    return AuditLogger(config)


@pytest.fixture
def sample_audit_event(basic_user: UserContext, search_tool_request: ToolCallRequest) -> AuditEventV2:
    """Create a sample audit event."""
    data = AuditEventData(
        event_type=EventType.AUTHORIZATION_GRANTED,
        user_id=basic_user.user_id,
        user_roles=basic_user.roles,
        session_id=basic_user.session_id,
        user_attributes=basic_user.attributes,
        agent_id=None,
        agent_capabilities=[],
        agent_trust_score=None,
        tool_name=search_tool_request.tool_name,
        tool_arguments=search_tool_request.arguments,
        tool_timestamp=search_tool_request.timestamp,
        authorization_allowed=True,
        authorization_reason="Policy allowed",
        policies_evaluated=["SearchPolicy"],
        authorization_metadata={},
    )
    event = AuditEventV2(
        data=data,
        previous_hash=GENESIS_HASH,
    )
    event.compute_hash()
    return event


# ============================================================================
# Helper Fixtures
# ============================================================================


@pytest.fixture
def temp_file(tmp_path: Path) -> Generator[Path, None, None]:
    """Create a temporary file for testing."""
    file_path = tmp_path / "test_file.txt"
    file_path.write_text("Test content")
    yield file_path


@pytest.fixture
def mock_tool_implementation():
    """Create a mock tool implementation that tracks calls."""
    class MockTool:
        def __init__(self):
            self.calls: list[dict[str, Any]] = []
            self.should_fail = False
            self.fail_count = 0

        def __call__(self, **kwargs) -> dict[str, Any]:
            self.calls.append(kwargs)
            if self.should_fail:
                self.fail_count += 1
                raise RuntimeError("Mock tool failure")
            return {"status": "success", "args": kwargs}

        async def async_call(self, **kwargs) -> dict[str, Any]:
            return self(**kwargs)

    return MockTool()
