"""
Core type definitions for Proxilion.

This module defines the fundamental data structures used throughout the SDK
for representing user context, agent context, tool call requests, authorization
results, and audit events.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def _generate_event_id() -> str:
    """Generate a UUID v4 for event identification.

    Note: UUID v7 would be ideal for time-ordering, but it's not available
    in Python stdlib until 3.14. Using UUID v4 with explicit timestamps instead.
    """
    return str(uuid.uuid4())


def _utc_now() -> datetime:
    """Get current UTC time with timezone info."""
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class UserContext:
    """
    Represents the authenticated user making a tool call request.

    This context travels through the agent to the tool, ensuring that
    authorization decisions are made based on the actual user's identity
    and permissions, not the agent's service account.

    Attributes:
        user_id: Unique identifier for the user (e.g., from your auth system).
        roles: List of role names assigned to the user (e.g., ["analyst", "viewer"]).
        session_id: Optional session identifier for tracking request context.
        attributes: Additional custom attributes for policy decisions
            (e.g., {"department": "engineering", "clearance_level": 3}).

    Example:
        >>> user = UserContext(
        ...     user_id="user_123",
        ...     roles=["analyst", "viewer"],
        ...     session_id="sess_abc",
        ...     attributes={"department": "engineering"}
        ... )
    """
    user_id: str
    roles: list[str] = field(default_factory=list)
    session_id: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)

    def has_role(self, role: str) -> bool:
        """Check if user has a specific role."""
        return role in self.roles

    def has_any_role(self, roles: list[str]) -> bool:
        """Check if user has any of the specified roles."""
        return any(role in self.roles for role in roles)

    def has_all_roles(self, roles: list[str]) -> bool:
        """Check if user has all of the specified roles."""
        return all(role in self.roles for role in roles)

    def get_attribute(self, key: str, default: Any = None) -> Any:
        """Get a user attribute with optional default."""
        return self.attributes.get(key, default)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "user_id": self.user_id,
            "roles": self.roles,
            "session_id": self.session_id,
            "attributes": self.attributes,
        }


@dataclass(frozen=True)
class AgentContext:
    """
    Represents the AI agent making tool calls on behalf of a user.

    The agent context helps track which agent is operating and can be used
    to implement agent-level security policies (e.g., limiting which agents
    can use sensitive tools).

    Attributes:
        agent_id: Unique identifier for the agent instance.
        capabilities: List of capability names the agent is allowed to use.
        trust_score: Float between 0-1 indicating agent trust level.
            Lower scores may trigger additional verification.

    Example:
        >>> agent = AgentContext(
        ...     agent_id="agent_openai_gpt4",
        ...     capabilities=["read_files", "search"],
        ...     trust_score=0.8
        ... )
    """
    agent_id: str
    capabilities: list[str] = field(default_factory=list)
    trust_score: float = 1.0

    def __post_init__(self) -> None:
        """Validate trust_score is within bounds."""
        if not 0.0 <= self.trust_score <= 1.0:
            raise ValueError(f"trust_score must be between 0 and 1, got {self.trust_score}")

    def has_capability(self, capability: str) -> bool:
        """Check if agent has a specific capability."""
        return capability in self.capabilities

    def is_high_trust(self, threshold: float = 0.8) -> bool:
        """Check if agent meets high trust threshold."""
        return self.trust_score >= threshold

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "agent_id": self.agent_id,
            "capabilities": self.capabilities,
            "trust_score": self.trust_score,
        }


@dataclass(frozen=True)
class ToolCallRequest:
    """
    Represents a request to execute a tool.

    This captures all the information about what tool is being called
    and with what arguments, enabling validation and authorization checks.

    Attributes:
        tool_name: Name of the tool being invoked.
        arguments: Dictionary of arguments passed to the tool.
        timestamp: When the request was made (UTC).

    Example:
        >>> request = ToolCallRequest(
        ...     tool_name="database_query",
        ...     arguments={"query": "SELECT * FROM users", "limit": 100}
        ... )
    """
    tool_name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=_utc_now)

    def get_argument(self, key: str, default: Any = None) -> Any:
        """Get an argument value with optional default."""
        return self.arguments.get(key, default)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "tool_name": self.tool_name,
            "arguments": self.arguments,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass(frozen=True)
class AuthorizationResult:
    """
    Result of an authorization check.

    Captures whether the action was allowed, the reason for the decision,
    and which policies were evaluated to reach the decision.

    Attributes:
        allowed: Whether the action is authorized.
        reason: Human-readable explanation of the decision.
        policies_evaluated: List of policy names that were checked.
        metadata: Additional information about the decision
            (e.g., rate limit remaining, matched rules).

    Example:
        >>> result = AuthorizationResult(
        ...     allowed=True,
        ...     reason="User has 'analyst' role",
        ...     policies_evaluated=["DatabaseQueryPolicy"]
        ... )
    """
    allowed: bool
    reason: str | None = None
    policies_evaluated: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def allow(cls, reason: str | None = None,
              policies: list[str] | None = None,
              metadata: dict[str, Any] | None = None) -> AuthorizationResult:
        """Create an allowed result."""
        return cls(
            allowed=True,
            reason=reason,
            policies_evaluated=policies or [],
            metadata=metadata or {},
        )

    @classmethod
    def deny(cls, reason: str,
             policies: list[str] | None = None,
             metadata: dict[str, Any] | None = None) -> AuthorizationResult:
        """Create a denied result."""
        return cls(
            allowed=False,
            reason=reason,
            policies_evaluated=policies or [],
            metadata=metadata or {},
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "policies_evaluated": self.policies_evaluated,
            "metadata": self.metadata,
        }


@dataclass
class AuditEvent:
    """
    A tamper-evident audit log entry for a tool call authorization decision.

    Each event is linked to the previous event via a hash chain, providing
    cryptographic proof of log integrity. Any modification to historical
    events will break the hash chain and be detectable.

    Attributes:
        event_id: Unique identifier for this event.
        timestamp: When the event occurred (UTC).
        sequence_number: Monotonically increasing counter for ordering.
        user_context: The user who initiated the tool call.
        agent_context: The agent that made the request (optional).
        tool_call: The tool call request details.
        authorization_result: The authorization decision.
        execution_result: Summary of tool execution (optional, no sensitive data).
        previous_hash: Hash of the previous event in the chain.
        event_hash: Hash of this event (computed after creation).

    Example:
        >>> event = AuditEvent(
        ...     user_context=user,
        ...     tool_call=request,
        ...     authorization_result=result,
        ...     sequence_number=1,
        ...     previous_hash="GENESIS"
        ... )
        >>> event.compute_hash()
    """
    user_context: UserContext
    tool_call: ToolCallRequest
    authorization_result: AuthorizationResult
    sequence_number: int
    previous_hash: str
    event_id: str = field(default_factory=_generate_event_id)
    timestamp: datetime = field(default_factory=_utc_now)
    agent_context: AgentContext | None = None
    execution_result: dict[str, Any] | None = None
    event_hash: str = ""

    def _canonical_json(self) -> str:
        """
        Generate canonical JSON representation for hashing.

        Uses sorted keys and consistent formatting to ensure the same
        data always produces the same hash.
        """
        data = {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "sequence_number": self.sequence_number,
            "user_context": self.user_context.to_dict(),
            "agent_context": self.agent_context.to_dict() if self.agent_context else None,
            "tool_call": self.tool_call.to_dict(),
            "authorization_result": self.authorization_result.to_dict(),
            "execution_result": self.execution_result,
            "previous_hash": self.previous_hash,
        }
        return json.dumps(data, sort_keys=True, separators=(",", ":"))

    def compute_hash(self) -> str:
        """
        Compute and set the event hash using SHA-256.

        Returns:
            The computed hash as a hex string prefixed with 'sha256:'.
        """
        canonical = self._canonical_json()
        hash_bytes = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        self.event_hash = f"sha256:{hash_bytes}"
        return self.event_hash

    def verify_hash(self) -> bool:
        """
        Verify that the stored hash matches the computed hash.

        Returns:
            True if the hash is valid, False if tampered.
        """
        if not self.event_hash:
            return False
        expected = self.compute_hash()
        # Restore the original hash since compute_hash modifies it
        current = self.event_hash
        self.event_hash = current
        return current == expected

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "sequence_number": self.sequence_number,
            "user_context": self.user_context.to_dict(),
            "agent_context": self.agent_context.to_dict() if self.agent_context else None,
            "tool_call": self.tool_call.to_dict(),
            "authorization_result": self.authorization_result.to_dict(),
            "execution_result": self.execution_result,
            "previous_hash": self.previous_hash,
            "event_hash": self.event_hash,
        }

    def to_json(self) -> str:
        """Convert to JSON string with canonical formatting."""
        return json.dumps(self.to_dict(), sort_keys=True, indent=2)
