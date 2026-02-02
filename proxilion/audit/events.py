"""
Audit event definitions for Proxilion.

This module provides enhanced audit event types with support for
UUID v7-style time-ordering, sensitive data redaction, and
canonical JSON serialization for hash chain integrity.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from re import Pattern
from typing import Any


class EventType(Enum):
    """Types of audit events."""
    AUTHORIZATION_REQUEST = "authorization_request"
    AUTHORIZATION_GRANTED = "authorization_granted"
    AUTHORIZATION_DENIED = "authorization_denied"
    TOOL_EXECUTION_START = "tool_execution_start"
    TOOL_EXECUTION_SUCCESS = "tool_execution_success"
    TOOL_EXECUTION_FAILURE = "tool_execution_failure"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    CIRCUIT_BREAKER_OPEN = "circuit_breaker_open"
    IDOR_VIOLATION = "idor_violation"
    SCHEMA_VALIDATION_FAILURE = "schema_validation_failure"


def _generate_uuid_v7() -> str:
    """
    Generate a UUID v7-style identifier for time-ordering.

    UUID v7 embeds a Unix timestamp for time-ordering while maintaining
    uniqueness. Since Python 3.10 doesn't have native UUID v7, we
    construct a compatible format manually.

    Format: xxxxxxxx-xxxx-7xxx-yxxx-xxxxxxxxxxxx
    Where x is derived from timestamp + random, 7 indicates version 7,
    and y is 8, 9, a, or b for variant 1.
    """
    # Get current timestamp in milliseconds
    timestamp_ms = int(time.time() * 1000)

    # Convert to 48-bit value (6 bytes)
    timestamp_bytes = timestamp_ms.to_bytes(6, byteorder='big')

    # Generate 10 random bytes
    random_bytes = os.urandom(10)

    # Combine: 6 bytes timestamp + 10 bytes random
    uuid_bytes = bytearray(16)
    uuid_bytes[0:6] = timestamp_bytes
    uuid_bytes[6:16] = random_bytes

    # Set version (4 bits) to 7: 0111xxxx at position 6
    uuid_bytes[6] = (uuid_bytes[6] & 0x0F) | 0x70

    # Set variant (2 bits) to RFC 4122: 10xxxxxx at position 8
    uuid_bytes[8] = (uuid_bytes[8] & 0x3F) | 0x80

    # Format as UUID string
    hex_str = uuid_bytes.hex()
    return f"{hex_str[:8]}-{hex_str[8:12]}-{hex_str[12:16]}-{hex_str[16:20]}-{hex_str[20:]}"


def _utc_now() -> datetime:
    """Get current UTC time with timezone info."""
    return datetime.now(timezone.utc)


# Global sequence counter (thread-safe via GIL for simple increments)
_sequence_counter = 0
_sequence_lock = None

def _next_sequence() -> int:
    """Get next sequence number (monotonically increasing)."""
    global _sequence_counter
    _sequence_counter += 1
    return _sequence_counter


def reset_sequence(value: int = 0) -> None:
    """Reset the sequence counter (for testing)."""
    global _sequence_counter
    _sequence_counter = value


@dataclass
class RedactionConfig:
    """
    Configuration for sensitive data redaction in audit logs.

    Attributes:
        patterns: Regex patterns to match sensitive data.
        field_names: Field names that should always be redacted.
        hash_pii: If True, hash PII instead of replacing with placeholder.
        placeholder: Replacement text for redacted values.
    """
    patterns: list[Pattern[str]] = field(default_factory=list)
    field_names: set[str] = field(default_factory=set)
    hash_pii: bool = False
    placeholder: str = "[REDACTED]"

    @classmethod
    def default(cls) -> RedactionConfig:
        """Create default redaction config with common patterns."""
        return cls(
            patterns=[
                re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),  # Email
                re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),  # SSN
                re.compile(r'\b\d{16}\b'),  # Credit card (simple)
                re.compile(
                    r'\b(?:password|passwd|pwd|secret|api_key|apikey|token)\s*[:=]\s*\S+',
                    re.IGNORECASE,
                ),
            ],
            field_names={
                "password", "passwd", "secret", "api_key", "apikey",
                "token", "access_token", "refresh_token", "private_key",
                "credit_card", "ssn", "social_security",
            },
            hash_pii=True,
        )


@dataclass
class AuditEventData:
    """
    Core data for an audit event, separate from hash chain fields.

    This separation allows for cleaner event creation before
    the event is added to a hash chain.
    """
    event_type: EventType
    user_id: str
    user_roles: list[str]
    session_id: str | None
    user_attributes: dict[str, Any]
    agent_id: str | None
    agent_capabilities: list[str]
    agent_trust_score: float | None
    tool_name: str
    tool_arguments: dict[str, Any]
    tool_timestamp: datetime
    authorization_allowed: bool
    authorization_reason: str | None
    policies_evaluated: list[str]
    authorization_metadata: dict[str, Any]
    execution_result: dict[str, Any] | None = None
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "event_type": self.event_type.value,
            "user": {
                "user_id": self.user_id,
                "roles": self.user_roles,
                "session_id": self.session_id,
                "attributes": self.user_attributes,
            },
            "agent": {
                "agent_id": self.agent_id,
                "capabilities": self.agent_capabilities,
                "trust_score": self.agent_trust_score,
            } if self.agent_id else None,
            "tool_call": {
                "tool_name": self.tool_name,
                "arguments": self.tool_arguments,
                "timestamp": self.tool_timestamp.isoformat(),
            },
            "authorization": {
                "allowed": self.authorization_allowed,
                "reason": self.authorization_reason,
                "policies_evaluated": self.policies_evaluated,
                "metadata": self.authorization_metadata,
            },
            "execution_result": self.execution_result,
            "error_message": self.error_message,
        }


@dataclass
class AuditEventV2:
    """
    Enhanced tamper-evident audit log entry.

    Improvements over the base AuditEvent:
    - UUID v7-style IDs for time-ordering
    - Event type categorization
    - Sensitive data redaction support
    - Improved canonical JSON serialization
    - Merkle tree integration support

    Attributes:
        event_id: UUID v7-style identifier for time-ordering.
        timestamp: When the event occurred (UTC, ISO format).
        sequence_number: Monotonically increasing counter.
        event_type: Categorization of the event.
        data: The core event data.
        previous_hash: Hash of the previous event in the chain.
        event_hash: SHA-256 hash of this event.
        merkle_index: Index in the current Merkle tree batch.
    """
    data: AuditEventData
    previous_hash: str
    event_id: str = field(default_factory=_generate_uuid_v7)
    timestamp: datetime = field(default_factory=_utc_now)
    sequence_number: int = field(default_factory=_next_sequence)
    event_hash: str = ""
    merkle_index: int | None = None

    def _canonical_dict(self) -> dict[str, Any]:
        """
        Create canonical dictionary for hashing.

        This ensures consistent ordering and formatting
        for reproducible hash computation.
        """
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "sequence_number": self.sequence_number,
            "data": self.data.to_dict(),
            "previous_hash": self.previous_hash,
        }

    def _canonical_json(self) -> str:
        """
        Generate canonical JSON representation for hashing.

        Uses sorted keys and minimal separators to ensure
        deterministic serialization.
        """
        return json.dumps(
            self._canonical_dict(),
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )

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

        # Store original hash
        stored_hash = self.event_hash

        # Compute expected hash (this sets self.event_hash)
        canonical = self._canonical_json()
        expected = f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"

        # Restore original
        self.event_hash = stored_hash

        return stored_hash == expected

    def to_dict(self, include_hash: bool = True) -> dict[str, Any]:
        """
        Convert to dictionary for serialization.

        Args:
            include_hash: Whether to include the event_hash field.
        """
        result = self._canonical_dict()
        if include_hash:
            result["event_hash"] = self.event_hash
        if self.merkle_index is not None:
            result["merkle_index"] = self.merkle_index
        return result

    def to_json(self, pretty: bool = False) -> str:
        """
        Convert to JSON string.

        Args:
            pretty: If True, use indented formatting.
        """
        if pretty:
            return json.dumps(self.to_dict(), sort_keys=True, indent=2, default=str)
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"), default=str)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditEventV2:
        """
        Create an AuditEventV2 from a dictionary.

        Args:
            data: Dictionary representation of the event.

        Returns:
            Reconstructed AuditEventV2 instance.
        """
        event_data = AuditEventData(
            event_type=EventType(data["data"]["event_type"]),
            user_id=data["data"]["user"]["user_id"],
            user_roles=data["data"]["user"]["roles"],
            session_id=data["data"]["user"]["session_id"],
            user_attributes=data["data"]["user"]["attributes"],
            agent_id=(
                data["data"]["agent"]["agent_id"] if data["data"]["agent"] else None
            ),
            agent_capabilities=(
                data["data"]["agent"]["capabilities"] if data["data"]["agent"] else []
            ),
            agent_trust_score=(
                data["data"]["agent"]["trust_score"] if data["data"]["agent"] else None
            ),
            tool_name=data["data"]["tool_call"]["tool_name"],
            tool_arguments=data["data"]["tool_call"]["arguments"],
            tool_timestamp=datetime.fromisoformat(data["data"]["tool_call"]["timestamp"]),
            authorization_allowed=data["data"]["authorization"]["allowed"],
            authorization_reason=data["data"]["authorization"]["reason"],
            policies_evaluated=data["data"]["authorization"]["policies_evaluated"],
            authorization_metadata=data["data"]["authorization"]["metadata"],
            execution_result=data["data"]["execution_result"],
            error_message=data["data"]["error_message"],
        )

        event = cls(
            data=event_data,
            previous_hash=data["previous_hash"],
            event_id=data["event_id"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            sequence_number=data["sequence_number"],
            event_hash=data.get("event_hash", ""),
            merkle_index=data.get("merkle_index"),
        )

        return event


def redact_sensitive_data(
    data: dict[str, Any],
    config: RedactionConfig,
) -> dict[str, Any]:
    """
    Redact sensitive data from a dictionary.

    Args:
        data: Dictionary to redact.
        config: Redaction configuration.

    Returns:
        New dictionary with sensitive data redacted.
    """
    result = {}

    for key, value in data.items():
        # Check if field name should be redacted
        if key.lower() in config.field_names:
            if config.hash_pii and isinstance(value, str):
                result[key] = f"[HASH:{hashlib.sha256(value.encode()).hexdigest()[:16]}]"
            else:
                result[key] = config.placeholder
            continue

        # Recursively handle nested dicts
        if isinstance(value, dict):
            result[key] = redact_sensitive_data(value, config)
            continue

        # Recursively handle lists
        if isinstance(value, list):
            result[key] = [
                redact_sensitive_data(item, config) if isinstance(item, dict)
                else _redact_string(item, config) if isinstance(item, str)
                else item
                for item in value
            ]
            continue

        # Check string values against patterns
        if isinstance(value, str):
            result[key] = _redact_string(value, config)
            continue

        result[key] = value

    return result


def _redact_string(value: str, config: RedactionConfig) -> str:
    """Redact sensitive patterns from a string."""
    result = value
    for pattern in config.patterns:
        if config.hash_pii:
            # Replace each match with a hash of the matched value
            def hash_replace(match: re.Match[str]) -> str:
                return f"[HASH:{hashlib.sha256(match.group().encode()).hexdigest()[:16]}]"
            result = pattern.sub(hash_replace, result)
        else:
            result = pattern.sub(config.placeholder, result)
    return result


def create_authorization_event(
    user_id: str,
    user_roles: list[str],
    tool_name: str,
    tool_arguments: dict[str, Any],
    allowed: bool,
    reason: str | None = None,
    policies_evaluated: list[str] | None = None,
    session_id: str | None = None,
    user_attributes: dict[str, Any] | None = None,
    agent_id: str | None = None,
    agent_capabilities: list[str] | None = None,
    agent_trust_score: float | None = None,
    previous_hash: str = "GENESIS",
    redaction_config: RedactionConfig | None = None,
) -> AuditEventV2:
    """
    Factory function to create an authorization audit event.

    This provides a convenient way to create events with minimal
    boilerplate while ensuring all required fields are set.

    Args:
        user_id: The user's identifier.
        user_roles: List of user roles.
        tool_name: Name of the tool being called.
        tool_arguments: Arguments passed to the tool.
        allowed: Whether authorization was granted.
        reason: Explanation for the decision.
        policies_evaluated: List of policies that were checked.
        session_id: Optional session identifier.
        user_attributes: Optional user attributes.
        agent_id: Optional agent identifier.
        agent_capabilities: Optional agent capabilities.
        agent_trust_score: Optional agent trust score.
        previous_hash: Hash of previous event in chain.
        redaction_config: Optional config for sensitive data redaction.

    Returns:
        A new AuditEventV2 instance.
    """
    # Apply redaction if configured
    if redaction_config:
        tool_arguments = redact_sensitive_data(tool_arguments, redaction_config)
        if user_attributes:
            user_attributes = redact_sensitive_data(user_attributes, redaction_config)

    event_type = (
        EventType.AUTHORIZATION_GRANTED if allowed
        else EventType.AUTHORIZATION_DENIED
    )

    data = AuditEventData(
        event_type=event_type,
        user_id=user_id,
        user_roles=user_roles,
        session_id=session_id,
        user_attributes=user_attributes or {},
        agent_id=agent_id,
        agent_capabilities=agent_capabilities or [],
        agent_trust_score=agent_trust_score,
        tool_name=tool_name,
        tool_arguments=tool_arguments,
        tool_timestamp=_utc_now(),
        authorization_allowed=allowed,
        authorization_reason=reason,
        policies_evaluated=policies_evaluated or [],
        authorization_metadata={},
    )

    return AuditEventV2(data=data, previous_hash=previous_hash)
