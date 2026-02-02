"""
Audit logger implementation for Proxilion.

This module provides the main AuditLogger class for writing
tamper-evident audit logs with features like:

- Structured JSON logging
- Hash chain integration
- Log rotation
- Sensitive data redaction
- Thread-safe operation
"""

from __future__ import annotations

import gzip
import json
import logging
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, TextIO

from proxilion.audit.events import (
    AuditEventData,
    AuditEventV2,
    EventType,
    RedactionConfig,
    redact_sensitive_data,
)
from proxilion.audit.hash_chain import (
    BatchedHashChain,
)

logger = logging.getLogger(__name__)


class RotationPolicy(Enum):
    """Log rotation policies."""
    NONE = "none"
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    SIZE = "size"


@dataclass
class LoggerConfig:
    """
    Configuration for the audit logger.

    Attributes:
        log_path: Path to the log file.
        rotation: Rotation policy.
        max_size_mb: Max file size for SIZE rotation.
        compress_rotated: Whether to gzip rotated files.
        batch_size: Events per Merkle batch.
        redaction_config: Config for sensitive data redaction.
        sync_writes: If True, flush after each write.
    """
    log_path: Path
    rotation: RotationPolicy = RotationPolicy.DAILY
    max_size_mb: float = 100.0
    compress_rotated: bool = True
    batch_size: int = 100
    redaction_config: RedactionConfig | None = None
    sync_writes: bool = True

    @classmethod
    def default(cls, log_path: str | Path) -> LoggerConfig:
        """Create default configuration."""
        return cls(
            log_path=Path(log_path),
            rotation=RotationPolicy.DAILY,
            redaction_config=RedactionConfig.default(),
        )


class AuditLogger:
    """
    Structured audit logger with tamper-evident hash chains.

    The AuditLogger writes audit events to JSON Lines files with
    cryptographic hash chaining. Each event links to the previous
    event's hash, making any tampering detectable.

    Features:
        - JSON Lines format for easy parsing
        - Hash chain for tamper evidence
        - Optional Merkle tree batching
        - Log rotation (hourly, daily, weekly, or by size)
        - Sensitive data redaction
        - Thread-safe operation

    Example:
        >>> config = LoggerConfig.default("./audit/events.jsonl")
        >>> logger = AuditLogger(config)
        >>>
        >>> event = create_authorization_event(
        ...     user_id="user_123",
        ...     user_roles=["analyst"],
        ...     tool_name="database_query",
        ...     tool_arguments={"query": "SELECT *"},
        ...     allowed=True,
        ... )
        >>> logger.log(event)
        >>>
        >>> # Verify log integrity
        >>> result = logger.verify()
        >>> print(result.valid)
    """

    def __init__(self, config: LoggerConfig) -> None:
        """
        Initialize the audit logger.

        Args:
            config: Logger configuration.
        """
        self.config = config
        self._chain = BatchedHashChain(batch_size=config.batch_size)
        self._lock = threading.RLock()
        self._file: TextIO | None = None
        self._current_file_path: Path | None = None
        self._last_rotation_check: datetime | None = None

        # Ensure directory exists
        config.log_path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def chain(self) -> BatchedHashChain:
        """Get the underlying hash chain."""
        return self._chain

    def log(self, event: AuditEventV2) -> AuditEventV2:
        """
        Log an audit event.

        The event is added to the hash chain and written to the log file.
        Sensitive data is redacted according to the configuration.

        Args:
            event: The event to log.

        Returns:
            The logged event with computed hash.
        """
        with self._lock:
            # Check if rotation is needed
            self._maybe_rotate()

            # Apply redaction if configured
            if self.config.redaction_config:
                event = self._redact_event(event)

            # Add to hash chain (computes hash)
            event = self._chain.append(event)

            # Write to file
            self._ensure_file_open()
            self._write_event(event)

            return event

    def log_authorization(
        self,
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
        execution_result: dict[str, Any] | None = None,
    ) -> AuditEventV2:
        """
        Log an authorization decision.

        Convenience method that creates and logs an authorization event.

        Args:
            user_id: The user's identifier.
            user_roles: List of user roles.
            tool_name: Name of the tool being called.
            tool_arguments: Arguments passed to the tool.
            allowed: Whether authorization was granted.
            reason: Explanation for the decision.
            policies_evaluated: List of policies checked.
            session_id: Optional session identifier.
            user_attributes: Optional user attributes.
            agent_id: Optional agent identifier.
            agent_capabilities: Optional agent capabilities.
            agent_trust_score: Optional agent trust score.
            execution_result: Optional execution result summary.

        Returns:
            The logged event.
        """
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
            tool_timestamp=datetime.now(timezone.utc),
            authorization_allowed=allowed,
            authorization_reason=reason,
            policies_evaluated=policies_evaluated or [],
            authorization_metadata={},
            execution_result=execution_result,
        )

        event = AuditEventV2(
            data=data,
            previous_hash=self._chain.chain.last_hash,
        )

        return self.log(event)

    def verify(self) -> Any:
        """
        Verify the integrity of the audit log.

        Returns:
            ChainVerificationResult from the hash chain.
        """
        with self._lock:
            return self._chain.chain.verify()

    def finalize_batch(self) -> Any:
        """
        Finalize the current Merkle batch.

        Returns:
            The finalized MerkleBatch, or None if empty.
        """
        with self._lock:
            batch = self._chain.finalize_batch()
            if batch:
                # Write batch marker to log
                self._write_batch_marker(batch)
            return batch

    def close(self) -> None:
        """Close the log file and finalize any pending batch."""
        with self._lock:
            self.finalize_batch()
            if self._file:
                self._file.close()
                self._file = None
                self._current_file_path = None

    def flush(self) -> None:
        """Flush buffered writes to disk."""
        with self._lock:
            if self._file:
                self._file.flush()
                os.fsync(self._file.fileno())

    def _ensure_file_open(self) -> None:
        """Ensure the log file is open."""
        target_path = self._get_current_file_path()

        if self._file is None or self._current_file_path != target_path:
            if self._file:
                self._file.close()

            self._current_file_path = target_path
            self._file = open(target_path, "a", encoding="utf-8")

    def _get_current_file_path(self) -> Path:
        """Get the current log file path based on rotation policy."""
        base_path = self.config.log_path
        now = datetime.now(timezone.utc)

        if self.config.rotation == RotationPolicy.NONE:
            return base_path

        if self.config.rotation == RotationPolicy.HOURLY:
            suffix = now.strftime("%Y%m%d_%H")
        elif self.config.rotation == RotationPolicy.DAILY:
            suffix = now.strftime("%Y%m%d")
        elif self.config.rotation == RotationPolicy.WEEKLY:
            suffix = now.strftime("%Y_W%W")
        else:  # SIZE - keep same path, check size separately
            return base_path

        # Insert suffix before extension
        stem = base_path.stem
        ext = base_path.suffix
        return base_path.parent / f"{stem}_{suffix}{ext}"

    def _maybe_rotate(self) -> None:
        """Check if log rotation is needed."""
        if self.config.rotation == RotationPolicy.NONE:
            return

        if self.config.rotation == RotationPolicy.SIZE:
            self._maybe_rotate_by_size()
        else:
            # Time-based rotation is handled by _get_current_file_path
            pass

    def _maybe_rotate_by_size(self) -> None:
        """Rotate log if it exceeds max size."""
        if self._current_file_path is None:
            return

        if not self._current_file_path.exists():
            return

        size_mb = self._current_file_path.stat().st_size / (1024 * 1024)
        if size_mb >= self.config.max_size_mb:
            self._rotate_current_file()

    def _rotate_current_file(self) -> None:
        """Rotate the current log file."""
        if self._file:
            self._file.close()
            self._file = None

        if self._current_file_path and self._current_file_path.exists():
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            rotated_path = self._current_file_path.with_suffix(
                f".{timestamp}{self._current_file_path.suffix}"
            )
            self._current_file_path.rename(rotated_path)

            if self.config.compress_rotated:
                self._compress_file(rotated_path)

        self._current_file_path = None

    def _compress_file(self, path: Path) -> None:
        """Compress a log file with gzip."""
        gz_path = path.with_suffix(path.suffix + ".gz")
        with open(path, "rb") as f_in, gzip.open(gz_path, "wb") as f_out:
            f_out.writelines(f_in)
        path.unlink()

    def _write_event(self, event: AuditEventV2) -> None:
        """Write an event to the log file."""
        if self._file is None:
            return

        line = event.to_json(pretty=False) + "\n"
        self._file.write(line)

        if self.config.sync_writes:
            self._file.flush()

    def _write_batch_marker(self, batch: Any) -> None:
        """Write a batch marker to the log file."""
        if self._file is None:
            return

        marker = {
            "_type": "batch_marker",
            "batch": batch.to_dict(),
        }
        line = json.dumps(marker, sort_keys=True) + "\n"
        self._file.write(line)

        if self.config.sync_writes:
            self._file.flush()

    def _redact_event(self, event: AuditEventV2) -> AuditEventV2:
        """Apply redaction to an event's sensitive data."""
        if not self.config.redaction_config:
            return event

        # Redact tool arguments
        redacted_args = redact_sensitive_data(
            event.data.tool_arguments,
            self.config.redaction_config,
        )

        # Redact user attributes
        redacted_attrs = redact_sensitive_data(
            event.data.user_attributes,
            self.config.redaction_config,
        )

        # Redact execution result if present
        redacted_result = None
        if event.data.execution_result:
            redacted_result = redact_sensitive_data(
                event.data.execution_result,
                self.config.redaction_config,
            )

        # Create new event data with redacted values
        new_data = AuditEventData(
            event_type=event.data.event_type,
            user_id=event.data.user_id,
            user_roles=event.data.user_roles,
            session_id=event.data.session_id,
            user_attributes=redacted_attrs,
            agent_id=event.data.agent_id,
            agent_capabilities=event.data.agent_capabilities,
            agent_trust_score=event.data.agent_trust_score,
            tool_name=event.data.tool_name,
            tool_arguments=redacted_args,
            tool_timestamp=event.data.tool_timestamp,
            authorization_allowed=event.data.authorization_allowed,
            authorization_reason=event.data.authorization_reason,
            policies_evaluated=event.data.policies_evaluated,
            authorization_metadata=event.data.authorization_metadata,
            execution_result=redacted_result,
            error_message=event.data.error_message,
        )

        return AuditEventV2(
            data=new_data,
            previous_hash=event.previous_hash,
            event_id=event.event_id,
            timestamp=event.timestamp,
            sequence_number=event.sequence_number,
        )

    def __enter__(self) -> AuditLogger:
        """Context manager entry."""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit."""
        self.close()


class InMemoryAuditLogger:
    """
    In-memory audit logger for testing and development.

    Stores events in memory instead of writing to disk.
    Useful for unit tests and development environments.

    Example:
        >>> logger = InMemoryAuditLogger()
        >>> event = logger.log_authorization(...)
        >>> assert len(logger.events) == 1
    """

    def __init__(
        self,
        batch_size: int = 100,
        redaction_config: RedactionConfig | None = None,
    ) -> None:
        """Initialize the in-memory logger."""
        self._chain = BatchedHashChain(batch_size=batch_size)
        self._events: list[AuditEventV2] = []
        self._redaction_config = redaction_config
        self._lock = threading.RLock()

    @property
    def events(self) -> list[AuditEventV2]:
        """Get all logged events."""
        with self._lock:
            return list(self._events)

    @property
    def chain(self) -> BatchedHashChain:
        """Get the underlying hash chain."""
        return self._chain

    def log(self, event: AuditEventV2) -> AuditEventV2:
        """Log an audit event."""
        with self._lock:
            event = self._chain.append(event)
            self._events.append(event)
            return event

    def log_authorization(
        self,
        user_id: str,
        user_roles: list[str],
        tool_name: str,
        tool_arguments: dict[str, Any],
        allowed: bool,
        reason: str | None = None,
        policies_evaluated: list[str] | None = None,
        **kwargs: Any,
    ) -> AuditEventV2:
        """Log an authorization decision."""
        event_type = (
            EventType.AUTHORIZATION_GRANTED if allowed
            else EventType.AUTHORIZATION_DENIED
        )

        data = AuditEventData(
            event_type=event_type,
            user_id=user_id,
            user_roles=user_roles,
            session_id=kwargs.get("session_id"),
            user_attributes=kwargs.get("user_attributes", {}),
            agent_id=kwargs.get("agent_id"),
            agent_capabilities=kwargs.get("agent_capabilities", []),
            agent_trust_score=kwargs.get("agent_trust_score"),
            tool_name=tool_name,
            tool_arguments=tool_arguments,
            tool_timestamp=datetime.now(timezone.utc),
            authorization_allowed=allowed,
            authorization_reason=reason,
            policies_evaluated=policies_evaluated or [],
            authorization_metadata={},
            execution_result=kwargs.get("execution_result"),
        )

        event = AuditEventV2(
            data=data,
            previous_hash=self._chain.chain.last_hash,
        )

        return self.log(event)

    def verify(self) -> Any:
        """Verify the integrity of the audit log."""
        return self._chain.chain.verify()

    def clear(self) -> None:
        """Clear all events."""
        with self._lock:
            self._events.clear()
            self._chain = BatchedHashChain(
                batch_size=self._chain._batch_size
            )
