"""
Audit logging module for Proxilion.

This module provides tamper-evident audit logging with hash chains
and Merkle trees for cryptographic integrity verification.

Features:
    - Hash-chained audit events for tamper detection
    - Merkle tree batching for efficient verification
    - Multiple export formats (JSON Lines, console, streams)
    - Sensitive data redaction
    - Log rotation support

Quick Start:
    >>> from proxilion.audit import (
    ...     AuditLogger,
    ...     LoggerConfig,
    ...     ConsoleExporter,
    ... )
    >>>
    >>> # Create a logger
    >>> config = LoggerConfig.default("./audit/events.jsonl")
    >>> logger = AuditLogger(config)
    >>>
    >>> # Log an authorization decision
    >>> event = logger.log_authorization(
    ...     user_id="user_123",
    ...     user_roles=["analyst"],
    ...     tool_name="database_query",
    ...     tool_arguments={"query": "SELECT *"},
    ...     allowed=True,
    ...     reason="User has analyst role",
    ... )
    >>>
    >>> # Verify log integrity
    >>> result = logger.verify()
    >>> print(result.valid)  # True if chain is intact
"""

from proxilion.audit.base_exporters import (
    CallbackExporter,
    ConsoleExporter,
    Exporter,
    FileExporter,
    MultiExporter,
    StreamExporter,
    read_jsonl_events,
    verify_jsonl_chain,
)
from proxilion.audit.events import (
    AuditEventData,
    AuditEventV2,
    EventType,
    RedactionConfig,
    create_authorization_event,
    redact_sensitive_data,
    reset_sequence,
)

# Explainability (CA SB 53 compliance)
from proxilion.audit.explainability import (
    DecisionExplainer,
    DecisionFactor,
    DecisionType,
    ExplainabilityLogger,
    ExplainableDecision,
    Explanation,
    ExplanationFormat,
    Outcome,
    create_authorization_decision,
    create_budget_decision,
    create_guard_decision,
    create_rate_limit_decision,
)
from proxilion.audit.hash_chain import (
    GENESIS_HASH,
    BatchedHashChain,
    ChainVerificationResult,
    HashChain,
    MerkleBatch,
    MerkleTree,
)
from proxilion.audit.logger import (
    AuditLogger,
    InMemoryAuditLogger,
    LoggerConfig,
    RotationPolicy,
)

__all__ = [
    # Events
    "AuditEventData",
    "AuditEventV2",
    "EventType",
    "RedactionConfig",
    "create_authorization_event",
    "redact_sensitive_data",
    "reset_sequence",
    # Hash chain
    "BatchedHashChain",
    "ChainVerificationResult",
    "GENESIS_HASH",
    "HashChain",
    "MerkleBatch",
    "MerkleTree",
    # Logger
    "AuditLogger",
    "InMemoryAuditLogger",
    "LoggerConfig",
    "RotationPolicy",
    # Exporters
    "CallbackExporter",
    "ConsoleExporter",
    "Exporter",
    "FileExporter",
    "MultiExporter",
    "StreamExporter",
    "read_jsonl_events",
    "verify_jsonl_chain",
    # Explainability (CA SB 53 compliance)
    "DecisionExplainer",
    "DecisionFactor",
    "DecisionType",
    "ExplainableDecision",
    "ExplainabilityLogger",
    "Explanation",
    "ExplanationFormat",
    "Outcome",
    "create_authorization_decision",
    "create_budget_decision",
    "create_guard_decision",
    "create_rate_limit_decision",
]
