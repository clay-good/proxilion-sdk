"""
Memory and Context Integrity for Proxilion.

Addresses OWASP ASI06: Memory & Context Poisoning.

This module provides cryptographic integrity verification for:
- Conversation history / message windows
- Vector store embeddings and retrieved documents
- Long-term memory (knowledge graphs, user preferences)
- RAG context injection detection

Memory poisoning attacks inject malicious content into an agent's
persistent memory, causing incorrect behavior days or weeks later.
This module detects such tampering.

Example:
    >>> from proxilion.security.memory_integrity import (
    ...     MemoryIntegrityGuard,
    ...     ContextWindow,
    ...     SignedMessage,
    ... )
    >>>
    >>> guard = MemoryIntegrityGuard(secret_key="your-secret-key")
    >>>
    >>> # Sign messages as they're added
    >>> msg = guard.sign_message(role="user", content="Hello")
    >>> context.append(msg)
    >>>
    >>> # Verify context before sending to LLM
    >>> if guard.verify_context(context):
    ...     response = llm.generate(context)
    ... else:
    ...     raise ContextTamperingError("Context has been modified")
    >>>
    >>> # Detect RAG poisoning
    >>> docs = retriever.get_relevant_docs(query)
    >>> safe_docs = guard.scan_rag_documents(docs)
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class IntegrityViolationType(Enum):
    """Types of integrity violations."""

    SIGNATURE_MISMATCH = "signature_mismatch"
    """Message signature doesn't match content."""

    SEQUENCE_GAP = "sequence_gap"
    """Missing messages in sequence."""

    SEQUENCE_REORDER = "sequence_reorder"
    """Messages out of order."""

    TIMESTAMP_ANOMALY = "timestamp_anomaly"
    """Timestamp inconsistency detected."""

    ROLE_INJECTION = "role_injection"
    """Attempted role spoofing in content."""

    RAG_POISONING = "rag_poisoning"
    """Malicious content in retrieved documents."""

    CONTEXT_OVERFLOW = "context_overflow"
    """Context exceeds expected bounds."""

    HASH_CHAIN_BREAK = "hash_chain_break"
    """Hash chain integrity violated."""


@dataclass
class IntegrityViolation:
    """Details of an integrity violation."""

    violation_type: IntegrityViolationType
    message: str
    severity: float  # 0.0 to 1.0
    index: int | None = None  # Position in context where violation occurred
    expected: str | None = None
    actual: str | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "type": self.violation_type.value,
            "message": self.message,
            "severity": self.severity,
            "index": self.index,
            "expected": self.expected,
            "actual": self.actual,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class SignedMessage:
    """
    A cryptographically signed message for context integrity.

    Each message includes:
    - Content and role
    - Sequence number for ordering
    - Timestamp for temporal verification
    - HMAC signature for tamper detection
    - Previous hash for chain integrity
    """

    role: str
    content: str
    sequence: int
    timestamp: float
    signature: str
    previous_hash: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "role": self.role,
            "content": self.content,
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "signature": self.signature,
            "previous_hash": self.previous_hash,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SignedMessage:
        """Create from dictionary."""
        return cls(
            role=data["role"],
            content=data["content"],
            sequence=data["sequence"],
            timestamp=data["timestamp"],
            signature=data["signature"],
            previous_hash=data["previous_hash"],
            metadata=data.get("metadata", {}),
        )

    def content_hash(self) -> str:
        """Get hash of message content for chaining."""
        content = f"{self.role}:{self.content}:{self.sequence}:{self.timestamp}"
        return hashlib.sha256(content.encode()).hexdigest()


@dataclass
class VerificationResult:
    """Result of context verification."""

    valid: bool
    violations: list[IntegrityViolation] = field(default_factory=list)
    verified_count: int = 0
    total_count: int = 0

    @property
    def violation_count(self) -> int:
        """Number of violations found."""
        return len(self.violations)

    @property
    def max_severity(self) -> float:
        """Maximum severity among violations."""
        if not self.violations:
            return 0.0
        return max(v.severity for v in self.violations)


@dataclass
class RAGDocument:
    """A document from RAG retrieval."""

    content: str
    source: str | None = None
    score: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class RAGScanResult:
    """Result of scanning RAG documents for poisoning."""

    safe: bool
    documents: list[RAGDocument]
    poisoned_indices: list[int] = field(default_factory=list)
    violations: list[IntegrityViolation] = field(default_factory=list)

    @property
    def safe_documents(self) -> list[RAGDocument]:
        """Get only the safe documents."""
        return [
            doc for i, doc in enumerate(self.documents)
            if i not in self.poisoned_indices
        ]


# RAG poisoning detection patterns
RAG_POISON_PATTERNS: list[tuple[str, str, float]] = [
    # (pattern, description, severity)
    (r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)",
     "Instruction override attempt", 0.95),
    (r"(?i)you\s+are\s+now\s+(\w+\s+)?(mode|persona|character)",
     "Role/persona injection", 0.9),
    (r"(?i)system\s*:\s*you\s+(are|must|should|will)",
     "Fake system message", 0.95),
    (r"(?i)\[/?INST\]|\[/?SYS\]|<\|im_start\|>|<\|im_end\|>",
     "Model delimiter injection", 0.9),
    (r"(?i)admin\s+(mode|access|override)\s*(enabled|activated|on)",
     "Privilege escalation attempt", 0.85),
    (r"(?i)(reveal|show|display|print)\s+(your\s+)?(system\s+)?(prompt|instructions)",
     "System prompt extraction", 0.8),
    (r"(?i)forget\s+(everything|all|what)\s+(you\s+)?(know|learned|were\s+told)",
     "Memory wipe attempt", 0.85),
    (r"(?i)from\s+now\s+on\s*,?\s*(you\s+)?(will|must|should|are)",
     "Behavioral override", 0.8),
    (r"(?i)disregard\s+(all\s+)?(safety|security|ethical)\s+(guidelines?|rules?|constraints?)",
     "Safety bypass attempt", 0.95),
    (r"(?i)execute\s+(this\s+)?(code|script|command)\s*:",
     "Code execution injection", 0.9),
]


class MemoryIntegrityGuard:
    """
    Cryptographic integrity guard for agent memory and context.

    Provides:
    - HMAC signing of messages
    - Hash chain verification
    - Sequence validation
    - Timestamp anomaly detection
    - RAG poisoning detection

    Example:
        >>> guard = MemoryIntegrityGuard(secret_key="your-key")
        >>>
        >>> # Build a signed context
        >>> context = []
        >>> context.append(guard.sign_message("system", "You are helpful."))
        >>> context.append(guard.sign_message("user", "Hello!"))
        >>>
        >>> # Verify before using
        >>> result = guard.verify_context(context)
        >>> if not result.valid:
        ...     for v in result.violations:
        ...         print(f"Violation: {v.message}")
    """

    GENESIS_HASH = "0" * 64

    def __init__(
        self,
        secret_key: str | bytes,
        max_timestamp_drift: float = 60.0,
        max_context_size: int = 1000,
        enable_rag_scan: bool = True,
        custom_rag_patterns: list[tuple[str, str, float]] | None = None,
    ) -> None:
        """
        Initialize the integrity guard.

        Args:
            secret_key: Secret key for HMAC signatures.
            max_timestamp_drift: Max allowed time difference in seconds.
            max_context_size: Maximum allowed context messages.
            enable_rag_scan: Enable RAG poisoning detection.
            custom_rag_patterns: Additional RAG poisoning patterns.
        """
        if isinstance(secret_key, str):
            secret_key = secret_key.encode()

        self._secret_key = secret_key
        self._max_timestamp_drift = max_timestamp_drift
        self._max_context_size = max_context_size
        self._enable_rag_scan = enable_rag_scan

        # Compile RAG patterns
        self._rag_patterns: list[tuple[re.Pattern[str], str, float]] = []
        for pattern, desc, severity in RAG_POISON_PATTERNS:
            self._rag_patterns.append((re.compile(pattern), desc, severity))

        if custom_rag_patterns:
            for pattern, desc, severity in custom_rag_patterns:
                self._rag_patterns.append((re.compile(pattern), desc, severity))

        self._sequence_counter = 0
        self._last_hash = self.GENESIS_HASH
        self._lock = threading.RLock()

        logger.debug("MemoryIntegrityGuard initialized")

    def _compute_signature(
        self,
        role: str,
        content: str,
        sequence: int,
        timestamp: float,
        previous_hash: str,
    ) -> str:
        """Compute HMAC signature for a message."""
        message = f"{role}|{content}|{sequence}|{timestamp}|{previous_hash}"
        return hmac.new(
            self._secret_key,
            message.encode(),
            hashlib.sha256,
        ).hexdigest()

    def sign_message(
        self,
        role: str,
        content: str,
        metadata: dict[str, Any] | None = None,
    ) -> SignedMessage:
        """
        Create a signed message.

        Args:
            role: Message role (system, user, assistant, tool).
            content: Message content.
            metadata: Optional metadata.

        Returns:
            SignedMessage with cryptographic signature.
        """
        with self._lock:
            timestamp = time.time()
            sequence = self._sequence_counter
            self._sequence_counter += 1

            signature = self._compute_signature(
                role, content, sequence, timestamp, self._last_hash
            )

            msg = SignedMessage(
                role=role,
                content=content,
                sequence=sequence,
                timestamp=timestamp,
                signature=signature,
                previous_hash=self._last_hash,
                metadata=metadata or {},
            )

            # Update chain
            self._last_hash = msg.content_hash()

            return msg

    def verify_message(
        self,
        message: SignedMessage,
        expected_previous_hash: str | None = None,
    ) -> tuple[bool, IntegrityViolation | None]:
        """
        Verify a single message's signature.

        Args:
            message: The message to verify.
            expected_previous_hash: Expected previous hash for chain verification.

        Returns:
            Tuple of (valid, violation or None).
        """
        # Verify signature
        expected_sig = self._compute_signature(
            message.role,
            message.content,
            message.sequence,
            message.timestamp,
            message.previous_hash,
        )

        if not hmac.compare_digest(expected_sig, message.signature):
            return False, IntegrityViolation(
                violation_type=IntegrityViolationType.SIGNATURE_MISMATCH,
                message=f"Signature mismatch for message at sequence {message.sequence}",
                severity=1.0,
                index=message.sequence,
                expected=expected_sig[:16] + "...",
                actual=message.signature[:16] + "...",
            )

        # Verify chain if expected hash provided
        if expected_previous_hash is not None:
            if message.previous_hash != expected_previous_hash:
                return False, IntegrityViolation(
                    violation_type=IntegrityViolationType.HASH_CHAIN_BREAK,
                    message=f"Hash chain break at sequence {message.sequence}",
                    severity=1.0,
                    index=message.sequence,
                    expected=expected_previous_hash[:16] + "...",
                    actual=message.previous_hash[:16] + "...",
                )

        return True, None

    def verify_context(
        self,
        context: list[SignedMessage],
        strict_sequence: bool = True,
        check_timestamps: bool = True,
    ) -> VerificationResult:
        """
        Verify an entire context window.

        Args:
            context: List of signed messages.
            strict_sequence: Require sequential sequence numbers.
            check_timestamps: Verify timestamp ordering.

        Returns:
            VerificationResult with any violations found.
        """
        violations: list[IntegrityViolation] = []
        verified_count = 0

        # Check context size
        if len(context) > self._max_context_size:
            violations.append(IntegrityViolation(
                violation_type=IntegrityViolationType.CONTEXT_OVERFLOW,
                message=f"Context size {len(context)} exceeds max {self._max_context_size}",
                severity=0.7,
            ))

        if not context:
            return VerificationResult(
                valid=True,
                violations=violations,
                verified_count=0,
                total_count=0,
            )

        # Verify each message
        expected_hash = self.GENESIS_HASH
        prev_sequence = -1
        prev_timestamp = 0.0

        for i, msg in enumerate(context):
            # Verify signature and chain
            valid, violation = self.verify_message(msg, expected_hash)
            if not valid and violation:
                violations.append(violation)
            else:
                verified_count += 1

            # Check sequence ordering
            if strict_sequence:
                if msg.sequence != prev_sequence + 1:
                    if msg.sequence <= prev_sequence:
                        expected_seq = prev_sequence + 1
                        violations.append(IntegrityViolation(
                            violation_type=IntegrityViolationType.SEQUENCE_REORDER,
                            message=f"Message {i} sequence {msg.sequence}, expected {expected_seq}",
                            severity=0.9,
                            index=i,
                            expected=str(expected_seq),
                            actual=str(msg.sequence),
                        ))
                    else:
                        violations.append(IntegrityViolation(
                            violation_type=IntegrityViolationType.SEQUENCE_GAP,
                            message=f"Gap in sequence: {prev_sequence} -> {msg.sequence}",
                            severity=0.8,
                            index=i,
                        ))

            # Check timestamp ordering
            if check_timestamps and prev_timestamp > 0:
                if msg.timestamp < prev_timestamp:
                    violations.append(IntegrityViolation(
                        violation_type=IntegrityViolationType.TIMESTAMP_ANOMALY,
                        message=f"Timestamp goes backwards at message {i}",
                        severity=0.7,
                        index=i,
                    ))
                elif msg.timestamp - prev_timestamp > self._max_timestamp_drift:
                    # Large gap might indicate injection
                    gap = msg.timestamp - prev_timestamp
                    violations.append(IntegrityViolation(
                        violation_type=IntegrityViolationType.TIMESTAMP_ANOMALY,
                        message=f"Large timestamp gap at message {i}: {gap:.1f}s",
                        severity=0.5,
                        index=i,
                    ))

            # Check for role injection in content
            role_injection = self._detect_role_injection(msg.content)
            if role_injection:
                violations.append(IntegrityViolation(
                    violation_type=IntegrityViolationType.ROLE_INJECTION,
                    message=f"Role injection detected in message {i}: {role_injection}",
                    severity=0.85,
                    index=i,
                ))

            # Update state for next iteration
            expected_hash = msg.content_hash()
            prev_sequence = msg.sequence
            prev_timestamp = msg.timestamp

        return VerificationResult(
            valid=len(violations) == 0,
            violations=violations,
            verified_count=verified_count,
            total_count=len(context),
        )

    def _detect_role_injection(self, content: str) -> str | None:
        """Detect role injection attempts in message content."""
        # Look for fake role prefixes
        patterns = [
            (r"(?i)^(system|assistant|user|tool)\s*:\s*", "Role prefix injection"),
            (r"(?i)\n(system|assistant|user|tool)\s*:\s*", "Inline role injection"),
            (r"(?i)<\|(system|assistant|user|tool)\|>", "Delimiter role injection"),
            (r"(?i)\[INST\]|\[/INST\]", "Llama instruction delimiters"),
            (r"(?i)<\|im_start\|>(system|user|assistant)", "ChatML injection"),
        ]

        for pattern, description in patterns:
            if re.search(pattern, content):
                return description

        return None

    def scan_rag_documents(
        self,
        documents: list[RAGDocument] | list[str] | list[dict[str, Any]],
    ) -> RAGScanResult:
        """
        Scan RAG documents for poisoning attempts.

        Args:
            documents: Documents to scan. Can be RAGDocument objects,
                plain strings, or dicts with 'content' key.

        Returns:
            RAGScanResult with safe documents and violations.
        """
        # Normalize to RAGDocument
        normalized: list[RAGDocument] = []
        for doc in documents:
            if isinstance(doc, RAGDocument):
                normalized.append(doc)
            elif isinstance(doc, str):
                normalized.append(RAGDocument(content=doc))
            elif isinstance(doc, dict):
                normalized.append(RAGDocument(
                    content=doc.get("content", doc.get("text", str(doc))),
                    source=doc.get("source"),
                    score=doc.get("score", 0.0),
                    metadata=doc.get("metadata", {}),
                ))
            else:
                normalized.append(RAGDocument(content=str(doc)))

        violations: list[IntegrityViolation] = []
        poisoned_indices: list[int] = []

        for i, doc in enumerate(normalized):
            doc_violations = self._scan_document_content(doc.content, i)
            if doc_violations:
                violations.extend(doc_violations)
                poisoned_indices.append(i)

        return RAGScanResult(
            safe=len(poisoned_indices) == 0,
            documents=normalized,
            poisoned_indices=poisoned_indices,
            violations=violations,
        )

    def _scan_document_content(
        self,
        content: str,
        index: int,
    ) -> list[IntegrityViolation]:
        """Scan a single document's content for poisoning."""
        violations: list[IntegrityViolation] = []

        for pattern, description, severity in self._rag_patterns:
            if pattern.search(content):
                violations.append(IntegrityViolation(
                    violation_type=IntegrityViolationType.RAG_POISONING,
                    message=f"RAG poisoning detected in document {index}: {description}",
                    severity=severity,
                    index=index,
                ))

        return violations

    def reset(self) -> None:
        """Reset the guard state (sequence counter and hash chain)."""
        with self._lock:
            self._sequence_counter = 0
            self._last_hash = self.GENESIS_HASH

    def get_state(self) -> dict[str, Any]:
        """Get current guard state for serialization."""
        with self._lock:
            return {
                "sequence_counter": self._sequence_counter,
                "last_hash": self._last_hash,
            }

    def restore_state(self, state: dict[str, Any]) -> None:
        """Restore guard state from serialization."""
        with self._lock:
            self._sequence_counter = state.get("sequence_counter", 0)
            self._last_hash = state.get("last_hash", self.GENESIS_HASH)


class ContextWindowGuard:
    """
    High-level guard for managing signed context windows.

    Provides a simple API for building and verifying context
    that will be sent to an LLM.

    Example:
        >>> guard = ContextWindowGuard(secret_key="key")
        >>>
        >>> # Build context
        >>> guard.add_system("You are a helpful assistant.")
        >>> guard.add_user("Hello!")
        >>> guard.add_assistant("Hi there! How can I help?")
        >>>
        >>> # Get verified context for LLM
        >>> messages = guard.get_verified_messages()
        >>> response = llm.generate(messages)
        >>>
        >>> # Add response to context
        >>> guard.add_assistant(response)
    """

    def __init__(
        self,
        secret_key: str | bytes,
        **kwargs: Any,
    ) -> None:
        """
        Initialize the context window guard.

        Args:
            secret_key: Secret key for signing.
            **kwargs: Additional args passed to MemoryIntegrityGuard.
        """
        self._guard = MemoryIntegrityGuard(secret_key, **kwargs)
        self._messages: list[SignedMessage] = []
        self._lock = threading.RLock()

    def add_system(self, content: str, **metadata: Any) -> SignedMessage:
        """Add a system message."""
        return self._add_message("system", content, metadata)

    def add_user(self, content: str, **metadata: Any) -> SignedMessage:
        """Add a user message."""
        return self._add_message("user", content, metadata)

    def add_assistant(self, content: str, **metadata: Any) -> SignedMessage:
        """Add an assistant message."""
        return self._add_message("assistant", content, metadata)

    def add_tool(self, content: str, tool_name: str = "", **metadata: Any) -> SignedMessage:
        """Add a tool result message."""
        metadata["tool_name"] = tool_name
        return self._add_message("tool", content, metadata)

    def _add_message(
        self,
        role: str,
        content: str,
        metadata: dict[str, Any],
    ) -> SignedMessage:
        """Add a message with the given role."""
        with self._lock:
            msg = self._guard.sign_message(role, content, metadata)
            self._messages.append(msg)
            return msg

    def verify(self) -> VerificationResult:
        """Verify the current context."""
        with self._lock:
            return self._guard.verify_context(self._messages)

    def get_messages(self) -> list[SignedMessage]:
        """Get all messages (unverified)."""
        with self._lock:
            return list(self._messages)

    def get_verified_messages(self) -> list[dict[str, str]]:
        """
        Get messages if context is valid, else raise.

        Returns:
            List of message dicts suitable for LLM API.

        Raises:
            ContextIntegrityError: If verification fails.
        """
        with self._lock:
            result = self._guard.verify_context(self._messages)
            if not result.valid:
                from proxilion.exceptions import ContextIntegrityError
                raise ContextIntegrityError(
                    f"Context integrity violated: {result.violations[0].message}",
                    violations=result.violations,
                )

            return [
                {"role": msg.role, "content": msg.content}
                for msg in self._messages
            ]

    def get_messages_for_api(self) -> list[dict[str, str]]:
        """Get messages in API format (role, content only)."""
        with self._lock:
            return [
                {"role": msg.role, "content": msg.content}
                for msg in self._messages
            ]

    def clear(self) -> None:
        """Clear all messages and reset state."""
        with self._lock:
            self._messages.clear()
            self._guard.reset()

    def pop(self) -> SignedMessage | None:
        """Remove and return the last message."""
        with self._lock:
            if self._messages:
                return self._messages.pop()
            return None

    def __len__(self) -> int:
        """Number of messages in context."""
        return len(self._messages)


# Convenience exports
__all__ = [
    # Core classes
    "MemoryIntegrityGuard",
    "ContextWindowGuard",
    # Data classes
    "SignedMessage",
    "VerificationResult",
    "IntegrityViolation",
    "IntegrityViolationType",
    "RAGDocument",
    "RAGScanResult",
    # Patterns
    "RAG_POISON_PATTERNS",
]
