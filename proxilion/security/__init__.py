"""
Security controls for Proxilion.

This module provides security mechanisms to protect against abuse
and ensure safe operation of LLM tool calls:

- Rate Limiting: Prevent unbounded consumption with token bucket,
  sliding window, and multi-dimensional rate limiters.

- Circuit Breaker: Prevent cascading failures when tools or
  external services fail repeatedly.

- IDOR Protection: Prevent Insecure Direct Object Reference attacks
  by validating object IDs against user scopes.

- Intent Validation: Detect anomalous patterns in tool usage
  without relying on LLM analysis.

- Cascade Protection: Prevent failures from propagating through
  dependent tools and services.

- Trust Boundaries: Control inter-agent communication with trust
  levels and delegation chains.

NEW - OWASP ASI Top 10 Protection:

- Memory Integrity (ASI06): Cryptographic context verification,
  RAG poisoning detection.

- Agent Trust (ASI07): mTLS-style signed messaging between agents,
  delegation chains with attestation.

- Intent Capsule (ASI01): Bind original user intent cryptographically
  to prevent goal hijacking.

- Behavioral Drift (ASI10): Detect rogue agent behavior with
  statistical baseline monitoring and kill switch.

Quick Start:
    >>> from proxilion.security import (
    ...     TokenBucketRateLimiter,
    ...     CircuitBreaker,
    ...     IDORProtector,
    ...     IntentValidator,
    ...     CascadeProtector,
    ...     TrustEnforcer,
    ... )
    >>>
    >>> # Rate limiting
    >>> rate_limiter = TokenBucketRateLimiter(capacity=100, refill_rate=10)
    >>> if rate_limiter.allow_request("user_123"):
    ...     # Process request
    ...     pass
    >>>
    >>> # Circuit breaker
    >>> breaker = CircuitBreaker(failure_threshold=5, reset_timeout=30)
    >>> result = breaker.call(external_api_function)
    >>>
    >>> # IDOR protection
    >>> protector = IDORProtector()
    >>> protector.register_scope("user_123", "document", {"doc_1", "doc_2"})
    >>> if protector.validate_access("user_123", "document", "doc_1"):
    ...     # User can access this document
    ...     pass
    >>>
    >>> # Cascade protection
    >>> graph = DependencyGraph()
    >>> graph.add_dependency("api", "database")
    >>> cascade = CascadeProtector(graph)
    >>> state = cascade.check_cascade_health("api")
    >>>
    >>> # Trust boundaries
    >>> enforcer = TrustEnforcer()
    >>> enforcer.register_agent(AgentIdentity(
    ...     agent_id="main", trust_level=TrustLevel.INTERNAL
    ... ))
"""

from proxilion.security.agent_trust import (
    AgentCredential,
    AgentTrustManager,
    DelegationChain,
)
from proxilion.security.agent_trust import (
    DelegationToken as AgentDelegationToken,
)
from proxilion.security.agent_trust import (
    SignedMessage as AgentSignedMessage,
)
from proxilion.security.agent_trust import (
    TrustLevel as AgentTrustLevel,
)
from proxilion.security.agent_trust import (
    VerificationResult as AgentVerificationResult,
)
from proxilion.security.behavioral_drift import (
    BaselineStats,
    BehavioralMonitor,
    DriftDetector,
    DriftMetric,
    DriftResult,
    KillSwitch,
)
from proxilion.security.cascade_protection import (
    CascadeAwareCircuitBreakerRegistry,
    CascadeEvent,
    CascadeProtector,
    CascadeState,
    DependencyGraph,
    DependencyInfo,
)
from proxilion.security.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerRegistry,
    CircuitState,
    CircuitStats,
)
from proxilion.security.idor_protection import (
    IDORProtector,
    IDPattern,
    ResourceScope,
)
from proxilion.security.intent_capsule import (
    HijackDetection,
    IntentCapsule,
    IntentCapsuleManager,
    IntentCategory,
    IntentGuard,
)
from proxilion.security.intent_capsule import (
    IntentValidator as IntentHijackValidator,
)
from proxilion.security.intent_validator import (
    AnomalyThresholds,
    IntentValidator,
    ValidationOutcome,
    ValidationResult,
    WorkflowState,
)

# New ASI Top 10 features
from proxilion.security.memory_integrity import (
    ContextWindowGuard,
    IntegrityViolation,
    IntegrityViolationType,
    MemoryIntegrityGuard,
    RAGDocument,
    RAGScanResult,
)
from proxilion.security.memory_integrity import (
    SignedMessage as MemorySignedMessage,
)
from proxilion.security.memory_integrity import (
    VerificationResult as MemoryVerificationResult,
)
from proxilion.security.rate_limiter import (
    MultiDimensionalRateLimiter,
    RateLimitConfig,
    RateLimiterMiddleware,
    SlidingWindowRateLimiter,
    TokenBucketRateLimiter,
)
from proxilion.security.sequence_validator import (
    DEFAULT_SEQUENCE_RULES,
    SequenceAction,
    SequenceRule,
    SequenceValidator,
    SequenceViolation,
    ToolCallRecord,
    create_sequence_validator,
)
from proxilion.security.trust_boundaries import (
    DEFAULT_BOUNDARIES,
    AgentIdentity,
    DelegationToken,
    TrustBoundary,
    TrustBoundaryViolation,
    TrustEnforcer,
    TrustLevel,
)

__all__ = [
    # Rate limiting
    "TokenBucketRateLimiter",
    "SlidingWindowRateLimiter",
    "MultiDimensionalRateLimiter",
    "RateLimitConfig",
    "RateLimiterMiddleware",
    # Circuit breaker
    "CircuitBreaker",
    "CircuitBreakerRegistry",
    "CircuitState",
    "CircuitStats",
    # IDOR protection
    "IDORProtector",
    "IDPattern",
    "ResourceScope",
    # Intent validation
    "IntentValidator",
    "ValidationOutcome",
    "ValidationResult",
    "AnomalyThresholds",
    "WorkflowState",
    # Cascade protection
    "CascadeAwareCircuitBreakerRegistry",
    "CascadeEvent",
    "CascadeProtector",
    "CascadeState",
    "DependencyGraph",
    "DependencyInfo",
    # Trust boundaries
    "AgentIdentity",
    "DEFAULT_BOUNDARIES",
    "DelegationToken",
    "TrustBoundary",
    "TrustBoundaryViolation",
    "TrustEnforcer",
    "TrustLevel",
    # Sequence validation
    "DEFAULT_SEQUENCE_RULES",
    "SequenceAction",
    "SequenceRule",
    "SequenceValidator",
    "SequenceViolation",
    "ToolCallRecord",
    "create_sequence_validator",
    # Memory Integrity (ASI06)
    "MemoryIntegrityGuard",
    "ContextWindowGuard",
    "IntegrityViolation",
    "IntegrityViolationType",
    "MemorySignedMessage",
    "MemoryVerificationResult",
    "RAGDocument",
    "RAGScanResult",
    # Agent Trust (ASI07)
    "AgentTrustManager",
    "AgentCredential",
    "AgentDelegationToken",
    "DelegationChain",
    "AgentSignedMessage",
    "AgentTrustLevel",
    "AgentVerificationResult",
    # Intent Capsule (ASI01)
    "IntentCapsule",
    "IntentGuard",
    "IntentHijackValidator",
    "IntentCapsuleManager",
    "IntentCategory",
    "HijackDetection",
    # Behavioral Drift (ASI10)
    "BehavioralMonitor",
    "DriftDetector",
    "KillSwitch",
    "DriftResult",
    "DriftMetric",
    "BaselineStats",
]
