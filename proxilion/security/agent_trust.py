"""
Agent-to-Agent Trust Enforcement for Proxilion.

Addresses OWASP ASI07: Insecure Inter-Agent Communication.

This module provides cryptographic trust verification for multi-agent
systems, ensuring that:
- Agents can only communicate with authorized peers
- Messages are signed and verified
- Delegation chains are tracked and validated
- Trust levels control what actions agents can request

Example:
    >>> from proxilion.security.agent_trust import (
    ...     AgentTrustManager,
    ...     AgentCredential,
    ...     DelegationChain,
    ...     TrustLevel,
    ... )
    >>>
    >>> # Create trust manager
    >>> manager = AgentTrustManager(secret_key="your-secret")
    >>>
    >>> # Register agents
    >>> orchestrator = manager.register_agent(
    ...     agent_id="orchestrator",
    ...     trust_level=TrustLevel.FULL,
    ...     capabilities=["delegate", "execute_all"],
    ... )
    >>>
    >>> worker = manager.register_agent(
    ...     agent_id="worker_1",
    ...     trust_level=TrustLevel.LIMITED,
    ...     capabilities=["read", "write"],
    ...     parent_agent="orchestrator",
    ... )
    >>>
    >>> # Create signed message from orchestrator to worker
    >>> message = manager.create_signed_message(
    ...     from_agent="orchestrator",
    ...     to_agent="worker_1",
    ...     action="execute",
    ...     payload={"task": "process_data"},
    ... )
    >>>
    >>> # Verify and process on receiving end
    >>> verified = manager.verify_message(message)
    >>> if verified.valid:
    ...     process_task(message.payload)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import IntEnum
from typing import Any

from proxilion.exceptions import AgentTrustError

logger = logging.getLogger(__name__)


class TrustLevel(IntEnum):
    """
    Trust levels for agents.

    Higher levels can delegate to lower levels but not vice versa.
    """

    UNTRUSTED = 0
    """No trust - cannot communicate."""

    MINIMAL = 1
    """Can receive read-only requests."""

    LIMITED = 2
    """Can receive read/write requests within scope."""

    STANDARD = 3
    """Normal agent trust level."""

    ELEVATED = 4
    """Can delegate to standard agents."""

    FULL = 5
    """Full trust - can delegate to all levels."""

    SYSTEM = 6
    """System-level trust (internal use)."""


@dataclass
class AgentCredential:
    """
    Cryptographic credential for an agent.

    Contains the agent's identity, trust level, capabilities,
    and cryptographic material for signing messages.
    """

    agent_id: str
    trust_level: TrustLevel
    capabilities: set[str]
    public_key: str  # Hex-encoded public identifier
    parent_agent: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    # Internal secret (never serialized)
    _secret: str = field(default="", repr=False)

    def is_expired(self) -> bool:
        """Check if credential has expired."""
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at

    def has_capability(self, capability: str) -> bool:
        """Check if agent has a specific capability."""
        # Wildcard capability
        if "*" in self.capabilities:
            return True
        # Exact match
        if capability in self.capabilities:
            return True
        # Prefix match (e.g., "read" matches "read:documents")
        for cap in self.capabilities:
            if capability.startswith(cap + ":"):
                return True
        return False

    def can_delegate_to(self, other: AgentCredential) -> bool:
        """Check if this agent can delegate to another."""
        # Must have higher trust level
        if self.trust_level <= other.trust_level:
            return False
        # Must have delegate capability
        if not self.has_capability("delegate"):
            return False
        return True

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict (excludes secret)."""
        return {
            "agent_id": self.agent_id,
            "trust_level": self.trust_level.value,
            "capabilities": list(self.capabilities),
            "public_key": self.public_key,
            "parent_agent": self.parent_agent,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "metadata": self.metadata,
        }


@dataclass
class DelegationToken:
    """
    A token that grants delegated authority from one agent to another.

    Delegation tokens are time-limited and scope-limited.
    """

    token_id: str
    issuer_agent: str
    delegate_agent: str
    granted_capabilities: set[str]
    issued_at: datetime
    expires_at: datetime
    signature: str
    chain_depth: int = 1  # How many delegations deep
    max_chain_depth: int = 3  # Maximum delegation chain length
    constraints: dict[str, Any] = field(default_factory=dict)

    def is_expired(self) -> bool:
        """Check if token has expired."""
        return datetime.now(timezone.utc) > self.expires_at

    def is_valid(self) -> bool:
        """Basic validity check (not signature verification)."""
        if self.is_expired():
            return False
        if self.chain_depth > self.max_chain_depth:
            return False
        return True

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "token_id": self.token_id,
            "issuer_agent": self.issuer_agent,
            "delegate_agent": self.delegate_agent,
            "granted_capabilities": list(self.granted_capabilities),
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "signature": self.signature,
            "chain_depth": self.chain_depth,
            "max_chain_depth": self.max_chain_depth,
            "constraints": self.constraints,
        }


@dataclass
class SignedMessage:
    """
    A cryptographically signed message between agents.
    """

    message_id: str
    from_agent: str
    to_agent: str
    action: str
    payload: dict[str, Any]
    timestamp: float
    signature: str
    delegation_token: DelegationToken | None = None
    reply_to: str | None = None  # ID of message being replied to
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "message_id": self.message_id,
            "from_agent": self.from_agent,
            "to_agent": self.to_agent,
            "action": self.action,
            "payload": self.payload,
            "timestamp": self.timestamp,
            "signature": self.signature,
            "delegation_token": self.delegation_token.to_dict() if self.delegation_token else None,
            "reply_to": self.reply_to,
            "metadata": self.metadata,
        }


@dataclass
class VerificationResult:
    """Result of message or token verification."""

    valid: bool
    error: str | None = None
    warnings: list[str] = field(default_factory=list)
    verified_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "valid": self.valid,
            "error": self.error,
            "warnings": self.warnings,
            "verified_at": self.verified_at.isoformat(),
        }


class DelegationChain:
    """
    Tracks the chain of delegations for an action.

    Ensures that delegation chains don't exceed maximum depth
    and that all delegations in the chain are valid.
    """

    def __init__(self, max_depth: int = 3) -> None:
        """
        Initialize delegation chain.

        Args:
            max_depth: Maximum allowed delegation depth.
        """
        self.max_depth = max_depth
        self._chain: list[DelegationToken] = []

    def add(self, token: DelegationToken) -> bool:
        """
        Add a delegation to the chain.

        Returns:
            True if added successfully, False if chain would be too deep.
        """
        if len(self._chain) >= self.max_depth:
            return False
        self._chain.append(token)
        return True

    def validate(self) -> tuple[bool, str | None]:
        """
        Validate the entire chain.

        Returns:
            Tuple of (valid, error message or None).
        """
        if not self._chain:
            return True, None

        # Check depth
        if len(self._chain) > self.max_depth:
            return False, f"Chain depth {len(self._chain)} exceeds max {self.max_depth}"

        # Check each token
        for i, token in enumerate(self._chain):
            if token.is_expired():
                return False, f"Token at position {i} has expired"
            if not token.is_valid():
                return False, f"Token at position {i} is invalid"

            # Check chain continuity
            if i > 0:
                prev_token = self._chain[i - 1]
                if token.issuer_agent != prev_token.delegate_agent:
                    return False, f"Chain break at position {i}: {prev_token.delegate_agent} != {token.issuer_agent}"

        return True, None

    @property
    def depth(self) -> int:
        """Current chain depth."""
        return len(self._chain)

    @property
    def tokens(self) -> list[DelegationToken]:
        """Get all tokens in chain."""
        return list(self._chain)

    def get_effective_capabilities(self) -> set[str]:
        """Get capabilities available at end of chain (intersection of all)."""
        if not self._chain:
            return set()

        caps = self._chain[0].granted_capabilities.copy()
        for token in self._chain[1:]:
            caps &= token.granted_capabilities

        return caps


class AgentTrustManager:
    """
    Manages trust relationships between agents.

    Provides:
    - Agent registration with cryptographic credentials
    - Message signing and verification
    - Delegation token creation and validation
    - Trust level enforcement

    Example:
        >>> manager = AgentTrustManager(secret_key="master-secret")
        >>>
        >>> # Register agents
        >>> manager.register_agent("orchestrator", TrustLevel.FULL, {"*"})
        >>> manager.register_agent("worker", TrustLevel.LIMITED, {"read", "write"})
        >>>
        >>> # Create delegation
        >>> token = manager.create_delegation(
        ...     from_agent="orchestrator",
        ...     to_agent="worker",
        ...     capabilities={"read"},
        ...     ttl_seconds=3600,
        ... )
        >>>
        >>> # Send signed message
        >>> message = manager.create_signed_message(
        ...     from_agent="orchestrator",
        ...     to_agent="worker",
        ...     action="read_file",
        ...     payload={"path": "/data/file.txt"},
        ... )
        >>>
        >>> # Verify on receiving end
        >>> result = manager.verify_message(message)
    """

    def __init__(
        self,
        secret_key: str | bytes,
        default_token_ttl: int = 3600,
        max_delegation_depth: int = 3,
        require_explicit_trust: bool = True,
    ) -> None:
        """
        Initialize the trust manager.

        Args:
            secret_key: Master secret for deriving agent keys.
            default_token_ttl: Default TTL for delegation tokens (seconds).
            max_delegation_depth: Maximum delegation chain depth.
            require_explicit_trust: If True, agents must be explicitly registered.
        """
        if isinstance(secret_key, str):
            secret_key = secret_key.encode()

        self._master_secret = secret_key
        self._default_token_ttl = default_token_ttl
        self._max_delegation_depth = max_delegation_depth
        self._require_explicit_trust = require_explicit_trust

        self._agents: dict[str, AgentCredential] = {}
        self._delegation_tokens: dict[str, DelegationToken] = {}
        self._revoked_tokens: set[str] = set()
        self._message_nonces: set[str] = set()  # Replay protection
        self._lock = threading.RLock()

        logger.debug("AgentTrustManager initialized")

    def _derive_agent_secret(self, agent_id: str) -> str:
        """Derive a unique secret for an agent."""
        return hmac.new(
            self._master_secret,
            f"agent:{agent_id}".encode(),
            hashlib.sha256,
        ).hexdigest()

    def _derive_public_key(self, secret: str) -> str:
        """Derive public key from secret."""
        return hashlib.sha256(secret.encode()).hexdigest()[:32]

    def register_agent(
        self,
        agent_id: str,
        trust_level: TrustLevel,
        capabilities: set[str] | list[str],
        parent_agent: str | None = None,
        ttl_seconds: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AgentCredential:
        """
        Register an agent with the trust manager.

        Args:
            agent_id: Unique identifier for the agent.
            trust_level: Trust level for the agent.
            capabilities: Set of capabilities the agent has.
            parent_agent: Optional parent agent (for hierarchical trust).
            ttl_seconds: Optional credential TTL.
            metadata: Optional metadata.

        Returns:
            AgentCredential for the registered agent.

        Raises:
            AgentTrustError: If agent already registered or invalid parent.
        """
        with self._lock:
            if agent_id in self._agents:
                raise AgentTrustError(
                    source_agent=agent_id,
                    target_agent="",
                    reason=f"Agent '{agent_id}' is already registered",
                )

            # Validate parent
            if parent_agent and parent_agent not in self._agents:
                raise AgentTrustError(
                    source_agent=agent_id,
                    target_agent=parent_agent,
                    reason=f"Parent agent '{parent_agent}' not found",
                )

            # Check parent has higher trust
            if parent_agent:
                parent = self._agents[parent_agent]
                if parent.trust_level <= trust_level:
                    raise AgentTrustError(
                        source_agent=agent_id,
                        target_agent=parent_agent,
                        reason="Child agent cannot have equal or higher trust than parent",
                    )

            # Derive credentials
            secret = self._derive_agent_secret(agent_id)
            public_key = self._derive_public_key(secret)

            expires_at = None
            if ttl_seconds:
                expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)

            if isinstance(capabilities, list):
                capabilities = set(capabilities)

            credential = AgentCredential(
                agent_id=agent_id,
                trust_level=trust_level,
                capabilities=capabilities,
                public_key=public_key,
                parent_agent=parent_agent,
                expires_at=expires_at,
                metadata=metadata or {},
                _secret=secret,
            )

            self._agents[agent_id] = credential
            logger.info(f"Registered agent: {agent_id} (trust={trust_level.name})")

            return credential

    def unregister_agent(self, agent_id: str) -> bool:
        """
        Unregister an agent.

        Args:
            agent_id: Agent to unregister.

        Returns:
            True if agent was unregistered.
        """
        with self._lock:
            if agent_id in self._agents:
                del self._agents[agent_id]

                # Revoke all tokens issued by or to this agent
                tokens_to_revoke = [
                    tid for tid, token in self._delegation_tokens.items()
                    if token.issuer_agent == agent_id or token.delegate_agent == agent_id
                ]
                for tid in tokens_to_revoke:
                    self._revoked_tokens.add(tid)
                    del self._delegation_tokens[tid]

                logger.info(f"Unregistered agent: {agent_id}")
                return True
            return False

    def get_agent(self, agent_id: str) -> AgentCredential | None:
        """Get an agent's credential."""
        with self._lock:
            return self._agents.get(agent_id)

    def create_delegation(
        self,
        from_agent: str,
        to_agent: str,
        capabilities: set[str] | list[str],
        ttl_seconds: int | None = None,
        constraints: dict[str, Any] | None = None,
    ) -> DelegationToken:
        """
        Create a delegation token from one agent to another.

        Args:
            from_agent: Agent issuing the delegation.
            to_agent: Agent receiving the delegation.
            capabilities: Capabilities being delegated.
            ttl_seconds: Token lifetime (default: manager default).
            constraints: Optional constraints on the delegation.

        Returns:
            DelegationToken that can be used for delegated actions.

        Raises:
            AgentTrustError: If delegation is not allowed.
        """
        with self._lock:
            # Validate agents
            issuer = self._agents.get(from_agent)
            delegate = self._agents.get(to_agent)

            if not issuer:
                raise AgentTrustError(
                    source_agent=from_agent,
                    target_agent=to_agent,
                    reason=f"Issuer agent '{from_agent}' not found",
                )

            if not delegate:
                raise AgentTrustError(
                    source_agent=from_agent,
                    target_agent=to_agent,
                    reason=f"Delegate agent '{to_agent}' not found",
                )

            if issuer.is_expired():
                raise AgentTrustError(
                    source_agent=from_agent,
                    target_agent=to_agent,
                    reason="Issuer credential has expired",
                )

            if not issuer.can_delegate_to(delegate):
                raise AgentTrustError(
                    source_agent=from_agent,
                    target_agent=to_agent,
                    reason=f"Agent '{from_agent}' cannot delegate to '{to_agent}'",
                )

            # Normalize capabilities
            if isinstance(capabilities, list):
                capabilities = set(capabilities)

            # Can only delegate capabilities the issuer has
            invalid_caps = capabilities - issuer.capabilities
            if invalid_caps and "*" not in issuer.capabilities:
                raise AgentTrustError(
                    source_agent=from_agent,
                    target_agent=to_agent,
                    reason=f"Cannot delegate capabilities not owned: {invalid_caps}",
                )

            # Create token
            ttl = ttl_seconds or self._default_token_ttl
            now = datetime.now(timezone.utc)
            token_id = str(uuid.uuid4())

            # Sign the token
            token_data = f"{token_id}|{from_agent}|{to_agent}|{sorted(capabilities)}|{now.isoformat()}"
            signature = hmac.new(
                issuer._secret.encode(),
                token_data.encode(),
                hashlib.sha256,
            ).hexdigest()

            token = DelegationToken(
                token_id=token_id,
                issuer_agent=from_agent,
                delegate_agent=to_agent,
                granted_capabilities=capabilities,
                issued_at=now,
                expires_at=now + timedelta(seconds=ttl),
                signature=signature,
                chain_depth=1,
                max_chain_depth=self._max_delegation_depth,
                constraints=constraints or {},
            )

            self._delegation_tokens[token_id] = token
            logger.debug(f"Created delegation: {from_agent} -> {to_agent} ({capabilities})")

            return token

    def revoke_delegation(self, token_id: str) -> bool:
        """
        Revoke a delegation token.

        Args:
            token_id: Token to revoke.

        Returns:
            True if token was revoked.
        """
        with self._lock:
            if token_id in self._delegation_tokens:
                self._revoked_tokens.add(token_id)
                del self._delegation_tokens[token_id]
                logger.info(f"Revoked delegation token: {token_id}")
                return True
            return False

    def create_signed_message(
        self,
        from_agent: str,
        to_agent: str,
        action: str,
        payload: dict[str, Any],
        delegation_token: DelegationToken | None = None,
        reply_to: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SignedMessage:
        """
        Create a signed message from one agent to another.

        Args:
            from_agent: Sending agent.
            to_agent: Receiving agent.
            action: Action being requested.
            payload: Message payload.
            delegation_token: Optional delegation token for delegated actions.
            reply_to: Message ID being replied to.
            metadata: Optional metadata.

        Returns:
            SignedMessage that can be verified by the receiver.

        Raises:
            AgentTrustError: If agent not found or expired.
        """
        with self._lock:
            sender = self._agents.get(from_agent)
            if not sender:
                raise AgentTrustError(
                    source_agent=from_agent,
                    target_agent=to_agent,
                    reason=f"Sender agent '{from_agent}' not found",
                )

            if sender.is_expired():
                raise AgentTrustError(
                    source_agent=from_agent,
                    target_agent=to_agent,
                    reason="Sender credential has expired",
                )

            # Create message
            message_id = str(uuid.uuid4())
            timestamp = time.time()

            # Build signature data
            sig_data = (
                f"{message_id}|{from_agent}|{to_agent}|{action}|"
                f"{json.dumps(payload, sort_keys=True)}|{timestamp}"
            )
            signature = hmac.new(
                sender._secret.encode(),
                sig_data.encode(),
                hashlib.sha256,
            ).hexdigest()

            return SignedMessage(
                message_id=message_id,
                from_agent=from_agent,
                to_agent=to_agent,
                action=action,
                payload=payload,
                timestamp=timestamp,
                signature=signature,
                delegation_token=delegation_token,
                reply_to=reply_to,
                metadata=metadata or {},
            )

    def verify_message(
        self,
        message: SignedMessage,
        check_replay: bool = True,
        max_age_seconds: float = 300.0,
    ) -> VerificationResult:
        """
        Verify a signed message.

        Args:
            message: Message to verify.
            check_replay: Check for replay attacks.
            max_age_seconds: Maximum message age.

        Returns:
            VerificationResult indicating if message is valid.
        """
        warnings: list[str] = []

        with self._lock:
            # Check replay
            if check_replay:
                if message.message_id in self._message_nonces:
                    return VerificationResult(
                        valid=False,
                        error="Replay attack detected: message already processed",
                    )

            # Check message age
            age = time.time() - message.timestamp
            if age > max_age_seconds:
                return VerificationResult(
                    valid=False,
                    error=f"Message too old: {age:.1f}s > {max_age_seconds}s",
                )
            if age < -60:  # Allow 60s clock skew
                return VerificationResult(
                    valid=False,
                    error="Message timestamp in the future",
                )

            # Get sender
            sender = self._agents.get(message.from_agent)
            if not sender:
                if self._require_explicit_trust:
                    return VerificationResult(
                        valid=False,
                        error=f"Unknown sender: {message.from_agent}",
                    )
                else:
                    warnings.append(f"Sender {message.from_agent} not registered")

            # Check sender credentials
            if sender:
                if sender.is_expired():
                    return VerificationResult(
                        valid=False,
                        error="Sender credential has expired",
                    )

                # Verify signature
                sig_data = (
                    f"{message.message_id}|{message.from_agent}|{message.to_agent}|"
                    f"{message.action}|{json.dumps(message.payload, sort_keys=True)}|"
                    f"{message.timestamp}"
                )
                expected_sig = hmac.new(
                    sender._secret.encode(),
                    sig_data.encode(),
                    hashlib.sha256,
                ).hexdigest()

                if not hmac.compare_digest(expected_sig, message.signature):
                    return VerificationResult(
                        valid=False,
                        error="Invalid signature",
                    )

            # Check receiver exists
            receiver = self._agents.get(message.to_agent)
            if not receiver and self._require_explicit_trust:
                return VerificationResult(
                    valid=False,
                    error=f"Unknown receiver: {message.to_agent}",
                )

            # Check trust levels allow communication
            if sender and receiver:
                if sender.trust_level == TrustLevel.UNTRUSTED:
                    return VerificationResult(
                        valid=False,
                        error="Sender has UNTRUSTED trust level",
                    )

                # Check if action is allowed
                if not sender.has_capability(message.action):
                    # Check delegation token
                    if message.delegation_token:
                        token = message.delegation_token
                        if token.token_id in self._revoked_tokens:
                            return VerificationResult(
                                valid=False,
                                error="Delegation token has been revoked",
                            )
                        if token.is_expired():
                            return VerificationResult(
                                valid=False,
                                error="Delegation token has expired",
                            )
                        if message.action not in token.granted_capabilities:
                            if "*" not in token.granted_capabilities:
                                return VerificationResult(
                                    valid=False,
                                    error=f"Action '{message.action}' not in delegation",
                                )
                    else:
                        return VerificationResult(
                            valid=False,
                            error=f"Sender lacks capability for action '{message.action}'",
                        )

            # Record nonce for replay protection
            if check_replay:
                self._message_nonces.add(message.message_id)
                # Cleanup old nonces (keep last 10000)
                if len(self._message_nonces) > 10000:
                    # Remove oldest (this is approximate but effective)
                    to_remove = list(self._message_nonces)[:5000]
                    for nonce in to_remove:
                        self._message_nonces.discard(nonce)

            return VerificationResult(valid=True, warnings=warnings)

    def verify_delegation_chain(self, chain: DelegationChain) -> VerificationResult:
        """
        Verify a delegation chain.

        Args:
            chain: The delegation chain to verify.

        Returns:
            VerificationResult for the chain.
        """
        valid, error = chain.validate()
        if not valid:
            return VerificationResult(valid=False, error=error)

        # Verify each token's signature
        with self._lock:
            for token in chain.tokens:
                if token.token_id in self._revoked_tokens:
                    return VerificationResult(
                        valid=False,
                        error=f"Token {token.token_id} has been revoked",
                    )

                issuer = self._agents.get(token.issuer_agent)
                if not issuer:
                    return VerificationResult(
                        valid=False,
                        error=f"Issuer {token.issuer_agent} not found",
                    )

                # Verify signature
                token_data = (
                    f"{token.token_id}|{token.issuer_agent}|{token.delegate_agent}|"
                    f"{sorted(token.granted_capabilities)}|{token.issued_at.isoformat()}"
                )
                expected_sig = hmac.new(
                    issuer._secret.encode(),
                    token_data.encode(),
                    hashlib.sha256,
                ).hexdigest()

                if not hmac.compare_digest(expected_sig, token.signature):
                    return VerificationResult(
                        valid=False,
                        error=f"Invalid signature on token {token.token_id}",
                    )

        return VerificationResult(valid=True)

    def get_registered_agents(self) -> list[str]:
        """Get list of registered agent IDs."""
        with self._lock:
            return list(self._agents.keys())

    def get_trust_level(self, agent_id: str) -> TrustLevel | None:
        """Get an agent's trust level."""
        with self._lock:
            agent = self._agents.get(agent_id)
            return agent.trust_level if agent else None

    def cleanup_expired(self) -> int:
        """
        Clean up expired credentials and tokens.

        Returns:
            Number of items cleaned up.
        """
        count = 0
        now = datetime.now(timezone.utc)

        with self._lock:
            # Clean expired agents
            expired_agents = [
                aid for aid, agent in self._agents.items()
                if agent.expires_at and agent.expires_at < now
            ]
            for aid in expired_agents:
                del self._agents[aid]
                count += 1

            # Clean expired tokens
            expired_tokens = [
                tid for tid, token in self._delegation_tokens.items()
                if token.expires_at < now
            ]
            for tid in expired_tokens:
                del self._delegation_tokens[tid]
                count += 1

        if count > 0:
            logger.debug(f"Cleaned up {count} expired items")

        return count


# Convenience exports
__all__ = [
    # Core classes
    "AgentTrustManager",
    "AgentCredential",
    "DelegationToken",
    "DelegationChain",
    "SignedMessage",
    "VerificationResult",
    # Enums
    "TrustLevel",
]
