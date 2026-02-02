"""
Inter-agent trust boundaries for Proxilion.

This module provides trust-based authorization for inter-agent communication,
ensuring that delegation chains don't violate trust boundaries.

Quick Start:
    >>> from proxilion.security import (
    ...     TrustLevel,
    ...     AgentIdentity,
    ...     TrustEnforcer,
    ... )
    >>>
    >>> # Create trust enforcer with default boundaries
    >>> enforcer = TrustEnforcer()
    >>>
    >>> # Register agents with their trust levels
    >>> enforcer.register_agent(AgentIdentity(
    ...     agent_id="main_agent",
    ...     trust_level=TrustLevel.INTERNAL,
    ...     allowed_scopes={"read", "write", "admin"},
    ... ))
    >>> enforcer.register_agent(AgentIdentity(
    ...     agent_id="external_plugin",
    ...     trust_level=TrustLevel.EXTERNAL,
    ...     allowed_scopes={"read"},
    ... ))
    >>>
    >>> # Check trust boundary
    >>> allowed, requires_approval = enforcer.check_trust_boundary(
    ...     "main_agent", "external_plugin"
    ... )
    >>> if not allowed:
    ...     raise TrustBoundaryViolation("Not allowed")
    >>> if requires_approval:
    ...     await request_approval()

Trust Levels:
    - INTERNAL: Fully trusted internal agents (same organization).
    - PARTNER: Trusted partner agents (shared service agreements).
    - EXTERNAL: External agents with limited trust.
    - UNTRUSTED: No trust, all operations denied.

Delegation:
    >>> # Create a delegation token
    >>> token = enforcer.create_delegation(
    ...     from_agent="main_agent",
    ...     to_agent="partner_agent",
    ...     scopes={"read", "write"},
    ...     ttl=3600,  # 1 hour
    ... )
    >>>
    >>> # Validate the delegation
    >>> valid, reason = enforcer.validate_delegation(token)
    >>> if not valid:
    ...     print(f"Invalid delegation: {reason}")
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import IntEnum
from typing import Any

from proxilion.exceptions import ProxilionError


class TrustBoundaryViolation(ProxilionError):
    """
    Raised when a delegation crosses an invalid trust boundary.

    Attributes:
        reason: Description of the violation.
        chain_depth: Current depth of the delegation chain.
        from_level: Trust level of the issuer.
        to_level: Trust level of the target.

    Example:
        >>> raise TrustBoundaryViolation(
        ...     reason="External agents cannot delegate to internal agents",
        ...     from_level=TrustLevel.EXTERNAL,
        ...     to_level=TrustLevel.INTERNAL,
        ... )
    """

    def __init__(
        self,
        reason: str,
        chain_depth: int | None = None,
        from_level: TrustLevel | None = None,
        to_level: TrustLevel | None = None,
    ):
        self.reason = reason
        self.chain_depth = chain_depth
        self.from_level = from_level
        self.to_level = to_level

        details = {"reason": reason}
        if chain_depth is not None:
            details["chain_depth"] = chain_depth
        if from_level is not None:
            details["from_level"] = from_level.name
        if to_level is not None:
            details["to_level"] = to_level.name

        super().__init__(f"Trust boundary violation: {reason}", details)


class TrustLevel(IntEnum):
    """
    Trust levels for agents.

    Lower values indicate higher trust. This allows trust level
    comparisons using standard comparison operators.

    Example:
        >>> TrustLevel.INTERNAL < TrustLevel.EXTERNAL
        True
        >>> # Trust can only decrease (increase in numeric value)
    """

    INTERNAL = 0
    """Fully trusted internal agents (same organization)."""

    PARTNER = 1
    """Trusted partner agents with formal agreements."""

    EXTERNAL = 2
    """External agents with limited, verified trust."""

    UNTRUSTED = 3
    """No trust - all operations denied."""


@dataclass
class AgentIdentity:
    """
    Identity and trust attributes for an agent.

    Attributes:
        agent_id: Unique identifier for the agent.
        trust_level: The agent's trust level.
        allowed_scopes: Set of scopes this agent can access.
        metadata: Additional metadata about the agent.

    Example:
        >>> agent = AgentIdentity(
        ...     agent_id="data_processor",
        ...     trust_level=TrustLevel.PARTNER,
        ...     allowed_scopes={"read", "transform"},
        ...     metadata={"organization": "partner_corp"},
        ... )
    """

    agent_id: str
    trust_level: TrustLevel
    allowed_scopes: set[str] = field(default_factory=set)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __hash__(self) -> int:
        return hash(self.agent_id)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "agent_id": self.agent_id,
            "trust_level": self.trust_level.name,
            "allowed_scopes": list(self.allowed_scopes),
            "metadata": self.metadata,
        }


@dataclass
class DelegationToken:
    """
    Token representing a delegation of authority from one agent to another.

    Attributes:
        token_id: Unique identifier for this token.
        issuer: Agent ID that created this delegation.
        subject: Agent ID that receives the delegation.
        scopes: Set of scopes being delegated.
        issued_at: When the token was issued.
        expires_at: When the token expires.
        chain: List of prior delegations in the chain.
        signature: Cryptographic signature for integrity.

    Example:
        >>> token = DelegationToken(
        ...     token_id="tok_123",
        ...     issuer="main_agent",
        ...     subject="helper_agent",
        ...     scopes={"read"},
        ...     issued_at=datetime.now(timezone.utc),
        ...     expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        ...     chain=[],
        ... )
    """

    token_id: str
    issuer: str
    subject: str
    scopes: set[str]
    issued_at: datetime
    expires_at: datetime
    chain: list[DelegationToken] = field(default_factory=list)
    signature: str | None = None

    @property
    def is_expired(self) -> bool:
        """Check if the token has expired."""
        return datetime.now(timezone.utc) >= self.expires_at

    @property
    def chain_depth(self) -> int:
        """Get the total depth of the delegation chain."""
        return len(self.chain) + 1

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "token_id": self.token_id,
            "issuer": self.issuer,
            "subject": self.subject,
            "scopes": list(self.scopes),
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "chain_depth": self.chain_depth,
            "chain": [t.token_id for t in self.chain],
        }


@dataclass
class TrustBoundary:
    """
    Definition of a trust boundary between trust levels.

    Attributes:
        from_level: Trust level of the initiator.
        to_level: Trust level of the target (or "*" for any).
        allowed: Whether this boundary crossing is allowed.
        requires_approval: Whether human approval is required.

    Example:
        >>> # Internal can delegate to partner without approval
        >>> boundary = TrustBoundary(
        ...     from_level=TrustLevel.INTERNAL,
        ...     to_level=TrustLevel.PARTNER,
        ...     allowed=True,
        ...     requires_approval=False,
        ... )
    """

    from_level: TrustLevel
    to_level: TrustLevel | str  # str for "*" wildcard
    allowed: bool
    requires_approval: bool = False


# Default trust boundaries
DEFAULT_BOUNDARIES = [
    # Internal can communicate with anyone (external requires approval)
    TrustBoundary(TrustLevel.INTERNAL, TrustLevel.INTERNAL, allowed=True, requires_approval=False),
    TrustBoundary(TrustLevel.INTERNAL, TrustLevel.PARTNER, allowed=True, requires_approval=False),
    TrustBoundary(TrustLevel.INTERNAL, TrustLevel.EXTERNAL, allowed=True, requires_approval=True),
    TrustBoundary(
        TrustLevel.INTERNAL, TrustLevel.UNTRUSTED, allowed=False, requires_approval=False
    ),

    # Partner can communicate with internal (with approval) and other partners
    TrustBoundary(TrustLevel.PARTNER, TrustLevel.INTERNAL, allowed=True, requires_approval=True),
    TrustBoundary(TrustLevel.PARTNER, TrustLevel.PARTNER, allowed=True, requires_approval=False),
    TrustBoundary(TrustLevel.PARTNER, TrustLevel.EXTERNAL, allowed=False, requires_approval=False),
    TrustBoundary(TrustLevel.PARTNER, TrustLevel.UNTRUSTED, allowed=False, requires_approval=False),

    # External can only communicate with each other
    TrustBoundary(TrustLevel.EXTERNAL, TrustLevel.INTERNAL, allowed=False, requires_approval=False),
    TrustBoundary(TrustLevel.EXTERNAL, TrustLevel.PARTNER, allowed=False, requires_approval=False),
    TrustBoundary(TrustLevel.EXTERNAL, TrustLevel.EXTERNAL, allowed=True, requires_approval=False),
    TrustBoundary(
        TrustLevel.EXTERNAL, TrustLevel.UNTRUSTED, allowed=False, requires_approval=False
    ),

    # Untrusted cannot communicate with anyone
    TrustBoundary(TrustLevel.UNTRUSTED, "*", allowed=False, requires_approval=False),
]


class TrustEnforcer:
    """
    Main class for enforcing trust boundaries between agents.

    Manages agent identities, validates delegations, and enforces
    trust boundaries.

    Example:
        >>> enforcer = TrustEnforcer()
        >>>
        >>> # Register agents
        >>> enforcer.register_agent(AgentIdentity(
        ...     agent_id="orchestrator",
        ...     trust_level=TrustLevel.INTERNAL,
        ...     allowed_scopes={"*"},
        ... ))
        >>>
        >>> # Create delegation
        >>> token = enforcer.create_delegation(
        ...     from_agent="orchestrator",
        ...     to_agent="worker",
        ...     scopes={"read", "write"},
        ...     ttl=3600,
        ... )
        >>>
        >>> # Validate before use
        >>> valid, reason = enforcer.validate_delegation(token)
    """

    def __init__(
        self,
        boundaries: list[TrustBoundary] | None = None,
        max_chain_depth: int = 5,
        signing_key: bytes | None = None,
    ):
        """
        Initialize the trust enforcer.

        Args:
            boundaries: List of trust boundaries. Defaults to DEFAULT_BOUNDARIES.
            max_chain_depth: Maximum allowed delegation chain depth.
            signing_key: Secret key for signing tokens. Auto-generated if not provided.
        """
        self.boundaries = boundaries or DEFAULT_BOUNDARIES
        self.max_chain_depth = max_chain_depth
        self._signing_key = signing_key or secrets.token_bytes(32)

        self._agents: dict[str, AgentIdentity] = {}
        self._lock = threading.RLock()

        # Build boundary lookup for fast access
        self._boundary_map: dict[tuple[TrustLevel, TrustLevel | str], TrustBoundary] = {}
        for boundary in self.boundaries:
            key = (boundary.from_level, boundary.to_level)
            self._boundary_map[key] = boundary

    def register_agent(self, identity: AgentIdentity) -> None:
        """
        Register an agent with its identity.

        Args:
            identity: The agent identity to register.

        Example:
            >>> enforcer.register_agent(AgentIdentity(
            ...     agent_id="data_agent",
            ...     trust_level=TrustLevel.PARTNER,
            ...     allowed_scopes={"read", "write"},
            ... ))
        """
        with self._lock:
            self._agents[identity.agent_id] = identity

    def unregister_agent(self, agent_id: str) -> bool:
        """
        Unregister an agent.

        Args:
            agent_id: The agent ID to unregister.

        Returns:
            True if the agent was unregistered, False if not found.
        """
        with self._lock:
            if agent_id in self._agents:
                del self._agents[agent_id]
                return True
            return False

    def get_agent(self, agent_id: str) -> AgentIdentity | None:
        """
        Get an agent's identity.

        Args:
            agent_id: The agent ID to look up.

        Returns:
            The agent identity, or None if not found.
        """
        with self._lock:
            return self._agents.get(agent_id)

    def check_trust_boundary(
        self,
        from_agent: str,
        to_agent: str,
    ) -> tuple[bool, bool]:
        """
        Check if communication between two agents is allowed.

        Args:
            from_agent: The agent initiating communication.
            to_agent: The target agent.

        Returns:
            Tuple of (allowed, requires_approval).

        Raises:
            ValueError: If either agent is not registered.

        Example:
            >>> allowed, needs_approval = enforcer.check_trust_boundary(
            ...     "internal_agent", "external_plugin"
            ... )
            >>> if not allowed:
            ...     raise TrustBoundaryViolation("Not allowed")
        """
        with self._lock:
            from_identity = self._agents.get(from_agent)
            to_identity = self._agents.get(to_agent)

            if from_identity is None:
                raise ValueError(f"Agent not registered: {from_agent}")
            if to_identity is None:
                raise ValueError(f"Agent not registered: {to_agent}")

            return self._check_boundary(
                from_identity.trust_level,
                to_identity.trust_level,
            )

    def _check_boundary(
        self,
        from_level: TrustLevel,
        to_level: TrustLevel,
    ) -> tuple[bool, bool]:
        """Check boundary between trust levels."""
        # Check specific boundary first
        key = (from_level, to_level)
        if key in self._boundary_map:
            boundary = self._boundary_map[key]
            return boundary.allowed, boundary.requires_approval

        # Check wildcard
        wildcard_key = (from_level, "*")
        if wildcard_key in self._boundary_map:
            boundary = self._boundary_map[wildcard_key]
            return boundary.allowed, boundary.requires_approval

        # Default: deny
        return False, False

    def create_delegation(
        self,
        from_agent: str,
        to_agent: str,
        scopes: set[str],
        ttl: int,
        parent_token: DelegationToken | None = None,
    ) -> DelegationToken:
        """
        Create a delegation token.

        Args:
            from_agent: The agent creating the delegation.
            to_agent: The agent receiving the delegation.
            scopes: Scopes to delegate.
            ttl: Time-to-live in seconds.
            parent_token: Optional parent token for chained delegation.

        Returns:
            The created delegation token.

        Raises:
            TrustBoundaryViolation: If the delegation violates trust rules.

        Example:
            >>> token = enforcer.create_delegation(
            ...     from_agent="main",
            ...     to_agent="helper",
            ...     scopes={"read"},
            ...     ttl=3600,
            ... )
        """
        with self._lock:
            from_identity = self._agents.get(from_agent)
            to_identity = self._agents.get(to_agent)

            if from_identity is None:
                raise ValueError(f"Agent not registered: {from_agent}")
            if to_identity is None:
                raise ValueError(f"Agent not registered: {to_agent}")

            # Check trust boundary
            allowed, requires_approval = self._check_boundary(
                from_identity.trust_level,
                to_identity.trust_level,
            )
            if not allowed:
                raise TrustBoundaryViolation(
                    f"Delegation from {from_identity.trust_level.name} to "
                    f"{to_identity.trust_level.name} is not allowed",
                    from_level=from_identity.trust_level,
                    to_level=to_identity.trust_level,
                )

            # Build chain
            chain: list[DelegationToken] = []
            if parent_token:
                chain = parent_token.chain + [parent_token]

                # Check chain depth
                if len(chain) + 1 > self.max_chain_depth:
                    raise TrustBoundaryViolation(
                        f"Delegation chain too long: {len(chain) + 1} > {self.max_chain_depth}",
                        chain_depth=len(chain) + 1,
                    )

            # Validate scope narrowing
            if parent_token:
                if not scopes.issubset(parent_token.scopes):
                    raise TrustBoundaryViolation(
                        f"Scope expansion not allowed: requesting {scopes - parent_token.scopes}",
                    )
            else:
                # Initial delegation - validate against from_agent's allowed scopes
                if "*" not in from_identity.allowed_scopes:
                    if not scopes.issubset(from_identity.allowed_scopes):
                        raise TrustBoundaryViolation(
                            f"Agent {from_agent} cannot delegate scopes: "
                            f"{scopes - from_identity.allowed_scopes}",
                        )

            # Validate against to_agent's allowed scopes
            if "*" not in to_identity.allowed_scopes:
                effective_scopes = scopes & to_identity.allowed_scopes
                if not effective_scopes:
                    raise TrustBoundaryViolation(
                        f"No overlapping scopes for agent {to_agent}",
                    )
                scopes = effective_scopes

            # Create token
            now = datetime.now(timezone.utc)
            token = DelegationToken(
                token_id=f"dtk_{secrets.token_hex(16)}",
                issuer=from_agent,
                subject=to_agent,
                scopes=scopes,
                issued_at=now,
                expires_at=now + timedelta(seconds=ttl),
                chain=chain,
            )

            # Sign the token
            token.signature = self._sign_token(token)

            return token

    def validate_delegation(self, token: DelegationToken) -> tuple[bool, str | None]:
        """
        Validate a delegation token.

        Args:
            token: The token to validate.

        Returns:
            Tuple of (is_valid, error_reason).

        Example:
            >>> valid, reason = enforcer.validate_delegation(token)
            >>> if not valid:
            ...     print(f"Invalid: {reason}")
        """
        with self._lock:
            # Check expiry
            if token.is_expired:
                return False, "Token has expired"

            # Check signature
            if not self._verify_signature(token):
                return False, "Invalid token signature"

            # Check chain depth
            if token.chain_depth > self.max_chain_depth:
                return False, (
                    f"Chain depth {token.chain_depth} exceeds maximum {self.max_chain_depth}"
                )

            # Validate chain
            return self._validate_chain(token)

    def _validate_chain(self, token: DelegationToken) -> tuple[bool, str | None]:
        """Validate the entire delegation chain."""
        if not token.chain:
            # No chain, just validate this token
            return self._validate_single_hop(token.issuer, token.subject, token.scopes)

        # Start with the first token in the chain
        prev_level: TrustLevel | None = None
        prev_scopes: set[str] | None = None  # None means wildcard (all scopes)
        prev_subject: str | None = None

        for i, chain_token in enumerate(token.chain):
            # Verify issuer matches previous subject
            if prev_subject is not None and chain_token.issuer != prev_subject:
                return False, f"Chain broken at hop {i}: expected issuer {prev_subject}"

            # Check expiry
            if chain_token.is_expired:
                return False, f"Token in chain at hop {i} has expired"

            # Get agent identities
            issuer = self._agents.get(chain_token.issuer)
            subject = self._agents.get(chain_token.subject)

            if issuer is None:
                return False, f"Unknown issuer in chain: {chain_token.issuer}"
            if subject is None:
                return False, f"Unknown subject in chain: {chain_token.subject}"

            # Trust can only decrease (level increases)
            if prev_level is not None and subject.trust_level < prev_level:
                return False, (
                    f"Trust escalation detected at hop {i}: "
                    f"{prev_level.name} -> {subject.trust_level.name}"
                )

            # Scopes can only narrow (None/wildcard allows any scopes)
            if prev_scopes is not None and "*" not in prev_scopes:
                if not chain_token.scopes.issubset(prev_scopes):
                    return False, f"Scope expansion detected at hop {i}"

            prev_level = subject.trust_level
            prev_scopes = chain_token.scopes
            prev_subject = chain_token.subject

        # Validate final hop (from last chain token to current token)
        if prev_subject is not None and token.issuer != prev_subject:
            return False, f"Final hop broken: expected issuer {prev_subject}"

        # Check scopes don't expand in final hop (prev_scopes can't be None here if we have a chain)
        if prev_scopes is not None and "*" not in prev_scopes:
            if not token.scopes.issubset(prev_scopes):
                return False, "Scope expansion in final delegation"

        # Validate trust boundary for final hop
        issuer = self._agents.get(token.issuer)
        subject = self._agents.get(token.subject)

        if issuer is None:
            return False, f"Unknown issuer: {token.issuer}"
        if subject is None:
            return False, f"Unknown subject: {token.subject}"

        # Trust can only decrease
        if prev_level is not None and subject.trust_level < prev_level:
            return False, (
                f"Trust escalation in final hop: "
                f"{prev_level.name} -> {subject.trust_level.name}"
            )

        return True, None

    def _validate_single_hop(
        self,
        from_agent: str,
        to_agent: str,
        scopes: set[str],
    ) -> tuple[bool, str | None]:
        """Validate a single delegation hop."""
        from_identity = self._agents.get(from_agent)
        to_identity = self._agents.get(to_agent)

        if from_identity is None:
            return False, f"Unknown issuer: {from_agent}"
        if to_identity is None:
            return False, f"Unknown subject: {to_agent}"

        # Check trust boundary
        allowed, _ = self._check_boundary(
            from_identity.trust_level,
            to_identity.trust_level,
        )
        if not allowed:
            return False, (
                f"Trust boundary violation: {from_identity.trust_level.name} -> "
                f"{to_identity.trust_level.name}"
            )

        return True, None

    def get_delegation_chain(self, token: DelegationToken) -> list[AgentIdentity]:
        """
        Get the full chain of agent identities from a delegation token.

        Args:
            token: The delegation token.

        Returns:
            List of agent identities in the chain, from root to subject.

        Example:
            >>> chain = enforcer.get_delegation_chain(token)
            >>> for agent in chain:
            ...     print(f"{agent.agent_id} ({agent.trust_level.name})")
        """
        with self._lock:
            identities: list[AgentIdentity] = []

            # Add chain token identities
            for chain_token in token.chain:
                issuer = self._agents.get(chain_token.issuer)
                if issuer:
                    identities.append(issuer)

            # Add current token's issuer and subject
            issuer = self._agents.get(token.issuer)
            if issuer:
                identities.append(issuer)

            subject = self._agents.get(token.subject)
            if subject:
                identities.append(subject)

            return identities

    def _sign_token(self, token: DelegationToken) -> str:
        """Generate signature for a token."""
        scopes_str = str(sorted(token.scopes))
        expires_str = token.expires_at.isoformat()
        data = f"{token.token_id}:{token.issuer}:{token.subject}:{scopes_str}:{expires_str}"
        signature = hmac.new(
            self._signing_key,
            data.encode(),
            hashlib.sha256,
        ).hexdigest()
        return signature

    def _verify_signature(self, token: DelegationToken) -> bool:
        """Verify token signature."""
        if not token.signature:
            return False
        expected = self._sign_token(token)
        return hmac.compare_digest(token.signature, expected)

    def get_effective_scopes(self, token: DelegationToken) -> set[str]:
        """
        Get the effective scopes for a delegation token.

        Takes into account scope narrowing through the chain.

        Args:
            token: The delegation token.

        Returns:
            Set of effective scopes.
        """
        with self._lock:
            scopes = token.scopes.copy()

            # Intersect with subject's allowed scopes
            subject = self._agents.get(token.subject)
            if subject and "*" not in subject.allowed_scopes:
                scopes &= subject.allowed_scopes

            return scopes

    def get_all_agents(self) -> list[AgentIdentity]:
        """Get all registered agents."""
        with self._lock:
            return list(self._agents.values())

    def get_agents_by_trust_level(self, trust_level: TrustLevel) -> list[AgentIdentity]:
        """Get all agents at a specific trust level."""
        with self._lock:
            return [
                agent
                for agent in self._agents.values()
                if agent.trust_level == trust_level
            ]
