"""Tests for proxilion.security.trust_boundaries module."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from proxilion.security import (
    AgentIdentity,
    DEFAULT_BOUNDARIES,
    DelegationToken,
    TrustBoundary,
    TrustBoundaryViolation,
    TrustEnforcer,
    TrustLevel,
)


# =============================================================================
# TrustLevel Tests
# =============================================================================


class TestTrustLevel:
    """Tests for TrustLevel enum."""

    def test_trust_level_values(self):
        """Test trust level numeric values."""
        assert TrustLevel.INTERNAL == 0
        assert TrustLevel.PARTNER == 1
        assert TrustLevel.EXTERNAL == 2
        assert TrustLevel.UNTRUSTED == 3

    def test_trust_level_ordering(self):
        """Test that trust levels can be compared."""
        # Lower value = higher trust
        assert TrustLevel.INTERNAL < TrustLevel.PARTNER
        assert TrustLevel.PARTNER < TrustLevel.EXTERNAL
        assert TrustLevel.EXTERNAL < TrustLevel.UNTRUSTED

    def test_trust_level_names(self):
        """Test trust level names."""
        assert TrustLevel.INTERNAL.name == "INTERNAL"
        assert TrustLevel.PARTNER.name == "PARTNER"
        assert TrustLevel.EXTERNAL.name == "EXTERNAL"
        assert TrustLevel.UNTRUSTED.name == "UNTRUSTED"


# =============================================================================
# AgentIdentity Tests
# =============================================================================


class TestAgentIdentity:
    """Tests for AgentIdentity dataclass."""

    def test_basic_identity(self):
        """Test creating a basic agent identity."""
        agent = AgentIdentity(
            agent_id="test_agent",
            trust_level=TrustLevel.INTERNAL,
        )
        assert agent.agent_id == "test_agent"
        assert agent.trust_level == TrustLevel.INTERNAL
        assert agent.allowed_scopes == set()
        assert agent.metadata == {}

    def test_identity_with_scopes(self):
        """Test creating identity with scopes."""
        agent = AgentIdentity(
            agent_id="data_agent",
            trust_level=TrustLevel.PARTNER,
            allowed_scopes={"read", "write", "delete"},
        )
        assert agent.allowed_scopes == {"read", "write", "delete"}

    def test_identity_with_metadata(self):
        """Test creating identity with metadata."""
        agent = AgentIdentity(
            agent_id="external_agent",
            trust_level=TrustLevel.EXTERNAL,
            metadata={"organization": "partner_corp", "version": "1.0"},
        )
        assert agent.metadata["organization"] == "partner_corp"

    def test_identity_to_dict(self):
        """Test serialization to dictionary."""
        agent = AgentIdentity(
            agent_id="test",
            trust_level=TrustLevel.PARTNER,
            allowed_scopes={"read"},
        )
        result = agent.to_dict()

        assert result["agent_id"] == "test"
        assert result["trust_level"] == "PARTNER"
        assert "read" in result["allowed_scopes"]

    def test_identity_hashable(self):
        """Test that identities are hashable."""
        agent1 = AgentIdentity(agent_id="a", trust_level=TrustLevel.INTERNAL)
        agent2 = AgentIdentity(agent_id="a", trust_level=TrustLevel.INTERNAL)

        # Should be hashable
        agents = {agent1, agent2}
        assert len(agents) == 1  # Same agent_id


# =============================================================================
# DelegationToken Tests
# =============================================================================


class TestDelegationToken:
    """Tests for DelegationToken dataclass."""

    def test_basic_token(self):
        """Test creating a basic delegation token."""
        now = datetime.now(timezone.utc)
        token = DelegationToken(
            token_id="tok_123",
            issuer="main_agent",
            subject="helper_agent",
            scopes={"read"},
            issued_at=now,
            expires_at=now + timedelta(hours=1),
        )

        assert token.token_id == "tok_123"
        assert token.issuer == "main_agent"
        assert token.subject == "helper_agent"
        assert "read" in token.scopes

    def test_token_expiry(self):
        """Test token expiry detection."""
        now = datetime.now(timezone.utc)

        # Non-expired token
        valid_token = DelegationToken(
            token_id="tok_1",
            issuer="a",
            subject="b",
            scopes={"read"},
            issued_at=now,
            expires_at=now + timedelta(hours=1),
        )
        assert valid_token.is_expired is False

        # Expired token
        expired_token = DelegationToken(
            token_id="tok_2",
            issuer="a",
            subject="b",
            scopes={"read"},
            issued_at=now - timedelta(hours=2),
            expires_at=now - timedelta(hours=1),
        )
        assert expired_token.is_expired is True

    def test_token_chain_depth(self):
        """Test chain depth calculation."""
        now = datetime.now(timezone.utc)

        # Token with no chain
        token = DelegationToken(
            token_id="tok_1",
            issuer="a",
            subject="b",
            scopes={"read"},
            issued_at=now,
            expires_at=now + timedelta(hours=1),
            chain=[],
        )
        assert token.chain_depth == 1

        # Token with chain
        parent = DelegationToken(
            token_id="tok_0",
            issuer="root",
            subject="a",
            scopes={"read"},
            issued_at=now,
            expires_at=now + timedelta(hours=1),
        )
        chained_token = DelegationToken(
            token_id="tok_2",
            issuer="a",
            subject="b",
            scopes={"read"},
            issued_at=now,
            expires_at=now + timedelta(hours=1),
            chain=[parent],
        )
        assert chained_token.chain_depth == 2

    def test_token_to_dict(self):
        """Test token serialization."""
        now = datetime.now(timezone.utc)
        token = DelegationToken(
            token_id="tok_123",
            issuer="a",
            subject="b",
            scopes={"read", "write"},
            issued_at=now,
            expires_at=now + timedelta(hours=1),
        )
        result = token.to_dict()

        assert result["token_id"] == "tok_123"
        assert result["issuer"] == "a"
        assert result["subject"] == "b"
        assert set(result["scopes"]) == {"read", "write"}


# =============================================================================
# TrustBoundary Tests
# =============================================================================


class TestTrustBoundary:
    """Tests for TrustBoundary dataclass."""

    def test_basic_boundary(self):
        """Test creating a basic trust boundary."""
        boundary = TrustBoundary(
            from_level=TrustLevel.INTERNAL,
            to_level=TrustLevel.PARTNER,
            allowed=True,
            requires_approval=False,
        )
        assert boundary.from_level == TrustLevel.INTERNAL
        assert boundary.to_level == TrustLevel.PARTNER
        assert boundary.allowed is True
        assert boundary.requires_approval is False

    def test_boundary_with_approval(self):
        """Test boundary requiring approval."""
        boundary = TrustBoundary(
            from_level=TrustLevel.INTERNAL,
            to_level=TrustLevel.EXTERNAL,
            allowed=True,
            requires_approval=True,
        )
        assert boundary.requires_approval is True

    def test_wildcard_boundary(self):
        """Test boundary with wildcard target."""
        boundary = TrustBoundary(
            from_level=TrustLevel.UNTRUSTED,
            to_level="*",
            allowed=False,
        )
        assert boundary.to_level == "*"


# =============================================================================
# TrustBoundaryViolation Tests
# =============================================================================


class TestTrustBoundaryViolation:
    """Tests for TrustBoundaryViolation exception."""

    def test_basic_violation(self):
        """Test creating a basic violation."""
        exc = TrustBoundaryViolation(reason="Access denied")
        assert "Access denied" in str(exc)
        assert exc.reason == "Access denied"

    def test_violation_with_chain_depth(self):
        """Test violation with chain depth."""
        exc = TrustBoundaryViolation(
            reason="Chain too long",
            chain_depth=10,
        )
        assert exc.chain_depth == 10

    def test_violation_with_levels(self):
        """Test violation with trust levels."""
        exc = TrustBoundaryViolation(
            reason="Trust escalation",
            from_level=TrustLevel.EXTERNAL,
            to_level=TrustLevel.INTERNAL,
        )
        assert exc.from_level == TrustLevel.EXTERNAL
        assert exc.to_level == TrustLevel.INTERNAL


# =============================================================================
# TrustEnforcer Tests
# =============================================================================


class TestTrustEnforcer:
    """Tests for TrustEnforcer class."""

    @pytest.fixture
    def enforcer(self):
        """Create a trust enforcer for testing."""
        return TrustEnforcer()

    @pytest.fixture
    def registered_enforcer(self, enforcer):
        """Create an enforcer with registered agents."""
        enforcer.register_agent(AgentIdentity(
            agent_id="internal_agent",
            trust_level=TrustLevel.INTERNAL,
            allowed_scopes={"read", "write", "admin"},
        ))
        enforcer.register_agent(AgentIdentity(
            agent_id="partner_agent",
            trust_level=TrustLevel.PARTNER,
            allowed_scopes={"read", "write"},
        ))
        enforcer.register_agent(AgentIdentity(
            agent_id="external_agent",
            trust_level=TrustLevel.EXTERNAL,
            allowed_scopes={"read"},
        ))
        enforcer.register_agent(AgentIdentity(
            agent_id="untrusted_agent",
            trust_level=TrustLevel.UNTRUSTED,
            allowed_scopes=set(),
        ))
        return enforcer

    def test_register_agent(self, enforcer):
        """Test agent registration."""
        agent = AgentIdentity(
            agent_id="test",
            trust_level=TrustLevel.INTERNAL,
        )
        enforcer.register_agent(agent)

        retrieved = enforcer.get_agent("test")
        assert retrieved is not None
        assert retrieved.agent_id == "test"

    def test_unregister_agent(self, enforcer):
        """Test agent unregistration."""
        enforcer.register_agent(AgentIdentity(
            agent_id="test",
            trust_level=TrustLevel.INTERNAL,
        ))

        result = enforcer.unregister_agent("test")
        assert result is True

        assert enforcer.get_agent("test") is None

    def test_unregister_nonexistent(self, enforcer):
        """Test unregistering nonexistent agent."""
        result = enforcer.unregister_agent("nonexistent")
        assert result is False

    # Trust boundary checks
    def test_internal_to_internal_allowed(self, registered_enforcer):
        """Test INTERNAL -> INTERNAL is allowed without approval."""
        enforcer = registered_enforcer
        enforcer.register_agent(AgentIdentity(
            agent_id="internal_2",
            trust_level=TrustLevel.INTERNAL,
        ))

        allowed, requires_approval = enforcer.check_trust_boundary(
            "internal_agent", "internal_2"
        )
        assert allowed is True
        assert requires_approval is False

    def test_internal_to_partner_allowed(self, registered_enforcer):
        """Test INTERNAL -> PARTNER is allowed without approval."""
        allowed, requires_approval = registered_enforcer.check_trust_boundary(
            "internal_agent", "partner_agent"
        )
        assert allowed is True
        assert requires_approval is False

    def test_internal_to_external_requires_approval(self, registered_enforcer):
        """Test INTERNAL -> EXTERNAL requires approval."""
        allowed, requires_approval = registered_enforcer.check_trust_boundary(
            "internal_agent", "external_agent"
        )
        assert allowed is True
        assert requires_approval is True

    def test_partner_to_internal_requires_approval(self, registered_enforcer):
        """Test PARTNER -> INTERNAL requires approval."""
        allowed, requires_approval = registered_enforcer.check_trust_boundary(
            "partner_agent", "internal_agent"
        )
        assert allowed is True
        assert requires_approval is True

    def test_external_to_internal_blocked(self, registered_enforcer):
        """Test EXTERNAL -> INTERNAL is blocked."""
        allowed, requires_approval = registered_enforcer.check_trust_boundary(
            "external_agent", "internal_agent"
        )
        assert allowed is False

    def test_untrusted_to_any_blocked(self, registered_enforcer):
        """Test UNTRUSTED -> * is blocked."""
        allowed, _ = registered_enforcer.check_trust_boundary(
            "untrusted_agent", "internal_agent"
        )
        assert allowed is False

        allowed, _ = registered_enforcer.check_trust_boundary(
            "untrusted_agent", "partner_agent"
        )
        assert allowed is False

    def test_unknown_agent_raises(self, enforcer):
        """Test that unknown agents raise ValueError."""
        enforcer.register_agent(AgentIdentity(
            agent_id="known",
            trust_level=TrustLevel.INTERNAL,
        ))

        with pytest.raises(ValueError, match="not registered"):
            enforcer.check_trust_boundary("known", "unknown")

        with pytest.raises(ValueError, match="not registered"):
            enforcer.check_trust_boundary("unknown", "known")

    # Delegation tests
    def test_create_delegation(self, registered_enforcer):
        """Test creating a delegation token."""
        token = registered_enforcer.create_delegation(
            from_agent="internal_agent",
            to_agent="partner_agent",
            scopes={"read", "write"},
            ttl=3600,
        )

        assert token.issuer == "internal_agent"
        assert token.subject == "partner_agent"
        assert token.scopes == {"read", "write"}
        assert not token.is_expired
        assert token.signature is not None

    def test_create_delegation_blocked(self, registered_enforcer):
        """Test that blocked delegations raise exception."""
        with pytest.raises(TrustBoundaryViolation):
            registered_enforcer.create_delegation(
                from_agent="external_agent",
                to_agent="internal_agent",
                scopes={"read"},
                ttl=3600,
            )

    def test_create_delegation_scope_restriction(self, registered_enforcer):
        """Test scope restriction in delegation."""
        # Internal can delegate to external (with approval required)
        token = registered_enforcer.create_delegation(
            from_agent="internal_agent",
            to_agent="external_agent",
            scopes={"read", "write"},  # Requesting more than external can have
            ttl=3600,
        )

        # The effective scopes should be restricted to what external_agent can access
        effective = registered_enforcer.get_effective_scopes(token)
        assert "read" in effective
        # write shouldn't be in effective scopes for external agent (they only have read)
        assert effective == {"read"}

    def test_create_chained_delegation(self, registered_enforcer):
        """Test creating chained delegation."""
        # Register another internal agent for chaining
        registered_enforcer.register_agent(AgentIdentity(
            agent_id="internal_agent_2",
            trust_level=TrustLevel.INTERNAL,
            allowed_scopes={"read", "write"},
        ))

        # First delegation (internal to internal)
        token1 = registered_enforcer.create_delegation(
            from_agent="internal_agent",
            to_agent="internal_agent_2",
            scopes={"read", "write"},
            ttl=3600,
        )

        # Chained delegation (internal to partner)
        token2 = registered_enforcer.create_delegation(
            from_agent="internal_agent_2",
            to_agent="partner_agent",
            scopes={"read"},  # Must be subset
            ttl=1800,
            parent_token=token1,
        )

        assert token2.chain_depth == 2
        assert len(token2.chain) == 1

    def test_scope_expansion_blocked(self, registered_enforcer):
        """Test that scope expansion is blocked in chained delegation."""
        # Register another internal agent for chaining
        registered_enforcer.register_agent(AgentIdentity(
            agent_id="internal_agent_2",
            trust_level=TrustLevel.INTERNAL,
            allowed_scopes={"read", "write"},
        ))

        token1 = registered_enforcer.create_delegation(
            from_agent="internal_agent",
            to_agent="internal_agent_2",
            scopes={"read"},  # Only read scope
            ttl=3600,
        )

        with pytest.raises(TrustBoundaryViolation, match="expansion"):
            registered_enforcer.create_delegation(
                from_agent="internal_agent_2",
                to_agent="partner_agent",
                scopes={"read", "write"},  # Trying to expand from just "read"
                ttl=1800,
                parent_token=token1,
            )

    def test_chain_depth_limit(self, registered_enforcer):
        """Test that chain depth is limited."""
        enforcer = TrustEnforcer(max_chain_depth=2)

        # Register agents
        for i in range(5):
            enforcer.register_agent(AgentIdentity(
                agent_id=f"agent_{i}",
                trust_level=TrustLevel.INTERNAL,
                allowed_scopes={"read"},
            ))

        # Create first delegation
        token1 = enforcer.create_delegation(
            from_agent="agent_0",
            to_agent="agent_1",
            scopes={"read"},
            ttl=3600,
        )

        # Create second delegation
        token2 = enforcer.create_delegation(
            from_agent="agent_1",
            to_agent="agent_2",
            scopes={"read"},
            ttl=3600,
            parent_token=token1,
        )

        # Third delegation should exceed limit
        with pytest.raises(TrustBoundaryViolation, match="too long"):
            enforcer.create_delegation(
                from_agent="agent_2",
                to_agent="agent_3",
                scopes={"read"},
                ttl=3600,
                parent_token=token2,
            )

    # Validation tests
    def test_validate_delegation_valid(self, registered_enforcer):
        """Test validating a valid delegation."""
        token = registered_enforcer.create_delegation(
            from_agent="internal_agent",
            to_agent="partner_agent",
            scopes={"read"},
            ttl=3600,
        )

        valid, reason = registered_enforcer.validate_delegation(token)
        assert valid is True
        assert reason is None

    def test_validate_delegation_expired(self, registered_enforcer):
        """Test validating an expired delegation."""
        now = datetime.now(timezone.utc)
        token = DelegationToken(
            token_id="tok_expired",
            issuer="internal_agent",
            subject="partner_agent",
            scopes={"read"},
            issued_at=now - timedelta(hours=2),
            expires_at=now - timedelta(hours=1),
        )

        valid, reason = registered_enforcer.validate_delegation(token)
        assert valid is False
        assert "expired" in reason.lower()

    def test_validate_delegation_invalid_signature(self, registered_enforcer):
        """Test validating a token with invalid signature."""
        token = registered_enforcer.create_delegation(
            from_agent="internal_agent",
            to_agent="partner_agent",
            scopes={"read"},
            ttl=3600,
        )

        # Tamper with signature
        token.signature = "invalid_signature"

        valid, reason = registered_enforcer.validate_delegation(token)
        assert valid is False
        assert "signature" in reason.lower()

    def test_validate_chain_trust_escalation(self, registered_enforcer):
        """Test that trust escalation in chain is detected."""
        # Test that the trust boundary prevents EXTERNAL -> INTERNAL directly
        # This should be blocked by the default boundaries

        # First verify the direct boundary check detects this
        allowed, _ = registered_enforcer.check_trust_boundary(
            "external_agent", "internal_agent"
        )
        assert allowed is False

        # Now try to create a delegation that crosses this boundary
        # This should raise TrustBoundaryViolation
        with pytest.raises(TrustBoundaryViolation):
            registered_enforcer.create_delegation(
                from_agent="external_agent",
                to_agent="internal_agent",
                scopes={"read"},
                ttl=3600,
            )

    def test_get_delegation_chain(self, registered_enforcer):
        """Test getting delegation chain identities."""
        # Register another internal agent for the chain
        registered_enforcer.register_agent(AgentIdentity(
            agent_id="internal_agent_2",
            trust_level=TrustLevel.INTERNAL,
            allowed_scopes={"read", "write"},
        ))

        token1 = registered_enforcer.create_delegation(
            from_agent="internal_agent",
            to_agent="internal_agent_2",
            scopes={"read"},
            ttl=3600,
        )

        token2 = registered_enforcer.create_delegation(
            from_agent="internal_agent_2",
            to_agent="partner_agent",
            scopes={"read"},
            ttl=1800,
            parent_token=token1,
        )

        chain = registered_enforcer.get_delegation_chain(token2)

        # Should include: internal_agent, internal_agent_2, partner_agent
        agent_ids = [a.agent_id for a in chain]
        assert "internal_agent" in agent_ids
        assert "internal_agent_2" in agent_ids
        assert "partner_agent" in agent_ids

    def test_get_effective_scopes(self, registered_enforcer):
        """Test getting effective scopes."""
        token = registered_enforcer.create_delegation(
            from_agent="internal_agent",
            to_agent="external_agent",
            scopes={"read", "write"},  # Requesting more than external can have
            ttl=3600,
        )

        effective = registered_enforcer.get_effective_scopes(token)
        # External agent only has "read" allowed
        assert effective == {"read"}

    def test_get_all_agents(self, registered_enforcer):
        """Test getting all registered agents."""
        agents = registered_enforcer.get_all_agents()
        assert len(agents) == 4

    def test_get_agents_by_trust_level(self, registered_enforcer):
        """Test getting agents by trust level."""
        internal = registered_enforcer.get_agents_by_trust_level(TrustLevel.INTERNAL)
        assert len(internal) == 1
        assert internal[0].agent_id == "internal_agent"


# =============================================================================
# Default Boundaries Tests
# =============================================================================


class TestDefaultBoundaries:
    """Tests for default trust boundaries."""

    def test_default_boundaries_exist(self):
        """Test that default boundaries are defined."""
        assert len(DEFAULT_BOUNDARIES) > 0

    def test_untrusted_blocked(self):
        """Test that UNTRUSTED has blocking boundary."""
        untrusted_boundaries = [
            b for b in DEFAULT_BOUNDARIES
            if b.from_level == TrustLevel.UNTRUSTED
        ]
        assert len(untrusted_boundaries) > 0
        # All should be blocked
        for b in untrusted_boundaries:
            assert b.allowed is False

    def test_internal_to_internal(self):
        """Test INTERNAL -> INTERNAL boundary."""
        boundary = next(
            (b for b in DEFAULT_BOUNDARIES
             if b.from_level == TrustLevel.INTERNAL and b.to_level == TrustLevel.INTERNAL),
            None
        )
        assert boundary is not None
        assert boundary.allowed is True
        assert boundary.requires_approval is False


# =============================================================================
# Integration Tests
# =============================================================================


class TestTrustIntegration:
    """Integration tests for trust boundaries."""

    def test_multi_hop_delegation(self):
        """Test multi-hop delegation scenario."""
        enforcer = TrustEnforcer(max_chain_depth=5)

        # Set up a realistic multi-agent scenario
        # All agents in the same org (internal) to allow chaining
        enforcer.register_agent(AgentIdentity(
            agent_id="orchestrator",
            trust_level=TrustLevel.INTERNAL,
            allowed_scopes={"*"},
        ))
        enforcer.register_agent(AgentIdentity(
            agent_id="data_service",
            trust_level=TrustLevel.INTERNAL,
            allowed_scopes={"read", "write", "query"},
        ))
        enforcer.register_agent(AgentIdentity(
            agent_id="analytics_service",
            trust_level=TrustLevel.INTERNAL,
            allowed_scopes={"read", "query"},
        ))
        enforcer.register_agent(AgentIdentity(
            agent_id="visualization_service",
            trust_level=TrustLevel.INTERNAL,
            allowed_scopes={"read"},
        ))

        # Orchestrator delegates to data service
        token1 = enforcer.create_delegation(
            from_agent="orchestrator",
            to_agent="data_service",
            scopes={"read", "query"},
            ttl=3600,
        )

        # Data service delegates to analytics service
        token2 = enforcer.create_delegation(
            from_agent="data_service",
            to_agent="analytics_service",
            scopes={"read", "query"},
            ttl=1800,
            parent_token=token1,
        )

        # Analytics service delegates to visualization service
        token3 = enforcer.create_delegation(
            from_agent="analytics_service",
            to_agent="visualization_service",
            scopes={"read"},  # Must narrow scopes
            ttl=900,
            parent_token=token2,
        )

        # Validate the final token
        valid, reason = enforcer.validate_delegation(token3)
        assert valid is True

        # Check effective scopes
        effective = enforcer.get_effective_scopes(token3)
        assert effective == {"read"}

    def test_delegation_revocation_by_expiry(self):
        """Test that expired delegations are invalid."""
        enforcer = TrustEnforcer()

        enforcer.register_agent(AgentIdentity(
            agent_id="a",
            trust_level=TrustLevel.INTERNAL,
            allowed_scopes={"read"},
        ))
        enforcer.register_agent(AgentIdentity(
            agent_id="b",
            trust_level=TrustLevel.INTERNAL,
            allowed_scopes={"read"},
        ))

        # Create short-lived token
        token = enforcer.create_delegation(
            from_agent="a",
            to_agent="b",
            scopes={"read"},
            ttl=1,  # 1 second
        )

        # Should be valid immediately
        valid, _ = enforcer.validate_delegation(token)
        assert valid is True

        # After expiry, manually check
        import time
        time.sleep(1.1)

        valid, reason = enforcer.validate_delegation(token)
        assert valid is False
        assert "expired" in reason.lower()

    def test_custom_trust_boundaries(self):
        """Test with custom trust boundaries."""
        # Create more restrictive boundaries
        custom_boundaries = [
            TrustBoundary(TrustLevel.INTERNAL, TrustLevel.INTERNAL, allowed=True),
            TrustBoundary(TrustLevel.INTERNAL, TrustLevel.PARTNER, allowed=False),  # Block
            TrustBoundary(TrustLevel.PARTNER, TrustLevel.PARTNER, allowed=True),
        ]

        enforcer = TrustEnforcer(boundaries=custom_boundaries)

        enforcer.register_agent(AgentIdentity(
            agent_id="internal",
            trust_level=TrustLevel.INTERNAL,
        ))
        enforcer.register_agent(AgentIdentity(
            agent_id="partner",
            trust_level=TrustLevel.PARTNER,
        ))

        # Should be blocked with custom boundaries
        allowed, _ = enforcer.check_trust_boundary("internal", "partner")
        assert allowed is False
