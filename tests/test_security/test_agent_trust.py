"""Tests for proxilion.security.agent_trust module."""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import pytest

from proxilion.exceptions import AgentTrustError
from proxilion.security.agent_trust import (
    AgentCredential,
    AgentTrustManager,
    DelegationChain,
    DelegationToken,
    SignedMessage,
    TrustLevel,
    VerificationResult,
)


# ---------------------------------------------------------------------------
# TrustLevel
# ---------------------------------------------------------------------------


class TestTrustLevel:
    """Tests for TrustLevel enum ordering and values."""

    def test_values(self):
        assert TrustLevel.UNTRUSTED == 0
        assert TrustLevel.MINIMAL == 1
        assert TrustLevel.LIMITED == 2
        assert TrustLevel.STANDARD == 3
        assert TrustLevel.ELEVATED == 4
        assert TrustLevel.FULL == 5
        assert TrustLevel.SYSTEM == 6

    def test_ordering(self):
        assert TrustLevel.UNTRUSTED < TrustLevel.MINIMAL
        assert TrustLevel.MINIMAL < TrustLevel.LIMITED
        assert TrustLevel.LIMITED < TrustLevel.STANDARD
        assert TrustLevel.STANDARD < TrustLevel.ELEVATED
        assert TrustLevel.ELEVATED < TrustLevel.FULL
        assert TrustLevel.FULL < TrustLevel.SYSTEM

    def test_comparison_with_int(self):
        assert TrustLevel.STANDARD > 2
        assert TrustLevel.STANDARD == 3


# ---------------------------------------------------------------------------
# AgentCredential
# ---------------------------------------------------------------------------


class TestAgentCredential:
    """Tests for AgentCredential dataclass."""

    def _make_credential(self, **overrides):
        defaults = dict(
            agent_id="agent-1",
            trust_level=TrustLevel.STANDARD,
            capabilities={"read", "write"},
            public_key="abc123",
        )
        defaults.update(overrides)
        return AgentCredential(**defaults)

    def test_has_capability_exact(self):
        cred = self._make_credential(capabilities={"read", "write"})
        assert cred.has_capability("read") is True
        assert cred.has_capability("delete") is False

    def test_has_capability_wildcard_star(self):
        cred = self._make_credential(capabilities={"*"})
        assert cred.has_capability("anything") is True
        assert cred.has_capability("read:docs") is True

    def test_has_capability_prefix_wildcard(self):
        cred = self._make_credential(capabilities={"read:*", "write"})
        assert cred.has_capability("read:documents") is True
        assert cred.has_capability("read:logs") is True
        assert cred.has_capability("write") is True
        assert cred.has_capability("delete") is False

    def test_has_capability_no_implicit_hierarchy(self):
        """Having 'read' does NOT grant 'read:documents'."""
        cred = self._make_credential(capabilities={"read"})
        assert cred.has_capability("read:documents") is False

    def test_is_expired_no_expiry(self):
        cred = self._make_credential(expires_at=None)
        assert cred.is_expired() is False

    def test_is_expired_future(self):
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        cred = self._make_credential(expires_at=future)
        assert cred.is_expired() is False

    def test_is_expired_past(self):
        past = datetime.now(timezone.utc) - timedelta(seconds=1)
        cred = self._make_credential(expires_at=past)
        assert cred.is_expired() is True

    def test_can_delegate_to_success(self):
        high = self._make_credential(
            agent_id="high",
            trust_level=TrustLevel.FULL,
            capabilities={"delegate", "read"},
        )
        low = self._make_credential(
            agent_id="low",
            trust_level=TrustLevel.LIMITED,
            capabilities={"read"},
        )
        assert high.can_delegate_to(low) is True

    def test_can_delegate_to_equal_trust_fails(self):
        a = self._make_credential(
            agent_id="a",
            trust_level=TrustLevel.STANDARD,
            capabilities={"delegate"},
        )
        b = self._make_credential(
            agent_id="b",
            trust_level=TrustLevel.STANDARD,
            capabilities={"read"},
        )
        assert a.can_delegate_to(b) is False

    def test_can_delegate_to_lower_trust_no_delegate_cap(self):
        high = self._make_credential(
            agent_id="high",
            trust_level=TrustLevel.FULL,
            capabilities={"read"},
        )
        low = self._make_credential(
            agent_id="low",
            trust_level=TrustLevel.LIMITED,
        )
        assert high.can_delegate_to(low) is False

    def test_can_delegate_to_higher_trust_fails(self):
        low = self._make_credential(
            agent_id="low",
            trust_level=TrustLevel.LIMITED,
            capabilities={"delegate"},
        )
        high = self._make_credential(
            agent_id="high",
            trust_level=TrustLevel.FULL,
        )
        assert low.can_delegate_to(high) is False

    def test_to_dict(self):
        cred = self._make_credential(metadata={"role": "worker"})
        d = cred.to_dict()
        assert d["agent_id"] == "agent-1"
        assert d["trust_level"] == TrustLevel.STANDARD.value
        assert set(d["capabilities"]) == {"read", "write"}
        assert d["metadata"] == {"role": "worker"}
        assert "created_at" in d


# ---------------------------------------------------------------------------
# DelegationToken
# ---------------------------------------------------------------------------


class TestDelegationToken:
    def _make_token(self, **overrides):
        now = datetime.now(timezone.utc)
        defaults = dict(
            token_id="tok-1",
            issuer_agent="issuer",
            delegate_agent="delegate",
            granted_capabilities={"read"},
            issued_at=now,
            expires_at=now + timedelta(hours=1),
            signature="sig",
        )
        defaults.update(overrides)
        return DelegationToken(**defaults)

    def test_is_valid_fresh_token(self):
        token = self._make_token()
        assert token.is_valid() is True

    def test_is_expired(self):
        past = datetime.now(timezone.utc) - timedelta(seconds=1)
        token = self._make_token(expires_at=past)
        assert token.is_expired() is True
        assert token.is_valid() is False

    def test_is_invalid_chain_depth_exceeded(self):
        token = self._make_token(chain_depth=5, max_chain_depth=3)
        assert token.is_valid() is False

    def test_to_dict(self):
        token = self._make_token()
        d = token.to_dict()
        assert d["token_id"] == "tok-1"
        assert d["issuer_agent"] == "issuer"
        assert isinstance(d["granted_capabilities"], list)


# ---------------------------------------------------------------------------
# DelegationChain
# ---------------------------------------------------------------------------


class TestDelegationChain:
    def _make_token(self, issuer, delegate, caps=None, valid=True):
        now = datetime.now(timezone.utc)
        exp = now + timedelta(hours=1) if valid else now - timedelta(seconds=1)
        return DelegationToken(
            token_id=f"tok-{issuer}-{delegate}",
            issuer_agent=issuer,
            delegate_agent=delegate,
            granted_capabilities=caps or {"read"},
            issued_at=now,
            expires_at=exp,
            signature="sig",
        )

    def test_empty_chain_valid(self):
        chain = DelegationChain()
        valid, error = chain.validate()
        assert valid is True
        assert error is None
        assert chain.depth == 0

    def test_add_and_depth(self):
        chain = DelegationChain(max_depth=3)
        t1 = self._make_token("a", "b")
        t2 = self._make_token("b", "c")
        assert chain.add(t1) is True
        assert chain.add(t2) is True
        assert chain.depth == 2

    def test_add_exceeds_max_depth(self):
        chain = DelegationChain(max_depth=2)
        assert chain.add(self._make_token("a", "b")) is True
        assert chain.add(self._make_token("b", "c")) is True
        assert chain.add(self._make_token("c", "d")) is False
        assert chain.depth == 2

    def test_validate_continuous_chain(self):
        chain = DelegationChain(max_depth=3)
        chain.add(self._make_token("a", "b"))
        chain.add(self._make_token("b", "c"))
        valid, error = chain.validate()
        assert valid is True

    def test_validate_broken_chain(self):
        chain = DelegationChain(max_depth=3)
        chain.add(self._make_token("a", "b"))
        chain.add(self._make_token("x", "c"))  # break: b != x
        valid, error = chain.validate()
        assert valid is False
        assert "Chain break" in error

    def test_validate_expired_token_in_chain(self):
        chain = DelegationChain(max_depth=3)
        chain.add(self._make_token("a", "b", valid=False))
        valid, error = chain.validate()
        assert valid is False
        assert "expired" in error

    def test_get_effective_capabilities_intersection(self):
        chain = DelegationChain()
        chain.add(self._make_token("a", "b", caps={"read", "write", "delete"}))
        chain.add(self._make_token("b", "c", caps={"read", "write"}))
        chain.add(self._make_token("c", "d", caps={"read"}))
        assert chain.get_effective_capabilities() == {"read"}

    def test_get_effective_capabilities_empty_chain(self):
        chain = DelegationChain()
        assert chain.get_effective_capabilities() == set()

    def test_tokens_property_returns_copy(self):
        chain = DelegationChain()
        t = self._make_token("a", "b")
        chain.add(t)
        tokens = chain.tokens
        tokens.clear()
        assert chain.depth == 1  # internal list unaffected


# ---------------------------------------------------------------------------
# AgentTrustManager - registration
# ---------------------------------------------------------------------------


@pytest.fixture()
def manager():
    return AgentTrustManager(secret_key="test-secret")


class TestAgentTrustManagerRegistration:
    def test_register_agent(self, manager):
        cred = manager.register_agent(
            "agent-1", TrustLevel.STANDARD, {"read", "write"}
        )
        assert cred.agent_id == "agent-1"
        assert cred.trust_level == TrustLevel.STANDARD
        assert cred.capabilities == {"read", "write"}
        assert cred.public_key  # non-empty

    def test_register_duplicate_raises(self, manager):
        manager.register_agent("agent-1", TrustLevel.STANDARD, {"read"})
        with pytest.raises(AgentTrustError):
            manager.register_agent("agent-1", TrustLevel.STANDARD, {"read"})

    def test_register_with_parent(self, manager):
        manager.register_agent("parent", TrustLevel.FULL, {"delegate", "read"})
        child = manager.register_agent(
            "child", TrustLevel.LIMITED, {"read"}, parent_agent="parent"
        )
        assert child.parent_agent == "parent"

    def test_register_with_missing_parent_raises(self, manager):
        with pytest.raises(AgentTrustError):
            manager.register_agent(
                "child", TrustLevel.LIMITED, {"read"}, parent_agent="ghost"
            )

    def test_register_child_equal_trust_to_parent_raises(self, manager):
        manager.register_agent("parent", TrustLevel.STANDARD, {"read"})
        with pytest.raises(AgentTrustError):
            manager.register_agent(
                "child", TrustLevel.STANDARD, {"read"}, parent_agent="parent"
            )

    def test_register_child_higher_trust_than_parent_raises(self, manager):
        manager.register_agent("parent", TrustLevel.LIMITED, {"read"})
        with pytest.raises(AgentTrustError):
            manager.register_agent(
                "child", TrustLevel.FULL, {"read"}, parent_agent="parent"
            )

    def test_register_with_ttl(self, manager):
        cred = manager.register_agent(
            "temp", TrustLevel.MINIMAL, {"read"}, ttl_seconds=3600
        )
        assert cred.expires_at is not None

    def test_register_with_list_capabilities(self, manager):
        cred = manager.register_agent("agent-1", TrustLevel.STANDARD, ["read", "write"])
        assert cred.capabilities == {"read", "write"}

    def test_unregister_agent(self, manager):
        manager.register_agent("agent-1", TrustLevel.STANDARD, {"read"})
        assert manager.unregister_agent("agent-1") is True
        assert manager.get_agent("agent-1") is None

    def test_unregister_nonexistent(self, manager):
        assert manager.unregister_agent("ghost") is False

    def test_get_agent(self, manager):
        manager.register_agent("agent-1", TrustLevel.STANDARD, {"read"})
        assert manager.get_agent("agent-1") is not None
        assert manager.get_agent("ghost") is None

    def test_get_registered_agents(self, manager):
        manager.register_agent("a", TrustLevel.STANDARD, {"read"})
        manager.register_agent("b", TrustLevel.LIMITED, {"read"})
        agents = manager.get_registered_agents()
        assert set(agents) == {"a", "b"}

    def test_get_trust_level(self, manager):
        manager.register_agent("agent-1", TrustLevel.ELEVATED, {"read"})
        assert manager.get_trust_level("agent-1") == TrustLevel.ELEVATED
        assert manager.get_trust_level("ghost") is None


# ---------------------------------------------------------------------------
# AgentTrustManager - delegation
# ---------------------------------------------------------------------------


class TestAgentTrustManagerDelegation:
    def test_create_delegation_success(self, manager):
        manager.register_agent("boss", TrustLevel.FULL, {"delegate", "read", "write"})
        manager.register_agent("worker", TrustLevel.LIMITED, {"read"})
        token = manager.create_delegation("boss", "worker", {"read"})
        assert token.issuer_agent == "boss"
        assert token.delegate_agent == "worker"
        assert token.granted_capabilities == {"read"}
        assert token.is_valid() is True

    def test_create_delegation_lower_trust_issuer_fails(self, manager):
        manager.register_agent("low", TrustLevel.LIMITED, {"delegate", "read"})
        manager.register_agent("high", TrustLevel.FULL, {"read"})
        with pytest.raises(AgentTrustError):
            manager.create_delegation("low", "high", {"read"})

    def test_create_delegation_equal_trust_fails(self, manager):
        manager.register_agent("a", TrustLevel.STANDARD, {"delegate", "read"})
        manager.register_agent("b", TrustLevel.STANDARD, {"read"})
        with pytest.raises(AgentTrustError):
            manager.create_delegation("a", "b", {"read"})

    def test_create_delegation_missing_delegate_cap_fails(self, manager):
        manager.register_agent("boss", TrustLevel.FULL, {"read"})  # no "delegate"
        manager.register_agent("worker", TrustLevel.LIMITED, {"read"})
        with pytest.raises(AgentTrustError):
            manager.create_delegation("boss", "worker", {"read"})

    def test_create_delegation_caps_not_owned_fails(self, manager):
        manager.register_agent("boss", TrustLevel.FULL, {"delegate", "read"})
        manager.register_agent("worker", TrustLevel.LIMITED, {"read"})
        with pytest.raises(AgentTrustError):
            manager.create_delegation("boss", "worker", {"write"})

    def test_create_delegation_wildcard_issuer_can_delegate_anything(self, manager):
        manager.register_agent("boss", TrustLevel.FULL, {"*"})
        manager.register_agent("worker", TrustLevel.LIMITED, {"read"})
        token = manager.create_delegation("boss", "worker", {"read", "write", "admin"})
        assert token.granted_capabilities == {"read", "write", "admin"}

    def test_create_delegation_unregistered_issuer_fails(self, manager):
        manager.register_agent("worker", TrustLevel.LIMITED, {"read"})
        with pytest.raises(AgentTrustError):
            manager.create_delegation("ghost", "worker", {"read"})

    def test_create_delegation_unregistered_delegate_fails(self, manager):
        manager.register_agent("boss", TrustLevel.FULL, {"delegate", "read"})
        with pytest.raises(AgentTrustError):
            manager.create_delegation("boss", "ghost", {"read"})

    def test_revoke_delegation(self, manager):
        manager.register_agent("boss", TrustLevel.FULL, {"delegate", "read"})
        manager.register_agent("worker", TrustLevel.LIMITED, {"read"})
        token = manager.create_delegation("boss", "worker", {"read"})
        assert manager.revoke_delegation(token.token_id) is True

    def test_revoke_nonexistent_delegation(self, manager):
        assert manager.revoke_delegation("no-such-token") is False

    def test_unregister_agent_revokes_delegations(self, manager):
        manager.register_agent("boss", TrustLevel.FULL, {"delegate", "read"})
        manager.register_agent("worker", TrustLevel.LIMITED, {"read"})
        token = manager.create_delegation("boss", "worker", {"read"})
        manager.unregister_agent("boss")
        # Token should no longer be active
        assert manager.revoke_delegation(token.token_id) is False


# ---------------------------------------------------------------------------
# AgentTrustManager - signed messages
# ---------------------------------------------------------------------------


class TestAgentTrustManagerMessages:
    def test_create_and_verify_message(self, manager):
        manager.register_agent("sender", TrustLevel.STANDARD, {"execute"})
        manager.register_agent("receiver", TrustLevel.STANDARD, {"read"})
        msg = manager.create_signed_message(
            "sender", "receiver", "execute", {"task": "test"}
        )
        assert msg.from_agent == "sender"
        assert msg.to_agent == "receiver"
        assert msg.signature
        result = manager.verify_message(msg)
        assert result.valid is True

    def test_create_message_unknown_sender_raises(self, manager):
        with pytest.raises(AgentTrustError):
            manager.create_signed_message(
                "ghost", "receiver", "execute", {"task": "test"}
            )

    def test_create_message_expired_sender_raises(self, manager):
        manager.register_agent(
            "expired", TrustLevel.STANDARD, {"read"}, ttl_seconds=1
        )
        # Force expiration
        agent = manager.get_agent("expired")
        agent.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        with pytest.raises(AgentTrustError):
            manager.create_signed_message(
                "expired", "receiver", "read", {"data": 1}
            )

    def test_verify_message_replay_detection(self, manager):
        manager.register_agent("sender", TrustLevel.STANDARD, {"execute"})
        manager.register_agent("receiver", TrustLevel.STANDARD, {"read"})
        msg = manager.create_signed_message(
            "sender", "receiver", "execute", {"task": "test"}
        )
        result1 = manager.verify_message(msg)
        assert result1.valid is True
        result2 = manager.verify_message(msg)
        assert result2.valid is False
        assert "Replay" in result2.error

    def test_verify_message_replay_disabled(self, manager):
        manager.register_agent("sender", TrustLevel.STANDARD, {"execute"})
        manager.register_agent("receiver", TrustLevel.STANDARD, {"read"})
        msg = manager.create_signed_message(
            "sender", "receiver", "execute", {"task": "test"}
        )
        r1 = manager.verify_message(msg, check_replay=False)
        r2 = manager.verify_message(msg, check_replay=False)
        assert r1.valid is True
        assert r2.valid is True

    def test_verify_message_too_old(self, manager):
        manager.register_agent("sender", TrustLevel.STANDARD, {"execute"})
        manager.register_agent("receiver", TrustLevel.STANDARD, {"read"})
        msg = manager.create_signed_message(
            "sender", "receiver", "execute", {"task": "test"}
        )
        # Fake old timestamp
        msg.timestamp = time.time() - 600
        # Re-sign won't match, but age check happens first
        result = manager.verify_message(msg, max_age_seconds=300)
        assert result.valid is False
        assert "too old" in result.error

    def test_verify_message_unknown_sender(self, manager):
        manager.register_agent("sender", TrustLevel.STANDARD, {"execute"})
        manager.register_agent("receiver", TrustLevel.STANDARD, {"read"})
        msg = manager.create_signed_message(
            "sender", "receiver", "execute", {"task": "test"}
        )
        manager.unregister_agent("sender")
        result = manager.verify_message(msg)
        assert result.valid is False
        assert "Unknown sender" in result.error

    def test_verify_message_unknown_receiver(self, manager):
        manager.register_agent("sender", TrustLevel.STANDARD, {"execute"})
        msg = manager.create_signed_message(
            "sender", "ghost", "execute", {"task": "test"}
        )
        result = manager.verify_message(msg)
        assert result.valid is False
        assert "Unknown receiver" in result.error

    def test_verify_message_tampered_signature(self, manager):
        manager.register_agent("sender", TrustLevel.STANDARD, {"execute"})
        manager.register_agent("receiver", TrustLevel.STANDARD, {"read"})
        msg = manager.create_signed_message(
            "sender", "receiver", "execute", {"task": "test"}
        )
        msg.signature = "tampered"
        result = manager.verify_message(msg)
        assert result.valid is False
        assert "Invalid signature" in result.error

    def test_verify_message_expired_sender_credential(self, manager):
        manager.register_agent(
            "sender", TrustLevel.STANDARD, {"execute"}, ttl_seconds=3600
        )
        manager.register_agent("receiver", TrustLevel.STANDARD, {"read"})
        msg = manager.create_signed_message(
            "sender", "receiver", "execute", {"task": "test"}
        )
        # Expire the sender after message was created
        agent = manager.get_agent("sender")
        agent.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        result = manager.verify_message(msg)
        assert result.valid is False
        assert "expired" in result.error

    def test_verify_message_sender_lacks_capability(self, manager):
        manager.register_agent("sender", TrustLevel.STANDARD, {"read"})
        manager.register_agent("receiver", TrustLevel.STANDARD, {"read"})
        msg = manager.create_signed_message(
            "sender", "receiver", "execute", {"task": "test"}
        )
        result = manager.verify_message(msg)
        assert result.valid is False
        assert "lacks capability" in result.error

    def test_verify_message_with_delegation_token(self, manager):
        manager.register_agent("boss", TrustLevel.FULL, {"delegate", "execute"})
        manager.register_agent("worker", TrustLevel.LIMITED, {"read"})
        token = manager.create_delegation("boss", "worker", {"execute"})
        msg = manager.create_signed_message(
            "worker", "boss", "execute", {"task": "test"}, delegation_token=token
        )
        result = manager.verify_message(msg)
        assert result.valid is True

    def test_verify_message_with_revoked_delegation(self, manager):
        manager.register_agent("boss", TrustLevel.FULL, {"delegate", "execute"})
        manager.register_agent("worker", TrustLevel.LIMITED, {"read"})
        token = manager.create_delegation("boss", "worker", {"execute"})
        manager.revoke_delegation(token.token_id)
        msg = manager.create_signed_message(
            "worker", "boss", "execute", {"task": "test"}, delegation_token=token
        )
        result = manager.verify_message(msg)
        assert result.valid is False
        assert "revoked" in result.error

    def test_verify_message_untrusted_sender(self, manager):
        manager.register_agent("untrusted", TrustLevel.UNTRUSTED, {"execute"})
        manager.register_agent("receiver", TrustLevel.STANDARD, {"read"})
        msg = manager.create_signed_message(
            "untrusted", "receiver", "execute", {"task": "test"}
        )
        result = manager.verify_message(msg)
        assert result.valid is False
        assert "UNTRUSTED" in result.error

    def test_create_message_with_reply_to(self, manager):
        manager.register_agent("a", TrustLevel.STANDARD, {"execute"})
        manager.register_agent("b", TrustLevel.STANDARD, {"read"})
        msg1 = manager.create_signed_message("a", "b", "execute", {"task": "test"})
        msg2 = manager.create_signed_message(
            "a", "b", "execute", {"task": "follow-up"}, reply_to=msg1.message_id
        )
        assert msg2.reply_to == msg1.message_id

    def test_create_message_with_metadata(self, manager):
        manager.register_agent("a", TrustLevel.STANDARD, {"execute"})
        msg = manager.create_signed_message(
            "a", "b", "execute", {}, metadata={"priority": "high"}
        )
        assert msg.metadata == {"priority": "high"}


# ---------------------------------------------------------------------------
# AgentTrustManager - delegation chain verification
# ---------------------------------------------------------------------------


class TestAgentTrustManagerDelegationChainVerification:
    def test_verify_valid_chain(self, manager):
        manager.register_agent("a", TrustLevel.SYSTEM, {"*"})
        manager.register_agent("b", TrustLevel.FULL, {"delegate", "read"})
        manager.register_agent("c", TrustLevel.LIMITED, {"read"})
        t1 = manager.create_delegation("a", "b", {"read"})
        t2 = manager.create_delegation("b", "c", {"read"})
        chain = DelegationChain(max_depth=3)
        chain.add(t1)
        chain.add(t2)
        result = manager.verify_delegation_chain(chain)
        assert result.valid is True

    def test_verify_chain_with_revoked_token(self, manager):
        manager.register_agent("a", TrustLevel.SYSTEM, {"*"})
        manager.register_agent("b", TrustLevel.FULL, {"delegate", "read"})
        manager.register_agent("c", TrustLevel.LIMITED, {"read"})
        t1 = manager.create_delegation("a", "b", {"read"})
        t2 = manager.create_delegation("b", "c", {"read"})
        manager.revoke_delegation(t1.token_id)
        chain = DelegationChain(max_depth=3)
        chain.add(t1)
        chain.add(t2)
        result = manager.verify_delegation_chain(chain)
        assert result.valid is False
        assert "revoked" in result.error

    def test_verify_empty_chain(self, manager):
        chain = DelegationChain()
        result = manager.verify_delegation_chain(chain)
        assert result.valid is True


# ---------------------------------------------------------------------------
# AgentTrustManager - cleanup
# ---------------------------------------------------------------------------


class TestAgentTrustManagerCleanup:
    def test_cleanup_expired_agents(self, manager):
        manager.register_agent(
            "temp", TrustLevel.MINIMAL, {"read"}, ttl_seconds=3600
        )
        # Force expiration
        agent = manager.get_agent("temp")
        agent.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        count = manager.cleanup_expired()
        assert count >= 1
        assert manager.get_agent("temp") is None

    def test_cleanup_no_expired(self, manager):
        manager.register_agent("perm", TrustLevel.STANDARD, {"read"})
        count = manager.cleanup_expired()
        assert count == 0


# ---------------------------------------------------------------------------
# Serialization (to_dict)
# ---------------------------------------------------------------------------


class TestSerialization:
    def test_signed_message_to_dict(self, manager):
        manager.register_agent("a", TrustLevel.STANDARD, {"execute"})
        msg = manager.create_signed_message("a", "b", "execute", {"k": "v"})
        d = msg.to_dict()
        assert d["from_agent"] == "a"
        assert d["action"] == "execute"
        assert d["payload"] == {"k": "v"}
        assert d["delegation_token"] is None

    def test_signed_message_to_dict_with_delegation(self, manager):
        manager.register_agent("boss", TrustLevel.FULL, {"delegate", "execute"})
        manager.register_agent("worker", TrustLevel.LIMITED, {"read"})
        token = manager.create_delegation("boss", "worker", {"execute"})
        msg = manager.create_signed_message(
            "worker", "boss", "execute", {}, delegation_token=token
        )
        d = msg.to_dict()
        assert d["delegation_token"] is not None
        assert d["delegation_token"]["issuer_agent"] == "boss"

    def test_verification_result_to_dict(self):
        r = VerificationResult(valid=True, warnings=["something"])
        d = r.to_dict()
        assert d["valid"] is True
        assert d["warnings"] == ["something"]
        assert d["error"] is None
        assert "verified_at" in d
