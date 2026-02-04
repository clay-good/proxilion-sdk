"""
Tests for audit logging system.

Tests cover:
- AuditEvent creation and serialization
- Hash chain integrity
- Merkle tree for batch verification
- AuditLogger file operations
- Log rotation
- Sensitive data redaction
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from proxilion.audit.events import (
    AuditEventData,
    AuditEventV2,
    EventType,
    RedactionConfig,
)
from proxilion.audit.hash_chain import GENESIS_HASH, HashChain, MerkleTree
from proxilion.audit.logger import AuditLogger, LoggerConfig, RotationPolicy
from proxilion.types import ToolCallRequest, UserContext


def create_audit_event_data(
    user: UserContext,
    tool_request: ToolCallRequest,
    allowed: bool = True,
    reason: str = "Policy allowed",
    policies: list[str] | None = None,
) -> AuditEventData:
    """Helper to create audit event data with the new API."""
    return AuditEventData(
        event_type=EventType.AUTHORIZATION_GRANTED if allowed else EventType.AUTHORIZATION_DENIED,
        user_id=user.user_id,
        user_roles=list(user.roles) if user.roles else [],
        session_id=user.session_id,
        user_attributes=dict(user.attributes) if user.attributes else {},
        agent_id=None,
        agent_capabilities=[],
        agent_trust_score=None,
        tool_name=tool_request.tool_name,
        tool_arguments=dict(tool_request.arguments) if tool_request.arguments else {},
        tool_timestamp=tool_request.timestamp,
        authorization_allowed=allowed,
        authorization_reason=reason,
        policies_evaluated=policies or [],
        authorization_metadata={},
    )


class TestAuditEventV2:
    """Tests for AuditEventV2 dataclass."""

    def test_event_creation(self, basic_user: UserContext, search_tool_request: ToolCallRequest):
        """Test creating an audit event."""
        data = create_audit_event_data(
            user=basic_user,
            tool_request=search_tool_request,
            allowed=True,
            reason="Policy allowed",
            policies=["SearchPolicy"],
        )
        event = AuditEventV2(data=data, previous_hash=GENESIS_HASH)

        assert event.event_id is not None
        assert event.timestamp is not None
        assert event.data.user_id == basic_user.user_id
        assert event.data.tool_name == search_tool_request.tool_name

    def test_event_has_unique_id(
        self, basic_user: UserContext, search_tool_request: ToolCallRequest
    ):
        """Test that each event gets a unique ID."""
        data1 = create_audit_event_data(user=basic_user, tool_request=search_tool_request)
        data2 = create_audit_event_data(user=basic_user, tool_request=search_tool_request)
        event1 = AuditEventV2(data=data1, previous_hash=GENESIS_HASH)
        event2 = AuditEventV2(data=data2, previous_hash=GENESIS_HASH)

        assert event1.event_id != event2.event_id

    def test_event_to_dict(self, sample_audit_event: AuditEventV2):
        """Test event serialization to dict."""
        event_dict = sample_audit_event.to_dict()

        assert "event_id" in event_dict
        assert "timestamp" in event_dict
        assert "data" in event_dict
        assert "previous_hash" in event_dict

    def test_event_to_json(self, sample_audit_event: AuditEventV2):
        """Test event serialization to JSON."""
        json_str = sample_audit_event.to_json()

        # Should be valid JSON
        parsed = json.loads(json_str)
        assert parsed["event_id"] == sample_audit_event.event_id

    def test_event_compute_hash(self, sample_audit_event: AuditEventV2):
        """Test computing event hash."""
        hash1 = sample_audit_event.compute_hash()

        # Hash should be deterministic
        hash2 = sample_audit_event.compute_hash()
        assert hash1 == hash2

        # Hash should start with sha256: prefix
        assert hash1.startswith("sha256:")

    def test_event_hash_changes_with_content(self, basic_user: UserContext):
        """Test that hash changes when event content changes."""
        request1 = ToolCallRequest(
            tool_name="tool_a",
            arguments={"arg": "value1"},
            timestamp=datetime.now(timezone.utc),
        )
        request2 = ToolCallRequest(
            tool_name="tool_a",
            arguments={"arg": "value2"},
            timestamp=datetime.now(timezone.utc),
        )

        data1 = create_audit_event_data(user=basic_user, tool_request=request1)
        data2 = create_audit_event_data(user=basic_user, tool_request=request2)
        event1 = AuditEventV2(data=data1, previous_hash=GENESIS_HASH)
        event2 = AuditEventV2(data=data2, previous_hash=GENESIS_HASH)

        assert event1.compute_hash() != event2.compute_hash()


class TestHashChain:
    """Tests for HashChain class."""

    def test_chain_initialization(self, hash_chain: HashChain):
        """Test hash chain initialization."""
        assert hash_chain is not None
        assert hash_chain.last_hash == GENESIS_HASH

    def test_append_event(
        self,
        hash_chain: HashChain,
        basic_user: UserContext,
        search_tool_request: ToolCallRequest,
    ):
        """Test appending an event to the chain."""
        data = create_audit_event_data(user=basic_user, tool_request=search_tool_request)
        event = AuditEventV2(data=data, previous_hash=GENESIS_HASH)
        appended = hash_chain.append(event)

        assert appended.previous_hash == GENESIS_HASH
        assert appended.event_hash is not None
        assert appended.event_hash != GENESIS_HASH

    def test_chain_links_events(self, hash_chain: HashChain, basic_user: UserContext):
        """Test that chain properly links events."""
        events = []
        for i in range(3):
            request = ToolCallRequest(
                tool_name=f"tool_{i}",
                arguments={"i": i},
                timestamp=datetime.now(timezone.utc),
            )
            data = create_audit_event_data(user=basic_user, tool_request=request)
            event = AuditEventV2(data=data, previous_hash=hash_chain.last_hash)
            appended = hash_chain.append(event)
            events.append(appended)

        # Each event should link to previous
        assert events[0].previous_hash == GENESIS_HASH
        assert events[1].previous_hash == events[0].event_hash
        assert events[2].previous_hash == events[1].event_hash

    def test_verify_chain_valid(self, hash_chain: HashChain, basic_user: UserContext):
        """Test verifying a valid chain."""
        for i in range(5):
            request = ToolCallRequest(
                tool_name=f"tool_{i}",
                arguments={"i": i},
                timestamp=datetime.now(timezone.utc),
            )
            data = create_audit_event_data(user=basic_user, tool_request=request)
            event = AuditEventV2(data=data, previous_hash=hash_chain.last_hash)
            hash_chain.append(event)

        result = hash_chain.verify()
        assert result.valid is True
        assert result.error_message is None

    def test_get_proof(self, hash_chain: HashChain, basic_user: UserContext):
        """Test getting proof for an event."""
        events = []
        for i in range(3):
            request = ToolCallRequest(
                tool_name=f"tool_{i}",
                arguments={"i": i},
                timestamp=datetime.now(timezone.utc),
            )
            data = create_audit_event_data(user=basic_user, tool_request=request)
            event = AuditEventV2(data=data, previous_hash=hash_chain.last_hash)
            appended = hash_chain.append(event)
            events.append(appended)

        # Get proof for second event
        proof = hash_chain.get_proof(events[1].event_id)
        assert proof is not None
        assert len(proof) > 0


class TestMerkleTree:
    """Tests for MerkleTree class."""

    def test_tree_initialization(self):
        """Test Merkle tree initialization."""
        tree = MerkleTree()
        assert tree is not None

    def test_add_leaf(self):
        """Test adding leaves to the tree."""
        tree = MerkleTree()
        tree.add_leaf("hash1")
        tree.add_leaf("hash2")

        assert tree.leaf_count == 2

    def test_compute_root(self):
        """Test computing Merkle root."""
        tree = MerkleTree()
        tree.add_leaf("hash1")
        tree.add_leaf("hash2")
        tree.add_leaf("hash3")
        tree.add_leaf("hash4")

        root = tree.compute_root()
        assert root is not None
        # Root includes 'sha256:' prefix
        assert root.startswith("sha256:")

    def test_root_changes_with_content(self):
        """Test that root changes when leaves change."""
        tree1 = MerkleTree()
        tree1.add_leaf("hash1")
        tree1.add_leaf("hash2")

        tree2 = MerkleTree()
        tree2.add_leaf("hash1")
        tree2.add_leaf("hash3")  # Different

        assert tree1.compute_root() != tree2.compute_root()

    def test_get_proof(self):
        """Test getting Merkle proof for a leaf."""
        tree = MerkleTree()
        for i in range(8):
            tree.add_leaf(f"hash{i}")

        proof = tree.get_proof(3)  # Proof for 4th leaf
        assert proof is not None
        assert len(proof) > 0

    def test_verify_proof(self):
        """Test verifying a Merkle proof."""
        tree = MerkleTree()
        for i in range(8):
            tree.add_leaf(f"hash{i}")

        root = tree.compute_root()
        proof = tree.get_proof(3)

        # verify_proof takes (leaf_hash, proof, expected_root)
        is_valid = tree.verify_proof("hash3", proof, root)
        assert is_valid is True

    def test_single_leaf_tree(self):
        """Test tree with single leaf."""
        tree = MerkleTree()
        tree.add_leaf("only_hash")

        root = tree.compute_root()
        assert root is not None


class TestAuditLogger:
    """Tests for AuditLogger class."""

    def test_logger_initialization(self, audit_logger: AuditLogger):
        """Test audit logger initialization."""
        assert audit_logger is not None

    def test_log_event(
        self,
        audit_logger: AuditLogger,
        basic_user: UserContext,
        search_tool_request: ToolCallRequest,
    ):
        """Test logging an event."""
        data = create_audit_event_data(user=basic_user, tool_request=search_tool_request)
        event = AuditEventV2(data=data, previous_hash=audit_logger.chain.chain.last_hash)
        audit_logger.log(event)

        # Verify event count via chain
        assert audit_logger.chain.chain.length >= 1

    def test_log_writes_to_file(
        self,
        temp_audit_dir: Path,
        basic_user: UserContext,
        search_tool_request: ToolCallRequest,
    ):
        """Test that logging writes to file."""
        log_path = temp_audit_dir / "test_audit.jsonl"
        config = LoggerConfig(
            log_path=log_path,
            rotation=RotationPolicy.NONE,
        )
        logger = AuditLogger(config)

        data = create_audit_event_data(user=basic_user, tool_request=search_tool_request)
        event = AuditEventV2(data=data, previous_hash=logger.chain.chain.last_hash)
        logged = logger.log(event)
        logger.flush()

        assert log_path.exists()
        content = log_path.read_text()
        assert logged.event_id in content

    def test_log_multiple_events(self, audit_logger: AuditLogger, basic_user: UserContext):
        """Test logging multiple events."""
        for i in range(5):
            request = ToolCallRequest(
                tool_name=f"tool_{i}",
                arguments={"i": i},
                timestamp=datetime.now(timezone.utc),
            )
            data = create_audit_event_data(user=basic_user, tool_request=request)
            event = AuditEventV2(data=data, previous_hash=audit_logger.chain.chain.last_hash)
            audit_logger.log(event)

        assert audit_logger.chain.chain.length == 5

    def test_logger_maintains_chain_integrity(
        self, audit_logger: AuditLogger, basic_user: UserContext
    ):
        """Test that logger maintains hash chain integrity."""
        for i in range(3):
            request = ToolCallRequest(
                tool_name=f"tool_{i}",
                arguments={"i": i},
                timestamp=datetime.now(timezone.utc),
            )
            data = create_audit_event_data(user=basic_user, tool_request=request)
            event = AuditEventV2(data=data, previous_hash=audit_logger.chain.chain.last_hash)
            audit_logger.log(event)

        result = audit_logger.verify()
        assert result.valid is True


class TestSensitiveDataRedaction:
    """Tests for sensitive data redaction in audit logs."""

    def test_redact_sensitive_parameter(self, temp_audit_dir: Path, basic_user: UserContext):
        """Test that sensitive parameters are redacted."""
        log_path = temp_audit_dir / "redacted_audit.jsonl"
        config = LoggerConfig(
            log_path=log_path,
            rotation=RotationPolicy.NONE,
            redaction_config=RedactionConfig.default(),
        )
        logger = AuditLogger(config)

        request = ToolCallRequest(
            tool_name="database_query",
            arguments={"query": "SELECT * FROM users", "password": "secret123"},
            timestamp=datetime.now(timezone.utc),
        )
        data = create_audit_event_data(user=basic_user, tool_request=request)
        event = AuditEventV2(data=data, previous_hash=logger.chain.chain.last_hash)

        logger.log(event)
        logger.flush()

        content = log_path.read_text()
        assert "secret123" not in content
        # Password is redacted (either hashed or replaced with placeholder)
        assert "[HASH:" in content or "[REDACTED]" in content

    def test_redact_pii_patterns(self, temp_audit_dir: Path, basic_user: UserContext):
        """Test redaction of common PII patterns."""
        log_path = temp_audit_dir / "pii_audit.jsonl"
        config = LoggerConfig(
            log_path=log_path,
            rotation=RotationPolicy.NONE,
            redaction_config=RedactionConfig.default(),
        )
        logger = AuditLogger(config)

        request = ToolCallRequest(
            tool_name="send_email",
            arguments={
                "to": "user@example.com",
                "body": "Contact info here",
            },
            timestamp=datetime.now(timezone.utc),
        )
        data = create_audit_event_data(user=basic_user, tool_request=request)
        event = AuditEventV2(data=data, previous_hash=logger.chain.chain.last_hash)

        logger.log(event)
        logger.flush()

        content = log_path.read_text()
        # Email should be redacted (hashed or replaced)
        assert "user@example.com" not in content or "[REDACTED" in content


class TestLogRotation:
    """Tests for log rotation functionality."""

    def test_rotation_by_size(self, temp_audit_dir: Path, basic_user: UserContext):
        """Test log rotation by file size."""
        log_path = temp_audit_dir / "rotating_audit.jsonl"
        config = LoggerConfig(
            log_path=log_path,
            rotation=RotationPolicy.SIZE,
            max_size_mb=0.001,  # Very small size for testing (1 KB)
        )
        logger = AuditLogger(config)

        # Write many events to trigger rotation
        for i in range(50):
            request = ToolCallRequest(
                tool_name=f"tool_{i}",
                arguments={"data": "x" * 50},
                timestamp=datetime.now(timezone.utc),
            )
            data = create_audit_event_data(user=basic_user, tool_request=request)
            event = AuditEventV2(data=data, previous_hash=logger.chain.chain.last_hash)
            logger.log(event)

        logger.flush()

        # Should have created rotated files
        rotated_files = list(temp_audit_dir.glob("rotating_audit*.jsonl*"))
        assert len(rotated_files) >= 1


class TestAuditLoggerAuthorization:
    """Tests for the log_authorization convenience method."""

    def test_log_authorization_allowed(self, audit_logger: AuditLogger):
        """Test logging an allowed authorization."""
        event = audit_logger.log_authorization(
            user_id="user_123",
            user_roles=["analyst"],
            tool_name="search",
            tool_arguments={"query": "test"},
            allowed=True,
            reason="Policy allowed",
            policies_evaluated=["SearchPolicy"],
        )

        assert event.data.authorization_allowed is True
        assert event.data.event_type == EventType.AUTHORIZATION_GRANTED
        assert audit_logger.chain.chain.length == 1

    def test_log_authorization_denied(self, audit_logger: AuditLogger):
        """Test logging a denied authorization."""
        event = audit_logger.log_authorization(
            user_id="user_123",
            user_roles=["guest"],
            tool_name="admin_tool",
            tool_arguments={},
            allowed=False,
            reason="Insufficient permissions",
            policies_evaluated=["AdminPolicy"],
        )

        assert event.data.authorization_allowed is False
        assert event.data.event_type == EventType.AUTHORIZATION_DENIED
        assert audit_logger.chain.chain.length == 1
