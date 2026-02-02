"""
Hash chain implementation for tamper-evident audit logging.

This module provides cryptographic data structures for ensuring
the integrity of audit logs:

- HashChain: Linear chain where each event links to the previous
- MerkleTree: Binary tree for batch aggregation and efficient proofs
"""

from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from proxilion.audit.events import AuditEventV2

# Genesis hash is the starting point of every new chain
GENESIS_HASH = "sha256:0000000000000000000000000000000000000000000000000000000000000000"


@dataclass
class ChainVerificationResult:
    """Result of verifying a hash chain."""
    valid: bool
    error_message: str | None = None
    error_index: int | None = None
    verified_count: int = 0


class HashChain:
    """
    A hash chain for tamper-evident audit logging.

    Each event in the chain contains the hash of the previous event,
    creating an unbroken chain from the genesis event. Any modification
    to a historical event will break the chain and be detectable.

    Thread Safety:
        All operations are thread-safe using internal locking.

    Example:
        >>> chain = HashChain()
        >>> event1 = AuditEventV2(data=..., previous_hash=GENESIS_HASH)
        >>> event1 = chain.append(event1)
        >>> print(event1.event_hash)  # Hash is now computed
        >>>
        >>> event2 = AuditEventV2(data=..., previous_hash=event1.event_hash)
        >>> event2 = chain.append(event2)
        >>>
        >>> result = chain.verify()
        >>> print(result.valid)  # True if chain is intact
    """

    def __init__(self) -> None:
        """Initialize an empty hash chain."""
        self._events: list[AuditEventV2] = []
        self._hashes: dict[str, int] = {}  # hash -> index mapping
        self._lock = threading.RLock()
        self._last_hash = GENESIS_HASH

    @property
    def genesis_hash(self) -> str:
        """Get the genesis hash constant."""
        return GENESIS_HASH

    @property
    def last_hash(self) -> str:
        """Get the hash of the last event in the chain."""
        with self._lock:
            return self._last_hash

    @property
    def length(self) -> int:
        """Get the number of events in the chain."""
        with self._lock:
            return len(self._events)

    def append(self, event: AuditEventV2) -> AuditEventV2:
        """
        Append an event to the chain.

        Computes and sets the event's hash, linking it to the
        previous event in the chain.

        Args:
            event: The event to append.

        Returns:
            The event with computed hash.

        Raises:
            ValueError: If the event's previous_hash doesn't match
                the current chain head.
        """
        with self._lock:
            # Verify the event links to the current chain head
            if event.previous_hash != self._last_hash:
                raise ValueError(
                    f"Event previous_hash ({event.previous_hash}) doesn't match "
                    f"chain head ({self._last_hash})"
                )

            # Compute the event's hash
            event.compute_hash()

            # Add to chain
            index = len(self._events)
            self._events.append(event)
            self._hashes[event.event_hash] = index
            self._last_hash = event.event_hash

            return event

    def create_and_append(self, event: AuditEventV2) -> AuditEventV2:
        """
        Create an event with correct previous_hash and append it.

        This is a convenience method that automatically sets the
        previous_hash to the current chain head before appending.

        Args:
            event: The event to modify and append.

        Returns:
            The event with computed hash.
        """
        with self._lock:
            # Update the previous_hash to link to chain head
            # Since AuditEventV2 is a dataclass, we need to create a new one
            # or modify it directly (it's not frozen)
            event.previous_hash = self._last_hash
            return self.append(event)

    def verify(self) -> ChainVerificationResult:
        """
        Verify the entire hash chain.

        Checks that:
        1. Each event's stored hash matches its computed hash
        2. Each event's previous_hash matches the prior event's hash
        3. The first event links to the genesis hash

        Returns:
            ChainVerificationResult with validity status and details.
        """
        with self._lock:
            if not self._events:
                return ChainVerificationResult(valid=True, verified_count=0)

            # Verify first event links to genesis
            if self._events[0].previous_hash != GENESIS_HASH:
                return ChainVerificationResult(
                    valid=False,
                    error_message="First event doesn't link to genesis hash",
                    error_index=0,
                    verified_count=0,
                )

            expected_previous = GENESIS_HASH

            for i, event in enumerate(self._events):
                # Check previous_hash linkage
                if event.previous_hash != expected_previous:
                    return ChainVerificationResult(
                        valid=False,
                        error_message=(
                            f"Chain broken at index {i}: expected previous_hash "
                            f"{expected_previous}, got {event.previous_hash}"
                        ),
                        error_index=i,
                        verified_count=i,
                    )

                # Verify the event's own hash
                if not event.verify_hash():
                    return ChainVerificationResult(
                        valid=False,
                        error_message=f"Invalid hash at index {i}: event tampered",
                        error_index=i,
                        verified_count=i,
                    )

                expected_previous = event.event_hash

            return ChainVerificationResult(
                valid=True,
                verified_count=len(self._events),
            )

    def get_event(self, index: int) -> AuditEventV2 | None:
        """
        Get an event by index.

        Args:
            index: Zero-based index of the event.

        Returns:
            The event at that index, or None if out of bounds.
        """
        with self._lock:
            if 0 <= index < len(self._events):
                return self._events[index]
            return None

    def get_event_by_hash(self, event_hash: str) -> AuditEventV2 | None:
        """
        Get an event by its hash.

        Args:
            event_hash: The event's hash.

        Returns:
            The event with that hash, or None if not found.
        """
        with self._lock:
            if event_hash in self._hashes:
                return self._events[self._hashes[event_hash]]
            return None

    def get_proof(self, event_id: str) -> list[str]:
        """
        Get the hash path from an event to the chain head.

        This proof can be used to verify that an event is part
        of the chain without having access to all events.

        Args:
            event_id: The event's ID.

        Returns:
            List of hashes from the event to the chain head.
        """
        with self._lock:
            # Find the event
            event_index = None
            for i, event in enumerate(self._events):
                if event.event_id == event_id:
                    event_index = i
                    break

            if event_index is None:
                return []

            # Build the hash path
            proof = [self._events[event_index].event_hash]
            for i in range(event_index + 1, len(self._events)):
                proof.append(self._events[i].event_hash)

            return proof

    def __iter__(self) -> Iterator[AuditEventV2]:
        """Iterate over events in order."""
        with self._lock:
            return iter(list(self._events))

    def __len__(self) -> int:
        """Get number of events."""
        return self.length

    def to_list(self) -> list[dict[str, Any]]:
        """Export chain as a list of dictionaries."""
        with self._lock:
            return [event.to_dict() for event in self._events]


class MerkleTree:
    """
    A Merkle tree for batch aggregation of audit events.

    Merkle trees allow efficient verification of event inclusion
    without needing the entire dataset. Events are grouped into
    batches, and each batch is summarized by a Merkle root hash.

    This is useful for:
    - Periodic external anchoring (e.g., to a blockchain)
    - Efficient inclusion proofs for specific events
    - Batch verification of audit logs

    Example:
        >>> tree = MerkleTree()
        >>> tree.add_leaf("sha256:abc...")
        >>> tree.add_leaf("sha256:def...")
        >>> root = tree.compute_root()
        >>> proof = tree.get_proof(0)  # Proof for first leaf
    """

    def __init__(self) -> None:
        """Initialize an empty Merkle tree."""
        self._leaves: list[str] = []
        self._root: str | None = None
        self._lock = threading.RLock()

    @property
    def leaf_count(self) -> int:
        """Get the number of leaves."""
        with self._lock:
            return len(self._leaves)

    @property
    def root(self) -> str | None:
        """Get the Merkle root (None if tree is empty or not computed)."""
        with self._lock:
            return self._root

    def add_leaf(self, hash_value: str) -> int:
        """
        Add a leaf (hash) to the tree.

        Args:
            hash_value: The hash to add as a leaf.

        Returns:
            The index of the added leaf.
        """
        with self._lock:
            index = len(self._leaves)
            self._leaves.append(hash_value)
            self._root = None  # Invalidate cached root
            return index

    def add_event(self, event: AuditEventV2) -> int:
        """
        Add an event's hash as a leaf.

        Args:
            event: The audit event.

        Returns:
            The index of the added leaf.
        """
        if not event.event_hash:
            event.compute_hash()
        return self.add_leaf(event.event_hash)

    def compute_root(self) -> str:
        """
        Compute the Merkle root hash.

        Returns:
            The Merkle root hash.

        Raises:
            ValueError: If the tree is empty.
        """
        with self._lock:
            if not self._leaves:
                raise ValueError("Cannot compute root of empty tree")

            # Use cached root if available
            if self._root is not None:
                return self._root

            # Build the tree
            current_level = self._leaves.copy()

            while len(current_level) > 1:
                next_level = []
                for i in range(0, len(current_level), 2):
                    left = current_level[i]
                    # If odd number of nodes, duplicate the last one
                    right = current_level[i + 1] if i + 1 < len(current_level) else left
                    combined = self._hash_pair(left, right)
                    next_level.append(combined)
                current_level = next_level

            self._root = current_level[0]
            return self._root

    def get_proof(self, leaf_index: int) -> list[tuple[str, str]]:
        """
        Get the Merkle proof for a leaf.

        The proof is a list of (hash, side) tuples that can be used
        to verify the leaf is part of the tree with the computed root.

        Args:
            leaf_index: Index of the leaf.

        Returns:
            List of (hash, side) tuples where side is 'L' or 'R'.

        Raises:
            IndexError: If leaf_index is out of bounds.
        """
        with self._lock:
            if not 0 <= leaf_index < len(self._leaves):
                raise IndexError(f"Leaf index {leaf_index} out of bounds")

            if len(self._leaves) == 1:
                return []

            proof = []
            current_level = self._leaves.copy()
            index = leaf_index

            while len(current_level) > 1:
                next_level = []
                for i in range(0, len(current_level), 2):
                    left = current_level[i]
                    right = current_level[i + 1] if i + 1 < len(current_level) else left

                    # If this pair contains our target
                    if i == (index // 2) * 2:
                        if index % 2 == 0:
                            # Target is on left, sibling is on right
                            if i + 1 < len(current_level):
                                proof.append((right, 'R'))
                            # else: no sibling needed (duplicated)
                        else:
                            # Target is on right, sibling is on left
                            proof.append((left, 'L'))

                    next_level.append(self._hash_pair(left, right))

                current_level = next_level
                index = index // 2

            return proof

    def verify_proof(
        self,
        leaf_hash: str,
        proof: list[tuple[str, str]],
        expected_root: str,
    ) -> bool:
        """
        Verify a Merkle proof.

        Args:
            leaf_hash: The hash of the leaf being verified.
            proof: The Merkle proof from get_proof().
            expected_root: The expected Merkle root.

        Returns:
            True if the proof is valid.
        """
        current = leaf_hash

        for sibling_hash, side in proof:
            if side == 'L':
                current = self._hash_pair(sibling_hash, current)
            else:
                current = self._hash_pair(current, sibling_hash)

        return current == expected_root

    def _hash_pair(self, left: str, right: str) -> str:
        """Hash two values together."""
        # Remove 'sha256:' prefix for consistent hashing
        left_clean = left.replace("sha256:", "")
        right_clean = right.replace("sha256:", "")
        combined = f"{left_clean}{right_clean}"
        hash_value = hashlib.sha256(combined.encode()).hexdigest()
        return f"sha256:{hash_value}"

    def clear(self) -> None:
        """Clear all leaves from the tree."""
        with self._lock:
            self._leaves.clear()
            self._root = None

    def to_dict(self) -> dict[str, Any]:
        """Export tree state as a dictionary."""
        with self._lock:
            return {
                "leaves": self._leaves.copy(),
                "root": self._root,
                "leaf_count": len(self._leaves),
            }


@dataclass
class MerkleBatch:
    """
    A batch of audit events with Merkle tree aggregation.

    Batches are created periodically (e.g., every N events or every hour)
    and can be externally anchored for additional tamper evidence.

    Attributes:
        batch_id: Unique identifier for this batch.
        start_sequence: First sequence number in batch.
        end_sequence: Last sequence number in batch.
        event_count: Number of events in batch.
        merkle_root: The Merkle root hash.
        created_at: When the batch was finalized.
        previous_batch_root: Merkle root of previous batch (for chaining).
    """
    batch_id: str
    start_sequence: int
    end_sequence: int
    event_count: int
    merkle_root: str
    created_at: str
    previous_batch_root: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "batch_id": self.batch_id,
            "start_sequence": self.start_sequence,
            "end_sequence": self.end_sequence,
            "event_count": self.event_count,
            "merkle_root": self.merkle_root,
            "created_at": self.created_at,
            "previous_batch_root": self.previous_batch_root,
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), sort_keys=True)


class BatchedHashChain:
    """
    Hash chain with periodic Merkle tree batching.

    Combines linear hash chaining with batch aggregation
    for efficient verification and external anchoring.

    Example:
        >>> chain = BatchedHashChain(batch_size=100)
        >>> for event in events:
        ...     chain.append(event)
        >>> batch = chain.finalize_batch()  # Creates Merkle root
    """

    def __init__(self, batch_size: int = 100) -> None:
        """
        Initialize the batched hash chain.

        Args:
            batch_size: Number of events per batch.
        """
        self._chain = HashChain()
        self._current_tree = MerkleTree()
        self._batch_size = batch_size
        self._batches: list[MerkleBatch] = []
        self._lock = threading.RLock()
        self._batch_counter = 0

    @property
    def chain(self) -> HashChain:
        """Get the underlying hash chain."""
        return self._chain

    @property
    def batches(self) -> list[MerkleBatch]:
        """Get all finalized batches."""
        with self._lock:
            return list(self._batches)

    def append(self, event: AuditEventV2) -> AuditEventV2:
        """
        Append an event to the chain.

        Automatically finalizes batch when batch_size is reached.

        Args:
            event: The event to append.

        Returns:
            The event with computed hash and merkle_index.
        """
        with self._lock:
            # Link to chain and compute hash
            event.previous_hash = self._chain.last_hash
            event = self._chain.append(event)

            # Add to current Merkle tree
            event.merkle_index = self._current_tree.add_leaf(event.event_hash)

            # Auto-finalize batch if full
            if self._current_tree.leaf_count >= self._batch_size:
                self._finalize_current_batch()

            return event

    def finalize_batch(self) -> MerkleBatch | None:
        """
        Finalize the current batch and start a new one.

        Returns:
            The finalized batch, or None if no events in current batch.
        """
        with self._lock:
            return self._finalize_current_batch()

    def _finalize_current_batch(self) -> MerkleBatch | None:
        """Internal method to finalize current batch."""
        if self._current_tree.leaf_count == 0:
            return None

        from datetime import datetime, timezone

        self._batch_counter += 1
        merkle_root = self._current_tree.compute_root()

        # Calculate sequence range
        chain_length = self._chain.length
        start_seq = chain_length - self._current_tree.leaf_count + 1
        end_seq = chain_length

        batch = MerkleBatch(
            batch_id=f"batch_{self._batch_counter}",
            start_sequence=start_seq,
            end_sequence=end_seq,
            event_count=self._current_tree.leaf_count,
            merkle_root=merkle_root,
            created_at=datetime.now(timezone.utc).isoformat(),
            previous_batch_root=self._batches[-1].merkle_root if self._batches else None,
        )

        self._batches.append(batch)
        self._current_tree = MerkleTree()  # Start new tree

        return batch

    def get_inclusion_proof(self, event: AuditEventV2) -> dict[str, Any] | None:
        """
        Get proof that an event is included in a batch.

        Args:
            event: The event to prove inclusion for.

        Returns:
            Proof data including Merkle path and batch info.
        """
        if event.merkle_index is None:
            return None

        # Find which batch contains this event
        for batch in self._batches:
            # Check if event sequence is in this batch's range
            event_seq = event.sequence_number
            if batch.start_sequence <= event_seq <= batch.end_sequence:
                # Reconstruct the tree for this batch to get proof
                # (In production, you'd cache the tree structure)
                return {
                    "event_hash": event.event_hash,
                    "batch_id": batch.batch_id,
                    "merkle_root": batch.merkle_root,
                    "merkle_index": event.merkle_index,
                    # Full proof would require storing tree structure
                }

        return None
