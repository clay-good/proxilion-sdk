"""
Priority queue implementation for request scheduling.

Provides a thread-safe priority queue with aging mechanism
to prevent starvation of low-priority requests.
"""

from __future__ import annotations

import heapq
import logging
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any

logger = logging.getLogger(__name__)


class PriorityLevel(IntEnum):
    """
    Request priority levels.

    Lower values = higher priority.

    Attributes:
        CRITICAL: Highest priority, processed immediately.
        HIGH: Important requests, processed before normal.
        NORMAL: Default priority level.
        LOW: Background tasks, can be delayed.
        BACKGROUND: Lowest priority, processed when idle.
    """

    CRITICAL = 0
    HIGH = 1
    NORMAL = 2
    LOW = 3
    BACKGROUND = 4


@dataclass(order=True)
class QueuedRequest:
    """
    A request queued for processing.

    Attributes:
        id: Unique identifier for the request.
        priority: Priority level for ordering.
        created_at: When the request was created.
        timeout: Maximum time to wait in queue (seconds).
        payload: Request data to process.
        callback: Optional callback when processed.
        metadata: Additional metadata about the request.

    Example:
        >>> request = QueuedRequest(
        ...     id="req-123",
        ...     priority=PriorityLevel.HIGH,
        ...     payload={"tool": "search", "args": {"query": "test"}},
        ...     timeout=30.0,
        ... )
    """

    # Sort key: (priority, created_at) - lower priority value and earlier time wins
    sort_key: tuple[int, float] = field(init=False, repr=False, compare=True)

    id: str = field(default_factory=lambda: str(uuid.uuid4()), compare=False)
    priority: PriorityLevel = field(default=PriorityLevel.NORMAL, compare=False)
    created_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc), compare=False
    )
    timeout: float | None = field(default=None, compare=False)
    payload: Any = field(default=None, compare=False)
    callback: Callable[[Any], None] | None = field(default=None, compare=False)
    metadata: dict[str, Any] = field(default_factory=dict, compare=False)

    # Track original priority for aging
    _original_priority: PriorityLevel = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Initialize sort key and original priority."""
        self._original_priority = self.priority
        self._update_sort_key()

    def _update_sort_key(self) -> None:
        """Update sort key based on current priority and creation time."""
        self.sort_key = (self.priority.value, self.created_at.timestamp())

    def boost_priority(self, levels: int = 1) -> bool:
        """
        Boost the priority of this request.

        Args:
            levels: Number of priority levels to boost.

        Returns:
            True if priority was boosted, False if already at highest.
        """
        new_value = max(0, self.priority.value - levels)
        if new_value < self.priority.value:
            self.priority = PriorityLevel(new_value)
            self._update_sort_key()
            return True
        return False

    def is_expired(self) -> bool:
        """Check if the request has exceeded its timeout."""
        if self.timeout is None:
            return False
        age = (datetime.now(timezone.utc) - self.created_at).total_seconds()
        return age > self.timeout

    def age_seconds(self) -> float:
        """Get the age of this request in seconds."""
        return (datetime.now(timezone.utc) - self.created_at).total_seconds()

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "id": self.id,
            "priority": self.priority.name,
            "original_priority": self._original_priority.name,
            "created_at": self.created_at.isoformat(),
            "timeout": self.timeout,
            "age_seconds": self.age_seconds(),
            "is_expired": self.is_expired(),
            "metadata": self.metadata,
        }


class PriorityQueue:
    """
    Thread-safe priority queue with aging mechanism.

    Implements a priority queue that prevents starvation of
    low-priority requests by periodically boosting their priority.

    Attributes:
        max_size: Maximum number of requests in queue.
        aging_interval: Seconds before priority boost.
        aging_boost: Priority levels to boost on aging.

    Example:
        >>> queue = PriorityQueue(max_size=100, aging_interval=60.0)
        >>>
        >>> # Enqueue requests
        >>> queue.enqueue(QueuedRequest(priority=PriorityLevel.LOW, payload="task1"))
        >>> queue.enqueue(QueuedRequest(priority=PriorityLevel.HIGH, payload="task2"))
        >>>
        >>> # High priority dequeued first
        >>> req = queue.dequeue()
        >>> assert req.payload == "task2"
        >>>
        >>> # Check queue stats
        >>> print(queue.size_by_priority())
    """

    def __init__(
        self,
        max_size: int = 1000,
        aging_interval: float = 60.0,
        aging_boost: int = 1,
    ) -> None:
        """
        Initialize the priority queue.

        Args:
            max_size: Maximum number of requests in queue.
            aging_interval: Seconds before priority boost.
            aging_boost: Priority levels to boost on aging.
        """
        self.max_size = max_size
        self.aging_interval = aging_interval
        self.aging_boost = aging_boost

        self._heap: list[QueuedRequest] = []
        self._lock = threading.RLock()
        self._not_empty = threading.Condition(self._lock)
        self._not_full = threading.Condition(self._lock)

        # Track requests by ID for fast lookup
        self._request_map: dict[str, QueuedRequest] = {}

        # Statistics
        self._total_enqueued = 0
        self._total_dequeued = 0
        self._total_expired = 0
        self._total_aged = 0

    def enqueue(
        self,
        request: QueuedRequest,
        block: bool = True,
        timeout: float | None = None,
    ) -> bool:
        """
        Add a request to the queue.

        Args:
            request: The request to enqueue.
            block: Whether to block if queue is full.
            timeout: Maximum time to wait (seconds).

        Returns:
            True if enqueued, False if queue is full and not blocking.

        Raises:
            ValueError: If request with same ID already exists.
        """
        with self._not_full:
            if request.id in self._request_map:
                raise ValueError(f"Request with ID {request.id} already in queue")

            while len(self._heap) >= self.max_size:
                if not block:
                    return False
                if not self._not_full.wait(timeout):
                    return False  # Timeout

            heapq.heappush(self._heap, request)
            self._request_map[request.id] = request
            self._total_enqueued += 1

            self._not_empty.notify()
            return True

    def dequeue(
        self,
        block: bool = True,
        timeout: float | None = None,
    ) -> QueuedRequest | None:
        """
        Remove and return the highest priority request.

        Args:
            block: Whether to block if queue is empty.
            timeout: Maximum time to wait (seconds).

        Returns:
            The highest priority request, or None if empty/timeout.
        """
        with self._not_empty:
            while not self._heap:
                if not block:
                    return None
                if not self._not_empty.wait(timeout):
                    return None  # Timeout

            # Age requests before dequeuing
            self._age_requests()

            # Remove expired requests
            self._remove_expired()

            if not self._heap:
                return None

            # Re-heapify after aging may have changed priorities
            heapq.heapify(self._heap)

            request = heapq.heappop(self._heap)
            self._request_map.pop(request.id, None)
            self._total_dequeued += 1

            self._not_full.notify()
            return request

    def peek(self) -> QueuedRequest | None:
        """
        View the highest priority request without removing it.

        Returns:
            The highest priority request, or None if empty.
        """
        with self._lock:
            if not self._heap:
                return None
            return self._heap[0]

    def size(self) -> int:
        """Get the current queue size."""
        with self._lock:
            return len(self._heap)

    def is_empty(self) -> bool:
        """Check if the queue is empty."""
        return self.size() == 0

    def is_full(self) -> bool:
        """Check if the queue is full."""
        return self.size() >= self.max_size

    def size_by_priority(self) -> dict[PriorityLevel, int]:
        """
        Get queue size breakdown by priority level.

        Returns:
            Dictionary mapping priority levels to counts.
        """
        with self._lock:
            counts: dict[PriorityLevel, int] = dict.fromkeys(PriorityLevel, 0)
            for request in self._heap:
                counts[request.priority] += 1
            return counts

    def get_request(self, request_id: str) -> QueuedRequest | None:
        """
        Get a request by ID without removing it.

        Args:
            request_id: The request ID to find.

        Returns:
            The request if found, None otherwise.
        """
        with self._lock:
            return self._request_map.get(request_id)

    def remove(self, request_id: str) -> bool:
        """
        Remove a specific request from the queue.

        Args:
            request_id: The request ID to remove.

        Returns:
            True if removed, False if not found.
        """
        with self._lock:
            if request_id not in self._request_map:
                return False

            request = self._request_map.pop(request_id)
            self._heap.remove(request)
            heapq.heapify(self._heap)

            self._not_full.notify()
            return True

    def clear(self) -> int:
        """
        Clear all requests from the queue.

        Returns:
            Number of requests cleared.
        """
        with self._lock:
            count = len(self._heap)
            self._heap.clear()
            self._request_map.clear()
            self._not_full.notify_all()
            return count

    def _age_requests(self) -> None:
        """Boost priority of old requests to prevent starvation."""
        now = datetime.now(timezone.utc)
        aged_count = 0

        for request in self._heap:
            age = (now - request.created_at).total_seconds()
            # Calculate how many aging intervals have passed
            intervals_passed = int(age / self.aging_interval)
            # Calculate target priority based on intervals
            aging_amount = intervals_passed * self.aging_boost
            target_value = max(0, request._original_priority.value - aging_amount)

            if target_value < request.priority.value:
                request.priority = PriorityLevel(target_value)
                request._update_sort_key()
                aged_count += 1

        if aged_count > 0:
            self._total_aged += aged_count
            logger.debug(f"Aged {aged_count} requests in queue")

    def _remove_expired(self) -> None:
        """Remove expired requests from the queue."""
        expired = [r for r in self._heap if r.is_expired()]
        for request in expired:
            self._heap.remove(request)
            self._request_map.pop(request.id, None)
            self._total_expired += 1
            logger.debug(f"Removed expired request: {request.id}")

        if expired:
            heapq.heapify(self._heap)

    def get_stats(self) -> dict[str, Any]:
        """
        Get queue statistics.

        Returns:
            Dictionary with queue statistics.
        """
        with self._lock:
            return {
                "current_size": len(self._heap),
                "max_size": self.max_size,
                "total_enqueued": self._total_enqueued,
                "total_dequeued": self._total_dequeued,
                "total_expired": self._total_expired,
                "total_aged": self._total_aged,
                "size_by_priority": {
                    level.name: count
                    for level, count in self.size_by_priority().items()
                },
            }

    def __len__(self) -> int:
        """Get queue size."""
        return self.size()

    def __contains__(self, request_id: str) -> bool:
        """Check if a request ID is in the queue."""
        with self._lock:
            return request_id in self._request_map
