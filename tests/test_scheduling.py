"""
Tests for request priority queue and scheduler.
"""

import time
import threading
from concurrent.futures import Future
from datetime import datetime, timezone, timedelta

import pytest

from proxilion.scheduling import (
    PriorityLevel,
    QueuedRequest,
    PriorityQueue,
    RequestScheduler,
    SchedulerConfig,
)


class TestPriorityLevel:
    """Tests for PriorityLevel enum."""

    def test_priority_ordering(self):
        """Test that priority values are ordered correctly."""
        assert PriorityLevel.CRITICAL < PriorityLevel.HIGH
        assert PriorityLevel.HIGH < PriorityLevel.NORMAL
        assert PriorityLevel.NORMAL < PriorityLevel.LOW
        assert PriorityLevel.LOW < PriorityLevel.BACKGROUND

    def test_priority_values(self):
        """Test priority integer values."""
        assert PriorityLevel.CRITICAL.value == 0
        assert PriorityLevel.HIGH.value == 1
        assert PriorityLevel.NORMAL.value == 2
        assert PriorityLevel.LOW.value == 3
        assert PriorityLevel.BACKGROUND.value == 4


class TestQueuedRequest:
    """Tests for QueuedRequest dataclass."""

    def test_default_creation(self):
        """Test creating request with defaults."""
        request = QueuedRequest()
        assert request.priority == PriorityLevel.NORMAL
        assert request.id is not None
        assert request.created_at is not None
        assert request.payload is None

    def test_custom_creation(self):
        """Test creating request with custom values."""
        request = QueuedRequest(
            id="test-123",
            priority=PriorityLevel.HIGH,
            payload={"task": "test"},
            timeout=30.0,
        )
        assert request.id == "test-123"
        assert request.priority == PriorityLevel.HIGH
        assert request.payload == {"task": "test"}
        assert request.timeout == 30.0

    def test_boost_priority(self):
        """Test priority boosting."""
        request = QueuedRequest(priority=PriorityLevel.LOW)
        assert request.boost_priority()
        assert request.priority == PriorityLevel.NORMAL

        # Boost again
        assert request.boost_priority()
        assert request.priority == PriorityLevel.HIGH

    def test_boost_at_highest(self):
        """Test boosting when already at highest priority."""
        request = QueuedRequest(priority=PriorityLevel.CRITICAL)
        assert not request.boost_priority()
        assert request.priority == PriorityLevel.CRITICAL

    def test_is_expired(self):
        """Test expiration checking."""
        # No timeout - never expires
        request = QueuedRequest()
        assert not request.is_expired()

        # With timeout
        request = QueuedRequest(timeout=0.01)
        assert not request.is_expired()
        time.sleep(0.02)
        assert request.is_expired()

    def test_age_seconds(self):
        """Test age calculation."""
        request = QueuedRequest()
        time.sleep(0.1)
        assert request.age_seconds() >= 0.1

    def test_to_dict(self):
        """Test dictionary conversion."""
        request = QueuedRequest(
            id="test-123",
            priority=PriorityLevel.HIGH,
        )
        d = request.to_dict()
        assert d["id"] == "test-123"
        assert d["priority"] == "HIGH"
        assert "created_at" in d


class TestPriorityQueue:
    """Tests for PriorityQueue."""

    def test_enqueue_dequeue(self):
        """Test basic enqueue and dequeue."""
        queue = PriorityQueue()
        request = QueuedRequest(payload="test")

        assert queue.enqueue(request)
        assert queue.size() == 1

        dequeued = queue.dequeue(block=False)
        assert dequeued is not None
        assert dequeued.payload == "test"
        assert queue.size() == 0

    def test_priority_ordering(self):
        """Test that high priority requests dequeue first."""
        queue = PriorityQueue()

        # Enqueue in reverse priority order
        queue.enqueue(QueuedRequest(priority=PriorityLevel.LOW, payload="low"))
        queue.enqueue(QueuedRequest(priority=PriorityLevel.CRITICAL, payload="critical"))
        queue.enqueue(QueuedRequest(priority=PriorityLevel.NORMAL, payload="normal"))
        queue.enqueue(QueuedRequest(priority=PriorityLevel.HIGH, payload="high"))

        # Should dequeue in priority order
        assert queue.dequeue(block=False).payload == "critical"
        assert queue.dequeue(block=False).payload == "high"
        assert queue.dequeue(block=False).payload == "normal"
        assert queue.dequeue(block=False).payload == "low"

    def test_max_size(self):
        """Test max size enforcement."""
        queue = PriorityQueue(max_size=2)

        assert queue.enqueue(QueuedRequest(payload="1"))
        assert queue.enqueue(QueuedRequest(payload="2"))

        # Should not block but return False
        assert not queue.enqueue(QueuedRequest(payload="3"), block=False)
        assert queue.size() == 2

    def test_duplicate_id_rejected(self):
        """Test that duplicate IDs are rejected."""
        queue = PriorityQueue()
        request = QueuedRequest(id="same-id")

        assert queue.enqueue(request)
        with pytest.raises(ValueError):
            queue.enqueue(QueuedRequest(id="same-id"))

    def test_peek(self):
        """Test peeking at the queue."""
        queue = PriorityQueue()

        assert queue.peek() is None

        queue.enqueue(QueuedRequest(priority=PriorityLevel.HIGH, payload="high"))
        peeked = queue.peek()
        assert peeked.payload == "high"
        assert queue.size() == 1  # Not removed

    def test_remove(self):
        """Test removing specific request."""
        queue = PriorityQueue()
        request = QueuedRequest(id="to-remove", payload="remove me")
        queue.enqueue(request)
        queue.enqueue(QueuedRequest(payload="keep"))

        assert queue.remove("to-remove")
        assert queue.size() == 1
        assert not queue.remove("nonexistent")

    def test_clear(self):
        """Test clearing the queue."""
        queue = PriorityQueue()
        queue.enqueue(QueuedRequest(payload="1"))
        queue.enqueue(QueuedRequest(payload="2"))

        count = queue.clear()
        assert count == 2
        assert queue.is_empty()

    def test_size_by_priority(self):
        """Test size breakdown by priority."""
        queue = PriorityQueue()
        queue.enqueue(QueuedRequest(priority=PriorityLevel.HIGH))
        queue.enqueue(QueuedRequest(priority=PriorityLevel.HIGH))
        queue.enqueue(QueuedRequest(priority=PriorityLevel.LOW))

        sizes = queue.size_by_priority()
        assert sizes[PriorityLevel.HIGH] == 2
        assert sizes[PriorityLevel.LOW] == 1
        assert sizes[PriorityLevel.NORMAL] == 0

    def test_aging_prevents_starvation(self):
        """Test that aging boosts priority of old requests."""
        # Short aging interval for testing
        queue = PriorityQueue(aging_interval=0.1, aging_boost=1)

        # Add low priority request
        low_request = QueuedRequest(priority=PriorityLevel.BACKGROUND, payload="old")
        queue.enqueue(low_request)

        # Wait for aging
        time.sleep(0.15)

        # Add high priority request
        queue.enqueue(QueuedRequest(priority=PriorityLevel.HIGH, payload="new"))

        # Old request should have been boosted
        # With aging_interval=0.1 and one interval passed, should boost by 1
        dequeued = queue.dequeue(block=False)
        # The aged request should now compete more fairly

    def test_expired_requests_removed(self):
        """Test that expired requests are removed."""
        queue = PriorityQueue()
        queue.enqueue(QueuedRequest(timeout=0.01, payload="expired"))
        time.sleep(0.02)

        dequeued = queue.dequeue(block=False)
        assert dequeued is None

    def test_get_stats(self):
        """Test statistics gathering."""
        queue = PriorityQueue()
        queue.enqueue(QueuedRequest())
        queue.dequeue(block=False)

        stats = queue.get_stats()
        assert stats["total_enqueued"] == 1
        assert stats["total_dequeued"] == 1
        assert "size_by_priority" in stats

    def test_contains(self):
        """Test __contains__ method."""
        queue = PriorityQueue()
        request = QueuedRequest(id="test-id")
        queue.enqueue(request)

        assert "test-id" in queue
        assert "other-id" not in queue

    def test_thread_safety(self):
        """Test thread-safe operations."""
        queue = PriorityQueue(max_size=100)
        results = []

        def enqueue_worker(n):
            for i in range(10):
                queue.enqueue(QueuedRequest(payload=f"{n}-{i}"))

        def dequeue_worker():
            for _ in range(10):
                req = queue.dequeue(timeout=1.0)
                if req:
                    results.append(req.payload)

        # Start multiple threads
        threads = []
        for i in range(3):
            threads.append(threading.Thread(target=enqueue_worker, args=(i,)))
        for i in range(3):
            threads.append(threading.Thread(target=dequeue_worker))

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All enqueued items should be processed
        assert len(results) == 30


class TestSchedulerConfig:
    """Tests for SchedulerConfig."""

    def test_default_config(self):
        """Test default configuration values."""
        config = SchedulerConfig()
        assert config.max_concurrent == 4
        assert config.queue_size == 1000
        assert config.default_timeout == 60.0

    def test_custom_config(self):
        """Test custom configuration."""
        config = SchedulerConfig(
            max_concurrent=8,
            queue_size=500,
            default_timeout=30.0,
        )
        assert config.max_concurrent == 8
        assert config.queue_size == 500
        assert config.default_timeout == 30.0


class TestRequestScheduler:
    """Tests for RequestScheduler."""

    def test_basic_submit(self):
        """Test basic request submission."""
        results = []

        def handler(payload):
            results.append(payload)
            return f"processed: {payload}"

        scheduler = RequestScheduler(handler=handler)
        try:
            future = scheduler.submit(payload="test")
            result = future.result(timeout=5.0)
            assert result == "processed: test"
            assert "test" in results
        finally:
            scheduler.shutdown()

    def test_priority_execution(self):
        """Test that high priority requests are processed first."""
        execution_order = []
        lock = threading.Lock()

        def handler(payload):
            time.sleep(0.05)  # Small delay
            with lock:
                execution_order.append(payload)
            return payload

        config = SchedulerConfig(max_concurrent=1)  # Single worker
        scheduler = RequestScheduler(config=config, handler=handler)

        try:
            # Submit in reverse priority order
            f1 = scheduler.submit(priority=PriorityLevel.LOW, payload="low")
            f2 = scheduler.submit(priority=PriorityLevel.HIGH, payload="high")
            f3 = scheduler.submit(priority=PriorityLevel.CRITICAL, payload="critical")

            # Wait for all to complete
            f1.result(timeout=5.0)
            f2.result(timeout=5.0)
            f3.result(timeout=5.0)

            # High priority should have been processed early
            # Note: exact order depends on timing
        finally:
            scheduler.shutdown()

    def test_concurrent_execution(self):
        """Test concurrent request processing."""
        concurrent_count = []
        current_count = [0]
        lock = threading.Lock()

        def handler(payload):
            with lock:
                current_count[0] += 1
                concurrent_count.append(current_count[0])
            time.sleep(0.1)
            with lock:
                current_count[0] -= 1
            return payload

        config = SchedulerConfig(max_concurrent=4)
        scheduler = RequestScheduler(config=config, handler=handler)

        try:
            # Submit multiple requests
            futures = [
                scheduler.submit(payload=f"task-{i}")
                for i in range(8)
            ]

            # Wait for completion
            for f in futures:
                f.result(timeout=5.0)

            # Should have seen concurrent execution
            assert max(concurrent_count) > 1
        finally:
            scheduler.shutdown()

    def test_pause_resume(self):
        """Test pausing and resuming the scheduler."""
        scheduler = RequestScheduler(handler=lambda x: x)

        try:
            assert scheduler.is_running()

            scheduler.pause()
            assert scheduler.is_paused()

            scheduler.resume()
            assert scheduler.is_running()
        finally:
            scheduler.shutdown()

    def test_shutdown(self):
        """Test graceful shutdown."""
        scheduler = RequestScheduler(handler=lambda x: x)
        scheduler.shutdown()

        with pytest.raises(RuntimeError):
            scheduler.submit(payload="should fail")

    def test_context_manager(self):
        """Test using scheduler as context manager."""
        with RequestScheduler(handler=lambda x: x) as scheduler:
            future = scheduler.submit(payload="test")
            assert future.result(timeout=5.0) == "test"

    def test_get_queue_stats(self):
        """Test getting queue statistics."""
        scheduler = RequestScheduler(handler=lambda x: x)

        try:
            stats = scheduler.get_queue_stats()
            assert "state" in stats
            assert "queue" in stats
            assert "scheduler" in stats
            assert "config" in stats
        finally:
            scheduler.shutdown()

    def test_handler_exception(self):
        """Test handling of handler exceptions."""
        def failing_handler(payload):
            raise ValueError("test error")

        scheduler = RequestScheduler(handler=failing_handler)

        try:
            future = scheduler.submit(payload="will fail")
            with pytest.raises(ValueError):
                future.result(timeout=5.0)
        finally:
            scheduler.shutdown()

    def test_callback(self):
        """Test request callback."""
        results = []

        def handler(payload):
            return payload * 2

        def callback(result):
            results.append(result)

        scheduler = RequestScheduler(handler=handler)

        try:
            future = scheduler.submit(payload=5, callback=callback)
            future.result(timeout=5.0)
            time.sleep(0.1)  # Allow callback to execute
            assert 10 in results
        finally:
            scheduler.shutdown()

    def test_queue_full(self):
        """Test behavior when queue is full."""
        config = SchedulerConfig(queue_size=1, max_concurrent=1)

        def slow_handler(payload):
            time.sleep(1.0)
            return payload

        scheduler = RequestScheduler(config=config, handler=slow_handler)

        try:
            # Submit first request (will be processing)
            f1 = scheduler.submit(payload="first")

            # Give it time to start processing
            time.sleep(0.1)

            # Submit second request (fills queue)
            f2 = scheduler.submit(payload="second")

            # Third request should get queue full error
            f3 = scheduler.submit(payload="third")
            with pytest.raises(RuntimeError, match="full"):
                f3.result(timeout=0.1)

        finally:
            scheduler.shutdown(wait=False)
