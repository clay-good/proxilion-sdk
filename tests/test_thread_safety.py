"""
Thread safety tests for critical components.

This test suite covers:
- TestRateLimiterThreadSafety: 50 threads hitting rate limiter simultaneously
- TestCircuitBreakerThreadSafety: 20 threads recording failures
- TestHashChainThreadSafety: 10 threads appending events
- TestCacheThreadSafety: 30 threads reading/writing cache
"""

from __future__ import annotations

import threading
import time

from proxilion.audit.events import AuditEventData, AuditEventV2, EventType, reset_sequence
from proxilion.audit.hash_chain import GENESIS_HASH, HashChain
from proxilion.caching.tool_cache import CacheConfig, ToolCache
from proxilion.security.circuit_breaker import CircuitBreaker, CircuitState
from proxilion.security.rate_limiter import TokenBucketRateLimiter

# ============================================================================
# Test Helpers
# ============================================================================


def create_test_event(user_id: str, tool_name: str) -> AuditEventV2:
    """Create a test audit event."""
    data = AuditEventData(
        event_type=EventType.AUTHORIZATION_GRANTED,
        user_id=user_id,
        user_roles=["user"],
        session_id="test_session",
        user_attributes={},
        agent_id="test_agent",
        agent_capabilities=[],
        agent_trust_score=0.9,
        tool_name=tool_name,
        tool_arguments={"arg": "value"},
        tool_timestamp=AuditEventV2.__dataclass_fields__["timestamp"].default_factory(),
        authorization_allowed=True,
        authorization_reason="Test allowed",
        policies_evaluated=["TestPolicy"],
        authorization_metadata={},
    )
    return AuditEventV2(data=data, previous_hash=GENESIS_HASH)


# ============================================================================
# RateLimiter Thread Safety Tests
# ============================================================================


class TestRateLimiterThreadSafety:
    """Test thread safety of TokenBucketRateLimiter."""

    def test_50_threads_concurrent_requests(self) -> None:
        """50 threads hitting rate limiter should maintain correct count."""
        limiter = TokenBucketRateLimiter(capacity=100, refill_rate=10.0)
        num_threads = 50
        requests_per_thread = 2
        total_expected = num_threads * requests_per_thread

        allowed_count = 0
        denied_count = 0
        count_lock = threading.Lock()
        errors = []

        def make_requests(thread_id: int) -> None:
            nonlocal allowed_count, denied_count
            try:
                for _ in range(requests_per_thread):
                    if limiter.allow_request(f"user_{thread_id % 10}", cost=1):
                        with count_lock:
                            allowed_count += 1
                    else:
                        with count_lock:
                            denied_count += 1
            except Exception as e:
                errors.append(e)

        threads = []
        for i in range(num_threads):
            thread = threading.Thread(target=make_requests, args=(i,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        assert len(errors) == 0, f"Errors occurred: {errors}"
        assert allowed_count + denied_count == total_expected
        assert allowed_count <= 100  # Should not exceed capacity

    def test_concurrent_different_keys(self) -> None:
        """Concurrent requests with different keys should not interfere."""
        limiter = TokenBucketRateLimiter(capacity=10, refill_rate=1.0)
        num_threads = 20
        results = {}
        results_lock = threading.Lock()
        errors = []

        def make_request(thread_id: int) -> None:
            try:
                key = f"user_{thread_id}"
                allowed = limiter.allow_request(key, cost=5)
                with results_lock:
                    results[key] = allowed
            except Exception as e:
                errors.append(e)

        threads = []
        for i in range(num_threads):
            thread = threading.Thread(target=make_request, args=(i,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        assert len(errors) == 0
        # Each unique key should have its own bucket
        assert len(results) == num_threads
        # All should be allowed since they're different buckets
        assert all(results.values())

    def test_race_condition_same_key(self) -> None:
        """Multiple threads with same key should not have race conditions."""
        limiter = TokenBucketRateLimiter(capacity=50, refill_rate=5.0)
        num_threads = 50
        success_count = 0
        count_lock = threading.Lock()

        def make_request() -> None:
            nonlocal success_count
            if limiter.allow_request("shared_key", cost=1):
                with count_lock:
                    success_count += 1

        threads = []
        for _ in range(num_threads):
            thread = threading.Thread(target=make_request)
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        # Should not exceed capacity despite race conditions
        assert success_count <= 50


# ============================================================================
# CircuitBreaker Thread Safety Tests
# ============================================================================


class TestCircuitBreakerThreadSafety:
    """Test thread safety of CircuitBreaker."""

    def test_20_threads_recording_failures(self) -> None:
        """20 threads recording failures should correctly trip circuit."""
        breaker = CircuitBreaker(failure_threshold=10, reset_timeout=5.0)
        num_threads = 20
        errors = []

        def record_failure(thread_id: int) -> None:
            try:
                breaker._record_failure(Exception(f"Failure from thread {thread_id}"))
            except Exception as e:
                errors.append(e)

        threads = []
        for i in range(num_threads):
            thread = threading.Thread(target=record_failure, args=(i,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        assert len(errors) == 0
        # Circuit should be OPEN after exceeding threshold
        assert breaker.state == CircuitState.OPEN
        assert breaker.stats.failures == num_threads
        assert breaker.stats.consecutive_failures >= breaker.failure_threshold

    def test_concurrent_call_executions(self) -> None:
        """Concurrent call executions should maintain thread safety."""
        breaker = CircuitBreaker(failure_threshold=5, reset_timeout=1.0)
        num_threads = 10
        success_count = 0
        failure_count = 0
        count_lock = threading.Lock()
        call_count = 0
        call_lock = threading.Lock()

        def test_function() -> str:
            nonlocal call_count
            with call_lock:
                call_count += 1
                current_call = call_count

            # First 3 calls succeed, rest fail
            if current_call <= 3:
                return "success"
            raise Exception("Simulated failure")

        def execute_call() -> None:
            nonlocal success_count, failure_count
            try:
                breaker.call(test_function)
                with count_lock:
                    success_count += 1
            except Exception:
                with count_lock:
                    failure_count += 1

        threads = []
        for _ in range(num_threads):
            thread = threading.Thread(target=execute_call)
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        assert success_count + failure_count == num_threads
        # Circuit should open after threshold failures
        assert breaker.state in [CircuitState.OPEN, CircuitState.CLOSED]

    def test_half_open_concurrency(self) -> None:
        """Half-open state should handle concurrent requests correctly."""
        breaker = CircuitBreaker(
            failure_threshold=3,
            reset_timeout=0.1,
            half_open_max=2,
            success_threshold=5,  # Require 5 successes to close
        )

        # Trip the circuit
        for _ in range(3):
            breaker._record_failure(Exception("Failure"))

        assert breaker.state == CircuitState.OPEN

        # Wait for half-open transition
        time.sleep(0.15)

        # Force state check to transition to half-open
        breaker._maybe_transition_to_half_open()
        assert breaker.state == CircuitState.HALF_OPEN

        # Multiple threads should respect half_open_max
        from proxilion.exceptions import CircuitOpenError

        success_count = 0
        rejected_count = 0
        count_lock = threading.Lock()

        def test_call() -> None:
            nonlocal success_count, rejected_count
            try:
                breaker.call(lambda: "success")
                with count_lock:
                    success_count += 1
            except CircuitOpenError:
                with count_lock:
                    rejected_count += 1

        threads = []
        for _ in range(10):
            thread = threading.Thread(target=test_call)
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        # With higher success_threshold, circuit stays half-open longer
        # so we can verify that concurrent access is properly controlled
        # Some requests should succeed (up to half_open_max at a time)
        # and some should be rejected
        assert success_count + rejected_count == 10
        assert rejected_count > 0  # At least some should be rejected


# ============================================================================
# HashChain Thread Safety Tests
# ============================================================================


class TestHashChainThreadSafety:
    """Test thread safety of HashChain."""

    def test_10_threads_appending_events(self) -> None:
        """10 threads appending events should maintain chain integrity."""
        reset_sequence(0)
        chain = HashChain()
        num_threads = 10
        events_per_thread = 5
        errors = []

        def append_events(thread_id: int) -> None:
            try:
                for i in range(events_per_thread):
                    event = create_test_event(
                        user_id=f"thread_{thread_id}_user_{i}",
                        tool_name=f"tool_{thread_id}_{i}",
                    )
                    chain.create_and_append(event)
            except Exception as e:
                errors.append(e)

        threads = []
        for i in range(num_threads):
            thread = threading.Thread(target=append_events, args=(i,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        assert len(errors) == 0
        assert chain.length == num_threads * events_per_thread

        # Verify chain integrity
        result = chain.verify()
        assert result.valid is True
        assert result.verified_count == num_threads * events_per_thread

    def test_concurrent_reads_and_writes(self) -> None:
        """Concurrent reads and writes should not corrupt chain."""
        reset_sequence(0)
        chain = HashChain()
        num_writers = 5
        num_readers = 5
        events_per_writer = 3
        errors = []
        read_results = []
        read_lock = threading.Lock()

        def write_events(thread_id: int) -> None:
            try:
                for i in range(events_per_writer):
                    event = create_test_event(
                        user_id=f"writer_{thread_id}_{i}",
                        tool_name=f"tool_{thread_id}",
                    )
                    chain.create_and_append(event)
                    time.sleep(0.001)  # Small delay
            except Exception as e:
                errors.append(e)

        def read_chain(thread_id: int) -> None:
            try:
                for _ in range(5):
                    length = chain.length
                    last_hash = chain.last_hash
                    with read_lock:
                        read_results.append((length, last_hash))
                    time.sleep(0.001)
            except Exception as e:
                errors.append(e)

        threads = []

        # Start readers and writers
        for i in range(num_writers):
            thread = threading.Thread(target=write_events, args=(i,))
            threads.append(thread)
            thread.start()

        for i in range(num_readers):
            thread = threading.Thread(target=read_chain, args=(i,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        assert len(errors) == 0
        assert chain.length == num_writers * events_per_writer

        # Verify no corruption
        result = chain.verify()
        assert result.valid is True


# ============================================================================
# Cache Thread Safety Tests
# ============================================================================


class TestCacheThreadSafety:
    """Test thread safety of ToolCache."""

    def test_30_threads_reading_writing(self) -> None:
        """30 threads reading and writing cache should maintain consistency."""
        config = CacheConfig(max_size=100, default_ttl=60)
        cache = ToolCache(config)
        num_threads = 30
        operations_per_thread = 10
        errors = []

        def cache_operations(thread_id: int) -> None:
            try:
                for i in range(operations_per_thread):
                    tool_name = f"tool_{thread_id % 5}"
                    args = {"arg": i, "thread": thread_id}

                    # Write
                    cache.set(tool_name, args, f"result_{thread_id}_{i}")

                    # Read
                    result = cache.get(tool_name, args)
                    if result is not None:
                        assert isinstance(result, str)
            except Exception as e:
                errors.append(e)

        threads = []
        for i in range(num_threads):
            thread = threading.Thread(target=cache_operations, args=(i,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        assert len(errors) == 0
        # Cache size should not exceed max_size
        assert len(cache) <= config.max_size

    def test_concurrent_evictions(self) -> None:
        """Concurrent operations should handle evictions correctly."""
        config = CacheConfig(max_size=20, default_ttl=60)
        cache = ToolCache(config)
        num_threads = 20
        writes_per_thread = 5
        errors = []

        def write_to_cache(thread_id: int) -> None:
            try:
                for i in range(writes_per_thread):
                    cache.set(
                        f"tool_{thread_id}",
                        {"index": i},
                        f"value_{thread_id}_{i}",
                    )
            except Exception as e:
                errors.append(e)

        threads = []
        for i in range(num_threads):
            thread = threading.Thread(target=write_to_cache, args=(i,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        assert len(errors) == 0
        # Size should be at or below max_size
        assert len(cache) <= config.max_size

        # Stats should be consistent
        stats = cache.get_stats()
        assert stats.size <= config.max_size
        assert stats.evictions >= 0

    def test_concurrent_invalidations(self) -> None:
        """Concurrent invalidations should not corrupt cache."""
        cache = ToolCache()
        num_threads = 15
        errors = []

        # Pre-populate cache
        for i in range(50):
            cache.set(f"tool_{i % 5}", {"id": i}, f"value_{i}")

        def invalidate_and_write(thread_id: int) -> None:
            try:
                tool_name = f"tool_{thread_id % 5}"

                # Invalidate
                cache.invalidate(tool_name)

                # Write new entries
                for i in range(3):
                    cache.set(tool_name, {"id": f"{thread_id}_{i}"}, f"new_value_{thread_id}_{i}")
            except Exception as e:
                errors.append(e)

        threads = []
        for i in range(num_threads):
            thread = threading.Thread(target=invalidate_and_write, args=(i,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        assert len(errors) == 0
        # Cache should be in valid state
        stats = cache.get_stats()
        assert stats.size >= 0
