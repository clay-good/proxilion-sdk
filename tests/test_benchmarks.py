"""
Performance benchmark tests for Proxilion.

These are regression guards, not micro-benchmarks. The budgets are 10x generous
to avoid CI flakiness. If any test fails, it indicates a severe regression
(not a 2x slowdown, but a 10x+ slowdown).

Run with: pytest tests/test_benchmarks.py -v
Run only benchmarks: pytest tests/test_benchmarks.py -v -m benchmark
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import pytest

from proxilion.audit.events import create_authorization_event
from proxilion.audit.hash_chain import GENESIS_HASH, HashChain
from proxilion.guards.input_guard import GuardAction, InputGuard
from proxilion.guards.output_guard import OutputGuard
from proxilion.security.idor_protection import IDORProtector
from proxilion.security.intent_capsule import IntentCapsule, IntentGuard
from proxilion.security.memory_integrity import MemoryIntegrityGuard
from proxilion.security.rate_limiter import TokenBucketRateLimiter
from proxilion.security.sequence_validator import SequenceValidator

if TYPE_CHECKING:
    pass

# Marker for benchmark tests
pytestmark = pytest.mark.benchmark

# Number of iterations for each benchmark
ITERATIONS = 1000

# Performance budgets (in milliseconds per call)
# These are intentionally generous (10x expected) to avoid flakiness
BUDGETS = {
    "input_guard_check": 1.0,  # 1ms per call
    "output_guard_check": 1.0,  # 1ms per call
    "rate_limiter_allow": 0.1,  # 0.1ms per call
    "hash_chain_append": 0.5,  # 0.5ms per call
    "intent_capsule_create": 1.0,  # 1ms per call
    "intent_guard_validate": 0.5,  # 0.5ms per call
    "memory_guard_sign": 0.5,  # 0.5ms per call
    "memory_guard_verify": 2.0,  # 2ms per call (10 messages)
    "idor_validate": 0.1,  # 0.1ms per call
    "sequence_validate": 0.5,  # 0.5ms per call
}

# Secret key for cryptographic operations (16+ chars)
TEST_SECRET_KEY = "benchmark-secret-key-1234567890"


class TestInputGuardBenchmark:
    """Benchmarks for InputGuard.check()."""

    @pytest.fixture
    def guard(self) -> InputGuard:
        """Create an InputGuard for benchmarking."""
        return InputGuard(action=GuardAction.BLOCK, threshold=0.5)

    def test_input_guard_safe_string(self, guard: InputGuard) -> None:
        """Benchmark InputGuard.check() with safe strings."""
        safe_input = "This is a completely safe user input without any injection patterns."

        start = time.perf_counter()
        for _ in range(ITERATIONS):
            result = guard.check(safe_input)
            assert result.passed  # Sanity check
        elapsed = time.perf_counter() - start

        avg_ms = (elapsed / ITERATIONS) * 1000
        budget = BUDGETS["input_guard_check"]
        assert avg_ms < budget, f"InputGuard.check() took {avg_ms:.3f}ms/call, budget is {budget}ms"

    def test_input_guard_longer_string(self, guard: InputGuard) -> None:
        """Benchmark InputGuard.check() with longer safe strings."""
        safe_input = "This is a longer user input. " * 50  # ~1500 chars

        start = time.perf_counter()
        for _ in range(ITERATIONS):
            result = guard.check(safe_input)
            assert result.passed
        elapsed = time.perf_counter() - start

        avg_ms = (elapsed / ITERATIONS) * 1000
        # Allow 5x budget for longer strings (more generous to avoid CI flakiness)
        budget = BUDGETS["input_guard_check"] * 5
        assert avg_ms < budget, (
            f"InputGuard.check() (long) took {avg_ms:.3f}ms/call, budget is {budget}ms"
        )


class TestOutputGuardBenchmark:
    """Benchmarks for OutputGuard.check()."""

    @pytest.fixture
    def guard(self) -> OutputGuard:
        """Create an OutputGuard for benchmarking."""
        return OutputGuard(action=GuardAction.BLOCK, threshold=0.5)

    def test_output_guard_safe_response(self, guard: OutputGuard) -> None:
        """Benchmark OutputGuard.check() with safe responses."""
        safe_output = "Here is the information you requested about Python programming."

        start = time.perf_counter()
        for _ in range(ITERATIONS):
            result = guard.check(safe_output)
            assert result.passed
        elapsed = time.perf_counter() - start

        avg_ms = (elapsed / ITERATIONS) * 1000
        budget = BUDGETS["output_guard_check"]
        assert avg_ms < budget, (
            f"OutputGuard.check() took {avg_ms:.3f}ms/call, budget is {budget}ms"
        )

    def test_output_guard_longer_response(self, guard: OutputGuard) -> None:
        """Benchmark OutputGuard.check() with longer responses."""
        safe_output = "This is a longer response with more content. " * 100  # ~4500 chars

        start = time.perf_counter()
        for _ in range(ITERATIONS):
            result = guard.check(safe_output)
            assert result.passed
        elapsed = time.perf_counter() - start

        avg_ms = (elapsed / ITERATIONS) * 1000
        # Allow 5x budget for longer strings (more generous to avoid CI flakiness)
        budget = BUDGETS["output_guard_check"] * 5
        assert avg_ms < budget, (
            f"OutputGuard.check() (long) took {avg_ms:.3f}ms/call, budget is {budget}ms"
        )


class TestRateLimiterBenchmark:
    """Benchmarks for TokenBucketRateLimiter.allow_request()."""

    @pytest.fixture
    def limiter(self) -> TokenBucketRateLimiter:
        """Create a rate limiter with high capacity for benchmarking."""
        # High capacity ensures all requests pass
        return TokenBucketRateLimiter(capacity=100000, refill_rate=100000)

    def test_rate_limiter_allow(self, limiter: TokenBucketRateLimiter) -> None:
        """Benchmark TokenBucketRateLimiter.allow_request()."""
        start = time.perf_counter()
        for i in range(ITERATIONS):
            # Use different keys to test bucket creation too
            result = limiter.allow_request(f"user_{i % 100}")
            assert result  # All should pass with high capacity
        elapsed = time.perf_counter() - start

        avg_ms = (elapsed / ITERATIONS) * 1000
        budget = BUDGETS["rate_limiter_allow"]
        assert avg_ms < budget, (
            f"RateLimiter.allow_request() took {avg_ms:.3f}ms/call, budget is {budget}ms"
        )

    def test_rate_limiter_same_key(self, limiter: TokenBucketRateLimiter) -> None:
        """Benchmark rate limiter with same key (bucket reuse)."""
        start = time.perf_counter()
        for _ in range(ITERATIONS):
            result = limiter.allow_request("same_user")
            assert result
        elapsed = time.perf_counter() - start

        avg_ms = (elapsed / ITERATIONS) * 1000
        budget = BUDGETS["rate_limiter_allow"]
        assert avg_ms < budget, (
            f"RateLimiter.allow_request() (same key) took {avg_ms:.3f}ms/call, budget is {budget}ms"
        )


class TestHashChainBenchmark:
    """Benchmarks for HashChain.append()."""

    @pytest.fixture
    def chain(self) -> HashChain:
        """Create a fresh HashChain for benchmarking."""
        return HashChain()

    def test_hash_chain_append(self, chain: HashChain) -> None:
        """Benchmark HashChain.append() (via create_and_append)."""
        # Pre-create events to measure append time only
        events = []
        prev_hash = GENESIS_HASH
        for i in range(ITERATIONS):
            event = create_authorization_event(
                user_id=f"user_{i}",
                user_roles=["viewer"],
                tool_name=f"tool_{i}",
                tool_arguments={"query": "test"},
                allowed=True,
                reason="benchmark test",
                policies_evaluated=["test_policy"],
                previous_hash=prev_hash,
            )
            events.append(event)
            prev_hash = event.event_hash

        # Reset chain for benchmarking the append operation
        chain = HashChain()
        start = time.perf_counter()
        for event in events:
            chain.create_and_append(event)
        elapsed = time.perf_counter() - start

        avg_ms = (elapsed / ITERATIONS) * 1000
        budget = BUDGETS["hash_chain_append"]
        assert avg_ms < budget, f"HashChain.append() took {avg_ms:.3f}ms/call, budget is {budget}ms"

        # Verify chain integrity
        result = chain.verify()
        assert result.valid, "Hash chain integrity check failed"


class TestIntentCapsuleBenchmark:
    """Benchmarks for IntentCapsule.create()."""

    def test_intent_capsule_create(self) -> None:
        """Benchmark IntentCapsule.create()."""
        start = time.perf_counter()
        for i in range(ITERATIONS):
            capsule = IntentCapsule.create(
                user_id=f"user_{i}",
                intent="Help me find documents about Python",
                allowed_tools=["search_documents", "read_document", "list_files"],
                secret_key=TEST_SECRET_KEY,
            )
            assert capsule.capsule_id  # Sanity check
        elapsed = time.perf_counter() - start

        avg_ms = (elapsed / ITERATIONS) * 1000
        budget = BUDGETS["intent_capsule_create"]
        assert avg_ms < budget, (
            f"IntentCapsule.create() took {avg_ms:.3f}ms/call, budget is {budget}ms"
        )


class TestIntentGuardBenchmark:
    """Benchmarks for IntentGuard.validate_tool_call()."""

    @pytest.fixture
    def guard(self) -> IntentGuard:
        """Create an IntentGuard for benchmarking."""
        capsule = IntentCapsule.create(
            user_id="benchmark_user",
            intent="Search and read documents",
            allowed_tools=["search_*", "read_*", "list_*"],
            secret_key=TEST_SECRET_KEY,
        )
        return IntentGuard(capsule)

    def test_intent_guard_validate(self, guard: IntentGuard) -> None:
        """Benchmark IntentGuard.validate_tool_call()."""
        start = time.perf_counter()
        for i in range(ITERATIONS):
            result = guard.validate_tool_call(
                tool_name="search_documents",
                arguments={"query": f"python tutorial {i}"},
            )
            assert result  # Should pass
        elapsed = time.perf_counter() - start

        avg_ms = (elapsed / ITERATIONS) * 1000
        budget = BUDGETS["intent_guard_validate"]
        assert avg_ms < budget, (
            f"IntentGuard.validate_tool_call() took {avg_ms:.3f}ms/call, budget is {budget}ms"
        )


class TestMemoryIntegrityBenchmark:
    """Benchmarks for MemoryIntegrityGuard."""

    @pytest.fixture
    def guard(self) -> MemoryIntegrityGuard:
        """Create a MemoryIntegrityGuard for benchmarking."""
        return MemoryIntegrityGuard(secret_key=TEST_SECRET_KEY)

    def test_memory_guard_sign_message(self, guard: MemoryIntegrityGuard) -> None:
        """Benchmark MemoryIntegrityGuard.sign_message()."""
        start = time.perf_counter()
        for i in range(ITERATIONS):
            msg = guard.sign_message(
                role="user",
                content=f"Hello, this is message number {i}",
            )
            assert msg.signature  # Sanity check
        elapsed = time.perf_counter() - start

        avg_ms = (elapsed / ITERATIONS) * 1000
        budget = BUDGETS["memory_guard_sign"]
        assert avg_ms < budget, (
            f"MemoryIntegrityGuard.sign_message() took {avg_ms:.3f}ms/call, budget is {budget}ms"
        )

    def test_memory_guard_verify_context(self) -> None:
        """Benchmark MemoryIntegrityGuard.verify_context() with 10 messages."""
        guard = MemoryIntegrityGuard(secret_key=TEST_SECRET_KEY)

        # Build a context of 10 messages
        context = []
        for i in range(10):
            role = "user" if i % 2 == 0 else "assistant"
            msg = guard.sign_message(role=role, content=f"Message {i}")
            context.append(msg)

        # Reset guard for verification (simulate new instance)
        verifier = MemoryIntegrityGuard(secret_key=TEST_SECRET_KEY)

        start = time.perf_counter()
        for _ in range(ITERATIONS):
            result = verifier.verify_context(context)
            assert result.valid
        elapsed = time.perf_counter() - start

        avg_ms = (elapsed / ITERATIONS) * 1000
        budget = BUDGETS["memory_guard_verify"]
        assert avg_ms < budget, (
            f"MemoryIntegrityGuard.verify_context() took {avg_ms:.3f}ms/call, budget is {budget}ms"
        )


class TestIDORProtectorBenchmark:
    """Benchmarks for IDORProtector.validate_access()."""

    @pytest.fixture
    def protector(self) -> IDORProtector:
        """Create an IDORProtector with pre-registered scopes."""
        protector = IDORProtector()
        # Register scope for benchmark user with many allowed IDs
        allowed_ids = {f"doc_{i}" for i in range(100)}
        protector.register_scope(
            user_id="benchmark_user",
            resource_type="document",
            allowed_ids=allowed_ids,
        )
        return protector

    def test_idor_validate_access(self, protector: IDORProtector) -> None:
        """Benchmark IDORProtector.validate_access()."""
        start = time.perf_counter()
        for i in range(ITERATIONS):
            result = protector.validate_access(
                user_id="benchmark_user",
                resource_type="document",
                object_id=f"doc_{i % 100}",
            )
            assert result  # All should pass (within allowed IDs)
        elapsed = time.perf_counter() - start

        avg_ms = (elapsed / ITERATIONS) * 1000
        budget = BUDGETS["idor_validate"]
        assert avg_ms < budget, (
            f"IDORProtector.validate_access() took {avg_ms:.3f}ms/call, budget is {budget}ms"
        )


class TestSequenceValidatorBenchmark:
    """Benchmarks for SequenceValidator.validate_call()."""

    @pytest.fixture
    def validator(self) -> SequenceValidator:
        """Create a SequenceValidator with default rules."""
        validator = SequenceValidator()
        # Record some baseline calls to have history
        for i in range(10):
            validator.record_call(f"read_file_{i}", "benchmark_user")
        return validator

    def test_sequence_validate_call(self, validator: SequenceValidator) -> None:
        """Benchmark SequenceValidator.validate_call()."""
        start = time.perf_counter()
        for i in range(ITERATIONS):
            allowed, violation = validator.validate_call(
                tool_name=f"read_file_{i}",
                user_id="benchmark_user",
            )
            assert allowed  # read_* tools should pass
        elapsed = time.perf_counter() - start

        avg_ms = (elapsed / ITERATIONS) * 1000
        budget = BUDGETS["sequence_validate"]
        assert avg_ms < budget, (
            f"SequenceValidator.validate_call() took {avg_ms:.3f}ms/call, budget is {budget}ms"
        )


class TestCombinedBenchmark:
    """Test typical combined usage patterns."""

    def test_typical_authorization_flow(self) -> None:
        """Benchmark a typical authorization flow with multiple checks."""
        # Set up all components
        input_guard = InputGuard(action=GuardAction.BLOCK, threshold=0.5)
        rate_limiter = TokenBucketRateLimiter(capacity=100000, refill_rate=100000)
        idor = IDORProtector()
        idor.register_scope(
            user_id="user",
            resource_type="document",
            allowed_ids={f"doc_{i}" for i in range(100)},
        )

        # Measure combined flow
        start = time.perf_counter()
        for i in range(ITERATIONS):
            # Step 1: Rate limit check
            rate_limiter.allow_request("user")

            # Step 2: Input guard check
            input_guard.check("Search for document about Python")

            # Step 3: IDOR check
            idor.validate_access("user", "document", f"doc_{i % 100}")
        elapsed = time.perf_counter() - start

        avg_ms = (elapsed / ITERATIONS) * 1000
        # Budget is sum of individual budgets + overhead
        combined_budget = (
            BUDGETS["rate_limiter_allow"]
            + BUDGETS["input_guard_check"]
            + BUDGETS["idor_validate"]
            + 0.5  # Allow 0.5ms overhead
        )
        assert avg_ms < combined_budget, (
            f"Combined auth flow took {avg_ms:.3f}ms/call, budget is {combined_budget}ms"
        )
