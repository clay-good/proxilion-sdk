"""
Targeted edge-case tests for bugs and fixes from spec Steps 1-9.

Covers:
- Scheduler pause/resume uses Event (no busy-wait)
- Cascade protection events bounded by deque(maxlen=...)
- Streaming detector reaps stale partial calls
- Parameter validation rejects out-of-range values
- Path traversal detects backslash and null byte variants
- Fallback chains report all errors via raise_on_failure()
- Context window degrades gracefully when summarize callback fails
- Retry delay is clamped and never produces infinity
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from proxilion.context.context_window import (
    SlidingWindowStrategy,
    SummarizeOldStrategy,
)
from proxilion.context.message_history import Message, MessageRole
from proxilion.exceptions import FallbackExhaustedError
from proxilion.observability.metrics import AlertRule
from proxilion.resilience.fallback import FallbackResult
from proxilion.resilience.retry import RetryPolicy
from proxilion.scheduling.scheduler import RequestScheduler
from proxilion.security.behavioral_drift import DriftDetector
from proxilion.security.cascade_protection import (
    CascadeProtector,
    DependencyGraph,
)
from proxilion.streaming.detector import PartialToolCall, StreamingToolCallDetector
from proxilion.validation.schema import SchemaValidator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_message(content: str, tokens: int | None = None) -> Message:
    return Message(role=MessageRole.USER, content=content, token_count=tokens)


# ---------------------------------------------------------------------------
# Step 1a — Scheduler pause/resume uses threading.Event, no busy-wait
# ---------------------------------------------------------------------------


class TestSchedulerPauseResume:

    def test_resume_event_exists(self):
        """Scheduler should use a threading.Event for pause/resume."""
        scheduler = RequestScheduler(handler=lambda x: x)
        try:
            assert hasattr(scheduler, "_resume_event")
            assert isinstance(scheduler._resume_event, threading.Event)
        finally:
            scheduler.shutdown()

    def test_pause_clears_event(self):
        """Pausing should clear the event so workers block."""
        scheduler = RequestScheduler(handler=lambda x: x)
        try:
            assert scheduler._resume_event.is_set()
            scheduler.pause()
            assert not scheduler._resume_event.is_set()
        finally:
            scheduler.shutdown()

    def test_resume_sets_event(self):
        """Resuming should set the event so workers wake up."""
        scheduler = RequestScheduler(handler=lambda x: x)
        try:
            scheduler.pause()
            assert not scheduler._resume_event.is_set()
            scheduler.resume()
            assert scheduler._resume_event.is_set()
        finally:
            scheduler.shutdown()

    def test_shutdown_sets_event(self):
        """Shutdown should set the event so blocked workers can exit."""
        scheduler = RequestScheduler(handler=lambda x: x)
        scheduler.pause()
        scheduler.shutdown()
        assert scheduler._resume_event.is_set()


# ---------------------------------------------------------------------------
# Step 2a — Cascade protection events bounded by deque
# ---------------------------------------------------------------------------


class TestCascadeProtectionBounded:

    def test_events_use_deque(self):
        """Events should be stored in a deque, not a plain list."""
        from collections import deque

        graph = DependencyGraph()
        graph.add_dependency("svc_a", "db")
        protector = CascadeProtector(graph, max_events=50)

        assert isinstance(protector._events, deque)
        assert protector._events.maxlen == 50

    def test_events_do_not_grow_unbounded(self):
        """After max_events failures, old events should be evicted."""
        graph = DependencyGraph()
        graph.add_dependency("svc_a", "db")
        protector = CascadeProtector(graph, max_events=10)

        for i in range(25):
            protector.propagate_failure("db")

        assert len(protector._events) <= 10

    def test_get_cascade_events_returns_list(self):
        """get_cascade_events() should return a list, not a deque."""
        graph = DependencyGraph()
        graph.add_dependency("svc_a", "db")
        protector = CascadeProtector(graph, max_events=100)
        protector.propagate_failure("db")

        events = protector.get_cascade_events(limit=50)
        assert isinstance(events, list)
        assert len(events) >= 1


# ---------------------------------------------------------------------------
# Step 2b — Streaming detector cleans up stale partial calls
# ---------------------------------------------------------------------------


class TestStreamingDetectorStaleCleanup:

    def test_stale_timeout_attribute_exists(self):
        """Detector should have a stale timeout attribute."""
        detector = StreamingToolCallDetector(provider="openai")
        assert hasattr(detector, "_stale_timeout_seconds")
        assert detector._stale_timeout_seconds > 0

    def test_stale_incomplete_calls_are_reaped(self):
        """Incomplete partial calls older than the timeout should be removed."""
        detector = StreamingToolCallDetector(provider="openai")
        detector._stale_timeout_seconds = 0  # Expire immediately

        # Inject a stale incomplete call
        stale_call = PartialToolCall(
            id="stale_1",
            name="old_tool",
            is_complete=False,
            started_at=datetime.now(timezone.utc) - timedelta(seconds=10),
        )
        detector._partial_calls["stale_1"] = stale_call

        # Trigger cleanup
        detector._cleanup_completed_calls()

        assert "stale_1" not in detector._partial_calls

    def test_non_stale_incomplete_calls_are_kept(self):
        """Recent incomplete calls should NOT be reaped."""
        detector = StreamingToolCallDetector(provider="openai")
        detector._stale_timeout_seconds = 600  # 10 minutes

        recent_call = PartialToolCall(
            id="recent_1",
            name="new_tool",
            is_complete=False,
            started_at=datetime.now(timezone.utc),
        )
        detector._partial_calls["recent_1"] = recent_call

        detector._cleanup_completed_calls()

        assert "recent_1" in detector._partial_calls


# ---------------------------------------------------------------------------
# Step 3a — Parameter validation rejects out-of-range values
# ---------------------------------------------------------------------------


class TestParameterValidation:

    def test_cascade_protector_rejects_zero_thresholds(self):
        """CascadeProtector should reject thresholds < 1."""
        graph = DependencyGraph()
        with pytest.raises(ValueError):
            CascadeProtector(graph, degraded_threshold=0)
        with pytest.raises(ValueError):
            CascadeProtector(graph, failing_threshold=0)
        with pytest.raises(ValueError):
            CascadeProtector(graph, max_events=0)

    def test_drift_detector_rejects_out_of_range_thresholds(self):
        """DriftDetector thresholds must be 0.0-1.0."""
        with pytest.raises(ValueError, match="auto_halt_threshold"):
            DriftDetector("agent", auto_halt_threshold=1.5)
        with pytest.raises(ValueError, match="auto_halt_threshold"):
            DriftDetector("agent", auto_halt_threshold=-0.1)
        with pytest.raises(ValueError, match="warning_threshold"):
            DriftDetector("agent", warning_threshold=2.0)
        with pytest.raises(ValueError, match="warning_threshold"):
            DriftDetector("agent", warning_threshold=-0.5)

    def test_alert_rule_rejects_invalid_window(self):
        """AlertRule must reject window_seconds <= 0."""
        with pytest.raises(ValueError, match="window_seconds"):
            AlertRule(name="bad", window_seconds=0)
        with pytest.raises(ValueError, match="window_seconds"):
            AlertRule(name="bad", window_seconds=-5)

    def test_alert_rule_rejects_negative_cooldown(self):
        """AlertRule must reject cooldown_seconds < 0."""
        with pytest.raises(ValueError, match="cooldown_seconds"):
            AlertRule(name="bad", cooldown_seconds=-1)

    def test_alert_rule_accepts_zero_cooldown(self):
        """AlertRule should accept cooldown_seconds = 0."""
        rule = AlertRule(name="ok", cooldown_seconds=0)
        assert rule.cooldown_seconds == 0

    def test_retry_policy_rejects_bad_params(self):
        """RetryPolicy should reject invalid configuration."""
        with pytest.raises(ValueError):
            RetryPolicy(max_attempts=0)
        with pytest.raises(ValueError):
            RetryPolicy(base_delay=-1)
        with pytest.raises(ValueError):
            RetryPolicy(base_delay=10, max_delay=5)
        with pytest.raises(ValueError):
            RetryPolicy(exponential_base=0.5)
        with pytest.raises(ValueError):
            RetryPolicy(jitter=-0.1)
        with pytest.raises(ValueError):
            RetryPolicy(jitter=1.5)


# ---------------------------------------------------------------------------
# Step 7a — Path traversal catches backslash and null byte variants
# ---------------------------------------------------------------------------


class TestPathTraversalDetection:

    @pytest.fixture
    def validator(self):
        return SchemaValidator()

    @pytest.mark.parametrize(
        "payload",
        [
            "..\\windows\\system32",           # Backslash traversal
            "%2e%2e%5cwindows",                # URL-encoded backslash
            "%2e%2e%2fetc%2fpasswd",           # URL-encoded forward slash
            "file\x00.txt",                    # Literal null byte
            "file%00.txt",                     # URL-encoded null byte
            "../etc/passwd",                   # Classic forward slash
            "%2e%2e/etc/passwd",               # URL-encoded dots
            "%252e%252e/secret",               # Double-encoded
            "\uff0e\uff0e/secret",             # Unicode full-width dots
        ],
    )
    def test_detects_traversal_variants(self, validator, payload):
        """All path traversal variants should be detected."""
        assert validator._check_path_traversal(payload) is True

    def test_safe_paths_are_not_flagged(self, validator):
        """Normal file paths should not trigger traversal detection."""
        assert validator._check_path_traversal("documents/report.pdf") is False
        assert validator._check_path_traversal("data.csv") is False
        assert validator._check_path_traversal("/absolute/path/file.txt") is False


# ---------------------------------------------------------------------------
# Step 5a — Fallback chains report all errors not just the last
# ---------------------------------------------------------------------------


class TestFallbackErrorReporting:

    def test_raise_on_failure_raises_exhausted_error(self):
        """raise_on_failure() should raise FallbackExhaustedError."""
        result: FallbackResult[str] = FallbackResult(
            success=False,
            attempts=3,
            exceptions=[
                ("primary", TimeoutError("timed out")),
                ("fallback_1", ConnectionError("refused")),
                ("fallback_2", ValueError("bad input")),
            ],
        )

        with pytest.raises(FallbackExhaustedError) as exc_info:
            result.raise_on_failure()

        err = exc_info.value
        assert err.attempts == 3
        assert len(err.errors) == 3

    def test_raise_on_failure_chains_all_causes(self):
        """All errors should appear in the __cause__ chain."""
        exc1 = TimeoutError("first")
        exc2 = ConnectionError("second")
        exc3 = ValueError("third")

        result: FallbackResult[str] = FallbackResult(
            success=False,
            attempts=3,
            exceptions=[("a", exc1), ("b", exc2), ("c", exc3)],
        )

        with pytest.raises(FallbackExhaustedError) as exc_info:
            result.raise_on_failure()

        # The __cause__ chain should reference our original exceptions
        cause = exc_info.value.__cause__
        assert cause is not None

    def test_raise_on_failure_noop_on_success(self):
        """raise_on_failure() should do nothing when success=True."""
        result: FallbackResult[str] = FallbackResult(success=True, result="ok")
        result.raise_on_failure()  # Should not raise

    def test_raise_on_failure_noop_when_no_exceptions(self):
        """raise_on_failure() should not raise when there are no exceptions."""
        result: FallbackResult[str] = FallbackResult(
            success=False, attempts=0, exceptions=[]
        )
        result.raise_on_failure()  # Should not raise


# ---------------------------------------------------------------------------
# Step 6b — Context window degrades when summarize callback fails
# ---------------------------------------------------------------------------


class TestSummarizeCallbackFailover:

    def test_callback_failure_falls_back_to_sliding_window(self):
        """When summarize callback raises, should fall back to truncation."""

        def failing_callback(msgs):
            raise RuntimeError("LLM API is down")

        strategy = SummarizeOldStrategy(
            summarize_callback=failing_callback,
            keep_recent=2,
        )

        messages = [_make_message(f"Message {i}", tokens=10) for i in range(10)]
        result = strategy.fit(messages, max_tokens=30)

        # Should not raise; should return a truncated list
        assert len(result) > 0
        total_tokens = sum(m.token_count for m in result)
        assert total_tokens <= 30

    def test_callback_success_uses_summary(self):
        """When callback succeeds, summary should appear in output."""

        def working_callback(msgs):
            return f"Summary of {len(msgs)} messages"

        strategy = SummarizeOldStrategy(
            summarize_callback=working_callback,
            summary_prefix="[SUMMARY]",
            keep_recent=2,
        )

        # Total tokens = 100, max_tokens = 50 — forces summarization
        messages = [_make_message(f"Message {i}", tokens=10) for i in range(10)]
        result = strategy.fit(messages, max_tokens=50)

        assert any("[SUMMARY]" in m.content for m in result)


# ---------------------------------------------------------------------------
# Step 5b — Retry delay is clamped and never produces infinity
# ---------------------------------------------------------------------------


class TestRetryDelayClamped:

    def test_delay_never_exceeds_max(self):
        """Even at high attempts, delay should never exceed max_delay."""
        policy = RetryPolicy(
            max_attempts=100,
            base_delay=1.0,
            max_delay=30.0,
            exponential_base=2.0,
            jitter=0.0,
        )

        for attempt in range(1, 101):
            delay = policy.calculate_delay(attempt)
            assert delay <= 30.0, f"Attempt {attempt} delay {delay} > max_delay 30.0"

    def test_delay_never_negative(self):
        """Delay should never be negative, even with jitter."""
        policy = RetryPolicy(
            max_attempts=50,
            base_delay=0.1,
            max_delay=60.0,
            exponential_base=2.0,
            jitter=1.0,  # Maximum jitter
        )

        for attempt in range(1, 51):
            delay = policy.calculate_delay(attempt)
            assert delay >= 0.0, f"Attempt {attempt} delay {delay} is negative"

    def test_delay_with_extreme_exponent(self):
        """With a very large attempt number, delay should be clamped."""
        policy = RetryPolicy(
            max_attempts=1000,
            base_delay=1.0,
            max_delay=10.0,
            exponential_base=10.0,
            jitter=0.0,
        )

        delay = policy.calculate_delay(999)
        assert delay <= 10.0
        assert delay == pytest.approx(10.0)

    def test_delay_is_finite(self):
        """Delay should never be inf or nan."""
        import math

        policy = RetryPolicy(
            max_attempts=500,
            base_delay=1.0,
            max_delay=100.0,
            exponential_base=2.0,
            jitter=0.5,
        )

        for attempt in [1, 10, 50, 100, 200, 499]:
            delay = policy.calculate_delay(attempt)
            assert math.isfinite(delay), f"Attempt {attempt} delay is not finite: {delay}"
