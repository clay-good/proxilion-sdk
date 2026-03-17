"""Tests for proxilion.security.behavioral_drift module."""

from __future__ import annotations

import time

import pytest

from proxilion.exceptions import EmergencyHaltError
from proxilion.security.behavioral_drift import (
    BaselineStats,
    BehavioralMonitor,
    DriftDetector,
    DriftMetric,
    DriftResult,
    KillSwitch,
)

# ---------------------------------------------------------------------------
# BaselineStats
# ---------------------------------------------------------------------------


class TestBaselineStats:
    def _make_stats(self, mean: float = 10.0, std_dev: float = 2.0) -> BaselineStats:
        return BaselineStats(
            metric=DriftMetric.TOOL_CALL_RATE,
            mean=mean,
            std_dev=std_dev,
            min_value=5.0,
            max_value=15.0,
            sample_count=100,
            percentile_95=14.0,
            percentile_99=14.8,
        )

    def test_z_score_positive(self) -> None:
        stats = self._make_stats(mean=10.0, std_dev=2.0)
        assert stats.z_score(14.0) == pytest.approx(2.0)

    def test_z_score_negative(self) -> None:
        stats = self._make_stats(mean=10.0, std_dev=2.0)
        assert stats.z_score(6.0) == pytest.approx(-2.0)

    def test_z_score_zero_std_dev_same_value(self) -> None:
        stats = self._make_stats(mean=10.0, std_dev=0.0)
        assert stats.z_score(10.0) == 0.0

    def test_z_score_zero_std_dev_different_value(self) -> None:
        stats = self._make_stats(mean=10.0, std_dev=0.0)
        assert stats.z_score(11.0) == float("inf")

    def test_is_anomaly_true(self) -> None:
        stats = self._make_stats(mean=10.0, std_dev=2.0)
        # z-score = 4.0, above default threshold 3.0
        assert stats.is_anomaly(18.0) is True

    def test_is_anomaly_false(self) -> None:
        stats = self._make_stats(mean=10.0, std_dev=2.0)
        # z-score = 1.0
        assert stats.is_anomaly(12.0) is False

    def test_is_anomaly_custom_threshold(self) -> None:
        stats = self._make_stats(mean=10.0, std_dev=2.0)
        # z-score = 1.5, above threshold 1.0
        assert stats.is_anomaly(13.0, threshold=1.0) is True


# ---------------------------------------------------------------------------
# DriftResult
# ---------------------------------------------------------------------------


class TestDriftResult:
    def test_to_dict_keys(self) -> None:
        result = DriftResult(
            is_drifting=True,
            severity=0.7,
            drifting_metrics=[(DriftMetric.LATENCY, 500.0, 5.2)],
            reason="high latency",
        )
        d = result.to_dict()
        assert d["is_drifting"] is True
        assert d["severity"] == 0.7
        assert d["reason"] == "high latency"
        assert len(d["drifting_metrics"]) == 1
        assert d["drifting_metrics"][0]["metric"] == "latency"
        assert "timestamp" in d

    def test_to_dict_empty_metrics(self) -> None:
        result = DriftResult(
            is_drifting=False,
            severity=0.0,
            drifting_metrics=[],
            reason="ok",
        )
        d = result.to_dict()
        assert d["drifting_metrics"] == []


# ---------------------------------------------------------------------------
# BehavioralMonitor
# ---------------------------------------------------------------------------


class TestBehavioralMonitor:
    def test_creation_defaults(self) -> None:
        monitor = BehavioralMonitor(agent_id="test")
        assert monitor.agent_id == "test"

    @pytest.mark.parametrize(
        "kwarg,value",
        [
            ("baseline_window", 0),
            ("baseline_window", -1),
            ("detection_window", 0),
            ("drift_threshold", -0.5),
            ("min_baseline_samples", 0),
        ],
    )
    def test_invalid_params_raise_value_error(self, kwarg: str, value: float) -> None:
        with pytest.raises(ValueError):
            BehavioralMonitor(agent_id="test", **{kwarg: value})

    def test_record_tool_call(self) -> None:
        monitor = BehavioralMonitor(agent_id="test")
        monitor.record_tool_call("search", {"query": "hello"}, latency_ms=42.0)
        metrics = monitor.get_current_metrics()
        assert "tool_call_rate" in metrics

    def test_record_response(self) -> None:
        monitor = BehavioralMonitor(agent_id="test")
        monitor.record_response({"content": "hello world", "tokens": 10})
        metrics = monitor.get_current_metrics()
        assert "response_length" in metrics
        assert "token_usage" in metrics

    def test_record_error(self) -> None:
        monitor = BehavioralMonitor(agent_id="test")
        monitor.record_error({"type": "ValueError"})
        metrics = monitor.get_current_metrics()
        assert "error_rate" in metrics

    def test_record_event_generic(self) -> None:
        monitor = BehavioralMonitor(agent_id="test")
        monitor.record_event("tool_call", {"tool": "search"})
        metrics = monitor.get_current_metrics()
        assert len(metrics) > 0

    def test_lock_baseline_with_enough_samples(self) -> None:
        monitor = BehavioralMonitor(
            agent_id="test",
            baseline_window=100,
            min_baseline_samples=20,
        )
        for _i in range(25):
            monitor.record_response({"content": "x" * 100})
        baseline = monitor.lock_baseline()
        assert len(baseline) > 0
        for stats in baseline.values():
            assert stats.sample_count >= 20

    def test_lock_baseline_skips_sparse_metrics(self) -> None:
        monitor = BehavioralMonitor(
            agent_id="test",
            min_baseline_samples=20,
        )
        for _i in range(5):
            monitor.record_response({"content": "x"})
        baseline = monitor.lock_baseline()
        # Not enough samples, so no metric should appear
        assert len(baseline) == 0

    def test_check_drift_no_baseline(self) -> None:
        monitor = BehavioralMonitor(agent_id="test", min_baseline_samples=50)
        result = monitor.check_drift()
        assert result.is_drifting is False
        assert "not yet established" in result.reason.lower()

    def test_check_drift_no_drift(self) -> None:
        monitor = BehavioralMonitor(
            agent_id="test",
            baseline_window=100,
            detection_window=5,
            min_baseline_samples=20,
            drift_threshold=3.0,
        )
        # Build baseline with consistent data
        for _ in range(30):
            monitor.record_response({"content": "x" * 100})
        monitor.lock_baseline()

        # Record similar data in detection window
        for _ in range(5):
            monitor.record_response({"content": "x" * 100})

        result = monitor.check_drift()
        assert result.is_drifting is False

    def test_check_drift_detects_drift(self) -> None:
        monitor = BehavioralMonitor(
            agent_id="test",
            baseline_window=100,
            detection_window=5,
            min_baseline_samples=20,
            drift_threshold=2.0,
        )
        # Build baseline with short responses
        for _ in range(30):
            monitor.record_response({"content": "x" * 50})
        monitor.lock_baseline()

        # Now record very long responses to cause drift
        for _ in range(5):
            monitor.record_response({"content": "x" * 50000})

        result = monitor.check_drift()
        assert result.is_drifting is True
        assert result.severity > 0.0
        assert len(result.drifting_metrics) > 0

    def test_drift_callback_invoked(self) -> None:
        monitor = BehavioralMonitor(
            agent_id="test",
            baseline_window=100,
            detection_window=5,
            min_baseline_samples=20,
            drift_threshold=2.0,
        )
        callback_results: list[DriftResult] = []
        monitor.on_drift(callback_results.append)

        for _ in range(30):
            monitor.record_response({"content": "x" * 50})
        monitor.lock_baseline()

        for _ in range(5):
            monitor.record_response({"content": "x" * 50000})

        monitor.check_drift()
        assert len(callback_results) == 1
        assert callback_results[0].is_drifting is True

    def test_callback_not_invoked_when_no_drift(self) -> None:
        monitor = BehavioralMonitor(
            agent_id="test",
            baseline_window=100,
            detection_window=5,
            min_baseline_samples=20,
        )
        callback_results: list[DriftResult] = []
        monitor.on_drift(callback_results.append)

        for _ in range(30):
            monitor.record_response({"content": "x" * 100})
        monitor.lock_baseline()

        for _ in range(5):
            monitor.record_response({"content": "x" * 100})

        monitor.check_drift()
        assert len(callback_results) == 0

    def test_reset_clears_state(self) -> None:
        monitor = BehavioralMonitor(agent_id="test", min_baseline_samples=20)
        for _ in range(25):
            monitor.record_response({"content": "hello"})
        monitor.lock_baseline()
        assert len(monitor.get_baseline()) > 0

        monitor.reset()
        assert len(monitor.get_baseline()) == 0
        assert monitor.get_current_metrics() == {}

    def test_get_current_metrics_empty(self) -> None:
        monitor = BehavioralMonitor(agent_id="test")
        assert monitor.get_current_metrics() == {}

    def test_check_drift_auto_locks_baseline(self) -> None:
        monitor = BehavioralMonitor(
            agent_id="test",
            min_baseline_samples=20,
        )
        for _ in range(25):
            monitor.record_response({"content": "x" * 100})

        # Should auto-lock baseline and return a result
        monitor.check_drift()
        assert len(monitor.get_baseline()) > 0

    def test_check_drift_empty_detection_window(self) -> None:
        """After locking baseline with one metric, clear data and check drift."""
        monitor = BehavioralMonitor(
            agent_id="test",
            baseline_window=100,
            detection_window=5,
            min_baseline_samples=20,
        )
        for _ in range(25):
            monitor.record_response({"content": "x" * 100})
        monitor.lock_baseline()

        # Clear metric data manually to simulate empty detection window
        for values in monitor._metrics.values():
            values.clear()

        result = monitor.check_drift()
        assert result.is_drifting is False


# ---------------------------------------------------------------------------
# KillSwitch
# ---------------------------------------------------------------------------


class TestKillSwitch:
    def test_initial_state(self) -> None:
        ks = KillSwitch()
        assert ks.is_active is False
        assert ks.reason == ""

    def test_activate_raises_emergency_halt(self) -> None:
        ks = KillSwitch()
        with pytest.raises(EmergencyHaltError):
            ks.activate("rogue behavior")
        assert ks.is_active is True
        assert ks.reason == "rogue behavior"

    def test_activate_no_exception(self) -> None:
        ks = KillSwitch()
        ks.activate("test", raise_exception=False)
        assert ks.is_active is True
        assert ks.reason == "test"

    def test_reset_returns_true_when_was_active(self) -> None:
        ks = KillSwitch()
        ks.activate("test", raise_exception=False)
        assert ks.reset() is True
        assert ks.is_active is False

    def test_reset_returns_false_when_not_active(self) -> None:
        ks = KillSwitch()
        assert ks.reset() is False

    def test_check_raises_when_active(self) -> None:
        ks = KillSwitch()
        ks.activate("test", raise_exception=False)
        with pytest.raises(EmergencyHaltError):
            ks.check()

    def test_check_passes_when_inactive(self) -> None:
        ks = KillSwitch()
        ks.check()  # should not raise

    def test_auto_reset(self) -> None:
        ks = KillSwitch(auto_reset_seconds=0.1)
        ks.activate("temp halt", raise_exception=False)
        assert ks.is_active is True
        time.sleep(0.15)
        assert ks.is_active is False

    def test_halt_callback_invoked(self) -> None:
        ks = KillSwitch()
        reasons: list[str] = []
        ks.on_halt(reasons.append)
        ks.activate("callback test", raise_exception=False)
        assert reasons == ["callback test"]

    def test_reset_callback_invoked(self) -> None:
        ks = KillSwitch()
        reset_count: list[int] = []
        ks.on_reset(lambda: reset_count.append(1))
        ks.activate("test", raise_exception=False)
        ks.reset()
        assert len(reset_count) == 1

    def test_reset_callback_not_invoked_when_not_active(self) -> None:
        ks = KillSwitch()
        reset_count: list[int] = []
        ks.on_reset(lambda: reset_count.append(1))
        ks.reset()
        assert len(reset_count) == 0

    def test_get_status(self) -> None:
        ks = KillSwitch()
        status = ks.get_status()
        assert status["active"] is False
        assert status["reason"] == ""
        assert status["activation_time"] is None

        ks.activate("status test", raise_exception=False)
        status = ks.get_status()
        assert status["active"] is True
        assert status["reason"] == "status test"
        assert status["activation_time"] is not None


# ---------------------------------------------------------------------------
# DriftDetector
# ---------------------------------------------------------------------------


class TestDriftDetector:
    def test_creation(self) -> None:
        detector = DriftDetector(agent_id="test")
        assert detector.agent_id == "test"
        assert detector.monitor is not None
        assert detector.kill_switch is not None

    def test_record_methods_delegate(self) -> None:
        detector = DriftDetector(agent_id="test")
        detector.record_tool_call("search", {"q": "hello"}, latency_ms=10.0)
        detector.record_response({"content": "result"})
        detector.record_error({"type": "ValueError"})
        detector.record_event("latency", {"value": 42})
        metrics = detector.monitor.get_current_metrics()
        assert len(metrics) > 0

    def test_check_no_drift(self) -> None:
        detector = DriftDetector(
            agent_id="test",
            monitor_kwargs={
                "min_baseline_samples": 20,
                "detection_window": 5,
                "drift_threshold": 3.0,
            },
        )
        for _ in range(25):
            detector.record_response({"content": "x" * 100})
        detector.lock_baseline()

        for _ in range(5):
            detector.record_response({"content": "x" * 100})

        result = detector.check()
        assert result.is_drifting is False

    def test_check_auto_halts_on_severe_drift(self) -> None:
        detector = DriftDetector(
            agent_id="test",
            auto_halt_threshold=0.3,
            monitor_kwargs={
                "min_baseline_samples": 20,
                "detection_window": 5,
                "drift_threshold": 2.0,
            },
        )
        for _ in range(30):
            detector.record_response({"content": "x" * 50})
        detector.lock_baseline()

        for _ in range(5):
            detector.record_response({"content": "x" * 50000})

        with pytest.raises(EmergencyHaltError):
            detector.check()

        assert detector.kill_switch.is_active is True

    def test_reset_clears_monitor_and_kill_switch(self) -> None:
        detector = DriftDetector(agent_id="test")
        detector.kill_switch.activate("test", raise_exception=False)
        assert detector.kill_switch.is_active is True

        detector.reset()
        assert detector.kill_switch.is_active is False
        assert detector.monitor.get_current_metrics() == {}

    def test_record_tool_call_fails_when_halted(self) -> None:
        detector = DriftDetector(agent_id="test")
        detector.kill_switch.activate("halted", raise_exception=False)
        with pytest.raises(EmergencyHaltError):
            detector.record_tool_call("search")

    def test_get_status(self) -> None:
        detector = DriftDetector(agent_id="test")
        status = detector.get_status()
        assert status["agent_id"] == "test"
        assert "kill_switch" in status
        assert "current_metrics" in status
        assert "baseline_locked" in status

    def test_lock_baseline_delegates(self) -> None:
        detector = DriftDetector(
            agent_id="test",
            monitor_kwargs={"min_baseline_samples": 20},
        )
        for _ in range(25):
            detector.record_response({"content": "x" * 100})
        baseline = detector.lock_baseline()
        assert len(baseline) > 0


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_zero_std_dev_baseline_no_false_drift(self) -> None:
        """When all baseline values are identical, std_dev is 0 and identical
        current values should not be flagged as drift."""
        monitor = BehavioralMonitor(
            agent_id="test",
            baseline_window=100,
            detection_window=5,
            min_baseline_samples=20,
            drift_threshold=3.0,
        )
        # All identical responses
        for _ in range(30):
            monitor.record_response({"content": "x" * 100})
        monitor.lock_baseline()

        # Same responses in detection window
        for _ in range(5):
            monitor.record_response({"content": "x" * 100})

        result = monitor.check_drift()
        assert result.is_drifting is False

    def test_zero_std_dev_baseline_different_value_detected(self) -> None:
        """When all baseline values are identical and a different value appears,
        it should register as infinite z-score and be flagged."""
        stats = BaselineStats(
            metric=DriftMetric.RESPONSE_LENGTH,
            mean=100.0,
            std_dev=0.0,
            min_value=100.0,
            max_value=100.0,
            sample_count=30,
            percentile_95=100.0,
            percentile_99=100.0,
        )
        assert stats.z_score(200.0) == float("inf")
        assert stats.is_anomaly(200.0) is True

    def test_drift_metric_enum_values(self) -> None:
        assert DriftMetric.TOOL_CALL_RATE.value == "tool_call_rate"
        assert DriftMetric.CUSTOM.value == "custom"
        assert len(DriftMetric) == 10

    def test_drift_result_to_dict_multiple_metrics(self) -> None:
        result = DriftResult(
            is_drifting=True,
            severity=0.9,
            drifting_metrics=[
                (DriftMetric.LATENCY, 500.0, 5.0),
                (DriftMetric.ERROR_RATE, 10.0, 4.0),
            ],
            reason="multiple drifts",
        )
        d = result.to_dict()
        assert len(d["drifting_metrics"]) == 2
        assert d["drifting_metrics"][0]["metric"] == "latency"
        assert d["drifting_metrics"][1]["metric"] == "error_rate"
