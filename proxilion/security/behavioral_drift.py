"""
Behavioral Drift Detection for Proxilion.

Addresses OWASP ASI10: Rogue Agents.

This module detects when an agent's behavior deviates significantly
from its established baseline, potentially indicating:
- Compromise or injection attack
- Malfunction or loop behavior
- Goal hijacking
- Rogue agent behavior

Example:
    >>> from proxilion.security.behavioral_drift import (
    ...     BehavioralMonitor,
    ...     DriftDetector,
    ...     KillSwitch,
    ... )
    >>>
    >>> # Create monitor
    >>> monitor = BehavioralMonitor(agent_id="my_agent")
    >>>
    >>> # Record normal behavior during baseline period
    >>> for i in range(100):
    ...     monitor.record_event("tool_call", {"tool": "search"})
    ...     monitor.record_event("response", {"length": 150})
    >>>
    >>> # Lock baseline
    >>> monitor.lock_baseline()
    >>>
    >>> # Detect drift during operation
    >>> drift = monitor.check_drift()
    >>> if drift.is_drifting:
    ...     print(f"Behavioral drift detected: {drift.reason}")
    ...     if drift.severity > 0.8:
    ...         kill_switch.activate("Severe behavioral drift")
"""

from __future__ import annotations

import logging
import statistics
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from proxilion.exceptions import EmergencyHaltError

logger = logging.getLogger(__name__)


class DriftMetric(Enum):
    """Types of behavioral metrics tracked."""

    TOOL_CALL_RATE = "tool_call_rate"
    """Calls per minute."""

    RESPONSE_LENGTH = "response_length"
    """Average response length."""

    ERROR_RATE = "error_rate"
    """Errors per minute."""

    UNIQUE_TOOLS = "unique_tools"
    """Number of unique tools used."""

    LATENCY = "latency"
    """Average response latency."""

    TOKEN_USAGE = "token_usage"
    """Tokens consumed per request."""

    TOOL_REPETITION = "tool_repetition"
    """Same tool called consecutively."""

    SCOPE_VIOLATIONS = "scope_violations"
    """Attempts to exceed scope."""

    CONTEXT_SIZE = "context_size"
    """Size of conversation context."""

    CUSTOM = "custom"
    """User-defined metric."""


@dataclass
class MetricValue:
    """A single metric measurement."""

    metric: DriftMetric
    value: float
    timestamp: float
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class BaselineStats:
    """Statistical baseline for a metric."""

    metric: DriftMetric
    mean: float
    std_dev: float
    min_value: float
    max_value: float
    sample_count: int
    percentile_95: float
    percentile_99: float

    def z_score(self, value: float) -> float:
        """Calculate z-score for a value."""
        if self.std_dev == 0:
            return 0.0 if value == self.mean else float("inf")
        return (value - self.mean) / self.std_dev

    def is_anomaly(self, value: float, threshold: float = 3.0) -> bool:
        """Check if value is anomalous (beyond threshold std devs)."""
        return abs(self.z_score(value)) > threshold


@dataclass
class DriftResult:
    """Result of drift detection."""

    is_drifting: bool
    severity: float  # 0.0 to 1.0
    drifting_metrics: list[tuple[DriftMetric, float, float]]  # (metric, value, z_score)
    reason: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "is_drifting": self.is_drifting,
            "severity": self.severity,
            "drifting_metrics": [
                {"metric": m.value, "value": v, "z_score": z}
                for m, v, z in self.drifting_metrics
            ],
            "reason": self.reason,
            "timestamp": self.timestamp.isoformat(),
        }


class BehavioralMonitor:
    """
    Monitors agent behavior and detects drift from baseline.

    Tracks multiple behavioral metrics and uses statistical analysis
    to detect when current behavior deviates from established patterns.

    Example:
        >>> monitor = BehavioralMonitor(agent_id="my_agent")
        >>>
        >>> # Record events during operation
        >>> monitor.record_tool_call("search", {"query": "test"})
        >>> monitor.record_response({"content": "result", "tokens": 50})
        >>>
        >>> # Check for drift
        >>> result = monitor.check_drift()
        >>> if result.is_drifting:
        ...     handle_drift(result)
    """

    def __init__(
        self,
        agent_id: str,
        baseline_window: int = 100,
        detection_window: int = 10,
        drift_threshold: float = 3.0,
        min_baseline_samples: int = 20,
    ) -> None:
        """
        Initialize the monitor.

        Args:
            agent_id: Unique identifier for the agent.
            baseline_window: Number of samples for baseline calculation.
            detection_window: Recent samples for drift detection.
            drift_threshold: Z-score threshold for drift detection.
            min_baseline_samples: Minimum samples before baseline is valid.
        """
        self.agent_id = agent_id
        self._baseline_window = baseline_window
        self._detection_window = detection_window
        self._drift_threshold = drift_threshold
        self._min_baseline_samples = min_baseline_samples

        # Metric storage
        self._metrics: dict[DriftMetric, deque[MetricValue]] = {}
        for metric in DriftMetric:
            self._metrics[metric] = deque(maxlen=baseline_window)

        # Baseline (locked after initial period)
        self._baseline: dict[DriftMetric, BaselineStats] = {}
        self._baseline_locked = False

        # Rate tracking
        self._event_times: deque[float] = deque(maxlen=1000)
        self._tool_history: deque[str] = deque(maxlen=100)
        self._error_count = 0

        # Callbacks
        self._drift_callbacks: list[Callable[[DriftResult], None]] = []

        self._lock = threading.RLock()

        logger.debug(f"BehavioralMonitor initialized for agent: {agent_id}")

    def record_event(
        self,
        event_type: str,
        data: dict[str, Any],
    ) -> None:
        """
        Record a generic event.

        Args:
            event_type: Type of event (tool_call, response, error, etc.).
            data: Event data.
        """
        now = time.time()

        with self._lock:
            self._event_times.append(now)
            if event_type == "tool_call":
                self._record_tool_call(data, now)
            elif event_type == "response":
                self._record_response(data, now)
            elif event_type == "error":
                self._record_error(data, now)
            elif event_type == "latency":
                self._record_metric(DriftMetric.LATENCY, data.get("value", 0), now)
            elif event_type == "tokens":
                self._record_metric(DriftMetric.TOKEN_USAGE, data.get("value", 0), now)
            elif event_type == "context_size":
                self._record_metric(DriftMetric.CONTEXT_SIZE, data.get("value", 0), now)
            elif event_type == "scope_violation":
                self._record_metric(DriftMetric.SCOPE_VIOLATIONS, 1.0, now)

    def record_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        latency_ms: float | None = None,
    ) -> None:
        """Record a tool call event."""
        now = time.time()

        with self._lock:
            self._event_times.append(now)
            self._tool_history.append(tool_name)

            # Calculate call rate (calls per minute)
            recent_calls = sum(1 for t in self._event_times if now - t < 60)
            self._record_metric(DriftMetric.TOOL_CALL_RATE, recent_calls, now)

            # Track unique tools
            unique_tools = len(set(self._tool_history))
            self._record_metric(DriftMetric.UNIQUE_TOOLS, unique_tools, now)

            # Track repetition
            if len(self._tool_history) >= 2:
                repetition = sum(
                    1 for i in range(1, len(self._tool_history))
                    if self._tool_history[i] == self._tool_history[i - 1]
                )
                self._record_metric(DriftMetric.TOOL_REPETITION, repetition, now)

            # Record latency if provided
            if latency_ms is not None:
                self._record_metric(DriftMetric.LATENCY, latency_ms, now)

    def record_response(
        self,
        response: dict[str, Any],
    ) -> None:
        """Record a response event."""
        now = time.time()

        with self._lock:
            # Response length
            content = response.get("content", "")
            if isinstance(content, str):
                self._record_metric(DriftMetric.RESPONSE_LENGTH, len(content), now)

            # Token usage
            tokens = response.get("tokens") or response.get("token_count")
            if tokens:
                self._record_metric(DriftMetric.TOKEN_USAGE, tokens, now)

    def record_error(self, error_info: dict[str, Any]) -> None:
        """Record an error event."""
        now = time.time()

        with self._lock:
            self._error_count += 1
            # Error rate (errors per minute)
            recent_errors = sum(
                1 for mv in self._metrics[DriftMetric.ERROR_RATE]
                if now - mv.timestamp < 60
            )
            self._record_metric(DriftMetric.ERROR_RATE, recent_errors + 1, now)

    def _record_tool_call(self, data: dict[str, Any], timestamp: float) -> None:
        """Internal tool call recording."""
        tool_name = data.get("tool") or data.get("tool_name", "unknown")
        self._tool_history.append(tool_name)

        # Calculate metrics
        recent_calls = sum(1 for t in self._event_times if timestamp - t < 60)
        self._record_metric(DriftMetric.TOOL_CALL_RATE, recent_calls, timestamp)

        unique_tools = len(set(self._tool_history))
        self._record_metric(DriftMetric.UNIQUE_TOOLS, unique_tools, timestamp)

    def _record_response(self, data: dict[str, Any], timestamp: float) -> None:
        """Internal response recording."""
        content = data.get("content", "")
        if isinstance(content, str):
            self._record_metric(DriftMetric.RESPONSE_LENGTH, len(content), timestamp)

        tokens = data.get("tokens", 0)
        if tokens:
            self._record_metric(DriftMetric.TOKEN_USAGE, tokens, timestamp)

    def _record_error(self, data: dict[str, Any], timestamp: float) -> None:
        """Internal error recording."""
        self._error_count += 1
        recent_errors = sum(
            1 for mv in self._metrics[DriftMetric.ERROR_RATE]
            if timestamp - mv.timestamp < 60
        )
        self._record_metric(DriftMetric.ERROR_RATE, recent_errors + 1, timestamp)

    def _record_metric(
        self,
        metric: DriftMetric,
        value: float,
        timestamp: float,
    ) -> None:
        """Record a metric value."""
        self._metrics[metric].append(MetricValue(
            metric=metric,
            value=value,
            timestamp=timestamp,
        ))

    def lock_baseline(self) -> dict[DriftMetric, BaselineStats]:
        """
        Lock the current baseline.

        Calculates statistical baselines from current data and
        locks them for future drift detection.

        Returns:
            Dictionary of baseline stats per metric.

        Raises:
            ValueError: If not enough samples for baseline.
        """
        with self._lock:
            self._baseline = {}

            for metric, values in self._metrics.items():
                if len(values) < self._min_baseline_samples:
                    continue

                samples = [v.value for v in values]

                # Calculate statistics
                mean = statistics.mean(samples)
                std_dev = statistics.stdev(samples) if len(samples) > 1 else 0.0
                sorted_samples = sorted(samples)
                n = len(sorted_samples)
                p95_idx = max(0, min(int((n - 1) * 0.95), n - 1))
                p99_idx = max(0, min(int((n - 1) * 0.99), n - 1))

                self._baseline[metric] = BaselineStats(
                    metric=metric,
                    mean=mean,
                    std_dev=std_dev,
                    min_value=min(samples),
                    max_value=max(samples),
                    sample_count=len(samples),
                    percentile_95=sorted_samples[p95_idx],
                    percentile_99=sorted_samples[p99_idx],
                )

            self._baseline_locked = True
            logger.info(f"Baseline locked with {len(self._baseline)} metrics")

            return self._baseline

    def check_drift(self) -> DriftResult:
        """
        Check for behavioral drift from baseline.

        Returns:
            DriftResult indicating if drift was detected.
        """
        with self._lock:
            if not self._baseline_locked:
                # Auto-lock baseline if we have enough samples
                has_enough = any(
                    len(values) >= self._min_baseline_samples
                    for values in self._metrics.values()
                )
                if has_enough:
                    self.lock_baseline()
                else:
                    return DriftResult(
                        is_drifting=False,
                        severity=0.0,
                        drifting_metrics=[],
                        reason="Baseline not yet established",
                    )

            drifting_metrics: list[tuple[DriftMetric, float, float]] = []
            max_severity = 0.0

            for metric, baseline in self._baseline.items():
                # Get recent values
                recent = list(self._metrics[metric])[-self._detection_window:]
                if not recent:
                    continue

                # Calculate current value (average of recent)
                current_value = statistics.mean([v.value for v in recent])

                # Calculate z-score
                z_score = baseline.z_score(current_value)

                # Check for drift
                if abs(z_score) > self._drift_threshold:
                    drifting_metrics.append((metric, current_value, z_score))

                    # Calculate severity (normalized z-score)
                    severity = min(1.0, abs(z_score) / (self._drift_threshold * 2))
                    max_severity = max(max_severity, severity)

            if drifting_metrics:
                reasons = [
                    f"{m.value}: {v:.2f} (z={z:.1f})"
                    for m, v, z in drifting_metrics
                ]
                result = DriftResult(
                    is_drifting=True,
                    severity=max_severity,
                    drifting_metrics=drifting_metrics,
                    reason=f"Drift detected in: {', '.join(reasons)}",
                )

                # Notify callbacks
                for callback in self._drift_callbacks:
                    try:
                        callback(result)
                    except Exception as e:
                        logger.error(f"Drift callback error: {e}")

                return result

            return DriftResult(
                is_drifting=False,
                severity=0.0,
                drifting_metrics=[],
                reason="Behavior within normal parameters",
            )

    def on_drift(self, callback: Callable[[DriftResult], None]) -> None:
        """Register a callback for drift detection."""
        self._drift_callbacks.append(callback)

    def get_current_metrics(self) -> dict[str, float]:
        """Get current metric values."""
        with self._lock:
            result = {}
            for metric, values in self._metrics.items():
                if values:
                    recent = list(values)[-self._detection_window:]
                    result[metric.value] = statistics.mean([v.value for v in recent])
            return result

    def get_baseline(self) -> dict[DriftMetric, BaselineStats]:
        """Get the current baseline."""
        with self._lock:
            return self._baseline.copy()

    def reset(self) -> None:
        """Reset the monitor."""
        with self._lock:
            for values in self._metrics.values():
                values.clear()
            self._baseline = {}
            self._baseline_locked = False
            self._event_times.clear()
            self._tool_history.clear()
            self._error_count = 0


class KillSwitch:
    """
    Emergency halt mechanism for rogue agent behavior.

    Provides immediate shutdown capability when severe behavioral
    drift or other anomalies are detected.

    Example:
        >>> kill_switch = KillSwitch()
        >>>
        >>> # Register halt handlers
        >>> kill_switch.on_halt(lambda reason: cleanup_resources())
        >>> kill_switch.on_halt(lambda reason: notify_operators(reason))
        >>>
        >>> # Activate when needed
        >>> if drift.severity > 0.9:
        ...     kill_switch.activate("Severe behavioral drift detected")
    """

    def __init__(
        self,
        auto_reset_seconds: float | None = None,
    ) -> None:
        """
        Initialize the kill switch.

        Args:
            auto_reset_seconds: If set, auto-reset after this many seconds.
        """
        self._active = False
        self._activation_time: datetime | None = None
        self._activation_reason: str = ""
        self._auto_reset_seconds = auto_reset_seconds

        self._halt_callbacks: list[Callable[[str], None]] = []
        self._reset_callbacks: list[Callable[[], None]] = []

        self._lock = threading.RLock()

        logger.debug("KillSwitch initialized")

    @property
    def is_active(self) -> bool:
        """Check if kill switch is active."""
        with self._lock:
            if self._active and self._auto_reset_seconds:
                # Check for auto-reset
                if self._activation_time:
                    elapsed = (datetime.now(timezone.utc) - self._activation_time).total_seconds()
                    if elapsed > self._auto_reset_seconds:
                        self._active = False
                        self._activation_reason = ""
                        logger.info("Kill switch auto-reset")
            return self._active

    @property
    def reason(self) -> str:
        """Get activation reason."""
        return self._activation_reason

    def activate(
        self,
        reason: str,
        triggered_by: str = "system",
        raise_exception: bool = True,
    ) -> None:
        """
        Activate the kill switch.

        Args:
            reason: Why the kill switch was activated.
            triggered_by: What triggered the activation.
            raise_exception: If True, raise EmergencyHaltError.

        Raises:
            EmergencyHaltError: If raise_exception is True.
        """
        with self._lock:
            self._active = True
            self._activation_time = datetime.now(timezone.utc)
            self._activation_reason = reason

            logger.critical(
                f"KILL SWITCH ACTIVATED: {reason} (triggered by: {triggered_by})"
            )

            # Notify handlers
            for callback in self._halt_callbacks:
                try:
                    callback(reason)
                except Exception as e:
                    logger.error(f"Halt callback error: {e}")

        if raise_exception:
            raise EmergencyHaltError(reason=reason, triggered_by=triggered_by)

    def reset(self) -> bool:
        """
        Reset the kill switch.

        Returns:
            True if was active and is now reset.
        """
        with self._lock:
            was_active = self._active
            self._active = False
            self._activation_reason = ""
            self._activation_time = None

            if was_active:
                logger.warning("Kill switch reset")
                for callback in self._reset_callbacks:
                    try:
                        callback()
                    except Exception as e:
                        logger.error(f"Reset callback error: {e}")

            return was_active

    def check(self) -> None:
        """
        Check if kill switch is active and raise if so.

        Raises:
            EmergencyHaltError: If kill switch is active.
        """
        if self.is_active:
            raise EmergencyHaltError(
                reason=self._activation_reason,
                triggered_by="kill_switch_check",
            )

    def on_halt(self, callback: Callable[[str], None]) -> None:
        """Register a callback for when kill switch activates."""
        self._halt_callbacks.append(callback)

    def on_reset(self, callback: Callable[[], None]) -> None:
        """Register a callback for when kill switch resets."""
        self._reset_callbacks.append(callback)

    def get_status(self) -> dict[str, Any]:
        """Get kill switch status."""
        with self._lock:
            return {
                "active": self._active,
                "reason": self._activation_reason,
                "activation_time": (
                    self._activation_time.isoformat() if self._activation_time else None
                ),
            }


class DriftDetector:
    """
    High-level drift detector with integrated kill switch.

    Combines behavioral monitoring with automatic response
    to detected anomalies.

    Example:
        >>> detector = DriftDetector(
        ...     agent_id="my_agent",
        ...     auto_halt_threshold=0.9,
        ... )
        >>>
        >>> # Record events
        >>> detector.record_tool_call("search", {"query": "test"})
        >>>
        >>> # This will auto-halt if drift exceeds threshold
        >>> detector.check()
    """

    def __init__(
        self,
        agent_id: str,
        auto_halt_threshold: float = 0.9,
        warning_threshold: float = 0.5,
        monitor_kwargs: dict[str, Any] | None = None,
    ) -> None:
        """
        Initialize the detector.

        Args:
            agent_id: Unique identifier for the agent.
            auto_halt_threshold: Severity threshold for automatic halt.
            warning_threshold: Severity threshold for warnings.
            monitor_kwargs: Additional kwargs for BehavioralMonitor.
        """
        self.agent_id = agent_id
        self._auto_halt_threshold = auto_halt_threshold
        self._warning_threshold = warning_threshold

        self._monitor = BehavioralMonitor(agent_id, **(monitor_kwargs or {}))
        self._kill_switch = KillSwitch()

        # Wire up automatic drift handling
        self._monitor.on_drift(self._handle_drift)

    @property
    def monitor(self) -> BehavioralMonitor:
        """Get the behavioral monitor."""
        return self._monitor

    @property
    def kill_switch(self) -> KillSwitch:
        """Get the kill switch."""
        return self._kill_switch

    def record_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        latency_ms: float | None = None,
    ) -> None:
        """Record a tool call and check for drift."""
        self._kill_switch.check()  # Fail fast if halted
        self._monitor.record_tool_call(tool_name, arguments, latency_ms)

    def record_response(self, response: dict[str, Any]) -> None:
        """Record a response and check for drift."""
        self._kill_switch.check()
        self._monitor.record_response(response)

    def record_error(self, error_info: dict[str, Any]) -> None:
        """Record an error and check for drift."""
        self._monitor.record_error(error_info)

    def record_event(self, event_type: str, data: dict[str, Any]) -> None:
        """Record a generic event."""
        self._kill_switch.check()
        self._monitor.record_event(event_type, data)

    def check(self) -> DriftResult:
        """
        Check for drift and respond accordingly.

        Returns:
            DriftResult from the check.

        Raises:
            EmergencyHaltError: If drift exceeds auto_halt_threshold.
        """
        self._kill_switch.check()
        result = self._monitor.check_drift()

        if result.is_drifting:
            self._handle_drift(result)

        return result

    def _handle_drift(self, result: DriftResult) -> None:
        """Handle detected drift."""
        if result.severity >= self._auto_halt_threshold:
            self._kill_switch.activate(
                reason=f"Severe behavioral drift: {result.reason}",
                triggered_by="drift_detector",
            )
        elif result.severity >= self._warning_threshold:
            logger.warning(
                f"Behavioral drift warning for {self.agent_id}: {result.reason}"
            )

    def lock_baseline(self) -> dict[DriftMetric, BaselineStats]:
        """Lock the baseline."""
        return self._monitor.lock_baseline()

    def reset(self) -> None:
        """Reset the detector."""
        self._monitor.reset()
        self._kill_switch.reset()

    def get_status(self) -> dict[str, Any]:
        """Get detector status."""
        return {
            "agent_id": self.agent_id,
            "kill_switch": self._kill_switch.get_status(),
            "current_metrics": self._monitor.get_current_metrics(),
            "baseline_locked": self._monitor._baseline_locked,
        }


# Convenience exports
__all__ = [
    # Core classes
    "BehavioralMonitor",
    "DriftDetector",
    "KillSwitch",
    # Data classes
    "DriftResult",
    "BaselineStats",
    "MetricValue",
    "DriftMetric",
]
