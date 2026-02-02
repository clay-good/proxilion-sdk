"""
Real-Time Metrics and Alerts for Proxilion.

Provides observability into Proxilion's security operations with:
- Prometheus-compatible metrics export
- Real-time alerting via webhooks
- Security event aggregation
- Dashboard-ready data

Example:
    >>> from proxilion.observability.metrics import (
    ...     MetricsCollector,
    ...     AlertManager,
    ...     PrometheusExporter,
    ... )
    >>>
    >>> # Create collector
    >>> collector = MetricsCollector()
    >>>
    >>> # Record security events
    >>> collector.record_authorization(allowed=True, user="alice", resource="db")
    >>> collector.record_guard_block(guard_type="input", pattern="injection")
    >>> collector.record_rate_limit_hit(user="bob")
    >>>
    >>> # Get Prometheus metrics
    >>> exporter = PrometheusExporter(collector)
    >>> print(exporter.export())
    >>>
    >>> # Configure alerts
    >>> alerts = AlertManager(webhook_url="https://hooks.slack.com/...")
    >>> alerts.add_rule("high_block_rate", threshold=10, window_seconds=60)
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable
from urllib.request import Request, urlopen
from urllib.error import URLError

logger = logging.getLogger(__name__)


class MetricType(Enum):
    """Types of metrics."""

    COUNTER = "counter"
    """Monotonically increasing value."""

    GAUGE = "gauge"
    """Value that can go up or down."""

    HISTOGRAM = "histogram"
    """Distribution of values."""

    SUMMARY = "summary"
    """Summary statistics."""


class EventType(Enum):
    """Types of security events."""

    AUTHORIZATION_ALLOWED = "authorization_allowed"
    AUTHORIZATION_DENIED = "authorization_denied"
    INPUT_GUARD_BLOCK = "input_guard_block"
    OUTPUT_GUARD_BLOCK = "output_guard_block"
    RATE_LIMIT_HIT = "rate_limit_hit"
    CIRCUIT_OPEN = "circuit_open"
    IDOR_VIOLATION = "idor_violation"
    SEQUENCE_VIOLATION = "sequence_violation"
    INTENT_HIJACK = "intent_hijack"
    BEHAVIORAL_DRIFT = "behavioral_drift"
    KILL_SWITCH_ACTIVATED = "kill_switch_activated"
    CONTEXT_TAMPERING = "context_tampering"
    AGENT_TRUST_VIOLATION = "agent_trust_violation"


@dataclass
class SecurityEvent:
    """A security-related event."""

    event_type: EventType
    timestamp: float
    user_id: str | None = None
    agent_id: str | None = None
    resource: str | None = None
    action: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    severity: float = 0.5  # 0.0 to 1.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "event_type": self.event_type.value,
            "timestamp": self.timestamp,
            "datetime": datetime.fromtimestamp(self.timestamp, tz=timezone.utc).isoformat(),
            "user_id": self.user_id,
            "agent_id": self.agent_id,
            "resource": self.resource,
            "action": self.action,
            "details": self.details,
            "severity": self.severity,
        }


@dataclass
class MetricSample:
    """A single metric sample."""

    name: str
    value: float
    timestamp: float
    labels: dict[str, str] = field(default_factory=dict)


class MetricsCollector:
    """
    Collects security metrics from Proxilion operations.

    Provides both real-time and aggregated metrics for monitoring
    and alerting.

    Example:
        >>> collector = MetricsCollector()
        >>>
        >>> # Record events
        >>> collector.record_authorization(True, "alice", "database")
        >>> collector.record_guard_block("input", "prompt_injection")
        >>>
        >>> # Get stats
        >>> stats = collector.get_summary()
        >>> print(f"Total authorizations: {stats['total_authorizations']}")
    """

    def __init__(
        self,
        event_window_size: int = 10000,
        aggregation_window_seconds: float = 60.0,
    ) -> None:
        """
        Initialize the collector.

        Args:
            event_window_size: Maximum events to keep in memory.
            aggregation_window_seconds: Window for rate calculations.
        """
        self._event_window_size = event_window_size
        self._aggregation_window = aggregation_window_seconds

        # Event storage
        self._events: deque[SecurityEvent] = deque(maxlen=event_window_size)

        # Counters
        self._counters: dict[str, int] = defaultdict(int)
        self._counter_labels: dict[str, dict[str, dict[str, int]]] = defaultdict(
            lambda: defaultdict(lambda: defaultdict(int))
        )

        # Gauges
        self._gauges: dict[str, float] = {}

        # Histograms (bucket counts)
        self._histograms: dict[str, list[tuple[float, int]]] = {}
        self._histogram_sums: dict[str, float] = defaultdict(float)
        self._histogram_counts: dict[str, int] = defaultdict(int)

        # Event callbacks
        self._event_callbacks: list[Callable[[SecurityEvent], None]] = []

        self._lock = threading.RLock()
        self._start_time = time.time()

        logger.debug("MetricsCollector initialized")

    def record_event(self, event: SecurityEvent) -> None:
        """Record a security event."""
        with self._lock:
            self._events.append(event)

            # Update counters
            self._counters[event.event_type.value] += 1

            # Labeled counters
            if event.user_id:
                self._counter_labels["by_user"][event.event_type.value][event.user_id] += 1
            if event.resource:
                self._counter_labels["by_resource"][event.event_type.value][event.resource] += 1

        # Notify callbacks
        for callback in self._event_callbacks:
            try:
                callback(event)
            except Exception as e:
                logger.error(f"Event callback error: {e}")

    def record_authorization(
        self,
        allowed: bool,
        user: str | None = None,
        resource: str | None = None,
        action: str | None = None,
        latency_ms: float | None = None,
    ) -> None:
        """Record an authorization decision."""
        event_type = EventType.AUTHORIZATION_ALLOWED if allowed else EventType.AUTHORIZATION_DENIED

        self.record_event(SecurityEvent(
            event_type=event_type,
            timestamp=time.time(),
            user_id=user,
            resource=resource,
            action=action,
            details={"latency_ms": latency_ms} if latency_ms else {},
            severity=0.0 if allowed else 0.5,
        ))

        if latency_ms:
            self.record_histogram("authorization_latency_ms", latency_ms)

    def record_guard_block(
        self,
        guard_type: str,
        pattern: str,
        risk_score: float = 0.0,
        user: str | None = None,
    ) -> None:
        """Record a guard block."""
        event_type = EventType.INPUT_GUARD_BLOCK if guard_type == "input" else EventType.OUTPUT_GUARD_BLOCK

        self.record_event(SecurityEvent(
            event_type=event_type,
            timestamp=time.time(),
            user_id=user,
            details={"pattern": pattern, "risk_score": risk_score},
            severity=risk_score,
        ))

    def record_rate_limit_hit(
        self,
        user: str | None = None,
        limit_type: str = "requests",
    ) -> None:
        """Record a rate limit hit."""
        self.record_event(SecurityEvent(
            event_type=EventType.RATE_LIMIT_HIT,
            timestamp=time.time(),
            user_id=user,
            details={"limit_type": limit_type},
            severity=0.4,
        ))

    def record_circuit_open(
        self,
        circuit_name: str,
        failure_count: int = 0,
    ) -> None:
        """Record a circuit breaker opening."""
        self.record_event(SecurityEvent(
            event_type=EventType.CIRCUIT_OPEN,
            timestamp=time.time(),
            details={"circuit_name": circuit_name, "failure_count": failure_count},
            severity=0.6,
        ))

    def record_idor_violation(
        self,
        user: str,
        resource_type: str,
        object_id: str,
    ) -> None:
        """Record an IDOR violation."""
        self.record_event(SecurityEvent(
            event_type=EventType.IDOR_VIOLATION,
            timestamp=time.time(),
            user_id=user,
            resource=resource_type,
            details={"object_id": object_id},
            severity=0.8,
        ))

    def record_sequence_violation(
        self,
        user: str,
        rule_name: str,
        tool_name: str,
    ) -> None:
        """Record a sequence violation."""
        self.record_event(SecurityEvent(
            event_type=EventType.SEQUENCE_VIOLATION,
            timestamp=time.time(),
            user_id=user,
            details={"rule_name": rule_name, "tool_name": tool_name},
            severity=0.7,
        ))

    def record_intent_hijack(
        self,
        user: str | None,
        agent: str | None,
        original_intent: str,
        detected_intent: str,
        confidence: float,
    ) -> None:
        """Record an intent hijack detection."""
        self.record_event(SecurityEvent(
            event_type=EventType.INTENT_HIJACK,
            timestamp=time.time(),
            user_id=user,
            agent_id=agent,
            details={
                "original_intent": original_intent,
                "detected_intent": detected_intent,
                "confidence": confidence,
            },
            severity=confidence,
        ))

    def record_behavioral_drift(
        self,
        agent: str,
        severity: float,
        drifting_metrics: list[str],
    ) -> None:
        """Record behavioral drift detection."""
        self.record_event(SecurityEvent(
            event_type=EventType.BEHAVIORAL_DRIFT,
            timestamp=time.time(),
            agent_id=agent,
            details={"drifting_metrics": drifting_metrics},
            severity=severity,
        ))

    def record_kill_switch(
        self,
        reason: str,
        triggered_by: str,
    ) -> None:
        """Record kill switch activation."""
        self.record_event(SecurityEvent(
            event_type=EventType.KILL_SWITCH_ACTIVATED,
            timestamp=time.time(),
            details={"reason": reason, "triggered_by": triggered_by},
            severity=1.0,
        ))

    def record_histogram(
        self,
        name: str,
        value: float,
        buckets: list[float] | None = None,
    ) -> None:
        """Record a histogram value."""
        if buckets is None:
            buckets = [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]

        with self._lock:
            if name not in self._histograms:
                self._histograms[name] = [(b, 0) for b in buckets]

            # Increment bucket counts
            new_buckets = []
            for bucket_le, count in self._histograms[name]:
                if value <= bucket_le:
                    new_buckets.append((bucket_le, count + 1))
                else:
                    new_buckets.append((bucket_le, count))
            self._histograms[name] = new_buckets

            self._histogram_sums[name] += value
            self._histogram_counts[name] += 1

    def set_gauge(self, name: str, value: float) -> None:
        """Set a gauge value."""
        with self._lock:
            self._gauges[name] = value

    def increment_counter(self, name: str, value: int = 1) -> None:
        """Increment a counter."""
        with self._lock:
            self._counters[name] += value

    def on_event(self, callback: Callable[[SecurityEvent], None]) -> None:
        """Register a callback for events."""
        self._event_callbacks.append(callback)

    def get_counter(self, name: str) -> int:
        """Get a counter value."""
        with self._lock:
            return self._counters.get(name, 0)

    def get_gauge(self, name: str) -> float | None:
        """Get a gauge value."""
        with self._lock:
            return self._gauges.get(name)

    def get_rate(self, event_type: EventType, window_seconds: float | None = None) -> float:
        """Get event rate (events per second)."""
        window = window_seconds or self._aggregation_window
        now = time.time()
        cutoff = now - window

        with self._lock:
            count = sum(
                1 for e in self._events
                if e.event_type == event_type and e.timestamp > cutoff
            )

        return count / window

    def get_recent_events(
        self,
        event_type: EventType | None = None,
        limit: int = 100,
    ) -> list[SecurityEvent]:
        """Get recent events, optionally filtered by type."""
        with self._lock:
            if event_type:
                events = [e for e in self._events if e.event_type == event_type]
            else:
                events = list(self._events)

            return events[-limit:]

    def get_summary(self) -> dict[str, Any]:
        """Get a summary of all metrics."""
        now = time.time()
        uptime = now - self._start_time

        with self._lock:
            # Calculate rates
            window = self._aggregation_window
            cutoff = now - window

            recent_events = [e for e in self._events if e.timestamp > cutoff]
            event_counts = defaultdict(int)
            for e in recent_events:
                event_counts[e.event_type.value] += 1

            # Total counts
            total_auth_allowed = self._counters.get(EventType.AUTHORIZATION_ALLOWED.value, 0)
            total_auth_denied = self._counters.get(EventType.AUTHORIZATION_DENIED.value, 0)
            total_authorizations = total_auth_allowed + total_auth_denied

            return {
                "uptime_seconds": uptime,
                "total_events": len(self._events),
                "total_authorizations": total_authorizations,
                "total_allowed": total_auth_allowed,
                "total_denied": total_auth_denied,
                "denial_rate": total_auth_denied / max(1, total_authorizations),
                "recent_events_per_minute": {
                    k: v * 60 / window for k, v in event_counts.items()
                },
                "gauges": dict(self._gauges),
                "counters": dict(self._counters),
            }


class AlertRule:
    """A rule for triggering alerts."""

    def __init__(
        self,
        name: str,
        event_type: EventType | None = None,
        threshold: float = 1.0,
        window_seconds: float = 60.0,
        severity: str = "warning",
        cooldown_seconds: float = 300.0,
    ) -> None:
        """
        Initialize the rule.

        Args:
            name: Rule name.
            event_type: Event type to monitor (None for custom metric).
            threshold: Threshold for triggering.
            window_seconds: Window for rate calculation.
            severity: Alert severity (info, warning, critical).
            cooldown_seconds: Minimum time between alerts.
        """
        self.name = name
        self.event_type = event_type
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.severity = severity
        self.cooldown_seconds = cooldown_seconds

        self._last_triggered: float = 0

    def can_trigger(self) -> bool:
        """Check if rule can trigger (respects cooldown)."""
        return time.time() - self._last_triggered > self.cooldown_seconds

    def mark_triggered(self) -> None:
        """Mark rule as triggered."""
        self._last_triggered = time.time()


@dataclass
class Alert:
    """An alert notification."""

    rule_name: str
    severity: str
    message: str
    value: float
    threshold: float
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "rule_name": self.rule_name,
            "severity": self.severity,
            "message": self.message,
            "value": self.value,
            "threshold": self.threshold,
            "timestamp": self.timestamp.isoformat(),
            "details": self.details,
        }


class AlertManager:
    """
    Manages alerting based on security metrics.

    Example:
        >>> alerts = AlertManager(webhook_url="https://hooks.slack.com/...")
        >>>
        >>> # Add rules
        >>> alerts.add_rule(
        ...     name="high_denial_rate",
        ...     event_type=EventType.AUTHORIZATION_DENIED,
        ...     threshold=10,
        ...     window_seconds=60,
        ...     severity="warning",
        ... )
        >>>
        >>> # Process events
        >>> alerts.check(collector)
    """

    def __init__(
        self,
        webhook_url: str | None = None,
        webhook_headers: dict[str, str] | None = None,
    ) -> None:
        """
        Initialize the alert manager.

        Args:
            webhook_url: URL to send alerts to.
            webhook_headers: HTTP headers for webhook requests.
        """
        self._webhook_url = webhook_url
        self._webhook_headers = webhook_headers or {"Content-Type": "application/json"}

        self._rules: dict[str, AlertRule] = {}
        self._alert_history: deque[Alert] = deque(maxlen=1000)
        self._alert_callbacks: list[Callable[[Alert], None]] = []

        self._lock = threading.RLock()

    def add_rule(
        self,
        name: str,
        event_type: EventType | None = None,
        threshold: float = 1.0,
        window_seconds: float = 60.0,
        severity: str = "warning",
        cooldown_seconds: float = 300.0,
    ) -> AlertRule:
        """Add an alert rule."""
        rule = AlertRule(
            name=name,
            event_type=event_type,
            threshold=threshold,
            window_seconds=window_seconds,
            severity=severity,
            cooldown_seconds=cooldown_seconds,
        )

        with self._lock:
            self._rules[name] = rule

        return rule

    def remove_rule(self, name: str) -> bool:
        """Remove an alert rule."""
        with self._lock:
            if name in self._rules:
                del self._rules[name]
                return True
            return False

    def check(self, collector: MetricsCollector) -> list[Alert]:
        """
        Check all rules against current metrics.

        Args:
            collector: MetricsCollector to check.

        Returns:
            List of triggered alerts.
        """
        triggered: list[Alert] = []

        with self._lock:
            for rule in self._rules.values():
                if not rule.can_trigger():
                    continue

                if rule.event_type:
                    # Rate-based rule
                    rate = collector.get_rate(rule.event_type, rule.window_seconds)
                    rate_per_minute = rate * 60

                    if rate_per_minute >= rule.threshold:
                        alert = Alert(
                            rule_name=rule.name,
                            severity=rule.severity,
                            message=f"{rule.event_type.value} rate ({rate_per_minute:.1f}/min) exceeds threshold ({rule.threshold}/min)",
                            value=rate_per_minute,
                            threshold=rule.threshold,
                            details={
                                "event_type": rule.event_type.value,
                                "window_seconds": rule.window_seconds,
                            },
                        )
                        triggered.append(alert)
                        rule.mark_triggered()

        # Process triggered alerts
        for alert in triggered:
            self._process_alert(alert)

        return triggered

    def _process_alert(self, alert: Alert) -> None:
        """Process a triggered alert."""
        with self._lock:
            self._alert_history.append(alert)

        logger.warning(f"ALERT [{alert.severity.upper()}] {alert.rule_name}: {alert.message}")

        # Send webhook
        if self._webhook_url:
            self._send_webhook(alert)

        # Notify callbacks
        for callback in self._alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Alert callback error: {e}")

    def _send_webhook(self, alert: Alert) -> bool:
        """Send alert to webhook."""
        try:
            payload = json.dumps(alert.to_dict()).encode()
            request = Request(
                self._webhook_url,
                data=payload,
                headers=self._webhook_headers,
                method="POST",
            )

            with urlopen(request, timeout=10) as response:
                return response.status == 200

        except URLError as e:
            logger.error(f"Webhook error: {e}")
            return False
        except Exception as e:
            logger.error(f"Webhook error: {e}")
            return False

    def on_alert(self, callback: Callable[[Alert], None]) -> None:
        """Register a callback for alerts."""
        self._alert_callbacks.append(callback)

    def get_recent_alerts(self, limit: int = 50) -> list[Alert]:
        """Get recent alerts."""
        with self._lock:
            return list(self._alert_history)[-limit:]


class PrometheusExporter:
    """
    Exports metrics in Prometheus format.

    Example:
        >>> exporter = PrometheusExporter(collector)
        >>> metrics_text = exporter.export()
        >>>
        >>> # Serve via HTTP (e.g., with Flask)
        >>> @app.route('/metrics')
        >>> def metrics():
        ...     return exporter.export(), 200, {'Content-Type': 'text/plain'}
    """

    def __init__(
        self,
        collector: MetricsCollector,
        namespace: str = "proxilion",
    ) -> None:
        """
        Initialize the exporter.

        Args:
            collector: MetricsCollector to export.
            namespace: Metric namespace prefix.
        """
        self._collector = collector
        self._namespace = namespace

    def export(self) -> str:
        """Export all metrics in Prometheus format."""
        lines: list[str] = []

        # Add header
        lines.append(f"# Proxilion Security Metrics")
        lines.append(f"# Generated at {datetime.now(timezone.utc).isoformat()}")
        lines.append("")

        # Export counters
        for event_type in EventType:
            name = f"{self._namespace}_events_total"
            count = self._collector.get_counter(event_type.value)
            labels = f'{{event_type="{event_type.value}"}}'

            lines.append(f"# HELP {name} Total security events by type")
            lines.append(f"# TYPE {name} counter")
            lines.append(f"{name}{labels} {count}")
            lines.append("")

        # Export gauges
        summary = self._collector.get_summary()
        gauges = summary.get("gauges", {})
        for gauge_name, value in gauges.items():
            name = f"{self._namespace}_{gauge_name}"
            lines.append(f"# HELP {name} {gauge_name}")
            lines.append(f"# TYPE {name} gauge")
            lines.append(f"{name} {value}")
            lines.append("")

        # Export summary stats
        lines.append(f"# HELP {self._namespace}_uptime_seconds Uptime in seconds")
        lines.append(f"# TYPE {self._namespace}_uptime_seconds gauge")
        lines.append(f"{self._namespace}_uptime_seconds {summary['uptime_seconds']:.2f}")
        lines.append("")

        lines.append(f"# HELP {self._namespace}_denial_rate Authorization denial rate")
        lines.append(f"# TYPE {self._namespace}_denial_rate gauge")
        lines.append(f"{self._namespace}_denial_rate {summary['denial_rate']:.4f}")
        lines.append("")

        # Export histograms
        for hist_name, buckets in self._collector._histograms.items():
            name = f"{self._namespace}_{hist_name}"
            lines.append(f"# HELP {name} {hist_name}")
            lines.append(f"# TYPE {name} histogram")

            for bucket_le, count in buckets:
                lines.append(f'{name}_bucket{{le="{bucket_le}"}} {count}')

            lines.append(f'{name}_bucket{{le="+Inf"}} {self._collector._histogram_counts.get(hist_name, 0)}')
            lines.append(f"{name}_sum {self._collector._histogram_sums.get(hist_name, 0):.6f}")
            lines.append(f"{name}_count {self._collector._histogram_counts.get(hist_name, 0)}")
            lines.append("")

        return "\n".join(lines)


# Convenience exports
__all__ = [
    # Core classes
    "MetricsCollector",
    "AlertManager",
    "AlertRule",
    "PrometheusExporter",
    # Data classes
    "SecurityEvent",
    "Alert",
    "MetricSample",
    # Enums
    "EventType",
    "MetricType",
]
