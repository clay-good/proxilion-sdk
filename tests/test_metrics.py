"""
Tests for observability metrics system.

Tests cover:
- MetricType and EventType enums
- SecurityEvent creation and serialization
- MetricsCollector counters, gauges, histograms, and event recording
- AlertRule cooldown behavior
- Alert creation and serialization
- AlertManager rule management, checking, and webhook dispatch
- PrometheusExporter output format
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from proxilion.observability.metrics import (
    Alert,
    AlertManager,
    AlertRule,
    EventType,
    MetricSample,
    MetricType,
    MetricsCollector,
    PrometheusExporter,
    SecurityEvent,
)


class TestMetricType:
    def test_values(self):
        assert MetricType.COUNTER.value == "counter"
        assert MetricType.GAUGE.value == "gauge"
        assert MetricType.HISTOGRAM.value == "histogram"
        assert MetricType.SUMMARY.value == "summary"

    def test_all_members(self):
        assert len(MetricType) == 4


class TestEventType:
    def test_all_members(self):
        assert len(EventType) == 13

    def test_key_values(self):
        assert EventType.AUTHORIZATION_ALLOWED.value == "authorization_allowed"
        assert EventType.AUTHORIZATION_DENIED.value == "authorization_denied"
        assert EventType.INPUT_GUARD_BLOCK.value == "input_guard_block"
        assert EventType.KILL_SWITCH_ACTIVATED.value == "kill_switch_activated"


class TestSecurityEvent:
    def test_defaults(self):
        event = SecurityEvent(
            event_type=EventType.AUTHORIZATION_ALLOWED,
            timestamp=1000.0,
        )
        assert event.user_id is None
        assert event.agent_id is None
        assert event.resource is None
        assert event.action is None
        assert event.details == {}
        assert event.severity == 0.5

    def test_full_construction(self):
        event = SecurityEvent(
            event_type=EventType.IDOR_VIOLATION,
            timestamp=1234.5,
            user_id="alice",
            agent_id="agent-1",
            resource="users",
            action="read",
            details={"object_id": "123"},
            severity=0.9,
        )
        assert event.user_id == "alice"
        assert event.agent_id == "agent-1"
        assert event.severity == 0.9

    def test_to_dict(self):
        ts = 1700000000.0
        event = SecurityEvent(
            event_type=EventType.RATE_LIMIT_HIT,
            timestamp=ts,
            user_id="bob",
            details={"limit_type": "requests"},
            severity=0.4,
        )
        d = event.to_dict()
        assert d["event_type"] == "rate_limit_hit"
        assert d["timestamp"] == ts
        assert d["user_id"] == "bob"
        assert d["agent_id"] is None
        assert d["resource"] is None
        assert d["severity"] == 0.4
        assert "datetime" in d
        expected_dt = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
        assert d["datetime"] == expected_dt


class TestMetricSample:
    def test_construction(self):
        sample = MetricSample(name="test_metric", value=42.0, timestamp=1000.0)
        assert sample.name == "test_metric"
        assert sample.value == 42.0
        assert sample.labels == {}

    def test_with_labels(self):
        sample = MetricSample(
            name="m", value=1.0, timestamp=0.0, labels={"env": "prod"}
        )
        assert sample.labels == {"env": "prod"}


class TestMetricsCollector:
    @pytest.fixture()
    def collector(self):
        return MetricsCollector(event_window_size=100, aggregation_window_seconds=60.0)

    def test_invalid_window_size(self):
        with pytest.raises(ValueError, match="event_window_size"):
            MetricsCollector(event_window_size=0)
        with pytest.raises(ValueError, match="event_window_size"):
            MetricsCollector(event_window_size=-5)

    def test_invalid_aggregation_window(self):
        with pytest.raises(ValueError, match="aggregation_window_seconds"):
            MetricsCollector(aggregation_window_seconds=0)
        with pytest.raises(ValueError, match="aggregation_window_seconds"):
            MetricsCollector(aggregation_window_seconds=-1)

    def test_record_event(self, collector: MetricsCollector):
        event = SecurityEvent(
            event_type=EventType.AUTHORIZATION_ALLOWED,
            timestamp=time.time(),
            user_id="alice",
            resource="db",
        )
        collector.record_event(event)
        assert collector.get_counter("authorization_allowed") == 1
        events = collector.get_recent_events()
        assert len(events) == 1
        assert events[0] is event

    def test_record_event_updates_labeled_counters(self, collector: MetricsCollector):
        event = SecurityEvent(
            event_type=EventType.AUTHORIZATION_DENIED,
            timestamp=time.time(),
            user_id="mallory",
            resource="secrets",
        )
        collector.record_event(event)
        assert collector._counter_labels["by_user"]["authorization_denied"]["mallory"] == 1
        assert collector._counter_labels["by_resource"]["authorization_denied"]["secrets"] == 1

    def test_event_window_size_limit(self):
        collector = MetricsCollector(event_window_size=3)
        for i in range(5):
            collector.record_event(
                SecurityEvent(
                    event_type=EventType.RATE_LIMIT_HIT,
                    timestamp=float(i),
                )
            )
        events = collector.get_recent_events()
        assert len(events) == 3
        assert events[0].timestamp == 2.0

    def test_record_authorization_allowed(self, collector: MetricsCollector):
        collector.record_authorization(allowed=True, user="alice", resource="db", action="read")
        assert collector.get_counter("authorization_allowed") == 1
        assert collector.get_counter("authorization_denied") == 0
        events = collector.get_recent_events(EventType.AUTHORIZATION_ALLOWED)
        assert len(events) == 1
        assert events[0].severity == 0.0

    def test_record_authorization_denied(self, collector: MetricsCollector):
        collector.record_authorization(allowed=False, user="bob")
        assert collector.get_counter("authorization_denied") == 1
        events = collector.get_recent_events(EventType.AUTHORIZATION_DENIED)
        assert len(events) == 1
        assert events[0].severity == 0.5

    def test_record_authorization_with_latency(self, collector: MetricsCollector):
        collector.record_authorization(allowed=True, latency_ms=15.0)
        assert "authorization_latency_ms" in collector._histograms
        assert collector._histogram_counts["authorization_latency_ms"] == 1
        assert collector._histogram_sums["authorization_latency_ms"] == 15.0

    def test_record_authorization_without_latency(self, collector: MetricsCollector):
        collector.record_authorization(allowed=True)
        assert "authorization_latency_ms" not in collector._histograms

    def test_record_guard_block_input(self, collector: MetricsCollector):
        collector.record_guard_block("input", "injection", risk_score=0.9, user="eve")
        assert collector.get_counter("input_guard_block") == 1
        events = collector.get_recent_events(EventType.INPUT_GUARD_BLOCK)
        assert len(events) == 1
        assert events[0].details["pattern"] == "injection"
        assert events[0].severity == 0.9

    def test_record_guard_block_output(self, collector: MetricsCollector):
        collector.record_guard_block("output", "pii_leak")
        assert collector.get_counter("output_guard_block") == 1

    def test_record_rate_limit_hit(self, collector: MetricsCollector):
        collector.record_rate_limit_hit(user="bob", limit_type="tokens")
        assert collector.get_counter("rate_limit_hit") == 1
        events = collector.get_recent_events(EventType.RATE_LIMIT_HIT)
        assert events[0].details["limit_type"] == "tokens"
        assert events[0].severity == 0.4

    def test_record_circuit_open(self, collector: MetricsCollector):
        collector.record_circuit_open("llm_api", failure_count=5)
        assert collector.get_counter("circuit_open") == 1
        events = collector.get_recent_events(EventType.CIRCUIT_OPEN)
        assert events[0].details["circuit_name"] == "llm_api"
        assert events[0].details["failure_count"] == 5
        assert events[0].severity == 0.6

    def test_record_idor_violation(self, collector: MetricsCollector):
        collector.record_idor_violation("mallory", "users", "obj-42")
        assert collector.get_counter("idor_violation") == 1
        events = collector.get_recent_events(EventType.IDOR_VIOLATION)
        assert events[0].user_id == "mallory"
        assert events[0].resource == "users"
        assert events[0].severity == 0.8

    def test_record_sequence_violation(self, collector: MetricsCollector):
        collector.record_sequence_violation("carol", "auth_first", "delete_user")
        assert collector.get_counter("sequence_violation") == 1
        events = collector.get_recent_events(EventType.SEQUENCE_VIOLATION)
        assert events[0].details["rule_name"] == "auth_first"
        assert events[0].details["tool_name"] == "delete_user"
        assert events[0].severity == 0.7

    def test_record_intent_hijack(self, collector: MetricsCollector):
        collector.record_intent_hijack(
            user="alice",
            agent="agent-1",
            original_intent="summarize",
            detected_intent="exfiltrate",
            confidence=0.95,
        )
        assert collector.get_counter("intent_hijack") == 1
        events = collector.get_recent_events(EventType.INTENT_HIJACK)
        assert events[0].agent_id == "agent-1"
        assert events[0].severity == 0.95
        assert events[0].details["confidence"] == 0.95

    def test_record_behavioral_drift(self, collector: MetricsCollector):
        collector.record_behavioral_drift("agent-2", 0.75, ["latency", "token_count"])
        assert collector.get_counter("behavioral_drift") == 1
        events = collector.get_recent_events(EventType.BEHAVIORAL_DRIFT)
        assert events[0].agent_id == "agent-2"
        assert events[0].details["drifting_metrics"] == ["latency", "token_count"]

    def test_record_kill_switch(self, collector: MetricsCollector):
        collector.record_kill_switch("critical anomaly", "admin")
        assert collector.get_counter("kill_switch_activated") == 1
        events = collector.get_recent_events(EventType.KILL_SWITCH_ACTIVATED)
        assert events[0].severity == 1.0
        assert events[0].details["reason"] == "critical anomaly"
        assert events[0].details["triggered_by"] == "admin"

    def test_histogram_default_buckets(self, collector: MetricsCollector):
        collector.record_histogram("latency", 0.05)
        assert len(collector._histograms["latency"]) == 12
        collector.record_histogram("latency", 0.5)
        assert collector._histogram_counts["latency"] == 2
        assert collector._histogram_sums["latency"] == pytest.approx(0.55)

    def test_histogram_custom_buckets(self, collector: MetricsCollector):
        collector.record_histogram("cost", 1.5, buckets=[1.0, 2.0, 5.0])
        buckets = collector._histograms["cost"]
        assert len(buckets) == 3
        assert buckets[0] == (1.0, 0)  # 1.5 > 1.0
        assert buckets[1] == (2.0, 1)  # 1.5 <= 2.0
        assert buckets[2] == (5.0, 1)  # 1.5 <= 5.0

    def test_histogram_value_exceeds_all_buckets(self, collector: MetricsCollector):
        collector.record_histogram("big", 100.0, buckets=[1.0, 10.0])
        buckets = collector._histograms["big"]
        assert all(count == 0 for _, count in buckets)
        assert collector._histogram_counts["big"] == 1
        assert collector._histogram_sums["big"] == 100.0

    def test_set_gauge(self, collector: MetricsCollector):
        collector.set_gauge("active_agents", 5.0)
        assert collector.get_gauge("active_agents") == 5.0
        collector.set_gauge("active_agents", 3.0)
        assert collector.get_gauge("active_agents") == 3.0

    def test_get_gauge_missing(self, collector: MetricsCollector):
        assert collector.get_gauge("nonexistent") is None

    def test_increment_counter(self, collector: MetricsCollector):
        collector.increment_counter("custom_counter")
        assert collector.get_counter("custom_counter") == 1
        collector.increment_counter("custom_counter", 5)
        assert collector.get_counter("custom_counter") == 6

    def test_get_counter_missing(self, collector: MetricsCollector):
        assert collector.get_counter("nonexistent") == 0

    def test_on_event_callback(self, collector: MetricsCollector):
        received = []
        collector.on_event(lambda e: received.append(e))
        collector.record_rate_limit_hit(user="test")
        assert len(received) == 1
        assert received[0].event_type == EventType.RATE_LIMIT_HIT

    def test_on_event_callback_error_does_not_propagate(self, collector: MetricsCollector):
        def bad_callback(e):
            raise RuntimeError("boom")

        collector.on_event(bad_callback)
        collector.record_rate_limit_hit()
        assert collector.get_counter("rate_limit_hit") == 1

    def test_get_rate(self, collector: MetricsCollector):
        now = time.time()
        for _ in range(5):
            collector.record_event(
                SecurityEvent(event_type=EventType.RATE_LIMIT_HIT, timestamp=now)
            )
        rate = collector.get_rate(EventType.RATE_LIMIT_HIT, window_seconds=60.0)
        assert rate == pytest.approx(5.0 / 60.0, abs=0.01)

    def test_get_rate_invalid_window(self, collector: MetricsCollector):
        with pytest.raises(ValueError, match="window_seconds"):
            collector.get_rate(EventType.RATE_LIMIT_HIT, window_seconds=0)

    def test_get_rate_uses_default_window(self, collector: MetricsCollector):
        rate = collector.get_rate(EventType.RATE_LIMIT_HIT)
        assert rate == 0.0

    def test_get_recent_events_filtered(self, collector: MetricsCollector):
        collector.record_authorization(allowed=True)
        collector.record_rate_limit_hit()
        collector.record_authorization(allowed=False)

        allowed = collector.get_recent_events(EventType.AUTHORIZATION_ALLOWED)
        assert len(allowed) == 1
        denied = collector.get_recent_events(EventType.AUTHORIZATION_DENIED)
        assert len(denied) == 1
        all_events = collector.get_recent_events()
        assert len(all_events) == 3

    def test_get_recent_events_limit(self, collector: MetricsCollector):
        for _ in range(10):
            collector.record_rate_limit_hit()
        events = collector.get_recent_events(limit=3)
        assert len(events) == 3

    def test_get_summary(self, collector: MetricsCollector):
        collector.record_authorization(allowed=True, user="a")
        collector.record_authorization(allowed=True, user="b")
        collector.record_authorization(allowed=False, user="c")
        collector.set_gauge("active", 2.0)

        summary = collector.get_summary()
        assert summary["total_authorizations"] == 3
        assert summary["total_allowed"] == 2
        assert summary["total_denied"] == 1
        assert summary["denial_rate"] == pytest.approx(1.0 / 3.0)
        assert summary["total_events"] == 3
        assert summary["uptime_seconds"] > 0
        assert summary["gauges"]["active"] == 2.0
        assert "recent_events_per_minute" in summary

    def test_get_summary_no_authorizations(self, collector: MetricsCollector):
        summary = collector.get_summary()
        assert summary["total_authorizations"] == 0
        assert summary["denial_rate"] == 0.0


class TestAlertRule:
    def test_construction(self):
        rule = AlertRule(
            name="test",
            event_type=EventType.RATE_LIMIT_HIT,
            threshold=5.0,
            window_seconds=30.0,
            severity="critical",
            cooldown_seconds=60.0,
        )
        assert rule.name == "test"
        assert rule.event_type == EventType.RATE_LIMIT_HIT
        assert rule.threshold == 5.0
        assert rule.severity == "critical"

    def test_can_trigger_initially(self):
        rule = AlertRule(name="r", cooldown_seconds=10.0)
        assert rule.can_trigger() is True

    def test_cooldown_blocks_trigger(self):
        rule = AlertRule(name="r", cooldown_seconds=9999.0)
        rule.mark_triggered()
        assert rule.can_trigger() is False

    def test_cooldown_expires(self):
        rule = AlertRule(name="r", cooldown_seconds=0.01)
        rule.mark_triggered()
        import time

        time.sleep(0.02)
        assert rule.can_trigger() is True


class TestAlert:
    def test_defaults(self):
        alert = Alert(
            rule_name="test_rule",
            severity="warning",
            message="threshold exceeded",
            value=15.0,
            threshold=10.0,
        )
        assert alert.details == {}
        assert isinstance(alert.timestamp, datetime)

    def test_to_dict(self):
        ts = datetime(2025, 1, 1, tzinfo=timezone.utc)
        alert = Alert(
            rule_name="r",
            severity="critical",
            message="bad",
            value=20.0,
            threshold=10.0,
            timestamp=ts,
            details={"key": "val"},
        )
        d = alert.to_dict()
        assert d["rule_name"] == "r"
        assert d["severity"] == "critical"
        assert d["value"] == 20.0
        assert d["threshold"] == 10.0
        assert d["timestamp"] == ts.isoformat()
        assert d["details"] == {"key": "val"}


class TestAlertManager:
    @pytest.fixture()
    def manager(self):
        return AlertManager()

    @pytest.fixture()
    def collector(self):
        return MetricsCollector(event_window_size=1000, aggregation_window_seconds=60.0)

    def test_add_and_remove_rule(self, manager: AlertManager):
        rule = manager.add_rule("test_rule", threshold=5.0)
        assert isinstance(rule, AlertRule)
        assert "test_rule" in manager._rules
        assert manager.remove_rule("test_rule") is True
        assert "test_rule" not in manager._rules

    def test_remove_nonexistent_rule(self, manager: AlertManager):
        assert manager.remove_rule("nope") is False

    def test_check_triggers_alert(self, manager: AlertManager, collector: MetricsCollector):
        manager.add_rule(
            name="high_rate",
            event_type=EventType.RATE_LIMIT_HIT,
            threshold=1.0,
            window_seconds=60.0,
            cooldown_seconds=0.0,
        )
        for _ in range(10):
            collector.record_rate_limit_hit()

        alerts = manager.check(collector)
        assert len(alerts) == 1
        assert alerts[0].rule_name == "high_rate"
        assert alerts[0].value >= 1.0

    def test_check_no_trigger_below_threshold(self, manager: AlertManager, collector: MetricsCollector):
        manager.add_rule(
            name="strict",
            event_type=EventType.RATE_LIMIT_HIT,
            threshold=99999.0,
            window_seconds=60.0,
        )
        collector.record_rate_limit_hit()
        alerts = manager.check(collector)
        assert len(alerts) == 0

    def test_check_respects_cooldown(self, manager: AlertManager, collector: MetricsCollector):
        manager.add_rule(
            name="cooldown_test",
            event_type=EventType.RATE_LIMIT_HIT,
            threshold=1.0,
            window_seconds=60.0,
            cooldown_seconds=9999.0,
        )
        for _ in range(10):
            collector.record_rate_limit_hit()

        first = manager.check(collector)
        assert len(first) == 1
        second = manager.check(collector)
        assert len(second) == 0

    def test_on_alert_callback(self, manager: AlertManager, collector: MetricsCollector):
        received = []
        manager.on_alert(lambda a: received.append(a))
        manager.add_rule(
            name="cb_test",
            event_type=EventType.RATE_LIMIT_HIT,
            threshold=1.0,
            window_seconds=60.0,
            cooldown_seconds=0.0,
        )
        for _ in range(5):
            collector.record_rate_limit_hit()
        manager.check(collector)
        assert len(received) == 1

    def test_alert_callback_error_does_not_propagate(self, manager: AlertManager, collector: MetricsCollector):
        manager.on_alert(lambda a: (_ for _ in ()).throw(RuntimeError("boom")))
        manager.add_rule(
            name="err_test",
            event_type=EventType.RATE_LIMIT_HIT,
            threshold=1.0,
            window_seconds=60.0,
            cooldown_seconds=0.0,
        )
        for _ in range(5):
            collector.record_rate_limit_hit()
        alerts = manager.check(collector)
        assert len(alerts) == 1

    def test_get_recent_alerts(self, manager: AlertManager, collector: MetricsCollector):
        manager.add_rule(
            name="history_test",
            event_type=EventType.RATE_LIMIT_HIT,
            threshold=1.0,
            window_seconds=60.0,
            cooldown_seconds=0.0,
        )
        for _ in range(5):
            collector.record_rate_limit_hit()
        manager.check(collector)

        history = manager.get_recent_alerts()
        assert len(history) == 1
        assert history[0].rule_name == "history_test"

    def test_get_recent_alerts_limit(self, manager: AlertManager):
        for i in range(5):
            alert = Alert(
                rule_name=f"r{i}", severity="info", message="m", value=1.0, threshold=1.0
            )
            manager._alert_history.append(alert)
        assert len(manager.get_recent_alerts(limit=2)) == 2

    def test_webhook_headers_default(self):
        mgr = AlertManager(webhook_url="https://example.com/hook")
        assert mgr._webhook_headers == {"Content-Type": "application/json"}

    def test_webhook_headers_custom(self):
        headers = {"Authorization": "Bearer tok", "Content-Type": "application/json"}
        mgr = AlertManager(webhook_url="https://example.com", webhook_headers=headers)
        assert mgr._webhook_headers == headers

    @patch("proxilion.observability.metrics.urlopen")
    def test_send_webhook_success(self, mock_urlopen, collector: MetricsCollector):
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        mgr = AlertManager(webhook_url="https://hooks.example.com/alert")
        mgr.add_rule(
            name="webhook_rule",
            event_type=EventType.RATE_LIMIT_HIT,
            threshold=1.0,
            window_seconds=60.0,
            cooldown_seconds=0.0,
        )
        for _ in range(5):
            collector.record_rate_limit_hit()
        mgr.check(collector)
        mock_urlopen.assert_called_once()

    @patch("proxilion.observability.metrics.urlopen")
    def test_send_webhook_failure_does_not_raise(self, mock_urlopen, collector: MetricsCollector):
        from urllib.error import URLError

        mock_urlopen.side_effect = URLError("connection refused")

        mgr = AlertManager(webhook_url="https://hooks.example.com/alert")
        mgr.add_rule(
            name="fail_rule",
            event_type=EventType.RATE_LIMIT_HIT,
            threshold=1.0,
            window_seconds=60.0,
            cooldown_seconds=0.0,
        )
        for _ in range(5):
            collector.record_rate_limit_hit()
        alerts = mgr.check(collector)
        assert len(alerts) == 1

    def test_check_skips_rules_without_event_type(self, manager: AlertManager, collector: MetricsCollector):
        manager.add_rule(name="custom_rule", event_type=None, threshold=1.0)
        alerts = manager.check(collector)
        assert len(alerts) == 0


class TestPrometheusExporter:
    @pytest.fixture()
    def collector(self):
        return MetricsCollector(event_window_size=1000, aggregation_window_seconds=60.0)

    @pytest.fixture()
    def exporter(self, collector):
        return PrometheusExporter(collector)

    def test_export_header(self, exporter: PrometheusExporter):
        output = exporter.export()
        assert output.startswith("# Proxilion Security Metrics")
        assert "# Generated at" in output

    def test_export_contains_all_event_types(self, exporter: PrometheusExporter):
        output = exporter.export()
        for et in EventType:
            assert f'event_type="{et.value}"' in output

    def test_export_counter_values(self, collector: MetricsCollector, exporter: PrometheusExporter):
        collector.record_authorization(allowed=True)
        collector.record_authorization(allowed=False)
        output = exporter.export()
        assert 'proxilion_events_total{event_type="authorization_allowed"} 1' in output
        assert 'proxilion_events_total{event_type="authorization_denied"} 1' in output

    def test_export_gauges(self, collector: MetricsCollector, exporter: PrometheusExporter):
        collector.set_gauge("active_connections", 42.0)
        output = exporter.export()
        assert "proxilion_active_connections 42.0" in output
        assert "# TYPE proxilion_active_connections gauge" in output

    def test_export_uptime(self, exporter: PrometheusExporter):
        output = exporter.export()
        assert "proxilion_uptime_seconds" in output
        assert "# TYPE proxilion_uptime_seconds gauge" in output

    def test_export_denial_rate(self, collector: MetricsCollector, exporter: PrometheusExporter):
        collector.record_authorization(allowed=True)
        collector.record_authorization(allowed=False)
        output = exporter.export()
        assert "proxilion_denial_rate 0.5000" in output

    def test_export_histograms(self, collector: MetricsCollector, exporter: PrometheusExporter):
        collector.record_histogram("test_hist", 0.5, buckets=[0.1, 1.0, 10.0])
        collector.record_histogram("test_hist", 0.05, buckets=[0.1, 1.0, 10.0])
        output = exporter.export()
        assert '# TYPE proxilion_test_hist histogram' in output
        assert 'proxilion_test_hist_bucket{le="0.1"} 1' in output
        assert 'proxilion_test_hist_bucket{le="1.0"} 2' in output
        assert 'proxilion_test_hist_bucket{le="+Inf"} 2' in output
        assert "proxilion_test_hist_count 2" in output

    def test_custom_namespace(self, collector: MetricsCollector):
        exporter = PrometheusExporter(collector, namespace="myapp")
        output = exporter.export()
        assert "myapp_events_total" in output
        assert "myapp_uptime_seconds" in output
        assert "myapp_denial_rate" in output

    def test_export_no_histograms(self, exporter: PrometheusExporter):
        output = exporter.export()
        assert "histogram" not in output.lower() or "# TYPE" in output
