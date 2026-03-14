from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from proxilion.observability.cost_tracker import BudgetPolicy, CostTracker
from proxilion.observability.session_cost_tracker import (
    AgentCostProfile,
    AlertCallback,
    AlertSeverity,
    AlertType,
    CostAlert,
    Session,
    SessionCostTracker,
    SessionState,
    SessionSummary,
    create_session_cost_tracker,
)


@pytest.fixture
def tracker() -> SessionCostTracker:
    return SessionCostTracker()


@pytest.fixture
def tracker_with_budget() -> SessionCostTracker:
    return SessionCostTracker(
        budget_policy=BudgetPolicy(max_cost_per_user_per_day=100.0),
        budget_warning_threshold=0.8,
        rate_warning_threshold=1.0,
    )


@pytest.fixture
def session(tracker: SessionCostTracker) -> Session:
    return tracker.start_session(user_id="user_1", agent_id="agent_1", budget_limit=10.0)


MODEL = "claude-sonnet-4-20250514"


class TestSessionState:
    def test_enum_values(self):
        assert SessionState.ACTIVE == "active"
        assert SessionState.PAUSED == "paused"
        assert SessionState.BUDGET_EXCEEDED == "budget_exceeded"
        assert SessionState.TERMINATED == "terminated"
        assert SessionState.EXPIRED == "expired"

    def test_string_enum(self):
        assert isinstance(SessionState.ACTIVE, str)


class TestAlertSeverity:
    def test_enum_values(self):
        assert AlertSeverity.INFO == "info"
        assert AlertSeverity.WARNING == "warning"
        assert AlertSeverity.CRITICAL == "critical"


class TestAlertType:
    def test_all_types_exist(self):
        assert AlertType.BUDGET_WARNING == "budget_warning"
        assert AlertType.BUDGET_EXCEEDED == "budget_exceeded"
        assert AlertType.RATE_WARNING == "rate_warning"
        assert AlertType.ANOMALY == "anomaly"
        assert AlertType.SESSION_EXPIRED == "session_expired"
        assert AlertType.FORECAST_WARNING == "forecast_warning"


class TestCostAlert:
    def test_creation_defaults(self):
        alert = CostAlert(
            alert_id="a1",
            alert_type=AlertType.BUDGET_WARNING,
            severity=AlertSeverity.WARNING,
            message="test",
            current_cost=5.0,
        )
        assert alert.threshold is None
        assert alert.session_id is None
        assert alert.user_id is None
        assert alert.agent_id is None
        assert isinstance(alert.timestamp, datetime)
        assert alert.metadata == {}

    def test_to_dict(self):
        alert = CostAlert(
            alert_id="a1",
            alert_type=AlertType.BUDGET_EXCEEDED,
            severity=AlertSeverity.CRITICAL,
            message="over budget",
            current_cost=12.0,
            threshold=10.0,
            session_id="s1",
            user_id="u1",
            agent_id="ag1",
            metadata={"extra": True},
        )
        d = alert.to_dict()
        assert d["alert_type"] == "budget_exceeded"
        assert d["severity"] == "critical"
        assert d["current_cost"] == 12.0
        assert d["threshold"] == 10.0
        assert d["session_id"] == "s1"
        assert d["metadata"] == {"extra": True}
        assert isinstance(d["timestamp"], str)


class TestAgentCostProfile:
    def test_defaults(self):
        profile = AgentCostProfile(agent_id="a1")
        assert profile.total_cost == 0.0
        assert profile.input_tokens == 0
        assert profile.output_tokens == 0
        assert profile.tool_calls == 0
        assert profile.by_tool == {}
        assert profile.by_model == {}
        assert profile.first_activity is None
        assert profile.last_activity is None

    def test_to_dict_with_none_timestamps(self):
        profile = AgentCostProfile(agent_id="a1")
        d = profile.to_dict()
        assert d["first_activity"] is None
        assert d["last_activity"] is None
        assert d["agent_id"] == "a1"

    def test_to_dict_with_timestamps(self):
        ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
        profile = AgentCostProfile(agent_id="a1", first_activity=ts, last_activity=ts)
        d = profile.to_dict()
        assert d["first_activity"] == ts.isoformat()
        assert d["last_activity"] == ts.isoformat()


class TestSession:
    def test_is_active(self):
        s = Session(session_id="s1", user_id="u1")
        assert s.is_active is True
        s.state = SessionState.PAUSED
        assert s.is_active is False

    def test_budget_remaining_no_limit(self):
        s = Session(session_id="s1", user_id="u1")
        assert s.budget_remaining is None

    def test_budget_remaining_with_limit(self):
        s = Session(session_id="s1", user_id="u1", budget_limit=10.0, total_cost=3.0)
        assert s.budget_remaining == 7.0

    def test_budget_remaining_exceeded(self):
        s = Session(session_id="s1", user_id="u1", budget_limit=5.0, total_cost=7.0)
        assert s.budget_remaining == 0.0

    def test_budget_percentage_no_limit(self):
        s = Session(session_id="s1", user_id="u1")
        assert s.budget_percentage is None

    def test_budget_percentage_zero_limit(self):
        s = Session(session_id="s1", user_id="u1", budget_limit=0.0)
        assert s.budget_percentage is None

    def test_budget_percentage_normal(self):
        s = Session(session_id="s1", user_id="u1", budget_limit=10.0, total_cost=5.0)
        assert s.budget_percentage == pytest.approx(0.5)

    def test_budget_percentage_capped_at_one(self):
        s = Session(session_id="s1", user_id="u1", budget_limit=10.0, total_cost=15.0)
        assert s.budget_percentage == 1.0

    def test_duration_seconds_active(self):
        start = datetime.now(timezone.utc) - timedelta(seconds=30)
        s = Session(session_id="s1", user_id="u1", start_time=start)
        assert s.duration_seconds >= 29

    def test_duration_seconds_ended(self):
        start = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        end = datetime(2026, 1, 1, 0, 1, 0, tzinfo=timezone.utc)
        s = Session(session_id="s1", user_id="u1", start_time=start, end_time=end)
        assert s.duration_seconds == pytest.approx(60.0)

    def test_is_expired_no_activity(self):
        s = Session(session_id="s1", user_id="u1")
        assert s.is_expired is False

    def test_is_expired_recent_activity(self):
        s = Session(
            session_id="s1",
            user_id="u1",
            last_activity=datetime.now(timezone.utc),
            timeout_minutes=60,
        )
        assert s.is_expired is False

    def test_is_expired_old_activity(self):
        s = Session(
            session_id="s1",
            user_id="u1",
            last_activity=datetime.now(timezone.utc) - timedelta(minutes=120),
            timeout_minutes=60,
        )
        assert s.is_expired is True

    def test_to_dict(self):
        s = Session(session_id="s1", user_id="u1", budget_limit=10.0, total_cost=3.0)
        d = s.to_dict()
        assert d["session_id"] == "s1"
        assert d["user_id"] == "u1"
        assert d["state"] == "active"
        assert d["budget_limit"] == 10.0
        assert d["budget_remaining"] == 7.0
        assert d["budget_percentage"] == pytest.approx(0.3)
        assert "duration_seconds" in d
        assert isinstance(d["agents"], dict)
        assert isinstance(d["alerts"], list)

    def test_to_json(self):
        s = Session(session_id="s1", user_id="u1")
        result = json.loads(s.to_json())
        assert result["session_id"] == "s1"


class TestSessionSummary:
    def test_to_dict(self):
        summary = SessionSummary(
            session_id="s1",
            user_id="u1",
            total_cost=5.0,
            total_tokens=1500,
            duration_seconds=120.0,
            tool_breakdown={"search": 3.0},
            model_breakdown={MODEL: 5.0},
            agent_breakdown={"agent_1": 5.0},
            peak_spend_rate=2.5,
            alerts_triggered=1,
            end_reason="user_ended",
        )
        d = summary.to_dict()
        assert d["session_id"] == "s1"
        assert d["total_cost"] == 5.0
        assert d["total_tokens"] == 1500
        assert d["end_reason"] == "user_ended"


class TestSessionCostTrackerInit:
    def test_default_init(self):
        t = SessionCostTracker()
        assert t.base_tracker is not None
        stats = t.get_stats()
        assert stats["total_sessions"] == 0
        assert stats["active_sessions"] == 0

    def test_custom_base_tracker(self):
        base = CostTracker()
        t = SessionCostTracker(base_tracker=base)
        assert t.base_tracker is base

    def test_custom_params(self):
        t = SessionCostTracker(
            default_session_timeout=30,
            budget_warning_threshold=0.5,
            rate_warning_threshold=2.0,
            max_sessions=100,
            enable_forecasting=False,
        )
        assert t._default_timeout == 30
        assert t._budget_warning_threshold == 0.5


class TestStartSession:
    def test_basic_start(self, tracker: SessionCostTracker):
        session = tracker.start_session(user_id="u1")
        assert session.session_id.startswith("sess_")
        assert session.user_id == "u1"
        assert session.is_active
        assert session.agent_id is None
        assert session.budget_limit is None

    def test_with_agent(self, tracker: SessionCostTracker):
        session = tracker.start_session(user_id="u1", agent_id="agent_1")
        assert session.agent_id == "agent_1"
        assert "agent_1" in session.agents

    def test_with_budget(self, tracker: SessionCostTracker):
        session = tracker.start_session(user_id="u1", budget_limit=25.0)
        assert session.budget_limit == 25.0
        assert session.budget_remaining == 25.0

    def test_with_metadata(self, tracker: SessionCostTracker):
        session = tracker.start_session(user_id="u1", metadata={"env": "test"})
        assert session.metadata == {"env": "test"}

    def test_custom_timeout(self, tracker: SessionCostTracker):
        session = tracker.start_session(user_id="u1", timeout_minutes=120)
        assert session.timeout_minutes == 120

    def test_stats_updated(self, tracker: SessionCostTracker):
        tracker.start_session(user_id="u1")
        tracker.start_session(user_id="u2")
        stats = tracker.get_stats()
        assert stats["sessions_created"] == 2
        assert stats["total_sessions"] == 2
        assert stats["active_sessions"] == 2
        assert stats["users_tracked"] == 2


class TestGetSession:
    def test_found(self, tracker: SessionCostTracker, session: Session):
        result = tracker.get_session(session.session_id)
        assert result is session

    def test_not_found(self, tracker: SessionCostTracker):
        assert tracker.get_session("nonexistent") is None

    def test_auto_expires(self, tracker: SessionCostTracker):
        s = tracker.start_session(user_id="u1", timeout_minutes=1)
        s.last_activity = datetime.now(timezone.utc) - timedelta(minutes=5)
        result = tracker.get_session(s.session_id)
        assert result is not None
        assert result.state == SessionState.EXPIRED


class TestGetUserSessions:
    def test_active_only(self, tracker: SessionCostTracker):
        s1 = tracker.start_session(user_id="u1")
        s2 = tracker.start_session(user_id="u1")
        tracker.pause_session(s2.session_id)
        active = tracker.get_user_sessions("u1", active_only=True)
        assert len(active) == 1
        assert active[0].session_id == s1.session_id

    def test_all_sessions(self, tracker: SessionCostTracker):
        tracker.start_session(user_id="u1")
        s2 = tracker.start_session(user_id="u1")
        tracker.pause_session(s2.session_id)
        all_sessions = tracker.get_user_sessions("u1", active_only=False)
        assert len(all_sessions) == 2

    def test_unknown_user(self, tracker: SessionCostTracker):
        assert tracker.get_user_sessions("nobody") == []


class TestRecordSessionUsage:
    def test_basic_record(self, tracker: SessionCostTracker, session: Session):
        record = tracker.record_session_usage(
            session_id=session.session_id,
            model=MODEL,
            input_tokens=1000,
            output_tokens=500,
        )
        assert record is not None
        assert record.cost_usd > 0
        assert session.total_cost > 0
        assert session.input_tokens == 1000
        assert session.output_tokens == 500
        assert session.record_count == 1

    def test_unknown_session(self, tracker: SessionCostTracker):
        result = tracker.record_session_usage(
            session_id="unknown", model=MODEL, input_tokens=100, output_tokens=50
        )
        assert result is None

    def test_inactive_session(self, tracker: SessionCostTracker, session: Session):
        tracker.pause_session(session.session_id)
        result = tracker.record_session_usage(
            session_id=session.session_id, model=MODEL, input_tokens=100, output_tokens=50
        )
        assert result is None

    def test_expired_session(self, tracker: SessionCostTracker):
        s = tracker.start_session(user_id="u1", timeout_minutes=1)
        s.last_activity = datetime.now(timezone.utc) - timedelta(minutes=5)
        result = tracker.record_session_usage(
            session_id=s.session_id, model=MODEL, input_tokens=100, output_tokens=50
        )
        assert result is None
        assert s.state == SessionState.EXPIRED

    def test_tool_breakdown(self, tracker: SessionCostTracker, session: Session):
        tracker.record_session_usage(
            session_id=session.session_id,
            model=MODEL,
            input_tokens=1000,
            output_tokens=500,
            tool_name="search",
        )
        assert "search" in session.by_tool
        assert session.by_tool["search"] > 0

    def test_model_breakdown(self, tracker: SessionCostTracker, session: Session):
        tracker.record_session_usage(
            session_id=session.session_id, model=MODEL, input_tokens=1000, output_tokens=500
        )
        assert MODEL in session.by_model

    def test_agent_profile_updated(self, tracker: SessionCostTracker, session: Session):
        tracker.record_session_usage(
            session_id=session.session_id,
            model=MODEL,
            input_tokens=1000,
            output_tokens=500,
            tool_name="search",
        )
        profile = session.agents["agent_1"]
        assert profile.total_cost > 0
        assert profile.input_tokens == 1000
        assert profile.output_tokens == 500
        assert profile.tool_calls == 1
        assert "search" in profile.by_tool
        assert MODEL in profile.by_model
        assert profile.first_activity is not None
        assert profile.last_activity is not None

    def test_new_agent_created(self, tracker: SessionCostTracker, session: Session):
        tracker.record_session_usage(
            session_id=session.session_id,
            model=MODEL,
            input_tokens=100,
            output_tokens=50,
            agent_id="new_agent",
        )
        assert "new_agent" in session.agents

    def test_multiple_records_accumulate(self, tracker: SessionCostTracker, session: Session):
        tracker.record_session_usage(
            session_id=session.session_id, model=MODEL, input_tokens=1000, output_tokens=500
        )
        cost_after_first = session.total_cost
        tracker.record_session_usage(
            session_id=session.session_id, model=MODEL, input_tokens=2000, output_tokens=1000
        )
        assert session.total_cost > cost_after_first
        assert session.record_count == 2
        assert session.input_tokens == 3000
        assert session.output_tokens == 1500

    def test_session_no_agent(self, tracker: SessionCostTracker):
        s = tracker.start_session(user_id="u1")
        tracker.record_session_usage(
            session_id=s.session_id, model=MODEL, input_tokens=100, output_tokens=50
        )
        assert s.agents == {}


class TestBudgetAlerts:
    def test_budget_warning_triggered(self, tracker: SessionCostTracker):
        s = tracker.start_session(user_id="u1", budget_limit=0.01)
        tracker.record_session_usage(
            session_id=s.session_id, model=MODEL, input_tokens=2000, output_tokens=1000
        )
        warning_alerts = [a for a in s.alerts if a.alert_type == AlertType.BUDGET_WARNING]
        exceeded_alerts = [a for a in s.alerts if a.alert_type == AlertType.BUDGET_EXCEEDED]
        has_budget_alert = len(warning_alerts) > 0 or len(exceeded_alerts) > 0
        assert has_budget_alert

    def test_budget_exceeded_terminates_session(self, tracker: SessionCostTracker):
        s = tracker.start_session(user_id="u1", budget_limit=0.001)
        tracker.record_session_usage(
            session_id=s.session_id, model=MODEL, input_tokens=5000, output_tokens=5000
        )
        assert s.state == SessionState.BUDGET_EXCEEDED
        assert s.end_time is not None
        exceeded = [a for a in s.alerts if a.alert_type == AlertType.BUDGET_EXCEEDED]
        assert len(exceeded) >= 1

    def test_no_alert_without_budget(self, tracker: SessionCostTracker):
        s = tracker.start_session(user_id="u1")
        tracker.record_session_usage(
            session_id=s.session_id, model=MODEL, input_tokens=100000, output_tokens=50000
        )
        assert len(s.alerts) == 0

    def test_alert_callback_invoked(self, tracker: SessionCostTracker):
        received: list[CostAlert] = []
        tracker.add_alert_callback(lambda a: received.append(a))
        s = tracker.start_session(user_id="u1", budget_limit=0.001)
        tracker.record_session_usage(
            session_id=s.session_id, model=MODEL, input_tokens=5000, output_tokens=5000
        )
        assert len(received) > 0

    def test_callback_error_doesnt_crash(self, tracker: SessionCostTracker):
        def bad_callback(a: CostAlert) -> None:
            raise RuntimeError("callback failed")

        tracker.add_alert_callback(bad_callback)
        s = tracker.start_session(user_id="u1", budget_limit=0.001)
        tracker.record_session_usage(
            session_id=s.session_id, model=MODEL, input_tokens=5000, output_tokens=5000
        )
        assert s.state == SessionState.BUDGET_EXCEEDED


class TestAlertCallbacks:
    def test_add_and_remove_callback(self, tracker: SessionCostTracker):
        cb = MagicMock()
        tracker.add_alert_callback(cb)
        tracker.remove_alert_callback(cb)
        s = tracker.start_session(user_id="u1", budget_limit=0.001)
        tracker.record_session_usage(
            session_id=s.session_id, model=MODEL, input_tokens=5000, output_tokens=5000
        )
        cb.assert_not_called()

    def test_remove_nonexistent_callback(self, tracker: SessionCostTracker):
        tracker.remove_alert_callback(lambda a: None)


class TestPauseResumeSession:
    def test_pause(self, tracker: SessionCostTracker, session: Session):
        assert tracker.pause_session(session.session_id) is True
        assert session.state == SessionState.PAUSED

    def test_pause_nonexistent(self, tracker: SessionCostTracker):
        assert tracker.pause_session("nope") is False

    def test_pause_inactive(self, tracker: SessionCostTracker, session: Session):
        tracker.pause_session(session.session_id)
        assert tracker.pause_session(session.session_id) is False

    def test_resume(self, tracker: SessionCostTracker, session: Session):
        tracker.pause_session(session.session_id)
        assert tracker.resume_session(session.session_id) is True
        assert session.state == SessionState.ACTIVE

    def test_resume_active(self, tracker: SessionCostTracker, session: Session):
        assert tracker.resume_session(session.session_id) is False

    def test_resume_nonexistent(self, tracker: SessionCostTracker):
        assert tracker.resume_session("nope") is False


class TestEndSession:
    def test_basic_end(self, tracker: SessionCostTracker, session: Session):
        tracker.record_session_usage(
            session_id=session.session_id, model=MODEL, input_tokens=1000, output_tokens=500
        )
        summary = tracker.end_session(session.session_id)
        assert summary is not None
        assert summary.session_id == session.session_id
        assert summary.user_id == "user_1"
        assert summary.total_cost > 0
        assert summary.total_tokens == 1500
        assert summary.end_reason == "user_ended"
        assert session.state == SessionState.TERMINATED

    def test_custom_reason(self, tracker: SessionCostTracker, session: Session):
        summary = tracker.end_session(session.session_id, reason="timeout")
        assert summary is not None
        assert summary.end_reason == "timeout"

    def test_end_nonexistent(self, tracker: SessionCostTracker):
        assert tracker.end_session("nope") is None

    def test_end_with_agent_breakdown(self, tracker: SessionCostTracker, session: Session):
        tracker.record_session_usage(
            session_id=session.session_id, model=MODEL, input_tokens=1000, output_tokens=500
        )
        summary = tracker.end_session(session.session_id)
        assert summary is not None
        assert "agent_1" in summary.agent_breakdown

    def test_stats_updated_on_end(self, tracker: SessionCostTracker, session: Session):
        tracker.end_session(session.session_id)
        stats = tracker.get_stats()
        assert stats["sessions_terminated"] == 1

    def test_end_empty_session(self, tracker: SessionCostTracker, session: Session):
        summary = tracker.end_session(session.session_id)
        assert summary is not None
        assert summary.total_cost == 0.0
        assert summary.total_tokens == 0
        assert summary.peak_spend_rate == 0.0


class TestGetSessionRecords:
    def test_get_records(self, tracker: SessionCostTracker, session: Session):
        for _ in range(5):
            tracker.record_session_usage(
                session_id=session.session_id, model=MODEL, input_tokens=100, output_tokens=50
            )
        records = tracker.get_session_records(session.session_id)
        assert len(records) == 5

    def test_get_records_with_limit(self, tracker: SessionCostTracker, session: Session):
        for _ in range(5):
            tracker.record_session_usage(
                session_id=session.session_id, model=MODEL, input_tokens=100, output_tokens=50
            )
        records = tracker.get_session_records(session.session_id, limit=3)
        assert len(records) == 3

    def test_get_records_unknown_session(self, tracker: SessionCostTracker):
        assert tracker.get_session_records("nope") == []


class TestForecastSessionCost:
    def test_insufficient_data(self, tracker: SessionCostTracker, session: Session):
        result = tracker.forecast_session_cost(session.session_id)
        assert result is None

    def test_unknown_session(self, tracker: SessionCostTracker):
        assert tracker.forecast_session_cost("nope") is None

    def test_forecasting_disabled(self):
        t = SessionCostTracker(enable_forecasting=False)
        s = t.start_session(user_id="u1")
        assert t.forecast_session_cost(s.session_id) is None

    def test_forecast_with_data(self, tracker: SessionCostTracker):
        s = tracker.start_session(user_id="u1")
        s.start_time = datetime.now(timezone.utc) - timedelta(minutes=10)
        tracker.record_session_usage(
            session_id=s.session_id, model=MODEL, input_tokens=10000, output_tokens=5000
        )
        result = tracker.forecast_session_cost(s.session_id, duration_minutes=60)
        assert result is not None
        assert result > 0


class TestGetUserTotalCost:
    def test_across_sessions(self, tracker: SessionCostTracker):
        s1 = tracker.start_session(user_id="u1")
        s2 = tracker.start_session(user_id="u1")
        tracker.record_session_usage(
            session_id=s1.session_id, model=MODEL, input_tokens=1000, output_tokens=500
        )
        tracker.record_session_usage(
            session_id=s2.session_id, model=MODEL, input_tokens=1000, output_tokens=500
        )
        total = tracker.get_user_total_cost("u1")
        assert total > 0
        assert total == pytest.approx(s1.total_cost + s2.total_cost)

    def test_unknown_user(self, tracker: SessionCostTracker):
        assert tracker.get_user_total_cost("nobody") == 0.0

    def test_with_period(self, tracker: SessionCostTracker):
        s = tracker.start_session(user_id="u1")
        tracker.record_session_usage(
            session_id=s.session_id, model=MODEL, input_tokens=1000, output_tokens=500
        )
        total = tracker.get_user_total_cost("u1", period=timedelta(hours=1))
        assert total > 0


class TestGetAgentTotalCost:
    def test_agent_cost(self, tracker: SessionCostTracker, session: Session):
        tracker.record_session_usage(
            session_id=session.session_id, model=MODEL, input_tokens=1000, output_tokens=500
        )
        cost = tracker.get_agent_total_cost("agent_1")
        assert cost > 0

    def test_unknown_agent(self, tracker: SessionCostTracker):
        assert tracker.get_agent_total_cost("nope") == 0.0

    def test_agent_across_sessions(self, tracker: SessionCostTracker):
        s1 = tracker.start_session(user_id="u1", agent_id="shared_agent")
        s2 = tracker.start_session(user_id="u2", agent_id="shared_agent")
        tracker.record_session_usage(
            session_id=s1.session_id, model=MODEL, input_tokens=1000, output_tokens=500
        )
        tracker.record_session_usage(
            session_id=s2.session_id, model=MODEL, input_tokens=1000, output_tokens=500
        )
        cost = tracker.get_agent_total_cost("shared_agent")
        assert cost == pytest.approx(
            s1.agents["shared_agent"].total_cost + s2.agents["shared_agent"].total_cost
        )


class TestExportSession:
    def test_export_json(self, tracker: SessionCostTracker, session: Session):
        tracker.record_session_usage(
            session_id=session.session_id,
            model=MODEL,
            input_tokens=1000,
            output_tokens=500,
            tool_name="search",
        )
        result = tracker.export_session(session.session_id, format="json")
        assert result is not None
        parsed = json.loads(result)
        assert "session" in parsed
        assert "records" in parsed
        assert parsed["session"]["session_id"] == session.session_id
        assert len(parsed["records"]) == 1

    def test_export_csv(self, tracker: SessionCostTracker, session: Session):
        tracker.record_session_usage(
            session_id=session.session_id,
            model=MODEL,
            input_tokens=1000,
            output_tokens=500,
            tool_name="search",
            agent_id="agent_1",
        )
        result = tracker.export_session(session.session_id, format="csv")
        assert result is not None
        lines = result.strip().split("\n")
        assert len(lines) == 2
        assert lines[0].startswith("timestamp,model,")
        assert "search" in lines[1]

    def test_export_unknown_session(self, tracker: SessionCostTracker):
        assert tracker.export_session("nope") is None

    def test_export_empty_session(self, tracker: SessionCostTracker, session: Session):
        result = tracker.export_session(session.session_id, format="csv")
        assert result is not None
        lines = result.strip().split("\n")
        assert len(lines) == 1


class TestCleanupExpiredSessions:
    def test_cleanup(self, tracker: SessionCostTracker):
        s = tracker.start_session(user_id="u1", timeout_minutes=1)
        s.state = SessionState.TERMINATED
        s.end_time = datetime.now(timezone.utc) - timedelta(hours=2)
        cleaned = tracker._cleanup_expired_sessions()
        assert cleaned == 1
        assert s.session_id not in tracker._sessions

    def test_no_cleanup_recent(self, tracker: SessionCostTracker):
        s = tracker.start_session(user_id="u1")
        s.state = SessionState.TERMINATED
        s.end_time = datetime.now(timezone.utc) - timedelta(minutes=30)
        cleaned = tracker._cleanup_expired_sessions()
        assert cleaned == 0

    def test_max_sessions_triggers_cleanup(self):
        t = SessionCostTracker(max_sessions=2)
        s1 = t.start_session(user_id="u1")
        s1.state = SessionState.TERMINATED
        s1.end_time = datetime.now(timezone.utc) - timedelta(hours=2)
        t.start_session(user_id="u2")
        t.start_session(user_id="u3")
        assert s1.session_id not in t._sessions


class TestCreateSessionCostTracker:
    def test_basic_factory(self):
        t = create_session_cost_tracker()
        assert isinstance(t, SessionCostTracker)

    def test_with_policy(self):
        policy = BudgetPolicy(max_cost_per_user_per_day=50.0)
        t = create_session_cost_tracker(budget_policy=policy)
        assert t.base_tracker is not None

    def test_with_callback(self):
        cb = MagicMock()
        t = create_session_cost_tracker(alert_callback=cb)
        assert cb in t._alert_callbacks


class TestRateWarning:
    def test_rate_warning_triggered(self):
        t = SessionCostTracker(rate_warning_threshold=0.0001)
        s = t.start_session(user_id="u1", budget_limit=999.0)
        s.start_time = datetime.now(timezone.utc) - timedelta(minutes=2)
        t.record_session_usage(
            session_id=s.session_id, model=MODEL, input_tokens=10000, output_tokens=5000
        )
        rate_alerts = [a for a in s.alerts if a.alert_type == AlertType.RATE_WARNING]
        assert len(rate_alerts) >= 1
        assert rate_alerts[0].metadata.get("rate_per_minute") is not None

    def test_rate_warning_not_before_one_minute(self, tracker: SessionCostTracker):
        s = tracker.start_session(user_id="u1", budget_limit=100.0)
        tracker.record_session_usage(
            session_id=s.session_id, model=MODEL, input_tokens=100000, output_tokens=50000
        )
        rate_alerts = [a for a in s.alerts if a.alert_type == AlertType.RATE_WARNING]
        assert len(rate_alerts) == 0


class TestExpireSession:
    def test_expire_sets_state_and_alert(self, tracker: SessionCostTracker):
        s = tracker.start_session(user_id="u1", timeout_minutes=1)
        s.last_activity = datetime.now(timezone.utc) - timedelta(minutes=5)
        tracker.get_session(s.session_id)
        assert s.state == SessionState.EXPIRED
        assert s.end_time is not None
        expired_alerts = [a for a in s.alerts if a.alert_type == AlertType.SESSION_EXPIRED]
        assert len(expired_alerts) == 1


class TestGetStats:
    def test_comprehensive_stats(self, tracker: SessionCostTracker):
        s1 = tracker.start_session(user_id="u1")
        s2 = tracker.start_session(user_id="u2")
        tracker.end_session(s2.session_id)
        stats = tracker.get_stats()
        assert stats["total_sessions"] == 2
        assert stats["active_sessions"] == 1
        assert stats["sessions_created"] == 2
        assert stats["sessions_terminated"] == 1
        assert stats["users_tracked"] == 2
        assert stats["total_alerts"] == 0
