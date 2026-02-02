"""
Enhanced Session-Based Cost Tracking for Proxilion.

Extends the base CostTracker with per-user and per-agent session
tracking, real-time budget alerts, and detailed cost attribution.

Features:
    - Per-session cost tracking with automatic session management
    - Per-agent cost attribution in multi-agent systems
    - Real-time budget alerts and callbacks
    - Cost breakdown by tool, model, and time period
    - Session cost limits and automatic termination
    - Cost forecasting based on usage patterns
    - Export formats for billing integration

Example:
    >>> from proxilion.observability.session_cost_tracker import (
    ...     SessionCostTracker,
    ...     Session,
    ...     CostAlert,
    ... )
    >>>
    >>> # Create tracker with session support
    >>> tracker = SessionCostTracker()
    >>>
    >>> # Start a user session
    >>> session = tracker.start_session(
    ...     user_id="user_123",
    ...     agent_id="assistant_main",
    ...     budget_limit=10.00,
    ... )
    >>>
    >>> # Record usage
    >>> tracker.record_session_usage(
    ...     session_id=session.session_id,
    ...     model="claude-sonnet-4-20250514",
    ...     input_tokens=1000,
    ...     output_tokens=500,
    ...     tool_name="search",
    ... )
    >>>
    >>> # Check session costs
    >>> print(f"Session cost: ${session.total_cost:.4f}")
    >>> print(f"Budget remaining: ${session.budget_remaining:.4f}")
    >>>
    >>> # End session
    >>> summary = tracker.end_session(session.session_id)
    >>> print(f"Final cost: ${summary.total_cost:.4f}")
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import uuid
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable

from proxilion.observability.cost_tracker import (
    BudgetPolicy,
    CostSummary,
    CostTracker,
    ModelPricing,
    UsageRecord,
    DEFAULT_PRICING,
)

logger = logging.getLogger(__name__)


class SessionState(str, Enum):
    """Session lifecycle states."""

    ACTIVE = "active"
    PAUSED = "paused"
    BUDGET_EXCEEDED = "budget_exceeded"
    TERMINATED = "terminated"
    EXPIRED = "expired"


class AlertSeverity(str, Enum):
    """Alert severity levels."""

    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class AlertType(str, Enum):
    """Types of cost alerts."""

    BUDGET_WARNING = "budget_warning"       # Approaching budget limit
    BUDGET_EXCEEDED = "budget_exceeded"     # Budget limit hit
    RATE_WARNING = "rate_warning"           # High spend rate
    ANOMALY = "anomaly"                     # Unusual spending pattern
    SESSION_EXPIRED = "session_expired"     # Session timeout
    FORECAST_WARNING = "forecast_warning"   # Projected to exceed budget


@dataclass
class CostAlert:
    """
    A cost-related alert.

    Attributes:
        alert_id: Unique identifier.
        alert_type: Type of alert.
        severity: Alert severity level.
        session_id: Associated session (if any).
        user_id: Associated user.
        agent_id: Associated agent (if any).
        message: Human-readable message.
        current_cost: Current cost when alert was triggered.
        threshold: Threshold that was crossed.
        timestamp: When the alert was created.
        metadata: Additional metadata.
    """

    alert_id: str
    alert_type: AlertType
    severity: AlertSeverity
    message: str
    current_cost: float
    threshold: float | None = None
    session_id: str | None = None
    user_id: str | None = None
    agent_id: str | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "alert_id": self.alert_id,
            "alert_type": self.alert_type.value,
            "severity": self.severity.value,
            "message": self.message,
            "current_cost": self.current_cost,
            "threshold": self.threshold,
            "session_id": self.session_id,
            "user_id": self.user_id,
            "agent_id": self.agent_id,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class AgentCostProfile:
    """
    Cost profile for an agent within a session.

    Tracks costs attributed to a specific agent in a multi-agent
    system, including delegation costs.

    Attributes:
        agent_id: Unique agent identifier.
        parent_agent_id: Parent agent (if delegated).
        total_cost: Total cost attributed to this agent.
        input_tokens: Total input tokens.
        output_tokens: Total output tokens.
        tool_calls: Number of tool calls.
        by_tool: Cost breakdown by tool.
        by_model: Cost breakdown by model.
        first_activity: First activity timestamp.
        last_activity: Last activity timestamp.
    """

    agent_id: str
    parent_agent_id: str | None = None
    total_cost: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    tool_calls: int = 0
    by_tool: dict[str, float] = field(default_factory=dict)
    by_model: dict[str, float] = field(default_factory=dict)
    first_activity: datetime | None = None
    last_activity: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "agent_id": self.agent_id,
            "parent_agent_id": self.parent_agent_id,
            "total_cost": self.total_cost,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "tool_calls": self.tool_calls,
            "by_tool": self.by_tool,
            "by_model": self.by_model,
            "first_activity": self.first_activity.isoformat() if self.first_activity else None,
            "last_activity": self.last_activity.isoformat() if self.last_activity else None,
        }


@dataclass
class Session:
    """
    A user/agent session with cost tracking.

    Attributes:
        session_id: Unique session identifier.
        user_id: User who owns the session.
        agent_id: Primary agent for the session.
        state: Current session state.
        budget_limit: Maximum cost allowed for this session.
        total_cost: Total cost incurred so far.
        input_tokens: Total input tokens used.
        output_tokens: Total output tokens used.
        record_count: Number of usage records.
        agents: Per-agent cost profiles.
        by_tool: Cost breakdown by tool.
        by_model: Cost breakdown by model.
        start_time: When the session started.
        end_time: When the session ended (if ended).
        last_activity: Last activity timestamp.
        timeout_minutes: Session timeout in minutes.
        metadata: Additional session metadata.
        alerts: Alerts triggered during session.
    """

    session_id: str
    user_id: str
    state: SessionState = SessionState.ACTIVE
    agent_id: str | None = None
    budget_limit: float | None = None
    total_cost: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    record_count: int = 0
    agents: dict[str, AgentCostProfile] = field(default_factory=dict)
    by_tool: dict[str, float] = field(default_factory=dict)
    by_model: dict[str, float] = field(default_factory=dict)
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: datetime | None = None
    last_activity: datetime | None = None
    timeout_minutes: int = 60
    metadata: dict[str, Any] = field(default_factory=dict)
    alerts: list[CostAlert] = field(default_factory=list)

    @property
    def is_active(self) -> bool:
        """Whether the session is active."""
        return self.state == SessionState.ACTIVE

    @property
    def budget_remaining(self) -> float | None:
        """Remaining budget, or None if no limit."""
        if self.budget_limit is None:
            return None
        return max(0.0, self.budget_limit - self.total_cost)

    @property
    def budget_percentage(self) -> float | None:
        """Percentage of budget used, or None if no limit."""
        if self.budget_limit is None or self.budget_limit == 0:
            return None
        return min(1.0, self.total_cost / self.budget_limit)

    @property
    def duration_seconds(self) -> float:
        """Session duration in seconds."""
        end = self.end_time or datetime.now(timezone.utc)
        return (end - self.start_time).total_seconds()

    @property
    def is_expired(self) -> bool:
        """Whether the session has expired due to timeout."""
        if self.last_activity is None:
            return False
        inactive = datetime.now(timezone.utc) - self.last_activity
        return inactive > timedelta(minutes=self.timeout_minutes)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "session_id": self.session_id,
            "user_id": self.user_id,
            "agent_id": self.agent_id,
            "state": self.state.value,
            "budget_limit": self.budget_limit,
            "budget_remaining": self.budget_remaining,
            "budget_percentage": self.budget_percentage,
            "total_cost": self.total_cost,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "record_count": self.record_count,
            "agents": {k: v.to_dict() for k, v in self.agents.items()},
            "by_tool": self.by_tool,
            "by_model": self.by_model,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "last_activity": self.last_activity.isoformat() if self.last_activity else None,
            "duration_seconds": self.duration_seconds,
            "timeout_minutes": self.timeout_minutes,
            "metadata": self.metadata,
            "alerts": [a.to_dict() for a in self.alerts],
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


@dataclass
class SessionSummary:
    """
    Summary of a completed session.

    Attributes:
        session_id: Session identifier.
        user_id: User who owned the session.
        total_cost: Total cost incurred.
        total_tokens: Total tokens used.
        duration_seconds: Session duration.
        tool_breakdown: Cost by tool.
        model_breakdown: Cost by model.
        agent_breakdown: Cost by agent.
        peak_spend_rate: Highest spend rate ($/minute).
        alerts_triggered: Number of alerts triggered.
        end_reason: Why the session ended.
    """

    session_id: str
    user_id: str
    total_cost: float
    total_tokens: int
    duration_seconds: float
    tool_breakdown: dict[str, float]
    model_breakdown: dict[str, float]
    agent_breakdown: dict[str, float]
    peak_spend_rate: float = 0.0
    alerts_triggered: int = 0
    end_reason: str = "user_ended"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


# Type alias for alert callbacks
AlertCallback = Callable[[CostAlert], None]


class SessionCostTracker:
    """
    Enhanced cost tracker with session management.

    Provides per-user and per-agent cost tracking with automatic
    session management, budget enforcement, and alerting.

    Example:
        >>> tracker = SessionCostTracker(
        ...     budget_policy=BudgetPolicy(max_cost_per_user_per_day=100.0)
        ... )
        >>>
        >>> # Start session with budget
        >>> session = tracker.start_session(
        ...     user_id="alice",
        ...     budget_limit=10.0,
        ... )
        >>>
        >>> # Record usage
        >>> record = tracker.record_session_usage(
        ...     session_id=session.session_id,
        ...     model="claude-sonnet-4-20250514",
        ...     input_tokens=1000,
        ...     output_tokens=500,
        ... )
        >>>
        >>> # Check status
        >>> print(f"Session cost: ${session.total_cost:.4f}")
        >>> print(f"Remaining: ${session.budget_remaining:.4f}")
    """

    def __init__(
        self,
        base_tracker: CostTracker | None = None,
        budget_policy: BudgetPolicy | None = None,
        default_session_timeout: int = 60,
        budget_warning_threshold: float = 0.8,
        rate_warning_threshold: float = 1.0,  # $/minute
        max_sessions: int = 10000,
        enable_forecasting: bool = True,
    ) -> None:
        """
        Initialize the session cost tracker.

        Args:
            base_tracker: Optional base CostTracker to wrap.
            budget_policy: Budget policy for global limits.
            default_session_timeout: Default session timeout in minutes.
            budget_warning_threshold: Percentage at which to warn (0.0 to 1.0).
            rate_warning_threshold: Spend rate ($/min) that triggers warning.
            max_sessions: Maximum active sessions to track.
            enable_forecasting: Whether to enable cost forecasting.
        """
        self._lock = threading.RLock()

        # Use provided tracker or create new one
        self._base_tracker = base_tracker or CostTracker(budget_policy=budget_policy)

        self._default_timeout = default_session_timeout
        self._budget_warning_threshold = budget_warning_threshold
        self._rate_warning_threshold = rate_warning_threshold
        self._max_sessions = max_sessions
        self._enable_forecasting = enable_forecasting

        # Session storage
        self._sessions: dict[str, Session] = {}
        self._user_sessions: dict[str, list[str]] = defaultdict(list)
        self._session_records: dict[str, list[UsageRecord]] = defaultdict(list)

        # Alert callbacks
        self._alert_callbacks: list[AlertCallback] = []

        # Metrics
        self._total_alerts = 0
        self._sessions_created = 0
        self._sessions_terminated = 0

    def add_alert_callback(self, callback: AlertCallback) -> None:
        """
        Register a callback for cost alerts.

        Args:
            callback: Function to call when an alert is triggered.
        """
        self._alert_callbacks.append(callback)

    def remove_alert_callback(self, callback: AlertCallback) -> None:
        """Remove an alert callback."""
        if callback in self._alert_callbacks:
            self._alert_callbacks.remove(callback)

    def start_session(
        self,
        user_id: str,
        agent_id: str | None = None,
        budget_limit: float | None = None,
        timeout_minutes: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Session:
        """
        Start a new cost tracking session.

        Args:
            user_id: User who owns the session.
            agent_id: Primary agent for the session.
            budget_limit: Maximum cost for this session.
            timeout_minutes: Session timeout (uses default if not provided).
            metadata: Additional metadata to store.

        Returns:
            The created Session.
        """
        session_id = f"sess_{uuid.uuid4().hex[:12]}"

        session = Session(
            session_id=session_id,
            user_id=user_id,
            agent_id=agent_id,
            budget_limit=budget_limit,
            timeout_minutes=timeout_minutes or self._default_timeout,
            metadata=metadata or {},
            last_activity=datetime.now(timezone.utc),
        )

        # Register primary agent if provided
        if agent_id:
            session.agents[agent_id] = AgentCostProfile(agent_id=agent_id)

        with self._lock:
            # Clean up expired sessions if at capacity
            if len(self._sessions) >= self._max_sessions:
                self._cleanup_expired_sessions()

            self._sessions[session_id] = session
            self._user_sessions[user_id].append(session_id)
            self._sessions_created += 1

        budget_str = f"${budget_limit:.2f}" if budget_limit else "unlimited"
        logger.info(
            f"Started session {session_id} for user {user_id} "
            f"(budget: {budget_str})"
        )

        return session

    def get_session(self, session_id: str) -> Session | None:
        """Get a session by ID."""
        with self._lock:
            session = self._sessions.get(session_id)

            # Check for expiration
            if session and session.is_expired and session.is_active:
                self._expire_session(session)

            return session

    def get_user_sessions(
        self,
        user_id: str,
        active_only: bool = True,
    ) -> list[Session]:
        """
        Get all sessions for a user.

        Args:
            user_id: User to get sessions for.
            active_only: Whether to return only active sessions.

        Returns:
            List of sessions.
        """
        with self._lock:
            session_ids = self._user_sessions.get(user_id, [])
            sessions = []

            for sid in session_ids:
                session = self._sessions.get(sid)
                if session:
                    if active_only and not session.is_active:
                        continue
                    sessions.append(session)

            return sessions

    def record_session_usage(
        self,
        session_id: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        cache_read_tokens: int = 0,
        cache_write_tokens: int = 0,
        tool_name: str | None = None,
        agent_id: str | None = None,
        request_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> UsageRecord | None:
        """
        Record usage for a session.

        Args:
            session_id: Session to record usage for.
            model: Model used.
            input_tokens: Number of input tokens.
            output_tokens: Number of output tokens.
            cache_read_tokens: Cached tokens read.
            cache_write_tokens: Tokens written to cache.
            tool_name: Tool that triggered the usage.
            agent_id: Agent that incurred the usage.
            request_id: Request identifier.
            metadata: Additional metadata.

        Returns:
            UsageRecord if successful, None if session not found or inactive.
        """
        with self._lock:
            session = self._sessions.get(session_id)

            if session is None:
                logger.warning(f"Session {session_id} not found")
                return None

            if not session.is_active:
                logger.warning(f"Session {session_id} is not active (state: {session.state})")
                return None

            # Check for expiration
            if session.is_expired:
                self._expire_session(session)
                return None

            # Record in base tracker
            record = self._base_tracker.record_usage(
                model=model,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                cache_read_tokens=cache_read_tokens,
                cache_write_tokens=cache_write_tokens,
                tool_name=tool_name,
                user_id=session.user_id,
                request_id=request_id,
                metadata={
                    **(metadata or {}),
                    "session_id": session_id,
                    "agent_id": agent_id,
                },
            )

            # Update session
            session.total_cost += record.cost_usd
            session.input_tokens += input_tokens
            session.output_tokens += output_tokens
            session.record_count += 1
            session.last_activity = record.timestamp

            # Update tool breakdown
            if tool_name:
                session.by_tool[tool_name] = session.by_tool.get(tool_name, 0.0) + record.cost_usd

            # Update model breakdown
            session.by_model[model] = session.by_model.get(model, 0.0) + record.cost_usd

            # Update agent breakdown
            effective_agent = agent_id or session.agent_id
            if effective_agent:
                if effective_agent not in session.agents:
                    session.agents[effective_agent] = AgentCostProfile(agent_id=effective_agent)

                agent_profile = session.agents[effective_agent]
                agent_profile.total_cost += record.cost_usd
                agent_profile.input_tokens += input_tokens
                agent_profile.output_tokens += output_tokens
                agent_profile.tool_calls += 1

                if tool_name:
                    agent_profile.by_tool[tool_name] = agent_profile.by_tool.get(tool_name, 0.0) + record.cost_usd
                agent_profile.by_model[model] = agent_profile.by_model.get(model, 0.0) + record.cost_usd

                if agent_profile.first_activity is None:
                    agent_profile.first_activity = record.timestamp
                agent_profile.last_activity = record.timestamp

            # Store record
            self._session_records[session_id].append(record)

            # Check budget and alerts
            self._check_budget_alerts(session, record)

            return record

    def _check_budget_alerts(self, session: Session, record: UsageRecord) -> None:
        """Check for budget-related alerts."""
        if session.budget_limit is None:
            return

        percentage = session.budget_percentage or 0.0

        # Budget warning
        if (
            percentage >= self._budget_warning_threshold
            and percentage < 1.0
            and not any(a.alert_type == AlertType.BUDGET_WARNING for a in session.alerts)
        ):
            alert = CostAlert(
                alert_id=f"alert_{uuid.uuid4().hex[:8]}",
                alert_type=AlertType.BUDGET_WARNING,
                severity=AlertSeverity.WARNING,
                session_id=session.session_id,
                user_id=session.user_id,
                agent_id=session.agent_id,
                message=(
                    f"Session approaching budget limit: "
                    f"${session.total_cost:.2f}/${session.budget_limit:.2f} "
                    f"({percentage:.0%})"
                ),
                current_cost=session.total_cost,
                threshold=session.budget_limit * self._budget_warning_threshold,
            )
            self._trigger_alert(session, alert)

        # Budget exceeded
        if percentage >= 1.0:
            alert = CostAlert(
                alert_id=f"alert_{uuid.uuid4().hex[:8]}",
                alert_type=AlertType.BUDGET_EXCEEDED,
                severity=AlertSeverity.CRITICAL,
                session_id=session.session_id,
                user_id=session.user_id,
                agent_id=session.agent_id,
                message=(
                    f"Session budget exceeded: "
                    f"${session.total_cost:.2f}/${session.budget_limit:.2f}"
                ),
                current_cost=session.total_cost,
                threshold=session.budget_limit,
            )
            self._trigger_alert(session, alert)

            # Terminate session
            session.state = SessionState.BUDGET_EXCEEDED
            session.end_time = datetime.now(timezone.utc)
            logger.warning(f"Session {session.session_id} terminated: budget exceeded")

        # Check spend rate
        if session.duration_seconds > 60:  # At least 1 minute
            rate_per_minute = session.total_cost / (session.duration_seconds / 60)

            if (
                rate_per_minute > self._rate_warning_threshold
                and not any(a.alert_type == AlertType.RATE_WARNING for a in session.alerts)
            ):
                alert = CostAlert(
                    alert_id=f"alert_{uuid.uuid4().hex[:8]}",
                    alert_type=AlertType.RATE_WARNING,
                    severity=AlertSeverity.WARNING,
                    session_id=session.session_id,
                    user_id=session.user_id,
                    agent_id=session.agent_id,
                    message=(
                        f"High spend rate detected: ${rate_per_minute:.2f}/minute "
                        f"(threshold: ${self._rate_warning_threshold:.2f}/minute)"
                    ),
                    current_cost=session.total_cost,
                    threshold=self._rate_warning_threshold,
                    metadata={"rate_per_minute": rate_per_minute},
                )
                self._trigger_alert(session, alert)

    def _trigger_alert(self, session: Session, alert: CostAlert) -> None:
        """Trigger an alert and notify callbacks."""
        session.alerts.append(alert)
        self._total_alerts += 1

        logger.warning(f"Cost alert: {alert.message}")

        # Notify callbacks
        for callback in self._alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Alert callback error: {e}")

    def _expire_session(self, session: Session) -> None:
        """Mark a session as expired."""
        session.state = SessionState.EXPIRED
        session.end_time = datetime.now(timezone.utc)

        alert = CostAlert(
            alert_id=f"alert_{uuid.uuid4().hex[:8]}",
            alert_type=AlertType.SESSION_EXPIRED,
            severity=AlertSeverity.INFO,
            session_id=session.session_id,
            user_id=session.user_id,
            agent_id=session.agent_id,
            message=f"Session expired after {session.timeout_minutes} minutes of inactivity",
            current_cost=session.total_cost,
        )
        self._trigger_alert(session, alert)

        logger.info(f"Session {session.session_id} expired")

    def pause_session(self, session_id: str) -> bool:
        """
        Pause a session.

        Args:
            session_id: Session to pause.

        Returns:
            True if paused successfully.
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if session and session.is_active:
                session.state = SessionState.PAUSED
                logger.info(f"Session {session_id} paused")
                return True
        return False

    def resume_session(self, session_id: str) -> bool:
        """
        Resume a paused session.

        Args:
            session_id: Session to resume.

        Returns:
            True if resumed successfully.
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if session and session.state == SessionState.PAUSED:
                session.state = SessionState.ACTIVE
                session.last_activity = datetime.now(timezone.utc)
                logger.info(f"Session {session_id} resumed")
                return True
        return False

    def end_session(self, session_id: str, reason: str = "user_ended") -> SessionSummary | None:
        """
        End a session and get summary.

        Args:
            session_id: Session to end.
            reason: Reason for ending.

        Returns:
            SessionSummary or None if not found.
        """
        with self._lock:
            session = self._sessions.get(session_id)

            if session is None:
                return None

            # Mark as terminated
            session.state = SessionState.TERMINATED
            session.end_time = datetime.now(timezone.utc)
            self._sessions_terminated += 1

            # Calculate peak spend rate
            peak_rate = 0.0
            records = self._session_records.get(session_id, [])
            if len(records) >= 2:
                # Calculate rolling 1-minute windows
                for i in range(len(records) - 1):
                    window_cost = 0.0
                    window_start = records[i].timestamp

                    for j in range(i, len(records)):
                        if (records[j].timestamp - window_start).total_seconds() <= 60:
                            window_cost += records[j].cost_usd
                        else:
                            break

                    if window_cost > peak_rate:
                        peak_rate = window_cost

            summary = SessionSummary(
                session_id=session.session_id,
                user_id=session.user_id,
                total_cost=session.total_cost,
                total_tokens=session.input_tokens + session.output_tokens,
                duration_seconds=session.duration_seconds,
                tool_breakdown=dict(session.by_tool),
                model_breakdown=dict(session.by_model),
                agent_breakdown={
                    agent_id: profile.total_cost
                    for agent_id, profile in session.agents.items()
                },
                peak_spend_rate=peak_rate,
                alerts_triggered=len(session.alerts),
                end_reason=reason,
            )

            logger.info(
                f"Session {session_id} ended: ${session.total_cost:.4f}, "
                f"{session.record_count} records, {len(session.alerts)} alerts"
            )

            return summary

    def get_session_records(
        self,
        session_id: str,
        limit: int | None = None,
    ) -> list[UsageRecord]:
        """
        Get usage records for a session.

        Args:
            session_id: Session to get records for.
            limit: Maximum records to return.

        Returns:
            List of usage records.
        """
        with self._lock:
            records = self._session_records.get(session_id, [])
            if limit:
                return list(records[-limit:])
            return list(records)

    def forecast_session_cost(
        self,
        session_id: str,
        duration_minutes: int = 60,
    ) -> float | None:
        """
        Forecast session cost based on current usage pattern.

        Args:
            session_id: Session to forecast.
            duration_minutes: Minutes to forecast.

        Returns:
            Forecasted additional cost, or None if insufficient data.
        """
        if not self._enable_forecasting:
            return None

        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return None

            # Need at least 2 minutes of data
            if session.duration_seconds < 120:
                return None

            # Calculate rate
            rate_per_minute = session.total_cost / (session.duration_seconds / 60)

            return rate_per_minute * duration_minutes

    def _cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions. Returns number cleaned."""
        cleaned = 0
        expired_ids = []

        for session_id, session in self._sessions.items():
            if session.is_expired or session.state in (
                SessionState.TERMINATED,
                SessionState.EXPIRED,
            ):
                # Only clean if ended more than 1 hour ago
                if session.end_time:
                    age = datetime.now(timezone.utc) - session.end_time
                    if age > timedelta(hours=1):
                        expired_ids.append(session_id)

        for session_id in expired_ids:
            del self._sessions[session_id]
            if session_id in self._session_records:
                del self._session_records[session_id]
            cleaned += 1

        if cleaned:
            logger.info(f"Cleaned up {cleaned} expired sessions")

        return cleaned

    def get_user_total_cost(
        self,
        user_id: str,
        period: timedelta | None = None,
    ) -> float:
        """
        Get total cost for a user across all sessions.

        Args:
            user_id: User to check.
            period: Time period (None for all time).

        Returns:
            Total cost in USD.
        """
        with self._lock:
            if period:
                return self._base_tracker.get_user_spend(user_id, period)

            # Sum across all sessions
            total = 0.0
            for session_id in self._user_sessions.get(user_id, []):
                session = self._sessions.get(session_id)
                if session:
                    total += session.total_cost

            return total

    def get_agent_total_cost(self, agent_id: str) -> float:
        """
        Get total cost attributed to an agent.

        Args:
            agent_id: Agent to check.

        Returns:
            Total cost in USD.
        """
        with self._lock:
            total = 0.0

            for session in self._sessions.values():
                if agent_id in session.agents:
                    total += session.agents[agent_id].total_cost

            return total

    def get_stats(self) -> dict[str, Any]:
        """Get tracker statistics."""
        with self._lock:
            active_sessions = sum(1 for s in self._sessions.values() if s.is_active)

            return {
                "total_sessions": len(self._sessions),
                "active_sessions": active_sessions,
                "sessions_created": self._sessions_created,
                "sessions_terminated": self._sessions_terminated,
                "total_alerts": self._total_alerts,
                "users_tracked": len(self._user_sessions),
            }

    def export_session(
        self,
        session_id: str,
        format: str = "json",
    ) -> str | None:
        """
        Export session data for billing/audit.

        Args:
            session_id: Session to export.
            format: Output format ("json" or "csv").

        Returns:
            Exported data as string, or None if not found.
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return None

            records = self._session_records.get(session_id, [])

            if format == "csv":
                lines = ["timestamp,model,input_tokens,output_tokens,cost_usd,tool_name,agent_id"]
                for record in records:
                    agent_id = record.metadata.get("agent_id", "")
                    lines.append(
                        f"{record.timestamp.isoformat()},"
                        f"{record.model},"
                        f"{record.input_tokens},"
                        f"{record.output_tokens},"
                        f"{record.cost_usd:.6f},"
                        f"{record.tool_name or ''},"
                        f"{agent_id}"
                    )
                return "\n".join(lines)

            else:
                return json.dumps({
                    "session": session.to_dict(),
                    "records": [r.to_dict() for r in records],
                }, indent=2)

    @property
    def base_tracker(self) -> CostTracker:
        """Get the underlying CostTracker."""
        return self._base_tracker


def create_session_cost_tracker(
    budget_policy: BudgetPolicy | None = None,
    default_session_budget: float | None = None,
    alert_callback: AlertCallback | None = None,
) -> SessionCostTracker:
    """
    Factory function to create a SessionCostTracker.

    Args:
        budget_policy: Global budget policy.
        default_session_budget: Default budget for new sessions.
        alert_callback: Optional alert callback.

    Returns:
        Configured SessionCostTracker.
    """
    tracker = SessionCostTracker(budget_policy=budget_policy)

    if alert_callback:
        tracker.add_alert_callback(alert_callback)

    return tracker
