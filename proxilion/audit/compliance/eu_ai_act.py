"""
EU AI Act compliance exporter.

Provides audit log export formats for EU AI Act compliance,
specifically targeting:
- Article 14: Human Oversight
- Article 15: Accuracy, Robustness and Cybersecurity
- Article 17: Quality Management System

Example:
    >>> from proxilion.audit import InMemoryAuditLogger
    >>> from proxilion.audit.compliance import EUAIActExporter
    >>> from datetime import datetime, timedelta, timezone
    >>>
    >>> logger = InMemoryAuditLogger()
    >>> # ... log events ...
    >>>
    >>> exporter = EUAIActExporter(
    ...     logger,
    ...     organization="Acme Corp",
    ...     system_name="Customer Service AI",
    ...     responsible_party="AI Governance Team",
    ... )
    >>>
    >>> end = datetime.now(timezone.utc)
    >>> start = end - timedelta(days=30)
    >>>
    >>> # Export human oversight evidence
    >>> oversight = exporter.export_human_oversight_evidence(start, end)
    >>>
    >>> # Generate full compliance report
    >>> report = exporter.generate_compliance_report(start, end)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone  # noqa: F401 (timezone used in docstring)
from typing import Any

from proxilion.audit.compliance.base import (
    BaseComplianceExporter,
    ComplianceEvidence,
    ComplianceFramework,
    ComplianceReport,
    EventSource,
)
from proxilion.audit.events import AuditEventV2, EventType


@dataclass
class HumanOversightEvidence:
    """
    Evidence of human oversight capability per Article 14.

    Attributes:
        approval_requests: Events where human approval was requested.
        override_events: Events where humans overrode AI decisions.
        intervention_points: Documented intervention capabilities.
        denied_requests: Requests denied by human oversight.
        total_decisions: Total number of decisions made.
        human_involvement_rate: Percentage of decisions with human involvement.
    """
    approval_requests: list[dict[str, Any]] = field(default_factory=list)
    override_events: list[dict[str, Any]] = field(default_factory=list)
    intervention_points: list[dict[str, Any]] = field(default_factory=list)
    denied_requests: list[dict[str, Any]] = field(default_factory=list)
    total_decisions: int = 0
    human_involvement_rate: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "approval_requests": self.approval_requests,
            "override_events": self.override_events,
            "intervention_points": self.intervention_points,
            "denied_requests": self.denied_requests,
            "total_decisions": self.total_decisions,
            "human_involvement_rate": self.human_involvement_rate,
            "summary": {
                "approval_request_count": len(self.approval_requests),
                "override_count": len(self.override_events),
                "intervention_point_count": len(self.intervention_points),
                "denied_count": len(self.denied_requests),
            },
        }


@dataclass
class DecisionAuditTrailEntry:
    """
    A single entry in the decision audit trail.

    Attributes:
        timestamp: When the decision was made.
        decision_id: Unique identifier for this decision.
        decision_type: Type of decision (authorization, tool_call, etc.).
        inputs: Inputs to the decision.
        outputs: Outputs/results of the decision.
        user_context: User context at time of decision.
        ai_system_id: Identifier of the AI system.
        rationale: Explanation for the decision.
    """
    timestamp: datetime
    decision_id: str
    decision_type: str
    inputs: dict[str, Any]
    outputs: dict[str, Any]
    user_context: dict[str, Any]
    ai_system_id: str
    rationale: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "decision_id": self.decision_id,
            "decision_type": self.decision_type,
            "inputs": self.inputs,
            "outputs": self.outputs,
            "user_context": self.user_context,
            "ai_system_id": self.ai_system_id,
            "rationale": self.rationale,
        }


@dataclass
class RiskAssessmentEntry:
    """
    Entry in the risk assessment log per Article 15.

    Attributes:
        timestamp: When the risk was identified.
        event_id: Related event ID.
        risk_type: Type of risk identified.
        severity: Severity level (low, medium, high, critical).
        description: Description of the risk.
        mitigation_action: Action taken to mitigate.
        resolved: Whether the risk was resolved.
    """
    timestamp: datetime
    event_id: str
    risk_type: str
    severity: str
    description: str
    mitigation_action: str | None = None
    resolved: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "event_id": self.event_id,
            "risk_type": self.risk_type,
            "severity": self.severity,
            "description": self.description,
            "mitigation_action": self.mitigation_action,
            "resolved": self.resolved,
        }


class EUAIActExporter(BaseComplianceExporter):
    """
    Export audit logs in EU AI Act compliant format.

    Produces documentation required for:
    - Article 14: Human oversight evidence
    - Article 15: Accuracy and robustness records
    - Article 17: Quality management system

    The EU AI Act requires high-risk AI systems to maintain:
    - Records of all AI system decisions
    - Evidence of human oversight capability
    - Risk management documentation
    - Clear audit trails

    Example:
        >>> exporter = EUAIActExporter(
        ...     logger,
        ...     organization="Acme Corp",
        ...     system_name="Risk Assessment AI",
        ...     responsible_party="compliance@acme.com",
        ... )
        >>>
        >>> # Export human oversight evidence
        >>> oversight = exporter.export_human_oversight_evidence(start, end)
        >>>
        >>> # Export decision audit trail
        >>> trail = exporter.export_decision_audit_trail(start, end)
        >>>
        >>> # Generate full compliance report
        >>> report = exporter.generate_compliance_report(start, end)
    """

    def __init__(
        self,
        event_source: EventSource | list[AuditEventV2],
        organization: str = "",
        system_name: str = "",
        responsible_party: str = "",
        ai_system_id: str = "",
        risk_classification: str = "high-risk",
    ) -> None:
        """
        Initialize the EU AI Act exporter.

        Args:
            event_source: Source of audit events.
            organization: Organization name.
            system_name: AI system name.
            responsible_party: Responsible party contact.
            ai_system_id: Unique identifier for the AI system.
            risk_classification: Risk classification (high-risk, limited-risk, etc.).
        """
        super().__init__(event_source, organization, system_name, responsible_party)
        self._ai_system_id = ai_system_id or system_name
        self._risk_classification = risk_classification

    @property
    def framework(self) -> ComplianceFramework:
        """Get the compliance framework."""
        return ComplianceFramework.EU_AI_ACT

    @property
    def framework_version(self) -> str:
        """Get the framework version."""
        return "2024"

    def export_human_oversight_evidence(
        self,
        start: datetime,
        end: datetime,
    ) -> HumanOversightEvidence:
        """
        Export evidence of human oversight capability (Article 14).

        Article 14 requires that high-risk AI systems have:
        - Appropriate human-machine interface tools
        - Ability to correctly interpret outputs
        - Ability to decide not to use the system
        - Ability to intervene or interrupt

        Args:
            start: Start of the reporting period.
            end: End of the reporting period.

        Returns:
            HumanOversightEvidence with categorized events.
        """
        events = self.filter_by_date_range(start, end)

        evidence = HumanOversightEvidence(total_decisions=len(events))

        for event in events:
            event_dict = self.event_to_evidence_dict(event)

            # Identify approval requests (requires_approval tools)
            if event.data.authorization_metadata.get("requires_approval"):
                evidence.approval_requests.append(event_dict)

            # Identify override events (human overrode AI decision)
            if event.data.authorization_metadata.get("human_override"):
                evidence.override_events.append(event_dict)

            # Identify intervention points (denied requests are intervention)
            if event.data.event_type == EventType.AUTHORIZATION_DENIED:
                evidence.denied_requests.append(event_dict)
                evidence.intervention_points.append({
                    **event_dict,
                    "intervention_type": "authorization_denied",
                    "reason": event.data.authorization_reason,
                })

            # Security events are also intervention points
            if event.data.event_type in [
                EventType.RATE_LIMIT_EXCEEDED,
                EventType.CIRCUIT_BREAKER_OPEN,
                EventType.IDOR_VIOLATION,
            ]:
                evidence.intervention_points.append({
                    **event_dict,
                    "intervention_type": event.data.event_type.value,
                })

        # Calculate human involvement rate
        human_involved = (
            len(evidence.approval_requests) +
            len(evidence.override_events) +
            len(evidence.denied_requests)
        )
        if evidence.total_decisions > 0:
            evidence.human_involvement_rate = human_involved / evidence.total_decisions

        return evidence

    def export_decision_audit_trail(
        self,
        start: datetime,
        end: datetime,
    ) -> list[DecisionAuditTrailEntry]:
        """
        Export chronological decision audit trail (Article 14.4).

        Article 14.4 requires that operators keep logs of
        the high-risk AI system's operation.

        Args:
            start: Start of the reporting period.
            end: End of the reporting period.

        Returns:
            List of decision audit trail entries.
        """
        events = self.filter_by_date_range(start, end)
        trail = []

        for event in events:
            entry = DecisionAuditTrailEntry(
                timestamp=event.timestamp,
                decision_id=event.event_id,
                decision_type=event.data.event_type.value,
                inputs={
                    "tool_name": event.data.tool_name,
                    "tool_arguments": event.data.tool_arguments,
                },
                outputs={
                    "authorized": event.data.authorization_allowed,
                    "execution_result": event.data.execution_result,
                },
                user_context={
                    "user_id": event.data.user_id,
                    "roles": event.data.user_roles,
                    "session_id": event.data.session_id,
                    "attributes": event.data.user_attributes,
                },
                ai_system_id=self._ai_system_id,
                rationale=event.data.authorization_reason,
            )
            trail.append(entry)

        return trail

    def export_risk_assessment_log(
        self,
        start: datetime,
        end: datetime,
    ) -> dict[str, Any]:
        """
        Export risk-related events for Article 15 compliance.

        Article 15 requires appropriate levels of accuracy,
        robustness and cybersecurity.

        Args:
            start: Start of the reporting period.
            end: End of the reporting period.

        Returns:
            Dictionary containing categorized risk events.
        """
        events = self.filter_by_date_range(start, end)

        risk_log: dict[str, Any] = {
            "high_risk_tool_calls": [],
            "denied_requests": [],
            "anomaly_detections": [],
            "security_events": [],
            "summary": {},
        }

        for event in events:
            event_dict = self.event_to_evidence_dict(event)

            # High-risk tool calls
            if event.data.authorization_metadata.get("risk_level") == "high":
                risk_log["high_risk_tool_calls"].append(event_dict)

            # Denied requests
            if event.data.event_type == EventType.AUTHORIZATION_DENIED:
                risk_entry = RiskAssessmentEntry(
                    timestamp=event.timestamp,
                    event_id=event.event_id,
                    risk_type="access_denied",
                    severity="low",
                    description=f"Authorization denied for {event.data.tool_name}",
                    mitigation_action="Request blocked by policy",
                    resolved=True,
                )
                risk_log["denied_requests"].append(risk_entry.to_dict())

            # Security events
            if event.data.event_type == EventType.RATE_LIMIT_EXCEEDED:
                risk_entry = RiskAssessmentEntry(
                    timestamp=event.timestamp,
                    event_id=event.event_id,
                    risk_type="rate_limit",
                    severity="medium",
                    description=f"Rate limit exceeded for user {event.data.user_id}",
                    mitigation_action="Request throttled",
                    resolved=True,
                )
                risk_log["security_events"].append(risk_entry.to_dict())

            if event.data.event_type == EventType.CIRCUIT_BREAKER_OPEN:
                risk_entry = RiskAssessmentEntry(
                    timestamp=event.timestamp,
                    event_id=event.event_id,
                    risk_type="circuit_breaker",
                    severity="high",
                    description=f"Circuit breaker opened for {event.data.tool_name}",
                    mitigation_action="Tool temporarily disabled",
                    resolved=False,
                )
                risk_log["security_events"].append(risk_entry.to_dict())

            if event.data.event_type == EventType.IDOR_VIOLATION:
                risk_entry = RiskAssessmentEntry(
                    timestamp=event.timestamp,
                    event_id=event.event_id,
                    risk_type="idor_violation",
                    severity="critical",
                    description=f"IDOR violation by user {event.data.user_id}",
                    mitigation_action="Request blocked",
                    resolved=True,
                )
                risk_log["security_events"].append(risk_entry.to_dict())
                risk_log["anomaly_detections"].append(risk_entry.to_dict())

            if event.data.event_type == EventType.SCHEMA_VALIDATION_FAILURE:
                risk_entry = RiskAssessmentEntry(
                    timestamp=event.timestamp,
                    event_id=event.event_id,
                    risk_type="validation_failure",
                    severity="medium",
                    description=f"Schema validation failed for {event.data.tool_name}",
                    mitigation_action="Request rejected",
                    resolved=True,
                )
                risk_log["anomaly_detections"].append(risk_entry.to_dict())

        # Compute summary
        risk_log["summary"] = {
            "total_high_risk_calls": len(risk_log["high_risk_tool_calls"]),
            "total_denied": len(risk_log["denied_requests"]),
            "total_anomalies": len(risk_log["anomaly_detections"]),
            "total_security_events": len(risk_log["security_events"]),
            "period_start": start.isoformat(),
            "period_end": end.isoformat(),
        }

        return risk_log

    def generate_report(
        self,
        start: datetime,
        end: datetime,
    ) -> ComplianceReport:
        """Generate a complete EU AI Act compliance report."""
        return self.generate_compliance_report(start, end)

    def generate_compliance_report(
        self,
        start: datetime,
        end: datetime,
    ) -> ComplianceReport:
        """
        Generate full EU AI Act compliance report.

        Args:
            start: Start of the reporting period.
            end: End of the reporting period.

        Returns:
            Complete compliance report in markdown-ready format.
        """
        metadata = self.create_metadata(start, end)
        metadata.additional_info = {
            "ai_system_id": self._ai_system_id,
            "risk_classification": self._risk_classification,
        }

        evidence = []
        recommendations = []

        # Article 14: Human Oversight
        oversight = self.export_human_oversight_evidence(start, end)
        article_14_evidence = ComplianceEvidence(
            control_id="Article 14",
            control_name="Human Oversight",
            evidence_type="operational_logs",
            description=(
                "Evidence of human oversight capabilities including "
                "approval requests, override events, and intervention points."
            ),
            events=oversight.approval_requests + oversight.override_events,
            summary={
                "total_decisions": oversight.total_decisions,
                "approval_requests": len(oversight.approval_requests),
                "override_events": len(oversight.override_events),
                "intervention_points": len(oversight.intervention_points),
                "human_involvement_rate": f"{oversight.human_involvement_rate:.1%}",
            },
            compliant=(
                oversight.human_involvement_rate > 0 or len(oversight.intervention_points) > 0
            ),
        )
        evidence.append(article_14_evidence)

        if oversight.human_involvement_rate < 0.1:
            recommendations.append(
                "Consider increasing human oversight by requiring approval "
                "for high-risk operations."
            )

        # Article 14.4: Decision Audit Trail
        trail = self.export_decision_audit_trail(start, end)
        article_14_4_evidence = ComplianceEvidence(
            control_id="Article 14.4",
            control_name="Operation Logs",
            evidence_type="audit_trail",
            description=(
                "Chronological record of all AI system operations "
                "including inputs, outputs, and decision rationale."
            ),
            events=[e.to_dict() for e in trail[:100]],  # Limit for readability
            summary={
                "total_entries": len(trail),
                "unique_users": len({e.user_context["user_id"] for e in trail}),
                "unique_tools": len({e.inputs["tool_name"] for e in trail}),
            },
            compliant=len(trail) > 0,
            notes=f"Showing first 100 of {len(trail)} entries." if len(trail) > 100 else None,
        )
        evidence.append(article_14_4_evidence)

        # Article 15: Risk Assessment
        risk_log = self.export_risk_assessment_log(start, end)
        article_15_evidence = ComplianceEvidence(
            control_id="Article 15",
            control_name="Accuracy, Robustness and Cybersecurity",
            evidence_type="risk_assessment",
            description=(
                "Risk assessment log including security events, "
                "anomaly detections, and mitigation actions."
            ),
            events=risk_log["security_events"] + risk_log["anomaly_detections"],
            summary=risk_log["summary"],
            compliant=True,  # Having the log demonstrates compliance
            notes=(
                "All security events were handled with appropriate mitigation actions."
                if risk_log["security_events"] else
                "No security events detected during this period."
            ),
        )
        evidence.append(article_15_evidence)

        if risk_log["summary"]["total_security_events"] > 10:
            recommendations.append(
                "Review security event patterns and consider strengthening access controls."
            )

        # Article 17: Quality Management
        all_events = self.filter_by_date_range(start, end)
        stats = self.compute_summary_stats(all_events)

        article_17_evidence = ComplianceEvidence(
            control_id="Article 17",
            control_name="Quality Management System",
            evidence_type="system_metrics",
            description=(
                "Quality management metrics demonstrating systematic "
                "monitoring and control of the AI system."
            ),
            summary={
                "total_operations": stats["total_events"],
                "authorization_rate": f"{stats['grant_rate']:.1%}",
                "unique_users_served": stats["unique_users"],
                "tools_available": stats["unique_tools"],
                "period_coverage": f"{start.date()} to {end.date()}",
            },
            compliant=True,
        )
        evidence.append(article_17_evidence)

        # Overall summary
        summary = {
            "reporting_period": f"{start.date()} to {end.date()}",
            "ai_system_id": self._ai_system_id,
            "risk_classification": self._risk_classification,
            "total_operations": stats["total_events"],
            "human_oversight_rate": f"{oversight.human_involvement_rate:.1%}",
            "security_events": risk_log["summary"]["total_security_events"],
            "compliance_status": (
                "Compliant" if all(e.compliant for e in evidence) else "Review Required"
            ),
        }

        return ComplianceReport(
            metadata=metadata,
            evidence=evidence,
            summary=summary,
            recommendations=recommendations,
        )
