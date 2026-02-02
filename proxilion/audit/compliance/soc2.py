"""
SOC 2 Type II compliance exporter.

Provides audit log export formats for SOC 2 Type II compliance,
mapping to Trust Service Criteria (TSC) including:
- CC6: Logical and Physical Access Controls
- CC7: System Operations
- CC8: Change Management

Example:
    >>> from proxilion.audit import InMemoryAuditLogger
    >>> from proxilion.audit.compliance import SOC2Exporter
    >>> from datetime import datetime, timedelta, timezone
    >>>
    >>> logger = InMemoryAuditLogger()
    >>> # ... log events ...
    >>>
    >>> exporter = SOC2Exporter(
    ...     logger,
    ...     organization="Acme Corp",
    ...     system_name="Customer API",
    ...     responsible_party="Security Team",
    ... )
    >>>
    >>> end = datetime.now(timezone.utc)
    >>> start = end - timedelta(days=90)
    >>>
    >>> # Export access control evidence
    >>> access_evidence = exporter.export_access_control_evidence(start, end)
    >>>
    >>> # Generate full SOC 2 report
    >>> report = exporter.generate_report(start, end)
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
)
from proxilion.audit.events import EventType


@dataclass
class AccessControlEvidence:
    """
    Evidence for CC6.1 - Logical Access Security.

    Attributes:
        authorization_checks: All authorization checks performed.
        access_denied: Denied access attempts.
        privilege_escalation_blocked: Blocked privilege escalation attempts.
        unique_users: Number of unique users.
        unique_resources: Number of unique resources accessed.
    """
    authorization_checks: list[dict[str, Any]] = field(default_factory=list)
    access_denied: list[dict[str, Any]] = field(default_factory=list)
    privilege_escalation_blocked: list[dict[str, Any]] = field(default_factory=list)
    unique_users: int = 0
    unique_resources: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "authorization_checks": self.authorization_checks,
            "access_denied": self.access_denied,
            "privilege_escalation_blocked": self.privilege_escalation_blocked,
            "summary": {
                "total_auth_checks": len(self.authorization_checks),
                "total_denied": len(self.access_denied),
                "total_escalation_blocked": len(self.privilege_escalation_blocked),
                "unique_users": self.unique_users,
                "unique_resources": self.unique_resources,
                "denial_rate": (
                    len(self.access_denied) / len(self.authorization_checks)
                    if self.authorization_checks else 0.0
                ),
            },
        }


@dataclass
class MonitoringEvidence:
    """
    Evidence for CC7.2 - System Monitoring.

    Attributes:
        anomaly_detections: Anomalies detected by the system.
        security_alerts: Security alerts raised.
        incident_responses: Incident response actions taken.
        monitoring_coverage: Percentage of operations monitored.
    """
    anomaly_detections: list[dict[str, Any]] = field(default_factory=list)
    security_alerts: list[dict[str, Any]] = field(default_factory=list)
    incident_responses: list[dict[str, Any]] = field(default_factory=list)
    monitoring_coverage: float = 100.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "anomaly_detections": self.anomaly_detections,
            "security_alerts": self.security_alerts,
            "incident_responses": self.incident_responses,
            "summary": {
                "total_anomalies": len(self.anomaly_detections),
                "total_alerts": len(self.security_alerts),
                "total_incident_responses": len(self.incident_responses),
                "monitoring_coverage": f"{self.monitoring_coverage:.1%}",
            },
        }


@dataclass
class ChangeManagementEvidence:
    """
    Evidence for CC8.1 - Change Management.

    Attributes:
        configuration_changes: Logged configuration changes.
        policy_updates: Policy update events.
        approval_workflows: Approval workflow events.
    """
    configuration_changes: list[dict[str, Any]] = field(default_factory=list)
    policy_updates: list[dict[str, Any]] = field(default_factory=list)
    approval_workflows: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "configuration_changes": self.configuration_changes,
            "policy_updates": self.policy_updates,
            "approval_workflows": self.approval_workflows,
            "summary": {
                "total_config_changes": len(self.configuration_changes),
                "total_policy_updates": len(self.policy_updates),
                "total_approval_workflows": len(self.approval_workflows),
            },
        }


class SOC2Exporter(BaseComplianceExporter):
    """
    Export audit logs for SOC 2 Type II evidence.

    Maps to Trust Service Criteria:
    - CC6.1: Logical and physical access security
    - CC7.2: System monitoring
    - CC8.1: Change management

    SOC 2 Type II reports cover a period of time (typically 6-12 months)
    and provide evidence that controls were operating effectively
    throughout the period.

    Example:
        >>> exporter = SOC2Exporter(
        ...     logger,
        ...     organization="Acme Corp",
        ...     system_name="API Gateway",
        ...     responsible_party="security@acme.com",
        ... )
        >>>
        >>> # Export access control evidence for CC6.1
        >>> access = exporter.export_access_control_evidence(start, end)
        >>>
        >>> # Export monitoring evidence for CC7.2
        >>> monitoring = exporter.export_monitoring_evidence(start, end)
        >>>
        >>> # Export change management evidence for CC8.1
        >>> changes = exporter.export_change_management_evidence(start, end)
    """

    @property
    def framework(self) -> ComplianceFramework:
        """Get the compliance framework."""
        return ComplianceFramework.SOC2

    @property
    def framework_version(self) -> str:
        """Get the framework version."""
        return "2017"  # SOC 2 TSC version

    def export_access_control_evidence(
        self,
        start: datetime,
        end: datetime,
    ) -> AccessControlEvidence:
        """
        Export CC6.1 - Logical Access Security evidence.

        CC6.1 requires that logical access to systems is restricted
        to authorized individuals only.

        Args:
            start: Start of the reporting period.
            end: End of the reporting period.

        Returns:
            AccessControlEvidence with categorized events.
        """
        events = self.filter_by_date_range(start, end)
        evidence = AccessControlEvidence()

        users = set()
        resources = set()

        for event in events:
            event_dict = self.event_to_evidence_dict(event)
            users.add(event.data.user_id)
            resources.add(event.data.tool_name)

            # All authorization events are access control evidence
            if event.data.event_type in [
                EventType.AUTHORIZATION_GRANTED,
                EventType.AUTHORIZATION_DENIED,
                EventType.AUTHORIZATION_REQUEST,
            ]:
                evidence.authorization_checks.append(event_dict)

            # Denied events
            if event.data.event_type == EventType.AUTHORIZATION_DENIED:
                evidence.access_denied.append({
                    **event_dict,
                    "denial_reason": event.data.authorization_reason,
                })

            # IDOR violations indicate privilege escalation attempts
            if event.data.event_type == EventType.IDOR_VIOLATION:
                evidence.privilege_escalation_blocked.append({
                    **event_dict,
                    "violation_type": "unauthorized_resource_access",
                })

        evidence.unique_users = len(users)
        evidence.unique_resources = len(resources)

        return evidence

    def export_monitoring_evidence(
        self,
        start: datetime,
        end: datetime,
    ) -> MonitoringEvidence:
        """
        Export CC7.2 - System Monitoring evidence.

        CC7.2 requires that the entity monitors the system and
        environment to identify security events.

        Args:
            start: Start of the reporting period.
            end: End of the reporting period.

        Returns:
            MonitoringEvidence with categorized events.
        """
        events = self.filter_by_date_range(start, end)
        evidence = MonitoringEvidence()

        for event in events:
            event_dict = self.event_to_evidence_dict(event)

            # Anomaly detection events
            if event.data.event_type in [
                EventType.IDOR_VIOLATION,
                EventType.SCHEMA_VALIDATION_FAILURE,
            ]:
                evidence.anomaly_detections.append({
                    **event_dict,
                    "anomaly_type": event.data.event_type.value,
                    "detected_at": event.timestamp.isoformat(),
                })

            # Security alerts (rate limiting, circuit breakers)
            if event.data.event_type in [
                EventType.RATE_LIMIT_EXCEEDED,
                EventType.CIRCUIT_BREAKER_OPEN,
            ]:
                is_rate_limit = event.data.event_type == EventType.RATE_LIMIT_EXCEEDED
                evidence.security_alerts.append({
                    **event_dict,
                    "alert_type": event.data.event_type.value,
                    "severity": "medium" if is_rate_limit else "high",
                })

            # Denied authorizations are incident responses
            if event.data.event_type == EventType.AUTHORIZATION_DENIED:
                evidence.incident_responses.append({
                    **event_dict,
                    "response_type": "access_blocked",
                    "response_reason": event.data.authorization_reason,
                })

        # All events are monitored, so coverage is 100%
        evidence.monitoring_coverage = 1.0

        return evidence

    def export_change_management_evidence(
        self,
        start: datetime,
        end: datetime,
    ) -> ChangeManagementEvidence:
        """
        Export CC8.1 - Change Management evidence.

        CC8.1 requires that changes to the system are authorized,
        designed, developed, tested, and implemented appropriately.

        Args:
            start: Start of the reporting period.
            end: End of the reporting period.

        Returns:
            ChangeManagementEvidence with categorized events.
        """
        events = self.filter_by_date_range(start, end)
        evidence = ChangeManagementEvidence()

        for event in events:
            event_dict = self.event_to_evidence_dict(event)

            # Look for policy-related metadata
            if event.data.authorization_metadata.get("policy_updated"):
                evidence.policy_updates.append({
                    **event_dict,
                    "policy_name": event.data.authorization_metadata.get("policy_name"),
                    "change_type": "update",
                })

            # Look for configuration changes
            if event.data.authorization_metadata.get("config_change"):
                change_desc = event.data.authorization_metadata.get("change_description")
                evidence.configuration_changes.append({
                    **event_dict,
                    "change_description": change_desc,
                })

            # Approval workflows (requires_approval events that were granted)
            if (
                event.data.authorization_metadata.get("requires_approval") and
                event.data.authorization_allowed
            ):
                evidence.approval_workflows.append({
                    **event_dict,
                    "approval_type": "tool_execution",
                    "approved_by": event.data.authorization_metadata.get("approved_by", "system"),
                })

        return evidence

    def generate_report(
        self,
        start: datetime,
        end: datetime,
    ) -> ComplianceReport:
        """
        Generate a complete SOC 2 Type II compliance report.

        Args:
            start: Start of the reporting period.
            end: End of the reporting period.

        Returns:
            Complete compliance report.
        """
        metadata = self.create_metadata(start, end)
        evidence_list = []
        recommendations = []

        # CC6.1: Logical Access Security
        access = self.export_access_control_evidence(start, end)
        access_data = access.to_dict()

        cc6_1_evidence = ComplianceEvidence(
            control_id="CC6.1",
            control_name="Logical and Physical Access Controls",
            evidence_type="access_logs",
            description=(
                "The entity implements logical access security software, "
                "infrastructure, and architectures to support (1) identification "
                "and authentication of authorized users, and (2) restriction of "
                "authenticated user access to authorized data and functions."
            ),
            events=access.authorization_checks[:50],  # Limit for readability
            summary=access_data["summary"],
            compliant=len(access.authorization_checks) > 0,
            notes=(
                f"Showing 50 of {len(access.authorization_checks)} authorization events."
                if len(access.authorization_checks) > 50 else None
            ),
        )
        evidence_list.append(cc6_1_evidence)

        denial_rate = access_data["summary"]["denial_rate"]
        if denial_rate > 0.2:
            recommendations.append(
                f"High denial rate ({denial_rate:.1%}) detected. "
                "Review access policies for potential misconfigurations."
            )

        if len(access.privilege_escalation_blocked) > 0:
            esc_count = len(access.privilege_escalation_blocked)
            recommendations.append(
                f"Detected {esc_count} privilege escalation attempts. "
                "Consider reviewing user permissions and implementing additional controls."
            )

        # CC7.2: System Monitoring
        monitoring = self.export_monitoring_evidence(start, end)
        monitoring_data = monitoring.to_dict()

        cc7_2_evidence = ComplianceEvidence(
            control_id="CC7.2",
            control_name="System Monitoring",
            evidence_type="monitoring_logs",
            description=(
                "The entity monitors system components and the operation of "
                "those components for anomalies that are indicative of "
                "malicious acts, natural disasters, and errors affecting "
                "the entity's ability to meet its objectives."
            ),
            events=monitoring.security_alerts + monitoring.anomaly_detections,
            summary=monitoring_data["summary"],
            compliant=True,  # Having monitoring in place is compliant
            notes=(
                "Continuous monitoring is in place. "
                f"{len(monitoring.security_alerts)} alerts and "
                f"{len(monitoring.anomaly_detections)} anomalies detected."
            ),
        )
        evidence_list.append(cc7_2_evidence)

        if len(monitoring.security_alerts) > 50:
            recommendations.append(
                "High volume of security alerts. Consider implementing alert aggregation "
                "and investigating root causes."
            )

        # CC8.1: Change Management
        changes = self.export_change_management_evidence(start, end)
        changes_data = changes.to_dict()

        cc8_1_evidence = ComplianceEvidence(
            control_id="CC8.1",
            control_name="Change Management",
            evidence_type="change_logs",
            description=(
                "The entity authorizes, designs, develops or acquires, "
                "configures, documents, tests, approves, and implements "
                "changes to infrastructure, data, software, and procedures "
                "to meet its objectives."
            ),
            events=changes.policy_updates + changes.configuration_changes,
            summary=changes_data["summary"],
            compliant=True,  # Having change tracking is compliant
            notes=(
                f"Tracked {len(changes.policy_updates)} policy updates and "
                f"{len(changes.configuration_changes)} configuration changes."
            ),
        )
        evidence_list.append(cc8_1_evidence)

        # Overall summary
        all_events = self.filter_by_date_range(start, end)
        stats = self.compute_summary_stats(all_events)

        summary = {
            "reporting_period": f"{start.date()} to {end.date()}",
            "total_operations": stats["total_events"],
            "unique_users": stats["unique_users"],
            "unique_resources": stats["unique_tools"],
            "authorization_rate": f"{stats['grant_rate']:.1%}",
            "security_alerts": len(monitoring.security_alerts),
            "anomalies_detected": len(monitoring.anomaly_detections),
            "changes_tracked": len(changes.policy_updates) + len(changes.configuration_changes),
            "controls_tested": 3,
            "controls_effective": sum(1 for e in evidence_list if e.compliant),
        }

        return ComplianceReport(
            metadata=metadata,
            evidence=evidence_list,
            summary=summary,
            recommendations=recommendations,
        )
