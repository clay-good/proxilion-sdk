"""
ISO 27001 compliance exporter.

Provides audit log export formats for ISO 27001 compliance,
mapping to Annex A controls including:
- A.9: Access Control
- A.12: Operations Security
- A.16: Information Security Incident Management

Example:
    >>> from proxilion.audit import InMemoryAuditLogger
    >>> from proxilion.audit.compliance import ISO27001Exporter
    >>> from datetime import datetime, timedelta, timezone
    >>>
    >>> logger = InMemoryAuditLogger()
    >>> # ... log events ...
    >>>
    >>> exporter = ISO27001Exporter(
    ...     logger,
    ...     organization="Acme Corp",
    ...     system_name="Enterprise API",
    ...     responsible_party="ISMS Manager",
    ... )
    >>>
    >>> end = datetime.now(timezone.utc)
    >>> start = end - timedelta(days=365)
    >>>
    >>> # Export access control evidence (A.9)
    >>> access = exporter.export_access_control_a9(start, end)
    >>>
    >>> # Generate full ISO 27001 report
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
class AccessControlA9Evidence:
    """
    Evidence for A.9 - Access Control.

    Covers:
    - A.9.1: Business requirements of access control
    - A.9.2: User access management
    - A.9.4: System and application access control
    """
    user_access_events: list[dict[str, Any]] = field(default_factory=list)
    access_denied_events: list[dict[str, Any]] = field(default_factory=list)
    privileged_access_events: list[dict[str, Any]] = field(default_factory=list)
    unique_users: int = 0
    unique_resources: int = 0
    role_distribution: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        total = len(self.user_access_events)
        denied = len(self.access_denied_events)
        return {
            "user_access_events": self.user_access_events,
            "access_denied_events": self.access_denied_events,
            "privileged_access_events": self.privileged_access_events,
            "summary": {
                "total_access_events": total,
                "access_denied": denied,
                "privileged_access": len(self.privileged_access_events),
                "unique_users": self.unique_users,
                "unique_resources": self.unique_resources,
                "denial_rate": denied / total if total > 0 else 0.0,
                "role_distribution": self.role_distribution,
            },
        }


@dataclass
class OperationsSecurityA12Evidence:
    """
    Evidence for A.12 - Operations Security.

    Covers:
    - A.12.1: Operational procedures and responsibilities
    - A.12.4: Logging and monitoring
    - A.12.6: Technical vulnerability management
    """
    operational_events: list[dict[str, Any]] = field(default_factory=list)
    logging_events: list[dict[str, Any]] = field(default_factory=list)
    vulnerability_events: list[dict[str, Any]] = field(default_factory=list)
    monitoring_active: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "operational_events": self.operational_events,
            "logging_events": self.logging_events,
            "vulnerability_events": self.vulnerability_events,
            "summary": {
                "total_operations": len(self.operational_events),
                "logging_events": len(self.logging_events),
                "vulnerabilities_detected": len(self.vulnerability_events),
                "monitoring_status": "Active" if self.monitoring_active else "Inactive",
            },
        }


@dataclass
class IncidentManagementA16Evidence:
    """
    Evidence for A.16 - Information Security Incident Management.

    Covers:
    - A.16.1: Management of security incidents
    """
    security_incidents: list[dict[str, Any]] = field(default_factory=list)
    incident_responses: list[dict[str, Any]] = field(default_factory=list)
    incident_by_severity: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "security_incidents": self.security_incidents,
            "incident_responses": self.incident_responses,
            "summary": {
                "total_incidents": len(self.security_incidents),
                "incidents_responded": len(self.incident_responses),
                "response_rate": (
                    len(self.incident_responses) / len(self.security_incidents)
                    if self.security_incidents else 1.0
                ),
                "by_severity": self.incident_by_severity,
            },
        }


class ISO27001Exporter(BaseComplianceExporter):
    """
    Export audit logs for ISO 27001 evidence.

    Maps to Annex A controls:
    - A.9: Access control
    - A.12: Operations security
    - A.16: Incident management

    ISO 27001 is an international standard for information security
    management systems (ISMS). This exporter produces evidence
    for key controls related to access, operations, and incidents.

    Example:
        >>> exporter = ISO27001Exporter(
        ...     logger,
        ...     organization="Acme Corp",
        ...     system_name="Core Platform",
        ...     responsible_party="isms@acme.com",
        ... )
        >>>
        >>> # Export A.9 Access Control evidence
        >>> access = exporter.export_access_control_a9(start, end)
        >>>
        >>> # Export A.12 Operations Security evidence
        >>> ops = exporter.export_operations_security_a12(start, end)
        >>>
        >>> # Export A.16 Incident Management evidence
        >>> incidents = exporter.export_incident_management_a16(start, end)
    """

    @property
    def framework(self) -> ComplianceFramework:
        """Get the compliance framework."""
        return ComplianceFramework.ISO27001

    @property
    def framework_version(self) -> str:
        """Get the framework version."""
        return "2022"  # ISO 27001:2022

    def export_access_control_a9(
        self,
        start: datetime,
        end: datetime,
    ) -> AccessControlA9Evidence:
        """
        Export A.9 - Access Control evidence.

        A.9 covers:
        - A.9.1.1: Access control policy
        - A.9.2.1: User registration and de-registration
        - A.9.2.2: User access provisioning
        - A.9.2.3: Management of privileged access rights
        - A.9.4.1: Information access restriction

        Args:
            start: Start of the reporting period.
            end: End of the reporting period.

        Returns:
            AccessControlA9Evidence with categorized events.
        """
        events = self.filter_by_date_range(start, end)
        evidence = AccessControlA9Evidence()

        users = set()
        resources = set()
        role_counts: dict[str, int] = {}

        for event in events:
            event_dict = self.event_to_evidence_dict(event)
            users.add(event.data.user_id)
            resources.add(event.data.tool_name)

            # Count roles
            for role in event.data.user_roles:
                role_counts[role] = role_counts.get(role, 0) + 1

            # All authorization events are access control evidence
            if event.data.event_type in [
                EventType.AUTHORIZATION_GRANTED,
                EventType.AUTHORIZATION_DENIED,
                EventType.AUTHORIZATION_REQUEST,
            ]:
                evidence.user_access_events.append({
                    **event_dict,
                    "control": "A.9.4.1",
                    "access_type": "granted" if event.data.authorization_allowed else "denied",
                })

            # Denied access events
            if event.data.event_type == EventType.AUTHORIZATION_DENIED:
                evidence.access_denied_events.append({
                    **event_dict,
                    "control": "A.9.4.1",
                    "denial_reason": event.data.authorization_reason,
                })

            # Privileged access (admin roles or high-risk tools)
            is_admin = "admin" in event.data.user_roles
            is_high_risk = event.data.authorization_metadata.get("risk_level") == "high"
            if is_admin or is_high_risk:
                evidence.privileged_access_events.append({
                    **event_dict,
                    "control": "A.9.2.3",
                    "privilege_type": "admin" if is_admin else "high_risk_tool",
                })

        evidence.unique_users = len(users)
        evidence.unique_resources = len(resources)
        evidence.role_distribution = role_counts

        return evidence

    def export_operations_security_a12(
        self,
        start: datetime,
        end: datetime,
    ) -> OperationsSecurityA12Evidence:
        """
        Export A.12 - Operations Security evidence.

        A.12 covers:
        - A.12.1.1: Documented operating procedures
        - A.12.4.1: Event logging
        - A.12.4.3: Administrator and operator logs
        - A.12.6.1: Management of technical vulnerabilities

        Args:
            start: Start of the reporting period.
            end: End of the reporting period.

        Returns:
            OperationsSecurityA12Evidence with categorized events.
        """
        events = self.filter_by_date_range(start, end)
        evidence = OperationsSecurityA12Evidence()

        for event in events:
            event_dict = self.event_to_evidence_dict(event)

            # All events demonstrate logging (A.12.4.1)
            evidence.logging_events.append({
                **event_dict,
                "control": "A.12.4.1",
                "log_type": "authorization",
            })

            # Operational events (successful executions)
            if event.data.event_type in [
                EventType.TOOL_EXECUTION_SUCCESS,
                EventType.AUTHORIZATION_GRANTED,
            ]:
                evidence.operational_events.append({
                    **event_dict,
                    "control": "A.12.1.1",
                    "operation_status": "success",
                })

            # Vulnerability-related events
            if event.data.event_type in [
                EventType.IDOR_VIOLATION,
                EventType.SCHEMA_VALIDATION_FAILURE,
            ]:
                evidence.vulnerability_events.append({
                    **event_dict,
                    "control": "A.12.6.1",
                    "vulnerability_type": event.data.event_type.value,
                    "mitigation": "Request blocked by security control",
                })

        return evidence

    def export_incident_management_a16(
        self,
        start: datetime,
        end: datetime,
    ) -> IncidentManagementA16Evidence:
        """
        Export A.16 - Incident Management evidence.

        A.16 covers:
        - A.16.1.1: Responsibilities and procedures
        - A.16.1.2: Reporting information security events
        - A.16.1.4: Assessment of and decision on security events
        - A.16.1.5: Response to security incidents

        Args:
            start: Start of the reporting period.
            end: End of the reporting period.

        Returns:
            IncidentManagementA16Evidence with categorized events.
        """
        events = self.filter_by_date_range(start, end)
        evidence = IncidentManagementA16Evidence()

        severity_counts: dict[str, int] = {
            "low": 0,
            "medium": 0,
            "high": 0,
            "critical": 0,
        }

        for event in events:
            event_dict = self.event_to_evidence_dict(event)

            # Security incidents
            if event.data.event_type in [
                EventType.RATE_LIMIT_EXCEEDED,
                EventType.CIRCUIT_BREAKER_OPEN,
                EventType.IDOR_VIOLATION,
                EventType.SCHEMA_VALIDATION_FAILURE,
            ]:
                # Determine severity
                if event.data.event_type == EventType.IDOR_VIOLATION:
                    severity = "critical"
                elif event.data.event_type == EventType.CIRCUIT_BREAKER_OPEN:
                    severity = "high"
                elif event.data.event_type == EventType.SCHEMA_VALIDATION_FAILURE:
                    severity = "medium"
                else:
                    severity = "low"

                severity_counts[severity] += 1

                incident = {
                    **event_dict,
                    "control": "A.16.1.2",
                    "incident_type": event.data.event_type.value,
                    "severity": severity,
                    "reported_at": event.timestamp.isoformat(),
                }
                evidence.security_incidents.append(incident)

                # All detected incidents have automated response
                evidence.incident_responses.append({
                    **incident,
                    "control": "A.16.1.5",
                    "response_type": "automated_block",
                    "response_time_ms": 0,  # Immediate
                    "resolution": "Request blocked by security control",
                })

            # Authorization denials are also security events
            if event.data.event_type == EventType.AUTHORIZATION_DENIED:
                severity_counts["low"] += 1
                evidence.security_incidents.append({
                    **event_dict,
                    "control": "A.16.1.2",
                    "incident_type": "access_denied",
                    "severity": "low",
                    "reported_at": event.timestamp.isoformat(),
                })
                evidence.incident_responses.append({
                    **event_dict,
                    "control": "A.16.1.5",
                    "response_type": "access_blocked",
                    "response_time_ms": 0,
                    "resolution": event.data.authorization_reason,
                })

        evidence.incident_by_severity = severity_counts

        return evidence

    def generate_report(
        self,
        start: datetime,
        end: datetime,
    ) -> ComplianceReport:
        """
        Generate a complete ISO 27001 compliance report.

        Args:
            start: Start of the reporting period.
            end: End of the reporting period.

        Returns:
            Complete compliance report.
        """
        metadata = self.create_metadata(start, end)
        evidence_list = []
        recommendations = []

        # A.9: Access Control
        access = self.export_access_control_a9(start, end)
        access_data = access.to_dict()

        a9_evidence = ComplianceEvidence(
            control_id="A.9",
            control_name="Access Control",
            evidence_type="access_logs",
            description=(
                "Evidence of access control implementation covering user access "
                "management (A.9.2), system and application access control (A.9.4), "
                "and management of privileged access rights (A.9.2.3)."
            ),
            events=access.user_access_events[:50],
            summary=access_data["summary"],
            compliant=len(access.user_access_events) > 0,
            notes=(
                f"Monitoring {access.unique_users} users across "
                f"{access.unique_resources} resources. "
                f"{len(access.privileged_access_events)} privileged access events tracked."
            ),
        )
        evidence_list.append(a9_evidence)

        if access_data["summary"]["denial_rate"] > 0.3:
            recommendations.append(
                "High access denial rate detected. Review access policies and user permissions."
            )

        # A.12: Operations Security
        ops = self.export_operations_security_a12(start, end)
        ops_data = ops.to_dict()

        a12_evidence = ComplianceEvidence(
            control_id="A.12",
            control_name="Operations Security",
            evidence_type="operational_logs",
            description=(
                "Evidence of operations security including event logging (A.12.4.1), "
                "operational procedures (A.12.1.1), and technical vulnerability "
                "management (A.12.6.1)."
            ),
            events=ops.logging_events[:50],
            summary=ops_data["summary"],
            compliant=ops.monitoring_active,
            notes=(
                f"Logging is active with {len(ops.logging_events)} events recorded. "
                f"{len(ops.vulnerability_events)} potential vulnerabilities detected and mitigated."
            ),
        )
        evidence_list.append(a12_evidence)

        if len(ops.vulnerability_events) > 10:
            recommendations.append(
                "Multiple vulnerability events detected. Conduct a security review "
                "and consider additional input validation controls."
            )

        # A.16: Incident Management
        incidents = self.export_incident_management_a16(start, end)
        incidents_data = incidents.to_dict()

        a16_evidence = ComplianceEvidence(
            control_id="A.16",
            control_name="Information Security Incident Management",
            evidence_type="incident_logs",
            description=(
                "Evidence of incident management including security event reporting "
                "(A.16.1.2) and incident response (A.16.1.5)."
            ),
            events=incidents.security_incidents[:50],
            summary=incidents_data["summary"],
            compliant=incidents_data["summary"]["response_rate"] >= 0.95,
            notes=(
                f"{len(incidents.security_incidents)} security events detected. "
                f"Response rate: {incidents_data['summary']['response_rate']:.1%}. "
                f"By severity: {incidents.incident_by_severity}"
            ),
        )
        evidence_list.append(a16_evidence)

        if incidents.incident_by_severity.get("critical", 0) > 0:
            recommendations.append(
                f"Critical incidents detected ({incidents.incident_by_severity['critical']}). "
                "Review root causes and implement preventive controls."
            )

        # Overall summary
        all_events = self.filter_by_date_range(start, end)
        stats = self.compute_summary_stats(all_events)

        summary = {
            "reporting_period": f"{start.date()} to {end.date()}",
            "framework_version": "ISO 27001:2022",
            "total_events_analyzed": stats["total_events"],
            "unique_users": stats["unique_users"],
            "unique_resources": stats["unique_tools"],
            "controls_assessed": 3,
            "controls_compliant": sum(1 for e in evidence_list if e.compliant),
            "security_incidents": len(incidents.security_incidents),
            "incident_response_rate": f"{incidents_data['summary']['response_rate']:.1%}",
            "privileged_access_events": len(access.privileged_access_events),
            "overall_status": (
                "Compliant" if all(e.compliant for e in evidence_list) else "Review Required"
            ),
        }

        return ComplianceReport(
            metadata=metadata,
            evidence=evidence_list,
            summary=summary,
            recommendations=recommendations,
        )
