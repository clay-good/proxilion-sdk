"""
Base classes for compliance audit exporters.

Provides common infrastructure for exporting audit logs in
compliance-ready formats for various regulatory frameworks.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Protocol, runtime_checkable

from proxilion.audit.events import AuditEventV2, EventType


class ComplianceFramework(Enum):
    """Supported compliance frameworks.

    Currently implemented: EU_AI_ACT, SOC2, ISO27001
    """
    EU_AI_ACT = "eu_ai_act"
    SOC2 = "soc2"
    ISO27001 = "iso27001"


@dataclass
class ComplianceMetadata:
    """
    Metadata for compliance reports.

    Attributes:
        framework: The compliance framework this report targets.
        version: Version of the framework (e.g., "2024").
        organization: Name of the organization.
        system_name: Name of the AI system being audited.
        responsible_party: Contact person/team.
        export_timestamp: When the report was generated.
        period_start: Start of the audit period.
        period_end: End of the audit period.
        additional_info: Any additional metadata.
    """
    framework: ComplianceFramework
    version: str
    organization: str
    system_name: str
    responsible_party: str
    export_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    period_start: datetime | None = None
    period_end: datetime | None = None
    additional_info: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "framework": self.framework.value,
            "version": self.version,
            "organization": self.organization,
            "system_name": self.system_name,
            "responsible_party": self.responsible_party,
            "export_timestamp": self.export_timestamp.isoformat(),
            "period_start": self.period_start.isoformat() if self.period_start else None,
            "period_end": self.period_end.isoformat() if self.period_end else None,
            "additional_info": self.additional_info,
        }


@dataclass
class ComplianceEvidence:
    """
    A piece of evidence for compliance reporting.

    Attributes:
        control_id: The control/article this evidence supports.
        control_name: Human-readable control name.
        evidence_type: Type of evidence (e.g., "log", "configuration").
        description: Description of what this evidence shows.
        events: Relevant audit events.
        summary: Summary statistics.
        compliant: Whether this control appears compliant.
        notes: Additional notes or observations.
    """
    control_id: str
    control_name: str
    evidence_type: str
    description: str
    events: list[dict[str, Any]] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    compliant: bool | None = None
    notes: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "control_id": self.control_id,
            "control_name": self.control_name,
            "evidence_type": self.evidence_type,
            "description": self.description,
            "event_count": len(self.events),
            "events": self.events,
            "summary": self.summary,
            "compliant": self.compliant,
            "notes": self.notes,
        }


@dataclass
class ComplianceReport:
    """
    A complete compliance report.

    Attributes:
        metadata: Report metadata.
        evidence: List of evidence items.
        summary: Overall summary.
        recommendations: Suggested improvements.
    """
    metadata: ComplianceMetadata
    evidence: list[ComplianceEvidence] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "metadata": self.metadata.to_dict(),
            "evidence": [e.to_dict() for e in self.evidence],
            "summary": self.summary,
            "recommendations": self.recommendations,
        }

    def to_json(self, pretty: bool = True) -> str:
        """Convert to JSON string."""
        if pretty:
            return json.dumps(self.to_dict(), indent=2, default=str)
        return json.dumps(self.to_dict(), default=str)


@runtime_checkable
class EventSource(Protocol):
    """Protocol for audit event sources."""

    @property
    def events(self) -> list[AuditEventV2]:
        """Get all events."""
        ...


class BaseComplianceExporter(ABC):
    """
    Base class for compliance exporters.

    Provides common infrastructure for filtering events,
    generating reports, and formatting output.

    Subclasses should implement framework-specific export methods.
    """

    def __init__(
        self,
        event_source: EventSource | list[AuditEventV2],
        organization: str = "",
        system_name: str = "",
        responsible_party: str = "",
    ) -> None:
        """
        Initialize the exporter.

        Args:
            event_source: Source of audit events (logger or list).
            organization: Organization name for reports.
            system_name: AI system name for reports.
            responsible_party: Responsible party for reports.
        """
        self._event_source = event_source
        self._organization = organization
        self._system_name = system_name
        self._responsible_party = responsible_party

    @property
    @abstractmethod
    def framework(self) -> ComplianceFramework:
        """Get the compliance framework this exporter targets."""
        ...

    @property
    @abstractmethod
    def framework_version(self) -> str:
        """Get the version of the compliance framework."""
        ...

    def get_events(self) -> list[AuditEventV2]:
        """Get all events from the source."""
        if isinstance(self._event_source, list):
            return self._event_source
        return self._event_source.events

    def filter_events(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
        event_types: list[EventType] | None = None,
        user_id: str | None = None,
        tool_name: str | None = None,
    ) -> list[AuditEventV2]:
        """
        Filter events by various criteria.

        Args:
            start: Filter events after this timestamp.
            end: Filter events before this timestamp.
            event_types: Filter by event types.
            user_id: Filter by user ID.
            tool_name: Filter by tool name.

        Returns:
            Filtered list of events.
        """
        events = self.get_events()
        filtered = []

        for event in events:
            # Time range filter
            if start and event.timestamp < start:
                continue
            if end and event.timestamp > end:
                continue

            # Event type filter
            if event_types and event.data.event_type not in event_types:
                continue

            # User filter
            if user_id and event.data.user_id != user_id:
                continue

            # Tool filter
            if tool_name and event.data.tool_name != tool_name:
                continue

            filtered.append(event)

        return filtered

    def filter_by_date_range(
        self,
        start: datetime,
        end: datetime,
    ) -> list[AuditEventV2]:
        """Filter events by date range."""
        return self.filter_events(start=start, end=end)

    def get_authorization_events(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> list[AuditEventV2]:
        """Get authorization-related events."""
        return self.filter_events(
            start=start,
            end=end,
            event_types=[
                EventType.AUTHORIZATION_GRANTED,
                EventType.AUTHORIZATION_DENIED,
                EventType.AUTHORIZATION_REQUEST,
            ],
        )

    def get_denied_events(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> list[AuditEventV2]:
        """Get denied authorization events."""
        return self.filter_events(
            start=start,
            end=end,
            event_types=[EventType.AUTHORIZATION_DENIED],
        )

    def get_security_events(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> list[AuditEventV2]:
        """Get security-related events."""
        return self.filter_events(
            start=start,
            end=end,
            event_types=[
                EventType.RATE_LIMIT_EXCEEDED,
                EventType.CIRCUIT_BREAKER_OPEN,
                EventType.IDOR_VIOLATION,
                EventType.SCHEMA_VALIDATION_FAILURE,
            ],
        )

    def event_to_evidence_dict(self, event: AuditEventV2) -> dict[str, Any]:
        """Convert an event to an evidence dictionary."""
        return {
            "event_id": event.event_id,
            "timestamp": event.timestamp.isoformat(),
            "event_type": event.data.event_type.value,
            "user_id": event.data.user_id,
            "user_roles": event.data.user_roles,
            "tool_name": event.data.tool_name,
            "authorized": event.data.authorization_allowed,
            "reason": event.data.authorization_reason,
            "policies": event.data.policies_evaluated,
        }

    def create_metadata(
        self,
        period_start: datetime | None = None,
        period_end: datetime | None = None,
    ) -> ComplianceMetadata:
        """Create metadata for a report."""
        return ComplianceMetadata(
            framework=self.framework,
            version=self.framework_version,
            organization=self._organization,
            system_name=self._system_name,
            responsible_party=self._responsible_party,
            period_start=period_start,
            period_end=period_end,
        )

    def compute_summary_stats(
        self,
        events: list[AuditEventV2],
    ) -> dict[str, Any]:
        """Compute summary statistics for a list of events."""
        if not events:
            return {
                "total_events": 0,
                "unique_users": 0,
                "unique_tools": 0,
                "authorization_granted": 0,
                "authorization_denied": 0,
                "grant_rate": 0.0,
            }

        granted = sum(1 for e in events if e.data.authorization_allowed)
        denied = sum(1 for e in events if not e.data.authorization_allowed)
        users = {e.data.user_id for e in events}
        tools = {e.data.tool_name for e in events}

        return {
            "total_events": len(events),
            "unique_users": len(users),
            "unique_tools": len(tools),
            "authorization_granted": granted,
            "authorization_denied": denied,
            "grant_rate": granted / len(events) if events else 0.0,
            "period_start": min(e.timestamp for e in events).isoformat(),
            "period_end": max(e.timestamp for e in events).isoformat(),
        }

    @abstractmethod
    def generate_report(
        self,
        start: datetime,
        end: datetime,
    ) -> ComplianceReport:
        """
        Generate a compliance report for the given period.

        Args:
            start: Start of the reporting period.
            end: End of the reporting period.

        Returns:
            Complete compliance report.
        """
        ...

    def export_json(
        self,
        start: datetime,
        end: datetime,
        pretty: bool = True,
    ) -> str:
        """Export report as JSON."""
        report = self.generate_report(start, end)
        return report.to_json(pretty=pretty)

    def export_markdown(
        self,
        start: datetime,
        end: datetime,
    ) -> str:
        """Export report as Markdown."""
        report = self.generate_report(start, end)
        return self._report_to_markdown(report)

    def _report_to_markdown(self, report: ComplianceReport) -> str:
        """Convert a report to Markdown format."""
        lines = [
            f"# {report.metadata.framework.value.upper()} Compliance Report",
            "",
            "## Metadata",
            "",
            f"- **Organization:** {report.metadata.organization}",
            f"- **System:** {report.metadata.system_name}",
            f"- **Responsible Party:** {report.metadata.responsible_party}",
            f"- **Report Generated:** {report.metadata.export_timestamp.isoformat()}",
            f"- **Period:** "
            f"{report.metadata.period_start.isoformat() if report.metadata.period_start else 'N/A'}"
            f" to "
            f"{report.metadata.period_end.isoformat() if report.metadata.period_end else 'N/A'}",
            "",
            "## Summary",
            "",
        ]

        for key, value in report.summary.items():
            lines.append(f"- **{key.replace('_', ' ').title()}:** {value}")

        lines.extend(["", "## Evidence", ""])

        for evidence in report.evidence:
            lines.extend([
                f"### {evidence.control_id}: {evidence.control_name}",
                "",
                f"**Type:** {evidence.evidence_type}",
                "",
                evidence.description,
                "",
                f"**Events:** {len(evidence.events)}",
                "",
            ])

            if evidence.summary:
                lines.append("**Summary:**")
                for key, value in evidence.summary.items():
                    lines.append(f"- {key}: {value}")
                lines.append("")

            if evidence.compliant is not None:
                status = "Compliant" if evidence.compliant else "Non-Compliant"
                lines.append(f"**Status:** {status}")
                lines.append("")

            if evidence.notes:
                lines.append(f"**Notes:** {evidence.notes}")
                lines.append("")

        if report.recommendations:
            lines.extend(["## Recommendations", ""])
            for i, rec in enumerate(report.recommendations, 1):
                lines.append(f"{i}. {rec}")
            lines.append("")

        return "\n".join(lines)
