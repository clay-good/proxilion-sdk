"""
Compliance-ready audit export formats.

This module provides exporters that transform audit logs into
compliance-ready formats for various regulatory frameworks:

- EU AI Act (Article 14, 15, 17 requirements)
- SOC 2 Type II (Trust Service Criteria)
- ISO 27001 (Annex A controls)

Each exporter provides framework-specific evidence gathering,
report generation, and export capabilities.

Quick Start:
    >>> from proxilion.audit import InMemoryAuditLogger
    >>> from proxilion.audit.compliance import (
    ...     EUAIActExporter,
    ...     SOC2Exporter,
    ...     ISO27001Exporter,
    ... )
    >>> from datetime import datetime, timedelta, timezone
    >>>
    >>> # Create logger and log some events
    >>> logger = InMemoryAuditLogger()
    >>> # ... log events ...
    >>>
    >>> # Define reporting period
    >>> end = datetime.now(timezone.utc)
    >>> start = end - timedelta(days=90)
    >>>
    >>> # EU AI Act compliance
    >>> eu_exporter = EUAIActExporter(
    ...     logger,
    ...     organization="Acme Corp",
    ...     system_name="Customer AI",
    ...     responsible_party="AI Team",
    ... )
    >>> eu_report = eu_exporter.generate_report(start, end)
    >>>
    >>> # SOC 2 compliance
    >>> soc2_exporter = SOC2Exporter(logger, organization="Acme Corp")
    >>> soc2_report = soc2_exporter.generate_report(start, end)
    >>>
    >>> # ISO 27001 compliance
    >>> iso_exporter = ISO27001Exporter(logger, organization="Acme Corp")
    >>> iso_report = iso_exporter.generate_report(start, end)

Export Formats:
    Each exporter supports multiple export formats:

    - JSON: Machine-readable format
    >>> json_output = exporter.export_json(start, end)

    - Markdown: Human-readable report
    >>> markdown_output = exporter.export_markdown(start, end)

    - Report object: Structured Python object
    >>> report = exporter.generate_report(start, end)
    >>> print(report.summary)

Framework-Specific Methods:
    Each exporter also provides framework-specific evidence methods:

    EU AI Act:
    >>> oversight = eu_exporter.export_human_oversight_evidence(start, end)
    >>> trail = eu_exporter.export_decision_audit_trail(start, end)
    >>> risks = eu_exporter.export_risk_assessment_log(start, end)

    SOC 2:
    >>> access = soc2_exporter.export_access_control_evidence(start, end)
    >>> monitoring = soc2_exporter.export_monitoring_evidence(start, end)
    >>> changes = soc2_exporter.export_change_management_evidence(start, end)

    ISO 27001:
    >>> a9 = iso_exporter.export_access_control_a9(start, end)
    >>> a12 = iso_exporter.export_operations_security_a12(start, end)
    >>> a16 = iso_exporter.export_incident_management_a16(start, end)
"""

from proxilion.audit.compliance.base import (
    BaseComplianceExporter,
    ComplianceEvidence,
    ComplianceFramework,
    ComplianceMetadata,
    ComplianceReport,
    EventSource,
)
from proxilion.audit.compliance.eu_ai_act import (
    DecisionAuditTrailEntry,
    EUAIActExporter,
    HumanOversightEvidence,
    RiskAssessmentEntry,
)
from proxilion.audit.compliance.iso27001 import (
    AccessControlA9Evidence,
    IncidentManagementA16Evidence,
    ISO27001Exporter,
    OperationsSecurityA12Evidence,
)
from proxilion.audit.compliance.soc2 import (
    AccessControlEvidence,
    ChangeManagementEvidence,
    MonitoringEvidence,
    SOC2Exporter,
)

__all__ = [
    # Base classes
    "BaseComplianceExporter",
    "ComplianceEvidence",
    "ComplianceFramework",
    "ComplianceMetadata",
    "ComplianceReport",
    "EventSource",
    # EU AI Act
    "EUAIActExporter",
    "DecisionAuditTrailEntry",
    "HumanOversightEvidence",
    "RiskAssessmentEntry",
    # SOC 2
    "SOC2Exporter",
    "AccessControlEvidence",
    "MonitoringEvidence",
    "ChangeManagementEvidence",
    # ISO 27001
    "ISO27001Exporter",
    "AccessControlA9Evidence",
    "OperationsSecurityA12Evidence",
    "IncidentManagementA16Evidence",
]
