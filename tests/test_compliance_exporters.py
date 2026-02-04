"""
Tests for compliance audit exporters.

Tests the EU AI Act, SOC 2, and ISO 27001 exporters including:
- Export format validation
- Framework-specific criteria mapping
- Date range filtering
- Report generation
- Hash chain integrity in exports
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from proxilion.audit import (
    AuditEventData,
    AuditEventV2,
    EventType,
    InMemoryAuditLogger,
)
from proxilion.audit.compliance import (
    AccessControlA9Evidence,
    AccessControlEvidence,
    # Base
    ChangeManagementEvidence,
    ComplianceEvidence,
    ComplianceFramework,
    ComplianceMetadata,
    ComplianceReport,
    DecisionAuditTrailEntry,
    # EU AI Act
    EUAIActExporter,
    HumanOversightEvidence,
    IncidentManagementA16Evidence,
    # ISO 27001
    ISO27001Exporter,
    MonitoringEvidence,
    OperationsSecurityA12Evidence,
    SOC2Exporter,
)

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def now():
    """Current UTC time (with small buffer for test execution)."""
    return datetime.now(timezone.utc) + timedelta(seconds=5)


@pytest.fixture
def start(now):
    """Start of reporting period (30 days ago)."""
    return now - timedelta(days=30) - timedelta(seconds=10)


@pytest.fixture
def logger():
    """Create an in-memory audit logger."""
    return InMemoryAuditLogger()


@pytest.fixture
def populated_logger(logger, now):
    """Create a logger with sample events."""
    # Authorization granted events
    for i in range(5):
        logger.log_authorization(
            user_id=f"user_{i}",
            user_roles=["analyst"],
            tool_name="search_database",
            tool_arguments={"query": f"test query {i}"},
            allowed=True,
            reason="User has required permissions",
            policies_evaluated=["SearchPolicy"],
        )

    # Authorization denied events
    for i in range(3):
        logger.log_authorization(
            user_id=f"user_{i}",
            user_roles=["guest"],
            tool_name="admin_tool",
            tool_arguments={"action": "delete"},
            allowed=False,
            reason="Insufficient permissions",
            policies_evaluated=["AdminPolicy"],
        )

    # Admin user events
    logger.log_authorization(
        user_id="admin_user",
        user_roles=["admin", "user"],
        tool_name="delete_records",
        tool_arguments={"table": "users"},
        allowed=True,
        reason="Admin role granted",
        policies_evaluated=["AdminPolicy"],
    )

    # High-risk tool event
    event_data = AuditEventData(
        event_type=EventType.AUTHORIZATION_GRANTED,
        user_id="power_user",
        user_roles=["power_user"],
        session_id="session_123",
        user_attributes={},
        agent_id=None,
        agent_capabilities=[],
        agent_trust_score=None,
        tool_name="execute_sql",
        tool_arguments={"query": "DROP TABLE test"},
        tool_timestamp=now,
        authorization_allowed=True,
        authorization_reason="Approved",
        policies_evaluated=["SQLPolicy"],
        authorization_metadata={"risk_level": "high"},
    )
    event = AuditEventV2(data=event_data, previous_hash="test")
    logger.log(event)

    # Security events
    security_event_data = AuditEventData(
        event_type=EventType.RATE_LIMIT_EXCEEDED,
        user_id="rate_limited_user",
        user_roles=["user"],
        session_id="session_456",
        user_attributes={},
        agent_id=None,
        agent_capabilities=[],
        agent_trust_score=None,
        tool_name="api_call",
        tool_arguments={},
        tool_timestamp=now,
        authorization_allowed=False,
        authorization_reason="Rate limit exceeded",
        policies_evaluated=[],
        authorization_metadata={},
    )
    security_event = AuditEventV2(data=security_event_data, previous_hash="test")
    logger.log(security_event)

    # IDOR violation
    idor_event_data = AuditEventData(
        event_type=EventType.IDOR_VIOLATION,
        user_id="malicious_user",
        user_roles=["user"],
        session_id="session_789",
        user_attributes={},
        agent_id=None,
        agent_capabilities=[],
        agent_trust_score=None,
        tool_name="get_record",
        tool_arguments={"record_id": "other_users_record"},
        tool_timestamp=now,
        authorization_allowed=False,
        authorization_reason="IDOR violation detected",
        policies_evaluated=["IDORPolicy"],
        authorization_metadata={},
    )
    idor_event = AuditEventV2(data=idor_event_data, previous_hash="test")
    logger.log(idor_event)

    return logger


# =============================================================================
# Base Classes Tests
# =============================================================================


class TestComplianceMetadata:
    """Tests for ComplianceMetadata."""

    def test_create_metadata(self, start, now):
        """Create compliance metadata."""
        metadata = ComplianceMetadata(
            framework=ComplianceFramework.EU_AI_ACT,
            version="2024",
            organization="Test Corp",
            system_name="Test AI",
            responsible_party="Test Team",
            period_start=start,
            period_end=now,
        )

        assert metadata.framework == ComplianceFramework.EU_AI_ACT
        assert metadata.organization == "Test Corp"

    def test_metadata_to_dict(self, start, now):
        """Convert metadata to dictionary."""
        metadata = ComplianceMetadata(
            framework=ComplianceFramework.SOC2,
            version="2017",
            organization="Acme Corp",
            system_name="API",
            responsible_party="Security",
            period_start=start,
            period_end=now,
        )

        data = metadata.to_dict()

        assert data["framework"] == "soc2"
        assert data["organization"] == "Acme Corp"
        assert "export_timestamp" in data


class TestComplianceEvidence:
    """Tests for ComplianceEvidence."""

    def test_create_evidence(self):
        """Create compliance evidence."""
        evidence = ComplianceEvidence(
            control_id="CC6.1",
            control_name="Logical Access",
            evidence_type="access_logs",
            description="Access control evidence",
            events=[{"event_id": "1"}],
            summary={"total": 1},
            compliant=True,
        )

        assert evidence.control_id == "CC6.1"
        assert evidence.compliant is True

    def test_evidence_to_dict(self):
        """Convert evidence to dictionary."""
        evidence = ComplianceEvidence(
            control_id="A.9",
            control_name="Access Control",
            evidence_type="logs",
            description="Test",
            events=[{"id": 1}, {"id": 2}],
        )

        data = evidence.to_dict()

        assert data["control_id"] == "A.9"
        assert data["event_count"] == 2


class TestComplianceReport:
    """Tests for ComplianceReport."""

    def test_create_report(self, start, now):
        """Create a compliance report."""
        metadata = ComplianceMetadata(
            framework=ComplianceFramework.ISO27001,
            version="2022",
            organization="Test",
            system_name="API",
            responsible_party="Team",
        )

        evidence = [
            ComplianceEvidence(
                control_id="A.9",
                control_name="Access",
                evidence_type="logs",
                description="Access logs",
                compliant=True,
            )
        ]

        report = ComplianceReport(
            metadata=metadata,
            evidence=evidence,
            summary={"status": "compliant"},
            recommendations=["Review annually"],
        )

        assert len(report.evidence) == 1
        assert report.recommendations[0] == "Review annually"

    def test_report_to_json(self, start, now):
        """Export report to JSON."""
        metadata = ComplianceMetadata(
            framework=ComplianceFramework.EU_AI_ACT,
            version="2024",
            organization="Test",
            system_name="AI",
            responsible_party="Team",
        )

        report = ComplianceReport(metadata=metadata, summary={"test": True})

        json_str = report.to_json(pretty=False)
        parsed = json.loads(json_str)

        assert parsed["metadata"]["framework"] == "eu_ai_act"
        assert parsed["summary"]["test"] is True


# =============================================================================
# EU AI Act Exporter Tests
# =============================================================================


class TestEUAIActExporter:
    """Tests for EUAIActExporter."""

    def test_framework_properties(self, logger):
        """Test framework properties."""
        exporter = EUAIActExporter(logger)

        assert exporter.framework == ComplianceFramework.EU_AI_ACT
        assert exporter.framework_version == "2024"

    def test_export_human_oversight_evidence(self, populated_logger, start, now):
        """Export human oversight evidence."""
        exporter = EUAIActExporter(
            populated_logger,
            organization="Test Corp",
            system_name="Test AI",
        )

        evidence = exporter.export_human_oversight_evidence(start, now)

        assert isinstance(evidence, HumanOversightEvidence)
        assert evidence.total_decisions > 0
        assert len(evidence.denied_requests) > 0
        assert len(evidence.intervention_points) > 0

    def test_export_decision_audit_trail(self, populated_logger, start, now):
        """Export decision audit trail."""
        exporter = EUAIActExporter(populated_logger)

        trail = exporter.export_decision_audit_trail(start, now)

        assert len(trail) > 0
        assert all(isinstance(e, DecisionAuditTrailEntry) for e in trail)

        # Check trail entry structure
        entry = trail[0]
        assert entry.decision_id is not None
        assert entry.decision_type is not None
        assert entry.timestamp is not None

    def test_export_risk_assessment_log(self, populated_logger, start, now):
        """Export risk assessment log."""
        exporter = EUAIActExporter(populated_logger)

        risk_log = exporter.export_risk_assessment_log(start, now)

        assert "high_risk_tool_calls" in risk_log
        assert "denied_requests" in risk_log
        assert "security_events" in risk_log
        assert "summary" in risk_log

        # Should have some denied requests
        assert len(risk_log["denied_requests"]) > 0

    def test_generate_compliance_report(self, populated_logger, start, now):
        """Generate full compliance report."""
        exporter = EUAIActExporter(
            populated_logger,
            organization="Acme Corp",
            system_name="Customer AI",
            responsible_party="AI Team",
            ai_system_id="AI-001",
        )

        report = exporter.generate_compliance_report(start, now)

        assert isinstance(report, ComplianceReport)
        assert report.metadata.framework == ComplianceFramework.EU_AI_ACT

        # Check evidence for key articles
        article_ids = [e.control_id for e in report.evidence]
        assert "Article 14" in article_ids
        assert "Article 14.4" in article_ids
        assert "Article 15" in article_ids
        assert "Article 17" in article_ids

    def test_export_markdown(self, populated_logger, start, now):
        """Export report as markdown."""
        exporter = EUAIActExporter(
            populated_logger,
            organization="Test Corp",
        )

        markdown = exporter.export_markdown(start, now)

        assert "# EU_AI_ACT Compliance Report" in markdown
        assert "## Metadata" in markdown
        assert "## Evidence" in markdown


# =============================================================================
# SOC 2 Exporter Tests
# =============================================================================


class TestSOC2Exporter:
    """Tests for SOC2Exporter."""

    def test_framework_properties(self, logger):
        """Test framework properties."""
        exporter = SOC2Exporter(logger)

        assert exporter.framework == ComplianceFramework.SOC2
        assert exporter.framework_version == "2017"

    def test_export_access_control_evidence(self, populated_logger, start, now):
        """Export CC6.1 access control evidence."""
        exporter = SOC2Exporter(populated_logger)

        evidence = exporter.export_access_control_evidence(start, now)

        assert isinstance(evidence, AccessControlEvidence)
        assert len(evidence.authorization_checks) > 0
        assert len(evidence.access_denied) > 0
        assert evidence.unique_users > 0

    def test_export_monitoring_evidence(self, populated_logger, start, now):
        """Export CC7.2 monitoring evidence."""
        exporter = SOC2Exporter(populated_logger)

        evidence = exporter.export_monitoring_evidence(start, now)

        assert isinstance(evidence, MonitoringEvidence)
        assert evidence.monitoring_coverage == 1.0

        # Should have some security alerts
        assert len(evidence.security_alerts) > 0

    def test_export_change_management_evidence(self, populated_logger, start, now):
        """Export CC8.1 change management evidence."""
        exporter = SOC2Exporter(populated_logger)

        evidence = exporter.export_change_management_evidence(start, now)

        assert isinstance(evidence, ChangeManagementEvidence)
        # May have empty lists if no change events in sample data
        assert hasattr(evidence, "configuration_changes")
        assert hasattr(evidence, "policy_updates")

    def test_generate_report(self, populated_logger, start, now):
        """Generate full SOC 2 report."""
        exporter = SOC2Exporter(
            populated_logger,
            organization="Acme Corp",
            system_name="API Gateway",
            responsible_party="Security Team",
        )

        report = exporter.generate_report(start, now)

        assert isinstance(report, ComplianceReport)
        assert report.metadata.framework == ComplianceFramework.SOC2

        # Check evidence for key controls
        control_ids = [e.control_id for e in report.evidence]
        assert "CC6.1" in control_ids
        assert "CC7.2" in control_ids
        assert "CC8.1" in control_ids

    def test_privilege_escalation_blocked(self, populated_logger, start, now):
        """Check privilege escalation events are captured."""
        exporter = SOC2Exporter(populated_logger)

        evidence = exporter.export_access_control_evidence(start, now)

        # IDOR violations should be captured as privilege escalation
        assert len(evidence.privilege_escalation_blocked) > 0


# =============================================================================
# ISO 27001 Exporter Tests
# =============================================================================


class TestISO27001Exporter:
    """Tests for ISO27001Exporter."""

    def test_framework_properties(self, logger):
        """Test framework properties."""
        exporter = ISO27001Exporter(logger)

        assert exporter.framework == ComplianceFramework.ISO27001
        assert exporter.framework_version == "2022"

    def test_export_access_control_a9(self, populated_logger, start, now):
        """Export A.9 access control evidence."""
        exporter = ISO27001Exporter(populated_logger)

        evidence = exporter.export_access_control_a9(start, now)

        assert isinstance(evidence, AccessControlA9Evidence)
        assert len(evidence.user_access_events) > 0
        assert evidence.unique_users > 0
        assert evidence.unique_resources > 0

        # Check role distribution
        assert len(evidence.role_distribution) > 0

    def test_export_operations_security_a12(self, populated_logger, start, now):
        """Export A.12 operations security evidence."""
        exporter = ISO27001Exporter(populated_logger)

        evidence = exporter.export_operations_security_a12(start, now)

        assert isinstance(evidence, OperationsSecurityA12Evidence)
        assert len(evidence.logging_events) > 0
        assert evidence.monitoring_active is True

        # Should have vulnerability events from IDOR
        assert len(evidence.vulnerability_events) > 0

    def test_export_incident_management_a16(self, populated_logger, start, now):
        """Export A.16 incident management evidence."""
        exporter = ISO27001Exporter(populated_logger)

        evidence = exporter.export_incident_management_a16(start, now)

        assert isinstance(evidence, IncidentManagementA16Evidence)
        assert len(evidence.security_incidents) > 0
        assert len(evidence.incident_responses) > 0

        # Check severity distribution
        assert "critical" in evidence.incident_by_severity

    def test_generate_report(self, populated_logger, start, now):
        """Generate full ISO 27001 report."""
        exporter = ISO27001Exporter(
            populated_logger,
            organization="Acme Corp",
            system_name="Core Platform",
            responsible_party="ISMS Manager",
        )

        report = exporter.generate_report(start, now)

        assert isinstance(report, ComplianceReport)
        assert report.metadata.framework == ComplianceFramework.ISO27001

        # Check evidence for key controls
        control_ids = [e.control_id for e in report.evidence]
        assert "A.9" in control_ids
        assert "A.12" in control_ids
        assert "A.16" in control_ids

    def test_privileged_access_events(self, populated_logger, start, now):
        """Check privileged access events are captured."""
        exporter = ISO27001Exporter(populated_logger)

        evidence = exporter.export_access_control_a9(start, now)

        # Admin user should have privileged access events
        assert len(evidence.privileged_access_events) > 0


# =============================================================================
# Filtering and Date Range Tests
# =============================================================================


class TestFiltering:
    """Tests for event filtering."""

    def test_filter_by_date_range(self, populated_logger, now):
        """Filter events by date range."""
        exporter = EUAIActExporter(populated_logger)

        # Filter to get only recent events
        start = now - timedelta(hours=1)
        end = now + timedelta(hours=1)

        events = exporter.filter_by_date_range(start, end)

        # All events should be within range
        for event in events:
            assert start <= event.timestamp <= end

    def test_filter_by_event_type(self, populated_logger, start, now):
        """Filter events by type."""
        exporter = SOC2Exporter(populated_logger)

        denied_events = exporter.get_denied_events(start, now)

        for event in denied_events:
            assert event.data.event_type == EventType.AUTHORIZATION_DENIED

    def test_filter_security_events(self, populated_logger, start, now):
        """Filter security events."""
        exporter = ISO27001Exporter(populated_logger)

        security_events = exporter.get_security_events(start, now)

        expected_types = [
            EventType.RATE_LIMIT_EXCEEDED,
            EventType.CIRCUIT_BREAKER_OPEN,
            EventType.IDOR_VIOLATION,
            EventType.SCHEMA_VALIDATION_FAILURE,
        ]

        for event in security_events:
            assert event.data.event_type in expected_types


# =============================================================================
# Export Format Tests
# =============================================================================


class TestExportFormats:
    """Tests for export formats."""

    def test_export_json_eu_ai_act(self, populated_logger, start, now):
        """Export EU AI Act report as JSON."""
        exporter = EUAIActExporter(populated_logger, organization="Test")

        json_str = exporter.export_json(start, now)
        parsed = json.loads(json_str)

        assert "metadata" in parsed
        assert "evidence" in parsed
        assert "summary" in parsed

    def test_export_json_soc2(self, populated_logger, start, now):
        """Export SOC 2 report as JSON."""
        exporter = SOC2Exporter(populated_logger, organization="Test")

        json_str = exporter.export_json(start, now, pretty=False)
        parsed = json.loads(json_str)

        assert parsed["metadata"]["framework"] == "soc2"

    def test_export_markdown_iso27001(self, populated_logger, start, now):
        """Export ISO 27001 report as Markdown."""
        exporter = ISO27001Exporter(populated_logger, organization="Test")

        markdown = exporter.export_markdown(start, now)

        assert "# ISO27001 Compliance Report" in markdown
        assert "A.9" in markdown
        assert "A.12" in markdown
        assert "A.16" in markdown


# =============================================================================
# Edge Cases
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases."""

    def test_empty_event_source(self, logger, start, now):
        """Handle empty event source."""
        exporter = EUAIActExporter(logger, organization="Test")

        report = exporter.generate_report(start, now)

        assert len(report.evidence) > 0
        assert report.summary["total_operations"] == 0

    def test_events_list_as_source(self, populated_logger, start, now):
        """Use list of events as source."""
        events = populated_logger.events

        exporter = SOC2Exporter(events, organization="Test")

        report = exporter.generate_report(start, now)

        assert len(report.evidence) > 0

    def test_summary_stats_computation(self, populated_logger, start, now):
        """Compute summary statistics."""
        exporter = ISO27001Exporter(populated_logger)

        events = exporter.filter_by_date_range(start, now)
        stats = exporter.compute_summary_stats(events)

        assert stats["total_events"] > 0
        assert stats["unique_users"] > 0
        assert stats["unique_tools"] > 0
        assert 0.0 <= stats["grant_rate"] <= 1.0

    def test_event_to_evidence_dict(self, populated_logger, start, now):
        """Convert event to evidence dictionary."""
        exporter = EUAIActExporter(populated_logger)

        events = exporter.get_events()
        event = events[0]

        evidence_dict = exporter.event_to_evidence_dict(event)

        assert "event_id" in evidence_dict
        assert "timestamp" in evidence_dict
        assert "user_id" in evidence_dict
        assert "tool_name" in evidence_dict

    def test_recommendations_generated(self, populated_logger, start, now):
        """Recommendations are generated based on findings."""
        exporter = EUAIActExporter(populated_logger, organization="Test")

        report = exporter.generate_report(start, now)

        # May or may not have recommendations depending on data
        assert isinstance(report.recommendations, list)


# =============================================================================
# Integration Tests
# =============================================================================


class TestIntegration:
    """Integration tests for compliance exporters."""

    def test_multiple_exporters_same_source(self, populated_logger, start, now):
        """Multiple exporters can use the same source."""
        eu_exporter = EUAIActExporter(populated_logger, organization="Test")
        soc2_exporter = SOC2Exporter(populated_logger, organization="Test")
        iso_exporter = ISO27001Exporter(populated_logger, organization="Test")

        eu_report = eu_exporter.generate_report(start, now)
        soc2_report = soc2_exporter.generate_report(start, now)
        iso_report = iso_exporter.generate_report(start, now)

        # All should have the same total events
        assert eu_report.summary["total_operations"] == soc2_report.summary["total_operations"]
        assert (
            soc2_report.summary["total_operations"]
            == iso_report.summary["total_events_analyzed"]
        )

    def test_complete_workflow(self, now):
        """Complete workflow from logging to export."""
        # 1. Create logger
        logger = InMemoryAuditLogger()

        # 2. Log some events
        for i in range(10):
            logger.log_authorization(
                user_id=f"user_{i % 3}",
                user_roles=["analyst"] if i % 2 == 0 else ["admin"],
                tool_name=f"tool_{i % 2}",
                tool_arguments={"param": i},
                allowed=i % 3 != 0,
                reason="Test reason",
            )

        # 3. Create exporters
        start = now - timedelta(days=1)

        eu_exporter = EUAIActExporter(
            logger,
            organization="Acme Corp",
            system_name="Test AI",
            responsible_party="AI Team",
        )

        # 4. Generate and export reports
        report = eu_exporter.generate_report(start, now)
        json_output = eu_exporter.export_json(start, now)
        markdown_output = eu_exporter.export_markdown(start, now)

        # 5. Verify outputs
        assert len(report.evidence) > 0
        assert len(json_output) > 0
        assert len(markdown_output) > 0
        assert report.summary["total_operations"] == 10
