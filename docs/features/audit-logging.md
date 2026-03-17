# Audit Logging

Tamper-evident audit logging with cryptographic hash chains, compliance exporters, and cloud storage integration.

## Overview

Proxilion's audit logger provides:
- **Hash-chained logs**: Each event links to the previous, making tampering detectable
- **Merkle tree batching**: Efficient proof of inclusion for large log sets
- **Compliance exporters**: SOC 2, ISO 27001, EU AI Act formatted reports
- **Cloud integration**: Export to AWS S3, Azure Blob, Google Cloud Storage
- **Structured JSON**: JSON Lines format for easy parsing
- **Sensitive data redaction**: Automatic PII removal
- **Log rotation**: Hourly, daily, weekly, or size-based

All logs are tamper-evident and verifiable offline.

## Quick Start

```python
from proxilion.audit import AuditLogger, LoggerConfig

# Create logger with default config
config = LoggerConfig.default("./audit/events.jsonl")
logger = AuditLogger(config)

# Log authorization events
from proxilion.audit.events import create_authorization_event

event = create_authorization_event(
    user_id="user_123",
    user_roles=["analyst"],
    tool_name="database_query",
    tool_arguments={"query": "SELECT * FROM users"},
    allowed=True,
)

logger.log(event)

# Verify log integrity
result = logger.verify()
print(f"Log valid: {result.valid}")
print(f"Verified {result.verified_count} events")
```

## LoggerConfig

Configure logger behavior, rotation, and redaction:

```python
from proxilion.audit import LoggerConfig, RotationPolicy, RedactionConfig
from pathlib import Path

config = LoggerConfig(
    log_path=Path("./audit/events.jsonl"),
    rotation=RotationPolicy.DAILY,
    max_size_mb=100.0,
    compress_rotated=True,
    batch_size=100,  # Events per Merkle batch
    redaction_config=RedactionConfig.default(),
    sync_writes=True,  # Flush after each write
)

logger = AuditLogger(config)
```

### Rotation Policies

| Policy | Behavior |
|--------|----------|
| `NONE` | Never rotate |
| `HOURLY` | New file every hour |
| `DAILY` | New file every day (default) |
| `WEEKLY` | New file every week |
| `SIZE` | Rotate when file exceeds `max_size_mb` |

```python
# Size-based rotation
config = LoggerConfig(
    log_path=Path("./audit/events.jsonl"),
    rotation=RotationPolicy.SIZE,
    max_size_mb=50.0,  # Rotate at 50 MB
    compress_rotated=True,  # Gzip old files
)
```

## Logging Events

### Authorization Events

```python
logger.log_authorization(
    user_id="alice",
    user_roles=["admin"],
    tool_name="delete_user",
    tool_arguments={"user_id": "bob"},
    allowed=True,
    reason="User has admin role",
    policies_evaluated=["admin_policy", "rbac_policy"],
    session_id="session_abc123",
)
```

### Guard Violations

```python
logger.log_guard_violation(
    user_id="alice",
    guard_type="input",
    violation_type="prompt_injection",
    input_text="Ignore previous instructions...",
    matched_patterns=["instruction_override"],
    risk_score=0.95,
)
```

### Security Events

```python
logger.log_security_event(
    event_type="idor_violation",
    user_id="alice",
    resource_id="document_999",
    details={
        "attempted_access": "document_999",
        "allowed_scope": ["document_1", "document_2"],
    },
)
```

## Hash Chain Verification

Verify log integrity at any time:

```python
# Verify entire log
result = logger.verify()

if result.valid:
    print(f"All {result.verified_count} events verified")
else:
    print(f"Tampering detected at index {result.error_index}")
    print(f"Error: {result.error_message}")
```

### How Hash Chains Work

Each event contains the hash of the previous event:

```
Event 1: hash = SHA256(event_data + GENESIS_HASH)
Event 2: hash = SHA256(event_data + Event1.hash)
Event 3: hash = SHA256(event_data + Event2.hash)
...
```

Modifying Event 1 will break Event 2's hash, which breaks Event 3's hash, etc. The entire chain from that point becomes invalid.

### Merkle Tree Batching

For efficient verification of large logs, events are grouped into Merkle tree batches:

```python
config = LoggerConfig(
    log_path=Path("./audit/events.jsonl"),
    batch_size=1000,  # 1000 events per Merkle batch
)

logger = AuditLogger(config)

# Merkle root is computed every 1000 events
# Provides O(log n) proof of inclusion
```

## Sensitive Data Redaction

Automatically redact PII and secrets from logs:

```python
from proxilion.audit import RedactionConfig

config = LoggerConfig(
    log_path=Path("./audit/events.jsonl"),
    redaction_config=RedactionConfig(
        redact_emails=True,
        redact_ip_addresses=True,
        redact_api_keys=True,
        custom_patterns=[
            r"password['\"]?\s*[:=]\s*['\"]?[^'\"]+",
            r"ssn['\"]?\s*[:=]\s*\d{3}-\d{2}-\d{4}",
        ],
    ),
)

logger = AuditLogger(config)

# Sensitive data is automatically redacted before writing
```

### Default Redaction

```python
# Default config redacts common PII
config = RedactionConfig.default()

# Redacts:
# - Email addresses
# - API keys (OpenAI, AWS, etc.)
# - Bearer tokens
# - Internal IP addresses
# - File paths
```

## Compliance Exporters

Export audit logs in compliance-ready formats.

### SOC 2 Type II

```python
from proxilion.audit.compliance import SOC2Exporter
from datetime import datetime, timedelta, timezone

exporter = SOC2Exporter(
    logger,
    organization="Acme Corp",
    system_name="Customer API",
    responsible_party="Security Team",
)

end = datetime.now(timezone.utc)
start = end - timedelta(days=90)

# Export access control evidence (CC6)
access_evidence = exporter.export_access_control_evidence(start, end)

# Export operations evidence (CC7)
ops_evidence = exporter.export_operations_evidence(start, end)

# Generate full SOC 2 report
report = exporter.generate_report(start, end)

# Save to JSON
with open("soc2_report.json", "w") as f:
    json.dump(report.to_dict(), f, indent=2)
```

### ISO 27001

```python
from proxilion.audit.compliance import ISO27001Exporter

exporter = ISO27001Exporter(
    logger,
    organization="Acme Corp",
    system_name="Enterprise API",
    responsible_party="ISMS Manager",
)

# Export access control evidence (Annex A.9)
access_a9 = exporter.export_access_control_a9(start, end)

# Export operations security (Annex A.12)
ops_a12 = exporter.export_operations_security_a12(start, end)

# Generate full ISO 27001 report
report = exporter.generate_report(start, end)
```

### EU AI Act

```python
from proxilion.audit.compliance import EUAIActExporter

exporter = EUAIActExporter(
    logger,
    organization="Acme Corp",
    system_name="Customer Service AI",
    responsible_party="AI Governance Team",
)

# Export human oversight evidence (Article 14)
oversight = exporter.export_human_oversight_evidence(start, end)

# Export accuracy/robustness evidence (Article 15)
accuracy = exporter.export_accuracy_robustness_evidence(start, end)

# Generate compliance report
report = exporter.generate_compliance_report(start, end)
```

## Cloud Exporters

Export audit logs to cloud storage for long-term retention.

### AWS S3

```python
from proxilion.audit.exporters import S3Exporter, CloudExporterConfig

config = CloudExporterConfig(
    provider="aws",
    bucket_name="my-audit-logs",
    prefix="proxilion/prod/",
    region="us-west-2",
    compression=True,
    partition_by="daily",  # Partitioning strategy
)

exporter = S3Exporter(config)

# Export events
result = exporter.export(events)

if result.success:
    print(f"Exported {result.events_exported} events to {result.remote_path}")
else:
    print(f"Export failed: {result.error_message}")
```

### Azure Blob Storage

```python
from proxilion.audit.exporters import AzureBlobExporter

config = CloudExporterConfig(
    provider="azure",
    bucket_name="audit-logs",  # Container name
    prefix="proxilion/prod/",
    region="eastus",
)

exporter = AzureBlobExporter(config)
result = exporter.export(events)
```

### Google Cloud Storage

```python
from proxilion.audit.exporters import GCPStorageExporter

config = CloudExporterConfig(
    provider="gcp",
    bucket_name="my-audit-logs",
    prefix="proxilion/prod/",
    region="us-central1",
)

exporter = GCPStorageExporter(config)
result = exporter.export(events)
```

### Multi-Cloud Export

Export to multiple cloud providers simultaneously:

```python
from proxilion.audit.exporters import MultiCloudExporter

exporter = MultiCloudExporter([
    S3Exporter(s3_config),
    AzureBlobExporter(azure_config),
    GCPStorageExporter(gcp_config),
])

# Exports to all providers in parallel
results = exporter.export(events)

for result in results:
    print(f"{result.provider}: {result.events_exported} events")
```

## Event Types

Proxilion logs various event types:

| Event Type | Purpose |
|------------|---------|
| `AUTHORIZATION_ALLOWED` | Tool call was authorized |
| `AUTHORIZATION_DENIED` | Tool call was denied |
| `GUARD_VIOLATION` | Input/output guard detected violation |
| `RATE_LIMIT_EXCEEDED` | Rate limit hit |
| `IDOR_VIOLATION` | IDOR protection triggered |
| `CIRCUIT_OPEN` | Circuit breaker opened |
| `BEHAVIORAL_DRIFT` | Behavioral drift detected |
| `KILL_SWITCH_ACTIVATED` | Emergency kill switch triggered |
| `CONTEXT_TAMPERING` | Context integrity violation |
| `AGENT_TRUST_VIOLATION` | Agent trust check failed |

## Log Format

Events are stored in JSON Lines format (one JSON object per line):

```json
{"event_id":"evt_abc123","timestamp":"2024-03-14T10:30:00Z","event_type":"authorization_allowed","user_id":"alice","tool_name":"database_query","allowed":true,"event_hash":"sha256:abc...","previous_hash":"sha256:def..."}
{"event_id":"evt_abc124","timestamp":"2024-03-14T10:30:01Z","event_type":"guard_violation","user_id":"bob","guard_type":"input","violation_type":"prompt_injection","event_hash":"sha256:ghi...","previous_hash":"sha256:abc..."}
```

This format is:
- Easy to parse line-by-line
- Streamable for real-time processing
- Compatible with log aggregation tools
- Grep-friendly for quick searches

## Log Querying

Read and query logs:

```python
# Read all events
events = logger.read_all()

# Filter events
authorization_events = [
    e for e in events
    if e.data.event_type == "authorization_allowed"
]

# Query by user
alice_events = [
    e for e in events
    if e.data.user_id == "alice"
]

# Query by time range
from datetime import datetime, timedelta, timezone

end = datetime.now(timezone.utc)
start = end - timedelta(hours=24)

recent_events = [
    e for e in events
    if start <= datetime.fromisoformat(e.data.timestamp) <= end
]
```

## Integration with Proxilion Core

```python
from proxilion import Proxilion
from proxilion.audit import AuditLogger, LoggerConfig

# Create audit logger
config = LoggerConfig.default("./audit/events.jsonl")
audit_logger = AuditLogger(config)

# Create Proxilion instance with audit logging
proxilion = Proxilion(
    policy_engine=my_policy,
    audit_logger=audit_logger,
)

# All authorization decisions are automatically logged
result = proxilion.authorize_tool_call(user_context, tool_call)
```

## Best Practices

1. **Enable daily rotation**: Prevents single files from growing too large
2. **Compress rotated files**: Save storage space
3. **Export to cloud storage**: Offsite backup for disaster recovery
4. **Verify regularly**: Run integrity checks periodically
5. **Redact sensitive data**: Prevent secrets in logs
6. **Use compliance exporters**: Generate audit-ready reports
7. **Monitor log gaps**: Alert on missing events
8. **Sync writes**: Ensure durability for critical events

## Performance Considerations

- **Batch size**: Larger batches = less overhead, but longer verification
- **Sync writes**: `sync_writes=True` ensures durability but is slower
- **Compression**: Gzip compression saves 80%+ storage but adds CPU overhead
- **Cloud export**: Async export to avoid blocking main thread

## Related

- [Observability](./observability.md) - Metrics and alerting
- [Security Controls](./security-controls.md) - IDOR, circuit breaker, behavioral drift
- [Input Guards](./input-guards.md) - Prompt injection detection

## API Reference

### AuditLogger

```python
class AuditLogger:
    def __init__(self, config: LoggerConfig) -> None

    def log(self, event: AuditEventV2) -> AuditEventV2

    def log_authorization(
        self,
        user_id: str,
        user_roles: list[str],
        tool_name: str,
        tool_arguments: dict[str, Any],
        allowed: bool,
        reason: str | None = None,
        policies_evaluated: list[str] | None = None,
        session_id: str | None = None,
    ) -> AuditEventV2

    def log_guard_violation(
        self,
        user_id: str,
        guard_type: str,
        violation_type: str,
        input_text: str,
        matched_patterns: list[str],
        risk_score: float,
    ) -> AuditEventV2

    def log_security_event(
        self,
        event_type: str,
        user_id: str,
        resource_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditEventV2

    def verify(self) -> ChainVerificationResult
    def read_all(self) -> list[AuditEventV2]
    def close(self) -> None
```

### LoggerConfig

```python
@dataclass
class LoggerConfig:
    log_path: Path
    rotation: RotationPolicy = RotationPolicy.DAILY
    max_size_mb: float = 100.0
    compress_rotated: bool = True
    batch_size: int = 100
    redaction_config: RedactionConfig | None = None
    sync_writes: bool = True

    @classmethod
    def default(cls, log_path: str | Path) -> LoggerConfig
```

### RotationPolicy

```python
class RotationPolicy(Enum):
    NONE = "none"
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    SIZE = "size"
```

### RedactionConfig

```python
@dataclass
class RedactionConfig:
    redact_emails: bool = True
    redact_ip_addresses: bool = True
    redact_api_keys: bool = True
    redact_passwords: bool = True
    custom_patterns: list[str] = field(default_factory=list)

    @classmethod
    def default(cls) -> RedactionConfig
```

### Compliance Exporters

```python
class SOC2Exporter:
    def __init__(
        self,
        logger: AuditLogger,
        organization: str,
        system_name: str,
        responsible_party: str,
    ) -> None

    def export_access_control_evidence(
        self,
        start: datetime,
        end: datetime,
    ) -> ComplianceEvidence

    def generate_report(
        self,
        start: datetime,
        end: datetime,
    ) -> ComplianceReport

class ISO27001Exporter:
    # Similar interface

class EUAIActExporter:
    # Similar interface
```

### Cloud Exporters

```python
class S3Exporter(BaseCloudExporter):
    def __init__(self, config: CloudExporterConfig) -> None

    def export(
        self,
        events: list[AuditEventV2],
    ) -> ExportResult

@dataclass
class CloudExporterConfig:
    provider: str
    bucket_name: str
    prefix: str = ""
    region: str | None = None
    compression: bool = True
    partition_by: str = "daily"  # "hourly", "daily", "monthly"
```
