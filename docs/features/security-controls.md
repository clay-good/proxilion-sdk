# Security Controls

Advanced security controls for protecting LLM-powered applications from sophisticated attacks and cascading failures.

## Overview

Proxilion provides four critical security controls:

| Control | Purpose | OWASP ASI |
|---------|---------|-----------|
| **IDOR Protection** | Prevent unauthorized resource access | ASI03 |
| **Circuit Breaker** | Isolate failing services | ASI05 |
| **Cascade Protection** | Prevent failure propagation | ASI05 |
| **Behavioral Drift** | Detect rogue agents | ASI10 |

All controls are deterministic with no LLM inference in the security path.

## IDOR Protection

Insecure Direct Object Reference (IDOR) attacks occur when users manipulate object IDs to access resources they shouldn't. The IDORProtector validates that object IDs in tool arguments are within the user's authorized scope.

### Quick Start

```python
from proxilion.security import IDORProtector

protector = IDORProtector()

# Register user's allowed resources
protector.register_scope(
    user_id="alice",
    resource_type="document",
    allowed_ids={"doc_1", "doc_2", "doc_3"},
)

# Define where IDs appear in tool arguments
protector.register_id_pattern(
    parameter_name="document_id",
    resource_type="document",
)

# Validate access before tool execution
if protector.validate_access("alice", "document", "doc_1"):
    # Allowed - proceed
    result = read_document("doc_1")
else:
    # IDOR violation - block
    raise IDORViolationError("Unauthorized access attempt")
```

### Dynamic Scope Loading

For large datasets, load scopes on-demand:

```python
def load_user_documents(user_id: str) -> set[str]:
    """Load documents from database."""
    return db.query("SELECT id FROM documents WHERE owner=?", user_id)

protector.register_scope_loader("document", load_user_documents)

# Scope is loaded automatically on first access
is_allowed = protector.validate_access("alice", "document", "doc_123")
```

### Pattern-Based Validation

Validate access using regex patterns:

```python
protector.register_scope(
    user_id="alice",
    resource_type="document",
    allowed_patterns=[
        r"^alice_.*",  # Documents starting with "alice_"
        r"^team_shared_.*",  # Shared team documents
    ],
)

# Pattern matching
protector.validate_access("alice", "document", "alice_report_2024")  # True
protector.validate_access("alice", "document", "bob_private_doc")  # False
```

### Custom ID Extractors

Extract IDs from complex argument structures:

```python
from proxilion.security import IDPattern

def extract_nested_ids(args: dict) -> list[str]:
    """Extract document IDs from nested structure."""
    ids = []
    if "documents" in args:
        ids.extend([doc["id"] for doc in args["documents"]])
    if "related_docs" in args:
        ids.extend(args["related_docs"])
    return ids

pattern = IDPattern(
    parameter_name="documents",
    resource_type="document",
    extractor=extract_nested_ids,
)

protector.register_id_pattern_obj(pattern)
```

### Integration with Tool Calls

```python
from proxilion.types import ToolCallRequest

def validate_tool_call(tool_call: ToolCallRequest, user_id: str) -> bool:
    """Validate all object IDs in tool arguments."""
    return protector.validate_tool_call(
        user_id=user_id,
        tool_name=tool_call.name,
        arguments=tool_call.arguments,
    )

# Before executing tool
if not validate_tool_call(tool_call, "alice"):
    raise IDORViolationError("Access denied to requested resources")
```

## Circuit Breaker

Prevent cascading failures when external services or tools fail repeatedly.

### Quick Start

```python
from proxilion.security import CircuitBreaker
from proxilion.exceptions import CircuitOpenError

breaker = CircuitBreaker(
    failure_threshold=5,    # Open after 5 failures
    reset_timeout=30.0,     # Try again after 30 seconds
)

try:
    result = breaker.call(external_api_request, arg1, arg2)
except CircuitOpenError:
    # Circuit is open - use fallback
    result = fallback_response()
```

### Circuit States

The circuit breaker has three states:

```
CLOSED (normal)
   |
   | 5 failures
   v
OPEN (failing)
   |
   | 30 seconds
   v
HALF_OPEN (testing)
   |
   | Success: back to CLOSED
   | Failure: back to OPEN
```

### Exponential Backoff

Enable exponential backoff for repeated failures:

```python
breaker = CircuitBreaker(
    failure_threshold=5,
    reset_timeout=30.0,
    exponential_backoff=True,
    max_backoff=300.0,  # Max 5 minutes
)

# Timeout increases on repeated failures:
# 1st open: 30s
# 2nd open: 60s
# 3rd open: 120s
# 4th open: 240s
# 5th open: 300s (max)
```

### Excluded Exceptions

Don't count certain exceptions as failures:

```python
breaker = CircuitBreaker(
    failure_threshold=5,
    reset_timeout=30.0,
    excluded_exceptions=(ValueError, KeyError),
)

# ValueError won't count as failure
try:
    breaker.call(validate_input, bad_data)
except ValueError:
    # Circuit remains closed
    pass
```

### Circuit Statistics

Monitor circuit health:

```python
stats = breaker.stats

print(f"State: {breaker.state}")
print(f"Failures: {stats.failures}")
print(f"Consecutive failures: {stats.consecutive_failures}")
print(f"Last failure: {stats.last_failure_time}")
print(f"Last error: {stats.last_failure_error}")
```

### Registry Pattern

Manage multiple circuit breakers:

```python
from proxilion.security import CircuitBreakerRegistry

registry = CircuitBreakerRegistry(
    default_failure_threshold=5,
    default_reset_timeout=30.0,
)

# Get or create circuit for a service
breaker = registry.get_or_create("database_service")

# Call through circuit
result = breaker.call(db.query, sql)
```

## Cascade Protection

Prevent failures from propagating through dependent tools and services.

### Quick Start

```python
from proxilion.security import (
    DependencyGraph,
    CascadeProtector,
    CircuitBreakerRegistry,
)

# Build dependency graph
graph = DependencyGraph()
graph.add_dependency("order_service", "database")
graph.add_dependency("order_service", "inventory")
graph.add_dependency("user_service", "database")
graph.add_dependency("notification_service", "user_service")

# Create protector
registry = CircuitBreakerRegistry()
protector = CascadeProtector(graph, registry)

# Check health before calling
state = protector.check_cascade_health("order_service")

if state == CascadeState.HEALTHY:
    # All dependencies healthy
    result = call_order_service()
elif state == CascadeState.DEGRADED:
    # Some dependencies failing, proceed with caution
    result = call_order_service(fallback=True)
else:
    # FAILING or ISOLATED - use fallback
    result = fallback_response()
```

### Cascade States

| State | Meaning | Action |
|-------|---------|--------|
| `HEALTHY` | All dependencies functioning | Proceed normally |
| `DEGRADED` | Some non-critical dependencies failing | Proceed with caution |
| `FAILING` | Critical dependencies failing | Use fallback |
| `ISOLATED` | Manually isolated | Block all calls |

### Critical Dependencies

Mark dependencies as critical or optional:

```python
graph.add_dependency(
    "order_service",
    "payment_gateway",
    critical=True,  # Failure blocks order_service
)

graph.add_dependency(
    "order_service",
    "recommendation_engine",
    critical=False,  # Failure doesn't block order_service
)
```

### Fallback Chains

Define fallback services:

```python
graph.add_dependency(
    "order_service",
    "primary_database",
    critical=True,
    fallback="replica_database",
)

# If primary_database fails, try replica_database
```

### Failure Propagation

Propagate failures through the graph:

```python
# When a service fails, propagate to dependents
affected = protector.propagate_failure("database")

print(f"Failure affected {len(affected)} services:")
for service in affected:
    print(f"  - {service}")
```

### Cascade-Aware Circuit Breakers

Integrate cascade protection with circuit breakers:

```python
from proxilion.security import CascadeAwareCircuitBreakerRegistry

# Circuit breakers automatically propagate failures
registry = CascadeAwareCircuitBreakerRegistry(protector)

# When a circuit opens, affected services are notified
breaker = registry.get_or_create("database")
# Circuit opens -> order_service, user_service marked as degraded
```

### Manual Isolation

Isolate a service for maintenance:

```python
# Isolate service (blocks all calls)
protector.isolate_service("order_service", reason="Maintenance")

# Restore service
protector.restore_service("order_service")
```

## Behavioral Drift Detection

Detect when an agent's behavior deviates from its baseline, indicating potential compromise or malfunction.

### Quick Start

```python
from proxilion.security import BehavioralMonitor

monitor = BehavioralMonitor(
    agent_id="my_agent",
    drift_threshold=3.0,  # Standard deviations
)

# Record baseline behavior (first 100 events)
for i in range(100):
    monitor.record_event("tool_call", {"tool": "search"})
    monitor.record_event("response", {"length": 150})

# Lock baseline
monitor.lock_baseline()

# Monitor during operation
drift = monitor.check_drift()

if drift.is_drifting:
    print(f"Drift detected: {drift.reason}")
    print(f"Severity: {drift.severity}")
    if drift.severity > 0.8:
        kill_switch.activate("Severe behavioral drift")
```

### Tracked Metrics

Behavioral monitor tracks:

| Metric | Description |
|--------|-------------|
| `TOOL_CALL_RATE` | Calls per minute |
| `RESPONSE_LENGTH` | Average response length |
| `ERROR_RATE` | Errors per minute |
| `UNIQUE_TOOLS` | Number of unique tools used |
| `LATENCY` | Average response latency |
| `TOKEN_USAGE` | Tokens per request |
| `TOOL_REPETITION` | Same tool called consecutively |
| `SCOPE_VIOLATIONS` | Attempts to exceed scope |
| `CONTEXT_SIZE` | Conversation context size |

### Custom Metrics

Track domain-specific metrics:

```python
monitor.record_metric(
    metric=DriftMetric.CUSTOM,
    value=database_queries_per_minute,
    metadata={"metric_name": "db_query_rate"},
)
```

### Drift Detection

Drift is detected using statistical analysis:

```python
drift = monitor.check_drift()

# DriftResult fields:
# - is_drifting: bool
# - severity: float (0.0 to 1.0)
# - reason: str
# - metrics_drifting: list[str]
# - baseline_stats: dict
# - current_stats: dict

if drift.is_drifting:
    for metric in drift.metrics_drifting:
        print(f"Drift in {metric}:")
        print(f"  Baseline: {drift.baseline_stats[metric]}")
        print(f"  Current: {drift.current_stats[metric]}")
```

### Kill Switch

Emergency halt mechanism for runaway agents:

```python
from proxilion.security.behavioral_drift import KillSwitch

kill_switch = KillSwitch()

# Activate kill switch
kill_switch.activate(reason="Severe behavioral drift detected")

# Check if active
if kill_switch.is_active:
    raise EmergencyHaltError("Agent halted by kill switch")

# Deactivate (requires reason)
kill_switch.deactivate(reason="Issue resolved, agent verified safe")
```

### Integration with Monitoring

```python
def monitor_agent_execution():
    """Monitor agent and activate kill switch on severe drift."""
    drift = monitor.check_drift()

    if drift.is_drifting:
        # Log drift event
        audit_logger.log_security_event(
            event_type="behavioral_drift",
            agent_id="my_agent",
            details={
                "severity": drift.severity,
                "reason": drift.reason,
                "metrics": drift.metrics_drifting,
            },
        )

        # Activate kill switch if severe
        if drift.severity > 0.8:
            kill_switch.activate(f"Severe drift: {drift.reason}")
            raise EmergencyHaltError("Agent halted")
```

### Baseline Management

```python
# Check baseline status
if monitor.is_baseline_locked:
    print("Baseline is locked")

# Extend baseline with more data
monitor.unlock_baseline()
monitor.record_event("tool_call", {"tool": "search"})
monitor.lock_baseline()

# Reset baseline entirely
monitor.reset_baseline()
```

## Best Practices

### IDOR Protection
1. **Always validate**: Check every object ID in tool arguments
2. **Use scope loaders**: Don't load all IDs upfront for large datasets
3. **Pattern matching**: Use patterns for predictable ID formats
4. **Log violations**: Track attempted IDOR attacks

### Circuit Breaker
1. **Set realistic thresholds**: Monitor failure rates before setting limits
2. **Use exponential backoff**: Prevent thundering herd on recovery
3. **Exclude expected errors**: Don't count validation errors as failures
4. **Monitor state changes**: Alert on circuit opens

### Cascade Protection
1. **Map dependencies**: Maintain accurate dependency graph
2. **Mark critical paths**: Identify which dependencies are critical
3. **Test failure scenarios**: Verify cascade behavior under failure
4. **Provide fallbacks**: Always have a degraded mode

### Behavioral Drift
1. **Collect sufficient baseline**: 100+ events for statistical significance
2. **Lock baseline**: Prevent drift from creeping baseline
3. **Tune threshold**: Start high (3σ), tune based on false positives
4. **Combine with kill switch**: Automatic halt on severe drift

## Related

- [Rate Limiting](./rate-limiting.md) - Request rate controls
- [Audit Logging](./audit-logging.md) - Log security events
- [Observability](./observability.md) - Metrics and alerting

## API Reference

### IDORProtector

```python
class IDORProtector:
    def __init__(self) -> None

    def register_scope(
        self,
        user_id: str,
        resource_type: str,
        allowed_ids: set[str] | None = None,
        allowed_patterns: list[str] | None = None,
        scope_loader: Callable[[str], set[str]] | None = None,
    ) -> None

    def register_id_pattern(
        self,
        parameter_name: str,
        resource_type: str,
        pattern: str = r".*",
    ) -> None

    def validate_access(
        self,
        user_id: str,
        resource_type: str,
        resource_id: str,
    ) -> bool

    def validate_tool_call(
        self,
        user_id: str,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> bool
```

### CircuitBreaker

```python
class CircuitBreaker:
    def __init__(
        self,
        failure_threshold: int = 5,
        reset_timeout: float = 30.0,
        half_open_max: int = 1,
        success_threshold: int = 1,
        excluded_exceptions: tuple[type[Exception], ...] | None = None,
        exponential_backoff: bool = True,
        max_backoff: float = 300.0,
    ) -> None

    def call(
        self,
        func: Callable[..., T],
        *args: Any,
        **kwargs: Any,
    ) -> T  # Raises CircuitOpenError

    @property
    def state(self) -> CircuitState

    @property
    def stats(self) -> CircuitStats
```

### CascadeProtector

```python
class CascadeProtector:
    def __init__(
        self,
        graph: DependencyGraph,
        circuit_registry: CircuitBreakerRegistry,
    ) -> None

    def check_cascade_health(
        self,
        service_name: str,
    ) -> CascadeState

    def propagate_failure(
        self,
        service_name: str,
    ) -> list[str]  # Affected services

    def isolate_service(
        self,
        service_name: str,
        reason: str,
    ) -> None

    def restore_service(
        self,
        service_name: str,
    ) -> None
```

### BehavioralMonitor

```python
class BehavioralMonitor:
    def __init__(
        self,
        agent_id: str,
        drift_threshold: float = 3.0,
        baseline_window: int = 100,
    ) -> None

    def record_event(
        self,
        event_type: str,
        data: dict[str, Any],
    ) -> None

    def record_metric(
        self,
        metric: DriftMetric,
        value: float,
        metadata: dict[str, Any] | None = None,
    ) -> None

    def check_drift(self) -> DriftResult

    def lock_baseline(self) -> None
    def unlock_baseline(self) -> None
    def reset_baseline(self) -> None

    @property
    def is_baseline_locked(self) -> bool
```

### KillSwitch

```python
class KillSwitch:
    def __init__(self) -> None

    def activate(self, reason: str) -> None
    def deactivate(self, reason: str) -> None

    @property
    def is_active(self) -> bool

    @property
    def activation_reason(self) -> str | None
```
