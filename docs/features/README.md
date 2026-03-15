# Features Guide

Comprehensive documentation for all Proxilion features.

## Feature Overview

| Feature | Purpose | OWASP ASI | Documentation |
|---------|---------|-----------|---------------|
| [Authorization Engine](./authorization.md) | Policy-based access control | ASI04, ASI06 | [Full Guide](./authorization.md) |
| [Input Guards](./input-guards.md) | Block prompt injection attacks | ASI01 | [Full Guide](./input-guards.md) |
| [Output Guards](./output-guards.md) | Prevent data leakage | ASI03 | [Full Guide](./output-guards.md) |
| [Rate Limiting](./rate-limiting.md) | Prevent abuse and DoS | ASI07 | [Full Guide](./rate-limiting.md) |
| [Security Controls](./security-controls.md) | IDOR, circuit breaker, drift detection | ASI03, ASI05, ASI10 | [Full Guide](./security-controls.md) |
| [Audit Logging](./audit-logging.md) | Tamper-evident logs | ASI10 | [Full Guide](./audit-logging.md) |
| [Observability](./observability.md) | Metrics, costs, alerts | ASI10 | [Full Guide](./observability.md) |
| Agent Trust | Trust levels for agents | ASI08 | See [Features Guide](#agent-trust) |
| Context Integrity | Cryptographic context verification | ASI09 | See [Features Guide](#context-integrity) |
| Intent Capsules | Scope-bound intent verification | ASI01 | See [Features Guide](#intent-capsules) |

## Documentation by Category

### Guards & Input Protection
- **[Input Guards](./input-guards.md)** - Detect and block prompt injection attacks
  - 14 built-in injection patterns
  - Custom pattern support
  - BLOCK, WARN, SANITIZE modes
- **[Output Guards](./output-guards.md)** - Prevent sensitive data leakage
  - API keys, credentials, PII detection
  - Automatic redaction
  - Custom leakage patterns

### Rate Limiting & Throttling
- **[Rate Limiting](./rate-limiting.md)** - Protect against abuse and DoS
  - Token bucket algorithm
  - Sliding window limiter
  - Multi-dimensional limits

### Security Controls
- **[Security Controls](./security-controls.md)** - Advanced protection mechanisms
  - IDOR protection
  - Circuit breaker pattern
  - Cascade failure prevention
  - Behavioral drift detection

### Logging & Compliance
- **[Audit Logging](./audit-logging.md)** - Tamper-evident audit logs
  - SHA-256 hash chains
  - Merkle tree batching
  - SOC 2, ISO 27001, EU AI Act exporters
  - Cloud storage integration (S3, Azure, GCP)

### Monitoring & Observability
- **[Observability](./observability.md)** - Metrics, costs, and alerts
  - Real-time metrics collection
  - Cost tracking per user/model/tool
  - Prometheus export
  - Webhook alerts

### Authorization & Policies
- **[Authorization Engine](./authorization.md)** - Policy-based access control
  - Role-based policies
  - Ownership policies
  - Custom policy engines

## Quick Examples

### Input Guards

```python
from proxilion.guards import InputGuard, GuardAction

guard = InputGuard(action=GuardAction.BLOCK, threshold=0.5)

result = guard.check(user_input)
if not result.passed:
    raise SecurityError(f"Blocked: {result.matched_patterns}")
```

### Output Guards

```python
from proxilion.guards import OutputGuard

guard = OutputGuard()

# Check for leakage
result = guard.check(llm_response)
if not result.passed:
    # Redact sensitive data
    safe_response = guard.redact(llm_response)
```

### Rate Limiting

```python
from proxilion.security import TokenBucketRateLimiter

limiter = TokenBucketRateLimiter(capacity=100, refill_rate=10)

if not limiter.allow_request(user_id):
    raise RateLimitExceeded("Too many requests")
```

### IDOR Protection

```python
from proxilion.security import IDORProtector

protector = IDORProtector()
protector.register_scope(
    user_id="alice",
    resource_type="document",
    allowed_ids={"doc_1", "doc_2"},
)

if not protector.validate_access("alice", "document", "doc_1"):
    raise IDORViolationError("Unauthorized access")
```

### Audit Logging

```python
from proxilion.audit import AuditLogger, LoggerConfig

config = LoggerConfig.default("./audit/events.jsonl")
logger = AuditLogger(config)

logger.log_authorization(
    user_id="alice",
    user_roles=["admin"],
    tool_name="delete_user",
    allowed=True,
)
```

### Cost Tracking

```python
from proxilion.observability import CostTracker

tracker = CostTracker()
record = tracker.record_usage(
    model="claude-sonnet-4-20250514",
    input_tokens=1000,
    output_tokens=500,
    user_id="alice",
)
print(f"Cost: ${record.cost_usd:.4f}")
```

## Advanced Features

### Agent Trust
Multi-tenant agent security with hierarchical trust levels.

```python
from proxilion.security import AgentTrustManager, AgentTrustLevel

manager = AgentTrustManager(secret_key="your-secret-key")
manager.register_agent(
    agent_id="orchestrator",
    trust_level=AgentTrustLevel.FULL,
    capabilities=["delegate", "execute_all"],
)
```

### Intent Capsules
Cryptographically bind user intent to prevent goal hijacking.

```python
from proxilion.security import IntentCapsule

capsule = IntentCapsule.create(
    user_id="alice",
    intent="Help me find Python documentation",
    secret_key="your-secret-key",
    allowed_tools=["search", "read_doc"],
)
```

### Context Integrity
Cryptographic verification of conversation context.

```python
from proxilion.security import MemoryIntegrityGuard

checker = MemoryIntegrityGuard(secret_key="your-secret-key")
signature = checker.sign(conversation_history)

# Later, verify integrity
if not checker.verify(conversation_history, signature):
    raise ContextTamperingError("Context has been modified")
```

## Next Steps

- [Quick Start](../quickstart.md) - Get running in 5 minutes
- [Authorization Engine](./authorization.md) - Policy-based access control
- [Input Guards](./input-guards.md) - Prompt injection detection
- [Output Guards](./output-guards.md) - Data leakage prevention
- [Rate Limiting](./rate-limiting.md) - Request throttling
- [Security Controls](./security-controls.md) - IDOR, circuit breaker, drift detection
- [Audit Logging](./audit-logging.md) - Compliance and tamper-evident logs
- [Observability](./observability.md) - Metrics, costs, and alerts
- [Security Model](../security.md) - Deep dive into security architecture
