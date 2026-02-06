# Security Model

Deep dive into Proxilion's security architecture and threat model.

## Threat Model

Proxilion is designed to protect against threats in agentic AI systems:

### Primary Threats

1. **Prompt Injection** - Malicious inputs that manipulate LLM behavior
2. **Privilege Escalation** - Users/agents gaining unauthorized access
3. **Data Exfiltration** - Unauthorized extraction of sensitive data
4. **Resource Exhaustion** - DoS attacks via excessive API usage
5. **Audit Tampering** - Covering tracks by modifying logs
6. **Context Manipulation** - Forging or modifying user/agent context

### Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│                    UNTRUSTED ZONE                                │
│  • User inputs                                                   │
│  • LLM outputs (tool calls)                                      │
│  • External API responses                                        │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    PROXILION BOUNDARY                            │
│  • Input validation                                              │
│  • Authorization checks                                          │
│  • Integrity verification                                        │
│  • Rate limiting                                                 │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    TRUSTED ZONE                                  │
│  • Protected tools                                               │
│  • Internal systems                                              │
│  • Databases                                                     │
└─────────────────────────────────────────────────────────────────┘
```

## Security Controls

### 1. Input Validation

**Threat Mitigated:** Injection attacks (SQL, command, path traversal)

```python
from proxilion.guardrails import InputValidator, ValidationRule, ThreatLevel

validator = InputValidator()

# SQL Injection prevention
validator.add_rule(ValidationRule(
    name="sql_injection",
    pattern=r"(\bUNION\b.*\bSELECT\b|\bDROP\b|\bDELETE\b|\b--\b|;\s*$)",
    action="block",
    threat_level=ThreatLevel.CRITICAL,
    message="SQL injection attempt detected"
))

# Command injection prevention
validator.add_rule(ValidationRule(
    name="command_injection",
    pattern=r"(;\s*|\||\$\(|`|&&|\|\|)",
    action="block",
    threat_level=ThreatLevel.CRITICAL,
    message="Command injection attempt detected"
))

# Path traversal prevention
validator.add_rule(ValidationRule(
    name="path_traversal",
    pattern=r"(\.\.\/|\.\.\\|%2e%2e|%252e)",
    action="block",
    threat_level=ThreatLevel.HIGH,
    message="Path traversal attempt detected"
))
```

**Security Properties:**
- Regex patterns are deterministic—no statistical bypass
- Validation happens before tool execution
- Failed validation logged for forensics

### 2. Authorization Engine

**Threat Mitigated:** Unauthorized access, privilege escalation

```python
from proxilion import Proxilion, Policy, UserContext

auth = Proxilion()

@auth.policy("sensitive_data")
class SensitiveDataPolicy(Policy):
    """Multi-factor authorization for sensitive operations."""

    def evaluate(self, context) -> bool:
        user = context.user

        # Require explicit permission
        if "data:sensitive:read" not in user.permissions:
            return False

        # Require specific role
        if "security_analyst" not in user.roles:
            return False

        # Time-based restriction (business hours only)
        from datetime import datetime
        hour = datetime.now().hour
        if not (9 <= hour <= 17):
            return False

        return True
```

**Security Properties:**
- Policies are code, not prompts—cannot be injected
- Evaluation is synchronous and blocking
- All decisions are logged with full context

### 3. Agent Trust Levels

**Threat Mitigated:** Compromised or untrusted agents

```python
from proxilion.guardrails import AgentTrustManager, TrustLevel

trust_manager = AgentTrustManager()

# Register agent with capabilities
trust_manager.register_agent(
    agent_id="research-agent",
    trust_level=TrustLevel.LIMITED,
    capabilities=["web:search", "file:read"],
    # Cannot: file:write, db:execute, api:call
)

# Verify before allowing action
can_act = trust_manager.can_perform(
    agent_id="research-agent",
    action="file:read",
    resource="/docs/public/report.pdf"
)
```

**Trust Levels:**
- `NONE` - No trust, all actions denied
- `MINIMAL` - Read-only, non-sensitive only
- `LIMITED` - Specific capabilities only
- `STANDARD` - Normal operations
- `ELEVATED` - Sensitive operations
- `FULL` - Administrative access

### 4. IDOR Prevention

**Threat Mitigated:** Insecure Direct Object Reference attacks

```python
from proxilion.guardrails import IDORProtection

idor = IDORProtection()

# Define ownership rules
idor.add_ownership_rule(
    resource_type="document",
    owner_field="owner_id",
    allowed_roles=["admin"]  # Admins can access any
)

# Check access
result = idor.check_access(
    user=user_context,
    resource_type="document",
    resource_id="doc_456",
    resource_owner="user_123"  # Different user
)

if not result.allowed:
    raise IDORViolationError(result.reason)
```

**Security Properties:**
- Ownership checked at runtime, not in queries
- Admin overrides are explicit and logged
- Resource IDs cannot be guessed to gain access

### 5. Integrity Verification

**Threat Mitigated:** Context manipulation, replay attacks

```python
from proxilion.guardrails import ContextIntegrity

integrity = ContextIntegrity(
    secret_key="your-256-bit-secret-key",
    algorithm="HMAC-SHA256"
)

# Sign context when created
user_context = UserContext(user_id="alice", roles=["analyst"])
signed_context = integrity.sign(user_context.model_dump())

# Verify context hasn't been tampered
verification = integrity.verify(signed_context)
if not verification.valid:
    raise ContextIntegrityError(
        f"Context tampering detected: {verification.reason}"
    )
```

**Security Properties:**
- HMAC-SHA256 provides cryptographic integrity
- Secret key required to forge signatures
- Timestamps prevent replay attacks

### 6. Intent Capsules

**Threat Mitigated:** Intent hijacking, goal drift

```python
from proxilion.guardrails import IntentCapsule

# Declare intent at session start
capsule = IntentCapsule(
    intent="Summarize Q3 sales data",
    allowed_tools=["database_query", "chart_generator"],
    allowed_resources=["sales_db"],
    constraints={
        "query_types": ["SELECT"],
        "date_range": "2024-Q3"
    },
    expires_at=datetime.now() + timedelta(hours=1)
)

# Verify tool calls match intent
if not capsule.verify_tool_call(tool_name="database_query", args={"table": "users"}):
    raise IntentHijackError("Tool call outside declared intent scope")
```

**Security Properties:**
- Intent declared upfront, cannot be modified
- Tool calls verified against declared scope
- Expiration prevents stale intents

### 7. Behavioral Drift Detection

**Threat Mitigated:** Gradual compromise, anomaly detection

```python
from proxilion.guardrails import BehavioralMonitor

monitor = BehavioralMonitor(
    agent_id="customer-service-agent",
    baseline_window=100,  # Learn from first 100 calls
    z_score_threshold=3.0  # 3 standard deviations = anomaly
)

# Record each action
monitor.record_action(
    tool_name="send_email",
    parameters={"to": "customer@example.com"},
    timestamp=datetime.now()
)

# Check for drift
drift_result = monitor.check_drift()
if drift_result.is_drifting:
    alert(f"Behavioral anomaly: {drift_result.anomalies}")
```

**Detection Methods:**
- Statistical analysis (z-score) on action patterns
- Tool usage frequency monitoring
- Time-of-day pattern analysis
- Parameter distribution changes

### 8. Kill Switch

**Threat Mitigated:** Runaway agents, emergency situations

```python
from proxilion.guardrails import KillSwitch

kill_switch = KillSwitch()

# Configure kill conditions
kill_switch.add_condition("cost_exceeded", lambda: total_cost > 1000)
kill_switch.add_condition("error_rate", lambda: error_rate > 0.5)
kill_switch.add_condition("manual", lambda: manual_halt_requested)

# Check before each operation
if kill_switch.is_triggered():
    raise EmergencyHaltError(
        f"Kill switch triggered: {kill_switch.triggered_conditions}"
    )
```

**Kill Switch Properties:**
- Immediate halt—no graceful degradation
- Multiple trigger conditions supported
- Manual override always available
- All halts logged with reason

### 9. Rate Limiting

**Threat Mitigated:** Resource exhaustion, DoS, cost attacks

```python
from proxilion import rate_limited

# Per-user rate limit
@rate_limited(
    max_calls=100,
    window_seconds=60,
    key_func=lambda user: user.user_id  # Per-user tracking
)
async def expensive_operation(user: UserContext):
    pass

# Fails immediately on 101st call in window
# No "soft" limits—hard enforcement
```

**Security Properties:**
- Token bucket algorithm—mathematically precise
- Per-user, per-agent, or global limits
- No bypass possible via any input

### 10. Circuit Breaker

**Threat Mitigated:** Cascading failures, dependency attacks

```python
from proxilion import circuit_protected

@circuit_protected(
    failure_threshold=5,      # Open after 5 failures
    recovery_timeout=60,      # Stay open 60 seconds
    half_open_max_calls=1     # Allow 1 test call
)
async def external_api_call():
    pass
```

**States:**
- **CLOSED**: Normal operation
- **OPEN**: All calls rejected immediately
- **HALF_OPEN**: One test call allowed

### 11. Audit Logging

**Threat Mitigated:** Repudiation, forensic gaps

```python
from proxilion.audit import AuditLogger

logger = AuditLogger(
    log_path="./logs/audit.jsonl",
    enable_hash_chain=True,  # Tamper-evident chain
    rotation_size_mb=100,
    retention_days=90
)

# Automatic logging of all authorization decisions
# Each entry contains:
# - Timestamp (ISO 8601)
# - User/Agent context
# - Tool call details
# - Decision and reason
# - Previous hash (chain integrity)
# - Current hash
```

**Tamper Detection:**
```python
from proxilion.audit import verify_audit_chain

result = verify_audit_chain("./logs/audit.jsonl")
if not result.valid:
    alert(f"Audit log tampering at entry {result.break_point}")
```

## Cryptographic Primitives

Proxilion uses standard, well-vetted cryptographic primitives:

| Purpose | Algorithm | Key Size |
|---------|-----------|----------|
| Integrity (HMAC) | HMAC-SHA256 | 256 bits |
| Hash Chain | SHA-256 | 256 bits |
| Signatures (optional) | Ed25519 | 256 bits |
| Encryption (optional) | AES-256-GCM | 256 bits |

## Security Recommendations

### Development

1. **Use strong secret keys**
   ```python
   import secrets
   secret_key = secrets.token_hex(32)  # 256 bits
   ```

2. **Enable all security layers**
   ```python
   auth = Proxilion(
       enable_audit=True,
       enable_integrity=True,
       enable_rate_limiting=True
   )
   ```

3. **Define restrictive policies first**
   ```python
   # Deny by default, allow explicitly
   @auth.policy("default")
   class DefaultPolicy(Policy):
       def evaluate(self, context):
           return False  # Deny unless specific policy allows
   ```

### Production

1. **Secure audit logs**
   - Store on write-once storage if possible
   - Enable hash chain verification
   - Regular integrity checks

2. **Monitor behavioral drift**
   - Set appropriate thresholds for your use case
   - Alert on anomalies, don't auto-block initially
   - Tune based on observed patterns

3. **Configure appropriate rate limits**
   - Start conservative, adjust based on usage
   - Different limits for different operations
   - Consider cost-based limits for expensive APIs

4. **Regular security reviews**
   - Review policies quarterly
   - Audit log analysis for patterns
   - Update validation rules for new threats

## Compliance

Proxilion helps with compliance requirements:

| Regulation | Proxilion Features |
|------------|-------------------|
| **SOC 2** | Audit logging, access controls, integrity verification |
| **GDPR** | Data access logging, user context tracking |
| **HIPAA** | Access controls, audit trails, integrity |
| **CA SB 53** | Explainable decisions with legal format |
| **PCI DSS** | Access logging, input validation, integrity |

## Next Steps

- [Features Guide](./features/README.md) - Detailed feature documentation
- [Quickstart](./quickstart.md) - Get started quickly
