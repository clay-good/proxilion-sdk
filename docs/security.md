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
from proxilion.guards.input_guard import InputGuard, InjectionPattern

guard = InputGuard()

# SQL Injection prevention
guard.add_pattern(InjectionPattern(
    name="sql_injection",
    pattern=r"(\bUNION\b.*\bSELECT\b|\bDROP\b|\bDELETE\b|\b--\b|;\s*$)",
    severity=1.0,
    description="SQL injection attempt detected"
))

# Command injection prevention
guard.add_pattern(InjectionPattern(
    name="command_injection",
    pattern=r"(;\s*|\||\$\(|`|&&|\|\|)",
    severity=1.0,
    description="Command injection attempt detected"
))

# Path traversal prevention
guard.add_pattern(InjectionPattern(
    name="path_traversal",
    pattern=r"(\.\.\/|\.\.\\|%2e%2e|%252e)",
    severity=0.8,
    description="Path traversal attempt detected"
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

    def can_read(self, context) -> bool:
        # Require explicit permission
        if "data:sensitive:read" not in self.user.attributes.get("permissions", []):
            return False

        # Require specific role
        if "security_analyst" not in self.user.roles:
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
from proxilion.security import AgentTrustManager, AgentTrustLevel

trust_manager = AgentTrustManager(secret_key="your-secret-key")

# Register agent with capabilities
trust_manager.register_agent(
    agent_id="research-agent",
    trust_level=AgentTrustLevel.LIMITED,
    capabilities=["web:search", "file:read"],
    # Cannot: file:write, db:execute, api:call
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
from proxilion import AuthorizationError
from proxilion.security import IDORProtector

protector = IDORProtector()

# Register what each user can access
protector.register_scope("user_123", "document", {"doc_1", "doc_2"})
protector.register_scope("admin_456", "document", {"doc_1", "doc_2", "doc_3"})

# Validate before tool execution
if not protector.validate_access("user_123", "document", "doc_3"):
    raise AuthorizationError("Access denied")
```

**Security Properties:**
- Ownership checked at runtime, not in queries
- Admin overrides are explicit and logged
- Resource IDs cannot be guessed to gain access

### 5. Integrity Verification

**Threat Mitigated:** Context manipulation, replay attacks

```python
from proxilion import ContextIntegrityError
from proxilion.security import MemoryIntegrityGuard

guard = MemoryIntegrityGuard(secret_key="your-256-bit-secret-key")

# Sign each message in conversation
msg1 = guard.sign_message("user", "Help me with Python")
msg2 = guard.sign_message("assistant", "Sure! What do you need?")

# Verify entire context is intact
result = guard.verify_context([msg1, msg2])
if not result.valid:
    raise ContextIntegrityError(
        f"Context tampering detected: {result.violations}"
    )
```

**Security Properties:**
- HMAC-SHA256 provides cryptographic integrity
- Secret key required to forge signatures
- Timestamps prevent replay attacks

### 6. Intent Capsules

**Threat Mitigated:** Intent hijacking, goal drift

```python
from proxilion.security import IntentCapsule, IntentGuard

# Create capsule with original intent
capsule = IntentCapsule.create(
    user_id="alice",
    intent="Summarize Q3 sales data",
    secret_key="your-secret-key",
    allowed_tools=["database_query", "chart_generator"],
)

# Guard validates tool calls against original intent
guard = IntentGuard(capsule, "your-secret-key")

# Valid - matches allowed tools
assert guard.validate_tool_call("database_query", {"table": "sales"})

# Blocked - not in allowed tools
assert not guard.validate_tool_call("delete_table", {"table": "users"})
```

**Security Properties:**
- Intent declared upfront, cannot be modified
- Tool calls verified against declared scope
- Expiration prevents stale intents

### 7. Behavioral Drift Detection

**Threat Mitigated:** Gradual compromise, anomaly detection

```python
from proxilion.security.behavioral_drift import BehavioralMonitor

monitor = BehavioralMonitor(
    agent_id="customer-service-agent",
    drift_threshold=3.0,  # 3 standard deviations = anomaly
)

# Record each action
monitor.record_tool_call(
    tool_name="send_email",
    latency_ms=50.0,
)

# Lock baseline after sufficient samples
monitor.lock_baseline()

# Check for drift
drift_result = monitor.check_drift()
if drift_result.is_drifting:
    print(f"Behavioral anomaly: {drift_result.reason}")
```

**Detection Methods:**
- Statistical analysis (z-score) on action patterns
- Tool usage frequency monitoring
- Time-of-day pattern analysis
- Parameter distribution changes

### 8. Kill Switch

**Threat Mitigated:** Runaway agents, emergency situations

```python
from proxilion import EmergencyHaltError
from proxilion.security.behavioral_drift import KillSwitch

kill_switch = KillSwitch()

# Activate kill switch when needed
kill_switch.activate(
    reason="Severe behavioral drift detected",
    raise_exception=True,  # Halts all operations
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
from proxilion.audit import AuditLogger, LoggerConfig

config = LoggerConfig.default("./logs/audit.jsonl")
logger = AuditLogger(config)

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
# Verify integrity of audit log
result = logger.verify()
if result.valid:
    print("Audit log integrity verified")
else:
    print(f"Audit log tampering detected: {result.error}")
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
       def can_read(self, context):
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
