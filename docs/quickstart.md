# Quickstart Guide

Get Proxilion running in under 5 minutes.

## Installation

```bash
pip install proxilion
```

## Basic Setup

### 1. Initialize Proxilion

```python
from proxilion import Proxilion, UserContext, AgentContext

# Create Proxilion instance
auth = Proxilion()
```

### 2. Define Your First Policy

```python
from proxilion import Policy

@auth.policy("file_access")
class FileAccessPolicy(Policy):
    """Only allow users to access their own files."""

    def can_read(self, context):
        # Get the file being accessed
        file_owner = context.get("owner_id")

        # Users can only access their own files
        return self.user.user_id == file_owner
```

### 3. Protect a Tool

```python
@auth.authorize("read", resource="file_access")
async def read_file(file_path: str, owner_id: str, user: UserContext = None):
    """Read a file - only accessible to the file owner."""
    with open(file_path) as f:
        return f.read()
```

### 4. Use It

```python
import asyncio

async def main():
    # Create user context
    user = UserContext(
        user_id="alice",
        roles=["user"],
    )

    # This works - Alice accessing her own file
    content = await read_file("/data/alice/notes.txt", owner_id="alice", user=user)

    # This fails - Alice trying to access Bob's file
    try:
        content = await read_file("/data/bob/secrets.txt", owner_id="bob", user=user)
    except AuthorizationError as e:
        print(f"Access denied: {e}")

asyncio.run(main())
```

## Adding Rate Limiting

Prevent abuse with deterministic rate limits:

```python
from proxilion import rate_limited

@rate_limited(max_calls=100, window_seconds=60)  # 100 calls per minute
@auth.authorize("execute", resource="api_call")
async def call_external_api(endpoint: str, user: UserContext = None):
    return await make_api_call(endpoint)
```

## Adding Input Validation

Detect and block dangerous inputs before they reach your tools:

```python
from proxilion.guards.input_guard import InputGuard, InjectionPattern

guard = InputGuard()

# Block SQL injection attempts
guard.add_pattern(InjectionPattern(
    name="sql_injection",
    pattern=r"(\bUNION\b|\bSELECT\b.*\bFROM\b|\bDROP\b|\bDELETE\b)",
    severity=1.0,
    description="SQL injection detected"
))

# Block API key leakage
guard.add_pattern(InjectionPattern(
    name="api_key_leak",
    pattern=r"(sk-[a-zA-Z0-9]{20,}|api[_-]?key[=:]\s*['\"]?[\w-]+)",
    severity=0.9,
    description="API key detected"
))

# Check input before processing
result = guard.check(user_input)
if not result.passed:
    raise SecurityError(result.message)
```

## Adding Audit Logging

Track all authorization decisions:

```python
from proxilion.audit import AuditLogger, LoggerConfig

# Create audit logger with tamper-evident chain
config = LoggerConfig.default("./logs/audit.jsonl")
logger = AuditLogger(config)

# Logs are automatically created for all authorization decisions
# Each entry includes:
# - Timestamp
# - User/Agent context
# - Tool call details
# - Decision (allow/deny)
# - Policy that matched
# - Hash chain for tamper detection
```

## Full Example

Here's a complete example combining multiple features:

```python
import asyncio
from proxilion import (
    AuthorizationError,
    Proxilion,
    Policy,
    UserContext,
    rate_limited,
    circuit_protected,
)
from proxilion.guards.input_guard import InputGuard, InjectionPattern
from proxilion.audit import AuditLogger, LoggerConfig

# Initialize
auth = Proxilion()
config = LoggerConfig.default("./logs/audit.jsonl")
logger = AuditLogger(config)

# Input validation
guard = InputGuard()
guard.add_pattern(InjectionPattern(
    name="dangerous_command",
    pattern=r"(rm\s+-rf|sudo|chmod\s+777)",
    severity=1.0,
    description="Dangerous command pattern"
))

# Define policy
@auth.policy("database")
class DatabasePolicy(Policy):
    def can_execute(self, context):
        # Admins can do anything
        if "admin" in self.user.roles:
            return True
        # Users can only SELECT
        query = context.get("query", "")
        return query.strip().upper().startswith("SELECT")

# Protected tool with multiple layers
@circuit_protected(failure_threshold=5, recovery_timeout=60)
@rate_limited(max_calls=50, window_seconds=60)
@auth.authorize("execute", resource="database")
async def execute_query(query: str, user: UserContext = None):
    # Validate input
    result = validator.validate(query)
    if not result.is_safe:
        raise ValueError(result.message)

    # Execute query
    return await db.execute(query)

# Usage
async def main():
    user = UserContext(user_id="analyst", roles=["user"])

    # Allowed - SELECT query by user
    results = await execute_query("SELECT * FROM sales", user=user)

    # Denied - DELETE query by non-admin
    try:
        await execute_query("DELETE FROM users", user=user)
    except AuthorizationError:
        print("Only admins can modify data")

asyncio.run(main())
```

## Decorator-Based API

Proxilion provides standalone decorators for quick integration without full Proxilion setup.

### @authorize_tool_call

Automatically authorize tool calls based on a policy:

```python
from proxilion.decorators import authorize_tool_call
from proxilion import UserContext
from proxilion.policies import RoleBasedPolicy

# Create a simple role-based policy
policy = RoleBasedPolicy(
    role_permissions={
        "admin": ["read", "write", "delete"],
        "user": ["read"],
    }
)

@authorize_tool_call(policy)
def delete_user(user_id: str, user_context: UserContext):
    """Delete a user - admin only."""
    # Policy automatically checks if user has 'admin' role
    return db.delete_user(user_id)

# Usage
admin = UserContext(user_id="alice", roles=["admin"])
delete_user("bob", user_context=admin)  # Allowed

user = UserContext(user_id="bob", roles=["user"])
delete_user("alice", user_context=user)  # Raises AuthorizationDenied
```

### @rate_limited

Apply rate limiting to any function:

```python
from proxilion.decorators import rate_limited
from proxilion.security import TokenBucketRateLimiter

# Create rate limiter (100 requests, 10/sec refill)
limiter = TokenBucketRateLimiter(capacity=100, refill_rate=10)

@rate_limited(limiter, key_func=lambda user_id, **kw: user_id)
def expensive_operation(user_id: str, data: dict) -> dict:
    """Rate limited per user."""
    return process_data(data)

# Usage
result = expensive_operation("alice", {"query": "..."})  # OK
# After 100 calls in quick succession:
# expensive_operation("alice", {"query": "..."})  # Raises RateLimitExceeded
```

### @circuit_protected

Protect against cascading failures:

```python
from proxilion.decorators import circuit_protected

@circuit_protected(
    failure_threshold=5,      # Open circuit after 5 failures
    reset_timeout=30.0,       # Try again after 30 seconds
)
def call_external_api(endpoint: str) -> dict:
    """Call external API with circuit breaker protection."""
    response = requests.get(endpoint)
    response.raise_for_status()
    return response.json()

# If API fails 5 times, circuit opens
# Further calls raise CircuitOpenError immediately
# After 30 seconds, circuit tries again (half-open state)
```

### @require_approval

Require human approval before execution:

```python
from proxilion.decorators import require_approval

def slack_approval_prompt(tool_name: str, arguments: dict) -> bool:
    """Send approval request to Slack."""
    message = f"Approve {tool_name}({arguments})? (yes/no)"
    response = slack.send_message(channel="approvals", text=message)
    return response.lower() == "yes"

@require_approval(approval_func=slack_approval_prompt)
def delete_production_database(db_name: str):
    """Delete production database - requires approval."""
    return db.drop_database(db_name)

# Usage
delete_production_database("users")
# Sends Slack message, waits for response
# If approved: executes
# If denied: raises ApprovalDenied
```

### @cost_limited

Enforce spending budgets on expensive operations:

```python
from proxilion import UserContext
from proxilion.decorators import cost_limited
from proxilion.security.cost_limiter import CostLimiter, CostLimit

# Create limiter with $10/day budget per user
limiter = CostLimiter(limits=[
    CostLimit(max_cost=10.0, period_seconds=86400)
])

@cost_limited(limiter, estimate_cost=0.05)
def call_llm(prompt: str, user: UserContext = None):
    """LLM call costs $0.05 per request."""
    return client.chat(prompt)

# With dynamic cost estimation based on model
MODEL_COSTS = {"gpt-4": 0.10, "gpt-3.5": 0.01}

@cost_limited(limiter, estimate_cost=lambda model, **kw: MODEL_COSTS[model])
def call_model(model: str, prompt: str, user: UserContext = None):
    """Cost depends on which model is used."""
    return client.chat(model, prompt)

# Usage
user = UserContext(user_id="alice", roles=["user"])
call_llm("Hello", user=user)  # OK, $0.05 deducted
# After 200 calls: BudgetExceededError (daily limit reached)
```

### @enforce_scope

Restrict a function to a specific execution scope:

```python
from proxilion import Proxilion, UserContext
from proxilion.decorators import enforce_scope

auth = Proxilion()

@enforce_scope(auth, "read_only")
def handle_user_query(query: str, user: UserContext = None):
    """Only read operations allowed in this context."""
    return search_documents(query)

# Usage
user = UserContext(user_id="alice", roles=["user"])
handle_user_query("sales report", user=user)  # OK - read operations
# If search_documents tries to write, raises ScopeViolationError
```

### @sequence_validated

Validate that tool calls follow defined sequence rules:

```python
from proxilion import Proxilion, UserContext
from proxilion.decorators import sequence_validated
from proxilion.security.sequence_validator import SequenceRule, RuleType

auth = Proxilion()

# Require confirmation before any delete operation
auth.add_sequence_rule(SequenceRule(
    rule_name="confirm_before_delete",
    rule_type=RuleType.REQUIRE_BEFORE,
    target_pattern="delete_*",
    required_prior="confirm_*"
))

@sequence_validated(auth)
def delete_file(path: str, user: UserContext = None):
    """Delete file - requires confirm_* call first."""
    os.remove(path)

# Usage
user = UserContext(user_id="alice", roles=["user"])
delete_file("/data/file.txt", user=user)
# Raises SequenceViolationError if confirm_delete wasn't called first
```

### @scoped_tool

Declare the execution scope required for a tool:

```python
from proxilion import Proxilion, UserContext
from proxilion.decorators import enforce_scope, scoped_tool

auth = Proxilion()

@scoped_tool(auth, action="delete")
def delete_user(user_id: str, user: UserContext = None, _scope_context=None):
    """Delete operation - only allowed in admin scope."""
    remove_user_from_db(user_id)

@enforce_scope(auth, "read_only")
def read_only_handler(user: UserContext = None):
    delete_user("123", user=user)  # Raises ScopeViolationError

@enforce_scope(auth, "admin")
def admin_handler(user: UserContext = None):
    delete_user("123", user=user)  # OK - admin scope allows delete
```

### @authorize (alias)

Shorthand alias for `@authorize_tool_call`:

```python
from proxilion import Proxilion, UserContext
from proxilion.decorators import authorize  # Same as authorize_tool_call

auth = Proxilion()

@authorize(auth, action="execute", resource="search")
async def search(query: str, user: UserContext = None):
    return await perform_search(query)
```

### Combining Decorators

Stack decorators for multi-layered protection:

```python
from proxilion.decorators import authorize_tool_call, rate_limited, circuit_protected
from proxilion.policies import RoleBasedPolicy
from proxilion.security import TokenBucketRateLimiter

policy = RoleBasedPolicy(role_permissions={"admin": ["execute"]})
limiter = TokenBucketRateLimiter(capacity=10, refill_rate=1)

@circuit_protected(failure_threshold=3, reset_timeout=60)
@rate_limited(limiter, key_func=lambda user_ctx, **kw: user_ctx.user_id)
@authorize_tool_call(policy)
def critical_operation(user_context: UserContext, data: dict):
    """
    Critical operation with:
    1. Authorization check (admin role required)
    2. Rate limiting (10 calls, 1/sec refill per user)
    3. Circuit breaker (opens after 3 failures)
    """
    return execute_critical_task(data)
```

### Custom Decorator Parameters

All decorators support additional configuration:

```python
# Rate limiter with custom cost function
@rate_limited(
    limiter,
    key_func=lambda user_id, **kw: user_id,
    cost_func=lambda **kw: kw.get("complexity", 1),  # Variable cost
)
def query_database(user_id: str, query: str, complexity: int = 1):
    """Complex queries cost more tokens."""
    return db.execute(query)

# Circuit breaker with excluded exceptions
@circuit_protected(
    failure_threshold=5,
    reset_timeout=30.0,
    excluded_exceptions=(ValidationError, KeyError),  # Don't count these
)
def process_request(data: dict):
    """Validation errors don't trip the circuit."""
    validate(data)  # ValidationError doesn't count as failure
    return external_api.call(data)  # But network errors do
```

## Next Steps

- [Core Concepts](./concepts.md) - Understand deterministic vs probabilistic security
- [Security Model](./security.md) - Deep dive into the security architecture
- [Features Guide](./features/README.md) - Detailed feature documentation
- [Input Guards](./features/input-guards.md) - Prompt injection protection
- [Output Guards](./features/output-guards.md) - Data leakage prevention
- [Rate Limiting](./features/rate-limiting.md) - Request throttling
- [Security Controls](./features/security-controls.md) - IDOR, circuit breaker, drift detection
- [Audit Logging](./features/audit-logging.md) - Compliance and tamper-evident logs
- [Observability](./features/observability.md) - Metrics, costs, and alerts
