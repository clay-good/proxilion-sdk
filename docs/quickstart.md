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

## Next Steps

- [Core Concepts](./concepts.md) - Understand deterministic vs probabilistic security
- [Security Model](./security.md) - Deep dive into the security architecture
- [Features Guide](./features/README.md) - Detailed feature documentation
