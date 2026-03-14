# Authorization Engine

The core of Proxilion—deterministic policy-based authorization.

## Overview

The Authorization Engine evaluates every tool call against defined policies before execution. Unlike LLM-based authorization, policies are code—deterministic, auditable, and immune to prompt injection.

## Basic Usage

### Initialize Proxilion

```python
from proxilion import Proxilion

auth = Proxilion()
```

### Define a Policy

```python
from proxilion import Policy

@auth.policy("file_access")
class FileAccessPolicy(Policy):
    """Users can only access their own files."""

    def can_read(self, context) -> bool:
        file_owner = context.get("owner_id")

        # Simple ownership check
        return self.user.user_id == file_owner
```

### Protect a Tool

```python
@auth.authorize("read", resource="file_access")
async def read_file(path: str, owner_id: str, user: UserContext = None):
    """Read a file - only accessible to the owner."""
    with open(path) as f:
        return f.read()
```

### Execute with Context

```python
from proxilion import UserContext

user = UserContext(
    user_id="alice",
    roles=["user"],
)

# Allowed - alice accessing her own file
content = await read_file("/data/alice/notes.txt", owner_id="alice", user=user)

# Denied - alice trying to access bob's file
try:
    content = await read_file("/data/bob/secrets.txt", owner_id="bob", user=user)
except AuthorizationError:
    print("Access denied")
```

## Policy Evaluation Context

Each policy has access to `self.user` (the authenticated user) and `self.resource` (the resource being accessed). The `can_<action>` methods receive an optional `context` dict with additional runtime information:

```python
class MyPolicy(Policy):
    def can_read(self, context) -> bool:
        # User making the request (via self.user)
        self.user.user_id      # "alice"
        self.user.roles        # ["user", "analyst"]
        self.user.attributes   # {"department": "engineering"}

        # Additional context passed at authorization time
        owner_id = context.get("owner_id")

        return self.user.user_id == owner_id
```

## Policy Patterns

### Role-Based Access Control (RBAC)

```python
@auth.policy("admin_panel")
class AdminPolicy(Policy):
    """Only admins can access admin panel."""

    def can_read(self, context) -> bool:
        return "admin" in self.user.roles
```

### Permission-Based Access Control

```python
@auth.policy("database")
class DatabasePolicy(Policy):
    """Check specific permissions for database operations."""

    def can_read(self, context) -> bool:
        return "db:read" in self.user.attributes.get("permissions", [])

    def can_write(self, context) -> bool:
        return "db:write" in self.user.attributes.get("permissions", [])

    def can_delete(self, context) -> bool:
        return "db:delete" in self.user.attributes.get("permissions", [])
```

### Attribute-Based Access Control (ABAC)

```python
@auth.policy("department_data")
class DepartmentPolicy(Policy):
    """Users can only access their department's data."""

    def can_read(self, context) -> bool:
        user_dept = self.user.attributes.get("department")
        data_dept = context.get("department")

        return user_dept == data_dept
```

### Time-Based Access Control

```python
from datetime import datetime

@auth.policy("business_hours")
class BusinessHoursPolicy(Policy):
    """Restrict access to business hours."""

    def can_read(self, context) -> bool:
        now = datetime.now()

        # Weekdays only
        if now.weekday() >= 5:  # Saturday = 5, Sunday = 6
            return False

        # 9 AM to 6 PM only
        if not (9 <= now.hour < 18):
            return False

        return True
```

### Composite Policies

```python
@auth.policy("sensitive_operation")
class SensitivePolicy(Policy):
    """Multiple conditions for sensitive operations."""

    def can_execute(self, context) -> bool:
        # Must have explicit permission
        if "sensitive:access" not in self.user.attributes.get("permissions", []):
            return False

        # Must be in security team
        if "security" not in self.user.roles:
            return False

        # Must be during business hours
        hour = datetime.now().hour
        if not (9 <= hour < 18):
            return False

        # Must not exceed daily limit (custom attribute)
        daily_access = self.user.attributes.get("daily_sensitive_access", 0)
        if daily_access >= 10:
            return False

        return True
```

## Authorization Results

Use `check()` to get detailed authorization results:

```python
result = await auth.check(
    user=user,
    action="read",
    resource="file_access",
    parameters={"owner_id": "bob"}
)

result.allowed      # False
result.reason       # "Policy 'file_access' denied access"
result.policy_name  # "file_access"
result.evaluated_at # datetime
```

## Agent Context

When agents make tool calls on behalf of users:

```python
from proxilion import UserContext, AgentContext

user = UserContext(user_id="alice", roles=["user"])
agent = AgentContext(
    agent_id="research-agent",
    capabilities=["read", "search"],
    trust_score=0.5,
)

@auth.policy("agent_restricted")
class AgentRestrictedPolicy(Policy):
    """Agents have restricted access compared to direct users."""

    def can_read(self, context) -> bool:
        # Check if data is public
        is_public = context.get("public", False)
        if is_public:
            return True

        # Only users with data:read can access private data
        return "data:read" in self.user.attributes.get("permissions", [])
```

## Error Handling

```python
from proxilion import AuthorizationError, PolicyViolation

try:
    result = await protected_tool(user=user)
except AuthorizationError as e:
    # Generic authorization failure
    print(f"Access denied: {e}")
except PolicyViolation as e:
    # Specific policy violation
    print(f"Policy violated: {e.policy_name}")
    print(f"Reason: {e.reason}")
```

## Performance

The authorization engine is designed for high performance:

- **Latency**: < 1ms per authorization check
- **Throughput**: 100,000+ checks/second (single core)
- **Memory**: O(1) per check, O(n) for n policies

All policy evaluation is synchronous and blocking—no async overhead for simple checks.

## Best Practices

1. **Deny by default**: Create a default policy that denies access
   ```python
   @auth.policy("default")
   class DefaultPolicy(Policy):
       def can_read(self, context):
           return False
   ```

2. **Keep policies simple**: One policy, one concern
3. **Use specific resources**: `file:documents` not just `file`
4. **Log all decisions**: Enable audit logging
5. **Test edge cases**: Empty roles, missing permissions, null values

## Next Steps

- [Security Model](../security.md) - Deep dive into security architecture
- [Core Concepts](../concepts.md) - Deterministic vs probabilistic security
- [Quickstart](../quickstart.md) - Get started quickly
