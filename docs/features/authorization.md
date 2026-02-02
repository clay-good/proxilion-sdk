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

    def evaluate(self, context) -> bool:
        user = context.user
        file_owner = context.tool_call.parameters.get("owner_id")

        # Simple ownership check
        return user.user_id == file_owner
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
    permissions=["file:read"]
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

Every policy receives a `PolicyContext` with full request details:

```python
class MyPolicy(Policy):
    def evaluate(self, context) -> bool:
        # User making the request
        user = context.user
        user.user_id      # "alice"
        user.roles        # ["user", "analyst"]
        user.permissions  # ["file:read", "db:query"]
        user.attributes   # {"department": "engineering"}

        # Agent making the call (if applicable)
        agent = context.agent
        agent.agent_id    # "research-agent"
        agent.trust_level # TrustLevel.LIMITED

        # The tool call being authorized
        tool_call = context.tool_call
        tool_call.tool_name   # "read_file"
        tool_call.action      # "read"
        tool_call.resource    # "file_access"
        tool_call.parameters  # {"path": "/data/...", "owner_id": "alice"}

        return True  # or False
```

## Policy Patterns

### Role-Based Access Control (RBAC)

```python
@auth.policy("admin_panel")
class AdminPolicy(Policy):
    """Only admins can access admin panel."""

    def evaluate(self, context) -> bool:
        return "admin" in context.user.roles
```

### Permission-Based Access Control

```python
@auth.policy("database")
class DatabasePolicy(Policy):
    """Check specific permissions for database operations."""

    PERMISSION_MAP = {
        "read": "db:read",
        "write": "db:write",
        "delete": "db:delete",
        "admin": "db:admin"
    }

    def evaluate(self, context) -> bool:
        action = context.tool_call.action
        required_permission = self.PERMISSION_MAP.get(action)

        if not required_permission:
            return False

        return required_permission in context.user.permissions
```

### Attribute-Based Access Control (ABAC)

```python
@auth.policy("department_data")
class DepartmentPolicy(Policy):
    """Users can only access their department's data."""

    def evaluate(self, context) -> bool:
        user_dept = context.user.attributes.get("department")
        data_dept = context.tool_call.parameters.get("department")

        return user_dept == data_dept
```

### Time-Based Access Control

```python
from datetime import datetime

@auth.policy("business_hours")
class BusinessHoursPolicy(Policy):
    """Restrict access to business hours."""

    def evaluate(self, context) -> bool:
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

    def evaluate(self, context) -> bool:
        user = context.user

        # Must have explicit permission
        if "sensitive:access" not in user.permissions:
            return False

        # Must be in security team
        if "security" not in user.roles:
            return False

        # Must be during business hours
        hour = datetime.now().hour
        if not (9 <= hour < 18):
            return False

        # Must not exceed daily limit (custom attribute)
        daily_access = user.attributes.get("daily_sensitive_access", 0)
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
    trust_level=TrustLevel.LIMITED
)

@auth.policy("agent_restricted")
class AgentRestrictedPolicy(Policy):
    """Agents have restricted access compared to direct users."""

    def evaluate(self, context) -> bool:
        # If no agent, user has full access based on permissions
        if not context.agent:
            return "data:read" in context.user.permissions

        # Agents are more restricted
        if context.agent.trust_level < TrustLevel.STANDARD:
            # Limited agents can only read public data
            is_public = context.tool_call.parameters.get("public", False)
            return is_public

        return True
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
       def evaluate(self, context):
           return False
   ```

2. **Keep policies simple**: One policy, one concern
3. **Use specific resources**: `file:documents` not just `file`
4. **Log all decisions**: Enable audit logging
5. **Test edge cases**: Empty roles, missing permissions, null values

## Next Steps

- [Input Validation](./input-validation.md) - Add input security
- [Rate Limiting](./rate-limiting.md) - Prevent abuse
- [Audit Logging](./audit-logging.md) - Track all decisions
