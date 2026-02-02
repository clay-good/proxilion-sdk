"""
Proxilion: Application-layer security SDK for LLM tool call authorization.

Proxilion provides user-context authorization for agentic AI systems,
ensuring that LLM tool calls are validated against user identity and
business rules before execution.

Basic Usage:
    >>> from proxilion import Proxilion, Policy, UserContext
    >>>
    >>> # Initialize SDK
    >>> auth = Proxilion(
    ...     policy_engine="simple",
    ...     audit_log_path="./logs/audit.jsonl"
    ... )
    >>>
    >>> # Define a policy
    >>> @auth.policy("database_query")
    ... class DatabaseQueryPolicy(Policy):
    ...     def can_execute(self, context):
    ...         return "analyst" in self.user.roles
    >>>
    >>> # Protect a tool
    >>> @auth.authorize("execute", resource="database_query")
    ... async def database_query_tool(query: str, user: UserContext = None):
    ...     return await execute_query(query)
    >>>
    >>> # Use it
    >>> user = UserContext(user_id="alice", roles=["analyst"])
    >>> result = await database_query_tool("SELECT * FROM data", user=user)

For more information, see the documentation at:
https://proxilion.com

Source code: https://github.com/clay-good/proxilion-sdk
"""

__version__ = "0.0.2"

# Core types - always available
# Main Proxilion class
from proxilion.core import (
    Proxilion,
    get_current_agent,
    get_current_user,
)

# Decorators
from proxilion.decorators import (
    AlwaysApproveStrategy,
    AlwaysDenyStrategy,
    ApprovalStrategy,
    CallbackApprovalStrategy,
    QueueApprovalStrategy,
    authorize_tool_call,
    circuit_protected,
    rate_limited,
    require_approval,
)

# Exceptions - always available
from proxilion.exceptions import (
    AgentTrustError,
    AuthorizationError,
    BehavioralDriftError,
    CircuitOpenError,
    ConfigurationError,
    ContextIntegrityError,
    EmergencyHaltError,
    IDORViolationError,
    IntentHijackError,
    PolicyNotFoundError,
    PolicyViolation,
    ProxilionError,
    RateLimitExceeded,
    SchemaValidationError,
)

# Policy base class
from proxilion.policies.base import Policy
from proxilion.types import (
    AgentContext,
    AuditEvent,
    AuthorizationResult,
    ToolCallRequest,
    UserContext,
)

# Convenient type aliases
authorize = authorize_tool_call  # Alias for backwards compatibility

__all__ = [
    # Version
    "__version__",
    # Main class
    "Proxilion",
    # Policy
    "Policy",
    # Core types
    "UserContext",
    "AgentContext",
    "ToolCallRequest",
    "AuthorizationResult",
    "AuditEvent",
    # Exceptions
    "ProxilionError",
    "AuthorizationError",
    "PolicyViolation",
    "SchemaValidationError",
    "RateLimitExceeded",
    "CircuitOpenError",
    "ConfigurationError",
    "PolicyNotFoundError",
    "IDORViolationError",
    # ASI Top 10 exceptions
    "ContextIntegrityError",
    "IntentHijackError",
    "AgentTrustError",
    "BehavioralDriftError",
    "EmergencyHaltError",
    # Decorators
    "authorize_tool_call",
    "authorize",
    "require_approval",
    "rate_limited",
    "circuit_protected",
    # Approval strategies
    "ApprovalStrategy",
    "AlwaysApproveStrategy",
    "AlwaysDenyStrategy",
    "CallbackApprovalStrategy",
    "QueueApprovalStrategy",
    # Context helpers
    "get_current_user",
    "get_current_agent",
]
