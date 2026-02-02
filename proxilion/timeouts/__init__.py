"""
Timeout and deadline management for AI agent operations.

Provides configurable timeout handling for tool calls, LLM operations,
and overall request budgets. Essential for WebSocket/real-time applications
where responsiveness is critical.

Example:
    >>> from proxilion.timeouts import (
    ...     TimeoutManager, TimeoutConfig, DeadlineContext,
    ...     with_timeout, with_deadline,
    ... )
    >>>
    >>> # Configure timeouts
    >>> config = TimeoutConfig(
    ...     default_timeout=30.0,
    ...     tool_timeouts={"web_search": 60.0, "database_query": 10.0},
    ...     llm_timeout=120.0,
    ... )
    >>> manager = TimeoutManager(config)
    >>>
    >>> # Use deadline context for request budget
    >>> async with DeadlineContext(timeout=60.0) as deadline:
    ...     result1 = await tool1(timeout=deadline.remaining())
    ...     result2 = await tool2(timeout=deadline.remaining())
    >>>
    >>> # Use decorator for individual functions
    >>> @with_timeout(10.0)
    ... async def quick_operation():
    ...     return await some_api_call()
"""

from proxilion.timeouts.decorators import (
    with_deadline,
    with_timeout,
)
from proxilion.timeouts.manager import (
    DeadlineContext,
    TimeoutConfig,
    TimeoutManager,
)
from proxilion.timeouts.manager import (
    TimeoutError as ProxilionTimeoutError,
)

__all__ = [
    # Manager classes
    "DeadlineContext",
    "TimeoutConfig",
    "TimeoutManager",
    "ProxilionTimeoutError",
    # Decorators
    "with_deadline",
    "with_timeout",
]
