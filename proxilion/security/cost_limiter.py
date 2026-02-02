"""
Cost-based rate limiting for Proxilion.

Rate limit not just by request count, but by dollar spend. Prevents
runaway costs from expensive model calls or high-volume usage.

Example:
    >>> from proxilion.security.cost_limiter import (
    ...     CostLimiter, CostLimit, HybridRateLimiter
    ... )
    >>> from proxilion.observability import CostTracker
    >>> from datetime import timedelta
    >>>
    >>> # Create multi-tier cost limits
    >>> limits = [
    ...     CostLimit(max_cost=1.00, period=timedelta(minutes=1), scope="user"),
    ...     CostLimit(max_cost=10.00, period=timedelta(hours=1), scope="user"),
    ...     CostLimit(max_cost=50.00, period=timedelta(days=1), scope="user"),
    ... ]
    >>>
    >>> tracker = CostTracker()
    >>> limiter = CostLimiter(limits=limits, cost_tracker=tracker)
    >>>
    >>> # Check limit before request
    >>> result = limiter.check_limit("user_123", estimated_cost=0.50)
    >>> if not result.allowed:
    ...     print(f"Limit exceeded: {result.limit_name}")
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class LimitScope(Enum):
    """Scope of a cost limit."""

    USER = "user"
    """Per-user limit."""

    ORG = "org"
    """Organization-wide limit."""

    GLOBAL = "global"
    """Global limit across all users and orgs."""

    TOOL = "tool"
    """Per-tool limit."""


@dataclass
class CostLimit:
    """
    Definition of a cost limit.

    Attributes:
        max_cost: Maximum allowed cost in USD.
        period: Time period for the limit.
        scope: Scope of the limit (user, org, global, tool).
        name: Optional name for the limit.
        description: Optional description.
        warn_at: Percentage (0.0-1.0) at which to warn.
        hard_limit: If True, strictly enforce; if False, just warn.
    """

    max_cost: float
    period: timedelta
    scope: LimitScope | str = LimitScope.USER
    name: str = ""
    description: str = ""
    warn_at: float = 0.8
    hard_limit: bool = True

    def __post_init__(self) -> None:
        if isinstance(self.scope, str):
            self.scope = LimitScope(self.scope.lower())
        if not self.name:
            self.name = f"{self.scope.value}_{self._period_name}"

    @property
    def _period_name(self) -> str:
        """Get a human-readable period name."""
        total_seconds = self.period.total_seconds()
        if total_seconds < 60:
            return f"{int(total_seconds)}s"
        elif total_seconds < 3600:
            return f"{int(total_seconds / 60)}m"
        elif total_seconds < 86400:
            return f"{int(total_seconds / 3600)}h"
        else:
            return f"{int(total_seconds / 86400)}d"


@dataclass
class CostLimitResult:
    """
    Result of a cost limit check.

    Attributes:
        allowed: Whether the request is allowed.
        limit_name: Name of the limit (if exceeded).
        current_spend: Current spend in the period.
        limit: The limit amount.
        remaining: Remaining budget.
        reset_at: When the limit resets.
        warning: True if approaching limit.
        warning_message: Warning message if applicable.
    """

    allowed: bool
    limit_name: str = ""
    current_spend: float = 0.0
    limit: float = 0.0
    remaining: float = 0.0
    reset_at: datetime | None = None
    warning: bool = False
    warning_message: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "allowed": self.allowed,
            "limit_name": self.limit_name,
            "current_spend": self.current_spend,
            "limit": self.limit,
            "remaining": self.remaining,
            "reset_at": self.reset_at.isoformat() if self.reset_at else None,
            "warning": self.warning,
            "warning_message": self.warning_message,
        }


class CostLimiter:
    """
    Enforces cost-based rate limits.

    Tracks spending against configurable limits with multiple tiers
    and scopes (per-user, per-org, global).

    Example:
        >>> limiter = CostLimiter(
        ...     limits=[
        ...         CostLimit(max_cost=1.00, period=timedelta(minutes=1), scope="user"),
        ...         CostLimit(max_cost=50.00, period=timedelta(days=1), scope="user"),
        ...     ],
        ...     cost_tracker=tracker,
        ... )
        >>>
        >>> result = limiter.check_limit("user_123", estimated_cost=0.10)
        >>> if result.allowed:
        ...     # Proceed with request
        ...     pass
    """

    def __init__(
        self,
        limits: list[CostLimit],
        cost_tracker: Any | None = None,  # CostTracker
    ) -> None:
        """
        Initialize the cost limiter.

        Args:
            limits: List of cost limits to enforce.
            cost_tracker: CostTracker instance for spend data.
        """
        self._lock = threading.RLock()
        self._limits = limits
        self._cost_tracker = cost_tracker

        # Internal tracking for when no cost_tracker provided
        self._spend_records: dict[str, list[tuple[datetime, float]]] = {}

    def set_cost_tracker(self, tracker: Any) -> None:
        """
        Set the cost tracker.

        Args:
            tracker: CostTracker instance.
        """
        self._cost_tracker = tracker

    def add_limit(self, limit: CostLimit) -> None:
        """
        Add a cost limit.

        Args:
            limit: The limit to add.
        """
        with self._lock:
            self._limits.append(limit)

    def remove_limit(self, name: str) -> bool:
        """
        Remove a limit by name.

        Args:
            name: Name of the limit to remove.

        Returns:
            True if removed, False if not found.
        """
        with self._lock:
            for i, limit in enumerate(self._limits):
                if limit.name == name:
                    self._limits.pop(i)
                    return True
            return False

    def get_limits(self) -> list[CostLimit]:
        """Get all configured limits."""
        with self._lock:
            return list(self._limits)

    def check_limit(
        self,
        user_id: str,
        estimated_cost: float,
        org_id: str | None = None,
        tool_name: str | None = None,
    ) -> CostLimitResult:
        """
        Check if a request would exceed cost limits.

        Args:
            user_id: User making the request.
            estimated_cost: Estimated cost of the request.
            org_id: Organization ID (for org-scoped limits).
            tool_name: Tool name (for tool-scoped limits).

        Returns:
            CostLimitResult indicating if request is allowed.
        """
        with self._lock:
            now = datetime.now(timezone.utc)
            warnings = []

            for limit in self._limits:
                # Get the appropriate spend based on scope
                current_spend = self._get_spend_for_scope(
                    limit, user_id, org_id, tool_name
                )

                # Calculate remaining and reset time
                remaining = max(0, limit.max_cost - current_spend)
                reset_at = self._calculate_reset_time(limit, now)

                # Check if would exceed limit
                if current_spend + estimated_cost > limit.max_cost:
                    if limit.hard_limit:
                        return CostLimitResult(
                            allowed=False,
                            limit_name=limit.name,
                            current_spend=current_spend,
                            limit=limit.max_cost,
                            remaining=remaining,
                            reset_at=reset_at,
                        )
                    else:
                        # Soft limit - just warn
                        warnings.append(
                            f"Soft limit '{limit.name}' exceeded: "
                            f"${current_spend + estimated_cost:.4f} > ${limit.max_cost:.4f}"
                        )

                # Check warning threshold
                if limit.warn_at > 0:
                    usage_pct = (current_spend + estimated_cost) / limit.max_cost
                    if usage_pct >= limit.warn_at:
                        warnings.append(
                            f"Approaching limit '{limit.name}': "
                            f"{usage_pct * 100:.1f}% of ${limit.max_cost:.2f}"
                        )

            # All limits passed
            result = CostLimitResult(
                allowed=True,
                current_spend=self._get_total_spend(user_id, timedelta(days=1)),
                remaining=self._get_min_remaining(user_id, org_id, tool_name),
            )

            if warnings:
                result.warning = True
                result.warning_message = "; ".join(warnings)

            return result

    def _get_spend_for_scope(
        self,
        limit: CostLimit,
        user_id: str,
        org_id: str | None,
        tool_name: str | None,
    ) -> float:
        """Get spend for a specific limit scope."""
        if self._cost_tracker:
            if limit.scope == LimitScope.USER:
                return self._cost_tracker.get_user_spend(user_id, limit.period)
            elif limit.scope == LimitScope.ORG or limit.scope == LimitScope.GLOBAL:
                return self._cost_tracker.get_org_spend(limit.period)
            elif limit.scope == LimitScope.TOOL and tool_name:
                # Get tool-specific spend from summary
                summary = self._cost_tracker.get_summary(
                    start=datetime.now(timezone.utc) - limit.period
                )
                return summary.by_tool.get(tool_name, 0.0)
        else:
            # Fallback to internal tracking
            return self._get_internal_spend(user_id, limit.period)

        return 0.0

    def _get_internal_spend(self, key: str, period: timedelta) -> float:
        """Get spend from internal tracking."""
        now = datetime.now(timezone.utc)
        cutoff = now - period

        if key not in self._spend_records:
            return 0.0

        total = 0.0
        for timestamp, cost in self._spend_records[key]:
            if timestamp >= cutoff:
                total += cost

        return total

    def _get_total_spend(self, user_id: str, period: timedelta) -> float:
        """Get total spend for a user."""
        if self._cost_tracker:
            return self._cost_tracker.get_user_spend(user_id, period)
        return self._get_internal_spend(user_id, period)

    def _get_min_remaining(
        self,
        user_id: str,
        org_id: str | None,
        tool_name: str | None,
    ) -> float:
        """Get minimum remaining budget across all limits."""
        min_remaining = float("inf")

        for limit in self._limits:
            current = self._get_spend_for_scope(limit, user_id, org_id, tool_name)
            remaining = max(0, limit.max_cost - current)
            min_remaining = min(min_remaining, remaining)

        return min_remaining if min_remaining != float("inf") else 0.0

    def _calculate_reset_time(self, limit: CostLimit, now: datetime) -> datetime:
        """Calculate when a limit period resets."""
        # Align to period boundaries for consistency
        total_seconds = limit.period.total_seconds()

        if total_seconds <= 60:  # Minute or less
            return now.replace(second=0, microsecond=0) + limit.period
        elif total_seconds <= 3600:  # Hour or less
            return now.replace(minute=0, second=0, microsecond=0) + limit.period
        elif total_seconds <= 86400:  # Day or less
            return now.replace(hour=0, minute=0, second=0, microsecond=0) + limit.period
        else:  # Longer periods
            return now + limit.period

    def record_spend(
        self,
        user_id: str,
        actual_cost: float,
        tool_name: str | None = None,
    ) -> None:
        """
        Record actual spend (for internal tracking when no CostTracker).

        Args:
            user_id: User who incurred the cost.
            actual_cost: Actual cost in USD.
            tool_name: Tool that incurred the cost.
        """
        with self._lock:
            now = datetime.now(timezone.utc)

            if user_id not in self._spend_records:
                self._spend_records[user_id] = []

            self._spend_records[user_id].append((now, actual_cost))

            # Clean up old records
            self._cleanup_old_records(user_id)

    def _cleanup_old_records(self, key: str) -> None:
        """Remove records older than max period."""
        if key not in self._spend_records:
            return

        # Find max period
        if self._limits:
            max_period = max(limit.period for limit in self._limits)
        else:
            max_period = timedelta(days=30)
        cutoff = datetime.now(timezone.utc) - max_period

        self._spend_records[key] = [
            (t, c) for t, c in self._spend_records[key]
            if t >= cutoff
        ]

    def get_remaining_budget(
        self,
        user_id: str,
        period: timedelta | None = None,
    ) -> float:
        """
        Get remaining budget for a user.

        Args:
            user_id: User to check.
            period: Specific period (or minimum across all limits).

        Returns:
            Remaining budget in USD.
        """
        if period:
            # Find matching limit
            for limit in self._limits:
                if limit.period == period and limit.scope == LimitScope.USER:
                    current = self._get_total_spend(user_id, period)
                    return max(0, limit.max_cost - current)
            return 0.0
        else:
            return self._get_min_remaining(user_id, None, None)

    def get_spend_by_period(
        self,
        user_id: str,
        period: timedelta,
    ) -> float:
        """
        Get spend for a specific period.

        Args:
            user_id: User to check.
            period: Time period.

        Returns:
            Spend in USD.
        """
        return self._get_total_spend(user_id, period)

    def reset_period(
        self,
        user_id: str,
        limit_name: str | None = None,
    ) -> None:
        """
        Manually reset spend tracking for a user.

        Args:
            user_id: User to reset.
            limit_name: Specific limit to reset (or all).
        """
        with self._lock:
            if user_id in self._spend_records:
                del self._spend_records[user_id]

            logger.info(f"Reset spend tracking for user {user_id}")

    def get_status(
        self,
        user_id: str,
        org_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Get comprehensive status for a user.

        Args:
            user_id: User to check.
            org_id: Organization ID.

        Returns:
            Dictionary with status for all limits.
        """
        status = {
            "user_id": user_id,
            "limits": [],
        }

        now = datetime.now(timezone.utc)

        for limit in self._limits:
            current = self._get_spend_for_scope(limit, user_id, org_id, None)
            remaining = max(0, limit.max_cost - current)
            reset_at = self._calculate_reset_time(limit, now)

            status["limits"].append({
                "name": limit.name,
                "scope": limit.scope.value,
                "period_seconds": limit.period.total_seconds(),
                "max_cost": limit.max_cost,
                "current_spend": current,
                "remaining": remaining,
                "percentage_used": current / limit.max_cost if limit.max_cost > 0 else 0,
                "reset_at": reset_at.isoformat(),
                "hard_limit": limit.hard_limit,
            })

        return status


class HybridRateLimiter:
    """
    Combines request-based and cost-based rate limiting.

    Checks both request rate limits (fast) and cost limits for
    comprehensive protection against abuse.

    Example:
        >>> from proxilion.security.rate_limiter import TokenBucketRateLimiter
        >>>
        >>> hybrid = HybridRateLimiter(
        ...     request_limiter=TokenBucketRateLimiter(rate=10, capacity=100),
        ...     cost_limiter=cost_limiter,
        ... )
        >>>
        >>> allowed, reason = hybrid.allow_request("user_123", estimated_cost=0.10)
    """

    def __init__(
        self,
        request_limiter: Any | None = None,  # TokenBucketRateLimiter
        cost_limiter: CostLimiter | None = None,
    ) -> None:
        """
        Initialize hybrid rate limiter.

        Args:
            request_limiter: Request-based rate limiter.
            cost_limiter: Cost-based rate limiter.
        """
        self._request_limiter = request_limiter
        self._cost_limiter = cost_limiter

    def set_request_limiter(self, limiter: Any) -> None:
        """Set the request limiter."""
        self._request_limiter = limiter

    def set_cost_limiter(self, limiter: CostLimiter) -> None:
        """Set the cost limiter."""
        self._cost_limiter = limiter

    def allow_request(
        self,
        user_id: str,
        estimated_cost: float = 0.0,
        org_id: str | None = None,
        tool_name: str | None = None,
    ) -> tuple[bool, str | None]:
        """
        Check if a request is allowed.

        Args:
            user_id: User making the request.
            estimated_cost: Estimated cost in USD.
            org_id: Organization ID.
            tool_name: Tool being called.

        Returns:
            Tuple of (allowed, reason). If not allowed, reason explains why.
        """
        # Check request rate first (fast check)
        if self._request_limiter:
            # Try different common interfaces
            if hasattr(self._request_limiter, "allow_request"):
                if not self._request_limiter.allow_request(user_id):
                    return False, "Request rate limit exceeded"
            elif hasattr(self._request_limiter, "check"):
                result = self._request_limiter.check(user_id)
                if hasattr(result, "allowed") and not result.allowed:
                    return False, "Request rate limit exceeded"

        # Check cost limit
        if self._cost_limiter and estimated_cost > 0:
            cost_result = self._cost_limiter.check_limit(
                user_id, estimated_cost, org_id, tool_name
            )
            if not cost_result.allowed:
                return False, (
                    f"Cost limit exceeded ({cost_result.limit_name}): "
                    f"${cost_result.current_spend:.2f}/${cost_result.limit:.2f}"
                )

            # Log warnings
            if cost_result.warning:
                logger.warning(
                    f"Cost warning for user {user_id}: {cost_result.warning_message}"
                )

        return True, None

    def record_usage(
        self,
        user_id: str,
        actual_cost: float,
        tool_name: str | None = None,
    ) -> None:
        """
        Record actual usage after request completion.

        Args:
            user_id: User who made the request.
            actual_cost: Actual cost incurred.
            tool_name: Tool that was called.
        """
        if self._cost_limiter:
            self._cost_limiter.record_spend(user_id, actual_cost, tool_name)

    def get_status(self, user_id: str) -> dict[str, Any]:
        """
        Get combined status from both limiters.

        Args:
            user_id: User to check.

        Returns:
            Dictionary with status from both limiters.
        """
        status: dict[str, Any] = {"user_id": user_id}

        if self._request_limiter and hasattr(self._request_limiter, "get_status"):
            status["request_limiter"] = self._request_limiter.get_status(user_id)

        if self._cost_limiter:
            status["cost_limiter"] = self._cost_limiter.get_status(user_id)

        return status


def create_cost_limiter(
    limits: list[CostLimit] | None = None,
    cost_tracker: Any | None = None,
    include_defaults: bool = True,
) -> CostLimiter:
    """
    Factory function to create a CostLimiter.

    Args:
        limits: Custom limits to use.
        cost_tracker: CostTracker for spend data.
        include_defaults: Whether to include sensible default limits.

    Returns:
        Configured CostLimiter instance.
    """
    all_limits = []

    if include_defaults:
        # Sensible default limits
        all_limits.extend([
            CostLimit(
                max_cost=1.00,
                period=timedelta(minutes=1),
                scope=LimitScope.USER,
                name="user_burst",
                description="Burst protection",
            ),
            CostLimit(
                max_cost=10.00,
                period=timedelta(hours=1),
                scope=LimitScope.USER,
                name="user_hourly",
                description="Hourly cap",
            ),
            CostLimit(
                max_cost=50.00,
                period=timedelta(days=1),
                scope=LimitScope.USER,
                name="user_daily",
                description="Daily cap",
            ),
        ])

    if limits:
        all_limits.extend(limits)

    return CostLimiter(limits=all_limits, cost_tracker=cost_tracker)
