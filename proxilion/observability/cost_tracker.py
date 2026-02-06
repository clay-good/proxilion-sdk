"""
Token usage and cost tracking for Proxilion.

Tracks token usage and costs for every tool call and LLM interaction.
Essential for budgeting, chargebacks, and understanding agent costs.

Example:
    >>> from proxilion.observability.cost_tracker import (
    ...     CostTracker, BudgetPolicy, ModelPricing
    ... )
    >>>
    >>> # Create tracker with budget limits
    >>> tracker = CostTracker(
    ...     budget_policy=BudgetPolicy(
    ...         max_cost_per_request=1.00,
    ...         max_cost_per_user_per_day=50.00,
    ...     )
    ... )
    >>>
    >>> # Record usage
    >>> record = tracker.record_usage(
    ...     model="claude-sonnet-4-20250514",
    ...     input_tokens=1000,
    ...     output_tokens=500,
    ...     user_id="user_123",
    ...     tool_name="database_query",
    ... )
    >>> print(f"Cost: ${record.cost_usd:.4f}")
    >>>
    >>> # Get summary
    >>> summary = tracker.get_summary(user_id="user_123")
    >>> print(f"Total cost: ${summary.total_cost:.4f}")
"""

from __future__ import annotations

import json
import logging
import threading
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ModelPricing:
    """
    Pricing information for an LLM model.

    Prices are in USD per 1,000 tokens.

    Attributes:
        model_name: Display name for the model.
        input_price_per_1k: Cost per 1,000 input tokens.
        output_price_per_1k: Cost per 1,000 output tokens.
        cache_read_price_per_1k: Cost per 1,000 cached input tokens (optional).
        cache_write_price_per_1k: Cost per 1,000 tokens written to cache (optional).
    """

    model_name: str
    input_price_per_1k: float
    output_price_per_1k: float
    cache_read_price_per_1k: float = 0.0
    cache_write_price_per_1k: float = 0.0

    def calculate_cost(
        self,
        input_tokens: int,
        output_tokens: int,
        cache_read_tokens: int = 0,
        cache_write_tokens: int = 0,
    ) -> float:
        """
        Calculate the cost for a given usage.

        Args:
            input_tokens: Number of input tokens.
            output_tokens: Number of output tokens.
            cache_read_tokens: Number of cached input tokens read.
            cache_write_tokens: Number of tokens written to cache.

        Returns:
            Total cost in USD.
        """
        input_cost = (input_tokens / 1000) * self.input_price_per_1k
        output_cost = (output_tokens / 1000) * self.output_price_per_1k
        cache_read_cost = (cache_read_tokens / 1000) * self.cache_read_price_per_1k
        cache_write_cost = (cache_write_tokens / 1000) * self.cache_write_price_per_1k

        return input_cost + output_cost + cache_read_cost + cache_write_cost


# Default pricing for popular models (as of early 2026)
DEFAULT_PRICING: dict[str, ModelPricing] = {
    # Anthropic Claude models
    "claude-opus-4-5-20251101": ModelPricing(
        model_name="Claude Opus 4.5",
        input_price_per_1k=0.015,
        output_price_per_1k=0.075,
        cache_read_price_per_1k=0.00375,
        cache_write_price_per_1k=0.01875,
    ),
    "claude-sonnet-4-20250514": ModelPricing(
        model_name="Claude Sonnet 4",
        input_price_per_1k=0.003,
        output_price_per_1k=0.015,
        cache_read_price_per_1k=0.0006,
        cache_write_price_per_1k=0.00375,
    ),
    "claude-3-5-sonnet-20241022": ModelPricing(
        model_name="Claude 3.5 Sonnet",
        input_price_per_1k=0.003,
        output_price_per_1k=0.015,
        cache_read_price_per_1k=0.0003,
        cache_write_price_per_1k=0.00375,
    ),
    "claude-3-5-haiku-20241022": ModelPricing(
        model_name="Claude 3.5 Haiku",
        input_price_per_1k=0.001,
        output_price_per_1k=0.005,
        cache_read_price_per_1k=0.0001,
        cache_write_price_per_1k=0.00125,
    ),
    # OpenAI models
    "gpt-4o": ModelPricing(
        model_name="GPT-4o",
        input_price_per_1k=0.0025,
        output_price_per_1k=0.01,
        cache_read_price_per_1k=0.00125,
    ),
    "gpt-4o-mini": ModelPricing(
        model_name="GPT-4o Mini",
        input_price_per_1k=0.00015,
        output_price_per_1k=0.0006,
        cache_read_price_per_1k=0.000075,
    ),
    "gpt-4-turbo": ModelPricing(
        model_name="GPT-4 Turbo",
        input_price_per_1k=0.01,
        output_price_per_1k=0.03,
    ),
    "gpt-3.5-turbo": ModelPricing(
        model_name="GPT-3.5 Turbo",
        input_price_per_1k=0.0005,
        output_price_per_1k=0.0015,
    ),
    # Google models
    "gemini-1.5-pro": ModelPricing(
        model_name="Gemini 1.5 Pro",
        input_price_per_1k=0.00125,
        output_price_per_1k=0.005,
        cache_read_price_per_1k=0.000315,
    ),
    "gemini-1.5-flash": ModelPricing(
        model_name="Gemini 1.5 Flash",
        input_price_per_1k=0.000075,
        output_price_per_1k=0.0003,
        cache_read_price_per_1k=0.00001875,
    ),
    "gemini-2.0-flash": ModelPricing(
        model_name="Gemini 2.0 Flash",
        input_price_per_1k=0.0001,
        output_price_per_1k=0.0004,
    ),
}


@dataclass
class UsageRecord:
    """
    Record of a single usage event.

    Attributes:
        timestamp: When the usage occurred.
        model: Model identifier.
        input_tokens: Number of input tokens.
        output_tokens: Number of output tokens.
        cache_read_tokens: Number of cached tokens read.
        cache_write_tokens: Number of tokens written to cache.
        tool_name: Tool that triggered the usage (if any).
        user_id: User who incurred the usage.
        cost_usd: Calculated cost in USD.
        request_id: Optional request identifier.
        metadata: Additional metadata.
    """

    timestamp: datetime
    model: str
    input_tokens: int
    output_tokens: int
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    tool_name: str | None = None
    user_id: str | None = None
    cost_usd: float = 0.0
    request_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def total_tokens(self) -> int:
        """Total tokens (input + output)."""
        return self.input_tokens + self.output_tokens

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        result = asdict(self)
        result["timestamp"] = self.timestamp.isoformat()
        return result

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict())


@dataclass
class CostSummary:
    """
    Summary of costs over a period.

    Attributes:
        total_cost: Total cost in USD.
        total_input_tokens: Total input tokens.
        total_output_tokens: Total output tokens.
        total_cache_tokens: Total cache read tokens.
        record_count: Number of usage records.
        by_model: Cost breakdown by model.
        by_user: Cost breakdown by user.
        by_tool: Cost breakdown by tool.
        start_time: Start of the summary period.
        end_time: End of the summary period.
    """

    total_cost: float = 0.0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_cache_tokens: int = 0
    record_count: int = 0
    by_model: dict[str, float] = field(default_factory=dict)
    by_user: dict[str, float] = field(default_factory=dict)
    by_tool: dict[str, float] = field(default_factory=dict)
    start_time: datetime | None = None
    end_time: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total_cost": self.total_cost,
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "total_cache_tokens": self.total_cache_tokens,
            "record_count": self.record_count,
            "by_model": self.by_model,
            "by_user": self.by_user,
            "by_tool": self.by_tool,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
        }


@dataclass
class BudgetPolicy:
    """
    Budget limits for cost control.

    Attributes:
        max_cost_per_request: Maximum cost for a single request.
        max_cost_per_user_per_day: Maximum daily cost per user.
        max_cost_per_user_per_hour: Maximum hourly cost per user.
        max_tokens_per_request: Maximum tokens per request.
        max_org_cost_per_day: Maximum daily cost for the organization.
        max_org_cost_per_month: Maximum monthly cost for the organization.
        warn_at_percentage: Percentage at which to warn (0.0 to 1.0).
    """

    max_cost_per_request: float | None = None
    max_cost_per_user_per_day: float | None = None
    max_cost_per_user_per_hour: float | None = None
    max_tokens_per_request: int | None = None
    max_org_cost_per_day: float | None = None
    max_org_cost_per_month: float | None = None
    warn_at_percentage: float = 0.8


class CostTracker:
    """
    Tracks token usage and costs across all operations.

    The CostTracker maintains a history of usage records and can
    calculate costs, check budgets, and provide summaries.

    Example:
        >>> tracker = CostTracker()
        >>>
        >>> # Record usage
        >>> record = tracker.record_usage(
        ...     model="claude-sonnet-4-20250514",
        ...     input_tokens=1000,
        ...     output_tokens=500,
        ...     user_id="user_123",
        ... )
        >>>
        >>> # Check budget before expensive operation
        >>> allowed, reason = tracker.check_budget("user_123", estimated_tokens=10000)
        >>> if not allowed:
        ...     print(f"Budget issue: {reason}")
    """

    def __init__(
        self,
        pricing: dict[str, ModelPricing] | None = None,
        budget_policy: BudgetPolicy | None = None,
        max_records: int = 100000,
        default_model: str = "claude-sonnet-4-20250514",
    ) -> None:
        """
        Initialize the cost tracker.

        Args:
            pricing: Model pricing information. Defaults to DEFAULT_PRICING.
            budget_policy: Budget limits to enforce.
            max_records: Maximum records to keep in memory.
            default_model: Default model for cost estimation.
        """
        self._lock = threading.RLock()
        self._pricing = dict(DEFAULT_PRICING)
        if pricing:
            self._pricing.update(pricing)

        self._budget_policy = budget_policy
        self._max_records = max_records
        self._default_model = default_model

        # Storage
        self._records: list[UsageRecord] = []
        self._user_daily_spend: dict[str, dict[str, float]] = defaultdict(
            lambda: defaultdict(float)
        )
        self._user_hourly_spend: dict[str, dict[str, float]] = defaultdict(
            lambda: defaultdict(float)
        )
        self._org_daily_spend: dict[str, float] = defaultdict(float)
        self._org_monthly_spend: dict[str, float] = defaultdict(float)

    def set_pricing(self, model: str, pricing: ModelPricing) -> None:
        """
        Set or update pricing for a model.

        Args:
            model: Model identifier.
            pricing: Pricing information.
        """
        with self._lock:
            self._pricing[model] = pricing

    def get_pricing(self, model: str) -> ModelPricing | None:
        """
        Get pricing for a model.

        Args:
            model: Model identifier.

        Returns:
            ModelPricing if found, None otherwise.
        """
        return self._pricing.get(model)

    def record_usage(
        self,
        model: str,
        input_tokens: int,
        output_tokens: int,
        cache_read_tokens: int = 0,
        cache_write_tokens: int = 0,
        tool_name: str | None = None,
        user_id: str | None = None,
        request_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        timestamp: datetime | None = None,
    ) -> UsageRecord:
        """
        Record a usage event and calculate cost.

        Args:
            model: Model identifier.
            input_tokens: Number of input tokens.
            output_tokens: Number of output tokens.
            cache_read_tokens: Number of cached tokens read.
            cache_write_tokens: Number of tokens written to cache.
            tool_name: Tool that triggered the usage.
            user_id: User who incurred the usage.
            request_id: Request identifier.
            metadata: Additional metadata.
            timestamp: Event timestamp (defaults to now).

        Returns:
            The created UsageRecord.
        """
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)

        # Calculate cost
        pricing = self._pricing.get(model)
        if pricing:
            cost = pricing.calculate_cost(
                input_tokens, output_tokens, cache_read_tokens, cache_write_tokens
            )
        else:
            # Use default model pricing as fallback
            default_pricing = self._pricing.get(self._default_model)
            if default_pricing:
                cost = default_pricing.calculate_cost(
                    input_tokens, output_tokens, cache_read_tokens, cache_write_tokens
                )
                logger.warning(
                    f"Unknown model '{model}', using default pricing from '{self._default_model}'"
                )
            else:
                cost = 0.0
                logger.warning(f"Unknown model '{model}' and no default pricing available")

        record = UsageRecord(
            timestamp=timestamp,
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cache_read_tokens=cache_read_tokens,
            cache_write_tokens=cache_write_tokens,
            tool_name=tool_name,
            user_id=user_id,
            cost_usd=cost,
            request_id=request_id,
            metadata=metadata or {},
        )

        with self._lock:
            self._records.append(record)

            # Trim old records if needed
            if len(self._records) > self._max_records:
                self._records = self._records[-self._max_records:]

            # Update spend tracking
            if user_id:
                day_key = timestamp.strftime("%Y-%m-%d")
                hour_key = timestamp.strftime("%Y-%m-%d-%H")
                self._user_daily_spend[user_id][day_key] += cost
                self._user_hourly_spend[user_id][hour_key] += cost

            # Track org-wide spend
            day_key = timestamp.strftime("%Y-%m-%d")
            month_key = timestamp.strftime("%Y-%m")
            self._org_daily_spend[day_key] += cost
            self._org_monthly_spend[month_key] += cost

        logger.debug(
            f"Recorded usage: model={model}, tokens={input_tokens}+{output_tokens}, "
            f"cost=${cost:.4f}, user={user_id}"
        )

        return record

    def estimate_cost(
        self,
        model: str | None = None,
        input_tokens: int = 0,
        output_tokens: int = 0,
        cache_read_tokens: int = 0,
    ) -> float:
        """
        Estimate cost for a potential request.

        Args:
            model: Model to use (defaults to default_model).
            input_tokens: Expected input tokens.
            output_tokens: Expected output tokens.
            cache_read_tokens: Expected cached tokens.

        Returns:
            Estimated cost in USD.
        """
        model = model or self._default_model
        pricing = self._pricing.get(model)

        if pricing:
            return pricing.calculate_cost(input_tokens, output_tokens, cache_read_tokens)

        return 0.0

    def check_budget(
        self,
        user_id: str,
        estimated_cost: float = 0.0,
        estimated_tokens: int = 0,
    ) -> tuple[bool, str | None]:
        """
        Check if a request would exceed budget limits.

        Args:
            user_id: User making the request.
            estimated_cost: Estimated cost of the request.
            estimated_tokens: Estimated tokens for the request.

        Returns:
            Tuple of (allowed, reason). If not allowed, reason explains why.
        """
        if self._budget_policy is None:
            return True, None

        policy = self._budget_policy
        now = datetime.now(timezone.utc)

        # If estimated_cost not provided, estimate from tokens
        if estimated_cost == 0.0 and estimated_tokens > 0:
            # Assume 50/50 split between input/output for estimation
            estimated_cost = self.estimate_cost(
                input_tokens=estimated_tokens // 2,
                output_tokens=estimated_tokens // 2,
            )

        # Check per-request cost limit
        if policy.max_cost_per_request is not None:
            if estimated_cost > policy.max_cost_per_request:
                return False, (
                    f"Request would exceed per-request budget: "
                    f"${estimated_cost:.4f} > ${policy.max_cost_per_request:.4f}"
                )

        # Check per-request token limit
        if policy.max_tokens_per_request is not None:
            if estimated_tokens > policy.max_tokens_per_request:
                return False, (
                    f"Request would exceed token limit: "
                    f"{estimated_tokens} > {policy.max_tokens_per_request}"
                )

        # Check user daily limit
        if policy.max_cost_per_user_per_day is not None:
            daily_spend = self.get_user_spend(user_id, timedelta(days=1))
            if daily_spend + estimated_cost > policy.max_cost_per_user_per_day:
                return False, (
                    f"User daily budget exceeded: "
                    f"${daily_spend + estimated_cost:.4f} > ${policy.max_cost_per_user_per_day:.4f}"
                )

        # Check user hourly limit
        if policy.max_cost_per_user_per_hour is not None:
            hourly_spend = self.get_user_spend(user_id, timedelta(hours=1))
            if hourly_spend + estimated_cost > policy.max_cost_per_user_per_hour:
                return False, (
                    f"User hourly budget exceeded: ${hourly_spend + estimated_cost:.4f}"
                    f" > ${policy.max_cost_per_user_per_hour:.4f}"
                )

        # Check org daily limit
        if policy.max_org_cost_per_day is not None:
            day_key = now.strftime("%Y-%m-%d")
            org_daily = self._org_daily_spend.get(day_key, 0.0)
            if org_daily + estimated_cost > policy.max_org_cost_per_day:
                return False, (
                    f"Organization daily budget exceeded: "
                    f"${org_daily + estimated_cost:.4f} > ${policy.max_org_cost_per_day:.4f}"
                )

        # Check org monthly limit
        if policy.max_org_cost_per_month is not None:
            month_key = now.strftime("%Y-%m")
            org_monthly = self._org_monthly_spend.get(month_key, 0.0)
            if org_monthly + estimated_cost > policy.max_org_cost_per_month:
                return False, (
                    f"Organization monthly budget exceeded: "
                    f"${org_monthly + estimated_cost:.4f} > ${policy.max_org_cost_per_month:.4f}"
                )

        return True, None

    def get_user_spend(self, user_id: str, period: timedelta) -> float:
        """
        Get total spend for a user over a period.

        Args:
            user_id: User to check.
            period: Time period to check.

        Returns:
            Total spend in USD.
        """
        with self._lock:
            now = datetime.now(timezone.utc)
            cutoff = now - period

            total = 0.0
            for record in reversed(self._records):
                if record.timestamp < cutoff:
                    break
                if record.user_id == user_id:
                    total += record.cost_usd

            return total

    def get_org_spend(self, period: timedelta) -> float:
        """
        Get total organization spend over a period.

        Args:
            period: Time period to check.

        Returns:
            Total spend in USD.
        """
        with self._lock:
            now = datetime.now(timezone.utc)
            cutoff = now - period

            total = 0.0
            for record in reversed(self._records):
                if record.timestamp < cutoff:
                    break
                total += record.cost_usd

            return total

    def get_summary(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
        user_id: str | None = None,
        model: str | None = None,
        tool_name: str | None = None,
    ) -> CostSummary:
        """
        Get a cost summary for the specified period and filters.

        Args:
            start: Start of period (defaults to all time).
            end: End of period (defaults to now).
            user_id: Filter by user.
            model: Filter by model.
            tool_name: Filter by tool.

        Returns:
            CostSummary with aggregated data.
        """
        with self._lock:
            summary = CostSummary(
                start_time=start,
                end_time=end or datetime.now(timezone.utc),
            )

            by_model: dict[str, float] = defaultdict(float)
            by_user: dict[str, float] = defaultdict(float)
            by_tool: dict[str, float] = defaultdict(float)

            for record in self._records:
                # Apply time filters
                if start and record.timestamp < start:
                    continue
                if end and record.timestamp > end:
                    continue

                # Apply entity filters
                if user_id and record.user_id != user_id:
                    continue
                if model and record.model != model:
                    continue
                if tool_name and record.tool_name != tool_name:
                    continue

                # Aggregate
                summary.total_cost += record.cost_usd
                summary.total_input_tokens += record.input_tokens
                summary.total_output_tokens += record.output_tokens
                summary.total_cache_tokens += record.cache_read_tokens
                summary.record_count += 1

                by_model[record.model] += record.cost_usd
                if record.user_id:
                    by_user[record.user_id] += record.cost_usd
                if record.tool_name:
                    by_tool[record.tool_name] += record.cost_usd

            summary.by_model = dict(by_model)
            summary.by_user = dict(by_user)
            summary.by_tool = dict(by_tool)

            return summary

    def get_records(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
        user_id: str | None = None,
        limit: int | None = None,
    ) -> list[UsageRecord]:
        """
        Get usage records with optional filters.

        Args:
            start: Start of period.
            end: End of period.
            user_id: Filter by user.
            limit: Maximum records to return.

        Returns:
            List of UsageRecords, most recent first.
        """
        with self._lock:
            result = []

            for record in reversed(self._records):
                if start and record.timestamp < start:
                    continue
                if end and record.timestamp > end:
                    continue
                if user_id and record.user_id != user_id:
                    continue

                result.append(record)

                if limit and len(result) >= limit:
                    break

            return result

    def export_records(
        self,
        format: str = "json",
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> str:
        """
        Export records to a string format.

        Args:
            format: Output format ("json" or "jsonl").
            start: Start of period.
            end: End of period.

        Returns:
            Exported records as string.
        """
        records = self.get_records(start=start, end=end)

        if format == "jsonl":
            return "\n".join(r.to_json() for r in records)
        else:
            return json.dumps([r.to_dict() for r in records], indent=2)

    def clear_records(
        self,
        before: datetime | None = None,
        user_id: str | None = None,
    ) -> int:
        """
        Clear usage records.

        Args:
            before: Clear records before this time.
            user_id: Clear only records for this user.

        Returns:
            Number of records cleared.
        """
        with self._lock:
            original_count = len(self._records)

            if before is None and user_id is None:
                self._records.clear()
                self._user_daily_spend.clear()
                self._user_hourly_spend.clear()
                self._org_daily_spend.clear()
                self._org_monthly_spend.clear()
                return original_count

            self._records = [
                r for r in self._records
                if not (
                    (before is None or r.timestamp >= before) and
                    (user_id is None or r.user_id == user_id)
                )
            ]

            return original_count - len(self._records)

    def set_budget_policy(self, policy: BudgetPolicy | None) -> None:
        """
        Set or update the budget policy.

        Args:
            policy: New budget policy, or None to disable.
        """
        self._budget_policy = policy

    def get_budget_policy(self) -> BudgetPolicy | None:
        """Get the current budget policy."""
        return self._budget_policy

    def get_budget_status(self, user_id: str) -> dict[str, Any]:
        """
        Get current budget status for a user.

        Args:
            user_id: User to check.

        Returns:
            Dictionary with budget status information.
        """
        if self._budget_policy is None:
            return {"policy_active": False}

        policy = self._budget_policy
        now = datetime.now(timezone.utc)

        status: dict[str, Any] = {"policy_active": True}

        if policy.max_cost_per_user_per_day is not None:
            daily_spend = self.get_user_spend(user_id, timedelta(days=1))
            daily_limit = policy.max_cost_per_user_per_day
            status["daily"] = {
                "spent": daily_spend,
                "limit": daily_limit,
                "remaining": max(0, daily_limit - daily_spend),
                "percentage": daily_spend / daily_limit if daily_limit > 0 else 0.0,
            }

        if policy.max_cost_per_user_per_hour is not None:
            hourly_spend = self.get_user_spend(user_id, timedelta(hours=1))
            hourly_limit = policy.max_cost_per_user_per_hour
            status["hourly"] = {
                "spent": hourly_spend,
                "limit": hourly_limit,
                "remaining": max(0, hourly_limit - hourly_spend),
                "percentage": hourly_spend / hourly_limit if hourly_limit > 0 else 0.0,
            }

        if policy.max_org_cost_per_day is not None:
            day_key = now.strftime("%Y-%m-%d")
            org_daily = self._org_daily_spend.get(day_key, 0.0)
            org_limit = policy.max_org_cost_per_day
            status["org_daily"] = {
                "spent": org_daily,
                "limit": org_limit,
                "remaining": max(0, org_limit - org_daily),
                "percentage": org_daily / org_limit if org_limit > 0 else 0.0,
            }

        return status


def create_cost_tracker(
    budget_policy: BudgetPolicy | None = None,
    custom_pricing: dict[str, ModelPricing] | None = None,
) -> CostTracker:
    """
    Factory function to create a CostTracker.

    Args:
        budget_policy: Optional budget limits.
        custom_pricing: Additional model pricing.

    Returns:
        Configured CostTracker instance.
    """
    return CostTracker(
        pricing=custom_pricing,
        budget_policy=budget_policy,
    )
