"""
Graceful degradation for AI operations.

Provides tier-based feature availability for handling
reduced service capacity.
"""

from __future__ import annotations

import copy
import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any

logger = logging.getLogger(__name__)


class DegradationTier(Enum):
    """
    Degradation tiers representing service capability levels.

    Attributes:
        FULL: Full service with all features available.
        REDUCED: Reduced service with limited features.
        MINIMAL: Minimal service with essential features only.
        OFFLINE: Offline mode with local-only functionality.
    """

    FULL = auto()
    REDUCED = auto()
    MINIMAL = auto()
    OFFLINE = auto()

    def __lt__(self, other: DegradationTier) -> bool:
        """Compare tiers (FULL > REDUCED > MINIMAL > OFFLINE)."""
        if not isinstance(other, DegradationTier):
            return NotImplemented
        order = {
            DegradationTier.FULL: 4,
            DegradationTier.REDUCED: 3,
            DegradationTier.MINIMAL: 2,
            DegradationTier.OFFLINE: 1,
        }
        return order[self] < order[other]

    def __le__(self, other: DegradationTier) -> bool:
        return self == other or self < other

    def __gt__(self, other: DegradationTier) -> bool:
        return not self <= other

    def __ge__(self, other: DegradationTier) -> bool:
        return not self < other


@dataclass
class TierConfig:
    """
    Configuration for a degradation tier.

    Attributes:
        tier: The degradation tier this config applies to.
        available_tools: Set of tool names available at this tier.
                        Use {"*"} to allow all tools.
        available_models: List of model names available at this tier.
        max_tokens: Maximum tokens allowed at this tier.
        features: Set of feature names enabled at this tier.
        rate_limit_multiplier: Multiplier for rate limits at this tier.
        timeout_multiplier: Multiplier for timeouts at this tier.
        description: Human-readable description of this tier.

    Example:
        >>> config = TierConfig(
        ...     tier=DegradationTier.REDUCED,
        ...     available_tools={"search", "calculator"},
        ...     available_models=["gpt-4o-mini"],
        ...     max_tokens=32000,
        ...     features={"function_calling"},
        ... )
    """

    tier: DegradationTier
    available_tools: set[str] = field(default_factory=lambda: {"*"})
    available_models: list[str] = field(default_factory=list)
    max_tokens: int = 100000
    features: set[str] = field(default_factory=set)
    rate_limit_multiplier: float = 1.0
    timeout_multiplier: float = 1.0
    description: str = ""

    def __post_init__(self) -> None:
        """Ensure available_tools is a set."""
        if isinstance(self.available_tools, list):
            self.available_tools = set(self.available_tools)

    def is_tool_available(self, tool_name: str) -> bool:
        """
        Check if a tool is available at this tier.

        Args:
            tool_name: Name of the tool to check.

        Returns:
            True if the tool is available.
        """
        return "*" in self.available_tools or tool_name in self.available_tools

    def is_model_available(self, model_name: str) -> bool:
        """
        Check if a model is available at this tier.

        Args:
            model_name: Name of the model to check.

        Returns:
            True if the model is available.
        """
        return model_name in self.available_models

    def is_feature_enabled(self, feature: str) -> bool:
        """
        Check if a feature is enabled at this tier.

        Args:
            feature: Name of the feature to check.

        Returns:
            True if the feature is enabled.
        """
        return feature in self.features

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "tier": self.tier.name,
            "available_tools": list(self.available_tools),
            "available_models": self.available_models,
            "max_tokens": self.max_tokens,
            "features": list(self.features),
            "rate_limit_multiplier": self.rate_limit_multiplier,
            "timeout_multiplier": self.timeout_multiplier,
            "description": self.description,
        }


# Default tier configurations
DEFAULT_TIERS: dict[DegradationTier, TierConfig] = {
    DegradationTier.FULL: TierConfig(
        tier=DegradationTier.FULL,
        available_tools={"*"},
        available_models=["claude-opus-4-5", "claude-sonnet-4", "gpt-4o", "gpt-4o-mini"],
        max_tokens=100000,
        features={"streaming", "vision", "function_calling", "code_execution"},
        rate_limit_multiplier=1.0,
        timeout_multiplier=1.0,
        description="Full service with all features available",
    ),
    DegradationTier.REDUCED: TierConfig(
        tier=DegradationTier.REDUCED,
        available_tools={"search", "read_file", "calculator", "web_fetch"},
        available_models=["claude-sonnet-4", "gpt-4o-mini"],
        max_tokens=32000,
        features={"function_calling"},
        rate_limit_multiplier=0.5,
        timeout_multiplier=1.5,
        description="Reduced service with limited features",
    ),
    DegradationTier.MINIMAL: TierConfig(
        tier=DegradationTier.MINIMAL,
        available_tools={"search", "calculator"},
        available_models=["gpt-4o-mini"],
        max_tokens=8000,
        features=set(),
        rate_limit_multiplier=0.25,
        timeout_multiplier=2.0,
        description="Minimal service with essential features only",
    ),
    DegradationTier.OFFLINE: TierConfig(
        tier=DegradationTier.OFFLINE,
        available_tools=set(),
        available_models=[],
        max_tokens=4000,
        features=set(),
        rate_limit_multiplier=0.1,
        timeout_multiplier=3.0,
        description="Offline mode with cached/local-only functionality",
    ),
}


@dataclass
class DegradationEvent:
    """
    An event recording a tier change.

    Attributes:
        timestamp: When the change occurred.
        from_tier: Previous tier.
        to_tier: New tier.
        reason: Reason for the change.
        triggered_by: What triggered the change (tool name, etc.).
    """

    timestamp: datetime
    from_tier: DegradationTier
    to_tier: DegradationTier
    reason: str = ""
    triggered_by: str | None = None


class GracefulDegradation:
    """
    Manages graceful degradation across service tiers.

    Tracks current service tier and provides methods to check
    feature availability, auto-degrade on failures, and recover.

    Example:
        >>> degradation = GracefulDegradation()
        >>>
        >>> # Check availability
        >>> if degradation.is_tool_available("web_search"):
        ...     result = await web_search(query)
        >>>
        >>> # Auto-degrade on failure
        >>> try:
        ...     result = await call_api()
        ... except Exception as e:
        ...     degradation.record_failure("api_call")
        >>>
        >>> # Manual tier control
        >>> degradation.set_tier(DegradationTier.REDUCED, reason="High latency")
    """

    def __init__(
        self,
        tiers: dict[DegradationTier, TierConfig] | None = None,
        initial_tier: DegradationTier = DegradationTier.FULL,
        failure_threshold: int = 3,
        recovery_threshold: int = 5,
        auto_recover: bool = True,
    ) -> None:
        """
        Initialize graceful degradation.

        Args:
            tiers: Tier configurations. Uses DEFAULT_TIERS if None.
            initial_tier: Starting tier.
            failure_threshold: Consecutive failures before degrading.
            recovery_threshold: Consecutive successes before recovering.
            auto_recover: Whether to auto-recover after successes.
        """
        self._tiers = tiers or copy.deepcopy(DEFAULT_TIERS)
        self._current_tier = initial_tier
        self._failure_threshold = failure_threshold
        self._recovery_threshold = recovery_threshold
        self._auto_recover = auto_recover

        self._failure_counts: dict[str, int] = {}
        self._success_counts: dict[str, int] = {}
        self._history: list[DegradationEvent] = []
        self._callbacks: list[Callable[[DegradationEvent], None]] = []
        self._lock = threading.RLock()

    @property
    def current_tier(self) -> DegradationTier:
        """Get the current degradation tier."""
        return self._current_tier

    @property
    def current_config(self) -> TierConfig:
        """Get the configuration for the current tier."""
        return self._tiers[self._current_tier]

    def get_current_tier(self) -> DegradationTier:
        """Get the current tier."""
        return self._current_tier

    def set_tier(
        self,
        tier: DegradationTier,
        reason: str = "",
        triggered_by: str | None = None,
    ) -> None:
        """
        Set the degradation tier.

        Args:
            tier: The tier to set.
            reason: Reason for the change.
            triggered_by: What triggered the change.
        """
        with self._lock:
            if tier == self._current_tier:
                return

            event = DegradationEvent(
                timestamp=datetime.now(timezone.utc),
                from_tier=self._current_tier,
                to_tier=tier,
                reason=reason,
                triggered_by=triggered_by,
            )

            old_tier = self._current_tier
            self._current_tier = tier
            self._history.append(event)

            # Notify callbacks
            for callback in self._callbacks:
                try:
                    callback(event)
                except Exception as e:
                    logger.error(f"Degradation callback error: {e}")

            logger.info(
                f"Degradation tier changed: {old_tier.name} -> {tier.name} "
                f"(reason: {reason}, triggered_by: {triggered_by})"
            )

    def degrade(self, reason: str = "", triggered_by: str | None = None) -> bool:
        """
        Degrade to the next lower tier.

        Args:
            reason: Reason for degradation.
            triggered_by: What triggered the degradation.

        Returns:
            True if degradation occurred, False if already at lowest tier.
        """
        with self._lock:
            tier_order = [
                DegradationTier.FULL,
                DegradationTier.REDUCED,
                DegradationTier.MINIMAL,
                DegradationTier.OFFLINE,
            ]
            current_index = tier_order.index(self._current_tier)

            if current_index >= len(tier_order) - 1:
                return False  # Already at lowest tier

            new_tier = tier_order[current_index + 1]
            self.set_tier(new_tier, reason=reason, triggered_by=triggered_by)
            return True

    def recover(self, reason: str = "", triggered_by: str | None = None) -> bool:
        """
        Recover to the next higher tier.

        Args:
            reason: Reason for recovery.
            triggered_by: What triggered the recovery.

        Returns:
            True if recovery occurred, False if already at highest tier.
        """
        with self._lock:
            tier_order = [
                DegradationTier.FULL,
                DegradationTier.REDUCED,
                DegradationTier.MINIMAL,
                DegradationTier.OFFLINE,
            ]
            current_index = tier_order.index(self._current_tier)

            if current_index <= 0:
                return False  # Already at highest tier

            new_tier = tier_order[current_index - 1]
            self.set_tier(new_tier, reason=reason, triggered_by=triggered_by)
            return True

    def record_failure(self, component: str) -> None:
        """
        Record a failure for a component.

        May trigger automatic degradation if threshold is reached.

        Args:
            component: Name of the component that failed.
        """
        with self._lock:
            self._failure_counts[component] = self._failure_counts.get(component, 0) + 1
            self._success_counts[component] = 0  # Reset success count

            if self._failure_counts[component] >= self._failure_threshold:
                self.degrade(
                    reason=f"{self._failure_threshold} consecutive failures",
                    triggered_by=component,
                )
                self._failure_counts[component] = 0  # Reset after degrading

    def record_success(self, component: str) -> None:
        """
        Record a success for a component.

        May trigger automatic recovery if threshold is reached.

        Args:
            component: Name of the component that succeeded.
        """
        with self._lock:
            self._success_counts[component] = self._success_counts.get(component, 0) + 1
            self._failure_counts[component] = 0  # Reset failure count

            if (
                self._auto_recover
                and self._success_counts[component] >= self._recovery_threshold
            ):
                self.recover(
                    reason=f"{self._recovery_threshold} consecutive successes",
                    triggered_by=component,
                )
                self._success_counts[component] = 0  # Reset after recovering

    def auto_degrade_on_failure(self, tool_name: str) -> None:
        """
        Record a tool failure and potentially auto-degrade.

        Alias for record_failure for backward compatibility.

        Args:
            tool_name: Name of the tool that failed.
        """
        self.record_failure(tool_name)

    def is_tool_available(self, tool_name: str) -> bool:
        """
        Check if a tool is available at the current tier.

        Args:
            tool_name: Name of the tool to check.

        Returns:
            True if the tool is available.
        """
        return self.current_config.is_tool_available(tool_name)

    def is_model_available(self, model_name: str) -> bool:
        """
        Check if a model is available at the current tier.

        Args:
            model_name: Name of the model to check.

        Returns:
            True if the model is available.
        """
        return self.current_config.is_model_available(model_name)

    def is_feature_enabled(self, feature: str) -> bool:
        """
        Check if a feature is enabled at the current tier.

        Args:
            feature: Name of the feature to check.

        Returns:
            True if the feature is enabled.
        """
        return self.current_config.is_feature_enabled(feature)

    def get_available_tools(self) -> set[str]:
        """
        Get all tools available at the current tier.

        Returns:
            Set of available tool names.
        """
        return set(self.current_config.available_tools)

    def get_available_models(self) -> list[str]:
        """
        Get all models available at the current tier.

        Returns:
            List of available model names.
        """
        return list(self.current_config.available_models)

    def get_enabled_features(self) -> set[str]:
        """
        Get all features enabled at the current tier.

        Returns:
            Set of enabled feature names.
        """
        return set(self.current_config.features)

    def get_max_tokens(self) -> int:
        """Get maximum tokens for the current tier."""
        return self.current_config.max_tokens

    def get_rate_limit_multiplier(self) -> float:
        """Get rate limit multiplier for the current tier."""
        return self.current_config.rate_limit_multiplier

    def get_timeout_multiplier(self) -> float:
        """Get timeout multiplier for the current tier."""
        return self.current_config.timeout_multiplier

    def add_tier_change_callback(
        self, callback: Callable[[DegradationEvent], None]
    ) -> None:
        """
        Add a callback for tier changes.

        Args:
            callback: Function to call on tier change.
        """
        with self._lock:
            self._callbacks.append(callback)

    def remove_tier_change_callback(
        self, callback: Callable[[DegradationEvent], None]
    ) -> bool:
        """
        Remove a tier change callback.

        Args:
            callback: The callback to remove.

        Returns:
            True if callback was found and removed.
        """
        with self._lock:
            try:
                self._callbacks.remove(callback)
                return True
            except ValueError:
                return False

    def get_history(self) -> list[DegradationEvent]:
        """Get tier change history."""
        with self._lock:
            return list(self._history)

    def get_failure_counts(self) -> dict[str, int]:
        """Get current failure counts by component."""
        with self._lock:
            return dict(self._failure_counts)

    def get_success_counts(self) -> dict[str, int]:
        """Get current success counts by component."""
        with self._lock:
            return dict(self._success_counts)

    def reset_counts(self, component: str | None = None) -> None:
        """
        Reset failure and success counts.

        Args:
            component: Specific component to reset, or None for all.
        """
        with self._lock:
            if component:
                self._failure_counts.pop(component, None)
                self._success_counts.pop(component, None)
            else:
                self._failure_counts.clear()
                self._success_counts.clear()

    def reset(self, tier: DegradationTier = DegradationTier.FULL) -> None:
        """
        Reset to a specific tier and clear all counts.

        Args:
            tier: The tier to reset to.
        """
        with self._lock:
            old_tier = self._current_tier
            self._current_tier = tier
            self._failure_counts.clear()
            self._success_counts.clear()
            self._history.clear()

            if old_tier != tier:
                event = DegradationEvent(
                    timestamp=datetime.now(timezone.utc),
                    from_tier=old_tier,
                    to_tier=tier,
                    reason="reset",
                    triggered_by="manual",
                )
                for callback in self._callbacks:
                    try:
                        callback(event)
                    except Exception as e:
                        logger.error(f"Degradation callback error: {e}")

    def get_tier_config(self, tier: DegradationTier) -> TierConfig:
        """
        Get configuration for a specific tier.

        Args:
            tier: The tier to get config for.

        Returns:
            TierConfig for the tier.
        """
        return self._tiers[tier]

    def set_tier_config(self, tier: DegradationTier, config: TierConfig) -> None:
        """
        Set configuration for a specific tier.

        Args:
            tier: The tier to configure.
            config: The configuration to set.
        """
        with self._lock:
            self._tiers[tier] = config

    def to_dict(self) -> dict[str, Any]:
        """Convert current state to dictionary."""
        return {
            "current_tier": self._current_tier.name,
            "current_config": self.current_config.to_dict(),
            "failure_counts": dict(self._failure_counts),
            "success_counts": dict(self._success_counts),
            "history_length": len(self._history),
            "auto_recover": self._auto_recover,
            "failure_threshold": self._failure_threshold,
            "recovery_threshold": self._recovery_threshold,
        }
