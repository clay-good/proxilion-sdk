"""
Cascading failure protection for Proxilion.

This module provides cascade-aware circuit breaking to prevent failures
from propagating through dependent tools and services.

Quick Start:
    >>> from proxilion.security import (
    ...     DependencyGraph,
    ...     CascadeProtector,
    ...     CircuitBreakerRegistry,
    ... )
    >>>
    >>> # Build dependency graph
    >>> graph = DependencyGraph()
    >>> graph.add_dependency("user_service", "database")
    >>> graph.add_dependency("order_service", "user_service")
    >>> graph.add_dependency("order_service", "inventory")
    >>>
    >>> # Create cascade protector
    >>> registry = CircuitBreakerRegistry()
    >>> protector = CascadeProtector(graph, registry)
    >>>
    >>> # Check health before calling a tool
    >>> state = protector.check_cascade_health("order_service")
    >>> if state == CascadeState.HEALTHY:
    ...     # Safe to call
    ...     result = call_order_service()
    >>> elif state == CascadeState.DEGRADED:
    ...     # Proceed with caution, some dependencies may be failing
    ...     result = call_order_service(retry=False)
    >>> else:
    ...     # FAILING or ISOLATED - use fallback
    ...     result = fallback_response()

Cascade States:
    - HEALTHY: All dependencies are functioning normally.
    - DEGRADED: Some dependencies have failures but the tool can still function.
    - FAILING: Critical dependencies are failing, tool should not be called.
    - ISOLATED: Tool has been manually isolated from the system.

Integration with Circuit Breakers:
    >>> # When a circuit breaker opens, propagate the failure
    >>> def on_breaker_open(tool_name):
    ...     affected = protector.propagate_failure(tool_name)
    ...     print(f"Failure in {tool_name} affected {len(affected)} tools")
    >>>
    >>> # Register callback with circuit breaker
    >>> registry = CascadeAwareCircuitBreakerRegistry(protector)
"""

from __future__ import annotations

import logging
import threading
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from proxilion.security.circuit_breaker import CircuitBreakerRegistry, CircuitState

logger = logging.getLogger(__name__)


class CascadeState(Enum):
    """State of a tool in the cascade protection system."""

    HEALTHY = "healthy"
    """All dependencies are functioning normally."""

    DEGRADED = "degraded"
    """Some dependencies have failures but the tool can still function."""

    FAILING = "failing"
    """Critical dependencies are failing, tool should not be called."""

    ISOLATED = "isolated"
    """Tool has been manually isolated from the system."""


@dataclass
class DependencyInfo:
    """Information about a dependency."""

    name: str
    """Name of the dependency."""

    critical: bool = True
    """Whether this dependency is critical for the dependent tool."""

    fallback: str | None = None
    """Optional fallback tool to use if this dependency fails."""


@dataclass
class CascadeEvent:
    """Record of a cascade event."""

    timestamp: datetime
    """When the event occurred."""

    source_tool: str
    """The tool that initiated the cascade."""

    affected_tools: set[str]
    """Tools affected by the cascade."""

    event_type: str
    """Type of event (failure_propagated, recovery_started, etc.)."""

    details: dict[str, Any] = field(default_factory=dict)
    """Additional event details."""


class DependencyGraph:
    """
    Directed acyclic graph (DAG) of tool dependencies.

    Tracks which tools depend on other tools, enabling cascade-aware
    failure handling.

    Example:
        >>> graph = DependencyGraph()
        >>> graph.add_dependency("api_gateway", "auth_service")
        >>> graph.add_dependency("api_gateway", "rate_limiter")
        >>> graph.add_dependency("auth_service", "database")
        >>>
        >>> # Get direct dependencies
        >>> graph.get_dependencies("api_gateway")
        {'auth_service', 'rate_limiter'}
        >>>
        >>> # Get all transitive dependencies
        >>> graph.get_upstream("api_gateway")
        {'auth_service', 'rate_limiter', 'database'}
        >>>
        >>> # Get tools that depend on this one
        >>> graph.get_dependents("database")
        {'auth_service'}
        >>>
        >>> # Get all tools that would be affected by a failure
        >>> graph.get_downstream("database")
        {'auth_service', 'api_gateway'}
    """

    def __init__(self):
        """Initialize the dependency graph."""
        self._dependencies: dict[str, dict[str, DependencyInfo]] = defaultdict(dict)
        self._dependents: dict[str, set[str]] = defaultdict(set)
        self._lock = threading.RLock()

    def add_dependency(
        self,
        tool: str,
        depends_on: str,
        critical: bool = True,
        fallback: str | None = None,
    ) -> None:
        """
        Add a dependency relationship.

        Args:
            tool: The tool that has the dependency.
            depends_on: The tool it depends on.
            critical: Whether this is a critical dependency.
            fallback: Optional fallback tool if the dependency fails.

        Raises:
            ValueError: If adding this dependency would create a cycle.

        Example:
            >>> graph.add_dependency("order_service", "database")
            >>> graph.add_dependency("order_service", "cache", critical=False)
        """
        with self._lock:
            # Check if adding this would create a cycle
            if self._would_create_cycle(tool, depends_on):
                raise ValueError(
                    f"Adding dependency {tool} -> {depends_on} would create a cycle"
                )

            self._dependencies[tool][depends_on] = DependencyInfo(
                name=depends_on,
                critical=critical,
                fallback=fallback,
            )
            self._dependents[depends_on].add(tool)

    def remove_dependency(self, tool: str, depends_on: str) -> bool:
        """
        Remove a dependency relationship.

        Args:
            tool: The tool that has the dependency.
            depends_on: The dependency to remove.

        Returns:
            True if the dependency was removed, False if not found.
        """
        with self._lock:
            if depends_on in self._dependencies.get(tool, {}):
                del self._dependencies[tool][depends_on]
                self._dependents[depends_on].discard(tool)
                return True
            return False

    def get_dependencies(self, tool: str) -> set[str]:
        """
        Get direct dependencies of a tool.

        Args:
            tool: The tool to get dependencies for.

        Returns:
            Set of tool names this tool directly depends on.
        """
        with self._lock:
            return set(self._dependencies.get(tool, {}).keys())

    def get_dependency_info(self, tool: str, depends_on: str) -> DependencyInfo | None:
        """
        Get detailed info about a dependency.

        Args:
            tool: The tool that has the dependency.
            depends_on: The dependency to get info for.

        Returns:
            DependencyInfo if found, None otherwise.
        """
        with self._lock:
            return self._dependencies.get(tool, {}).get(depends_on)

    def get_dependents(self, tool: str) -> set[str]:
        """
        Get tools that directly depend on this tool.

        Args:
            tool: The tool to get dependents for.

        Returns:
            Set of tool names that directly depend on this tool.
        """
        with self._lock:
            return set(self._dependents.get(tool, set()))

    def get_upstream(self, tool: str) -> set[str]:
        """
        Get all transitive dependencies (upstream tools).

        Args:
            tool: The tool to get upstream dependencies for.

        Returns:
            Set of all tools this tool transitively depends on.
        """
        with self._lock:
            visited: set[str] = set()
            self._collect_upstream(tool, visited)
            return visited

    def _collect_upstream(self, tool: str, visited: set[str]) -> None:
        """Recursively collect upstream dependencies."""
        for dep in self._dependencies.get(tool, {}):
            if dep not in visited:
                visited.add(dep)
                self._collect_upstream(dep, visited)

    def get_downstream(self, tool: str) -> set[str]:
        """
        Get all tools that would be affected by this tool's failure.

        Args:
            tool: The tool to get downstream dependents for.

        Returns:
            Set of all tools that transitively depend on this tool.
        """
        with self._lock:
            visited: set[str] = set()
            self._collect_downstream(tool, visited)
            return visited

    def _collect_downstream(self, tool: str, visited: set[str]) -> None:
        """Recursively collect downstream dependents."""
        for dependent in self._dependents.get(tool, set()):
            if dependent not in visited:
                visited.add(dependent)
                self._collect_downstream(dependent, visited)

    def has_cycle(self) -> bool:
        """
        Check if the graph contains any cycles.

        Returns:
            True if a cycle exists, False otherwise.
        """
        with self._lock:
            visited: set[str] = set()
            rec_stack: set[str] = set()

            for tool in self._dependencies:
                if self._has_cycle_from(tool, visited, rec_stack):
                    return True
            return False

    def _has_cycle_from(
        self,
        tool: str,
        visited: set[str],
        rec_stack: set[str],
    ) -> bool:
        """Check for cycle starting from a specific tool."""
        visited.add(tool)
        rec_stack.add(tool)

        for dep in self._dependencies.get(tool, {}):
            if dep not in visited:
                if self._has_cycle_from(dep, visited, rec_stack):
                    return True
            elif dep in rec_stack:
                return True

        rec_stack.remove(tool)
        return False

    def _would_create_cycle(self, tool: str, depends_on: str) -> bool:
        """Check if adding a dependency would create a cycle."""
        if tool == depends_on:
            return True

        # Check if depends_on can reach tool (which would create a cycle)
        upstream_of_depends_on = self.get_upstream(depends_on)
        return tool in upstream_of_depends_on or tool == depends_on

    def get_all_tools(self) -> set[str]:
        """Get all tools in the graph."""
        with self._lock:
            tools = set(self._dependencies.keys())
            for deps in self._dependencies.values():
                tools.update(deps.keys())
            return tools

    def get_critical_dependencies(self, tool: str) -> set[str]:
        """
        Get only critical dependencies of a tool.

        Args:
            tool: The tool to get critical dependencies for.

        Returns:
            Set of critical dependency names.
        """
        with self._lock:
            return {
                name
                for name, info in self._dependencies.get(tool, {}).items()
                if info.critical
            }

    def to_dict(self) -> dict[str, list[dict[str, Any]]]:
        """Convert graph to dictionary for serialization."""
        with self._lock:
            return {
                tool: [
                    {
                        "name": info.name,
                        "critical": info.critical,
                        "fallback": info.fallback,
                    }
                    for info in deps.values()
                ]
                for tool, deps in self._dependencies.items()
            }


class CascadeProtector:
    """
    Main class for cascade-aware failure protection.

    Monitors the health of tools and their dependencies, propagating
    failure information and managing recovery.

    Example:
        >>> graph = DependencyGraph()
        >>> graph.add_dependency("api", "database")
        >>> graph.add_dependency("api", "cache", critical=False)
        >>>
        >>> registry = CircuitBreakerRegistry()
        >>> protector = CascadeProtector(graph, registry)
        >>>
        >>> # Check health before calling
        >>> state = protector.check_cascade_health("api")
        >>> if state in (CascadeState.FAILING, CascadeState.ISOLATED):
        ...     return use_fallback()
        >>>
        >>> # When a failure occurs, propagate it
        >>> affected = protector.propagate_failure("database")
        >>> print(f"Database failure affected {len(affected)} tools")
    """

    def __init__(
        self,
        graph: DependencyGraph,
        circuit_registry: CircuitBreakerRegistry | None = None,
        degraded_threshold: int = 1,
        failing_threshold: int = 2,
    ):
        """
        Initialize the cascade protector.

        Args:
            graph: The dependency graph to use.
            circuit_registry: Optional circuit breaker registry for integration.
            degraded_threshold: Number of failing dependencies to mark as DEGRADED.
            failing_threshold: Number of critical failing deps to mark as FAILING.
        """
        self.graph = graph
        self.circuit_registry = circuit_registry
        self.degraded_threshold = degraded_threshold
        self.failing_threshold = failing_threshold

        self._tool_states: dict[str, CascadeState] = {}
        self._isolated_tools: set[str] = set()
        self._events: list[CascadeEvent] = []
        self._lock = threading.RLock()
        self._state_listeners: list[Callable[[str, CascadeState, CascadeState], None]] = []

    def check_cascade_health(self, tool: str) -> CascadeState:
        """
        Check the cascade health of a tool.

        Args:
            tool: The tool to check health for.

        Returns:
            The current cascade state of the tool.

        Example:
            >>> state = protector.check_cascade_health("user_service")
            >>> if state == CascadeState.HEALTHY:
            ...     # All good
            ...     pass
            >>> elif state == CascadeState.DEGRADED:
            ...     # Some non-critical dependencies failing
            ...     pass
        """
        with self._lock:
            # Check if manually isolated
            if tool in self._isolated_tools:
                return CascadeState.ISOLATED

            # Check cached state if we have one (this is set by propagate_failure)
            if tool in self._tool_states:
                cached_state = self._tool_states[tool]
                # Return cached FAILING or ISOLATED states
                if cached_state in (CascadeState.FAILING, CascadeState.ISOLATED):
                    return cached_state

            # Calculate state based on dependencies
            return self._calculate_state(tool)

    def _calculate_state(self, tool: str) -> CascadeState:
        """Calculate the cascade state based on dependency health."""
        dependencies = self.graph.get_dependencies(tool)
        if not dependencies:
            return CascadeState.HEALTHY

        failing_critical = 0
        failing_total = 0

        for dep in dependencies:
            dep_state = self._get_tool_state(dep)
            if dep_state in (CascadeState.FAILING, CascadeState.ISOLATED):
                failing_total += 1
                dep_info = self.graph.get_dependency_info(tool, dep)
                if dep_info and dep_info.critical:
                    failing_critical += 1
            elif dep_state == CascadeState.DEGRADED:
                failing_total += 0.5  # Degraded contributes half

        if failing_critical >= self.failing_threshold:
            return CascadeState.FAILING
        elif failing_total >= self.degraded_threshold:
            return CascadeState.DEGRADED
        else:
            return CascadeState.HEALTHY

    def _get_tool_state(self, tool: str) -> CascadeState:
        """Get the state of a tool, checking circuit breakers if available."""
        # Check manual isolation first
        if tool in self._isolated_tools:
            return CascadeState.ISOLATED

        # Check circuit breaker state
        if self.circuit_registry:
            try:
                breaker = self.circuit_registry.get(tool, auto_create=False)
                if breaker.state == CircuitState.OPEN:
                    return CascadeState.FAILING
                elif breaker.state == CircuitState.HALF_OPEN:
                    return CascadeState.DEGRADED
            except KeyError:
                pass  # No breaker registered

        # Check cached state
        return self._tool_states.get(tool, CascadeState.HEALTHY)

    def propagate_failure(self, tool: str) -> set[str]:
        """
        Propagate a failure through the dependency graph.

        When a tool fails, this method marks all dependent tools as
        DEGRADED or FAILING based on their dependency configuration.

        Args:
            tool: The tool that failed.

        Returns:
            Set of affected tool names.

        Example:
            >>> affected = protector.propagate_failure("database")
            >>> print(f"Affected tools: {affected}")
        """
        with self._lock:
            affected: set[str] = set()

            # Mark the failing tool
            old_state = self._tool_states.get(tool, CascadeState.HEALTHY)
            self._tool_states[tool] = CascadeState.FAILING
            self._notify_state_change(tool, old_state, CascadeState.FAILING)

            # Propagate to dependents
            self._propagate_to_dependents(tool, affected)

            # Record event
            self._events.append(
                CascadeEvent(
                    timestamp=datetime.now(timezone.utc),
                    source_tool=tool,
                    affected_tools=affected,
                    event_type="failure_propagated",
                    details={"total_affected": len(affected)},
                )
            )

            logger.warning(
                f"Cascade failure propagated from {tool}: "
                f"{len(affected)} tools affected"
            )

            return affected

    def _propagate_to_dependents(self, tool: str, affected: set[str]) -> None:
        """Recursively propagate failure state to dependent tools."""
        dependents = self.graph.get_dependents(tool)

        for dependent in dependents:
            if dependent in affected:
                continue

            affected.add(dependent)

            # Calculate new state for this dependent
            new_state = self._calculate_state(dependent)
            old_state = self._tool_states.get(dependent, CascadeState.HEALTHY)

            if new_state != old_state:
                self._tool_states[dependent] = new_state
                self._notify_state_change(dependent, old_state, new_state)

            # Continue propagation if this tool is now failing
            if new_state in (CascadeState.FAILING, CascadeState.DEGRADED):
                self._propagate_to_dependents(dependent, affected)

    def isolate_tool(self, tool: str) -> set[str]:
        """
        Manually isolate a tool from the system.

        Isolated tools are treated as failing and their dependents
        are marked accordingly.

        Args:
            tool: The tool to isolate.

        Returns:
            Set of affected tool names.

        Example:
            >>> # Isolate a tool for maintenance
            >>> affected = protector.isolate_tool("database")
        """
        with self._lock:
            self._isolated_tools.add(tool)
            old_state = self._tool_states.get(tool, CascadeState.HEALTHY)
            self._tool_states[tool] = CascadeState.ISOLATED
            self._notify_state_change(tool, old_state, CascadeState.ISOLATED)

            affected = self.propagate_failure(tool)

            self._events.append(
                CascadeEvent(
                    timestamp=datetime.now(timezone.utc),
                    source_tool=tool,
                    affected_tools=affected,
                    event_type="tool_isolated",
                )
            )

            logger.info(f"Tool {tool} isolated, {len(affected)} tools affected")
            return affected

    def recover_tool(self, tool: str) -> set[str]:
        """
        Attempt to recover a tool from failed/isolated state.

        This removes the tool from isolation and recalculates states
        for all dependents.

        Args:
            tool: The tool to recover.

        Returns:
            Set of tools that may have improved states.

        Example:
            >>> # After maintenance, recover the tool
            >>> recovered = protector.recover_tool("database")
        """
        with self._lock:
            recovered: set[str] = set()

            # Remove from isolation
            self._isolated_tools.discard(tool)

            # Check if circuit breaker is still failing
            actual_state = CascadeState.HEALTHY
            if self.circuit_registry:
                try:
                    breaker = self.circuit_registry.get(tool, auto_create=False)
                    if breaker.state == CircuitState.OPEN:
                        actual_state = CascadeState.FAILING
                    elif breaker.state == CircuitState.HALF_OPEN:
                        actual_state = CascadeState.DEGRADED
                except KeyError:
                    pass

            old_state = self._tool_states.get(tool, CascadeState.HEALTHY)
            if actual_state != old_state:
                self._tool_states[tool] = actual_state
                self._notify_state_change(tool, old_state, actual_state)

            # Recalculate states for all dependents
            self._recalculate_downstream(tool, recovered)

            self._events.append(
                CascadeEvent(
                    timestamp=datetime.now(timezone.utc),
                    source_tool=tool,
                    affected_tools=recovered,
                    event_type="recovery_started",
                )
            )

            logger.info(f"Tool {tool} recovery started, {len(recovered)} tools may recover")
            return recovered

    def _recalculate_downstream(self, tool: str, recovered: set[str]) -> None:
        """Recalculate states for downstream tools after recovery."""
        dependents = self.graph.get_downstream(tool)

        for dependent in dependents:
            old_state = self._tool_states.get(dependent, CascadeState.HEALTHY)
            new_state = self._calculate_state(dependent)

            if new_state != old_state:
                self._tool_states[dependent] = new_state
                self._notify_state_change(dependent, old_state, new_state)

                # If state improved, add to recovered set
                if self._state_value(new_state) < self._state_value(old_state):
                    recovered.add(dependent)

    def _state_value(self, state: CascadeState) -> int:
        """Get numeric value for state comparison (higher = worse)."""
        return {
            CascadeState.HEALTHY: 0,
            CascadeState.DEGRADED: 1,
            CascadeState.FAILING: 2,
            CascadeState.ISOLATED: 3,
        }.get(state, 0)

    def get_healthy_alternatives(self, tool: str) -> list[str]:
        """
        Get healthy alternatives/fallbacks for a failing tool.

        Args:
            tool: The tool to find alternatives for.

        Returns:
            List of healthy alternative tool names.

        Example:
            >>> alternatives = protector.get_healthy_alternatives("primary_db")
            >>> if alternatives:
            ...     use_tool(alternatives[0])
        """
        with self._lock:
            alternatives: list[str] = []

            # Check configured fallbacks in dependencies
            for dependent in self.graph.get_dependents(tool):
                dep_info = self.graph.get_dependency_info(dependent, tool)
                if dep_info and dep_info.fallback:
                    fallback_state = self.check_cascade_health(dep_info.fallback)
                    if fallback_state == CascadeState.HEALTHY:
                        if dep_info.fallback not in alternatives:
                            alternatives.append(dep_info.fallback)

            return alternatives

    def add_state_listener(
        self,
        listener: Callable[[str, CascadeState, CascadeState], None],
    ) -> None:
        """
        Add a listener for state changes.

        Args:
            listener: Callback function(tool, old_state, new_state).

        Example:
            >>> def on_state_change(tool, old, new):
            ...     print(f"{tool}: {old.value} -> {new.value}")
            >>> protector.add_state_listener(on_state_change)
        """
        self._state_listeners.append(listener)

    def _notify_state_change(
        self,
        tool: str,
        old_state: CascadeState,
        new_state: CascadeState,
    ) -> None:
        """Notify listeners of a state change."""
        for listener in self._state_listeners:
            try:
                listener(tool, old_state, new_state)
            except Exception as e:
                logger.error(f"Error in state listener: {e}")

    def get_cascade_events(self, limit: int = 100) -> list[CascadeEvent]:
        """
        Get recent cascade events.

        Args:
            limit: Maximum number of events to return.

        Returns:
            List of recent cascade events, newest first.
        """
        with self._lock:
            return list(reversed(self._events[-limit:]))

    def get_all_states(self) -> dict[str, CascadeState]:
        """Get the current state of all tracked tools."""
        with self._lock:
            # Calculate states for all tools in the graph
            all_tools = self.graph.get_all_tools()
            return {tool: self.check_cascade_health(tool) for tool in all_tools}

    def get_failing_tools(self) -> set[str]:
        """Get all tools currently in FAILING or ISOLATED state."""
        with self._lock:
            return {
                tool
                for tool, state in self._tool_states.items()
                if state in (CascadeState.FAILING, CascadeState.ISOLATED)
            }

    def get_degraded_tools(self) -> set[str]:
        """Get all tools currently in DEGRADED state."""
        with self._lock:
            return {
                tool
                for tool, state in self._tool_states.items()
                if state == CascadeState.DEGRADED
            }

    def reset(self) -> None:
        """Reset all cascade states."""
        with self._lock:
            self._tool_states.clear()
            self._isolated_tools.clear()
            self._events.clear()


class CascadeAwareCircuitBreakerRegistry(CircuitBreakerRegistry):
    """
    Circuit breaker registry with cascade protection integration.

    Automatically propagates failures through the cascade protector
    when circuit breakers open.

    Example:
        >>> graph = DependencyGraph()
        >>> graph.add_dependency("api", "database")
        >>>
        >>> protector = CascadeProtector(graph)
        >>> registry = CascadeAwareCircuitBreakerRegistry(protector)
        >>>
        >>> # When the database circuit opens, cascade protector is notified
        >>> breaker = registry.get("database")
        >>> try:
        ...     result = breaker.call(database_query)
        ... except:
        ...     # Circuit may open after enough failures
        ...     pass
    """

    def __init__(
        self,
        cascade_protector: CascadeProtector,
        default_config: dict[str, Any] | None = None,
    ):
        """
        Initialize the cascade-aware registry.

        Args:
            cascade_protector: The cascade protector to notify on failures.
            default_config: Default circuit breaker configuration.
        """
        super().__init__(default_config)
        self._cascade_protector = cascade_protector

    def on_circuit_open(self, name: str) -> set[str]:
        """
        Handle a circuit opening.

        Args:
            name: Name of the circuit that opened.

        Returns:
            Set of affected tools from cascade propagation.
        """
        affected = self._cascade_protector.propagate_failure(name)
        logger.warning(
            f"Cascade from {name}: {len(affected)} tools affected"
        )
        return affected

    def on_circuit_close(self, name: str) -> set[str]:
        """
        Handle a circuit closing (recovery).

        Args:
            name: Name of the circuit that closed.

        Returns:
            Set of tools that may have recovered.
        """
        recovered = self._cascade_protector.recover_tool(name)
        logger.info(
            f"Recovery from {name}: {len(recovered)} tools may recover"
        )
        return recovered
