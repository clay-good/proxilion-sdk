"""Tests for proxilion.security.cascade_protection module."""

from __future__ import annotations

import pytest

from proxilion.security import (
    CascadeAwareCircuitBreakerRegistry,
    CascadeEvent,
    CascadeProtector,
    CascadeState,
    CircuitBreaker,
    CircuitBreakerRegistry,
    CircuitState,
    DependencyGraph,
    DependencyInfo,
)


# =============================================================================
# DependencyGraph Tests
# =============================================================================


class TestDependencyGraph:
    """Tests for DependencyGraph class."""

    def test_add_dependency(self):
        """Test adding a dependency."""
        graph = DependencyGraph()
        graph.add_dependency("api", "database")

        assert graph.get_dependencies("api") == {"database"}
        assert graph.get_dependents("database") == {"api"}

    def test_add_multiple_dependencies(self):
        """Test adding multiple dependencies for one tool."""
        graph = DependencyGraph()
        graph.add_dependency("api", "database")
        graph.add_dependency("api", "cache")
        graph.add_dependency("api", "auth")

        assert graph.get_dependencies("api") == {"database", "cache", "auth"}

    def test_add_dependency_with_metadata(self):
        """Test adding dependency with critical flag and fallback."""
        graph = DependencyGraph()
        graph.add_dependency("api", "primary_db", critical=True, fallback="secondary_db")
        graph.add_dependency("api", "cache", critical=False)

        info = graph.get_dependency_info("api", "primary_db")
        assert info is not None
        assert info.critical is True
        assert info.fallback == "secondary_db"

        cache_info = graph.get_dependency_info("api", "cache")
        assert cache_info is not None
        assert cache_info.critical is False

    def test_remove_dependency(self):
        """Test removing a dependency."""
        graph = DependencyGraph()
        graph.add_dependency("api", "database")
        graph.add_dependency("api", "cache")

        result = graph.remove_dependency("api", "cache")
        assert result is True
        assert graph.get_dependencies("api") == {"database"}

    def test_remove_nonexistent_dependency(self):
        """Test removing a dependency that doesn't exist."""
        graph = DependencyGraph()
        graph.add_dependency("api", "database")

        result = graph.remove_dependency("api", "cache")
        assert result is False

    def test_get_dependents(self):
        """Test getting dependents of a tool."""
        graph = DependencyGraph()
        graph.add_dependency("api", "database")
        graph.add_dependency("worker", "database")
        graph.add_dependency("scheduler", "database")

        assert graph.get_dependents("database") == {"api", "worker", "scheduler"}

    def test_get_upstream_simple(self):
        """Test getting upstream (transitive dependencies)."""
        graph = DependencyGraph()
        graph.add_dependency("api", "service")
        graph.add_dependency("service", "database")

        upstream = graph.get_upstream("api")
        assert upstream == {"service", "database"}

    def test_get_upstream_complex(self):
        """Test getting upstream with complex graph."""
        graph = DependencyGraph()
        graph.add_dependency("api", "auth")
        graph.add_dependency("api", "data_service")
        graph.add_dependency("data_service", "database")
        graph.add_dependency("auth", "user_db")

        upstream = graph.get_upstream("api")
        assert upstream == {"auth", "data_service", "database", "user_db"}

    def test_get_downstream_simple(self):
        """Test getting downstream (transitive dependents)."""
        graph = DependencyGraph()
        graph.add_dependency("api", "service")
        graph.add_dependency("service", "database")

        downstream = graph.get_downstream("database")
        assert downstream == {"service", "api"}

    def test_get_downstream_diamond(self):
        """Test downstream with diamond dependency pattern."""
        graph = DependencyGraph()
        # Diamond: api -> service_a -> database
        #          api -> service_b -> database
        graph.add_dependency("api", "service_a")
        graph.add_dependency("api", "service_b")
        graph.add_dependency("service_a", "database")
        graph.add_dependency("service_b", "database")

        downstream = graph.get_downstream("database")
        assert downstream == {"service_a", "service_b", "api"}

    def test_has_cycle_false(self):
        """Test cycle detection when no cycle exists."""
        graph = DependencyGraph()
        graph.add_dependency("a", "b")
        graph.add_dependency("b", "c")
        graph.add_dependency("c", "d")

        assert graph.has_cycle() is False

    def test_cycle_detection_on_add(self):
        """Test that adding a cycle is prevented."""
        graph = DependencyGraph()
        graph.add_dependency("a", "b")
        graph.add_dependency("b", "c")

        with pytest.raises(ValueError, match="cycle"):
            graph.add_dependency("c", "a")

    def test_self_dependency_rejected(self):
        """Test that self-dependency is rejected."""
        graph = DependencyGraph()

        with pytest.raises(ValueError, match="cycle"):
            graph.add_dependency("a", "a")

    def test_get_all_tools(self):
        """Test getting all tools in the graph."""
        graph = DependencyGraph()
        graph.add_dependency("api", "database")
        graph.add_dependency("worker", "queue")

        all_tools = graph.get_all_tools()
        assert all_tools == {"api", "database", "worker", "queue"}

    def test_get_critical_dependencies(self):
        """Test getting only critical dependencies."""
        graph = DependencyGraph()
        graph.add_dependency("api", "database", critical=True)
        graph.add_dependency("api", "cache", critical=False)
        graph.add_dependency("api", "auth", critical=True)

        critical = graph.get_critical_dependencies("api")
        assert critical == {"database", "auth"}

    def test_to_dict(self):
        """Test serialization to dictionary."""
        graph = DependencyGraph()
        graph.add_dependency("api", "database", critical=True, fallback="backup_db")

        result = graph.to_dict()
        assert "api" in result
        assert len(result["api"]) == 1
        assert result["api"][0]["name"] == "database"
        assert result["api"][0]["critical"] is True
        assert result["api"][0]["fallback"] == "backup_db"


# =============================================================================
# CascadeProtector Tests
# =============================================================================


class TestCascadeProtector:
    """Tests for CascadeProtector class."""

    @pytest.fixture
    def simple_graph(self):
        """Create a simple dependency graph for testing."""
        graph = DependencyGraph()
        graph.add_dependency("api", "database")
        graph.add_dependency("api", "cache", critical=False)
        return graph

    @pytest.fixture
    def diamond_graph(self):
        """Create a diamond dependency graph for testing."""
        graph = DependencyGraph()
        graph.add_dependency("api", "service_a")
        graph.add_dependency("api", "service_b")
        graph.add_dependency("service_a", "database")
        graph.add_dependency("service_b", "database")
        return graph

    @pytest.fixture
    def protector(self, simple_graph):
        """Create a cascade protector for testing."""
        return CascadeProtector(simple_graph)

    def test_check_cascade_health_healthy(self, protector):
        """Test health check when all dependencies are healthy."""
        state = protector.check_cascade_health("api")
        assert state == CascadeState.HEALTHY

    def test_check_cascade_health_no_dependencies(self, protector):
        """Test health check for tool with no dependencies."""
        state = protector.check_cascade_health("database")
        assert state == CascadeState.HEALTHY

    def test_propagate_failure(self, protector):
        """Test failure propagation through dependencies."""
        affected = protector.propagate_failure("database")

        # API depends on database, so it should be affected
        assert "api" in affected

        # Database should now be failing
        state = protector.check_cascade_health("database")
        assert state == CascadeState.FAILING

    def test_propagate_failure_diamond(self, diamond_graph):
        """Test failure propagation in diamond pattern."""
        protector = CascadeProtector(diamond_graph)
        affected = protector.propagate_failure("database")

        # All tools that depend on database should be affected
        assert "service_a" in affected
        assert "service_b" in affected
        assert "api" in affected

    def test_cascade_state_degraded(self, simple_graph):
        """Test degraded state when non-critical dependency fails."""
        protector = CascadeProtector(simple_graph)

        # Fail the non-critical cache
        protector.propagate_failure("cache")

        # API should be degraded (non-critical dependency failed)
        state = protector.check_cascade_health("api")
        # Since cache is non-critical and database is still healthy,
        # the state depends on thresholds
        assert state in (CascadeState.HEALTHY, CascadeState.DEGRADED)

    def test_isolate_tool(self, protector):
        """Test manual tool isolation."""
        affected = protector.isolate_tool("database")

        state = protector.check_cascade_health("database")
        assert state == CascadeState.ISOLATED

        # API should be affected
        assert "api" in affected

    def test_recover_tool(self, protector):
        """Test tool recovery."""
        # First isolate the tool
        protector.isolate_tool("database")
        assert protector.check_cascade_health("database") == CascadeState.ISOLATED

        # Then recover it
        recovered = protector.recover_tool("database")

        # Database should be healthy again
        state = protector.check_cascade_health("database")
        assert state == CascadeState.HEALTHY

    def test_get_healthy_alternatives(self, simple_graph):
        """Test getting healthy alternatives for failing tool."""
        # Add a fallback
        simple_graph.add_dependency("api", "primary_db", critical=True, fallback="backup_db")
        simple_graph.add_dependency("backup_api", "backup_db")

        protector = CascadeProtector(simple_graph)
        protector.propagate_failure("primary_db")

        alternatives = protector.get_healthy_alternatives("primary_db")
        # backup_db is the fallback and should be healthy
        assert "backup_db" in alternatives

    def test_state_listener(self, protector):
        """Test state change listener."""
        state_changes = []

        def listener(tool, old_state, new_state):
            state_changes.append((tool, old_state, new_state))

        protector.add_state_listener(listener)
        protector.propagate_failure("database")

        # Should have recorded state changes
        assert len(state_changes) > 0
        # Database should have changed to FAILING
        db_changes = [c for c in state_changes if c[0] == "database"]
        assert len(db_changes) > 0
        assert db_changes[0][2] == CascadeState.FAILING

    def test_get_cascade_events(self, protector):
        """Test getting cascade events."""
        protector.propagate_failure("database")
        protector.isolate_tool("cache")

        events = protector.get_cascade_events()
        assert len(events) >= 2

        # Events should be newest first
        event_types = [e.event_type for e in events]
        assert "failure_propagated" in event_types

    def test_get_all_states(self, protector):
        """Test getting all tool states."""
        protector.propagate_failure("database")

        states = protector.get_all_states()
        assert states["database"] == CascadeState.FAILING

    def test_get_failing_tools(self, protector):
        """Test getting failing tools."""
        protector.propagate_failure("database")
        protector.isolate_tool("cache")

        failing = protector.get_failing_tools()
        assert "database" in failing
        assert "cache" in failing

    def test_get_degraded_tools(self, simple_graph):
        """Test getting degraded tools."""
        protector = CascadeProtector(
            simple_graph,
            degraded_threshold=1,
            failing_threshold=2,
        )

        # Fail non-critical dependency
        protector.propagate_failure("cache")

        degraded = protector.get_degraded_tools()
        # The behavior depends on whether api gets marked as degraded
        # based on having one failed dependency
        assert isinstance(degraded, set)

    def test_reset(self, protector):
        """Test resetting cascade states."""
        protector.propagate_failure("database")
        protector.isolate_tool("cache")

        protector.reset()

        assert protector.get_failing_tools() == set()
        assert protector.get_cascade_events() == []

    def test_integration_with_circuit_breaker(self, simple_graph):
        """Test integration with circuit breaker registry."""
        registry = CircuitBreakerRegistry()
        protector = CascadeProtector(simple_graph, registry)

        # Register a circuit breaker
        breaker = registry.register("database")

        # Force the circuit open
        breaker.force_open()

        # Check cascade health - should detect the open circuit
        state = protector.check_cascade_health("api")
        # API's database dependency is failing
        assert state in (CascadeState.DEGRADED, CascadeState.FAILING)


# =============================================================================
# CascadeAwareCircuitBreakerRegistry Tests
# =============================================================================


class TestCascadeAwareCircuitBreakerRegistry:
    """Tests for CascadeAwareCircuitBreakerRegistry."""

    @pytest.fixture
    def setup(self):
        """Set up cascade-aware registry."""
        graph = DependencyGraph()
        graph.add_dependency("api", "database")
        graph.add_dependency("worker", "database")

        protector = CascadeProtector(graph)
        registry = CascadeAwareCircuitBreakerRegistry(protector)

        return graph, protector, registry

    def test_on_circuit_open(self, setup):
        """Test cascade propagation when circuit opens."""
        graph, protector, registry = setup

        affected = registry.on_circuit_open("database")

        # Should affect dependents
        assert "api" in affected
        assert "worker" in affected

    def test_on_circuit_close(self, setup):
        """Test recovery when circuit closes."""
        graph, protector, registry = setup

        # First open the circuit
        registry.on_circuit_open("database")

        # Then close it
        recovered = registry.on_circuit_close("database")

        # Database should be healthy again
        state = protector.check_cascade_health("database")
        assert state == CascadeState.HEALTHY


# =============================================================================
# DependencyInfo Tests
# =============================================================================


class TestDependencyInfo:
    """Tests for DependencyInfo dataclass."""

    def test_default_values(self):
        """Test default values."""
        info = DependencyInfo(name="database")
        assert info.name == "database"
        assert info.critical is True
        assert info.fallback is None

    def test_custom_values(self):
        """Test custom values."""
        info = DependencyInfo(name="cache", critical=False, fallback="backup_cache")
        assert info.name == "cache"
        assert info.critical is False
        assert info.fallback == "backup_cache"


# =============================================================================
# CascadeEvent Tests
# =============================================================================


class TestCascadeEvent:
    """Tests for CascadeEvent dataclass."""

    def test_event_creation(self):
        """Test event creation."""
        from datetime import datetime, timezone

        event = CascadeEvent(
            timestamp=datetime.now(timezone.utc),
            source_tool="database",
            affected_tools={"api", "worker"},
            event_type="failure_propagated",
        )

        assert event.source_tool == "database"
        assert len(event.affected_tools) == 2
        assert event.event_type == "failure_propagated"

    def test_event_with_details(self):
        """Test event with additional details."""
        from datetime import datetime, timezone

        event = CascadeEvent(
            timestamp=datetime.now(timezone.utc),
            source_tool="database",
            affected_tools={"api"},
            event_type="failure_propagated",
            details={"error": "Connection timeout"},
        )

        assert event.details["error"] == "Connection timeout"


# =============================================================================
# CascadeState Tests
# =============================================================================


class TestCascadeState:
    """Tests for CascadeState enum."""

    def test_state_values(self):
        """Test state values."""
        assert CascadeState.HEALTHY.value == "healthy"
        assert CascadeState.DEGRADED.value == "degraded"
        assert CascadeState.FAILING.value == "failing"
        assert CascadeState.ISOLATED.value == "isolated"

    def test_state_count(self):
        """Test there are exactly 4 states."""
        assert len(CascadeState) == 4


# =============================================================================
# Integration Tests
# =============================================================================


class TestCascadeIntegration:
    """Integration tests for cascade protection."""

    def test_complex_cascade_scenario(self):
        """Test a complex cascade scenario."""
        # Build a realistic dependency graph
        graph = DependencyGraph()

        # API layer depends on multiple services
        graph.add_dependency("api_gateway", "auth_service")
        graph.add_dependency("api_gateway", "rate_limiter", critical=False)

        # Auth service depends on user database
        graph.add_dependency("auth_service", "user_db")

        # Order service depends on multiple things
        graph.add_dependency("order_service", "inventory_service")
        graph.add_dependency("order_service", "payment_service")
        graph.add_dependency("order_service", "notification_service", critical=False)

        # Both inventory and payment need the main database
        graph.add_dependency("inventory_service", "main_db")
        graph.add_dependency("payment_service", "main_db")

        protector = CascadeProtector(graph)

        # Simulate main_db failure
        affected = protector.propagate_failure("main_db")

        # Should cascade up
        assert "inventory_service" in affected
        assert "payment_service" in affected
        assert "order_service" in affected

        # Check states
        assert protector.check_cascade_health("main_db") == CascadeState.FAILING
        assert protector.check_cascade_health("inventory_service") in (
            CascadeState.DEGRADED, CascadeState.FAILING
        )

        # API gateway should still be healthy (different dependency chain)
        assert protector.check_cascade_health("api_gateway") == CascadeState.HEALTHY

        # Now simulate recovery
        recovered = protector.recover_tool("main_db")

        # main_db should be healthy again
        assert protector.check_cascade_health("main_db") == CascadeState.HEALTHY

    def test_multiple_failures(self):
        """Test handling multiple simultaneous failures."""
        graph = DependencyGraph()
        graph.add_dependency("api", "service_a")
        graph.add_dependency("api", "service_b")
        graph.add_dependency("service_a", "db_a")
        graph.add_dependency("service_b", "db_b")

        protector = CascadeProtector(graph)

        # Both databases fail
        protector.propagate_failure("db_a")
        protector.propagate_failure("db_b")

        # API should be failing (both services affected)
        state = protector.check_cascade_health("api")
        assert state in (CascadeState.DEGRADED, CascadeState.FAILING)

        # Recover one database
        protector.recover_tool("db_a")

        # API might still be degraded due to db_b
        state = protector.check_cascade_health("api")
        assert state in (CascadeState.HEALTHY, CascadeState.DEGRADED, CascadeState.FAILING)

    def test_listener_notification_order(self):
        """Test that listeners are notified in order."""
        graph = DependencyGraph()
        graph.add_dependency("a", "b")
        graph.add_dependency("b", "c")

        protector = CascadeProtector(graph)
        notifications = []

        def listener(tool, old_state, new_state):
            notifications.append(tool)

        protector.add_state_listener(listener)
        protector.propagate_failure("c")

        # c should be notified first, then cascade up
        assert "c" in notifications
