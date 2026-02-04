"""
Tests for proxilion.security.scope_enforcer module.

Covers ExecutionScope, ScopeBinding, ScopeEnforcer, ScopeContext,
and the scoped_execution context manager.
"""

from __future__ import annotations

import pytest

from proxilion import UserContext
from proxilion.exceptions import ScopeViolationError
from proxilion.security.scope_enforcer import (
    BUILTIN_SCOPES,
    DEFAULT_TOOL_CLASSIFICATIONS,
    ExecutionScope,
    ScopeBinding,
    ScopeContext,
    ScopeEnforcer,
    create_scope_enforcer,
    scoped_execution,
)

# =============================================================================
# ExecutionScope Tests
# =============================================================================


class TestExecutionScope:
    """Tests for ExecutionScope enum."""

    def test_scope_values(self) -> None:
        """Test scope enum values."""
        assert ExecutionScope.READ_ONLY.value == "read_only"
        assert ExecutionScope.READ_WRITE.value == "read_write"
        assert ExecutionScope.ADMIN.value == "admin"
        assert ExecutionScope.CUSTOM.value == "custom"

    def test_scope_members(self) -> None:
        """Test all expected scopes exist."""
        scopes = list(ExecutionScope)
        assert len(scopes) == 4
        assert ExecutionScope.READ_ONLY in scopes
        assert ExecutionScope.READ_WRITE in scopes
        assert ExecutionScope.ADMIN in scopes
        assert ExecutionScope.CUSTOM in scopes


# =============================================================================
# ScopeBinding Tests
# =============================================================================


class TestScopeBinding:
    """Tests for ScopeBinding dataclass."""

    def test_allows_action_with_wildcard(self) -> None:
        """Test wildcard allows all actions."""
        binding = ScopeBinding(
            scope=ExecutionScope.ADMIN,
            allowed_actions={"*"},
        )
        assert binding.allows_action("read")
        assert binding.allows_action("write")
        assert binding.allows_action("delete")
        assert binding.allows_action("execute")

    def test_allows_action_explicit_allow(self) -> None:
        """Test explicit action allowlist."""
        binding = ScopeBinding(
            scope=ExecutionScope.READ_ONLY,
            allowed_actions={"read", "list"},
        )
        assert binding.allows_action("read")
        assert binding.allows_action("list")
        assert not binding.allows_action("write")
        assert not binding.allows_action("delete")

    def test_allows_action_explicit_deny(self) -> None:
        """Test explicit action denylist."""
        binding = ScopeBinding(
            scope=ExecutionScope.READ_WRITE,
            allowed_actions={"read", "write"},
            denied_actions={"delete"},
        )
        assert binding.allows_action("read")
        assert binding.allows_action("write")
        assert not binding.allows_action("delete")

    def test_allows_action_case_insensitive(self) -> None:
        """Test case insensitive action matching."""
        binding = ScopeBinding(
            scope=ExecutionScope.READ_ONLY,
            allowed_actions={"Read", "LIST"},
        )
        assert binding.allows_action("read")
        assert binding.allows_action("READ")
        assert binding.allows_action("list")

    def test_allows_tool_explicit_allow(self) -> None:
        """Test explicit tool allowlist."""
        binding = ScopeBinding(
            scope=ExecutionScope.CUSTOM,
            allowed_tools={"get_user", "list_users"},
        )
        assert binding.allows_tool("get_user")
        assert binding.allows_tool("list_users")
        assert not binding.allows_tool("delete_user")

    def test_allows_tool_wildcard_pattern(self) -> None:
        """Test wildcard pattern in tool list."""
        binding = ScopeBinding(
            scope=ExecutionScope.CUSTOM,
            allowed_tools={"get_*", "list_*"},
        )
        assert binding.allows_tool("get_user")
        assert binding.allows_tool("get_document")
        assert binding.allows_tool("list_users")
        assert not binding.allows_tool("delete_user")

    def test_allows_tool_explicit_deny(self) -> None:
        """Test explicit tool denylist."""
        binding = ScopeBinding(
            scope=ExecutionScope.CUSTOM,
            allowed_tools={"*"},
            denied_tools={"delete_*", "drop_*"},
        )
        assert binding.allows_tool("get_user")
        assert binding.allows_tool("update_user")
        assert not binding.allows_tool("delete_user")
        assert not binding.allows_tool("drop_table")

    def test_allows_tool_case_insensitive(self) -> None:
        """Test case insensitive tool matching."""
        binding = ScopeBinding(
            scope=ExecutionScope.CUSTOM,
            allowed_tools={"Get_User"},
        )
        assert binding.allows_tool("get_user")
        assert binding.allows_tool("GET_USER")

    def test_allows_tool_no_restrictions(self) -> None:
        """Test default behavior with no tool restrictions."""
        binding = ScopeBinding(
            scope=ExecutionScope.ADMIN,
        )
        assert binding.allows_tool("any_tool")
        assert binding.allows_tool("delete_everything")


# =============================================================================
# ScopeEnforcer Core Tests
# =============================================================================


class TestScopeEnforcerCore:
    """Tests for ScopeEnforcer basic operations."""

    def test_init_default(self) -> None:
        """Test default initialization includes built-in scopes."""
        enforcer = ScopeEnforcer()
        scopes = enforcer.get_scopes()
        assert "read_only" in scopes
        assert "read_write" in scopes
        assert "admin" in scopes

    def test_init_custom_scopes(self) -> None:
        """Test initialization with custom scopes."""
        custom = ScopeBinding(
            scope=ExecutionScope.CUSTOM,
            allowed_tools={"my_tool"},
            name="custom_scope",
        )
        enforcer = ScopeEnforcer(custom_scopes={"custom_scope": custom})
        scope = enforcer.get_scope("custom_scope")
        assert scope.name == "custom_scope"
        assert "my_tool" in scope.allowed_tools

    def test_get_scope_by_name(self) -> None:
        """Test getting scope by name string."""
        enforcer = ScopeEnforcer()
        scope = enforcer.get_scope("read_only")
        assert scope.scope == ExecutionScope.READ_ONLY

    def test_get_scope_by_enum(self) -> None:
        """Test getting scope by enum."""
        enforcer = ScopeEnforcer()
        scope = enforcer.get_scope(ExecutionScope.READ_WRITE)
        assert scope.scope == ExecutionScope.READ_WRITE

    def test_get_scope_unknown(self) -> None:
        """Test getting unknown scope raises error."""
        enforcer = ScopeEnforcer()
        with pytest.raises(ValueError, match="Unknown scope"):
            enforcer.get_scope("nonexistent")

    def test_create_scope(self) -> None:
        """Test creating a custom scope."""
        enforcer = ScopeEnforcer()
        scope = enforcer.create_scope(
            name="my_scope",
            allowed_tools={"get_*"},
            denied_tools={"delete_*"},
            allowed_actions={"read"},
            description="My custom scope",
        )
        assert scope.name == "my_scope"
        assert "get_*" in scope.allowed_tools
        assert "delete_*" in scope.denied_tools
        assert "read" in scope.allowed_actions

        # Verify it's registered
        fetched = enforcer.get_scope("my_scope")
        assert fetched.name == "my_scope"

    def test_create_scope_from_enum(self) -> None:
        """Test creating scope binding from enum."""
        enforcer = ScopeEnforcer()
        scope = enforcer.create_scope_from_enum(ExecutionScope.ADMIN)
        assert scope.scope == ExecutionScope.ADMIN

    def test_add_scope(self) -> None:
        """Test adding a scope binding."""
        enforcer = ScopeEnforcer()
        binding = ScopeBinding(
            scope=ExecutionScope.CUSTOM,
            name="added_scope",
        )
        enforcer.add_scope("added_scope", binding)
        assert enforcer.get_scope("added_scope") == binding

    def test_remove_scope(self) -> None:
        """Test removing a custom scope."""
        enforcer = ScopeEnforcer()
        enforcer.create_scope(name="to_remove")
        assert enforcer.remove_scope("to_remove")
        with pytest.raises(ValueError):
            enforcer.get_scope("to_remove")

    def test_remove_builtin_scope_fails(self) -> None:
        """Test that built-in scopes cannot be removed."""
        enforcer = ScopeEnforcer()
        assert not enforcer.remove_scope("read_only")
        # Should still exist
        scope = enforcer.get_scope("read_only")
        assert scope is not None


# =============================================================================
# Tool Classification Tests
# =============================================================================


class TestToolClassification:
    """Tests for tool classification."""

    def test_classify_tool_by_pattern_read(self) -> None:
        """Test read operations are classified as READ_ONLY."""
        enforcer = ScopeEnforcer()
        for prefix in ["get_", "read_", "list_", "search_", "query_", "fetch_", "find_"]:
            classification = enforcer.classify_tool(f"{prefix}user")
            assert classification.default_scope == ExecutionScope.READ_ONLY

    def test_classify_tool_by_pattern_write(self) -> None:
        """Test write operations are classified as READ_WRITE."""
        enforcer = ScopeEnforcer()
        for prefix in ["create_", "write_", "update_", "modify_", "set_", "add_"]:
            classification = enforcer.classify_tool(f"{prefix}user")
            assert classification.default_scope == ExecutionScope.READ_WRITE

    def test_classify_tool_by_pattern_admin(self) -> None:
        """Test admin operations are classified as ADMIN."""
        enforcer = ScopeEnforcer()
        for prefix in ["delete_", "remove_", "drop_", "destroy_", "execute_", "run_"]:
            classification = enforcer.classify_tool(f"{prefix}user")
            assert classification.default_scope == ExecutionScope.ADMIN

    def test_classify_tool_explicit_scope(self) -> None:
        """Test explicit scope assignment."""
        enforcer = ScopeEnforcer()
        classification = enforcer.classify_tool(
            "custom_tool",
            scope=ExecutionScope.ADMIN,
            actions={"execute", "destroy"},
        )
        assert classification.default_scope == ExecutionScope.ADMIN
        assert "execute" in classification.actions

    def test_classify_tool_caching(self) -> None:
        """Test tool classification is cached."""
        enforcer = ScopeEnforcer()

        # First classification
        c1 = enforcer.classify_tool("get_user")
        # Second classification should use cache
        c2 = enforcer.classify_tool("get_user")

        assert c1.default_scope == c2.default_scope

    def test_classify_tool_unknown_defaults_to_default_scope(self) -> None:
        """Test unknown tools use default scope."""
        enforcer = ScopeEnforcer(default_scope=ExecutionScope.READ_ONLY)
        classification = enforcer.classify_tool("unknown_operation")
        assert classification.default_scope == ExecutionScope.READ_ONLY

    def test_add_tool_classification(self) -> None:
        """Test adding custom tool classification patterns."""
        enforcer = ScopeEnforcer()
        enforcer.add_tool_classification(r"^safe_", ExecutionScope.READ_ONLY)

        classification = enforcer.classify_tool("safe_operation")
        assert classification.default_scope == ExecutionScope.READ_ONLY


# =============================================================================
# Scope Validation Tests
# =============================================================================


class TestScopeValidation:
    """Tests for validate_in_scope."""

    def test_read_only_allows_read_operations(self) -> None:
        """Test READ_ONLY scope allows read operations."""
        enforcer = ScopeEnforcer()
        scope = enforcer.get_scope("read_only")

        allowed, reason = enforcer.validate_in_scope("get_user", "read", scope)
        assert allowed
        assert reason is None

    def test_read_only_blocks_write_operations(self) -> None:
        """Test READ_ONLY scope blocks write operations."""
        enforcer = ScopeEnforcer()
        scope = enforcer.get_scope("read_only")

        allowed, reason = enforcer.validate_in_scope("update_user", "write", scope)
        assert not allowed
        assert "not allowed" in reason.lower()

    def test_read_only_blocks_delete_operations(self) -> None:
        """Test READ_ONLY scope blocks delete operations."""
        enforcer = ScopeEnforcer()
        scope = enforcer.get_scope("read_only")

        allowed, reason = enforcer.validate_in_scope("delete_user", "delete", scope)
        assert not allowed

    def test_read_write_allows_read_and_write(self) -> None:
        """Test READ_WRITE scope allows read and write."""
        enforcer = ScopeEnforcer()
        scope = enforcer.get_scope("read_write")

        allowed, _ = enforcer.validate_in_scope("get_user", "read", scope)
        assert allowed

        allowed, _ = enforcer.validate_in_scope("create_user", "create", scope)
        assert allowed

    def test_read_write_blocks_delete(self) -> None:
        """Test READ_WRITE scope blocks delete."""
        enforcer = ScopeEnforcer()
        scope = enforcer.get_scope("read_write")

        allowed, reason = enforcer.validate_in_scope("delete_user", "delete", scope)
        assert not allowed

    def test_admin_allows_everything(self) -> None:
        """Test ADMIN scope allows all operations."""
        enforcer = ScopeEnforcer()
        scope = enforcer.get_scope("admin")

        for action in ["read", "write", "delete", "execute"]:
            allowed, _ = enforcer.validate_in_scope(f"{action}_something", action, scope)
            assert allowed

    def test_custom_scope_explicit_rules(self) -> None:
        """Test custom scope with explicit allow/deny rules."""
        enforcer = ScopeEnforcer()
        scope = enforcer.create_scope(
            name="user_data",
            allowed_tools={"get_user", "update_user"},
            denied_tools={"delete_*"},
            allowed_actions={"read", "write"},
        )

        # Allowed tool and action
        allowed, _ = enforcer.validate_in_scope("get_user", "read", scope)
        assert allowed

        # Denied tool
        allowed, reason = enforcer.validate_in_scope("delete_user", "delete", scope)
        assert not allowed

    def test_tool_scope_hierarchy(self) -> None:
        """Test that tool scope requirements are enforced."""
        enforcer = ScopeEnforcer()

        # delete_user requires ADMIN scope - execute action is blocked in read_only
        read_only = enforcer.get_scope("read_only")
        allowed, reason = enforcer.validate_in_scope("delete_user", "execute", read_only)
        assert not allowed
        assert "not allowed" in reason.lower()

    def test_get_allowed_tools_read_only(self) -> None:
        """Test getting allowed tools for read_only scope."""
        enforcer = ScopeEnforcer()
        scope = enforcer.get_scope("read_only")
        allowed = enforcer.get_allowed_tools(scope)
        assert "get_*" in allowed
        assert "read_*" in allowed
        assert "delete_*" not in allowed

    def test_get_allowed_tools_admin(self) -> None:
        """Test getting allowed tools for admin scope."""
        enforcer = ScopeEnforcer()
        scope = enforcer.get_scope("admin")
        allowed = enforcer.get_allowed_tools(scope)
        assert "*" in allowed


# =============================================================================
# ScopeContext Tests
# =============================================================================


class TestScopeContext:
    """Tests for ScopeContext class."""

    @pytest.fixture
    def user(self) -> UserContext:
        return UserContext(user_id="test_user", roles=["viewer"])

    @pytest.fixture
    def enforcer(self) -> ScopeEnforcer:
        return ScopeEnforcer()

    def test_validate_tool_allowed(self, enforcer: ScopeEnforcer, user: UserContext) -> None:
        """Test validating allowed tool."""
        scope = enforcer.get_scope("read_only")
        ctx = ScopeContext(enforcer, scope, user)

        result = ctx.validate_tool("get_user", "read")
        assert result is True

    def test_validate_tool_blocked(self, enforcer: ScopeEnforcer, user: UserContext) -> None:
        """Test validating blocked tool raises exception."""
        scope = enforcer.get_scope("read_only")
        ctx = ScopeContext(enforcer, scope, user)

        with pytest.raises(ScopeViolationError) as exc_info:
            ctx.validate_tool("delete_user", "delete")

        assert exc_info.value.tool_name == "delete_user"
        assert "read_only" in exc_info.value.scope_name

    def test_is_tool_allowed(self, enforcer: ScopeEnforcer, user: UserContext) -> None:
        """Test is_tool_allowed without raising exception."""
        scope = enforcer.get_scope("read_only")
        ctx = ScopeContext(enforcer, scope, user)

        assert ctx.is_tool_allowed("get_user", "read")
        assert not ctx.is_tool_allowed("delete_user", "delete")

    def test_get_calls_tracks_validated_tools(
        self, enforcer: ScopeEnforcer, user: UserContext,
    ) -> None:
        """Test that validated calls are tracked."""
        scope = enforcer.get_scope("admin")
        ctx = ScopeContext(enforcer, scope, user)

        ctx.validate_tool("get_user", "read")
        ctx.validate_tool("update_user", "write")

        calls = ctx.get_calls()
        assert len(calls) == 2
        assert calls[0] == ("get_user", "read")
        assert calls[1] == ("update_user", "write")

    def test_get_tool_names(self, enforcer: ScopeEnforcer, user: UserContext) -> None:
        """Test getting just tool names."""
        scope = enforcer.get_scope("admin")
        ctx = ScopeContext(enforcer, scope, user)

        ctx.validate_tool("get_user", "read")
        ctx.validate_tool("update_user", "write")

        names = ctx.get_tool_names()
        assert names == ["get_user", "update_user"]

    def test_close_context(self, enforcer: ScopeEnforcer, user: UserContext) -> None:
        """Test closing context."""
        scope = enforcer.get_scope("read_only")
        ctx = ScopeContext(enforcer, scope, user)

        assert not ctx.is_closed
        ctx.close()
        assert ctx.is_closed

    def test_validate_after_close_raises(self, enforcer: ScopeEnforcer, user: UserContext) -> None:
        """Test validation after close raises error."""
        scope = enforcer.get_scope("read_only")
        ctx = ScopeContext(enforcer, scope, user)
        ctx.close()

        with pytest.raises(RuntimeError, match="closed"):
            ctx.validate_tool("get_user", "read")


# =============================================================================
# scoped_execution Context Manager Tests
# =============================================================================


class TestScopedExecution:
    """Tests for scoped_execution context manager."""

    @pytest.fixture
    def user(self) -> UserContext:
        return UserContext(user_id="test_user", roles=["viewer"])

    @pytest.fixture
    def enforcer(self) -> ScopeEnforcer:
        return ScopeEnforcer()

    def test_context_manager_by_name(self, enforcer: ScopeEnforcer, user: UserContext) -> None:
        """Test context manager with scope name."""
        with scoped_execution(enforcer, "read_only", user) as ctx:
            assert ctx.scope.scope == ExecutionScope.READ_ONLY
            ctx.validate_tool("get_user", "read")

        assert ctx.is_closed

    def test_context_manager_by_enum(self, enforcer: ScopeEnforcer, user: UserContext) -> None:
        """Test context manager with ExecutionScope enum."""
        with scoped_execution(enforcer, ExecutionScope.ADMIN, user) as ctx:
            assert ctx.scope.scope == ExecutionScope.ADMIN
            ctx.validate_tool("delete_user", "delete")

    def test_context_manager_closes_on_success(
        self, enforcer: ScopeEnforcer, user: UserContext,
    ) -> None:
        """Test context is closed after successful execution."""
        with scoped_execution(enforcer, "read_only", user) as ctx:
            ctx.validate_tool("get_user", "read")

        assert ctx.is_closed

    def test_context_manager_closes_on_exception(
        self, enforcer: ScopeEnforcer, user: UserContext,
    ) -> None:
        """Test context is closed even on exception."""
        ctx = None
        try:
            with scoped_execution(enforcer, "read_only", user) as ctx:
                raise ValueError("test error")
        except ValueError:
            pass

        assert ctx is not None
        assert ctx.is_closed

    def test_context_manager_tracks_calls(self, enforcer: ScopeEnforcer, user: UserContext) -> None:
        """Test context manager tracks validated calls."""
        with scoped_execution(enforcer, "admin", user) as ctx:
            ctx.validate_tool("get_user", "read")
            ctx.validate_tool("update_user", "write")
            ctx.validate_tool("delete_user", "delete")

        assert len(ctx.get_calls()) == 3

    def test_context_manager_blocks_disallowed_tools(
        self, enforcer: ScopeEnforcer, user: UserContext,
    ) -> None:
        """Test context manager raises on disallowed tools."""
        with (
            pytest.raises(ScopeViolationError),
            scoped_execution(enforcer, "read_only", user) as ctx,
        ):
            ctx.validate_tool("delete_user", "delete")


# =============================================================================
# Built-in Scopes Tests
# =============================================================================


class TestBuiltinScopes:
    """Tests for built-in scope definitions."""

    def test_read_only_scope_actions(self) -> None:
        """Test read_only scope action restrictions."""
        scope = BUILTIN_SCOPES["read_only"]
        assert "read" in scope.allowed_actions
        assert "list" in scope.allowed_actions
        assert "write" in scope.denied_actions
        assert "delete" in scope.denied_actions

    def test_read_write_scope_actions(self) -> None:
        """Test read_write scope action restrictions."""
        scope = BUILTIN_SCOPES["read_write"]
        assert "read" in scope.allowed_actions
        assert "write" in scope.allowed_actions
        assert "create" in scope.allowed_actions
        assert "delete" in scope.denied_actions
        assert "execute" in scope.denied_actions

    def test_admin_scope_actions(self) -> None:
        """Test admin scope allows all."""
        scope = BUILTIN_SCOPES["admin"]
        assert "*" in scope.allowed_actions
        assert len(scope.denied_actions) == 0

    def test_builtin_scopes_have_names(self) -> None:
        """Test all built-in scopes have names."""
        for name, scope in BUILTIN_SCOPES.items():
            assert scope.name == name


# =============================================================================
# Default Tool Classifications Tests
# =============================================================================


class TestDefaultToolClassifications:
    """Tests for default tool classification patterns."""

    def test_classifications_not_empty(self) -> None:
        """Test classifications are defined."""
        assert len(DEFAULT_TOOL_CLASSIFICATIONS) >= 3

    def test_read_patterns(self) -> None:
        """Test read patterns are classified correctly."""
        import re
        for pattern, scope in DEFAULT_TOOL_CLASSIFICATIONS.items():
            if scope == ExecutionScope.READ_ONLY:
                # Should match get_, read_, etc.
                assert any(
                    re.match(pattern, prefix, re.IGNORECASE)
                    for prefix in ["get_", "read_", "list_", "search_"]
                )


# =============================================================================
# Factory Function Tests
# =============================================================================


class TestCreateScopeEnforcer:
    """Tests for create_scope_enforcer factory function."""

    def test_create_default(self) -> None:
        """Test factory with defaults."""
        enforcer = create_scope_enforcer()
        assert enforcer is not None
        assert enforcer.get_scope("read_only") is not None

    def test_create_with_custom_default_scope(self) -> None:
        """Test factory with custom default scope."""
        enforcer = create_scope_enforcer(default_scope=ExecutionScope.READ_WRITE)
        classification = enforcer.classify_tool("unknown_tool")
        assert classification.default_scope == ExecutionScope.READ_WRITE

    def test_create_with_custom_scopes(self) -> None:
        """Test factory with custom scopes."""
        custom = ScopeBinding(
            scope=ExecutionScope.CUSTOM,
            name="my_scope",
        )
        enforcer = create_scope_enforcer(custom_scopes={"my_scope": custom})
        assert enforcer.get_scope("my_scope") is not None


# =============================================================================
# ScopeViolationError Tests
# =============================================================================


class TestScopeViolationError:
    """Tests for ScopeViolationError exception."""

    def test_error_message_basic(self) -> None:
        """Test basic error message."""
        error = ScopeViolationError(
            tool_name="delete_user",
            scope_name="read_only",
        )
        assert "delete_user" in str(error)
        assert "read_only" in str(error)

    def test_error_message_with_reason(self) -> None:
        """Test error message with reason."""
        error = ScopeViolationError(
            tool_name="delete_user",
            scope_name="read_only",
            reason="Action 'delete' is not allowed",
        )
        assert "delete_user" in str(error)
        assert "read_only" in str(error)
        assert "not allowed" in str(error)

    def test_error_attributes(self) -> None:
        """Test error attributes are set."""
        error = ScopeViolationError(
            tool_name="delete_user",
            scope_name="read_only",
            reason="test reason",
        )
        assert error.tool_name == "delete_user"
        assert error.scope_name == "read_only"
        assert error.reason == "test reason"

    def test_error_to_dict(self) -> None:
        """Test error serialization."""
        error = ScopeViolationError(
            tool_name="delete_user",
            scope_name="read_only",
            reason="test reason",
        )
        d = error.to_dict()
        assert d["error_type"] == "ScopeViolationError"
        assert d["details"]["tool_name"] == "delete_user"
        assert d["details"]["scope_name"] == "read_only"


# =============================================================================
# Integration Tests
# =============================================================================


class TestIntegration:
    """Integration tests for scope enforcement."""

    @pytest.fixture
    def user(self) -> UserContext:
        return UserContext(user_id="alice", roles=["analyst"])

    def test_read_only_workflow(self) -> None:
        """Test complete read-only workflow."""
        enforcer = ScopeEnforcer()
        user = UserContext(user_id="viewer", roles=["viewer"])

        with scoped_execution(enforcer, "read_only", user) as ctx:
            # These should all succeed
            ctx.validate_tool("get_user", "read")
            ctx.validate_tool("list_documents", "list")
            ctx.validate_tool("search_files", "search")

            # This should fail
            with pytest.raises(ScopeViolationError):
                ctx.validate_tool("delete_user", "delete")

        # Should have 3 successful calls
        assert len(ctx.get_calls()) == 3

    def test_read_write_workflow(self) -> None:
        """Test complete read-write workflow."""
        enforcer = ScopeEnforcer()
        user = UserContext(user_id="editor", roles=["editor"])

        with scoped_execution(enforcer, "read_write", user) as ctx:
            # Read operations
            ctx.validate_tool("get_user", "read")

            # Write operations
            ctx.validate_tool("create_document", "create")
            ctx.validate_tool("update_user", "modify")

            # Delete should fail
            with pytest.raises(ScopeViolationError):
                ctx.validate_tool("delete_document", "delete")

    def test_admin_workflow(self) -> None:
        """Test complete admin workflow."""
        enforcer = ScopeEnforcer()
        user = UserContext(user_id="admin", roles=["admin"])

        with scoped_execution(enforcer, "admin", user) as ctx:
            # All operations should succeed
            ctx.validate_tool("get_user", "read")
            ctx.validate_tool("create_user", "create")
            ctx.validate_tool("update_user", "write")
            ctx.validate_tool("delete_user", "delete")
            ctx.validate_tool("execute_script", "execute")

        assert len(ctx.get_calls()) == 5

    def test_custom_scope_workflow(self) -> None:
        """Test custom scope workflow."""
        enforcer = ScopeEnforcer()

        # Create a scope that only allows user-related read operations
        enforcer.create_scope(
            name="user_viewer",
            allowed_tools={"get_user", "list_users", "search_users"},
            denied_tools={"*_admin*", "*_config*"},
            allowed_actions={"read", "list", "search"},
        )

        user = UserContext(user_id="support", roles=["support"])

        with scoped_execution(enforcer, "user_viewer", user) as ctx:
            ctx.validate_tool("get_user", "read")
            ctx.validate_tool("list_users", "list")

            with pytest.raises(ScopeViolationError):
                ctx.validate_tool("get_admin_config", "read")


# =============================================================================
# Thread Safety Tests
# =============================================================================


class TestThreadSafety:
    """Tests for thread-safe operations."""

    def test_concurrent_scope_creation(self) -> None:
        """Test concurrent scope creation."""
        import threading

        enforcer = ScopeEnforcer()
        results = []
        lock = threading.Lock()

        def create_scope(name: str) -> None:
            scope = enforcer.create_scope(name=name)
            with lock:
                results.append(scope.name)

        threads = [
            threading.Thread(target=create_scope, args=(f"scope_{i}",))
            for i in range(10)
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 10

    def test_concurrent_classification(self) -> None:
        """Test concurrent tool classification."""
        import threading

        enforcer = ScopeEnforcer()
        results = []
        lock = threading.Lock()

        def classify(tool: str) -> None:
            classification = enforcer.classify_tool(tool)
            with lock:
                results.append(classification)

        tools = [f"get_user_{i}" for i in range(20)]
        threads = [
            threading.Thread(target=classify, args=(tool,))
            for tool in tools
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 20
        assert all(c.default_scope == ExecutionScope.READ_ONLY for c in results)


# =============================================================================
# Edge Cases
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_empty_scope_binding(self) -> None:
        """Test scope binding with no restrictions."""
        binding = ScopeBinding(scope=ExecutionScope.CUSTOM)
        assert binding.allows_action("anything")
        assert binding.allows_tool("anything")

    def test_scope_with_only_denies(self) -> None:
        """Test scope with only deny rules."""
        binding = ScopeBinding(
            scope=ExecutionScope.CUSTOM,
            denied_tools={"dangerous_*"},
            denied_actions={"execute"},
        )
        assert binding.allows_tool("safe_tool")
        assert not binding.allows_tool("dangerous_tool")
        assert binding.allows_action("read")
        assert not binding.allows_action("execute")

    def test_wildcard_in_denied_with_allowed(self) -> None:
        """Test wildcard deny with specific allows."""
        binding = ScopeBinding(
            scope=ExecutionScope.CUSTOM,
            allowed_tools={"*"},
            denied_tools={"admin_*"},
            allowed_actions={"*"},
            denied_actions={"destroy"},
        )
        assert binding.allows_tool("user_tool")
        assert not binding.allows_tool("admin_tool")
        assert binding.allows_action("read")
        assert not binding.allows_action("destroy")

    def test_case_sensitivity_patterns(self) -> None:
        """Test case handling in patterns."""
        enforcer = ScopeEnforcer()

        # Classification should be case-insensitive
        c1 = enforcer.classify_tool("GET_USER")
        c2 = enforcer.classify_tool("get_user")
        assert c1.default_scope == c2.default_scope

    def test_unknown_tool_prefix(self) -> None:
        """Test tools with unknown prefixes."""
        enforcer = ScopeEnforcer()
        classification = enforcer.classify_tool("process_data")
        # Should default to default_scope (READ_ONLY by default)
        assert classification.default_scope == ExecutionScope.READ_ONLY

    def test_infer_actions(self) -> None:
        """Test action inference from tool names."""
        enforcer = ScopeEnforcer()

        # Test read tools
        classification = enforcer.classify_tool("get_user")
        assert "read" in classification.actions

        # Test write tools
        classification = enforcer.classify_tool("create_document")
        assert "write" in classification.actions or "create" in classification.actions

        # Test delete tools
        classification = enforcer.classify_tool("delete_record")
        assert "delete" in classification.actions
