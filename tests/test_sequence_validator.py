"""
Tests for proxilion.security.sequence_validator module.

Covers all sequence actions: REQUIRE_BEFORE, FORBID_AFTER, REQUIRE_SEQUENCE,
MAX_CONSECUTIVE, and COOLDOWN.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import pytest

from proxilion.security.sequence_validator import (
    DEFAULT_SEQUENCE_RULES,
    SequenceAction,
    SequenceRule,
    SequenceValidator,
    SequenceViolation,
    ToolCallRecord,
    create_sequence_validator,
)
from proxilion.exceptions import SequenceViolationError


# =============================================================================
# SequenceRule Tests
# =============================================================================


class TestSequenceRule:
    """Tests for SequenceRule dataclass."""

    def test_matches_target_exact(self) -> None:
        """Test exact pattern matching (case insensitive)."""
        rule = SequenceRule(
            name="test",
            action=SequenceAction.REQUIRE_BEFORE,
            target_pattern="delete_file",
        )
        assert rule.matches_target("delete_file")
        assert not rule.matches_target("delete_folder")
        assert rule.matches_target("DELETE_FILE")  # Case insensitive by design

    def test_matches_target_wildcard_prefix(self) -> None:
        """Test wildcard prefix matching."""
        rule = SequenceRule(
            name="test",
            action=SequenceAction.REQUIRE_BEFORE,
            target_pattern="delete_*",
        )
        assert rule.matches_target("delete_file")
        assert rule.matches_target("delete_folder")
        assert rule.matches_target("delete_database")
        assert not rule.matches_target("remove_file")

    def test_matches_target_wildcard_all(self) -> None:
        """Test universal wildcard."""
        rule = SequenceRule(
            name="test",
            action=SequenceAction.MAX_CONSECUTIVE,
            target_pattern="*",
        )
        assert rule.matches_target("any_tool")
        assert rule.matches_target("another_tool")

    def test_matches_target_case_insensitive(self) -> None:
        """Test case-insensitive matching."""
        rule = SequenceRule(
            name="test",
            action=SequenceAction.REQUIRE_BEFORE,
            target_pattern="delete_*",
        )
        assert rule.matches_target("DELETE_FILE")
        assert rule.matches_target("Delete_Folder")

    def test_matches_pattern(self) -> None:
        """Test pattern matching helper."""
        rule = SequenceRule(
            name="test",
            action=SequenceAction.REQUIRE_BEFORE,
            target_pattern="delete_*",
            required_pattern="confirm_*",
        )
        assert rule.matches_pattern("confirm_delete", "confirm_*")
        assert rule.matches_pattern("confirm_action", "confirm_*")
        assert not rule.matches_pattern("verify_delete", "confirm_*")


# =============================================================================
# SequenceValidator Core Tests
# =============================================================================


class TestSequenceValidatorCore:
    """Tests for SequenceValidator basic operations."""

    def test_init_default(self) -> None:
        """Test default initialization includes default rules."""
        validator = SequenceValidator()
        rules = validator.get_rules()
        assert len(rules) >= 4  # At least 4 default rules
        rule_names = [r.name for r in rules]
        assert "require_confirm_before_delete" in rule_names
        assert "max_consecutive_calls" in rule_names
        assert "forbid_download_execute" in rule_names

    def test_init_no_defaults(self) -> None:
        """Test initialization without default rules."""
        validator = SequenceValidator(include_defaults=False)
        assert len(validator.get_rules()) == 0

    def test_init_custom_rules(self) -> None:
        """Test initialization with custom rules."""
        custom_rule = SequenceRule(
            name="custom",
            action=SequenceAction.COOLDOWN,
            target_pattern="expensive_*",
            cooldown_seconds=30.0,
        )
        validator = SequenceValidator(rules=[custom_rule], include_defaults=False)
        rules = validator.get_rules()
        assert len(rules) == 1
        assert rules[0].name == "custom"

    def test_init_custom_history_size(self) -> None:
        """Test custom history size."""
        validator = SequenceValidator(history_size=5, include_defaults=False)

        # Record more than history_size calls
        for i in range(10):
            validator.record_call(f"tool_{i}", "user_1")

        history = validator.get_history("user_1")
        assert len(history) == 5  # Truncated to history_size

    def test_add_rule(self) -> None:
        """Test adding a rule."""
        validator = SequenceValidator(include_defaults=False)
        rule = SequenceRule(
            name="new_rule",
            action=SequenceAction.REQUIRE_BEFORE,
            target_pattern="test_*",
        )
        validator.add_rule(rule)
        assert validator.get_rule("new_rule") is not None

    def test_remove_rule(self) -> None:
        """Test removing a rule."""
        validator = SequenceValidator(include_defaults=False)
        rule = SequenceRule(
            name="to_remove",
            action=SequenceAction.REQUIRE_BEFORE,
            target_pattern="test_*",
        )
        validator.add_rule(rule)
        assert validator.remove_rule("to_remove")
        assert validator.get_rule("to_remove") is None

    def test_remove_rule_not_found(self) -> None:
        """Test removing non-existent rule."""
        validator = SequenceValidator(include_defaults=False)
        assert not validator.remove_rule("nonexistent")

    def test_enable_disable_rule(self) -> None:
        """Test enabling and disabling rules."""
        validator = SequenceValidator(include_defaults=False)
        rule = SequenceRule(
            name="toggle_rule",
            action=SequenceAction.REQUIRE_BEFORE,
            target_pattern="delete_*",
            required_pattern="confirm_*",
        )
        validator.add_rule(rule)

        # Initially enabled
        allowed, _ = validator.validate_call("delete_file", "user_1")
        assert not allowed

        # Disable rule
        validator.disable_rule("toggle_rule")
        allowed, _ = validator.validate_call("delete_file", "user_1")
        assert allowed

        # Re-enable
        validator.enable_rule("toggle_rule")
        allowed, _ = validator.validate_call("delete_file", "user_1")
        assert not allowed

    def test_get_rules(self) -> None:
        """Test getting all rules returns a copy."""
        validator = SequenceValidator(include_defaults=False)
        rule = SequenceRule(
            name="test",
            action=SequenceAction.COOLDOWN,
            target_pattern="*",
        )
        validator.add_rule(rule)

        rules = validator.get_rules()
        rules.append(SequenceRule(
            name="extra",
            action=SequenceAction.COOLDOWN,
            target_pattern="*",
        ))

        # Original should not be modified
        assert len(validator.get_rules()) == 1


# =============================================================================
# REQUIRE_BEFORE Tests
# =============================================================================


class TestRequireBefore:
    """Tests for REQUIRE_BEFORE action."""

    def test_require_before_blocked_no_prior(self) -> None:
        """Test deletion blocked without confirmation."""
        validator = SequenceValidator(include_defaults=False)
        validator.add_rule(SequenceRule(
            name="require_confirm",
            action=SequenceAction.REQUIRE_BEFORE,
            target_pattern="delete_*",
            required_pattern="confirm_*",
        ))

        allowed, violation = validator.validate_call("delete_file", "user_1")
        assert not allowed
        assert violation is not None
        assert violation.rule_name == "require_confirm"
        assert violation.violation_type == SequenceAction.REQUIRE_BEFORE
        assert violation.required_prior == "confirm_*"

    def test_require_before_allowed_with_prior(self) -> None:
        """Test deletion allowed after confirmation."""
        validator = SequenceValidator(include_defaults=False)
        validator.add_rule(SequenceRule(
            name="require_confirm",
            action=SequenceAction.REQUIRE_BEFORE,
            target_pattern="delete_*",
            required_pattern="confirm_*",
        ))

        # Confirm first
        validator.record_call("confirm_delete", "user_1")

        # Now delete should succeed
        allowed, violation = validator.validate_call("delete_file", "user_1")
        assert allowed
        assert violation is None

    def test_require_before_wildcard_match(self) -> None:
        """Test wildcard matching for required pattern."""
        validator = SequenceValidator(include_defaults=False)
        validator.add_rule(SequenceRule(
            name="require_confirm",
            action=SequenceAction.REQUIRE_BEFORE,
            target_pattern="delete_*",
            required_pattern="confirm_*",
        ))

        # Any confirm_* should work
        validator.record_call("confirm_action", "user_1")

        allowed, _ = validator.validate_call("delete_file", "user_1")
        assert allowed

    def test_require_before_non_matching_tool_allowed(self) -> None:
        """Test non-matching tools are allowed."""
        validator = SequenceValidator(include_defaults=False)
        validator.add_rule(SequenceRule(
            name="require_confirm",
            action=SequenceAction.REQUIRE_BEFORE,
            target_pattern="delete_*",
            required_pattern="confirm_*",
        ))

        # Tools not matching delete_* should be allowed
        allowed, _ = validator.validate_call("read_file", "user_1")
        assert allowed

    def test_require_before_user_isolation(self) -> None:
        """Test that history is per-user."""
        validator = SequenceValidator(include_defaults=False)
        validator.add_rule(SequenceRule(
            name="require_confirm",
            action=SequenceAction.REQUIRE_BEFORE,
            target_pattern="delete_*",
            required_pattern="confirm_*",
        ))

        # User 1 confirms
        validator.record_call("confirm_delete", "user_1")

        # User 1 can delete
        allowed, _ = validator.validate_call("delete_file", "user_1")
        assert allowed

        # User 2 cannot delete (no confirmation)
        allowed, violation = validator.validate_call("delete_file", "user_2")
        assert not allowed
        assert violation is not None


# =============================================================================
# FORBID_AFTER Tests
# =============================================================================


class TestForbidAfter:
    """Tests for FORBID_AFTER action."""

    def test_forbid_after_blocked_in_window(self) -> None:
        """Test execute blocked after download within window."""
        validator = SequenceValidator(include_defaults=False)
        validator.add_rule(SequenceRule(
            name="forbid_download_execute",
            action=SequenceAction.FORBID_AFTER,
            target_pattern="execute_*",
            forbidden_pattern="download_*",
            window_seconds=300.0,
        ))

        # Download first
        validator.record_call("download_script", "user_1")

        # Execute should be blocked
        allowed, violation = validator.validate_call("execute_script", "user_1")
        assert not allowed
        assert violation is not None
        assert violation.rule_name == "forbid_download_execute"
        assert violation.violation_type == SequenceAction.FORBID_AFTER
        assert violation.forbidden_prior == "download_script"

    def test_forbid_after_allowed_outside_window(self) -> None:
        """Test execute allowed when download is outside window."""
        validator = SequenceValidator(include_defaults=False)
        validator.add_rule(SequenceRule(
            name="forbid_download_execute",
            action=SequenceAction.FORBID_AFTER,
            target_pattern="execute_*",
            forbidden_pattern="download_*",
            window_seconds=0.1,  # Very short window for testing
        ))

        # Download first
        validator.record_call("download_script", "user_1")

        # Wait for window to expire
        time.sleep(0.15)

        # Execute should now be allowed
        allowed, _ = validator.validate_call("execute_script", "user_1")
        assert allowed

    def test_forbid_after_allowed_without_prior(self) -> None:
        """Test execute allowed without prior download."""
        validator = SequenceValidator(include_defaults=False)
        validator.add_rule(SequenceRule(
            name="forbid_download_execute",
            action=SequenceAction.FORBID_AFTER,
            target_pattern="execute_*",
            forbidden_pattern="download_*",
            window_seconds=300.0,
        ))

        # No download, execute should be allowed
        allowed, _ = validator.validate_call("execute_script", "user_1")
        assert allowed

    def test_forbid_after_user_isolation(self) -> None:
        """Test forbid_after is per-user."""
        validator = SequenceValidator(include_defaults=False)
        validator.add_rule(SequenceRule(
            name="forbid_download_execute",
            action=SequenceAction.FORBID_AFTER,
            target_pattern="execute_*",
            forbidden_pattern="download_*",
            window_seconds=300.0,
        ))

        # User 1 downloads
        validator.record_call("download_script", "user_1")

        # User 1 cannot execute
        allowed, _ = validator.validate_call("execute_script", "user_1")
        assert not allowed

        # User 2 can execute (no prior download)
        allowed, _ = validator.validate_call("execute_script", "user_2")
        assert allowed


# =============================================================================
# REQUIRE_SEQUENCE Tests
# =============================================================================


class TestRequireSequence:
    """Tests for REQUIRE_SEQUENCE action."""

    def test_require_sequence_first_step_allowed(self) -> None:
        """Test first step in sequence is always allowed."""
        validator = SequenceValidator(include_defaults=False)
        validator.add_rule(SequenceRule(
            name="checkout_sequence",
            action=SequenceAction.REQUIRE_SEQUENCE,
            target_pattern="checkout_*",
            sequence_patterns=["checkout_cart", "checkout_payment", "checkout_confirm"],
        ))

        # First step allowed without prior
        allowed, _ = validator.validate_call("checkout_cart", "user_1")
        assert allowed

    def test_require_sequence_blocked_skipping_step(self) -> None:
        """Test blocking when steps are skipped."""
        validator = SequenceValidator(include_defaults=False)
        validator.add_rule(SequenceRule(
            name="checkout_sequence",
            action=SequenceAction.REQUIRE_SEQUENCE,
            target_pattern="checkout_*",
            sequence_patterns=["checkout_cart", "checkout_payment", "checkout_confirm"],
        ))

        # Try to skip to payment without cart
        allowed, violation = validator.validate_call("checkout_payment", "user_1")
        assert not allowed
        assert violation is not None
        assert violation.required_prior == "checkout_cart"

    def test_require_sequence_allowed_in_order(self) -> None:
        """Test sequence allowed in correct order."""
        validator = SequenceValidator(include_defaults=False)
        validator.add_rule(SequenceRule(
            name="checkout_sequence",
            action=SequenceAction.REQUIRE_SEQUENCE,
            target_pattern="checkout_*",
            sequence_patterns=["checkout_cart", "checkout_payment", "checkout_confirm"],
        ))

        # Step 1
        validator.record_call("checkout_cart", "user_1")
        allowed, _ = validator.validate_call("checkout_cart", "user_1")
        assert allowed

        # Step 2
        allowed, _ = validator.validate_call("checkout_payment", "user_1")
        assert allowed
        validator.record_call("checkout_payment", "user_1")

        # Step 3
        allowed, _ = validator.validate_call("checkout_confirm", "user_1")
        assert allowed

    def test_require_sequence_non_matching_allowed(self) -> None:
        """Test tools not in sequence are allowed."""
        validator = SequenceValidator(include_defaults=False)
        validator.add_rule(SequenceRule(
            name="checkout_sequence",
            action=SequenceAction.REQUIRE_SEQUENCE,
            target_pattern="checkout_*",
            sequence_patterns=["checkout_cart", "checkout_payment", "checkout_confirm"],
        ))

        # Tool not matching checkout_* is allowed
        allowed, _ = validator.validate_call("read_products", "user_1")
        assert allowed


# =============================================================================
# MAX_CONSECUTIVE Tests
# =============================================================================


class TestMaxConsecutive:
    """Tests for MAX_CONSECUTIVE action."""

    def test_max_consecutive_blocked_at_limit(self) -> None:
        """Test blocking when consecutive calls reach limit."""
        validator = SequenceValidator(include_defaults=False)
        validator.add_rule(SequenceRule(
            name="max_calls",
            action=SequenceAction.MAX_CONSECUTIVE,
            target_pattern="*",
            max_count=3,
        ))

        # First 3 calls allowed
        for i in range(3):
            allowed, _ = validator.validate_call("repeat_tool", "user_1")
            assert allowed
            validator.record_call("repeat_tool", "user_1")

        # 4th call blocked
        allowed, violation = validator.validate_call("repeat_tool", "user_1")
        assert not allowed
        assert violation is not None
        assert violation.rule_name == "max_calls"
        assert violation.violation_type == SequenceAction.MAX_CONSECUTIVE
        assert violation.consecutive_count == 3

    def test_max_consecutive_reset_by_different_tool(self) -> None:
        """Test consecutive count resets with different tool."""
        validator = SequenceValidator(include_defaults=False)
        validator.add_rule(SequenceRule(
            name="max_calls",
            action=SequenceAction.MAX_CONSECUTIVE,
            target_pattern="*",
            max_count=3,
        ))

        # 3 calls to tool A
        for _ in range(3):
            validator.record_call("tool_a", "user_1")

        # Call to different tool
        validator.record_call("tool_b", "user_1")

        # Now tool A is allowed again
        allowed, _ = validator.validate_call("tool_a", "user_1")
        assert allowed

    def test_max_consecutive_wildcard_pattern(self) -> None:
        """Test max_consecutive with wildcard pattern."""
        validator = SequenceValidator(include_defaults=False)
        validator.add_rule(SequenceRule(
            name="max_api_calls",
            action=SequenceAction.MAX_CONSECUTIVE,
            target_pattern="api_*",
            max_count=2,
        ))

        # Different api_* tools don't count as consecutive
        validator.record_call("api_read", "user_1")
        validator.record_call("api_write", "user_1")

        # api_read again is not consecutive (api_write broke the streak)
        allowed, _ = validator.validate_call("api_read", "user_1")
        assert allowed

    def test_max_consecutive_user_isolation(self) -> None:
        """Test max_consecutive is per-user."""
        validator = SequenceValidator(include_defaults=False)
        validator.add_rule(SequenceRule(
            name="max_calls",
            action=SequenceAction.MAX_CONSECUTIVE,
            target_pattern="*",
            max_count=2,
        ))

        # User 1 makes 2 calls
        for _ in range(2):
            validator.record_call("test_tool", "user_1")

        # User 1 is blocked
        allowed, _ = validator.validate_call("test_tool", "user_1")
        assert not allowed

        # User 2 is not blocked
        allowed, _ = validator.validate_call("test_tool", "user_2")
        assert allowed


# =============================================================================
# COOLDOWN Tests
# =============================================================================


class TestCooldown:
    """Tests for COOLDOWN action."""

    def test_cooldown_blocked_during_cooldown(self) -> None:
        """Test call blocked during cooldown period."""
        validator = SequenceValidator(include_defaults=False)
        validator.add_rule(SequenceRule(
            name="rate_limit",
            action=SequenceAction.COOLDOWN,
            target_pattern="expensive_*",
            cooldown_seconds=1.0,
        ))

        # First call allowed
        allowed, _ = validator.validate_call("expensive_query", "user_1")
        assert allowed
        validator.record_call("expensive_query", "user_1")

        # Immediate second call blocked
        allowed, violation = validator.validate_call("expensive_query", "user_1")
        assert not allowed
        assert violation is not None
        assert violation.rule_name == "rate_limit"
        assert violation.violation_type == SequenceAction.COOLDOWN
        assert violation.last_call_seconds_ago < 1.0

    def test_cooldown_allowed_after_cooldown(self) -> None:
        """Test call allowed after cooldown expires."""
        validator = SequenceValidator(include_defaults=False)
        validator.add_rule(SequenceRule(
            name="rate_limit",
            action=SequenceAction.COOLDOWN,
            target_pattern="expensive_*",
            cooldown_seconds=0.1,
        ))

        # First call
        validator.record_call("expensive_query", "user_1")

        # Wait for cooldown
        time.sleep(0.15)

        # Second call allowed
        allowed, _ = validator.validate_call("expensive_query", "user_1")
        assert allowed

    def test_cooldown_different_tools(self) -> None:
        """Test cooldown only applies to same tool."""
        validator = SequenceValidator(include_defaults=False)
        validator.add_rule(SequenceRule(
            name="rate_limit",
            action=SequenceAction.COOLDOWN,
            target_pattern="expensive_*",
            cooldown_seconds=60.0,
        ))

        # Call one tool
        validator.record_call("expensive_query", "user_1")

        # Different tool (matching pattern) allowed
        allowed, _ = validator.validate_call("expensive_report", "user_1")
        assert allowed

    def test_cooldown_user_isolation(self) -> None:
        """Test cooldown is per-user."""
        validator = SequenceValidator(include_defaults=False)
        validator.add_rule(SequenceRule(
            name="rate_limit",
            action=SequenceAction.COOLDOWN,
            target_pattern="expensive_*",
            cooldown_seconds=60.0,
        ))

        # User 1 in cooldown
        validator.record_call("expensive_query", "user_1")

        allowed, _ = validator.validate_call("expensive_query", "user_1")
        assert not allowed

        # User 2 not in cooldown
        allowed, _ = validator.validate_call("expensive_query", "user_2")
        assert allowed


# =============================================================================
# History Management Tests
# =============================================================================


class TestHistoryManagement:
    """Tests for history management operations."""

    def test_record_call(self) -> None:
        """Test recording calls to history."""
        validator = SequenceValidator(include_defaults=False)

        validator.record_call("tool_a", "user_1")
        validator.record_call("tool_b", "user_1")

        history = validator.get_history("user_1")
        assert len(history) == 2
        assert history[0][0] == "tool_b"  # Most recent first
        assert history[1][0] == "tool_a"

    def test_record_call_with_timestamp(self) -> None:
        """Test recording calls with custom timestamp."""
        validator = SequenceValidator(include_defaults=False)

        custom_time = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        validator.record_call("tool_a", "user_1", timestamp=custom_time)

        history = validator.get_history("user_1")
        assert history[0][1] == custom_time

    def test_get_history_limit(self) -> None:
        """Test history retrieval with limit."""
        validator = SequenceValidator(include_defaults=False)

        for i in range(10):
            validator.record_call(f"tool_{i}", "user_1")

        history = validator.get_history("user_1", limit=3)
        assert len(history) == 3

    def test_get_history_empty_user(self) -> None:
        """Test history for user with no calls."""
        validator = SequenceValidator(include_defaults=False)
        history = validator.get_history("unknown_user")
        assert history == []

    def test_clear_history_single_user(self) -> None:
        """Test clearing history for single user."""
        validator = SequenceValidator(include_defaults=False)

        validator.record_call("tool", "user_1")
        validator.record_call("tool", "user_2")

        validator.clear_history("user_1")

        assert len(validator.get_history("user_1")) == 0
        assert len(validator.get_history("user_2")) == 1

    def test_clear_history_all_users(self) -> None:
        """Test clearing all history."""
        validator = SequenceValidator(include_defaults=False)

        validator.record_call("tool", "user_1")
        validator.record_call("tool", "user_2")

        validator.clear_history()

        assert len(validator.get_history("user_1")) == 0
        assert len(validator.get_history("user_2")) == 0

    def test_history_size_limit(self) -> None:
        """Test history respects size limit."""
        validator = SequenceValidator(history_size=5, include_defaults=False)

        for i in range(10):
            validator.record_call(f"tool_{i}", "user_1")

        history = validator.get_history("user_1")
        assert len(history) == 5
        # Should have most recent 5 (tool_5 through tool_9)
        tool_names = [h[0] for h in history]
        assert "tool_9" in tool_names
        assert "tool_0" not in tool_names

    def test_configure_history_size(self) -> None:
        """Test reconfiguring history size."""
        validator = SequenceValidator(history_size=10, include_defaults=False)

        for i in range(10):
            validator.record_call(f"tool_{i}", "user_1")

        # Resize to smaller
        validator.configure(history_size=3)

        history = validator.get_history("user_1")
        assert len(history) == 3


# =============================================================================
# Default Rules Tests
# =============================================================================


class TestDefaultRules:
    """Tests for default security rules."""

    def test_default_require_confirm_before_delete(self) -> None:
        """Test default rule requiring confirmation before delete."""
        validator = SequenceValidator()

        # Delete without confirm should fail
        allowed, violation = validator.validate_call("delete_file", "user_1")
        assert not allowed
        assert violation.rule_name == "require_confirm_before_delete"

        # Confirm then delete should work
        validator.record_call("confirm_delete", "user_1")
        allowed, _ = validator.validate_call("delete_file", "user_1")
        assert allowed

    def test_default_max_consecutive_calls(self) -> None:
        """Test default max consecutive calls rule."""
        validator = SequenceValidator()

        # Record many consecutive calls
        for i in range(10):
            validator.record_call("repeat_action", "user_1")

        # 11th call should be blocked
        allowed, violation = validator.validate_call("repeat_action", "user_1")
        assert not allowed
        assert violation.rule_name == "max_consecutive_calls"

    def test_default_forbid_download_execute(self) -> None:
        """Test default rule forbidding execute after download."""
        validator = SequenceValidator()

        # Download then execute should fail
        validator.record_call("download_script", "user_1")
        allowed, violation = validator.validate_call("execute_command", "user_1")
        assert not allowed
        assert violation.rule_name == "forbid_download_execute"

    def test_default_forbid_download_run(self) -> None:
        """Test default rule forbidding run after download."""
        validator = SequenceValidator()

        # Download then run should fail
        validator.record_call("download_binary", "user_1")
        allowed, violation = validator.validate_call("run_process", "user_1")
        assert not allowed
        assert violation.rule_name == "forbid_download_run"


# =============================================================================
# Factory Function Tests
# =============================================================================


class TestCreateSequenceValidator:
    """Tests for create_sequence_validator factory function."""

    def test_create_with_defaults(self) -> None:
        """Test factory with default rules."""
        validator = create_sequence_validator()
        assert len(validator.get_rules()) >= 4

    def test_create_without_defaults(self) -> None:
        """Test factory without default rules."""
        validator = create_sequence_validator(include_defaults=False)
        assert len(validator.get_rules()) == 0

    def test_create_with_custom_rules(self) -> None:
        """Test factory with custom rules."""
        custom = SequenceRule(
            name="custom",
            action=SequenceAction.COOLDOWN,
            target_pattern="*",
        )
        validator = create_sequence_validator(
            include_defaults=False,
            custom_rules=[custom],
        )
        assert len(validator.get_rules()) == 1
        assert validator.get_rule("custom") is not None

    def test_create_with_custom_history_size(self) -> None:
        """Test factory with custom history size."""
        validator = create_sequence_validator(
            include_defaults=False,
            history_size=10,
        )

        for i in range(20):
            validator.record_call(f"tool_{i}", "user_1")

        assert len(validator.get_history("user_1")) == 10


# =============================================================================
# SequenceViolation Tests
# =============================================================================


class TestSequenceViolation:
    """Tests for SequenceViolation dataclass."""

    def test_violation_attributes(self) -> None:
        """Test violation has expected attributes."""
        violation = SequenceViolation(
            rule_name="test_rule",
            violation_type=SequenceAction.REQUIRE_BEFORE,
            tool_name="delete_file",
            required_prior="confirm_*",
            message="Test message",
            tool_sequence=["read_file", "write_file"],
        )

        assert violation.rule_name == "test_rule"
        assert violation.violation_type == SequenceAction.REQUIRE_BEFORE
        assert violation.tool_name == "delete_file"
        assert violation.required_prior == "confirm_*"
        assert violation.message == "Test message"
        assert len(violation.tool_sequence) == 2

    def test_violation_consecutive_count(self) -> None:
        """Test violation consecutive count attribute."""
        violation = SequenceViolation(
            rule_name="max_calls",
            violation_type=SequenceAction.MAX_CONSECUTIVE,
            tool_name="repeat_tool",
            consecutive_count=5,
            message="Too many calls",
        )

        assert violation.consecutive_count == 5


# =============================================================================
# SequenceViolationError Tests
# =============================================================================


class TestSequenceViolationError:
    """Tests for SequenceViolationError exception."""

    def test_error_with_required_prior(self) -> None:
        """Test error message with required prior."""
        error = SequenceViolationError(
            rule_name="require_confirm",
            tool_name="delete_file",
            required_prior="confirm_*",
        )

        assert "require_confirm" in str(error)
        assert "requires 'confirm_*'" in str(error)
        assert "delete_file" in str(error)
        assert error.required_prior == "confirm_*"

    def test_error_with_forbidden_prior(self) -> None:
        """Test error message with forbidden prior."""
        error = SequenceViolationError(
            rule_name="forbid_download_execute",
            tool_name="execute_script",
            forbidden_prior="download_*",
        )

        assert "forbid_download_execute" in str(error)
        assert "forbidden after" in str(error)
        assert error.forbidden_prior == "download_*"

    def test_error_with_consecutive_count(self) -> None:
        """Test error message with consecutive count."""
        error = SequenceViolationError(
            rule_name="max_calls",
            tool_name="repeat_tool",
            consecutive_count=10,
        )

        assert "10 times consecutively" in str(error)
        assert error.consecutive_count == 10

    def test_error_with_cooldown(self) -> None:
        """Test error message with cooldown remaining."""
        error = SequenceViolationError(
            rule_name="rate_limit",
            tool_name="expensive_call",
            cooldown_remaining=30.5,
        )

        assert "in cooldown" in str(error)
        assert "30.5" in str(error)
        assert error.cooldown_remaining == 30.5

    def test_error_to_dict(self) -> None:
        """Test error serialization."""
        error = SequenceViolationError(
            rule_name="test_rule",
            tool_name="test_tool",
            required_prior="prior_tool",
            violation_type="require_before",
        )

        d = error.to_dict()
        assert d["error_type"] == "SequenceViolationError"
        assert "test_rule" in d["message"]
        assert d["details"]["rule_name"] == "test_rule"
        assert d["details"]["tool_name"] == "test_tool"


# =============================================================================
# Thread Safety Tests
# =============================================================================


class TestThreadSafety:
    """Tests for thread-safe operations."""

    def test_concurrent_record_calls(self) -> None:
        """Test concurrent record calls don't corrupt history."""
        import threading

        validator = SequenceValidator(include_defaults=False)

        def record_calls(user_id: str, count: int) -> None:
            for i in range(count):
                validator.record_call(f"tool_{i}", user_id)

        threads = [
            threading.Thread(target=record_calls, args=(f"user_{i}", 50))
            for i in range(5)
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Each user should have 50 entries
        for i in range(5):
            history = validator.get_history(f"user_{i}")
            assert len(history) == 50

    def test_concurrent_validate_and_record(self) -> None:
        """Test concurrent validation and recording."""
        import threading

        validator = SequenceValidator(include_defaults=False)
        validator.add_rule(SequenceRule(
            name="test",
            action=SequenceAction.REQUIRE_BEFORE,
            target_pattern="delete_*",
            required_pattern="confirm_*",
        ))

        results = []
        lock = threading.Lock()

        def validate_and_record(user_id: str) -> None:
            validator.record_call("confirm_delete", user_id)
            allowed, _ = validator.validate_call("delete_file", user_id)
            with lock:
                results.append(allowed)

        threads = [
            threading.Thread(target=validate_and_record, args=(f"user_{i}",))
            for i in range(10)
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All should succeed (each user confirmed before deleting)
        assert all(results)


# =============================================================================
# Integration with DEFAULT_SEQUENCE_RULES
# =============================================================================


class TestDefaultSequenceRulesConstant:
    """Tests for DEFAULT_SEQUENCE_RULES constant."""

    def test_default_rules_not_empty(self) -> None:
        """Test default rules list is not empty."""
        assert len(DEFAULT_SEQUENCE_RULES) >= 4

    def test_default_rules_all_valid(self) -> None:
        """Test all default rules have valid configuration."""
        for rule in DEFAULT_SEQUENCE_RULES:
            assert rule.name
            assert isinstance(rule.action, SequenceAction)
            assert rule.target_pattern
            assert rule.enabled

    def test_default_rules_have_descriptions(self) -> None:
        """Test default rules have descriptions."""
        for rule in DEFAULT_SEQUENCE_RULES:
            assert rule.description, f"Rule {rule.name} has no description"


# =============================================================================
# Edge Cases
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_empty_history(self) -> None:
        """Test validation with empty history."""
        validator = SequenceValidator(include_defaults=False)
        validator.add_rule(SequenceRule(
            name="cooldown",
            action=SequenceAction.COOLDOWN,
            target_pattern="*",
            cooldown_seconds=60.0,
        ))

        # First call with no history should be allowed
        allowed, _ = validator.validate_call("any_tool", "user_1")
        assert allowed

    def test_disabled_rule_no_effect(self) -> None:
        """Test disabled rules don't affect validation."""
        validator = SequenceValidator(include_defaults=False)
        rule = SequenceRule(
            name="disabled",
            action=SequenceAction.REQUIRE_BEFORE,
            target_pattern="delete_*",
            required_pattern="confirm_*",
            enabled=False,
        )
        validator.add_rule(rule)

        # Should be allowed since rule is disabled
        allowed, _ = validator.validate_call("delete_file", "user_1")
        assert allowed

    def test_no_required_pattern(self) -> None:
        """Test REQUIRE_BEFORE with no required_pattern."""
        validator = SequenceValidator(include_defaults=False)
        rule = SequenceRule(
            name="incomplete",
            action=SequenceAction.REQUIRE_BEFORE,
            target_pattern="delete_*",
            # No required_pattern
        )
        validator.add_rule(rule)

        # Should be allowed (incomplete rule)
        allowed, _ = validator.validate_call("delete_file", "user_1")
        assert allowed

    def test_no_forbidden_pattern(self) -> None:
        """Test FORBID_AFTER with no forbidden_pattern."""
        validator = SequenceValidator(include_defaults=False)
        rule = SequenceRule(
            name="incomplete",
            action=SequenceAction.FORBID_AFTER,
            target_pattern="execute_*",
            # No forbidden_pattern
        )
        validator.add_rule(rule)

        # Should be allowed (incomplete rule)
        allowed, _ = validator.validate_call("execute_script", "user_1")
        assert allowed

    def test_no_sequence_patterns(self) -> None:
        """Test REQUIRE_SEQUENCE with empty sequence_patterns."""
        validator = SequenceValidator(include_defaults=False)
        rule = SequenceRule(
            name="incomplete",
            action=SequenceAction.REQUIRE_SEQUENCE,
            target_pattern="checkout_*",
            # No sequence_patterns
        )
        validator.add_rule(rule)

        # Should be allowed (incomplete rule)
        allowed, _ = validator.validate_call("checkout_payment", "user_1")
        assert allowed

    def test_multiple_rules_same_target(self) -> None:
        """Test multiple rules for same target pattern."""
        validator = SequenceValidator(include_defaults=False)

        validator.add_rule(SequenceRule(
            name="rule_1",
            action=SequenceAction.REQUIRE_BEFORE,
            target_pattern="delete_*",
            required_pattern="confirm_*",
        ))

        validator.add_rule(SequenceRule(
            name="rule_2",
            action=SequenceAction.COOLDOWN,
            target_pattern="delete_*",
            cooldown_seconds=60.0,
        ))

        # First rule should block (no confirm)
        allowed, violation = validator.validate_call("delete_file", "user_1")
        assert not allowed
        assert violation.rule_name == "rule_1"

    def test_validate_call_records_after_confirm(self) -> None:
        """Test that recording a call after successful validation works."""
        validator = SequenceValidator(include_defaults=False)
        validator.add_rule(SequenceRule(
            name="require_confirm",
            action=SequenceAction.REQUIRE_BEFORE,
            target_pattern="delete_*",
            required_pattern="confirm_*",
        ))

        # Confirm
        validator.record_call("confirm_action", "user_1")

        # Validate
        allowed, _ = validator.validate_call("delete_file", "user_1")
        assert allowed

        # Record the successful call
        validator.record_call("delete_file", "user_1")

        # Next delete should also work (confirm is still in history)
        allowed, _ = validator.validate_call("delete_database", "user_1")
        assert allowed
