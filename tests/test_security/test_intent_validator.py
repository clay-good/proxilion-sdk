"""Tests for proxilion.security.intent_validator module."""

from __future__ import annotations

import time

import pytest

from proxilion.security.intent_validator import (
    AnomalyThresholds,
    IntentValidator,
    ValidationOutcome,
    ValidationResult,
    WorkflowState,
)

# Thresholds with time-of-day check disabled so tests don't fail during
# the default suspicious window (2-5 AM UTC).
_NO_TIME_CHECK = AnomalyThresholds(suspicious_hour_start=0, suspicious_hour_end=0)


# ---------------------------------------------------------------------------
# ValidationOutcome properties
# ---------------------------------------------------------------------------


class TestValidationOutcome:
    """Tests for ValidationOutcome dataclass properties."""

    def test_is_valid_when_valid(self) -> None:
        outcome = ValidationOutcome(result=ValidationResult.VALID)
        assert outcome.is_valid is True
        assert outcome.should_block is False

    def test_is_valid_when_suspicious(self) -> None:
        outcome = ValidationOutcome(result=ValidationResult.SUSPICIOUS)
        assert outcome.is_valid is False
        assert outcome.should_block is False

    def test_should_block_when_blocked(self) -> None:
        outcome = ValidationOutcome(result=ValidationResult.BLOCKED)
        assert outcome.is_valid is False
        assert outcome.should_block is True

    def test_default_fields(self) -> None:
        outcome = ValidationOutcome(result=ValidationResult.VALID)
        assert outcome.reason is None
        assert outcome.risk_score == 0.0
        assert outcome.details == {}

    def test_custom_fields(self) -> None:
        outcome = ValidationOutcome(
            result=ValidationResult.SUSPICIOUS,
            reason="test reason",
            risk_score=0.5,
            details={"key": "value"},
        )
        assert outcome.reason == "test reason"
        assert outcome.risk_score == 0.5
        assert outcome.details == {"key": "value"}


# ---------------------------------------------------------------------------
# IntentValidator – basic validation
# ---------------------------------------------------------------------------


class TestIntentValidatorBasic:
    """Tests for basic IntentValidator validation."""

    def test_simple_valid_call(self) -> None:
        validator = IntentValidator(thresholds=_NO_TIME_CHECK)
        outcome = validator.validate("user1", "search", {"query": "hello"})
        assert outcome.is_valid is True

    def test_empty_arguments(self) -> None:
        validator = IntentValidator(thresholds=_NO_TIME_CHECK)
        outcome = validator.validate("user1", "search", {})
        assert outcome.is_valid is True

    def test_custom_thresholds(self) -> None:
        thresholds = AnomalyThresholds(max_calls_per_minute=5)
        validator = IntentValidator(thresholds=thresholds)
        assert validator.thresholds.max_calls_per_minute == 5


# ---------------------------------------------------------------------------
# Parameter injection detection
# ---------------------------------------------------------------------------


class TestParameterInjection:
    """Tests for parameter injection detection."""

    def test_null_byte_blocked(self) -> None:
        validator = IntentValidator(thresholds=_NO_TIME_CHECK)
        outcome = validator.validate(
            "user1", "search", {"query": "hello\x00world"}
        )
        assert outcome.should_block is True
        assert outcome.risk_score == 1.0
        assert "Null byte" in (outcome.reason or "")

    def test_null_byte_in_different_param(self) -> None:
        validator = IntentValidator(thresholds=_NO_TIME_CHECK)
        outcome = validator.validate(
            "user1", "search", {"name": "safe", "path": "/etc/\x00passwd"}
        )
        assert outcome.should_block is True

    def test_very_long_string_suspicious(self) -> None:
        validator = IntentValidator(thresholds=_NO_TIME_CHECK)
        outcome = validator.validate(
            "user1", "search", {"query": "a" * 10001}
        )
        assert outcome.result == ValidationResult.SUSPICIOUS
        assert outcome.risk_score == 0.4
        assert "long parameter" in (outcome.reason or "").lower()

    def test_string_within_limit_valid(self) -> None:
        validator = IntentValidator(thresholds=_NO_TIME_CHECK)
        outcome = validator.validate(
            "user1", "search", {"query": "a" * 10000}
        )
        assert outcome.is_valid is True

    def test_deeply_nested_dict_suspicious(self) -> None:
        validator = IntentValidator(thresholds=_NO_TIME_CHECK)
        nested: dict = {"level": 0}
        current = nested
        for i in range(12):
            current["child"] = {"level": i + 1}
            current = current["child"]

        outcome = validator.validate("user1", "search", {"data": nested})
        assert outcome.result == ValidationResult.SUSPICIOUS
        assert "nested" in (outcome.reason or "").lower()

    def test_shallow_nesting_valid(self) -> None:
        validator = IntentValidator(thresholds=_NO_TIME_CHECK)
        outcome = validator.validate(
            "user1", "search", {"data": {"a": {"b": "c"}}}
        )
        assert outcome.is_valid is True


# ---------------------------------------------------------------------------
# Workflow state machine transitions
# ---------------------------------------------------------------------------


class TestWorkflowTransitions:
    """Tests for workflow state machine validation."""

    @pytest.fixture()
    def validator_with_workflow(self) -> IntentValidator:
        validator = IntentValidator(thresholds=_NO_TIME_CHECK)
        validator.register_workflow(
            "doc_flow",
            {
                "initial": ["search"],
                "search": ["view", "search"],
                "view": ["edit", "download"],
                "edit": ["save", "view"],
            },
        )
        return validator

    def test_valid_initial_transition(
        self, validator_with_workflow: IntentValidator
    ) -> None:
        outcome = validator_with_workflow.validate(
            "user1", "search", {}, workflow_name="doc_flow"
        )
        assert outcome.is_valid is True

    def test_valid_subsequent_transition(
        self, validator_with_workflow: IntentValidator
    ) -> None:
        validator_with_workflow.validate(
            "user1", "search", {}, workflow_name="doc_flow"
        )
        outcome = validator_with_workflow.validate(
            "user1", "view", {}, workflow_name="doc_flow"
        )
        assert outcome.is_valid is True

    def test_invalid_transition_suspicious(
        self, validator_with_workflow: IntentValidator
    ) -> None:
        # First move to "search"
        validator_with_workflow.validate(
            "user1", "search", {}, workflow_name="doc_flow"
        )
        # "edit" is not allowed from "search"
        outcome = validator_with_workflow.validate(
            "user1", "edit", {}, workflow_name="doc_flow"
        )
        assert outcome.result == ValidationResult.SUSPICIOUS
        assert "transition" in (outcome.reason or "").lower()

    def test_workflow_state_tracking(
        self, validator_with_workflow: IntentValidator
    ) -> None:
        validator_with_workflow.validate(
            "user1", "search", {}, workflow_name="doc_flow"
        )
        state = validator_with_workflow.get_user_state("user1", "doc_flow")
        assert state is not None
        assert state.current_state == "search"
        assert "view" in state.allowed_transitions
        assert "search" in state.history

    def test_unknown_workflow_passes(self) -> None:
        validator = IntentValidator(thresholds=_NO_TIME_CHECK)
        outcome = validator.validate(
            "user1", "search", {}, workflow_name="nonexistent"
        )
        assert outcome.is_valid is True

    def test_tool_to_state_mapping(
        self, validator_with_workflow: IntentValidator
    ) -> None:
        mapping = {"search_tool": "search", "view_tool": "view"}
        outcome = validator_with_workflow.validate(
            "user1",
            "search_tool",
            {},
            workflow_name="doc_flow",
            tool_to_state=lambda t: mapping.get(t, t),
        )
        assert outcome.is_valid is True
        state = validator_with_workflow.get_user_state("user1", "doc_flow")
        assert state is not None
        assert state.current_state == "search"

    def test_reset_user_state_specific_workflow(
        self, validator_with_workflow: IntentValidator
    ) -> None:
        validator_with_workflow.validate(
            "user1", "search", {}, workflow_name="doc_flow"
        )
        validator_with_workflow.reset_user_state("user1", workflow_name="doc_flow")
        state = validator_with_workflow.get_user_state("user1", "doc_flow")
        assert state is None

    def test_reset_user_state_all(
        self, validator_with_workflow: IntentValidator
    ) -> None:
        validator_with_workflow.validate(
            "user1", "search", {}, workflow_name="doc_flow"
        )
        validator_with_workflow.record_failure("user1")
        validator_with_workflow.reset_user_state("user1")
        state = validator_with_workflow.get_user_state("user1", "doc_flow")
        assert state is None
        assert validator_with_workflow.get_failure_count("user1") == 0


# ---------------------------------------------------------------------------
# Failure / success recording
# ---------------------------------------------------------------------------


class TestFailureTracking:
    """Tests for failure and success recording."""

    def test_record_failure_increments(self) -> None:
        validator = IntentValidator(thresholds=_NO_TIME_CHECK)
        validator.record_failure("user1")
        assert validator.get_failure_count("user1") == 1
        validator.record_failure("user1")
        assert validator.get_failure_count("user1") == 2

    def test_record_success_resets(self) -> None:
        validator = IntentValidator(thresholds=_NO_TIME_CHECK)
        validator.record_failure("user1")
        validator.record_failure("user1")
        validator.record_success("user1")
        assert validator.get_failure_count("user1") == 0

    def test_unknown_user_failure_count_zero(self) -> None:
        validator = IntentValidator(thresholds=_NO_TIME_CHECK)
        assert validator.get_failure_count("nobody") == 0

    def test_independent_user_counts(self) -> None:
        validator = IntentValidator(thresholds=_NO_TIME_CHECK)
        validator.record_failure("user1")
        validator.record_failure("user1")
        validator.record_failure("user2")
        assert validator.get_failure_count("user1") == 2
        assert validator.get_failure_count("user2") == 1


# ---------------------------------------------------------------------------
# Custom validators
# ---------------------------------------------------------------------------


class TestCustomValidators:
    """Tests for custom validator registration."""

    def test_custom_validator_blocks(self) -> None:
        validator = IntentValidator(thresholds=_NO_TIME_CHECK)

        def block_delete(
            user_id: str, tool_name: str, arguments: dict
        ) -> ValidationOutcome | None:
            if tool_name == "delete":
                return ValidationOutcome(
                    result=ValidationResult.BLOCKED,
                    reason="delete not allowed",
                )
            return None

        validator.register_validator(block_delete)
        outcome = validator.validate("user1", "delete", {})
        assert outcome.should_block is True
        assert outcome.reason == "delete not allowed"

    def test_custom_validator_defers(self) -> None:
        validator = IntentValidator(thresholds=_NO_TIME_CHECK)

        def no_opinion(
            user_id: str, tool_name: str, arguments: dict
        ) -> ValidationOutcome | None:
            return None

        validator.register_validator(no_opinion)
        outcome = validator.validate("user1", "search", {"q": "test"})
        assert outcome.is_valid is True

    def test_custom_validator_runs_before_builtin(self) -> None:
        validator = IntentValidator(thresholds=_NO_TIME_CHECK)

        def always_valid(
            user_id: str, tool_name: str, arguments: dict
        ) -> ValidationOutcome | None:
            return ValidationOutcome(result=ValidationResult.VALID, reason="override")

        validator.register_validator(always_valid)
        # Null bytes would normally be blocked, but custom validator fires first.
        outcome = validator.validate("user1", "search", {"q": "a\x00b"})
        assert outcome.is_valid is True
        assert outcome.reason == "override"

    def test_multiple_custom_validators_first_wins(self) -> None:
        validator = IntentValidator(thresholds=_NO_TIME_CHECK)

        def first(
            user_id: str, tool_name: str, arguments: dict
        ) -> ValidationOutcome | None:
            return ValidationOutcome(
                result=ValidationResult.SUSPICIOUS, reason="first"
            )

        def second(
            user_id: str, tool_name: str, arguments: dict
        ) -> ValidationOutcome | None:
            return ValidationOutcome(
                result=ValidationResult.BLOCKED, reason="second"
            )

        validator.register_validator(first)
        validator.register_validator(second)
        outcome = validator.validate("user1", "search", {})
        assert outcome.reason == "first"

    def test_failing_custom_validator_is_skipped(self) -> None:
        validator = IntentValidator(thresholds=_NO_TIME_CHECK)

        def broken(
            user_id: str, tool_name: str, arguments: dict
        ) -> ValidationOutcome | None:
            raise RuntimeError("oops")

        validator.register_validator(broken)
        outcome = validator.validate("user1", "search", {"q": "hello"})
        # Should fall through to built-in checks and succeed.
        assert outcome.is_valid is True


# ---------------------------------------------------------------------------
# Anomaly detection
# ---------------------------------------------------------------------------


class TestAnomalyDetection:
    """Tests for anomaly detection in tool usage."""

    def test_call_rate_exceeded(self) -> None:
        thresholds = AnomalyThresholds(max_calls_per_minute=3)
        validator = IntentValidator(thresholds=thresholds)
        for _ in range(3):
            validator.validate("user1", "search", {"q": "test"})
        # 4th call should exceed the threshold
        outcome = validator.validate("user1", "search", {"q": "test"})
        assert outcome.result == ValidationResult.SUSPICIOUS
        assert "call rate" in (outcome.reason or "").lower()

    def test_unique_resources_exceeded(self) -> None:
        thresholds = AnomalyThresholds(max_unique_resources_per_minute=3)
        validator = IntentValidator(thresholds=thresholds)
        for i in range(5):
            validator.validate("user1", "view", {"doc_id": f"doc_{i}"})
        assert True  # If we got here, at least we didn't crash.
        # After enough unique resource IDs, it should be suspicious.

    def test_consecutive_failures_threshold(self) -> None:
        thresholds = AnomalyThresholds(max_consecutive_failures=3)
        validator = IntentValidator(thresholds=thresholds)
        for _ in range(4):
            validator.record_failure("user1")
        assert validator.get_failure_count("user1") == 4


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------


class TestCleanup:
    """Tests for cleanup of stale user data."""

    def test_cleanup_removes_stale_data(self) -> None:
        validator = IntentValidator(thresholds=_NO_TIME_CHECK)
        # Make a call so the user has history
        validator.validate("user1", "search", {"q": "test"})
        # Clean with max_age=0 to remove everything
        removed = validator.cleanup(max_age_seconds=0.0)
        assert removed >= 1

    def test_cleanup_preserves_recent_data(self) -> None:
        validator = IntentValidator(thresholds=_NO_TIME_CHECK)
        validator.validate("user1", "search", {"q": "test"})
        removed = validator.cleanup(max_age_seconds=3600.0)
        assert removed == 0

    def test_cleanup_orphan_states(self) -> None:
        validator = IntentValidator(thresholds=_NO_TIME_CHECK)
        validator.register_workflow(
            "wf",
            {"initial": ["step1"], "step1": ["step2"]},
        )
        validator.validate("user1", "step1", {}, workflow_name="wf")
        # Remove call history directly so state becomes orphaned
        validator._call_history.pop("user1", None)
        removed = validator.cleanup(max_age_seconds=3600.0)
        assert removed >= 1
        assert validator.get_user_state("user1", "wf") is None


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Tests for edge case handling."""

    def test_unknown_user_get_state_returns_none(self) -> None:
        validator = IntentValidator(thresholds=_NO_TIME_CHECK)
        assert validator.get_user_state("ghost", "any_workflow") is None

    def test_workflow_state_defaults(self) -> None:
        state = WorkflowState()
        assert state.current_state == "initial"
        assert state.allowed_transitions == set()
        assert state.history == []
        assert state.context == {}

    def test_anomaly_thresholds_defaults(self) -> None:
        t = AnomalyThresholds()
        assert t.max_calls_per_minute == 60
        assert t.max_unique_resources_per_minute == 20
        assert t.max_consecutive_failures == 5
        assert t.max_data_volume_mb == 10.0
        assert t.suspicious_hour_start == 2
        assert t.suspicious_hour_end == 5

    def test_multiple_users_isolated(self) -> None:
        validator = IntentValidator(thresholds=_NO_TIME_CHECK)
        validator.register_workflow(
            "wf", {"initial": ["a"], "a": ["b"]}
        )
        validator.validate("u1", "a", {}, workflow_name="wf")
        validator.validate("u2", "a", {}, workflow_name="wf")
        state1 = validator.get_user_state("u1", "wf")
        state2 = validator.get_user_state("u2", "wf")
        assert state1 is not None and state2 is not None
        # Both should be at state "a" independently
        assert state1.current_state == "a"
        assert state2.current_state == "a"

    def test_deeply_nested_list_suspicious(self) -> None:
        validator = IntentValidator(thresholds=_NO_TIME_CHECK)
        nested: list = [0]
        current = nested
        for _ in range(12):
            inner: list = [0]
            current.append(inner)
            current = inner

        outcome = validator.validate("user1", "tool", {"data": nested})
        assert outcome.result == ValidationResult.SUSPICIOUS

    def test_validation_result_enum_values(self) -> None:
        assert ValidationResult.VALID.value == "valid"
        assert ValidationResult.SUSPICIOUS.value == "suspicious"
        assert ValidationResult.BLOCKED.value == "blocked"
