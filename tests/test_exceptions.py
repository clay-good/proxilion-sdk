"""
Tests for structured exception context fields added in spec-v2 Step 5.

Covers all 7 enhanced exception classes:
  - RateLimitExceeded
  - CircuitOpenError
  - IDORViolationError
  - GuardViolation (and subclasses InputGuardViolation, OutputGuardViolation)
  - SequenceViolationError
  - BudgetExceededError
  - IntentHijackError
"""

import proxilion
from proxilion.exceptions import (
    BudgetExceededError,
    CircuitOpenError,
    GuardViolation,
    IDORViolationError,
    InputGuardViolation,
    IntentHijackError,
    OutputGuardViolation,
    ProxilionError,
    RateLimitExceeded,
    SequenceViolationError,
)

# ---------------------------------------------------------------------------
# RateLimitExceeded
# ---------------------------------------------------------------------------


class TestRateLimitExceeded:
    def test_default_construction(self) -> None:
        exc = RateLimitExceeded(limit_type="requests", limit_key="user_001")
        assert "requests" in str(exc)
        assert exc.user_id is None
        assert exc.limit is None
        assert exc.current_count is None
        assert exc.window_seconds is None
        assert exc.reset_at is None

    def test_message_only_construction(self) -> None:
        exc = RateLimitExceeded(limit_type="tokens", limit_key="user_002")
        assert exc.user_id is None
        assert exc.current_count is None

    def test_structured_fields(self) -> None:
        exc = RateLimitExceeded(
            limit_type="requests",
            limit_key="user_003",
            limit_value=100,
            retry_after=60.0,
            user_id="user_003",
            limit=100,
            current_count=101,
            window_seconds=60.0,
            reset_at=1700000000.0,
        )
        assert exc.user_id == "user_003"
        assert exc.limit == 100
        assert exc.current_count == 101
        assert exc.window_seconds == 60.0
        assert exc.reset_at == 1700000000.0

    def test_inheritance(self) -> None:
        exc = RateLimitExceeded(limit_type="requests", limit_key="user_004")
        assert isinstance(exc, ProxilionError)
        caught = False
        try:
            raise exc
        except ProxilionError:
            caught = True
        assert caught

    def test_str_representation(self) -> None:
        exc = RateLimitExceeded(limit_type="requests", limit_key="user_005")
        assert isinstance(str(exc), str)
        assert len(str(exc)) > 0

    def test_importable_from_proxilion(self) -> None:
        assert hasattr(proxilion, "RateLimitExceeded")

    def test_limit_falls_back_to_limit_value(self) -> None:
        exc = RateLimitExceeded(limit_type="requests", limit_key="u", limit_value=50)
        assert exc.limit == 50


# ---------------------------------------------------------------------------
# CircuitOpenError
# ---------------------------------------------------------------------------


class TestCircuitOpenError:
    def test_default_construction(self) -> None:
        exc = CircuitOpenError(circuit_name="my_circuit")
        assert exc.circuit_name == "my_circuit"
        assert exc.failure_count is None
        assert exc.reset_timeout is None

    def test_structured_fields(self) -> None:
        exc = CircuitOpenError(
            circuit_name="external_api",
            failure_count=5,
            reset_timeout=30.0,
            last_failure="Connection timeout",
        )
        assert exc.circuit_name == "external_api"
        assert exc.failure_count == 5
        assert exc.reset_timeout == 30.0
        assert exc.last_failure == "Connection timeout"

    def test_inheritance(self) -> None:
        exc = CircuitOpenError(circuit_name="test")
        assert isinstance(exc, ProxilionError)
        caught = False
        try:
            raise exc
        except ProxilionError:
            caught = True
        assert caught

    def test_str_representation(self) -> None:
        exc = CircuitOpenError(circuit_name="test_circuit")
        s = str(exc)
        assert "test_circuit" in s

    def test_importable_from_proxilion(self) -> None:
        assert hasattr(proxilion, "CircuitOpenError")


# ---------------------------------------------------------------------------
# IDORViolationError
# ---------------------------------------------------------------------------


class TestIDORViolationError:
    def test_construction(self) -> None:
        exc = IDORViolationError(
            user_id="user_001",
            resource_type="document",
            object_id="doc_456",
        )
        assert exc.user_id == "user_001"
        assert exc.resource_type == "document"
        assert exc.object_id == "doc_456"

    def test_resource_id_alias(self) -> None:
        exc = IDORViolationError(
            user_id="user_001",
            resource_type="document",
            object_id="doc_789",
        )
        assert exc.resource_id == exc.object_id

    def test_inheritance(self) -> None:
        exc = IDORViolationError(user_id="u", resource_type="r", object_id="o")
        assert isinstance(exc, ProxilionError)
        caught = False
        try:
            raise exc
        except ProxilionError:
            caught = True
        assert caught

    def test_str_representation(self) -> None:
        exc = IDORViolationError(user_id="user_001", resource_type="document", object_id="doc_001")
        s = str(exc)
        assert "user_001" in s
        assert "document" in s

    def test_importable_from_proxilion(self) -> None:
        assert hasattr(proxilion, "IDORViolationError")


# ---------------------------------------------------------------------------
# GuardViolation and subclasses
# ---------------------------------------------------------------------------


class TestGuardViolation:
    def test_construction(self) -> None:
        exc = GuardViolation(
            guard_type="input",
            matched_patterns=["instruction_override"],
            risk_score=0.95,
        )
        assert exc.guard_type == "input"
        assert exc.matched_patterns == ["instruction_override"]
        assert exc.risk_score == 0.95
        assert exc.input_preview is None

    def test_with_input_preview(self) -> None:
        exc = GuardViolation(
            guard_type="output",
            matched_patterns=["api_key"],
            risk_score=0.8,
            input_preview="The key is sk-abc...",
        )
        assert exc.input_preview == "The key is sk-abc..."

    def test_inheritance(self) -> None:
        exc = GuardViolation(guard_type="input", matched_patterns=[], risk_score=0.5)
        assert isinstance(exc, ProxilionError)

    def test_str_representation(self) -> None:
        exc = GuardViolation(guard_type="input", matched_patterns=["injection"], risk_score=0.9)
        s = str(exc)
        assert "input" in s.lower() or "guard" in s.lower()

    def test_importable_from_proxilion(self) -> None:
        assert hasattr(proxilion, "GuardViolation")


class TestInputGuardViolation:
    def test_construction(self) -> None:
        exc = InputGuardViolation(
            matched_patterns=["instruction_override", "role_switch"],
            risk_score=0.9,
            input_preview="Ignore previous...",
        )
        assert exc.guard_type == "input"
        assert exc.matched_patterns == ["instruction_override", "role_switch"]
        assert exc.risk_score == 0.9
        assert exc.input_preview == "Ignore previous..."

    def test_inherits_from_guard_violation(self) -> None:
        exc = InputGuardViolation(matched_patterns=[], risk_score=0.0)
        assert isinstance(exc, GuardViolation)
        assert isinstance(exc, ProxilionError)

    def test_structured_fields_accessible(self) -> None:
        exc = InputGuardViolation(
            matched_patterns=["pattern_a"],
            risk_score=0.7,
        )
        assert exc.guard_type == "input"
        assert exc.risk_score == 0.7
        assert exc.input_preview is None

    def test_importable_from_proxilion(self) -> None:
        assert hasattr(proxilion, "InputGuardViolation")


class TestOutputGuardViolation:
    def test_construction(self) -> None:
        exc = OutputGuardViolation(
            matched_patterns=["aws_key", "api_key_generic"],
            risk_score=0.95,
            input_preview="Key: AKIA...",
        )
        assert exc.guard_type == "output"
        assert exc.matched_patterns == ["aws_key", "api_key_generic"]
        assert exc.risk_score == 0.95

    def test_inherits_from_guard_violation(self) -> None:
        exc = OutputGuardViolation(matched_patterns=[], risk_score=0.0)
        assert isinstance(exc, GuardViolation)
        assert isinstance(exc, ProxilionError)

    def test_importable_from_proxilion(self) -> None:
        assert hasattr(proxilion, "OutputGuardViolation")


# ---------------------------------------------------------------------------
# SequenceViolationError
# ---------------------------------------------------------------------------


class TestSequenceViolationError:
    def test_default_construction(self) -> None:
        exc = SequenceViolationError(
            rule_name="require_confirm_before_delete",
            tool_name="delete_file",
        )
        assert exc.rule_name == "require_confirm_before_delete"
        assert exc.tool_name == "delete_file"
        assert exc.user_id is None

    def test_structured_fields(self) -> None:
        exc = SequenceViolationError(
            rule_name="forbid_execute_after_download",
            tool_name="execute_script",
            forbidden_prior="download_file",
            user_id="user_123",
        )
        assert exc.rule_name == "forbid_execute_after_download"
        assert exc.tool_name == "execute_script"
        assert exc.user_id == "user_123"

    def test_inheritance(self) -> None:
        exc = SequenceViolationError(rule_name="r", tool_name="t")
        assert isinstance(exc, ProxilionError)
        caught = False
        try:
            raise exc
        except ProxilionError:
            caught = True
        assert caught

    def test_str_representation(self) -> None:
        exc = SequenceViolationError(rule_name="my_rule", tool_name="my_tool")
        s = str(exc)
        assert "my_rule" in s

    def test_importable_from_proxilion(self) -> None:
        assert hasattr(proxilion, "SequenceViolationError")


# ---------------------------------------------------------------------------
# BudgetExceededError
# ---------------------------------------------------------------------------


class TestBudgetExceededError:
    def test_construction(self) -> None:
        exc = BudgetExceededError(
            limit_type="user_daily",
            current_spend=48.50,
            limit=50.0,
        )
        assert exc.limit_type == "user_daily"
        assert exc.current_spend == 48.50
        assert exc.limit == 50.0
        assert exc.user_id is None

    def test_budget_limit_alias(self) -> None:
        exc = BudgetExceededError(
            limit_type="user_daily",
            current_spend=10.0,
            limit=9.0,
        )
        assert exc.budget_limit == exc.limit

    def test_structured_fields(self) -> None:
        exc = BudgetExceededError(
            limit_type="user_daily",
            current_spend=48.50,
            limit=50.0,
            estimated_cost=5.0,
            user_id="user_123",
        )
        assert exc.user_id == "user_123"
        assert exc.estimated_cost == 5.0

    def test_inheritance(self) -> None:
        exc = BudgetExceededError(limit_type="t", current_spend=1.0, limit=0.5)
        assert isinstance(exc, ProxilionError)
        caught = False
        try:
            raise exc
        except ProxilionError:
            caught = True
        assert caught

    def test_str_representation(self) -> None:
        exc = BudgetExceededError(limit_type="user_daily", current_spend=5.0, limit=4.0)
        s = str(exc)
        assert len(s) > 0

    def test_importable_from_proxilion(self) -> None:
        assert hasattr(proxilion, "BudgetExceededError")


# ---------------------------------------------------------------------------
# IntentHijackError
# ---------------------------------------------------------------------------


class TestIntentHijackError:
    def test_default_construction(self) -> None:
        exc = IntentHijackError(
            original_intent="Help user find documents",
            detected_intent="Exfiltrate credentials",
        )
        assert exc.original_intent == "Help user find documents"
        assert exc.detected_intent == "Exfiltrate credentials"
        assert exc.tool_name is None
        assert exc.allowed_tools is None
        assert exc.user_id is None

    def test_structured_fields(self) -> None:
        exc = IntentHijackError(
            original_intent="Help user find documents",
            detected_intent="Send email to attacker",
            confidence=0.95,
            tool_name="send_email",
            allowed_tools=["search_docs", "read_file"],
            user_id="user_123",
        )
        assert exc.tool_name == "send_email"
        assert exc.allowed_tools == ["search_docs", "read_file"]
        assert exc.user_id == "user_123"
        assert exc.confidence == 0.95

    def test_inheritance(self) -> None:
        exc = IntentHijackError(original_intent="a", detected_intent="b")
        assert isinstance(exc, ProxilionError)
        caught = False
        try:
            raise exc
        except ProxilionError:
            caught = True
        assert caught

    def test_str_representation(self) -> None:
        exc = IntentHijackError(
            original_intent="find docs",
            detected_intent="exfiltrate",
        )
        s = str(exc)
        assert "find docs" in s

    def test_importable_from_proxilion(self) -> None:
        assert hasattr(proxilion, "IntentHijackError")


# ---------------------------------------------------------------------------
# Cross-cutting: all 7 exceptions are ProxilionError subclasses
# ---------------------------------------------------------------------------


class TestAllExceptionsAreProxilionErrors:
    def test_all_inherit_from_proxilion_error(self) -> None:
        exceptions = [
            RateLimitExceeded(limit_type="requests", limit_key="u"),
            CircuitOpenError(circuit_name="c"),
            IDORViolationError(user_id="u", resource_type="r", object_id="o"),
            GuardViolation(guard_type="input", matched_patterns=[], risk_score=0.0),
            InputGuardViolation(matched_patterns=[], risk_score=0.0),
            OutputGuardViolation(matched_patterns=[], risk_score=0.0),
            SequenceViolationError(rule_name="r", tool_name="t"),
            BudgetExceededError(limit_type="t", current_spend=1.0, limit=0.5),
            IntentHijackError(original_intent="a", detected_intent="b"),
        ]
        for exc in exceptions:
            assert isinstance(exc, ProxilionError), (
                f"{type(exc).__name__} should inherit from ProxilionError"
            )

    def test_all_have_str_representation(self) -> None:
        exceptions = [
            RateLimitExceeded(limit_type="requests", limit_key="u"),
            CircuitOpenError(circuit_name="c"),
            IDORViolationError(user_id="u", resource_type="r", object_id="o"),
            GuardViolation(guard_type="input", matched_patterns=[], risk_score=0.0),
            InputGuardViolation(matched_patterns=[], risk_score=0.0),
            OutputGuardViolation(matched_patterns=[], risk_score=0.0),
            SequenceViolationError(rule_name="r", tool_name="t"),
            BudgetExceededError(limit_type="t", current_spend=1.0, limit=0.5),
            IntentHijackError(original_intent="a", detected_intent="b"),
        ]
        for exc in exceptions:
            s = str(exc)
            assert isinstance(s, str) and len(s) > 0, (
                f"{type(exc).__name__} str() should return non-empty string"
            )
