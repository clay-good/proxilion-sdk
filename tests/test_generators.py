"""
Tests for the deterministic sample data generators.

Verifies that generators produce consistent output with the same seed,
respect configuration parameters, and return valid data structures.
"""

from __future__ import annotations

import pytest

from tests.fixtures.generators import (
    generate_audit_event_stream,
    generate_provider_response_batch,
    generate_tool_call_sequence,
    generate_user_population,
)


class TestGenerateUserPopulation:
    """Tests for generate_user_population."""

    def test_returns_correct_count(self) -> None:
        """Verify the correct number of users is generated."""
        users = generate_user_population(count=50, seed=42)
        assert len(users) == 50

    def test_deterministic_with_same_seed(self) -> None:
        """Verify same seed produces identical output."""
        users1 = generate_user_population(count=10, seed=123)
        users2 = generate_user_population(count=10, seed=123)

        for u1, u2 in zip(users1, users2, strict=True):
            assert u1.user_id == u2.user_id
            assert u1.roles == u2.roles
            assert u1.session_id == u2.session_id
            assert u1.attributes == u2.attributes

    def test_different_seeds_produce_different_output(self) -> None:
        """Verify different seeds produce different output."""
        users1 = generate_user_population(count=10, seed=42)
        users2 = generate_user_population(count=10, seed=99)

        # At least some users should differ (roles or attributes)
        differences = sum(
            1
            for u1, u2 in zip(users1, users2, strict=True)
            if u1.roles != u2.roles or u1.attributes != u2.attributes
        )
        assert differences > 0

    def test_user_ids_are_sequential(self) -> None:
        """Verify user IDs follow the expected format."""
        users = generate_user_population(count=5, seed=42)
        expected_ids = ["user_001", "user_002", "user_003", "user_004", "user_005"]
        actual_ids = [u.user_id for u in users]
        assert actual_ids == expected_ids

    def test_role_distribution_is_reasonable(self) -> None:
        """Verify role distribution roughly matches expected percentages."""
        # Use large count for statistical stability
        users = generate_user_population(count=1000, seed=42)

        viewer_only = sum(1 for u in users if u.roles == ["viewer"])
        editor = sum(1 for u in users if "editor" in u.roles and "admin" not in u.roles)
        admin = sum(1 for u in users if "admin" in u.roles)
        guest = sum(1 for u in users if u.roles == ["guest"])

        # Allow ±10% variance from expected distribution
        assert 500 <= viewer_only <= 700, f"viewer_only={viewer_only}"
        assert 150 <= editor <= 350, f"editor={editor}"
        assert 50 <= admin <= 150, f"admin={admin}"
        assert 20 <= guest <= 80, f"guest={guest}"

    def test_all_users_have_required_fields(self) -> None:
        """Verify all users have required fields populated."""
        users = generate_user_population(count=20, seed=42)

        for user in users:
            assert user.user_id
            assert isinstance(user.roles, list)
            assert len(user.roles) > 0
            assert user.session_id is not None
            assert "department" in user.attributes
            assert "region" in user.attributes


class TestGenerateToolCallSequence:
    """Tests for generate_tool_call_sequence."""

    def test_returns_correct_count(self) -> None:
        """Verify the correct number of tool calls is generated."""
        calls = generate_tool_call_sequence(count=75, seed=42)
        assert len(calls) == 75

    def test_deterministic_with_same_seed(self) -> None:
        """Verify same seed produces identical output."""
        calls1 = generate_tool_call_sequence(count=20, seed=456)
        calls2 = generate_tool_call_sequence(count=20, seed=456)

        for c1, c2 in zip(calls1, calls2, strict=True):
            assert c1.tool_name == c2.tool_name
            assert c1.arguments == c2.arguments
            assert c1.timestamp == c2.timestamp

    def test_attack_ratio_zero_produces_no_attacks(self) -> None:
        """Verify attack_ratio=0 produces only safe calls."""
        calls = generate_tool_call_sequence(count=100, seed=42, attack_ratio=0.0)

        attack_keywords = [
            "OR '1'='1'",
            "../",
            "rm -rf",
            "ignore previous",
            "<script>",
            "DROP TABLE",
        ]

        for call in calls:
            args_str = str(call.arguments).lower()
            for keyword in attack_keywords:
                assert keyword.lower() not in args_str, "Found attack pattern in safe sequence"

    def test_attack_ratio_one_produces_all_attacks(self) -> None:
        """Verify attack_ratio=1 produces only attack calls."""
        calls = generate_tool_call_sequence(count=50, seed=42, attack_ratio=1.0)

        # Attack tools include read_document (IDOR attempt)
        attack_tool_names = {
            "database_query",
            "read_file",
            "system_command",
            "search",
            "create_note",
            "read_document",
        }

        for call in calls:
            assert call.tool_name in attack_tool_names

    def test_attack_ratio_respected(self) -> None:
        """Verify attack_ratio roughly controls the proportion of attacks."""
        calls = generate_tool_call_sequence(count=1000, seed=42, attack_ratio=0.10)

        # Count calls with obvious attack patterns
        attack_patterns = ["OR '1'='1'", "../", "rm -rf", "ignore previous", "<script>"]
        attack_count = 0
        for call in calls:
            args_str = str(call.arguments)
            if any(pattern in args_str for pattern in attack_patterns):
                attack_count += 1

        # Allow ±5% variance
        assert 50 <= attack_count <= 150, f"attack_count={attack_count}"

    def test_all_calls_have_valid_timestamps(self) -> None:
        """Verify all calls have valid timestamps."""
        calls = generate_tool_call_sequence(count=20, seed=42)

        for call in calls:
            assert call.timestamp is not None
            assert call.timestamp.tzinfo is not None


class TestGenerateAuditEventStream:
    """Tests for generate_audit_event_stream."""

    def test_returns_correct_count(self) -> None:
        """Verify the correct number of events is generated."""
        events = generate_audit_event_stream(count=200, seed=42)
        assert len(events) == 200

    def test_deterministic_with_same_seed(self) -> None:
        """Verify same seed produces identical output."""
        events1 = generate_audit_event_stream(count=30, seed=789)
        events2 = generate_audit_event_stream(count=30, seed=789)

        for e1, e2 in zip(events1, events2, strict=True):
            assert e1 == e2

    def test_events_have_required_fields(self) -> None:
        """Verify all events have required fields."""
        events = generate_audit_event_stream(count=50, seed=42)

        required_fields = {
            "event_type",
            "user_id",
            "tool_name",
            "allowed",
            "timestamp",
            "sequence_number",
        }

        for event in events:
            assert required_fields.issubset(event.keys())
            assert event["event_type"] == "tool_call"
            assert isinstance(event["allowed"], bool)
            assert isinstance(event["sequence_number"], int)

    def test_allowed_denied_distribution(self) -> None:
        """Verify allowed/denied ratio roughly matches 85%/15%."""
        events = generate_audit_event_stream(count=1000, seed=42)

        allowed_count = sum(1 for e in events if e["allowed"])
        denied_count = len(events) - allowed_count

        # Allow ±5% variance
        assert 800 <= allowed_count <= 900, f"allowed_count={allowed_count}"
        assert 100 <= denied_count <= 200, f"denied_count={denied_count}"

    def test_denied_events_have_reason(self) -> None:
        """Verify denied events include a reason."""
        events = generate_audit_event_stream(count=100, seed=42)

        for event in events:
            if not event["allowed"]:
                assert event["reason"] is not None
                assert len(event["reason"]) > 0

    def test_sequence_numbers_are_sequential(self) -> None:
        """Verify sequence numbers are sequential starting from 1."""
        events = generate_audit_event_stream(count=10, seed=42)
        sequence_numbers = [e["sequence_number"] for e in events]
        assert sequence_numbers == list(range(1, 11))


class TestGenerateProviderResponseBatch:
    """Tests for generate_provider_response_batch."""

    def test_returns_correct_count(self) -> None:
        """Verify the correct number of responses is generated."""
        for provider in ["openai", "anthropic", "gemini"]:
            responses = generate_provider_response_batch(provider, count=15, seed=42)
            assert len(responses) == 15

    def test_deterministic_with_same_seed(self) -> None:
        """Verify same seed produces identical output."""
        responses1 = generate_provider_response_batch("openai", count=5, seed=321)
        responses2 = generate_provider_response_batch("openai", count=5, seed=321)

        assert responses1 == responses2

    def test_invalid_provider_raises_error(self) -> None:
        """Verify invalid provider raises ValueError."""
        with pytest.raises(ValueError, match="Unknown provider"):
            generate_provider_response_batch("invalid_provider", count=5, seed=42)

    def test_openai_response_structure(self) -> None:
        """Verify OpenAI responses have correct structure."""
        responses = generate_provider_response_batch("openai", count=5, seed=42)

        for response in responses:
            assert "id" in response
            assert "object" in response
            assert response["object"] == "chat.completion"
            assert "choices" in response
            assert len(response["choices"]) > 0
            assert "message" in response["choices"][0]
            assert "usage" in response

    def test_anthropic_response_structure(self) -> None:
        """Verify Anthropic responses have correct structure."""
        responses = generate_provider_response_batch("anthropic", count=5, seed=42)

        for response in responses:
            assert "id" in response
            assert "type" in response
            assert response["type"] == "message"
            assert "content" in response
            assert "role" in response
            assert response["role"] == "assistant"
            assert "usage" in response

    def test_gemini_response_structure(self) -> None:
        """Verify Gemini responses have correct structure."""
        responses = generate_provider_response_batch("gemini", count=5, seed=42)

        for response in responses:
            assert "candidates" in response
            assert len(response["candidates"]) > 0
            assert "content" in response["candidates"][0]
            assert "usageMetadata" in response

    def test_some_responses_have_tool_calls(self) -> None:
        """Verify some responses include tool calls (approximately 70%)."""
        # Test with large count for statistical stability
        responses = generate_provider_response_batch("openai", count=100, seed=42)

        with_tool_calls = sum(
            1 for r in responses if r["choices"][0]["message"].get("tool_calls") is not None
        )

        # Allow ±15% variance from 70%
        assert 55 <= with_tool_calls <= 85, f"with_tool_calls={with_tool_calls}"
