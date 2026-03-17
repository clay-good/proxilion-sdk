"""Tests for base_exporters and explainability audit modules."""

from __future__ import annotations

import io
import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from proxilion.audit.base_exporters import (
    CallbackExporter,
    ConsoleExporter,
    FileExporter,
    MultiExporter,
    StreamExporter,
    read_jsonl_events,
    verify_jsonl_chain,
)
from proxilion.audit.events import AuditEventData, AuditEventV2, EventType
from proxilion.audit.explainability import (
    DecisionExplainer,
    DecisionFactor,
    DecisionType,
    ExplainabilityLogger,
    ExplainableDecision,
    Explanation,
    ExplanationFormat,
    Outcome,
    create_authorization_decision,
    create_budget_decision,
    create_guard_decision,
    create_rate_limit_decision,
)
from proxilion.audit.hash_chain import GENESIS_HASH, HashChain, MerkleBatch


def _make_event(tool="search", allowed=True, prev=GENESIS_HASH, long_args=False) -> AuditEventV2:
    args = {"query": "x" * 200} if long_args else {"query": "test", "limit": 10}
    data = AuditEventData(
        event_type=EventType.AUTHORIZATION_GRANTED if allowed else EventType.AUTHORIZATION_DENIED,
        user_id="user_123",
        user_roles=["user"],
        session_id="sess_abc",
        user_attributes={"dept": "eng"},
        agent_id=None,
        agent_capabilities=[],
        agent_trust_score=None,
        tool_name=tool,
        tool_arguments=args,
        tool_timestamp=datetime.now(timezone.utc),
        authorization_allowed=allowed,
        authorization_reason="Policy allowed" if allowed else "Denied",
        policies_evaluated=["TestPolicy"],
        authorization_metadata={},
    )
    ev = AuditEventV2(data=data, previous_hash=prev)
    ev.compute_hash()
    return ev


def _make_batch() -> MerkleBatch:
    return MerkleBatch(
        batch_id="batch_1",
        start_sequence=0,
        end_sequence=9,
        event_count=10,
        merkle_root="sha256:abcdef1234567890abcdef1234567890abcdef1234567890",
        created_at=datetime.now(timezone.utc).isoformat(),
    )


def _make_chain(n=3) -> tuple[HashChain, list[AuditEventV2]]:
    chain = HashChain()
    events = []
    for i in range(n):
        ev = AuditEventV2(
            data=AuditEventData(
                event_type=EventType.AUTHORIZATION_GRANTED,
                user_id=f"u{i}",
                user_roles=["user"],
                session_id=f"s{i}",
                user_attributes={},
                agent_id=None,
                agent_capabilities=[],
                agent_trust_score=None,
                tool_name=f"tool_{i}",
                tool_arguments={"i": i},
                tool_timestamp=datetime.now(timezone.utc),
                authorization_allowed=True,
                authorization_reason="OK",
                policies_evaluated=[],
                authorization_metadata={},
            ),
            previous_hash=chain.last_hash,
        )
        events.append(chain.append(ev))
    return chain, events


def _decision(
    dt=DecisionType.AUTHORIZATION, outcome=Outcome.ALLOWED, factors=None, context=None, **kw
) -> ExplainableDecision:
    return ExplainableDecision(
        decision_type=dt,
        outcome=outcome,
        factors=factors or [],
        context=context or {},
        **kw,
    )


class TestBaseExporters:
    def test_file_exporter_write_and_append(self, tmp_path: Path):
        path = tmp_path / "audit.jsonl"
        ev = _make_event()
        with FileExporter(path, append=False) as exp:
            exp.export_event(ev)
        assert json.loads(path.read_text().strip())["event_id"] == ev.event_id
        path.write_text('{"existing": true}\n')
        with FileExporter(path, append=True) as exp:
            exp.export_event(ev)
        assert len(path.read_text().strip().split("\n")) == 2

    def test_file_exporter_overwrite(self, tmp_path: Path):
        path = tmp_path / "audit.jsonl"
        path.write_text('{"old": true}\n')
        with FileExporter(path, append=False) as exp:
            exp.export_event(_make_event())
        lines = path.read_text().strip().split("\n")
        assert len(lines) == 1
        assert "old" not in lines[0]

    def test_file_exporter_pretty_and_sync(self, tmp_path: Path):
        path = tmp_path / "pretty.jsonl"
        with FileExporter(path, pretty=True, sync_writes=True) as exp:
            exp.export_event(_make_event())
        assert "\n  " in path.read_text()

    def test_file_exporter_batch(self, tmp_path: Path):
        path = tmp_path / "batch.jsonl"
        batch = _make_batch()
        with FileExporter(path) as exp:
            exp.export_batch(batch)
        parsed = json.loads(path.read_text().strip())
        assert parsed["_type"] == "batch_marker"
        assert parsed["batch"]["batch_id"] == "batch_1"

    def test_file_exporter_batch_pretty(self, tmp_path: Path):
        path = tmp_path / "bp.jsonl"
        with FileExporter(path, pretty=True) as exp:
            exp.export_batch(_make_batch())
        assert "\n  " in path.read_text()

    def test_file_exporter_raises_after_close(self, tmp_path: Path):
        exp = FileExporter(tmp_path / "c.jsonl")
        exp.close()
        with pytest.raises(RuntimeError, match="closed"):
            exp.export_event(_make_event())
        with pytest.raises(RuntimeError, match="closed"):
            exp.export_batch(_make_batch())

    def test_file_exporter_creates_parent_dirs(self, tmp_path: Path):
        path = tmp_path / "a" / "b" / "c.jsonl"
        with FileExporter(path) as exp:
            exp.export_event(_make_event())
        assert path.exists()

    def test_file_exporter_flush_and_double_close(self, tmp_path: Path):
        exp = FileExporter(tmp_path / "f.jsonl")
        exp.export_event(_make_event())
        exp.flush()
        exp.close()
        exp.flush()
        exp.close()

    def test_file_exporter_context_manager_closes(self, tmp_path: Path):
        path = tmp_path / "ctx.jsonl"
        with FileExporter(path) as exp:
            exp.export_event(_make_event())
        with pytest.raises(RuntimeError):
            exp.export_event(_make_event())

    def test_file_exporter_export_chain(self, tmp_path: Path):
        chain, _ = _make_chain(3)
        path = tmp_path / "chain.jsonl"
        with FileExporter(path) as exp:
            exp.export_chain(chain)
        assert len([line for line in path.read_text().strip().split("\n") if line]) == 3

    def test_console_exporter_granted_and_denied(self):
        for allowed, expect in [(True, "ALLOWED"), (False, "DENIED")]:
            buf = io.StringIO()
            ConsoleExporter(output=buf, use_colors=False).export_event(_make_event(allowed=allowed))
            assert expect in buf.getvalue()

    def test_console_exporter_verbose(self):
        buf = io.StringIO()
        ConsoleExporter(output=buf, use_colors=False, verbose=True).export_event(_make_event())
        out = buf.getvalue()
        assert "Event ID:" in out and "Sequence:" in out and "Hash:" in out

    def test_console_exporter_no_colors_for_non_tty(self):
        exp = ConsoleExporter(output=io.StringIO(), use_colors=True)
        assert exp.use_colors is False

    def test_console_exporter_color_disabled(self):
        exp = ConsoleExporter(output=io.StringIO(), use_colors=False)
        assert exp._color("hello", "red") == "hello"

    def test_console_exporter_batch(self):
        buf = io.StringIO()
        ConsoleExporter(output=buf, use_colors=False).export_batch(_make_batch())
        assert "BATCH FINALIZED" in buf.getvalue() and "batch_1" in buf.getvalue()

    def test_console_exporter_batch_verbose(self):
        buf = io.StringIO()
        ConsoleExporter(output=buf, use_colors=False, verbose=True).export_batch(_make_batch())
        assert "Merkle Root:" in buf.getvalue()

    def test_console_exporter_truncates_long_args(self):
        buf = io.StringIO()
        ConsoleExporter(output=buf, use_colors=False).export_event(_make_event(long_args=True))
        assert "..." in buf.getvalue()

    def test_console_exporter_flush_and_close(self):
        buf = io.StringIO()
        exp = ConsoleExporter(output=buf)
        exp.flush()
        exp.close()

    def test_stream_exporter_event_and_batch(self):
        buf = io.StringIO()
        exp = StreamExporter(buf)
        ev = _make_event()
        exp.export_event(ev)
        exp.export_batch(_make_batch())
        lines = buf.getvalue().strip().split("\n")
        assert json.loads(lines[0])["event_id"] == ev.event_id
        assert json.loads(lines[1])["_type"] == "batch_marker"

    def test_stream_exporter_close_behavior(self):
        buf1, buf2 = io.StringIO(), io.StringIO()
        StreamExporter(buf1, close_on_exit=False).close()
        assert not buf1.closed
        StreamExporter(buf2, close_on_exit=True).close()
        assert buf2.closed

    def test_stream_exporter_context_manager(self):
        buf = io.StringIO()
        with StreamExporter(buf, close_on_exit=True) as exp:
            exp.export_event(_make_event())
        assert buf.closed

    def test_callback_exporter(self):
        events, batches = [], []
        exp = CallbackExporter(event_callback=events.append, batch_callback=batches.append)
        ev = _make_event()
        exp.export_event(ev)
        exp.export_batch(_make_batch())
        assert events[0] is ev
        assert len(batches) == 1
        exp.flush()
        exp.close()

    def test_callback_exporter_no_batch_callback(self):
        exp = CallbackExporter(event_callback=lambda e: None)
        exp.export_batch(_make_batch())

    def test_multi_exporter(self):
        buf1, buf2 = io.StringIO(), io.StringIO()
        multi = MultiExporter([StreamExporter(buf1), StreamExporter(buf2)])
        multi.export_event(_make_event())
        multi.export_batch(_make_batch())
        for b in (buf1, buf2):
            assert len(b.getvalue().strip().split("\n")) == 2
        multi.flush()

    def test_multi_exporter_close(self):
        buf1, buf2 = io.StringIO(), io.StringIO()
        MultiExporter(
            [
                StreamExporter(buf1, close_on_exit=True),
                StreamExporter(buf2, close_on_exit=True),
            ]
        ).close()
        assert buf1.closed and buf2.closed

    def test_multi_exporter_empty(self):
        multi = MultiExporter([])
        multi.export_event(_make_event())
        multi.flush()
        multi.close()

    def test_read_jsonl_events(self, tmp_path: Path):
        ev = _make_event()
        path = tmp_path / "events.jsonl"
        with FileExporter(path) as exp:
            exp.export_event(ev)
            exp.export_batch(_make_batch())
        events = list(read_jsonl_events(path))
        assert len(events) == 1 and events[0].event_id == ev.event_id

    def test_read_jsonl_events_skips_blanks(self, tmp_path: Path):
        path = tmp_path / "blanks.jsonl"
        with FileExporter(path) as exp:
            exp.export_event(_make_event())
        path.write_text(path.read_text() + "\n\n\n")
        assert len(list(read_jsonl_events(path))) == 1

    def test_verify_jsonl_chain_valid(self, tmp_path: Path):
        _, events = _make_chain(3)
        path = tmp_path / "valid.jsonl"
        with FileExporter(path) as exp:
            for ev in events:
                exp.export_event(ev)
        valid, error = verify_jsonl_chain(path)
        assert valid is True and error is None

    def test_verify_jsonl_chain_tampered(self, tmp_path: Path):
        _, events = _make_chain(3)
        path = tmp_path / "tampered.jsonl"
        with FileExporter(path) as exp:
            for ev in events:
                exp.export_event(ev)
        lines = path.read_text().strip().split("\n")
        obj = json.loads(lines[1])
        obj["data"]["authorization"]["reason"] = "TAMPERED"
        lines[1] = json.dumps(obj, sort_keys=True, separators=(",", ":"))
        path.write_text("\n".join(lines) + "\n")
        valid, error = verify_jsonl_chain(path)
        assert valid is False and error is not None

    def test_verify_jsonl_chain_broken_linkage(self, tmp_path: Path):
        _, events = _make_chain(3)
        path = tmp_path / "broken.jsonl"
        with FileExporter(path) as exp:
            for ev in events:
                exp.export_event(ev)
        lines = path.read_text().strip().split("\n")
        obj = json.loads(lines[1])
        obj["previous_hash"] = "sha256:0000000000000000"
        lines[1] = json.dumps(obj)
        path.write_text("\n".join(lines) + "\n")
        valid, error = verify_jsonl_chain(path)
        assert valid is False

    def test_verify_jsonl_chain_invalid_json(self, tmp_path: Path):
        path = tmp_path / "bad.jsonl"
        path.write_text("not json\n")
        valid, error = verify_jsonl_chain(path)
        assert valid is False and error is not None


class TestExplainability:
    def test_decision_factor_to_dict(self):
        f = DecisionFactor("role_check", False, 0.5, "Missing", {"req": "admin"}, ["LDAP"])
        d = f.to_dict()
        assert d["name"] == "role_check" and d["passed"] is False
        assert d["details"] == {"req": "admin"} and len(d["evidence"]) == 1

    def test_decision_factor_defaults(self):
        f = DecisionFactor("t", True, 0.3, "OK")
        assert f.details == {} and f.evidence == []

    def test_decision_auto_id_and_explicit_id(self):
        d1 = _decision()
        d2 = _decision(decision_id="custom")
        assert len(d1.decision_id) == 16
        assert d2.decision_id == "custom"

    def test_decision_string_enum_conversion(self):
        d = ExplainableDecision(decision_type="authorization", outcome="ALLOWED", factors=[])
        assert d.decision_type == DecisionType.AUTHORIZATION
        assert d.outcome == Outcome.ALLOWED

    def test_decision_invalid_string_stays_string(self):
        d = ExplainableDecision(decision_type="unknown", outcome="WEIRD", factors=[])
        assert d.decision_type == "unknown" and d.outcome == "WEIRD"

    def test_decision_passed_property(self):
        assert _decision(outcome=Outcome.ALLOWED).passed is True
        assert _decision(outcome=Outcome.DENIED).passed is False

    def test_primary_factor(self):
        denied = _decision(
            outcome=Outcome.DENIED,
            factors=[
                DecisionFactor("role", False, 0.6, "No"),
                DecisionFactor("rate", True, 0.4, "OK"),
            ],
        )
        assert denied.primary_factor.name == "role"
        allowed = _decision(
            factors=[
                DecisionFactor("a", True, 0.3, "OK"),
                DecisionFactor("b", True, 0.7, "OK"),
            ],
        )
        assert allowed.primary_factor.name == "b"
        assert _decision().primary_factor is None

    def test_decision_to_dict_and_json(self):
        d = _decision(
            outcome=Outcome.DENIED,
            factors=[DecisionFactor("c", False, 1.0, "Fail")],
            confidence=0.85,
        )
        dd = d.to_dict()
        assert dd["decision_type"] == "authorization" and dd["outcome"] == "DENIED"
        assert dd["confidence"] == 0.85
        parsed = json.loads(d.to_json())
        assert "decision_id" in parsed

    def test_explanation_to_dict(self):
        e = Explanation("abc", "summary", "detail", ["f1"], "cf", "conf", ["rec"])
        d = e.to_dict()
        assert d["format"] == "text" and d["language"] == "en"

    def test_explainer_auth_allowed_and_denied(self):
        explainer = DecisionExplainer()
        for outcome, expect in [(Outcome.ALLOWED, "ALLOWED"), (Outcome.DENIED, "DENIED")]:
            passed = outcome == Outcome.ALLOWED
            expl = explainer.explain(
                _decision(
                    outcome=outcome,
                    factors=[
                        DecisionFactor("role", passed, 1.0, "Has role" if passed else "No role")
                    ],
                )
            )
            assert expect in expl.summary

    def test_explainer_rate_limit(self):
        expl = DecisionExplainer().explain(
            _decision(
                dt=DecisionType.RATE_LIMIT,
                outcome=Outcome.DENIED,
                factors=[DecisionFactor("rc", False, 1.0, "Over")],
                context={"current": 105, "limit": 100},
            )
        )
        assert "105" in expl.summary or "DENIED" in expl.summary

    def test_explainer_guard_states(self):
        explainer = DecisionExplainer()
        assert (
            "ALLOWED"
            in explainer.explain(
                _decision(
                    dt=DecisionType.INPUT_GUARD,
                    outcome=Outcome.ALLOWED,
                )
            ).summary
        )
        assert (
            "MODIFIED"
            in explainer.explain(
                _decision(
                    dt=DecisionType.INPUT_GUARD,
                    outcome=Outcome.MODIFIED,
                )
            ).summary.upper()
            or "redact"
            in explainer.explain(
                _decision(
                    dt=DecisionType.INPUT_GUARD,
                    outcome=Outcome.MODIFIED,
                )
            ).summary.lower()
        )
        expl = explainer.explain(
            _decision(
                dt=DecisionType.OUTPUT_GUARD,
                outcome=Outcome.DENIED,
                factors=[DecisionFactor("pii", False, 1.0, "PII found")],
                context={"violation_type": "PII"},
            )
        )
        assert "PII" in expl.summary or "BLOCKED" in expl.summary

    def test_explainer_circuit_breaker_states(self):
        explainer = DecisionExplainer()
        states = [("closed", "AVAILABLE"), ("open", "UNAVAILABLE"), ("half_open", "TESTING")]
        for state, expect in states:
            expl = explainer.explain(
                _decision(
                    dt=DecisionType.CIRCUIT_BREAKER,
                    outcome=Outcome.ALLOWED if state == "closed" else Outcome.DENIED,
                    context={"state": state, "failures": 5},
                )
            )
            assert expect in expl.summary

    def test_explainer_intent_validation(self):
        expl = DecisionExplainer().explain(
            _decision(
                dt=DecisionType.INTENT_VALIDATION,
                outcome=Outcome.DENIED,
                factors=[DecisionFactor("intent", False, 1.0, "Hijack")],
            )
        )
        assert "hijack" in expl.summary.lower() or "BLOCKED" in expl.summary

    def test_explainer_budget(self):
        explainer = DecisionExplainer()
        assert (
            "5.00"
            in explainer.explain(
                _decision(
                    dt=DecisionType.BUDGET,
                    outcome=Outcome.ALLOWED,
                    factors=[DecisionFactor("b", True, 1.0, "OK")],
                    context={"spent": 5.0, "limit": 10.0},
                )
            ).summary
        )
        assert (
            "EXCEEDED"
            in explainer.explain(
                _decision(
                    dt=DecisionType.BUDGET,
                    outcome=Outcome.DENIED,
                    factors=[DecisionFactor("b", False, 1.0, "Over")],
                    context={"spent": 15.0, "limit": 10.0},
                )
            ).summary
        )

    def test_explainer_behavioral_drift(self):
        expl = DecisionExplainer().explain(
            _decision(
                dt=DecisionType.BEHAVIORAL_DRIFT,
                outcome=Outcome.DENIED,
                context={"metric": "latency", "deviation": 3.5},
            )
        )
        assert "latency" in expl.summary

    def test_explainer_unknown_type_fallback(self):
        expl = DecisionExplainer().explain(
            ExplainableDecision(
                decision_type="custom_check",
                outcome="DENIED",
                factors=[DecisionFactor("x", False, 1.0, "Nope")],
            )
        )
        assert "Nope" in expl.summary

    def test_explainer_formats(self):
        explainer = DecisionExplainer()
        base = _decision(
            outcome=Outcome.DENIED,
            factors=[DecisionFactor("role", False, 0.5, "No role", evidence=["Checked LDAP"])],
        )
        md = explainer.explain(base, format=ExplanationFormat.MARKDOWN)
        assert md.summary.startswith("**") and md.format == ExplanationFormat.MARKDOWN
        html = explainer.explain(base, format=ExplanationFormat.HTML)
        assert "<strong>" in html.summary and "<div" in html.detailed
        legal = explainer.explain(base, format=ExplanationFormat.LEGAL)
        assert "AUTOMATED DECISION DISCLOSURE" in legal.detailed
        assert "SB 53" in legal.detailed

    def test_explainer_counterfactuals(self):
        explainer = DecisionExplainer()
        denied_role = explainer.explain(
            _decision(
                outcome=Outcome.DENIED,
                factors=[DecisionFactor("role_check", False, 0.5, "Missing role")],
            )
        )
        assert "role" in denied_role.counterfactual.lower()
        allowed = explainer.explain(
            _decision(
                factors=[DecisionFactor("role", True, 0.8, "Has role")],
            )
        )
        assert "failed" in allowed.counterfactual.lower()
        assert explainer.explain(_decision()).counterfactual is None

    def test_explainer_counterfactual_factor_types(self):
        explainer = DecisionExplainer()
        factor_types = [
            ("rate_limit", "rate limit"),
            ("budget_x", "budget"),
            ("trust_lvl", "trust"),
            ("custom_xyz", "custom_xyz"),
        ]
        for name, expect in factor_types:
            expl = explainer.explain(
                _decision(
                    outcome=Outcome.DENIED,
                    factors=[DecisionFactor(name, False, 1.0, "Fail")],
                )
            )
            assert expect in expl.counterfactual.lower()

    def test_explainer_confidence_levels(self):
        explainer = DecisionExplainer()
        for conf, expect in [(0.95, "high"), (0.75, "medium"), (0.5, "low")]:
            expl = explainer.explain(_decision(confidence=conf))
            assert expect in expl.confidence_breakdown.lower()

    def test_explainer_recommendations(self):
        explainer = DecisionExplainer()
        recommendations = [
            ("role_check", "permission"),
            ("rate_x", "wait"),
            ("budget_x", "budget"),
            ("trust_x", "agent"),
            ("intent_x", "tool call"),
            ("circuit_x", "retry"),
        ]
        for name, expect in recommendations:
            expl = explainer.explain(
                _decision(
                    outcome=Outcome.DENIED,
                    factors=[DecisionFactor(name, False, 1.0, "No")],
                )
            )
            assert any(expect in r.lower() for r in expl.recommendations)

    def test_explainer_no_recommendations_when_disabled(self):
        expl = DecisionExplainer(include_recommendations=False).explain(
            _decision(
                outcome=Outcome.DENIED,
                factors=[DecisionFactor("role", False, 1.0, "No")],
            )
        )
        assert expl.recommendations == []

    def test_explainer_recommendations_dedup_and_limit(self):
        expl = DecisionExplainer().explain(
            _decision(
                outcome=Outcome.DENIED,
                factors=[DecisionFactor(f"role_{i}", False, 0.2, "No") for i in range(5)]
                + [DecisionFactor("rate_x", False, 0.1, "No")],
            )
        )
        assert len(expl.recommendations) <= 3

    def test_explainer_custom_templates(self):
        expl = DecisionExplainer(templates={"en": {"auth_allowed": "YEP: {reason}"}}).explain(
            _decision(factors=[DecisionFactor("r", True, 1.0, "OK")])
        )
        assert expl.summary.startswith("YEP:")

    def test_explainer_custom_language(self):
        expl = DecisionExplainer(templates={"es": {"auth_denied": "DENEGADO: {reason}"}}).explain(
            _decision(outcome=Outcome.DENIED, factors=[DecisionFactor("r", False, 1.0, "Sin rol")]),
            language="es",
        )
        assert "DENEGADO" in expl.summary and expl.language == "es"

    def test_explainer_register_custom_explainer(self):
        explainer = DecisionExplainer()
        custom = Explanation("x", "Custom!", "Details", [])
        explainer.register_explainer(DecisionType.AUTHORIZATION, lambda d: custom)
        assert explainer.explain(_decision()).summary == "Custom!"

    def test_explainer_detailed_includes_context_and_evidence(self):
        expl = DecisionExplainer().explain(
            _decision(
                factors=[DecisionFactor("role", True, 0.5, "OK", evidence=["Checked"])],
                context={"user_id": "alice"},
            )
        )
        assert "alice" in expl.detailed or "User Id" in expl.detailed

    def test_explainer_factors_explained_list(self):
        expl = DecisionExplainer().explain(
            _decision(
                outcome=Outcome.DENIED,
                factors=[
                    DecisionFactor("role", False, 0.5, "No role"),
                    DecisionFactor("rate", True, 0.5, "OK"),
                ],
            )
        )
        assert len(expl.factors_explained) == 2

    def test_logger_log_and_retrieve(self):
        logger = ExplainabilityLogger()
        d = _decision(factors=[DecisionFactor("r", True, 1.0, "OK")])
        expl = logger.log_decision(d)
        assert expl is not None and expl.decision_id == d.decision_id
        assert logger.get_decision(d.decision_id) is not None
        assert logger.get_explanation(d.decision_id) is not None

    def test_logger_auto_explain_disabled(self):
        logger = ExplainabilityLogger(auto_explain=False)
        d = _decision()
        assert logger.log_decision(d) is None

    def test_logger_get_nonexistent(self):
        logger = ExplainabilityLogger()
        assert logger.get_decision("nope") is None
        assert logger.explain("nope") is None

    def test_logger_explain_on_demand(self):
        logger = ExplainabilityLogger(auto_explain=False)
        d = _decision(factors=[DecisionFactor("r", True, 1.0, "OK")])
        logger.log_decision(d)
        expl = logger.explain(d.decision_id)
        assert expl is not None

    def test_logger_filtered_queries(self):
        logger = ExplainabilityLogger()
        for i in range(5):
            logger.log_decision(
                _decision(
                    dt=DecisionType.AUTHORIZATION if i < 3 else DecisionType.RATE_LIMIT,
                    outcome=Outcome.ALLOWED if i % 2 == 0 else Outcome.DENIED,
                    context={"user_id": f"u{i}", "current": 1, "limit": 10},
                )
            )
        assert len(logger.get_decisions(decision_type=DecisionType.AUTHORIZATION)) == 3
        assert len(logger.get_decisions(outcome=Outcome.DENIED)) == 2
        assert len(logger.get_decisions(user_id="u0")) == 1
        assert len(logger.get_decisions(limit=2)) == 2

    def test_logger_max_stored_eviction(self):
        logger = ExplainabilityLogger(max_stored=5)
        for i in range(10):
            logger.log_decision(_decision(decision_id=f"d{i}"))
        assert len(logger.get_decisions(limit=100)) <= 5

    def test_logger_export_json_and_jsonl(self):
        logger = ExplainabilityLogger()
        logger.log_decision(_decision(factors=[DecisionFactor("r", True, 1.0, "ok")]))
        ctx = {"current": 1, "limit": 10}
        logger.log_decision(_decision(dt=DecisionType.RATE_LIMIT, context=ctx))
        parsed = json.loads(logger.export_decisions(format="json"))
        assert len(parsed) == 2 and "explanation" in parsed[0]
        jsonl_export = logger.export_decisions(format="jsonl").strip().split("\n")
        lines = [line for line in jsonl_export if line]
        assert len(lines) == 2
        no_expl = json.loads(logger.export_decisions(format="json", include_explanations=False))
        assert "explanation" not in no_expl[0]

    def test_logger_clear(self):
        logger = ExplainabilityLogger()
        for _ in range(3):
            logger.log_decision(_decision())
        assert logger.clear() == 3
        assert logger.get_decisions() == []

    def test_logger_store_explanations_disabled(self):
        logger = ExplainabilityLogger(store_explanations=False)
        d = _decision()
        logger.log_decision(d)
        assert logger.get_explanation(d.decision_id) is None

    def test_logger_audit_integration(self):
        mock = MagicMock()
        ExplainabilityLogger(audit_logger=mock).log_decision(_decision())
        mock.log_custom.assert_called_once()

    def test_logger_audit_failure_handled(self):
        mock = MagicMock()
        mock.log_custom.side_effect = RuntimeError("fail")
        ExplainabilityLogger(audit_logger=mock).log_decision(_decision())

    def test_create_authorization_decision_helper(self):
        factors = [DecisionFactor("r", True, 1.0, "OK")]
        d = create_authorization_decision("alice", "delete", True, factors)
        assert d.decision_type == DecisionType.AUTHORIZATION and d.outcome == Outcome.ALLOWED
        assert d.context["user_id"] == "alice" and d.context["tool_name"] == "delete"
        d2 = create_authorization_decision("bob", "admin", False, [])
        assert d2.outcome == Outcome.DENIED

    def test_create_guard_decision_helper(self):
        assert create_guard_decision("input", True, []).decision_type == DecisionType.INPUT_GUARD
        assert create_guard_decision("output", False, [], modified=True).outcome == Outcome.MODIFIED
        assert create_guard_decision("input", False, []).outcome == Outcome.DENIED
        d = create_guard_decision("input", True, [], content_sample="x" * 200)
        preview = d.context["content_preview"]
        assert preview.endswith("...") and len(preview) == 103
        d2 = create_guard_decision("input", True, [], content_sample="short")
        assert d2.context["content_preview"] == "short"

    def test_create_rate_limit_decision_helper(self):
        d = create_rate_limit_decision("alice", True, 5, 100, 60)
        assert d.decision_type == DecisionType.RATE_LIMIT and d.context["current"] == 5
        assert create_rate_limit_decision("bob", False, 110, 100, 60).outcome == Outcome.DENIED

    def test_create_budget_decision_helper(self):
        d = create_budget_decision("alice", True, 5.0, 10.0)
        assert d.decision_type == DecisionType.BUDGET and d.context["percentage"] == 0.5
        assert create_budget_decision("alice", False, 1.0, 0.0).context["percentage"] == 0

    def test_enum_values(self):
        assert DecisionType.AUTHORIZATION.value == "authorization"
        assert DecisionType.CASCADE.value == "cascade"
        assert Outcome.DEFERRED.value == "DEFERRED"
        assert ExplanationFormat.LEGAL.value == "legal"
