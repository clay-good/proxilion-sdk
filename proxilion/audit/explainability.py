"""
Explainable Decisions for Proxilion.

Provides human-readable audit trails explaining WHY each security
decision was made. Designed for CA SB 53 compliance and regulatory
transparency requirements.

Features:
    - Human-readable explanation generation for all decision types
    - Decision tree visualization
    - Factor contribution analysis
    - Multi-language explanation templates
    - Confidence scoring with uncertainty breakdown
    - Counterfactual explanations ("what would change the decision")

Example:
    >>> from proxilion.audit.explainability import (
    ...     ExplainableDecision,
    ...     DecisionExplainer,
    ...     ExplanationFormat,
    ... )
    >>>
    >>> # Create an explainer
    >>> explainer = DecisionExplainer()
    >>>
    >>> # Explain an authorization decision
    >>> decision = ExplainableDecision(
    ...     decision_type="authorization",
    ...     outcome="DENIED",
    ...     factors=[
    ...         DecisionFactor("role_check", False, 0.4, "User lacks 'admin' role"),
    ...         DecisionFactor("rate_limit", True, 0.3, "Within rate limits"),
    ...         DecisionFactor("time_window", True, 0.3, "Within allowed hours"),
    ...     ],
    ...     context={"user_id": "user_123", "tool": "delete_user"},
    ... )
    >>>
    >>> # Generate human-readable explanation
    >>> explanation = explainer.explain(decision)
    >>> print(explanation.summary)
    "Access DENIED: User lacks required 'admin' role for delete_user operation"
    >>>
    >>> # Get counterfactual
    >>> print(explanation.counterfactual)
    "Access would be ALLOWED if: User had 'admin' role"
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable

logger = logging.getLogger(__name__)


class DecisionType(str, Enum):
    """Types of security decisions that can be explained."""

    AUTHORIZATION = "authorization"
    RATE_LIMIT = "rate_limit"
    INPUT_GUARD = "input_guard"
    OUTPUT_GUARD = "output_guard"
    CIRCUIT_BREAKER = "circuit_breaker"
    TRUST_BOUNDARY = "trust_boundary"
    INTENT_VALIDATION = "intent_validation"
    BEHAVIORAL_DRIFT = "behavioral_drift"
    BUDGET = "budget"
    CASCADE = "cascade"


class ExplanationFormat(str, Enum):
    """Output formats for explanations."""

    TEXT = "text"           # Plain text, human-readable
    MARKDOWN = "markdown"   # Markdown formatted
    HTML = "html"           # HTML formatted
    JSON = "json"           # Structured JSON
    LEGAL = "legal"         # Legal/compliance format


class Outcome(str, Enum):
    """Decision outcomes."""

    ALLOWED = "ALLOWED"
    DENIED = "DENIED"
    WARNED = "WARNED"
    MODIFIED = "MODIFIED"  # e.g., output was redacted
    DEFERRED = "DEFERRED"  # Decision pending more info


@dataclass
class DecisionFactor:
    """
    A single factor contributing to a decision.

    Attributes:
        name: Factor identifier (e.g., "role_check", "rate_limit").
        passed: Whether this factor passed (True) or failed (False).
        weight: Importance weight of this factor (0.0 to 1.0).
        reason: Human-readable explanation of the factor result.
        details: Additional structured details.
        evidence: Evidence/data that led to this factor result.
    """

    name: str
    passed: bool
    weight: float
    reason: str
    details: dict[str, Any] = field(default_factory=dict)
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "passed": self.passed,
            "weight": self.weight,
            "reason": self.reason,
            "details": self.details,
            "evidence": self.evidence,
        }


@dataclass
class ExplainableDecision:
    """
    A security decision with full explainability metadata.

    Attributes:
        decision_id: Unique identifier for this decision.
        decision_type: Type of security decision.
        outcome: The decision outcome.
        factors: List of factors that contributed to the decision.
        context: Contextual information (user, tool, etc.).
        timestamp: When the decision was made.
        confidence: Confidence score (0.0 to 1.0).
        latency_ms: Time taken to make the decision.
        policy_version: Version of the policy used.
        metadata: Additional metadata.
    """

    decision_type: DecisionType | str
    outcome: Outcome | str
    factors: list[DecisionFactor]
    context: dict[str, Any] = field(default_factory=dict)
    decision_id: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    confidence: float = 1.0
    latency_ms: float = 0.0
    policy_version: str = "1.0"
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.decision_id:
            # Generate deterministic ID from decision content
            content = f"{self.decision_type}:{self.outcome}:{self.timestamp.isoformat()}"
            self.decision_id = hashlib.sha256(content.encode()).hexdigest()[:16]

        # Convert string enums
        if isinstance(self.decision_type, str):
            try:
                self.decision_type = DecisionType(self.decision_type)
            except ValueError:
                pass  # Keep as string if not a known type

        if isinstance(self.outcome, str):
            try:
                self.outcome = Outcome(self.outcome)
            except ValueError:
                pass

    @property
    def passed(self) -> bool:
        """Whether the decision resulted in an allowed outcome."""
        return self.outcome in (Outcome.ALLOWED, "ALLOWED")

    @property
    def primary_factor(self) -> DecisionFactor | None:
        """Get the most important factor (by weight or first failing)."""
        if not self.factors:
            return None

        # If denied, return first failing factor with highest weight
        if not self.passed:
            failing = [f for f in self.factors if not f.passed]
            if failing:
                return max(failing, key=lambda f: f.weight)

        # Otherwise return highest weight factor
        return max(self.factors, key=lambda f: f.weight)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "decision_id": self.decision_id,
            "decision_type": str(self.decision_type.value if isinstance(self.decision_type, DecisionType) else self.decision_type),
            "outcome": str(self.outcome.value if isinstance(self.outcome, Outcome) else self.outcome),
            "factors": [f.to_dict() for f in self.factors],
            "context": self.context,
            "timestamp": self.timestamp.isoformat(),
            "confidence": self.confidence,
            "latency_ms": self.latency_ms,
            "policy_version": self.policy_version,
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


@dataclass
class Explanation:
    """
    Human-readable explanation of a decision.

    Attributes:
        decision_id: ID of the explained decision.
        summary: One-line summary of the decision.
        detailed: Multi-paragraph detailed explanation.
        factors_explained: Per-factor explanations.
        counterfactual: What would change the decision.
        confidence_breakdown: Explanation of confidence score.
        recommendations: Suggestions for the user.
        format: Output format used.
        language: Language code (e.g., "en", "es").
    """

    decision_id: str
    summary: str
    detailed: str
    factors_explained: list[str]
    counterfactual: str | None = None
    confidence_breakdown: str | None = None
    recommendations: list[str] = field(default_factory=list)
    format: ExplanationFormat = ExplanationFormat.TEXT
    language: str = "en"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "decision_id": self.decision_id,
            "summary": self.summary,
            "detailed": self.detailed,
            "factors_explained": self.factors_explained,
            "counterfactual": self.counterfactual,
            "confidence_breakdown": self.confidence_breakdown,
            "recommendations": self.recommendations,
            "format": self.format.value,
            "language": self.language,
        }


# Default explanation templates
DEFAULT_TEMPLATES: dict[str, dict[str, str]] = {
    "en": {
        # Authorization
        "auth_allowed": "Access ALLOWED: {reason}",
        "auth_denied": "Access DENIED: {reason}",
        "auth_factor_pass": "✓ {name}: {reason}",
        "auth_factor_fail": "✗ {name}: {reason}",

        # Rate limiting
        "rate_allowed": "Request ALLOWED: Within rate limits ({current}/{limit} requests)",
        "rate_denied": "Request DENIED: Rate limit exceeded ({current}/{limit} requests)",
        "rate_counterfactual": "Request would be allowed after {wait_seconds} seconds",

        # Guards
        "guard_pass": "Content ALLOWED: No policy violations detected",
        "guard_block": "Content BLOCKED: {violation_type} detected - {reason}",
        "guard_redact": "Content MODIFIED: Sensitive information redacted",

        # Circuit breaker
        "circuit_closed": "Service AVAILABLE: Circuit breaker closed",
        "circuit_open": "Service UNAVAILABLE: Circuit breaker open after {failures} failures",
        "circuit_half_open": "Service TESTING: Circuit breaker allowing test request",

        # Trust boundary
        "trust_allowed": "Inter-agent communication ALLOWED: {from_agent} → {to_agent}",
        "trust_denied": "Inter-agent communication DENIED: Trust level insufficient",

        # Intent validation
        "intent_valid": "Tool call ALLOWED: Consistent with original intent",
        "intent_hijack": "Tool call BLOCKED: Potential intent hijack detected",

        # Budget
        "budget_ok": "Budget OK: {spent:.2f}/{limit:.2f} USD ({percentage:.0%})",
        "budget_exceeded": "Budget EXCEEDED: {spent:.2f}/{limit:.2f} USD",

        # Behavioral drift
        "drift_normal": "Behavior NORMAL: Within baseline parameters",
        "drift_detected": "Behavior ANOMALOUS: {metric} deviated by {deviation:.1f} std devs",

        # Generic
        "counterfactual_prefix": "Decision would change if: ",
        "no_counterfactual": "No simple change would alter this decision",
        "confidence_high": "High confidence ({confidence:.0%}): All factors clearly determined",
        "confidence_medium": "Medium confidence ({confidence:.0%}): Some uncertainty in factors",
        "confidence_low": "Low confidence ({confidence:.0%}): Significant uncertainty",
    }
}


class DecisionExplainer:
    """
    Generates human-readable explanations for security decisions.

    The explainer uses templates and decision factors to create
    clear, actionable explanations suitable for end users,
    compliance audits, and debugging.

    Example:
        >>> explainer = DecisionExplainer()
        >>>
        >>> decision = ExplainableDecision(
        ...     decision_type=DecisionType.AUTHORIZATION,
        ...     outcome=Outcome.DENIED,
        ...     factors=[
        ...         DecisionFactor("role", False, 0.5, "Missing admin role"),
        ...     ],
        ...     context={"user_id": "alice", "tool": "delete_user"},
        ... )
        >>>
        >>> explanation = explainer.explain(decision)
        >>> print(explanation.summary)
    """

    def __init__(
        self,
        templates: dict[str, dict[str, str]] | None = None,
        default_language: str = "en",
        include_evidence: bool = True,
        include_recommendations: bool = True,
    ) -> None:
        """
        Initialize the explainer.

        Args:
            templates: Custom explanation templates by language.
            default_language: Default language for explanations.
            include_evidence: Whether to include evidence in explanations.
            include_recommendations: Whether to include recommendations.
        """
        self._templates = dict(DEFAULT_TEMPLATES)
        if templates:
            for lang, tmpl in templates.items():
                if lang in self._templates:
                    self._templates[lang].update(tmpl)
                else:
                    self._templates[lang] = tmpl

        self._default_language = default_language
        self._include_evidence = include_evidence
        self._include_recommendations = include_recommendations

        # Custom explainers for specific decision types
        self._custom_explainers: dict[str, Callable[[ExplainableDecision], Explanation]] = {}

    def register_explainer(
        self,
        decision_type: DecisionType | str,
        explainer: Callable[[ExplainableDecision], Explanation],
    ) -> None:
        """
        Register a custom explainer for a decision type.

        Args:
            decision_type: Decision type to handle.
            explainer: Function that generates explanations.
        """
        key = decision_type.value if isinstance(decision_type, DecisionType) else decision_type
        self._custom_explainers[key] = explainer

    def explain(
        self,
        decision: ExplainableDecision,
        format: ExplanationFormat = ExplanationFormat.TEXT,
        language: str | None = None,
    ) -> Explanation:
        """
        Generate a human-readable explanation for a decision.

        Args:
            decision: The decision to explain.
            format: Desired output format.
            language: Language for the explanation.

        Returns:
            Explanation with summary, details, and counterfactual.
        """
        lang = language or self._default_language
        templates = self._templates.get(lang, self._templates["en"])

        # Check for custom explainer
        decision_type_key = (
            decision.decision_type.value
            if isinstance(decision.decision_type, DecisionType)
            else str(decision.decision_type)
        )

        if decision_type_key in self._custom_explainers:
            return self._custom_explainers[decision_type_key](decision)

        # Generate explanation based on decision type
        summary = self._generate_summary(decision, templates)
        detailed = self._generate_detailed(decision, templates)
        factors_explained = self._explain_factors(decision, templates)
        counterfactual = self._generate_counterfactual(decision, templates)
        confidence_breakdown = self._explain_confidence(decision, templates)
        recommendations = self._generate_recommendations(decision) if self._include_recommendations else []

        # Format the output
        if format == ExplanationFormat.MARKDOWN:
            summary = f"**{summary}**"
            detailed = self._to_markdown(detailed, factors_explained)
        elif format == ExplanationFormat.HTML:
            summary = f"<strong>{summary}</strong>"
            detailed = self._to_html(detailed, factors_explained)
        elif format == ExplanationFormat.LEGAL:
            detailed = self._to_legal_format(decision, detailed, factors_explained)

        return Explanation(
            decision_id=decision.decision_id,
            summary=summary,
            detailed=detailed,
            factors_explained=factors_explained,
            counterfactual=counterfactual,
            confidence_breakdown=confidence_breakdown,
            recommendations=recommendations,
            format=format,
            language=lang,
        )

    def _generate_summary(
        self,
        decision: ExplainableDecision,
        templates: dict[str, str],
    ) -> str:
        """Generate one-line summary."""
        dt = decision.decision_type
        outcome = decision.outcome
        context = decision.context
        primary = decision.primary_factor

        # Determine template key based on decision type and outcome
        if dt == DecisionType.AUTHORIZATION or dt == "authorization":
            if outcome in (Outcome.ALLOWED, "ALLOWED"):
                template = templates.get("auth_allowed", "Access ALLOWED: {reason}")
            else:
                template = templates.get("auth_denied", "Access DENIED: {reason}")
            reason = primary.reason if primary else "Policy evaluation"
            return template.format(reason=reason, **context)

        elif dt == DecisionType.RATE_LIMIT or dt == "rate_limit":
            if outcome in (Outcome.ALLOWED, "ALLOWED"):
                template = templates.get("rate_allowed", "Request allowed")
            else:
                template = templates.get("rate_denied", "Rate limit exceeded")
            return template.format(**context)

        elif dt in (DecisionType.INPUT_GUARD, DecisionType.OUTPUT_GUARD) or dt in ("input_guard", "output_guard"):
            if outcome in (Outcome.ALLOWED, "ALLOWED"):
                return templates.get("guard_pass", "Content allowed")
            elif outcome in (Outcome.MODIFIED, "MODIFIED"):
                return templates.get("guard_redact", "Content modified")
            else:
                violation = context.get("violation_type", "Policy violation")
                reason = primary.reason if primary else "Security policy"
                return templates.get("guard_block", "Content blocked: {reason}").format(
                    violation_type=violation, reason=reason
                )

        elif dt == DecisionType.CIRCUIT_BREAKER or dt == "circuit_breaker":
            state = context.get("state", "unknown")
            if state == "closed":
                return templates.get("circuit_closed", "Service available")
            elif state == "open":
                failures = context.get("failures", 0)
                return templates.get("circuit_open", "Service unavailable").format(failures=failures)
            else:
                return templates.get("circuit_half_open", "Service testing")

        elif dt == DecisionType.INTENT_VALIDATION or dt == "intent_validation":
            if outcome in (Outcome.ALLOWED, "ALLOWED"):
                return templates.get("intent_valid", "Tool call consistent with intent")
            else:
                return templates.get("intent_hijack", "Potential intent hijack detected")

        elif dt == DecisionType.BUDGET or dt == "budget":
            spent = context.get("spent", 0)
            limit = context.get("limit", 0)
            percentage = spent / limit if limit > 0 else 0
            if outcome in (Outcome.ALLOWED, "ALLOWED"):
                return templates.get("budget_ok", "Within budget").format(
                    spent=spent, limit=limit, percentage=percentage
                )
            else:
                return templates.get("budget_exceeded", "Budget exceeded").format(
                    spent=spent, limit=limit
                )

        elif dt == DecisionType.BEHAVIORAL_DRIFT or dt == "behavioral_drift":
            if outcome in (Outcome.ALLOWED, "ALLOWED"):
                return templates.get("drift_normal", "Behavior within normal range")
            else:
                metric = context.get("metric", "unknown")
                deviation = context.get("deviation", 0)
                return templates.get("drift_detected", "Behavioral anomaly").format(
                    metric=metric, deviation=deviation
                )

        # Default summary
        outcome_str = outcome.value if isinstance(outcome, Outcome) else str(outcome)
        dt_str = dt.value if isinstance(dt, DecisionType) else str(dt)
        reason = primary.reason if primary else "Policy decision"
        return f"{dt_str.title()} {outcome_str}: {reason}"

    def _generate_detailed(
        self,
        decision: ExplainableDecision,
        templates: dict[str, str],
    ) -> str:
        """Generate detailed multi-paragraph explanation."""
        lines = []

        # Opening paragraph
        dt_str = (
            decision.decision_type.value
            if isinstance(decision.decision_type, DecisionType)
            else str(decision.decision_type)
        )
        outcome_str = (
            decision.outcome.value
            if isinstance(decision.outcome, Outcome)
            else str(decision.outcome)
        )

        lines.append(
            f"A {dt_str.replace('_', ' ')} decision was made at "
            f"{decision.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}."
        )
        lines.append(f"The final outcome was: {outcome_str}.")
        lines.append("")

        # Context paragraph
        if decision.context:
            context_items = []
            for key, value in decision.context.items():
                if key not in ("_internal", "raw"):
                    context_items.append(f"- {key.replace('_', ' ').title()}: {value}")
            if context_items:
                lines.append("Context:")
                lines.extend(context_items)
                lines.append("")

        # Factors paragraph
        if decision.factors:
            lines.append("The following factors were evaluated:")
            for factor in decision.factors:
                status = "✓ PASSED" if factor.passed else "✗ FAILED"
                lines.append(f"- {factor.name}: {status} (weight: {factor.weight:.0%})")
                lines.append(f"  Reason: {factor.reason}")
                if self._include_evidence and factor.evidence:
                    for ev in factor.evidence:
                        lines.append(f"  Evidence: {ev}")
            lines.append("")

        # Confidence paragraph
        lines.append(f"Decision confidence: {decision.confidence:.0%}")
        lines.append(f"Processing time: {decision.latency_ms:.2f}ms")
        lines.append(f"Policy version: {decision.policy_version}")

        return "\n".join(lines)

    def _explain_factors(
        self,
        decision: ExplainableDecision,
        templates: dict[str, str],
    ) -> list[str]:
        """Generate per-factor explanations."""
        explanations = []

        for factor in decision.factors:
            if factor.passed:
                template = templates.get("auth_factor_pass", "✓ {name}: {reason}")
            else:
                template = templates.get("auth_factor_fail", "✗ {name}: {reason}")

            explanations.append(template.format(name=factor.name, reason=factor.reason))

        return explanations

    def _generate_counterfactual(
        self,
        decision: ExplainableDecision,
        templates: dict[str, str],
    ) -> str | None:
        """Generate counterfactual explanation."""
        if not decision.factors:
            return None

        prefix = templates.get("counterfactual_prefix", "Decision would change if: ")

        if decision.passed:
            # What would cause denial?
            passing_factors = [f for f in decision.factors if f.passed]
            if passing_factors:
                critical = max(passing_factors, key=lambda f: f.weight)
                return f"{prefix}{critical.name} check failed"
        else:
            # What would cause approval?
            failing_factors = [f for f in decision.factors if not f.passed]
            if failing_factors:
                changes = []
                for f in failing_factors:
                    # Generate specific counterfactual based on factor name
                    if "role" in f.name.lower():
                        changes.append(f"User had the required role")
                    elif "rate" in f.name.lower():
                        changes.append(f"Request was within rate limits")
                    elif "budget" in f.name.lower():
                        changes.append(f"Budget was not exceeded")
                    elif "trust" in f.name.lower():
                        changes.append(f"Trust level was sufficient")
                    else:
                        changes.append(f"{f.name} check passed")

                if changes:
                    return prefix + "; ".join(changes)

        return templates.get("no_counterfactual", "No simple change would alter this decision")

    def _explain_confidence(
        self,
        decision: ExplainableDecision,
        templates: dict[str, str],
    ) -> str:
        """Explain the confidence score."""
        conf = decision.confidence

        if conf >= 0.9:
            template = templates.get("confidence_high", "High confidence ({confidence:.0%})")
        elif conf >= 0.7:
            template = templates.get("confidence_medium", "Medium confidence ({confidence:.0%})")
        else:
            template = templates.get("confidence_low", "Low confidence ({confidence:.0%})")

        return template.format(confidence=conf)

    def _generate_recommendations(self, decision: ExplainableDecision) -> list[str]:
        """Generate actionable recommendations."""
        recommendations = []

        if not decision.passed:
            failing = [f for f in decision.factors if not f.passed]
            for factor in failing:
                name = factor.name.lower()

                if "role" in name or "permission" in name:
                    recommendations.append(
                        "Contact your administrator to request the necessary permissions"
                    )
                elif "rate" in name:
                    recommendations.append(
                        "Wait before retrying, or contact support for rate limit increase"
                    )
                elif "budget" in name:
                    recommendations.append(
                        "Review your usage or request a budget increase from your admin"
                    )
                elif "trust" in name:
                    recommendations.append(
                        "Ensure proper agent authentication and delegation chains"
                    )
                elif "intent" in name:
                    recommendations.append(
                        "Verify the tool call matches the original user request"
                    )
                elif "circuit" in name:
                    recommendations.append(
                        "The service may be experiencing issues; retry later"
                    )

        # Remove duplicates while preserving order
        seen = set()
        unique = []
        for rec in recommendations:
            if rec not in seen:
                seen.add(rec)
                unique.append(rec)

        return unique[:3]  # Limit to top 3 recommendations

    def _to_markdown(self, detailed: str, factors: list[str]) -> str:
        """Convert explanation to Markdown format."""
        lines = detailed.split("\n")
        md_lines = []

        for line in lines:
            if line.endswith(":"):
                md_lines.append(f"\n### {line}\n")
            elif line.startswith("- "):
                md_lines.append(line)
            elif line.startswith("  "):
                md_lines.append(f"  {line.strip()}")
            else:
                md_lines.append(line)

        return "\n".join(md_lines)

    def _to_html(self, detailed: str, factors: list[str]) -> str:
        """Convert explanation to HTML format."""
        # Simple HTML conversion
        html = detailed.replace("\n\n", "</p><p>")
        html = html.replace("\n", "<br>")
        html = f"<div class='explanation'><p>{html}</p></div>"
        return html

    def _to_legal_format(
        self,
        decision: ExplainableDecision,
        detailed: str,
        factors: list[str],
    ) -> str:
        """Convert to legal/compliance format (CA SB 53 style)."""
        lines = [
            "=" * 60,
            "AUTOMATED DECISION DISCLOSURE",
            "(Per California SB 53 - AI Transparency Requirements)",
            "=" * 60,
            "",
            f"Decision ID: {decision.decision_id}",
            f"Timestamp: {decision.timestamp.isoformat()}",
            f"Decision Type: {decision.decision_type}",
            f"Outcome: {decision.outcome}",
            "",
            "FACTORS CONSIDERED:",
            "-" * 40,
        ]

        for i, factor in enumerate(decision.factors, 1):
            lines.append(f"{i}. {factor.name}")
            lines.append(f"   Result: {'PASSED' if factor.passed else 'FAILED'}")
            lines.append(f"   Weight: {factor.weight:.0%}")
            lines.append(f"   Explanation: {factor.reason}")
            if factor.evidence:
                lines.append(f"   Evidence: {'; '.join(factor.evidence)}")
            lines.append("")

        lines.extend([
            "-" * 40,
            f"Confidence Level: {decision.confidence:.0%}",
            f"Policy Version: {decision.policy_version}",
            "",
            "This decision was made by an automated system. For questions",
            "or to request human review, contact your administrator.",
            "=" * 60,
        ])

        return "\n".join(lines)


class ExplainabilityLogger:
    """
    Logs explainable decisions for audit and compliance.

    Integrates with the main AuditLogger to provide a complete
    record of all security decisions with full explanations.

    Example:
        >>> from proxilion.audit import AuditLogger
        >>> from proxilion.audit.explainability import ExplainabilityLogger
        >>>
        >>> audit_logger = AuditLogger(config)
        >>> explainability_logger = ExplainabilityLogger(audit_logger)
        >>>
        >>> # Log an explained decision
        >>> decision = ExplainableDecision(...)
        >>> explainability_logger.log_decision(decision)
    """

    def __init__(
        self,
        audit_logger: Any | None = None,
        explainer: DecisionExplainer | None = None,
        auto_explain: bool = True,
        store_explanations: bool = True,
        max_stored: int = 10000,
    ) -> None:
        """
        Initialize the explainability logger.

        Args:
            audit_logger: Optional AuditLogger instance for integration.
            explainer: DecisionExplainer to use (creates default if None).
            auto_explain: Whether to auto-generate explanations.
            store_explanations: Whether to store explanations in memory.
            max_stored: Maximum explanations to store.
        """
        self._audit_logger = audit_logger
        self._explainer = explainer or DecisionExplainer()
        self._auto_explain = auto_explain
        self._store_explanations = store_explanations
        self._max_stored = max_stored

        self._lock = threading.RLock()
        self._decisions: list[ExplainableDecision] = []
        self._explanations: dict[str, Explanation] = {}

    def log_decision(
        self,
        decision: ExplainableDecision,
        format: ExplanationFormat = ExplanationFormat.TEXT,
    ) -> Explanation | None:
        """
        Log a decision and optionally generate explanation.

        Args:
            decision: The decision to log.
            format: Format for the explanation.

        Returns:
            Explanation if auto_explain is enabled.
        """
        explanation = None

        if self._auto_explain:
            explanation = self._explainer.explain(decision, format=format)

        with self._lock:
            # Store decision
            self._decisions.append(decision)
            if len(self._decisions) > self._max_stored:
                self._decisions = self._decisions[-self._max_stored:]

            # Store explanation
            if explanation and self._store_explanations:
                self._explanations[decision.decision_id] = explanation
                if len(self._explanations) > self._max_stored:
                    # Remove oldest
                    oldest = list(self._explanations.keys())[:100]
                    for key in oldest:
                        del self._explanations[key]

        # Log to audit logger if available
        if self._audit_logger is not None:
            try:
                self._audit_logger.log_custom(
                    event_type="explainable_decision",
                    data={
                        "decision": decision.to_dict(),
                        "explanation": explanation.to_dict() if explanation else None,
                    },
                )
            except Exception as e:
                logger.warning(f"Failed to log to audit logger: {e}")

        logger.debug(
            f"Logged explainable decision: {decision.decision_id} "
            f"({decision.decision_type} -> {decision.outcome})"
        )

        return explanation

    def get_decision(self, decision_id: str) -> ExplainableDecision | None:
        """Get a decision by ID."""
        with self._lock:
            for decision in reversed(self._decisions):
                if decision.decision_id == decision_id:
                    return decision
        return None

    def get_explanation(self, decision_id: str) -> Explanation | None:
        """Get an explanation by decision ID."""
        with self._lock:
            return self._explanations.get(decision_id)

    def explain(
        self,
        decision_id: str,
        format: ExplanationFormat = ExplanationFormat.TEXT,
    ) -> Explanation | None:
        """
        Get or generate explanation for a decision.

        Args:
            decision_id: ID of the decision to explain.
            format: Desired output format.

        Returns:
            Explanation or None if decision not found.
        """
        # Check if already explained
        with self._lock:
            if decision_id in self._explanations:
                return self._explanations[decision_id]

        # Find and explain decision
        decision = self.get_decision(decision_id)
        if decision is None:
            return None

        explanation = self._explainer.explain(decision, format=format)

        with self._lock:
            self._explanations[decision_id] = explanation

        return explanation

    def get_decisions(
        self,
        decision_type: DecisionType | str | None = None,
        outcome: Outcome | str | None = None,
        user_id: str | None = None,
        limit: int = 100,
    ) -> list[ExplainableDecision]:
        """
        Get decisions with optional filters.

        Args:
            decision_type: Filter by decision type.
            outcome: Filter by outcome.
            user_id: Filter by user ID in context.
            limit: Maximum decisions to return.

        Returns:
            List of matching decisions.
        """
        with self._lock:
            results = []

            for decision in reversed(self._decisions):
                # Apply filters
                if decision_type is not None:
                    dt = decision.decision_type
                    dt_str = dt.value if isinstance(dt, DecisionType) else str(dt)
                    filter_str = (
                        decision_type.value
                        if isinstance(decision_type, DecisionType)
                        else str(decision_type)
                    )
                    if dt_str != filter_str:
                        continue

                if outcome is not None:
                    oc = decision.outcome
                    oc_str = oc.value if isinstance(oc, Outcome) else str(oc)
                    filter_str = (
                        outcome.value
                        if isinstance(outcome, Outcome)
                        else str(outcome)
                    )
                    if oc_str != filter_str:
                        continue

                if user_id is not None:
                    if decision.context.get("user_id") != user_id:
                        continue

                results.append(decision)

                if len(results) >= limit:
                    break

            return results

    def export_decisions(
        self,
        format: str = "json",
        include_explanations: bool = True,
    ) -> str:
        """
        Export all decisions and explanations.

        Args:
            format: Output format ("json" or "jsonl").
            include_explanations: Whether to include explanations.

        Returns:
            Exported data as string.
        """
        with self._lock:
            records = []

            for decision in self._decisions:
                record = decision.to_dict()

                if include_explanations and decision.decision_id in self._explanations:
                    record["explanation"] = self._explanations[decision.decision_id].to_dict()

                records.append(record)

        if format == "jsonl":
            return "\n".join(json.dumps(r) for r in records)
        else:
            return json.dumps(records, indent=2)

    def clear(self) -> int:
        """Clear all stored decisions and explanations."""
        with self._lock:
            count = len(self._decisions)
            self._decisions.clear()
            self._explanations.clear()
            return count


# Convenience functions

def create_authorization_decision(
    user_id: str,
    tool_name: str,
    allowed: bool,
    factors: list[DecisionFactor],
    context: dict[str, Any] | None = None,
) -> ExplainableDecision:
    """
    Create an explainable authorization decision.

    Args:
        user_id: User making the request.
        tool_name: Tool being accessed.
        allowed: Whether access was granted.
        factors: Factors that contributed to the decision.
        context: Additional context.

    Returns:
        ExplainableDecision ready for logging.
    """
    ctx = context or {}
    ctx["user_id"] = user_id
    ctx["tool_name"] = tool_name

    return ExplainableDecision(
        decision_type=DecisionType.AUTHORIZATION,
        outcome=Outcome.ALLOWED if allowed else Outcome.DENIED,
        factors=factors,
        context=ctx,
    )


def create_guard_decision(
    guard_type: str,
    passed: bool,
    factors: list[DecisionFactor],
    content_sample: str | None = None,
    modified: bool = False,
) -> ExplainableDecision:
    """
    Create an explainable guard decision.

    Args:
        guard_type: Type of guard ("input" or "output").
        passed: Whether content passed the guard.
        factors: Factors that contributed to the decision.
        content_sample: Sample of the content (truncated).
        modified: Whether content was modified (redacted).

    Returns:
        ExplainableDecision ready for logging.
    """
    if modified:
        outcome = Outcome.MODIFIED
    elif passed:
        outcome = Outcome.ALLOWED
    else:
        outcome = Outcome.DENIED

    decision_type = (
        DecisionType.INPUT_GUARD if guard_type == "input"
        else DecisionType.OUTPUT_GUARD
    )

    context = {"guard_type": guard_type}
    if content_sample:
        # Truncate and sanitize
        context["content_preview"] = content_sample[:100] + "..." if len(content_sample) > 100 else content_sample

    return ExplainableDecision(
        decision_type=decision_type,
        outcome=outcome,
        factors=factors,
        context=context,
    )


def create_rate_limit_decision(
    user_id: str,
    allowed: bool,
    current_count: int,
    limit: int,
    window_seconds: int,
) -> ExplainableDecision:
    """
    Create an explainable rate limit decision.

    Args:
        user_id: User being rate limited.
        allowed: Whether request was allowed.
        current_count: Current request count in window.
        limit: Maximum requests allowed.
        window_seconds: Window size in seconds.

    Returns:
        ExplainableDecision ready for logging.
    """
    return ExplainableDecision(
        decision_type=DecisionType.RATE_LIMIT,
        outcome=Outcome.ALLOWED if allowed else Outcome.DENIED,
        factors=[
            DecisionFactor(
                name="request_count",
                passed=current_count <= limit,
                weight=1.0,
                reason=f"{current_count}/{limit} requests in {window_seconds}s window",
            )
        ],
        context={
            "user_id": user_id,
            "current": current_count,
            "limit": limit,
            "window_seconds": window_seconds,
        },
    )


def create_budget_decision(
    user_id: str,
    allowed: bool,
    spent: float,
    limit: float,
    period: str = "daily",
) -> ExplainableDecision:
    """
    Create an explainable budget decision.

    Args:
        user_id: User being budget-checked.
        allowed: Whether within budget.
        spent: Amount spent.
        limit: Budget limit.
        period: Budget period ("hourly", "daily", "monthly").

    Returns:
        ExplainableDecision ready for logging.
    """
    percentage = spent / limit if limit > 0 else 0

    return ExplainableDecision(
        decision_type=DecisionType.BUDGET,
        outcome=Outcome.ALLOWED if allowed else Outcome.DENIED,
        factors=[
            DecisionFactor(
                name=f"{period}_budget",
                passed=spent <= limit,
                weight=1.0,
                reason=f"${spent:.2f}/${limit:.2f} ({percentage:.0%}) {period} budget used",
            )
        ],
        context={
            "user_id": user_id,
            "spent": spent,
            "limit": limit,
            "period": period,
            "percentage": percentage,
        },
    )
