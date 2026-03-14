"""
Input and output guards for Proxilion.

This module provides runtime guardrails for detecting and blocking
malicious inputs and outputs in LLM tool call workflows.

Features:
- Prompt injection detection (pattern-based, zero-dependency)
- Output filtering for sensitive data leakage
- Configurable severity levels and actions

Example:
    >>> from proxilion.guards import InputGuard, OutputGuard, GuardAction
    >>>
    >>> # Create input guard with default patterns
    >>> input_guard = InputGuard(action=GuardAction.BLOCK)
    >>>
    >>> # Check input for injection attempts
    >>> result = input_guard.check("Ignore all previous instructions")
    >>> if not result.passed:
    ...     print(f"Blocked: {result.matched_patterns}")
    >>>
    >>> # Create output guard for leakage detection
    >>> output_guard = OutputGuard()
    >>> redacted = output_guard.redact("API key: sk-1234567890abcdef")
"""

from __future__ import annotations

from proxilion.guards.input_guard import (
    GuardAction,
    GuardResult,
    InjectionPattern,
    InputGuard,
    create_input_guard,
)
from proxilion.guards.output_guard import (
    LeakageCategory,
    LeakagePattern,
    OutputFilter,
    OutputGuard,
    create_output_guard,
)

__all__ = [
    # Input guard
    "InputGuard",
    "InjectionPattern",
    "GuardResult",
    "GuardAction",
    "create_input_guard",
    # Output guard
    "OutputGuard",
    "OutputFilter",
    "LeakagePattern",
    "LeakageCategory",
    "create_output_guard",
]
