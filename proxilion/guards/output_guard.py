"""
Output guard for detecting sensitive data leakage.

Provides pattern-based detection of credentials, API keys, private keys,
internal paths, and other sensitive information that may leak through
LLM outputs.

Example:
    >>> from proxilion.guards import OutputGuard
    >>>
    >>> guard = OutputGuard()
    >>>
    >>> # Check for leakage
    >>> result = guard.check("The API key is sk-abc123...")
    >>> if not result.passed:
    ...     print(f"Leakage detected: {result.matched_patterns}")
    >>>
    >>> # Redact sensitive data
    >>> safe_output = guard.redact("Bearer token: eyJhbGc...")
    >>> print(safe_output)  # "Bearer token: [REDACTED]"
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from proxilion.guards.input_guard import GuardAction, GuardResult

logger = logging.getLogger(__name__)


class LeakageCategory(Enum):
    """Category of data leakage."""

    CREDENTIAL = "credential"
    """API keys, passwords, tokens."""

    INTERNAL = "internal"
    """Internal paths, URLs, infrastructure details."""

    SYSTEM_PROMPT = "system_prompt"
    """Leakage of system prompt or instructions."""

    PII = "pii"
    """Personally identifiable information."""

    FINANCIAL = "financial"
    """Credit card numbers, bank accounts."""

    INFRASTRUCTURE = "infrastructure"
    """Internal hostnames, IP addresses, database names."""


@dataclass
class LeakagePattern:
    """
    Pattern for detecting sensitive data leakage.

    Attributes:
        name: Unique identifier for the pattern.
        pattern: Regex pattern string.
        category: Category of data this detects.
        severity: Severity score from 0.0 to 1.0.
        description: Human-readable description.
        redaction: Text to replace matches with.
    """

    name: str
    pattern: str
    category: LeakageCategory
    severity: float = 0.8
    description: str = ""
    redaction: str = "[REDACTED]"
    _compiled: re.Pattern[str] | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Compile the regex pattern."""
        if self._compiled is None:
            try:
                self._compiled = re.compile(self.pattern, re.IGNORECASE | re.MULTILINE)
            except re.error as e:
                logger.error(f"Invalid regex pattern for {self.name}: {e}")
                raise ValueError(f"Invalid regex pattern for {self.name}: {e}") from e

    @property
    def compiled(self) -> re.Pattern[str]:
        """Get the compiled regex pattern."""
        if self._compiled is None:
            self._compiled = re.compile(self.pattern, re.IGNORECASE | re.MULTILINE)
        return self._compiled

    def match(self, text: str) -> list[re.Match[str]]:
        """Find all matches of this pattern in text."""
        return list(self.compiled.finditer(text))


@dataclass
class OutputFilter:
    """
    Custom filter for output validation.

    Allows for custom validation logic beyond regex patterns.

    Attributes:
        name: Unique identifier for the filter.
        check_func: Function that returns True if output is safe.
        action: Action to take if filter fails.
        description: Human-readable description.
    """

    name: str
    check_func: Callable[[str, dict[str, Any] | None], bool]
    action: GuardAction = GuardAction.WARN
    description: str = ""


# Built-in leakage patterns
DEFAULT_LEAKAGE_PATTERNS: list[LeakagePattern] = [
    # API Keys and Tokens
    LeakagePattern(
        name="api_key_generic",
        pattern=r"(?i)(api[_-]?key|apikey|api_secret|api_token)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})['\"]?",
        category=LeakageCategory.CREDENTIAL,
        severity=0.95,
        description="Generic API key patterns",
        redaction="[API_KEY_REDACTED]",
    ),
    LeakagePattern(
        name="bearer_token",
        pattern=r"(?i)bearer\s+([a-zA-Z0-9_\-\.]+\.[a-zA-Z0-9_\-\.]+\.[a-zA-Z0-9_\-\.]+)",
        category=LeakageCategory.CREDENTIAL,
        severity=0.95,
        description="Bearer authentication tokens (JWT)",
        redaction="Bearer [TOKEN_REDACTED]",
    ),
    LeakagePattern(
        name="openai_key",
        pattern=r"sk-(?:proj-)?[a-zA-Z0-9\-_]{20,}",
        category=LeakageCategory.CREDENTIAL,
        severity=0.95,
        description="OpenAI API keys (including project keys)",
        redaction="[OPENAI_KEY_REDACTED]",
    ),
    LeakagePattern(
        name="anthropic_key",
        pattern=r"sk-ant-[a-zA-Z0-9\-]{20,}",
        category=LeakageCategory.CREDENTIAL,
        severity=0.95,
        description="Anthropic API keys",
        redaction="[ANTHROPIC_KEY_REDACTED]",
    ),
    LeakagePattern(
        name="aws_key",
        pattern=r"(?i)(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}",
        category=LeakageCategory.CREDENTIAL,
        severity=0.95,
        description="AWS access key IDs",
        redaction="[AWS_KEY_REDACTED]",
    ),
    LeakagePattern(
        name="aws_secret",
        pattern=r"(?i)(aws_secret_access_key|aws_secret)\s*[:=]\s*['\"]?([a-zA-Z0-9/+=]{40})['\"]?",
        category=LeakageCategory.CREDENTIAL,
        severity=0.95,
        description="AWS secret access keys",
        redaction="[AWS_SECRET_REDACTED]",
    ),
    LeakagePattern(
        name="gcp_key",
        pattern=r"(?i)(gcp|google)[_-]?(api[_-]?key|key)\s*[:=]\s*['\"]?AIza[a-zA-Z0-9_\-]{35}['\"]?",
        category=LeakageCategory.CREDENTIAL,
        severity=0.95,
        description="Google Cloud API keys",
        redaction="[GCP_KEY_REDACTED]",
    ),
    LeakagePattern(
        name="azure_key",
        pattern=r"(?i)(azure|az)[_-]?(storage|account)[_-]?key\s*[:=]\s*['\"]?[a-zA-Z0-9/+=]{88}['\"]?",
        category=LeakageCategory.CREDENTIAL,
        severity=0.95,
        description="Azure storage keys",
        redaction="[AZURE_KEY_REDACTED]",
    ),
    LeakagePattern(
        name="github_token",
        pattern=r"(ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,}",
        category=LeakageCategory.CREDENTIAL,
        severity=0.95,
        description="GitHub personal access tokens",
        redaction="[GITHUB_TOKEN_REDACTED]",
    ),
    LeakagePattern(
        name="slack_token",
        pattern=r"xox[baprs]-[0-9a-zA-Z\-]{10,}",
        category=LeakageCategory.CREDENTIAL,
        severity=0.9,
        description="Slack API tokens",
        redaction="[SLACK_TOKEN_REDACTED]",
    ),

    # Private Keys
    LeakagePattern(
        name="private_key",
        pattern=r"-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----",
        category=LeakageCategory.CREDENTIAL,
        severity=0.99,
        description="Private key headers",
        redaction="[PRIVATE_KEY_REDACTED]",
    ),

    # Connection Strings
    LeakagePattern(
        name="connection_string_mongodb",
        pattern=r"mongodb(\+srv)?:\/\/[^:]+:[^@]+@[^\s]+",
        category=LeakageCategory.CREDENTIAL,
        severity=0.95,
        description="MongoDB connection strings with credentials",
        redaction="[MONGODB_CONN_REDACTED]",
    ),
    LeakagePattern(
        name="connection_string_postgres",
        pattern=r"postgres(ql)?:\/\/[^:]+:[^@]+@[^\s]+",
        category=LeakageCategory.CREDENTIAL,
        severity=0.95,
        description="PostgreSQL connection strings with credentials",
        redaction="[POSTGRES_CONN_REDACTED]",
    ),
    LeakagePattern(
        name="connection_string_mysql",
        pattern=r"mysql:\/\/[^:]+:[^@]+@[^\s]+",
        category=LeakageCategory.CREDENTIAL,
        severity=0.95,
        description="MySQL connection strings with credentials",
        redaction="[MYSQL_CONN_REDACTED]",
    ),
    LeakagePattern(
        name="connection_string_redis",
        pattern=r"redis(s)?:\/\/[^:]*:[^@]+@[^\s]+",
        category=LeakageCategory.CREDENTIAL,
        severity=0.95,
        description="Redis connection strings with credentials",
        redaction="[REDIS_CONN_REDACTED]",
    ),

    # Internal Paths
    LeakagePattern(
        name="internal_path_unix",
        pattern=r"(?i)(\/home\/[a-zA-Z0-9_\-]+|\/Users\/[a-zA-Z0-9_\-]+|\/var\/[a-zA-Z0-9_\-\/]+|\/etc\/[a-zA-Z0-9_\-\/]+|\/opt\/[a-zA-Z0-9_\-\/]+)\/[^\s]*",
        category=LeakageCategory.INTERNAL,
        severity=0.6,
        description="Unix internal paths",
        redaction="[PATH_REDACTED]",
    ),
    LeakagePattern(
        name="internal_path_windows",
        pattern=r"(?i)C:\\Users\\[a-zA-Z0-9_\-]+\\[^\s]*",
        category=LeakageCategory.INTERNAL,
        severity=0.6,
        description="Windows user paths",
        redaction="[PATH_REDACTED]",
    ),

    # System Prompt Leakage
    LeakagePattern(
        name="system_prompt_leak",
        pattern=r"(?i)(my\s+instructions\s+are|i\s+was\s+told\s+to|my\s+system\s+prompt|my\s+initial\s+instructions|i\s+am\s+programmed\s+to|my\s+guidelines\s+state)",
        category=LeakageCategory.SYSTEM_PROMPT,
        severity=0.85,
        description="Indicators of system prompt disclosure",
        redaction="[SYSTEM_PROMPT_CONTENT_REDACTED]",
    ),
    LeakagePattern(
        name="system_prompt_markers",
        pattern=r"(?i)(<<SYS>>|<\|system\|>|\[SYSTEM\]|###\s*System)",
        category=LeakageCategory.SYSTEM_PROMPT,
        severity=0.9,
        description="System prompt formatting markers",
        redaction="[SYSTEM_MARKER_REDACTED]",
    ),

    # PII Patterns
    LeakagePattern(
        name="email_address",
        pattern=r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        category=LeakageCategory.PII,
        severity=0.5,
        description="Email addresses",
        redaction="[EMAIL_REDACTED]",
    ),
    LeakagePattern(
        name="phone_number",
        pattern=r"(?i)(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}",
        category=LeakageCategory.PII,
        severity=0.5,
        description="Phone numbers (US format)",
        redaction="[PHONE_REDACTED]",
    ),
    LeakagePattern(
        name="ssn",
        pattern=r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b",
        category=LeakageCategory.PII,
        severity=0.9,
        description="Social Security Numbers",
        redaction="[SSN_REDACTED]",
    ),

    # Financial
    LeakagePattern(
        name="credit_card",
        pattern=r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9][0-9])[0-9]{12})\b",
        category=LeakageCategory.FINANCIAL,
        severity=0.95,
        description="Credit card numbers (Visa, MC, Amex, Discover)",
        redaction="[CARD_REDACTED]",
    ),

    # Infrastructure
    LeakagePattern(
        name="internal_ip",
        pattern=r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
        category=LeakageCategory.INFRASTRUCTURE,
        severity=0.6,
        description="Internal/private IP addresses",
        redaction="[INTERNAL_IP_REDACTED]",
    ),
    LeakagePattern(
        name="password_in_text",
        pattern=r"(?i)(password|passwd|pwd)\s*(?:is\s*)?[:=]\s*['\"]?[^\s'\"]{4,}['\"]?",
        category=LeakageCategory.CREDENTIAL,
        severity=0.9,
        description="Passwords in plaintext",
        redaction="[PASSWORD_REDACTED]",
    ),
]


class OutputGuard:
    """
    Guard for detecting sensitive data leakage in LLM outputs.

    Uses pattern matching to detect credentials, API keys, internal paths,
    and other sensitive information that may leak through model outputs.

    Example:
        >>> guard = OutputGuard()
        >>>
        >>> # Check output
        >>> result = guard.check("The API key is sk-abc123def456...")
        >>> if not result.passed:
        ...     print(f"Leakage: {result.matched_patterns}")
        >>>
        >>> # Redact sensitive data
        >>> safe = guard.redact("Connection: mongodb://user:pass@host")
        >>> print(safe)  # Connection: [MONGODB_CONN_REDACTED]

    Attributes:
        patterns: List of leakage patterns to check.
        filters: List of custom output filters.
        action: Default action on violations.
        threshold: Risk score threshold.
    """

    def __init__(
        self,
        patterns: list[LeakagePattern] | None = None,
        filters: list[OutputFilter] | None = None,
        action: GuardAction = GuardAction.WARN,
        threshold: float = 0.5,
        enable_pii: bool = False,
    ) -> None:
        """
        Initialize the output guard.

        Args:
            patterns: Custom patterns (uses defaults if None).
            filters: Custom output filters.
            action: Action to take when threshold is exceeded.
            threshold: Risk score threshold (0.0 to 1.0).
            enable_pii: Whether to enable PII detection patterns.
        """
        if patterns is not None:
            self.patterns = patterns
        else:
            # Filter out PII patterns if not enabled
            self.patterns = [
                p for p in DEFAULT_LEAKAGE_PATTERNS
                if enable_pii or p.category != LeakageCategory.PII
            ]

        self.filters = filters or []
        self.action = action
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("Threshold must be between 0.0 and 1.0")
        self.threshold = threshold
        self._pattern_index: dict[str, LeakagePattern] = {p.name: p for p in self.patterns}

    def add_pattern(self, pattern: LeakagePattern) -> None:
        """
        Add a custom leakage pattern.

        Args:
            pattern: The pattern to add.
        """
        self.patterns.append(pattern)
        self._pattern_index[pattern.name] = pattern

    def remove_pattern(self, name: str) -> bool:
        """
        Remove a pattern by name.

        Args:
            name: The pattern name to remove.

        Returns:
            True if pattern was removed, False if not found.
        """
        if name in self._pattern_index:
            pattern = self._pattern_index.pop(name)
            self.patterns.remove(pattern)
            return True
        return False

    def add_filter(self, filter_: OutputFilter) -> None:
        """
        Add a custom output filter.

        Args:
            filter_: The filter to add.
        """
        self.filters.append(filter_)

    def get_patterns(self) -> list[LeakagePattern]:
        """Get all registered patterns."""
        return list(self.patterns)

    def check(
        self,
        output_text: str,
        context: dict[str, Any] | None = None,
    ) -> GuardResult:
        """
        Check output text for sensitive data leakage.

        Args:
            output_text: The output to check.
            context: Optional context for evaluation.

        Returns:
            GuardResult with check outcome.
        """
        if not output_text:
            return GuardResult.allow()

        context = context or {}
        matched_patterns: list[str] = []
        all_matches: list[dict[str, Any]] = []
        severities: list[float] = []

        # Check each pattern
        for pattern in self.patterns:
            matches = pattern.match(output_text)
            if matches:
                matched_patterns.append(pattern.name)
                severities.append(pattern.severity)

                for match in matches:
                    all_matches.append({
                        "pattern": pattern.name,
                        "category": pattern.category.value,
                        "severity": pattern.severity,
                        "matched_text": self._truncate_match(match.group()),
                        "start": match.start(),
                        "end": match.end(),
                        "redaction": pattern.redaction,
                    })

        # Run custom filters
        filter_failures: list[str] = []
        for filter_ in self.filters:
            try:
                if not filter_.check_func(output_text, context):
                    filter_failures.append(filter_.name)
                    if filter_.action == GuardAction.BLOCK:
                        severities.append(1.0)
                    else:
                        severities.append(0.7)
            except Exception as e:
                # Fail-closed: treat filter exceptions as failures
                logger.error(f"Output filter {filter_.name} raised exception: {e}")
                filter_failures.append(filter_.name)
                severities.append(1.0)

        # Calculate risk score
        risk_score = self._calculate_risk_score(severities)

        # Determine if check passed
        passed = risk_score < self.threshold

        # Determine action
        action = GuardAction.ALLOW if passed else self.action

        # Log based on action
        if not passed:
            if action == GuardAction.WARN:
                logger.warning(
                    f"Output guard warning: risk_score={risk_score:.2f}, "
                    f"patterns={matched_patterns}, filters={filter_failures}"
                )
            elif action == GuardAction.BLOCK:
                logger.info(
                    f"Output guard blocked: risk_score={risk_score:.2f}, "
                    f"patterns={matched_patterns}, filters={filter_failures}"
                )

        return GuardResult(
            passed=passed,
            action=action,
            matched_patterns=matched_patterns + filter_failures,
            risk_score=risk_score,
            matches=all_matches,
            context={"output_length": len(output_text), **context},
        )

    def redact(
        self,
        output_text: str,
        categories: list[LeakageCategory] | None = None,
    ) -> str:
        """
        Redact sensitive data from output text.

        Args:
            output_text: Text to redact.
            categories: Categories to redact (all if None).

        Returns:
            Text with sensitive data redacted.
        """
        if not output_text:
            return output_text

        result = output_text

        for pattern in self.patterns:
            # Filter by category if specified
            if categories is not None and pattern.category not in categories:
                continue

            # Replace all matches with redaction text
            result = pattern.compiled.sub(pattern.redaction, result)

        return result

    def _calculate_risk_score(self, severities: list[float]) -> float:
        """
        Calculate overall risk score from matched pattern severities.

        Args:
            severities: List of severity scores from matches.

        Returns:
            Risk score between 0.0 and 1.0.
        """
        if not severities:
            return 0.0

        base_score = max(severities)
        bonus = 0.1 * (len(severities) - 1)
        return min(1.0, base_score + bonus)

    def _truncate_match(self, text: str, max_length: int = 20) -> str:
        """Truncate matched text for logging (avoid leaking in logs)."""
        if len(text) <= max_length:
            return text[:4] + "..." + text[-4:] if len(text) > 8 else "[...]"
        return text[:8] + "..." + text[-4:]

    def configure(
        self,
        action: GuardAction | None = None,
        threshold: float | None = None,
    ) -> None:
        """
        Update guard configuration.

        Args:
            action: New default action.
            threshold: New risk threshold.
        """
        if action is not None:
            self.action = action
        if threshold is not None:
            if not 0.0 <= threshold <= 1.0:
                raise ValueError("Threshold must be between 0.0 and 1.0")
            self.threshold = threshold


def create_output_guard(
    include_defaults: bool = True,
    custom_patterns: list[LeakagePattern] | None = None,
    enable_pii: bool = False,
    action: GuardAction = GuardAction.WARN,
    threshold: float = 0.5,
) -> OutputGuard:
    """
    Factory function to create an OutputGuard.

    Args:
        include_defaults: Whether to include default patterns.
        custom_patterns: Additional custom patterns.
        enable_pii: Whether to enable PII detection.
        action: Action to take on violations.
        threshold: Risk score threshold.

    Returns:
        Configured OutputGuard instance.
    """
    patterns: list[LeakagePattern] = []

    if include_defaults:
        default_patterns = [
            p for p in DEFAULT_LEAKAGE_PATTERNS
            if enable_pii or p.category != LeakageCategory.PII
        ]
        patterns.extend(default_patterns)

    if custom_patterns:
        patterns.extend(custom_patterns)

    return OutputGuard(
        patterns=patterns,
        action=action,
        threshold=threshold,
        enable_pii=enable_pii,
    )
