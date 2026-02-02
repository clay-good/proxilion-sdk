"""
Intent Capsule for Proxilion.

Addresses OWASP ASI01: Agent Goal Hijack.

This module provides cryptographic binding of the original user intent
to every execution cycle, making goal hijacking detectable.

The Intent Capsule pattern ensures that:
- The original user request is signed at creation
- Every tool call is validated against the original intent
- Mid-execution hijacking attempts are detected
- The agent cannot deviate from its mandate

Example:
    >>> from proxilion.security.intent_capsule import (
    ...     IntentCapsule,
    ...     IntentGuard,
    ...     IntentValidator,
    ... )
    >>>
    >>> # Create capsule from user request
    >>> capsule = IntentCapsule.create(
    ...     user_id="alice",
    ...     intent="Help me find documents about Python",
    ...     allowed_tools=["search_documents", "read_document"],
    ...     secret_key="your-secret",
    ... )
    >>>
    >>> # Validate each tool call against intent
    >>> guard = IntentGuard(capsule)
    >>>
    >>> if guard.validate_tool_call("search_documents", {"query": "Python"}):
    ...     result = search_documents(query="Python")
    ... else:
    ...     raise IntentHijackError("Tool call not aligned with intent")
    >>>
    >>> # Detect hijacking attempts
    >>> validator = IntentValidator()
    >>> is_hijack = validator.detect_hijack(
    ...     original_intent="Find documents",
    ...     current_action="Delete all files",
    ... )
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

from proxilion.exceptions import IntentHijackError

logger = logging.getLogger(__name__)


class IntentCategory(Enum):
    """Categories of user intent."""

    QUERY = "query"
    """Information retrieval (read-only)."""

    CREATE = "create"
    """Creating new resources."""

    UPDATE = "update"
    """Modifying existing resources."""

    DELETE = "delete"
    """Removing resources."""

    EXECUTE = "execute"
    """Running code or processes."""

    COMMUNICATE = "communicate"
    """Sending messages or notifications."""

    ANALYZE = "analyze"
    """Processing or analyzing data."""

    UNKNOWN = "unknown"
    """Unable to categorize."""


@dataclass
class IntentCapsule:
    """
    Cryptographically signed container for user intent.

    The capsule binds the original intent to a specific execution
    context, making it impossible for the agent to deviate without
    detection.
    """

    capsule_id: str
    user_id: str
    intent: str
    intent_category: IntentCategory
    allowed_tools: set[str]
    allowed_actions: set[str]
    constraints: dict[str, Any]
    created_at: datetime
    expires_at: datetime
    signature: str
    metadata: dict[str, Any] = field(default_factory=dict)

    # Execution tracking
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    _max_tool_calls: int = 100

    def is_expired(self) -> bool:
        """Check if capsule has expired."""
        return datetime.now(timezone.utc) > self.expires_at

    def is_tool_allowed(self, tool_name: str) -> bool:
        """Check if a tool is allowed by this capsule."""
        if "*" in self.allowed_tools:
            return True
        if tool_name in self.allowed_tools:
            return True
        # Pattern matching (e.g., "read_*")
        for pattern in self.allowed_tools:
            if "*" in pattern:
                regex = pattern.replace("*", ".*")
                if re.match(f"^{regex}$", tool_name):
                    return True
        return False

    def is_action_allowed(self, action: str) -> bool:
        """Check if an action is allowed by this capsule."""
        if "*" in self.allowed_actions:
            return True
        return action in self.allowed_actions

    def record_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        result: Any = None,
    ) -> None:
        """Record a tool call for tracking."""
        if len(self.tool_calls) >= self._max_tool_calls:
            # Remove oldest to prevent unbounded growth
            self.tool_calls = self.tool_calls[-self._max_tool_calls + 1:]

        self.tool_calls.append({
            "tool_name": tool_name,
            "arguments": arguments,
            "result_type": type(result).__name__ if result else None,
            "timestamp": time.time(),
        })

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "capsule_id": self.capsule_id,
            "user_id": self.user_id,
            "intent": self.intent,
            "intent_category": self.intent_category.value,
            "allowed_tools": list(self.allowed_tools),
            "allowed_actions": list(self.allowed_actions),
            "constraints": self.constraints,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "signature": self.signature,
            "metadata": self.metadata,
            "tool_call_count": len(self.tool_calls),
        }

    @classmethod
    def create(
        cls,
        user_id: str,
        intent: str,
        secret_key: str | bytes,
        allowed_tools: set[str] | list[str] | None = None,
        allowed_actions: set[str] | list[str] | None = None,
        constraints: dict[str, Any] | None = None,
        ttl_seconds: int = 3600,
        metadata: dict[str, Any] | None = None,
        intent_category: IntentCategory | None = None,
    ) -> IntentCapsule:
        """
        Create a new intent capsule.

        Args:
            user_id: ID of the user making the request.
            intent: Natural language description of user intent.
            secret_key: Secret key for signing.
            allowed_tools: Tools allowed for this intent.
            allowed_actions: Actions allowed (read, write, delete, etc.).
            constraints: Additional constraints (max_results, allowed_paths, etc.).
            ttl_seconds: Time-to-live for the capsule.
            metadata: Optional metadata.
            intent_category: Category of intent (auto-detected if not provided).

        Returns:
            Signed IntentCapsule.
        """
        if isinstance(secret_key, str):
            secret_key = secret_key.encode()

        capsule_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=ttl_seconds)

        # Normalize sets
        if allowed_tools is None:
            allowed_tools = set()
        elif isinstance(allowed_tools, list):
            allowed_tools = set(allowed_tools)

        if allowed_actions is None:
            allowed_actions = set()
        elif isinstance(allowed_actions, list):
            allowed_actions = set(allowed_actions)

        # Auto-detect category if not provided
        if intent_category is None:
            intent_category = cls._detect_intent_category(intent)

        # Create signature
        sig_data = (
            f"{capsule_id}|{user_id}|{intent}|{intent_category.value}|"
            f"{sorted(allowed_tools)}|{sorted(allowed_actions)}|"
            f"{json.dumps(constraints or {}, sort_keys=True)}|{now.isoformat()}"
        )
        signature = hmac.new(
            secret_key,
            sig_data.encode(),
            hashlib.sha256,
        ).hexdigest()

        return cls(
            capsule_id=capsule_id,
            user_id=user_id,
            intent=intent,
            intent_category=intent_category,
            allowed_tools=allowed_tools,
            allowed_actions=allowed_actions,
            constraints=constraints or {},
            created_at=now,
            expires_at=expires_at,
            signature=signature,
            metadata=metadata or {},
        )

    @staticmethod
    def _detect_intent_category(intent: str) -> IntentCategory:
        """Auto-detect intent category from natural language."""
        intent_lower = intent.lower()

        # Delete patterns
        if any(word in intent_lower for word in [
            "delete", "remove", "destroy", "erase", "drop", "clear"
        ]):
            return IntentCategory.DELETE

        # Create patterns
        if any(word in intent_lower for word in [
            "create", "make", "generate", "build", "add", "new", "write"
        ]):
            return IntentCategory.CREATE

        # Update patterns
        if any(word in intent_lower for word in [
            "update", "modify", "change", "edit", "fix", "correct"
        ]):
            return IntentCategory.UPDATE

        # Execute patterns
        if any(word in intent_lower for word in [
            "run", "execute", "start", "launch", "deploy", "install"
        ]):
            return IntentCategory.EXECUTE

        # Communicate patterns
        if any(word in intent_lower for word in [
            "send", "email", "message", "notify", "alert", "share"
        ]):
            return IntentCategory.COMMUNICATE

        # Analyze patterns
        if any(word in intent_lower for word in [
            "analyze", "process", "calculate", "compute", "summarize"
        ]):
            return IntentCategory.ANALYZE

        # Query patterns (most common, check last)
        if any(word in intent_lower for word in [
            "find", "search", "get", "show", "list", "display", "fetch",
            "what", "where", "when", "who", "how", "help", "tell"
        ]):
            return IntentCategory.QUERY

        return IntentCategory.UNKNOWN

    def verify(self, secret_key: str | bytes) -> bool:
        """Verify the capsule signature."""
        if isinstance(secret_key, str):
            secret_key = secret_key.encode()

        sig_data = (
            f"{self.capsule_id}|{self.user_id}|{self.intent}|{self.intent_category.value}|"
            f"{sorted(self.allowed_tools)}|{sorted(self.allowed_actions)}|"
            f"{json.dumps(self.constraints, sort_keys=True)}|{self.created_at.isoformat()}"
        )
        expected_sig = hmac.new(
            secret_key,
            sig_data.encode(),
            hashlib.sha256,
        ).hexdigest()

        return hmac.compare_digest(expected_sig, self.signature)


# Hijacking detection patterns
HIJACK_PATTERNS: list[tuple[str, str, float]] = [
    # (pattern, description, severity)
    (r"(?i)ignore\s+(all\s+)?(previous|prior|original)\s+(intent|instructions?|goals?)",
     "Intent override attempt", 0.95),
    (r"(?i)new\s+(goal|objective|task|mission)\s*:",
     "Goal replacement attempt", 0.9),
    (r"(?i)forget\s+(your|the)\s+(original|primary|main)\s+(purpose|goal|task)",
     "Purpose erasure attempt", 0.9),
    (r"(?i)your\s+(real|true|actual)\s+(purpose|goal|mission)\s+is",
     "False purpose injection", 0.95),
    (r"(?i)override\s+(priority|directive|command)",
     "Priority override attempt", 0.85),
    (r"(?i)emergency\s+(override|protocol|mode)",
     "Emergency bypass attempt", 0.8),
    (r"(?i)admin(istrator)?\s+(mode|override|access)",
     "Admin escalation attempt", 0.85),
    (r"(?i)disregard\s+(user|original)\s+(request|intent)",
     "Disregard user intent", 0.9),
]


@dataclass
class HijackDetection:
    """Result of hijack detection analysis."""

    is_hijack: bool
    confidence: float
    original_intent: str
    detected_action: str
    matched_patterns: list[str] = field(default_factory=list)
    reasoning: str = ""


class IntentValidator:
    """
    Validates that current actions align with original intent.

    Uses pattern matching and semantic analysis to detect
    when an agent's behavior deviates from the user's intent.
    """

    def __init__(
        self,
        custom_patterns: list[tuple[str, str, float]] | None = None,
        semantic_threshold: float = 0.5,
    ) -> None:
        """
        Initialize the validator.

        Args:
            custom_patterns: Additional hijack patterns.
            semantic_threshold: Threshold for semantic similarity (0-1).
        """
        self._patterns: list[tuple[re.Pattern[str], str, float]] = []
        for pattern, desc, severity in HIJACK_PATTERNS:
            self._patterns.append((re.compile(pattern), desc, severity))

        if custom_patterns:
            for pattern, desc, severity in custom_patterns:
                self._patterns.append((re.compile(pattern), desc, severity))

        self._semantic_threshold = semantic_threshold

    def detect_hijack(
        self,
        original_intent: str,
        current_action: str,
        tool_name: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> HijackDetection:
        """
        Detect if current action represents a goal hijack.

        Args:
            original_intent: The original user intent.
            current_action: What the agent is currently doing/planning.
            tool_name: Optional tool being called.
            context: Optional additional context.

        Returns:
            HijackDetection with analysis results.
        """
        matched_patterns: list[str] = []
        max_severity = 0.0

        # Check for explicit hijack patterns in current action
        for pattern, description, severity in self._patterns:
            if pattern.search(current_action):
                matched_patterns.append(description)
                max_severity = max(max_severity, severity)

        # Check for category mismatch
        category_mismatch = self._check_category_mismatch(
            original_intent, current_action, tool_name
        )
        if category_mismatch:
            matched_patterns.append(category_mismatch)
            max_severity = max(max_severity, 0.7)

        # Build reasoning
        if matched_patterns:
            reasoning = f"Detected patterns: {', '.join(matched_patterns)}"
        else:
            reasoning = "No hijacking patterns detected"

        is_hijack = max_severity >= self._semantic_threshold

        return HijackDetection(
            is_hijack=is_hijack,
            confidence=max_severity,
            original_intent=original_intent,
            detected_action=current_action,
            matched_patterns=matched_patterns,
            reasoning=reasoning,
        )

    def _check_category_mismatch(
        self,
        original_intent: str,
        current_action: str,
        tool_name: str | None,
    ) -> str | None:
        """Check for intent category mismatch."""
        original_category = IntentCapsule._detect_intent_category(original_intent)
        action_category = IntentCapsule._detect_intent_category(current_action)

        # Dangerous category escalations
        dangerous_transitions = {
            (IntentCategory.QUERY, IntentCategory.DELETE): "Read intent escalated to delete",
            (IntentCategory.QUERY, IntentCategory.EXECUTE): "Read intent escalated to execute",
            (IntentCategory.ANALYZE, IntentCategory.DELETE): "Analyze intent escalated to delete",
            (IntentCategory.ANALYZE, IntentCategory.EXECUTE): "Analyze intent escalated to execute",
        }

        transition = (original_category, action_category)
        return dangerous_transitions.get(transition)


class IntentGuard:
    """
    Guards agent execution against intent violations.

    Wraps an IntentCapsule and validates each action against
    the original intent before allowing execution.

    Example:
        >>> capsule = IntentCapsule.create(
        ...     user_id="alice",
        ...     intent="Search for documents",
        ...     secret_key="secret",
        ...     allowed_tools=["search"],
        ... )
        >>> guard = IntentGuard(capsule)
        >>>
        >>> # This will pass
        >>> guard.validate_tool_call("search", {"query": "python"})
        >>>
        >>> # This will fail
        >>> guard.validate_tool_call("delete_all", {})
    """

    def __init__(
        self,
        capsule: IntentCapsule,
        secret_key: str | bytes | None = None,
        validator: IntentValidator | None = None,
        strict_mode: bool = False,
    ) -> None:
        """
        Initialize the guard.

        Args:
            capsule: The intent capsule to guard.
            secret_key: Secret key for capsule verification.
            validator: Custom intent validator.
            strict_mode: If True, raise exceptions on violations.
        """
        self._capsule = capsule
        self._secret_key = secret_key
        self._validator = validator or IntentValidator()
        self._strict_mode = strict_mode
        self._lock = threading.RLock()

        # Verify capsule if key provided
        if secret_key:
            if not capsule.verify(secret_key):
                raise IntentHijackError(
                    original_intent=capsule.intent,
                    detected_intent="Capsule signature verification failed",
                    confidence=1.0,
                )

    @property
    def capsule(self) -> IntentCapsule:
        """Get the protected capsule."""
        return self._capsule

    def validate_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        description: str | None = None,
    ) -> bool:
        """
        Validate a tool call against the intent.

        Args:
            tool_name: Name of the tool being called.
            arguments: Tool arguments.
            description: Optional description of what the call does.

        Returns:
            True if the call is allowed.

        Raises:
            IntentHijackError: If strict_mode and violation detected.
        """
        with self._lock:
            # Check expiration
            if self._capsule.is_expired():
                return self._handle_violation(
                    "Intent capsule has expired",
                    0.9,
                )

            # Check tool is allowed
            if not self._capsule.is_tool_allowed(tool_name):
                return self._handle_violation(
                    f"Tool '{tool_name}' not allowed by intent",
                    0.8,
                )

            # Check for hijacking patterns if description provided
            if description:
                detection = self._validator.detect_hijack(
                    original_intent=self._capsule.intent,
                    current_action=description,
                    tool_name=tool_name,
                )
                if detection.is_hijack:
                    return self._handle_violation(
                        detection.reasoning,
                        detection.confidence,
                    )

            # Check constraints
            constraint_violation = self._check_constraints(tool_name, arguments)
            if constraint_violation:
                return self._handle_violation(
                    constraint_violation,
                    0.7,
                )

            # Record the call
            self._capsule.record_tool_call(tool_name, arguments)

            return True

    def _check_constraints(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> str | None:
        """Check if tool call violates constraints."""
        constraints = self._capsule.constraints

        # Check max results
        if "max_results" in constraints:
            limit = arguments.get("limit") or arguments.get("max_results")
            if limit and limit > constraints["max_results"]:
                return f"Result limit {limit} exceeds max {constraints['max_results']}"

        # Check allowed paths
        if "allowed_paths" in constraints:
            path = arguments.get("path") or arguments.get("file_path")
            if path:
                allowed = constraints["allowed_paths"]
                if not any(path.startswith(p) for p in allowed):
                    return f"Path '{path}' not in allowed paths"

        # Check forbidden arguments
        if "forbidden_args" in constraints:
            forbidden = constraints["forbidden_args"]
            for key in arguments:
                if key in forbidden:
                    return f"Argument '{key}' is forbidden"

        # Check resource limits
        if "max_tool_calls" in constraints:
            if len(self._capsule.tool_calls) >= constraints["max_tool_calls"]:
                return f"Exceeded max tool calls ({constraints['max_tool_calls']})"

        return None

    def _handle_violation(self, reason: str, confidence: float) -> bool:
        """Handle an intent violation."""
        logger.warning(f"Intent violation: {reason} (confidence: {confidence:.1%})")

        if self._strict_mode:
            raise IntentHijackError(
                original_intent=self._capsule.intent,
                detected_intent=reason,
                confidence=confidence,
            )

        return False

    def get_allowed_tools(self) -> set[str]:
        """Get the set of allowed tools."""
        return self._capsule.allowed_tools.copy()

    def get_intent_summary(self) -> dict[str, Any]:
        """Get a summary of the guarded intent."""
        return {
            "intent": self._capsule.intent,
            "category": self._capsule.intent_category.value,
            "allowed_tools": list(self._capsule.allowed_tools),
            "tool_calls_made": len(self._capsule.tool_calls),
            "expires_in_seconds": max(
                0,
                (self._capsule.expires_at - datetime.now(timezone.utc)).total_seconds()
            ),
        }


class IntentCapsuleManager:
    """
    Manages intent capsules for multiple sessions.

    Provides centralized management of intent capsules with
    automatic expiration and cleanup.
    """

    def __init__(
        self,
        secret_key: str | bytes,
        default_ttl: int = 3600,
        max_capsules: int = 10000,
    ) -> None:
        """
        Initialize the manager.

        Args:
            secret_key: Master secret key for signing capsules.
            default_ttl: Default TTL for capsules.
            max_capsules: Maximum capsules to track.
        """
        if isinstance(secret_key, str):
            secret_key = secret_key.encode()

        self._secret_key = secret_key
        self._default_ttl = default_ttl
        self._max_capsules = max_capsules

        self._capsules: dict[str, IntentCapsule] = {}
        self._user_capsules: dict[str, list[str]] = {}  # user_id -> capsule_ids
        self._lock = threading.RLock()

    def create_capsule(
        self,
        user_id: str,
        intent: str,
        allowed_tools: set[str] | list[str] | None = None,
        allowed_actions: set[str] | list[str] | None = None,
        constraints: dict[str, Any] | None = None,
        ttl_seconds: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> IntentCapsule:
        """
        Create and register a new intent capsule.

        Args:
            user_id: ID of the user.
            intent: User's intent.
            allowed_tools: Tools allowed for this intent.
            allowed_actions: Actions allowed.
            constraints: Additional constraints.
            ttl_seconds: Time-to-live.
            metadata: Optional metadata.

        Returns:
            The created IntentCapsule.
        """
        capsule = IntentCapsule.create(
            user_id=user_id,
            intent=intent,
            secret_key=self._secret_key,
            allowed_tools=allowed_tools,
            allowed_actions=allowed_actions,
            constraints=constraints,
            ttl_seconds=ttl_seconds or self._default_ttl,
            metadata=metadata,
        )

        with self._lock:
            # Cleanup if at capacity
            if len(self._capsules) >= self._max_capsules:
                self._cleanup_expired()

            self._capsules[capsule.capsule_id] = capsule

            if user_id not in self._user_capsules:
                self._user_capsules[user_id] = []
            self._user_capsules[user_id].append(capsule.capsule_id)

        logger.debug(f"Created intent capsule: {capsule.capsule_id} for user {user_id}")
        return capsule

    def get_capsule(self, capsule_id: str) -> IntentCapsule | None:
        """Get a capsule by ID."""
        with self._lock:
            capsule = self._capsules.get(capsule_id)
            if capsule and capsule.is_expired():
                del self._capsules[capsule_id]
                return None
            return capsule

    def get_user_capsules(self, user_id: str) -> list[IntentCapsule]:
        """Get all active capsules for a user."""
        with self._lock:
            capsule_ids = self._user_capsules.get(user_id, [])
            capsules = []
            for cid in capsule_ids:
                capsule = self._capsules.get(cid)
                if capsule and not capsule.is_expired():
                    capsules.append(capsule)
            return capsules

    def revoke_capsule(self, capsule_id: str) -> bool:
        """Revoke a capsule."""
        with self._lock:
            if capsule_id in self._capsules:
                capsule = self._capsules[capsule_id]
                del self._capsules[capsule_id]

                # Remove from user's list
                user_ids = list(self._user_capsules.keys())
                for uid in user_ids:
                    if capsule_id in self._user_capsules[uid]:
                        self._user_capsules[uid].remove(capsule_id)

                logger.info(f"Revoked capsule: {capsule_id}")
                return True
            return False

    def verify_capsule(self, capsule_id: str) -> bool:
        """Verify a capsule's signature."""
        with self._lock:
            capsule = self._capsules.get(capsule_id)
            if not capsule:
                return False
            return capsule.verify(self._secret_key)

    def create_guard(
        self,
        capsule_id: str,
        strict_mode: bool = False,
    ) -> IntentGuard | None:
        """
        Create a guard for a capsule.

        Args:
            capsule_id: ID of the capsule.
            strict_mode: If True, guard raises exceptions on violations.

        Returns:
            IntentGuard for the capsule, or None if not found.
        """
        capsule = self.get_capsule(capsule_id)
        if not capsule:
            return None

        return IntentGuard(
            capsule=capsule,
            secret_key=self._secret_key,
            strict_mode=strict_mode,
        )

    def _cleanup_expired(self) -> int:
        """Clean up expired capsules."""
        now = datetime.now(timezone.utc)
        expired = [
            cid for cid, capsule in self._capsules.items()
            if capsule.expires_at < now
        ]

        for cid in expired:
            del self._capsules[cid]

        # Clean up user mappings
        for uid in list(self._user_capsules.keys()):
            self._user_capsules[uid] = [
                cid for cid in self._user_capsules[uid]
                if cid in self._capsules
            ]
            if not self._user_capsules[uid]:
                del self._user_capsules[uid]

        return len(expired)

    def get_stats(self) -> dict[str, Any]:
        """Get manager statistics."""
        with self._lock:
            return {
                "total_capsules": len(self._capsules),
                "total_users": len(self._user_capsules),
                "max_capsules": self._max_capsules,
            }


# Convenience exports
__all__ = [
    # Core classes
    "IntentCapsule",
    "IntentGuard",
    "IntentValidator",
    "IntentCapsuleManager",
    # Data classes
    "HijackDetection",
    "IntentCategory",
    # Patterns
    "HIJACK_PATTERNS",
]
