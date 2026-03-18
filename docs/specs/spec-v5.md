# Proxilion SDK -- Production Readiness Spec v5

**Version:** 0.0.10 -> 0.0.11
**Date:** 2026-03-16
**Status:** READY FOR IMPLEMENTATION
**Previous spec:** docs/specs/spec-v4.md (0.0.9 -> 0.0.10, depends on spec-v4 completion)
**Depends on:** spec-v2 must be fully complete before this spec begins (spec-v3 and spec-v4 may be implemented in parallel after spec-v2)

---

## Executive Summary

This spec covers the sixth improvement cycle for the Proxilion SDK. It targets production-readiness defects discovered during a deep, line-by-line audit of all 89 Python source files, 2,541 collected tests (2,536 passed, 5 skipped), 53,999 source lines, and all prior spec files (spec.md through spec-v4.md). The previous five specs addressed critical bugs (spec.md), CI hardening and documentation (spec-v1), structured error context and developer experience (spec-v2), thread-safety stabilization with bounded collections (spec-v3), and security bypass vector closure with deployment guidance (spec-v4).

This cycle focuses on five pillars:

1. **Input validation hardening** -- closing gaps in UserContext, AgentContext, and ToolCallRequest field validation that allow empty or invalid data to propagate through the authorization pipeline unchecked.
2. **Secret key management enforcement** -- eliminating the three-file code duplication of secret key validation and upgrading placeholder key detection from a warning to a hard error.
3. **Exception safety discipline** -- making exception details immutable after creation, ensuring JSON serializability, and wiring structured context fields to all raise sites.
4. **Performance optimization** -- replacing per-check standard deviation recomputation with incremental statistics (Welford's algorithm), making rate limiter cleanup configurable, and moving cleanup off the hot path.
5. **Test coverage completion** -- adding Unicode normalization evasion tests, thread safety stress tests, decorator combination tests, rate limiter cleanup cycle tests, and an end-to-end authorization pipeline integration test.

Every item targets code that already exists. No net-new features are introduced. After this spec is complete, the SDK should pass a production security audit with confidence that all inputs are validated, all secrets are enforced, all exceptions are safe to serialize, all hot paths are optimized, and all security controls are tested against realistic evasion attempts.

---

## Codebase Snapshot (2026-03-16)

| Metric | Value |
|--------|-------|
| Python source files | 89 |
| Source lines (proxilion/) | 53,999 |
| Test files | 62+ |
| Test count | 2,541 collected, 2,536 passed, 5 skipped (OPA optional deps) |
| Python versions tested | 3.10, 3.11, 3.12, 3.13 |
| Ruff lint violations | 0 |
| Ruff format violations | 0 |
| Mypy errors | 5 (all in pydantic_schema.py, optional dep handling) |
| Version (pyproject.toml) | 0.0.7 |
| Version (__init__.py) | 0.0.7 |
| CI/CD | GitHub Actions (test, lint, typecheck, pip-audit) |
| Coverage threshold | 85% (enforced in CI) |
| Broad except Exception catches | 69 across 25 files |
| Spec-v2 progress | 6 of 18 steps complete |

---

## Logic Breakdown: Deterministic vs Probabilistic

Proxilion is explicitly designed to use deterministic logic for all security decisions. This breakdown quantifies the split across all 89 modules.

| Logic Type | Percentage | Module Count | Description |
|------------|-----------|--------------|-------------|
| Deterministic | ~97% | 86 of 89 | Regex pattern matching, set membership checks, SHA-256 hash chains, HMAC-SHA256 verification, token bucket counters, finite state machines, boolean policy evaluation, z-score threshold comparisons, path normalization via PurePosixPath, Merkle tree construction |
| Statistical (bounded, auditable) | ~3% | 3 of 89 | Token estimation heuristic in context/message_history.py (1.3 words/token ratio), risk score aggregation in guards (weighted sum of deterministic pattern matches), behavioral drift z-score thresholds (statistical but not ML -- same input always produces same output given same baseline) |

Zero LLM inference calls. Zero ML model evaluations. Zero non-deterministic random decisions in any security path. The three "statistical" modules use bounded arithmetic on deterministic inputs -- they are auditable and reproducible.

---

## Dependency Chain

This spec depends on the completion of spec-v2 (steps 7-18). Steps in this spec are ordered by dependency -- later steps may reference files modified by earlier steps. Within each priority tier, steps are independent and may be executed in parallel.

```
spec.md (0.0.4-0.0.5) COMPLETE
    |
spec-v1.md (0.0.6-0.0.7) COMPLETE
    |
spec-v2.md (0.0.7-0.0.8) IN PROGRESS (6/18)
    |
spec-v3.md (0.0.8-0.0.9) BLOCKED on spec-v2
    |
spec-v4.md (0.0.9-0.0.10) BLOCKED on spec-v3
    |
spec-v5.md (0.0.10-0.0.11) BLOCKED on spec-v2 (this document)
```

---

## Quick Install

```bash
# From PyPI
pip install proxilion

# With optional integrations
pip install proxilion[pydantic]     # Pydantic schema validation
pip install proxilion[casbin]       # Casbin policy engine
pip install proxilion[opa]          # Open Policy Agent
pip install proxilion[all]          # All optional dependencies

# Development (from source)
git clone https://github.com/clay-good/proxilion-sdk.git
cd proxilion-sdk
pip install -e ".[dev]"

# Verify installation
python3 -c "import proxilion; print(proxilion.__version__)"

# Run full CI check locally
python3 -m ruff check proxilion tests \
  && python3 -m ruff format --check proxilion tests \
  && python3 -m mypy proxilion \
  && python3 -m pytest -x -q
```

---

## Step 1 -- Extract Shared Secret Key Validation Utility

> **Priority:** HIGH
> **Estimated complexity:** Low
> **Files:** proxilion/security/_key_validation.py (new), proxilion/security/intent_capsule.py, proxilion/security/memory_integrity.py, proxilion/security/agent_trust.py

### Problem

The function `_validate_secret_key()` and the constant `_PLACEHOLDER_PATTERNS` are duplicated identically across three files: intent_capsule.py, memory_integrity.py, and agent_trust.py. Each copy contains the same minimum-length check (16 characters), the same placeholder pattern list ("your-", "changeme", "example", "placeholder", "secret-key", "TODO"), and the same warning-only behavior. If validation logic needs to change (and it does -- see Step 2), three files must be updated in lockstep.

### Intent

As a contributor modifying secret key validation rules, I expect to change one file and have the behavior apply everywhere. Currently I must find and update three identical copies, risking divergence.

As an operator deploying Proxilion, I expect consistent key validation across IntentCapsule, MemoryIntegrityGuard, and AgentTrustManager. Currently, if one copy is patched and another is not, behavior diverges silently.

### Fix

Create `proxilion/security/_key_validation.py` containing:
- `_PLACEHOLDER_PATTERNS: tuple[str, ...]` with all placeholder substrings
- `validate_secret_key(key: str, component_name: str) -> None` that raises `ConfigurationError` for keys shorter than 16 characters or containing placeholder patterns
- The function should accept a `component_name` parameter for clear error messages ("IntentCapsule secret key contains placeholder pattern 'changeme'")

Then update all three consumers to import and call the shared function, removing their local copies.

### Verification

- `python3 -m pytest tests/test_security/ -x -q` passes
- `python3 -m ruff check proxilion/security/` reports 0 violations
- `python3 -m mypy proxilion/security/` reports 0 errors
- `grep -r "_validate_secret_key" proxilion/` shows only the shared module and its callers
- `grep -r "_PLACEHOLDER_PATTERNS" proxilion/` shows only the shared module

### Claude Code Prompt

```
Read proxilion/security/intent_capsule.py, proxilion/security/memory_integrity.py, and proxilion/security/agent_trust.py. Find the _validate_secret_key() function and _PLACEHOLDER_PATTERNS constant in each file. They should be nearly identical.

Create a new file proxilion/security/_key_validation.py with:
1. A module docstring: "Shared secret key validation for cryptographic security components."
2. Import ConfigurationError from proxilion.exceptions
3. Import logging and create a module logger
4. Define _PLACEHOLDER_PATTERNS as a tuple of strings containing all placeholder substrings from the existing copies
5. Define validate_secret_key(key: str, component_name: str) -> None that:
   - Raises ConfigurationError if len(key) < 16 with message f"{component_name} secret key must be at least 16 characters, got {len(key)}"
   - Raises ConfigurationError if any placeholder pattern is found in key.lower() with message f"{component_name} secret key contains placeholder pattern '{pattern}'. Use a cryptographically random key in production."

Then update intent_capsule.py, memory_integrity.py, and agent_trust.py:
- Remove their local _validate_secret_key() function and _PLACEHOLDER_PATTERNS constant
- Import validate_secret_key from proxilion.security._key_validation
- Replace all calls to self._validate_secret_key(key) with validate_secret_key(key, "IntentCapsule") (or "MemoryIntegrityGuard" or "AgentTrustManager" respectively)

Run: python3 -m pytest tests/test_security/ -x -q && python3 -m ruff check proxilion/security/ && python3 -m mypy proxilion/security/
```

---

## Step 2 -- Enforce Secret Key Rejection for Placeholder Values

> **Priority:** HIGH
> **Estimated complexity:** Trivial
> **Files:** proxilion/security/_key_validation.py (from Step 1)

### Problem

The current `_validate_secret_key()` function logs a warning when a placeholder pattern is detected but allows the operation to continue. This means a developer who copies the README example (`prx_sk_a1b2c3d4e5f6g7h8`) or uses `"your-secret-key-here"` gets a warning in logs but the system runs with a weak key. In production, this is a cryptographic bypass -- HMAC signatures computed with known keys are forgeable.

### Intent

As a security auditor reviewing a Proxilion deployment, I expect the system to refuse to start if any cryptographic component is initialized with a placeholder key. A warning is insufficient because warnings are routinely ignored in production log noise.

As a developer integrating Proxilion, when I copy example code and run it, I expect a clear ConfigurationError telling me to replace the placeholder key, not a buried log warning that lets me deploy insecurely.

### Fix

In the `validate_secret_key()` function created in Step 1, ensure that placeholder detection raises `ConfigurationError` instead of logging a warning. This was already specified in Step 1's implementation, but this step exists to verify that all existing tests are updated to use valid (non-placeholder) keys, since many test fixtures currently use placeholder-style keys.

### Verification

- `python3 -m pytest -x -q` passes with all tests using valid keys
- No test uses a key containing "your-", "changeme", "example", "placeholder", "secret-key", or "TODO"
- `grep -rn "changeme\|your-.*key\|placeholder.*key\|TODO.*key" tests/` returns 0 matches

### Claude Code Prompt

```
After completing Step 1, search all test files for secret keys that would trigger the new ConfigurationError:

grep -rn "changeme\|your-.*key\|placeholder.*key\|TODO.*key\|example.*key\|secret-key" tests/

For each match, replace the placeholder key with a valid 32-character hex string like "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6". Make sure the replacement key is at least 16 characters and does not contain any placeholder patterns.

Also check conftest.py fixtures for placeholder keys and update them.

Run: python3 -m pytest -x -q
```

---

## Step 3 -- Add Field Validation to UserContext, AgentContext, and ToolCallRequest

> **Priority:** HIGH
> **Estimated complexity:** Low
> **Files:** proxilion/types.py, tests/test_core.py

### Problem

The frozen dataclasses UserContext, AgentContext, and ToolCallRequest accept invalid field values without raising errors:

- UserContext: `user_id=""` (empty string) is accepted silently. `roles=["admin", None, 123]` is accepted -- non-string role values propagate to policy evaluation where `"admin" in roles` may behave unexpectedly.
- AgentContext: `agent_id=""` is accepted. `trust_score` is validated (0.0-1.0) but `capabilities` is not validated for type correctness.
- ToolCallRequest: `tool_name=""` is accepted. `arguments` is not checked for type (could be None when dict is expected).

These invalid values propagate through the authorization pipeline and cause confusing errors downstream (e.g., a KeyError in policy evaluation when user_id is empty, or a TypeError when roles contains an integer).

### Intent

As a developer constructing a UserContext, when I accidentally pass `user_id=""`, I expect an immediate ValueError at construction time with a clear message like "user_id must be a non-empty string", not a cryptic error 5 function calls later in policy evaluation.

As a developer constructing a ToolCallRequest, when I pass `tool_name=""` or `arguments=None`, I expect validation at construction, not a downstream crash.

### Fix

Add `__post_init__` validation to each frozen dataclass:

**UserContext:**
- `user_id` must be a non-empty string: `if not isinstance(user_id, str) or not user_id.strip(): raise ValueError("user_id must be a non-empty string")`
- `roles` must be a frozenset (or set/list/tuple) of strings: validate each element is a string

**AgentContext:**
- `agent_id` must be a non-empty string (same check as user_id)
- `capabilities` must contain only strings

**ToolCallRequest:**
- `tool_name` must be a non-empty string
- `arguments` must be a dict (not None): `if not isinstance(arguments, dict): raise ValueError("arguments must be a dict")`

### Verification

- `python3 -m pytest tests/test_core.py -x -q` passes
- `python3 -m pytest -x -q` passes (no existing code constructs invalid contexts)
- `python3 -m mypy proxilion/types.py` reports 0 errors

### Claude Code Prompt

```
Read proxilion/types.py. Find the UserContext, AgentContext, and ToolCallRequest dataclasses.

For UserContext, add or extend __post_init__ to validate:
1. user_id is a non-empty string (isinstance check + strip check)
2. Every element in roles is a string (iterate and check isinstance)
Raise ValueError with clear messages for each violation.

For AgentContext, add or extend __post_init__ to validate:
1. agent_id is a non-empty string
2. Every element in capabilities is a string
Keep the existing trust_score validation.

For ToolCallRequest, add or extend __post_init__ to validate:
1. tool_name is a non-empty string
2. arguments is a dict (not None, not a list, not a string)

Then read tests/test_core.py. Add a new test class TestDataclassValidation with tests:
- test_user_context_empty_user_id_raises
- test_user_context_non_string_role_raises
- test_agent_context_empty_agent_id_raises
- test_agent_context_non_string_capability_raises
- test_tool_call_request_empty_tool_name_raises
- test_tool_call_request_none_arguments_raises
- test_valid_user_context_passes (positive case)
- test_valid_agent_context_passes (positive case)
- test_valid_tool_call_request_passes (positive case)

Run: python3 -m pytest tests/test_core.py -x -q && python3 -m mypy proxilion/types.py

If any existing tests break because they construct invalid contexts, fix those tests to use valid values.
```

---

## Step 4 -- Make Exception Details Immutable and JSON-Serializable

> **Priority:** HIGH
> **Estimated complexity:** Low
> **Files:** proxilion/exceptions.py, tests/test_exceptions.py (if it exists, otherwise tests/test_core.py)

### Problem

Two issues with the exception hierarchy:

1. **Mutable details dict:** `self.details = details or {}` stores a reference to the caller's dict. If the caller modifies the dict after raising, the exception's details change retroactively. This breaks audit logging -- an exception logged at time T1 may have different details at time T2 when the audit record is written.

2. **Non-serializable details:** The `details` dict accepts `dict[str, Any]`, meaning callers can store non-JSON-serializable objects (datetimes, custom classes, file handles). When `to_dict()` or audit serialization runs, it crashes with TypeError.

### Intent

As an operator running Proxilion with an audit exporter (S3, Azure, GCP), when a security exception is raised, I expect the exception details to be safely serializable to JSON at any point after creation. Currently, if a caller stores a datetime or custom object in details, the exporter crashes.

As a developer catching a ProxilionError, I expect the details dict to be a stable snapshot of the state at raise time, not a mutable reference that changes after the fact.

### Fix

1. In `ProxilionError.__init__`, deep-copy the details dict: `self.details = dict(details) if details else {}`
2. Add a `_ensure_serializable` helper that converts non-serializable values to strings via `str()` or `repr()`
3. Call `_ensure_serializable` on the copied dict before storing
4. Add tests for both behaviors

### Verification

- `python3 -m pytest tests/test_exceptions.py -x -q` passes (or test_core.py)
- Passing a dict with a datetime value does not crash
- Modifying the original dict after exception creation does not affect exception.details

### Claude Code Prompt

```
Read proxilion/exceptions.py. Find ProxilionError.__init__ and the self.details assignment.

1. Change the details assignment to make a shallow copy: self.details = dict(details) if details else {}
2. Add a static method _ensure_serializable(details: dict[str, Any]) -> dict[str, Any] that:
   - Iterates over all values
   - For values that are not str, int, float, bool, None, list, or dict, converts them to str(value)
   - For list values, recursively ensures each element is serializable
   - For dict values, recursively ensures each key-value pair is serializable
   - Returns the cleaned dict
3. Call _ensure_serializable on self.details after copying

Find or create tests/test_exceptions.py. Add tests:
- test_details_dict_is_copied (modify original dict, verify exception.details unchanged)
- test_details_with_datetime_serializable (pass datetime in details, verify no crash)
- test_details_with_custom_object_serializable (pass a custom class instance, verify converted to string)
- test_details_empty_default (pass no details, verify empty dict)

Run: python3 -m pytest tests/test_exceptions.py -x -q && python3 -m mypy proxilion/exceptions.py
```

---

## Step 5 -- Wire Structured Exception Context to All Raise Sites

> **Priority:** HIGH
> **Estimated complexity:** Medium
> **Files:** proxilion/security/rate_limiter.py, proxilion/security/circuit_breaker.py, proxilion/security/idor_protection.py, proxilion/security/intent_capsule.py, proxilion/security/behavioral_drift.py, proxilion/security/scope_enforcer.py, proxilion/guards/input_guard.py, proxilion/guards/output_guard.py

### Problem

Spec-v2 Step 5 added structured context fields to exception classes (RateLimitExceeded.user_id, CircuitOpenError.circuit_name, etc.) and Step 6 tested them. But the actual raise sites in the security modules have not been updated to pass these fields. When a RateLimitExceeded is raised in rate_limiter.py, it passes only a message string -- the structured fields (user_id, limit, current_count, window_seconds, reset_at) remain at their default values.

### Intent

As an operator with a monitoring pipeline, when I catch RateLimitExceeded, I expect `exc.user_id` to contain the actual user who was rate-limited, `exc.limit` to contain the configured limit, and `exc.reset_at` to contain the Unix timestamp when the limit resets. Currently these fields are empty/zero because the raise sites do not populate them.

### Fix

For each exception type with structured fields, find every `raise` statement in the codebase that creates that exception and update it to pass the structured fields. Specifically:

- **RateLimitExceeded**: Find all `raise RateLimitExceeded(...)` in rate_limiter.py. Pass user_id, limit, current_count, window_seconds, reset_at.
- **CircuitOpenError**: Find all `raise CircuitOpenError(...)` in circuit_breaker.py. Pass circuit_name, failure_count, reset_timeout.
- **IDORViolationError**: Find all `raise IDORViolationError(...)` in idor_protection.py. Pass user_id, resource_type, resource_id.
- **GuardViolation / InputGuardViolation / OutputGuardViolation**: Find all raises in input_guard.py and output_guard.py. Pass guard_type, matched_patterns, risk_score, input_preview (truncated to 200 chars).
- **SequenceViolationError**: Find all raises in sequence_validator.py. Pass rule_name, tool_name, user_id.
- **IntentHijackError**: Find all raises in intent_capsule.py. Pass tool_name, allowed_tools, user_id.
- **BudgetExceededError**: Find all raises in cost tracking. Pass user_id, budget_limit, current_spend.

### Verification

- `python3 -m pytest -x -q` passes
- For each exception type, write a test that triggers the exception and asserts the structured fields are populated (not default values)
- `python3 -m mypy proxilion/` reports 0 new errors

### Claude Code Prompt

```
Read proxilion/exceptions.py to understand the structured fields on each exception class. Then for each exception type listed below, find all raise sites and update them:

1. Read proxilion/security/rate_limiter.py. Find every "raise RateLimitExceeded". Update each to pass user_id=, limit=, current_count=, window_seconds=, reset_at= with actual values from the local scope.

2. Read proxilion/security/circuit_breaker.py. Find every "raise CircuitOpenError". Update each to pass circuit_name=, failure_count=, reset_timeout= with actual values.

3. Read proxilion/security/idor_protection.py. Find every "raise IDORViolationError". Update each to pass user_id=, resource_type=, resource_id= with actual values.

4. Read proxilion/guards/input_guard.py. Find every "raise InputGuardViolation". Update each to pass guard_type="input", matched_patterns=, risk_score=, input_preview=text[:200].

5. Read proxilion/guards/output_guard.py. Find every "raise OutputGuardViolation". Update each to pass guard_type="output", matched_patterns=, risk_score=, input_preview=text[:200].

6. Read proxilion/security/intent_capsule.py. Find every "raise IntentHijackError". Update each to pass tool_name=, allowed_tools=, user_id=.

7. Read proxilion/security/sequence_validator.py. Find every "raise SequenceViolationError". Update each to pass rule_name=, tool_name=, user_id=.

After updating all raise sites, add a test file tests/test_structured_exceptions_wiring.py that triggers each exception through the normal API (not by constructing the exception directly) and asserts the structured fields have correct non-default values.

Run: python3 -m pytest -x -q && python3 -m mypy proxilion/
```

---

## Step 6 -- Make Rate Limiter Cleanup Interval Configurable and Off Hot Path

> **Priority:** MEDIUM
> **Estimated complexity:** Low
> **Files:** proxilion/security/rate_limiter.py, tests/test_security/test_rate_limiter.py

### Problem

Two issues with rate limiter cleanup:

1. **Hardcoded interval:** `self._cleanup_interval = 300.0` (5 minutes) on line 86 of rate_limiter.py is not configurable. High-throughput systems need shorter intervals to prevent bucket accumulation. Low-traffic systems waste CPU on frequent checks.

2. **Cleanup on hot path:** `_maybe_cleanup()` is called synchronously inside `allow_request()`, meaning every rate limit check pays the cost of checking whether cleanup is due. When cleanup runs, it iterates all buckets, adding latency to the request that triggers it.

### Intent

As an operator running Proxilion at 10,000 requests/second, I expect to configure the cleanup interval to 30 seconds to keep memory bounded. Currently I cannot change the 5-minute default.

As a developer profiling Proxilion's latency, I expect rate limit checks to have consistent sub-millisecond latency. Currently, one in every N requests pays the cost of a full cleanup sweep.

### Fix

1. Add `cleanup_interval_seconds: float = 300.0` parameter to `__init__` of all rate limiter classes (TokenBucketRateLimiter, SlidingWindowRateLimiter, MultiDimensionalRateLimiter)
2. Validate the interval is positive: `if cleanup_interval_seconds <= 0: raise ConfigurationError(...)`
3. Move cleanup to a lazy background approach: instead of iterating all buckets synchronously, mark buckets for cleanup and process them in batches of at most 100 per call to `_maybe_cleanup()`, preventing single-request latency spikes

### Verification

- `python3 -m pytest tests/test_security/test_rate_limiter.py -x -q` passes
- New test: construct rate limiter with `cleanup_interval_seconds=1.0`, add 10 buckets, sleep 2 seconds, verify cleanup ran
- New test: construct rate limiter with `cleanup_interval_seconds=-1` raises ConfigurationError

### Claude Code Prompt

```
Read proxilion/security/rate_limiter.py. Find the __init__ methods of TokenBucketRateLimiter, SlidingWindowRateLimiter, and MultiDimensionalRateLimiter.

1. Add a cleanup_interval_seconds parameter (default 300.0) to each __init__
2. Add validation: if cleanup_interval_seconds <= 0, raise ConfigurationError("cleanup_interval_seconds must be positive")
3. Replace the hardcoded self._cleanup_interval = 300.0 with self._cleanup_interval = cleanup_interval_seconds
4. In _maybe_cleanup(), add a batch limit: process at most 100 expired buckets per call instead of iterating all buckets

Read tests/test_security/test_rate_limiter.py. Add tests:
- test_custom_cleanup_interval: create limiter with cleanup_interval_seconds=1.0, verify it uses the custom interval
- test_negative_cleanup_interval_raises: create limiter with cleanup_interval_seconds=-1, assert ConfigurationError raised
- test_zero_cleanup_interval_raises: create limiter with cleanup_interval_seconds=0, assert ConfigurationError raised
- test_cleanup_batching: create limiter, add 200 expired buckets, call _maybe_cleanup(), verify at most 100 were cleaned in one pass

Run: python3 -m pytest tests/test_security/test_rate_limiter.py -x -q && python3 -m ruff check proxilion/security/rate_limiter.py
```

---

## Step 7 -- Replace Per-Check Standard Deviation with Incremental Statistics (Welford's Algorithm)

> **Priority:** MEDIUM
> **Estimated complexity:** Medium
> **Files:** proxilion/security/behavioral_drift.py, tests/test_security/test_behavioral_drift.py

### Problem

The behavioral drift detector recomputes `statistics.stdev()` on a deque of up to 10,000 samples every time `check_drift()` is called. This is O(n) per call. At 1,000 requests/second with a full deque, this is 10,000 arithmetic operations per request -- 10 million operations per second consumed purely by statistics recomputation.

### Intent

As an operator running Proxilion at high throughput, I expect behavioral drift checks to be O(1) per call, not O(n) where n scales with deque size. The z-score calculation should use incrementally maintained running mean and variance.

### Fix

Implement Welford's online algorithm for incremental mean and variance:
- Maintain `_count`, `_mean`, `_m2` (sum of squared differences) as instance variables
- On each `record_tool_call()`, update these incrementally in O(1)
- On each `check_drift()`, compute standard deviation as `sqrt(_m2 / (_count - 1))` in O(1)
- When baseline is locked, snapshot the running statistics
- Keep the deque for historical data access but do not iterate it for statistics

### Verification

- `python3 -m pytest tests/test_security/test_behavioral_drift.py -x -q` passes
- New test: verify that incremental stdev matches `statistics.stdev()` on same data within floating-point tolerance (1e-10)
- New test: verify O(1) check_drift by timing 1000 calls with a full 10,000-entry deque -- all calls should complete in under 100ms total

### Claude Code Prompt

```
Read proxilion/security/behavioral_drift.py thoroughly. Find where statistics.stdev() is called and understand the data flow.

Implement Welford's online algorithm:
1. Add instance variables to the relevant class: _welford_count: int = 0, _welford_mean: float = 0.0, _welford_m2: float = 0.0
2. Add a method _welford_update(self, value: float) that updates count, mean, and m2 incrementally:
   count += 1
   delta = value - mean
   mean += delta / count
   delta2 = value - mean
   m2 += delta * delta2
3. Add a method _welford_stdev(self) -> float that returns sqrt(m2 / (count - 1)) if count > 1, else 0.0
4. Call _welford_update() in record_tool_call() whenever a metric value is recorded
5. Replace statistics.stdev() calls in check_drift() and z-score calculation with _welford_stdev()
6. When baseline is locked (lock_baseline()), snapshot _welford_mean and _welford_stdev as the baseline values
7. Keep the deque for other purposes (history access, serialization) but do not iterate it for stdev

Add tests in tests/test_security/test_behavioral_drift.py:
- test_welford_matches_stdlib: record 100 random values, compare _welford_stdev() to statistics.stdev() on same values, assert abs(difference) < 1e-10
- test_welford_single_value: record 1 value, verify stdev is 0.0
- test_welford_two_values: record 2 values, verify stdev matches manual calculation
- test_check_drift_performance: record 10000 values, time 1000 calls to check_drift(), assert total < 100ms

Run: python3 -m pytest tests/test_security/test_behavioral_drift.py -x -q && python3 -m mypy proxilion/security/behavioral_drift.py
```

---

## Step 8 -- Add Unicode Normalization to Input Guard

> **Priority:** HIGH
> **Estimated complexity:** Low
> **Files:** proxilion/guards/input_guard.py, tests/test_guards.py

### Problem

The input guard matches regex patterns against raw input text without Unicode normalization. An attacker can evade detection by using:
- Full-width characters: "ignore" as Unicode full-width letters
- Combining characters: inserting zero-width joiners or combining diacritical marks between letters
- Homoglyph substitution: using Cyrillic "a" (U+0430) instead of Latin "a" (U+0061)
- NFKD decomposition variants: using precomposed vs decomposed Unicode representations

The README's Mermaid diagram references "Unicode NFKD Normalization" as the first step in the hardened security pipeline, but the code does not implement it.

### Intent

As a security engineer testing Proxilion's input guard, when I submit "ignore previous instructions" written with full-width Unicode characters, I expect the guard to detect and block it with the same confidence as the ASCII version. Currently, the full-width version passes undetected.

### Fix

1. Import `unicodedata` in input_guard.py
2. At the top of the `check()` method, before any pattern matching, normalize the input text: `normalized = unicodedata.normalize('NFKD', text)`
3. Strip combining characters (Unicode category "Mn" -- Mark, Nonspacing) from the normalized text
4. Convert to ASCII-safe form by replacing non-ASCII characters with their closest ASCII equivalent where possible
5. Run pattern matching on both the original text AND the normalized text, taking the higher risk score

### Verification

- `python3 -m pytest tests/test_guards.py -x -q` passes
- New tests verify detection of:
  - Full-width "ignore previous instructions"
  - Homoglyph "ignore" with Cyrillic a
  - Zero-width joiner insertion between letters of "ignore"
  - Mixed-script evasion attempts

### Claude Code Prompt

```
Read proxilion/guards/input_guard.py. Find the check() method (or the main method that runs pattern matching against input text).

1. Add import unicodedata at the top of the file
2. At the start of the check method, before pattern matching, add normalization:
   - normalized = unicodedata.normalize('NFKD', text)
   - stripped = ''.join(c for c in normalized if unicodedata.category(c) != 'Mn')
   - ascii_form = stripped.encode('ascii', 'ignore').decode('ascii')
3. Run pattern matching against BOTH the original text and the ascii_form
4. Use the higher risk score from either check
5. If either check triggers a pattern, include it in matched_patterns

Read tests/test_guards.py. Add a new test class TestInputGuardUnicodeEvasion with tests:
- test_fullwidth_ignore_detected: Use full-width Unicode "ignore previous instructions" (each letter replaced with its full-width equivalent, e.g., chr(0xFF49) for 'i')
- test_homoglyph_cyrillic_a_detected: Replace 'a' in "ignore" with Cyrillic U+0430
- test_zero_width_joiner_detected: Insert U+200D (zero-width joiner) between each letter of "ignore previous"
- test_combining_diacritical_detected: Add combining acute accent (U+0301) after each letter
- test_normal_ascii_still_detected: Verify normal ASCII injection still works
- test_safe_unicode_passes: Verify legitimate Unicode text (e.g., Chinese, Japanese) passes without false positive

Run: python3 -m pytest tests/test_guards.py -x -q && python3 -m ruff check proxilion/guards/input_guard.py
```

---

## Step 9 -- Add Context Variable Cleanup to Core Authorization Pipeline

> **Priority:** HIGH
> **Estimated complexity:** Low
> **Files:** proxilion/core.py, tests/test_core.py

### Problem

In proxilion/core.py, the context variables `_current_user` and `_current_agent` are set at the start of the authorization flow but are not guaranteed to be cleaned up on exception. In async code using `asyncio.TaskGroup` or similar patterns, a leaked context variable from one failed task could be visible to subsequent tasks sharing the same context.

### Intent

As a developer using Proxilion in an async FastAPI application, when one request fails mid-authorization, I expect the next request to start with a clean context -- no leaked user or agent from the failed request. Currently, if an exception occurs after context vars are set but before they are cleaned up, the values persist.

### Fix

1. Wrap the authorization flow in a try/finally block that resets context variables
2. Use `contextvars.Token` for proper reset: `token = _current_user.set(user)` ... `finally: _current_user.reset(token)`
3. Apply the same pattern to `_current_agent`

### Verification

- `python3 -m pytest tests/test_core.py -x -q` passes
- New test: set context var, trigger authorization failure, verify context var is reset to its pre-call value
- New async test: run two concurrent tasks, one failing, verify the other has clean context

### Claude Code Prompt

```
Read proxilion/core.py. Find where _current_user and _current_agent context variables are set (look for .set() calls).

For each location where context variables are set:
1. Capture the token: user_token = _current_user.set(user)
2. Wrap the subsequent code in try/finally
3. In the finally block: _current_user.reset(user_token)
4. Do the same for _current_agent if it is set

Read tests/test_core.py. Add tests:
- test_context_var_cleanup_on_success: Run authorization, verify context vars are reset after
- test_context_var_cleanup_on_failure: Trigger authorization failure (e.g., policy deny), verify context vars are reset
- test_context_var_no_leak_between_calls: Run two sequential authorizations with different users, verify no cross-contamination

If there are async authorization methods, add async versions of these tests.

Run: python3 -m pytest tests/test_core.py -x -q && python3 -m mypy proxilion/core.py
```

---

## Step 10 -- Add End-to-End Authorization Pipeline Integration Test

> **Priority:** HIGH
> **Estimated complexity:** Medium
> **Files:** tests/test_authorization_pipeline_e2e.py (new)

### Problem

No test exercises the full authorization pipeline from input guard through policy evaluation through output guard in a single flow. Individual components are tested in isolation, but integration bugs (wrong argument passed between components, exception not propagated, audit event missing fields) are not caught.

### Intent

As a contributor refactoring the authorization pipeline, I expect a single test to verify the entire flow works end-to-end. If I break the connection between the input guard and the policy engine, this test should fail immediately.

### Fix

Create `tests/test_authorization_pipeline_e2e.py` with the following scenarios:

1. **Happy path:** Safe input, valid schema, within rate limit, policy allows, circuit closed, valid sequence, clean output. Verify: authorization succeeds, audit event logged with all fields populated, no guard violations.

2. **Input guard rejection:** Prompt injection input. Verify: authorization fails at input guard stage, audit event records the rejection reason, policy engine is never called.

3. **Rate limit rejection:** Exceed rate limit before authorization. Verify: fails with RateLimitExceeded, audit event records the rate limit details.

4. **Policy denial:** Valid input but user lacks required role. Verify: fails with AuthorizationError, audit event records the policy decision.

5. **Output guard redaction:** Authorization succeeds but output contains API key. Verify: output is redacted, audit event records the redaction.

6. **Full pipeline with all security controls:** Configure input guard, schema validation, rate limiter, policy engine, circuit breaker, sequence validator, and output guard. Run a valid request through all of them. Verify each control was exercised (check audit events or metrics).

### Verification

- `python3 -m pytest tests/test_authorization_pipeline_e2e.py -x -q` passes
- At least 6 test methods covering the scenarios above
- Tests use real components (not mocks) to catch integration bugs

### Claude Code Prompt

```
Read proxilion/core.py to understand the authorization flow. Read proxilion/types.py for UserContext and ToolCallRequest. Read proxilion/guards/input_guard.py and proxilion/guards/output_guard.py for guard APIs. Read proxilion/security/rate_limiter.py for rate limiter API. Read proxilion/audit/logger.py for audit API.

Create tests/test_authorization_pipeline_e2e.py with:

1. A fixture that creates a fully configured Proxilion instance with:
   - InputGuard with default patterns
   - OutputGuard with default patterns
   - A simple RoleBasedPolicy allowing "admin" to do everything, "viewer" to read only
   - A TokenBucketRateLimiter with capacity=5
   - An InMemoryAuditLogger
   - A SequenceValidator with at least one rule

2. Test class TestAuthorizationPipelineE2E with methods:
   - test_happy_path_full_pipeline: admin user, safe input, valid tool call -> success
   - test_input_guard_blocks_injection: any user, injection input -> blocked before policy
   - test_rate_limit_exceeded: viewer user, 6 rapid requests -> 6th fails with RateLimitExceeded
   - test_policy_denies_unauthorized: viewer user, write action -> denied
   - test_output_guard_redacts_sensitive: admin user, output contains "sk-proj-abc123" -> redacted
   - test_sequence_violation_blocked: admin user, forbidden sequence -> SequenceViolationError
   - test_audit_events_recorded: run happy path, verify audit logger has at least 1 event with correct fields

Use real components, not mocks. Import from proxilion directly.

Run: python3 -m pytest tests/test_authorization_pipeline_e2e.py -x -q
```

---

## Step 11 -- Add Thread Safety Stress Tests

> **Priority:** MEDIUM
> **Estimated complexity:** Medium
> **Files:** tests/test_thread_safety_stress.py (new)

### Problem

Thread safety is claimed (RLock on all mutable components) and individual lock patterns are correct in code review, but no test verifies that concurrent access from multiple threads produces correct results under contention. Race conditions often only manifest under high concurrency -- a code review cannot catch all timing-dependent bugs.

### Intent

As a security auditor reviewing Proxilion for multi-threaded deployment, I expect the test suite to include stress tests proving that concurrent access to rate limiters, circuit breakers, audit loggers, and session managers produces correct results. Currently, all threading tests run sequentially with manually controlled thread interleaving.

### Fix

Create `tests/test_thread_safety_stress.py` with concurrent stress tests:

1. **Rate limiter under contention:** 10 threads, each sending 100 requests through the same rate limiter. Total allowed requests should equal the configured capacity (within a tolerance of +/- 1 due to timing).

2. **Circuit breaker under contention:** 10 threads, each recording failures and successes. Final state should be consistent with the failure/success counts.

3. **Audit logger under contention:** 10 threads, each logging 100 events. Total events in the log should be exactly 1000, with a valid hash chain.

4. **IDOR protector under contention:** 10 threads, each checking access for different users. No cross-user scope leakage.

5. **Session manager under contention:** 10 threads creating and destroying sessions. No orphaned sessions, no double-free.

### Verification

- `python3 -m pytest tests/test_thread_safety_stress.py -x -q` passes
- Each test uses `concurrent.futures.ThreadPoolExecutor` with 10 workers
- Each test asserts a quantitative invariant (total count, no duplicates, valid hash chain)

### Claude Code Prompt

```
Create tests/test_thread_safety_stress.py with:

import concurrent.futures, threading, time, pytest

Test class TestThreadSafetyStress:

1. test_rate_limiter_concurrent_access:
   - Create TokenBucketRateLimiter(capacity=100, refill_rate=0) -- no refill during test
   - Submit 10 threads, each calling allow_request("user") 20 times
   - Collect results (True/False) from all threads
   - Assert sum(allowed) == 100 (exactly capacity, +/- 1 tolerance)

2. test_circuit_breaker_concurrent_failures:
   - Create CircuitBreaker(failure_threshold=50, reset_timeout=999)
   - Submit 10 threads, each recording 10 failures
   - After all threads complete, assert breaker.state is OPEN
   - Assert breaker.failure_count == 100

3. test_audit_logger_concurrent_writes:
   - Create InMemoryAuditLogger
   - Submit 10 threads, each logging 100 events with unique event content
   - After all threads complete, assert len(logger.events) == 1000
   - Verify hash chain integrity: logger.verify().valid is True

4. test_idor_concurrent_access_isolation:
   - Create IDORProtector
   - Register 10 users, each with different scopes
   - Submit 10 threads, each validating access for their assigned user 100 times
   - Assert zero cross-user access (user_1 never sees user_2's resources)

5. test_session_manager_concurrent_lifecycle:
   - Create SessionManager
   - Submit 10 threads, each creating 10 sessions and then destroying them
   - After all threads complete, assert no active sessions remain (or only unexpired ones)

Run: python3 -m pytest tests/test_thread_safety_stress.py -x -q -v
```

---

## Step 12 -- Add Decorator Combination Tests

> **Priority:** MEDIUM
> **Estimated complexity:** Low
> **Files:** tests/test_decorator_combinations.py (new)

### Problem

The SDK provides 9 decorators (@authorize_tool_call, @rate_limited, @circuit_protected, @require_approval, @scope_enforced, @cost_limited, @timeout_limited, @sequence_validated, @retry_with_backoff). No test verifies that multiple decorators can be stacked on the same function without conflict. Decorator ordering affects behavior (rate_limited should run before authorize_tool_call to prevent wasting policy evaluation on rate-limited requests), but ordering correctness is not tested.

### Intent

As a developer using multiple decorators on a tool function, I expect them to compose correctly. If I stack @rate_limited and @authorize_tool_call, the rate limit should be checked first. If I stack @circuit_protected and @retry_with_backoff, the retry should wrap the circuit breaker, not vice versa.

### Fix

Create `tests/test_decorator_combinations.py` testing common decorator combinations:
1. `@rate_limited` + `@authorize_tool_call` -- rate limit checked before policy
2. `@circuit_protected` + `@authorize_tool_call` -- circuit breaker checked before policy
3. `@rate_limited` + `@circuit_protected` + `@authorize_tool_call` -- all three in order
4. `@retry_with_backoff` + `@circuit_protected` -- retry wraps circuit breaker
5. `@timeout_limited` + `@authorize_tool_call` -- timeout wraps authorization
6. All 9 decorators stacked -- verify no crash, correct execution order

### Verification

- `python3 -m pytest tests/test_decorator_combinations.py -x -q` passes
- At least 6 test methods
- Tests verify execution order by checking which exception is raised first

### Claude Code Prompt

```
Read proxilion/decorators.py to understand all available decorators and their signatures.

Create tests/test_decorator_combinations.py with:

Test class TestDecoratorCombinations:

1. test_rate_limited_before_authorize: Stack @rate_limited then @authorize_tool_call on a function. Exhaust rate limit. Call function. Assert RateLimitExceeded raised (not AuthorizationError), proving rate limit ran first.

2. test_circuit_protected_before_authorize: Stack @circuit_protected then @authorize_tool_call. Open the circuit breaker. Call function. Assert CircuitOpenError raised.

3. test_triple_stack_rate_circuit_auth: Stack all three. Exhaust rate limit. Assert RateLimitExceeded. Reset rate limit, open circuit. Assert CircuitOpenError. Reset circuit, deny policy. Assert AuthorizationError.

4. test_retry_wraps_circuit_breaker: Stack @retry_with_backoff(max_retries=2) then @circuit_protected. Make the circuit breaker fail twice then succeed. Verify the function is called 3 times total.

5. test_timeout_wraps_authorize: Stack @timeout_limited(timeout_seconds=0.001) then @authorize_tool_call with a slow policy. Assert timeout error raised.

6. test_all_decorators_no_crash: Stack all available decorators on a simple function. Call it with valid inputs. Assert no crash (may succeed or raise expected exception).

Run: python3 -m pytest tests/test_decorator_combinations.py -x -q -v
```

---

## Step 13 -- Add Sample Data Generator Script

> **Priority:** MEDIUM
> **Estimated complexity:** Low
> **Files:** scripts/generate_sample_data.py (new)

### Problem

There is no way to quickly generate realistic test data for development, demos, or load testing. Developers must manually construct UserContext, AgentContext, and ToolCallRequest objects in every test or demo script. This slows onboarding and makes it harder to reproduce issues reported by users.

### Intent

As a developer onboarding to Proxilion, I want to run `python3 scripts/generate_sample_data.py` and get a complete set of sample users, agents, tool calls, policies, and audit events that I can use for testing and exploration.

As a load tester, I want to generate 10,000 realistic ToolCallRequests with varied users, tools, and arguments for throughput benchmarking.

### Fix

Create `scripts/generate_sample_data.py` that:
1. Generates 10 sample UserContext objects with varied roles (admin, viewer, editor, analyst, auditor)
2. Generates 5 sample AgentContext objects with varied trust levels and capabilities
3. Generates 50 sample ToolCallRequest objects with varied tools (search, read, write, delete, execute) and realistic arguments
4. Generates 5 sample policies (RoleBasedPolicy, OwnershipPolicy)
5. Runs each tool call through a Proxilion instance and collects audit events
6. Outputs summary statistics: total requests, allowed, denied, rate limited, guard blocked
7. Writes sample audit log to a temporary file and verifies hash chain integrity
8. Accepts `--count N` argument for generating N tool call requests (default 50)
9. Accepts `--output PATH` argument for writing results to a JSON file

### Verification

- `python3 scripts/generate_sample_data.py` runs without error and prints summary
- `python3 scripts/generate_sample_data.py --count 1000` generates 1000 requests
- Output includes at least one denied request and at least one allowed request

### Claude Code Prompt

```
Create scripts/ directory if it does not exist. Create scripts/generate_sample_data.py with:

1. Shebang line and module docstring
2. Import argparse, json, tempfile, sys, and all necessary proxilion modules
3. Define generate_users() returning 10 UserContext objects with roles like:
   - 3 admins, 3 viewers, 2 editors, 1 analyst, 1 auditor
   - User IDs like "user_admin_1", "user_viewer_1", etc.
4. Define generate_agents() returning 5 AgentContext objects with:
   - Varied trust scores (0.2, 0.5, 0.7, 0.9, 1.0)
   - Varied capabilities
5. Define generate_tool_calls(count: int) returning ToolCallRequest objects with:
   - Random selection from tools: search, read_document, write_document, delete_document, execute_query, list_files
   - Realistic arguments for each tool type
   - Random user assignment from the generated users
6. Define main() that:
   - Parses --count and --output arguments
   - Creates a Proxilion instance with simple engine, a RoleBasedPolicy, InputGuard, OutputGuard, and InMemoryAuditLogger
   - Runs each tool call through authorization
   - Collects results (allowed/denied/rate_limited/guard_blocked)
   - Prints summary table
   - If --output specified, writes results to JSON file
   - Verifies audit log hash chain integrity

Run: python3 scripts/generate_sample_data.py && python3 scripts/generate_sample_data.py --count 100
```

---

## Step 14 -- Add Comprehensive Docstrings to Public API Surface

> **Priority:** MEDIUM
> **Estimated complexity:** Medium
> **Files:** proxilion/core.py, proxilion/types.py, proxilion/exceptions.py, proxilion/guards/input_guard.py, proxilion/guards/output_guard.py, proxilion/security/rate_limiter.py, proxilion/security/circuit_breaker.py, proxilion/security/idor_protection.py, proxilion/security/intent_capsule.py, proxilion/security/memory_integrity.py, proxilion/security/agent_trust.py, proxilion/audit/logger.py

### Problem

Many public classes and methods lack docstrings or have minimal ones. The public API surface includes approximately 45 classes and 120 public methods. Without docstrings, IDE tooltip help is empty, and `help(proxilion.Proxilion)` produces unhelpful output.

### Intent

As a developer using Proxilion in my IDE, when I hover over `InputGuard.check()`, I expect to see a docstring explaining: what the method does, what parameters it accepts, what it returns, what exceptions it raises, and a brief usage example. Currently, many methods show no documentation.

### Fix

Add Google-style docstrings to all public classes and methods in the files listed above. Each docstring should include:
- One-line summary
- Parameters with types and descriptions
- Returns with type and description
- Raises with exception types and conditions
- No code examples in docstrings (those belong in docs/)

Focus on the 12 most-imported files listed above. Do not add docstrings to private methods (prefixed with underscore) or test files.

### Verification

- `python3 -m ruff check proxilion/ --select D` reports no missing docstring errors for public methods
- `python3 -c "import proxilion; help(proxilion.Proxilion)"` shows useful documentation
- `python3 -m mypy proxilion/` reports 0 new errors

### Claude Code Prompt

```
For each of the following files, read the file, identify all public classes and public methods (not prefixed with underscore), and add Google-style docstrings:

1. proxilion/core.py - Proxilion class and all public methods
2. proxilion/types.py - UserContext, AgentContext, ToolCallRequest, AuthorizationResult
3. proxilion/exceptions.py - All exception classes
4. proxilion/guards/input_guard.py - InputGuard class and check(), get_patterns() methods
5. proxilion/guards/output_guard.py - OutputGuard class and check(), redact() methods
6. proxilion/security/rate_limiter.py - All rate limiter classes and allow_request() methods
7. proxilion/security/circuit_breaker.py - CircuitBreaker class and call(), check_state() methods
8. proxilion/security/idor_protection.py - IDORProtector class and register_scope(), validate_access() methods
9. proxilion/security/intent_capsule.py - IntentCapsule, IntentGuard classes
10. proxilion/security/memory_integrity.py - MemoryIntegrityGuard class
11. proxilion/security/agent_trust.py - AgentTrustManager class
12. proxilion/audit/logger.py - AuditLogger class and log_authorization(), verify() methods

Docstring format (Google style):
"""One-line summary.

    Args:
        param_name: Description of parameter.

    Returns:
        Description of return value.

    Raises:
        ExceptionType: When this condition occurs.
"""

Do NOT add docstrings to private methods (starting with _).
Do NOT add code examples in docstrings.
Do NOT modify any logic -- only add docstrings.

Run: python3 -m ruff check proxilion/ && python3 -m mypy proxilion/
```

---

## Step 15 -- Update Quickstart Guide to Cover All Decorators and Security Controls

> **Priority:** MEDIUM
> **Estimated complexity:** Low
> **Files:** docs/quickstart.md

### Problem

The quickstart guide covers basic authorization and a few security controls but does not demonstrate all 9 decorators or the full set of security features added in specs v1 through v4. New users discover features only by reading source code or the README, which is not a guided tutorial.

### Intent

As a new developer reading the quickstart, I expect a step-by-step guide that walks me through: (1) basic authorization, (2) input/output guards, (3) rate limiting, (4) circuit breaker, (5) IDOR protection, (6) intent capsule, (7) memory integrity, (8) agent trust, (9) behavioral drift detection, (10) audit logging, (11) cost tracking, and (12) all 9 decorators. Each section should have a working code example that I can copy-paste and run.

### Fix

Rewrite docs/quickstart.md to include all 12 sections listed above. Each section should:
- Start with a one-sentence explanation of what the feature does
- Show a minimal working code example (5-15 lines)
- Show expected output
- Link to the relevant feature documentation page

### Verification

- All code examples in the quickstart are syntactically valid Python
- Running each example produces the expected output
- No references to deprecated APIs or incorrect class names

### Claude Code Prompt

```
Read docs/quickstart.md to understand current structure. Read README.md for feature examples.

Rewrite docs/quickstart.md with the following structure:

# Proxilion SDK Quick Start

## Prerequisites
- Python 3.10+
- pip install proxilion

## 1. Basic Authorization (Policy Engine)
[Working example with Proxilion, Policy, UserContext]

## 2. Input Guards (Prompt Injection Detection)
[Working example with InputGuard]

## 3. Output Guards (Data Leakage Prevention)
[Working example with OutputGuard]

## 4. Rate Limiting
[Working example with TokenBucketRateLimiter]

## 5. Circuit Breaker
[Working example with CircuitBreaker]

## 6. IDOR Protection
[Working example with IDORProtector]

## 7. Intent Capsule (Goal Hijack Prevention)
[Working example with IntentCapsule, IntentGuard]

## 8. Memory Integrity (Context Poisoning Detection)
[Working example with MemoryIntegrityGuard]

## 9. Agent Trust (Secure Inter-Agent Communication)
[Working example with AgentTrustManager]

## 10. Behavioral Drift Detection
[Working example with BehavioralMonitor]

## 11. Audit Logging
[Working example with AuditLogger or InMemoryAuditLogger]

## 12. Cost Tracking
[Working example with CostTracker]

## 13. Decorators Reference
[Table of all 9 decorators with one-line description and usage]

## Next Steps
[Links to feature docs, README, API reference]

Verify each code example is syntactically valid by running: python3 -c "exec(open('docs/quickstart.md').read())" -- or just visually verify imports match actual module paths.

Run: python3 -m ruff check docs/ || true  # docs may not be checked by ruff, that is fine
```

---

## Step 16 -- Lint and Type-Check All Test Files

> **Priority:** LOW
> **Estimated complexity:** Low
> **Files:** tests/**/*.py

### Problem

The CI pipeline runs `ruff check proxilion tests` and `mypy proxilion` but does not run `mypy tests`. Type errors in test code can hide real issues -- for example, a test passing a string where an int is expected may pass at runtime (Python is dynamically typed) but indicates a misunderstanding of the API that could mislead contributors.

### Intent

As a contributor reading test code to understand the API, I expect the test code to use correct types. If a test passes `user_id=123` to UserContext (which expects a string), that is misleading even if it works at runtime.

### Fix

1. Run `python3 -m mypy tests/ --ignore-missing-imports` and fix all type errors
2. Run `python3 -m ruff check tests/` and fix any new violations
3. Run `python3 -m ruff format tests/` and fix any format violations
4. Add `mypy tests/` to the CI check command in CLAUDE.md

### Verification

- `python3 -m mypy tests/ --ignore-missing-imports` reports 0 errors
- `python3 -m ruff check tests/` reports 0 violations
- `python3 -m ruff format --check tests/` reports 0 violations

### Claude Code Prompt

```
Run: python3 -m mypy tests/ --ignore-missing-imports 2>&1 | head -50

For each error reported, read the test file and fix the type error. Common fixes:
- Add type annotations to test helper functions
- Fix incorrect argument types in test assertions
- Add # type: ignore[...] comments ONLY for legitimate dynamic test patterns (e.g., testing that wrong types raise errors)

Then run: python3 -m ruff check tests/ 2>&1 | head -50
Fix any violations.

Then run: python3 -m ruff format tests/

Then run the full check: python3 -m mypy tests/ --ignore-missing-imports && python3 -m ruff check tests/ && python3 -m ruff format --check tests/ && python3 -m pytest -x -q
```

---

## Step 17 -- Update CHANGELOG, Version, and Documentation

> **Priority:** LOW
> **Estimated complexity:** Low
> **Files:** CHANGELOG.md, pyproject.toml, proxilion/__init__.py, .proxilion-build/STATE.md

### Problem

After all previous steps are complete, the version must be bumped from the post-spec-v4 version to 0.0.11, and the CHANGELOG must be updated with all changes made in this spec.

### Intent

As a user checking `proxilion.__version__`, I expect the version to reflect the latest release. As a contributor reading the CHANGELOG, I expect to see what changed in each version.

### Fix

1. Update `pyproject.toml` version to "0.0.11"
2. Update `proxilion/__init__.py` `__version__` to "0.0.11"
3. Add a new section to CHANGELOG.md for version 0.0.11 with all changes from this spec
4. Update .proxilion-build/STATE.md with completion status
5. Update CLAUDE.md version line if present

### Verification

- `python3 -c "import proxilion; print(proxilion.__version__)"` prints "0.0.11"
- `grep 'version = ' pyproject.toml` shows "0.0.11"
- CHANGELOG.md has a 0.0.11 section
- STATE.md shows all spec-v5 steps as DONE

### Claude Code Prompt

```
Read pyproject.toml, proxilion/__init__.py, CHANGELOG.md, and .proxilion-build/STATE.md.

1. In pyproject.toml, change version = "..." to version = "0.0.11"
2. In proxilion/__init__.py, change __version__ = "..." to __version__ = "0.0.11"
3. In CHANGELOG.md, add a new section at the top:

## 0.0.11

### Security Hardening
- Extracted shared secret key validation to proxilion/security/_key_validation.py
- Enforced placeholder key rejection (ConfigurationError instead of warning)
- Added field validation to UserContext, AgentContext, and ToolCallRequest
- Added Unicode normalization (NFKD) to input guard pattern matching
- Added context variable cleanup (try/finally) to core authorization pipeline

### Exception Safety
- Made exception details dict immutable (deep copy on creation)
- Ensured JSON serializability of all exception details
- Wired structured context fields to all exception raise sites

### Performance
- Replaced O(n) stdev computation with O(1) Welford's algorithm in behavioral drift
- Made rate limiter cleanup interval configurable
- Moved rate limiter cleanup off hot path with batch processing

### Testing
- Added end-to-end authorization pipeline integration test
- Added thread safety stress tests (10 threads x 100 operations)
- Added decorator combination tests (9 decorators stacked)
- Added Unicode evasion tests for input guard
- Added sample data generator script

### Documentation
- Added comprehensive docstrings to all public API classes and methods
- Updated quickstart guide to cover all 12 security features and 9 decorators
- Type-checked all test files with mypy

4. Update .proxilion-build/STATE.md to show spec-v5 as COMPLETE

5. Update CLAUDE.md version line to 0.0.11

Run: python3 -c "import proxilion; print(proxilion.__version__)" && grep "version" pyproject.toml | head -1
```

---

## Step 18 -- Final Validation and README Mermaid Diagrams

> **Priority:** LOW
> **Estimated complexity:** Low
> **Files:** README.md, all source files

### Problem

After all changes in this spec, a final validation pass must confirm: all tests pass, all lint checks pass, all type checks pass, all documentation is accurate, and the README Mermaid diagrams reflect the current architecture.

### Intent

As a release manager preparing version 0.0.11, I expect a single command to verify everything is green, and I expect the README to accurately describe the current state of the system.

### Fix

1. Run the full CI check: `python3 -m ruff check proxilion tests && python3 -m ruff format --check proxilion tests && python3 -m mypy proxilion && python3 -m pytest -x -q`
2. Verify test count has increased from the baseline (2,541 collected)
3. Verify all Mermaid diagrams in README.md are accurate (module names match actual files, exception hierarchy matches actual classes)
4. Add a new Mermaid diagram to README.md showing the secret key validation flow added in this spec
5. Update the "Stabilization Guarantees" section to reflect any new bounded collections or thread safety changes

### Verification

- Full CI check passes with 0 errors
- Test count is higher than 2,541
- All README Mermaid diagrams render correctly (no syntax errors)
- `python3 -c "import proxilion; print(proxilion.__version__)"` prints "0.0.11"

### Claude Code Prompt

```
Run the full CI check:
python3 -m ruff check proxilion tests && python3 -m ruff format --check proxilion tests && python3 -m mypy proxilion && python3 -m pytest -x -q

Verify the test count in the output is greater than 2541.

Read README.md. Verify all Mermaid diagrams:
1. Module names in diagrams match actual file names in proxilion/
2. Exception hierarchy matches proxilion/exceptions.py
3. Security pipeline flow matches proxilion/core.py authorization flow

Add a new Mermaid diagram after the "Stabilization Guarantees" section showing secret key validation:

### Secret Key Validation Flow

(Mermaid flowchart showing: Key Input -> Length Check (>=16) -> Placeholder Pattern Check -> Accept or Raise ConfigurationError)

Update the "Bounded Collections" Mermaid diagram if any new bounded collections were added.

Run the full CI check one final time to confirm everything is green.
```

---

## Summary Table

| Step | Priority | Description | Files | Estimated Tests Added |
|------|----------|-------------|-------|-----------------------|
| 1 | HIGH | Extract shared secret key validation | 4 files | 0 (existing tests cover) |
| 2 | HIGH | Enforce placeholder key rejection | test files | 0 (test updates only) |
| 3 | HIGH | Add field validation to dataclasses | 2 files | 9 |
| 4 | HIGH | Make exception details immutable | 2 files | 4 |
| 5 | HIGH | Wire structured context to raise sites | 8 files | 8+ |
| 6 | MEDIUM | Configurable rate limiter cleanup | 2 files | 4 |
| 7 | MEDIUM | Welford's algorithm for drift stats | 2 files | 4 |
| 8 | HIGH | Unicode normalization in input guard | 2 files | 6 |
| 9 | HIGH | Context variable cleanup | 2 files | 3 |
| 10 | HIGH | E2E authorization pipeline test | 1 file | 7 |
| 11 | MEDIUM | Thread safety stress tests | 1 file | 5 |
| 12 | MEDIUM | Decorator combination tests | 1 file | 6 |
| 13 | MEDIUM | Sample data generator script | 1 file | 0 (script, not test) |
| 14 | MEDIUM | Public API docstrings | 12 files | 0 (docs only) |
| 15 | MEDIUM | Quickstart guide update | 1 file | 0 (docs only) |
| 16 | LOW | Lint and type-check test files | 60+ files | 0 (fixes only) |
| 17 | LOW | Version bump and CHANGELOG | 4 files | 0 (metadata only) |
| 18 | LOW | Final validation and diagrams | 1 file | 0 (validation only) |

**Estimated total new tests:** 56+
**Estimated total test count after completion:** 2,597+

---

## Hardcoded Limits Reference

All hardcoded limits in the Proxilion SDK as of version 0.0.7. This table should be kept up to date as limits are made configurable.

| Module | Limit | Default Value | Configurable | Notes |
|--------|-------|---------------|-------------|-------|
| rate_limiter.py | Cleanup interval | 300 seconds | After Step 6: YES | Was hardcoded, made configurable in this spec |
| rate_limiter.py | Cleanup batch size | 100 buckets | After Step 6: YES | New in this spec |
| intent_capsule.py | Max tool calls per capsule | 100 | No | Raises IntentHijackError at limit |
| behavioral_drift.py | Metric deque maxlen | 10,000 | No | Evicts oldest on overflow |
| cost_tracker.py | Record deque maxlen | 100,000 | No | Evicts oldest on overflow |
| idor_protection.py | Max objects per scope | 100,000 | No | Documented in README |
| agent_trust.py | Max hierarchy depth | 10 | No | Raises AgentTrustError |
| agent_trust.py | Max nonces before cleanup | 10,000 | No | Approximate cleanup of 5,000 oldest |
| streaming/detector.py | Max partial calls | 1,000 | No | Stale entries reaped by timeout |
| streaming/detector.py | Stale timeout | 300 seconds | No | Entries older than this are reaped |
| memory_integrity.py | Max context size | 1,000 messages | Yes (constructor) | Adds violation if exceeded |
| secret key validation | Minimum key length | 16 characters | No | Raises ConfigurationError |
| input_guard.py | Built-in patterns | 14 regex patterns | Extensible | Custom patterns can be added |
| output_guard.py | Built-in patterns | 22 regex patterns | Extensible | Custom patterns can be added |
| hash_chain.py | Merkle tree batch size | Configurable | Yes | Set at construction time |
| session.py | Session expiry | Configurable | Yes | Set at construction time |

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Step 2 breaks existing tests using placeholder keys | HIGH | LOW | Search-and-replace in test files; CI catches any misses |
| Step 3 validation rejects currently-valid edge cases | MEDIUM | MEDIUM | Only validate non-empty string and correct types; permissive on content |
| Step 7 Welford's algorithm introduces floating-point drift | LOW | LOW | Test verifies results match stdlib within 1e-10 tolerance |
| Step 8 Unicode normalization causes false positives | MEDIUM | MEDIUM | Test includes legitimate Unicode text (CJK, Arabic) to verify no false positives |
| Step 11 stress tests are timing-sensitive (flaky) | MEDIUM | LOW | Use tolerance ranges (+/- 1) and generous timeouts |

---

## Acceptance Criteria

This spec is complete when:

1. All 18 steps are marked DONE in STATE.md
2. `python3 -m ruff check proxilion tests` reports 0 violations
3. `python3 -m ruff format --check proxilion tests` reports 0 violations
4. `python3 -m mypy proxilion` reports 0 errors (or fewer than the 5 pre-existing pydantic errors)
5. `python3 -m pytest -x -q` passes with 2,590+ tests (2,536 baseline + 56 new)
6. No test uses placeholder secret keys
7. All public API classes and methods have docstrings
8. The quickstart guide covers all 12 features and all 9 decorators
9. Version is 0.0.11 in both pyproject.toml and __init__.py
10. CHANGELOG.md has a 0.0.11 section
11. README.md Mermaid diagrams are accurate and include the secret key validation flow
12. The sample data generator script runs without error
