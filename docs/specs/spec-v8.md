# Proxilion SDK -- Production Hardening Spec v8

**Version:** 0.0.13 -> 0.0.14
**Date:** 2026-03-19
**Status:** READY FOR IMPLEMENTATION
**Previous spec:** docs/specs/spec-v7.md (0.0.12 -> 0.0.13, depends on spec-v7 completion)
**Depends on:** spec-v7 must be fully complete before this spec begins (spec-v2 through spec-v7 form a sequential dependency chain)

---

## Executive Summary

This spec covers the ninth improvement cycle for the Proxilion SDK. It targets issues discovered during a fresh deep-dive audit of 89 Python source files, 48,475 source lines, 2,658 collected tests, and all eight prior specs. Every item in this spec addresses a concrete deficiency in existing code -- no net-new features are introduced.

The previous eight specs addressed: critical runtime bugs (spec.md), CI hardening and version sync (spec-v1), structured errors and developer experience (spec-v2), thread-safety stabilization (spec-v3), security bypass vector closure (spec-v4), input validation and secret key management (spec-v5), rate limiter correctness and crypto robustness (spec-v6), and comprehensive gap closure across all prior findings (spec-v7).

This cycle focuses on six pillars:

1. **Cryptographic correctness** -- fixing delegation token serialization fragility, non-constant-time hash comparison in audit verification, and eliminating stored plaintext agent secrets in favor of on-demand derivation.
2. **Thread safety closure** -- adding missing locks to QueueApprovalStrategy, fixing the CircuitBreaker half-open count leak, and resolving the MultiDimensionalRateLimiter TOCTOU race with a proper atomic check-and-consume pattern.
3. **Data leakage prevention** -- truncating matched text in InputGuard to match OutputGuard behavior, fixing the OutputGuard truncation logic that reveals most of a short secret, and removing sensitive kwargs injection from the enforce_scope decorator.
4. **Performance optimization** -- caching canonical JSON in AuditEvent, adding an event ID index to HashChain, eliminating double pattern scanning in InputGuard sanitization, replacing O(n) LFU eviction with a heap, and removing a redundant inner import.
5. **Code maintainability** -- extracting the triplicated secret key validation into a shared utility, fixing ConfigurationError constructor misuse across three modules, replacing duck-typing in cost_limited with a proper protocol, and cleaning up dead code in verify_hash.
6. **Test coverage hardening** -- adding concurrency tests for MultiDimensionalRateLimiter and QueueApprovalStrategy, testing audit log file rotation, verifying LFU eviction correctness, and adding tamper-detection tests for verify_hash.

Every item targets code that already exists. After this spec is complete, the SDK should have zero known P1 findings, zero known P2 findings related to thread safety or data leakage, and measurable performance improvements in audit logging and cache eviction hot paths.

---

## Codebase Snapshot (2026-03-19)

| Metric | Value |
|--------|-------|
| Python source files | 89 |
| Source lines (proxilion/) | 48,475 |
| Test files | 58 |
| Test count | 2,658 collected, 2,490 passed, 108 skipped, 29 xfailed |
| Python versions tested | 3.10, 3.11, 3.12 (CI), 3.13 (local) |
| Ruff lint violations | 0 |
| Ruff format violations | 0 |
| Mypy errors | 0 (all 89 source files clean) |
| Version (pyproject.toml) | 0.0.7 |
| Version (__init__.py) | 0.0.7 |
| CI/CD | GitHub Actions (test, lint, typecheck) |
| Coverage threshold | 85% (enforced in CI) |
| Known P1 findings (pre-spec-v7) | 8 |
| Known P2 findings (pre-spec-v7) | 14 |
| Known P3 findings (pre-spec-v7) | 19 |
| Spec-v2 progress | 13/18 steps complete |
| Specs pending execution | spec-v2 (steps 14-18), spec-v3 through spec-v7 |

---

## Logic Breakdown: Deterministic vs Probabilistic

Proxilion uses deterministic logic for all security decisions. This breakdown quantifies the split across all 89 modules.

| Logic Type | Percentage | Module Count | Description |
|------------|-----------|--------------|-------------|
| Deterministic | ~97% | 86 of 89 | Regex pattern matching, set membership checks, SHA-256 hash chains, HMAC-SHA256 verification, token bucket counters, finite state machines, boolean policy evaluation, z-score threshold comparisons, path normalization via PurePosixPath, Merkle tree construction |
| Statistical (bounded, auditable) | ~3% | 3 of 89 | Token estimation heuristic in context/message_history.py (1.3 words/token ratio), risk score aggregation in guards (weighted sum of deterministic pattern matches), behavioral drift z-score thresholds (statistical but not ML -- same input always produces same output given same baseline) |

Zero LLM inference calls. Zero ML model evaluations. Zero non-deterministic random decisions in any security path. The three "statistical" modules use bounded arithmetic on deterministic inputs -- they are auditable and reproducible.

---

## Dependency Chain

```
spec.md (0.0.4-0.0.5) COMPLETE
    |
spec-v1.md (0.0.6-0.0.7) COMPLETE
    |
spec-v2.md (0.0.7-0.0.8) IN PROGRESS (13/18)
    |
spec-v3.md (0.0.8-0.0.9) BLOCKED on spec-v2
    |
spec-v4.md (0.0.9-0.0.10) BLOCKED on spec-v3
    |
spec-v5.md (0.0.10-0.0.11) BLOCKED on spec-v4
    |
spec-v6.md (0.0.11-0.0.12) BLOCKED on spec-v5
    |
spec-v7.md (0.0.12-0.0.13) BLOCKED on spec-v6
    |
spec-v8.md (0.0.13-0.0.14) BLOCKED on spec-v7  <-- THIS SPEC
```

---

## Quick Install

```bash
# Basic install (pure Python, no external dependencies)
pip install proxilion

# With optional extras
pip install proxilion[pydantic]    # Schema validation via Pydantic v2
pip install proxilion[casbin]      # Casbin policy engine backend
pip install proxilion[opa]         # Open Policy Agent backend

# Development install from source
git clone https://github.com/clay-good/proxilion-sdk.git
cd proxilion-sdk
pip install -e ".[dev,pydantic]"

# Run the full CI check locally
python3 -m ruff check proxilion tests \
  && python3 -m ruff format --check proxilion tests \
  && python3 -m mypy proxilion \
  && python3 -m pytest -x -q
```

---

## Intent Examples

These examples describe expected behavior from the perspective of a developer integrating Proxilion. Each maps to a specific module and describes the contract that the SDK must uphold.

### Input Guard (proxilion/guards/input_guard.py)

As a developer, when I pass user input through InputGuard.check(), I expect:
- The guard to normalize Unicode (NFKD) before pattern matching so that homoglyph evasion is blocked.
- The guard to return a GuardResult with a risk_score between 0.0 and 1.0.
- The guard to never include raw matched text in the result -- only truncated or redacted previews -- so that sensitive content is not leaked into logs.
- The guard to reject "ignore previous instructions" whether written normally, in ALL CAPS, with dots between letters, or with leetspeak substitutions.

### Output Guard (proxilion/guards/output_guard.py)

As a developer, when I pass LLM output through OutputGuard.check(), I expect:
- The guard to detect credit card numbers, SSNs, API keys, and other credential patterns via regex.
- The truncation of matched sensitive data to never reveal more than 25% of the original value, regardless of string length.
- The enable_pii flag to be respected even when custom patterns are provided (or the guard to raise ConfigurationError if the two conflict).

### Rate Limiter (proxilion/security/rate_limiter.py)

As a developer, when I configure a MultiDimensionalRateLimiter with three tiers (global, user, tool), I expect:
- Atomic check-and-consume: if any tier would reject the request, no tokens are consumed from any tier.
- Thread safety: two concurrent requests arriving when exactly one token remains must not both succeed.
- The SlidingWindowRateLimiter to bound its memory usage even under sustained high traffic.

### Circuit Breaker (proxilion/security/circuit_breaker.py)

As a developer, when a circuit transitions from OPEN to HALF_OPEN, I expect:
- The half_open_max parameter to correctly limit concurrent probe requests.
- Successful probes to decrement the half-open count so that additional probes can enter.
- The circuit to transition to CLOSED after success_threshold consecutive successes without rejecting valid probes.

### Audit Logger (proxilion/audit/logger.py)

As a developer, when I configure AuditLogger with sync_writes=True, I expect:
- Each write to be durable: if the process crashes immediately after the write call returns, the event must be on disk.
- File rotation to be atomic: no event is lost or duplicated during rotation.
- Hash chain integrity to be verifiable even after rotation creates a new file.

### Agent Trust (proxilion/security/agent_trust.py)

As a developer, when I create delegation tokens between agents, I expect:
- The capability set to be serialized identically during creation and verification -- changing the serialization format must break verification, not silently pass.
- Agent secrets to not be stored in long-lived data structures where a memory dump could expose them.
- Nonce replay protection to evict the oldest nonces first, not arbitrary ones, so that recent messages are always protected.

### Decorators (proxilion/decorators.py)

As a developer, when I use the @enforce_scope decorator, I expect:
- The scope context to be available to my function without it needing to accept a _scope_context keyword argument -- the decorator should use contextvars, not kwargs injection.
- The @cost_limited decorator to work with any limiter that implements a defined protocol, not rely on duck-typing with hasattr checks.

### Hash Chain (proxilion/audit/hash_chain.py)

As a developer, when I call HashChain.get_proof(event_id), I expect:
- The lookup to complete in O(1) time, not O(n), because audit logs grow without bound in production.
- The proof to be verifiable: I can independently recompute the hash and confirm it matches the chain.

### Tool Cache (proxilion/caching/tool_cache.py)

As a developer, when I configure ToolCache with EvictionPolicy.LFU, I expect:
- The least-frequently-used entry to be evicted, not an arbitrary entry.
- Eviction to complete in O(log n) time, not O(n), so that cache performance does not degrade as the cache grows.

---

## Steps

---

### Step 1: Extract shared secret key validation utility

**Priority:** HIGH
**Complexity:** LOW
**Category:** Maintainability

**Problem:** The function _validate_secret_key and the tuple _PLACEHOLDER_PATTERNS are copy-pasted identically across three modules: proxilion/security/memory_integrity.py (lines 57-70), proxilion/security/agent_trust.py (lines 70-83), and proxilion/security/intent_capsule.py (lines 65-78). Any future fix to validation logic must be applied in three places, creating divergence risk.

**Intent:** As a maintainer, when I update the placeholder detection patterns or minimum key length, I expect to change one file and have all three crypto modules pick up the change automatically.

**Fix:**
- Create proxilion/security/_crypto_utils.py containing _PLACEHOLDER_PATTERNS and _validate_secret_key.
- Update memory_integrity.py, agent_trust.py, and intent_capsule.py to import from _crypto_utils instead of defining their own copies.
- Verify that all three modules still pass their existing test suites unchanged.

**Claude Code Prompt:**
```
Read proxilion/security/memory_integrity.py lines 57-70 to capture the exact _PLACEHOLDER_PATTERNS tuple and _validate_secret_key function. Then read the same function from proxilion/security/agent_trust.py lines 70-83 and proxilion/security/intent_capsule.py lines 65-78. Confirm they are identical.

Create a new file proxilion/security/_crypto_utils.py with:
1. The module docstring: "Shared cryptographic utilities for security modules."
2. The import for ConfigurationError from proxilion.exceptions.
3. The _PLACEHOLDER_PATTERNS tuple (exact copy).
4. The _validate_secret_key function (exact copy).

In each of the three consuming modules, replace the local _PLACEHOLDER_PATTERNS and _validate_secret_key definitions with:
    from proxilion.security._crypto_utils import _validate_secret_key

Remove the now-unused import of ConfigurationError from each module ONLY if ConfigurationError is not used elsewhere in that module. Check each file for other usages before removing.

Run: python3 -m pytest tests/test_security/ -x -q
Run: python3 -m mypy proxilion/security/_crypto_utils.py proxilion/security/memory_integrity.py proxilion/security/agent_trust.py proxilion/security/intent_capsule.py
Run: python3 -m ruff check proxilion/security/_crypto_utils.py
```

**Verification:**
- All existing tests pass with zero changes to test files.
- mypy reports zero errors on all four files.
- ruff reports zero violations on the new file.
- grep confirms _validate_secret_key is defined in exactly one file.

---

### Step 2: Fix ConfigurationError constructor misuse

**Priority:** HIGH
**Complexity:** LOW
**Category:** Correctness

**Problem:** Three security modules call ConfigurationError("secret_key must be at least 16 characters..."), passing a full sentence as the config_key positional argument. The ConfigurationError constructor expects config_key as a short key name, with optional expected and received keyword arguments. The current usage produces confusing error messages like "Configuration error for 'secret_key must be at least 16 characters...'".

**Intent:** As a developer catching ConfigurationError, I expect the config_key field to contain the key name ("secret_key"), and the expected/received fields to describe the constraint and actual value, so I can programmatically inspect the error.

**Fix:**
- In _validate_secret_key (now in _crypto_utils.py from Step 1), update the two raise sites:
  - Length check: raise ConfigurationError(config_key="secret_key", expected="at least 16 characters for HMAC security", received=f"{len(key_str)} characters")
  - Placeholder check: raise ConfigurationError(config_key="secret_key", expected="a real cryptographic key", received="placeholder pattern detected")

**Claude Code Prompt:**
```
Read proxilion/security/_crypto_utils.py (created in Step 1) and locate the two raise ConfigurationError(...) calls inside _validate_secret_key.

For the length validation raise, change from:
    raise ConfigurationError("secret_key must be at least 16 characters...")
to:
    raise ConfigurationError(
        config_key="secret_key",
        expected="at least 16 characters for HMAC security",
        received=f"{len(secret_key)} characters",
    )

For the placeholder pattern raise, change from:
    raise ConfigurationError("secret_key appears to be a placeholder...")
to:
    raise ConfigurationError(
        config_key="secret_key",
        expected="a real cryptographic key (not a placeholder)",
        received="placeholder pattern detected in key value",
    )

Adjust variable names to match the actual parameter name used in the function signature. Read the function first to confirm the exact parameter name.

Run: python3 -m pytest tests/test_security/ -x -q
Run: python3 -m mypy proxilion/security/_crypto_utils.py

If any tests relied on the old error message string, update the test assertions to match the new structured format. The key behavior (raising ConfigurationError) must remain identical.
```

**Verification:**
- All security tests pass.
- mypy clean on the modified file.
- A test that catches ConfigurationError can inspect .config_key == "secret_key".

---

### Step 3: Fix non-constant-time hash comparison in AuditEvent.verify_hash

**Priority:** HIGH
**Complexity:** LOW
**Category:** Security

**Problem:** AuditEvent.verify_hash in proxilion/types.py (line 373) uses Python string equality (==) to compare SHA-256 hex digests. While Python string comparison is not guaranteed to be constant-time, the rest of the codebase consistently uses hmac.compare_digest for security-critical comparisons. This is a correctness gap in the audit integrity verification path.

**Intent:** As a security auditor, I expect all hash and signature comparisons in the SDK to use constant-time comparison functions, preventing timing side-channel attacks regardless of deployment context.

**Fix:**
- Import hmac at the top of types.py (if not already imported).
- Replace the == comparison in verify_hash with hmac.compare_digest(stored_hash, expected).
- Remove the unnecessary store/restore of self.event_hash (lines 362-371) since _canonical_json does not depend on event_hash.

**Claude Code Prompt:**
```
Read proxilion/types.py and locate the verify_hash method (around line 352-373). Understand the full method body.

1. Check if hmac is already imported at the top of the file. If not, add: import hmac

2. Simplify the verify_hash method. The current implementation unnecessarily stores and restores self.event_hash. Since _canonical_json() does not include event_hash in its output, this is dead code. Replace the entire method body with:

    def verify_hash(self) -> bool:
        """Verify the integrity of this event by recomputing its hash."""
        if not self.event_hash:
            return False
        canonical = self._canonical_json()
        if self.previous_hash:
            hash_input = f"{self.previous_hash}|{canonical}"
        else:
            hash_input = canonical
        expected = hashlib.sha256(hash_input.encode()).hexdigest()
        return hmac.compare_digest(self.event_hash, expected)

3. Verify that _canonical_json() does NOT reference self.event_hash by reading that method.

Run: python3 -m pytest tests/test_audit.py tests/test_hash_chain_detailed.py -x -q
Run: python3 -m mypy proxilion/types.py
```

**Verification:**
- All audit tests pass.
- mypy clean.
- grep confirms no == comparison on hash values in types.py verify_hash.

---

### Step 4: Fix delegation token capability serialization fragility

**Priority:** HIGH
**Complexity:** MEDIUM
**Category:** Security

**Problem:** In proxilion/security/agent_trust.py, delegation token creation (line 645) and verification (line 927) both serialize capabilities via str(sorted(capabilities)) and f"{sorted(token.granted_capabilities)}" respectively. While these produce identical output today because both convert a sorted list to its string representation, they are two separate code paths that are not explicitly aligned. More critically, the _secret field on AgentCredential is a hex string that gets .encode()'d for HMAC signing, meaning the effective key is the ASCII encoding of hex characters rather than raw HMAC output bytes. This does not reduce security in practice (the entropy is preserved) but deviates from cryptographic best practice.

**Intent:** As a security engineer, I expect token creation and verification to use a single canonical serialization function, so that any change to the format is applied in both paths simultaneously. I expect the serialization to use json.dumps with sort_keys for stability.

**Fix:**
- Add a private function _serialize_capabilities(caps: set[str]) -> str that returns json.dumps(sorted(caps), separators=(",", ":")) for compact, deterministic output.
- Replace both str(sorted(capabilities)) in token creation and the equivalent in verification with calls to _serialize_capabilities.
- Add a comment documenting the canonical format.

**Claude Code Prompt:**
```
Read proxilion/security/agent_trust.py and locate:
1. The delegation token creation code around line 645 where capabilities are serialized into token_data.
2. The verification code around line 927 where capabilities are re-serialized for signature comparison.

Add a private function near the top of the class or module:

    def _serialize_capabilities(capabilities: set[str]) -> str:
        """Canonical serialization of capability sets for HMAC signing.

        Uses JSON with sorted keys and compact separators to ensure
        identical output regardless of set iteration order.
        """
        import json
        return json.dumps(sorted(capabilities), separators=(",", ":"))

Replace str(sorted(capabilities)) in the token creation path with _serialize_capabilities(capabilities).
Replace the equivalent serialization in the verification path with _serialize_capabilities(token.granted_capabilities).

Ensure both paths now call the same function. The json import should be at module level, not inside the function.

Run: python3 -m pytest tests/test_security/test_agent_trust.py -x -q
Run: python3 -m mypy proxilion/security/agent_trust.py
```

**Verification:**
- All agent trust tests pass.
- mypy clean.
- grep confirms str(sorted( no longer appears in agent_trust.py in the context of capabilities.

---

### Step 5: Fix replay nonce eviction to be time-ordered

**Priority:** HIGH
**Complexity:** MEDIUM
**Category:** Security

**Problem:** In proxilion/security/agent_trust.py (lines 886-890), when the nonce store exceeds 10,000 entries, 5,000 are removed by converting the set to a list and slicing the first 5,000 elements. Since set iteration order is undefined in Python, this removes arbitrary nonces rather than the oldest ones. An attacker who knows a recent nonce was "evicted" could replay it.

**Intent:** As a security engineer, I expect replay protection nonces to be evicted oldest-first, so that recent messages are always protected against replay. The eviction should be bounded by both a hard capacity cap and a TTL.

**Fix:**
- Replace _message_nonces: set[str] with _message_nonces: OrderedDict[str, float] where keys are nonce strings and values are insertion timestamps (time.time()).
- On insertion, add the nonce with its timestamp.
- On eviction (when size exceeds threshold), remove the oldest entries (first entries in OrderedDict).
- In cleanup_expired (or equivalent), also purge entries older than a configurable nonce_ttl_seconds.

**Claude Code Prompt:**
```
Read proxilion/security/agent_trust.py and locate:
1. The _message_nonces attribute initialization (likely in __init__).
2. The nonce insertion code (where new nonces are added).
3. The eviction code around lines 886-890.
4. Any cleanup_expired or similar maintenance method.

Make the following changes:

1. At the top of the file, add: from collections import OrderedDict (if not already imported).

2. Change the _message_nonces type from set[str] to OrderedDict[str, float].

3. In __init__, initialize as: self._message_nonces: OrderedDict[str, float] = OrderedDict()

4. Where nonces are checked for existence, change "nonce in self._message_nonces" (works for both set and OrderedDict, no change needed).

5. Where nonces are added, change from self._message_nonces.add(nonce) to:
    self._message_nonces[nonce] = time.time()

6. Replace the eviction block (lines 886-890) with:
    if len(self._message_nonces) > 10000:
        # Evict oldest 5000 entries (first entries in OrderedDict)
        for _ in range(5000):
            self._message_nonces.popitem(last=False)

7. In any cleanup method, add TTL-based purge:
    now = time.time()
    expired = [
        nonce for nonce, ts in self._message_nonces.items()
        if now - ts > self._nonce_ttl_seconds
    ]
    for nonce in expired:
        del self._message_nonces[nonce]

If _nonce_ttl_seconds does not exist as an attribute, add it to __init__ with a default of 300 (5 minutes). Make it configurable via the constructor.

Run: python3 -m pytest tests/test_security/test_agent_trust.py -x -q
Run: python3 -m mypy proxilion/security/agent_trust.py
```

**Verification:**
- All agent trust tests pass.
- mypy clean.
- The nonce store is now an OrderedDict, confirmed by reading the attribute type.

---

### Step 6: Add thread safety to QueueApprovalStrategy

**Priority:** HIGH
**Complexity:** MEDIUM
**Category:** Reliability

**Problem:** QueueApprovalStrategy in proxilion/decorators.py (line 203) has a _request_counter that is a plain int incremented without any lock. Under concurrent callers, two requests could receive the same request_id, causing one to silently overwrite the other in _pending, _events, and _async_events dictionaries.

**Intent:** As a developer using QueueApprovalStrategy in a multi-threaded application, I expect each request to receive a unique request_id and for no approval state to be silently lost due to race conditions.

**Fix:**
- Add a threading.Lock to QueueApprovalStrategy.__init__.
- Wrap the _request_counter increment and _pending/_events/_async_events mutations in a with self._lock: block.
- Ensure approve() and deny() also acquire the lock when modifying shared state.

**Claude Code Prompt:**
```
Read proxilion/decorators.py and locate the QueueApprovalStrategy class. Find:
1. The __init__ method and the _request_counter attribute.
2. The request_approval method (or equivalent) where _request_counter is incremented.
3. The approve() and deny() methods.
4. Any other methods that mutate _pending, _events, or _async_events.

Make the following changes:

1. Add import threading at the top if not already present.

2. In __init__, add: self._lock = threading.Lock()

3. In the method that increments _request_counter and creates a new request entry, wrap the counter increment AND the dict insertion in:
    with self._lock:
        self._request_counter += 1
        request_id = f"req_{self._request_counter}"
        self._pending[request_id] = ...

4. In approve() and deny(), wrap the dict mutation (removing from _pending, setting events) in:
    with self._lock:
        ...

5. Do NOT hold the lock while calling external callbacks or awaiting. Only protect the shared state mutations.

Run: python3 -m pytest tests/test_decorators.py -x -q
Run: python3 -m mypy proxilion/decorators.py
Run: python3 -m ruff check proxilion/decorators.py
```

**Verification:**
- All decorator tests pass.
- mypy and ruff clean.
- grep confirms self._lock is used in QueueApprovalStrategy.

---

### Step 7: Fix CircuitBreaker half-open count leak

**Priority:** HIGH
**Complexity:** MEDIUM
**Category:** Reliability

**Problem:** In proxilion/security/circuit_breaker.py, when the circuit is in HALF_OPEN state, _half_open_count is incremented for each probe request (line 320) but is never decremented on the success path in _record_success (line 182). This means after half_open_max successful probes, the circuit starts rejecting new probes even though they are succeeding. The count is only reset to 0 when transitioning back to HALF_OPEN from OPEN, not when transitioning to CLOSED.

**Intent:** As a developer, I expect the circuit breaker to allow probe requests up to half_open_max concurrently. When a probe succeeds, it should release its slot so another probe can enter. After success_threshold consecutive successes, the circuit should transition to CLOSED.

**Fix:**
- In _record_success, decrement _half_open_count by 1 (clamped to 0) when the circuit is in HALF_OPEN state, before the potential transition to CLOSED.
- When transitioning to CLOSED, reset _half_open_count to 0.

**Claude Code Prompt:**
```
Read proxilion/security/circuit_breaker.py and locate:
1. The _record_success method (around line 182).
2. The code that increments _half_open_count (around line 320).
3. The _set_state method or wherever state transitions happen.
4. The _maybe_transition_to_half_open method (around line 162).

In _record_success, add the following BEFORE the transition check:

    if self._state == CircuitState.HALF_OPEN:
        self._half_open_count = max(0, self._half_open_count - 1)

Also confirm that when the circuit transitions to CLOSED (inside _record_success or _set_state), _half_open_count is reset to 0. If it is not, add:
    self._half_open_count = 0

This must happen under the existing self._lock that protects _record_success.

Run: python3 -m pytest tests/test_security/test_circuit_breaker.py -x -q
Run: python3 -m mypy proxilion/security/circuit_breaker.py
```

**Verification:**
- All circuit breaker tests pass.
- A new test (Step 17) will confirm the count does not leak.
- mypy clean.

---

### Step 8: Truncate matched text in InputGuard results

**Priority:** HIGH
**Complexity:** LOW
**Category:** Security / Data Leakage

**Problem:** InputGuard.check() in proxilion/guards/input_guard.py (line 356) stores raw match.group() in all_matches["matched_text"]. The GuardResult.matches list is returned to callers and may be logged. If the match contains user-supplied content (e.g., partial prompt injection text containing credentials or PII), this leaks sensitive content into structured results. OutputGuard already has a _truncate_match helper, but InputGuard does not use it.

**Intent:** As a developer, I expect GuardResult.matches to never contain raw sensitive text. Matched content should be truncated to prevent leakage into application logs, monitoring systems, or error responses.

**Fix:**
- Add a _truncate_match method to InputGuard (or import a shared version).
- Apply truncation to all_matches["matched_text"] before storing in the result.

**Claude Code Prompt:**
```
Read proxilion/guards/input_guard.py and locate:
1. The check() method and the line where matched_text is stored (around line 356).
2. Any existing _truncate_match or similar method.

Read proxilion/guards/output_guard.py and locate the _truncate_match method (around line 572).

Add a _truncate_match method to InputGuard. Use the improved version from Step 9 (not the current buggy one). The method should:

    def _truncate_match(self, text: str, max_visible: int = 8) -> str:
        """Truncate matched text to prevent sensitive data leakage in logs."""
        if len(text) <= 4:
            return "[REDACTED]"
        if len(text) <= max_visible:
            return text[:2] + "..." + text[-1]
        return text[:4] + "..." + text[-2:]

In the check() method, change:
    all_matches["matched_text"] = match.group()
to:
    all_matches["matched_text"] = self._truncate_match(match.group())

Run: python3 -m pytest tests/test_guards.py -x -q
Run: python3 -m mypy proxilion/guards/input_guard.py
```

**Verification:**
- Guard tests pass (some assertions may need updating if they checked exact matched_text values).
- mypy clean.
- No raw matched text appears in GuardResult for InputGuard.

---

### Step 9: Fix OutputGuard truncation logic for short secrets

**Priority:** HIGH
**Complexity:** LOW
**Category:** Security / Data Leakage

**Problem:** OutputGuard._truncate_match in proxilion/guards/output_guard.py (lines 572-576) has a logic bug: for a 9-character string (e.g., a short password), it returns text[:4] + "..." + text[-4:], which reveals 8 of 9 characters. The method name suggests data is being hidden, but for strings between 9 and 20 characters, most of the value is exposed.

**Intent:** As a developer, I expect _truncate_match to never reveal more than 25% of the original value. For very short values (8 characters or fewer), the entire value should be replaced with a redaction marker.

**Fix:**
- Rewrite _truncate_match to enforce a maximum reveal ratio.
- For strings of 8 characters or fewer: return "[REDACTED]".
- For strings of 9-20 characters: return text[:2] + "..." + text[-1] (reveal 3 of 9-20 chars = 15-33%).
- For strings longer than 20 characters: return text[:4] + "..." + text[-2:] (reveal 6 of 21+ chars = <29%).

**Claude Code Prompt:**
```
Read proxilion/guards/output_guard.py and locate the _truncate_match method (around line 572-576).

Replace the method body with:

    def _truncate_match(self, text: str, max_length: int = 20) -> str:
        """Truncate matched text to prevent sensitive data leakage.

        Ensures no more than ~25% of the original value is visible.
        """
        if len(text) <= 8:
            return "[REDACTED]"
        if len(text) <= max_length:
            return text[:2] + "..." + text[-1]
        return text[:4] + "..." + text[-2:]

Run: python3 -m pytest tests/test_guards.py -x -q
Run: python3 -m mypy proxilion/guards/output_guard.py

If any tests assert on specific truncated output format, update them to match the new format. The security property (not revealing the full value) is what matters.
```

**Verification:**
- Guard tests pass.
- mypy clean.
- Manual check: _truncate_match("password1") returns "pa...1" (3 of 9 chars = 33%).
- Manual check: _truncate_match("mypassword123456789012") returns "mypa...12" (6 of 22 chars = 27%).

---

### Step 10: Fix enforce_scope kwargs injection

**Priority:** MEDIUM
**Complexity:** MEDIUM
**Category:** Maintainability / Correctness

**Problem:** The enforce_scope decorator in proxilion/decorators.py (lines 860, 882) injects a _scope_context keyword argument into the decorated function's kwargs. If the function does not accept **kwargs, this raises TypeError at runtime. This is a hidden API contract that breaks functions with explicit signatures.

**Intent:** As a developer, I expect @enforce_scope to work with any function signature. The scope context should be available through a well-defined mechanism (such as a context variable) that does not modify the function's call signature.

**Fix:**
- Add a module-level ContextVar: _scope_context_var: contextvars.ContextVar[ScopeContext | None] = contextvars.ContextVar("_scope_context", default=None)
- In the decorator, set the context variable instead of injecting into kwargs.
- Export a get_scope_context() function that returns _scope_context_var.get().
- Remove the kwargs["_scope_context"] = ctx line.

**Claude Code Prompt:**
```
Read proxilion/decorators.py and locate the enforce_scope decorator. Find the lines where kwargs["_scope_context"] = ctx is set (around lines 860 and 882 -- there may be both sync and async paths).

1. Add at the top of the file (with other imports):
    import contextvars

2. Add a module-level context variable near other module-level declarations:
    _scope_context_var: contextvars.ContextVar[Any] = contextvars.ContextVar(
        "_scope_context", default=None
    )

3. Add a public accessor function:
    def get_scope_context() -> Any:
        """Retrieve the current scope context set by @enforce_scope.

        Returns None if called outside an @enforce_scope-decorated function.
        """
        return _scope_context_var.get()

4. In the enforce_scope decorator, replace:
    kwargs["_scope_context"] = ctx
    result = func(*args, **kwargs)
with:
    token = _scope_context_var.set(ctx)
    try:
        result = func(*args, **kwargs)
    finally:
        _scope_context_var.reset(token)

Do this for both the sync and async wrapper paths.

5. Add get_scope_context to the module's __all__ if one exists, and to proxilion/__init__.py exports.

Run: python3 -m pytest tests/test_decorators.py tests/test_scope_enforcer.py -x -q
Run: python3 -m mypy proxilion/decorators.py
Run: python3 -m ruff check proxilion/decorators.py
```

**Verification:**
- All decorator and scope enforcer tests pass.
- mypy and ruff clean.
- grep confirms kwargs["_scope_context"] no longer appears in decorators.py.

---

### Step 11: Replace duck-typing in cost_limited with protocol

**Priority:** MEDIUM
**Complexity:** MEDIUM
**Category:** Maintainability / Type Safety

**Problem:** The cost_limited decorator in proxilion/decorators.py (lines 1051-1115) uses hasattr(limiter, "allow_request") and hasattr(limiter, "get_status") to distinguish between HybridRateLimiter and CostLimiter. This fragile duck-typing means a future limiter type with allow_request but not get_status will silently produce incorrect BudgetExceededError values (current_spend=0.0, budget_limit=0.0).

**Intent:** As a developer, I expect the cost_limited decorator to work with any limiter that conforms to a defined protocol. The type checker should flag incompatible limiter types at development time, not at runtime.

**Fix:**
- Define a CostLimiterProtocol (runtime_checkable Protocol class) with the required methods.
- Use isinstance checks against the protocol instead of hasattr.
- Keep backward compatibility: the existing CostLimiter and HybridRateLimiter should already satisfy the protocol without modification.

**Claude Code Prompt:**
```
Read proxilion/decorators.py and locate the cost_limited decorator (around line 1051). Identify all hasattr checks used to distinguish limiter types.

Read proxilion/security/cost_limiter.py (or wherever CostLimiter is defined) to understand its interface.
Read the HybridRateLimiter class to understand its interface.

1. Near the top of decorators.py (after imports), define:

    from typing import Protocol, runtime_checkable

    @runtime_checkable
    class CostLimiterProtocol(Protocol):
        """Protocol for cost-aware rate limiters."""
        def check_limit(self, user_id: str, estimated_cost: float) -> None: ...
        def record_spend(self, user_id: str, actual_cost: float) -> None: ...

    @runtime_checkable
    class CostStatusProtocol(Protocol):
        """Protocol for limiters that report budget status."""
        def get_status(self, user_id: str) -> Any: ...

Adjust the method signatures to match what CostLimiter and HybridRateLimiter actually expose. Read those classes first.

2. Replace hasattr(limiter, "allow_request") with isinstance(limiter, CostLimiterProtocol) or keep the existing pattern but add type annotations.

3. Replace hasattr(limiter, "get_status") with isinstance(limiter, CostStatusProtocol).

Run: python3 -m pytest tests/test_decorators.py tests/test_cost_limiter.py -x -q
Run: python3 -m mypy proxilion/decorators.py
Run: python3 -m ruff check proxilion/decorators.py
```

**Verification:**
- All tests pass.
- mypy and ruff clean.
- hasattr checks for limiter type detection are replaced with isinstance.

---

### Step 12: Cache canonical JSON in AuditEvent

**Priority:** MEDIUM
**Complexity:** LOW
**Category:** Performance

**Problem:** AuditEvent._canonical_json in proxilion/types.py (lines 320-338) creates a fresh dict from all nested objects (user_context.to_dict(), tool_call.to_dict(), etc.) and JSON-serializes the full graph on every call. Both compute_hash() and verify_hash() call _canonical_json(). For high-frequency audit logging, this creates significant garbage collection pressure. The canonical form never changes after creation because AuditEvent fields that feed into the hash are set at creation time.

**Intent:** As a developer running Proxilion under high load, I expect audit event hashing to not be a performance bottleneck. The canonical JSON should be computed once and reused.

**Fix:**
- Add a _cached_canonical: str | None = field(default=None, init=False, repr=False, compare=False) to AuditEvent.
- In _canonical_json(), check if _cached_canonical is set. If so, return it. If not, compute, cache, and return.
- Since AuditEvent is a non-frozen dataclass, field mutation is allowed.

**Claude Code Prompt:**
```
Read proxilion/types.py and locate the AuditEvent class definition and the _canonical_json method.

1. Add a new field to AuditEvent (after the existing fields, before methods):
    _cached_canonical: str | None = field(default=None, init=False, repr=False, compare=False, hash=False)

2. At the beginning of _canonical_json(), add:
    if self._cached_canonical is not None:
        return self._cached_canonical

3. At the end of _canonical_json(), before the return statement, add:
    self._cached_canonical = result  # (where result is the json.dumps output)
    return result

Make sure the variable name matches what the method currently returns.

Run: python3 -m pytest tests/test_audit.py tests/test_hash_chain_detailed.py -x -q
Run: python3 -m mypy proxilion/types.py
```

**Verification:**
- All audit tests pass.
- mypy clean.
- The canonical JSON is computed only once per AuditEvent instance.

---

### Step 13: Add event ID index to HashChain

**Priority:** MEDIUM
**Complexity:** LOW
**Category:** Performance

**Problem:** HashChain.get_proof in proxilion/audit/hash_chain.py (lines 253-258) performs an O(n) linear scan to find an event by event_id. The existing _hashes dict indexes by event_hash but not by event_id. For audit logs that grow to millions of events, this linear scan becomes a performance bottleneck.

**Intent:** As a developer querying audit proofs in production, I expect get_proof(event_id) to complete in O(1) time, not O(n).

**Fix:**
- Add a _event_id_index: dict[str, int] attribute to HashChain.__init__, mapping event_id to the index in the events list.
- When events are added to the chain, also update _event_id_index.
- In get_proof, use _event_id_index.get(event_id) instead of iterating.

**Claude Code Prompt:**
```
Read proxilion/audit/hash_chain.py and locate:
1. The __init__ method to find where _hashes is initialized.
2. The method that adds events to the chain (likely add_event or append).
3. The get_proof method (around line 253).

1. In __init__, add:
    self._event_id_index: dict[str, int] = {}

2. In the method that adds events, after appending the event to the list, add:
    self._event_id_index[event.event_id] = len(self._events) - 1
   (adjust variable names to match the actual code)

3. In get_proof, replace the linear scan:
    for i, event in enumerate(self._events):
        if event.event_id == event_id:
            ...
with:
    idx = self._event_id_index.get(event_id)
    if idx is None:
        return None  # or raise, matching current behavior
    event = self._events[idx]

Run: python3 -m pytest tests/test_hash_chain_detailed.py tests/test_audit.py -x -q
Run: python3 -m mypy proxilion/audit/hash_chain.py
```

**Verification:**
- All hash chain and audit tests pass.
- mypy clean.
- get_proof no longer iterates all events.

---

### Step 14: Eliminate double pattern scan in InputGuard sanitization

**Priority:** MEDIUM
**Complexity:** LOW
**Category:** Performance

**Problem:** When InputGuard.check() triggers sanitization (action == GuardAction.SANITIZE) and a custom _sanitize_func is provided, the code at proxilion/guards/input_guard.py (lines 453-458) re-runs all pattern matches by iterating self.patterns and calling pattern.match(input_text) again. The matches were already computed during the check phase. This is an unnecessary O(n*m) double scan of the input text where n is input length and m is the number of patterns.

**Intent:** As a developer processing high-volume input through InputGuard, I expect the guard to not re-scan input that was already scanned during the check phase.

**Fix:**
- Pass the already-collected match results (the re.Match objects or their spans) from the check phase into the sanitization path.
- If the sanitize function needs the match objects, collect them during check and store them on the GuardResult or pass them as an internal parameter.

**Claude Code Prompt:**
```
Read proxilion/guards/input_guard.py and locate:
1. The check() method -- find where matches are collected (all_matches list).
2. The sanitization path (around lines 453-458) where patterns are re-iterated.

Refactor so that the sanitization path receives the already-collected match data from the check phase. The approach depends on the exact code structure:

Option A: If the sanitize path only needs the matched text and spans, pass them from the check results.
Option B: If the sanitize path needs re.Match objects, collect them during check and pass them through.

The goal is to remove the second iteration over self.patterns in the sanitization path. Do NOT change the public API of check() or sanitize().

Run: python3 -m pytest tests/test_guards.py -x -q
Run: python3 -m mypy proxilion/guards/input_guard.py
```

**Verification:**
- All guard tests pass.
- mypy clean.
- The sanitization path does not call pattern.match() again.

---

### Step 15: Replace O(n) LFU eviction with min-heap

**Priority:** MEDIUM
**Complexity:** MEDIUM
**Category:** Performance

**Problem:** ToolCache._evict_one with EvictionPolicy.LFU in proxilion/caching/tool_cache.py (lines 456-464) iterates all cache entries to find the minimum-hit entry, giving O(n) per eviction. Under a full cache with frequent writes, every insert triggers an O(n) scan.

**Intent:** As a developer using ToolCache with LFU policy under high load, I expect eviction to complete in O(log n) time, not O(n).

**Fix:**
- Add a heapq-based min-heap that tracks (hit_count, insertion_order, key) tuples.
- On cache hit, increment the hit count and push a new tuple (lazy deletion: old tuples remain in the heap but are skipped if the key no longer exists or the hit count has changed).
- On eviction, pop from the heap until finding a valid entry.

**Claude Code Prompt:**
```
Read proxilion/caching/tool_cache.py and locate:
1. The _evict_one method (around line 456).
2. The LFU branch within _evict_one.
3. How hit counts are tracked (likely a dict or attribute on cache entries).
4. The cache hit path where hit counts are incremented.

1. Add import heapq at the top of the file.

2. In __init__, add:
    self._lfu_heap: list[tuple[int, int, str]] = []  # (hit_count, insertion_order, key)
    self._lfu_counter: int = 0  # monotonic counter for insertion order tiebreaking

3. When a new entry is inserted into the cache, push to the heap:
    heapq.heappush(self._lfu_heap, (0, self._lfu_counter, key))
    self._lfu_counter += 1

4. When a cache hit increments the hit count, push a new tuple with the updated count:
    heapq.heappush(self._lfu_heap, (new_hit_count, self._lfu_counter, key))
    self._lfu_counter += 1

5. Replace the LFU branch of _evict_one with:
    while self._lfu_heap:
        hit_count, _, key = heapq.heappop(self._lfu_heap)
        if key in self._cache and self._cache[key].hit_count == hit_count:
            del self._cache[key]
            return
    # Fallback: if heap is out of sync, pick any entry
    if self._cache:
        key = next(iter(self._cache))
        del self._cache[key]

Adjust attribute names (_cache, hit_count, etc.) to match the actual code. Read the file first.

Run: python3 -m pytest tests/test_caching.py -x -q
Run: python3 -m mypy proxilion/caching/tool_cache.py
```

**Verification:**
- All caching tests pass.
- mypy clean.
- LFU eviction no longer iterates all entries.

---

### Step 16: Remove redundant inner import in cached_tool decorator

**Priority:** LOW
**Complexity:** LOW
**Category:** Performance / Code Quality

**Problem:** The cached_tool decorator in proxilion/caching/tool_cache.py (line 629) has import inspect inside the inner wrapper function body. This means Python performs a module lookup on every invocation of the decorated function. The inspect module is already imported at the top of the module, making this inner import redundant.

**Intent:** As a developer, I expect no unnecessary work on the hot path of a caching decorator.

**Fix:**
- Remove the import inspect line from inside the wrapper function.
- Verify that inspect is imported at the module level.

**Claude Code Prompt:**
```
Read proxilion/caching/tool_cache.py and:
1. Check if import inspect exists at the module level (top of file).
2. Locate the cached_tool decorator and find the inner import inspect (around line 629).

If inspect is already imported at the module level, remove the inner import.
If it is NOT imported at the module level, move the inner import to the module level instead.

Run: python3 -m pytest tests/test_caching.py -x -q
Run: python3 -m ruff check proxilion/caching/tool_cache.py
```

**Verification:**
- All caching tests pass.
- ruff clean.
- import inspect appears exactly once in tool_cache.py, at the module level.

---

### Step 17: Add concurrency test for MultiDimensionalRateLimiter

**Priority:** HIGH
**Complexity:** MEDIUM
**Category:** Testing

**Problem:** The TOCTOU race condition in MultiDimensionalRateLimiter.allow_request (identified in the security review) has no concurrent correctness test. A test is needed that fires two threads simultaneously when a limit is at exactly 1 remaining token, verifying that exactly one succeeds.

**Intent:** As a maintainer, I expect the test suite to catch TOCTOU regressions in the rate limiter. If the race condition is reintroduced, this test must fail.

**Fix:**
- Add a test in tests/test_security/test_rate_limiter.py that:
  1. Creates a MultiDimensionalRateLimiter with a single dimension limited to 1 request.
  2. Uses a threading.Barrier to synchronize two threads.
  3. Both threads call allow_request simultaneously.
  4. Asserts that exactly one returns True and the other returns False.
  5. Runs the test 20 times to increase confidence (race conditions are probabilistic).

**Claude Code Prompt:**
```
Read tests/test_security/test_rate_limiter.py to understand the existing test structure, imports, and fixtures.

Add a new test function (at the end of the file or in a logical grouping):

import threading
from concurrent.futures import ThreadPoolExecutor

def test_multi_dimensional_rate_limiter_concurrent_atomicity():
    """Two threads competing for the last token must not both succeed."""
    from proxilion.security.rate_limiter import MultiDimensionalRateLimiter, TokenBucketRateLimiter

    for attempt in range(20):
        # Create a limiter with exactly 1 token
        limiter = MultiDimensionalRateLimiter(
            limiters=[TokenBucketRateLimiter(capacity=1, refill_rate=0)]
        )
        # (adjust constructor args to match actual API -- read the class first)

        barrier = threading.Barrier(2)
        results = []

        def try_request():
            barrier.wait()
            result = limiter.allow_request("user1")
            results.append(result)

        with ThreadPoolExecutor(max_workers=2) as pool:
            f1 = pool.submit(try_request)
            f2 = pool.submit(try_request)
            f1.result()
            f2.result()

        true_count = sum(1 for r in results if r)
        assert true_count <= 1, (
            f"Attempt {attempt}: {true_count} threads succeeded, expected at most 1"
        )

Read the actual MultiDimensionalRateLimiter and TokenBucketRateLimiter constructors to get the correct parameter names and create the limiter with exactly 1 available token and 0 refill rate.

Run: python3 -m pytest tests/test_security/test_rate_limiter.py::test_multi_dimensional_rate_limiter_concurrent_atomicity -x -q
```

**Verification:**
- Test passes consistently (20 iterations).
- No flaky failures after 5 consecutive runs.

---

### Step 18: Add concurrency test for QueueApprovalStrategy

**Priority:** HIGH
**Complexity:** MEDIUM
**Category:** Testing

**Problem:** QueueApprovalStrategy has no test for concurrent access. The missing lock on _request_counter (fixed in Step 6) should be verified by a test that would fail without the lock.

**Intent:** As a maintainer, I expect the test suite to catch thread-safety regressions in QueueApprovalStrategy.

**Fix:**
- Add a test that submits 100 concurrent approval requests using a thread pool.
- Verify that all 100 receive unique request_ids.
- Verify that _pending contains exactly 100 entries.

**Claude Code Prompt:**
```
Read tests/test_decorators.py to understand the existing test structure and how QueueApprovalStrategy is tested.

Add a new test:

import threading
from concurrent.futures import ThreadPoolExecutor

def test_queue_approval_strategy_concurrent_unique_ids():
    """Concurrent approval requests must all receive unique IDs."""
    from proxilion.decorators import QueueApprovalStrategy
    # (adjust import path if different)

    strategy = QueueApprovalStrategy()
    request_ids = []
    lock = threading.Lock()

    def submit_request(i):
        # Call whatever method generates a request_id
        request_id = strategy.request_approval(
            user_id=f"user_{i}",
            action="read",
            resource="file",
        )
        with lock:
            request_ids.append(request_id)

    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = [pool.submit(submit_request, i) for i in range(100)]
        for f in futures:
            f.result()

    # All IDs must be unique
    assert len(set(request_ids)) == 100, (
        f"Expected 100 unique IDs, got {len(set(request_ids))}"
    )

Adjust the method name and parameters to match the actual QueueApprovalStrategy API. Read the class first.

Run: python3 -m pytest tests/test_decorators.py::test_queue_approval_strategy_concurrent_unique_ids -x -q
```

**Verification:**
- Test passes consistently.
- All 100 request IDs are unique.

---

### Step 19: Add audit log file rotation test

**Priority:** MEDIUM
**Complexity:** MEDIUM
**Category:** Testing

**Problem:** AuditLogger file rotation (size-based via RotationPolicy.SIZE) has no dedicated test. The test suite tests InMemoryAuditLogger extensively but the file-based rotation path is untested.

**Intent:** As a maintainer, I expect the test suite to verify that file rotation creates a new file, preserves all events, and maintains hash chain integrity across the rotation boundary.

**Fix:**
- Add a test in tests/test_audit.py or tests/test_audit_extended.py that:
  1. Creates an AuditLogger with a small max_file_size (e.g., 1 KB).
  2. Writes enough events to trigger rotation.
  3. Verifies that the original file was rotated (renamed/moved).
  4. Verifies that a new file was created for subsequent events.
  5. Verifies that no events were lost.

**Claude Code Prompt:**
```
Read tests/test_audit.py and tests/test_audit_extended.py to understand existing test patterns for AuditLogger.

Read proxilion/audit/logger.py to understand:
1. How RotationPolicy.SIZE works.
2. What max_file_size parameter controls rotation.
3. What happens to the old file on rotation (renamed? compressed?).

Add a test (in whichever test file is most appropriate):

import tempfile
import os

def test_audit_logger_size_based_rotation():
    """Size-based rotation creates a new file and preserves all events."""
    from proxilion.audit.logger import AuditLogger, AuditConfig, RotationPolicy

    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = os.path.join(tmpdir, "audit.jsonl")
        config = AuditConfig(
            log_file=log_path,
            rotation=RotationPolicy.SIZE,
            max_file_size=512,  # Very small to trigger rotation quickly
        )
        # (adjust config construction to match actual API)

        logger = AuditLogger(config)

        # Write enough events to trigger rotation
        events_written = 0
        for i in range(50):
            # Create and log a minimal audit event
            event = ...  # construct an AuditEvent
            logger.log(event)
            events_written += 1

        logger.close()

        # Verify rotation occurred: there should be more than one file in tmpdir
        files = os.listdir(tmpdir)
        assert len(files) > 1, f"Expected rotation to create multiple files, found: {files}"

        # Verify no events were lost by counting lines across all files
        total_lines = 0
        for f in files:
            with open(os.path.join(tmpdir, f)) as fh:
                total_lines += sum(1 for line in fh if line.strip())
        assert total_lines >= events_written

Adjust the AuditConfig constructor, event creation, and logger.log() call to match the actual API. Read the source first.

Run: python3 -m pytest tests/test_audit_extended.py::test_audit_logger_size_based_rotation -x -q
```

**Verification:**
- Test passes.
- Rotation creates at least 2 files.
- No events are lost.

---

### Step 20: Add LFU eviction correctness test

**Priority:** MEDIUM
**Complexity:** LOW
**Category:** Testing

**Problem:** ToolCache with LFU eviction policy has no adversarial test verifying that the entry with the fewest hits is actually the one evicted.

**Intent:** As a maintainer, I expect the test suite to verify that LFU eviction works correctly: the least-accessed entry is evicted, not an arbitrary one.

**Fix:**
- Add a test in tests/test_caching.py that:
  1. Creates a ToolCache with max_size=3 and EvictionPolicy.LFU.
  2. Inserts 3 entries (A, B, C).
  3. Accesses A 5 times, B 3 times, C 1 time.
  4. Inserts a 4th entry D, triggering eviction.
  5. Asserts that C was evicted (fewest hits) and A, B, D remain.

**Claude Code Prompt:**
```
Read tests/test_caching.py to understand existing test patterns for ToolCache.

Read proxilion/caching/tool_cache.py to understand:
1. The ToolCache constructor (max_size, eviction_policy parameters).
2. How to insert and retrieve entries (put/get or set/get).
3. The EvictionPolicy enum values.

Add a test:

def test_lfu_evicts_least_frequently_used():
    """LFU eviction removes the entry with the fewest cache hits."""
    from proxilion.caching.tool_cache import ToolCache, EvictionPolicy

    cache = ToolCache(max_size=3, eviction_policy=EvictionPolicy.LFU)

    cache.put("key_a", "value_a")
    cache.put("key_b", "value_b")
    cache.put("key_c", "value_c")

    # Access A 5 times, B 3 times, C 1 time
    for _ in range(5):
        cache.get("key_a")
    for _ in range(3):
        cache.get("key_b")
    cache.get("key_c")

    # Insert D, should evict C (fewest hits)
    cache.put("key_d", "value_d")

    assert cache.get("key_a") == "value_a", "A should not be evicted"
    assert cache.get("key_b") == "value_b", "B should not be evicted"
    assert cache.get("key_d") == "value_d", "D should not be evicted"
    assert cache.get("key_c") is None, "C should have been evicted (fewest hits)"

Adjust method names (put/get vs set/get) to match the actual API.

Run: python3 -m pytest tests/test_caching.py::test_lfu_evicts_least_frequently_used -x -q
```

**Verification:**
- Test passes.
- C is evicted, not A or B.

---

### Step 21: Add tamper-detection test for verify_hash

**Priority:** MEDIUM
**Complexity:** LOW
**Category:** Testing

**Problem:** No test confirms that mutating a single field of an AuditEvent causes verify_hash to return False. Existing tests verify chain integrity but do not test direct field mutation followed by re-verification.

**Intent:** As a maintainer, I expect the test suite to prove that any single-field tampering is detected by verify_hash.

**Fix:**
- Add a test that:
  1. Creates an AuditEvent with a computed hash.
  2. Verifies verify_hash() returns True.
  3. Mutates a single field (e.g., changes the action from "read" to "delete").
  4. Verifies verify_hash() returns False.
  5. Repeats for several different fields to ensure comprehensive coverage.

**Claude Code Prompt:**
```
Read proxilion/types.py to understand AuditEvent fields and the compute_hash/verify_hash methods.
Read tests/test_audit.py or tests/test_hash_chain_detailed.py for existing AuditEvent test patterns.

Add a test:

def test_verify_hash_detects_single_field_tampering():
    """Mutating any single field after hashing must cause verify_hash to return False."""
    from proxilion.types import AuditEvent, UserContext, ToolCallRequest
    import copy

    user = UserContext(user_id="user1", roles=["admin"])
    tool_call = ToolCallRequest(
        tool_name="read_file",
        action="read",
        resource="document.txt",
        arguments={"path": "/data/doc.txt"},
    )
    # (adjust constructor to match actual required fields)

    event = AuditEvent(
        event_id="evt_001",
        user_context=user,
        tool_call=tool_call,
        timestamp=1710000000.0,
    )
    event.compute_hash()

    # Baseline: hash should verify
    assert event.verify_hash() is True

    # Tamper with action
    tampered = copy.deepcopy(event)
    # Since ToolCallRequest is frozen, we need to create a new one or use object.__setattr__
    object.__setattr__(tampered.tool_call, "action", "delete")
    tampered._cached_canonical = None  # Clear cache if it exists
    assert tampered.verify_hash() is False, "Tampering with action should be detected"

    # Tamper with user_id
    tampered2 = copy.deepcopy(event)
    object.__setattr__(tampered2.user_context, "user_id", "attacker")
    tampered2._cached_canonical = None
    assert tampered2.verify_hash() is False, "Tampering with user_id should be detected"

    # Tamper with event_id (not included in hash, but verify)
    tampered3 = copy.deepcopy(event)
    tampered3.event_id = "evt_999"
    tampered3._cached_canonical = None
    # event_id may or may not be in the canonical JSON -- check and assert accordingly

Adjust field names and constructors to match the actual AuditEvent API. Read types.py first.

Run: python3 -m pytest tests/test_audit.py::test_verify_hash_detects_single_field_tampering -x -q
```

**Verification:**
- Test passes.
- Tampering with action, user_id, and resource all cause verify_hash to return False.

---

### Step 22: Eliminate stored plaintext agent secrets

**Priority:** MEDIUM
**Complexity:** MEDIUM
**Category:** Security

**Problem:** AgentCredential._secret in proxilion/security/agent_trust.py (lines 520-531) stores the derived HMAC secret as a hex string in a long-lived dict (self._agents). If a debugger, memory dump, or serialization bug exposes self._agents, all agent secrets are compromised simultaneously. The secret is derivable on demand from the master key and agent ID.

**Intent:** As a security engineer, I expect agent secrets to not be stored in long-lived data structures. The secret should be derived on demand using the master key and agent ID, so that only the master key needs to be protected.

**Fix:**
- Remove the _secret field from AgentCredential.
- Add a method _derive_agent_secret(self, agent_id: str) -> bytes to AgentTrustManager that computes the secret on demand.
- Replace all reads of credential._secret with calls to self._derive_agent_secret(agent_id).

**Claude Code Prompt:**
```
Read proxilion/security/agent_trust.py and locate:
1. The AgentCredential class/dataclass and its _secret field.
2. Where _secret is assigned during agent registration.
3. All places where _secret is read (grep for _secret in the file).

Assess whether _secret can be derived from the master key and agent_id. Look for the derivation logic (likely HMAC of master_key + agent_id).

If derivation is possible:
1. Add a method to AgentTrustManager:
    def _derive_agent_secret(self, agent_id: str) -> bytes:
        """Derive agent-specific secret from master key. Not stored."""
        return hmac.new(
            self._secret_key.encode(),
            agent_id.encode(),
            hashlib.sha256,
        ).digest()

2. Remove _secret from AgentCredential (or set it to None).

3. Replace every read of credential._secret or self._agents[agent_id]._secret with self._derive_agent_secret(agent_id).

4. In signing operations, replace credential._secret.encode() with self._derive_agent_secret(agent_id) (which already returns bytes).

Be careful: if _secret is used outside AgentTrustManager (e.g., passed to external callers), this refactor may need a compatibility shim. Check all usages first.

Run: python3 -m pytest tests/test_security/test_agent_trust.py -x -q
Run: python3 -m mypy proxilion/security/agent_trust.py
```

**Verification:**
- All agent trust tests pass.
- mypy clean.
- grep confirms _secret is no longer stored on AgentCredential.

---

### Step 23: Document silent enable_pii override in OutputGuard

**Priority:** LOW
**Complexity:** LOW
**Category:** Maintainability

**Problem:** OutputGuard constructor in proxilion/guards/output_guard.py (lines 379-387) silently ignores the enable_pii flag when custom patterns are explicitly provided. This is a reasonable design decision but is undocumented, leading to potential confusion.

**Intent:** As a developer, when I pass both patterns=[...] and enable_pii=True, I expect either the flag to be applied or a clear warning/error telling me that custom patterns override the PII setting.

**Fix:**
- Add a log warning (using the standard library logging module) when both patterns and enable_pii=True are provided.
- Add a note to the OutputGuard docstring explaining this behavior.

**Claude Code Prompt:**
```
Read proxilion/guards/output_guard.py and locate the __init__ method where patterns and enable_pii interact (around lines 379-387).

1. Import logging at the top if not already present:
    import logging
    logger = logging.getLogger(__name__)

2. In __init__, after the if patterns is not None: block, add:
    if patterns is not None and enable_pii:
        logger.warning(
            "OutputGuard: enable_pii=True is ignored when custom patterns are provided. "
            "Include PII patterns in your custom patterns list if PII detection is needed."
        )

3. Add a note to the OutputGuard class docstring or __init__ docstring:
    Note: When custom patterns are provided via the patterns parameter,
    the enable_pii flag is ignored. Include PII detection patterns in
    your custom patterns list if PII detection is needed.

Run: python3 -m pytest tests/test_guards.py -x -q
Run: python3 -m mypy proxilion/guards/output_guard.py
```

**Verification:**
- All guard tests pass.
- mypy clean.
- The warning is logged when both arguments are provided.

---

### Step 24: Update version to 0.0.14

**Priority:** HIGH
**Complexity:** LOW
**Category:** Release

**Problem:** After all fixes are applied, the version must be bumped to 0.0.14 in both pyproject.toml and proxilion/__init__.py, and CHANGELOG.md must be updated.

**Intent:** As a developer, I expect the SDK version to reflect the changes applied in this spec cycle. Both version sources must be synchronized.

**Fix:**
- Update pyproject.toml version to "0.0.14".
- Update proxilion/__init__.py __version__ to "0.0.14".
- Add a CHANGELOG.md entry for 0.0.14 summarizing the changes.

**Claude Code Prompt:**
```
Read pyproject.toml and locate the version = "..." line. Change it to version = "0.0.14".

Read proxilion/__init__.py and locate the __version__ = "..." line. Change it to __version__ = "0.0.14".

Read CHANGELOG.md and add a new entry at the top (after the header, before the previous version entry):

## 0.0.14 (2026-03-XX)

### Security
- Fixed non-constant-time hash comparison in AuditEvent.verify_hash (now uses hmac.compare_digest)
- Fixed delegation token capability serialization fragility (canonical JSON instead of str(sorted()))
- Fixed replay nonce eviction to be time-ordered (OrderedDict instead of set)
- Eliminated stored plaintext agent secrets in favor of on-demand derivation
- Added matched text truncation to InputGuard (prevents sensitive data leakage in logs)
- Fixed OutputGuard truncation logic that revealed most of short secrets

### Reliability
- Added thread safety to QueueApprovalStrategy (missing lock on request counter)
- Fixed CircuitBreaker half-open count leak (probes now release their slots on success)

### Performance
- Cached canonical JSON in AuditEvent (computed once per instance instead of per hash call)
- Added O(1) event ID index to HashChain.get_proof (was O(n) linear scan)
- Eliminated double pattern scan in InputGuard sanitization
- Replaced O(n) LFU eviction with O(log n) min-heap in ToolCache
- Removed redundant inner import in cached_tool decorator

### Maintainability
- Extracted shared secret key validation into proxilion/security/_crypto_utils.py
- Fixed ConfigurationError constructor misuse (proper config_key/expected/received fields)
- Replaced kwargs injection in enforce_scope with contextvars
- Replaced duck-typing in cost_limited with runtime-checkable Protocol
- Added documentation for OutputGuard enable_pii override behavior

### Testing
- Added concurrency test for MultiDimensionalRateLimiter atomicity
- Added concurrency test for QueueApprovalStrategy unique IDs
- Added audit log file rotation test
- Added LFU eviction correctness test
- Added tamper-detection test for AuditEvent.verify_hash

Run: python3 -m ruff check proxilion/__init__.py
Run: python3 -m pytest -x -q --tb=short 2>&1 | tail -5
```

**Verification:**
- Version is 0.0.14 in both files.
- All tests pass.
- CHANGELOG.md has the new entry.

---

### Step 25: Final validation and documentation update

**Priority:** HIGH
**Complexity:** LOW
**Category:** Validation

**Problem:** After all changes, the full CI check must pass and all documentation must reflect the current state.

**Intent:** As a maintainer, I expect the SDK to pass all quality gates after the spec is complete. No regressions, no lint violations, no type errors.

**Fix:**
- Run the full CI check.
- Update CLAUDE.md test count and version if needed.
- Update .codelicious/STATE.md with the final status.

**Claude Code Prompt:**
```
Run the full CI check:
    python3 -m ruff check proxilion tests \
      && python3 -m ruff format --check proxilion tests \
      && python3 -m mypy proxilion \
      && python3 -m pytest -x -q

If any step fails, fix the issue and re-run.

Update CLAUDE.md:
- Change "Current: 0.0.7" to "Current: 0.0.14" in the Version section.
- Update the test count to match the current total.
- Update the architecture section if new files were added (e.g., proxilion/security/_crypto_utils.py).

Update .codelicious/STATE.md with:
- New version: 0.0.14
- Updated test counts
- Spec-v8 completion status
- New verification pass entry

Update proxilion/__init__.py exports if get_scope_context() was added in Step 10.

Run the full CI check one final time to confirm everything passes.
```

**Verification:**
- Full CI check passes (ruff, format, mypy, pytest).
- CLAUDE.md version matches pyproject.toml.
- STATE.md reflects spec-v8 completion.
- All 25 steps are verified.

---

## Summary of Changes

| Step | Priority | Category | File(s) | Description |
|------|----------|----------|---------|-------------|
| 1 | HIGH | Maintainability | security/_crypto_utils.py (new), memory_integrity.py, agent_trust.py, intent_capsule.py | Extract shared secret key validation |
| 2 | HIGH | Correctness | security/_crypto_utils.py | Fix ConfigurationError constructor args |
| 3 | HIGH | Security | types.py | Constant-time hash comparison in verify_hash |
| 4 | HIGH | Security | security/agent_trust.py | Canonical capability serialization |
| 5 | HIGH | Security | security/agent_trust.py | Time-ordered nonce eviction |
| 6 | HIGH | Reliability | decorators.py | Thread-safe QueueApprovalStrategy |
| 7 | HIGH | Reliability | security/circuit_breaker.py | Fix half-open count leak |
| 8 | HIGH | Security | guards/input_guard.py | Truncate matched text |
| 9 | HIGH | Security | guards/output_guard.py | Fix truncation logic for short secrets |
| 10 | MEDIUM | Maintainability | decorators.py | Replace kwargs injection with contextvars |
| 11 | MEDIUM | Maintainability | decorators.py | Protocol-based limiter typing |
| 12 | MEDIUM | Performance | types.py | Cache canonical JSON |
| 13 | MEDIUM | Performance | audit/hash_chain.py | O(1) event ID index |
| 14 | MEDIUM | Performance | guards/input_guard.py | Eliminate double pattern scan |
| 15 | MEDIUM | Performance | caching/tool_cache.py | O(log n) LFU eviction |
| 16 | LOW | Performance | caching/tool_cache.py | Remove redundant import |
| 17 | HIGH | Testing | tests/test_security/test_rate_limiter.py | Concurrency test for rate limiter |
| 18 | HIGH | Testing | tests/test_decorators.py | Concurrency test for approval strategy |
| 19 | MEDIUM | Testing | tests/test_audit_extended.py | File rotation test |
| 20 | MEDIUM | Testing | tests/test_caching.py | LFU eviction correctness test |
| 21 | MEDIUM | Testing | tests/test_audit.py | Tamper-detection test |
| 22 | MEDIUM | Security | security/agent_trust.py | Eliminate stored plaintext secrets |
| 23 | LOW | Maintainability | guards/output_guard.py | Document enable_pii override |
| 24 | HIGH | Release | pyproject.toml, __init__.py, CHANGELOG.md | Version bump to 0.0.14 |
| 25 | HIGH | Validation | CLAUDE.md, STATE.md | Final validation and docs update |

---

## Findings Cross-Reference

This table maps each step to the finding that motivated it, providing traceability from audit finding to fix.

| Finding Source | Severity | Finding | Spec-v8 Step |
|---------------|----------|---------|--------------|
| Deep review 2026-03-19 | P1 | ConfigurationError wrong argument type | Step 2 |
| Deep review 2026-03-19 | P1 | Delegation token serialization fragility | Step 4 |
| Deep review 2026-03-19 | P2 | Replay nonce eviction non-deterministic | Step 5 |
| Deep review 2026-03-19 | P2 | AuditEvent.verify_hash non-constant-time | Step 3 |
| Deep review 2026-03-19 | P2 | QueueApprovalStrategy._request_counter not thread-safe | Step 6 |
| Deep review 2026-03-19 | P2 | AgentCredential._secret stored as plaintext | Step 22 |
| Deep review 2026-03-19 | P2 | CircuitBreaker _half_open_count leak | Step 7 |
| Deep review 2026-03-19 | P2 | InputGuard raw matched_text leakage | Step 8 |
| Deep review 2026-03-19 | P2 | OutputGuard _truncate_match reveals short secrets | Step 9 |
| Deep review 2026-03-19 | P2 | _validate_secret_key triplicated | Step 1 |
| Deep review 2026-03-19 | P2 | enforce_scope kwargs injection | Step 10 |
| Deep review 2026-03-19 | P2 | cost_limited duck-typing | Step 11 |
| Deep review 2026-03-19 | P2 | HashChain.get_proof O(n) scan | Step 13 |
| Deep review 2026-03-19 | P2 | InputGuard double pattern scan | Step 14 |
| Deep review 2026-03-19 | P3 | AuditEvent._canonical_json GC pressure | Step 12 |
| Deep review 2026-03-19 | P3 | ToolCache LFU O(n) eviction | Step 15 |
| Deep review 2026-03-19 | P3 | cached_tool redundant inner import | Step 16 |
| Deep review 2026-03-19 | P3 | OutputGuard enable_pii silently ignored | Step 23 |
| Test coverage gap | P2 | No MultiDimensionalRateLimiter concurrency test | Step 17 |
| Test coverage gap | P2 | No QueueApprovalStrategy concurrency test | Step 18 |
| Test coverage gap | P2 | No AuditLogger file rotation test | Step 19 |
| Test coverage gap | P3 | No LFU eviction correctness test | Step 20 |
| Test coverage gap | P3 | No verify_hash tamper-detection test | Step 21 |

---

## Post-Completion Checklist

After all 25 steps are complete, verify:

- [ ] Version is 0.0.14 in pyproject.toml and __init__.py
- [ ] python3 -m ruff check proxilion tests exits 0
- [ ] python3 -m ruff format --check proxilion tests exits 0
- [ ] python3 -m mypy proxilion exits 0
- [ ] python3 -m pytest -x -q shows all tests passing
- [ ] CHANGELOG.md has a 0.0.14 entry
- [ ] CLAUDE.md version section is updated
- [ ] .codelicious/STATE.md reflects spec-v8 completion
- [ ] grep confirms _validate_secret_key is defined in exactly one file
- [ ] grep confirms no == comparison on hashes in verify_hash
- [ ] grep confirms no kwargs["_scope_context"] in decorators.py
- [ ] grep confirms no hasattr(limiter, "allow_request") in decorators.py
- [ ] grep confirms _secret is not stored on AgentCredential
- [ ] New file proxilion/security/_crypto_utils.py exists and is imported by 3 modules
- [ ] 5 new test functions exist and pass
