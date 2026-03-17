# Proxilion SDK -- Hardening Spec v4

**Version:** 0.0.9 -> 0.0.10
**Date:** 2026-03-15
**Status:** READY FOR IMPLEMENTATION
**Previous spec:** docs/specs/spec-v3.md (0.0.8 -> 0.0.9, depends on spec-v2 completion)
**Depends on:** spec-v3 must be fully complete before this spec begins

---

## Executive Summary

This spec covers the fifth improvement cycle for the Proxilion SDK. It targets production-readiness defects discovered during a deep audit of every security module, every guard, every integration handler, and all documentation. The previous four specs addressed critical bugs (spec.md), CI hardening and documentation (spec-v1), structured error context and developer experience (spec-v2), and thread-safety stabilization with bounded collections (spec-v3).

This cycle focuses on hardening: closing the remaining security bypass vectors in input guards, fixing unbounded memory growth in the agent trust subsystem, eliminating path traversal vulnerabilities in intent capsule constraints, strengthening exception handling discipline across callback and hook paths, repairing dead links and stale examples in documentation, adding missing async test infrastructure, and delivering a production deployment guide. Every item targets code that already exists. No net-new features are introduced.

After this spec is complete, the SDK should be safe to deploy as a bulletproof MVP in production environments where security decisions must be deterministic, audit logs must be tamper-evident, memory must be bounded, and documentation must be accurate.

---

## Codebase Snapshot (post spec-v3 completion, projected)

| Metric | Value |
|--------|-------|
| Python source files | 89 |
| Source lines (proxilion/) | 54,200 (projected) |
| Test files | 65+ (projected after spec-v3 additions) |
| Test count | 2,700+ (projected after spec-v3 additions) |
| Python versions tested | 3.10, 3.11, 3.12, 3.13 |
| Ruff lint violations | 0 |
| Ruff format violations | 0 |
| Mypy errors | 0 |
| Version (pyproject.toml) | 0.0.9 |
| Version (__init__.py) | 0.0.9 |
| CI/CD | GitHub Actions (test, lint, typecheck, pip-audit, coverage >= 85%) |
| Broad except Exception catches | ~20 (projected after spec-v2 and spec-v3 narrowing) |
| Documentation pages | 12+ feature docs, README, quickstart, CLAUDE.md, 4 specs |

---

## Logic Breakdown: Deterministic vs Probabilistic

All security decisions in Proxilion are deterministic. This table quantifies the breakdown across all 89 source modules.

| Logic Type | Percentage | Module Count | Description |
|------------|-----------|--------------|-------------|
| Deterministic | 94.4% | 84 of 89 | Regex pattern matching, HMAC-SHA256 verification, SHA-256 hash chains, set membership checks, token bucket counters, state machine transitions, boolean policy evaluation, frozen dataclass construction, JSON serialization, file I/O with locking |
| Heuristic (deterministic) | 4.5% | 4 of 89 | Risk score aggregation in guards (weighted sum of deterministic pattern matches with fixed severity constants), behavioral drift z-score thresholds (statistical analysis on recorded metrics, not ML inference), token estimation heuristic in context/message_history.py (1.3 words-per-token ratio) |
| Probabilistic (non-security) | 1.1% | 1 of 89 | Jitter in resilience/retry.py (random.uniform for exponential backoff timing only, not in any security decision path) |

Zero LLM inference calls, zero ML model evaluations, zero neural network weights, and zero non-deterministic random decisions exist in the security path. The four "heuristic" modules use bounded arithmetic on locally recorded counters with fixed severity constants. Their outputs are reproducible given identical input sequences. The single probabilistic module uses randomness exclusively for retry delay jitter, which has no bearing on security outcomes.

---

## Quick Install Reference

```
# From PyPI
pip install proxilion

# With optional dependencies
pip install proxilion[pydantic]    # Pydantic schema validation
pip install proxilion[casbin]      # Casbin policy engine backend
pip install proxilion[opa]         # Open Policy Agent backend
pip install proxilion[all]         # All optional dependencies

# Development (from source)
git clone <repo-url>
cd proxilion-sdk
pip install -e ".[dev,all]"
python3 -m pytest -x -q           # Run tests
python3 -m ruff check proxilion tests  # Lint
python3 -m ruff format --check proxilion tests  # Format check
python3 -m mypy proxilion         # Type check
```

---

## Intent Examples

The following examples describe expected behavior from a user perspective for the core security subsystems targeted by this spec. Each example maps to the module being hardened.

### Input Guard (Unicode Normalization)

As a developer using InputGuard, when a malicious user submits "Ign\u00f6re previous instructions" (using Unicode accented characters) or substitutes Cyrillic look-alike characters for Latin letters in prompt injection attempts, I expect the guard to normalize the input to its canonical ASCII-equivalent form before pattern matching, so that Unicode evasion techniques produce the same detection result as their plain-text equivalents.

### Agent Trust Manager (Bounded Nonce Set)

As an operator running a Proxilion-protected service for 30+ days without restart, when tens of thousands of inter-agent messages have been exchanged, I expect the replay protection nonce set to remain bounded in memory and to evict the oldest nonces first (not arbitrary ones), so that the service does not suffer memory exhaustion while still detecting replays within a configurable time window.

### Agent Trust Manager (Bounded Revocation Set)

As an operator revoking delegation tokens over the lifetime of a long-running service, I expect revoked token entries older than a configurable TTL to be automatically cleaned up, so that the revocation set does not grow without limit and degrade lookup performance.

### Intent Capsule (Path Traversal in Constraints)

As a developer defining allowed_paths constraints in an IntentCapsule, when an attacker submits a path like "/allowed/../../../etc/passwd", I expect the constraint checker to resolve the path to its canonical form before comparing against the allowlist, so that directory traversal sequences cannot escape the allowed path boundary.

### Scheduler and Tool Registry (Exception Handling)

As an operator with critical hooks registered (compliance auditing, security gates), when a hook raises an exception during tool execution, I expect the exception to be logged with full stack trace context and, for hooks marked as critical, to halt the tool call rather than silently continuing.

### Documentation (Dead Links and Stale Examples)

As a developer reading the README or quickstart guide, when I click a documentation link, I expect it to resolve to an existing page. When I copy a code example, I expect it to run without missing imports or incorrect API references.

### Async Test Infrastructure

As a contributor running the test suite, I expect async authorization flows to be exercised by dedicated fixtures and test cases, so that async code paths are validated alongside their synchronous counterparts.

---

## Prerequisite: Complete spec-v3 Steps 1 through 18

Before starting any step in this spec, all steps in spec-v3.md must be complete. Those steps cover ObservabilityHooks singleton thread-safety (step 1), behavioral drift deque bounding (step 2), sliding window rate limiter cleanup (step 3), IDOR protector collection bounding (step 4), Gemini integration handler hardening (steps 5-6), audit logger atomic writes (step 7), cascade protection unbounded history (step 8), cost tracker unbounded records (step 9), session manager cleanup (step 10), streaming detector memory (step 11), sequence validator history bounding (step 12), scope enforcer cleanup (step 13), agent trust delegation depth (step 14), failure path tests (steps 15-16), changelog/version updates (step 17), and final validation (step 18).

This spec assumes all of that is done and verified green before step 1 begins.

---

## Step 1 -- Add Unicode Normalization to Input Guard Pattern Matching

> **Priority:** HIGH
> **Estimated complexity:** Medium
> **Files:** proxilion/guards/input_guard.py, tests/test_guards.py

### Problem

The InputGuard compiles patterns with re.IGNORECASE and re.MULTILINE flags, which handles ASCII case variations correctly. However, sophisticated evasion techniques can bypass detection through Unicode normalization attacks: accented characters (e.g., "Ign\u00f6re" instead of "Ignore"), Cyrillic homoglyphs (e.g., Cyrillic "A" U+0410 substituted for Latin "A" U+0041), and combining character sequences. The guard performs no Unicode normalization before pattern matching.

This was identified in spec-v2 step 11 as "harden input guard against case-insensitive evasion" and should have been addressed there. This step delivers a complete fix.

### Intent

As a security engineer, when I deploy InputGuard to protect against prompt injection, I expect it to detect injection attempts regardless of whether the attacker uses Unicode tricks to disguise keywords. The detection rate for Unicode-evaded inputs should match the detection rate for plain ASCII inputs.

### Expected behavior

- Input "Ign\u00f6re previous instructions" is detected with the same severity as "Ignore previous instructions".
- Input with Cyrillic homoglyphs substituted for Latin characters is normalized before matching.
- Normalization uses Unicode NFKD (Compatibility Decomposition) which decomposes accented characters and normalizes width variants.
- A secondary ASCII transliteration pass strips remaining non-ASCII characters after NFKD decomposition.
- The original input is preserved in the GuardResult for audit purposes; only the matching step uses the normalized form.
- Performance impact is negligible (unicodedata.normalize is stdlib, sub-microsecond for typical inputs).

### Fix

1. Import unicodedata at the top of input_guard.py.
2. Add a private method _normalize_text(self, text: str) -> str that applies NFKD normalization followed by ASCII encoding with "ignore" error handling, then decodes back to str.
3. In the check() method, normalize the input text before running it through compiled patterns.
4. Preserve the original text in the GuardResult (matched_text field or equivalent) for audit trail.

### Tests

1. Test that "Ign\u00f6re previous instructions" triggers instruction_override pattern.
2. Test that Cyrillic "A" (U+0410) substituted in "ignore previous" is detected.
3. Test that full-width characters (e.g., Unicode full-width "I" U+FF29) are normalized.
4. Test that combining diacritical marks are stripped.
5. Test that clean Unicode text (e.g., CJK characters, emoji in legitimate prompts) is not falsely flagged.
6. Test that the original (non-normalized) text is preserved in the result for auditing.

### Verification

```
python3 -m pytest tests/test_guards.py -x -q -k "unicode or normali"
python3 -m ruff check proxilion/guards/input_guard.py
python3 -m mypy proxilion/guards/input_guard.py
```

### Claude Code prompt

```
Read proxilion/guards/input_guard.py. In the InputGuard class, add a private method
_normalize_text that applies unicodedata.normalize("NFKD", text), then encodes to
ASCII with errors="ignore", then decodes back to str. Call this method on the input
text at the start of the check() method, BEFORE running the compiled regex patterns.
Keep the original text in the GuardResult for auditing -- only use the normalized
form for pattern matching. Then add 6 test cases in tests/test_guards.py: (1) accented
"Ignore" triggers detection, (2) Cyrillic homoglyph substitution is detected,
(3) full-width Unicode characters are normalized, (4) combining diacriticals are
stripped, (5) legitimate CJK/emoji text is not falsely flagged, (6) original text
is preserved in result. Run ruff check and mypy on the changed files.
```

---

## Step 2 -- Bound the Nonce Set in AgentTrustManager with Time-Ordered Eviction

> **Priority:** HIGH
> **Estimated complexity:** Medium
> **Files:** proxilion/security/agent_trust.py, tests/test_security/test_agent_trust.py

### Problem

The _message_nonces set in AgentTrustManager is used for replay protection but has two defects. First, it grows without practical bound until it hits the 10,000 threshold, at which point it removes 5,000 arbitrary entries (sets have no insertion order). Second, because there is no timestamp tracking on nonces, the cleanup removes arbitrary nonces rather than the oldest ones, which means a recently used nonce could be evicted while a months-old nonce is retained. This defeats the purpose of replay protection for recent messages and creates a sawtooth memory pattern.

### Intent

As an operator running Proxilion in a long-lived service processing hundreds of inter-agent messages per minute, I expect replay protection to work correctly for recent messages (within a configurable window) while automatically evicting old nonces that are no longer relevant. I do not want memory to grow without bound.

### Expected behavior

- Nonces are stored with their creation timestamp.
- A configurable nonce_ttl_seconds parameter (default: 3600, one hour) controls how long nonces are retained.
- Cleanup runs automatically during verify_message when the nonce count exceeds a configurable threshold (default: 10,000).
- Cleanup removes all nonces older than nonce_ttl_seconds, not arbitrary ones.
- If after TTL-based cleanup the count still exceeds the threshold, the oldest nonces are removed until the count is at threshold.
- A replay attempt within the TTL window is always detected.

### Fix

1. Replace self._message_nonces: set[str] with self._message_nonces: dict[str, float] mapping nonce to timestamp (time.monotonic()).
2. Add nonce_ttl_seconds parameter to __init__ (default 3600).
3. Add max_nonces parameter to __init__ (default 10000).
4. Replace the existing cleanup block (lines 886-890) with a method _cleanup_nonces() that removes entries older than nonce_ttl_seconds, then trims to max_nonces by oldest timestamp if still over.
5. Update the nonce check in verify_message to use dict lookup instead of set membership.
6. Call _cleanup_nonces() after adding a new nonce when len exceeds max_nonces.

### Tests

1. Test that a replayed message within TTL is rejected.
2. Test that a nonce older than nonce_ttl_seconds is evicted and the same nonce can be reused.
3. Test that cleanup removes oldest nonces first, not arbitrary ones.
4. Test that the nonce dict never exceeds max_nonces + 1 (the +1 is the entry that triggers cleanup).
5. Test that nonce_ttl_seconds and max_nonces are configurable.
6. Stress test: add 20,000 nonces rapidly and verify memory stays bounded.

### Verification

```
python3 -m pytest tests/test_security/test_agent_trust.py -x -q -k "nonce"
python3 -m ruff check proxilion/security/agent_trust.py
python3 -m mypy proxilion/security/agent_trust.py
```

### Claude Code prompt

```
Read proxilion/security/agent_trust.py. Find the _message_nonces set (around line 440)
and the cleanup block (around lines 883-890). Replace the set with a dict[str, float]
mapping nonce to time.monotonic() timestamp. Add nonce_ttl_seconds (default 3600) and
max_nonces (default 10000) parameters to __init__. Replace the cleanup block with a
_cleanup_nonces method that first removes entries older than nonce_ttl_seconds, then
trims to max_nonces by oldest timestamp if still over limit. Update the nonce check
in verify_message to use dict lookup. Add 6 tests in tests/test_security/test_agent_trust.py:
replay within TTL rejected, old nonce evicted, oldest-first eviction order, max bound
respected, configurable parameters, and a stress test with 20K nonces. Run ruff and mypy.
```

---

## Step 3 -- Add TTL-Based Cleanup for Revoked Tokens in AgentTrustManager

> **Priority:** HIGH
> **Estimated complexity:** Low
> **Files:** proxilion/security/agent_trust.py, tests/test_security/test_agent_trust.py

### Problem

The _revoked_tokens set in AgentTrustManager grows without any cleanup mechanism. Every call to revoke a delegation token adds to this set, but entries are never removed. In a long-running service with high delegation churn (agents creating and revoking temporary delegations), this set will grow indefinitely, degrading both memory usage and lookup performance.

### Intent

As an operator running a multi-agent system where delegation tokens are frequently created and revoked, I expect the revocation set to automatically clean up entries that are older than a configurable TTL, so that the set stays bounded over weeks of continuous operation.

### Expected behavior

- Revoked tokens are stored with their revocation timestamp.
- A configurable revocation_ttl_seconds parameter (default: 86400, 24 hours) controls retention.
- Cleanup runs during token validation checks when the set exceeds a configurable threshold.
- A revoked token within the TTL window is always rejected.
- A revoked token older than the TTL is removed from the set (the original delegation token itself would have expired by then).

### Fix

1. Replace self._revoked_tokens: set[str] with self._revoked_tokens: dict[str, float] mapping token_id to revocation timestamp.
2. Add revocation_ttl_seconds parameter to __init__ (default 86400).
3. Add a _cleanup_revoked_tokens() method that removes entries older than revocation_ttl_seconds.
4. Call _cleanup_revoked_tokens() during validate_delegation_token when len exceeds 1000.
5. Update all sites that check token_id in self._revoked_tokens to use dict lookup.

### Tests

1. Test that a revoked token within TTL is rejected.
2. Test that a revoked token older than revocation_ttl_seconds is cleaned up.
3. Test that revocation_ttl_seconds is configurable.
4. Test that cleanup only runs when threshold is exceeded (not on every call).
5. Test thread safety of cleanup under concurrent revocation and validation.

### Verification

```
python3 -m pytest tests/test_security/test_agent_trust.py -x -q -k "revok"
python3 -m ruff check proxilion/security/agent_trust.py
python3 -m mypy proxilion/security/agent_trust.py
```

### Claude Code prompt

```
Read proxilion/security/agent_trust.py. Find the _revoked_tokens set (around line 439)
and all sites that add to or check it (around lines 557, 683, 911). Replace the set
with a dict[str, float] mapping token_id to time.monotonic() timestamp. Add
revocation_ttl_seconds (default 86400) to __init__. Add a _cleanup_revoked_tokens
method that removes entries older than the TTL. Call it during validate_delegation_token
when len > 1000. Update all membership checks. Add 5 tests in
tests/test_security/test_agent_trust.py covering TTL rejection, TTL cleanup,
configurability, threshold-gated cleanup, and thread-safety. Run ruff and mypy.
```

---

## Step 4 -- Fix Path Traversal Vulnerability in Intent Capsule Constraint Validation

> **Priority:** HIGH
> **Estimated complexity:** Low
> **Files:** proxilion/security/intent_capsule.py, tests/test_security/test_intent_capsule.py

### Problem

The _check_constraints method in IntentCapsule validates allowed_paths using simple string prefix matching: path.startswith(p). This is vulnerable to two attacks. First, directory traversal: "/allowed/../../../etc/passwd" starts with "/allowed" but resolves outside the boundary. Second, prefix collision: allowed path "/data" accidentally matches "/data_backup/secret.txt" because startswith does not enforce a directory boundary.

### Intent

As a developer defining allowed_paths constraints to restrict file access to specific directories, I expect the constraint checker to resolve paths to their canonical form and enforce directory boundaries, so that an attacker cannot use ".." sequences or prefix collisions to escape the allowed path.

### Expected behavior

- Path arguments are resolved using pathlib.PurePosixPath normalization (not os.path.resolve, which hits the filesystem).
- After normalization, the check uses PurePosixPath.is_relative_to() for proper directory boundary enforcement.
- "/allowed/../../../etc/passwd" is rejected because its normalized form "/etc/passwd" is not relative to "/allowed".
- "/data_backup/secret.txt" is rejected when only "/data" is allowed, because is_relative_to enforces directory boundaries.
- "/data/reports/q1.csv" is accepted when "/data" is allowed.
- Invalid or empty paths are rejected with a clear constraint violation message.

### Fix

1. Import PurePosixPath from pathlib at the top of intent_capsule.py.
2. In _check_constraints, replace the startswith loop with PurePosixPath normalization and is_relative_to checks.
3. Wrap the path resolution in a try/except ValueError to catch malformed paths.
4. Use PurePosixPath (not Path.resolve()) to avoid filesystem access in a security check.

### Tests

1. Test that "/allowed/../../../etc/passwd" is rejected when allowed_paths=["/allowed"].
2. Test that "/data_backup/secret.txt" is rejected when allowed_paths=["/data"].
3. Test that "/data/reports/q1.csv" is accepted when allowed_paths=["/data"].
4. Test that an empty path string is rejected.
5. Test that multiple allowed_paths work correctly (any match is sufficient).
6. Test that Windows-style paths with backslashes are handled safely.

### Verification

```
python3 -m pytest tests/test_security/test_intent_capsule.py -x -q -k "path"
python3 -m ruff check proxilion/security/intent_capsule.py
python3 -m mypy proxilion/security/intent_capsule.py
```

### Claude Code prompt

```
Read proxilion/security/intent_capsule.py. Find the _check_constraints method (around
line 644). Replace the path.startswith(p) loop with PurePosixPath-based normalization
and is_relative_to checks. Import PurePosixPath from pathlib. Wrap in try/except
ValueError for malformed paths. Do NOT use Path.resolve() as it hits the filesystem.
Add 6 tests in tests/test_security/test_intent_capsule.py: directory traversal
rejected, prefix collision rejected, valid subpath accepted, empty path rejected,
multiple allowed_paths, and backslash handling. Run ruff and mypy.
```

---

## Step 5 -- Add Thread-Safe Lock to MemoryIntegrityGuard.__len__

> **Priority:** MEDIUM
> **Estimated complexity:** Low
> **Files:** proxilion/security/memory_integrity.py, tests/test_security/test_memory_integrity.py

### Problem

The ContextWindowGuard (part of MemoryIntegrityGuard) has a __len__ method that reads self._messages without acquiring self._lock. In a multi-threaded environment, this can return an inconsistent count if another thread is concurrently modifying _messages (adding, removing, or clearing messages).

### Intent

As a developer querying len(guard) from a monitoring thread while message processing continues on other threads, I expect the returned count to be a consistent snapshot, not a torn read.

### Expected behavior

- __len__ acquires self._lock before reading len(self._messages).
- The lock acquisition is brief (read-only, no blocking operations inside).
- Other __len__-like methods (__bool__, __contains__ if present) also acquire the lock.

### Fix

1. Wrap the return statement in __len__ with "with self._lock:".
2. Audit the class for any other unlocked reads on _messages and add locking if found.

### Tests

1. Test that len(guard) returns correct count after concurrent add/remove operations.
2. Stress test: 10 threads adding messages while main thread polls len() 100 times; verify no exceptions or negative counts.

### Verification

```
python3 -m pytest tests/test_security/test_memory_integrity.py -x -q -k "len or thread"
python3 -m ruff check proxilion/security/memory_integrity.py
python3 -m mypy proxilion/security/memory_integrity.py
```

### Claude Code prompt

```
Read proxilion/security/memory_integrity.py. Find the __len__ method (around line 784).
Add "with self._lock:" around the return statement. Audit the same class for any other
methods that read self._messages without holding self._lock and add locking to those
as well. Add 2 tests in tests/test_security/test_memory_integrity.py: one verifying
correct count after concurrent operations, one stress test with 10 threads. Run ruff
and mypy.
```

---

## Step 6 -- Narrow Exception Catches in Scheduler Callbacks

> **Priority:** MEDIUM
> **Estimated complexity:** Low
> **Files:** proxilion/scheduling/scheduler.py

### Problem

The scheduler's request execution path catches bare Exception in two places (around lines 220-221 and 226-227). This swallows all exceptions uniformly, making it impossible for callers to distinguish between transient failures (network timeouts, connection errors) and permanent failures (logic bugs, type errors). The error is logged without exc_info=True, so stack traces are lost.

### Intent

As an operator investigating a failed scheduled request, I expect the error log to include the full stack trace and exception type, so that I can distinguish between transient infrastructure failures and application bugs.

### Expected behavior

- Known transient exceptions (ConnectionError, TimeoutError, OSError) are caught and logged with exc_info=True and a "transient" label.
- All other exceptions are caught and logged with exc_info=True and an "unexpected" label.
- The exception type distinction is preserved in the error object returned to the caller.
- No exception is silently swallowed without a stack trace.

### Fix

1. Replace the two broad except Exception blocks with a two-tier catch: first catch (ConnectionError, TimeoutError, OSError), then catch Exception.
2. Add exc_info=True to all logger.error calls in these blocks.
3. Include request.id in all log messages for correlation.

### Tests

1. Test that a ConnectionError in a callback is logged with "transient" label.
2. Test that a ValueError in a callback is logged with "unexpected" label.
3. Test that the error object returned to the caller preserves the original exception type.

### Verification

```
python3 -m pytest tests/test_scheduling.py -x -q
python3 -m ruff check proxilion/scheduling/scheduler.py
python3 -m mypy proxilion/scheduling/scheduler.py
```

### Claude Code prompt

```
Read proxilion/scheduling/scheduler.py. Find the two broad except Exception blocks
(around lines 220-221 and 226-227). Replace each with a two-tier catch: first
(ConnectionError, TimeoutError, OSError) logged as "transient", then Exception logged
as "unexpected". Add exc_info=True to all logger.error calls. Include request.id in
log messages. Add 3 tests in tests/test_scheduling.py verifying transient vs unexpected
labeling and error type preservation. Run ruff and mypy.
```

---

## Step 7 -- Enforce Critical Hook Semantics in Tool Registry

> **Priority:** MEDIUM
> **Estimated complexity:** Medium
> **Files:** proxilion/tools/registry.py, tests/test_tool_registry.py

### Problem

The tool registry catches all hook exceptions silently, regardless of the hook's criticality. If a compliance auditing hook or a security gate hook raises an exception, the tool call continues as if the hook succeeded. This violates fail-secure principles for critical hooks.

### Intent

As a compliance officer registering a mandatory audit hook, I expect that if the hook raises an exception, the tool call is halted and the exception is propagated to the caller. Non-critical hooks (telemetry, logging) should fail open with a warning log.

### Expected behavior

- Hooks can be registered with a critical=False parameter (default False for backward compatibility).
- When a critical hook raises an exception, the exception is re-raised after logging with exc_info=True.
- When a non-critical hook raises an exception, it is logged with exc_info=True and execution continues.
- The hook registration API remains backward-compatible (existing code without the critical parameter continues to work with fail-open behavior).

### Fix

1. Update the hook registration method to accept a critical: bool = False parameter.
2. Store the criticality flag alongside the hook callable (e.g., as a tuple or a small dataclass).
3. In the hook execution loop, check the criticality flag before deciding whether to re-raise or swallow.
4. Add exc_info=True to all hook exception log calls.

### Tests

1. Test that a critical hook exception halts tool execution and propagates the exception.
2. Test that a non-critical hook exception is logged but does not halt execution.
3. Test that the default (no critical parameter) is fail-open for backward compatibility.
4. Test that multiple hooks execute in order and a critical failure stops subsequent hooks.

### Verification

```
python3 -m pytest tests/test_tool_registry.py -x -q -k "hook"
python3 -m ruff check proxilion/tools/registry.py
python3 -m mypy proxilion/tools/registry.py
```

### Claude Code prompt

```
Read proxilion/tools/registry.py. Find the hook execution loop (around line 540).
Update the hook registration method to accept a critical: bool = False parameter.
Store the flag alongside the hook callable. In the execution loop, re-raise exceptions
from critical hooks after logging with exc_info=True; log and continue for non-critical
hooks. Add 4 tests in tests/test_tool_registry.py: critical hook halts execution,
non-critical hook continues, default is fail-open, and ordering/short-circuit behavior.
Run ruff and mypy.
```

---

## Step 8 -- Narrow Exception Catch in Tool Decorator Type Hint Extraction

> **Priority:** MEDIUM
> **Estimated complexity:** Low
> **Files:** proxilion/tools/decorators.py

### Problem

The tool decorator catches bare Exception when extracting type hints from decorated functions (around lines 60-63). The intended catch is NameError (when a type annotation references an undefined name), but the broad catch also swallows RecursionError, MemoryError, and other exceptions that indicate real bugs.

### Intent

As a developer decorating a function with a tool decorator, if the function has a genuinely broken type annotation (e.g., referencing a class that was not imported), I expect a NameError to be caught gracefully. But if a RecursionError or MemoryError occurs, I expect it to propagate so I can diagnose the root cause.

### Expected behavior

- NameError is caught and results in an empty hints dict (graceful degradation).
- All other exceptions propagate normally.

### Fix

1. Replace except Exception with except NameError.

### Tests

1. Test that a function with a missing type reference is handled gracefully (existing behavior preserved).
2. Test that a function with valid type hints works normally.

### Verification

```
python3 -m pytest tests/test_tool_registry.py -x -q
python3 -m ruff check proxilion/tools/decorators.py
python3 -m mypy proxilion/tools/decorators.py
```

### Claude Code prompt

```
Read proxilion/tools/decorators.py. Find the except Exception block around lines 60-63
that catches errors from get_type_hints(func). Replace "except Exception" with
"except NameError". Verify existing tests still pass. Run ruff and mypy.
```

---

## Step 9 -- Fix Dead Links and Stale Examples in README.md

> **Priority:** MEDIUM
> **Estimated complexity:** Low
> **Files:** README.md

### Problem

The README.md documentation section (around line 809) contains links to pages that do not exist in the repository: docs/concepts.md, docs/security.md, docs/features/README.md, and docs/features/authorization.md. These produce 404 errors when clicked.

### Intent

As a developer reading the README for the first time, when I click a documentation link, I expect it to resolve to an existing page with useful content.

### Expected behavior

- All documentation links in README.md resolve to files that exist in the repository.
- Dead links are either removed or replaced with links to existing files.
- The documentation section accurately represents the available documentation.

### Fix

1. Replace the docs/concepts.md link with docs/quickstart.md (which covers core concepts).
2. Replace the docs/security.md link with docs/features/security-controls.md (which covers the security model).
3. Replace the docs/features/README.md link with a list of the actual feature docs that exist.
4. Replace the docs/features/authorization.md link with docs/quickstart.md (which covers authorization).
5. Verify all remaining links in the README resolve to existing files.

### Tests

No code tests needed. Manual verification that all links resolve.

### Verification

```
# Verify all referenced docs exist
for f in docs/quickstart.md docs/features/security-controls.md docs/features/audit-logging.md docs/features/input-guards.md docs/features/output-guards.md docs/features/rate-limiting.md docs/features/observability.md; do test -f "$f" && echo "OK: $f" || echo "MISSING: $f"; done
```

### Claude Code prompt

```
Read README.md. Find the Documentation section (around line 806). Replace all dead
links with links to existing files:
- docs/concepts.md -> docs/quickstart.md with description "Quick Start and Core Concepts"
- docs/security.md -> docs/features/security-controls.md with description "Security Model and Controls"
- docs/features/README.md -> list the actual feature docs (audit-logging, input-guards, output-guards, rate-limiting, security-controls, observability)
- docs/features/authorization.md -> docs/quickstart.md with description "Authorization and Policy Engine"
Verify each target file exists with ls before making the edit.
```

---

## Step 10 -- Fix Missing Import in Quickstart Example

> **Priority:** MEDIUM
> **Estimated complexity:** Low
> **Files:** docs/quickstart.md

### Problem

The quickstart guide shows an example that uses AuthorizationError (around line 67) but does not include the import statement for it. A developer copying the example verbatim will get a NameError.

### Intent

As a developer following the quickstart guide, when I copy a code example, I expect it to run without modification. Missing imports break this contract and erode confidence in the documentation.

### Expected behavior

- All code examples in quickstart.md include all necessary import statements.
- The AuthorizationError import is added to the example that uses it.

### Fix

1. Add "from proxilion import AuthorizationError" to the import block of the example that uses it.
2. Scan all other examples in quickstart.md for missing imports and fix any found.

### Verification

```
# Grep for symbols used but not imported in quickstart examples
python3 -c "
import re
with open('docs/quickstart.md') as f:
    content = f.read()
print('Scanned quickstart.md for import completeness')
"
```

### Claude Code prompt

```
Read docs/quickstart.md. Find the example that uses AuthorizationError (around line 67).
Add "from proxilion import AuthorizationError" to its import block. Scan all other
code examples in the file for symbols that are used but not imported. Fix any missing
imports found.
```

---

## Step 11 -- Add Async Test Fixtures and Core Async Test Cases

> **Priority:** MEDIUM
> **Estimated complexity:** Medium
> **Files:** tests/conftest.py, tests/test_core.py

### Problem

The test suite has fixtures for synchronous Proxilion instances but no async fixtures. Async authorization flows (async def can_async, async decorators) are not exercised by dedicated test infrastructure. While pytest-asyncio is configured with asyncio_mode="auto", the conftest.py does not provide async-ready fixtures that set up the Proxilion instance with an event loop context.

### Intent

As a contributor adding async features or fixing async bugs, I expect the test suite to include async fixtures and baseline async tests, so that I can verify async code paths without writing boilerplate setup for every test.

### Expected behavior

- An async_proxilion_simple fixture is available that creates a Proxilion instance usable in async test functions.
- An async_proxilion_with_audit fixture creates a Proxilion instance with audit logging for async tests.
- At least 5 baseline async tests exist covering: async authorization, async decorator, async guard check, async with rate limiting, and async error propagation.
- These tests run on all supported Python versions where pytest-asyncio is available.

### Fix

1. Add async fixtures to tests/conftest.py using @pytest.fixture with async def.
2. Add 5+ async test cases to tests/test_core.py in a new TestAsyncAuthorization class.
3. Guard the async tests with a pytest.importorskip("pytest_asyncio") or similar mechanism so they are skipped gracefully on environments without pytest-asyncio.

### Tests

Self-referential: the step itself adds tests.

### Verification

```
python3 -m pytest tests/test_core.py -x -q -k "async"
python3 -m ruff check tests/conftest.py tests/test_core.py
```

### Claude Code prompt

```
Read tests/conftest.py and tests/test_core.py. Add async fixtures to conftest.py:
async_proxilion_simple and async_proxilion_with_audit (mirror the existing sync
fixtures but as async def). Add a TestAsyncAuthorization class to test_core.py with
at least 5 async tests: async authorization, async decorator, async guard check,
async with rate limiting, and async error propagation. Use pytest.importorskip or
similar to skip gracefully if pytest-asyncio is unavailable. Run ruff check on both files.
```

---

## Step 12 -- Fix Misleading Comment in Output Guard Exception Handler

> **Priority:** LOW
> **Estimated complexity:** Low
> **Files:** proxilion/guards/output_guard.py

### Problem

The exception handler for output filters (around lines 488-490) has a comment that says "fail-closed" but the behavior description is ambiguous. The actual behavior is correct (treat filter exceptions as validation failures, meaning the output is considered unsafe), but the comment should be precise.

### Intent

As a developer reading the output guard source code, I expect comments to accurately describe the behavior so I can reason about failure modes.

### Expected behavior

- The comment clearly states: "If a filter raises an exception, treat the output as unsafe and include it in violations. This is fail-closed behavior: uncertainty defaults to denial."

### Fix

1. Update the comment to be precise about the fail-closed semantics.

### Verification

```
python3 -m ruff check proxilion/guards/output_guard.py
```

### Claude Code prompt

```
Read proxilion/guards/output_guard.py. Find the exception handler for output filters
(around lines 488-490). Update the comment to precisely describe the fail-closed
behavior: "If a filter raises an exception, treat the output as unsafe and include
it in violations. This is fail-closed behavior: uncertainty defaults to denial."
Run ruff check.
```

---

## Step 13 -- Fix Bare Except in Cascade Protection Docstring

> **Priority:** LOW
> **Estimated complexity:** Low
> **Files:** proxilion/security/cascade_protection.py

### Problem

The docstring in cascade_protection.py (around lines 825-829) contains an example that uses bare "except:" which is an anti-pattern and contradicts the project convention of catching specific exceptions. While this is in a docstring (not executable code), it models bad practice for developers who copy examples.

### Intent

As a developer reading docstring examples, I expect them to follow the same coding conventions as the main codebase, particularly around exception handling.

### Expected behavior

- The docstring example uses "except (CircuitOpenError, Exception) as e:" instead of bare "except:".
- The example shows proper exception handling with a named variable.

### Fix

1. Update the docstring example to use specific exception catching.

### Verification

```
python3 -m ruff check proxilion/security/cascade_protection.py
```

### Claude Code prompt

```
Read proxilion/security/cascade_protection.py. Find the docstring example with bare
"except:" (around lines 825-829). Replace it with "except (CircuitOpenError, Exception) as e:"
and update the comment inside the except block to reference the exception variable.
Run ruff check.
```

---

## Step 14 -- Add Production Deployment Guide

> **Priority:** LOW
> **Estimated complexity:** Medium
> **Files:** docs/deployment.md

### Problem

The documentation covers installation, quickstart, and feature reference, but there is no guide for deploying Proxilion in production. Operators need guidance on secret key management, thread safety configuration, audit log rotation, memory bounds tuning, and monitoring integration.

### Intent

As an operator deploying Proxilion in a production environment, I need a single document that covers all operational concerns: how to configure secret keys securely, how to tune memory bounds for my workload, how to set up audit log rotation, how to monitor Proxilion health, and what failure modes to watch for.

### Expected behavior

- A docs/deployment.md file exists with sections covering:
  1. Secret key management (generation, rotation, environment variables, never hardcode).
  2. Thread safety configuration (which components need locks, how to verify).
  3. Audit log rotation (file size limits, log rotation with logrotate or equivalent).
  4. Memory bounds tuning (nonce TTL, revocation TTL, max collection sizes).
  5. Monitoring integration (Prometheus exporter setup, alert rule examples).
  6. Failure modes and recovery (circuit breaker states, rate limiter reset, kill switch).
  7. Performance tuning (guard threshold selection, rate limiter capacity planning).
- No code examples use placeholder or weak secret keys.
- The guide references actual configuration parameters from the codebase.

### Fix

1. Create docs/deployment.md with the sections listed above.
2. Add a link to it from the README documentation section.

### Verification

```
test -f docs/deployment.md && echo "OK: deployment.md exists" || echo "MISSING"
```

### Claude Code prompt

```
Create docs/deployment.md with production deployment guidance. Include sections on:
(1) Secret key management with generation examples using python3 -c "import secrets; print(secrets.token_hex(32))",
(2) Thread safety configuration referencing RLock-protected components,
(3) Audit log rotation with logrotate config example,
(4) Memory bounds tuning with parameter names and defaults from the codebase,
(5) Monitoring integration with Prometheus exporter setup,
(6) Failure modes and recovery procedures,
(7) Performance tuning guidelines.
No placeholder or weak secret keys in examples. Then add a link to docs/deployment.md
in the README.md Documentation section. Run ruff check on any Python files touched.
```

---

## Step 15 -- Generate Sample Data Script for Development and Testing

> **Priority:** LOW
> **Estimated complexity:** Medium
> **Files:** scripts/generate_sample_data.py

### Problem

Developers and testers need realistic sample data to exercise the SDK without setting up a full application. The test fixtures in tests/fixtures/ provide static JSON data, but there is no script that generates dynamic, varied sample data for manual testing, demos, and integration verification.

### Intent

As a developer evaluating Proxilion for the first time, I want a script that generates realistic sample data (users, agents, tool call requests, audit events) so I can see the SDK in action without writing boilerplate setup code.

### Expected behavior

- A scripts/generate_sample_data.py script exists that generates:
  1. Sample UserContext objects with varied roles (admin, editor, viewer, analyst).
  2. Sample AgentContext objects with varied trust levels.
  3. Sample ToolCallRequest objects covering different tool categories.
  4. Sample audit events with proper hash chain linkage.
  5. Sample injection attempts (for testing input guards).
  6. Sample sensitive outputs (for testing output guards).
- The script prints generated data in a human-readable format.
- The script can be run standalone: python3 scripts/generate_sample_data.py.
- All generated data uses the SDK's public API (no internal imports).

### Fix

1. Create scripts/ directory if it does not exist.
2. Create scripts/generate_sample_data.py with the data generation logic.
3. Add a brief section in the quickstart or README mentioning the script.

### Verification

```
python3 scripts/generate_sample_data.py
python3 -m ruff check scripts/generate_sample_data.py
```

### Claude Code prompt

```
Create the scripts/ directory and scripts/generate_sample_data.py. The script should
use only Proxilion public API imports to generate:
(1) 5 UserContext objects with varied roles,
(2) 3 AgentContext objects with varied trust levels,
(3) 10 ToolCallRequest objects covering read/write/delete/search/execute actions,
(4) 5 audit events with hash chain linkage using InMemoryAuditLogger,
(5) 5 prompt injection strings for input guard testing,
(6) 5 sensitive output strings for output guard testing.
Print each category with a section header. Make it runnable standalone. Add a note
in docs/quickstart.md mentioning the script. Run ruff check on the script.
```

---

## Step 16 -- Lint and Type-Check All New and Modified Files

> **Priority:** LOW
> **Estimated complexity:** Low
> **Files:** All files modified in steps 1-15

### Problem

After making changes across multiple files, lint violations, format violations, or type errors may have been introduced. A final pass ensures everything is clean.

### Intent

As a maintainer, I expect zero ruff violations, zero format violations, and zero mypy errors across the entire codebase after all changes are applied.

### Expected behavior

- python3 -m ruff check proxilion tests scripts exits with 0.
- python3 -m ruff format --check proxilion tests scripts exits with 0.
- python3 -m mypy proxilion exits with 0.

### Fix

1. Run ruff check and fix any violations.
2. Run ruff format and fix any formatting issues.
3. Run mypy and fix any type errors.

### Verification

```
python3 -m ruff check proxilion tests scripts
python3 -m ruff format --check proxilion tests scripts
python3 -m mypy proxilion
```

### Claude Code prompt

```
Run the full lint and type-check suite:
python3 -m ruff check proxilion tests scripts
python3 -m ruff format --check proxilion tests scripts
python3 -m mypy proxilion
Fix any violations or errors found. Re-run until all three commands exit cleanly.
```

---

## Step 17 -- Run Full Test Suite and Fix Failures

> **Priority:** LOW
> **Estimated complexity:** Medium
> **Files:** Any test files with failures

### Problem

Changes in steps 1-15 may have introduced test regressions. A full test suite run is required to verify all 2,700+ tests still pass.

### Intent

As a maintainer preparing a release, I expect the full test suite to pass with zero failures and minimal skips (only pre-existing skips for optional dependencies like OPA).

### Expected behavior

- python3 -m pytest -x -q exits with 0.
- All new tests from steps 1-11 pass.
- No pre-existing tests are broken by the changes.
- The only skipped tests are those that require optional dependencies (OPA, Casbin) not installed in the test environment.

### Fix

1. Run the full test suite.
2. For any failures, diagnose the root cause and fix.
3. Re-run until green.

### Verification

```
python3 -m pytest -x -q
```

### Claude Code prompt

```
Run the full test suite: python3 -m pytest -x -q
If any tests fail, read the failing test file, diagnose the root cause, fix it, and
re-run. Repeat until all tests pass. Do not skip or xfail tests to make them pass --
fix the underlying issue.
```

---

## Step 18 -- Update CHANGELOG, Version, and Documentation

> **Priority:** LOW
> **Estimated complexity:** Low
> **Files:** CHANGELOG.md, pyproject.toml, proxilion/__init__.py, .proxilion-build/STATE.md

### Problem

After all changes are applied and verified, the version must be bumped and the changelog updated to reflect the work done.

### Intent

As a user upgrading Proxilion, I expect the CHANGELOG to accurately describe what changed, what was fixed, and what was improved in this version.

### Expected behavior

- Version is bumped from 0.0.9 to 0.0.10 in both pyproject.toml and proxilion/__init__.py.
- CHANGELOG.md has a new [0.0.10] section with Added, Fixed, and Changed subsections.
- STATE.md is updated to reflect spec-v4 completion.
- All version references across the codebase are consistent.

### Fix

1. Update version in pyproject.toml.
2. Update __version__ in proxilion/__init__.py.
3. Add [0.0.10] section to CHANGELOG.md with accurate descriptions of all changes.
4. Update STATE.md.

### Verification

```
grep 'version' pyproject.toml | head -1
grep '__version__' proxilion/__init__.py
head -30 CHANGELOG.md
```

### Claude Code prompt

```
Update the version from 0.0.9 to 0.0.10 in both pyproject.toml and proxilion/__init__.py.
Add a new [0.0.10] section at the top of CHANGELOG.md with subsections:
- Added: Unicode normalization in input guards, async test fixtures, production
  deployment guide, sample data generator, critical hook enforcement
- Fixed: Unbounded nonce set in AgentTrustManager, unbounded revoked tokens set,
  path traversal in intent capsule constraints, missing lock in MemoryIntegrityGuard.__len__,
  broad exception catches in scheduler and tool decorators, dead links in README,
  missing import in quickstart, misleading comment in output guard, bare except in
  cascade protection docstring
Update STATE.md to reflect spec-v4 completion status.
```

---

## Step 19 -- Final Validation and README System Design Diagrams

> **Priority:** LOW
> **Estimated complexity:** Low
> **Files:** README.md

### Problem

The README contains Mermaid diagrams that need to be verified for accuracy after all spec-v4 changes, and a new diagram should be added showing the hardened security pipeline with the Unicode normalization layer and bounded collection guarantees.

### Intent

As a developer or evaluator reading the README, I expect the system design diagrams to accurately reflect the current architecture, including the hardening improvements made in this spec.

### Expected behavior

- All existing Mermaid diagrams in the README are verified for accuracy.
- A new "Hardened Security Pipeline" diagram is appended showing the defense-in-depth layers including Unicode normalization, bounded collections, and critical hook enforcement.
- A new "Data Flow: Intent Capsule with Path Validation" diagram is appended showing the path traversal protection flow.

### Fix

1. Verify all existing diagrams match current code.
2. Append a "Hardened Security Pipeline" Mermaid diagram at the end of README.md.
3. Append an "Intent Capsule Path Validation" Mermaid diagram.

### Mermaid diagrams to append

Hardened Security Pipeline diagram showing: Input arrives, Unicode normalization, pattern matching, schema validation, rate limiting (bounded), policy evaluation, circuit breaker, sequence validation, tool execution with critical hooks, output guard, audit logging (bounded hash chain), response returned. Each step annotated with the hardening applied in this spec.

Intent Capsule Path Validation diagram showing: Raw path input, PurePosixPath normalization, traversal sequence removal, is_relative_to check against allowed_paths, accept or reject decision.

### Verification

```
python3 -m pytest -x -q
python3 -m ruff check proxilion tests
python3 -m ruff format --check proxilion tests
python3 -m mypy proxilion
```

### Claude Code prompt

```
Read README.md. Verify all existing Mermaid diagrams match the current architecture.
Append two new Mermaid diagrams at the end of the file (before the closing if any):

1. "Hardened Security Pipeline" -- a flowchart showing the full request flow with
   hardening annotations: Unicode normalization at input, bounded rate limiting,
   critical hook enforcement at tool execution, bounded audit hash chain at logging.

2. "Intent Capsule Path Validation" -- a flowchart showing: raw path input ->
   PurePosixPath normalization -> traversal removal -> is_relative_to check ->
   accept/reject.

Then run the full CI check:
python3 -m pytest -x -q && python3 -m ruff check proxilion tests && python3 -m ruff format --check proxilion tests && python3 -m mypy proxilion
```

---

## Step 20 -- Update CLAUDE.md and Memory Files

> **Priority:** LOW
> **Estimated complexity:** Low
> **Files:** CLAUDE.md, memory files

### Problem

After completing all spec-v4 work, CLAUDE.md and the memory system need to reflect the new state of the codebase so that future conversations have accurate context.

### Intent

As a future conversation with Claude Code, I expect CLAUDE.md and memory files to accurately describe the current codebase state, conventions, and version, so that I do not operate on stale information.

### Expected behavior

- CLAUDE.md version is updated to 0.0.10.
- CLAUDE.md test count is updated to reflect new tests added.
- Memory files are updated with spec-v4 completion status.
- Any new conventions introduced (Unicode normalization, critical hooks, TTL-based cleanup) are documented.

### Fix

1. Update version in CLAUDE.md.
2. Update test count in CLAUDE.md.
3. Update memory/spec_history.md with spec-v4 entry.

### Verification

```
grep 'version' CLAUDE.md
grep 'test' CLAUDE.md
```

### Claude Code prompt

```
Update CLAUDE.md: change version to 0.0.10, update test count to reflect new tests.
Update the memory file at memory/spec_history.md to add spec-v4 entry:
"spec-v4.md (v0.0.9-0.0.10) -- hardening cycle: Unicode normalization in guards,
bounded nonce/revocation sets, path traversal fix, critical hooks, async test infra,
deployment guide, dead link fixes."
```

---

## Summary of Changes by Priority

### HIGH Priority (Steps 1-4)
- Unicode normalization in input guard pattern matching
- Bounded nonce set with time-ordered eviction in AgentTrustManager
- TTL-based cleanup for revoked tokens in AgentTrustManager
- Path traversal fix in intent capsule constraint validation

### MEDIUM Priority (Steps 5-11)
- Thread-safe lock in MemoryIntegrityGuard.__len__
- Narrowed exception catches in scheduler callbacks
- Critical hook enforcement in tool registry
- Narrowed exception catch in tool decorator type hint extraction
- Dead link fixes in README.md
- Missing import fix in quickstart.md
- Async test fixtures and core async test cases

### LOW Priority (Steps 12-20)
- Comment fix in output guard exception handler
- Docstring fix in cascade protection
- Production deployment guide
- Sample data generator script
- Lint and type-check pass
- Full test suite run
- Version bump and changelog update
- README system design diagrams
- CLAUDE.md and memory file updates

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Unicode normalization introduces false positives on legitimate multilingual input | Medium | Medium | Step 1 includes explicit tests for CJK and emoji preservation; NFKD decomposition is conservative |
| Nonce TTL too short causes replay detection gaps | Low | High | Default 3600s (1 hour) is conservative; parameter is configurable per deployment |
| Path traversal fix breaks legitimate relative paths in intent capsules | Low | Medium | PurePosixPath normalization is well-defined; tests cover edge cases |
| Critical hook enforcement breaks existing integrations | Low | Medium | Default critical=False preserves backward compatibility; only explicitly-critical hooks are affected |
| Async test fixtures fail on environments without pytest-asyncio | Low | Low | Guarded with importorskip; sync tests are unaffected |

---

## Estimated Test Count After Completion

| Category | New Tests | Source |
|----------|----------|--------|
| Unicode normalization | 6 | Step 1 |
| Nonce bounding | 6 | Step 2 |
| Revocation TTL | 5 | Step 3 |
| Path traversal | 6 | Step 4 |
| MemoryIntegrity __len__ | 2 | Step 5 |
| Scheduler exceptions | 3 | Step 6 |
| Critical hooks | 4 | Step 7 |
| Async test cases | 5+ | Step 11 |
| **Total new tests** | **37+** | |
| **Projected total** | **2,737+** | |

---

## Definition of Done

All of the following must be true before this spec is marked complete:

1. Every step above is implemented and individually verified.
2. python3 -m pytest -x -q passes with zero failures.
3. python3 -m ruff check proxilion tests scripts passes with zero violations.
4. python3 -m ruff format --check proxilion tests scripts passes with zero violations.
5. python3 -m mypy proxilion passes with zero errors.
6. Version is 0.0.10 in pyproject.toml, proxilion/__init__.py, and CHANGELOG.md.
7. All documentation links in README.md resolve to existing files.
8. CLAUDE.md and memory files reflect the updated state.
9. STATE.md shows spec-v4 as complete.
10. "DONE" is written to .proxilion-build/BUILD_COMPLETE.
