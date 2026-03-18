# Proxilion SDK -- Deep Audit Spec v6

**Version:** 0.0.11 -> 0.0.12
**Date:** 2026-03-16
**Status:** READY FOR IMPLEMENTATION
**Previous spec:** docs/specs/spec-v5.md (0.0.10 -> 0.0.11, depends on spec-v5 completion)
**Depends on:** spec-v5 must be fully complete before this spec begins (spec-v2 through spec-v5 form a sequential dependency chain)

---

## Executive Summary

This spec covers the seventh improvement cycle for the Proxilion SDK. It targets critical correctness bugs, security bypass vectors, thread-safety holes, platform compatibility gaps, and API inconsistencies discovered during a line-by-line audit of all 89 Python source files, all 62+ test files, all prior spec files (spec.md through spec-v5.md), the README, quickstart guide, and CLAUDE.md.

The previous six specs addressed critical bugs (spec.md), CI hardening and documentation (spec-v1), structured error context and developer experience (spec-v2), thread-safety stabilization with bounded collections (spec-v3), security bypass vector closure with deployment guidance (spec-v4), and production readiness with input validation, secret key management, exception safety, and performance optimization (spec-v5).

This cycle focuses on six pillars:

1. **Rate limiter correctness** -- fixing a broken cleanup routine that never evicts stale buckets and a non-atomic multi-tier consumption pattern that silently drains quotas on rejection.
2. **Cryptographic signature robustness** -- replacing fragile Python repr-based HMAC payloads with canonical JSON serialization to prevent signature collision attacks.
3. **Replay protection reliability** -- replacing the unordered nonce set with a TTL-bounded ordered structure that evicts the oldest entries first, not arbitrary ones.
4. **Thread safety for guards** -- adding lock protection to InputGuard and OutputGuard pattern mutation methods and eliminating a mutation-during-verification race in AuditEvent.verify_hash.
5. **API correctness and consistency** -- fixing inverted truncation logic in OutputGuard, a side-effecting property in KillSwitch, a broken capability delegation check in AgentTrustManager, and deprecated asyncio calls across 9 files.
6. **Operational safety** -- adding deadlock prevention in CascadeProtector callbacks, context manager support for AuditLogger, and platform-awareness for file locking on Windows.

Every item targets code that already exists. No net-new features are introduced. The goal is to close every correctness, security, and reliability gap found during the deep audit so the SDK can be deployed in production with confidence.

---

## Codebase Snapshot (post spec-v5 completion, projected)

| Metric | Value |
|--------|-------|
| Python source files | 89 |
| Source lines (proxilion/) | 54,500 (projected) |
| Test files | 68+ (projected after spec-v5 additions) |
| Test count | 2,850+ (projected after spec-v5 additions) |
| Python versions tested | 3.10, 3.11, 3.12, 3.13 |
| Ruff lint violations | 0 |
| Ruff format violations | 0 |
| Mypy errors | 0 |
| Version (pyproject.toml) | 0.0.11 |
| Version (__init__.py) | 0.0.11 |
| CI/CD | GitHub Actions (test, lint, typecheck, pip-audit, coverage >= 85%) |
| Broad except Exception catches | ~15 (projected after spec-v2 through spec-v5 narrowing) |
| Documentation pages | 14+ feature docs, README, quickstart, CLAUDE.md, 6 specs |

---

## Logic Breakdown: Deterministic vs Probabilistic

All security decisions in Proxilion are deterministic. This table quantifies the breakdown across all 89 source modules.

| Logic Type | Percentage | Module Count | Description |
|------------|-----------|--------------|-------------|
| Deterministic | 94.4% | 84 of 89 | Regex pattern matching, HMAC-SHA256 verification, SHA-256 hash chains, set membership checks, token bucket counters, state machine transitions, boolean policy evaluation, frozen dataclass construction, JSON serialization, file I/O with locking |
| Heuristic (deterministic) | 4.5% | 4 of 89 | Risk score aggregation in guards (weighted sum of deterministic pattern matches with fixed severity constants), behavioral drift z-score thresholds (statistical analysis on recorded metrics, not ML inference), token estimation heuristic in context/message_history.py (1.3 words-per-token ratio) |
| Probabilistic (non-security) | 1.1% | 1 of 89 | Jitter in resilience/retry.py (random.uniform for exponential backoff timing only, not in any security decision path) |

Zero LLM inference calls, zero ML model evaluations, zero neural network weights, and zero non-deterministic random decisions exist in the security path. The four heuristic modules use bounded arithmetic on locally recorded counters with fixed severity constants. Their outputs are reproducible given identical input sequences. The single probabilistic module uses randomness exclusively for retry delay jitter, which has no bearing on security outcomes.

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

# Full CI check (all four gates)
python3 -m ruff check proxilion tests && \
python3 -m ruff format --check proxilion tests && \
python3 -m mypy proxilion && \
python3 -m pytest -x -q
```

---

## Intent Examples

The following examples describe expected behavior from a user perspective for the core subsystems targeted by this spec. Each example maps to one or more steps.

### Rate Limiter Cleanup (Steps 1-2)

As an operator running a Proxilion-protected service with thousands of users, when users become inactive and their rate limit buckets go unused for over an hour, I expect the cleanup routine to actually remove those stale buckets from memory. Currently, calling cleanup() refills every bucket before checking its age, which resets the last_update timestamp to "now" and causes every bucket to appear fresh. No bucket is ever evicted, leading to unbounded memory growth proportional to the total number of unique users ever seen.

### Rate Limiter Middleware Atomicity (Step 2)

As a developer using RateLimiterMiddleware with global, user, and tool tiers, when the tool-tier limiter rejects a request, I expect that no tokens have been consumed from the global or user tiers. Currently, tokens are consumed sequentially from global, then user, then tool. If the tool check fails, the global and user tokens are already spent. This means every tool-rate-limited rejection silently drains the user's global and per-user quotas without performing real work, creating a denial-of-service amplification vector.

### HMAC Signature Canonicalization (Step 3)

As a security engineer reviewing the cryptographic signing of intent capsules and delegation tokens, I expect the HMAC payload to use a canonical serialization format that is unambiguous across all possible input values. Currently, the payload uses Python's list repr (e.g., "['search', 'write']") which is implementation-dependent and can produce collisions when tool names contain characters like |, [, ], or single quotes. Two different sets of allowed_tools could produce identical signature payloads, allowing an attacker to forge a valid capsule for tools they were not authorized to use.

### Replay Protection Nonce Eviction (Step 4)

As an operator running a Proxilion-protected multi-agent system for extended periods, when the replay protection nonce set reaches its capacity limit, I expect the oldest nonces to be evicted first. Currently, the cleanup converts the set to a list and removes the "first" 5,000 entries, but Python sets are unordered, so the entries removed are arbitrary. Recently added nonces may be discarded while months-old nonces are retained, allowing replay attacks using message IDs that happened to survive the eviction.

### Guard Thread Safety (Step 5)

As a developer sharing a single InputGuard or OutputGuard instance across multiple request-handling threads (the documented usage pattern for singletons), when one thread calls add_pattern() while another thread calls check(), I expect both operations to complete without crashing or silently skipping patterns. Currently, neither guard holds a lock during pattern mutation, which can cause RuntimeError from dictionary-changed-size-during-iteration or silently skip patterns mid-scan.

### AuditEvent Hash Verification (Step 6)

As an operator running concurrent audit log verification alongside active logging, when verify_hash() is called on an AuditEvent, I expect it to compute the verification hash without modifying the event object. Currently, verify_hash() temporarily sets event_hash to None, recomputes the hash, then restores the original value. A concurrent reader accessing event_hash during this window sees None, causing false integrity violation alerts.

### Output Guard Truncation (Step 7)

As a developer reviewing audit logs that contain redacted PII matches, I expect short matched strings (8 characters or fewer) to be shown as "[...]" for privacy, and longer strings to show a truncated preview (first few and last few characters). Currently, the _truncate_match method has inverted branch logic: strings shorter than max_length get the truncated preview treatment, while strings over max_length get a different truncation. The condition check and the branches are swapped.

### KillSwitch Property Side Effect (Step 8)

As a developer checking whether a kill switch is active in a guard chain with multiple conditional checks, I expect reading the is_active property to be idempotent. Currently, the is_active property contains auto-reset logic that modifies internal state. Checking is_active twice in quick succession can return different values from what appears to be a read-only property access, causing the kill switch to auto-reset unexpectedly between guard checks.

### Capability Delegation Validation (Step 9)

As a developer using wildcard capabilities like "read:*" in the AgentTrustManager, when agent A (with "read:*") delegates "read:documents" to agent B, I expect the delegation to succeed because A can exercise that capability. Currently, the delegation check uses set difference instead of calling has_capability(), so "read:documents" is flagged as invalid because it is not literally present in A's capability set, even though A's "read:*" wildcard covers it.

### Deprecated asyncio Calls (Step 10)

As a developer running Proxilion on Python 3.12 or 3.13, I expect the SDK to work without DeprecationWarnings or RuntimeErrors from asyncio. Currently, asyncio.get_event_loop() is called in 9 files (scheduler.py, fallback.py, transformer.py, and 5 contrib handlers plus tools/registry.py). This call is deprecated since Python 3.10 and raises RuntimeError in Python 3.12+ when no event loop is running.

### CascadeProtector Callback Deadlock (Step 11)

As a developer registering state-change callbacks on CascadeProtector, I expect callbacks to execute without risk of deadlock. Currently, _notify_state_change is called while holding self._lock, and user-supplied callbacks may attempt to acquire external locks or call back into the protector. If a callback blocks on an external resource held by a thread waiting for the CascadeProtector lock, the system deadlocks.

### AuditLogger Lifecycle Safety (Step 12)

As a developer using AuditLogger in application code, I expect to be warned if the logger is garbage-collected without being properly closed, since pending Merkle tree batches would be silently lost. I also expect to be able to use AuditLogger as a context manager for automatic cleanup.

### Platform-Aware File Locking (Step 13)

As a developer deploying Proxilion on Windows, I expect the AuditLogger to either provide file locking equivalent to the Unix fcntl-based implementation or emit a clear warning at initialization that concurrent multi-process writes are not protected. Currently, HAS_FCNTL silently falls back to no-op locking on Windows without any warning.

### ContextWindowGuard Pop Consistency (Step 14)

As a developer using ContextWindowGuard.pop() to manage conversation context, I expect the hash chain to remain valid after removing the last message. Currently, pop() removes the message from the list but does not update the underlying MemoryIntegrityGuard's chain state, causing the next sign_message() call to reference the removed message's hash. Any subsequent verify_context() call will report a false chain break.

### IntentCapsuleManager Capacity Enforcement (Step 15)

As an operator setting _max_capsules to bound memory usage, I expect the limit to be enforced even when no capsules have expired. Currently, create_capsule() calls _cleanup_expired() when at capacity, then unconditionally creates the new capsule regardless of whether cleanup freed any space. Under sustained load with long TTLs, the capsule dictionary grows beyond the configured maximum.

### Sequence Validator Time Window (Step 16)

As a developer configuring REQUIRE_BEFORE rules for operation ordering, I expect the requirement to be scoped to a reasonable time window. Currently, the validator searches the entire per-user history with no time bound, so a confirm_payment call from hours or days ago satisfies the check for submit_payment made today.

### Schema Validation Boolean-as-Integer (Step 17)

As a developer defining tool schemas with integer parameters, I expect that passing True or False is rejected. Python's bool is a subclass of int, so isinstance(True, int) returns True. Booleans passing integer validation can cause unexpected behavior in downstream consumers.

### Dead Code in Path Traversal Check (Step 18)

As a security reviewer reading the path traversal detection code in schema.py, I expect each check to serve a distinct purpose. Currently, the check for "..\\" is redundant because the earlier check for ".." already covers all sequences containing two consecutive dots, including those followed by a backslash.

---

## Prerequisite: Complete spec-v5 Steps 1 through 20

Before starting any step in this spec, all steps in spec-v5.md must be complete. Those steps cover input validation hardening (steps 1-4), secret key management centralization (steps 5-7), exception safety discipline (steps 8-10), performance optimization with Welford's algorithm (steps 11-13), comprehensive test coverage (steps 14-18), changelog/version updates (step 19), and final validation (step 20).

This spec assumes all of that is done and verified green before step 1 begins.

---

## Step 1 -- Fix Rate Limiter Cleanup Never Evicting Stale Buckets

> **Priority:** P1 (CRITICAL)
> **Estimated complexity:** Low
> **Files:** proxilion/security/rate_limiter.py, tests/test_security/test_rate_limiter.py

### Problem

TokenBucketRateLimiter.cleanup() at line 206 calls self._refill_bucket(bucket) on every bucket before checking its age. The _refill_bucket method (line 106) unconditionally sets bucket.last_update = now. After the refill, the age computation age = now - bucket.last_update evaluates to approximately zero, so no bucket ever passes the age > max_age_seconds threshold. The cleanup routine is completely non-functional. Inactive buckets accumulate indefinitely, creating an unbounded memory growth vector proportional to the total number of unique rate-limit keys ever seen.

### Root cause

Line 212 refills before recording the pre-refill timestamp. The refill overwrites last_update, destroying the information needed to determine staleness.

### Fix

1. In the cleanup() method, before calling _refill_bucket(bucket), snapshot the bucket's current last_update value.
2. After calling _refill_bucket(bucket), use the pre-refill snapshot to compute the age: age = now - snapshot.
3. This preserves the staleness information while still refilling the bucket (necessary to check if it is at capacity).

### Expected behavior

- A bucket unused for longer than max_age_seconds is evicted from self._buckets.
- A bucket that received a request within the last max_age_seconds is retained.
- The _maybe_cleanup periodic trigger continues to work unchanged.

### Tests

1. Create a TokenBucketRateLimiter with a short cleanup interval.
2. Call allow_request for 10 unique keys.
3. Advance time (mock time.monotonic) past max_age_seconds for all keys.
4. Call cleanup() and assert all 10 buckets are removed.
5. Call allow_request for 5 more keys, advance time past max_age_seconds for only 3 of them.
6. Call cleanup() and assert exactly 3 are removed and 2 remain.
7. Assert that a bucket with recent activity (even if refilled to capacity) is not evicted.

### Verification

```
python3 -m pytest tests/test_security/test_rate_limiter.py -x -q -k "cleanup"
python3 -m ruff check proxilion/security/rate_limiter.py
python3 -m mypy proxilion/security/rate_limiter.py
```

### Claude Code prompt

```
Read proxilion/security/rate_limiter.py, focusing on the cleanup() method around line
206 and the _refill_bucket() method around line 97. The bug is that cleanup() calls
_refill_bucket(bucket) which sets bucket.last_update = now, then computes
age = now - bucket.last_update which is always ~0. Fix this by capturing
snapshot = bucket.last_update BEFORE calling _refill_bucket, then using
age = now - snapshot for the staleness check. Do not change _refill_bucket itself.
Then read tests/test_security/test_rate_limiter.py and add tests that:
(a) create a limiter, issue requests for multiple keys, mock time forward past
max_age_seconds, call cleanup(), and assert all stale buckets are removed;
(b) create a limiter with mixed stale and fresh buckets and assert only stale ones
are removed. Use unittest.mock.patch on time.monotonic for time advancement.
Run python3 -m pytest tests/test_security/test_rate_limiter.py -x -q -k cleanup
and python3 -m ruff check proxilion/security/rate_limiter.py to verify.
```

---

## Step 2 -- Fix RateLimiterMiddleware Non-Atomic Multi-Tier Token Consumption

> **Priority:** P1 (CRITICAL)
> **Estimated complexity:** Medium
> **Files:** proxilion/security/rate_limiter.py, tests/test_security/test_rate_limiter.py

### Problem

RateLimiterMiddleware.check_rate_limit() at line 534 calls allow_request() sequentially on global_limit, user_limit, and then the tool-specific limiter. Each allow_request() call consumes tokens immediately. If the tool limiter rejects the request (line 575), tokens already consumed from global_limit (line 552) and user_limit (line 562) are not restored. This means every tool-rate-limited rejection silently drains the user's global and per-user quotas without performing real work. An attacker can exploit this by repeatedly calling a tool-rate-limited endpoint to exhaust a user's global budget.

### Root cause

The three allow_request() calls are not atomic. Each one independently consumes tokens before the next tier is checked.

### Fix

1. Add a dry_run parameter (default False) to TokenBucketRateLimiter.allow_request() and SlidingWindowRateLimiter.allow_request(). When dry_run=True, the method checks whether the request would be allowed without consuming tokens.
2. In RateLimiterMiddleware.check_rate_limit(), first dry-run all three tiers. If all pass, then consume tokens from all three. If any dry-run fails, raise RateLimitExceeded without consuming from any tier.
3. Alternative approach (simpler): add a get_remaining(key, cost) check before each allow_request. If get_remaining returns less than cost on any tier, raise immediately without calling allow_request on any tier.

### Expected behavior

- If the tool limiter would reject a request, no tokens are consumed from the global or user limiters.
- If all three tiers allow the request, tokens are consumed from all three atomically.
- The RateLimitExceeded exception correctly identifies which tier caused the rejection.

### Tests

1. Create a middleware with global (capacity=10), user (capacity=5), and tool (capacity=1) limiters.
2. Call check_rate_limit once to consume the tool limiter's single token.
3. Record the global and user limiter remaining tokens.
4. Call check_rate_limit again and catch RateLimitExceeded.
5. Assert the global and user limiter remaining tokens are unchanged (no tokens consumed).
6. Assert the exception identifies "tool" as the limit_type.

### Verification

```
python3 -m pytest tests/test_security/test_rate_limiter.py -x -q -k "middleware"
python3 -m ruff check proxilion/security/rate_limiter.py
python3 -m mypy proxilion/security/rate_limiter.py
```

### Claude Code prompt

```
Read proxilion/security/rate_limiter.py, focusing on RateLimiterMiddleware.check_rate_limit()
around line 534 and TokenBucketRateLimiter.allow_request() and get_remaining(). The bug
is that check_rate_limit calls allow_request (which consumes tokens) sequentially on
global, user, then tool limiters. If the tool limiter rejects, global and user tokens
are already spent. Fix this by checking all three tiers with get_remaining() first
(a read-only check). Only if all three have sufficient remaining capacity, call
allow_request() on each to actually consume tokens. If any get_remaining check fails,
raise RateLimitExceeded for that tier without consuming tokens from any tier.
Then read tests/test_security/test_rate_limiter.py and add a test that creates a
middleware with 3 tiers, exhausts the tool tier, then verifies that subsequent
rejections do NOT consume tokens from global or user tiers. Use get_remaining to
assert token counts before and after. Run the tests and ruff check to verify.
```

---

## Step 3 -- Replace Python Repr-Based HMAC Payloads with Canonical JSON

> **Priority:** P1 (CRITICAL)
> **Estimated complexity:** Medium
> **Files:** proxilion/security/intent_capsule.py, proxilion/security/agent_trust.py, tests/test_security/test_intent_capsule.py, tests/test_security/test_agent_trust.py

### Problem

The HMAC signature computation in IntentCapsule (lines 250-258) and AgentTrustManager.create_delegation (line 645) serializes allowed_tools and capabilities using Python's str(sorted(...)) which produces list repr output like "['search', 'write']". This format is fragile and ambiguous:

- Tool names containing |, [, ], or single quote characters can produce collisions with different tool sets.
- The repr format is a CPython implementation detail, not a language guarantee.
- Two semantically different tool sets could produce identical HMAC payloads, allowing signature forgery.

The same fragile pattern appears in verify_delegation_chain (line 924) for verification.

### Fix

1. In intent_capsule.py, replace str(sorted(allowed_tools)) with json.dumps(sorted(list(allowed_tools)), separators=(",", ":")) in both the sign and verify paths.
2. In agent_trust.py, replace str(sorted(capabilities)) with the same json.dumps call in both create_delegation and verify_delegation_chain.
3. Import json at the top of both files (if not already imported).
4. Use separators=(",", ":") to produce compact, deterministic output with no spaces.

### Expected behavior

- Existing capsules and tokens signed with the old repr format will fail verification (this is a breaking change, acceptable at 0.0.x semver).
- All new signatures use canonical JSON, which is unambiguous for any valid string content.
- Tool names with special characters (|, quotes, brackets) produce distinct, non-colliding payloads.
- Verification is round-trip safe: sign then verify always succeeds for the same inputs.

### Tests

1. Test that a capsule signed with tools containing special characters verifies correctly.
2. Test that two tool sets that would collide under repr produce different signatures under JSON.
3. Test that delegation tokens with capabilities containing ":" (e.g., "read:docs") sign and verify correctly.
4. Test round-trip: create capsule, verify capsule for 10 different tool sets.

### Verification

```
python3 -m pytest tests/test_security/test_intent_capsule.py tests/test_security/test_agent_trust.py -x -q
python3 -m ruff check proxilion/security/intent_capsule.py proxilion/security/agent_trust.py
python3 -m mypy proxilion/security/intent_capsule.py proxilion/security/agent_trust.py
```

### Claude Code prompt

```
Read proxilion/security/intent_capsule.py. Find every place where str(sorted(...)) or
f"...{sorted(...)}..." is used to construct HMAC signature payloads (around lines 250-258
for signing and 351-362 for verification). Replace each occurrence with
json.dumps(sorted(list(...)), separators=(",", ":")) to produce canonical, unambiguous
JSON. Import json at the top of the file. Then do the same in
proxilion/security/agent_trust.py -- find str(sorted(capabilities)) in
create_delegation (around line 645) and verify_delegation_chain (around line 924) and
replace with the same json.dumps pattern. Both the signing and verification paths must
use the identical serialization. Then add tests in tests/test_security/test_intent_capsule.py
verifying that tool names with special characters (|, ', [, ]) produce valid capsules,
and in tests/test_security/test_agent_trust.py verifying delegation tokens with
colon-containing capabilities verify correctly. Run the full test suites for both
modules and ruff check to verify.
```

---

## Step 4 -- Replace Unordered Nonce Set with TTL-Bounded OrderedDict

> **Priority:** P1 (CRITICAL)
> **Estimated complexity:** Medium
> **Files:** proxilion/security/agent_trust.py, tests/test_security/test_agent_trust.py

### Problem

AgentTrustManager._message_nonces (line 882) is a plain set used for replay protection. When the set exceeds 10,000 entries, the cleanup converts it to a list and removes the "first" 5,000 elements. Python sets are unordered, so the entries removed are arbitrary, not the oldest. This means:

- Recently added nonces may be discarded, allowing immediate replay attacks.
- Old nonces may be retained indefinitely, wasting memory.
- There is no TTL-based expiry, so the replay window is unbounded until the 10,000 threshold.

### Fix

1. Replace _message_nonces: set[str] with _message_nonces: OrderedDict[str, float] where the value is the insertion timestamp (time.monotonic()).
2. On insertion, add the nonce with the current timestamp: self._message_nonces[message_id] = time.monotonic().
3. On replay check, look up the message_id in the OrderedDict (O(1) average).
4. Replace the threshold-based cleanup with TTL-based eviction: iterate from the oldest entry (front of the OrderedDict) and remove entries older than nonce_ttl_seconds (default: the max_age_seconds parameter, or 3600 if not specified).
5. Add a hard cap (default 50,000) as a safety bound: if the OrderedDict exceeds the cap after TTL eviction, remove the oldest entries until at cap.
6. Call the cleanup at the end of every verify_message invocation (it is already called there).

### Expected behavior

- Nonces are evicted oldest-first, preserving replay detection for the most recent messages.
- Nonces older than the TTL are evicted regardless of set size.
- The hard cap prevents unbounded growth even under sustained load with long TTLs.
- Replay detection works correctly for all nonces within the TTL window.

### Tests

1. Add 100 nonces, verify all are present.
2. Mock time forward past TTL, trigger cleanup, verify all 100 are evicted.
3. Add 200 nonces with staggered timestamps, mock time forward so the oldest 100 expire, verify only those 100 are evicted.
4. Exceed the hard cap, verify the oldest entries (beyond cap) are removed.
5. Verify that a replayed message_id within the TTL window is correctly rejected.
6. Verify that a replayed message_id after TTL expiry is incorrectly accepted (document this as the expected tradeoff between memory and detection window).

### Verification

```
python3 -m pytest tests/test_security/test_agent_trust.py -x -q -k "nonce or replay"
python3 -m ruff check proxilion/security/agent_trust.py
python3 -m mypy proxilion/security/agent_trust.py
```

### Claude Code prompt

```
Read proxilion/security/agent_trust.py. Find _message_nonces (it is a set). Replace it
with an OrderedDict[str, float] from collections. Import OrderedDict and time at the
top. Change the nonce insertion at line 884 from self._message_nonces.add(message_id)
to self._message_nonces[message_id] = time.monotonic(). Change the replay check
(the "if message_id in self._message_nonces" check) to use the same dict lookup.
Replace the cleanup block (lines 886-890) with TTL-based eviction: iterate from
the front of the OrderedDict, remove entries where (now - timestamp) > nonce_ttl_seconds
(add nonce_ttl_seconds as an __init__ parameter, default 3600). After TTL eviction,
enforce a hard cap of 50000 by removing the oldest entries if over the cap. Add an
__init__ parameter nonce_max_size with default 50000. Then add tests in
tests/test_security/test_agent_trust.py covering: (a) TTL eviction removes oldest
nonces, (b) hard cap enforcement, (c) replay detection within TTL window,
(d) replay allowed after TTL expiry. Use unittest.mock.patch on time.monotonic.
Run tests and ruff check.
```

---

## Step 5 -- Add Thread Safety to InputGuard and OutputGuard Pattern Mutation

> **Priority:** P2 (IMPORTANT)
> **Estimated complexity:** Low
> **Files:** proxilion/guards/input_guard.py, proxilion/guards/output_guard.py, tests/test_guards.py

### Problem

InputGuard.add_pattern(), remove_pattern(), and the equivalent methods in OutputGuard modify self.patterns and self._pattern_index without holding any lock. These objects are documented as reusable singletons shared across requests. Concurrent calls to add_pattern from one thread and check() from another can cause:

- RuntimeError: dictionary changed size during iteration (crash).
- Silently skipped patterns during iteration (security bypass).

### Fix

1. Add a threading.RLock to InputGuard.__init__ as self._lock.
2. Acquire self._lock in add_pattern(), remove_pattern(), and check().
3. Repeat for OutputGuard: add self._lock, acquire in add_pattern(), remove_pattern(), check(), and redact().
4. Use RLock (not Lock) to allow check() to call internal methods that also acquire the lock.

### Expected behavior

- Concurrent add_pattern and check calls do not crash or skip patterns.
- Single-threaded performance is unaffected (RLock acquisition is sub-microsecond when uncontended).
- The lock does not introduce deadlock risk (RLock is reentrant; no external locks are acquired while held).

### Tests

1. Spawn 10 threads: 5 calling check() in a loop, 5 calling add_pattern/remove_pattern in a loop.
2. Run for 1000 iterations per thread.
3. Assert no RuntimeError or other exceptions.
4. Assert all patterns are correctly applied after the threads complete.

### Verification

```
python3 -m pytest tests/test_guards.py -x -q -k "thread"
python3 -m ruff check proxilion/guards/input_guard.py proxilion/guards/output_guard.py
python3 -m mypy proxilion/guards/input_guard.py proxilion/guards/output_guard.py
```

### Claude Code prompt

```
Read proxilion/guards/input_guard.py. In InputGuard.__init__, add self._lock =
threading.RLock(). Import threading at the top. Wrap the body of add_pattern(),
remove_pattern(), and check() with "with self._lock:". Do the same for
proxilion/guards/output_guard.py -- add self._lock to OutputGuard.__init__, wrap
add_pattern(), remove_pattern(), check(), and redact() with "with self._lock:".
Then add a thread-safety test in tests/test_guards.py: spawn 10 threads (5 calling
check with benign input in a tight loop, 5 calling add_pattern/remove_pattern with
a test pattern). Run 1000 iterations per thread. Assert no exceptions are raised.
Run tests and ruff check.
```

---

## Step 6 -- Eliminate Mutation in AuditEvent.verify_hash

> **Priority:** P2 (IMPORTANT)
> **Estimated complexity:** Low
> **Files:** proxilion/types.py, tests/test_core.py

### Problem

AuditEvent.verify_hash() temporarily sets self.event_hash = None, recomputes the hash, then restores the original value. Since AuditEvent is a non-frozen dataclass with no lock, a concurrent reader (compliance exporter, Merkle tree builder) accessing event_hash during this window sees None. This causes false integrity violation alerts in concurrent environments.

### Fix

1. Extract the hash computation logic from compute_hash() into a pure function or static method _compute_hash_for(event_data_dict: dict) -> str that takes the event's data as a dict (without event_hash).
2. Modify compute_hash() to call this pure function and assign the result to self.event_hash.
3. Modify verify_hash() to call the pure function without mutating self.event_hash. Compare the returned hash to the stored self.event_hash.
4. Remove the temporary None assignment and restoration.

### Expected behavior

- verify_hash() never modifies self.event_hash, even transiently.
- Concurrent readers always see the correct event_hash value.
- compute_hash() continues to work as before (assigns the computed hash to self.event_hash).
- The hash computation logic exists in exactly one place.

### Tests

1. Create an AuditEvent, compute its hash, verify it passes verify_hash.
2. Spawn 100 threads: 50 calling verify_hash, 50 reading event_hash.
3. Assert no thread ever reads None for event_hash.
4. Assert all verify_hash calls return True.

### Verification

```
python3 -m pytest tests/test_core.py -x -q -k "audit" && python3 -m pytest tests/test_audit_extended.py -x -q
python3 -m ruff check proxilion/types.py
python3 -m mypy proxilion/types.py
```

### Claude Code prompt

```
Read proxilion/types.py. Find the AuditEvent class and its compute_hash() and
verify_hash() methods. Currently verify_hash temporarily sets self.event_hash = None,
calls compute_hash logic, then restores. Refactor: extract the core hash computation
into a private method _compute_hash_data() that builds the hash input string from all
fields EXCEPT event_hash and returns the SHA-256 hex digest, without modifying any
instance attributes. Change compute_hash() to call self.event_hash = self._compute_hash_data().
Change verify_hash() to: expected = self._compute_hash_data(); return expected == self.event_hash.
No temporary mutation. Then add a thread-safety test in tests/test_core.py: create an
AuditEvent, compute its hash, spawn 100 threads all calling verify_hash() simultaneously,
assert none of them see event_hash as None and all return True. Run tests and ruff check.
```

---

## Step 7 -- Fix Inverted Truncation Logic in OutputGuard._truncate_match

> **Priority:** P2 (IMPORTANT)
> **Estimated complexity:** Low
> **Files:** proxilion/guards/output_guard.py, tests/test_guards.py

### Problem

OutputGuard._truncate_match (line 572) has inverted branch logic:

```
if len(text) <= max_length:
    return text[:4] + "..." + text[-4:] if len(text) > 8 else "[...]"
return text[:8] + "..." + text[-4:]
```

When len(text) <= max_length (e.g., a 4-digit CVV with max_length=20): if the text is 8 characters or fewer, it returns "[...]" (correct for very short text), but if it is 9-20 characters, it returns a truncated preview (leaking partial PII for text that was supposed to be safe to show in full). When len(text) > max_length: it always returns text[:8] + "..." + text[-4:] (showing 12 characters of long sensitive data).

The intent appears to be: short text is fully obscured, medium text gets a truncated preview, and the max_length parameter controls the threshold.

### Fix

1. Rewrite _truncate_match with clear, correct logic:
   - If len(text) <= 8: return "[...]" (fully obscured, too short to truncate meaningfully).
   - If len(text) <= max_length: return text[:4] + "..." + text[-4:] (truncated preview).
   - Otherwise: return text[:4] + "..." + text[-4:] (same truncation for long text).
2. Add a docstring clarifying the behavior for each length range.

### Expected behavior

- A 4-character CVV match "1234" is logged as "[...]".
- A 16-character credit card "4111111111111111" is logged as "4111...1111".
- A 40-character API key is logged as "sk-p...789a".

### Tests

1. Test _truncate_match with text of length 4 (returns "[...]").
2. Test with text of length 10 (returns truncated preview).
3. Test with text of length 30 (returns truncated preview).
4. Test with empty string (returns "[...]").
5. Test with text of exactly max_length (returns truncated preview).

### Verification

```
python3 -m pytest tests/test_guards.py -x -q -k "truncat"
python3 -m ruff check proxilion/guards/output_guard.py
python3 -m mypy proxilion/guards/output_guard.py
```

### Claude Code prompt

```
Read proxilion/guards/output_guard.py, find the _truncate_match method around line 572.
The current logic has inverted branches. Rewrite it clearly:
  def _truncate_match(self, text: str, max_length: int = 20) -> str:
      if len(text) <= 8:
          return "[...]"
      return text[:4] + "..." + text[-4:]
The max_length parameter is no longer needed for the branching since we always
truncate if over 8 chars. Keep the parameter for backwards compatibility but
simplify the logic. Add tests in tests/test_guards.py for: empty string, 4-char
string, 8-char string, 16-char string, 40-char string. Assert the expected
truncation for each. Run tests and ruff check.
```

---

## Step 8 -- Rename KillSwitch.is_active Property to check_active() Method

> **Priority:** P2 (IMPORTANT)
> **Estimated complexity:** Low
> **Files:** proxilion/security/behavioral_drift.py, tests/test_security/test_behavioral_drift.py

### Problem

KillSwitch.is_active is a property that contains auto-reset logic modifying internal state. Properties are expected to be side-effect-free by Python convention. A developer who checks is_active twice in a guard chain (e.g., if kill_switch.is_active: log(); if kill_switch.is_active: halt()) may get different results from the same property access because the first read triggered auto-reset.

### Fix

1. Rename the is_active property to a method check_active() -> bool.
2. Add a new read-only property is_active that returns self._active without any side effects (pure read).
3. Move the auto-reset logic into check_active().
4. Update all internal callers and tests to use check_active() where the auto-reset behavior is needed, and is_active where a pure read is needed.
5. Document the distinction in the class docstring.

### Expected behavior

- kill_switch.is_active returns the current state without side effects, safe to call multiple times.
- kill_switch.check_active() returns the current state and performs auto-reset if the duration has elapsed.
- Existing behavior is preserved: the auto-reset still happens, but only when explicitly requested via check_active().

### Tests

1. Activate a kill switch with a short duration.
2. Assert is_active returns True.
3. Assert calling is_active again still returns True (no side effect).
4. Call check_active() and assert it returns True.
5. Mock time past the duration, call check_active(), assert it returns False (auto-reset triggered).
6. Assert is_active now returns False.

### Verification

```
python3 -m pytest tests/test_security/test_behavioral_drift.py -x -q
python3 -m ruff check proxilion/security/behavioral_drift.py
python3 -m mypy proxilion/security/behavioral_drift.py
```

### Claude Code prompt

```
Read proxilion/security/behavioral_drift.py. Find the KillSwitch class and its
is_active property. Currently is_active contains auto-reset logic (modifies _active).
Refactor: (1) rename the current is_active property to check_active() as a regular
method; (2) add a new is_active property that simply returns self._active with no
side effects. Update all callers within behavioral_drift.py that use is_active to
use check_active() if they need the auto-reset behavior, or leave as is_active if
they just need a read. Then update tests/test_security/test_behavioral_drift.py:
add tests showing is_active is idempotent (calling twice returns same value) and
check_active() triggers auto-reset after duration elapses. Update any existing
tests that relied on the property having side effects. Run tests and ruff check.
```

---

## Step 9 -- Fix Capability Delegation Using Set Difference Instead of has_capability

> **Priority:** P2 (IMPORTANT)
> **Estimated complexity:** Low
> **Files:** proxilion/security/agent_trust.py, tests/test_security/test_agent_trust.py

### Problem

AgentTrustManager.create_delegation (around line 631) checks delegation validity with:

```
invalid_caps = capabilities - issuer.capabilities
```

This set difference only considers literal string equality. If the issuer has capabilities like "read:*" (a wildcard prefix), delegating "read:documents" is flagged as invalid because "read:documents" is not literally in the issuer's capability set. However, the has_capability() method correctly handles wildcards by checking if any registered capability matches the requested one via prefix or glob. The delegation check is stricter than the capability check.

### Fix

1. Replace the set difference with a loop that calls issuer.has_capability(cap) for each requested capability:
   invalid_caps = {cap for cap in capabilities if not issuer.has_capability(cap)}
2. The existing "*" wildcard shortcut (line 633) can be removed since has_capability already handles it.

### Expected behavior

- An agent with "read:*" can delegate "read:documents", "read:logs", etc.
- An agent with "*" can delegate any capability.
- An agent with only "read" cannot delegate "write" (correctly rejected).
- The delegation token's granted_capabilities reflects exactly what was requested.

### Tests

1. Register an agent with capabilities={"read:*", "write:reports"}.
2. Delegate "read:documents" -- assert success.
3. Delegate "read:logs" -- assert success.
4. Delegate "write:reports" -- assert success.
5. Delegate "write:logs" -- assert failure (not covered by any wildcard).
6. Register an agent with capabilities={"*"}, delegate any capability -- assert success.

### Verification

```
python3 -m pytest tests/test_security/test_agent_trust.py -x -q -k "delegat"
python3 -m ruff check proxilion/security/agent_trust.py
python3 -m mypy proxilion/security/agent_trust.py
```

### Claude Code prompt

```
Read proxilion/security/agent_trust.py. Find create_delegation() (around line 625-650).
The line "invalid_caps = capabilities - issuer.capabilities" uses set difference which
does not respect wildcards. The issuer's has_capability() method handles wildcards
correctly. Replace the set difference with:
  invalid_caps = {cap for cap in capabilities if not issuer.has_capability(cap)}
Remove the separate "if '*' in issuer.capabilities" shortcut since has_capability
already handles that. Then add tests in tests/test_security/test_agent_trust.py:
register an agent with capabilities={"read:*"}, delegate "read:documents" (should
succeed), delegate "write:anything" (should fail). Register an agent with {"*"},
delegate anything (should succeed). Run tests and ruff check.
```

---

## Step 10 -- Replace Deprecated asyncio.get_event_loop() Across 9 Files

> **Priority:** P2 (IMPORTANT)
> **Estimated complexity:** Medium
> **Files:** proxilion/scheduling/scheduler.py, proxilion/resilience/fallback.py, proxilion/streaming/transformer.py, proxilion/contrib/openai.py, proxilion/contrib/anthropic.py, proxilion/contrib/google.py, proxilion/contrib/langchain.py, proxilion/tools/registry.py, tests/test_scheduling.py

### Problem

asyncio.get_event_loop() is deprecated since Python 3.10 and raises RuntimeError in Python 3.12+ when called outside of an async context with no running event loop. The project classifies Python 3.13 as supported (pyproject.toml). Nine files use this deprecated call:

- proxilion/scheduling/scheduler.py (line 354)
- proxilion/resilience/fallback.py (line 386)
- proxilion/streaming/transformer.py (lines 652, 656)
- proxilion/contrib/openai.py (line 440)
- proxilion/contrib/anthropic.py (line 477)
- proxilion/contrib/google.py (line 764)
- proxilion/contrib/langchain.py (lines 314, 344)
- proxilion/tools/registry.py (line 623)

### Fix

For each call site, determine the context:

1. If inside an async def: replace with asyncio.get_running_loop().
2. If in a sync function that needs to run an async coroutine: use asyncio.run() for the top-level call, or check for a running loop first with a try/except pattern:
   ```
   try:
       loop = asyncio.get_running_loop()
   except RuntimeError:
       loop = asyncio.new_event_loop()
       asyncio.set_event_loop(loop)
   ```
3. Also move "import time" from inside scheduler.py's shutdown() method body (line 391) to the module-level imports for consistency.

### Expected behavior

- No DeprecationWarning from asyncio on any supported Python version.
- No RuntimeError when calling sync-to-async bridge methods in Python 3.12+.
- Async methods correctly use the running loop.
- Sync methods that bridge to async create a new loop if none exists.

### Tests

1. Test that scheduler.submit_async works in Python 3.12+ without warnings.
2. Test that contrib handlers' sync wrappers work without a pre-existing event loop.
3. Filter for DeprecationWarning in pytest configuration and assert zero asyncio deprecation warnings.

### Verification

```
python3 -m pytest tests/test_scheduling.py -x -q
python3 -m ruff check proxilion/scheduling/ proxilion/resilience/ proxilion/streaming/ proxilion/contrib/ proxilion/tools/
python3 -m mypy proxilion
```

### Claude Code prompt

```
Search all Python files under proxilion/ for "get_event_loop" using grep. For each
occurrence, read the surrounding context to determine if it is inside an async def
or a sync def. For async def functions, replace asyncio.get_event_loop() with
asyncio.get_running_loop(). For sync functions that need to run a coroutine, replace
with a try/except pattern: try: loop = asyncio.get_running_loop() except RuntimeError:
loop = asyncio.new_event_loop(). In scheduler.py, also move the "import time" from
inside the shutdown() method to the top-level imports. Run the full test suite
(python3 -m pytest -x -q) and ruff check to verify no regressions.
```

---

## Step 11 -- Fix CascadeProtector Callback Deadlock Risk

> **Priority:** P2 (IMPORTANT)
> **Estimated complexity:** Medium
> **Files:** proxilion/security/cascade_protection.py, tests/test_cascade_protection.py

### Problem

CascadeProtector._notify_state_change is called while self._lock (an RLock) is held. This method invokes user-supplied callbacks. If a callback attempts to acquire an external lock held by a thread waiting for the CascadeProtector's lock, the system deadlocks.

### Fix

1. In every method that calls _notify_state_change, collect the state change data while holding the lock, then release the lock before dispatching callbacks.
2. Pattern: within the lock, append change events to a local list. After the "with self._lock:" block exits, iterate the list and call each callback.
3. _notify_state_change should not be called inside any lock scope.

### Expected behavior

- State changes are detected and recorded atomically under the lock.
- Callbacks execute outside the lock scope, free to acquire external resources.
- The CascadeProtector's internal state is consistent when callbacks see it (since changes were committed before the lock was released).

### Tests

1. Register a callback that acquires an external threading.Lock.
2. From another thread, hold that external lock and call a CascadeProtector method that triggers a state change.
3. Assert no deadlock (use a timeout on thread.join).
4. Assert the callback was called with the correct state change data.

### Verification

```
python3 -m pytest tests/test_cascade_protection.py -x -q
python3 -m ruff check proxilion/security/cascade_protection.py
python3 -m mypy proxilion/security/cascade_protection.py
```

### Claude Code prompt

```
Read proxilion/security/cascade_protection.py. Find all methods that call
_notify_state_change. In each case, the call is made inside a "with self._lock:" block.
Refactor each method so that: (1) within the lock, compute what state changes occurred
and store them in a local variable (e.g., pending_notifications = []); (2) after the
lock is released, iterate pending_notifications and call _notify_state_change for each.
Move the _notify_state_change call OUTSIDE the lock scope. Then add a deadlock
regression test in tests/test_cascade_protection.py: register a callback that acquires
an external lock, from another thread hold that lock and trigger a state change, use
thread.join(timeout=5) to detect deadlock. Run tests and ruff check.
```

---

## Step 12 -- Add Context Manager and Lifecycle Warning to AuditLogger

> **Priority:** P3 (MINOR)
> **Estimated complexity:** Low
> **Files:** proxilion/audit/logger.py, tests/test_audit_extended.py

### Problem

AuditLogger has no __del__ finalizer and no warning when the object is garbage-collected without calling close(). If a Merkle tree batch is in progress and the object is GC'd, the pending batch is silently lost. The audit log is the primary tamper-evidence mechanism, so silent data loss undermines its reliability guarantee.

### Fix

1. Add a _closed: bool = False flag to __init__.
2. Set _closed = True in close().
3. Add __enter__ and __exit__ methods for context manager support (__exit__ calls close()).
4. Add a __del__ method that logs a WARNING if _closed is False when the object is garbage-collected.

### Expected behavior

- Using AuditLogger as a context manager automatically closes it on exit.
- Forgetting to close the logger produces a warning in the log output.
- Calling close() explicitly suppresses the warning.
- No behavior change for existing code that already calls close().

### Tests

1. Test context manager usage: "with AuditLogger(config) as logger: logger.log_authorization(...)" -- assert no warnings.
2. Test lifecycle warning: create a logger, del it without closing, capture warnings and assert one is emitted.
3. Test that close() then del produces no warning.

### Verification

```
python3 -m pytest tests/test_audit_extended.py -x -q -k "context_manager or lifecycle"
python3 -m ruff check proxilion/audit/logger.py
python3 -m mypy proxilion/audit/logger.py
```

### Claude Code prompt

```
Read proxilion/audit/logger.py. In AuditLogger.__init__, add self._closed = False.
In close(), set self._closed = True at the start. Add __enter__(self) returning self,
and __exit__(self, *args) calling self.close(). Add __del__(self) that checks
if not self._closed: import warnings; warnings.warn("AuditLogger was not closed.
Pending audit data may be lost. Use 'with AuditLogger(config) as logger:' or call
logger.close() explicitly.", ResourceWarning, stacklevel=2). Then add tests in
tests/test_audit_extended.py: (a) test context manager usage logs and closes
cleanly, (b) test that deleting without close emits ResourceWarning. Run tests
and ruff check.
```

---

## Step 13 -- Add Platform-Aware Warning for Windows File Locking

> **Priority:** P3 (MINOR)
> **Estimated complexity:** Low
> **Files:** proxilion/audit/logger.py, tests/test_audit_extended.py

### Problem

AuditLogger uses fcntl file locking (Unix-only) for concurrent write protection. On Windows, HAS_FCNTL=False and locking is silently skipped. Concurrent writes from multiple processes on Windows will produce corrupt log files, undermining the tamper-evident audit log guarantee. The public API makes no mention of this limitation.

### Fix

1. In AuditLogger.__init__, if HAS_FCNTL is False, emit a logging.warning: "File locking is not available on this platform. Multi-process concurrent writes to the audit log are not protected. Use a single-process writer or an external locking mechanism."
2. Add a note to the LoggerConfig docstring documenting the platform limitation.
3. Add a class attribute PLATFORM_LOCKING_AVAILABLE = HAS_FCNTL for programmatic checking.

### Expected behavior

- On Unix/macOS: no warning, fcntl locking works as before.
- On Windows: a clear warning at logger initialization, and a class attribute to check programmatically.
- Documentation accurately describes the platform limitation.

### Tests

1. Mock HAS_FCNTL to False, create an AuditLogger, assert the warning is logged.
2. Mock HAS_FCNTL to True, create an AuditLogger, assert no warning is logged.
3. Assert AuditLogger.PLATFORM_LOCKING_AVAILABLE matches HAS_FCNTL.

### Verification

```
python3 -m pytest tests/test_audit_extended.py -x -q -k "platform"
python3 -m ruff check proxilion/audit/logger.py
python3 -m mypy proxilion/audit/logger.py
```

### Claude Code prompt

```
Read proxilion/audit/logger.py. Find HAS_FCNTL (set near the top based on an import
try/except for fcntl). Add a class attribute to AuditLogger:
PLATFORM_LOCKING_AVAILABLE = HAS_FCNTL. In __init__, after existing initialization,
add: if not HAS_FCNTL: logger.warning("File locking is not available on this
platform. Multi-process concurrent writes to the audit log are not protected.").
Add a note to LoggerConfig's docstring about the platform limitation. Then mock
HAS_FCNTL in tests/test_audit_extended.py to test both the warning and no-warning
paths. Run tests and ruff check.
```

---

## Step 14 -- Fix ContextWindowGuard.pop() Breaking Hash Chain

> **Priority:** P2 (IMPORTANT)
> **Estimated complexity:** Medium
> **Files:** proxilion/security/memory_integrity.py, tests/test_security/test_memory_integrity.py

### Problem

ContextWindowGuard.pop() (line 777) removes the last message from self._messages but does not update the underlying MemoryIntegrityGuard's _sequence_counter or _last_hash. After a pop:

- The guard's chain state still reflects the removed message as the last entry.
- The next sign_message() call will reference the removed message's hash as previous_hash.
- Any subsequent verify_context() call will report a hash chain break.

The pop operation is semantically incompatible with an append-only hash chain.

### Fix

Two options (choose the safer one):

Option A (recommended): After popping, reset the MemoryIntegrityGuard and re-sign all remaining messages. This preserves the hash chain invariant but is O(n) in the number of remaining messages.

Option B: Remove the pop() method entirely and raise NotImplementedError with a clear message explaining that hash chains are append-only. Add a rebuild_context() method that takes a list of messages, resets the guard, and re-signs all of them.

Recommended: Option A, since pop() is part of the public API and removing it would be a breaking change.

### Expected behavior

- After pop(), verify_context() returns valid=True for the remaining messages.
- After pop() followed by sign_message(), the new message's hash chain is valid.
- The operation is documented as O(n) in the number of remaining messages.

### Tests

1. Sign 5 messages, pop the last, verify_context returns valid.
2. Sign 5 messages, pop the last, sign a new message, verify_context returns valid.
3. Sign 5 messages, pop twice, verify_context returns valid.
4. Pop from an empty context, assert appropriate error handling.

### Verification

```
python3 -m pytest tests/test_security/test_memory_integrity.py -x -q -k "pop"
python3 -m ruff check proxilion/security/memory_integrity.py
python3 -m mypy proxilion/security/memory_integrity.py
```

### Claude Code prompt

```
Read proxilion/security/memory_integrity.py. Find ContextWindowGuard.pop() around
line 777. It removes the last message from self._messages but does not update the
MemoryIntegrityGuard's internal state (_sequence_counter, _last_hash). Fix this by:
after removing the message from self._messages, reset the underlying guard
(self._guard.reset() or re-initialize its chain state), then re-sign all remaining
messages in self._messages to rebuild the hash chain. If the guard has a reset()
method, use it; otherwise manually set _sequence_counter=0 and _last_hash=None (or
whatever the initial state is). After reset, iterate self._messages and call
self._guard.sign_message(msg.role, msg.content) for each to rebuild the chain.
Add a comment documenting that pop() is O(n). Then add tests in
tests/test_security/test_memory_integrity.py: sign 5 messages, pop, verify context
is still valid; sign 5, pop, sign 1 more, verify valid. Run tests and ruff check.
```

---

## Step 15 -- Enforce IntentCapsuleManager Capacity After Cleanup

> **Priority:** P2 (IMPORTANT)
> **Estimated complexity:** Low
> **Files:** proxilion/security/intent_capsule.py, tests/test_security/test_intent_capsule.py

### Problem

IntentCapsuleManager.create_capsule() (line 766) calls _cleanup_expired() when at capacity, then unconditionally creates the new capsule. If no capsules expired (all active with long TTLs), the dictionary grows beyond _max_capsules. The capacity limit is not enforced.

### Fix

1. After calling _cleanup_expired(), re-check len(self._capsules) >= self._max_capsules.
2. If still at capacity, raise a ConfigurationError (or a new CapacityExceededError) with a clear message: "IntentCapsuleManager at capacity ({max_capsules} active capsules). Cannot create new capsule."
3. Document the behavior in the create_capsule docstring.

### Expected behavior

- When all capsules are active and the manager is at capacity, create_capsule raises an error.
- When some capsules have expired, cleanup frees space and the new capsule is created.
- The _max_capsules limit is a hard bound, never exceeded.

### Tests

1. Create a manager with max_capsules=3.
2. Create 3 capsules with long TTLs.
3. Attempt to create a 4th, assert the appropriate error is raised.
4. Expire one capsule (mock time), create a 4th, assert success.

### Verification

```
python3 -m pytest tests/test_security/test_intent_capsule.py -x -q -k "capacity"
python3 -m ruff check proxilion/security/intent_capsule.py
python3 -m mypy proxilion/security/intent_capsule.py
```

### Claude Code prompt

```
Read proxilion/security/intent_capsule.py. Find IntentCapsuleManager.create_capsule()
around line 766. After the _cleanup_expired() call, add a re-check:
  if len(self._capsules) >= self._max_capsules:
      raise ConfigurationError(
          f"IntentCapsuleManager at capacity ({self._max_capsules} active capsules). "
          "Cannot create new capsule. Wait for existing capsules to expire."
      )
Import ConfigurationError from proxilion.exceptions if not already imported. Then add
tests in tests/test_security/test_intent_capsule.py: create a manager with max_capsules=3,
fill it, assert the 4th creation raises ConfigurationError, expire one, assert the 4th
succeeds. Run tests and ruff check.
```

---

## Step 16 -- Add Time Window to Sequence Validator REQUIRE_BEFORE Rules

> **Priority:** P3 (MINOR)
> **Estimated complexity:** Low
> **Files:** proxilion/security/sequence_validator.py, tests/test_sequence_validator.py

### Problem

The REQUIRE_BEFORE rule in SequenceValidator._check_require_before searches the entire per-user history with no time bound. A confirm_payment call from hours or days ago satisfies the check for submit_payment made today. This makes the validator ineffective for time-sensitive operation ordering.

### Fix

1. Add an optional window_seconds field to SequenceRule (default: None, meaning no time limit for backwards compatibility).
2. In _check_require_before, if rule.window_seconds is set, only consider history entries within the last window_seconds.
3. Document that setting window_seconds makes the rule time-bounded.

### Expected behavior

- A REQUIRE_BEFORE rule with window_seconds=300 only accepts the prerequisite if it occurred within the last 5 minutes.
- A REQUIRE_BEFORE rule with no window_seconds behaves as before (searches all history).
- The SequenceRule dataclass remains backwards-compatible.

### Tests

1. Create a REQUIRE_BEFORE rule with window_seconds=60.
2. Record the prerequisite call, immediately validate the target -- assert allowed.
3. Mock time forward 61 seconds, validate the target -- assert rejected.
4. Create a rule with no window_seconds, record prerequisite, mock time forward 3600 seconds, validate -- assert still allowed.

### Verification

```
python3 -m pytest tests/test_sequence_validator.py -x -q -k "window"
python3 -m ruff check proxilion/security/sequence_validator.py
python3 -m mypy proxilion/security/sequence_validator.py
```

### Claude Code prompt

```
Read proxilion/security/sequence_validator.py. Find the SequenceRule dataclass and add
an optional field: window_seconds: float | None = None. Find _check_require_before().
When searching the user's history for the required predecessor tool, if
rule.window_seconds is not None, filter history entries to only those where
(current_time - entry.timestamp) <= rule.window_seconds. If no matching entry is
found within the window, the check fails. Keep the existing behavior when
window_seconds is None. Then add tests in tests/test_sequence_validator.py: create a
REQUIRE_BEFORE rule with window_seconds=60, verify it passes when prereq is recent,
fails when prereq is old (mock time forward). Run tests and ruff check.
```

---

## Step 17 -- Reject Booleans in Integer/Float Schema Validation

> **Priority:** P3 (MINOR)
> **Estimated complexity:** Low
> **Files:** proxilion/validation/schema.py, tests/test_validation.py

### Problem

Python's bool is a subclass of int, so isinstance(True, int) returns True. If a schema parameter is typed "int" or "float", passing True or False passes validation. Booleans in numeric contexts are usually programmer errors or injection attempts.

### Fix

1. In the type validation branch for "int" and "integer", add an explicit check: if isinstance(value, bool): return validation failure.
2. In the type validation branch for "float" and "number", add the same check.
3. Place the boolean check before the int/float isinstance check.

### Expected behavior

- validate({"type": "int"}, True) returns invalid.
- validate({"type": "int"}, 1) returns valid.
- validate({"type": "float"}, False) returns invalid.
- validate({"type": "float"}, 1.0) returns valid.
- validate({"type": "boolean"}, True) returns valid (unchanged).

### Tests

1. Test integer schema rejects True and False.
2. Test float schema rejects True and False.
3. Test integer schema accepts 0, 1, -1, 999.
4. Test float schema accepts 0.0, 1.5, -3.14.
5. Test boolean schema accepts True and False (regression).

### Verification

```
python3 -m pytest tests/test_validation.py -x -q -k "bool"
python3 -m ruff check proxilion/validation/schema.py
python3 -m mypy proxilion/validation/schema.py
```

### Claude Code prompt

```
Read proxilion/validation/schema.py. Find the type validation logic where
isinstance(value, int) and isinstance(value, float) are checked. Before each of
these checks, add: if isinstance(value, bool): return a validation failure result
(match the existing error format, e.g., "Expected int, got bool"). This prevents
True/False from passing as integers or floats. Then add tests in tests/test_validation.py:
assert that True and False are rejected for int and float schemas, assert that normal
ints and floats still pass, assert booleans still pass for boolean schemas. Run tests
and ruff check.
```

---

## Step 18 -- Remove Redundant Path Traversal Check

> **Priority:** P3 (MINOR)
> **Estimated complexity:** Low
> **Files:** proxilion/validation/schema.py, tests/test_validation.py

### Problem

The _check_path_traversal function checks for "..\\" as a separate case after already checking for "..". Since "..\\" contains "..", the second check is redundant dead code. In a security-sensitive function, dead code can mislead reviewers into thinking it covers a case the first check does not.

### Fix

1. Remove the redundant "..\\" check.
2. Add a comment explaining that ".." covers all traversal variants including forward and back slash forms.

### Expected behavior

- Path traversal detection behavior is unchanged (all ".." sequences are caught by the single check).
- The code is clearer about what it detects and why.

### Tests

1. Test that "foo/../../etc/passwd" is detected (forward slash).
2. Test that "foo\\..\\..\\etc\\passwd" is detected (backslash).
3. Test that "foo/../bar" is detected.
4. Test that "foo..bar" is NOT detected (dots not forming a traversal).
5. Assert existing path traversal tests still pass.

### Verification

```
python3 -m pytest tests/test_validation.py -x -q -k "traversal"
python3 -m ruff check proxilion/validation/schema.py
python3 -m mypy proxilion/validation/schema.py
```

### Claude Code prompt

```
Read proxilion/validation/schema.py. Find _check_path_traversal. There is a check for
"..\\" that is redundant because an earlier check for ".." already catches all
traversal sequences. Remove the "..\\" check. Add a comment above the ".." check:
# Catches all traversal variants: ../, ..\, and bare .. sequences.
Verify that existing tests in tests/test_validation.py still pass, and add tests
for backslash traversal if not already present. Run tests and ruff check.
```

---

## Step 19 -- Update CHANGELOG, Version, and Documentation

> **Priority:** LOW
> **Estimated complexity:** Low
> **Files:** CHANGELOG.md, pyproject.toml, proxilion/__init__.py, docs/quickstart.md, CLAUDE.md

### Changes

1. Bump version from 0.0.11 to 0.0.12 in pyproject.toml and proxilion/__init__.py.
2. Add a CHANGELOG.md entry for 0.0.12 summarizing all 18 steps.
3. Update CLAUDE.md version reference.
4. Update docs/quickstart.md if any API changes affect examples (check_active rename, new context manager pattern for AuditLogger).
5. Update the test count and source line count in CLAUDE.md.

### Verification

```
grep -r "0.0.11" pyproject.toml proxilion/__init__.py  # Should find nothing
grep -r "0.0.12" pyproject.toml proxilion/__init__.py  # Should find both
python3 -m pytest -x -q
python3 -m ruff check proxilion tests
python3 -m ruff format --check proxilion tests
python3 -m mypy proxilion
```

### Claude Code prompt

```
Update the version from 0.0.11 to 0.0.12 in pyproject.toml (the version field) and
proxilion/__init__.py (the __version__ variable). Update CLAUDE.md to reflect the
new version. Add a new section to CHANGELOG.md for 0.0.12 with a summary of all
changes from this spec: rate limiter cleanup fix, middleware atomicity, HMAC
canonicalization, nonce TTL eviction, guard thread safety, AuditEvent mutation
elimination, output guard truncation fix, KillSwitch API fix, capability delegation
fix, asyncio modernization, cascade callback deadlock fix, AuditLogger lifecycle,
platform locking warning, pop chain fix, capsule capacity enforcement, sequence
validator time window, boolean validation, dead code removal. Review
docs/quickstart.md for any API changes (check_active rename, AuditLogger context
manager). Update CLAUDE.md test count. Run the full CI check.
```

---

## Step 20 -- Final Validation, README Diagrams, and Memory Update

> **Priority:** LOW
> **Estimated complexity:** Low
> **Files:** README.md, .proxilion-build/STATE.md, CLAUDE.md

### Changes

1. Run the full CI check (ruff check, ruff format, mypy, pytest).
2. Update .proxilion-build/STATE.md with the final status.
3. Add or update Mermaid diagrams at the end of README.md (see next section for diagram specifications).
4. Update CLAUDE.md memory references if any new modules were added.
5. Write "DONE" to .proxilion-build/BUILD_COMPLETE.

### Mermaid Diagrams to Add/Update in README.md

The following diagrams should be appended or updated at the end of README.md, after the existing diagrams section.

#### Rate Limiter Multi-Tier Atomic Check Flow

This diagram shows the corrected check-then-consume pattern introduced in Step 2.

```
flowchart TD
    A[Incoming Request] --> B{Dry-Run Check:<br/>Global Limiter}
    B -->|Insufficient tokens| C[REJECT: Global Rate Limited<br/>No tokens consumed anywhere]
    B -->|Sufficient tokens| D{Dry-Run Check:<br/>User Limiter}
    D -->|Insufficient tokens| E[REJECT: User Rate Limited<br/>No tokens consumed anywhere]
    D -->|Sufficient tokens| F{Dry-Run Check:<br/>Tool Limiter}
    F -->|Insufficient tokens| G[REJECT: Tool Rate Limited<br/>No tokens consumed anywhere]
    F -->|Sufficient tokens| H[All Tiers Passed]
    H --> I[Consume: Global Tokens]
    I --> J[Consume: User Tokens]
    J --> K[Consume: Tool Tokens]
    K --> L[REQUEST ALLOWED]
```

#### Nonce Eviction: TTL-Bounded OrderedDict

This diagram shows the corrected replay protection nonce lifecycle from Step 4.

```
flowchart LR
    A[New Message ID] --> B[Insert into OrderedDict<br/>with timestamp]
    B --> C{Size > Hard Cap?}
    C -->|Yes| D[Evict oldest entries<br/>until at cap]
    C -->|No| E[Check TTL]
    D --> E
    E --> F{Oldest entry age<br/>> nonce_ttl_seconds?}
    F -->|Yes| G[Remove oldest entry]
    G --> F
    F -->|No| H[Nonce Store Ready]
```

#### CascadeProtector Callback Safety Pattern

This diagram shows the corrected lock-then-notify pattern from Step 11.

```
sequenceDiagram
    participant Caller
    participant CP as CascadeProtector
    participant Lock as self._lock
    participant CB as User Callback

    Caller->>CP: isolate_tool(tool)
    CP->>Lock: acquire()
    Note over CP: Compute state changes<br/>Store in local list
    CP->>Lock: release()
    Note over CP: Lock released BEFORE callbacks
    CP->>CB: notify(state_change)
    Note over CB: Safe to acquire<br/>external locks
    CB-->>CP: callback complete
    CP-->>Caller: return result
```

### Verification

```
python3 -m ruff check proxilion tests && \
python3 -m ruff format --check proxilion tests && \
python3 -m mypy proxilion && \
python3 -m pytest -x -q
```

### Claude Code prompt

```
Run the full CI check: python3 -m ruff check proxilion tests && python3 -m ruff format
--check proxilion tests && python3 -m mypy proxilion && python3 -m pytest -x -q.
If everything passes, update .proxilion-build/STATE.md to mark spec-v6 as complete
with the final test count and version 0.0.12. Add the three Mermaid diagrams specified
in the spec (Rate Limiter Multi-Tier Atomic Check, Nonce Eviction TTL OrderedDict,
CascadeProtector Callback Safety) to the end of README.md in the diagrams section.
Update CLAUDE.md version to 0.0.12 and update the test count. Write "DONE" to
.proxilion-build/BUILD_COMPLETE.
```

---

## Summary of All Steps

| Step | Priority | Category | Description | Files |
|------|----------|----------|-------------|-------|
| 1 | P1 | Correctness | Fix rate limiter cleanup never evicting stale buckets | rate_limiter.py |
| 2 | P1 | Security | Fix non-atomic multi-tier token consumption | rate_limiter.py |
| 3 | P1 | Security | Replace repr-based HMAC payloads with canonical JSON | intent_capsule.py, agent_trust.py |
| 4 | P1 | Security | Replace unordered nonce set with TTL-bounded OrderedDict | agent_trust.py |
| 5 | P2 | Thread Safety | Add lock to InputGuard and OutputGuard pattern mutation | input_guard.py, output_guard.py |
| 6 | P2 | Thread Safety | Eliminate mutation in AuditEvent.verify_hash | types.py |
| 7 | P2 | Correctness | Fix inverted truncation logic in OutputGuard | output_guard.py |
| 8 | P2 | API Consistency | Rename KillSwitch side-effecting property to method | behavioral_drift.py |
| 9 | P2 | Correctness | Fix capability delegation ignoring wildcards | agent_trust.py |
| 10 | P2 | Compatibility | Replace deprecated asyncio.get_event_loop across 9 files | 9 files |
| 11 | P2 | Reliability | Fix callback deadlock in CascadeProtector | cascade_protection.py |
| 12 | P3 | Reliability | Add context manager and lifecycle warning to AuditLogger | logger.py |
| 13 | P3 | Platform | Add Windows file locking warning | logger.py |
| 14 | P2 | Correctness | Fix ContextWindowGuard.pop breaking hash chain | memory_integrity.py |
| 15 | P2 | Correctness | Enforce IntentCapsuleManager capacity after cleanup | intent_capsule.py |
| 16 | P3 | Correctness | Add time window to REQUIRE_BEFORE rules | sequence_validator.py |
| 17 | P3 | Security | Reject booleans in integer/float schema validation | schema.py |
| 18 | P3 | Code Quality | Remove redundant path traversal check | schema.py |
| 19 | LOW | Release | Update CHANGELOG, version, documentation | 5 files |
| 20 | LOW | Release | Final validation, README diagrams, memory update | 3 files |

---

## Risk Assessment

| Risk | Mitigation |
|------|-----------|
| Step 3 (HMAC canonicalization) is a breaking change for existing signed capsules/tokens | Acceptable at 0.0.x semver; no production deployments depend on cross-version signature compatibility |
| Step 8 (KillSwitch rename) changes the public API | is_active remains as a property (pure read); check_active() is the new method; no removal, only addition |
| Step 14 (pop chain rebuild) makes pop() O(n) | Document the cost; typical context windows are small (< 100 messages); O(n) on pop is acceptable |
| Step 2 (atomic rate limiting) adds a dry-run check phase | Marginal latency increase (~1 microsecond) for the extra get_remaining calls; negligible for the safety guarantee |
| Step 10 (asyncio modernization) changes event loop acquisition | Covered by tests on all supported Python versions (3.10-3.13) |

---

## Dependency Graph Between Steps

Steps are listed in recommended execution order. Steps within the same priority tier can be parallelized.

```
P1 Critical (Steps 1-4): Execute first, in order
  Step 1 (cleanup fix) -> Step 2 (middleware atomicity) [both in rate_limiter.py]
  Step 3 (HMAC canonicalization) -- independent
  Step 4 (nonce OrderedDict) -- independent

P2 Important (Steps 5-11, 14-15): Execute after P1, parallelizable
  Step 5 (guard locks) -- independent
  Step 6 (verify_hash mutation) -- independent
  Step 7 (truncation logic) -- independent
  Step 8 (KillSwitch rename) -- independent
  Step 9 (delegation wildcards) -- independent, but touches agent_trust.py (coordinate with Step 4)
  Step 10 (asyncio) -- independent
  Step 11 (cascade callbacks) -- independent
  Step 14 (pop chain fix) -- independent
  Step 15 (capsule capacity) -- independent

P3 Minor (Steps 12-13, 16-18): Execute after P2
  Step 12 (logger lifecycle) -> Step 13 (platform warning) [both in logger.py]
  Step 16 (sequence window) -- independent
  Step 17 (boolean validation) -- independent
  Step 18 (dead code) -- independent

Release (Steps 19-20): Execute last, after all other steps
  Step 19 (version/changelog) -> Step 20 (final validation)
```
