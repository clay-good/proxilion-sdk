# Proxilion SDK -- Hardening and Production Readiness Spec v10

**Version:** 0.0.15 -> 0.0.16
**Date:** 2026-03-21
**Status:** READY FOR IMPLEMENTATION
**Previous spec:** docs/specs/spec-v9.md (0.0.14 -> 0.0.15, depends on spec-v9 completion)
**Depends on:** spec-v2 steps 16-18 must be complete. spec-v3 through spec-v9 form a sequential dependency chain. This spec consolidates the highest-impact remaining findings from the full audit into a single actionable cycle.

---

## Executive Summary

This spec covers the eleventh improvement cycle for the Proxilion SDK. It was produced from a fresh deep-dive audit of all 89 Python source files (54,375 source lines), 69 test files, 10 prior spec documents, and the cumulative findings log in STATE.md. Every item addresses a concrete deficiency in existing code, tests, or documentation. No net-new features are introduced.

The previous ten specs addressed: critical runtime bugs (spec.md), CI hardening and version sync (spec-v1), structured error context and developer experience (spec-v2), thread-safety stabilization with bounded collections (spec-v3), security bypass vector closure and deployment guidance (spec-v4), production readiness with input validation and secret key management (spec-v5), rate limiter correctness, crypto robustness, and replay protection (spec-v6), comprehensive gap closure across all prior findings (spec-v7), cryptographic correctness, thread safety closure, data leakage prevention, and performance optimization (spec-v8), and security boundary hardening, operational reliability, and observability (spec-v9).

This cycle focuses on eight pillars:

1. **Cryptographic integrity** -- replacing MD5 checksums in cloud audit exporters with SHA-256, replacing non-CSPRNG jitter in retry backoff with os.urandom-backed randomness, and making IntentCapsule a frozen dataclass to prevent post-creation signature invalidation.
2. **Thread safety closure** -- adding RLock to QueueApprovalStrategy, fixing the TOCTOU in IntentCapsuleManager capacity checks, and making request counter generation collision-resistant.
3. **Security default hardening** -- inverting SQL injection detection to opt-out, extending path traversal checks to non-string typed parameters, escaping regex metacharacters in wildcard-to-regex conversion, and replacing re.match with re.fullmatch in IDOR pattern checks.
4. **Memory safety** -- bounding the revoked tokens set in AgentTrustManager, implementing deterministic nonce eviction with TTL-ordered structures, and adding max-retry-with-dead-letter semantics to cloud exporter batch failure recovery.
5. **Operational correctness** -- replacing assert with explicit guards in production code, adding constant-time comparison to Merkle proof verification, fixing OutputGuard truncation off-by-one, and eliminating side effects from ToolCache containment checks.
6. **Code deduplication** -- extracting triplicated secret key validation into a shared utility, exposing BatchedHashChain.batch_size as a public property, and adding O(1) event ID indexing to HashChain.
7. **Test and CI hardening** -- adding concurrency stress tests for QueueApprovalStrategy, adding LFU eviction correctness tests, adding decorator combination edge cases, replacing hardcoded test keys with secrets.token_hex, and linting all test files.
8. **Documentation and observability** -- updating README with current Mermaid architecture diagrams, updating CLAUDE.md with current metrics, adding install instructions, updating CHANGELOG, and bumping version.

After this spec is complete, the SDK should have zero known cryptographic weaknesses in production paths, zero unbounded memory growth vectors, thread-safe approval workflows, secure-by-default validation settings, and complete documentation reflecting the current architecture.

---

## Codebase Snapshot (2026-03-21)

| Metric | Value |
|--------|-------|
| Python source files | 89 |
| Source lines (proxilion/) | 54,375 |
| Test files | 69 |
| Test count | 2,517 passed, 122 skipped, 29 xfailed |
| Python versions tested | 3.10, 3.11, 3.12 (CI), 3.13 (local) |
| Ruff lint violations | 0 |
| Ruff format violations | 0 (157 files) |
| Mypy errors | 0 (89 source files) |
| Version (pyproject.toml) | 0.0.7 |
| Version (__init__.py) | 0.0.7 |
| CI/CD | GitHub Actions (test, lint, typecheck, coverage, pip-audit) |
| Coverage threshold | 85% (enforced in CI) |
| Known P1 findings (this audit) | 8 |
| Known P2 findings (this audit) | 12 |
| Known P3 findings (this audit) | 15 |
| Spec-v2 steps remaining | 3 of 18 (steps 16-18) |

---

## Logic Breakdown: Deterministic vs Probabilistic

Proxilion is explicitly designed to use deterministic logic for all security decisions. This breakdown quantifies the split across all 89 modules.

| Logic Type | Percentage | Module Count | Description |
|------------|-----------|--------------|-------------|
| Deterministic | ~97% | 86 of 89 | Regex pattern matching, set membership checks, SHA-256 hash chains, HMAC-SHA256 verification, token bucket counters, finite state machines, boolean policy evaluation, path normalization via PurePosixPath, Merkle tree construction, sliding window counters, circuit breaker state machines, frozen dataclass validation, schema constraint enforcement |
| Statistical (bounded, auditable) | ~3% | 3 of 89 | Token estimation heuristic in context/message_history.py (1.3 words/token ratio with configurable TokenEstimator), risk score aggregation in guards (weighted sum of deterministic pattern matches), behavioral drift z-score thresholds (statistical but not ML -- same input always produces same output given same baseline) |

Zero LLM inference calls. Zero ML model evaluations. Zero non-deterministic random decisions in any security path. The three "statistical" modules use bounded arithmetic on deterministic inputs -- they are auditable and reproducible.

---

## Dependency Chain

```
spec.md (0.0.4-0.0.5) COMPLETE
    |
spec-v1.md (0.0.6-0.0.7) COMPLETE
    |
spec-v2.md (0.0.7-0.0.8) IN PROGRESS (15/18)
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
spec-v8.md (0.0.13-0.0.14) BLOCKED on spec-v7
    |
spec-v9.md (0.0.14-0.0.15) BLOCKED on spec-v8
    |
spec-v10.md (0.0.15-0.0.16) BLOCKED on spec-v9 <-- THIS SPEC
```

---

## Quick Install

```bash
# Core SDK (zero runtime dependencies)
pip install proxilion

# With Pydantic schema validation
pip install proxilion[pydantic]

# With Casbin policy engine
pip install proxilion[casbin]

# With OPA policy engine
pip install proxilion[opa]

# All optional dependencies
pip install proxilion[all]

# Development (tests, linting, type checking)
pip install proxilion[dev]
```

---

## Findings Summary

All findings below were identified during a fresh audit on 2026-03-21. Each finding includes the exact file path, line number, root cause, and impact assessment. Findings are organized by the pillar they belong to and referenced by their step number.

### P1 Critical Findings (8)

| ID | File | Line(s) | Finding | Step |
|----|------|---------|---------|------|
| P1-01 | audit/exporters/cloud_base.py | 341 | MD5 used for audit export integrity checksums; MD5 is cryptographically broken and undermines tamper-evidence guarantees | 1 |
| P1-02 | resilience/retry.py | 99 | random.uniform (non-CSPRNG) used for retry jitter; predictable timing enables synchronized timing attacks | 2 |
| P1-03 | security/intent_capsule.py | 109 | IntentCapsule dataclass is mutable; post-creation field mutation silently invalidates signature verification without detection | 3 |
| P1-04 | decorators.py | 192-310 | QueueApprovalStrategy has no threading lock; concurrent approve/deny/request calls produce data races on shared dicts | 4 |
| P1-05 | security/intent_capsule.py | 776-788 | IntentCapsuleManager capacity check has TOCTOU; capsule creation outside lock allows max_capsules overshoot | 5 |
| P1-06 | validation/schema.py | 477 | SQL injection detection defaults to allow_sql_keywords=True; schemas without explicit opt-out get zero SQL protection | 6 |
| P1-07 | validation/schema.py | 452,472 | Path traversal check only runs on type="str" parameters; type="any" or list/dict parameters bypass all traversal detection | 7 |
| P1-08 | security/intent_capsule.py | 147-150 | Wildcard-to-regex uses pattern.replace("*", ".*") without re.escape; regex metacharacters in pattern names are interpreted | 8 |

### P2 Important Findings (12)

| ID | File | Line(s) | Finding | Step |
|----|------|---------|---------|------|
| P2-01 | security/agent_trust.py | 439,557,683 | _revoked_tokens set grows without bound; cleanup_expired never touches it; adversarial revoke loops cause OOM | 9 |
| P2-02 | security/agent_trust.py | 440,886-890 | _message_nonces cleanup removes arbitrary entries from unordered set; old nonces retained while new ones dropped, creating replay windows | 9 |
| P2-03 | security/intent_capsule.py | 252,353 | Signature data uses Python list repr for set serialization; repr format is implementation-defined and ambiguous for names containing quotes/commas | 10 |
| P2-04 | security/agent_trust.py | 445-451,528 | Agent secret derivation has no nonce; re-registering same agent_id produces identical secret, enabling revoked agent signature reuse | 10 |
| P2-05 | audit/exporters/cloud_base.py | 459-465 | Failed export batch restore prepends to pending list outside lock; TOCTOU causes ordering violation and unbounded growth on repeated failure | 11 |
| P2-06 | observability/metrics.py | 711 | assert used for runtime null guard; disabled by python -O flag in production, causing TypeError with no diagnostic context | 12 |
| P2-07 | audit/hash_chain.py | 465 | Merkle proof verification uses == (short-circuit) instead of hmac.compare_digest (constant-time) | 13 |
| P2-08 | guards/output_guard.py | 574-576 | _truncate_match produces longer output than input for 9-10 character matches; off-by-one in short-string branch | 14 |
| P2-09 | caching/tool_cache.py | 582-585 | __contains__ calls get() which increments hit counter and moves LRU entry; read-only probe mutates state | 15 |
| P2-10 | security/idor_protection.py | 251 | re.match used instead of re.fullmatch; suffix injection bypasses pattern validation (e.g., "doc_1_evil" matches "doc_[0-9]+") | 8 |
| P2-11 | caching/tool_cache.py | 455-465 | LFU eviction scans entire cache dict under lock; O(n) per insert at capacity becomes bottleneck at high throughput | 16 |
| P2-12 | engines/casbin_engine.py | 321-329 | Bare except Exception: continue swallows all Casbin role enforcement errors; infrastructure failures masked as authorization denials | 17 |

### P3 Minor Findings (15)

| ID | File | Line(s) | Finding | Step |
|----|------|---------|---------|------|
| P3-01 | security/{intent_capsule,memory_integrity,agent_trust}.py | 65-78,57-70,70-83 | _validate_secret_key function body is identical across three files; changes must be applied in three places | 18 |
| P3-02 | audit/logger.py | 577 | InMemoryAuditLogger.clear() accesses private _batch_size attribute of BatchedHashChain | 19 |
| P3-03 | audit/hash_chain.py | 252-268 | get_proof is O(n) linear scan by event_id; hash index exists but event_id index does not | 19 |
| P3-04 | decorators.py | 203,242 | _request_counter is a plain int incremented without lock; concurrent calls generate duplicate request IDs | 4 |
| P3-05 | guards/input_guard.py | 350-361 | Full injection payload stored in GuardResult.matches without truncation; serialized to audit logs leaks payload | 20 |
| P3-06 | tools/decorators.py | 62 | Bare except Exception silently drops type-hint resolution errors; auto-generated tool schema silently loses type info | 17 |
| P3-07 | validation/schema.py | 468 | User-supplied regex recompiled on every validation call; malformed regex raises re.error uncaught as unhandled exception | 20 |
| P3-08 | security/intent_capsule.py | 65 | _PLACEHOLDER_PATTERNS includes "TODO" which false-positives on legitimate base64 keys containing those characters | 18 |
| P3-09 | audit/logger.py | 479-484 | No __del__ or weakref.finalize; file handle leaked if AuditLogger dropped without close() | 20 |
| P3-10 | tests/test_benchmarks.py | 54 | Hardcoded non-random test secret key "benchmark-secret-key-1234567890" | 21 |
| P3-11 | tests/test_guards.py | 918 | Real-format OpenAI key "sk-example123456789..." triggers automated secret scanners in CI | 21 |
| P3-12 | security/agent_trust.py | 70 | _PLACEHOLDER_PATTERNS tuple duplicated (same as P3-01) | 18 |
| P3-13 | security/memory_integrity.py | 57 | _PLACEHOLDER_PATTERNS tuple duplicated (same as P3-01) | 18 |
| P3-14 | engines/opa_engine.py | 172-181 | No HTTPS enforcement on OPA URL; policy decisions travel plaintext over HTTP | 17 |
| P3-15 | security/rate_limiter.py | 267-275 | time.monotonic() in SlidingWindowRateLimiter not serializable for multi-process deployments; undocumented constraint | 20 |

---

## User Intent and Expected Behavior

This section defines how each change should behave from the perspective of a developer integrating Proxilion.

### As a developer using cloud audit exporters
- **Service:** CloudBaseExporter, S3Exporter, AzureExporter, GCPExporter
- **Before:** Audit log integrity checksums use MD5. A determined attacker who can influence the upload payload can craft a collision, undermining tamper-evidence.
- **After:** All integrity checksums use SHA-256. The checksum method is consistent with the SHA-256 hash chains used internally. No API change; the switch is transparent.
- **Expected behavior:** Calling exporter.export() produces SHA-256 checksums in upload metadata. Existing S3 request signing (already SHA-256) is unaffected. No migration needed for stored logs since checksums are computed at upload time.

### As a developer using retry with backoff
- **Service:** RetryPolicy in resilience/retry.py
- **Before:** Jitter added to retry delays uses random.uniform, which is seeded from the system clock and predictable.
- **After:** Jitter uses os.urandom-backed randomness via random.SystemRandom().uniform(). No API change.
- **Expected behavior:** retry_policy.execute(fn) produces unpredictable jitter intervals. Retry timing cannot be predicted by an external observer.

### As a developer creating intent capsules
- **Service:** IntentCapsule, IntentCapsuleManager
- **Before:** IntentCapsule fields are mutable after creation. Code that mutates fields post-creation silently invalidates the HMAC signature without raising an error.
- **After:** IntentCapsule is a frozen dataclass. Attempting to set any field after creation raises FrozenInstanceError. Signature integrity is guaranteed for the lifetime of the object.
- **Expected behavior:** capsule = IntentCapsule.create(...) succeeds. capsule.intent = "new" raises FrozenInstanceError. capsule.verify() always returns the correct result for the data that was signed.

### As a developer using the approval workflow
- **Service:** QueueApprovalStrategy in decorators.py
- **Before:** Concurrent approve/deny/request_approval calls produce data races. Two simultaneous request_approval calls can generate the same request_id, causing one request to overwrite the other.
- **After:** All shared state mutations are protected by threading.RLock. Request IDs use uuid4 instead of a sequential counter. Concurrent usage is safe.
- **Expected behavior:** Under 50-thread concurrent load, zero duplicate request IDs are generated and zero requests are lost.

### As a developer using schema validation
- **Service:** SchemaValidator in validation/schema.py
- **Before:** SQL injection detection is off by default (allow_sql_keywords=True). Path traversal checks skip non-string parameters. Wildcard patterns with regex metacharacters are misinterpreted.
- **After:** SQL keywords are disallowed by default. Path traversal checks run on all string-like values regardless of declared type. Wildcard patterns are properly escaped before regex conversion. IDOR patterns use fullmatch.
- **Expected behavior:** A schema with no explicit allow_sql_keywords setting rejects "DROP TABLE users". A parameter typed as "any" containing "../etc/passwd" is caught. A wildcard pattern "read.file" matches only "read.file", not "readXfile".

### As a developer managing agent trust
- **Service:** AgentTrustManager in security/agent_trust.py
- **Before:** _revoked_tokens grows without bound. Nonce cleanup removes arbitrary entries. Agent secret derivation is deterministic on agent_id alone.
- **After:** _revoked_tokens stores (token_id, expiry_time) tuples with TTL-based eviction. Nonces use ordered eviction (oldest first). Agent secret derivation includes a random registration nonce.
- **Expected behavior:** After 10,000 token revocations with 1-hour TTL, memory usage stabilizes. cleanup_expired() removes both expired tokens and expired revocation records. Re-registering the same agent_id produces a different secret than before.

---

## Implementation Steps

Each step includes a Claude Code prompt that can be executed directly. Steps are ordered by dependency: earlier steps do not depend on later steps. Steps within the same pillar can be executed in parallel where noted.

---

### Step 1: Replace MD5 with SHA-256 in cloud audit exporters

**Pillar:** Cryptographic integrity
**Severity:** P1-01
**Files:** proxilion/audit/exporters/cloud_base.py
**Estimated test count:** 3 new tests

**Root cause:** cloud_base.py line 341 uses hashlib.md5(data).hexdigest() for upload integrity checksums. MD5 has known collision attacks (2017 SHAttered, 2020 chosen-prefix). For audit logs where tamper-evidence is the explicit security guarantee, this undermines the entire chain of trust.

**Fix:** Replace hashlib.md5 with hashlib.sha256 in the checksum method. Update any references to the checksum format in upload metadata headers. Add tests verifying SHA-256 output format.

**Claude Code prompt:**

```
Read proxilion/audit/exporters/cloud_base.py. Find the method that computes MD5 checksums (around line 341). Replace hashlib.md5 with hashlib.sha256. Search the same file and all files in proxilion/audit/exporters/ for any other references to md5 or MD5 and replace them with sha256/SHA-256. Add 3 tests to the appropriate test file verifying: (1) the checksum method returns a 64-character hex string (SHA-256 output length), (2) the checksum is deterministic for the same input, (3) different inputs produce different checksums. Run python3 -m pytest -x -q to verify all tests pass.
```

---

### Step 2: Replace random.uniform with CSPRNG in retry backoff

**Pillar:** Cryptographic integrity
**Severity:** P1-02
**Files:** proxilion/resilience/retry.py
**Estimated test count:** 2 new tests

**Root cause:** retry.py line 99 uses random.uniform for jitter. The random module uses a Mersenne Twister PRNG seeded from the system clock. An adversary observing 624 consecutive outputs can reconstruct the internal state and predict all future values, including retry timing.

**Fix:** Replace `import random` with a module-level `_secure_random = random.SystemRandom()` instance (which delegates to os.urandom). Replace `random.uniform(-jitter_range, jitter_range)` with `_secure_random.uniform(-jitter_range, jitter_range)`. Add tests verifying jitter is applied and that the retry module does not import the non-secure random for any other purpose.

**Claude Code prompt:**

```
Read proxilion/resilience/retry.py. Find the import of random (around line 14) and the usage of random.uniform (around line 99). Add a module-level _secure_random = random.SystemRandom() instance. Replace random.uniform with _secure_random.uniform. Search the entire file for any other uses of the random module and replace them similarly. Add 2 tests: (1) verify that retry with jitter produces non-zero delay variation across 10 retries, (2) verify that the jitter stays within the configured jitter_range bounds. Run python3 -m pytest -x -q to verify.
```

---

### Step 3: Make IntentCapsule a frozen dataclass

**Pillar:** Cryptographic integrity
**Severity:** P1-03
**Files:** proxilion/security/intent_capsule.py
**Estimated test count:** 3 new tests

**Root cause:** IntentCapsule at line 109 is decorated with @dataclass (not frozen). All fields including signature, capsule_id, user_id, intent, and created_at are mutable after creation. Code that mutates any field post-creation silently invalidates the HMAC signature. The verify() method will return False with no indication of why, because the data no longer matches the signature that was computed at creation time.

**Fix:** Change @dataclass to @dataclass(frozen=True). Identify any code paths that mutate IntentCapsule fields after creation and refactor them to create new instances instead. The create() classmethod constructs the object in one shot, so freezing should not affect the creation path. Add tests verifying that field mutation raises FrozenInstanceError and that verify() works correctly on frozen instances.

**Claude Code prompt:**

```
Read proxilion/security/intent_capsule.py. Find the IntentCapsule dataclass definition (around line 109). Change @dataclass to @dataclass(frozen=True). Search the entire file for any code that assigns to IntentCapsule fields after construction (e.g., capsule.field = value) and refactor to use dataclasses.replace() or construct a new instance. Add 3 tests: (1) verify that attempting to set a field on a created IntentCapsule raises FrozenInstanceError, (2) verify that create() still works and produces a valid capsule, (3) verify that verify() returns True on a freshly created frozen capsule. Run python3 -m pytest -x -q to verify. If any existing tests fail due to the frozen change, fix them by removing the mutation or using dataclasses.replace().
```

---

### Step 4: Add thread safety to QueueApprovalStrategy

**Pillar:** Thread safety closure
**Severity:** P1-04, P3-04
**Files:** proxilion/decorators.py
**Estimated test count:** 5 new tests

**Root cause:** QueueApprovalStrategy.__init__ (line 192) creates _pending, _approved, _denied, _request_counter, _events, and _async_events but has no threading.RLock. The approve() method (line 212), deny() (line 223), and request_approval() (line 234) all mutate shared state without synchronization. Additionally, _request_counter is a plain int incremented without atomicity; concurrent calls can generate duplicate request IDs.

**Fix:** Add self._lock = threading.RLock() to __init__. Wrap all mutations of _pending, _approved, _denied, and _request_counter in with self._lock: blocks. Replace the sequential counter with uuid.uuid4() for request ID generation to eliminate collision risk entirely. Add concurrent stress tests.

**Claude Code prompt:**

```
Read proxilion/decorators.py. Find QueueApprovalStrategy.__init__ (around line 192). Add self._lock = threading.RLock() and import threading at the top if not already imported. Wrap every method that reads or writes _pending, _approved, _denied, _request_counter, _events, or _async_events in with self._lock: blocks. This includes approve(), deny(), request_approval(), get_pending(), and any async variants. Replace _request_counter integer increment with str(uuid.uuid4()) for request ID generation (import uuid if needed). Remove the _request_counter field entirely. Add 5 tests in the appropriate test file: (1) 50-thread concurrent request_approval produces 50 unique request IDs, (2) concurrent approve and deny on different request IDs does not corrupt state, (3) concurrent approve and request_approval does not lose requests, (4) get_pending returns consistent snapshot under concurrent modification, (5) verify no duplicate request IDs across 1000 sequential calls. Run python3 -m pytest -x -q to verify.
```

---

### Step 5: Fix TOCTOU in IntentCapsuleManager capacity check

**Pillar:** Thread safety closure
**Severity:** P1-05
**Files:** proxilion/security/intent_capsule.py
**Estimated test count:** 2 new tests

**Root cause:** IntentCapsuleManager.create_capsule (around line 776) checks capacity outside the lock, then creates the capsule object, then acquires the lock to insert. Two threads that pass the capacity check simultaneously both insert, overshooting max_capsules.

**Fix:** Move the entire capacity-check-and-insert sequence into a single with self._lock: block. The capsule creation call itself is side-effect-free (it just constructs a dataclass), so it is safe to do inside the lock without performance concern.

**Claude Code prompt:**

```
Read proxilion/security/intent_capsule.py. Find IntentCapsuleManager.create_capsule (around line 765-790). Restructure the method so that the capacity check (len(self._capsules) >= self._max_capsules), the cleanup call, and the capsule insertion all happen inside a single with self._lock: block. The IntentCapsule.create() call can be inside or outside the lock -- if performance is a concern, create outside and re-check capacity inside, but the simplest correct fix is to put everything inside the lock. Add 2 tests: (1) verify that creating max_capsules + 1 capsules sequentially raises the expected error or blocks, (2) verify that 20 concurrent create_capsule calls with max_capsules=10 never result in more than 10 capsules stored. Run python3 -m pytest -x -q to verify.
```

---

### Step 6: Invert SQL injection detection default to opt-out

**Pillar:** Security default hardening
**Severity:** P1-06
**Files:** proxilion/validation/schema.py
**Estimated test count:** 4 new tests

**Root cause:** schema.py line 477 uses constraints.get("allow_sql_keywords", True), meaning SQL injection detection is disabled by default. Any schema that omits the constraint gets zero SQL protection. For a security SDK, the safe default is to reject SQL keywords unless explicitly allowed.

**Fix:** Change the default from True to False. Add a warning log when allow_sql_keywords=True is explicitly set on a parameter marked sensitive=True. Update any existing tests that rely on the old default. Add new tests for the inverted behavior.

**Claude Code prompt:**

```
Read proxilion/validation/schema.py. Find the SQL keyword check (around line 477). Change constraints.get("allow_sql_keywords", True) to constraints.get("allow_sql_keywords", False). Search for any other references to allow_sql_keywords in the codebase to understand the full impact. Add a logger.warning() call when allow_sql_keywords is explicitly True and the parameter has sensitive=True in its constraints. Add 4 tests: (1) verify that a schema with no allow_sql_keywords setting rejects "SELECT * FROM users", (2) verify that allow_sql_keywords=True explicitly set permits SQL keywords, (3) verify that allow_sql_keywords=False rejects SQL keywords (same as default now), (4) verify that DROP TABLE, INSERT INTO, DELETE FROM, and UNION SELECT are all caught by default. Run python3 -m pytest -x -q. Fix any existing tests that broke due to the default change -- they should be updated to explicitly set allow_sql_keywords=True if they need SQL keywords to pass.
```

---

### Step 7: Extend path traversal checks to non-string parameters

**Pillar:** Security default hardening
**Severity:** P1-07
**Files:** proxilion/validation/schema.py
**Estimated test count:** 4 new tests

**Root cause:** The path traversal check at line 472 is inside the if value_type == "str" block. Parameters with type="any", type="object", or type="array" bypass all traversal detection. An attacker who supplies a path as a list element or dict value evades the check entirely.

**Fix:** Extract path traversal checking into a separate recursive function that inspects all string values regardless of the declared schema type. Apply this function after the type-specific validation. The function should handle str, list (checking each element), and dict (checking each value) types.

**Claude Code prompt:**

```
Read proxilion/validation/schema.py. Find the path traversal check (around line 472) inside the str type block. Extract the path traversal detection logic into a standalone function _check_path_traversal(value: Any, param_name: str, allow_path_traversal: bool) that: (1) if value is a str, runs the existing traversal patterns, (2) if value is a list, recursively checks each element, (3) if value is a dict, recursively checks each value. Call this function for ALL parameter types, not just str, after the type-specific validation completes. Make sure the allow_path_traversal constraint is respected. Add 4 tests: (1) path traversal in a list element ["../etc/passwd"] is detected, (2) path traversal in a dict value {"path": "../etc/passwd"} is detected, (3) path traversal in a nested structure is detected, (4) allow_path_traversal=True permits traversal in all types. Run python3 -m pytest -x -q to verify.
```

---

### Step 8: Escape regex metacharacters in wildcard conversion and fix IDOR fullmatch

**Pillar:** Security default hardening
**Severity:** P1-08, P2-10
**Files:** proxilion/security/intent_capsule.py, proxilion/security/idor_protection.py
**Estimated test count:** 5 new tests

**Root cause (intent_capsule):** Line 147-150 converts wildcards to regex via pattern.replace("*", ".*"). Regex metacharacters like ., +, ?, [, (, ^, $ in the pattern are passed directly to the regex engine. A pattern "read.file" matches "readXfile" as well as "read.file".

**Root cause (idor):** Line 251 uses re.match(pattern, object_id) which only anchors at the start. An object_id of "doc_1_evil_suffix" matches pattern "doc_[0-9]+".

**Fix (intent_capsule):** Use re.escape on the full pattern first, then replace only the escaped asterisk: regex = re.escape(pattern).replace(r"\*", ".*").

**Fix (idor):** Replace re.match with re.fullmatch.

**Claude Code prompt:**

```
Read proxilion/security/intent_capsule.py. Find the wildcard-to-regex conversion (around line 147-150). Replace the pattern.replace("*", ".*") with: regex = re.escape(pattern).replace(r"\*", ".*"). Keep the re.match(f"^{regex}$", tool_name) call or simplify to re.fullmatch(regex, tool_name) since the pattern is now fully escaped.

Then read proxilion/security/idor_protection.py. Find re.match(pattern, object_id) around line 251. Replace with re.fullmatch(pattern, object_id).

Add 5 tests total: (1) wildcard "read.*" matches "read.anything" and "read.file", (2) wildcard "read.file" does NOT match "readXfile" (the dot is literal), (3) wildcard pattern with special chars "tool[1]" matches only "tool[1]" literally, (4) IDOR pattern "doc_[0-9]+" matches "doc_123" but NOT "doc_123_evil", (5) IDOR pattern "user_[a-z]+" matches "user_alice" but NOT "user_alice_admin". Run python3 -m pytest -x -q to verify.
```

---

### Step 9: Bound revoked tokens and fix nonce eviction in AgentTrustManager

**Pillar:** Memory safety
**Severity:** P2-01, P2-02
**Files:** proxilion/security/agent_trust.py
**Estimated test count:** 4 new tests

**Root cause (_revoked_tokens):** The _revoked_tokens set at line 439 is only appended to. cleanup_expired() at line 954 cleans _delegation_tokens and _agents but never touches _revoked_tokens. In a long-running service, every revoked token UUID is retained permanently.

**Root cause (_message_nonces):** The nonce cleanup at lines 886-890 removes arbitrary entries from a set with no time-ordering. Older valid nonces may be retained while newer ones are dropped, creating replay windows.

**Fix:** Replace _revoked_tokens: set[str] with _revoked_tokens: dict[str, float] mapping token_id to expiry_time. In cleanup_expired(), remove entries whose expiry has passed. Replace _message_nonces: set[str] with _message_nonces: OrderedDict[str, float] mapping nonce to received_at_timestamp, and evict entries older than max_age_seconds in FIFO order.

**Claude Code prompt:**

```
Read proxilion/security/agent_trust.py. Find _revoked_tokens initialization (around line 439). Change from set[str] to dict[str, float] where the value is the token's expiry timestamp. Update revoke_token() to store the expiry time alongside the token ID. Update cleanup_expired() to also iterate _revoked_tokens and remove entries whose expiry time has passed. Update is_revoked() to check _revoked_tokens as a dict (token_id in self._revoked_tokens).

Find _message_nonces (around line 440). Change from set[str] to an OrderedDict[str, float] (from collections import OrderedDict) where the value is time.monotonic() at insertion. Update the nonce check to add new nonces to the end. Update or create a cleanup method that iterates from the front of the OrderedDict and removes entries older than a configurable max_nonce_age_seconds (default 300 seconds). Call this cleanup in the same path as the existing cleanup logic.

Add 4 tests: (1) after revoking 100 tokens with 1-second TTL, sleeping 2 seconds, and calling cleanup_expired(), _revoked_tokens is empty, (2) _revoked_tokens does not grow beyond expected size after repeated revoke+cleanup cycles, (3) nonce eviction removes oldest nonces first (insert nonce_a, nonce_b, nonce_c; after eviction with tight TTL, nonce_a is gone but nonce_c remains), (4) replay detection still works for nonces within the TTL window. Run python3 -m pytest -x -q to verify.
```

---

### Step 10: Use canonical JSON for signature data serialization

**Pillar:** Memory safety (data integrity)
**Severity:** P2-03, P2-04
**Files:** proxilion/security/intent_capsule.py, proxilion/security/agent_trust.py
**Estimated test count:** 3 new tests

**Root cause (P2-03):** Signature data at lines 252 and 353 uses f"{sorted(allowed_tools)}" which produces Python list repr. The repr format is implementation-defined and ambiguous for tool names containing quotes or commas. A tool named "a', 'b" produces a signature over an ambiguous string.

**Root cause (P2-04):** Agent secret derivation at line 445-451 uses HMAC of agent_id against the master secret with no nonce. Re-registering the same agent_id produces the same derived secret, allowing revoked agents to reuse previously observed signatures.

**Fix (P2-03):** Replace all sorted(collection).__repr__ usage in signature data with json.dumps(sorted(collection), separators=(",", ":"), sort_keys=True) for canonical, portable, unambiguous serialization.

**Fix (P2-04):** Add a random registration nonce (os.urandom(16).hex()) to the agent secret derivation: hmac(master_key, f"agent:{agent_id}:{nonce}"). Store the nonce per-agent in AgentCredential.

**Claude Code prompt:**

```
Read proxilion/security/intent_capsule.py. Find all places where sorted(allowed_tools) or sorted(allowed_actions) is used in string formatting for signature data (around lines 252, 353). Replace f"{sorted(x)}" with json.dumps(sorted(x), separators=(",", ":")) (import json at top). This produces deterministic, portable, unambiguous output like ["a","b","c"] instead of Python's ['a', 'b', 'c'].

Then read proxilion/security/agent_trust.py. Find _derive_agent_secret (around line 445-451). Add a nonce parameter: generate os.urandom(16).hex() during agent registration and include it in the HMAC input: f"agent:{agent_id}:{nonce}". Store the nonce in AgentCredential (add a _registration_nonce field). Update any code that calls _derive_agent_secret to pass the nonce. Ensure the nonce is generated fresh on each register_agent call.

Add 3 tests: (1) IntentCapsule signature verification works with tool names containing quotes, commas, and brackets, (2) registering the same agent_id twice produces different secrets, (3) a token signed with a previous registration's secret fails verification after re-registration. Run python3 -m pytest -x -q to verify.
```

---

### Step 11: Fix cloud exporter batch failure recovery

**Pillar:** Memory safety
**Severity:** P2-05
**Files:** proxilion/audit/exporters/cloud_base.py
**Estimated test count:** 3 new tests

**Root cause:** After a failed export attempt (line 459-465), the failed batch is prepended to _pending_events outside the lock window. If another thread called add_event between extraction and restore, ordering is violated. On repeated failures the same batch is retried indefinitely with no discard, causing unbounded growth.

**Fix:** Add a max_retries counter per batch (default 3). Track retry count alongside each batch. After exceeding max_retries, log at ERROR level and either discard the batch or write to a configurable dead-letter callback. Ensure the restore operation happens inside the same lock acquisition as the retry count check.

**Claude Code prompt:**

```
Read proxilion/audit/exporters/cloud_base.py. Find the batch failure recovery logic (around line 455-465). Add a _retry_counts: dict mapping batch identifier to retry count. When a batch fails, increment its retry count under the lock. If retry count exceeds max_retries (configurable, default 3), log the batch at ERROR level with the event count and last error, then discard it (do not re-prepend). If retry count is within limit, re-prepend under the same lock acquisition as the extraction. Ensure the lock is held for the entire check-retry-restore sequence to prevent TOCTOU.

Add 3 tests: (1) a batch that fails 3 times is discarded after the third failure, (2) a batch that fails twice and succeeds on the third attempt is processed correctly, (3) concurrent add_event calls during batch failure recovery do not cause ordering violations. Run python3 -m pytest -x -q to verify.
```

---

### Step 12: Replace assert with explicit guards in production code

**Pillar:** Operational correctness
**Severity:** P2-06
**Files:** proxilion/observability/metrics.py (and any other files using assert for runtime checks)
**Estimated test count:** 2 new tests

**Root cause:** metrics.py line 711 uses assert self._webhook_url is not None as a runtime guard. Python's assert is disabled by the -O (optimize) flag, which is common in production Docker images and deployment configurations. When disabled, the null check is silently skipped, causing a TypeError with no diagnostic context.

**Fix:** Replace all assert statements used for runtime control flow with explicit if/raise guards. Search the entire proxilion/ directory for assert statements that are not in test files. Replace each with an appropriate explicit check and error.

**Claude Code prompt:**

```
Search proxilion/ (not tests/) for all assert statements using: grep -rn "assert " proxilion/ --include="*.py". For each assert found, determine if it is a runtime guard (should raise an exception) or a development-time invariant (acceptable as assert). Replace all runtime guards with explicit if/raise patterns. For example, replace "assert self._webhook_url is not None" with "if self._webhook_url is None: raise ConfigurationError('webhook_url must be set before sending alerts')". Use the most specific ProxilionError subclass for each case. Add 2 tests: (1) verify that the explicit guard raises the expected exception with a clear message, (2) verify that the code path works correctly when the guard condition is met. Run python3 -m pytest -x -q to verify.
```

---

### Step 13: Add constant-time comparison to Merkle proof verification

**Pillar:** Operational correctness
**Severity:** P2-07
**Files:** proxilion/audit/hash_chain.py
**Estimated test count:** 1 new test

**Root cause:** hash_chain.py line 465 uses == for Merkle proof verification (current == expected_root). The == operator short-circuits on the first differing character, leaking timing information about the hash prefix. While the primary concern for audit logs is tamper detection rather than MAC verification, using constant-time comparison is the correct practice and consistent with the rest of the codebase which uses hmac.compare_digest everywhere else.

**Fix:** Replace == with hmac.compare_digest(current, expected_root). Import hmac if not already imported.

**Claude Code prompt:**

```
Read proxilion/audit/hash_chain.py. Find the Merkle proof verification (around line 465) where current == expected_root is used. Replace with hmac.compare_digest(current, expected_root). Ensure hmac is imported at the top of the file. Search the rest of the file for any other hash comparisons using == and replace them similarly. Add 1 test: verify that MerkleTree.verify_proof returns True for a valid proof and False for a tampered proof. Run python3 -m pytest -x -q to verify.
```

---

### Step 14: Fix OutputGuard truncation off-by-one

**Pillar:** Operational correctness
**Severity:** P2-08
**Files:** proxilion/guards/output_guard.py
**Estimated test count:** 3 new tests

**Root cause:** _truncate_match at line 574-576 truncates strings of length 9-20 to text[:4] + "..." + text[-4:] which is 11 characters. For a 9-character input, the "truncated" form is longer than the original. The intent is to redact match content to prevent credential leakage in logs, but the current logic leaks more data than the original for short matches.

**Fix:** Simplify the logic: if len(text) <= max_length, return the text as-is (it is already short enough). Only truncate when the text exceeds max_length.

**Claude Code prompt:**

```
Read proxilion/guards/output_guard.py. Find _truncate_match (around line 574-576). Replace the method body with:
    if len(text) <= max_length:
        return text
    return text[:4] + "..." + text[-4:]

This ensures that short strings are never "truncated" to a longer form. Add 3 tests: (1) a 5-character match is returned as-is, (2) a 20-character match (equal to max_length) is returned as-is, (3) a 30-character match is truncated to "first...last" format with length < 30. Run python3 -m pytest -x -q to verify.
```

---

### Step 15: Eliminate side effects from ToolCache.__contains__

**Pillar:** Operational correctness
**Severity:** P2-09
**Files:** proxilion/caching/tool_cache.py
**Estimated test count:** 2 new tests

**Root cause:** __contains__ at line 582-585 delegates to get(), which increments the hit counter, moves the entry in LRU order, and calls entry.access(). A containment check (if (tool, args) in cache) should be a read-only probe, not a state mutation. Code that checks containment before calling get() counts the same access twice.

**Fix:** Implement __contains__ as a direct key lookup: generate the cache key, check key in self._cache under lock, and handle expiry by removing stale entries, but do NOT call get() or increment any counters.

**Claude Code prompt:**

```
Read proxilion/caching/tool_cache.py. Find __contains__ (around line 582-585). Rewrite it to: (1) generate the cache key from tool_name and args using the same key generation as get(), (2) acquire self._lock, (3) check if the key exists in self._cache, (4) if the entry exists but is expired, remove it and return False, (5) if the entry exists and is valid, return True without incrementing hits or moving LRU position, (6) if the key does not exist, return False. Do not call self.get(). Add 2 tests: (1) checking "in" on the cache does not increment the hit counter (check stats before and after), (2) checking "in" for an expired entry returns False and removes the entry. Run python3 -m pytest -x -q to verify.
```

---

### Step 16: Optimize LFU eviction from O(n) to O(log n)

**Pillar:** Operational correctness (performance)
**Severity:** P2-11
**Files:** proxilion/caching/tool_cache.py
**Estimated test count:** 3 new tests

**Root cause:** LFU eviction at line 455-465 scans the entire _cache OrderedDict to find the minimum-hits entry on every eviction. With max_size=1000 and high throughput, this is 1000 comparisons per insert while holding the lock, blocking all concurrent reads.

**Fix:** Maintain a secondary structure for O(log n) eviction. The simplest approach using only stdlib is a dict mapping hit_count to a set of keys, with a _min_hits tracker. On access, move the key from count N to count N+1. On eviction, pop any key from the _min_hits bucket. This is the standard O(1) LFU approach.

**Claude Code prompt:**

```
Read proxilion/caching/tool_cache.py. Find the LFU eviction logic (around line 455-465). Add two auxiliary data structures to the LFU cache class: (1) _freq_to_keys: defaultdict(OrderedDict) mapping frequency count to an ordered dict of keys, (2) _key_to_freq: dict mapping each cache key to its current frequency. Add a _min_freq tracker. On cache insert: set frequency to 1, add to _freq_to_keys[1], set _min_freq = 1. On cache access (hit): remove key from old frequency bucket, increment frequency, add to new bucket, update _min_freq if the old bucket is now empty. On eviction: pop the oldest key from _freq_to_keys[_min_freq]. Remove the old O(n) scan logic. All operations on _freq_to_keys must be under self._lock (which should already be held). Add 3 tests: (1) LFU eviction removes the least-frequently-used entry (insert A accessed 3 times, B accessed 1 time, C accessed 2 times; on eviction B is removed), (2) entries with equal frequency are evicted in FIFO order, (3) eviction under 50-thread concurrent load does not corrupt state. Run python3 -m pytest -x -q to verify.
```

---

### Step 17: Narrow remaining broad exception catches and add OPA HTTPS warning

**Pillar:** Operational correctness (error handling)
**Severity:** P2-12, P3-06, P3-14
**Files:** proxilion/engines/casbin_engine.py, proxilion/tools/decorators.py, proxilion/engines/opa_engine.py
**Estimated test count:** 3 new tests

**Root cause (casbin):** casbin_engine.py line 321-329 uses except Exception: continue, silently swallowing all Casbin role enforcement errors. Infrastructure failures are masked as authorization denials.

**Root cause (tools/decorators):** tools/decorators.py line 62 uses except Exception to swallow type-hint resolution errors. Tool schemas silently lose type information.

**Root cause (opa):** opa_engine.py lines 172-181 uses urllib.request.urlopen without HTTPS enforcement. Policy decisions can travel over plaintext HTTP.

**Fix:** Narrow each exception catch to the specific expected exceptions. Add logging at ERROR level. For OPA, add a startup warning when the URL scheme is http://.

**Claude Code prompt:**

```
Read proxilion/engines/casbin_engine.py. Find the except Exception: continue block (around line 321-329). Replace with except (AttributeError, TypeError, ValueError) as e: and add logger.error(f"Casbin enforcement error for role {role}: {e}") before continue.

Read proxilion/tools/decorators.py. Find the except Exception block (around line 62). Replace with except (NameError, AttributeError, TypeError) as e: and add logger.warning(f"Type hint resolution failed for {func.__qualname__}: {e}") before hints = {}.

Read proxilion/engines/opa_engine.py. Find the URL handling in __init__ or evaluate (around line 172-181). Add a check: if the opa_url starts with "http://" (not https), log logger.warning("OPA endpoint configured with HTTP (not HTTPS). Policy decisions will travel in plaintext. Use HTTPS in production.") during initialization.

Add 3 tests: (1) Casbin engine logs an error and denies when enforcement raises, rather than silently continuing, (2) tools/decorators logs a warning when type hints fail to resolve, (3) OPA engine initialization with http:// URL produces a warning log. Run python3 -m pytest -x -q to verify.
```

---

### Step 18: Extract shared secret key validation utility

**Pillar:** Code deduplication
**Severity:** P3-01, P3-08, P3-12, P3-13
**Files:** proxilion/security/intent_capsule.py, proxilion/security/memory_integrity.py, proxilion/security/agent_trust.py (new: proxilion/security/_key_utils.py)
**Estimated test count:** 4 new tests

**Root cause:** _validate_secret_key is copy-pasted identically across three files (intent_capsule.py:68-78, memory_integrity.py:60-70, agent_trust.py:73-83), including the _PLACEHOLDER_PATTERNS tuple. Any change to validation logic must be applied in three places. Additionally, "TODO" in the placeholder list causes false positives on legitimate base64 keys.

**Fix:** Create proxilion/security/_key_utils.py with the shared function and constant. Import from all three modules. Remove "TODO" from _PLACEHOLDER_PATTERNS (it is not a realistic placeholder for a secret key). Keep "test", "example", "changeme", "your-", and "secret" as the placeholder patterns.

**Claude Code prompt:**

```
Create a new file proxilion/security/_key_utils.py with:
- _PLACEHOLDER_PATTERNS tuple (same as current but remove "TODO")
- _validate_secret_key(secret_key: str, component_name: str) function (same logic as current)
- Import logger from logging

Then read proxilion/security/intent_capsule.py, proxilion/security/memory_integrity.py, and proxilion/security/agent_trust.py. In each file:
1. Remove the local _PLACEHOLDER_PATTERNS definition
2. Remove the local _validate_secret_key function
3. Add: from proxilion.security._key_utils import _validate_secret_key

Ensure all three modules import and call the function identically to before. Add 4 tests for _key_utils.py: (1) key shorter than 16 chars raises ConfigurationError, (2) key containing "changeme" logs a warning, (3) key containing "TODO" does NOT trigger a warning (regression test for the false positive fix), (4) a valid 32-char random key passes without warning. Run python3 -m pytest -x -q to verify.
```

---

### Step 19: Expose BatchedHashChain.batch_size and add event ID index

**Pillar:** Code deduplication (encapsulation)
**Severity:** P3-02, P3-03
**Files:** proxilion/audit/hash_chain.py, proxilion/audit/logger.py
**Estimated test count:** 3 new tests

**Root cause (P3-02):** InMemoryAuditLogger.clear() at line 577 accesses the private _batch_size attribute of BatchedHashChain. If the attribute is renamed, clear() fails at runtime with no static analysis warning.

**Root cause (P3-03):** HashChain.get_proof at line 252-268 scans the entire _events list to find an event by event_id. With _hashes already providing O(1) hash-to-index lookup, event_id should have a similar index.

**Fix:** Add a @property batch_size to BatchedHashChain that exposes _batch_size read-only. Update InMemoryAuditLogger.clear() to use the property. Add _event_id_index: dict[str, int] to HashChain, populate it in append(), and use it in get_proof() for O(1) lookup.

**Claude Code prompt:**

```
Read proxilion/audit/hash_chain.py. Find the BatchedHashChain class. Add a @property def batch_size(self) -> int: return self._batch_size. Then find the HashChain class. Add self._event_id_index: dict[str, int] = {} to __init__. In append(), after appending the event, add self._event_id_index[event.event_id] = len(self._events) - 1. In get_proof(), replace the linear scan with a direct lookup: idx = self._event_id_index.get(event_id). If None, return the not-found result. Otherwise use idx directly.

Read proxilion/audit/logger.py. Find InMemoryAuditLogger.clear() (around line 577). Replace self._chain._batch_size with self._chain.batch_size.

Add 3 tests: (1) BatchedHashChain.batch_size property returns the configured value, (2) HashChain.get_proof returns correct proof for event_id without scanning (verify performance by timing with 1000 events vs 10 events -- both should be similar), (3) InMemoryAuditLogger.clear() works correctly and creates a new chain with the same batch_size. Run python3 -m pytest -x -q to verify.
```

---

### Step 20: Harden input guard match truncation, schema regex caching, and audit logger cleanup

**Pillar:** Defense in depth
**Severity:** P3-05, P3-07, P3-09, P3-15
**Files:** proxilion/guards/input_guard.py, proxilion/validation/schema.py, proxilion/audit/logger.py, proxilion/security/rate_limiter.py
**Estimated test count:** 4 new tests

**Root cause (P3-05):** input_guard.py line 350-361 stores the full matched injection payload in GuardResult.matches without truncation. The output_guard applies _truncate_match but input_guard does not.

**Root cause (P3-07):** schema.py line 468 recompiles user-supplied regex on every validation call. Malformed regex raises re.error uncaught.

**Root cause (P3-09):** audit/logger.py has no __del__ or weakref.finalize. File handles leak if the logger is dropped without close().

**Root cause (P3-15):** rate_limiter.py line 267-275 uses time.monotonic() which is not serializable or multi-process safe. This is undocumented.

**Claude Code prompt:**

```
Read proxilion/guards/input_guard.py. Find where matched text is stored in GuardResult (around line 350-361). Add truncation: limit matched_text to 50 characters using text[:23] + "..." + text[-23:] if len(text) > 50 else text. This prevents large injection payloads from being stored in memory or serialized to audit logs.

Read proxilion/validation/schema.py. Find the re.fullmatch call (around line 468). Wrap it in a try/except re.error as e: raise SchemaValidationError(f"Invalid regex pattern for {param_name}: {e}") block. Consider caching compiled patterns by adding a _compiled_patterns: dict[str, re.Pattern] class-level cache.

Read proxilion/audit/logger.py. Add a __del__ method to AuditLogger that calls self.close() with a guard against double-close (check if self._file is not None and not closed). Add import warnings and emit warnings.warn("AuditLogger was not explicitly closed", ResourceWarning) in __del__ if the file was still open.

Read proxilion/security/rate_limiter.py. Find the SlidingWindowRateLimiter class docstring. Add a note: "Note: This rate limiter uses time.monotonic() internally, which is not serializable across process restarts or shareable between processes. For multi-process deployments, use an external rate limiter (e.g., Redis-backed)."

Add 4 tests: (1) input guard match text is truncated to max 50 characters, (2) schema validation with an invalid regex pattern raises SchemaValidationError with a clear message, (3) AuditLogger.__del__ emits ResourceWarning if not explicitly closed, (4) SlidingWindowRateLimiter docstring contains the multi-process caveat. Run python3 -m pytest -x -q to verify.
```

---

### Step 21: Harden test fixtures and replace hardcoded keys

**Pillar:** Test and CI hardening
**Severity:** P3-10, P3-11
**Files:** tests/test_benchmarks.py, tests/test_guards.py, tests/conftest.py
**Estimated test count:** 0 new tests (modifications to existing tests)

**Root cause (P3-10):** test_benchmarks.py line 54 uses a hardcoded string "benchmark-secret-key-1234567890" which is not randomly generated and does not exercise the same code paths as production keys.

**Root cause (P3-11):** test_guards.py line 918 uses "sk-example123456789012345678901234" which matches OpenAI key patterns and triggers automated secret scanners (trufflehog, GitHub Advanced Security) in CI.

**Fix:** Replace hardcoded test keys with secrets.token_hex(32) calls at module level or via conftest fixtures. Replace the OpenAI-format test key with a clearly synthetic value like "sk-" + "x" * 40 that is obviously not a real key but still matches the detection pattern.

**Claude Code prompt:**

```
Read tests/test_benchmarks.py. Find TEST_SECRET_KEY (around line 54). Replace the hardcoded string with secrets.token_hex(32) (import secrets at top). This generates a random 64-character hex key each test run.

Read tests/test_guards.py. Find the OpenAI key test value (around line 918). Replace "sk-example123456789012345678901234" with "sk-" + "x" * 40. Verify this still matches the output guard's openai_key pattern. Search the entire tests/ directory for any other hardcoded strings that look like API keys (sk-, AKIA, etc.) and replace them with clearly synthetic values.

Run python3 -m pytest -x -q to verify all tests still pass with the new key values.
```

---

### Step 22: Complete spec-v2 step 16 -- lint and type-check all test files

**Pillar:** Test and CI hardening
**Severity:** Required for spec-v2 completion
**Files:** All files in tests/
**Estimated test count:** 0 (quality improvement)

**Root cause:** Spec-v2 step 16 requires running ruff and mypy against all test files to ensure consistent code quality across the entire codebase, not just the source modules.

**Claude Code prompt:**

```
Run python3 -m ruff check tests/ and fix all violations. Run python3 -m ruff format tests/ to auto-format. Run python3 -m mypy tests/ --ignore-missing-imports and fix any type errors that are fixable without major refactoring (add type: ignore comments for third-party library issues that cannot be resolved). Run python3 -m pytest -x -q to verify no tests broke. Report the before and after violation counts.
```

---

### Step 23: Update CHANGELOG, bump version, and update documentation

**Pillar:** Documentation and observability
**Severity:** Required for release
**Files:** pyproject.toml, proxilion/__init__.py, CHANGELOG.md, CLAUDE.md, .codelicious/STATE.md
**Estimated test count:** 1 new test (version sync)

**Claude Code prompt:**

```
Update pyproject.toml version from "0.0.15" to "0.0.16". Update proxilion/__init__.py __version__ from "0.0.15" to "0.0.16". Note: these updates should be applied at the end after all prior specs have been completed and have bumped the version through 0.0.15.

Update CHANGELOG.md with a new entry for v0.0.16 that summarizes all changes in this spec: cryptographic integrity (MD5 to SHA-256, CSPRNG jitter, frozen IntentCapsule), thread safety (QueueApprovalStrategy locking, capsule manager TOCTOU), security defaults (SQL opt-out, path traversal expansion, regex escaping, IDOR fullmatch), memory safety (bounded revocation, deterministic nonce eviction, batch retry limits), operational correctness (assert removal, constant-time Merkle, truncation fix, cache containment), code deduplication (shared key validation, batch_size property, event ID index), and test hardening (synthetic keys, test linting).

Update CLAUDE.md with current metrics: test count, module count, source lines.

Update .codelicious/STATE.md to reflect spec-v10 completion status.

Add 1 test: verify that pyproject.toml version matches __init__.py __version__ by importing both and comparing. Run python3 -m pytest -x -q to verify.
```

---

### Step 24: Update README with Mermaid architecture diagrams

**Pillar:** Documentation and observability
**Severity:** Required for spec completion
**Files:** README.md
**Estimated test count:** 0

This step adds Mermaid diagrams to the end of README.md showing the current architecture. The diagrams should reflect the actual module structure and data flow, not aspirational design.

**Claude Code prompt:**

```
Read README.md. Append the following Mermaid diagrams at the end of the file, before any existing Mermaid content if present. If there are already Mermaid diagrams, replace them with these updated versions.

Add three diagrams:

1. **Authorization Flow** -- shows the sequence from tool call request through input guards, policy engine, rate limiter, circuit breaker, scope enforcement, approval workflow, output guards, and audit logging.

2. **Module Architecture** -- shows the package structure with proxilion/core.py at the center, connected to guards/, security/, engines/, policies/, audit/, observability/, providers/, contrib/, resilience/, streaming/, context/, caching/, validation/, timeouts/, and scheduling/.

3. **Security Decision Pipeline** -- shows the deterministic decision tree: input validation -> policy evaluation -> rate limiting -> circuit breaker check -> scope enforcement -> IDOR check -> intent capsule verification -> tool execution -> output guard -> audit log.

Use proper Mermaid syntax (```mermaid blocks). Keep diagrams readable and accurate to the current codebase.
```

---

### Step 25: Final validation and quality gate

**Pillar:** Release readiness
**Severity:** Required for release
**Files:** None (verification only)
**Estimated test count:** 0

**Claude Code prompt:**

```
Run the full CI check sequence and report results:
1. python3 -m ruff check proxilion tests
2. python3 -m ruff format --check proxilion tests
3. python3 -m mypy proxilion
4. python3 -m pytest -x -q

All four must pass with zero violations and zero failures. If any fail, fix the issues and re-run until clean. Report the final test count, skip count, and xfail count.

Then verify:
- pyproject.toml version matches __init__.py __version__
- CHANGELOG.md has an entry for the current version
- README.md contains Mermaid diagrams
- .codelicious/STATE.md reflects current progress
- No TODO or FIXME comments were introduced by this spec's changes

Write "DONE" to .codelicious/BUILD_COMPLETE if all checks pass.
```

---

## Verification Checklist

After all 25 steps are complete, the following invariants must hold:

| Check | Expected |
|-------|----------|
| python3 -m pytest -x -q | All pass (target: 2,580+ passed) |
| python3 -m ruff check proxilion tests | 0 violations |
| python3 -m ruff format --check proxilion tests | 0 files would be reformatted |
| python3 -m mypy proxilion | Success: no issues found in 90 source files |
| MD5 in production code | Zero references (only SHA-256) |
| random.uniform in production code | Zero references (only SystemRandom) |
| Mutable security dataclasses | Zero (IntentCapsule now frozen) |
| Unlocked shared mutable state | Zero (QueueApprovalStrategy now locked) |
| SQL injection default | opt-out (allow_sql_keywords=False) |
| Path traversal coverage | All parameter types (str, list, dict, any) |
| Wildcard regex injection | Impossible (re.escape applied) |
| IDOR suffix injection | Impossible (re.fullmatch used) |
| Unbounded revocation memory | Bounded (TTL-based eviction) |
| assert in production code | Zero runtime guards (all explicit if/raise) |
| Merkle comparison timing | Constant-time (hmac.compare_digest) |
| OutputGuard truncation correctness | Short strings returned as-is |
| ToolCache containment side effects | Zero (read-only probe) |
| LFU eviction complexity | O(1) amortized |
| Duplicated _validate_secret_key | Zero (shared _key_utils.py) |
| Hardcoded test keys | Zero (all generated or clearly synthetic) |
| Version sync | pyproject.toml == __init__.py |
| README Mermaid diagrams | Present and current |

---

## Step Dependency Graph

Steps can be parallelized where there are no file conflicts. The following groups are independent and can be executed concurrently:

**Group A (cryptographic integrity):** Steps 1, 2, 3
**Group B (thread safety):** Steps 4, 5
**Group C (security defaults):** Steps 6, 7, 8
**Group D (memory safety):** Steps 9, 10, 11
**Group E (operational correctness):** Steps 12, 13, 14, 15, 16
**Group F (deduplication):** Steps 18, 19
**Group G (defense in depth):** Steps 17, 20

Groups A through G can run in parallel. Steps 21-25 must run sequentially after all groups complete.

```
Groups A-G (parallel)
    |
    v
Step 21 (test fixture hardening)
    |
    v
Step 22 (lint all test files)
    |
    v
Step 23 (version bump, CHANGELOG, docs)
    |
    v
Step 24 (README Mermaid diagrams)
    |
    v
Step 25 (final validation gate)
```

---

## Estimated Impact

| Metric | Before | After |
|--------|--------|-------|
| P1 findings | 8 | 0 |
| P2 findings | 12 | 0 |
| P3 findings | 15 | 0 |
| Test count | ~2,517 | ~2,580+ |
| Source files | 89 | 90 (+_key_utils.py) |
| Cryptographic weaknesses | 2 (MD5, PRNG) | 0 |
| Unbounded memory vectors | 2 (revoked tokens, nonces) | 0 |
| Thread-unsafe components | 2 (QueueApproval, CapsuleMgr) | 0 |
| Insecure defaults | 2 (SQL allow, path str-only) | 0 |
