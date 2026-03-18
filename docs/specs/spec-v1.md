# Proxilion SDK -- Hardening Spec v1

**Version:** 0.0.6 -> 0.0.7
**Date:** 2026-03-14
**Status:** READY FOR IMPLEMENTATION
**Previous spec:** docs/specs/spec.md (0.0.4 -> 0.0.5, all steps complete)

---

## Executive Summary

This spec covers the second improvement cycle for the Proxilion SDK, a runtime security layer for LLM-powered applications. The codebase currently has 88 modules, 53,764 source lines of Python, 2,386 passing tests, and CI/CD with lint, typecheck, and test jobs. The previous spec (spec.md) addressed critical bugs, memory leaks, input validation, streaming robustness, resilience improvements, context window management, validation coverage, provider adapters, code quality, and edge case tests. All 10 steps of that spec are complete.

This spec identifies issues that remain after the first cycle: version drift, lint/format/type regressions, CI pipeline gaps, missing documentation, test coverage blind spots, secret key handling, thread safety gaps, and observability shortcomings. Every item is scoped to what exists in the codebase today. No net-new features are introduced.

---

## Codebase Snapshot (2026-03-14)

| Metric | Value |
|--------|-------|
| Python modules | 88 |
| Source lines | 53,764 |
| Test count | 2,386 (1 pre-existing skip) |
| Python versions | 3.10, 3.11, 3.12 |
| Lint errors (ruff) | 67 (21 fixable) |
| Type errors (mypy) | 10 unused type-ignore comments |
| Version in pyproject.toml | 0.0.6 |
| Version in __init__.py | 0.0.5 (MISMATCH) |
| CI/CD | GitHub Actions (test, lint, typecheck) |
| Docs pages | 5 (README, quickstart, concepts, security, authorization) |
| Feature docs | 2 files (README.md, authorization.md) |

---

## Logic Breakdown: Deterministic vs Probabilistic

Proxilion is explicitly designed to use deterministic logic for all security decisions. The breakdown below quantifies this across all 88 modules.

| Logic Type | Percentage | Modules | Description |
|------------|-----------|---------|-------------|
| Deterministic | ~97% | 85 of 88 | Regex pattern matching, set membership, hash chains, HMAC verification, token bucket counters, state machines, boolean policy evaluation, z-score statistics |
| Probabilistic | ~3% | 3 of 88 | Token estimation heuristic in context/message_history.py (1.3 words/token ratio), risk score aggregation in guards (weighted sum of pattern matches), behavioral drift z-score thresholds (statistical, not ML) |

Even the "probabilistic" components are bounded and auditable. There are zero LLM inference calls, zero ML model evaluations, and zero non-deterministic random decisions in the security path.

---

## Step 1 -- Fix Version Drift Between pyproject.toml and __init__.py

> **Priority:** CRITICAL
> **Estimated complexity:** Trivial
> **Files:** proxilion/__init__.py

### Problem

`pyproject.toml` declares `version = "0.0.6"` but `proxilion/__init__.py` declares `__version__ = "0.0.5"`. Any consumer calling `proxilion.__version__` gets a stale value. This breaks version-pinned integrations and confuses debugging.

### Intent

As a developer importing proxilion, when I check `proxilion.__version__`, I expect the value to match what `pip show proxilion` reports. Currently it does not.

### Fix

Update `__init__.py` line 38 from `"0.0.5"` to `"0.0.6"`.

### Claude Code Prompt

```
Read proxilion/__init__.py. Change `__version__ = "0.0.5"` to `__version__ = "0.0.6"` on line 38. Then run `python3 -c "import proxilion; print(proxilion.__version__)"` to verify it prints "0.0.6".
```

---

## Step 2 -- Fix All Ruff Lint and Format Violations

> **Priority:** HIGH
> **Estimated complexity:** Low
> **Files:** Multiple (13 unused imports, 8 unsorted imports, 14 line-too-long, 21 multiple-with-statements, 3 unused loop variables, 2 unnecessary collection calls, 2 lambda assignments, 2 ambiguous variable names, 2 unused variables)

### Problem

There are 67 ruff violations across the source code. 21 are auto-fixable. The CI lint job (`ruff check proxilion`) will fail on these. The codebase claims strict linting but does not pass its own lint checks.

### Intent

As a contributor opening a PR, when CI runs `ruff check proxilion` and `ruff format --check proxilion`, I expect zero errors. Currently there are 67.

### Fix

1. Run `ruff check --fix proxilion` to auto-fix the 21 fixable violations (unused imports, unsorted imports).
2. Manually fix the remaining 46 violations:
   - E501 (line-too-long): break lines or adjust logic to stay under 100 chars.
   - SIM117 (multiple-with-statements): combine nested `with` statements where readability is not harmed. For cases where combining reduces readability, add `SIM117` to the per-file ignore list in pyproject.toml only for those specific files.
   - B007 (unused-loop-control-variable): prefix with underscore.
   - C408 (unnecessary-collection-call): replace `dict()` with `{}`, `list()` with `[]`.
   - E731 (lambda-assignment): convert lambdas to named functions.
   - E741 (ambiguous-variable-name): rename `l`, `O`, or `I` variables to descriptive names.
   - F841 (unused-variable): remove or prefix with underscore.
3. Run `ruff format proxilion` to fix any formatting drift.
4. Run `ruff check proxilion && ruff format --check proxilion` to confirm zero violations.

### Claude Code Prompt

```
Run `python3 -m ruff check --fix proxilion` to auto-fix what it can. Then run `python3 -m ruff check proxilion --statistics` to see remaining issues. For each remaining violation, read the file and fix it manually following ruff rules. After all fixes, run `python3 -m ruff format proxilion` then `python3 -m ruff check proxilion && python3 -m ruff format --check proxilion` to confirm zero violations. Then run `python3 -m pytest -x -q` to confirm no tests broke.
```

---

## Step 3 -- Fix All Mypy Type Errors

> **Priority:** HIGH
> **Estimated complexity:** Low
> **Files:** proxilion/providers/gemini_adapter.py, proxilion/audit/exporters/azure_storage.py, proxilion/audit/exporters/aws_s3.py, proxilion/audit/exporters/gcp_storage.py, proxilion/contrib/google.py, proxilion/engines/casbin_engine.py, proxilion/engines/__init__.py

### Problem

There are 10 "unused type: ignore" comments flagged by mypy. These are leftover from previous refactors where the underlying type errors were fixed but the suppression comments were not removed. They mask future real type errors and add noise.

### Intent

As a developer running `mypy proxilion` with strict mode, I expect zero errors. Currently there are 10 stale type-ignore comments that should be removed.

### Fix

Remove each unused `# type: ignore` comment from the listed files. Then run `mypy proxilion` to confirm zero errors remain.

### Claude Code Prompt

```
Run `python3 -m mypy proxilion/ --ignore-missing-imports 2>&1 | grep "unused-ignore"` to get exact file and line numbers. For each result, read the file and remove the `# type: ignore` comment (or the `# type: ignore[...]` variant) from that line. Then run `python3 -m mypy proxilion/ --ignore-missing-imports` to confirm zero errors. Then run `python3 -m pytest -x -q` to confirm no tests broke.
```

---

## Step 4 -- Harden CI Pipeline

> **Priority:** HIGH
> **Estimated complexity:** Low
> **Files:** .github/workflows/ci.yml

### Problem

The CI pipeline has several gaps:
1. Lint job runs `ruff check proxilion` but does not check tests/ directory, so test files can have import errors and lint violations undetected.
2. No security scanning (e.g., `pip-audit` or `safety` for known vulnerabilities in dependencies).
3. No coverage threshold enforcement. Tests run with `--cov` but there is no `--cov-fail-under` to prevent coverage regression.
4. No test for Python 3.13 (released October 2025, stable for 5 months).
5. Typecheck job does not install optional dependencies (casbin, opa) so those modules' type checking is incomplete.

### Intent

As a maintainer merging a PR, when CI passes I expect confidence that: lint is clean across all Python files, no known dependency vulnerabilities exist, test coverage has not regressed, typing is verified for all code paths including optional dependencies, and the SDK works on the latest stable Python.

### Fix

Update `.github/workflows/ci.yml` to:
1. Add `tests/` to ruff check scope: `ruff check proxilion tests`.
2. Add `pip-audit` step after install: `pip install pip-audit && pip-audit`.
3. Add `--cov-fail-under=85` to the pytest command.
4. Add Python 3.13 to the test matrix.
5. Install `[dev,pydantic,all]` in the typecheck job.
6. Add ruff format check for tests: `ruff format --check proxilion tests`.

### Claude Code Prompt

```
Read .github/workflows/ci.yml. Make the following changes:
1. In the test job matrix, add "3.13" to python-version list.
2. In the test job, change the pytest command to: `pytest --cov=proxilion --cov-report=xml --cov-fail-under=85 -q`
3. In the lint job, change ruff check to: `ruff check proxilion tests`
4. In the lint job, change ruff format to: `ruff format --check proxilion tests`
5. In the lint job, add a new step after ruff format: `- name: Security audit` with `run: pip install pip-audit && pip-audit`
6. In the typecheck job, change the install to: `pip install -e ".[dev,all]"`
Verify the YAML is valid by running `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"` (install pyyaml first if needed).
```

---

## Step 5 -- Fix Secret Key Handling in Security Modules

> **Priority:** HIGH
> **Estimated complexity:** Medium
> **Files:** proxilion/security/intent_capsule.py, proxilion/security/memory_integrity.py, proxilion/security/agent_trust.py

### Problem

The `IntentCapsule`, `MemoryIntegrityGuard`, and `AgentTrustManager` all accept a `secret_key` parameter as a plain string. There are several issues:
1. No minimum length enforcement. A 1-character secret key is accepted, which provides no cryptographic security.
2. No warning when a key looks like a placeholder (e.g., "your-secret-key", "changeme", "test").
3. The README examples use `"your-secret-key"` as the secret key value, which a developer might copy verbatim.

### Intent

As a developer initializing `IntentCapsule.create(secret_key="x")`, I expect a clear error telling me the key is too short for HMAC security. As a developer who copies the README example secret key, I expect a warning at initialization time.

### Fix

1. In each module's constructor or factory method that accepts `secret_key`:
   - Validate minimum length of 16 characters. Raise `ConfigurationError` if shorter.
   - Log a warning (using the module's logger) if the key matches common placeholder patterns: contains "your-", "changeme", "test", "example", "placeholder", "secret-key", "TODO", or is all the same character.
2. Update README.md examples to use a realistic-looking key (e.g., `"prx_sk_a1b2c3d4e5f6g7h8"`) with a comment noting to use a real key in production.
3. Add tests for the validation (key too short raises ConfigurationError, placeholder key logs warning but does not raise).

### Claude Code Prompt

```
Read proxilion/security/intent_capsule.py, proxilion/security/memory_integrity.py, and proxilion/security/agent_trust.py. Find all places where secret_key is accepted as a parameter. Add validation:
1. If len(secret_key) < 16, raise ConfigurationError with message "secret_key must be at least 16 characters for HMAC security".
2. If secret_key matches common placeholder patterns (contains "your-", "changeme", "test", "example", "placeholder", "secret-key", "TODO", or all chars are the same), log a warning: "secret_key appears to be a placeholder. Use a cryptographically random key in production."
Import ConfigurationError from proxilion.exceptions. Then update tests that use short secret keys to use keys of 16+ characters. Run `python3 -m pytest -x -q` to confirm all tests pass. Finally, update README.md examples that use "your-secret-key" to use "prx_sk_a1b2c3d4e5f6g7h8" with a comment.
```

---

## Step 6 -- Add Missing Test Coverage for Untested Modules

> **Priority:** HIGH
> **Estimated complexity:** Medium
> **Files:** New test files in tests/

### Problem

While the codebase claims 100% module coverage, several modules have minimal or no dedicated tests:
1. `proxilion/caching/tool_cache.py` -- no `tests/test_caching.py` exists.
2. `proxilion/audit/hash_chain.py` -- tested indirectly through audit logger but no dedicated tests for MerkleTree, edge cases like empty chains, or concurrent appends.
3. `proxilion/audit/compliance/` -- `tests/test_compliance_exporters.py` exists but compliance-specific logic (SOC 2, ISO 27001, EU AI Act report generation) may have gaps.
4. `proxilion/engines/opa_engine.py` and `proxilion/engines/casbin_engine.py` -- tests may be skipped due to missing optional dependencies but should have mock-based tests.
5. `proxilion/policies/builtin.py` -- no dedicated test file for built-in policy classes.
6. `proxilion/guards/__init__.py` -- guards re-export verification.

### Intent

As a maintainer running `pytest --cov=proxilion --cov-report=term-missing`, I expect every public method in every module to have at least one test exercising its happy path and one test exercising its error path.

### Fix

Create the following test files with targeted tests:

1. `tests/test_caching.py` -- Test `ToolCache` with: cache hit, cache miss, TTL expiry, LRU eviction, LFU eviction, FIFO eviction, per-user cache isolation, cache invalidation, concurrent access, max_size enforcement, cache decorator.
2. `tests/test_hash_chain_detailed.py` -- Test `HashChain` with: empty chain verification, single event, chain of 10 events, tamper detection at various positions, concurrent appends. Test `MerkleTree` with: empty tree, single leaf, power-of-two leaves, non-power-of-two leaves, proof generation, proof verification, tamper detection.
3. `tests/test_builtin_policies.py` -- Test `RoleBasedPolicy`, `OwnershipPolicy`, `AllowAllPolicy`, `DenyAllPolicy` with various user contexts.
4. `tests/test_engines_mocked.py` -- Mock-based tests for `OPAEngine` and `CasbinEngine` to verify they call the right external APIs and handle errors.

### Claude Code Prompt

```
Create tests/test_caching.py. Read proxilion/caching/tool_cache.py to understand the public API. Write tests for: cache hit/miss, TTL expiry (use time.sleep or mock time), LRU/LFU/FIFO eviction, per-user isolation, cache invalidation, concurrent access with threading, max_size enforcement, and the cache decorator. Use pytest fixtures. Run `python3 -m pytest tests/test_caching.py -v` to verify.

Create tests/test_hash_chain_detailed.py. Read proxilion/audit/hash_chain.py to understand HashChain and MerkleTree APIs. Write tests for: empty chain verify, single event append+verify, 10-event chain verify, tamper detection (modify middle event and verify fails), concurrent appends with threading. For MerkleTree: empty tree, single leaf, even/odd leaf counts, proof generation and verification, tamper detection. Run `python3 -m pytest tests/test_hash_chain_detailed.py -v`.

Create tests/test_builtin_policies.py. Read proxilion/policies/builtin.py. Write tests for each built-in policy class with various user contexts (admin, user, guest). Run `python3 -m pytest tests/test_builtin_policies.py -v`.

Create tests/test_engines_mocked.py. Read proxilion/engines/opa_engine.py and proxilion/engines/casbin_engine.py. Write mock-based tests (use unittest.mock.patch) for both engines: successful evaluation, policy not found, engine errors. Run `python3 -m pytest tests/test_engines_mocked.py -v`.

Run the full suite: `python3 -m pytest -x -q` to confirm all tests pass including new ones.
```

---

## Step 7 -- Generate Sample Data and Integration Test Fixtures

> **Priority:** MEDIUM
> **Estimated complexity:** Medium
> **Files:** tests/fixtures/ (new directory), tests/conftest.py

### Problem

The test suite uses inline fixtures in conftest.py but has no reusable sample data for:
1. Realistic user populations (multiple users with various role combinations).
2. Realistic tool call sequences (normal workflow, attack patterns, edge cases).
3. Realistic audit event streams (for hash chain and compliance testing).
4. Realistic LLM provider responses (OpenAI, Anthropic, Gemini format payloads).

### Intent

As a developer writing new tests, when I need sample data for a user with 3 roles calling 5 tools in sequence, I can import a pre-built fixture rather than constructing everything inline. This reduces test boilerplate and ensures consistent test data across the suite.

### Fix

1. Create `tests/fixtures/__init__.py`.
2. Create `tests/fixtures/users.py` with factory functions for 8 user archetypes: admin, analyst, viewer, guest, service_account, multi_role_user, external_partner, suspended_user.
3. Create `tests/fixtures/tool_calls.py` with factory functions for: safe_search_request, sql_injection_attempt, path_traversal_attempt, normal_crud_sequence, attack_sequence (download then execute), high_frequency_burst (20 rapid calls).
4. Create `tests/fixtures/provider_responses.py` with factory functions returning realistic OpenAI, Anthropic, and Gemini response payloads (with tool calls).
5. Update `tests/conftest.py` to import and expose these fixtures.

### Claude Code Prompt

```
Create directory tests/fixtures/ and the file tests/fixtures/__init__.py. Then create tests/fixtures/users.py with factory functions that return UserContext objects for 8 user archetypes: make_admin_user(), make_analyst_user(), make_viewer_user(), make_guest_user(), make_service_account(), make_multi_role_user(), make_external_partner(), make_suspended_user(). Each should have realistic roles, session_ids, and attributes.

Create tests/fixtures/tool_calls.py with factory functions returning ToolCallRequest objects: make_safe_search(), make_sql_injection_attempt(), make_path_traversal_attempt(). Also create make_normal_crud_sequence() returning a list of 5 ToolCallRequests (create, read, update, read, delete), and make_attack_sequence() returning a list of 3 ToolCallRequests (download, download, execute).

Create tests/fixtures/provider_responses.py with functions returning dict payloads matching OpenAI ChatCompletion format, Anthropic Messages format, and Gemini GenerateContent format, each containing tool_use/function_call blocks.

Import all factories into tests/fixtures/__init__.py. Then update tests/conftest.py to add pytest fixtures wrapping the most common factory functions. Run `python3 -m pytest -x -q` to confirm nothing breaks.
```

---

## Step 8 -- Add Thread Safety Tests for Shared State

> **Priority:** MEDIUM
> **Estimated complexity:** Medium
> **Files:** tests/test_thread_safety.py (new)

### Problem

Several modules use `threading.RLock` or `threading.Lock` for thread safety but have no concurrent stress tests to verify correctness under contention:
1. `TokenBucketRateLimiter` -- shared token state across threads.
2. `CircuitBreaker` -- shared failure count and state transitions.
3. `HashChain` -- concurrent appends must maintain chain integrity.
4. `IDORProtector` -- concurrent scope registrations and validations.
5. `SequenceValidator` -- concurrent tool call recordings from different users.
6. `ToolCache` -- concurrent reads and writes with eviction.

### Intent

As an operator running Proxilion in a multi-threaded ASGI server, when 50 concurrent requests hit the rate limiter simultaneously, I expect zero race conditions, zero data corruption, and correct rate limiting behavior.

### Fix

Create `tests/test_thread_safety.py` with concurrent stress tests using `concurrent.futures.ThreadPoolExecutor`:
1. 50 threads hitting the same rate limiter key simultaneously.
2. 20 threads alternating success/failure on the same circuit breaker.
3. 10 threads appending events to the same hash chain, then verify chain integrity.
4. 20 threads doing concurrent scope registration and validation on IDORProtector.
5. 30 threads doing concurrent cache reads/writes with eviction pressure.

Each test should assert: no exceptions raised, final state is consistent, and (where applicable) thread-safe counters match expected totals.

### Claude Code Prompt

```
Create tests/test_thread_safety.py. Import ThreadPoolExecutor from concurrent.futures. Write these test classes:

TestRateLimiterThreadSafety: Create a TokenBucketRateLimiter(capacity=100, refill_rate=0). Submit 200 allow_request("user") calls across 50 threads. Assert exactly 100 return True and 100 return False (since refill_rate=0, no tokens are replenished).

TestCircuitBreakerThreadSafety: Create a CircuitBreaker(failure_threshold=10, reset_timeout=999). Submit 20 threads each recording a failure. Assert failure_count equals 20 and state transitions correctly.

TestHashChainThreadSafety: Create a HashChain. Submit 10 threads each appending 5 events. Assert chain length is 50 and chain.verify() returns valid=True.

TestIDORProtectorThreadSafety: Create an IDORProtector. Submit 20 threads each registering a unique user scope and then validating it. Assert all validations succeed.

TestCacheThreadSafety: Create a ToolCache with max_size=50. Submit 30 threads each writing 10 unique entries. Assert cache size never exceeds max_size and no exceptions are raised.

Run `python3 -m pytest tests/test_thread_safety.py -v`.
```

---

## Step 9 -- Fix Documentation Gaps and Staleness

> **Priority:** MEDIUM
> **Estimated complexity:** Medium
> **Files:** docs/quickstart.md, docs/concepts.md, docs/security.md, docs/features/README.md, docs/features/authorization.md, README.md

### Problem

1. `docs/features/` only has 2 files (README.md, authorization.md) but the SDK has 15+ distinct features. Missing docs for: input guards, output guards, rate limiting, circuit breaker, IDOR protection, sequence validation, audit logging, cost tracking, streaming, intent capsule, memory integrity, agent trust, behavioral drift, resilience (retry/fallback/degradation), caching.
2. README.md references `docs/features/README.md` but that file is thin.
3. `docs/quickstart.md` does not cover the decorator-based API (`@authorize_tool_call`, `@rate_limited`, etc.) which was added in 0.0.4.
4. No CLAUDE.md in the project root for Claude Code best practices.
5. No MEMORY.md or memory files for Claude Code persistent context.

### Intent

As a new developer reading the docs, when I want to use output guards, I expect a dedicated page at `docs/features/output-guards.md` with usage examples, configuration options, and pattern lists. Currently no such page exists.

### Fix

1. Create `docs/features/input-guards.md` documenting InputGuard API, all built-in patterns, configuration, and examples.
2. Create `docs/features/output-guards.md` documenting OutputGuard API, all leakage patterns, redaction, and examples.
3. Create `docs/features/rate-limiting.md` documenting all three rate limiter types with examples.
4. Create `docs/features/audit-logging.md` documenting AuditLogger, hash chains, compliance exporters.
5. Create `docs/features/security-controls.md` covering IDOR, sequence validation, circuit breaker, cascade protection.
6. Create `docs/features/observability.md` covering cost tracking, metrics, Prometheus export, session cost tracking.
7. Update `docs/features/README.md` to be an index linking to all feature docs.
8. Update `docs/quickstart.md` to include decorator-based examples.
9. Create project-root `CLAUDE.md` with project conventions, commands, and architecture summary.

### Claude Code Prompt

```
Create docs/features/input-guards.md. Read proxilion/guards/input_guard.py to extract all InjectionPattern entries, GuardAction options, and configuration parameters. Write documentation with: overview, installation, usage examples (basic check, custom patterns, BLOCK vs WARN vs SANITIZE modes), built-in pattern table, and configuration reference.

Create docs/features/output-guards.md similarly from proxilion/guards/output_guard.py. Include the redaction API, all LeakagePattern entries, and PII opt-in configuration.

Create docs/features/rate-limiting.md from proxilion/security/rate_limiter.py. Cover TokenBucket, SlidingWindow, and MultiDimensional with examples.

Create docs/features/audit-logging.md from proxilion/audit/. Cover AuditLogger, LoggerConfig, hash chain verification, compliance exporters (SOC2, ISO27001, EU AI Act), and cloud exporters (S3, Azure, GCP).

Create docs/features/security-controls.md covering IDOR protection, sequence validation, circuit breaker, and cascade protection with examples from each module.

Create docs/features/observability.md covering CostTracker, SessionCostTracker, MetricsCollector, AlertManager, and PrometheusExporter.

Update docs/features/README.md to be an index with links to all feature docs.

Update docs/quickstart.md to add a "Decorator-Based API" section showing @authorize_tool_call, @rate_limited, @circuit_protected, @require_approval examples.

Create CLAUDE.md in the project root with sections: Project Overview, Quick Commands (pytest, ruff, mypy), Architecture (module map), Conventions (naming, error handling, threading), and CI/CD.
```

---

## Step 10 -- Set Up Claude Code Memory and Project Context

> **Priority:** MEDIUM
> **Estimated complexity:** Low
> **Files:** CLAUDE.md (project root), ~/.claude/projects/-Users-user-Documents-proxilion-sdk/memory/

### Problem

There is no project-level CLAUDE.md and no memory files for persistent context across Claude Code sessions. This means every new conversation starts from scratch without understanding the project's conventions, architecture, or ongoing work.

### Intent

As a developer using Claude Code on this project, when I start a new session and ask "run the tests", Claude Code should already know to run `python3 -m pytest -x -q` and understand the project structure without re-exploration.

### Fix

1. Create `CLAUDE.md` in the project root with:
   - Project description (runtime security SDK for LLM apps).
   - Quick commands: `python3 -m pytest -x -q`, `python3 -m ruff check proxilion tests`, `python3 -m ruff format proxilion tests`, `python3 -m mypy proxilion`.
   - Architecture overview: module map showing core.py -> engines -> policies -> security -> guards -> audit -> observability -> providers -> contrib.
   - Conventions: deterministic security (no LLM calls in security path), thread safety (use RLock for shared state), error handling (raise specific ProxilionError subclasses, never bare except), testing (pytest, pytest-asyncio auto mode).
   - Version management: keep pyproject.toml version and __init__.py __version__ in sync.

2. Create memory files:
   - `project_overview.md` -- what Proxilion is and its architecture.
   - `project_conventions.md` -- coding conventions discovered during analysis.

### Claude Code Prompt

```
Create CLAUDE.md in /Users/user/Documents/proxilion-sdk/ with the following content:

# Proxilion SDK

Runtime security SDK for LLM-powered applications. Deterministic pattern matching and rule-based logic for all security decisions.

## Quick Commands
- Tests: `python3 -m pytest -x -q`
- Lint: `python3 -m ruff check proxilion tests`
- Format: `python3 -m ruff format proxilion tests`
- Type check: `python3 -m mypy proxilion`
- Full CI check: `python3 -m ruff check proxilion tests && python3 -m ruff format --check proxilion tests && python3 -m mypy proxilion && python3 -m pytest -x -q`

## Architecture
- proxilion/core.py: Main Proxilion class, authorization flow
- proxilion/engines/: Policy engine backends (simple, casbin, OPA)
- proxilion/policies/: Policy base class and built-in policies
- proxilion/security/: Rate limiting, circuit breaker, IDOR, intent capsule, memory integrity, agent trust, behavioral drift, cascade protection, sequence validation, scope enforcement
- proxilion/guards/: Input guards (prompt injection) and output guards (data leakage)
- proxilion/audit/: Tamper-evident logging, hash chains, compliance, cloud exporters
- proxilion/observability/: Cost tracking, metrics, Prometheus, hooks
- proxilion/providers/: LLM provider adapters (OpenAI, Anthropic, Gemini)
- proxilion/contrib/: Integration handlers (OpenAI, Anthropic, Google, LangChain, MCP)
- proxilion/resilience/: Retry, fallback, graceful degradation
- proxilion/streaming/: Streaming response transformer and tool call detection
- proxilion/context/: Context window and session management
- proxilion/caching/: Tool call result caching
- proxilion/validation/: Schema validation
- proxilion/timeouts/: Timeout and deadline management
- proxilion/scheduling/: Request scheduling and priority queues

## Conventions
- All security decisions are deterministic (no LLM inference)
- Thread safety via threading.RLock for shared mutable state
- Raise specific ProxilionError subclasses, never bare except
- pytest with pytest-asyncio (asyncio_mode = "auto")
- ruff for linting and formatting (line-length = 100)
- mypy strict mode
- Keep pyproject.toml version and __init__.py __version__ in sync

Then create the memory directory and files as described.
```

---

## Step 11 -- Harden Audit Log File Handling

> **Priority:** MEDIUM
> **Estimated complexity:** Low
> **Files:** proxilion/audit/logger.py

### Problem

The `AuditLogger` writes to a JSONL file but has potential issues:
1. If the parent directory does not exist, `LoggerConfig.default()` creates a `Path` but does not create parent directories. The first write will fail with `FileNotFoundError`.
2. File writes are not guaranteed atomic. A crash mid-write could produce a corrupted JSONL line, breaking chain verification for all subsequent reads.
3. No file locking for multi-process scenarios (e.g., gunicorn with multiple workers writing to the same audit file).

### Intent

As an operator running Proxilion in a multi-worker deployment, when two workers write audit events simultaneously, I expect no data corruption and no lost events.

### Fix

1. In `AuditLogger.__init__` or `LoggerConfig.default()`, add `log_path.parent.mkdir(parents=True, exist_ok=True)` to auto-create parent directories.
2. Use atomic write pattern: write to a temporary file in the same directory, then `os.rename()` to append. Alternatively, use `fcntl.flock()` (Unix) or `msvcrt.locking()` (Windows) for file-level locking before each append. Since the SDK targets Python 3.10+ and the primary deployment is Linux/macOS, use `fcntl.flock` with a fallback no-op on Windows.
3. Add a newline flush after each event write to ensure complete JSONL lines.

### Claude Code Prompt

```
Read proxilion/audit/logger.py. Find the AuditLogger class and its write methods. Make these changes:
1. In __init__ or the method that opens the log file, add `self._log_path.parent.mkdir(parents=True, exist_ok=True)`.
2. In the method that writes events to the file, wrap the write in a file lock. Import fcntl at the top. Use: `fcntl.flock(f.fileno(), fcntl.LOCK_EX)` before writing and `fcntl.flock(f.fileno(), fcntl.LOCK_UN)` after. Wrap in try/finally. Add a comment noting this is Unix-only; on Windows the lock is a no-op since fcntl is not available (use try/except ImportError).
3. Ensure each event write ends with a newline and is flushed: `f.write(json_line + "\n"); f.flush()`.
Run `python3 -m pytest tests/ -k audit -v` to verify audit tests still pass.
```

---

## Step 12 -- Add Lint and Test Coverage for Test Files

> **Priority:** MEDIUM
> **Estimated complexity:** Low
> **Files:** tests/*.py

### Problem

The ruff lint configuration only checks `proxilion/` but not `tests/`. Test files may have:
1. Unused imports that mask broken test dependencies.
2. Ambiguous variable names that reduce readability.
3. Line-too-long violations that make test code harder to review.

### Intent

As a reviewer reading test code, I expect the same code quality standards as production code. Lint violations in test files reduce confidence in test correctness.

### Fix

1. Run `ruff check tests/ --statistics` to identify violations.
2. Fix all violations in test files.
3. Run `ruff format tests/` to normalize formatting.
4. Update pyproject.toml to extend ruff scope if needed.

### Claude Code Prompt

```
Run `python3 -m ruff check tests/ --statistics` to see violations. Fix all fixable ones with `python3 -m ruff check --fix tests/`. Manually fix remaining ones by reading each file. Run `python3 -m ruff format tests/`. Then run `python3 -m ruff check tests/ && python3 -m ruff format --check tests/` to confirm zero violations. Run `python3 -m pytest -x -q` to confirm tests still pass.
```

---

## Step 13 -- Add Graceful Shutdown to Scheduler and Background Components

> **Priority:** LOW
> **Estimated complexity:** Low
> **Files:** proxilion/scheduling/scheduler.py, proxilion/observability/metrics.py

### Problem

1. The `Scheduler` has a `shutdown()` method but it does not wait for in-flight tasks to complete. If a task is mid-execution when shutdown is called, its result is silently dropped.
2. `MetricsCollector` with alert rules may have background threads for periodic metric aggregation that are not cleaned up on interpreter exit.

### Intent

As an operator shutting down a Proxilion-protected service, when I call `scheduler.shutdown()`, I expect in-flight tasks to complete (up to a configurable timeout) before the scheduler stops accepting new tasks.

### Fix

1. Add a `shutdown(timeout: float = 5.0)` parameter to `Scheduler.shutdown()`. Call `self._executor.shutdown(wait=True)` with the timeout to allow in-flight tasks to complete. Log a warning if tasks are still running after timeout.
2. Add `__del__` or `atexit` cleanup for MetricsCollector if it has background threads.

### Claude Code Prompt

```
Read proxilion/scheduling/scheduler.py. Find the shutdown() method. Add a `timeout` parameter (default 5.0). Change the implementation to call `self._executor.shutdown(wait=True)` if it uses a ThreadPoolExecutor. If tasks are still running after the executor returns (check via threading.enumerate or task tracking), log a warning. Read proxilion/observability/metrics.py and check if MetricsCollector has any background threads. If so, add cleanup in a close() method. Run `python3 -m pytest tests/test_scheduling.py tests/test_metrics.py -v` to verify.
```

---

## Step 14 -- Add Comprehensive Security Regression Tests

> **Priority:** LOW
> **Estimated complexity:** Medium
> **Files:** tests/test_security_regression.py (new)

### Problem

The codebase protects against OWASP ASI Top 10 threats but has no dedicated regression test suite that exercises each attack vector end-to-end through the main Proxilion class. Individual component tests exist but they do not verify the full authorization pipeline catches attacks.

### Intent

As a security auditor reviewing the SDK, when I look at the test suite, I expect a dedicated file that demonstrates each OWASP ASI attack vector being blocked by the appropriate Proxilion security control, exercised through the main `Proxilion` class.

### Fix

Create `tests/test_security_regression.py` with these test classes:
1. `TestASI01_GoalHijacking` -- Create IntentCapsule, attempt tool call outside allowed tools, verify blocked.
2. `TestASI02_ToolMisuse` -- Register policy, attempt unauthorized action, verify AuthorizationError.
3. `TestASI03_PrivilegeEscalation` -- Low-privilege user attempts admin action, verify denied.
4. `TestASI04_DataExfiltration` -- OutputGuard catches API key in response, verify blocked and redacted.
5. `TestASI05_IDOR` -- User attempts to access another user's resource, verify IDORViolationError.
6. `TestASI06_MemoryPoisoning` -- MemoryIntegrityGuard detects tampered message, verify ContextIntegrityError.
7. `TestASI07_InsecureAgentComms` -- AgentTrustManager rejects unsigned message, verify AgentTrustError.
8. `TestASI08_ResourceExhaustion` -- Rate limiter blocks after capacity exceeded, verify RateLimitExceeded.
9. `TestASI09_ShadowAI` -- AuditLogger captures all authorization decisions, verify event count matches.
10. `TestASI10_RogueAgent` -- BehavioralMonitor detects drift, KillSwitch halts, verify EmergencyHaltError.

### Claude Code Prompt

```
Create tests/test_security_regression.py. For each OWASP ASI Top 10 attack vector (ASI01 through ASI10), write a test class with 2-3 tests that exercise the attack through the relevant Proxilion security control. Use the actual module APIs (not mocks) to create realistic attack scenarios. Each test should:
1. Set up the security control with realistic configuration.
2. Attempt the attack.
3. Assert the correct exception is raised or the correct denial result is returned.
4. Verify the attack is logged (where audit logging is involved).

Use secret keys of 16+ characters in all tests. Run `python3 -m pytest tests/test_security_regression.py -v` to verify all tests pass.
```

---

## Step 15 -- Final Validation and Version Bump

> **Priority:** LOW
> **Estimated complexity:** Low
> **Files:** pyproject.toml, proxilion/__init__.py, CHANGELOG.md

### Problem

After all previous steps are complete, the version should be bumped to 0.0.7 and the CHANGELOG should document all changes.

### Intent

As a consumer upgrading from 0.0.6, when I read the CHANGELOG, I expect a complete list of what changed and why.

### Fix

1. Update `pyproject.toml` version to `"0.0.7"`.
2. Update `proxilion/__init__.py` `__version__` to `"0.0.7"`.
3. Add a `[0.0.7]` section to CHANGELOG.md documenting all changes from this spec.
4. Run the full validation suite: `ruff check proxilion tests && ruff format --check proxilion tests && mypy proxilion && pytest --cov=proxilion --cov-fail-under=85 -q`.

### Claude Code Prompt

```
Update pyproject.toml line 7: change version to "0.0.7". Update proxilion/__init__.py line 38: change __version__ to "0.0.7". Read CHANGELOG.md and add a new section at the top:

## [0.0.7] - 2026-03-14

### Fixed
- Version mismatch between pyproject.toml (0.0.6) and __init__.py (0.0.5)
- 67 ruff lint violations (unused imports, unsorted imports, line-too-long, etc.)
- 10 stale mypy type-ignore comments
- Secret key minimum length enforcement in IntentCapsule, MemoryIntegrityGuard, AgentTrustManager
- Audit log file handling (parent directory creation, file locking, atomic writes)
- Scheduler graceful shutdown with timeout parameter

### Added
- Python 3.13 to CI test matrix
- pip-audit security scanning in CI
- Coverage threshold enforcement (--cov-fail-under=85) in CI
- Test coverage for caching module, hash chain details, built-in policies, engine mocks
- Thread safety stress tests for rate limiter, circuit breaker, hash chain, IDOR, cache
- OWASP ASI Top 10 security regression test suite
- Sample data fixtures (users, tool calls, provider responses)
- Feature documentation for input guards, output guards, rate limiting, audit logging, security controls, observability
- Project CLAUDE.md with commands, architecture, and conventions
- Claude Code memory files for persistent context

### Changed
- CI pipeline: lint scope expanded to include tests/, typecheck installs all optional deps
- Updated README examples to use realistic secret keys
- Updated quickstart guide with decorator-based API examples

Run the full validation: `python3 -m ruff check proxilion tests && python3 -m ruff format --check proxilion tests && python3 -m mypy proxilion && python3 -m pytest --cov=proxilion --cov-fail-under=85 -q`
```

---

## Implementation Order and Dependencies

| Step | Priority | Complexity | Dependencies | Description |
|------|----------|-----------|--------------|-------------|
| 1 | CRITICAL | Trivial | None | Fix version drift |
| 2 | HIGH | Low | None | Fix ruff lint/format violations |
| 3 | HIGH | Low | None | Fix mypy type errors |
| 4 | HIGH | Low | Step 2 | Harden CI pipeline |
| 5 | HIGH | Medium | None | Secret key validation |
| 6 | HIGH | Medium | None | Missing test coverage |
| 7 | MEDIUM | Medium | Step 6 | Sample data fixtures |
| 8 | MEDIUM | Medium | None | Thread safety tests |
| 9 | MEDIUM | Medium | None | Documentation gaps |
| 10 | MEDIUM | Low | Step 9 | Claude Code memory setup |
| 11 | MEDIUM | Low | None | Audit log file handling |
| 12 | MEDIUM | Low | Step 2 | Test file lint |
| 13 | LOW | Low | None | Graceful shutdown |
| 14 | LOW | Medium | Steps 5, 6 | Security regression tests |
| 15 | LOW | Low | All above | Version bump and changelog |

Steps 1-3 can be done in parallel. Steps 4-6 can be done in parallel after 1-3. Steps 7-12 can be done in parallel. Steps 13-14 can be done in parallel. Step 15 must be last.

---

## Quick Install and Verification

```bash
# Clone and install
git clone https://github.com/clay-good/proxilion-sdk.git
cd proxilion-sdk
pip install -e ".[dev,pydantic]"

# Verify current state
python3 -m pytest -x -q                    # Expect 2386 tests, 1 skip
python3 -m ruff check proxilion            # Expect 67 errors (pre-spec)
python3 -m mypy proxilion                  # Expect 10 unused-ignore errors
python3 -c "import proxilion; print(proxilion.__version__)"  # Expect 0.0.5 (stale)

# After completing all spec steps
python3 -m pytest --cov=proxilion --cov-fail-under=85 -q  # Expect 2500+ tests, 0 failures
python3 -m ruff check proxilion tests      # Expect 0 errors
python3 -m ruff format --check proxilion tests  # Expect 0 reformats
python3 -m mypy proxilion                  # Expect 0 errors
python3 -c "import proxilion; print(proxilion.__version__)"  # Expect 0.0.7
```

---

## Out of Scope

The following are explicitly excluded from this spec:

- New security features not already in the codebase (e.g., WAF, IP blocklisting, OAuth integration).
- Breaking API changes to existing public interfaces.
- Publishing to PyPI or setting up hosted documentation.
- License changes (currently MIT, no change needed for private org MVP).
- Performance benchmarking or optimization beyond the thread safety fixes.
- Support for Python 3.9 or earlier.
- Kubernetes/container deployment configuration.
- Database-backed audit storage (the file-based and cloud exporter patterns already exist).
- Frontend/dashboard UI for observability.
