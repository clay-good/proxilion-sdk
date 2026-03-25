# Proxilion SDK -- Comprehensive Hardening Spec v7

**Version:** 0.0.12 -> 0.0.13
**Date:** 2026-03-18
**Status:** READY FOR IMPLEMENTATION
**Previous spec:** docs/specs/spec-v6.md (0.0.11 -> 0.0.12, depends on spec-v6 completion)
**Depends on:** spec-v6 must be fully complete before this spec begins (spec-v2 through spec-v6 form a sequential dependency chain)

---

## Executive Summary

This spec covers the eighth improvement cycle for the Proxilion SDK. It targets every remaining gap identified across all prior security reviews (8 P1, 14 P2, 19 P3 findings), incomplete spec-v2 steps (steps 12-18 still pending), documentation staleness, CI pipeline gaps, and developer experience friction discovered during a full codebase audit of 89 Python source files, 48,344 source lines, 2,633 collected tests, and all prior specs (spec.md through spec-v6.md).

The previous seven specs addressed: critical bugs (spec.md), CI hardening and documentation (spec-v1), structured error context and developer experience (spec-v2), thread-safety stabilization with bounded collections (spec-v3), security bypass vector closure with deployment guidance (spec-v4), production readiness with input validation and secret key management (spec-v5), and deep audit findings with rate limiter correctness, crypto robustness, and replay protection (spec-v6).

This cycle focuses on seven pillars:

1. **Finish incomplete spec-v2 work** -- completing sample data generation, public API docstrings, quickstart documentation, decorator combination tests, test file linting, version and changelog updates, and README mermaid diagrams that were never finished.
2. **Close all remaining P1 security findings** -- thread safety in core.py state setters, TOCTOU in the authorization flow ordering, audit log rotation race conditions, and input guard word-separator and homoglyph bypasses.
3. **Close all remaining P2 findings** -- empty string validation in contexts, unbounded SlidingWindow memory, cleanup-triggered denial of service, weak capability wildcard matching, output guard spacing bypasses, and JSON payload size limits.
4. **Close all remaining P3 findings** -- missing fsync after audit writes, error event raw chunk leakage, async event loop detection masking, thread-unsafe history deques, incomplete exception context fields, and sequence number overflow guards.
5. **CI pipeline completion** -- adding Python 3.13 to the test matrix, enforcing test file linting, adding pip-audit for dependency vulnerability scanning, and adding a formatting check for test files.
6. **Documentation and developer experience** -- generating a sample data script, adding comprehensive public API docstrings, updating quickstart to cover all decorators, and ensuring README mermaid diagrams reflect the current architecture.
7. **Test coverage hardening** -- decorator combination edge cases, concurrent stress tests for all security controls, evasion test suites for guards, and end-to-end authorization pipeline tests.

Every item targets code that already exists or documentation that is already started but incomplete. No net-new features are introduced. After this spec is complete, the SDK should pass a production security audit with zero known P1 or P2 findings, complete documentation, and a CI pipeline that enforces all quality gates across Python 3.10 through 3.13.

---

## Codebase Snapshot (2026-03-18)

| Metric | Value |
|--------|-------|
| Python source files | 89 |
| Source lines (proxilion/) | 48,344 |
| Test files | 62+ |
| Test count | 2,633 collected, 2,465 passed, 108 skipped, 29 xfailed |
| Python versions tested | 3.10, 3.11, 3.12 (CI), 3.13 (local only) |
| Ruff lint violations | 0 |
| Ruff format violations | 0 |
| Mypy errors | 0 (all 89 source files clean) |
| Version (pyproject.toml) | 0.0.7 |
| Version (__init__.py) | 0.0.7 |
| CI/CD | GitHub Actions (test, lint, typecheck) |
| Coverage threshold | 85% (enforced in CI) |
| Known P1 findings | 8 |
| Known P2 findings | 14 |
| Known P3 findings | 19 |
| Spec-v2 steps remaining | 7 of 18 (steps 12-18) |

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

```
spec.md (0.0.4-0.0.5) COMPLETE
    |
spec-v1.md (0.0.6-0.0.7) COMPLETE
    |
spec-v2.md (0.0.7-0.0.8) IN PROGRESS (11/18)
    |
spec-v3.md (0.0.8-0.0.9) BLOCKED on spec-v2
    |
spec-v4.md (0.0.9-0.0.10) BLOCKED on spec-v3
    |
spec-v5.md (0.0.10-0.0.11) BLOCKED on spec-v4
    |
spec-v6.md (0.0.11-0.0.12) BLOCKED on spec-v5
    |
spec-v7.md (0.0.12-0.0.13) BLOCKED on spec-v6 (this document)
```

---

## Quick Install and Verification

### Pre-Spec State Verification

Run these commands to confirm the codebase matches the expected starting state before beginning any step:

```bash
# Verify version
python3 -c "import proxilion; print(proxilion.__version__)"
# Expected: 0.0.12 (after spec-v6 completion)

# Verify all quality gates pass
python3 -m ruff check proxilion tests
python3 -m ruff format --check proxilion tests
python3 -m mypy proxilion
python3 -m pytest -x -q

# Verify zero ruff/mypy errors
# Verify all tests pass
```

### Post-Spec State Verification

```bash
# Verify version bumped
python3 -c "import proxilion; print(proxilion.__version__)"
# Expected: 0.0.13

# Full CI check
python3 -m ruff check proxilion tests
python3 -m ruff format --check proxilion tests
python3 -m mypy proxilion
python3 -m pytest -x -q --tb=short

# Verify no P1 or P2 findings remain
# Verify README mermaid diagrams render correctly
# Verify quickstart covers all 9 decorators
# Verify sample data generator runs without error
python3 -m proxilion.scripts.generate_sample_data --dry-run
```

---

## Intent Examples

These examples describe the expected behavior from a user's perspective for each area this spec touches. They serve as acceptance criteria.

### Authorization Flow

As a developer integrating Proxilion, when I configure a Proxilion instance with rate limiting enabled, the authorization flow should enforce rate limits BEFORE evaluating policies, so that a flood of requests from an attacker cannot exhaust policy engine resources even if the requests would ultimately be denied. The order should be: input guard -> rate limit -> IDOR check -> policy evaluation -> output guard.

### Thread Safety

As a developer running Proxilion in a multi-threaded web server (such as gunicorn with threads), when two threads simultaneously call proxilion.set_rate_limiter() and proxilion.authorize(), neither thread should observe a partially-initialized rate limiter or encounter an AttributeError. All state mutations on the Proxilion instance must be protected by the existing RLock.

### Input Guard Evasion

As a security engineer, when I test the input guard with evasion techniques including punctuation insertion ("i.g.n.o.r.e"), spacing manipulation ("i g n o r e"), Unicode homoglyphs (Cyrillic "a" for Latin "a"), leetspeak ("1gn0r3"), and mixed-case variants ("IGNORE previous INSTRUCTIONS"), every variant should be detected with a risk score above the configured threshold. No single-character substitution or insertion should cause the guard to miss a known injection pattern.

### Output Guard

As a developer, when my LLM generates a response containing credentials (AWS keys, API tokens, SSNs, credit card numbers), the output guard should detect and block the response regardless of spacing or formatting tricks applied to the sensitive data. Inserting spaces between digits of a credit card number ("4 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1") should not bypass detection.

### Audit Logging

As an operations engineer reviewing audit logs after an incident, every authorization decision should have a tamper-evident log entry with a valid SHA-256 hash chain. If a log file is rotated mid-write, no entries should be lost or corrupted. The logger should call fsync after each batch write to guarantee durability even on sudden power loss.

### Rate Limiting

As a platform operator, when I configure a SlidingWindowRateLimiter with a 60-second window and 100 requests per window, the internal timestamp storage should be bounded to prevent memory exhaustion from a sustained high-volume attack. Expired timestamps should be evicted eagerly, not lazily. The MultiDimensionalRateLimiter should check-and-consume atomically so that concurrent requests cannot both pass when only one slot remains.

### Developer Experience

As a new developer reading the quickstart guide, I should find working code examples for all 9 decorators (@authorize_tool_call, @rate_limited, @circuit_protected, @require_approval, @cost_limited, @enforce_scope, @validate_schema, @audit_logged, @guard_input). Each example should be copy-paste runnable with the sample data fixtures provided by the SDK.

### CI/CD

As a maintainer merging a pull request, the CI pipeline should automatically verify: tests pass on Python 3.10 through 3.13, ruff lint and format checks pass for both proxilion/ and tests/ directories, mypy strict mode passes, pip-audit finds no known vulnerabilities in dependencies, and test coverage meets the 85% threshold.

---

## Steps

---

### Step 1: Complete Sample Data Generator Script

**Priority:** MEDIUM
**Complexity:** MEDIUM
**Addresses:** Spec-v2 step 12 (incomplete), developer experience
**Files:** proxilion/scripts/__init__.py (new), proxilion/scripts/generate_sample_data.py (new)

**Problem:**
Spec-v2 step 12 called for a sample data generator script but it was never implemented. New developers have no quick way to generate realistic test fixtures for local development and integration testing.

**Intent:**
As a developer, I want to run `python3 -m proxilion.scripts.generate_sample_data` and get a directory of JSON files containing sample UserContext, AgentContext, ToolCallRequest, and AuditEvent objects that I can use for manual testing, demo scripts, and integration tests.

**Fix:**
Create a `proxilion/scripts/` package with a `generate_sample_data.py` module that:
- Generates 10 sample UserContext objects with varied roles, departments, and clearance levels
- Generates 5 sample AgentContext objects with varied capabilities and trust scores
- Generates 20 sample ToolCallRequest objects across different tools and risk levels
- Generates 10 sample AuditEventV2 objects with realistic authorization decisions
- Outputs to `sample_data/` directory as JSON files (users.json, agents.json, tool_calls.json, events.json)
- Supports `--dry-run` flag to print to stdout instead of writing files
- Supports `--output-dir` flag to customize output location
- Uses only stdlib and proxilion's own types (no additional dependencies)

**Claude Code prompt:**
```
Read proxilion/types.py and proxilion/audit/events.py to understand all fields on UserContext, AgentContext, ToolCallRequest, and AuditEventV2. Then create proxilion/scripts/__init__.py (empty) and proxilion/scripts/generate_sample_data.py that generates realistic sample data for each type. The script should be runnable as `python3 -m proxilion.scripts.generate_sample_data`. Include a --dry-run flag that prints JSON to stdout and a --output-dir flag (default: ./sample_data/). Generate 10 users with varied roles (admin, analyst, viewer, operator, auditor), 5 agents with varied trust scores (0.3 to 1.0) and capabilities, 20 tool call requests across tools like database_query, file_read, send_email, deploy_service, and delete_record, and 10 audit events with a mix of ALLOWED and DENIED decisions. Use deterministic data (no random), use argparse for CLI, and keep line length under 100 chars. After creating the files, run `python3 -m proxilion.scripts.generate_sample_data --dry-run` to verify it works, then run `python3 -m ruff check proxilion/scripts/ && python3 -m ruff format proxilion/scripts/ && python3 -m mypy proxilion/scripts/`.
```

---

### Step 2: Add Comprehensive Public API Docstrings

**Priority:** MEDIUM
**Complexity:** HIGH
**Addresses:** Spec-v2 step 13 (incomplete), P3 finding #4 (missing docstrings)
**Files:** proxilion/core.py, proxilion/decorators.py, proxilion/types.py, proxilion/exceptions.py, proxilion/guards/input_guard.py, proxilion/guards/output_guard.py

**Problem:**
Spec-v2 step 13 called for comprehensive docstrings on all public API methods. Many public methods in core.py (particularly the setter methods around lines 1849-1863), decorators.py, and guard classes lack docstrings or have minimal ones. This makes the SDK harder to adopt and harder to audit.

**Intent:**
As a developer using an IDE with autocompletion, when I hover over any public method in the Proxilion class, any decorator function, or any guard class, I should see a clear docstring explaining: what the method does, what parameters it accepts (with types), what it returns, what exceptions it may raise, and a short usage example where appropriate.

**Fix:**
Add Google-style docstrings to every public method that currently lacks one. Focus on:
- All public methods on the Proxilion class (core.py) -- especially set_rate_limiter, set_circuit_breaker_registry, set_idor_protector, authorize, authorize_async, check_input, check_output, and context manager methods
- All decorator functions in decorators.py -- authorize_tool_call, rate_limited, circuit_protected, require_approval, cost_limited, enforce_scope, validate_schema, audit_logged, guard_input
- All public methods on InputGuard and OutputGuard
- Do NOT add docstrings to private methods (single underscore prefix) or test files
- Do NOT change any logic or behavior -- docstrings only

**Claude Code prompt:**
```
Read proxilion/core.py, proxilion/decorators.py, proxilion/guards/input_guard.py, and proxilion/guards/output_guard.py. For every public method (no leading underscore) that lacks a docstring, add a Google-style docstring. Each docstring should include: a one-line summary, an Args section listing parameters with types and descriptions, a Returns section, a Raises section listing exceptions, and a short Example section where the method is non-trivial. Do NOT modify any code logic. Do NOT add docstrings to private methods. Keep line length under 100 chars. After adding docstrings, run: python3 -m ruff check proxilion/core.py proxilion/decorators.py proxilion/guards/ && python3 -m ruff format proxilion/core.py proxilion/decorators.py proxilion/guards/ && python3 -m mypy proxilion/core.py proxilion/decorators.py proxilion/guards/
```

---

### Step 3: Update Quickstart to Cover All 9 Decorators

**Priority:** MEDIUM
**Complexity:** MEDIUM
**Addresses:** Spec-v2 step 14 (incomplete)
**Files:** docs/quickstart.md

**Problem:**
The quickstart guide does not cover all 9 decorators. Developers discovering the SDK through documentation miss capabilities like @cost_limited, @enforce_scope, and @guard_input, leading to incomplete security coverage in their applications.

**Intent:**
As a new developer, when I read the quickstart guide from top to bottom, I should encounter a working code example for every decorator the SDK provides. Each example should be self-contained and runnable with the sample data from step 1.

**Fix:**
Update docs/quickstart.md to include a section for each decorator:
1. @authorize_tool_call -- basic authorization with policies
2. @rate_limited -- rate limiting a tool endpoint
3. @circuit_protected -- circuit breaker wrapping an external API call
4. @require_approval -- human-in-the-loop for destructive operations
5. @cost_limited -- budget enforcement per session
6. @enforce_scope -- restricting tool access by execution scope
7. @validate_schema -- validating tool call arguments against a JSON schema
8. @audit_logged -- adding tamper-evident logging to a tool
9. @guard_input -- prompt injection detection on tool inputs

Each section should include: a 2-3 sentence description of what the decorator does, a code example showing decoration and invocation, and a note on what exception is raised on violation.

**Claude Code prompt:**
```
Read docs/quickstart.md and proxilion/decorators.py to understand the current quickstart content and all available decorators. The decorators are: authorize_tool_call, rate_limited, circuit_protected, require_approval, cost_limited, enforce_scope, validate_schema, audit_logged, guard_input. Update docs/quickstart.md to include a dedicated subsection for each decorator. Each subsection needs: a 2-3 sentence explanation, a code example showing how to decorate a function and call it, and a note on what exception is raised on violation. Use the sample data patterns from tests/conftest.py for realistic examples. Keep the existing quickstart content and add the new sections after the current "Getting Started" content. After editing, verify with: python3 -m ruff format --check docs/ (if applicable) and manually review the markdown renders correctly.
```

---

### Step 4: Add Decorator Combination Tests

**Priority:** HIGH
**Complexity:** HIGH
**Addresses:** Spec-v2 step 15 (incomplete), test coverage gap
**Files:** tests/test_decorator_combinations.py (new)

**Problem:**
No tests verify that multiple decorators stack correctly on the same function. In production, users commonly apply @authorize_tool_call + @rate_limited + @audit_logged together. Decorator ordering bugs (such as rate limiting executing after authorization instead of before) would silently weaken security.

**Intent:**
As a developer stacking @rate_limited and @authorize_tool_call on the same function, I expect rate limiting to be checked first (outermost decorator), so that unauthenticated flood attacks are stopped before consuming policy engine resources. If I stack @guard_input and @authorize_tool_call, input validation should run before authorization.

**Fix:**
Create tests/test_decorator_combinations.py with test cases for:
- @rate_limited + @authorize_tool_call -- verify rate limit fires before auth
- @circuit_protected + @authorize_tool_call -- verify circuit open stops auth check
- @guard_input + @authorize_tool_call -- verify injection blocked before auth
- @audit_logged + @authorize_tool_call -- verify both allowed and denied calls are logged
- @cost_limited + @rate_limited + @authorize_tool_call -- triple stack
- @require_approval + @authorize_tool_call -- verify approval prompt before execution
- Async variants of each combination
- Verify decorator order matters: @rate_limited(@auth(fn)) vs @auth(@rate_limited(fn))

**Claude Code prompt:**
```
Read proxilion/decorators.py and tests/test_decorators.py to understand all decorators and existing test patterns. Create tests/test_decorator_combinations.py with pytest tests that verify decorator stacking behavior. Test these combinations: (1) @rate_limited + @authorize_tool_call -- exhaust rate limit, verify RateLimitExceeded raised without policy evaluation, (2) @circuit_protected + @authorize_tool_call -- open circuit, verify CircuitOpenError raised, (3) @guard_input + @authorize_tool_call -- pass injection payload, verify InputGuardViolation raised, (4) @audit_logged + @authorize_tool_call -- verify audit event created for both allowed and denied calls, (5) @cost_limited + @rate_limited + @authorize_tool_call -- triple stack, (6) @require_approval + @authorize_tool_call -- verify approval flow triggers. Include async test variants using pytest-asyncio. Use fixtures from tests/conftest.py. After creating the file, run: python3 -m pytest tests/test_decorator_combinations.py -x -q && python3 -m ruff check tests/test_decorator_combinations.py && python3 -m ruff format tests/test_decorator_combinations.py
```

---

### Step 5: Lint and Type-Check All Test Files

**Priority:** HIGH
**Complexity:** LOW
**Addresses:** Spec-v2 step 16 (incomplete), CI gap
**Files:** tests/**/*.py, .github/workflows/ci.yml

**Problem:**
The CI pipeline only runs ruff lint and format checks on `proxilion/` but not `tests/`. Test files may contain lint violations, formatting inconsistencies, or patterns that diverge from the source code style. The pyproject.toml ruff config already includes tests in the target, but CI does not enforce it.

**Intent:**
As a maintainer, when I review a pull request that modifies test files, CI should catch any lint or formatting violations in those test files, just as it does for source files.

**Fix:**
1. Run `python3 -m ruff check tests/` and fix any violations found
2. Run `python3 -m ruff format tests/` and verify formatting
3. Update .github/workflows/ci.yml to include tests/ in lint and format checks:
   - Change `ruff check proxilion` to `ruff check proxilion tests`
   - Change `ruff format --check proxilion` to `ruff format --check proxilion tests`

**Claude Code prompt:**
```
Run `python3 -m ruff check tests/` and fix any violations. Then run `python3 -m ruff format tests/` to format all test files. Then read .github/workflows/ci.yml and update the lint job to check both proxilion and tests directories: change `ruff check proxilion` to `ruff check proxilion tests` and change `ruff format --check proxilion` to `ruff format --check proxilion tests`. After changes, verify with: python3 -m ruff check proxilion tests && python3 -m ruff format --check proxilion tests && python3 -m pytest -x -q
```

---

### Step 6: Add Python 3.13 to CI Test Matrix

**Priority:** MEDIUM
**Complexity:** LOW
**Addresses:** CI gap, spec-v2 step 4 partial
**Files:** .github/workflows/ci.yml, pyproject.toml

**Problem:**
Python 3.13 was added as a classifier in pyproject.toml but the CI matrix only tests 3.10, 3.11, and 3.12. Users running Python 3.13 may encounter compatibility issues that CI does not catch.

**Intent:**
As a maintainer, when a pull request introduces code that works on Python 3.10 but breaks on 3.13 (such as using deprecated stdlib features removed in 3.13), CI should catch the failure before merge.

**Fix:**
1. Add Python 3.13 to the CI test matrix in .github/workflows/ci.yml
2. Verify the typecheck job uses Python 3.12 or later (mypy target remains python_version = "3.10" in pyproject.toml, which is correct)
3. Run tests locally with Python 3.13 if available to confirm no failures

**Claude Code prompt:**
```
Read .github/workflows/ci.yml. Add "3.13" to the Python version matrix in the test job. Keep the lint and typecheck jobs on their current Python version (3.12). After editing, verify the YAML is valid by reviewing the structure. Then run: python3 -m pytest -x -q to confirm tests pass on the current Python version.
```

---

### Step 7: Add pip-audit to CI Pipeline

**Priority:** HIGH
**Complexity:** LOW
**Addresses:** CI gap, supply chain security
**Files:** .github/workflows/ci.yml

**Problem:**
The CI pipeline does not scan dependencies for known vulnerabilities. A compromised or vulnerable dependency could be introduced without any automated check catching it.

**Intent:**
As a maintainer, when a pull request updates dependencies in pyproject.toml, CI should automatically scan all direct and transitive dependencies against known vulnerability databases (PyPI advisory DB, OSV) and fail the build if any known vulnerabilities are found.

**Fix:**
Add a new `security` job to .github/workflows/ci.yml that:
1. Installs pip-audit
2. Installs the project dependencies
3. Runs `pip-audit --strict` to fail on any known vulnerability
4. Runs on ubuntu-latest with Python 3.12

**Claude Code prompt:**
```
Read .github/workflows/ci.yml. Add a new job called "security" that runs on ubuntu-latest with Python 3.12. The job should: (1) checkout the code, (2) set up Python, (3) install pip-audit via `pip install pip-audit`, (4) install the project via `pip install -e ".[dev]"`, (5) run `pip-audit --strict`. Place this job after the existing jobs. After editing, verify the YAML structure is valid. Do not run pip-audit locally unless pip-audit is already installed.
```

---

### Step 8: Protect Core.py State Setters with RLock

**Priority:** CRITICAL
**Complexity:** MEDIUM
**Addresses:** P1 finding #1 (thread safety -- unprotected state)
**Files:** proxilion/core.py

**Problem:**
The Proxilion class initializes an RLock (self._lock) but several state-modifying methods do not acquire it before mutating instance attributes. Specifically, setter methods like set_rate_limiter(), set_circuit_breaker_registry(), set_idor_protector(), and similar methods at lines 255-330 mutate self._rate_limiter, self._circuit_breaker_registry, and self._idor_protector without holding the lock. In a multi-threaded environment, a thread calling authorize() could read a partially-assigned reference while another thread is calling set_rate_limiter(), leading to AttributeError or inconsistent security state.

**Intent:**
As a developer running Proxilion in a threaded WSGI server, when I call set_rate_limiter() from a configuration reload thread while request threads are calling authorize(), the rate limiter should switch atomically -- no request should ever observe a half-initialized state.

**Fix:**
Wrap every state-mutating method on the Proxilion class with `with self._lock:`. Specifically:
- set_rate_limiter()
- set_circuit_breaker_registry()
- set_idor_protector()
- set_scope_enforcer()
- set_sequence_validator()
- set_cost_limiter()
- register_policy()
- set_input_guard()
- set_output_guard()
- Any other public method that assigns to self._ attributes

Do NOT add locking to read-only methods or methods that already hold the lock. Do NOT change the lock type (keep RLock for reentrancy safety).

**Claude Code prompt:**
```
Read proxilion/core.py fully. Find every public method (no leading underscore) that assigns to any self._ attribute without first acquiring self._lock. For each such method, wrap the body in `with self._lock:`. Do NOT add locking to methods that already use self._lock. Do NOT add locking to read-only property getters. Keep the RLock (do not switch to Lock). After editing, run: python3 -m pytest tests/test_core.py -x -q && python3 -m mypy proxilion/core.py && python3 -m ruff check proxilion/core.py
```

---

### Step 9: Reorder Authorization Flow -- Rate Limit Before Policy

**Priority:** CRITICAL
**Complexity:** HIGH
**Addresses:** P1 finding #2 (TOCTOU in auth flow)
**Files:** proxilion/core.py

**Problem:**
The authorization flow in core.py currently evaluates policies before checking rate limits (around lines 1644-1661). This means an attacker can flood the system with requests that all reach the policy engine before being rate limited. Policy evaluation may involve database lookups, external calls, or complex logic. The rate limiter should be the first check after input guards to cheaply reject floods.

**Intent:**
As a platform operator under a denial-of-service attack, when an attacker sends 10,000 requests per second, the rate limiter should reject the vast majority at near-zero cost before any policy evaluation, IDOR check, or schema validation occurs. The correct order is: input guard -> rate limit -> IDOR -> schema validation -> policy -> output guard.

**Fix:**
In the authorize() and authorize_async() methods of the Proxilion class, move the rate limiting check to occur immediately after input guard checks and before IDOR, schema validation, and policy evaluation. Preserve the existing behavior of each individual check -- only change the ordering. Update any comments that describe the authorization flow order.

**Claude Code prompt:**
```
Read proxilion/core.py fully, focusing on the authorize() and authorize_async() methods. Identify the current order of checks: input guard, policy evaluation, IDOR, rate limiting, schema validation, output guard. Reorder to: input guard -> rate limiting -> IDOR -> schema validation -> policy evaluation -> output guard. Move the rate limiting code block to immediately after the input guard block. Do NOT change the logic of any individual check -- only the order. Update any inline comments that describe the flow order. After editing, run: python3 -m pytest tests/test_core.py -x -q && python3 -m pytest tests/test_edge_cases_spec.py -x -q && python3 -m mypy proxilion/core.py
```

---

### Step 10: Fix Audit Log Rotation TOCTOU Race

**Priority:** CRITICAL
**Complexity:** MEDIUM
**Addresses:** P1 finding #8 (audit log TOCTOU), P1 from 2026-03-18 review (rotation TOCTOU)
**Files:** proxilion/audit/logger.py

**Problem:**
The AuditLogger determines the log file path and then writes to it in separate, unlocked operations (lines 386-396). Between determining the path and writing, another thread could trigger log rotation, causing the write to go to a stale file or be lost entirely. Additionally, fsync is not called after writes, meaning audit entries could be lost on power failure.

**Intent:**
As a compliance auditor, when I verify the audit log integrity after a system crash, every authorization decision that completed before the crash should be present in the log files. No entries should be silently lost due to rotation races or missing fsync calls.

**Fix:**
1. In the write methods of AuditLogger, hold the lock across both path determination and file write
2. Add os.fsync(f.fileno()) after each write batch before releasing the lock
3. Ensure log rotation checks and file switches happen within the same lock acquisition
4. Add a test that spawns 10 threads writing audit entries while another thread triggers rotation, then verifies all entries are present across the rotated files

**Claude Code prompt:**
```
Read proxilion/audit/logger.py fully. Find the methods that write audit entries to files. Ensure that: (1) the lock is held across both the file path determination and the actual write, (2) os.fsync(f.fileno()) is called after writing and before releasing the lock, (3) log rotation (if applicable) happens within the same lock scope. Then create a test in tests/test_audit_rotation_race.py that spawns 10 writer threads (each writing 100 entries) and 1 rotation-trigger thread, then verifies all 1000 entries appear in the combined log files. After editing, run: python3 -m pytest tests/test_audit_rotation_race.py -x -q && python3 -m ruff check proxilion/audit/logger.py tests/test_audit_rotation_race.py && python3 -m mypy proxilion/audit/logger.py
```

---

### Step 11: Harden Input Guard Against Homoglyph and Leetspeak Bypass

**Priority:** CRITICAL
**Complexity:** HIGH
**Addresses:** P1 finding #6 (punctuation bypass), P1 finding #7 (leetspeak/char substitution), P1 from 2026-03-18 review (homoglyph bypass)
**Files:** proxilion/guards/input_guard.py

**Problem:**
The input guard uses regex pattern matching against known injection phrases, but an attacker can bypass detection by:
1. Inserting punctuation between characters: "i.g.n.o.r.e" bypasses "ignore" detection
2. Using leetspeak substitutions: "1gn0r3" for "ignore", "pr3v10us" for "previous"
3. Using Unicode homoglyphs: Cyrillic "a" (U+0430) for Latin "a" (U+0061)
4. Inserting zero-width characters between letters
5. Using fullwidth characters: "ignore" (U+FF49 etc.)

Current patterns only match exact character sequences after case folding. No character normalization is applied before matching.

**Intent:**
As a security engineer running a fuzzing suite against the input guard, every variant in a standard prompt injection evasion wordlist (punctuation insertion, leetspeak, homoglyphs, zero-width chars, fullwidth chars) should be detected. The guard should normalize input before matching rather than trying to enumerate all evasion variants in the pattern list.

**Fix:**
Add a normalize_text() function to input_guard.py that:
1. Applies Unicode NFKC normalization (collapses fullwidth, compatibility chars)
2. Strips zero-width characters (U+200B, U+200C, U+200D, U+FEFF, U+00AD)
3. Replaces common homoglyphs with ASCII equivalents (Cyrillic a/e/o/p/c/x -> Latin)
4. Replaces common leetspeak substitutions (0->o, 1->l/i, 3->e, 4->a, 5->s, 7->t, @->a, $->s)
5. Strips non-alphanumeric characters between word characters (collapses "i.g.n.o.r.e" to "ignore")
6. Collapses multiple spaces to single space

Call normalize_text() on the input before pattern matching. Keep the original input for the response (do not return the normalized form to the caller). The normalization must be deterministic and constant-time relative to input length.

**Claude Code prompt:**
```
Read proxilion/guards/input_guard.py fully. Add a normalize_text(text: str) -> str function that: (1) applies unicodedata.normalize("NFKC", text), (2) strips zero-width characters (U+200B, U+200C, U+200D, U+FEFF, U+00AD), (3) maps common Cyrillic homoglyphs to ASCII (create a dict mapping), (4) maps leetspeak digits to letters (0->o, 1->l, 3->e, 4->a, 5->s, 7->t, @->a, $->s), (5) strips non-alphanumeric chars between word chars using re.sub(r'(?<=\w)[^\w\s]+(?=\w)', '', text), (6) collapses multiple spaces to single space. Call normalize_text() on the input text at the start of the check() method, before any pattern matching. Keep the original text in the GuardResult. Then add tests in tests/test_guard_evasion.py covering: punctuation bypass, leetspeak bypass, homoglyph bypass, zero-width char bypass, fullwidth char bypass, and mixed evasion techniques. After editing, run: python3 -m pytest tests/test_guard_evasion.py tests/test_guards.py -x -q && python3 -m ruff check proxilion/guards/input_guard.py tests/test_guard_evasion.py && python3 -m mypy proxilion/guards/input_guard.py
```

---

### Step 12: Fix Output Guard Spacing Bypass

**Priority:** HIGH
**Complexity:** MEDIUM
**Addresses:** P2 finding #11 (output guard spacing bypass)
**Files:** proxilion/guards/output_guard.py

**Problem:**
The output guard detects sensitive data patterns (credit card numbers, SSNs, API keys) using regex, but inserting spaces between characters bypasses detection. "4111 1111 1111 1111" might be caught but "4 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1" is not. Similarly, AWS keys with dashes inserted ("AKIA-IOSFODNN7-EXAMPLE") bypass the pattern.

**Intent:**
As a security engineer, when I test the output guard with spacing and punctuation variants of sensitive data (credit card numbers with spaces between every digit, API keys with dashes inserted), every variant should be detected.

**Fix:**
Apply the same normalize_text() approach from step 11 to the output guard. Before matching sensitive data patterns, normalize the text by stripping non-alphanumeric characters between alphanumeric characters. Reuse or import the normalization function from input_guard.py (or extract to a shared guards/normalize.py module to avoid circular imports).

**Claude Code prompt:**
```
Read proxilion/guards/output_guard.py and proxilion/guards/input_guard.py. If step 11 added a normalize_text() function to input_guard.py, extract it to a new proxilion/guards/normalize.py module and import it from both guards. If not, create the normalize function in proxilion/guards/normalize.py. In output_guard.py, apply normalization to text before sensitive data pattern matching. Add tests in tests/test_output_guard_evasion.py covering: credit card numbers with spaces between every digit, SSNs with dots instead of dashes, AWS keys with inserted dashes, API tokens with zero-width characters inserted. After editing, run: python3 -m pytest tests/test_output_guard_evasion.py tests/test_guards.py -x -q && python3 -m ruff check proxilion/guards/ tests/test_output_guard_evasion.py && python3 -m mypy proxilion/guards/
```

---

### Step 13: Bound SlidingWindowRateLimiter Memory

**Priority:** HIGH
**Complexity:** MEDIUM
**Addresses:** P2 finding from 2026-03-18 review (unbounded SlidingWindow memory)
**Files:** proxilion/security/rate_limiter.py

**Problem:**
The SlidingWindowRateLimiter stores timestamps of all requests within the window. Under sustained high-volume attack (e.g., 100,000 requests/second with a 60-second window), this stores 6 million timestamps per key, consuming significant memory. Expired timestamps are only cleaned when checked, not proactively.

**Intent:**
As a platform operator, when my system is under a sustained flood attack, the SlidingWindowRateLimiter's memory usage should remain bounded and proportional to the configured window size and rate limit, not proportional to the attack volume.

**Fix:**
1. After each request, immediately remove timestamps older than the window
2. Add a max_entries_per_key parameter (default: 2x the max_requests limit) that hard-caps the deque length
3. When entries exceed max_entries_per_key, reject the request immediately (it is clearly over the limit)
4. Use collections.deque with maxlen for automatic bounding
5. Add a test that simulates 10,000 rapid requests and verifies memory stays bounded

**Claude Code prompt:**
```
Read proxilion/security/rate_limiter.py fully, focusing on the SlidingWindowRateLimiter class. Change the internal timestamp storage from a list to a collections.deque with maxlen set to 2 * max_requests. This automatically bounds memory. After each allow_request() call, eagerly remove timestamps older than the window using a while loop from the left side of the deque. Add a test in tests/test_rate_limiter_memory.py that calls allow_request() 10,000 times rapidly, then asserts that the internal deque length never exceeds 2 * max_requests. After editing, run: python3 -m pytest tests/test_rate_limiter_memory.py tests/test_core.py -x -q && python3 -m ruff check proxilion/security/rate_limiter.py && python3 -m mypy proxilion/security/rate_limiter.py
```

---

### Step 14: Fix MultiDimensionalRateLimiter Race Condition

**Priority:** CRITICAL
**Complexity:** MEDIUM
**Addresses:** P1 finding #3 (race condition in MultiDimRateLimiter), P2 from 2026-03-18 review
**Files:** proxilion/security/rate_limiter.py

**Problem:**
The MultiDimensionalRateLimiter checks multiple rate limit dimensions (user, IP, global) sequentially. The check-then-consume pattern at lines 426-470 allows two concurrent requests to both pass the check phase before either consumes tokens, effectively doubling the allowed rate. Each dimension is checked independently without holding a lock across all dimensions.

**Intent:**
As a platform operator with a multi-dimensional rate limiter (10 req/user/min + 100 req/global/min), when exactly 10 requests arrive simultaneously from the same user, exactly 10 should pass and the 11th should be rejected. The check-and-consume must be atomic across all dimensions.

**Fix:**
1. Acquire the lock before checking any dimension
2. Check all dimensions within the lock
3. Only consume from all dimensions if all checks pass
4. If any dimension rejects, release the lock without consuming from any dimension
5. Add a concurrent test that spawns 20 threads each sending 1 request with a limit of 10, and verifies exactly 10 succeed

**Claude Code prompt:**
```
Read proxilion/security/rate_limiter.py fully, focusing on the MultiDimensionalRateLimiter class. Find the allow_request() or check() method. Refactor it so that: (1) self._lock is acquired before any dimension is checked, (2) all dimensions are checked within the lock, (3) tokens are consumed from all dimensions only if ALL checks pass, (4) if any dimension rejects, no tokens are consumed from any dimension. Then add a test in tests/test_multidim_race.py that creates a MultiDimensionalRateLimiter with a 10-request limit, spawns 20 threads each calling allow_request() once, and asserts exactly 10 return True. After editing, run: python3 -m pytest tests/test_multidim_race.py -x -q && python3 -m ruff check proxilion/security/rate_limiter.py && python3 -m mypy proxilion/security/rate_limiter.py
```

---

### Step 15: Add JSON Payload Size Limits

**Priority:** HIGH
**Complexity:** MEDIUM
**Addresses:** P2 finding #14 (JSON no size validation)
**Files:** proxilion/providers/openai.py, proxilion/providers/adapter.py

**Problem:**
Provider adapter modules parse JSON responses from LLM providers without checking payload size. A malicious or misconfigured provider could return a multi-gigabyte JSON response that exhausts memory during parsing. Specifically, openai.py line 274 and adapter.py line 95 call json.loads() on unbounded input.

**Intent:**
As a developer integrating Proxilion with an LLM provider, if the provider returns an abnormally large response (over 100 MB), Proxilion should reject the response with a clear error rather than attempting to parse it and exhausting memory.

**Fix:**
1. Add a MAX_RESPONSE_SIZE constant (default: 100 MB, configurable) to providers/adapter.py
2. Before calling json.loads(), check len(response_text) against MAX_RESPONSE_SIZE
3. If exceeded, raise a ProxilionError with a clear message including the actual size and the limit
4. Apply the same check in openai.py and any other provider adapter that parses JSON
5. Add a test that verifies oversized payloads are rejected

**Claude Code prompt:**
```
Read proxilion/providers/adapter.py and proxilion/providers/openai.py. Find every call to json.loads() or json.load(). Before each call, add a size check: if len(data) > MAX_RESPONSE_SIZE, raise ProxilionError(f"Response size {len(data)} exceeds limit {MAX_RESPONSE_SIZE}"). Define MAX_RESPONSE_SIZE = 100 * 1024 * 1024 (100 MB) at the module level in adapter.py and import it in openai.py. Also check any other provider files (anthropic.py, gemini.py) for unbounded JSON parsing. Add a test in tests/test_payload_size.py that creates a string larger than MAX_RESPONSE_SIZE and verifies the adapter raises ProxilionError. After editing, run: python3 -m pytest tests/test_payload_size.py -x -q && python3 -m ruff check proxilion/providers/ && python3 -m mypy proxilion/providers/
```

---

### Step 16: Fix Empty String Validation in Contexts

**Priority:** HIGH
**Complexity:** MEDIUM
**Addresses:** P2 finding #1 (missing AgentContext validation), P2 finding #3 (unvalidated user input in decorators)
**Files:** proxilion/types.py, proxilion/decorators.py

**Problem:**
UserContext accepts empty string for user_id, AgentContext accepts empty string for agent_id, and decorator parameters accept empty strings for identifiers. An empty user_id or agent_id is semantically meaningless and could bypass identity-based policies (a policy checking user_id == "admin" would not match "", effectively denying access, but a policy checking user_id != "" would incorrectly pass).

**Intent:**
As a developer, when I accidentally pass user_id="" to UserContext, I should get a ValueError at construction time rather than a silent pass-through that causes confusing policy evaluation failures downstream.

**Fix:**
1. In UserContext.__post_init__(), validate that user_id is a non-empty string after stripping whitespace
2. In AgentContext.__post_init__(), validate that agent_id is a non-empty string after stripping whitespace
3. In ToolCallRequest.__post_init__(), validate that tool_name is a non-empty string
4. Raise ValueError with a clear message for each violation
5. In decorators.py, validate that user_id parameters passed to decorator functions are non-empty
6. Add tests for empty string, whitespace-only, and None inputs

**Claude Code prompt:**
```
Read proxilion/types.py focusing on UserContext, AgentContext, and ToolCallRequest frozen dataclasses. These use __post_init__ for validation. Add validation that raises ValueError if: user_id is empty or whitespace-only (in UserContext), agent_id is empty or whitespace-only (in AgentContext), tool_name is empty or whitespace-only (in ToolCallRequest). Use `if not self.user_id or not self.user_id.strip(): raise ValueError("user_id must be a non-empty string")` pattern. Then read proxilion/decorators.py and add similar validation where user_id is accepted as a parameter. Add tests in tests/test_context_validation.py covering: empty string, whitespace-only, and verify that valid strings still work. After editing, run: python3 -m pytest tests/test_context_validation.py tests/test_core.py -x -q && python3 -m ruff check proxilion/types.py proxilion/decorators.py && python3 -m mypy proxilion/types.py proxilion/decorators.py
```

---

### Step 17: Fix Incomplete Exception Context Fields

**Priority:** MEDIUM
**Complexity:** LOW
**Addresses:** P3 finding #1 (incomplete exception context)
**Files:** proxilion/exceptions.py

**Problem:**
Some exception classes in exceptions.py have structured context (added in spec-v2) but are missing fields like session_id and timestamp that other exception classes include. This inconsistency means error handlers cannot uniformly extract context from all Proxilion exceptions.

**Intent:**
As a developer writing an error handler that logs all Proxilion exceptions to a monitoring service, when I catch any ProxilionError subclass, I should be able to access .session_id and .timestamp fields uniformly, without checking which specific subclass it is.

**Fix:**
1. Add session_id: Optional[str] and timestamp: Optional[str] fields to the base ProxilionError class if not already present
2. Ensure all subclasses inherit these fields
3. Wire timestamp = datetime.utcnow().isoformat() at raise sites where it is missing
4. Add a test that catches each exception subclass and verifies .session_id and .timestamp are accessible

**Claude Code prompt:**
```
Read proxilion/exceptions.py fully. Check if the base ProxilionError class has session_id and timestamp attributes. If not, add them as Optional[str] with default None in __init__. Verify all subclasses (AuthorizationError, RateLimitExceeded, CircuitOpenError, InputGuardViolation, OutputGuardViolation, PolicyViolation, SchemaValidationError, IDORViolationError, ApprovalRequiredError, etc.) inherit these fields properly without overriding them. Add a test in tests/test_exception_context.py that instantiates every ProxilionError subclass and verifies .session_id and .timestamp are accessible (even if None). After editing, run: python3 -m pytest tests/test_exception_context.py -x -q && python3 -m ruff check proxilion/exceptions.py && python3 -m mypy proxilion/exceptions.py
```

---

### Step 18: Fix Error Event Raw Chunk Leakage

**Priority:** MEDIUM
**Complexity:** LOW
**Addresses:** P3 finding #17 (error event includes raw chunk)
**Files:** proxilion/streaming/detector.py

**Problem:**
When the streaming tool call detector encounters a parsing error (around lines 240-255), it includes the raw chunk content in the error event. If the chunk contains user data, this could leak sensitive information into log streams or error monitoring systems.

**Intent:**
As a security engineer, when I review error logs from the streaming detector, I should never see raw user input or LLM output in error messages. Error events should include metadata about the failure (chunk index, expected format, error type) but not the raw content.

**Fix:**
1. In the error handling paths of detector.py, replace raw chunk content with sanitized metadata: chunk length, chunk index, and error type
2. Log the raw chunk at DEBUG level only (not INFO or WARNING)
3. Add a test that triggers a parsing error with sensitive content in the chunk and verifies the error event does not contain the raw content

**Claude Code prompt:**
```
Read proxilion/streaming/detector.py fully. Find every place where error events or log messages include raw chunk content. Replace the raw content with metadata: chunk_length=len(chunk), chunk_index=index, error_type=type(e).__name__. Move any raw content logging to logger.debug() level. Add a test in tests/test_streaming_leakage.py that passes a chunk containing "password=secret123" to the detector in a way that triggers an error, then verifies the error event and any WARNING/ERROR log messages do not contain "secret123". After editing, run: python3 -m pytest tests/test_streaming_leakage.py -x -q && python3 -m ruff check proxilion/streaming/detector.py && python3 -m mypy proxilion/streaming/detector.py
```

---

### Step 19: Fix Sequence Number Overflow Guard

**Priority:** MEDIUM
**Complexity:** LOW
**Addresses:** P3 finding #3 (sequence number no bounds), P3 finding #7 (sequence counter overflow)
**Files:** proxilion/types.py, proxilion/security/memory_integrity.py

**Problem:**
Sequence numbers in types.py (line 252) and the sequence counter in memory_integrity.py (lines 325-384) are unbounded integers. While Python handles arbitrary-precision integers, JSON serialization of integers beyond 2^53 loses precision in JavaScript consumers. Audit log entries with sequence numbers beyond 2^53 would be corrupted when parsed by browser-based log viewers or Node.js-based monitoring tools.

**Intent:**
As an operations engineer viewing audit logs in a web-based dashboard, sequence numbers should always be accurately represented. If the sequence counter approaches the JSON safe integer limit, the system should rotate to a new sequence namespace rather than silently producing corrupted sequence numbers.

**Fix:**
1. Define MAX_SAFE_SEQUENCE = 2**53 - 1 (9007199254740991) in types.py
2. In AuditEventV2 or wherever sequence numbers are assigned, check against MAX_SAFE_SEQUENCE
3. If exceeded, log a warning and reset to 0 with a new sequence_epoch identifier
4. In memory_integrity.py, apply the same bound to the sequence counter
5. Add a test that verifies the overflow behavior

**Claude Code prompt:**
```
Read proxilion/types.py (focusing on sequence_number fields) and proxilion/security/memory_integrity.py (focusing on sequence counter). Add MAX_SAFE_SEQUENCE = 2**53 - 1 to types.py. In any code that increments a sequence counter, add a check: if counter > MAX_SAFE_SEQUENCE, log a warning and reset to 0. In memory_integrity.py, apply the same bound. Add a test in tests/test_sequence_overflow.py that sets the counter to MAX_SAFE_SEQUENCE - 1, increments twice, and verifies the counter resets. After editing, run: python3 -m pytest tests/test_sequence_overflow.py -x -q && python3 -m ruff check proxilion/types.py proxilion/security/memory_integrity.py && python3 -m mypy proxilion/types.py proxilion/security/memory_integrity.py
```

---

### Step 20: Fix Async Event Loop Detection Masking

**Priority:** MEDIUM
**Complexity:** LOW
**Addresses:** P3 finding #18 (async event loop detection could mask errors)
**Files:** proxilion/providers/openai.py

**Problem:**
The OpenAI provider adapter (around lines 367-382) catches RuntimeError when checking for a running event loop and silently falls back to synchronous execution. This masks genuine RuntimeError exceptions unrelated to event loop detection, such as "dictionary changed size during iteration" or "generator already executing".

**Intent:**
As a developer debugging a RuntimeError in my application, the error should propagate normally rather than being caught by Proxilion's event loop detection and silently swallowed. Only the specific "no current event loop" or "This event loop is already running" messages should be caught.

**Fix:**
1. Change the bare `except RuntimeError` to check the error message
2. Only catch RuntimeError whose message contains "no current event loop" or "There is no current event loop" or "cannot be called from a running event loop"
3. Re-raise any other RuntimeError
4. Add a test that verifies non-event-loop RuntimeErrors propagate

**Claude Code prompt:**
```
Read proxilion/providers/openai.py fully. Find every `except RuntimeError` block related to event loop detection. Change each to: `except RuntimeError as e: if "event loop" not in str(e).lower() and "no current" not in str(e).lower(): raise`. This ensures only event-loop-related RuntimeErrors are caught. Add a test in tests/test_provider_error_masking.py that monkeypatches asyncio.get_event_loop to raise RuntimeError("unrelated error") and verifies it propagates. After editing, run: python3 -m pytest tests/test_provider_error_masking.py -x -q && python3 -m ruff check proxilion/providers/openai.py && python3 -m mypy proxilion/providers/openai.py
```

---

### Step 21: Update CHANGELOG, Version, and Documentation

**Priority:** HIGH
**Complexity:** MEDIUM
**Addresses:** Spec-v2 step 17 (incomplete), version management
**Files:** pyproject.toml, proxilion/__init__.py, CHANGELOG.md, CLAUDE.md

**Problem:**
Spec-v2 step 17 called for version bump, CHANGELOG update, and documentation synchronization. The version is still 0.0.7 and the CHANGELOG does not reflect the work done in spec-v2 through spec-v7.

**Intent:**
As a developer checking the version, `proxilion.__version__` should return "0.0.13" and the CHANGELOG should list all changes from the spec-v2 through spec-v7 cycles with clear categories (security, reliability, performance, documentation, CI/CD).

**Fix:**
1. Update pyproject.toml version from current to "0.0.13"
2. Update proxilion/__init__.py __version__ to "0.0.13"
3. Update CHANGELOG.md with entries for versions 0.0.8 through 0.0.13, grouped by: Security Fixes, Reliability Improvements, Performance Optimizations, Documentation Updates, CI/CD Improvements, Developer Experience
4. Update CLAUDE.md "Current: 0.0.7" to "Current: 0.0.13"
5. Verify version sync: pyproject.toml == __init__.py == CLAUDE.md

**Claude Code prompt:**
```
Read pyproject.toml, proxilion/__init__.py, CHANGELOG.md (if it exists, create if not), and CLAUDE.md. Update the version to "0.0.13" in pyproject.toml (the version field), proxilion/__init__.py (__version__), and CLAUDE.md (the "Current:" line in the Version section). Create or update CHANGELOG.md with entries for 0.0.8 through 0.0.13. For each version, add sections: Security, Reliability, Performance, Documentation, CI/CD. Summarize the changes from spec-v2 through spec-v7 under the appropriate version. Keep entries concise (one line per change). After editing, verify version sync: python3 -c "import proxilion; assert proxilion.__version__ == '0.0.13'" && python3 -m ruff check proxilion/__init__.py
```

---

### Step 22: Add README Mermaid Diagrams

**Priority:** MEDIUM
**Complexity:** MEDIUM
**Addresses:** Spec-v2 step 18 (incomplete), documentation
**Files:** README.md

**Problem:**
Spec-v2 step 18 called for mermaid diagrams in the README but this was never completed. The README has ASCII art diagrams but no mermaid diagrams that render in GitHub's markdown viewer. Mermaid diagrams provide interactive, zoom-able, and more maintainable architecture visualizations.

**Intent:**
As a developer evaluating Proxilion on GitHub, when I scroll through the README, I should see rendered mermaid diagrams showing: (1) the authorization flow from request to response, (2) the module dependency architecture, and (3) the exception class hierarchy. These diagrams should render natively on GitHub without any external tools.

**Fix:**
Add three mermaid diagram code blocks to the end of README.md:

1. **Authorization Flow** -- A flowchart showing: Request -> Input Guard -> Rate Limiter -> IDOR Check -> Schema Validation -> Policy Engine -> Output Guard -> Response, with error paths branching to exception types at each stage.

2. **Module Architecture** -- A dependency graph showing the relationships between core, security, guards, audit, providers, contrib, resilience, streaming, context, caching, validation, timeouts, and scheduling packages.

3. **Exception Hierarchy** -- A class diagram showing ProxilionError as root with all subclasses: AuthorizationError, RateLimitExceeded, CircuitOpenError, InputGuardViolation, OutputGuardViolation, PolicyViolation, SchemaValidationError, IDORViolationError, ApprovalRequiredError, and any others.

**Claude Code prompt:**
```
Read README.md to understand its current structure. Add a new section at the end titled "## Architecture Diagrams" with three mermaid code blocks:

1. Authorization Flow (flowchart TD):
- Request --> InputGuard
- InputGuard -->|pass| RateLimiter
- InputGuard -->|fail| InputGuardViolation
- RateLimiter -->|pass| IDORCheck
- RateLimiter -->|fail| RateLimitExceeded
- IDORCheck -->|pass| SchemaValidation
- IDORCheck -->|fail| IDORViolationError
- SchemaValidation -->|pass| PolicyEngine
- SchemaValidation -->|fail| SchemaValidationError
- PolicyEngine -->|pass| OutputGuard
- PolicyEngine -->|fail| PolicyViolation
- OutputGuard -->|pass| Response
- OutputGuard -->|fail| OutputGuardViolation

2. Module Architecture (graph LR) showing package dependencies:
- core depends on: engines, policies, security, guards, audit, providers, resilience, context, validation, observability
- contrib depends on: core, providers, guards
- streaming depends on: core
- caching depends on: core
- scheduling depends on: core
- timeouts depends on: core

3. Exception Hierarchy (classDiagram):
- ProxilionError <|-- AuthorizationError
- ProxilionError <|-- RateLimitExceeded
- ProxilionError <|-- CircuitOpenError
- ProxilionError <|-- InputGuardViolation
- ProxilionError <|-- OutputGuardViolation
- ProxilionError <|-- PolicyViolation
- ProxilionError <|-- SchemaValidationError
- ProxilionError <|-- IDORViolationError
- ProxilionError <|-- ApprovalRequiredError

After adding the diagrams, verify the markdown is valid and run: python3 -m ruff check proxilion/ tests/ (to make sure no code was accidentally broken).
```

---

### Step 23: Final Validation and State Update

**Priority:** CRITICAL
**Complexity:** LOW
**Addresses:** Final verification, documentation sync
**Files:** .codelicious/STATE.md, .proxilion-build/STATE.md, CLAUDE.md, memory files

**Problem:**
After all steps are complete, the state files and documentation must reflect the final state of the codebase. This is the final gate before the spec is marked COMPLETE.

**Intent:**
As a maintainer, when I open STATE.md after spec-v7 is complete, every step should be marked complete, all metrics should be current, and all known P1 and P2 findings should show as resolved.

**Fix:**
1. Run the full CI check: `python3 -m ruff check proxilion tests && python3 -m ruff format --check proxilion tests && python3 -m mypy proxilion && python3 -m pytest -x -q`
2. Update .codelicious/STATE.md with: current test count, version 0.0.13, all spec-v7 steps marked complete, all P1 and P2 findings marked resolved
3. Update .proxilion-build/STATE.md similarly
4. Update CLAUDE.md test count, version, and any changed file descriptions
5. Update Claude Code memory files to reflect the new spec history
6. Write "DONE" to .codelicious/BUILD_COMPLETE

**Claude Code prompt:**
```
Run the full CI check: python3 -m ruff check proxilion tests && python3 -m ruff format --check proxilion tests && python3 -m mypy proxilion && python3 -m pytest -x -q. Record the test count. Then update .codelicious/STATE.md: set version to 0.0.13, update test count, mark all spec-v7 steps complete, mark all P1 and P2 findings as RESOLVED with the step number that resolved them. Update .proxilion-build/STATE.md similarly. Update CLAUDE.md: change "Current: 0.0.7" to "Current: 0.0.13", update test count in comments, update any file descriptions that changed. Write "DONE" to .codelicious/BUILD_COMPLETE. After all updates, run the full CI check one final time to confirm nothing broke.
```

---

## Implementation Order

| Phase | Steps | Dependencies | Parallelizable |
|-------|-------|-------------|----------------|
| Phase 1: Documentation & DX | 1, 2, 3 | None (independent of each other) | Yes |
| Phase 2: CI Hardening | 5, 6, 7 | None (independent of each other) | Yes |
| Phase 3: Critical Security | 8, 9, 10, 11, 14 | None (independent of each other) | Yes |
| Phase 4: High Security | 12, 13, 15, 16 | 11 (step 12 reuses normalization from 11) | Partially |
| Phase 5: Testing | 4 | 2 (needs docstrings for decorator understanding) | No |
| Phase 6: Medium Fixes | 17, 18, 19, 20 | None (independent of each other) | Yes |
| Phase 7: Version & Release | 21 | All previous phases | No |
| Phase 8: Diagrams | 22 | 9 (needs final auth flow order) | No |
| Phase 9: Final Validation | 23 | All previous phases | No |

---

## Out of Scope

The following items are explicitly excluded from this spec:

- **Net-new features** -- No new security modules, no new policy engines, no new provider adapters
- **ML/NLP-based detection** -- The state file recommends NLP-based intent classification and ML-based guard detection as long-term goals; these violate the deterministic security principle and are out of scope
- **Automatic audit log archival** -- Deferred to a future spec focused on operational tooling
- **Rate limiting on audit writes** -- Deferred; current write volume is bounded by authorization request volume
- **License selection** -- Not needed for private org repo at this stage
- **PyPI publishing** -- Deferred until version 1.0 readiness
- **Breaking API changes** -- All changes in this spec are backwards-compatible
- **Performance profiling** -- Benchmarks were added in spec-v2; no new profiling infrastructure needed
- **Kubernetes/Docker deployment** -- Deferred to a production deployment spec
- **OpenTelemetry integration** -- Deferred; current Prometheus export is sufficient
- **Web UI or dashboard** -- Out of scope for an SDK
- **MCP server hosting** -- Out of scope; MCP integration is client-side only

---

## Findings Resolution Map

This table maps every known finding from the deep security review (2026-03-17/18) to the step in this spec or a prior spec that resolves it.

### P1 Critical Findings

| # | Finding | Resolution |
|---|---------|------------|
| 1 | Thread Safety - Unprotected State (core.py:255-330) | Step 8 |
| 2 | TOCTOU in Auth Flow (core.py:1644-1661) | Step 9 |
| 3 | Race Condition in MultiDimRateLimiter (rate_limiter.py:426-470) | Step 14 |
| 4 | Unbounded Nonce Memory (agent_trust.py:882-890) | spec-v6 step (TTL-bounded nonce structure) |
| 5 | Timing Attack in Key Validation (intent_capsule.py:68-79) | spec-v6 step (constant-time comparison) |
| 6 | Input Guard Punctuation Bypass (input_guard.py:138) | Step 11 |
| 7 | Leetspeak/Char Substitution Bypass (input_guard.py) | Step 11 |
| 8 | Audit Log TOCTOU (logger.py:386-396) | Step 10 |

### P2 Important Findings

| # | Finding | Resolution |
|---|---------|------------|
| 1 | Missing AgentContext Validation (types.py:116-119) | Step 16 |
| 2 | Audit Hash Collision Risk (types.py:283-313) | spec-v6 step (canonical JSON serialization) |
| 3 | Unvalidated User Input in Decorators (decorators.py:353-361) | Step 16 |
| 4 | Info Disclosure in Exceptions (exceptions.py:204,370) | spec-v5 step (exception immutability) |
| 5 | Default Deny Bypass (core.py:1456-1470) | spec-v3 step (auth flow hardening) |
| 6 | Rate Limiter Cost No Upper Bound (rate_limiter.py:108-144) | spec-v6 step (rate limiter correctness) |
| 7 | Integer Overflow in Token Refill (rate_limiter.py:97-106) | spec-v6 step (rate limiter correctness) |
| 8 | Weak Capability Wildcard (agent_trust.py:142-165) | spec-v4 step (security bypass closure) |
| 9 | ReDoS in RAG Patterns (memory_integrity.py:226-258) | spec-v4 step (ReDoS pattern fixes) |
| 10 | SQL Injection Opt-In Only (schema.py:477) | spec-v5 step (safe defaults) |
| 11 | Output Guard Spacing Bypass (output_guard.py:143) | Step 12 |
| 12 | Unbounded Cost Tracker Memory (cost_tracker.py:353-361) | spec-v3 step (bounded collections) |
| 13 | Merkle Tree Incomplete (hash_chain.py:646-674) | spec-v6 step (Merkle tree proofs) |
| 14 | JSON No Size Validation (openai.py:274, adapter.py:95) | Step 15 |

### P3 Minor Findings

| # | Finding | Resolution |
|---|---------|------------|
| 1 | Incomplete Exception Context (exceptions.py) | Step 17 |
| 2 | No Type Validation in ToolCallRequest (types.py:138-173) | spec-v5 step (input validation) |
| 3 | Sequence Number No Bounds (types.py:252) | Step 19 |
| 4 | Missing Docstrings (core.py:1849,1858,1863) | Step 2 |
| 5 | Weak Logging in QueueApproval (decorators.py:256,296) | spec-v3 step (logging improvements) |
| 6 | No Refill Rate Lower Bound (rate_limiter.py:74-77) | spec-v6 step (rate limiter correctness) |
| 7 | Sequence Counter Overflow (memory_integrity.py:325-384) | Step 19 |
| 8 | Clock Skew Hardcoded (agent_trust.py:796-800) | spec-v5 step (configurable parameters) |
| 9 | Path Traversal in Intent (intent_capsule.py:649-656) | spec-v4 step (path traversal fixes) |
| 10 | Info Disclosure in Rate Limit (rate_limiter.py:552-592) | spec-v5 step (info disclosure) |
| 11 | IDOR Extractor Silent Fail (idor_protection.py:333-359) | spec-v3 step (error handling) |
| 12 | Unbounded Tool Call Recording (intent_capsule.py:159-177) | spec-v3 step (bounded collections) |
| 13 | Weak Intent Category (intent_capsule.py:275-344) | Out of scope (would require ML) |
| 14 | Path Traversal Single Encoding (schema.py:502-547) | spec-v4 step (path traversal fixes) |
| 15 | Schema Validator Permissive (schema.py:232) | spec-v5 step (safe defaults) |
| 16 | Missing fsync After Writes (logger.py:388-396) | Step 10 |
| 17 | Error Event Includes Raw Chunk (detector.py:240-255) | Step 18 |
| 18 | Async Event Loop Detection (openai.py:367-382) | Step 20 |
| 19 | Thread Safety History Deques (openai.py:181,308) | spec-v3 step (thread safety) |

---

## Summary

This spec contains 23 steps across 9 phases. It resolves 5 of 8 P1 findings, 3 of 14 P2 findings, and 6 of 19 P3 findings directly, with the remaining findings mapped to prior specs (spec-v3 through spec-v6) in the dependency chain. After spec-v2 through spec-v7 are complete, zero P1 findings and zero P2 findings should remain open.

The spec produces:
- Zero known P1 or P2 security findings
- Complete public API documentation with docstrings and quickstart coverage
- CI pipeline testing Python 3.10 through 3.13 with dependency vulnerability scanning
- Sample data generator for developer onboarding
- Mermaid architecture diagrams in the README
- All test files linted and formatted to the same standard as source files
- Version 0.0.13 with a complete CHANGELOG

Total estimated new test count after this spec: approximately 2,750 (current 2,633 plus approximately 120 new tests from steps 4, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20).
