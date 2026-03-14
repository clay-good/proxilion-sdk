# Proxilion SDK — Improvement Spec

**Version:** 0.0.4 → 0.0.5
**Date:** 2026-03-12 (completed 2026-03-13)
**Status:** ALL STEPS COMPLETE

---

## Assessment Summary

Full gap/feature/bug/improvement assessment of the proxilion-sdk codebase performed on 2026-03-12. The SDK is a runtime security layer for LLM-powered applications with 89 modules, 2,350 passing tests, strict mypy, and full CI/CD. All modules have test coverage. The items below are scoped to in-repo improvements only — no new features outside the existing module boundaries.

---

## Step 1 — Fix Critical Bugs

> **Priority:** CRITICAL
> **Status:** COMPLETED (2026-03-12)

### 1a. Scheduler busy-wait loop (`proxilion/scheduling/scheduler.py`)

**Problem:** While the scheduler was paused, a `while` loop spun with `pass` inside `_state_lock`, burning 100% CPU and deadlocking (since `resume()` also needed the lock).

**Fix applied:** Added `threading.Event` (`_resume_event`). `pause()` calls `clear()`, `resume()` and `shutdown()` call `set()`. Worker loop calls `_resume_event.wait()` instead of spinning — releases CPU and avoids deadlock.

**Files changed:** `proxilion/scheduling/scheduler.py`

### 1b. Sync timeout thread leak (`proxilion/timeouts/decorators.py`)

**Problem:** `future.cancel()` after a `ThreadPoolExecutor` timeout could not actually kill a running thread. The timed-out function continued executing silently in the background.

**Fix applied:** Executor now uses `shutdown(wait=False)` so leaked threads don't block. Added `logger.warning()` when a sync timeout fires so operators know a background thread is still running. Added docstring documenting the Python thread limitation.

**Files changed:** `proxilion/timeouts/decorators.py`

### 1c. QueueApprovalStrategy busy-wait polling (`proxilion/decorators.py`)

**Problem:** `time.sleep(0.1)` polling loop to check approval status. Wasteful and blocks the thread unnecessarily.

**Fix applied:** Replaced with `threading.Event.wait(timeout=self.timeout)` for sync path and `asyncio.wait_for(event.wait(), timeout=self.timeout)` for async path. `approve()` and `deny()` now call `event.set()` to wake up the waiting thread/task immediately.

**Files changed:** `proxilion/decorators.py`

**All 2,349 tests pass after Step 1 changes (1 pre-existing skip).**

---

## Step 2 — Fix Unbounded Memory Growth

> **Priority:** HIGH
> **Status:** COMPLETED (2026-03-12)

### 2a. Cascade protection events (`proxilion/security/cascade_protection.py`)

**Problem:** `self._events: list[CascadeEvent]` was appended to on every failure propagation but never pruned. In long-running processes this grew without limit.

**Fix applied:** Changed `_events` from `list` to `collections.deque(maxlen=max_events)` with a configurable `max_events` parameter (default 10,000). Oldest events are automatically evicted. Also fixed `get_cascade_events()` which used list slicing (`[-limit:]`) incompatible with `deque` — now converts to list first.

**Files changed:** `proxilion/security/cascade_protection.py`

### 2b. Streaming detector partial calls (`proxilion/streaming/detector.py`)

**Problem:** `_max_partial_calls = 1000` limited completed-call cleanup, but incomplete/abandoned partial calls were never reaped. A stream that hung mid-tool-call left entries forever.

**Fix applied:** Added `_stale_timeout_seconds = 300.0` (5 minutes). `_cleanup_completed_calls()` now reaps incomplete partial calls older than the staleness timeout on every invocation, regardless of dictionary size.

**Files changed:** `proxilion/streaming/detector.py`

**All 2,349 tests pass after Step 2 changes (1 pre-existing skip).**

---

## Step 3 — Harden Input Validation on Public APIs

> **Priority:** HIGH
> **Status:** COMPLETED (2026-03-12)

### 3a. Missing parameter bounds checks

**Problem:** Several public constructors accepted numeric parameters without validation.

**Assessment & fix applied:** Audited all five modules listed. Three already had validation (`CircuitBreaker`, `RetryPolicy`, `MetricsCollector`). Added validation to the three that lacked it:

| Module | Parameters validated | Constraint |
|--------|---------------------|------------|
| `security/cascade_protection.py` | `degraded_threshold`, `failing_threshold`, `max_events` | Must be >= 1 |
| `security/behavioral_drift.py` | `auto_halt_threshold`, `warning_threshold` in `DriftDetector` | Must be 0.0-1.0 |
| `observability/metrics.py` | `window_seconds`, `cooldown_seconds` in `AlertRule` | > 0, >= 0 respectively |

**Files changed:** `proxilion/security/cascade_protection.py`, `proxilion/security/behavioral_drift.py`, `proxilion/observability/metrics.py`

### 3b. Broad exception catching (`proxilion/engines/simple.py`)

**Problem:** `except Exception as e` when looking up a policy masked unexpected errors.

**Fix applied:** Narrowed to `except PolicyNotFoundError as e:` and added the import from `proxilion.exceptions`.

**Files changed:** `proxilion/engines/simple.py`

**All 2,349 tests pass after Step 3 changes (1 pre-existing skip).**

---

## Step 4 — Improve Streaming Robustness

> **Priority:** MEDIUM
> **Status:** COMPLETED (2026-03-12)

### 4a. Chunk validation in `proxilion/streaming/detector.py`

**Problem:** `process_chunk()` accepted `Any` and accessed attributes without validation. `None` or primitive-type chunks caused `AttributeError` deep inside provider handlers.

**Fix applied:** Added early type checks at the top of `process_chunk()`. `None` chunks return empty list with a debug log. Unsupported primitive types (`int`, `float`, `bool`, `bytes`, `bytearray`) return an error `StreamEvent` with a clear message. Valid types (dict, str, objects) proceed to provider-specific processing as before.

**Files changed:** `proxilion/streaming/detector.py`

### 4b. Empty-chunk handling in `proxilion/streaming/transformer.py`

**Problem:** If a filter removed all content from a chunk, an empty string was yielded downstream.

**Fix applied:** Added `and result != ""` checks alongside existing `result is not None` checks in all four filter-application sites: `transform()`, `transform_sync()`, `transform_events()`, and `FilteredStream.__anext__()`. Empty strings are now silently dropped.

**Files changed:** `proxilion/streaming/transformer.py`

**All 2,349 tests pass after Step 4 changes (1 pre-existing skip).**

---

## Step 5 — Improve Resilience Module

> **Priority:** MEDIUM
> **Status:** COMPLETED (2026-03-12)

### 5a. Fallback error reporting (`proxilion/resilience/fallback.py`)

**Problem:** When all fallbacks failed, earlier errors were inaccessible. The `FallbackResult` collected all `(name, exception)` tuples but provided no way to raise them as a single exception with full context.

**Fix applied:** Added `FallbackExhaustedError` to `proxilion/exceptions.py` (inherits `ProxilionError`) with `errors` and `attempts` attributes. Added `raise_on_failure()` method to `FallbackResult` that raises `FallbackExhaustedError` with all collected errors chained via `__cause__`, so every failure is visible in the traceback. Exported from `proxilion/__init__.py`.

**Files changed:** `proxilion/exceptions.py`, `proxilion/resilience/fallback.py`, `proxilion/__init__.py`

### 5b. Retry delay overflow (`proxilion/resilience/retry.py`)

**Problem:** Exponential backoff with large `max_attempts` could theoretically produce overflow.

**Assessment:** Already fixed. `RetryPolicy.calculate_delay()` already clamps to `max_delay` at line 91 (`min(delay, self.max_delay)`) and again after jitter at line 97 (`max(0, min(delay, self.max_delay))`). The `RetryPolicy` dataclass also validates `max_delay >= base_delay` in `__post_init__`. No changes needed.

**All 2,349 tests pass after Step 5 changes (1 pre-existing skip).**

---

## Step 6 — Improve Context Window Management

> **Priority:** MEDIUM
> **Status:** COMPLETED (2026-03-12)

### 6a. Token estimation accuracy (`proxilion/context/message_history.py`)

**Problem:** Token estimation used a fixed 1.3 words/token heuristic with no disclaimer or configuration. Could cause context window overflows or premature truncation.

**Fix applied:** Added `TokenEstimator` type alias (`Callable[[str], int]`). Added `token_estimator` parameter to `MessageHistory.__init__` (default: built-in heuristic). Messages appended to a history with a custom estimator are automatically recounted. Added `Message.recount_tokens(estimator)` method. Updated `estimate_tokens()` docstring with accuracy warning and pointer to `token_estimator` parameter.

**Files changed:** `proxilion/context/message_history.py`

### 6b. Summarize strategy error handling (`proxilion/context/context_window.py`)

**Problem:** `SUMMARIZE_OLD` strategy called `summarize_callback()` but didn't handle errors or timeouts from the callback.

**Fix applied:** Wrapped `summarize_callback()` invocation in `SummarizeOldStrategy.fit()` with `try/except Exception`. On failure, logs a warning with the error details and falls back to `SlidingWindowStrategy` (truncate old) so context fitting never raises from a broken callback.

**Files changed:** `proxilion/context/context_window.py`

**All 2,349 tests pass after Step 6 changes (1 pre-existing skip).**

---

## Step 7 — Improve Validation Coverage

> **Priority:** MEDIUM
> **Status:** COMPLETED (2026-03-12)

### 7a. Path traversal detection (`proxilion/validation/schema.py`)

**Problem:** `_check_path_traversal()` checked `..`, URL-encoded, double-encoded, and unicode variants but missed backslash variants (`..\\`) and null byte injection (`%00`).

**Fix applied:** Added detection for: backslash traversal (`..\`), URL-encoded backslash (`%2e%2e%5c`), URL-encoded forward slash (`%2e%2e%2f`), literal null byte (`\x00`), and URL-encoded null byte (`%00`). Also consolidated lowercase conversion into a single `lower` variable for efficiency.

**Files changed:** `proxilion/validation/schema.py`

### 7b. Schema auto-generation exclusion list (`proxilion/validation/schema.py`)

**Problem:** `create_schema_from_function()` hardcoded excluded parameter names (`self`, `cls`, `user`, `context`). Other common injected parameters like `agent`, `session`, `request` were not excluded.

**Fix applied:** Extracted exclusion list to class attribute `DEFAULT_EXCLUDED_PARAMS` (`frozenset` containing `self`, `cls`, `user`, `context`, `agent`, `session`, `request`). Added `exclude_params` parameter to `create_schema_from_function()` so callers can override the default set.

**Files changed:** `proxilion/validation/schema.py`

**All 2,349 tests pass after Step 7 changes (1 pre-existing skip).**

---

## Step 8 — Improve Provider Adapters

> **Priority:** LOW
> **Status:** COMPLETED (2026-03-13)

### 8a. OpenAI adapter tool_call_id (`proxilion/providers/openai_adapter.py`)

**Problem:** `format_assistant_message()` may not include the `id` field in tool call format, which OpenAI requires.

**Fix applied:** Added `uuid` import. In `format_assistant_message()`, changed `"id": tc.id` to `"id": tc.id or str(uuid.uuid4())` so a UUID is generated when the tool call has a falsy id. This ensures the `id` field required by the OpenAI API is always present.

**Files changed:** `proxilion/providers/openai_adapter.py`

### 8b. Gemini protobuf conversion (`proxilion/contrib/google.py`)

**Problem:** `_convert_protobuf_value()` only handles basic types (string, number, bool, struct, list). NoneType, datetime, bytes, and other protobuf types fell through silently, returning the raw protobuf object.

**Fix applied:** Added handlers for: `None` (returns `None`), protobuf `null_value` attribute (returns `None`), native Python types (`str`, `int`, `float`, `bool`), `bytes` (decoded as UTF-8 with replacement), `datetime` (converted to ISO format string), `dict` (recursively converted), and `list`/`tuple` (recursively converted). Unsupported types now raise `TypeError` with a clear message instead of silently returning the raw object. Preserved original attribute check order for compatibility with mock-based tests.

**Files changed:** `proxilion/contrib/google.py`

**All 2,350 tests pass after Step 8 changes (1 pre-existing skip).**

---

## Step 9 — Code Quality Improvements

> **Priority:** LOW
> **Status:** COMPLETED (2026-03-13)

### 9a. DRY violation in contrib/openai.py

**Problem:** `execute()` and `execute_async()` contained ~150 lines of nearly identical logic for: extracting from `function_call` objects, parsing JSON arguments, looking up registered functions, and checking authorization.

**Fix applied:** Extracted shared logic into `_prepare_execution()` which returns either a `(function_name, call_args, func, None)` tuple on success or a `FunctionCallResult` on early failure. Both `execute()` and `execute_async()` now call `_prepare_execution()` first and only contain their respective execution logic (sync with thread pool fallback vs. async with `run_in_executor`).

**Files changed:** `proxilion/contrib/openai.py`

### 9b. Anthropic adapter duplicate methods

**Problem:** `_extract_text_content()` and `_extract_text_content_from_objects()` in `proxilion/providers/anthropic_adapter.py` were near-duplicates differing only in how they accessed block type/text (dict `.get()` vs. `getattr()`).

**Fix applied:** Consolidated logic into `_extract_text_content()` which now handles both dict and object forms by checking `isinstance(block, dict)` for each block. `_extract_text_content_from_objects()` is retained as a thin delegate to `_extract_text_content()` for backward compatibility.

**Files changed:** `proxilion/providers/anthropic_adapter.py`

**All 2,350 tests pass after Step 9 changes (1 pre-existing skip).**

---

## Step 10 — Add Missing Edge Case Tests

> **Priority:** LOW
> **Status:** COMPLETED (2026-03-13)

Added 36 targeted tests in `tests/test_edge_cases_spec.py` covering all fixes from Steps 1-9:

| Test Class | Tests | Covers |
|------------|-------|--------|
| `TestSchedulerPauseResume` | 4 | Step 1a — `_resume_event` exists, pause clears it, resume/shutdown sets it |
| `TestCascadeProtectionBounded` | 3 | Step 2a — `_events` is a deque with maxlen, old events evicted, `get_cascade_events()` returns list |
| `TestStreamingDetectorStaleCleanup` | 3 | Step 2b — stale timeout exists, stale incomplete calls reaped, recent calls kept |
| `TestParameterValidation` | 6 | Step 3a — cascade thresholds, drift thresholds, alert rule window/cooldown, retry policy params |
| `TestPathTraversalDetection` | 2 (9 parametrized + 1) | Step 7a — backslash, URL-encoded backslash/slash, null byte, unicode, double-encoded; safe paths not flagged |
| `TestFallbackErrorReporting` | 4 | Step 5a — raises `FallbackExhaustedError`, chains all causes, noop on success, noop when no exceptions |
| `TestSummarizeCallbackFailover` | 2 | Step 6b — callback failure falls back to sliding window, callback success produces summary |
| `TestRetryDelayClamped` | 4 | Step 5b — delay <= max_delay, delay >= 0, extreme exponent clamped, delay always finite |

**Bonus fix discovered:** `RetryPolicy.calculate_delay()` raised `OverflowError` when `exponential_base ** (attempt - 1)` produced a number too large for float (e.g., `10^998`). The `min()` clamp on the next line never executed because the exponentiation itself overflowed. Added `try/except OverflowError` to catch this and return `max_delay` directly.

**Files changed:** `tests/test_edge_cases_spec.py` (new), `proxilion/resilience/retry.py` (overflow fix)

**All 2,386 tests pass after Step 10 (2,350 existing + 36 new, 1 pre-existing skip).**

---

## Out of Scope

The following were considered but are outside the scope of this improvement cycle:

- New modules or features not already in the codebase
- External service integrations (GitLab, PyPI publishing, hosted docs)
- Breaking API changes
- Performance optimization beyond fixing the busy-wait bugs
- Python 3.9 or earlier support
- Cloud exporter `list_exports()` implementations (require optional deps)

---

## Implementation Order

| Step | Priority | Est. Complexity | Dependencies |
|------|----------|----------------|--------------|
| 1a   | CRITICAL | Low            | None         |
| 1b   | CRITICAL | Low            | None         |
| 1c   | CRITICAL | Low            | None         |
| 2a   | HIGH     | Low            | None         |
| 2b   | HIGH     | Low            | None         |
| 3a   | HIGH     | Low            | None         |
| 3b   | HIGH     | Low            | None         |
| 4a   | MEDIUM   | Low            | None         |
| 4b   | MEDIUM   | Low            | None         |
| 5a   | MEDIUM   | Medium         | None         |
| 5b   | MEDIUM   | Low            | None         |
| 6a   | MEDIUM   | Medium         | None         |
| 6b   | MEDIUM   | Low            | None         |
| 7a   | MEDIUM   | Low            | None         |
| 7b   | MEDIUM   | Low            | None         |
| 8a   | LOW      | Low            | None         |
| 8b   | LOW      | Low            | None         |
| 9a   | LOW      | Medium         | None         |
| 9b   | LOW      | Low            | None         |
| 10   | LOW      | Medium         | Steps 1-9    |

All steps are independent except Step 10 (tests), which should be done after the corresponding fixes.

---

## Next Step

**All 10 steps are complete. Version bumped to 0.0.5. CHANGELOG updated.** This spec is fully implemented. No further action required.
