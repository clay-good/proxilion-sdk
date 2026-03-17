# Changelog

All notable changes to the Proxilion SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.7] - 2026-03-14

### Added
- **Secret key validation**: `IntentCapsule`, `MemoryIntegrityGuard`, and `AgentTrustManager` now require secret keys ≥ 16 characters and warn on placeholder patterns
- **Test coverage**: New test modules for hash chain internals (`test_hash_chain_detailed.py`), built-in policies (`test_builtin_policies.py`), policy engine mocks (`test_engines_mocked.py`), and thread safety (`test_thread_safety.py`)
- **Integration test fixtures**: `tests/fixtures/` package with shared `UserContext`, `ToolCallRequest`, and provider response objects
- **Security regression tests**: `test_security_regression.py` covering OWASP ASI01-ASI10 attack vectors (prompt injection, tool misuse, data exfiltration, IDOR, replay, privilege escalation, intent hijacking, cascade failure, DoS, supply chain)
- **Feature documentation**: Six new `docs/features/` files covering input guards, output guards, rate limiting, audit logging, security controls, and observability
- **Decorator API docs**: New quickstart section for `@authorize_tool_call`, `@rate_limited`, `@circuit_protected`, `@require_approval`
- **CI hardening**: Python 3.13 in test matrix, `--cov-fail-under=85` coverage threshold, `pip-audit` security scanning, `tests/` included in ruff scope, `[dev,all]` extras for typecheck job
- **Scheduler graceful shutdown**: `RequestScheduler.shutdown()` now accepts `timeout: float = 5.0` parameter and logs a warning if workers do not stop within the deadline
- **Audit log hardening**: `AuditLogger` uses `fcntl.LOCK_EX` (Unix) for concurrent multi-process write safety and flushes after every event

### Fixed
- **Version drift**: Synchronized `proxilion/__init__.py` `__version__` to `0.0.6` (from `0.0.5`)
- **Stale mypy type-ignore comments**: Removed 13 unused `# type: ignore[import-not-found]` annotations from optional-import try/except blocks
- **Ruff violations in test files**: Fixed `B007` (unused loop variables), `F841` (unused assignments), `C408` (dict() literals), `N806` (class names in function scope), `I001` (import sorting), `F401` (unused imports), and `E501` (line length) across 12 test files

### Changed
- **CLAUDE.md**: Updated version note to reflect synchronized 0.0.6 state
- **README.md**: Updated secret key examples to use `prx_sk_a1b2c3d4e5f6g7h8` pattern with production guidance

## [0.0.5] - 2026-03-13

### Fixed
- **Scheduler busy-wait deadlock**: Replaced `while`/`pass` spin loop with `threading.Event` for pause/resume, eliminating 100% CPU usage and lock contention
- **Sync timeout thread leak**: Added `shutdown(wait=False)` and warning log when sync timeouts fire, documenting the Python thread limitation
- **QueueApprovalStrategy polling**: Replaced `time.sleep(0.1)` loop with `threading.Event.wait()` (sync) and `asyncio.wait_for()` (async)
- **Cascade protection memory leak**: Changed `_events` from unbounded `list` to `deque(maxlen=max_events)` with automatic eviction
- **Streaming detector memory leak**: Added `_stale_timeout_seconds` to reap incomplete partial calls abandoned mid-stream
- **Broad exception catch in simple engine**: Narrowed `except Exception` to `except PolicyNotFoundError`
- **Streaming chunk validation**: Added type checks in `process_chunk()` for `None` and unsupported primitive types
- **Empty chunk propagation**: Added empty-string filtering in all four transformer filter-application sites
- **Summarize callback errors**: Wrapped `summarize_callback()` in try/except with fallback to `SlidingWindowStrategy`
- **Retry delay overflow**: Added `try/except OverflowError` in `calculate_delay()` for extreme exponential backoff values
- **OpenAI tool_call_id missing**: `format_assistant_message()` now generates a UUID fallback when `tc.id` is falsy
- **Gemini protobuf silent fallthrough**: `_convert_protobuf_value()` now handles `None`, `bytes`, `datetime`, `dict`, `list`/`tuple`, and raises `TypeError` for unsupported types

### Added
- Input validation on `CascadeProtector` thresholds (`degraded_threshold`, `failing_threshold`, `max_events` >= 1)
- Input validation on `DriftDetector` thresholds (0.0-1.0 range)
- Input validation on `AlertRule` (`window_seconds` > 0, `cooldown_seconds` >= 0)
- Path traversal detection for backslash variants (`..\`), URL-encoded slashes (`%2e%2e%5c`, `%2e%2e%2f`), and null byte injection (`\x00`, `%00`)
- Configurable `exclude_params` parameter on `create_schema_from_function()` with expanded defaults (`agent`, `session`, `request`)
- `FallbackExhaustedError` exception with `raise_on_failure()` method that chains all errors via `__cause__`
- Configurable `token_estimator` parameter on `MessageHistory` with `Message.recount_tokens()` method
- 36 targeted edge-case tests in `tests/test_edge_cases_spec.py`

### Changed
- `_prepare_execution()` extracted in OpenAI contrib to DRY up `execute()` / `execute_async()` (~80 lines removed)
- Anthropic adapter `_extract_text_content()` consolidated to handle both dict and object forms; `_extract_text_content_from_objects()` retained as delegate

## [0.0.4] - 2026-03-11

### Added
- LangChain integration (`proxilion.contrib.langchain`) with tool wrapping and user context management
- Guardrail decorators (`@authorize_tool_call`, `@require_approval`, `@rate_limited`, etc.)
- Full package exports in `__init__.py` for all public APIs
- 430+ security and decorator tests
- CI/CD pipeline with lint, typecheck, and test jobs
- MCP client validation

### Changed
- Improved cost scoping and validation
- Refactored MCP permissions and audit logging
- Fixed sequence validation and event loop handling

### Fixed
- Async timing issues in decorator wrappers
- Documentation accuracy for all code examples

## [0.0.3] - 2026-03-10

### Added
- OWASP ASI Top 10 security protections:
  - Intent capsule validation
  - Memory integrity guard with RAG document scanning
  - Agent trust manager with delegation chains
  - Behavioral drift detection with kill switch
  - Cascade protection for nested agent calls
- Cloud audit exporters (AWS S3, Azure Blob Storage, GCP Cloud Storage)
- Compliance frameworks (SOC 2, ISO 27001, EU AI Act)
- Streaming response transformer with tool call detection
- Cost tracking and budget enforcement
- Prometheus metrics exporter
- Pydantic schema validation support
- Provider adapters for OpenAI, Anthropic, and Gemini
- Resilience patterns (retry, fallback, graceful degradation)
- Request scheduling with priority queues
- Timeout and deadline management

### Changed
- Improved input/output guard detection patterns
- Enhanced circuit breaker with half-open state support

### Fixed
- Authorization bypasses in capability matching
- Thread-safety races in rate limiter and session management
- Memory leaks in context window tracking
- TOCTOU vulnerability in memory integrity checks

## [0.0.2] - 2026-03-09

### Added
- Policy-based authorization engine with simple, Casbin, and OPA backends
- Input guards for prompt injection detection
- Output guards for data leakage prevention
- IDOR protection with scope-based validation
- Rate limiting (token bucket, sliding window, multi-dimensional)
- Circuit breaker pattern
- Sequence validation for tool call ordering
- Tamper-evident audit logging with hash chains
- Schema validation for tool parameters

### Fixed
- Security vulnerabilities in core authorization flow
- Division-by-zero in cost calculations
- Broken links in documentation

## [0.0.1] - 2026-03-08

### Added
- Initial release
- Core `Proxilion` class with tool call authorization
- `UserContext` and `AgentContext` data models
- Simple policy engine
- Basic audit event logging
