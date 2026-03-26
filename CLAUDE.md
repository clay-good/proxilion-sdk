# Proxilion SDK

Runtime security SDK for LLM-powered applications. Deterministic pattern matching and rule-based logic for all security decisions. No LLM inference in the security path.

## Quick Commands

- Tests: `python3 -m pytest -x -q`
- Lint: `python3 -m ruff check proxilion tests`
- Format: `python3 -m ruff format proxilion tests`
- Format check: `python3 -m ruff format --check proxilion tests`
- Type check: `python3 -m mypy proxilion`
- Full CI check: `python3 -m ruff check proxilion tests && python3 -m ruff format --check proxilion tests && python3 -m mypy proxilion && python3 -m pytest -x -q`

## Architecture

- `proxilion/core.py` - Main Proxilion class, authorization flow orchestration
- `proxilion/types.py` - Core data types (UserContext, AgentContext, ToolCallRequest, AuthorizationResult, AuditEvent)
- `proxilion/exceptions.py` - Exception hierarchy (all inherit ProxilionError)
- `proxilion/decorators.py` - Standalone decorators (@authorize_tool_call, @rate_limited, @circuit_protected, @require_approval)
- `proxilion/engines/` - Policy engine backends (simple, casbin, OPA)
- `proxilion/policies/` - Policy base class and built-in policies (RoleBasedPolicy, OwnershipPolicy)
- `proxilion/security/` - Rate limiting, circuit breaker, IDOR, intent capsule, memory integrity, agent trust, behavioral drift, cascade protection, sequence validation, scope enforcement, cost limiter
- `proxilion/guards/` - Input guards (prompt injection detection) and output guards (data leakage prevention)
- `proxilion/audit/` - Tamper-evident logging, SHA-256 hash chains, Merkle trees, compliance (SOC2, ISO27001, EU AI Act), cloud exporters (S3, Azure, GCP)
- `proxilion/observability/` - Cost tracking, metrics, Prometheus export, hooks, session cost tracking
- `proxilion/providers/` - LLM provider adapters (OpenAI, Anthropic, Gemini)
- `proxilion/contrib/` - Integration handlers (OpenAI, Anthropic, Google, LangChain, MCP)
- `proxilion/resilience/` - Retry with backoff, fallback chains, graceful degradation
- `proxilion/streaming/` - Streaming response transformer and tool call detection
- `proxilion/context/` - Context window management and session management
- `proxilion/caching/` - Tool call result caching (LRU, LFU, FIFO)
- `proxilion/validation/` - Schema validation with path traversal detection
- `proxilion/timeouts/` - Timeout and deadline management
- `proxilion/scheduling/` - Request scheduling with priority queues

## Conventions

- All security decisions are deterministic (no LLM inference, no ML models)
- Thread safety via `threading.RLock` for shared mutable state
- Raise specific `ProxilionError` subclasses, never bare `except Exception`
- `pytest` with `pytest-asyncio` (`asyncio_mode = "auto"`)
- `ruff` for linting and formatting (`line-length = 100`)
- `mypy` strict mode (`python_version = "3.10"`)
- Keep `pyproject.toml` version and `__init__.py` `__version__` in sync
- Frozen dataclasses for immutable data types (`UserContext`, `AgentContext`, `ToolCallRequest`, `AuthorizationResult`)
- `AuditEvent` uses non-frozen dataclass (hash computed after creation)
- HMAC-SHA256 for cryptographic signing (intent capsules, memory integrity, agent trust)
- SHA-256 hash chains for tamper-evident audit logs

## Test Structure

- `tests/conftest.py` - Shared fixtures (users, agents, schemas, rate limiters, circuit breakers)
- `tests/test_core.py` - Main Proxilion class tests
- `tests/test_guards.py` - Input and output guard tests
- `tests/test_decorators.py` - Decorator tests
- `tests/test_edge_cases_spec.py` - Edge case tests from spec.md
- `tests/test_integrations/` - Provider integration tests (OpenAI, Anthropic, LangChain, MCP)
- 2,669 tests total (2,633 passed, 7 skipped, 29 xfailed), asyncio_mode=auto

## Version

Current: 0.0.8 (synchronized across pyproject.toml and __init__.py)
