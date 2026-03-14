# Contributing to Proxilion

Thank you for your interest in contributing to Proxilion! This document provides
guidelines and instructions for contributing.

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/clay-good/proxilion-sdk.git
   cd proxilion-sdk
   ```

2. Create a virtual environment and install dependencies:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   make dev
   ```

   Or manually:
   ```bash
   pip install -e ".[dev,pydantic]"
   ```

## Running Checks

Before submitting a pull request, make sure all checks pass:

```bash
# Run all tests
make test

# Run linting
make lint

# Run formatting check
ruff format --check proxilion

# Run type checking
make typecheck
```

Or run everything at once:
```bash
make lint && ruff format --check proxilion && make typecheck && make test
```

## Code Style

- **Formatting**: We use [ruff](https://docs.astral.sh/ruff/) for both linting and formatting. Run `make format` to auto-format your code.
- **Type hints**: The project uses `mypy --strict`. All public functions must have complete type annotations.
- **Line length**: Maximum 100 characters.
- **Imports**: Sorted by ruff (isort-compatible). Use `from __future__ import annotations` for forward references.

## Pull Request Process

1. Fork the repository and create a feature branch from `main`.
2. Make your changes with clear, focused commits.
3. Add tests for any new functionality.
4. Ensure all CI checks pass (lint, format, typecheck, tests).
5. Update documentation if you're changing public APIs.
6. Submit a pull request with a clear description of the changes.

## Project Structure

```
proxilion/
├── core.py              # Main Proxilion class
├── decorators.py        # Authorization decorators
├── exceptions.py        # Exception hierarchy
├── types.py             # Shared type definitions
├── audit/               # Tamper-evident logging and compliance
├── caching/             # Tool call result caching
├── context/             # Session and message history management
├── contrib/             # Framework integrations (OpenAI, LangChain, MCP)
├── engines/             # Policy engines (Simple, Casbin, OPA)
├── guards/              # Input/output guards
├── observability/       # Metrics, cost tracking, alerts
├── policies/            # Policy definition and registry
├── providers/           # LLM provider adapters
├── resilience/          # Retry, fallback, degradation
├── scheduling/          # Request priority and scheduling
├── security/            # Rate limiting, circuit breaker, OWASP ASI Top 10
├── streaming/           # Streaming response handling
├── timeouts/            # Deadline and timeout management
├── tools/               # Tool registry and decorators
└── validation/          # Schema validation
```

## Testing Guidelines

- Place tests in the `tests/` directory, mirroring the source structure.
- Use pytest fixtures from `tests/conftest.py` for common objects.
- Use `pytest.mark.asyncio` (or rely on `asyncio_mode = "auto"`) for async tests.
- Aim for clear, focused test cases that test one behavior each.

## Reporting Issues

- Use [GitHub Issues](https://github.com/clay-good/proxilion-sdk/issues) to report bugs or request features.
- Include Python version, OS, and a minimal reproduction case for bug reports.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
