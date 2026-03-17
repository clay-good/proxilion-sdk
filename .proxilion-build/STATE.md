# proxilion-build STATE

## Current Status

| Metric | Value |
|--------|-------|
| Version | 0.0.7 |
| Tests passing | 2,354 sync tests passing, 6 skipped (OPA optional deps), async tests skipped (pytest-asyncio not in Python 3.14 env) |
| Ruff violations | 0 |
| Mypy errors | 0 |
| Active branch | proxilion-build/spec-v2-clean |

## Specs

| Spec | Version | Status |
|------|---------|--------|
| docs/specs/spec.md | 0.0.4 → 0.0.5 | ALL COMPLETE (10/10 steps) |
| docs/specs/spec-v1.md | 0.0.6 → 0.0.7 | ALL COMPLETE (15/15 steps) |
| docs/specs/spec-v2.md | 0.0.7 → 0.0.8 | IN PROGRESS (6/18 steps complete) |

## spec-v2.md Progress

| Step | Priority | Description | Status |
|------|----------|-------------|--------|
| 1 | HIGH | Fix mypy errors in pydantic_schema.py | DONE (pre-existing) |
| 2 | HIGH | Narrow broad exception catches in security modules | DONE |
| 3 | HIGH | Fix MemoryIntegrityChecker → MemoryIntegrityGuard in docs | DONE |
| 4 | MEDIUM | Add Python 3.13 classifier | DONE |
| 5 | MEDIUM | Add structured error context to security exceptions | DONE |
| 6 | MEDIUM | Add tests for structured exception context | DONE |
| 7 | MEDIUM | Wire structured exception context to raise sites | DONE |
| 8 | HIGH | Add integration test for full authorization pipeline | TODO |
| 9 | MEDIUM | Add performance benchmark suite | TODO |
| 10 | HIGH | Add negative test cases for input guard bypass attempts | TODO |
| 11 | HIGH | Harden input guard against case-insensitive evasion | TODO |
| 12 | MEDIUM | Add sample data generator script | TODO |
| 13 | MEDIUM | Add comprehensive docstrings to public API surface | TODO |
| 14 | MEDIUM | Update quickstart to cover all 9 decorators | TODO |
| 15 | MEDIUM | Add missing decorator combination tests | TODO |
| 16 | LOW | Lint and type-check all test files | TODO |
| 17 | LOW | Update CHANGELOG, version, and documentation | TODO |
| 18 | LOW | Final validation and README mermaid diagrams | TODO |

## Last Updated

2026-03-17 — Completed spec-v2 Step 7: Wired structured exception context to all raise sites. Updated rate_limiter.py (3 sites), decorators.py (6 sites), core.py (2 sites), and intent_capsule.py (2 sites) to pass structured fields (user_id, limit, current_count, input_preview, tool_name, allowed_tools, etc.) to exceptions.
