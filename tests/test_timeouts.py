"""Tests for timeout and deadline management."""

from __future__ import annotations

import asyncio
import time
import threading
from typing import Any

import pytest

from proxilion.timeouts.manager import (
    DeadlineContext,
    TimeoutConfig,
    TimeoutError,
    TimeoutManager,
    get_current_deadline,
    get_default_manager,
    set_default_manager,
)
from proxilion.timeouts.decorators import (
    TimeoutScope,
    run_with_deadline,
    run_with_timeout,
    with_deadline,
    with_timeout,
)


class TestTimeoutConfig:
    """Tests for TimeoutConfig dataclass."""

    def test_default_values(self):
        """Test default configuration values."""
        config = TimeoutConfig()
        assert config.default_timeout == 30.0
        assert config.llm_timeout == 120.0
        assert config.total_request_timeout == 300.0
        assert config.warn_at_percent == 80.0
        assert config.tool_timeouts == {}

    def test_custom_values(self):
        """Test custom configuration."""
        config = TimeoutConfig(
            default_timeout=10.0,
            tool_timeouts={"search": 60.0, "db": 5.0},
            llm_timeout=90.0,
        )
        assert config.default_timeout == 10.0
        assert config.tool_timeouts["search"] == 60.0
        assert config.llm_timeout == 90.0

    def test_get_timeout_with_override(self):
        """Get timeout for tool with specific override."""
        config = TimeoutConfig(
            default_timeout=30.0,
            tool_timeouts={"web_search": 60.0},
        )
        assert config.get_timeout("web_search") == 60.0

    def test_get_timeout_uses_default(self):
        """Get timeout falls back to default."""
        config = TimeoutConfig(default_timeout=30.0)
        assert config.get_timeout("unknown_tool") == 30.0

    def test_set_tool_timeout(self):
        """Set timeout for specific tool."""
        config = TimeoutConfig()
        config.set_tool_timeout("new_tool", 15.0)
        assert config.get_timeout("new_tool") == 15.0

    def test_to_dict(self):
        """Serialize config to dict."""
        config = TimeoutConfig(
            default_timeout=20.0,
            tool_timeouts={"api": 45.0},
        )
        data = config.to_dict()
        assert data["default_timeout"] == 20.0
        assert data["tool_timeouts"]["api"] == 45.0

    def test_from_dict(self):
        """Deserialize config from dict."""
        data = {
            "default_timeout": 25.0,
            "llm_timeout": 100.0,
            "tool_timeouts": {"search": 50.0},
        }
        config = TimeoutConfig.from_dict(data)
        assert config.default_timeout == 25.0
        assert config.llm_timeout == 100.0
        assert config.get_timeout("search") == 50.0


class TestDeadlineContext:
    """Tests for DeadlineContext class."""

    def test_basic_context(self):
        """Basic deadline context usage."""
        with DeadlineContext(timeout=5.0) as deadline:
            assert deadline.remaining() > 0
            assert deadline.remaining() <= 5.0
            assert not deadline.is_expired()

    def test_elapsed_time(self):
        """Track elapsed time."""
        with DeadlineContext(timeout=10.0) as deadline:
            time.sleep(0.1)
            elapsed = deadline.elapsed()
            assert 0.05 < elapsed < 0.3

    def test_is_expired(self):
        """Check expiration."""
        with DeadlineContext(timeout=0.1) as deadline:
            time.sleep(0.15)
            assert deadline.is_expired()

    def test_remaining_raises_when_expired(self):
        """Remaining raises TimeoutError when expired."""
        with DeadlineContext(timeout=0.05) as deadline:
            time.sleep(0.1)
            with pytest.raises(TimeoutError) as exc_info:
                deadline.remaining()
            assert "exceeded" in str(exc_info.value).lower()

    def test_remaining_or_default(self):
        """Get remaining or default value."""
        with DeadlineContext(timeout=0.05, raise_on_expire=True) as deadline:
            time.sleep(0.1)
            result = deadline.remaining_or_default(0.0)
            assert result == 0.0

    def test_check_raises_when_expired(self):
        """Check method raises when expired."""
        with DeadlineContext(timeout=0.05) as deadline:
            time.sleep(0.1)
            with pytest.raises(TimeoutError):
                deadline.check()

    def test_get_timeout_for_operation(self):
        """Get effective timeout for sub-operation."""
        with DeadlineContext(timeout=5.0) as deadline:
            effective = deadline.get_timeout_for_operation(10.0)
            # Should be capped at remaining deadline (with small tolerance for timing)
            assert effective < 10.0
            # Allow small timing tolerance
            assert effective <= 5.0

    def test_no_raise_on_expire(self):
        """Test raise_on_expire=False."""
        with DeadlineContext(timeout=0.05, raise_on_expire=False) as deadline:
            time.sleep(0.1)
            # Should not raise
            result = deadline.remaining()
            assert result == 0.0

    def test_nested_deadlines(self):
        """Nested deadline uses shorter timeout."""
        with DeadlineContext(timeout=5.0) as outer:
            with DeadlineContext(timeout=10.0) as inner:
                # Inner deadline should be capped by outer
                assert inner.deadline <= outer.deadline

    def test_nested_deadline_respects_parent(self):
        """Inner deadline cannot exceed outer."""
        with DeadlineContext(timeout=2.0) as outer:
            time.sleep(0.5)
            with DeadlineContext(timeout=5.0) as inner:
                # Inner should have at most ~1.5s remaining
                assert inner.remaining() < 2.0

    def test_context_variable_set(self):
        """Context variable is set during execution."""
        assert get_current_deadline() is None
        with DeadlineContext(timeout=5.0) as deadline:
            current = get_current_deadline()
            assert current is deadline
        assert get_current_deadline() is None

    def test_operation_name_in_error(self):
        """Operation name included in error."""
        with DeadlineContext(timeout=0.05, operation="test_op") as deadline:
            time.sleep(0.1)
            with pytest.raises(TimeoutError) as exc_info:
                deadline.remaining()
            assert "test_op" in str(exc_info.value)


class TestDeadlineContextAsync:
    """Async tests for DeadlineContext."""

    @pytest.mark.asyncio
    async def test_async_context(self):
        """Async context manager usage."""
        async with DeadlineContext(timeout=5.0) as deadline:
            assert deadline.remaining() > 0

    @pytest.mark.asyncio
    async def test_async_elapsed(self):
        """Track elapsed time in async context."""
        async with DeadlineContext(timeout=10.0) as deadline:
            await asyncio.sleep(0.1)
            elapsed = deadline.elapsed()
            assert 0.05 < elapsed < 0.3

    @pytest.mark.asyncio
    async def test_async_nested(self):
        """Nested async deadline contexts."""
        async with DeadlineContext(timeout=5.0) as outer:
            async with DeadlineContext(timeout=10.0) as inner:
                assert inner.deadline <= outer.deadline


class TestTimeoutManager:
    """Tests for TimeoutManager class."""

    def test_create_with_default_config(self):
        """Create manager with default config."""
        manager = TimeoutManager()
        assert manager.get_timeout("any") == 30.0

    def test_create_with_custom_config(self):
        """Create manager with custom config."""
        config = TimeoutConfig(default_timeout=15.0)
        manager = TimeoutManager(config)
        assert manager.get_timeout("any") == 15.0

    def test_get_timeout(self):
        """Get timeout for operation."""
        config = TimeoutConfig(
            default_timeout=10.0,
            tool_timeouts={"special": 20.0},
        )
        manager = TimeoutManager(config)
        assert manager.get_timeout("special") == 20.0
        assert manager.get_timeout("other") == 10.0

    def test_get_llm_timeout(self):
        """Get LLM timeout."""
        config = TimeoutConfig(llm_timeout=90.0)
        manager = TimeoutManager(config)
        assert manager.get_llm_timeout() == 90.0

    def test_set_tool_timeout(self):
        """Dynamically set tool timeout."""
        manager = TimeoutManager()
        manager.set_tool_timeout("dynamic", 45.0)
        assert manager.get_timeout("dynamic") == 45.0

    def test_create_deadline(self):
        """Create deadline context."""
        manager = TimeoutManager()
        deadline = manager.create_deadline(timeout=10.0)
        assert deadline.timeout == 10.0

    def test_create_deadline_uses_total_request_timeout(self):
        """Create deadline uses total_request_timeout as default."""
        config = TimeoutConfig(total_request_timeout=120.0)
        manager = TimeoutManager(config)
        deadline = manager.create_deadline()
        assert deadline.timeout == 120.0

    def test_create_tool_deadline(self):
        """Create tool-specific deadline."""
        config = TimeoutConfig(tool_timeouts={"search": 60.0})
        manager = TimeoutManager(config)
        deadline = manager.create_tool_deadline("search")
        assert deadline.timeout == 60.0

    def test_create_llm_deadline(self):
        """Create LLM deadline."""
        config = TimeoutConfig(llm_timeout=90.0)
        manager = TimeoutManager(config)
        deadline = manager.create_llm_deadline()
        assert deadline.timeout == 90.0

    def test_get_effective_timeout_no_deadline(self):
        """Get effective timeout without active deadline."""
        config = TimeoutConfig(default_timeout=30.0)
        manager = TimeoutManager(config)
        assert manager.get_effective_timeout("op") == 30.0

    def test_get_effective_timeout_with_deadline(self):
        """Get effective timeout with active deadline."""
        manager = TimeoutManager()
        with DeadlineContext(timeout=5.0):
            effective = manager.get_effective_timeout("op", 30.0)
            assert effective < 30.0

    def test_deadline_context_manager(self):
        """Use deadline_context context manager."""
        manager = TimeoutManager()
        with manager.deadline_context(timeout=5.0) as deadline:
            assert deadline.remaining() <= 5.0

    def test_serialization_roundtrip(self):
        """Test to_dict and from_dict."""
        config = TimeoutConfig(
            default_timeout=25.0,
            tool_timeouts={"api": 45.0},
        )
        manager = TimeoutManager(config)

        data = manager.to_dict()
        restored = TimeoutManager.from_dict(data)

        assert restored.get_timeout("api") == 45.0
        assert restored.get_timeout("other") == 25.0


class TestWithTimeoutDecorator:
    """Tests for @with_timeout decorator."""

    @pytest.mark.asyncio
    async def test_async_function_completes(self):
        """Async function completes within timeout."""
        @with_timeout(5.0)
        async def fast_op():
            await asyncio.sleep(0.1)
            return "done"

        result = await fast_op()
        assert result == "done"

    @pytest.mark.asyncio
    async def test_async_function_times_out(self):
        """Async function raises on timeout."""
        @with_timeout(0.1)
        async def slow_op():
            await asyncio.sleep(1.0)
            return "done"

        with pytest.raises(TimeoutError):
            await slow_op()

    def test_sync_function_completes(self):
        """Sync function completes within timeout."""
        @with_timeout(5.0)
        def fast_op():
            time.sleep(0.1)
            return "done"

        result = fast_op()
        assert result == "done"

    def test_sync_function_times_out(self):
        """Sync function raises on timeout."""
        @with_timeout(0.1)
        def slow_op():
            time.sleep(1.0)
            return "done"

        with pytest.raises(TimeoutError):
            slow_op()

    @pytest.mark.asyncio
    async def test_respects_deadline(self):
        """Decorator respects active deadline."""
        @with_timeout(10.0, use_deadline=True)
        async def op():
            await asyncio.sleep(0.1)
            return "done"

        async with DeadlineContext(timeout=0.05):
            with pytest.raises(TimeoutError):
                await op()

    def test_custom_operation_name(self):
        """Error includes custom operation name."""
        @with_timeout(0.05, operation_name="my_operation")
        def slow():
            time.sleep(0.2)

        with pytest.raises(TimeoutError) as exc_info:
            slow()
        assert "my_operation" in str(exc_info.value)


class TestWithDeadlineDecorator:
    """Tests for @with_deadline decorator."""

    @pytest.mark.asyncio
    async def test_creates_deadline_context(self):
        """Decorator creates deadline context."""
        deadline_seen = None

        @with_deadline(5.0)
        async def op():
            nonlocal deadline_seen
            deadline_seen = get_current_deadline()
            return "done"

        await op()
        assert deadline_seen is not None

    @pytest.mark.asyncio
    async def test_async_completes(self):
        """Async function completes within deadline."""
        @with_deadline(5.0)
        async def fast_op():
            await asyncio.sleep(0.1)
            return "done"

        result = await fast_op()
        assert result == "done"

    @pytest.mark.asyncio
    async def test_async_times_out(self):
        """Async function raises on deadline exceeded."""
        @with_deadline(0.1)
        async def slow_op():
            await asyncio.sleep(1.0)
            return "done"

        with pytest.raises(TimeoutError):
            await slow_op()

    def test_sync_completes(self):
        """Sync function completes within deadline."""
        @with_deadline(5.0)
        def fast_op():
            time.sleep(0.1)
            return "done"

        result = fast_op()
        assert result == "done"

    def test_sync_times_out(self):
        """Sync function raises on deadline exceeded."""
        @with_deadline(0.1)
        def slow_op():
            time.sleep(1.0)
            return "done"

        with pytest.raises(TimeoutError):
            slow_op()


class TestRunWithTimeout:
    """Tests for run_with_timeout function."""

    @pytest.mark.asyncio
    async def test_completes(self):
        """Coroutine completes within timeout."""
        async def fast():
            await asyncio.sleep(0.1)
            return "done"

        result = await run_with_timeout(fast(), timeout=5.0)
        assert result == "done"

    @pytest.mark.asyncio
    async def test_times_out(self):
        """Coroutine raises on timeout."""
        async def slow():
            await asyncio.sleep(1.0)
            return "done"

        with pytest.raises(TimeoutError):
            await run_with_timeout(slow(), timeout=0.1)

    @pytest.mark.asyncio
    async def test_operation_name_in_error(self):
        """Operation name in error message."""
        async def slow():
            await asyncio.sleep(1.0)

        with pytest.raises(TimeoutError) as exc_info:
            await run_with_timeout(slow(), timeout=0.05, operation_name="test_op")
        assert "test_op" in str(exc_info.value)


class TestRunWithDeadline:
    """Tests for run_with_deadline function."""

    @pytest.mark.asyncio
    async def test_completes_within_deadline(self):
        """Coroutine completes within deadline."""
        async def fast():
            await asyncio.sleep(0.1)
            return "done"

        async with DeadlineContext(timeout=5.0) as deadline:
            result = await run_with_deadline(fast(), deadline)
        assert result == "done"

    @pytest.mark.asyncio
    async def test_exceeds_deadline(self):
        """Coroutine raises when deadline exceeded."""
        async def slow():
            await asyncio.sleep(1.0)
            return "done"

        async with DeadlineContext(timeout=0.1) as deadline:
            with pytest.raises(TimeoutError):
                await run_with_deadline(slow(), deadline)


class TestTimeoutScope:
    """Tests for TimeoutScope class."""

    @pytest.mark.asyncio
    async def test_basic_scope(self):
        """Basic timeout scope usage."""
        async with TimeoutScope(5.0) as scope:
            assert scope.remaining() > 0

    @pytest.mark.asyncio
    async def test_run_operations(self):
        """Run operations with scope."""
        async def op1():
            await asyncio.sleep(0.05)
            return "result1"

        async def op2():
            await asyncio.sleep(0.05)
            return "result2"

        async with TimeoutScope(5.0) as scope:
            r1 = await scope.run("op1", op1())
            r2 = await scope.run("op2", op2())

        assert r1 == "result1"
        assert r2 == "result2"

    @pytest.mark.asyncio
    async def test_checkpoints(self):
        """Record checkpoints."""
        async def op():
            await asyncio.sleep(0.05)
            return "done"

        async with TimeoutScope(5.0) as scope:
            await scope.run("operation", op())

        checkpoints = scope.get_checkpoints()
        assert len(checkpoints) >= 2
        names = [c[0] for c in checkpoints]
        assert "operation_start" in names
        assert "operation_end" in names

    @pytest.mark.asyncio
    async def test_elapsed_tracking(self):
        """Track elapsed time."""
        async with TimeoutScope(5.0) as scope:
            await asyncio.sleep(0.1)
            elapsed = scope.elapsed()
            assert 0.05 < elapsed < 0.3

    def test_sync_scope(self):
        """Synchronous scope usage."""
        def op():
            time.sleep(0.05)
            return "done"

        with TimeoutScope(5.0) as scope:
            result = scope.run_sync("op", op)
        assert result == "done"

    @pytest.mark.asyncio
    async def test_scope_timeout(self):
        """Scope raises on timeout."""
        async def slow():
            await asyncio.sleep(1.0)
            return "done"

        async with TimeoutScope(0.1) as scope:
            with pytest.raises(TimeoutError):
                await scope.run("slow", slow())


class TestDefaultManager:
    """Tests for default manager functions."""

    def test_get_default_manager(self):
        """Get default manager creates one if needed."""
        manager = get_default_manager()
        assert manager is not None
        assert isinstance(manager, TimeoutManager)

    def test_set_default_manager(self):
        """Set custom default manager."""
        custom = TimeoutManager(TimeoutConfig(default_timeout=99.0))
        set_default_manager(custom)
        assert get_default_manager().get_timeout("any") == 99.0
        # Reset
        set_default_manager(TimeoutManager())


class TestTimeoutError:
    """Tests for TimeoutError exception."""

    def test_basic_error(self):
        """Basic error creation."""
        error = TimeoutError("Test timeout")
        assert "Test timeout" in str(error)

    def test_error_with_details(self):
        """Error with all details."""
        error = TimeoutError(
            message="Operation timed out",
            operation="test_op",
            timeout=5.0,
            elapsed=5.5,
        )
        error_str = str(error)
        assert "Operation timed out" in error_str
        assert "test_op" in error_str
        assert "5.0" in error_str

    def test_error_attributes(self):
        """Error attributes accessible."""
        error = TimeoutError(
            message="test",
            operation="op",
            timeout=10.0,
            elapsed=12.0,
        )
        assert error.operation == "op"
        assert error.timeout == 10.0
        assert error.elapsed == 12.0


class TestThreadSafety:
    """Thread safety tests."""

    def test_concurrent_deadline_contexts(self):
        """Concurrent deadline contexts are isolated."""
        results = []
        errors = []

        def worker(worker_id: int, timeout: float):
            try:
                with DeadlineContext(timeout=timeout) as deadline:
                    time.sleep(0.05)
                    results.append((worker_id, deadline.remaining()))
            except Exception as e:
                errors.append((worker_id, e))

        threads = [
            threading.Thread(target=worker, args=(i, i + 1))
            for i in range(5)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(results) == 5

    def test_manager_thread_safety(self):
        """Manager operations are thread-safe."""
        manager = TimeoutManager()
        errors = []

        def reader():
            for _ in range(100):
                try:
                    manager.get_timeout("test")
                    manager.get_llm_timeout()
                except Exception as e:
                    errors.append(e)

        def writer():
            for i in range(100):
                try:
                    manager.set_tool_timeout(f"tool_{i}", float(i))
                except Exception as e:
                    errors.append(e)

        threads = [
            threading.Thread(target=reader),
            threading.Thread(target=writer),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
