"""
Tests for LangChain integration.

Tests cover:
- ProxilionTool wrapper
- ProxilionCallbackHandler
- wrap_langchain_tools helper
- LangChainUserContextManager
- Context variable management
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest

from proxilion import Proxilion, Policy, UserContext, AgentContext
from proxilion.contrib.langchain import (
    ProxilionTool,
    ProxilionCallbackHandler,
    wrap_langchain_tools,
    LangChainUserContextManager,
    langchain_user_context,
    set_langchain_user,
    get_langchain_user,
    set_langchain_agent,
    get_langchain_agent,
    ToolInvocation,
)
from proxilion.exceptions import AuthorizationError


class TestContextVariables:
    """Tests for context variable management."""

    def test_set_and_get_user(self, basic_user: UserContext):
        """Test setting and getting user context."""
        token = set_langchain_user(basic_user)

        try:
            retrieved = get_langchain_user()
            assert retrieved == basic_user
            assert retrieved.user_id == "user_123"
        finally:
            # Reset for other tests
            from proxilion.contrib.langchain import _langchain_user_context
            _langchain_user_context.reset(token)

    def test_set_and_get_agent(self, basic_agent: AgentContext):
        """Test setting and getting agent context."""
        token = set_langchain_agent(basic_agent)

        try:
            retrieved = get_langchain_agent()
            assert retrieved == basic_agent
            assert retrieved.agent_id == "agent_001"
        finally:
            from proxilion.contrib.langchain import _langchain_agent_context
            _langchain_agent_context.reset(token)

    def test_default_user_is_none(self):
        """Test that default user context is None."""
        user = get_langchain_user()
        assert user is None


class TestProxilionTool:
    """Tests for ProxilionTool wrapper."""

    def test_tool_initialization(self, proxilion_simple: Proxilion):
        """Test tool wrapper initialization."""
        class MockTool:
            name = "calculator"
            description = "Perform calculations"

            def run(self, query):
                return f"Result: {query}"

        wrapped = ProxilionTool(
            original_tool=MockTool(),
            proxilion=proxilion_simple,
        )

        assert wrapped.name == "calculator"
        assert wrapped.description == "Perform calculations"
        assert wrapped.resource == "calculator"

    def test_tool_custom_resource(self, proxilion_simple: Proxilion):
        """Test tool with custom resource name."""
        class MockTool:
            name = "calculator"
            def run(self, query):
                return query

        wrapped = ProxilionTool(
            original_tool=MockTool(),
            proxilion=proxilion_simple,
            resource="math_operations",
        )

        assert wrapped.resource == "math_operations"

    def test_tool_run_with_user(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test running tool with user context."""
        @proxilion_simple.policy("calculator")
        class CalculatorPolicy(Policy):
            def can_execute(self, context):
                return True

        class MockTool:
            name = "calculator"
            def run(self, query):
                return f"Result: {query}"

        wrapped = ProxilionTool(
            original_tool=MockTool(),
            proxilion=proxilion_simple,
        )

        # Set user context
        token = set_langchain_user(basic_user)
        try:
            result = wrapped.run("2 + 2")
            assert result == "Result: 2 + 2"
        finally:
            from proxilion.contrib.langchain import _langchain_user_context
            _langchain_user_context.reset(token)

    def test_tool_run_denied(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test that tool denies unauthorized access."""
        @proxilion_simple.policy("admin_tool")
        class AdminToolPolicy(Policy):
            def can_execute(self, context):
                return "admin" in self.user.roles

        class MockTool:
            name = "admin_tool"
            def run(self, query):
                return "admin result"

        wrapped = ProxilionTool(
            original_tool=MockTool(),
            proxilion=proxilion_simple,
        )

        token = set_langchain_user(basic_user)
        try:
            with pytest.raises(AuthorizationError):
                wrapped.run("query")
        finally:
            from proxilion.contrib.langchain import _langchain_user_context
            _langchain_user_context.reset(token)

    def test_tool_run_no_user_required(self, proxilion_simple: Proxilion):
        """Test tool that doesn't require user context."""
        class MockTool:
            name = "public_tool"
            def run(self, query):
                return f"Public: {query}"

        wrapped = ProxilionTool(
            original_tool=MockTool(),
            proxilion=proxilion_simple,
            require_user=False,
        )

        result = wrapped.run("query")
        assert result == "Public: query"

    def test_tool_run_no_user_raises(self, proxilion_simple: Proxilion):
        """Test that tool raises when user required but missing."""
        class MockTool:
            name = "private_tool"
            def run(self, query):
                return query

        wrapped = ProxilionTool(
            original_tool=MockTool(),
            proxilion=proxilion_simple,
            require_user=True,
        )

        with pytest.raises(AuthorizationError) as exc:
            wrapped.run("query")

        assert "No user context" in str(exc.value)

    @pytest.mark.asyncio
    async def test_tool_arun(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test async tool execution."""
        @proxilion_simple.policy("async_tool")
        class AsyncToolPolicy(Policy):
            def can_execute(self, context):
                return True

        class MockTool:
            name = "async_tool"
            async def arun(self, query):
                return f"Async: {query}"

        wrapped = ProxilionTool(
            original_tool=MockTool(),
            proxilion=proxilion_simple,
        )

        token = set_langchain_user(basic_user)
        try:
            result = await wrapped.arun("test")
            assert result == "Async: test"
        finally:
            from proxilion.contrib.langchain import _langchain_user_context
            _langchain_user_context.reset(token)

    def test_tool_callable(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test calling tool directly."""
        @proxilion_simple.policy("callable_tool")
        class CallableToolPolicy(Policy):
            def can_execute(self, context):
                return True

        class MockTool:
            name = "callable_tool"
            def run(self, query):
                return f"Called: {query}"

        wrapped = ProxilionTool(
            original_tool=MockTool(),
            proxilion=proxilion_simple,
        )

        token = set_langchain_user(basic_user)
        try:
            result = wrapped("direct call")
            assert result == "Called: direct call"
        finally:
            from proxilion.contrib.langchain import _langchain_user_context
            _langchain_user_context.reset(token)


class TestProxilionCallbackHandler:
    """Tests for ProxilionCallbackHandler class."""

    def test_handler_initialization(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test callback handler initialization."""
        handler = ProxilionCallbackHandler(
            proxilion=proxilion_simple,
            user_context=basic_user,
        )

        assert handler.proxilion == proxilion_simple
        assert handler.user_context == basic_user
        assert handler.log_inputs is True
        assert handler.log_outputs is True
        assert handler.block_unauthorized is True

    def test_handler_on_tool_start(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test on_tool_start callback."""
        @proxilion_simple.policy("test_tool")
        class TestToolPolicy(Policy):
            def can_execute(self, context):
                return True

        handler = ProxilionCallbackHandler(
            proxilion=proxilion_simple,
            user_context=basic_user,
        )

        handler.on_tool_start(
            serialized={"name": "test_tool"},
            input_str="test input",
        )

        # Should have started an invocation
        assert handler._current_invocation is not None
        assert handler._current_invocation.tool_name == "test_tool"
        assert handler._current_invocation.input_str == "test input"

    def test_handler_on_tool_end(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test on_tool_end callback."""
        @proxilion_simple.policy("test_tool")
        class TestToolPolicy(Policy):
            def can_execute(self, context):
                return True

        handler = ProxilionCallbackHandler(
            proxilion=proxilion_simple,
            user_context=basic_user,
        )

        handler.on_tool_start(
            serialized={"name": "test_tool"},
            input_str="test input",
        )
        handler.on_tool_end(output="test output")

        assert len(handler.invocations) == 1
        assert handler.invocations[0].tool_name == "test_tool"
        assert handler.invocations[0].output == "test output"

    def test_handler_on_tool_error(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test on_tool_error callback."""
        @proxilion_simple.policy("test_tool")
        class TestToolPolicy(Policy):
            def can_execute(self, context):
                return True

        handler = ProxilionCallbackHandler(
            proxilion=proxilion_simple,
            user_context=basic_user,
        )

        handler.on_tool_start(
            serialized={"name": "test_tool"},
            input_str="test input",
        )
        handler.on_tool_error(error=ValueError("Test error"))

        assert len(handler.invocations) == 1
        assert handler.invocations[0].error == "Test error"

    def test_handler_blocks_unauthorized(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test that handler blocks unauthorized tool calls."""
        @proxilion_simple.policy("restricted_tool")
        class RestrictedPolicy(Policy):
            def can_execute(self, context):
                return "admin" in self.user.roles

        handler = ProxilionCallbackHandler(
            proxilion=proxilion_simple,
            user_context=basic_user,
            block_unauthorized=True,
        )

        with pytest.raises(AuthorizationError):
            handler.on_tool_start(
                serialized={"name": "restricted_tool"},
                input_str="test",
            )

        # Should have recorded the failed invocation
        assert len(handler.invocations) == 1
        assert handler.invocations[0].authorized is False

    def test_handler_redacts_inputs(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test that handler can redact inputs."""
        @proxilion_simple.policy("test_tool")
        class TestToolPolicy(Policy):
            def can_execute(self, context):
                return True

        handler = ProxilionCallbackHandler(
            proxilion=proxilion_simple,
            user_context=basic_user,
            log_inputs=False,
        )

        handler.on_tool_start(
            serialized={"name": "test_tool"},
            input_str="sensitive input",
        )
        handler.on_tool_end(output="output")

        assert handler.invocations[0].input_str == "[REDACTED]"

    def test_handler_redacts_outputs(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test that handler can redact outputs."""
        @proxilion_simple.policy("test_tool")
        class TestToolPolicy(Policy):
            def can_execute(self, context):
                return True

        handler = ProxilionCallbackHandler(
            proxilion=proxilion_simple,
            user_context=basic_user,
            log_outputs=False,
        )

        handler.on_tool_start(
            serialized={"name": "test_tool"},
            input_str="input",
        )
        handler.on_tool_end(output="sensitive output")

        assert handler.invocations[0].output == "[REDACTED]"

    def test_handler_duration_tracking(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test that handler tracks execution duration."""
        import time

        @proxilion_simple.policy("test_tool")
        class TestToolPolicy(Policy):
            def can_execute(self, context):
                return True

        handler = ProxilionCallbackHandler(
            proxilion=proxilion_simple,
            user_context=basic_user,
        )

        handler.on_tool_start(
            serialized={"name": "test_tool"},
            input_str="input",
        )
        time.sleep(0.01)  # Small delay
        handler.on_tool_end(output="output")

        assert handler.invocations[0].duration_ms >= 10


class TestWrapLangchainTools:
    """Tests for wrap_langchain_tools helper function."""

    def test_wrap_multiple_tools(self, proxilion_simple: Proxilion):
        """Test wrapping multiple tools at once."""
        class Tool1:
            name = "tool1"
            description = "First tool"
            def run(self, q): return q

        class Tool2:
            name = "tool2"
            description = "Second tool"
            def run(self, q): return q

        tools = [Tool1(), Tool2()]
        wrapped = wrap_langchain_tools(tools, proxilion_simple)

        assert len(wrapped) == 2
        assert wrapped[0].name == "tool1"
        assert wrapped[1].name == "tool2"

    def test_wrap_with_prefix(self, proxilion_simple: Proxilion):
        """Test wrapping with resource prefix."""
        class Tool:
            name = "calculator"
            def run(self, q): return q

        wrapped = wrap_langchain_tools(
            [Tool()],
            proxilion_simple,
            resource_prefix="agent_",
        )

        assert wrapped[0].resource == "agent_calculator"

    def test_wrap_empty_list(self, proxilion_simple: Proxilion):
        """Test wrapping empty tool list."""
        wrapped = wrap_langchain_tools([], proxilion_simple)
        assert len(wrapped) == 0


class TestLangChainUserContextManager:
    """Tests for LangChainUserContextManager."""

    def test_context_manager_basic(self, basic_user: UserContext):
        """Test basic context manager usage."""
        with LangChainUserContextManager(basic_user):
            user = get_langchain_user()
            assert user == basic_user

        # After exiting, should be reset
        assert get_langchain_user() is None

    def test_context_manager_with_agent(
        self, basic_user: UserContext, basic_agent: AgentContext
    ):
        """Test context manager with agent context."""
        with LangChainUserContextManager(basic_user, basic_agent):
            user = get_langchain_user()
            agent = get_langchain_agent()
            assert user == basic_user
            assert agent == basic_agent

        assert get_langchain_user() is None
        assert get_langchain_agent() is None

    def test_langchain_user_context_decorator(
        self, proxilion_simple: Proxilion, basic_user: UserContext
    ):
        """Test langchain_user_context as context manager."""
        @proxilion_simple.policy("tool")
        class ToolPolicy(Policy):
            def can_execute(self, context):
                return True

        class Tool:
            name = "tool"
            def run(self, q): return q

        wrapped = ProxilionTool(
            original_tool=Tool(),
            proxilion=proxilion_simple,
        )

        with langchain_user_context(basic_user):
            result = wrapped.run("test")
            assert result == "test"


class TestToolInvocation:
    """Tests for ToolInvocation dataclass."""

    def test_invocation_creation(self):
        """Test creating a tool invocation record."""
        invocation = ToolInvocation(
            tool_name="test_tool",
            input_str="test input",
            user_id="user_123",
        )

        assert invocation.tool_name == "test_tool"
        assert invocation.input_str == "test input"
        assert invocation.user_id == "user_123"
        assert invocation.timestamp is not None
        assert invocation.authorized is False

    def test_invocation_with_output(self):
        """Test invocation with output and error."""
        invocation = ToolInvocation(
            tool_name="test_tool",
            input_str="input",
            user_id="user_123",
            authorized=True,
            output="success",
            duration_ms=50.5,
        )

        assert invocation.authorized is True
        assert invocation.output == "success"
        assert invocation.duration_ms == 50.5
        assert invocation.error is None
