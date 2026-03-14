"""
Additional tests for provider adapter classes.

Covers edge cases, object-form responses, format conversions,
error handling paths, and helper methods not exercised in test_providers.py.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from proxilion.providers.adapter import (
    BaseAdapter,
    Provider,
    ProviderAdapter,
    UnifiedResponse,
    UnifiedToolCall,
    UnifiedToolResult,
    detect_provider,
    detect_provider_safe,
)
from proxilion.providers.openai_adapter import OpenAIAdapter
from proxilion.providers.anthropic_adapter import AnthropicAdapter
from proxilion.providers.gemini_adapter import GeminiAdapter


# ---------------------------------------------------------------------------
# Helpers & Fixtures
# ---------------------------------------------------------------------------

@dataclass
class FakeFunction:
    name: str
    arguments: str


@dataclass
class FakeToolCall:
    id: str
    function: FakeFunction


@dataclass
class FakeChoice:
    message: Any
    finish_reason: str | None = None


@dataclass
class FakeMessage:
    content: str | None = None
    tool_calls: list | None = None


@dataclass
class FakeUsage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


@dataclass
class FakeOpenAIResponse:
    choices: list[FakeChoice]
    usage: FakeUsage | None = None


@dataclass
class FakeContentBlock:
    type: str
    text: str = ""
    id: str = ""
    name: str = ""
    input: dict | None = None


@dataclass
class FakeAnthropicUsage:
    input_tokens: int = 0
    output_tokens: int = 0


@dataclass
class FakeAnthropicResponse:
    content: list[FakeContentBlock]
    stop_reason: str | None = None
    usage: FakeAnthropicUsage | None = None


@dataclass
class FakePart:
    text: str | None = None
    function_call: Any = None


@dataclass
class FakeGeminiContent:
    parts: list[FakePart]


@dataclass
class FakeCandidate:
    content: FakeGeminiContent
    finish_reason: str | None = None


@dataclass
class FakeUsageMetadata:
    prompt_token_count: int = 0
    candidates_token_count: int = 0
    total_token_count: int = 0


@dataclass
class FakeGeminiResponse:
    candidates: list[FakeCandidate]
    usage_metadata: FakeUsageMetadata | None = None


@dataclass
class FakeGeminiFunctionCall:
    name: str
    args: dict


@pytest.fixture
def openai_adapter():
    return OpenAIAdapter()


@pytest.fixture
def anthropic_adapter():
    return AnthropicAdapter()


@pytest.fixture
def gemini_adapter():
    return GeminiAdapter()


def _make_unified_call(id_="tc_1", name="my_tool", args=None):
    return UnifiedToolCall(id=id_, name=name, arguments=args or {})


# ---------------------------------------------------------------------------
# UnifiedToolCall additional edge-case tests
# ---------------------------------------------------------------------------

class TestUnifiedToolCallEdgeCases:

    def test_from_openai_object_no_function(self):
        obj = MagicMock(spec=[])
        call = UnifiedToolCall.from_openai(obj)
        assert call.name == "unknown"
        assert call.arguments == {}

    def test_from_openai_dict_missing_keys(self):
        call = UnifiedToolCall.from_openai({})
        assert call.name == "unknown"
        assert call.arguments == {}
        assert call.provider == Provider.OPENAI

    def test_from_openai_arguments_already_dict(self):
        openai_call = {
            "id": "c1",
            "function": {"name": "fn", "arguments": {"pre": "parsed"}},
        }
        call = UnifiedToolCall.from_openai(openai_call)
        assert call.arguments == {"pre": "parsed"}

    def test_from_openai_arguments_none(self):
        openai_call = {"id": "c1", "function": {"name": "fn", "arguments": None}}
        call = UnifiedToolCall.from_openai(openai_call)
        assert call.arguments == {}

    def test_from_anthropic_non_dict_input(self):
        block = MagicMock()
        block.id = "t1"
        block.name = "tool"
        block.input = "not a dict"
        call = UnifiedToolCall.from_anthropic(block)
        assert call.arguments == {}

    def test_from_gemini_object_with_plain_dict_args(self):
        obj = MagicMock(spec=["name", "args"])
        obj.name = "fn"
        obj.args = {"k": "v"}
        call = UnifiedToolCall.from_gemini(obj)
        assert call.arguments == {"k": "v"}

    def test_from_gemini_object_unconvertible_args(self):
        class BadArgs:
            def __iter__(self):
                raise TypeError("not iterable")
        obj = MagicMock(spec=["name", "args"])
        obj.name = "fn"
        obj.args = BadArgs()
        call = UnifiedToolCall.from_gemini(obj)
        assert call.arguments == {}

    def test_from_dict_defaults(self):
        call = UnifiedToolCall.from_dict({})
        assert call.name == "unknown"
        assert call.arguments == {}
        assert call.provider == Provider.UNKNOWN

    def test_roundtrip_dict(self):
        original = UnifiedToolCall(
            id="abc", name="tool", arguments={"x": 1}, provider=Provider.OPENAI
        )
        d = original.to_dict()
        restored = UnifiedToolCall.from_dict(d)
        assert restored.id == original.id
        assert restored.name == original.name
        assert restored.arguments == original.arguments


class TestUnifiedToolResult:

    def test_to_dict_success(self):
        r = UnifiedToolResult(tool_call_id="tc1", result={"ok": True})
        d = r.to_dict()
        assert d["tool_call_id"] == "tc1"
        assert d["is_error"] is False
        assert d["error_message"] is None

    def test_to_dict_error(self):
        r = UnifiedToolResult(
            tool_call_id="tc2", result=None, is_error=True, error_message="boom"
        )
        d = r.to_dict()
        assert d["is_error"] is True
        assert d["error_message"] == "boom"


class TestUnifiedResponseExtra:

    def test_empty_response_defaults(self):
        r = UnifiedResponse()
        assert r.content is None
        assert r.has_tool_calls() is False
        assert r.finish_reason is None
        assert r.usage == {}

    def test_to_dict_with_tool_calls(self):
        tc = _make_unified_call()
        r = UnifiedResponse(content="hi", tool_calls=[tc], provider=Provider.OPENAI)
        d = r.to_dict()
        assert len(d["tool_calls"]) == 1
        assert d["provider"] == "openai"


# ---------------------------------------------------------------------------
# OpenAIAdapter
# ---------------------------------------------------------------------------

class TestOpenAIAdapterExtended:

    def test_extract_tool_calls_object_form(self, openai_adapter):
        fn = FakeFunction(name="greet", arguments='{"name":"World"}')
        tc = FakeToolCall(id="c1", function=fn)
        msg = FakeMessage(tool_calls=[tc])
        resp = FakeOpenAIResponse(choices=[FakeChoice(message=msg)])

        calls = openai_adapter.extract_tool_calls(resp)
        assert len(calls) == 1
        assert calls[0].name == "greet"
        assert calls[0].arguments == {"name": "World"}

    def test_extract_tool_calls_no_choices(self, openai_adapter):
        resp = MagicMock(spec=[])
        assert openai_adapter.extract_tool_calls(resp) == []

    def test_extract_tool_calls_empty_choices(self, openai_adapter):
        resp = MagicMock()
        resp.choices = []
        assert openai_adapter.extract_tool_calls(resp) == []

    def test_extract_tool_calls_no_message(self, openai_adapter):
        choice = MagicMock(spec=[])
        resp = MagicMock()
        resp.choices = [choice]
        assert openai_adapter.extract_tool_calls(resp) == []

    def test_extract_tool_calls_none_tool_calls(self, openai_adapter):
        msg = FakeMessage(tool_calls=None)
        resp = FakeOpenAIResponse(choices=[FakeChoice(message=msg)])
        assert openai_adapter.extract_tool_calls(resp) == []

    def test_extract_response_object_form(self, openai_adapter):
        msg = FakeMessage(content="hello", tool_calls=None)
        usage = FakeUsage(prompt_tokens=10, completion_tokens=5, total_tokens=15)
        resp = FakeOpenAIResponse(
            choices=[FakeChoice(message=msg, finish_reason="stop")],
            usage=usage,
        )
        unified = openai_adapter.extract_response(resp)
        assert unified.content == "hello"
        assert unified.finish_reason == "stop"
        assert unified.usage["input_tokens"] == 10
        assert unified.usage["output_tokens"] == 5
        assert unified.usage["total_tokens"] == 15
        assert unified.provider == Provider.OPENAI

    def test_extract_response_object_no_usage(self, openai_adapter):
        msg = FakeMessage(content="ok")
        resp = FakeOpenAIResponse(choices=[FakeChoice(message=msg)], usage=None)
        unified = openai_adapter.extract_response(resp)
        assert unified.usage == {}

    def test_extract_response_dict_no_choices(self, openai_adapter):
        unified = openai_adapter.extract_response({"choices": []})
        assert unified.content is None
        assert unified.finish_reason is None

    def test_extract_response_dict_no_usage(self, openai_adapter):
        resp = {
            "choices": [{"message": {"content": "yo"}, "finish_reason": "stop"}]
        }
        unified = openai_adapter.extract_response(resp)
        assert unified.usage["input_tokens"] == 0

    def test_format_tool_result_string(self, openai_adapter):
        tc = _make_unified_call()
        result = openai_adapter.format_tool_result(tc, "plain text")
        assert result["content"] == "plain text"
        assert result["role"] == "tool"

    def test_format_tool_result_dict_error(self, openai_adapter):
        tc = _make_unified_call()
        result = openai_adapter.format_tool_result(tc, {"detail": "fail"}, is_error=True)
        parsed = json.loads(result["content"])
        assert "error" in parsed

    def test_format_tool_result_non_serializable(self, openai_adapter):
        tc = _make_unified_call()
        result = openai_adapter.format_tool_result(tc, object())
        assert isinstance(result["content"], str)

    def test_format_tools_with_to_openai_format(self, openai_adapter):
        tool = MagicMock()
        tool.to_openai_format.return_value = {"type": "function", "function": {"name": "x"}}
        formatted = openai_adapter.format_tools([tool])
        assert formatted[0]["type"] == "function"
        tool.to_openai_format.assert_called_once()

    def test_format_tools_object_with_name_desc(self, openai_adapter):
        tool = MagicMock(spec=["name", "description", "parameters"])
        tool.name = "calc"
        tool.description = "Calculate"
        tool.parameters = {"type": "object", "properties": {"x": {"type": "number"}}}
        formatted = openai_adapter.format_tools([tool])
        assert formatted[0]["function"]["name"] == "calc"
        assert formatted[0]["function"]["parameters"]["properties"]["x"]["type"] == "number"

    def test_format_tools_object_no_parameters(self, openai_adapter):
        tool = MagicMock(spec=["name", "description"])
        tool.name = "ping"
        tool.description = "Ping"
        formatted = openai_adapter.format_tools([tool])
        assert formatted[0]["function"]["parameters"] == {"type": "object", "properties": {}}

    def test_format_tools_dict_already_wrapped(self, openai_adapter):
        raw = {"type": "function", "function": {"name": "f", "description": "d"}}
        formatted = openai_adapter.format_tools([raw])
        assert formatted[0] is raw

    def test_format_tools_dict_unwrapped(self, openai_adapter):
        raw = {"name": "f", "description": "d"}
        formatted = openai_adapter.format_tools([raw])
        assert formatted[0]["type"] == "function"
        assert formatted[0]["function"] is raw

    def test_format_tools_ignores_unrecognized(self, openai_adapter):
        assert openai_adapter.format_tools([42]) == []

    def test_format_assistant_message_no_content(self, openai_adapter):
        msg = openai_adapter.format_assistant_message(None, [])
        assert msg["role"] == "assistant"
        assert "content" not in msg
        assert "tool_calls" not in msg

    def test_format_assistant_message_with_calls(self, openai_adapter):
        tc = _make_unified_call(args={"a": 1})
        msg = openai_adapter.format_assistant_message("thinking", [tc])
        assert msg["content"] == "thinking"
        assert len(msg["tool_calls"]) == 1
        fn_data = msg["tool_calls"][0]["function"]
        assert json.loads(fn_data["arguments"]) == {"a": 1}

    def test_extract_parallel_tool_calls_dict(self, openai_adapter):
        response = {
            "choices": [{
                "message": {
                    "tool_calls": [
                        {"id": "c1", "function": {"name": "a", "arguments": "{}"}},
                        {"id": "c2", "function": {"name": "b", "arguments": "{}"}},
                        {"id": "c3", "function": {"name": "c", "arguments": "{}"}},
                    ]
                }
            }]
        }
        calls = openai_adapter.extract_tool_calls(response)
        assert len(calls) == 3
        assert [c.name for c in calls] == ["a", "b", "c"]


# ---------------------------------------------------------------------------
# AnthropicAdapter
# ---------------------------------------------------------------------------

class TestAnthropicAdapterExtended:

    def test_extract_tool_calls_object_form(self, anthropic_adapter):
        text_block = FakeContentBlock(type="text", text="I will search.")
        tool_block = FakeContentBlock(
            type="tool_use", id="tu_1", name="search", input={"q": "test"}
        )
        resp = FakeAnthropicResponse(content=[text_block, tool_block])
        calls = anthropic_adapter.extract_tool_calls(resp)
        assert len(calls) == 1
        assert calls[0].name == "search"
        assert calls[0].arguments == {"q": "test"}

    def test_extract_tool_calls_object_empty_content(self, anthropic_adapter):
        resp = FakeAnthropicResponse(content=[])
        assert anthropic_adapter.extract_tool_calls(resp) == []

    def test_extract_tool_calls_object_no_content(self, anthropic_adapter):
        resp = MagicMock(spec=[])
        assert anthropic_adapter.extract_tool_calls(resp) == []

    def test_extract_tool_calls_dict_mixed_blocks(self, anthropic_adapter):
        response = {
            "content": [
                {"type": "text", "text": "Let me help."},
                {"type": "tool_use", "id": "t1", "name": "a", "input": {"x": 1}},
                {"type": "text", "text": "Also doing this."},
                {"type": "tool_use", "id": "t2", "name": "b", "input": {"y": 2}},
            ]
        }
        calls = anthropic_adapter.extract_tool_calls(response)
        assert len(calls) == 2
        assert calls[0].arguments == {"x": 1}
        assert calls[1].arguments == {"y": 2}

    def test_extract_response_object_form(self, anthropic_adapter):
        text_block = FakeContentBlock(type="text", text="Hello ")
        text_block2 = FakeContentBlock(type="text", text="World")
        usage = FakeAnthropicUsage(input_tokens=30, output_tokens=10)
        resp = FakeAnthropicResponse(
            content=[text_block, text_block2], stop_reason="end_turn", usage=usage
        )
        unified = anthropic_adapter.extract_response(resp)
        assert unified.content == "Hello World"
        assert unified.finish_reason == "end_turn"
        assert unified.usage["input_tokens"] == 30
        assert unified.usage["output_tokens"] == 10
        assert unified.provider == Provider.ANTHROPIC

    def test_extract_response_object_no_usage(self, anthropic_adapter):
        resp = FakeAnthropicResponse(content=[], usage=None, stop_reason=None)
        unified = anthropic_adapter.extract_response(resp)
        assert unified.usage == {}
        assert unified.content is None

    def test_extract_response_dict_no_text(self, anthropic_adapter):
        response = {
            "content": [
                {"type": "tool_use", "id": "t1", "name": "x", "input": {}}
            ],
            "stop_reason": "tool_use",
            "usage": {"input_tokens": 5, "output_tokens": 2},
        }
        unified = anthropic_adapter.extract_response(response)
        assert unified.content is None
        assert unified.has_tool_calls() is True

    def test_extract_text_content_empty(self, anthropic_adapter):
        assert anthropic_adapter._extract_text_content([]) is None

    def test_extract_text_content_from_objects_empty(self, anthropic_adapter):
        assert anthropic_adapter._extract_text_content_from_objects([]) is None

    def test_format_tool_result_success(self, anthropic_adapter):
        tc = _make_unified_call(id_="tu_1")
        result = anthropic_adapter.format_tool_result(tc, {"status": "ok"})
        assert result["type"] == "tool_result"
        assert result["tool_use_id"] == "tu_1"
        assert result["is_error"] is False
        parsed = json.loads(result["content"])
        assert parsed["status"] == "ok"

    def test_format_tool_result_error(self, anthropic_adapter):
        tc = _make_unified_call(id_="tu_err")
        result = anthropic_adapter.format_tool_result(tc, "timeout", is_error=True)
        assert result["is_error"] is True
        assert result["content"] == "timeout"

    def test_format_tools_with_to_anthropic_format(self, anthropic_adapter):
        tool = MagicMock()
        tool.to_anthropic_format.return_value = {
            "name": "x", "description": "d", "input_schema": {}
        }
        formatted = anthropic_adapter.format_tools([tool])
        assert formatted[0]["name"] == "x"
        tool.to_anthropic_format.assert_called_once()

    def test_format_tools_object_with_name_desc(self, anthropic_adapter):
        tool = MagicMock(spec=["name", "description", "parameters"])
        tool.name = "reader"
        tool.description = "Read files"
        tool.parameters = {"type": "object", "properties": {"path": {"type": "string"}}}
        formatted = anthropic_adapter.format_tools([tool])
        assert formatted[0]["name"] == "reader"
        assert formatted[0]["input_schema"] == tool.parameters

    def test_format_tools_object_no_parameters(self, anthropic_adapter):
        tool = MagicMock(spec=["name", "description"])
        tool.name = "noop"
        tool.description = "Does nothing"
        formatted = anthropic_adapter.format_tools([tool])
        assert formatted[0]["input_schema"] == {"type": "object", "properties": {}}

    def test_format_tools_dict_with_input_schema(self, anthropic_adapter):
        raw = {"name": "t", "description": "d", "input_schema": {"type": "object"}}
        formatted = anthropic_adapter.format_tools([raw])
        assert formatted[0] is raw

    def test_format_tools_dict_with_parameters(self, anthropic_adapter):
        raw = {"name": "t", "description": "d", "parameters": {"type": "object"}}
        formatted = anthropic_adapter.format_tools([raw])
        assert formatted[0]["input_schema"] == {"type": "object"}
        assert formatted[0]["name"] == "t"

    def test_format_tools_dict_unrecognized(self, anthropic_adapter):
        raw = {"weird": "format"}
        formatted = anthropic_adapter.format_tools([raw])
        assert formatted == []

    def test_format_tools_ignores_unrecognized(self, anthropic_adapter):
        assert anthropic_adapter.format_tools([42, "str"]) == []

    def test_format_user_message_with_results(self, anthropic_adapter):
        results = [
            (_make_unified_call(id_="t1"), {"ok": True}, False),
            (_make_unified_call(id_="t2"), "fail", True),
        ]
        msg = anthropic_adapter.format_user_message_with_results(results)
        assert msg["role"] == "user"
        assert len(msg["content"]) == 2
        assert msg["content"][0]["tool_use_id"] == "t1"
        assert msg["content"][1]["is_error"] is True

    def test_format_assistant_message_text_only(self, anthropic_adapter):
        msg = anthropic_adapter.format_assistant_message("Hello", [])
        assert msg["role"] == "assistant"
        assert len(msg["content"]) == 1
        assert msg["content"][0]["type"] == "text"
        assert msg["content"][0]["text"] == "Hello"

    def test_format_assistant_message_tool_only(self, anthropic_adapter):
        tc = _make_unified_call(id_="tu_1", name="fn", args={"a": 1})
        msg = anthropic_adapter.format_assistant_message(None, [tc])
        assert msg["role"] == "assistant"
        assert len(msg["content"]) == 1
        assert msg["content"][0]["type"] == "tool_use"
        assert msg["content"][0]["id"] == "tu_1"
        assert msg["content"][0]["input"] == {"a": 1}

    def test_format_assistant_message_mixed(self, anthropic_adapter):
        tc = _make_unified_call(id_="tu_2", name="fn2")
        msg = anthropic_adapter.format_assistant_message("Thinking", [tc])
        assert len(msg["content"]) == 2
        types = [b["type"] for b in msg["content"]]
        assert types == ["text", "tool_use"]


# ---------------------------------------------------------------------------
# GeminiAdapter
# ---------------------------------------------------------------------------

class TestGeminiAdapterExtended:

    def test_extract_tool_calls_object_form(self, gemini_adapter):
        fc = FakeGeminiFunctionCall(name="lookup", args={"id": "42"})
        part = FakePart(function_call=fc)
        content = FakeGeminiContent(parts=[part])
        candidate = FakeCandidate(content=content)
        resp = FakeGeminiResponse(candidates=[candidate])

        calls = gemini_adapter.extract_tool_calls(resp)
        assert len(calls) == 1
        assert calls[0].name == "lookup"
        assert calls[0].arguments == {"id": "42"}
        assert calls[0].provider == Provider.GEMINI

    def test_extract_tool_calls_object_no_candidates(self, gemini_adapter):
        resp = MagicMock(spec=[])
        assert gemini_adapter.extract_tool_calls(resp) == []

    def test_extract_tool_calls_object_empty_candidates(self, gemini_adapter):
        resp = MagicMock()
        resp.candidates = []
        assert gemini_adapter.extract_tool_calls(resp) == []

    def test_extract_tool_calls_object_no_content(self, gemini_adapter):
        candidate = MagicMock(spec=[])
        resp = MagicMock()
        resp.candidates = [candidate]
        assert gemini_adapter.extract_tool_calls(resp) == []

    def test_extract_tool_calls_object_no_parts(self, gemini_adapter):
        candidate = MagicMock()
        candidate.content = MagicMock(spec=[])
        resp = MagicMock()
        resp.candidates = [candidate]
        assert gemini_adapter.extract_tool_calls(resp) == []

    def test_extract_tool_calls_object_no_function_call(self, gemini_adapter):
        part = FakePart(text="just text", function_call=None)
        content = FakeGeminiContent(parts=[part])
        candidate = FakeCandidate(content=content)
        resp = FakeGeminiResponse(candidates=[candidate])
        assert gemini_adapter.extract_tool_calls(resp) == []

    def test_extract_tool_calls_dict_snake_case(self, gemini_adapter):
        response = {
            "candidates": [{
                "content": {
                    "parts": [{
                        "function_call": {"name": "fn", "args": {"k": "v"}}
                    }]
                }
            }]
        }
        calls = gemini_adapter.extract_tool_calls(response)
        assert len(calls) == 1
        assert calls[0].name == "fn"

    def test_extract_tool_calls_dict_camel_case(self, gemini_adapter):
        response = {
            "candidates": [{
                "content": {
                    "parts": [{
                        "functionCall": {"name": "fn2", "args": {"a": 1}}
                    }]
                }
            }]
        }
        calls = gemini_adapter.extract_tool_calls(response)
        assert len(calls) == 1
        assert calls[0].name == "fn2"

    def test_extract_tool_calls_dict_multiple_parts(self, gemini_adapter):
        response = {
            "candidates": [{
                "content": {
                    "parts": [
                        {"functionCall": {"name": "a", "args": {}}},
                        {"text": "some text"},
                        {"functionCall": {"name": "b", "args": {"x": 1}}},
                    ]
                }
            }]
        }
        calls = gemini_adapter.extract_tool_calls(response)
        assert len(calls) == 2

    def test_extract_response_object_form(self, gemini_adapter):
        part = FakePart(text="Answer is 42")
        content = FakeGeminiContent(parts=[part])
        candidate = FakeCandidate(content=content, finish_reason="STOP")
        usage = FakeUsageMetadata(
            prompt_token_count=20, candidates_token_count=8, total_token_count=28
        )
        resp = FakeGeminiResponse(candidates=[candidate], usage_metadata=usage)

        unified = gemini_adapter.extract_response(resp)
        assert unified.content == "Answer is 42"
        assert unified.finish_reason == "STOP"
        assert unified.usage["input_tokens"] == 20
        assert unified.usage["output_tokens"] == 8
        assert unified.usage["total_tokens"] == 28
        assert unified.provider == Provider.GEMINI

    def test_extract_response_object_no_usage(self, gemini_adapter):
        part = FakePart(text="hi")
        content = FakeGeminiContent(parts=[part])
        candidate = FakeCandidate(content=content)
        resp = FakeGeminiResponse(candidates=[candidate], usage_metadata=None)
        unified = gemini_adapter.extract_response(resp)
        assert unified.usage == {}

    def test_extract_response_dict_with_text(self, gemini_adapter):
        response = {
            "candidates": [{
                "content": {"parts": [{"text": "yes"}]},
                "finishReason": "STOP",
            }],
            "usageMetadata": {
                "promptTokenCount": 5,
                "candidatesTokenCount": 1,
                "totalTokenCount": 6,
            },
        }
        unified = gemini_adapter.extract_response(response)
        assert unified.content == "yes"
        assert unified.finish_reason == "STOP"
        assert unified.usage["total_tokens"] == 6

    def test_extract_response_dict_empty_candidates(self, gemini_adapter):
        unified = gemini_adapter.extract_response({"candidates": []})
        assert unified.content is None
        assert unified.finish_reason is None

    def test_extract_text_from_object_no_text(self, gemini_adapter):
        part = FakePart(function_call=FakeGeminiFunctionCall("fn", {}))
        content = FakeGeminiContent(parts=[part])
        candidate = FakeCandidate(content=content)
        resp = FakeGeminiResponse(candidates=[candidate])
        assert gemini_adapter._extract_text_from_object(resp) is None

    def test_extract_text_from_object_no_content(self, gemini_adapter):
        candidate = MagicMock(spec=[])
        resp = MagicMock()
        resp.candidates = [candidate]
        assert gemini_adapter._extract_text_from_object(resp) is None

    def test_extract_finish_reason_from_dict_empty(self, gemini_adapter):
        assert gemini_adapter._extract_finish_reason_from_dict({"candidates": []}) is None

    def test_extract_finish_reason_from_object_empty(self, gemini_adapter):
        resp = MagicMock()
        resp.candidates = []
        assert gemini_adapter._extract_finish_reason_from_object(resp) is None

    def test_format_tool_result_dict_result(self, gemini_adapter):
        tc = _make_unified_call(name="search")
        result = gemini_adapter.format_tool_result(tc, {"items": [1, 2]})
        fr = result["function_response"]
        assert fr["name"] == "search"
        assert fr["response"]["items"] == [1, 2]

    def test_format_tool_result_non_dict(self, gemini_adapter):
        tc = _make_unified_call(name="count")
        result = gemini_adapter.format_tool_result(tc, 42)
        assert result["function_response"]["response"] == {"result": 42}

    def test_format_tool_result_string(self, gemini_adapter):
        tc = _make_unified_call(name="echo")
        result = gemini_adapter.format_tool_result(tc, "hello")
        assert result["function_response"]["response"] == {"result": "hello"}

    def test_format_tool_result_error(self, gemini_adapter):
        tc = _make_unified_call(name="fail")
        result = gemini_adapter.format_tool_result(tc, "oops", is_error=True)
        fr = result["function_response"]
        assert "error" in fr["response"]

    def test_format_tools_with_to_gemini_format(self, gemini_adapter):
        tool = MagicMock()
        tool.to_gemini_format.return_value = {"name": "x", "description": "d", "parameters": {}}
        formatted = gemini_adapter.format_tools([tool])
        assert formatted[0]["name"] == "x"
        tool.to_gemini_format.assert_called_once()

    def test_format_tools_object_with_name_desc(self, gemini_adapter):
        tool = MagicMock(spec=["name", "description", "parameters"])
        tool.name = "fn"
        tool.description = "Does stuff"
        tool.parameters = {"type": "object"}
        formatted = gemini_adapter.format_tools([tool])
        assert formatted[0]["name"] == "fn"
        assert formatted[0]["parameters"] == {"type": "object"}

    def test_format_tools_object_no_parameters(self, gemini_adapter):
        tool = MagicMock(spec=["name", "description"])
        tool.name = "bare"
        tool.description = "Bare tool"
        formatted = gemini_adapter.format_tools([tool])
        assert formatted[0]["parameters"] == {"type": "object", "properties": {}}

    def test_format_tools_dict_passthrough(self, gemini_adapter):
        raw = {"name": "t", "description": "d", "parameters": {}}
        formatted = gemini_adapter.format_tools([raw])
        assert formatted[0] is raw

    def test_format_tools_ignores_unrecognized(self, gemini_adapter):
        assert gemini_adapter.format_tools([42, None, "x"]) == []

    def test_format_content_with_results(self, gemini_adapter):
        results = [
            (_make_unified_call(name="a"), {"ok": True}, False),
            (_make_unified_call(name="b"), "err", True),
        ]
        parts = gemini_adapter.format_content_with_results(results)
        assert len(parts) == 2
        assert parts[0]["function_response"]["name"] == "a"
        assert "error" in parts[1]["function_response"]["response"]

    def test_create_vertex_tool_import_error(self, gemini_adapter):
        with pytest.raises(ImportError, match="vertexai"):
            gemini_adapter.create_vertex_tool([])

    def test_create_function_response_part_import_error(self, gemini_adapter):
        tc = _make_unified_call(name="fn")
        with pytest.raises(ImportError, match="vertexai"):
            gemini_adapter.create_function_response_part(tc, {"ok": True})


# ---------------------------------------------------------------------------
# BaseAdapter._serialize_result
# ---------------------------------------------------------------------------

class TestBaseAdapterSerialize:

    def test_serialize_string(self, openai_adapter):
        assert openai_adapter._serialize_result("hello") == "hello"

    def test_serialize_dict(self, openai_adapter):
        assert json.loads(openai_adapter._serialize_result({"k": "v"})) == {"k": "v"}

    def test_serialize_int(self, openai_adapter):
        assert openai_adapter._serialize_result(42) == "42"

    def test_serialize_list(self, openai_adapter):
        assert json.loads(openai_adapter._serialize_result([1, 2, 3])) == [1, 2, 3]

    def test_serialize_non_json_falls_back_to_str(self, openai_adapter):
        obj = object()
        result = openai_adapter._serialize_result(obj)
        assert isinstance(result, str)


# ---------------------------------------------------------------------------
# ProviderAdapter protocol compliance
# ---------------------------------------------------------------------------

class TestProtocolCompliance:

    def test_openai_adapter_is_provider_adapter(self):
        assert isinstance(OpenAIAdapter(), ProviderAdapter)

    def test_anthropic_adapter_is_provider_adapter(self):
        assert isinstance(AnthropicAdapter(), ProviderAdapter)

    def test_gemini_adapter_is_provider_adapter(self):
        assert isinstance(GeminiAdapter(), ProviderAdapter)

    def test_base_adapter_subclass(self):
        assert issubclass(OpenAIAdapter, BaseAdapter)
        assert issubclass(AnthropicAdapter, BaseAdapter)
        assert issubclass(GeminiAdapter, BaseAdapter)


# ---------------------------------------------------------------------------
# detect_provider additional paths
# ---------------------------------------------------------------------------

class TestDetectProviderExtra:

    def test_detect_google_generativeai_module(self):
        resp = MagicMock()
        resp.__class__.__module__ = "google.generativeai.types"
        resp.__class__.__name__ = "GenerateContentResponse"
        assert detect_provider(resp) == Provider.GEMINI

    def test_detect_google_aiplatform_module(self):
        resp = MagicMock()
        resp.__class__.__module__ = "google.cloud.aiplatform.models"
        resp.__class__.__name__ = "SomeResponse"
        assert detect_provider(resp) == Provider.GEMINI

    def test_detect_by_candidates_attribute(self):
        class Resp:
            candidates = []
        resp = Resp()
        resp.__class__.__module__ = "unknown"
        resp.__class__.__name__ = "Resp"
        assert detect_provider(resp) == Provider.GEMINI

    def test_detect_by_stop_reason_attribute(self):
        class Resp:
            stop_reason = "end_turn"
        resp = Resp()
        resp.__class__.__module__ = "unknown"
        resp.__class__.__name__ = "Resp"
        assert detect_provider(resp) == Provider.ANTHROPIC

    def test_detect_generation_response_type_name(self):
        resp = MagicMock()
        resp.__class__.__module__ = "some.other"
        resp.__class__.__name__ = "GenerationResponse"
        assert detect_provider(resp) == Provider.GEMINI

    def test_detect_provider_safe_returns_unknown(self):
        class Plain:
            pass
        obj = Plain()
        assert detect_provider_safe(obj) == Provider.UNKNOWN
