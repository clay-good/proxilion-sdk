"""
Provider response fixtures for testing.

Provides factory functions for creating mock responses from various
LLM providers (OpenAI, Anthropic, Google Gemini).
"""

from __future__ import annotations

from typing import Any


def make_openai_response(
    content: str = "Hello! How can I help you today?",
    tool_calls: list[dict[str, Any]] | None = None,
    model: str = "gpt-4",
) -> dict[str, Any]:
    """
    Create a mock OpenAI API response.

    Args:
        content: Message content.
        tool_calls: Optional tool calls in OpenAI format.
        model: Model name.

    Returns:
        Dictionary matching OpenAI response format.
    """
    response = {
        "id": "chatcmpl-abc123",
        "object": "chat.completion",
        "created": 1677652288,
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": content,
                },
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": 10,
            "completion_tokens": 20,
            "total_tokens": 30,
        },
    }

    if tool_calls:
        response["choices"][0]["message"]["tool_calls"] = tool_calls
        response["choices"][0]["finish_reason"] = "tool_calls"

    return response


def make_anthropic_response(
    content: str = "Hello! How can I assist you?",
    tool_use: list[dict[str, Any]] | None = None,
    model: str = "claude-3-5-sonnet-20241022",
) -> dict[str, Any]:
    """
    Create a mock Anthropic API response.

    Args:
        content: Message content.
        tool_use: Optional tool use blocks in Anthropic format.
        model: Model name.

    Returns:
        Dictionary matching Anthropic response format.
    """
    content_blocks = [
        {
            "type": "text",
            "text": content,
        }
    ]

    if tool_use:
        content_blocks.extend(tool_use)

    return {
        "id": "msg_abc123",
        "type": "message",
        "role": "assistant",
        "content": content_blocks,
        "model": model,
        "stop_reason": "end_turn" if not tool_use else "tool_use",
        "stop_sequence": None,
        "usage": {
            "input_tokens": 15,
            "output_tokens": 25,
        },
    }


def make_gemini_response(
    content: str = "Hello! I'm here to help.",
    function_calls: list[dict[str, Any]] | None = None,
    model: str = "gemini-1.5-pro",
) -> dict[str, Any]:
    """
    Create a mock Google Gemini API response.

    Args:
        content: Message content.
        function_calls: Optional function calls in Gemini format.
        model: Model name.

    Returns:
        Dictionary matching Gemini response format.
    """
    parts = [{"text": content}]

    if function_calls:
        parts.extend(function_calls)

    return {
        "candidates": [
            {
                "content": {
                    "parts": parts,
                    "role": "model",
                },
                "finishReason": "STOP" if not function_calls else "FUNCTION_CALL",
                "index": 0,
                "safetyRatings": [
                    {
                        "category": "HARM_CATEGORY_HARASSMENT",
                        "probability": "NEGLIGIBLE",
                    },
                    {
                        "category": "HARM_CATEGORY_HATE_SPEECH",
                        "probability": "NEGLIGIBLE",
                    },
                    {
                        "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                        "probability": "NEGLIGIBLE",
                    },
                    {
                        "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
                        "probability": "NEGLIGIBLE",
                    },
                ],
            }
        ],
        "usageMetadata": {
            "promptTokenCount": 12,
            "candidatesTokenCount": 18,
            "totalTokenCount": 30,
        },
        "modelVersion": model,
    }
