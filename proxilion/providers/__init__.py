"""
Provider-agnostic helpers for AI integrations.

Supports:
- OpenAI / Azure OpenAI
- Anthropic Claude
- Google Vertex AI / Gemini
- AWS Bedrock (via OpenAI-compatible interface)
- Local models (Ollama)

This module provides a unified interface for working with tool calls
across different LLM providers, enabling provider-agnostic authorization
and execution.

Example:
    >>> from proxilion.providers import (
    ...     get_adapter, detect_provider, UnifiedToolCall,
    ...     OpenAIAdapter, AnthropicAdapter, GeminiAdapter,
    ... )
    >>>
    >>> # Auto-detect provider from response
    >>> adapter = get_adapter(response=llm_response)
    >>> tool_calls = adapter.extract_tool_calls(llm_response)
    >>>
    >>> # Or specify provider explicitly
    >>> adapter = get_adapter(provider="openai")
    >>> openai_tools = adapter.format_tools(registry.list_enabled())
    >>>
    >>> # Work with unified tool calls
    >>> for call in tool_calls:
    ...     if auth.can(user, "execute", call.name):
    ...         result = execute_tool(call.name, **call.arguments)
    ...         response_msg = adapter.format_tool_result(call, result)
"""

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
from proxilion.providers.anthropic_adapter import AnthropicAdapter
from proxilion.providers.gemini_adapter import GeminiAdapter
from proxilion.providers.openai_adapter import OpenAIAdapter

# Adapter registry
_ADAPTERS: dict[str, type[BaseAdapter]] = {
    "openai": OpenAIAdapter,
    "anthropic": AnthropicAdapter,
    "gemini": GeminiAdapter,
    "vertexai": GeminiAdapter,  # Alias
    "google": GeminiAdapter,  # Alias
}

# Singleton instances
_adapter_instances: dict[str, BaseAdapter] = {}


def get_adapter(
    provider: str | Provider | None = None,
    response: object | None = None,
) -> BaseAdapter:
    """
    Get the appropriate adapter for a provider.

    Can auto-detect the provider from a response object or
    accept an explicit provider name.

    Args:
        provider: Provider name or enum (e.g., "openai", Provider.ANTHROPIC).
        response: Optional response object for auto-detection.

    Returns:
        Appropriate adapter instance.

    Raises:
        ValueError: If provider cannot be determined or is unknown.

    Example:
        >>> # Auto-detect from response
        >>> adapter = get_adapter(response=openai_response)
        >>>
        >>> # Explicit provider
        >>> adapter = get_adapter(provider="anthropic")
        >>> adapter = get_adapter(provider=Provider.GEMINI)
    """
    # Auto-detect if no provider specified
    if provider is None:
        if response is not None:
            provider = detect_provider(response)
        else:
            raise ValueError("Must specify provider or response for auto-detection")

    # Convert Provider enum to string
    provider_key = provider.value if isinstance(provider, Provider) else provider.lower()

    # Get or create adapter instance
    if provider_key not in _adapter_instances:
        if provider_key not in _ADAPTERS:
            raise ValueError(
                f"Unknown provider: {provider_key}. "
                f"Supported: {list(_ADAPTERS.keys())}"
            )
        _adapter_instances[provider_key] = _ADAPTERS[provider_key]()

    return _adapter_instances[provider_key]


def register_adapter(name: str, adapter_class: type[BaseAdapter]) -> None:
    """
    Register a custom adapter.

    Args:
        name: Provider name to register under.
        adapter_class: Adapter class (must inherit from BaseAdapter).

    Example:
        >>> class MyCustomAdapter(BaseAdapter):
        ...     ...
        >>> register_adapter("custom", MyCustomAdapter)
        >>> adapter = get_adapter("custom")
    """
    _ADAPTERS[name.lower()] = adapter_class
    # Clear cached instance if exists
    if name.lower() in _adapter_instances:
        del _adapter_instances[name.lower()]


def list_providers() -> list[str]:
    """
    List all registered provider names.

    Returns:
        List of provider names.
    """
    return list(_ADAPTERS.keys())


def extract_tool_calls(response: object) -> list[UnifiedToolCall]:
    """
    Convenience function to extract tool calls from any supported response.

    Auto-detects the provider and extracts tool calls.

    Args:
        response: LLM response object.

    Returns:
        List of unified tool calls.

    Example:
        >>> tool_calls = extract_tool_calls(llm_response)
        >>> for call in tool_calls:
        ...     print(f"{call.name}: {call.arguments}")
    """
    adapter = get_adapter(response=response)
    return adapter.extract_tool_calls(response)


def extract_response(response: object) -> UnifiedResponse:
    """
    Convenience function to extract full response from any supported response.

    Auto-detects the provider and extracts the response.

    Args:
        response: LLM response object.

    Returns:
        UnifiedResponse instance.
    """
    adapter = get_adapter(response=response)
    return adapter.extract_response(response)


__all__ = [
    # Core types
    "Provider",
    "ProviderAdapter",
    "BaseAdapter",
    "UnifiedToolCall",
    "UnifiedToolResult",
    "UnifiedResponse",
    # Adapters
    "OpenAIAdapter",
    "AnthropicAdapter",
    "GeminiAdapter",
    # Factory functions
    "get_adapter",
    "register_adapter",
    "list_providers",
    "detect_provider",
    "detect_provider_safe",
    # Convenience functions
    "extract_tool_calls",
    "extract_response",
]
