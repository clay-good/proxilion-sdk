"""
Proxilion contrib module - Framework integrations.

This package provides integrations with popular AI frameworks
and protocols:

- MCP (Model Context Protocol) - Anthropic's agent-tool protocol
- LangChain - Popular LLM framework
- OpenAI - Function calling integration
- Anthropic - Tool use integration
- Google - Vertex AI / Gemini integration

Usage:
    >>> # MCP integration
    >>> from proxilion.contrib.mcp import (
    ...     MCPToolWrapper,
    ...     ProxilionMCPServer,
    ...     MCPSession,
    ... )
    >>>
    >>> # LangChain integration
    >>> from proxilion.contrib.langchain import (
    ...     ProxilionTool,
    ...     ProxilionCallbackHandler,
    ...     wrap_langchain_tools,
    ... )
    >>>
    >>> # OpenAI integration
    >>> from proxilion.contrib.openai import (
    ...     ProxilionFunctionHandler,
    ...     create_secure_function,
    ... )
    >>>
    >>> # Anthropic integration
    >>> from proxilion.contrib.anthropic import (
    ...     ProxilionToolHandler,
    ...     process_tool_use,
    ... )
    >>>
    >>> # Google Vertex AI / Gemini integration
    >>> from proxilion.contrib.google import (
    ...     ProxilionVertexHandler,
    ...     GeminiFunctionCall,
    ...     GeminiToolResult,
    ...     extract_function_calls,
    ...     format_tool_response,
    ... )
"""

# Note: Individual modules handle optional dependencies gracefully
# and will work without their respective SDKs installed
