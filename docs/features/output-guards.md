# Output Guards

Output guards detect and prevent sensitive data leakage in LLM responses. They catch credentials, API keys, PII, and other confidential information before it reaches the end user.

## Overview

The `OutputGuard` uses pattern matching to detect:
- API keys and tokens (OpenAI, Anthropic, AWS, Azure, GCP, GitHub, Slack)
- Private keys and certificates
- Database connection strings
- Internal file paths
- System prompt leakage
- PII (email, phone, SSN)
- Financial data (credit cards)
- Internal IP addresses

All detection is deterministic with no LLM inference in the security path.

## Quick Start

```python
from proxilion.guards import OutputGuard, GuardAction

# Create output guard
guard = OutputGuard(action=GuardAction.BLOCK, threshold=0.5)

# Check LLM response before returning to user
llm_response = "Your API key is sk-abc123..."
result = guard.check(llm_response)

if result.passed:
    # Safe to return
    return llm_response
else:
    # Sensitive data detected
    print(f"Leakage: {result.matched_patterns}")
    # Use redacted version or block entirely
    return guard.redact(llm_response)
```

## LeakageCategory

Output patterns are organized by category:

| Category | Description | Examples |
|----------|-------------|----------|
| `CREDENTIAL` | API keys, passwords, tokens | `sk-*`, `Bearer *`, passwords |
| `INTERNAL` | Internal paths, infrastructure | `/home/user/`, `C:\Users\` |
| `SYSTEM_PROMPT` | System prompt disclosure | "my instructions are", system markers |
| `PII` | Personally identifiable info | emails, phones, SSN |
| `FINANCIAL` | Financial data | credit card numbers |
| `INFRASTRUCTURE` | Internal network details | private IPs, hostnames |

```python
from proxilion.guards import LeakageCategory

# Redact only credentials
safe_output = guard.redact(
    llm_output,
    categories=[LeakageCategory.CREDENTIAL],
)
```

## Built-in Patterns

### API Keys and Tokens

```python
# OpenAI keys
# Pattern: sk-(?:proj-)?[a-zA-Z0-9\-_]{20,}
# Severity: 0.95

# Anthropic keys
# Pattern: sk-ant-[a-zA-Z0-9\-]{20,}
# Severity: 0.95

# AWS keys
# Pattern: (AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}
# Severity: 0.95

# Bearer tokens (JWT)
# Pattern: bearer\s+([a-zA-Z0-9_\-\.]+\.){2}[a-zA-Z0-9_\-\.]+
# Severity: 0.95

# GitHub tokens
# Pattern: (ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,}
# Severity: 0.95
```

### Connection Strings

```python
# MongoDB
# Pattern: mongodb(\+srv)?://[^:]+:[^@]+@[^\s]+
# Severity: 0.95

# PostgreSQL
# Pattern: postgres(ql)?://[^:]+:[^@]+@[^\s]+
# Severity: 0.95

# Redis
# Pattern: redis(s)?://[^:]*:[^@]+@[^\s]+
# Severity: 0.95
```

### Private Keys

```python
# Pattern: -----BEGIN\s+(RSA\s+|EC\s+)? PRIVATE\s+KEY-----
# Severity: 0.99
```

### PII (Optional)

PII detection is **disabled by default** to avoid false positives. Enable explicitly:

```python
guard = OutputGuard(enable_pii=True)

# Now detects:
# - Email addresses (severity: 0.5)
# - Phone numbers (severity: 0.5)
# - SSN (severity: 0.9)
```

## Redaction API

The `redact()` method removes sensitive data from output:

```python
# Redact all sensitive patterns
safe_output = guard.redact(llm_response)

# Redact only specific categories
safe_output = guard.redact(
    llm_response,
    categories=[
        LeakageCategory.CREDENTIAL,
        LeakageCategory.FINANCIAL,
    ],
)
```

### Redaction Examples

```python
original = "Use API key sk-proj-abc123def456 to authenticate"
redacted = guard.redact(original)
# Result: "Use API key [OPENAI_KEY_REDACTED] to authenticate"

original = "Connect to mongodb://user:pass@host/db"
redacted = guard.redact(original)
# Result: "Connect to [MONGODB_CONN_REDACTED]"

original = "Email me at alice@example.com"
guard = OutputGuard(enable_pii=True)
redacted = guard.redact(original)
# Result: "Email me at [EMAIL_REDACTED]"
```

## Custom Patterns

Add domain-specific leakage patterns:

```python
from proxilion.guards import OutputGuard, LeakagePattern, LeakageCategory

guard = OutputGuard()

# Add custom pattern
guard.add_pattern(
    LeakagePattern(
        name="internal_project_code",
        pattern=r"PROJECT-\d{4}-[A-Z]{3}",
        category=LeakageCategory.INTERNAL,
        severity=0.8,
        description="Internal project codes",
        redaction="[PROJECT_CODE_REDACTED]",
    )
)
```

### Pattern Fields

```python
@dataclass
class LeakagePattern:
    name: str                           # Unique identifier
    pattern: str                        # Regex pattern
    category: LeakageCategory           # Category of leakage
    severity: float = 0.8               # 0.0 to 1.0
    description: str = ""               # Description
    redaction: str = "[REDACTED]"       # Replacement text
```

## Custom Filters

For complex validation beyond regex:

```python
from proxilion.guards import OutputFilter, GuardAction

def check_no_internal_urls(text: str, context: dict | None) -> bool:
    """Check for internal domain names."""
    internal_domains = [".internal", ".corp", ".local"]
    return not any(domain in text for domain in internal_domains)

filter = OutputFilter(
    name="internal_urls",
    check_func=check_no_internal_urls,
    action=GuardAction.WARN,
    description="Blocks internal domain names",
)

guard = OutputGuard(filters=[filter])
```

## Match Details

```python
result = guard.check(llm_output)

if not result.passed:
    for match in result.matches:
        print(f"Pattern: {match['pattern']}")
        print(f"Category: {match['category']}")
        print(f"Severity: {match['severity']}")
        print(f"Redaction: {match['redaction']}")
        # Note: matched_text is truncated to avoid logging secrets
        print(f"Matched: {match['matched_text']}")  # "sk-a...def"
```

## Integration Example

```python
from proxilion.guards import OutputGuard, GuardAction

class SecureLLMClient:
    def __init__(self):
        self.output_guard = OutputGuard(
            action=GuardAction.BLOCK,
            threshold=0.6,
            enable_pii=False,  # Tune for your use case
        )

    def generate(self, user_input: str) -> str:
        # Get LLM response
        response = self.llm.generate(user_input)

        # Check for leakage
        result = self.output_guard.check(response)

        if not result.passed:
            if result.risk_score > 0.9:
                # Critical leakage - block entirely
                raise SecurityError("Output blocked: sensitive data detected")
            else:
                # Non-critical - redact and proceed
                return self.output_guard.redact(response)

        return response
```

## Selective Redaction

```python
# Only redact credentials and financial data
guard = OutputGuard()

safe_output = guard.redact(
    llm_output,
    categories=[
        LeakageCategory.CREDENTIAL,
        LeakageCategory.FINANCIAL,
    ],
)

# Internal paths and PII left as-is
```

## Pattern Management

```python
# List all patterns
patterns = guard.get_patterns()
for p in patterns:
    print(f"{p.name}: {p.category.value}, severity={p.severity}")

# Remove pattern
guard.remove_pattern("email_address")  # Returns True if removed

# Create guard without defaults
from proxilion.guards import create_output_guard

guard = create_output_guard(
    include_defaults=False,
    custom_patterns=[my_pattern1, my_pattern2],
)
```

## PII Detection

PII detection is opt-in due to potential false positives:

```python
# Enable PII patterns
guard = OutputGuard(enable_pii=True)

# Or add selectively
from proxilion.guards.output_guard import DEFAULT_LEAKAGE_PATTERNS
from proxilion.guards import LeakageCategory

pii_patterns = [
    p for p in DEFAULT_LEAKAGE_PATTERNS
    if p.category == LeakageCategory.PII
]

for pattern in pii_patterns:
    guard.add_pattern(pattern)
```

### PII Patterns Included

- **Email addresses**: `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`
- **Phone numbers**: US format, `(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}`
- **Social Security Numbers**: `\d{3}[-\s]?\d{2}[-\s]?\d{4}`

## System Prompt Leakage

Detects when the LLM reveals its system prompt:

```python
# Pattern: system_prompt_leak
# Detects: "my instructions are", "i was told to", etc.
# Severity: 0.85

# Pattern: system_prompt_markers
# Detects: <<SYS>>, <|system|>, [SYSTEM], etc.
# Severity: 0.9
```

## Risk Score Calculation

Same as input guards:

```
risk_score = max(severity) + 0.1 * (pattern_count - 1)
```

Capped at 1.0.

## Configuration Updates

```python
guard.configure(
    action=GuardAction.WARN,
    threshold=0.7,
)
```

## Best Practices

1. **Start with credentials only**: Enable PII gradually based on needs
2. **Use redaction liberally**: Better safe than sorry
3. **Log detections separately**: Don't log actual secrets
4. **Test with real outputs**: Tune threshold based on false positive rate
5. **Combine with input guards**: Defense in depth
6. **Add custom patterns**: Cover domain-specific secrets

## Streaming Support

For streaming LLM responses, buffer and check in chunks:

```python
from proxilion.streaming import StreamingGuard

streaming_guard = StreamingGuard(output_guard=guard, buffer_size=100)

for chunk in llm.stream(prompt):
    safe_chunk = streaming_guard.process_chunk(chunk)
    if safe_chunk:
        yield safe_chunk
```

## Related

- [Input Guards](./input-guards.md) - Prevent prompt injection
- [Audit Logging](./audit-logging.md) - Track leakage attempts
- [Security Model](../security.md) - Overall security architecture

## API Reference

### OutputGuard

```python
class OutputGuard:
    def __init__(
        self,
        patterns: list[LeakagePattern] | None = None,
        filters: list[OutputFilter] | None = None,
        action: GuardAction = GuardAction.WARN,
        threshold: float = 0.5,
        enable_pii: bool = False,
    ) -> None

    def check(
        self,
        output_text: str,
        context: dict[str, Any] | None = None,
    ) -> GuardResult

    def redact(
        self,
        output_text: str,
        categories: list[LeakageCategory] | None = None,
    ) -> str

    def add_pattern(self, pattern: LeakagePattern) -> None
    def remove_pattern(self, name: str) -> bool
    def add_filter(self, filter_: OutputFilter) -> None
    def get_patterns(self) -> list[LeakagePattern]

    def configure(
        self,
        action: GuardAction | None = None,
        threshold: float | None = None,
    ) -> None
```

### LeakagePattern

```python
@dataclass
class LeakagePattern:
    name: str
    pattern: str
    category: LeakageCategory
    severity: float = 0.8
    description: str = ""
    redaction: str = "[REDACTED]"
```

### OutputFilter

```python
@dataclass
class OutputFilter:
    name: str
    check_func: Callable[[str, dict[str, Any] | None], bool]
    action: GuardAction = GuardAction.WARN
    description: str = ""
```
