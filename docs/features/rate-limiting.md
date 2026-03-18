# Rate Limiting

Rate limiting protects your system from denial-of-service attacks, prevents unbounded consumption, and enforces fair usage policies.

## Overview

Proxilion provides three rate limiting strategies:

| Strategy | Best For | Algorithm |
|----------|----------|-----------|
| **Token Bucket** | Allowing bursts with sustained rate control | Tokens refill at fixed rate |
| **Sliding Window** | Consistent rate limiting without burst spikes | Tracks requests in rolling time window |
| **Multi-Dimensional** | Complex limits across user/tool/resource | Multiple limiters combined atomically |

All rate limiters are thread-safe and memory-efficient.

## Token Bucket Rate Limiter

The token bucket algorithm allows bursts up to capacity while maintaining a long-term average rate.

### Quick Start

```python
from proxilion.security import TokenBucketRateLimiter

# 100 requests with 10 req/sec refill
limiter = TokenBucketRateLimiter(
    capacity=100,
    refill_rate=10.0,  # tokens per second
)

# Check rate limit
if limiter.allow_request("user_123"):
    # Process request
    result = process_user_request()
else:
    # Rate limited
    retry_after = limiter.get_retry_after("user_123")
    raise RateLimitExceeded(f"Retry after {retry_after:.1f} seconds")
```

### Weighted Requests

Assign different costs to different operations:

```python
# Expensive operation costs 5 tokens
if limiter.allow_request("user_123", cost=5):
    result = expensive_database_query()

# Cheap operation costs 1 token (default)
if limiter.allow_request("user_123"):
    result = simple_lookup()
```

### Checking Remaining Capacity

```python
remaining = limiter.get_remaining("user_123")
print(f"Tokens remaining: {remaining}")

retry_after = limiter.get_retry_after("user_123", cost=10)
if retry_after > 0:
    print(f"Wait {retry_after:.2f} seconds for 10 tokens")
```

### Reset Buckets

```python
# Reset specific user
limiter.reset("user_123")

# Reset all buckets
limiter.reset_all()
```

### Memory Management

Token bucket automatically cleans up stale buckets to prevent memory leaks:

```python
# Manual cleanup (removes inactive buckets older than 1 hour)
removed = limiter.cleanup(max_age_seconds=3600)
print(f"Removed {removed} stale buckets")
```

## Sliding Window Rate Limiter

Provides more consistent rate limiting by tracking all requests in a time window.

### Quick Start

```python
from proxilion.security import SlidingWindowRateLimiter

# 100 requests per 60 seconds
limiter = SlidingWindowRateLimiter(
    max_requests=100,
    window_seconds=60.0,
)

if limiter.allow_request("user_123"):
    # Process request
    pass
```

### Advantages

- **No burst spikes**: Prevents users from consuming limit at window boundaries
- **Precise tracking**: Exact request count in rolling window
- **Predictable behavior**: No token refill logic

### Disadvantages

- **Higher memory usage**: Stores timestamp for each request
- **No burst allowance**: Stricter than token bucket

### When to Use

- APIs requiring strict rate limits
- Preventing coordinated attacks
- Public endpoints with high traffic

## Multi-Dimensional Rate Limiter

Apply multiple rate limits simultaneously across different dimensions.

### Quick Start

```python
from proxilion.security import MultiDimensionalRateLimiter, RateLimitConfig

limiter = MultiDimensionalRateLimiter({
    "user": RateLimitConfig(capacity=100, refill_rate=10),
    "tool": RateLimitConfig(capacity=50, refill_rate=5),
    "resource": RateLimitConfig(capacity=20, refill_rate=2),
    "global": RateLimitConfig(capacity=10000, refill_rate=1000),
})

# Check all dimensions atomically
keys = {
    "user": "user_123",
    "tool": "database_query",
    "resource": "prod_db",
}

if limiter.allow_request(keys):
    # All limits passed
    result = execute_tool_call()
else:
    # At least one limit exceeded
    dimension, remaining = limiter.get_most_restrictive(keys)
    raise RateLimitExceeded(f"{dimension} limit hit, {remaining} remaining")
```

### Per-Dimension Costs

Different dimensions can have different costs:

```python
costs = {
    "user": 1,     # Costs 1 user token
    "tool": 5,     # Costs 5 tool tokens (expensive operation)
    "resource": 2, # Costs 2 resource tokens
}

if limiter.allow_request(keys, costs=costs):
    result = expensive_operation()
```

### Find Most Restrictive Limit

```python
dimension, remaining = limiter.get_most_restrictive(keys)
print(f"Bottleneck: {dimension} ({remaining} remaining)")
```

### Sliding Window Mode

```python
# Use sliding window for all dimensions
limiter = MultiDimensionalRateLimiter(
    {
        "user": RateLimitConfig(
            capacity=100,
            refill_rate=10,
            window_seconds=60,  # Required for sliding window
        ),
    },
    use_sliding_window=True,
)
```

## Rate Limiter Middleware

Integrate rate limiting with tool call authorization.

### Quick Start

```python
from proxilion.security import RateLimiterMiddleware, TokenBucketRateLimiter
from proxilion.exceptions import RateLimitExceeded

middleware = RateLimiterMiddleware(
    user_limit=TokenBucketRateLimiter(capacity=100, refill_rate=10),
    tool_limits={
        "database_query": TokenBucketRateLimiter(capacity=10, refill_rate=1),
        "file_delete": TokenBucketRateLimiter(capacity=5, refill_rate=0.5),
    },
    global_limit=TokenBucketRateLimiter(capacity=10000, refill_rate=1000),
)

# Check rate limit before tool execution
try:
    middleware.check_rate_limit(
        user_id="user_123",
        tool_name="database_query",
        cost=1,
    )
    result = execute_tool()
except RateLimitExceeded as e:
    print(f"Rate limit exceeded: {e.limit_type}")
    print(f"Retry after: {e.retry_after} seconds")
```

### Rate Limit Headers

Generate HTTP headers for API responses:

```python
headers = middleware.get_headers(
    user_id="user_123",
    tool_name="database_query",
)

# Returns:
# {
#     "X-RateLimit-Limit": "100",
#     "X-RateLimit-Remaining": "87"
# }
```

## Decorator Integration

Use the `@rate_limited` decorator for automatic rate limiting:

```python
from proxilion.decorators import rate_limited
from proxilion.security import TokenBucketRateLimiter

limiter = TokenBucketRateLimiter(capacity=10, refill_rate=1)

@rate_limited(limiter, key_func=lambda user_id, **kw: user_id)
def expensive_operation(user_id: str, data: dict) -> dict:
    """Automatically rate limited per user."""
    return process_data(data)

# Raises RateLimitExceeded if limit hit
result = expensive_operation("user_123", {"query": "..."})
```

## Integration with Proxilion Core

```python
from proxilion import Proxilion
from proxilion.security import TokenBucketRateLimiter, RateLimiterMiddleware

# Create rate limiter
user_limiter = TokenBucketRateLimiter(capacity=100, refill_rate=10)
tool_limiters = {
    "database_query": TokenBucketRateLimiter(capacity=10, refill_rate=1),
}

middleware = RateLimiterMiddleware(
    user_limit=user_limiter,
    tool_limits=tool_limiters,
)

# Create Proxilion instance
proxilion = Proxilion(
    policy_engine=my_policy,
    rate_limiter=middleware,
)

# Rate limiting happens automatically during authorization
result = proxilion.authorize_tool_call(
    user_context=user,
    tool_call=tool_call,
)
```

## Common Patterns

### Per-User Rate Limiting

```python
# 100 requests per user with 10 req/sec refill
user_limiter = TokenBucketRateLimiter(capacity=100, refill_rate=10)

if user_limiter.allow_request(user_id):
    result = process_request()
```

### Per-Tool Rate Limiting

```python
# Different limits for different tools
tool_limiters = {
    "search": TokenBucketRateLimiter(capacity=100, refill_rate=20),
    "database_query": TokenBucketRateLimiter(capacity=10, refill_rate=1),
    "file_write": TokenBucketRateLimiter(capacity=5, refill_rate=0.5),
}

limiter = tool_limiters[tool_name]
if limiter.allow_request(f"{user_id}:{tool_name}"):
    result = execute_tool()
```

### IP-Based Rate Limiting

```python
# Rate limit by IP address
ip_limiter = TokenBucketRateLimiter(capacity=1000, refill_rate=100)

def rate_limit_by_ip(request):
    ip_address = request.remote_addr
    if not ip_limiter.allow_request(ip_address):
        raise RateLimitExceeded(f"IP {ip_address} rate limited")
```

### Time-of-Day Rate Limiting

```python
from datetime import datetime

def get_capacity_for_time() -> int:
    """Higher limits during business hours."""
    hour = datetime.now().hour
    if 9 <= hour < 17:  # Business hours
        return 1000
    else:  # Off hours
        return 100

# Recreate limiter based on time of day
current_limiter = TokenBucketRateLimiter(
    capacity=get_capacity_for_time(),
    refill_rate=10,
)
```

## Best Practices

1. **Choose the right algorithm**: Use token bucket for bursty workloads, sliding window for strict limits
2. **Set realistic limits**: Monitor usage patterns before enforcing
3. **Provide retry-after**: Always tell clients when they can retry
4. **Log rate limit hits**: Track abuse patterns
5. **Use multi-dimensional**: Combine user, tool, and global limits
6. **Clean up stale buckets**: Prevent memory leaks in long-running processes
7. **Cost-based limiting**: Expensive operations should cost more tokens

## Error Handling

```python
from proxilion.exceptions import RateLimitExceeded

try:
    limiter.check_rate_limit("user_123", "database_query")
    result = execute_query()
except RateLimitExceeded as e:
    # RateLimitExceeded fields:
    # - limit_type: "user", "tool", or "global"
    # - limit_key: The key that hit the limit
    # - limit_value: The limit capacity
    # - retry_after: Seconds until tokens available

    logging.warning(
        f"Rate limit hit: {e.limit_type} limit for {e.limit_key}, "
        f"retry after {e.retry_after:.1f}s"
    )

    # Return 429 response
    return {
        "error": "Rate limit exceeded",
        "retry_after": e.retry_after,
    }, 429
```

## Performance Considerations

### Token Bucket
- **Memory**: O(1) per key (just current tokens + timestamp)
- **Lookup**: O(1) with lock contention
- **Cleanup**: Automatic periodic cleanup of stale buckets

### Sliding Window
- **Memory**: O(n) where n = requests in window
- **Lookup**: O(n) to filter old requests
- **Cleanup**: Automatic periodic cleanup of empty keys

### Multi-Dimensional
- **Memory**: Sum of all dimension limiters
- **Lookup**: O(d) where d = number of dimensions
- **Atomic**: Single lock for all dimensions prevents TOCTOU races

## Related

- [Decorators](../quickstart.md#decorator-based-api) - Decorator-based rate limiting
- [Security Controls](./security-controls.md) - Circuit breaker, cascade protection
- [Cost Tracking](./observability.md#cost-tracker) - Track API costs alongside rate limits

## API Reference

### TokenBucketRateLimiter

```python
class TokenBucketRateLimiter:
    def __init__(
        self,
        capacity: int,
        refill_rate: float,
        key_func: Callable[[Any], str] | None = None,
    ) -> None

    def allow_request(self, key: str, cost: int = 1) -> bool
    def get_remaining(self, key: str) -> int
    def get_retry_after(self, key: str, cost: int = 1) -> float
    def reset(self, key: str) -> None
    def reset_all(self) -> None
    def cleanup(self, max_age_seconds: float = 3600.0) -> int
```

### SlidingWindowRateLimiter

```python
class SlidingWindowRateLimiter:
    def __init__(
        self,
        max_requests: int,
        window_seconds: float,
    ) -> None

    def allow_request(self, key: str, cost: int = 1) -> bool
    def get_remaining(self, key: str) -> int
    def get_retry_after(self, key: str) -> float
    def reset(self, key: str) -> None
    def reset_all(self) -> None
    def cleanup() -> int
```

### MultiDimensionalRateLimiter

```python
class MultiDimensionalRateLimiter:
    def __init__(
        self,
        limits: dict[str, RateLimitConfig],
        use_sliding_window: bool = False,
    ) -> None

    def allow_request(
        self,
        keys: dict[str, str],
        costs: dict[str, int] | None = None,
    ) -> bool

    def get_most_restrictive(
        self,
        keys: dict[str, str],
    ) -> tuple[str, int]
```

### RateLimiterMiddleware

```python
class RateLimiterMiddleware:
    def __init__(
        self,
        user_limit: TokenBucketRateLimiter | None = None,
        tool_limits: dict[str, TokenBucketRateLimiter] | None = None,
        global_limit: TokenBucketRateLimiter | None = None,
    ) -> None

    def check_rate_limit(
        self,
        user_id: str,
        tool_name: str,
        cost: int = 1,
    ) -> None  # Raises RateLimitExceeded

    def get_headers(
        self,
        user_id: str,
        tool_name: str,
    ) -> dict[str, str]
```
