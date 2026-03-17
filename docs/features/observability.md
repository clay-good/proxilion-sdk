# Observability

Real-time metrics, cost tracking, and alerting for LLM-powered applications.

## Overview

Proxilion's observability stack provides:

| Component | Purpose |
|-----------|---------|
| **MetricsCollector** | Track security events and metrics |
| **CostTracker** | Monitor token usage and costs |
| **AlertManager** | Real-time alerting via webhooks |
| **PrometheusExporter** | Export metrics in Prometheus format |

All components are thread-safe and optimized for production use.

## Metrics Collector

Collect and aggregate security metrics from Proxilion operations.

### Quick Start

```python
from proxilion.observability import MetricsCollector

collector = MetricsCollector()

# Record security events
collector.record_authorization(allowed=True, user="alice", resource="database")
collector.record_guard_block(guard_type="input", pattern="prompt_injection")
collector.record_rate_limit_hit(user="bob")
collector.record_circuit_open(service="external_api")

# Get summary statistics
stats = collector.get_summary()
print(f"Total authorizations: {stats['total_authorizations']}")
print(f"Denial rate: {stats['denial_rate']:.2%}")
print(f"Guard blocks: {stats['guard_blocks']}")
```

### Tracked Event Types

| Event | Method | Description |
|-------|--------|-------------|
| Authorization | `record_authorization()` | Tool call allowed/denied |
| Guard Block | `record_guard_block()` | Input/output guard triggered |
| Rate Limit | `record_rate_limit_hit()` | Rate limit exceeded |
| IDOR Violation | `record_idor_violation()` | IDOR attack attempt |
| Circuit Open | `record_circuit_open()` | Circuit breaker opened |
| Behavioral Drift | `record_behavioral_drift()` | Agent drift detected |
| Kill Switch | `record_kill_switch()` | Emergency halt activated |

### Custom Metrics

Track domain-specific metrics:

```python
# Increment counter
collector.increment_counter("custom_metric", value=1, labels={"type": "important"})

# Set gauge
collector.set_gauge("queue_depth", value=42)

# Record histogram value
collector.record_histogram("request_duration_ms", value=125.5)
```

### Event Window

Metrics collector maintains a sliding window of recent events:

```python
collector = MetricsCollector(
    event_window_size=10000,  # Keep last 10k events
    aggregation_window_seconds=60.0,  # Aggregate over 60 seconds
)

# Get recent events
events = collector.get_events(limit=100)

# Filter events by type
from proxilion.observability.metrics import EventType

auth_events = collector.get_events_by_type(EventType.AUTHORIZATION_ALLOWED)
```

### Real-Time Rates

Calculate event rates in real-time:

```python
stats = collector.get_summary()

# Events per second
print(f"Authorization rate: {stats['authorization_rate']:.2f}/s")
print(f"Block rate: {stats['block_rate']:.2f}/s")
print(f"Error rate: {stats['error_rate']:.2f}/s")
```

## Cost Tracker

Track token usage and costs per user, per model, per tool.

### Quick Start

```python
from proxilion.observability import CostTracker

tracker = CostTracker()

# Record LLM usage
record = tracker.record_usage(
    model="claude-sonnet-4-20250514",
    input_tokens=1000,
    output_tokens=500,
    user_id="alice",
    tool_name="database_query",
)

print(f"Cost: ${record.cost_usd:.4f}")
print(f"Model: {record.model}")
print(f"Total tokens: {record.input_tokens + record.output_tokens}")
```

### Built-in Pricing

Proxilion includes pricing for popular models:

| Model | Input | Output | Cache Read |
|-------|-------|--------|------------|
| Claude Opus 4.5 | $15/M | $75/M | $3.75/M |
| Claude Sonnet 4 | $3/M | $15/M | $0.60/M |
| Claude 3.5 Haiku | $1/M | $5/M | $0.10/M |
| GPT-4o | $2.50/M | $10/M | $1.25/M |
| GPT-4o Mini | $0.15/M | $0.60/M | $0.075/M |
| Gemini 1.5 Pro | $1.25/M | $5/M | $0.315/M |
| Gemini 2.0 Flash | $0.10/M | $0.40/M | - |

Prices are per 1M tokens (M = 1,000,000).

### Custom Pricing

Add pricing for custom models:

```python
from proxilion.observability import ModelPricing

tracker.register_pricing(
    model_id="custom-model-v1",
    pricing=ModelPricing(
        model_name="Custom Model v1",
        input_price_per_1k=0.002,
        output_price_per_1k=0.008,
    ),
)
```

### Budget Policies

Enforce budget limits:

```python
from proxilion.observability import BudgetPolicy

tracker = CostTracker(
    budget_policy=BudgetPolicy(
        max_cost_per_request=1.00,        # $1 per request
        max_cost_per_user_per_day=50.00,  # $50 per user per day
        max_cost_per_user_per_month=1000.00,  # $1000 per user per month
    ),
)

# Recording usage automatically checks budget
try:
    record = tracker.record_usage(
        model="claude-opus-4-5-20251101",
        input_tokens=100000,  # Very expensive
        output_tokens=50000,
        user_id="alice",
    )
except BudgetExceededError as e:
    print(f"Budget exceeded: {e.limit_type}")
    print(f"Current: ${e.current_cost:.2f}")
    print(f"Limit: ${e.limit:.2f}")
```

### Cost Summaries

Get cost breakdowns:

```python
# Per-user summary
summary = tracker.get_summary(user_id="alice")
print(f"Total cost: ${summary.total_cost:.2f}")
print(f"Total tokens: {summary.total_tokens:,}")
print(f"Request count: {summary.request_count}")

# Per-model summary
summary = tracker.get_summary(model="claude-sonnet-4-20250514")

# Per-tool summary
summary = tracker.get_summary(tool_name="database_query")

# Time range
from datetime import datetime, timedelta, timezone

end = datetime.now(timezone.utc)
start = end - timedelta(days=7)

summary = tracker.get_summary(
    user_id="alice",
    start_time=start,
    end_time=end,
)
```

### Cost Breakdowns

Get detailed cost breakdown by dimension:

```python
# By user
by_user = tracker.get_cost_by_user(start_time, end_time)
for user_id, cost in sorted(by_user.items(), key=lambda x: x[1], reverse=True):
    print(f"{user_id}: ${cost:.2f}")

# By model
by_model = tracker.get_cost_by_model(start_time, end_time)

# By tool
by_tool = tracker.get_cost_by_tool(start_time, end_time)
```

### Export Cost Data

```python
import json

# Export all usage records
records = tracker.export_usage_records(start_time, end_time)

with open("usage_report.jsonl", "w") as f:
    for record in records:
        f.write(json.dumps(record.to_dict()) + "\n")
```

## Alert Manager

Real-time alerting via webhooks (Slack, Discord, PagerDuty, etc.).

### Quick Start

```python
from proxilion.observability import AlertManager

alerts = AlertManager(
    webhook_url="https://hooks.slack.com/services/YOUR/WEBHOOK/URL",
)

# Add alert rules
alerts.add_rule(
    name="high_denial_rate",
    threshold=10,          # 10 denials
    window_seconds=60,     # in 60 seconds
    event_type="authorization_denied",
)

alerts.add_rule(
    name="guard_blocks",
    threshold=5,
    window_seconds=300,    # 5 minutes
    event_type="guard_block",
)

# Alert manager checks rules automatically when events are recorded
collector.add_event_callback(alerts.process_event)
```

### Alert Webhooks

AlertManager sends webhook payloads:

```json
{
  "alert_name": "high_denial_rate",
  "threshold": 10,
  "current_count": 15,
  "window_seconds": 60,
  "timestamp": "2024-03-14T10:30:00Z",
  "severity": "warning",
  "details": {
    "event_type": "authorization_denied",
    "users_affected": ["alice", "bob"],
    "resources": ["database", "api"]
  }
}
```

### Custom Alert Actions

Use callbacks instead of webhooks:

```python
def custom_alert_handler(alert_data: dict):
    """Custom alert handling logic."""
    print(f"ALERT: {alert_data['alert_name']}")
    # Send to PagerDuty, email, etc.

alerts = AlertManager(callback=custom_alert_handler)
```

## Prometheus Exporter

Export metrics in Prometheus format for scraping.

### Quick Start

```python
from proxilion.observability import PrometheusExporter

exporter = PrometheusExporter(collector)

# Export metrics
metrics_text = exporter.export()
print(metrics_text)
```

### Example Output

```prometheus
# HELP proxilion_authorizations_total Total authorization requests
# TYPE proxilion_authorizations_total counter
proxilion_authorizations_total{result="allowed"} 1523
proxilion_authorizations_total{result="denied"} 47

# HELP proxilion_guard_blocks_total Guard violations detected
# TYPE proxilion_guard_blocks_total counter
proxilion_guard_blocks_total{guard_type="input"} 23
proxilion_guard_blocks_total{guard_type="output"} 8

# HELP proxilion_rate_limits_total Rate limit hits
# TYPE proxilion_rate_limits_total counter
proxilion_rate_limits_total{limit_type="user"} 15
proxilion_rate_limits_total{limit_type="tool"} 7

# HELP proxilion_cost_usd_total Total cost in USD
# TYPE proxilion_cost_usd_total counter
proxilion_cost_usd_total{model="claude-sonnet-4-20250514"} 45.67

# HELP proxilion_tokens_total Total tokens used
# TYPE proxilion_tokens_total counter
proxilion_tokens_total{model="claude-sonnet-4-20250514",type="input"} 1523000
proxilion_tokens_total{model="claude-sonnet-4-20250514",type="output"} 876000
```

### HTTP Endpoint

Serve metrics via HTTP for Prometheus scraping:

```python
from http.server import HTTPServer, BaseHTTPRequestHandler

class MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/metrics":
            metrics = exporter.export()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(metrics.encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

server = HTTPServer(("0.0.0.0", 9090), MetricsHandler)
server.serve_forever()
```

### Prometheus Configuration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: "proxilion"
    static_configs:
      - targets: ["localhost:9090"]
    scrape_interval: 15s
```

## Integration with Proxilion Core

```python
from proxilion import Proxilion
from proxilion.observability import MetricsCollector, CostTracker, AlertManager

# Create observability stack
collector = MetricsCollector()
tracker = CostTracker()
alerts = AlertManager(webhook_url="https://hooks.slack.com/...")

# Configure alerts
alerts.add_rule("high_denial_rate", threshold=10, window_seconds=60)
collector.add_event_callback(alerts.process_event)

# Create Proxilion with observability
proxilion = Proxilion(
    policy_engine=my_policy,
    metrics_collector=collector,
    cost_tracker=tracker,
)

# Metrics are automatically collected during operations
result = proxilion.authorize_tool_call(user_context, tool_call)

# Track LLM costs
response = llm.generate(prompt)
tracker.record_usage(
    model=response.model,
    input_tokens=response.usage.input_tokens,
    output_tokens=response.usage.output_tokens,
    user_id=user_context.user_id,
)
```

## Dashboards

### Grafana Dashboard

Example Grafana dashboard queries:

```promql
# Authorization rate
rate(proxilion_authorizations_total[5m])

# Denial rate by user
rate(proxilion_authorizations_total{result="denied"}[5m])

# Guard block rate
rate(proxilion_guard_blocks_total[5m])

# Cost per hour
increase(proxilion_cost_usd_total[1h])

# Top users by cost
topk(10, increase(proxilion_cost_usd_total[24h]))
```

### Custom Dashboards

Export metrics for custom dashboards:

```python
# Get all metrics
metrics = collector.get_all_metrics()

# Transform for dashboard
dashboard_data = {
    "authorization_rate": metrics["authorization_rate"],
    "block_rate": metrics["block_rate"],
    "top_users": tracker.get_top_users(limit=10),
    "cost_by_model": tracker.get_cost_by_model(),
}

# Send to dashboard API
requests.post("https://dashboard.example.com/api/metrics", json=dashboard_data)
```

## Best Practices

1. **Set appropriate windows**: Balance memory usage with granularity
2. **Configure alerts**: Alert on anomalies, not normal operations
3. **Track costs**: Monitor spend daily, set budgets
4. **Export regularly**: Push metrics to external systems for long-term storage
5. **Monitor dashboards**: Create visibility for security and operations teams
6. **Test alert routing**: Ensure alerts reach the right people
7. **Tune thresholds**: Adjust based on baseline traffic patterns

## Performance Considerations

- **MetricsCollector**: O(1) event recording, bounded memory (deque)
- **CostTracker**: O(1) usage recording, periodic cleanup
- **AlertManager**: O(n) rule checking, where n = number of rules
- **PrometheusExporter**: O(m) export, where m = number of metrics

## Related

- [Audit Logging](./audit-logging.md) - Tamper-evident logs
- [Rate Limiting](./rate-limiting.md) - Request throttling
- [Security Controls](./security-controls.md) - Circuit breaker, IDOR, drift detection

## API Reference

### MetricsCollector

```python
class MetricsCollector:
    def __init__(
        self,
        event_window_size: int = 10000,
        aggregation_window_seconds: float = 60.0,
    ) -> None

    def record_authorization(
        self,
        allowed: bool,
        user: str | None = None,
        resource: str | None = None,
    ) -> None

    def record_guard_block(
        self,
        guard_type: str,
        pattern: str | None = None,
    ) -> None

    def record_rate_limit_hit(
        self,
        user: str | None = None,
        limit_type: str | None = None,
    ) -> None

    def get_summary(self) -> dict[str, Any]
    def get_events(self, limit: int = 100) -> list[SecurityEvent]
    def add_event_callback(self, callback: Callable[[SecurityEvent], None]) -> None
```

### CostTracker

```python
class CostTracker:
    def __init__(
        self,
        budget_policy: BudgetPolicy | None = None,
        pricing: dict[str, ModelPricing] | None = None,
    ) -> None

    def record_usage(
        self,
        model: str,
        input_tokens: int,
        output_tokens: int,
        user_id: str | None = None,
        tool_name: str | None = None,
        cache_read_tokens: int = 0,
        cache_write_tokens: int = 0,
    ) -> UsageRecord  # Raises BudgetExceededError

    def get_summary(
        self,
        user_id: str | None = None,
        model: str | None = None,
        tool_name: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> CostSummary

    def get_cost_by_user(
        self,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> dict[str, float]

    def register_pricing(self, model_id: str, pricing: ModelPricing) -> None
```

### AlertManager

```python
class AlertManager:
    def __init__(
        self,
        webhook_url: str | None = None,
        callback: Callable[[dict], None] | None = None,
    ) -> None

    def add_rule(
        self,
        name: str,
        threshold: int,
        window_seconds: float,
        event_type: str | None = None,
        severity: str = "warning",
    ) -> None

    def process_event(self, event: SecurityEvent) -> None
    def get_active_alerts(self) -> list[dict[str, Any]]
```

### PrometheusExporter

```python
class PrometheusExporter:
    def __init__(
        self,
        collector: MetricsCollector,
        cost_tracker: CostTracker | None = None,
    ) -> None

    def export(self) -> str  # Returns Prometheus text format
```

### BudgetPolicy

```python
@dataclass
class BudgetPolicy:
    max_cost_per_request: float | None = None
    max_cost_per_user_per_day: float | None = None
    max_cost_per_user_per_month: float | None = None
    max_tokens_per_request: int | None = None
```
