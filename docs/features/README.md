# Features Guide

Comprehensive documentation for all Proxilion features.

## Feature Overview

| Feature | Purpose | OWASP ASI |
|---------|---------|-----------|
| [Authorization Engine](./authorization.md) | Policy-based access control | ASI04, ASI06 |
| [Input Validation](./input-validation.md) | Block malicious inputs | ASI01 |
| [Agent Trust](./agent-trust.md) | Trust levels for agents | ASI08 |
| [IDOR Protection](./idor-protection.md) | Prevent object reference attacks | ASI03 |
| [Context Integrity](./context-integrity.md) | Cryptographic context verification | ASI09 |
| [Intent Capsules](./intent-capsules.md) | Scope-bound intent verification | ASI01 |
| [Behavioral Drift](./behavioral-drift.md) | Anomaly detection | ASI08 |
| [Kill Switch](./kill-switch.md) | Emergency halt mechanism | ASI04 |
| [Rate Limiting](./rate-limiting.md) | Prevent abuse | ASI07 |
| [Circuit Breaker](./circuit-breaker.md) | Failure isolation | ASI05 |
| [Cost Tracking](./cost-tracking.md) | Budget enforcement | ASI07 |
| [Audit Logging](./audit-logging.md) | Tamper-evident logs | ASI10 |
| [Explainability](./explainability.md) | CA SB 53 compliance | - |
| [Metrics](./metrics.md) | Real-time observability | ASI10 |

## Quick Links

### Core Security
- [Authorization Engine](./authorization.md) - The foundation of Proxilion
- [Input Validation](./input-validation.md) - First line of defense
- [Agent Trust](./agent-trust.md) - Multi-tenant agent security

### Advanced Security
- [Intent Capsules](./intent-capsules.md) - Scope-bound operations
- [Behavioral Drift](./behavioral-drift.md) - Statistical anomaly detection
- [Kill Switch](./kill-switch.md) - Emergency controls

### Observability
- [Cost Tracking](./cost-tracking.md) - Per-user/agent cost management
- [Audit Logging](./audit-logging.md) - Comprehensive audit trails
- [Metrics](./metrics.md) - Prometheus-compatible metrics
