<p align="center">
  <img src="https://cdn.prod.website-files.com/68e09cef90d613c94c3671c0/697e805a9246c7e090054706_logo_horizontal_grey.png" alt="Yeti" width="200" />
</p>

---

# app-siem

[![Yeti](https://img.shields.io/badge/Yeti-Application-blue)](https://yetirocks.com)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> **[Yeti](https://yetirocks.com)** - The Performance Platform for Agent-Driven Development.
> Schema-driven APIs, real-time streaming, and vector search. From prompt to production.

Security event ingestion with tiered AI analysis, cost tracking, and real-time SOC streaming.

## Features

- **Event ingestion** from any source (Akamai, Cloudflare, AWS WAF, custom webhooks) with deduplication
- **Tiered AI analysis** -- Haiku for routine batches, Sonnet when deny ratios spike, Opus for strategic reviews
- **Cost tracking** with daily budgets, warning thresholds ($5), and hard caps ($10) that halt analysis
- **Simulation mode** with 7 attack scenarios for demos and testing
- **Real-time streaming** via SSE and MQTT on Event and AnalysisBatch tables
- **Automatic severity inference** from risk scores, actions, and attack categories
- **Batch sampling** -- intelligent 40/30/20/10 split (deny/high-risk/high-bot/random) for cost-efficient analysis

## Installation

```bash
git clone https://github.com/yetirocks/app-siem.git
cp -r app-siem ~/yeti/applications/
```

## Project Structure

```
app-siem/
  config.yaml
  schemas/
    schema.graphql
  resources/
    ingest.rs       # Event ingestion with dedup and severity inference
    analyze.rs      # Tiered AI analysis (batch + strategic)
    simulate.rs     # Attack scenario simulation
```

## Configuration

```yaml
name: "SIEM Analyzer"
app_id: "app-siem"
version: "0.1.0"
description: "Security event ingestion with tiered AI analysis, cost tracking, and real-time SOC dashboard"

schemas:
  - schemas/schema.graphql

resources:
  - resources/*.rs

auth:
  methods: [jwt, basic]
```

## Schema

**Event** -- Ingested security events with 7-day TTL. Public read and subscribe access for SOC dashboards. Fields include source, sourceIp, action, severity, category, riskScore, botScore, and the raw payload.

**AnalysisBatch** -- AI-generated batch analysis results with 90-day TTL. Each record captures the model used, event/sample counts, severity assessment, notable IPs, detected patterns, and token cost.

**AnalysisStrategic** -- Opus-tier strategic analysis with 180-day TTL. Covers a time window of batch analyses, producing recommendations, campaign detection, and policy effectiveness notes.

**CostTracking** -- Daily token usage and cost per model tier. Tracks budget warnings and hard cap breaches.

**Settings** -- Runtime configuration including Anthropic API key, batch thresholds, escalation ratios, budget limits, and simulation mode toggle.

```graphql
type Event @table(expiration: 604800, database: "app-siem")
    @export(sse: true, mqtt: true, public: [read, subscribe]) {
    id: ID! @primaryKey
    timestamp: String! @indexed
    source: String! @indexed
    sourceIp: String @indexed
    action: String @indexed          # "deny", "allow", "alert", "monitor"
    severity: String @indexed        # "critical", "high", "medium", "low", "info"
    category: String @indexed        # "credential_stuffing", "sqli", "xss", "bot", "ddos", "path_traversal"
    riskScore: Int                   # 0-100
    botScore: Int                    # 0-100
    # ... plus method, path, host, userAgent, country, rules, rawPayload, batchId, metadata
}

type AnalysisBatch @table(expiration: 7776000, database: "app-siem")
    @export(sse: true, public: [read, subscribe]) { ... }

type AnalysisStrategic @table(expiration: 15552000, database: "app-siem")
    @export(public: [read]) { ... }

type CostTracking @table(database: "app-siem") @export { ... }

type Settings @table(database: "app-siem") @export { ... }
```

## API Reference

### POST /app-siem/ingest

Ingest one or more security events. Accepts a single event object or an array (max 10,000). Events are deduplicated by a deterministic hash of source + sourceIp + timestamp + path. Severity is auto-inferred from risk scores and categories when not provided.

```bash
# Single event
curl -X POST https://localhost:9996/app-siem/ingest \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "source": "cloudflare",
    "sourceIp": "203.0.113.42",
    "action": "deny",
    "category": "sqli",
    "method": "POST",
    "path": "/api/login",
    "riskScore": 92
  }'

# Response
# 201 { "ingested": 1, "duplicates": 0, "batchId": "batch-1711700000", "total": 1 }
```

```bash
# Batch of events
curl -X POST https://localhost:9996/app-siem/ingest \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '[
    { "source": "akamai", "sourceIp": "10.0.0.1", "action": "deny", "severity": "high", "category": "credential_stuffing" },
    { "source": "akamai", "sourceIp": "10.0.0.2", "action": "allow", "severity": "low", "category": "bot" }
  ]'
```

### POST /app-siem/analyze

Run AI analysis on a batch of events, or trigger a strategic review.

```bash
# Batch analysis (Haiku default, escalates to Sonnet if deny ratio >= 30%)
curl -X POST https://localhost:9996/app-siem/analyze \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{ "batchId": "batch-1711700000" }'

# Strategic analysis (always Opus, reviews last 24h of batch analyses)
curl -X POST https://localhost:9996/app-siem/analyze \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{ "strategic": true }'
```

Returns 429 when the daily budget hard cap is exceeded.

### POST /app-siem/simulate

Generate simulated attack events for testing and demos.

```bash
curl -X POST https://localhost:9996/app-siem/simulate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{ "scenario": "credential_stuffing", "count": 100 }'

# Response
# 201 { "scenario": "credential_stuffing", "generated": 100, "batchId": "sim-1711700000" }
```

**Scenarios:** `credential_stuffing`, `sqli`, `xss`, `path_traversal`, `bot_scanner`, `ddos`, `mixed`

### Table Endpoints (auto-generated)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/app-siem/Event?limit=50` | List recent events |
| GET | `/app-siem/Event/{id}` | Get single event |
| GET | `/app-siem/Event?stream=sse` | Real-time event stream |
| GET | `/app-siem/AnalysisBatch?limit=10` | List batch analyses |
| GET | `/app-siem/AnalysisStrategic?limit=5` | List strategic analyses |
| GET | `/app-siem/CostTracking/{date}` | Daily cost record |
| GET/PUT | `/app-siem/Settings/default` | Read/update settings |

---

Built with [Yeti](https://yetirocks.com) | The Performance Platform for Agent-Driven Development
