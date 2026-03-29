<p align="center">
  <img src="https://cdn.prod.website-files.com/68e09cef90d613c94c3671c0/697e805a9246c7e090054706_logo_horizontal_grey.png" alt="Yeti" width="200" />
</p>

---

# app-siem

[![Yeti](https://img.shields.io/badge/Yeti-Application-blue)](https://yetirocks.com)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> **[Yeti](https://yetirocks.com)** - The Performance Platform for Agent-Driven Development.
> Schema-driven APIs, real-time streaming, and vector search. From prompt to production.

**AI-powered security event analysis with cost controls.** Ingest, analyze, escalate, budget.

app-siem turns raw security events from any source -- Akamai, Cloudflare, AWS WAF, custom webhooks -- into structured AI analysis using tiered Anthropic models. Haiku handles routine batches cheaply, Sonnet kicks in when deny ratios spike, and Opus produces strategic reviews across time windows. Every token is tracked against daily budgets with warning thresholds and hard caps that halt analysis before costs run away. Seven built-in attack simulations let you demo and test the full pipeline without real traffic.

---

## Why app-siem

Security teams drown in events. A mid-size WAF generates thousands of alerts per hour, and most of them are noise. Manual triage does not scale -- analysts burn out on repetitive pattern matching while real threats hide in the volume. AI analysis solves the triage problem, but running every event through a large model is prohibitively expensive and operationally reckless without cost controls.

app-siem solves this with a tiered approach:

- **Cost-aware model selection** -- Haiku processes routine batches at $0.25/MTok input. When the deny ratio crosses 30%, Sonnet takes over at $3/MTok. Opus is reserved for strategic reviews only. You get the right model for the right severity.
- **Intelligent sampling** -- batches of thousands of events are distilled into 50-event samples using a weighted strategy: 40% deny events, 30% high risk, 20% high bot score, 10% random. Full coverage, fraction of the cost.
- **Hard budget caps** -- daily spending is tracked per model tier. A warning fires at $5. Analysis halts entirely at $10. No surprises on the invoice.
- **Real-time SOC streaming** -- events and analyses stream via SSE and MQTT the moment they arrive. Dashboards stay live without polling.
- **Simulation mode** -- seven attack scenarios generate realistic events for testing, demos, and pipeline validation without touching production traffic.
- **Single binary deployment** -- compiles to a native Rust plugin. No Python, no Elasticsearch, no Kafka. Loads with yeti in seconds.

---

## Quick Start

### 1. Install

```bash
cd ~/yeti/applications
git clone https://github.com/yetirocks/app-siem.git
```

Restart yeti. app-siem compiles automatically on first load (~2 minutes) and is cached for subsequent starts (~10 seconds).

### 2. Configure API key

```bash
curl -X POST https://localhost:9996/app-siem/Settings \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "id": "default",
    "anthropicApiKey": "sk-ant-...",
    "batchThreshold": 500,
    "dailyBudgetWarning": 5.0,
    "dailyBudgetHardCap": 10.0
  }'
```

Response:
```json
{
  "id": "default",
  "anthropicApiKey": "sk-ant-...",
  "batchThreshold": 500,
  "dailyBudgetWarning": 5.0,
  "dailyBudgetHardCap": 10.0
}
```

### 3. Ingest events

```bash
curl -X POST https://localhost:9996/app-siem/ingest \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '[
    {
      "source": "cloudflare",
      "sourceIp": "203.0.113.42",
      "action": "deny",
      "category": "sqli",
      "method": "POST",
      "path": "/api/login",
      "riskScore": 92
    },
    {
      "source": "cloudflare",
      "sourceIp": "198.51.100.7",
      "action": "allow",
      "category": "bot",
      "method": "GET",
      "path": "/robots.txt",
      "riskScore": 15,
      "botScore": 88
    }
  ]'
```

Response:
```json
{
  "ingested": 2,
  "duplicates": 0,
  "batchId": "batch-1711700000",
  "total": 2
}
```

### 4. Run batch analysis

```bash
curl -X POST https://localhost:9996/app-siem/analyze \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{ "batchId": "batch-1711700000" }'
```

Response:
```json
{
  "id": "ab-1711700100",
  "createdAt": "1711700100",
  "model": "haiku",
  "eventCount": 2,
  "sampledCount": 2,
  "severity": "high",
  "analysis": "SQL injection attempt detected from 203.0.113.42 targeting /api/login...",
  "flags": "[\"sqli-active\", \"single-source-attack\"]",
  "notableIps": "[\"203.0.113.42\"]",
  "notablePatterns": "[\"POST /api/login with risk 92\"]",
  "tokenInput": 1200,
  "tokenOutput": 450,
  "costUsd": "0.000863",
  "escalated": "false",
  "triggerReason": "manual"
}
```

### 5. Run simulation

```bash
curl -X POST https://localhost:9996/app-siem/simulate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{ "scenario": "credential_stuffing", "count": 100 }'
```

Response:
```json
{
  "scenario": "credential_stuffing",
  "generated": 100,
  "batchId": "sim-1711700200"
}
```

### 6. Check costs

```bash
curl https://localhost:9996/app-siem/CostTracking/day-19810 \
  -H "Authorization: Bearer $TOKEN"
```

Response:
```json
{
  "id": "day-19810",
  "haikuInput": 1200,
  "haikuOutput": 450,
  "sonnetInput": 0,
  "sonnetOutput": 0,
  "opusInput": 0,
  "opusOutput": 0,
  "totalCostUsd": "0.000863",
  "budgetWarning": "false",
  "budgetExceeded": "false",
  "escalationCount": 0
}
```

---

## Architecture

```
Event Sources (Akamai, Cloudflare, AWS WAF, webhooks)
    |
    v
POST /app-siem/ingest
    |
    +-- dedup (hash of source+ip+timestamp+path)
    +-- severity inference (risk/action/category)
    |
    v
+-----------------------------------------------+
|                  app-siem                      |
|                                                |
|  +---------+   +--------------+   +--------+  |
|  |  Event  |   |AnalysisBatch |   |Settings|  |
|  | (7d TTL)|   |  (90d TTL)   |   |        |  |
|  +---------+   +--------------+   +--------+  |
|       |               |                        |
|       |  batch trigger |                       |
|       +-------->-------+                       |
|                |                               |
|   +------------+------------+                  |
|   |            |            |                  |
|   v            v            v                  |
|  Haiku      Sonnet       Opus                  |
|  (routine)  (escalated)  (strategic)           |
|   |            |            |                  |
|   v            v            v                  |    +-------------+
|  AnalysisBatch       AnalysisStrategic         |    |CostTracking |
|  (per batch)         (24h window)              |    | (per day)   |
|                                                |    +-------------+
+-----------------------------------------------+
    |
    v
Yeti (embedded RocksDB, SSE + MQTT broker)
```

**Ingest path:** Event source -> POST /ingest -> dedup check (deterministic hash) -> severity inference -> store in Event table -> broadcast via SSE + MQTT.

**Analysis path:** POST /analyze with batchId -> load events -> compute deny ratio -> select model (Haiku default, Sonnet if deny >= 30%) -> sample 50 events (40/30/20/10 weighted split) -> Anthropic API call -> store AnalysisBatch -> update CostTracking.

**Strategic path:** POST /analyze with `strategic: true` -> load last 24h of AnalysisBatch records -> Opus analysis -> store AnalysisStrategic -> update CostTracking.

**Cost control:** Every API call updates the daily CostTracking record. Warning at $5. Hard cap at $10 returns HTTP 429 and halts all analysis.

---

## Features

### Event Ingestion (POST /app-siem/ingest)

Ingest security events from any source. Accepts a single event object or a JSON array (max 10,000 events per request).

| Field | Type | Description |
|-------|------|-------------|
| `source` | String | Origin: "akamai", "cloudflare", "aws-waf", "custom" |
| `sourceIp` | String | Attacker/client IP address |
| `destinationIp` | String | Target server IP |
| `action` | String | WAF action: "deny", "allow", "alert", "monitor" |
| `severity` | String | Override: "critical", "high", "medium", "low", "info" |
| `category` | String | Attack type: "sqli", "xss", "credential_stuffing", "bot", "ddos", "path_traversal" |
| `method` | String | HTTP method |
| `path` | String | Request path |
| `host` | String | Target hostname |
| `userAgent` | String | Client user-agent string |
| `country` | String | GeoIP country code |
| `riskScore` | Int | 0-100 risk score from source |
| `botScore` | Int | 0-100 bot probability from source |
| `rules` | String | JSON array of triggered rule IDs |
| `rawPayload` | String | Original event payload (truncated to 4KB) |
| `metadata` | String | Arbitrary JSON key-value pairs |

**Deduplication:** Each event gets a deterministic ID computed from `hash(source + sourceIp + timestamp + path)`. If an event with the same ID already exists, it is counted as a duplicate and skipped.

**Severity inference:** When `severity` is not provided, it is inferred automatically:

| Condition | Inferred Severity |
|-----------|-------------------|
| riskScore >= 90, or category is credential_stuffing/ddos | critical |
| riskScore >= 70, or action is deny | high |
| riskScore >= 40 | medium |
| riskScore >= 20, or action is alert | low |
| Everything else | info |

### Batch Analysis (POST /app-siem/analyze)

Run AI analysis on a batch of ingested events. Provide `{ "batchId": "batch-..." }` to analyze a specific batch.

**Model escalation logic:**

| Condition | Model | Input Rate | Output Rate |
|-----------|-------|------------|-------------|
| Deny ratio < 30% (default) | claude-haiku-4-5-20251001 | $0.25/MTok | $1.25/MTok |
| Deny ratio >= 30% | claude-sonnet-4-6 | $3.00/MTok | $15.00/MTok |

**Sampling strategy:** When a batch exceeds 50 events, the analyzer selects a representative sample:

| Priority | Allocation | Selection Criteria |
|----------|------------|-------------------|
| 1 | 40% (20 events) | Events with action = "deny" |
| 2 | 30% (15 events) | Events with riskScore >= 70 |
| 3 | 20% (10 events) | Events with botScore >= 70 |
| 4 | 10% (5 events) | Random fill from remaining events |

The AI receives the sampled events and returns structured JSON with severity assessment, flags, notable IPs, and detected patterns. The response is stored as an AnalysisBatch record.

Returns HTTP 429 when the daily budget hard cap is exceeded.

### Strategic Analysis (POST /app-siem/analyze)

Trigger a strategic review with `{ "strategic": true }`. Always uses claude-opus-4-6 ($15/$75 per MTok).

Strategic analysis reviews all AnalysisBatch records from the last 24 hours, synthesizing cross-batch patterns into recommendations, campaign detection, and policy effectiveness notes. Results are stored as AnalysisStrategic records with a 180-day TTL.

### Simulation Mode (POST /app-siem/simulate)

Generate realistic attack events for testing and demos. Events are written to the real Event table with `source: "simulation"`.

| Field | Type | Description |
|-------|------|-------------|
| `scenario` | String | Attack scenario name (see table below) |
| `count` | Int | Number of events to generate (default 50, max 1000) |

**Available scenarios:**

| Scenario | Description | Default Severity | Typical Risk Score |
|----------|-------------|-----------------|-------------------|
| `credential_stuffing` | Login brute-force from rotating IPs (5 IPs, bot user-agents, CN/RU/BR/VN/ID) | high | 70-99 |
| `sqli` | SQL injection probes (sqlmap, UNION SELECT, xp_cmdshell payloads) | critical | 90-99 |
| `xss` | Cross-site scripting attempts on comment/input endpoints | high | 75-99 |
| `path_traversal` | Directory traversal with encoded sequences (../../etc/passwd) | critical | 85-99 |
| `bot_scanner` | Vulnerability scanners probing /.env, /wp-admin, /.git/config | medium | 30-79 |
| `ddos` | Distributed flood from unique IPs across 8 countries | critical | 95 |
| `mixed` | Round-robin of all six scenarios | varies | varies |

### Cost Tracking

Every AI analysis call updates the daily CostTracking record. The system enforces two thresholds:

| Threshold | Default | Behavior |
|-----------|---------|----------|
| Budget warning | $5.00/day | Sets `budgetWarning: "true"` on the daily record |
| Hard cap | $10.00/day | Sets `budgetExceeded: "true"`, returns HTTP 429, halts all analysis |

**Model pricing (per million tokens):**

| Model | Input | Output | Used For |
|-------|-------|--------|----------|
| Haiku (claude-haiku-4-5-20251001) | $0.25 | $1.25 | Default batch analysis |
| Sonnet (claude-sonnet-4-6) | $3.00 | $15.00 | Escalated batch analysis (deny ratio >= 30%) |
| Opus (claude-opus-4-6) | $15.00 | $75.00 | Strategic analysis only |

Escalation count is tracked per day -- every non-Haiku analysis increments the counter.

### Real-Time Streaming (auto-generated)

Real-time updates are built into the platform via `@export(sse: true, mqtt: true)`:

```bash
# SSE -- server-sent events for SOC dashboards
curl "https://localhost:9996/app-siem/Event?stream=sse" --max-time 60

# SSE -- stream batch analysis results
curl "https://localhost:9996/app-siem/AnalysisBatch?stream=sse" --max-time 60

# MQTT -- subscribe to security events
mosquitto_sub -t "app-siem/Event" -h localhost -p 8883

# MQTT -- subscribe to batch analyses
mosquitto_sub -t "app-siem/AnalysisBatch" -h localhost -p 8883
```

When events are ingested, every subscribed SOC dashboard receives them immediately.

### REST CRUD (auto-generated)

Full CRUD on all tables is auto-generated from the schema:

| Endpoint | Methods | Description |
|----------|---------|-------------|
| `/app-siem/Event` | GET, POST | List/create events |
| `/app-siem/Event/{id}` | GET, PUT, DELETE | Read/update/delete an event |
| `/app-siem/AnalysisBatch` | GET, POST | List/create batch analyses |
| `/app-siem/AnalysisBatch/{id}` | GET, PUT, DELETE | Read/update/delete a batch analysis |
| `/app-siem/AnalysisStrategic` | GET, POST | List/create strategic analyses |
| `/app-siem/AnalysisStrategic/{id}` | GET, PUT, DELETE | Read/update/delete a strategic analysis |
| `/app-siem/CostTracking` | GET, POST | List/create cost records |
| `/app-siem/CostTracking/{id}` | GET, PUT, DELETE | Read/update/delete a cost record |
| `/app-siem/Settings` | GET, POST | List/create settings |
| `/app-siem/Settings/{id}` | GET, PUT, DELETE | Read/update/delete settings |

Use `?limit=N` on collection endpoints to control result count. Use `?stream=sse` on exported tables for real-time streaming.

---

## Data Model

### Event Table

7-day TTL. Public read and subscribe access for SOC dashboards.

| Field | Type | Indexed | Description |
|-------|------|---------|-------------|
| `id` | ID! | Primary key | Deterministic hash: `evt-{hash(source+ip+ts+path)}` |
| `timestamp` | String! | Yes | Unix timestamp of the event |
| `source` | String! | Yes | Origin system: "akamai", "cloudflare", "aws-waf", "custom", "simulation" |
| `sourceIp` | String | Yes | Client/attacker IP address |
| `destinationIp` | String | -- | Target server IP |
| `action` | String | Yes | WAF action: "deny", "allow", "alert", "monitor" |
| `severity` | String | Yes | "critical", "high", "medium", "low", "info" (auto-inferred if omitted) |
| `category` | String | Yes | Attack category: "credential_stuffing", "sqli", "xss", "bot", "ddos", "path_traversal" |
| `method` | String | -- | HTTP method |
| `path` | String | -- | Request path |
| `host` | String | -- | Target hostname |
| `userAgent` | String | -- | Client user-agent string |
| `country` | String | Yes | GeoIP country code |
| `riskScore` | Int | -- | 0-100 risk score from source |
| `botScore` | Int | -- | 0-100 bot probability from source |
| `rules` | String | -- | JSON array of triggered rule IDs/names |
| `rawPayload` | String | -- | Original event payload (truncated to 4KB) |
| `batchId` | String | Yes | Links event to its ingestion batch |
| `metadata` | String | -- | Arbitrary JSON key-value pairs |

### AnalysisBatch Table

90-day TTL. AI-generated analysis of event batches.

| Field | Type | Indexed | Description |
|-------|------|---------|-------------|
| `id` | ID! | Primary key | Format: `ab-{timestamp}` |
| `createdAt` | String! | -- | Unix timestamp of analysis |
| `model` | String! | -- | Model used: "haiku", "sonnet", "opus" |
| `eventCount` | Int! | -- | Total events in the batch |
| `sampledCount` | Int! | -- | Number of events sent to the AI |
| `severity` | String! | Yes | Overall batch severity assessment |
| `analysis` | String! | -- | AI-generated analysis text |
| `flags` | String | -- | JSON array of flag strings |
| `notableIps` | String | -- | JSON array of notable IPs with context |
| `notablePatterns` | String | -- | JSON array of detected attack patterns |
| `tokenInput` | Int | -- | Input tokens consumed |
| `tokenOutput` | Int | -- | Output tokens generated |
| `costUsd` | String | -- | Cost as string (avoids float precision issues) |
| `escalated` | String | -- | "true" if model was escalated from default |
| `triggerReason` | String | -- | "count", "time", "severity", or "manual" |

### AnalysisStrategic Table

180-day TTL. Opus-tier strategic reviews across time windows.

| Field | Type | Indexed | Description |
|-------|------|---------|-------------|
| `id` | ID! | Primary key | Format: `as-{timestamp}` |
| `createdAt` | String! | -- | Unix timestamp of analysis |
| `model` | String! | -- | Always "opus" for strategic reviews |
| `periodStart` | String! | -- | Start of reviewed time window (unix timestamp) |
| `periodEnd` | String! | -- | End of reviewed time window (unix timestamp) |
| `batchCount` | Int! | -- | Number of batch analyses reviewed |
| `analysis` | String! | -- | AI-generated strategic analysis text |
| `severity` | String! | Yes | Overall severity for the period |
| `recommendations` | String | -- | JSON array of actionable recommendations |
| `campaignsDetected` | String | -- | JSON array of detected attack campaigns |
| `policyNotes` | String | -- | JSON array of policy effectiveness observations |
| `flags` | String | -- | JSON array of flag strings |
| `tokenInput` | Int | -- | Input tokens consumed |
| `tokenOutput` | Int | -- | Output tokens generated |
| `costUsd` | String | -- | Cost as string |

### CostTracking Table

No expiration. Daily token usage and cost per model tier.

| Field | Type | Indexed | Description |
|-------|------|---------|-------------|
| `id` | ID! | Primary key | Date key: `day-{epoch_days}` |
| `haikuInput` | Int | -- | Haiku input tokens for the day |
| `haikuOutput` | Int | -- | Haiku output tokens for the day |
| `sonnetInput` | Int | -- | Sonnet input tokens for the day |
| `sonnetOutput` | Int | -- | Sonnet output tokens for the day |
| `opusInput` | Int | -- | Opus input tokens for the day |
| `opusOutput` | Int | -- | Opus output tokens for the day |
| `totalCostUsd` | String | -- | Total USD cost for the day |
| `budgetWarning` | String | -- | "true" if daily cost exceeded warning threshold |
| `budgetExceeded` | String | -- | "true" if daily cost exceeded hard cap |
| `escalationCount` | Int | -- | Number of non-Haiku analyses for the day |

### Settings Table

No expiration. Runtime configuration for the application.

| Field | Type | Indexed | Description |
|-------|------|---------|-------------|
| `id` | ID! | Primary key | "default" for global settings |
| `anthropicApiKey` | String | -- | Anthropic API key for model calls |
| `batchThreshold` | Int | -- | Event count to trigger batch analysis (default 500) |
| `timeCeiling` | Int | -- | Seconds before forced batch analysis (default 300) |
| `denyRatioEscalation` | Float | -- | Deny ratio threshold for model escalation (default 0.3) |
| `dailyBudgetWarning` | Float | -- | USD warning threshold (default 5.0) |
| `dailyBudgetHardCap` | Float | -- | USD hard cap that halts analysis (default 10.0) |
| `strategicInterval` | Int | -- | Hours between strategic analyses (default 24) |
| `simulationMode` | String | -- | "true" to enable simulation endpoints |

---

## Configuration

### Settings (PUT /app-siem/Settings/default)

All runtime configuration is stored in the Settings table. Update via REST:

```bash
curl -X PUT https://localhost:9996/app-siem/Settings/default \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "id": "default",
    "anthropicApiKey": "sk-ant-...",
    "batchThreshold": 500,
    "timeCeiling": 300,
    "denyRatioEscalation": 0.3,
    "dailyBudgetWarning": 5.0,
    "dailyBudgetHardCap": 10.0,
    "strategicInterval": 24,
    "simulationMode": "false"
  }'
```

| Setting | Default | Description |
|---------|---------|-------------|
| `anthropicApiKey` | (none) | **Required.** Anthropic API key. Analysis fails without it. |
| `batchThreshold` | 500 | Number of events that triggers automatic batch analysis |
| `timeCeiling` | 300 | Seconds before forcing a batch analysis regardless of count |
| `denyRatioEscalation` | 0.3 | Deny ratio (0.0-1.0) that triggers Haiku -> Sonnet escalation |
| `dailyBudgetWarning` | 5.0 | USD threshold that sets the budget warning flag |
| `dailyBudgetHardCap` | 10.0 | USD threshold that halts all analysis (returns HTTP 429) |
| `strategicInterval` | 24 | Hours between strategic (Opus) analysis runs |
| `simulationMode` | "false" | Set to "true" to enable the simulate endpoint |

### Application Config (config.yaml)

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

---

## Project Structure

```
app-siem/
  config.yaml              # App configuration
  schemas/
    schema.graphql         # Event, AnalysisBatch, AnalysisStrategic, CostTracking, Settings tables
  resources/
    ingest.rs              # Event ingestion with dedup and severity inference
    analyze.rs             # Tiered AI analysis (batch + strategic) with cost tracking
    simulate.rs            # 7 attack scenario generators
```

---

## Authentication

app-siem uses yeti's built-in auth system. In development mode, all endpoints are accessible without authentication. In production:

- **JWT** and **Basic Auth** supported (configured in config.yaml)
- Event table allows public `read` and `subscribe` access (for SOC dashboards)
- AnalysisBatch table allows public `read` and `subscribe` access
- AnalysisStrategic table allows public `read` access
- Write operations (ingest, analyze, simulate) require authentication
- Settings table requires authentication for all operations

---

## Comparison

| | app-siem | Building Your Own |
|---|---|---|
| **Deployment** | Loads with yeti, zero config | Elasticsearch + Logstash + Kibana + custom AI pipeline |
| **AI analysis** | Tiered models with auto-escalation | Custom LLM integration per analysis type |
| **Cost control** | Built-in daily budgets and hard caps | Custom cost tracking, easy to forget |
| **Ingestion** | Single POST endpoint, dedup included | Custom parsers per source, separate dedup layer |
| **Real-time** | Native SSE + MQTT from schema | Custom WebSocket server or external broker |
| **Simulation** | 7 built-in attack scenarios | Write custom event generators |
| **Auth** | Built-in JWT/Basic from yeti | Custom auth implementation |
| **Storage** | Embedded RocksDB with automatic TTL | Separate database, manual retention policies |
| **Binary** | Compiles to native Rust plugin | Python/Node.js runtime + dependencies |

---

Built with [Yeti](https://yetirocks.com) | The Performance Platform for Agent-Driven Development
