use yeti_sdk::prelude::*;

// Ingest security events from any source.
//
// POST /app-siem/ingest
//   Body: single event object or array of events
//   { "source": "cloudflare", "sourceIp": "1.2.3.4", "action": "deny",
//     "severity": "high", "category": "sqli", "method": "POST",
//     "path": "/api/login", "riskScore": 85, ... }
//
// Returns: { "ingested": N, "duplicates": N, "batchId": "..." }
resource!(Ingest {
    name = "ingest",
    post(request, ctx) => {
        let body: Value = request.json()?;
        let event_table = ctx.get_table("Event")?;
        let now = unix_timestamp()?.to_string();
        let batch_id = format!("batch-{}", now);

        // Accept single event or array
        let events: Vec<Value> = if body.is_array() {
            body.as_array().unwrap_or(&vec![]).clone()
        } else {
            vec![body]
        };

        if events.is_empty() {
            return bad_request("no events provided");
        }

        if events.len() > 10_000 {
            return bad_request("batch size exceeds 10,000 event limit");
        }

        let mut ingested = 0u32;
        let mut duplicates = 0u32;

        for event in &events {
            let source_ip = event["sourceIp"].as_str().unwrap_or("");
            let timestamp = event["timestamp"].as_str().unwrap_or(&now);
            let source = event["source"].as_str().unwrap_or("custom");

            // Generate deterministic ID from source + sourceIp + timestamp + path
            let id_input = format!("{}:{}:{}:{}",
                source, source_ip, timestamp,
                event["path"].as_str().unwrap_or("")
            );
            let id = format!("evt-{}", hash_string(&id_input));

            // Dedup check
            if event_table.does_exist(&id).await? {
                duplicates += 1;
                continue;
            }

            let inferred = infer_severity(event);
            let severity = event["severity"].as_str().unwrap_or(&inferred);

            let record = json!({
                "id": id,
                "timestamp": timestamp,
                "source": source,
                "sourceIp": source_ip,
                "destinationIp": event["destinationIp"].as_str().unwrap_or(""),
                "action": event["action"].as_str().unwrap_or("alert"),
                "severity": severity,
                "category": event["category"].as_str().unwrap_or("unknown"),
                "method": event["method"].as_str().unwrap_or(""),
                "path": event["path"].as_str().unwrap_or(""),
                "host": event["host"].as_str().unwrap_or(""),
                "userAgent": event["userAgent"].as_str().unwrap_or(""),
                "country": event["country"].as_str().unwrap_or(""),
                "riskScore": event["riskScore"].as_u64().unwrap_or(0),
                "botScore": event["botScore"].as_u64().unwrap_or(0),
                "rules": event["rules"].as_str().unwrap_or("[]"),
                "rawPayload": truncate(
                    &event.get("rawPayload").unwrap_or(&json!("")).to_string(), 4096
                ),
                "batchId": batch_id,
                "metadata": event["metadata"].as_str().unwrap_or("{}"),
            });

            event_table.put(&id, record).await?;
            ingested += 1;
        }

        created_json!({
            "ingested": ingested,
            "duplicates": duplicates,
            "batchId": batch_id,
            "total": events.len()
        })
    }
});

fn infer_severity(event: &Value) -> String {
    let risk = event["riskScore"].as_u64().unwrap_or(0);
    let action = event["action"].as_str().unwrap_or("");
    let category = event["category"].as_str().unwrap_or("");

    if risk >= 90 || category == "credential_stuffing" || category == "ddos" {
        "critical".to_string()
    } else if risk >= 70 || action == "deny" {
        "high".to_string()
    } else if risk >= 40 {
        "medium".to_string()
    } else if risk >= 20 || action == "alert" {
        "low".to_string()
    } else {
        "info".to_string()
    }
}

fn hash_string(s: &str) -> String {
    let mut hash: u64 = 5381;
    for byte in s.as_bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(*byte as u64);
    }
    format!("{:016x}", hash)
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max { s.to_string() } else { s[..max].to_string() }
}
