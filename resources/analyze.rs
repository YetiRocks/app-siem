use yeti_sdk::prelude::*;

// Tiered AI analysis of security events.
//
// POST /app-siem/analyze
//   Body: { "batchId": "batch-..." }               — analyze a specific batch
//   Body: { "strategic": true, "hours": 24 }        — strategic analysis over time window
//   Body: { "simulate": true, "scenario": "sqli" }  — generate + analyze simulated events
//
// Model selection:
//   Batch: Haiku (default) -> Sonnet (if deny ratio >= 30% or risk spike)
//   Strategic: Opus (always)
//
// Cost tracking: every call updates CostTracking table for the day
resource!(Analyze {
    name = "analyze",
    create(request, ctx) => {
        let body: Value = request.json()?;
        let settings_table = ctx.get_table("Settings")?;
        let cost_table = ctx.get_table("CostTracking")?;
        let event_table = ctx.get_table("Event")?;

        // Load settings
        let settings = settings_table.get("default").await?.unwrap_or(json!({}));
        let api_key = settings["anthropicApiKey"].as_str().unwrap_or("");
        if api_key.is_empty() {
            return bad_request("anthropicApiKey not configured in Settings");
        }

        // Check daily budget
        let today = today_key();
        let cost_record = cost_table.get(&today).await?.unwrap_or(json!({"id": today}));
        let total_cost: f64 = cost_record["totalCostUsd"].as_str()
            .and_then(|s| s.parse().ok()).unwrap_or(0.0);
        let hard_cap = settings["dailyBudgetHardCap"].as_f64().unwrap_or(10.0);
        if total_cost >= hard_cap {
            return reply().code(429).json(json!({
                "error": "daily budget exceeded",
                "totalCostUsd": total_cost,
                "hardCap": hard_cap
            }));
        }

        if body["strategic"].as_bool().unwrap_or(false) {
            return run_strategic(ctx, api_key, &settings, &cost_record).await;
        }

        // Batch analysis
        let batch_id = body["batchId"].as_str().unwrap_or("");
        if batch_id.is_empty() {
            return bad_request("batchId required for batch analysis");
        }

        // Collect events for this batch
        let all_events: Vec<Value> = event_table.get_all().await?;
        let batch_events: Vec<&Value> = all_events.iter()
            .filter(|e| e["batchId"].as_str() == Some(batch_id))
            .collect();

        if batch_events.is_empty() {
            return not_found(&format!("no events found for batch {}", batch_id));
        }

        // Compute batch stats for model selection
        let total = batch_events.len();
        let deny_count = batch_events.iter()
            .filter(|e| e["action"].as_str() == Some("deny"))
            .count();
        let deny_ratio = deny_count as f64 / total as f64;
        let escalation_threshold = settings["denyRatioEscalation"].as_f64().unwrap_or(0.3);
        let escalated = deny_ratio >= escalation_threshold;

        let model = if escalated { "claude-sonnet-4-6" } else { "claude-haiku-4-5-20251001" };
        let model_label = if escalated { "sonnet" } else { "haiku" };

        // Sample events (max 50): 40% deny, 30% high risk, 20% high bot, 10% random
        let sampled = sample_events(&batch_events, 50);

        // Build analysis prompt
        let event_summary = sampled.iter().map(|e| {
            format!("[{}] {} {} {} → {} (risk:{} bot:{} cat:{})",
                e["id"].as_str().unwrap_or("?"),
                e["sourceIp"].as_str().unwrap_or("?"),
                e["method"].as_str().unwrap_or("?"),
                e["path"].as_str().unwrap_or("?"),
                e["action"].as_str().unwrap_or("?"),
                e["riskScore"].as_u64().unwrap_or(0),
                e["botScore"].as_u64().unwrap_or(0),
                e["category"].as_str().unwrap_or("?"),
            )
        }).collect::<Vec<_>>().join("\n");

        let prompt = format!(
            "Analyze these {} security events (sampled {} shown). Deny ratio: {:.0}%.\n\n{}\n\n\
             Respond with JSON only: {{\"analysis\": \"...\", \"severity\": \"critical|high|medium|low|info\", \
             \"flags\": [...], \"notableIps\": [...], \"notablePatterns\": [...]}}",
            total, sampled.len(), deny_ratio * 100.0, event_summary
        );

        let (analysis_json, input_tokens, output_tokens) =
            call_anthropic(api_key, model, &prompt, 4096)?;

        // Calculate cost
        let (input_rate, output_rate) = model_pricing(model_label);
        let cost = (input_tokens as f64 * input_rate + output_tokens as f64 * output_rate) / 1_000_000.0;

        // Parse AI response
        let ai: Value = serde_json::from_str(&analysis_json).unwrap_or(json!({
            "analysis": analysis_json,
            "severity": if escalated { "high" } else { "medium" },
            "flags": [],
            "notableIps": [],
            "notablePatterns": []
        }));

        // Store batch analysis
        let analysis_table = ctx.get_table("AnalysisBatch")?;
        let analysis_id = format!("ab-{}", unix_timestamp()?);
        let now = unix_timestamp()?.to_string();

        let record = json!({
            "id": analysis_id,
            "createdAt": now,
            "model": model_label,
            "eventCount": total,
            "sampledCount": sampled.len(),
            "severity": ai["severity"].as_str().unwrap_or("medium"),
            "analysis": ai["analysis"].as_str().unwrap_or(&analysis_json),
            "flags": ai["flags"].to_string(),
            "notableIps": ai["notableIps"].to_string(),
            "notablePatterns": ai["notablePatterns"].to_string(),
            "tokenInput": input_tokens,
            "tokenOutput": output_tokens,
            "costUsd": format!("{:.6}", cost),
            "escalated": if escalated { "true" } else { "false" },
            "triggerReason": "manual"
        });
        analysis_table.put(&analysis_id, record.clone()).await?;

        // Update cost tracking
        update_cost_tracking(ctx, &today, model_label, input_tokens, output_tokens, cost).await?;

        reply().code(201).json(record)
    }
});

fn sample_events<'a>(events: &[&'a Value], max: usize) -> Vec<&'a Value> {
    if events.len() <= max {
        return events.to_vec();
    }

    let mut sampled: Vec<&Value> = Vec::new();
    let target_deny = max * 40 / 100;
    let target_risk = max * 30 / 100;
    let target_bot = max * 20 / 100;

    // Deny events
    for e in events.iter().filter(|e| e["action"].as_str() == Some("deny")) {
        if sampled.len() >= target_deny { break; }
        sampled.push(e);
    }
    // High risk
    for e in events.iter().filter(|e| e["riskScore"].as_u64().unwrap_or(0) >= 70) {
        if sampled.len() >= target_deny + target_risk { break; }
        if !sampled.contains(e) { sampled.push(e); }
    }
    // High bot score
    for e in events.iter().filter(|e| e["botScore"].as_u64().unwrap_or(0) >= 70) {
        if sampled.len() >= target_deny + target_risk + target_bot { break; }
        if !sampled.contains(e) { sampled.push(e); }
    }
    // Fill remaining
    for e in events {
        if sampled.len() >= max { break; }
        if !sampled.contains(e) { sampled.push(e); }
    }

    sampled
}

async fn run_strategic(
    ctx: &ResourceParams,
    api_key: &str,
    settings: &Value,
    _cost_record: &Value,
) -> Result<Response<Vec<u8>>> {
    let batch_table = ctx.get_table("AnalysisBatch")?;
    let strategic_table = ctx.get_table("AnalysisStrategic")?;
    let now = unix_timestamp()?;
    let hours = 24u64;
    let period_start = now.saturating_sub(hours * 3600);

    let all_batches: Vec<Value> = batch_table.get_all().await?;
    let recent: Vec<&Value> = all_batches.iter().filter(|b| {
        b["createdAt"].as_str()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0) >= period_start
    }).collect();

    if recent.is_empty() {
        return reply().json(json!({"error": "no batch analyses in the last 24 hours"}));
    }

    // Build summary for Opus
    let batch_summary = recent.iter().map(|b| {
        format!("[{}] severity:{} events:{} model:{} flags:{}",
            b["id"].as_str().unwrap_or("?"),
            b["severity"].as_str().unwrap_or("?"),
            b["eventCount"].as_u64().unwrap_or(0),
            b["model"].as_str().unwrap_or("?"),
            b["flags"].as_str().unwrap_or("[]"),
        )
    }).collect::<Vec<_>>().join("\n");

    let prompt = format!(
        "Strategic security analysis of {} batch analyses over the last {} hours.\n\n{}\n\n\
         Respond with JSON only: {{\"analysis\": \"...\", \"severity\": \"...\", \
         \"recommendations\": [...], \"campaignsDetected\": [...], \
         \"policyEffectivenessNotes\": [...], \"flags\": [...]}}",
        recent.len(), hours, batch_summary
    );

    let model = "claude-opus-4-6";
    let (analysis_json, input_tokens, output_tokens) =
        call_anthropic(api_key, model, &prompt, 8192)?;

    let cost = (input_tokens as f64 * 15.0 + output_tokens as f64 * 75.0) / 1_000_000.0;

    let ai: Value = serde_json::from_str(&analysis_json).unwrap_or(json!({
        "analysis": analysis_json, "severity": "medium",
        "recommendations": [], "campaignsDetected": [], "policyEffectivenessNotes": [], "flags": []
    }));

    let now_str = now.to_string();
    let analysis_id = format!("as-{}", now);
    let record = json!({
        "id": analysis_id,
        "createdAt": now_str,
        "model": "opus",
        "periodStart": period_start.to_string(),
        "periodEnd": now_str,
        "batchCount": recent.len(),
        "analysis": ai["analysis"],
        "severity": ai["severity"],
        "recommendations": ai["recommendations"].to_string(),
        "campaignsDetected": ai["campaignsDetected"].to_string(),
        "policyNotes": ai["policyEffectivenessNotes"].to_string(),
        "flags": ai["flags"].to_string(),
        "tokenInput": input_tokens,
        "tokenOutput": output_tokens,
        "costUsd": format!("{:.6}", cost),
    });
    strategic_table.put(&analysis_id, record.clone()).await?;

    let today = today_key();
    update_cost_tracking(ctx, &today, "opus", input_tokens, output_tokens, cost).await?;

    reply().code(201).json(record)
}

fn call_anthropic(api_key: &str, model: &str, prompt: &str, max_tokens: u32) -> Result<(String, u64, u64)> {
    let body = json!({
        "model": model,
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}]
    });

    let resp = fetch("https://api.anthropic.com/v1/messages", Some(json!({
        "method": "POST",
        "headers": {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        },
        "body": body.to_string()
    })))?;

    if !resp.ok() {
        return Err(YetiError::Validation(format!("Anthropic API error {}: {}", resp.status, resp.body)));
    }

    let parsed: Value = serde_json::from_str(&resp.body).unwrap_or(json!({}));
    let text = parsed["content"][0]["text"].as_str().unwrap_or("").to_string();
    let input = parsed["usage"]["input_tokens"].as_u64().unwrap_or(0);
    let output = parsed["usage"]["output_tokens"].as_u64().unwrap_or(0);

    Ok((text, input, output))
}

fn model_pricing(model: &str) -> (f64, f64) {
    match model {
        "haiku" => (0.25, 1.25),
        "sonnet" => (3.0, 15.0),
        "opus" => (15.0, 75.0),
        _ => (0.25, 1.25),
    }
}

async fn update_cost_tracking(
    ctx: &ResourceParams,
    today: &str,
    model: &str,
    input_tokens: u64,
    output_tokens: u64,
    cost: f64,
) -> Result<()> {
    let cost_table = ctx.get_table("CostTracking")?;
    let mut record = cost_table.get(today).await?.unwrap_or(json!({
        "id": today,
        "haikuInput": 0, "haikuOutput": 0,
        "sonnetInput": 0, "sonnetOutput": 0,
        "opusInput": 0, "opusOutput": 0,
        "totalCostUsd": "0.0",
        "budgetWarning": "false",
        "budgetExceeded": "false",
        "escalationCount": 0,
    }));

    let input_key = format!("{}Input", model);
    let output_key = format!("{}Output", model);
    let prev_input = record[&input_key].as_u64().unwrap_or(0);
    let prev_output = record[&output_key].as_u64().unwrap_or(0);
    record[&input_key] = json!(prev_input + input_tokens);
    record[&output_key] = json!(prev_output + output_tokens);

    let prev_cost: f64 = record["totalCostUsd"].as_str()
        .and_then(|s| s.parse().ok()).unwrap_or(0.0);
    let new_cost = prev_cost + cost;
    record["totalCostUsd"] = json!(format!("{:.6}", new_cost));

    if new_cost >= 5.0 { record["budgetWarning"] = json!("true"); }
    if new_cost >= 10.0 { record["budgetExceeded"] = json!("true"); }

    if model != "haiku" {
        let prev_esc = record["escalationCount"].as_u64().unwrap_or(0);
        record["escalationCount"] = json!(prev_esc + 1);
    }

    cost_table.put(today, record).await?;
    Ok(())
}

fn today_key() -> String {
    let ts = unix_timestamp().unwrap_or(0);
    let days = ts / 86400;
    // Approximate date from epoch days
    format!("day-{}", days)
}
