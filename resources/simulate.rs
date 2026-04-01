use yeti_sdk::prelude::*;

// Generate simulated security events for demos and testing.
//
// POST /app-siem/simulate
//   Body: { "scenario": "credential_stuffing", "count": 100 }
//
// Scenarios: credential_stuffing, sqli, xss, path_traversal, bot_scanner, ddos, mixed
// Events are ingested into the real Event table with source="simulation".
resource!(Simulate {
    name = "simulate",
    post(request, ctx) => {
        let body: Value = request.json()?;
        let scenario = body["scenario"].as_str().unwrap_or("mixed");
        let count = body["count"].as_u64().unwrap_or(50).min(1000) as usize;
        let event_table = ctx.get_table("Event")?;
        let now = unix_timestamp()?;
        let batch_id = format!("sim-{}", now);

        let events = generate_scenario(scenario, count, now, &batch_id);

        for event in &events {
            let id = event["id"].as_str().unwrap_or("");
            event_table.put(id, event.clone()).await?;
        }

        created_json!({
            "scenario": scenario,
            "generated": events.len(),
            "batchId": batch_id
        })
    }
});

fn generate_scenario(scenario: &str, count: usize, base_ts: u64, batch_id: &str) -> Vec<Value> {
    let mut events = Vec::with_capacity(count);

    for i in 0..count {
        let ts = base_ts - (count as u64 - i as u64);
        let event = match scenario {
            "credential_stuffing" => sim_credential_stuffing(i, ts, batch_id),
            "sqli" => sim_sqli(i, ts, batch_id),
            "xss" => sim_xss(i, ts, batch_id),
            "path_traversal" => sim_path_traversal(i, ts, batch_id),
            "bot_scanner" => sim_bot_scanner(i, ts, batch_id),
            "ddos" => sim_ddos(i, ts, batch_id),
            _ => sim_mixed(i, ts, batch_id),
        };
        events.push(event);
    }

    events
}

fn sim_credential_stuffing(i: usize, ts: u64, batch_id: &str) -> Value {
    let ip_idx = i % 5;
    let ips = ["192.168.1.100", "10.0.0.50", "172.16.0.22", "192.168.2.200", "10.0.1.33"];
    let agents = ["python-requests/2.28", "Go-http-client/2.0", "curl/7.88", "axios/1.4", "bot/1.0"];
    let countries = ["CN", "RU", "BR", "VN", "ID"];
    let action = if i % 3 == 0 { "allow" } else { "deny" };
    json!({
        "id": format!("sim-cs-{}-{}", ts, i),
        "timestamp": ts.to_string(),
        "source": "simulation",
        "sourceIp": ips[ip_idx],
        "action": action,
        "severity": if action == "deny" { "high" } else { "medium" },
        "category": "credential_stuffing",
        "method": "POST",
        "path": "/api/auth/login",
        "host": "api.example.com",
        "userAgent": agents[ip_idx],
        "country": countries[ip_idx],
        "riskScore": 70 + (i % 30) as u64,
        "botScore": 60 + (i % 40) as u64,
        "rules": "[\"rate-limit-login\", \"geo-block\"]",
        "batchId": batch_id,
        "metadata": "{}",
        "rawPayload": ""
    })
}

fn sim_sqli(i: usize, ts: u64, batch_id: &str) -> Value {
    let paths = ["/api/users?id=1' OR 1=1--", "/search?q='; DROP TABLE--",
                 "/api/products?cat=1 UNION SELECT", "/login?user=admin'--",
                 "/api/data?filter=1;EXEC xp_cmdshell"];
    json!({
        "id": format!("sim-sq-{}-{}", ts, i),
        "timestamp": ts.to_string(),
        "source": "simulation",
        "sourceIp": format!("10.{}.{}.{}", i % 256, (i * 7) % 256, (i * 13) % 256),
        "action": "deny",
        "severity": "critical",
        "category": "sqli",
        "method": "GET",
        "path": paths[i % paths.len()],
        "host": "app.example.com",
        "userAgent": "sqlmap/1.7",
        "country": "US",
        "riskScore": 90 + (i % 10) as u64,
        "botScore": 95,
        "rules": "[\"sqli-detection\", \"waf-block\"]",
        "batchId": batch_id,
        "metadata": "{}",
        "rawPayload": ""
    })
}

fn sim_xss(i: usize, ts: u64, batch_id: &str) -> Value {
    let xss_countries = ["US", "DE", "FR", "GB", "JP"];
    json!({
        "id": format!("sim-xss-{}-{}", ts, i),
        "timestamp": ts.to_string(),
        "source": "simulation",
        "sourceIp": format!("172.{}.{}.{}", 16 + i % 16, (i * 3) % 256, (i * 11) % 256),
        "action": "deny",
        "severity": "high",
        "category": "xss",
        "method": "POST",
        "path": "/api/comments",
        "host": "app.example.com",
        "userAgent": "Mozilla/5.0 (compatible; scanner)",
        "country": xss_countries[i % 5],
        "riskScore": 75 + (i % 25) as u64,
        "botScore": 50 + (i % 50) as u64,
        "rules": "[\"xss-detection\"]",
        "batchId": batch_id,
        "metadata": "{}",
        "rawPayload": ""
    })
}

fn sim_path_traversal(i: usize, ts: u64, batch_id: &str) -> Value {
    let paths = ["/../../etc/passwd", "/..%2f..%2fetc/shadow",
                 "/api/../../../config.yaml", "/static/..%00/admin",
                 "/files/../../../../etc/hosts"];
    json!({
        "id": format!("sim-pt-{}-{}", ts, i),
        "timestamp": ts.to_string(),
        "source": "simulation",
        "sourceIp": format!("192.168.{}.{}", (i * 5) % 256, (i * 9) % 256),
        "action": "deny",
        "severity": "critical",
        "category": "path_traversal",
        "method": "GET",
        "path": paths[i % paths.len()],
        "host": "files.example.com",
        "userAgent": "Mozilla/5.0",
        "country": "RU",
        "riskScore": 85 + (i % 15) as u64,
        "botScore": 80,
        "rules": "[\"path-traversal-block\"]",
        "batchId": batch_id,
        "metadata": "{}",
        "rawPayload": ""
    })
}

fn sim_bot_scanner(i: usize, ts: u64, batch_id: &str) -> Value {
    let paths = ["/robots.txt", "/.env", "/wp-admin", "/phpMyAdmin",
                 "/.git/config", "/api/swagger.json", "/actuator/health"];
    let bot_agents = ["Googlebot/2.1", "AhrefsBot/7.0", "SemrushBot/7", "MJ12bot/v1.4", "masscan/1.3"];
    let bot_countries = ["US", "DE", "NL", "SG", "GB"];
    json!({
        "id": format!("sim-bot-{}-{}", ts, i),
        "timestamp": ts.to_string(),
        "source": "simulation",
        "sourceIp": format!("45.{}.{}.{}", 33 + i % 200, (i * 7) % 256, (i * 3) % 256),
        "action": if i % 4 == 0 { "allow" } else { "deny" },
        "severity": "medium",
        "category": "bot",
        "method": "GET",
        "path": paths[i % paths.len()],
        "host": "www.example.com",
        "userAgent": bot_agents[i % 5],
        "country": bot_countries[i % 5],
        "riskScore": 30 + (i % 50) as u64,
        "botScore": 90 + (i % 10) as u64,
        "rules": "[\"bot-management\"]",
        "batchId": batch_id,
        "metadata": "{}",
        "rawPayload": ""
    })
}

fn sim_ddos(i: usize, ts: u64, batch_id: &str) -> Value {
    let methods = ["GET", "POST", "HEAD"];
    let ddos_countries = ["CN", "RU", "BR", "VN", "KR", "ID", "IN", "TR"];
    json!({
        "id": format!("sim-ddos-{}-{}", ts, i),
        "timestamp": ts.to_string(),
        "source": "simulation",
        "sourceIp": format!("{}.{}.{}.{}", (i * 17) % 256, (i * 31) % 256, (i * 43) % 256, (i * 7) % 256),
        "action": "deny",
        "severity": "critical",
        "category": "ddos",
        "method": methods[i % 3],
        "path": "/",
        "host": "api.example.com",
        "userAgent": "",
        "country": ddos_countries[i % 8],
        "riskScore": 95,
        "botScore": 99,
        "rules": "[\"ddos-mitigation\", \"rate-limit\"]",
        "batchId": batch_id,
        "metadata": "{}",
        "rawPayload": ""
    })
}

fn sim_mixed(i: usize, ts: u64, batch_id: &str) -> Value {
    match i % 6 {
        0 => sim_credential_stuffing(i, ts, batch_id),
        1 => sim_sqli(i, ts, batch_id),
        2 => sim_xss(i, ts, batch_id),
        3 => sim_bot_scanner(i, ts, batch_id),
        4 => sim_path_traversal(i, ts, batch_id),
        _ => sim_ddos(i, ts, batch_id),
    }
}
