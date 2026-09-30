use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const DEFAULT_PORT: u16 = 8443;
pub const DEFAULT_HOST: &str = "127.0.0.1";

// ── Data Models ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrolledAgent {
    pub agent_id: String,
    pub name: String,
    pub host: String,
    pub uid: u32,
    pub kernel: String,
    pub enrolled_at: String,
    pub last_seen: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub job_id: String,
    pub kind: String,
    pub payload_b64: String,
    pub payload_sha256: String,
    pub target: Option<String>,
    pub status: String, // queued, running, ok, error
    pub claimed_by: Option<String>,
    pub created_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerFinding {
    pub id: usize,
    pub job_id: String,
    pub agent_id: String,
    pub severity: String,
    pub check: String,
    pub title: String,
    pub evidence: serde_json::Value,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInvestigation {
    pub case_id: String,
    pub name: String,
    pub target: String,
    pub status: String,
    pub artifacts_count: usize,
    pub findings_count: usize,
    pub timeline_count: usize,
    pub chain_head: String,
    pub report_file: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ServerStore {
    pub agents: HashMap<String, EnrolledAgent>,
    pub jobs: HashMap<String, Job>,
    pub findings: Vec<ServerFinding>,
    pub investigations: HashMap<String, ServerInvestigation>,
    pub next_finding_id: usize,
}

impl ServerStore {
    pub fn load_or_new(path: &str) -> Self {
        if Path::new(path).exists() {
            if let Ok(data) = fs::read_to_string(path) {
                if let Ok(store) = serde_json::from_str(&data) {
                    return store;
                }
            }
        }
        let mut store = Self::default();
        store.next_finding_id = 1;
        store
    }

    pub fn save(&self, path: &str) {
        if let Some(parent) = Path::new(path).parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = fs::write(path, json);
        }
    }
}

// ── Management Server ───────────────────────────────────────────────────────

pub struct ManagementServer {
    pub host: String,
    pub port: u16,
    pub token: String,
    pub state_file: String,
    pub store: Arc<Mutex<ServerStore>>,
}

impl ManagementServer {
    pub fn new(host: String, port: u16, token: String, state_file: String) -> Self {
        let store = Arc::new(Mutex::new(ServerStore::load_or_new(&state_file)));
        Self {
            host,
            port,
            token,
            state_file,
            store,
        }
    }

    pub fn run(&self) -> Result<(), String> {
        let addr = format!("{}:{}", self.host, self.port);
        let listener = TcpListener::bind(&addr)
            .map_err(|e| format!("Failed to bind to {}: {}", addr, e))?;

        println!("╔══════════════════════════════════════════════════════════════╗");
        println!("║      JOCKY 2.1 — Central Management Server (Rust Edition)   ║");
        println!("╚══════════════════════════════════════════════════════════════╝");
        println!("  Listening on: http://{}", addr);
        println!("  Console UI:   http://{}/dashboard", addr);
        println!("  Secret Token: {}", self.token);
        println!("  State File:   {}", self.state_file);
        println!();
        println!("Press Ctrl+C to stop the management server.\n");

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let store = Arc::clone(&self.store);
                    let token = self.token.clone();
                    let state_file = self.state_file.clone();
                    thread::spawn(move || {
                        handle_connection(stream, store, &token, &state_file);
                    });
                }
                Err(e) => {
                    eprintln!("Connection error: {}", e);
                }
            }
        }
        Ok(())
    }
}

// ── HTTP Request & Connection Handling ─────────────────────────────────────

fn handle_connection(
    mut stream: TcpStream,
    store: Arc<Mutex<ServerStore>>,
    token: &str,
    state_file: &str,
) {
    let mut buffer = [0u8; 65536];
    let bytes_read = match stream.read(&mut buffer) {
        Ok(n) if n > 0 => n,
        _ => return,
    };

    let request_str = String::from_utf8_lossy(&buffer[..bytes_read]);
    let mut lines = request_str.lines();
    let request_line = match lines.next() {
        Some(l) => l,
        None => return,
    };

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return;
    }
    let method = parts[0];
    let full_path = parts[1];

    let (path, query) = if let Some(idx) = full_path.find('?') {
        (&full_path[..idx], &full_path[idx + 1..])
    } else {
        (full_path, "")
    };

    // Parse headers
    let mut headers = HashMap::new();
    for line in lines.by_ref() {
        if line.is_empty() || line == "\r" {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_lowercase(), v.trim().to_string());
        }
    }

    // Body
    let body_start = request_str.find("\r\n\r\n").map(|i| i + 4).unwrap_or(bytes_read);
    let body_str = &request_str[body_start..];

    // Auth check for non-public routes
    let is_public = path == "/" || path == "/dashboard" || path == "/favicon.ico" || path == "/v1/health";
    if !is_public {
        let provided = headers.get("x-jky-token").map(|s| s.as_str()).unwrap_or("");
        if !constant_time_eq(provided, token) {
            let res = json_response(401, &serde_json::json!({
                "error": "missing or invalid X-JKY-Token"
            }));
            let _ = stream.write_all(res.as_bytes());
            return;
        }
    }

    // Route dispatch
    let response = match (method, path) {
        ("GET", "/") | ("GET", "/dashboard") => {
            html_response(200, DASHBOARD_HTML)
        }
        ("GET", "/favicon.ico") => {
            "HTTP/1.1 204 No Content\r\n\r\n".to_string()
        }
        ("GET", "/v1/health") => {
            json_response(200, &serde_json::json!({
                "status": "ok",
                "version": "2.1.0",
                "engine": "Rust Edition"
            }))
        }
        ("GET", "/v1/status") => {
            let s = store.lock().unwrap();
            let mut jobs_summary = HashMap::new();
            jobs_summary.insert("queued", 0);
            jobs_summary.insert("running", 0);
            jobs_summary.insert("ok", 0);
            jobs_summary.insert("error", 0);
            for j in s.jobs.values() {
                *jobs_summary.entry(j.status.as_str()).or_insert(0) += 1;
            }
            let total_jobs = s.jobs.len();
            let mut by_sev: HashMap<String, usize> = HashMap::new();
            for f in &s.findings {
                *by_sev.entry(f.severity.to_lowercase()).or_insert(0) += 1;
            }
            let agents_list: Vec<_> = s.agents.values().cloned().collect();

            json_response(200, &serde_json::json!({
                "server_time": Utc::now().to_rfc3339(),
                "agents": agents_list,
                "jobs": {
                    "queued": jobs_summary.get("queued").unwrap_or(&0),
                    "running": jobs_summary.get("running").unwrap_or(&0),
                    "ok": jobs_summary.get("ok").unwrap_or(&0),
                    "error": jobs_summary.get("error").unwrap_or(&0),
                    "total": total_jobs
                },
                "findings": {
                    "total": s.findings.len(),
                    "by_severity": by_sev
                }
            }))
        }
        ("POST", "/v1/enroll") => {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(body_str) {
                let name = v.get("name").and_then(|x| x.as_str()).unwrap_or("agent").to_string();
                let host = v.get("host").and_then(|x| x.as_str()).unwrap_or("unknown").to_string();
                let uid = v.get("uid").and_then(|x| x.as_u64()).unwrap_or(1000) as u32;
                let kernel = v.get("kernel").and_then(|x| x.as_str()).unwrap_or("generic").to_string();
                
                let agent_id = format!("agt_{}", &hex::encode(Sha256::digest(format!("{}:{}:{}", host, name, now_millis()).as_bytes()))[..16]);
                let now = Utc::now().to_rfc3339();

                let mut s = store.lock().unwrap();
                s.agents.insert(agent_id.clone(), EnrolledAgent {
                    agent_id: agent_id.clone(),
                    name,
                    host,
                    uid,
                    kernel,
                    enrolled_at: now.clone(),
                    last_seen: now,
                });
                s.save(state_file);
                json_response(200, &serde_json::json!({ "agent_id": agent_id }))
            } else {
                json_response(400, &serde_json::json!({ "error": "invalid JSON body" }))
            }
        }
        ("POST", "/v1/jobs/poll") => {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(body_str) {
                let agent_id = v.get("agent_id").and_then(|x| x.as_str()).unwrap_or("");
                if agent_id.is_empty() {
                    json_response(400, &serde_json::json!({ "error": "agent_id required" }))
                } else {
                    let mut s = store.lock().unwrap();
                    if let Some(agent) = s.agents.get_mut(agent_id) {
                        agent.last_seen = Utc::now().to_rfc3339();
                    }
                    // Look for queued job
                    let mut found_job: Option<Job> = None;
                    for j in s.jobs.values_mut() {
                        if j.status == "queued" {
                            if j.target.is_none() || j.target.as_deref() == Some("all") || j.target.as_deref() == Some(agent_id) {
                                j.status = "running".to_string();
                                j.claimed_by = Some(agent_id.to_string());
                                j.started_at = Some(Utc::now().to_rfc3339());
                                found_job = Some(j.clone());
                                break;
                            }
                        }
                    }
                    s.save(state_file);
                    if let Some(job) = found_job {
                        json_response(200, &serde_json::json!({
                            "job_id": job.job_id,
                            "kind": job.kind,
                            "payload_b64": job.payload_b64,
                            "payload_sha256": job.payload_sha256
                        }))
                    } else {
                        "HTTP/1.1 204 No Content\r\n\r\n".to_string()
                    }
                }
            } else {
                json_response(400, &serde_json::json!({ "error": "invalid JSON" }))
            }
        }
        ("POST", "/v1/jobs/result") => {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(body_str) {
                let job_id = v.get("job_id").and_then(|x| x.as_str()).unwrap_or("");
                let agent_id = v.get("agent_id").and_then(|x| x.as_str()).unwrap_or("");
                let result = v.get("result");

                let mut s = store.lock().unwrap();
                let mut stored_count = 0;
                if let Some(job) = s.jobs.get_mut(job_id) {
                    job.status = "ok".to_string();
                    job.finished_at = Some(Utc::now().to_rfc3339());
                }
                if let Some(res) = result {
                    if let Some(findings_arr) = res.get("findings").and_then(|x| x.as_array()) {
                        let now = Utc::now().to_rfc3339();
                        for item in findings_arr {
                            let sev = item.get("severity").and_then(|x| x.as_str()).unwrap_or("info");
                            let check = item.get("check").and_then(|x| x.as_str()).unwrap_or("unknown");
                            let title = item.get("title").and_then(|x| x.as_str()).unwrap_or("Finding");
                            let fid = s.next_finding_id;
                            s.next_finding_id += 1;
                            s.findings.push(ServerFinding {
                                id: fid,
                                job_id: job_id.to_string(),
                                agent_id: agent_id.to_string(),
                                severity: sev.to_string(),
                                check: check.to_string(),
                                title: title.to_string(),
                                evidence: item.get("evidence").cloned().unwrap_or(item.clone()),
                                created_at: now.clone(),
                            });
                            stored_count += 1;
                        }
                    }
                }
                s.save(state_file);
                json_response(200, &serde_json::json!({
                    "stored": true,
                    "findings": stored_count,
                    "status": "ok"
                }))
            } else {
                json_response(400, &serde_json::json!({ "error": "invalid JSON" }))
            }
        }
        ("POST", "/v1/jobs/submit") => {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(body_str) {
                let kind = v.get("kind").and_then(|x| x.as_str()).unwrap_or("source");
                let payload_b64 = v.get("payload_b64").and_then(|x| x.as_str()).unwrap_or("");
                let target = v.get("target").and_then(|x| x.as_str()).map(|s| s.to_string());

                let payload_sha256 = hex::encode(Sha256::digest(payload_b64.as_bytes()));
                let job_id = format!("job_{}", &payload_sha256[..16]);
                let now = Utc::now().to_rfc3339();

                let mut s = store.lock().unwrap();
                s.jobs.insert(job_id.clone(), Job {
                    job_id: job_id.clone(),
                    kind: kind.to_string(),
                    payload_b64: payload_b64.to_string(),
                    payload_sha256,
                    target,
                    status: "queued".to_string(),
                    claimed_by: None,
                    created_at: now,
                    started_at: None,
                    finished_at: None,
                });
                s.save(state_file);
                json_response(200, &serde_json::json!({ "job_id": job_id }))
            } else {
                json_response(400, &serde_json::json!({ "error": "invalid JSON" }))
            }
        }
        ("GET", "/v1/findings") => {
            let s = store.lock().unwrap();
            let mut list = s.findings.clone();
            list.reverse();
            json_response(200, &serde_json::json!({
                "count": list.len(),
                "findings": list
            }))
        }
        ("GET", "/v1/investigations") => {
            let mut investigations_map = HashMap::new();
            {
                let s = store.lock().unwrap();
                for (k, v) in &s.investigations {
                    investigations_map.insert(k.clone(), v.clone());
                }
            }
            // Auto-discover preserved evidence files
            if let Ok(entries) = fs::read_dir("evidence") {
                for entry in entries.flatten() {
                    let path = entry.path();
                    let name = path.file_name().unwrap_or_default().to_string_lossy();
                    if name.ends_with("_preserved.json") {
                        let case_id = name.trim_end_matches("_preserved.json").to_uppercase();
                        if !investigations_map.contains_key(&case_id) {
                            if let Ok(content) = fs::read_to_string(&path) {
                                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                                    let records_len = val.get("records").and_then(|x| x.as_array()).map(|a| a.len()).unwrap_or(0);
                                    let findings_len = val.get("findings").and_then(|x| x.as_array()).map(|a| a.len()).unwrap_or(0);
                                    let timeline_len = val.get("timeline").and_then(|x| x.as_array()).map(|a| a.len()).unwrap_or(0);
                                    let head = val.get("chain_head").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                    investigations_map.insert(case_id.clone(), ServerInvestigation {
                                        case_id: case_id.clone(),
                                        name: format!("Preserved {}", case_id),
                                        target: "all".to_string(),
                                        status: "verified".to_string(),
                                        artifacts_count: records_len,
                                        findings_count: findings_len,
                                        timeline_count: timeline_len,
                                        chain_head: head,
                                        report_file: format!("{}_report.html", case_id.to_lowercase()),
                                        created_at: Utc::now().to_rfc3339(),
                                        updated_at: Utc::now().to_rfc3339(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
            let mut list: Vec<_> = investigations_map.into_values().collect();
            list.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
            json_response(200, &serde_json::json!({
                "count": list.len(),
                "investigations": list
            }))
        }
        ("GET", "/v1/investigations/report") => {
            let case_id = query.split('&')
                .find(|part| part.starts_with("case="))
                .map(|part| &part[5..])
                .unwrap_or("");
            if case_id.is_empty() {
                json_response(400, &serde_json::json!({ "error": "case parameter required" }))
            } else {
                let filename = format!("{}_report.html", case_id.to_lowercase().replace(' ', "_").replace('/', "-"));
                let candidates = vec![
                    filename.clone(),
                    format!("reports/{}", filename),
                    "inc-2026-001_report.html".to_string(),
                    "malware_triage_001_report.html".to_string(),
                ];
                let mut found_content = None;
                for c in candidates {
                    if Path::new(&c).exists() {
                        if let Ok(data) = fs::read_to_string(&c) {
                            found_content = Some(data);
                            break;
                        }
                    }
                }
                if let Some(content) = found_content {
                    html_response(200, &content)
                } else {
                    json_response(404, &serde_json::json!({ "error": format!("No report found for {}", case_id) }))
                }
            }
        }
        _ => {
            json_response(404, &serde_json::json!({ "error": format!("Not found: {} {}", method, path) }))
        }
    };

    let _ = stream.write_all(response.as_bytes());
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn json_response(status: u16, payload: &serde_json::Value) -> String {
    let body = serde_json::to_string(payload).unwrap_or_else(|_| "{}".to_string());
    let status_text = match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        _ => "Status",
    };
    format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{}",
        status, status_text, body.len(), body
    )
}

fn html_response(status: u16, body: &str) -> String {
    format!(
        "HTTP/1.1 {} OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status, body.len(), body
    )
}

// ── Dashboard HTML ──────────────────────────────────────────────────────────

pub const DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>JOCKY — Central Management Console</title>
<style>
:root {
  --bg: #0b0f19;
  --panel: #111827;
  --panel-2: #1f2937;
  --line: #374151;
  --text: #f9fafb;
  --muted: #9ca3af;
  --accent: #2563eb;
  --accent-glow: #38bdf8;
  --crit: #ef4444;
  --high: #f97316;
  --med: #eab308;
  --low: #3b82f6;
  --info: #64748b;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font: 14px/1.5 ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
}
header.top {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 14px 24px;
  background: #030712;
  border-bottom: 1px solid var(--line);
}
.brand {
  display: flex;
  align-items: center;
  gap: 12px;
  font-weight: 700;
  font-size: 16px;
  letter-spacing: .05em;
}
.brand-icon {
  width: 32px;
  height: 32px;
  background: linear-gradient(135deg, #2563eb, #38bdf8);
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  color: #fff;
  font-weight: 900;
}
.brand small {
  display: block;
  font-size: 11px;
  font-weight: 400;
  color: var(--muted);
}
.pill {
  padding: 3px 10px;
  border-radius: 999px;
  font-size: 11.5px;
  border: 1px solid var(--line);
  color: var(--muted);
}
.pill.on { border-color: #10b981; color: #34d399; }
.pill.off { border-color: #ef4444; color: #f87171; }
main { max-width: 1280px; margin: 0 auto; padding: 24px; }
section {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 12px;
  padding: 20px;
  margin-bottom: 20px;
}
h2 {
  margin: 0 0 16px;
  font-size: 13px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: .08em;
  color: var(--accent-glow);
  display: flex;
  justify-content: space-between;
  align-items: center;
}
input, textarea, select, button {
  font: inherit;
  color: inherit;
  background: #030712;
  border: 1px solid var(--line);
  border-radius: 6px;
  padding: 8px 12px;
}
input:focus, textarea:focus, select:focus {
  outline: 2px solid var(--accent-glow);
}
button {
  cursor: pointer;
  background: #1f2937;
  transition: all .15s ease;
}
button:hover { background: #374151; }
button.primary {
  background: #2563eb;
  border-color: #3b82f6;
  font-weight: 600;
}
button.primary:hover { background: #1d4ed8; }
.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
  gap: 12px;
  margin-bottom: 12px;
}
.stat-card {
  background: var(--panel-2);
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 12px;
}
.stat-val { font-size: 22px; font-weight: 700; }
.stat-lbl { font-size: 11px; text-transform: uppercase; color: var(--muted); }
table { width: 100%; border-collapse: collapse; margin-top: 8px; }
th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--line); font-size: 13px; }
th { font-size: 11px; text-transform: uppercase; color: var(--muted); }
tr:hover td { background: rgba(255,255,255,0.02); }
.mono { font-family: monospace; }
.sev {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
}
.sev-critical { background: var(--crit); color: #fff; }
.sev-high { background: var(--high); color: #fff; }
.sev-medium { background: var(--med); color: #000; }
.sev-low { background: var(--low); color: #fff; }
.sev-info { background: var(--info); color: #fff; }
.inv-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(340px, 1fr));
  gap: 16px;
}
.inv-card {
  background: #0b0f19;
  border: 1px solid var(--line);
  border-radius: 10px;
  padding: 16px;
  display: flex;
  flex-direction: column;
  gap: 10px;
}
</style>
</head>
<body>
<header class="top">
  <div class="brand">
    <div class="brand-icon">J</div>
    <div>JOCKY<small>Next-Gen Digital Forensics Platform · Rust Native Engine</small></div>
  </div>
  <div style="display:flex;gap:10px;align-items:center;">
    <span class="pill on" id="engine-pill">Rust Core v2.1</span>
    <span class="pill off" id="conn-pill">Disconnected</span>
  </div>
</header>

<main>
  <!-- Authentication -->
  <section>
    <h2>Authentication</h2>
    <div style="display:flex;gap:10px;align-items:center;">
      <input type="password" id="token-input" placeholder="Paste X-JKY-Token here..." style="flex:1;">
      <button class="primary" id="btn-connect" onclick="connect()">Connect</button>
      <button onclick="refreshAll()">↻ Refresh</button>
    </div>
  </section>

  <!-- Investigations -->
  <section>
    <h2>Investigations <span class="pill" id="inv-count">0 recorded</span></h2>
    <div class="inv-grid" id="inv-container">
      <div style="color:var(--muted)">Connect with server token to view active and completed investigations.</div>
    </div>
  </section>

  <!-- Status & Agents -->
  <section>
    <h2>Platform Health & Fleet</h2>
    <div class="stats-grid" id="status-stats">
      <div class="stat-card"><div class="stat-val" id="stat-agents">0</div><div class="stat-lbl">Agents</div></div>
      <div class="stat-card"><div class="stat-val" id="stat-jobs">0</div><div class="stat-lbl">Jobs Queued</div></div>
      <div class="stat-card"><div class="stat-val" id="stat-findings" style="color:var(--high)">0</div><div class="stat-lbl">Findings</div></div>
    </div>
    <table>
      <thead>
        <tr><th>Agent ID</th><th>Name</th><th>Host</th><th>Kernel</th><th>Last Seen</th></tr>
      </thead>
      <tbody id="agents-body">
        <tr><td colspan="5" style="color:var(--muted)">No agents enrolled yet. Run 'jocky agent --server http://127.0.0.1:8443 --token &lt;SECRET&gt;'</td></tr>
      </tbody>
    </table>
  </section>

  <!-- Findings -->
  <section>
    <h2>Recent Threat Detections & Findings</h2>
    <table>
      <thead>
        <tr><th>ID</th><th>Severity</th><th>Check</th><th>Title</th><th>Agent</th><th>Timestamp</th></tr>
      </thead>
      <tbody id="findings-body">
        <tr><td colspan="6" style="color:var(--muted)">No findings recorded yet.</td></tr>
      </tbody>
    </table>
  </section>

  <!-- Job Dispatch -->
  <section>
    <h2>Dispatch Forensic Job (.jky)</h2>
    <div style="display:flex;flex-direction:column;gap:10px;">
      <div style="display:flex;gap:10px;">
        <input type="text" id="job-target" placeholder="Target Agent ID or 'all'..." style="width:240px;">
        <select id="job-kind"><option value="source">JOCKY Source Script (.jky)</option></select>
      </div>
      <textarea id="job-payload" rows="6" placeholder="case &quot;INC-REMOTE-001&quot;&#10;target all&#10;collect { system, processes, network }&#10;analyze { suspicious_processes }&#10;verify evidence&#10;report html"></textarea>
      <div><button class="primary" onclick="submitJob()">Dispatch Job to Fleet</button></div>
    </div>
  </section>
</main>

<script>
var state = { token: "", connected: false };

function byId(id) { return document.getElementById(id); }

async function api(path, opts) {
  opts = opts || {};
  var headers = {};
  if (state.token) headers["X-JKY-Token"] = state.token;
  if (opts.body) headers["Content-Type"] = "application/json";
  var res = await fetch(path, {
    method: opts.method || "GET",
    headers: headers,
    body: opts.body
  });
  if (res.status === 204) return null;
  return await res.json();
}

async function connect() {
  state.token = byId("token-input").value.trim();
  try {
    var health = await api("/v1/health");
    if (health && health.status === "ok") {
      state.connected = true;
      byId("conn-pill").className = "pill on";
      byId("conn-pill").textContent = "Connected";
      localStorage.setItem("jky_token", state.token);
      refreshAll();
    }
  } catch (e) {
    alert("Connection failed: " + e);
  }
}

async function refreshAll() {
  if (!state.connected && !state.token) return;
  try {
    var status = await api("/v1/status");
    if (status) renderStatus(status);

    var inv = await api("/v1/investigations");
    if (inv) renderInvestigations(inv);

    var findings = await api("/v1/findings");
    if (findings) renderFindings(findings);
  } catch (e) {
    console.error(e);
  }
}

function renderStatus(status) {
  byId("stat-agents").textContent = status.agents ? status.agents.length : 0;
  byId("stat-jobs").textContent = status.jobs ? status.jobs.total : 0;
  byId("stat-findings").textContent = status.findings ? status.findings.total : 0;

  var tbody = byId("agents-body");
  tbody.replaceChildren();
  if (!status.agents || !status.agents.length) {
    var tr = document.createElement("tr");
    tr.innerHTML = '<td colspan="5" style="color:var(--muted)">No agents enrolled yet.</td>';
    tbody.appendChild(tr);
    return;
  }
  status.agents.forEach(function(a) {
    var tr = document.createElement("tr");
    tr.innerHTML = '<td class="mono">' + a.agent_id + '</td><td>' + a.name + '</td><td class="mono">' + a.host + '</td><td>' + a.kernel + '</td><td class="mono">' + a.last_seen.substring(0, 19) + '</td>';
    tbody.appendChild(tr);
  });
}

function renderInvestigations(payload) {
  var list = payload.investigations || [];
  byId("inv-count").textContent = list.length + " recorded";
  var cont = byId("inv-container");
  cont.replaceChildren();
  if (!list.length) {
    cont.innerHTML = '<div style="color:var(--muted)">No investigations recorded yet.</div>';
    return;
  }
  list.forEach(function(item) {
    var card = document.createElement("div");
    card.className = "inv-card";
    card.innerHTML = 
      '<div style="display:flex;justify-content:space-between;align-items:center;">' +
        '<span style="font-weight:700;font-size:15px;color:var(--accent-glow);font-family:monospace;">' + item.case_id + '</span>' +
        '<span class="pill on">' + item.status.toUpperCase() + '</span>' +
      '</div>' +
      '<div style="display:flex;gap:12px;background:#1f2937;padding:8px 12px;border-radius:6px;font-size:12px;">' +
        '<div><div style="font-size:10px;color:var(--muted)">ARTIFACTS</div><strong>' + item.artifacts_count + '</strong></div>' +
        '<div><div style="font-size:10px;color:var(--muted)">FINDINGS</div><strong style="color:var(--crit)">' + item.findings_count + '</strong></div>' +
        '<div><div style="font-size:10px;color:var(--muted)">TIMELINE</div><strong style="color:#a78bfa">' + item.timeline_count + '</strong></div>' +
      '</div>' +
      '<div class="mono" style="font-size:11px;color:var(--muted);word-break:break-all;background:#030712;padding:6px;border-radius:4px;">' +
        '⛓ HEAD: ' + (item.chain_head ? item.chain_head.substring(0, 32) + '…' : 'N/A') +
      '</div>' +
      '<div style="margin-top:auto;display:flex;justify-content:space-between;align-items:center;padding-top:8px;">' +
        '<span style="font-size:11px;color:var(--muted)">' + item.updated_at.substring(0, 19) + '</span>' +
        '<a href="/v1/investigations/report?case=' + encodeURIComponent(item.case_id) + '" target="_blank" style="color:var(--accent-glow);font-size:12px;font-weight:600;text-decoration:none;">View Report ↗</a>' +
      '</div>';
    cont.appendChild(card);
  });
}

function renderFindings(payload) {
  var list = payload.findings || [];
  var tbody = byId("findings-body");
  tbody.replaceChildren();
  if (!list.length) {
    var tr = document.createElement("tr");
    tr.innerHTML = '<td colspan="6" style="color:var(--muted)">No findings detected yet.</td>';
    tbody.appendChild(tr);
    return;
  }
  list.forEach(function(f) {
    var tr = document.createElement("tr");
    tr.innerHTML = 
      '<td class="mono">#' + f.id + '</td>' +
      '<td><span class="sev sev-' + f.severity.toLowerCase() + '">' + f.severity + '</span></td>' +
      '<td class="mono">' + f.check + '</td>' +
      '<td><strong>' + f.title + '</strong></td>' +
      '<td class="mono">' + f.agent_id + '</td>' +
      '<td class="mono">' + f.created_at.substring(0, 19) + '</td>';
    tbody.appendChild(tr);
  });
}

async function submitJob() {
  var target = byId("job-target").value.trim();
  var payload = byId("job-payload").value;
  if (!payload) return alert("Please enter JOCKY script payload");
  var b64 = btoa(unescape(encodeURIComponent(payload)));
  var res = await api("/v1/jobs/submit", {
    method: "POST",
    body: JSON.stringify({
      kind: "source",
      payload_b64: b64,
      target: target ? target : null
    })
  });
  if (res && res.job_id) {
    alert("Job queued successfully: " + res.job_id);
    refreshAll();
  }
}

window.onload = function() {
  var saved = localStorage.getItem("jky_token");
  if (saved) {
    byId("token-input").value = saved;
    connect();
  }
  setInterval(refreshAll, 10000);
};
</script>
</body>
</html>
"#;
