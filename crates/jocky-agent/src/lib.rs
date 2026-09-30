use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

use chrono::Utc;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub server_url: String,
    pub token: String,
    pub name: String,
    pub state_dir: String,
    pub poll_interval_secs: u64,
    pub once: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentIdentity {
    pub agent_id: String,
    pub name: String,
    pub host: String,
    pub enrolled_at: String,
}

pub struct Agent {
    pub config: AgentConfig,
    pub identity: Option<AgentIdentity>,
}

impl Agent {
    pub fn new(config: AgentConfig) -> Self {
        let identity = Self::load_identity(&config.state_dir);
        Self { config, identity }
    }

    fn load_identity(state_dir: &str) -> Option<AgentIdentity> {
        let path = format!("{}/agent.json", state_dir);
        if let Ok(data) = fs::read_to_string(path) {
            serde_json::from_str(&data).ok()
        } else {
            None
        }
    }

    fn save_identity(&self, identity: &AgentIdentity) {
        let _ = fs::create_dir_all(&self.config.state_dir);
        let path = format!("{}/agent.json", self.config.state_dir);
        if let Ok(data) = serde_json::to_string_pretty(identity) {
            let _ = fs::write(path, data);
        }
    }

    pub fn run(&mut self) -> Result<(), String> {
        println!("╔══════════════════════════════════════════════════════════════╗");
        println!("║       JOCKY 2.1 — Native Forensics Agent (Rust Edition)      ║");
        println!("╚══════════════════════════════════════════════════════════════╝");
        println!("  Target Server: {}", self.config.server_url);
        println!("  State Dir:     {}", self.config.state_dir);
        println!("  Execution:     {}", if self.config.once { "Single-shot (--once)" } else { "Continuous daemon" });
        println!();

        // 1. Enrol or verify identity
        if self.identity.is_none() {
            println!("[AGENT] Enrolling with central management server...");
            let identity = self.enroll()?;
            println!("✓ Enrolled successfully as Agent ID: {}", identity.agent_id);
            self.save_identity(&identity);
            self.identity = Some(identity);
        } else {
            let id = self.identity.as_ref().unwrap();
            println!("[AGENT] Loaded active identity: {} (host: {})", id.agent_id, id.host);
        }

        let agent_id = self.identity.as_ref().unwrap().agent_id.clone();

        // 2. Poll loop
        loop {
            print!("[AGENT] Polling server for pending jobs... ");
            match self.poll_job(&agent_id) {
                Ok(Some(job)) => {
                    println!("JOB RECEIVED: {}", job.job_id);
                    self.execute_and_report(&agent_id, job);
                }
                Ok(None) => {
                    println!("no pending jobs.");
                    if self.config.once {
                        println!("[AGENT] --once flag set: performing baseline host triage & exiting.");
                        self.run_baseline_and_report(&agent_id);
                        break;
                    }
                }
                Err(e) => {
                    println!("poll error: {}", e);
                    if self.config.once {
                        break;
                    }
                }
            }

            if self.config.once {
                break;
            }
            thread::sleep(Duration::from_secs(self.config.poll_interval_secs));
        }

        println!("[AGENT] Execution completed cleanly.");
        Ok(())
    }

    fn enroll(&self) -> Result<AgentIdentity, String> {
        let host = jocky_forensics::ForensicCollector::collect_system().hostname;
        let payload = serde_json::json!({
            "name": self.config.name,
            "host": host,
            "uid": 1000,
            "kernel": std::env::consts::OS
        });

        let res = http_post(&self.config.server_url, "/v1/enroll", &self.config.token, &payload)?;
        let agent_id = res.get("agent_id")
            .and_then(|x| x.as_str())
            .ok_or_else(|| "Missing agent_id in enroll response".to_string())?
            .to_string();

        Ok(AgentIdentity {
            agent_id,
            name: self.config.name.clone(),
            host,
            enrolled_at: Utc::now().to_rfc3339(),
        })
    }

    fn poll_job(&self, agent_id: &str) -> Result<Option<DispatchedJob>, String> {
        let payload = serde_json::json!({ "agent_id": agent_id });
        let res = http_post_optional(&self.config.server_url, "/v1/jobs/poll", &self.config.token, &payload)?;
        match res {
            Some(v) => {
                let job: DispatchedJob = serde_json::from_value(v)
                    .map_err(|e| format!("Failed to parse job: {}", e))?;
                Ok(Some(job))
            }
            None => Ok(None),
        }
    }

    fn execute_and_report(&self, agent_id: &str, job: DispatchedJob) {
        println!("  [EXEC] Decoding job payload ({} bytes)...", job.payload_b64.len());
        let script_bytes = match base64_decode(&job.payload_b64) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("  ✗ Base64 decode failed: {}", e);
                return;
            }
        };
        let script = String::from_utf8_lossy(&script_bytes);

        println!("  [EXEC] Compiling JOCKY script...");
        let ir = match jocky_compiler::compile_source(&script) {
            Ok(ir) => ir,
            Err(e) => {
                eprintln!("  ✗ Script compilation failed: {}", e);
                return;
            }
        };

        println!("  [EXEC] Running on host runtime...");
        match jocky_runtime::Runtime::execute(&ir) {
            Ok(ctx) => {
                println!("  ✓ Execution successful: {} findings, {} artifacts", ctx.findings.len(), ctx.evidence.records.len());
                let result_payload = serde_json::json!({
                    "job_id": job.job_id,
                    "agent_id": agent_id,
                    "result": {
                        "findings": ctx.findings,
                        "artifacts": ctx.evidence.records.len(),
                        "chain_head": ctx.evidence.chain_head,
                        "status": "ok"
                    }
                });
                if let Err(e) = http_post(&self.config.server_url, "/v1/jobs/result", &self.config.token, &result_payload) {
                    eprintln!("  ✗ Failed to report job result: {}", e);
                } else {
                    println!("  ✓ Reported findings back to management server.");
                }
            }
            Err(e) => {
                eprintln!("  ✗ Execution failed: {}", e);
            }
        }
    }

    fn run_baseline_and_report(&self, agent_id: &str) {
        let triage_script = r#"
case "AGENT-AUTO-TRIAGE"
target all
investigation {
    collect { system, processes, network, users }
    analyze { suspicious_processes, suspicious_network }
    verify evidence
}
report html
"#;
        println!("  [TRIAGE] Executing built-in baseline investigation...");
        if let Ok(ir) = jocky_compiler::compile_source(triage_script) {
            if let Ok(ctx) = jocky_runtime::Runtime::execute(&ir) {
                println!("  ✓ Baseline triage produced {} findings, {} artifacts", ctx.findings.len(), ctx.evidence.records.len());
                let result_payload = serde_json::json!({
                    "job_id": "job_baseline_triage",
                    "agent_id": agent_id,
                    "result": {
                        "findings": ctx.findings,
                        "artifacts": ctx.evidence.records.len(),
                        "chain_head": ctx.evidence.chain_head,
                        "status": "ok"
                    }
                });
                let _ = http_post(&self.config.server_url, "/v1/jobs/result", &self.config.token, &result_payload);
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DispatchedJob {
    pub job_id: String,
    pub kind: String,
    pub payload_b64: String,
    pub payload_sha256: String,
}

// ── HTTP Client ─────────────────────────────────────────────────────────────

fn parse_url(url: &str) -> Result<(String, u16), String> {
    let clean = url.trim_start_matches("http://").trim_start_matches("https://");
    if let Some((host, port_str)) = clean.split_once(':') {
        let port = port_str.split('/').next().unwrap_or("80")
            .parse::<u16>()
            .map_err(|e| format!("Invalid port: {}", e))?;
        Ok((host.to_string(), port))
    } else {
        let host = clean.split('/').next().unwrap_or("127.0.0.1").to_string();
        Ok((host, 80))
    }
}

pub fn http_post(
    server_url: &str,
    path: &str,
    token: &str,
    body: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    http_post_optional(server_url, path, token, body)?
        .ok_or_else(|| "Server returned empty response".to_string())
}

pub fn http_post_optional(
    server_url: &str,
    path: &str,
    token: &str,
    body: &serde_json::Value,
) -> Result<Option<serde_json::Value>, String> {
    let (host, port) = parse_url(server_url)?;
    let addr = format!("{}:{}", host, port);
    let mut stream = TcpStream::connect(&addr)
        .map_err(|e| format!("Cannot connect to {}: {}", addr, e))?;

    let json_body = serde_json::to_string(body).unwrap_or_else(|_| "{}".to_string());
    let req = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nX-JKY-Token: {}\r\nConnection: close\r\n\r\n{}",
        path, host, json_body.len(), token, json_body
    );

    stream.write_all(req.as_bytes())
        .map_err(|e| format!("Write failed: {}", e))?;

    let mut res_bytes = Vec::new();
    stream.read_to_end(&mut res_bytes)
        .map_err(|e| format!("Read failed: {}", e))?;

    let res_str = String::from_utf8_lossy(&res_bytes);
    if let Some(idx) = res_str.find("\r\n\r\n") {
        let header_part = &res_str[..idx];
        let body_part = &res_str[idx + 4..];

        if header_part.contains("204 No Content") {
            return Ok(None);
        }
        if header_part.contains("401 Unauthorized") {
            return Err("401 Unauthorized: Invalid X-JKY-Token".to_string());
        }
        if header_part.contains("404 Not Found") {
            return Err("404 Not Found".to_string());
        }

        let val: serde_json::Value = serde_json::from_str(body_part)
            .map_err(|e| format!("Invalid JSON response: {} (Body: {})", e, body_part))?;
        Ok(Some(val))
    } else {
        Err("Invalid HTTP response".to_string())
    }
}

// Simple standard base64 decoding helper
fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let clean: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let mut out = Vec::new();

    let mut i = 0;
    while i < clean.len() {
        let mut buf = [0u8; 4];
        let mut count = 0;
        for j in 0..4 {
            if i + j < clean.len() {
                let c = clean[i + j];
                if c == b'=' {
                    break;
                }
                if let Some(pos) = TABLE.iter().position(|&x| x == c) {
                    buf[j] = pos as u8;
                    count += 1;
                }
            }
        }
        if count >= 2 {
            out.push((buf[0] << 2) | (buf[1] >> 4));
        }
        if count >= 3 {
            out.push((buf[1] << 4) | (buf[2] >> 2));
        }
        if count == 4 {
            out.push((buf[2] << 6) | buf[3]);
        }
        i += 4;
    }
    Ok(out)
}
