use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub finding_id: String,
    pub host: String,
    pub check: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub recommendation: String,
    pub evidence: serde_json::Value,
    pub timestamp: DateTime<Utc>,
}

pub struct DetectionEngine;

impl DetectionEngine {
    pub fn analyze_processes(host: &str, processes: &[jocky_forensics::ProcessInfo]) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut counter = 1;

        for p in processes {
            // Rule 1: Executable running from temp or user writable paths
            let path_lower = p.exe_path.to_lowercase();
            if path_lower.contains("\\temp\\") || path_lower.contains("/tmp/") || path_lower.contains("\\appdata\\local\\temp") {
                findings.push(Finding {
                    finding_id: format!("FIND-{:04}", counter),
                    host: host.to_string(),
                    check: "temp_executable".into(),
                    severity: Severity::High,
                    title: format!("Process {} running from temporary directory", p.name),
                    description: format!(
                        "Process {} (PID {}) is executing from an atypical temp path: {}",
                        p.name, p.pid, p.exe_path
                    ),
                    recommendation: "Inspect process parentage, verify digital signature and quarantine image.".into(),
                    evidence: serde_json::json!({
                        "pid": p.pid,
                        "exe": p.exe_path,
                        "cmdline": p.cmdline
                    }),
                    timestamp: Utc::now(),
                });
                counter += 1;
            }

            // Rule 2: Unsigned or masquerading system binaries
            if (p.name == "svchost.exe" || p.name == "lsass.exe") && !path_lower.starts_with("c:\\windows\\system32") {
                findings.push(Finding {
                    finding_id: format!("FIND-{:04}", counter),
                    host: host.to_string(),
                    check: "masquerading_binary".into(),
                    severity: Severity::Critical,
                    title: format!("Critical system binary {} masquerading from invalid path", p.name),
                    description: format!(
                        "Expected {} in system32, but running from {}",
                        p.name, p.exe_path
                    ),
                    recommendation: "Immediate incident response required: isolate host and preserve memory image.".into(),
                    evidence: serde_json::json!({
                        "pid": p.pid,
                        "exe": p.exe_path
                    }),
                    timestamp: Utc::now(),
                });
                counter += 1;
            }
        }

        findings
    }

    pub fn analyze_network(host: &str, connections: &[jocky_forensics::NetworkConnection]) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut counter = 100;

        for c in connections {
            // Suspicious remote ports or plain HTTP connections to remote IPs
            if c.remote_port == 4444 || c.remote_port == 1337 || c.remote_port == 8888 {
                findings.push(Finding {
                    finding_id: format!("FIND-{:04}", counter),
                    host: host.to_string(),
                    check: "suspicious_c2_port".into(),
                    severity: Severity::High,
                    title: format!("Outbound connection to known C2/reverse-shell port {}", c.remote_port),
                    description: format!(
                        "PID {} ({:?}) connected to {}:{}",
                        c.pid, c.process_name, c.remote_address, c.remote_port
                    ),
                    recommendation: "Sever connection, extract remote IP reputation and perform process memory dump.".into(),
                    evidence: serde_json::json!(c),
                    timestamp: Utc::now(),
                });
                counter += 1;
            }
        }

        findings
    }
}
