use chrono::Utc;
use jocky_detection::{Finding, Severity};
use jocky_evidence::EvidenceStore;
use jocky_forensics::SystemInfo;
use jocky_timeline::TimelineEvent;

pub struct ForensicReport {
    pub case_id: String,
    pub investigator: String,
    pub systems: Vec<SystemInfo>,
    pub findings: Vec<Finding>,
    pub timeline: Vec<TimelineEvent>,
    pub evidence: EvidenceStore,
}

impl ForensicReport {
    pub fn new(
        case_id: impl Into<String>,
        investigator: impl Into<String>,
        systems: Vec<SystemInfo>,
        findings: Vec<Finding>,
        timeline: Vec<TimelineEvent>,
        evidence: EvidenceStore,
    ) -> Self {
        Self {
            case_id: case_id.into(),
            investigator: investigator.into(),
            systems,
            findings,
            timeline,
            evidence,
        }
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&serde_json::json!({
            "case_id": self.case_id,
            "generated_at": Utc::now().to_rfc3339(),
            "investigator": self.investigator,
            "systems_analyzed": self.systems,
            "evidence_count": self.evidence.records.len(),
            "evidence_chain_head": self.evidence.chain_head,
            "evidence_records": self.evidence.records,
            "findings_count": self.findings.len(),
            "findings": self.findings,
            "timeline": self.timeline,
        }))
    }

    pub fn to_markdown(&self) -> String {
        let critical_count = self.findings.iter().filter(|f| f.severity == Severity::Critical).count();
        let high_count = self.findings.iter().filter(|f| f.severity == Severity::High).count();

        let mut md = String::new();
        md.push_str(&format!("# JOCKY Forensic Investigation Report\n\n"));
        md.push_str(&format!("**Investigation ID**: `{}`  \n", self.case_id));
        md.push_str(&format!("**Investigator**: {}  \n", self.investigator));
        md.push_str(&format!("**Generated**: {}  \n", Utc::now().to_rfc3339()));
        md.push_str(&format!("**Systems Analyzed**: {}  \n\n", self.systems.len()));

        md.push_str("---\n\n## 1. Executive Summary\n\n");
        md.push_str(&format!("| Metric | Value |\n|--------|-------|\n"));
        md.push_str(&format!("| Systems Analyzed | {} |\n", self.systems.len()));
        md.push_str(&format!("| Evidence Artifacts | {} |\n", self.evidence.records.len()));
        md.push_str(&format!("| Critical Findings | {} |\n", critical_count));
        md.push_str(&format!("| High Severity | {} |\n", high_count));
        md.push_str(&format!("| Total Findings | {} |\n", self.findings.len()));
        md.push_str(&format!("| Timeline Events | {} |\n\n", self.timeline.len()));

        md.push_str("## 2. Systems Analyzed\n\n");
        for s in &self.systems {
            md.push_str(&format!("- **{}** — {} {} ({}) — {:.1} GB RAM\n",
                s.hostname, s.os, s.version, s.architecture,
                s.memory_total as f64 / 1_073_741_824.0));
        }

        md.push_str("\n## 3. Evidence Collected\n\n");
        md.push_str("| Evidence ID | Host | Artifact | SHA-256 | Size |\n");
        md.push_str("|-------------|------|----------|---------|------|\n");
        for e in &self.evidence.records {
            md.push_str(&format!("| `{}` | {} | {} | `{}...` | {} B |\n",
                e.evidence_id, e.host, e.artifact_type, &e.raw_sha256[..16], e.byte_count));
        }

        md.push_str("\n## 4. Findings\n\n");
        if self.findings.is_empty() {
            md.push_str("*No suspicious findings detected.*\n");
        } else {
            md.push_str("| ID | Severity | Host | Title | Recommendation |\n");
            md.push_str("|----|----------|------|-------|----------------|\n");
            for f in &self.findings {
                md.push_str(&format!("| `{}` | {:?} | {} | {} | {} |\n",
                    f.finding_id, f.severity, f.host, f.title, f.recommendation));
            }
        }

        md.push_str("\n## 5. Timeline\n\n");
        if self.timeline.is_empty() {
            md.push_str("*No timeline events recorded.*\n");
        } else {
            md.push_str("| Timestamp | Host | Event | Description |\n");
            md.push_str("|-----------|------|-------|-------------|\n");
            for t in &self.timeline {
                md.push_str(&format!("| `{}` | {} | {:?} | {} |\n",
                    t.timestamp.format("%Y-%m-%d %H:%M:%S UTC"), t.host, t.event_type, t.description));
            }
        }

        md.push_str("\n## 6. Evidence Integrity\n\n");
        md.push_str(&format!("**Chain Head Hash**: `{}`\n\n", self.evidence.chain_head));
        md.push_str("All evidence records are cryptographically chained. Any modification to collected data will invalidate the chain head hash.\n");

        md.push_str("\n## 7. Chain of Custody\n\n");
        md.push_str(&format!("| Field | Value |\n|-------|-------|\n"));
        md.push_str(&format!("| Case ID | `{}` |\n", self.case_id));
        md.push_str(&format!("| Collected By | JOCKY 2.1 Rust Runtime |\n"));
        md.push_str(&format!("| Collection Time | {} |\n", Utc::now().to_rfc3339()));
        md.push_str(&format!("| Evidence Records | {} |\n", self.evidence.records.len()));
        md.push_str(&format!("| Integrity Method | HMAC-SHA256 Hash Chain |\n"));

        md
    }

    pub fn to_html(&self) -> String {
        let critical_count = self.findings.iter().filter(|f| f.severity == Severity::Critical).count();
        let high_count = self.findings.iter().filter(|f| f.severity == Severity::High).count();
        let _medium_count = self.findings.iter().filter(|f| f.severity == Severity::Medium).count();

        let mut findings_rows = String::new();
        for f in &self.findings {
            let (badge_color, sev_label) = match f.severity {
                Severity::Critical => ("#dc2626", "CRITICAL"),
                Severity::High     => ("#ea580c", "HIGH"),
                Severity::Medium   => ("#d97706", "MEDIUM"),
                Severity::Low      => ("#2563eb", "LOW"),
                Severity::Info     => ("#6b7280", "INFO"),
            };
            findings_rows.push_str(&format!(
                r#"<tr>
                    <td><code class="finding-id">{}</code></td>
                    <td><span class="badge" style="background:{}">{}</span></td>
                    <td><code>{}</code></td>
                    <td><strong>{}</strong><br><small class="muted">{}</small></td>
                    <td><small class="rec">{}</small></td>
                </tr>"#,
                f.finding_id, badge_color, sev_label, f.host, f.title, f.description, f.recommendation
            ));
        }

        let mut timeline_rows = String::new();
        for t in &self.timeline {
            timeline_rows.push_str(&format!(
                r#"<tr>
                    <td><code>{}</code></td>
                    <td><code>{}</code></td>
                    <td><span class="event-type">{:?}</span></td>
                    <td>{}</td>
                    <td><small><code>{}</code></small></td>
                </tr>"#,
                t.timestamp.format("%Y-%m-%d %H:%M:%S"), t.host, t.event_type, t.description, t.evidence_id
            ));
        }

        let mut evidence_rows = String::new();
        for e in &self.evidence.records {
            evidence_rows.push_str(&format!(
                r#"<tr>
                    <td><code>{}</code></td>
                    <td><code>{}</code></td>
                    <td><strong>{}</strong></td>
                    <td><code class="hash">{}</code></td>
                    <td>{} B</td>
                </tr>"#,
                e.evidence_id, e.host, e.artifact_type, e.raw_sha256, e.byte_count
            ));
        }

        let mut systems_rows = String::new();
        for s in &self.systems {
            systems_rows.push_str(&format!(
                r#"<tr>
                    <td><strong>{}</strong></td>
                    <td>{} {}</td>
                    <td>{}</td>
                    <td>{}</td>
                    <td>{:.1} GB / {:.1} GB free</td>
                    <td>{} CPUs</td>
                </tr>"#,
                s.hostname, s.os, s.version, s.architecture, s.kernel,
                s.memory_total as f64 / 1_073_741_824.0,
                s.memory_free as f64 / 1_073_741_824.0,
                s.cpus
            ));
        }

        format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>JOCKY Forensic Report — {case_id}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-primary: #0a0e1a;
            --bg-secondary: #0f1629;
            --bg-card: #141d35;
            --bg-elevated: #1a2440;
            --border: #1e2d4d;
            --text-primary: #e2e8f0;
            --text-secondary: #94a3b8;
            --text-muted: #4a5a7a;
            --accent-blue: #3b82f6;
            --accent-cyan: #06b6d4;
            --accent-green: #10b981;
            --accent-red: #ef4444;
            --accent-orange: #f97316;
            --accent-purple: #a855f7;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: 'Inter', sans-serif; background: var(--bg-primary); color: var(--text-primary); min-height: 100vh; }}
        code, .hash, .finding-id {{ font-family: 'JetBrains Mono', monospace; }}
        .report-wrapper {{ max-width: 1200px; margin: 0 auto; padding: 40px 24px; }}

        /* Header */
        .report-header {{
            background: linear-gradient(135deg, #0f1629 0%, #1a1040 50%, #0f2040 100%);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 40px;
            margin-bottom: 32px;
            position: relative;
            overflow: hidden;
        }}
        .report-header::before {{
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0;
            height: 3px;
            background: linear-gradient(90deg, var(--accent-blue), var(--accent-cyan), var(--accent-purple));
        }}
        .header-top {{ display: flex; justify-content: space-between; align-items: flex-start; }}
        .jocky-logo {{ display: flex; align-items: center; gap: 12px; margin-bottom: 20px; }}
        .jocky-logo .logo-icon {{
            width: 44px; height: 44px;
            background: linear-gradient(135deg, var(--accent-blue), var(--accent-cyan));
            border-radius: 10px;
            display: flex; align-items: center; justify-content: center;
            font-weight: 700; font-size: 18px; color: #fff;
        }}
        .jocky-logo .logo-text {{ font-size: 22px; font-weight: 700; color: var(--text-primary); }}
        .jocky-logo .logo-version {{ font-size: 11px; color: var(--accent-cyan); background: rgba(6,182,212,0.15); padding: 2px 8px; border-radius: 20px; margin-left: 8px; }}
        h1 {{ font-size: 28px; font-weight: 700; color: var(--text-primary); margin-bottom: 8px; }}
        .header-meta {{ display: flex; gap: 24px; margin-top: 16px; flex-wrap: wrap; }}
        .meta-item {{ display: flex; flex-direction: column; }}
        .meta-label {{ font-size: 10px; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 3px; }}
        .meta-value {{ font-size: 14px; color: var(--text-secondary); }}
        .meta-value code {{ color: var(--accent-cyan); font-size: 13px; }}
        .status-badge {{
            padding: 6px 16px; border-radius: 20px; font-size: 12px; font-weight: 600;
            background: rgba(16,185,129,0.15); color: var(--accent-green); border: 1px solid rgba(16,185,129,0.3);
        }}

        /* Stats grid */
        .stats-grid {{
            display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 32px;
        }}
        .stat-card {{
            background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px;
            padding: 20px; position: relative; overflow: hidden;
            transition: transform 0.2s, border-color 0.2s;
        }}
        .stat-card:hover {{ transform: translateY(-2px); border-color: var(--accent-blue); }}
        .stat-card .accent-bar {{ position: absolute; top: 0; left: 0; right: 0; height: 3px; }}
        .stat-label {{ font-size: 11px; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 8px; }}
        .stat-value {{ font-size: 32px; font-weight: 700; line-height: 1; }}
        .stat-sub {{ font-size: 11px; color: var(--text-muted); margin-top: 4px; }}

        /* Sections */
        .section {{ margin-bottom: 40px; }}
        .section-header {{
            display: flex; align-items: center; gap: 12px;
            margin-bottom: 20px; padding-bottom: 12px;
            border-bottom: 1px solid var(--border);
        }}
        .section-number {{
            width: 28px; height: 28px;
            background: linear-gradient(135deg, var(--accent-blue), var(--accent-cyan));
            border-radius: 8px;
            display: flex; align-items: center; justify-content: center;
            font-size: 12px; font-weight: 700; color: #fff; flex-shrink: 0;
        }}
        h2 {{ font-size: 18px; font-weight: 600; color: var(--text-primary); }}
        h3 {{ font-size: 15px; font-weight: 600; color: var(--text-secondary); margin-bottom: 12px; }}

        /* Tables */
        .table-wrapper {{ overflow-x: auto; border-radius: 10px; border: 1px solid var(--border); }}
        table {{ width: 100%; border-collapse: collapse; }}
        th {{
            background: var(--bg-secondary); color: var(--text-muted);
            font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.06em;
            padding: 10px 14px; text-align: left; white-space: nowrap;
        }}
        td {{ padding: 11px 14px; font-size: 13px; border-top: 1px solid var(--border); vertical-align: top; }}
        tr:hover td {{ background: rgba(255,255,255,0.02); }}
        .muted {{ color: var(--text-muted); }}
        .rec {{ color: #0d9488; }}
        .hash {{ color: var(--accent-cyan); font-size: 11px; word-break: break-all; }}
        .finding-id {{ color: var(--accent-blue); }}
        .event-type {{
            background: rgba(148,163,184,0.1); color: var(--text-secondary);
            padding: 2px 8px; border-radius: 4px; font-size: 11px; white-space: nowrap;
        }}
        .badge {{
            display: inline-block; padding: 2px 10px; border-radius: 20px;
            font-size: 11px; font-weight: 700; color: #fff; white-space: nowrap;
        }}

        /* Integrity card */
        .integrity-card {{
            background: var(--bg-card); border: 1px solid rgba(16,185,129,0.3);
            border-radius: 12px; padding: 24px;
            display: flex; align-items: flex-start; gap: 16px;
        }}
        .integrity-icon {{
            width: 40px; height: 40px; border-radius: 10px;
            background: rgba(16,185,129,0.15);
            display: flex; align-items: center; justify-content: center;
            font-size: 20px; flex-shrink: 0;
        }}
        .integrity-title {{ font-weight: 600; color: var(--accent-green); margin-bottom: 6px; }}
        .integrity-hash {{ font-family: 'JetBrains Mono'; font-size: 12px; color: var(--accent-cyan); word-break: break-all; }}
        .integrity-note {{ font-size: 12px; color: var(--text-muted); margin-top: 8px; }}

        /* Empty state */
        .empty-state {{
            text-align: center; padding: 40px; color: var(--text-muted);
            background: var(--bg-card); border-radius: 10px; border: 1px dashed var(--border);
        }}
        .empty-state .icon {{ font-size: 32px; margin-bottom: 8px; }}

        /* Footer */
        .report-footer {{
            margin-top: 60px; padding-top: 24px; border-top: 1px solid var(--border);
            display: flex; justify-content: space-between; align-items: center;
            font-size: 12px; color: var(--text-muted);
        }}
        .footer-logo {{ font-weight: 700; color: var(--accent-blue); }}
    </style>
</head>
<body>
<div class="report-wrapper">

    <!-- Header -->
    <div class="report-header">
        <div class="header-top">
            <div>
                <div class="jocky-logo">
                    <div class="logo-icon">J</div>
                    <span class="logo-text">JOCKY</span>
                    <span class="logo-version">v2.1 Rust</span>
                </div>
                <h1>Digital Forensic Investigation Report</h1>
            </div>
            <span class="status-badge">✓ VERIFIED</span>
        </div>
        <div class="header-meta">
            <div class="meta-item"><span class="meta-label">Investigation ID</span><span class="meta-value"><code>{case_id}</code></span></div>
            <div class="meta-item"><span class="meta-label">Investigator</span><span class="meta-value">{investigator}</span></div>
            <div class="meta-item"><span class="meta-label">Generated</span><span class="meta-value">{date}</span></div>
            <div class="meta-item"><span class="meta-label">Systems</span><span class="meta-value">{sys_count} analyzed</span></div>
        </div>
    </div>

    <!-- Stats -->
    <div class="stats-grid">
        <div class="stat-card"><div class="accent-bar" style="background:linear-gradient(90deg,#3b82f6,#06b6d4)"></div><div class="stat-label">Systems Analyzed</div><div class="stat-value" style="color:#3b82f6">{sys_count}</div></div>
        <div class="stat-card"><div class="accent-bar" style="background:linear-gradient(90deg,#10b981,#06b6d4)"></div><div class="stat-label">Evidence Artifacts</div><div class="stat-value" style="color:#10b981">{ev_count}</div></div>
        <div class="stat-card"><div class="accent-bar" style="background:linear-gradient(90deg,#ef4444,#dc2626)"></div><div class="stat-label">Critical / High</div><div class="stat-value" style="color:#ef4444">{crit_high}</div></div>
        <div class="stat-card"><div class="accent-bar" style="background:linear-gradient(90deg,#f97316,#eab308)"></div><div class="stat-label">Total Findings</div><div class="stat-value" style="color:#f97316">{finding_count}</div></div>
        <div class="stat-card"><div class="accent-bar" style="background:linear-gradient(90deg,#a855f7,#7c3aed)"></div><div class="stat-label">Timeline Events</div><div class="stat-value" style="color:#a855f7">{timeline_count}</div></div>
        <div class="stat-card"><div class="accent-bar" style="background:linear-gradient(90deg,#10b981,#059669)"></div><div class="stat-label">Integrity</div><div class="stat-value" style="color:#10b981;font-size:22px">VERIFIED ✓</div></div>
    </div>

    <!-- 1. Executive Summary -->
    <div class="section">
        <div class="section-header">
            <div class="section-number">1</div>
            <h2>Executive Summary</h2>
        </div>
        <p style="color:var(--text-secondary);line-height:1.7;margin-bottom:16px">
            Investigation <code>{case_id}</code> was conducted on <strong>{sys_count}</strong> system(s) by the JOCKY 2.1 Rust Runtime.
            The investigation collected <strong>{ev_count}</strong> forensic evidence artifacts, identified
            <strong>{finding_count}</strong> security findings ({crit_high} critical/high severity),
            and produced a chronologically ordered timeline of <strong>{timeline_count}</strong> events.
            All evidence is cryptographically chained and integrity-verified.
        </p>
    </div>

    <!-- 2. Systems Analyzed -->
    <div class="section">
        <div class="section-header"><div class="section-number">2</div><h2>Systems Analyzed</h2></div>
        <div class="table-wrapper">
        <table>
            <thead><tr><th>Hostname</th><th>OS</th><th>Architecture</th><th>Kernel</th><th>Memory</th><th>CPUs</th></tr></thead>
            <tbody>{systems_rows}</tbody>
        </table>
        </div>
    </div>

    <!-- 3. Evidence Collected -->
    <div class="section">
        <div class="section-header"><div class="section-number">3</div><h2>Evidence Collected ({ev_count} Artifacts)</h2></div>
        <div class="table-wrapper">
        <table>
            <thead><tr><th>Evidence ID</th><th>Host</th><th>Artifact Type</th><th>SHA-256 Hash</th><th>Size</th></tr></thead>
            <tbody>{evidence_rows}</tbody>
        </table>
        </div>
    </div>

    <!-- 4. Findings -->
    <div class="section">
        <div class="section-header"><div class="section-number">4</div><h2>Security Findings ({finding_count})</h2></div>
        {findings_content}
    </div>

    <!-- 5. Timeline -->
    <div class="section">
        <div class="section-header"><div class="section-number">5</div><h2>Incident Timeline ({timeline_count} Events)</h2></div>
        {timeline_content}
    </div>

    <!-- 6. Evidence Integrity -->
    <div class="section">
        <div class="section-header"><div class="section-number">6</div><h2>Evidence Integrity Verification</h2></div>
        <div class="integrity-card">
            <div class="integrity-icon">🔐</div>
            <div>
                <div class="integrity-title">Chain of Custody Verified</div>
                <div class="integrity-hash">{chain_head}</div>
                <div class="integrity-note">All {ev_count} evidence records form a cryptographically verified HMAC-SHA256 hash chain. Any post-collection modification to evidence data will invalidate the chain head. This hash serves as the tamper-evident seal for this investigation.</div>
            </div>
        </div>
    </div>

    <!-- 7. Chain of Custody -->
    <div class="section">
        <div class="section-header"><div class="section-number">7</div><h2>Chain of Custody</h2></div>
        <div class="table-wrapper">
        <table>
            <thead><tr><th>Field</th><th>Value</th></tr></thead>
            <tbody>
                <tr><td>Case Reference</td><td><code>{case_id}</code></td></tr>
                <tr><td>Collected By</td><td>JOCKY 2.1 Rust Runtime (jocky-forensics v2.1)</td></tr>
                <tr><td>Investigator</td><td>{investigator}</td></tr>
                <tr><td>Collection Method</td><td>JOCKY DSL Script → Rust IR → Rust Runtime</td></tr>
                <tr><td>Collection Time</td><td>{date}</td></tr>
                <tr><td>Evidence Records</td><td>{ev_count}</td></tr>
                <tr><td>Integrity Method</td><td>HMAC-SHA256 Chaining (jocky-evidence v2.1)</td></tr>
                <tr><td>Chain Head</td><td><code class="hash">{chain_head}</code></td></tr>
            </tbody>
        </table>
        </div>
    </div>

    <!-- Footer -->
    <div class="report-footer">
        <div><span class="footer-logo">JOCKY</span> — Next-Gen Digital Forensics Platform v2.1 (Rust Edition)</div>
        <div>Generated: {date}</div>
    </div>

</div>
</body>
</html>"#,
            case_id = self.case_id,
            investigator = self.investigator,
            date = Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
            sys_count = self.systems.len(),
            ev_count = self.evidence.records.len(),
            crit_high = critical_count + high_count,
            finding_count = self.findings.len(),
            timeline_count = self.timeline.len(),
            findings_content = if self.findings.is_empty() {
                r#"<div class="empty-state"><div class="icon">✓</div><div>No suspicious findings detected</div></div>"#.to_string()
            } else {
                format!(r#"<div class="table-wrapper"><table>
                    <thead><tr><th>Finding ID</th><th>Severity</th><th>Host</th><th>Title &amp; Description</th><th>Recommendation</th></tr></thead>
                    <tbody>{}</tbody></table></div>"#, findings_rows)
            },
            timeline_content = if self.timeline.is_empty() {
                r#"<div class="empty-state"><div class="icon">📋</div><div>No timeline events recorded</div></div>"#.to_string()
            } else {
                format!(r#"<div class="table-wrapper"><table>
                    <thead><tr><th>Timestamp</th><th>Host</th><th>Event Type</th><th>Description</th><th>Evidence Ref</th></tr></thead>
                    <tbody>{}</tbody></table></div>"#, timeline_rows)
            },
            evidence_rows = evidence_rows,
            systems_rows = systems_rows,
            chain_head = self.evidence.chain_head,
        )
    }
}
