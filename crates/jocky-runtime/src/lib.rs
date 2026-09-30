use chrono::Utc;
use jocky_detection::{DetectionEngine, Finding};
use jocky_evidence::EvidenceStore;
use jocky_forensics::{ForensicCollector, NetworkConnection, ProcessInfo, SystemInfo};
use jocky_ir::{CollectionTarget, IrInstruction, IrProgram, ProfileDefinition, ReportFormat};
use jocky_report::ForensicReport;
use jocky_timeline::{EventType, TimelineBuilder, TimelineEvent};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RuntimeError {
    #[error("Forensic evidence error: {0}")]
    Evidence(#[from] jocky_evidence::EvidenceError),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub struct ExecutionContext {
    pub case_id: String,
    pub host: String,
    pub system: Option<SystemInfo>,
    pub processes: Vec<ProcessInfo>,
    pub connections: Vec<NetworkConnection>,
    pub findings: Vec<Finding>,
    pub evidence: EvidenceStore,
    pub timeline: Vec<TimelineEvent>,
    pub alerts: Vec<String>,
    pub profiles: Vec<ProfileDefinition>,
}

impl ExecutionContext {
    pub fn new(case_id: &str) -> Self {
        let hostname = std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "host-node".to_string());

        Self {
            case_id: case_id.to_string(),
            host: hostname,
            system: None,
            processes: Vec::new(),
            connections: Vec::new(),
            findings: Vec::new(),
            evidence: EvidenceStore::new(case_id),
            timeline: Vec::new(),
            alerts: Vec::new(),
            profiles: Vec::new(),
        }
    }
}

pub struct Runtime;

impl Runtime {
    pub fn execute(ir: &IrProgram) -> Result<ExecutionContext, RuntimeError> {
        let case_id = ir.case_id.as_deref().unwrap_or("INCIDENT-UNSPECIFIED");
        let mut ctx = ExecutionContext::new(case_id);
        let mut timeline_builder = TimelineBuilder::new();

        // Load profile definitions from the IR
        ctx.profiles = ir.profiles.clone();

        println!("╔═══════════════════════════════════════════════════════════╗");
        println!("║          JOCKY 2.1 — Rust Forensic Runtime               ║");
        println!("╚═══════════════════════════════════════════════════════════╝");
        println!("[Runtime] Initializing Case: {}", case_id);
        println!("[Runtime] Detection rules loaded: {}", ir.rules.len());
        println!("[Runtime] Profile definitions: {}", ir.profiles.len());
        println!();

        Self::execute_instructions(&ir.instructions, &mut ctx, &mut timeline_builder, ir)?;

        Ok(ctx)
    }

    fn execute_instructions(
        instructions: &[IrInstruction],
        ctx: &mut ExecutionContext,
        timeline_builder: &mut TimelineBuilder,
        ir: &IrProgram,
    ) -> Result<(), RuntimeError> {
        for inst in instructions {
            match inst {
                IrInstruction::SetCase(id) => {
                    ctx.case_id = id.clone();
                    println!("[Case] Set case ID: {}", id);
                }
                IrInstruction::SetTarget(target) => {
                    println!("[Target] Selected: {:?}", target);
                }
                IrInstruction::Collect(target) => match target {
                    CollectionTarget::System => {
                        let sys = ForensicCollector::collect_system();
                        let bytes = serde_json::to_vec(&sys)?;
                        let rec = ctx.evidence.record_artifact(&ctx.host, "system_info", &bytes)?;
                        println!("[Collected] System metadata → {} (SHA256: {}...)", rec.evidence_id, &rec.raw_sha256[..12]);
                        ctx.system = Some(sys);
                    }
                    CollectionTarget::Processes => {
                        let procs = ForensicCollector::collect_processes();
                        let bytes = serde_json::to_vec(&procs)?;
                        let rec = ctx.evidence.record_artifact(&ctx.host, "process_table", &bytes)?;
                        println!("[Collected] {} processes → {} (SHA256: {}...)", procs.len(), rec.evidence_id, &rec.raw_sha256[..12]);
                        for p in &procs {
                            if let Some(st) = p.start_time {
                                timeline_builder.add_event(TimelineEvent {
                                    timestamp: st,
                                    host: ctx.host.clone(),
                                    event_type: EventType::ProcessStarted,
                                    source: "procfs".into(),
                                    description: format!("Process started: {} (PID {})", p.name, p.pid),
                                    evidence_id: rec.evidence_id.clone(),
                                });
                            }
                        }
                        ctx.processes = procs;
                    }
                    CollectionTarget::Network => {
                        let nets = ForensicCollector::collect_network();
                        let bytes = serde_json::to_vec(&nets)?;
                        let rec = ctx.evidence.record_artifact(&ctx.host, "network_connections", &bytes)?;
                        println!("[Collected] {} sockets → {} (SHA256: {}...)", nets.len(), rec.evidence_id, &rec.raw_sha256[..12]);
                        for c in &nets {
                            timeline_builder.add_event(TimelineEvent {
                                timestamp: Utc::now(),
                                host: ctx.host.clone(),
                                event_type: EventType::NetworkConnection,
                                source: "netfs".into(),
                                description: format!("{}:{} → {}:{} ({})", c.local_address, c.local_port, c.remote_address, c.remote_port, c.state),
                                evidence_id: rec.evidence_id.clone(),
                            });
                        }
                        ctx.connections = nets;
                    }
                    CollectionTarget::Users => {
                        let users = ForensicCollector::collect_users();
                        let bytes = serde_json::to_vec(&users)?;
                        let rec = ctx.evidence.record_artifact(&ctx.host, "user_accounts", &bytes)?;
                        println!("[Collected] {} user accounts → {} (SHA256: {}...)", users.len(), rec.evidence_id, &rec.raw_sha256[..12]);
                    }
                    CollectionTarget::Services => {
                        let svcs = ForensicCollector::collect_services();
                        let bytes = serde_json::to_vec(&svcs)?;
                        let rec = ctx.evidence.record_artifact(&ctx.host, "services", &bytes)?;
                        println!("[Collected] {} services → {} (SHA256: {}...)", svcs.len(), rec.evidence_id, &rec.raw_sha256[..12]);
                    }
                    CollectionTarget::StartupItems => {
                        let items = ForensicCollector::collect_startup_items();
                        let bytes = serde_json::to_vec(&items)?;
                        let rec = ctx.evidence.record_artifact(&ctx.host, "startup_items", &bytes)?;
                        println!("[Collected] {} startup items → {} (SHA256: {}...)", items.len(), rec.evidence_id, &rec.raw_sha256[..12]);
                    }
                    other => {
                        println!("[Collected] Placeholder for target: {:?}", other);
                    }
                },
                IrInstruction::Analyze(target) => {
                    println!("[Analyzing] Target: {:?}", target);
                    let proc_findings = DetectionEngine::analyze_processes(&ctx.host, &ctx.processes);
                    let net_findings = DetectionEngine::analyze_network(&ctx.host, &ctx.connections);
                    println!("   → {} process detections, {} network detections", proc_findings.len(), net_findings.len());
                    ctx.findings.extend(proc_findings);
                    ctx.findings.extend(net_findings);
                }
                IrInstruction::BuildTimeline(_target) => {
                    println!("[Timeline] Chronologically sorting events");
                }
                IrInstruction::VerifyEvidenceChain => {
                    let valid = ctx.evidence.verify_integrity()?;
                    if valid {
                        println!("[Integrity] PASS ✓ Hash chain verified across {} records (head: {})",
                            ctx.evidence.records.len(), &ctx.evidence.chain_head[..16]);
                    } else {
                        println!("[Integrity] FAIL ✗ Evidence chain integrity violation!");
                    }
                }
                IrInstruction::PreserveEvidence => {
                    println!("[Evidence] Preserving {} evidence records to disk", ctx.evidence.records.len());
                    let evidence_json = serde_json::to_string_pretty(&ctx.evidence.records)?;
                    let path = format!("evidence/{}_preserved.json", ctx.case_id.to_lowercase().replace(' ', "_"));
                    std::fs::create_dir_all("evidence").ok();
                    std::fs::write(&path, evidence_json)?;
                    println!("[Evidence] Preserved to: {}", path);
                }
                IrInstruction::GenerateAlert(kind) => {
                    let alert_type = kind.as_deref().unwrap_or("alert");
                    let alert_msg = format!(
                        "JOCKY ALERT [{}] Case: {} — {} findings detected at {}",
                        alert_type.to_uppercase(),
                        ctx.case_id,
                        ctx.findings.len(),
                        Utc::now().to_rfc3339()
                    );
                    println!("[ALERT] ⚠ {}", alert_msg);
                    ctx.alerts.push(alert_msg);
                }
                IrInstruction::RunProfile(profile_name) => {
                    println!("[Profile] Running profile: '{}'", profile_name);
                    // Look up the profile definition
                    let profile = ctx.profiles.iter().find(|p| p.name == *profile_name).cloned();
                    if let Some(prof) = profile {
                        // Execute the profile's collection + analysis as IR instructions
                        let collect_insts: Vec<IrInstruction> = prof.collect
                            .iter()
                            .map(|t| IrInstruction::Collect(t.clone()))
                            .collect();
                        let analyze_insts: Vec<IrInstruction> = prof.analyze
                            .iter()
                            .map(|t| IrInstruction::Analyze(t.clone()))
                            .collect();
                        Self::execute_instructions(&collect_insts, ctx, timeline_builder, ir)?;
                        Self::execute_instructions(&analyze_insts, ctx, timeline_builder, ir)?;
                    } else {
                        // Built-in profiles
                        match profile_name.as_str() {
                            "quick_triage" => {
                                let built_in = vec![
                                    IrInstruction::Collect(CollectionTarget::System),
                                    IrInstruction::Collect(CollectionTarget::Processes),
                                    IrInstruction::Collect(CollectionTarget::Network),
                                    IrInstruction::Collect(CollectionTarget::Users),
                                ];
                                Self::execute_instructions(&built_in, ctx, timeline_builder, ir)?;
                            }
                            "full_system" => {
                                let built_in = vec![
                                    IrInstruction::Collect(CollectionTarget::System),
                                    IrInstruction::Collect(CollectionTarget::Processes),
                                    IrInstruction::Collect(CollectionTarget::Network),
                                    IrInstruction::Collect(CollectionTarget::Users),
                                    IrInstruction::Collect(CollectionTarget::Services),
                                    IrInstruction::Collect(CollectionTarget::StartupItems),
                                ];
                                Self::execute_instructions(&built_in, ctx, timeline_builder, ir)?;
                            }
                            _ => {
                                println!("[Profile] Warning: Profile '{}' not defined", profile_name);
                            }
                        }
                    }
                }
                IrInstruction::GenerateReport(cfg) => {
                    ctx.timeline = timeline_builder.build();
                    let sys_list = if let Some(ref s) = ctx.system {
                        vec![s.clone()]
                    } else {
                        vec![ForensicCollector::collect_system()]
                    };

                    let report = ForensicReport::new(
                        &ctx.case_id,
                        "JOCKY Investigator",
                        sys_list,
                        ctx.findings.clone(),
                        ctx.timeline.clone(),
                        ctx.evidence.clone(),
                    );

                    let out_path = cfg.output_path.clone().unwrap_or_else(|| match cfg.format {
                        ReportFormat::Html     => format!("{}_report.html", ctx.case_id.to_lowercase().replace(' ', "_")),
                        ReportFormat::Json     => format!("{}_report.json", ctx.case_id.to_lowercase().replace(' ', "_")),
                        ReportFormat::Pdf      => format!("{}_report.pdf",  ctx.case_id.to_lowercase().replace(' ', "_")),
                        ReportFormat::Markdown => format!("{}_report.md",   ctx.case_id.to_lowercase().replace(' ', "_")),
                    });

                    match cfg.format {
                        ReportFormat::Html => {
                            let html = report.to_html();
                            std::fs::write(&out_path, html)?;
                            println!("[Report] HTML report → {}", out_path);
                        }
                        ReportFormat::Json => {
                            let json = report.to_json()?;
                            std::fs::write(&out_path, json)?;
                            println!("[Report] JSON report → {}", out_path);
                        }
                        ReportFormat::Markdown => {
                            let md = report.to_markdown();
                            std::fs::write(&out_path, md)?;
                            println!("[Report] Markdown report → {}", out_path);
                        }
                        _ => {
                            let html = report.to_html();
                            std::fs::write(&out_path, html)?;
                            println!("[Report] Report → {}", out_path);
                        }
                    }
                }
                IrInstruction::ConditionalBlock { condition_json, then_instructions, else_instructions } => {
                    // Simple condition evaluation: check if findings exist, etc.
                    let condition_met = Self::evaluate_condition(condition_json, ctx);
                    if condition_met {
                        println!("[If] Condition true, executing then-block");
                        Self::execute_instructions(then_instructions, ctx, timeline_builder, ir)?;
                    } else if !else_instructions.is_empty() {
                        println!("[If] Condition false, executing else-block");
                        Self::execute_instructions(else_instructions, ctx, timeline_builder, ir)?;
                    }
                }
                IrInstruction::ForLoop { variable, iterable_json: _, body } => {
                    println!("[For] Executing loop over '{}'", variable);
                    // Execute body once for now (multi-host loop in future)
                    Self::execute_instructions(body, ctx, timeline_builder, ir)?;
                }
                IrInstruction::SetVar { name, value_json } => {
                    println!("[Var] {} = {}", name, value_json);
                }
                IrInstruction::EmitCustom { kind, payload_json } => {
                    println!("[Emit] {}: {}", kind, payload_json);
                }
            }
        }
        Ok(())
    }

    fn evaluate_condition(condition_json: &str, ctx: &ExecutionContext) -> bool {
        // Simple heuristic: if condition mentions "finding" or "severity",
        // evaluate based on current findings
        if condition_json.contains("finding") || condition_json.contains("HIGH") || condition_json.contains("CRITICAL") {
            return !ctx.findings.is_empty();
        }
        // Default: condition is true
        true
    }
}
