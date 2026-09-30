use serde::{Deserialize, Serialize};
pub use jocky_ast::{
    AnalysisTarget, CollectionTarget, CompareOp, Condition, Expression,
    InvestigationBlock, ProfileDefinition, ReportConfig, ReportFormat,
    ReportSection, RuleDefinition, Severity, TargetSelector, TimelineTarget,
};

/// The compiled JOCKY Intermediate Representation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IrProgram {
    pub case_id: Option<String>,
    pub target: TargetSelector,
    pub profiles: Vec<ProfileDefinition>,
    pub rules: Vec<RuleDefinition>,
    pub instructions: Vec<IrInstruction>,
}

/// Individual IR instructions executed by the runtime
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum IrInstruction {
    SetCase(String),
    SetTarget(TargetSelector),
    Collect(CollectionTarget),
    Analyze(AnalysisTarget),
    BuildTimeline(TimelineTarget),
    VerifyEvidenceChain,
    PreserveEvidence,
    GenerateAlert(Option<String>),
    GenerateReport(ReportConfig),
    RunProfile(String),
    EmitCustom {
        kind: String,
        payload_json: String,
    },
    /// Compiled from `if` statements — serialized as JSON
    ConditionalBlock {
        condition_json: String,
        then_instructions: Vec<IrInstruction>,
        else_instructions: Vec<IrInstruction>,
    },
    /// Compiled from `for` loops
    ForLoop {
        variable: String,
        iterable_json: String,
        body: Vec<IrInstruction>,
    },
    /// Variable binding for runtime
    SetVar {
        name: String,
        value_json: String,
    },
}

impl IrProgram {
    pub fn new() -> Self {
        Self {
            case_id: None,
            target: TargetSelector::All,
            profiles: Vec::new(),
            rules: Vec::new(),
            instructions: Vec::new(),
        }
    }

    pub fn push(&mut self, inst: IrInstruction) {
        if let IrInstruction::SetCase(ref id) = inst {
            self.case_id = Some(id.clone());
        }
        if let IrInstruction::SetTarget(ref t) = inst {
            self.target = t.clone();
        }
        self.instructions.push(inst);
    }
}

impl Default for IrProgram {
    fn default() -> Self { Self::new() }
}
