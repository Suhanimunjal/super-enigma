use serde::{Deserialize, Serialize};

/// Root AST node for a JOCKY script
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Program {
    pub statements: Vec<Statement>,
}

/// Top-level JOCKY language statements
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Statement {
    /// `case "INC-001"`
    Case(String),
    /// `target all` / `target "WIN-001"`
    Target(TargetSelector),
    /// `collect { system processes ... }`
    Collect(Vec<CollectionTarget>),
    /// `analyze { suspicious_processes ... }`
    Analyze(Vec<AnalysisTarget>),
    /// `timeline { processes network ... }`
    Timeline(Vec<TimelineTarget>),
    /// `verify evidence`
    VerifyEvidence,
    /// `report html "output.html"`
    Report(ReportConfig),
    /// `investigation { ... }` — structured investigation block
    Investigation(InvestigationBlock),
    /// `profile "name" { ... }` — reusable investigation profile definition
    ProfileDef(ProfileDefinition),
    /// `run profile "name"` — execute a defined profile
    RunProfile(String),
    /// `rule name { when ... severity ... message ... }`
    RuleDef(RuleDefinition),
    /// `let name = value`
    Let { name: String, value: Expression },
    /// `if condition { ... } else { ... }`
    If {
        condition: Expression,
        then_block: Vec<Statement>,
        else_block: Option<Vec<Statement>>,
    },
    /// `for var in expr { ... }`
    For {
        variable: String,
        iterable: Expression,
        body: Vec<Statement>,
    },
    /// `preserve evidence`
    PreserveEvidence,
    /// `generate alert`
    GenerateAlert(Option<String>),
    /// Emit / debug
    Emit(Expression),
    /// Raw expression used as statement
    Expr(Expression),
}

/// Structured investigation block
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InvestigationBlock {
    pub collect: Vec<CollectionTarget>,
    pub analyze: Vec<AnalysisTarget>,
    pub timeline: Vec<TimelineTarget>,
    pub verify: bool,
}

/// Reusable profile definition
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProfileDefinition {
    pub name: String,
    pub collect: Vec<CollectionTarget>,
    pub analyze: Vec<AnalysisTarget>,
}

/// Detection rule definition
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleDefinition {
    pub name: String,
    pub when: Vec<Condition>,
    pub severity: Severity,
    pub message: String,
}

/// A single condition in a rule's `when` clause
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Condition {
    pub field: String,
    pub op: CompareOp,
    pub value: Expression,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CompareOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Contains,
    StartsWith,
    EndsWith,
}

/// Severity levels (matches detection crate)
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TargetSelector {
    All,
    Host(String),
    Group(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CollectionTarget {
    System,
    Processes,
    Users,
    Services,
    Network,
    Filesystem,
    EventLogs,
    StartupItems,
    Modules,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AnalysisTarget {
    SuspiciousProcesses,
    SuspiciousNetwork,
    Persistence,
    UnsignedBinaries,
    FilelessProcesses,
    VulnerableDrivers,
    SuspiciousFiles,
    IocMatch(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TimelineTarget {
    All,
    Processes,
    Files,
    Network,
    Logs,
    Events,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReportConfig {
    pub format: ReportFormat,
    pub output_path: Option<String>,
    pub sections: Vec<ReportSection>,
}

impl ReportConfig {
    pub fn with_defaults(format: ReportFormat, output_path: Option<String>) -> Self {
        Self {
            format,
            output_path,
            sections: ReportSection::all(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ReportSection {
    ExecutiveSummary,
    Scope,
    SystemsAnalyzed,
    EvidenceCollected,
    Findings,
    Timeline,
    NetworkAnalysis,
    ProcessAnalysis,
    PersistenceAnalysis,
    EvidenceIntegrity,
    ChainOfCustody,
    Appendix,
}

impl ReportSection {
    pub fn all() -> Vec<Self> {
        vec![
            Self::ExecutiveSummary,
            Self::Scope,
            Self::SystemsAnalyzed,
            Self::EvidenceCollected,
            Self::Findings,
            Self::Timeline,
            Self::NetworkAnalysis,
            Self::ProcessAnalysis,
            Self::PersistenceAnalysis,
            Self::EvidenceIntegrity,
            Self::ChainOfCustody,
            Self::Appendix,
        ]
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ReportFormat {
    Html,
    Pdf,
    Json,
    Markdown,
}

/// JOCKY expression language
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Expression {
    StringLit(String),
    IntLit(i64),
    FloatLit(f64),
    BoolLit(bool),
    Null,
    Identifier(String),
    FieldAccess { object: Box<Expression>, field: String },
    Index { object: Box<Expression>, index: Box<Expression> },
    BinaryOp { lhs: Box<Expression>, op: BinOp, rhs: Box<Expression> },
    Not(Box<Expression>),
    List(Vec<Expression>),
    Map(Vec<(String, Expression)>),
    Call { callee: String, arguments: Vec<Expression> },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BinOp {
    Add, Sub, Mul, Div,
    And, Or,
    Eq, Ne, Lt, Le, Gt, Ge,
    Contains, StartsWith, EndsWith,
}
