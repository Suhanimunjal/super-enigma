use thiserror::Error;
use jocky_ast::*;
use jocky_ir::*;

#[derive(Error, Debug)]
pub enum CompilerError {
    #[error("Compilation error: {0}")]
    General(String),
    #[error("Semantic error: {0}")]
    Semantic(String),
}

pub struct Compiler;

impl Default for Compiler {
    fn default() -> Self { Self::new() }
}

impl Compiler {
    pub fn new() -> Self {
        Self
    }

    pub fn compile(&self, program: &Program) -> Result<IrProgram, CompilerError> {
        let mut ir = IrProgram::new();

        for stmt in &program.statements {
            self.compile_statement(stmt, &mut ir)?;
        }

        Ok(ir)
    }

    fn compile_statement(&self, stmt: &Statement, ir: &mut IrProgram) -> Result<(), CompilerError> {
        match stmt {
            Statement::Case(ref id) => {
                ir.push(IrInstruction::SetCase(id.clone()));
            }
            Statement::Target(ref t) => {
                ir.push(IrInstruction::SetTarget(t.clone()));
            }
            Statement::Collect(ref targets) => {
                for target in targets {
                    ir.push(IrInstruction::Collect(target.clone()));
                }
            }
            Statement::Analyze(ref targets) => {
                for target in targets {
                    ir.push(IrInstruction::Analyze(target.clone()));
                }
            }
            Statement::Timeline(ref targets) => {
                for target in targets {
                    ir.push(IrInstruction::BuildTimeline(target.clone()));
                }
            }
            Statement::VerifyEvidence => {
                ir.push(IrInstruction::VerifyEvidenceChain);
            }
            Statement::PreserveEvidence => {
                ir.push(IrInstruction::PreserveEvidence);
            }
            Statement::GenerateAlert(ref kind) => {
                ir.push(IrInstruction::GenerateAlert(kind.clone()));
            }
            Statement::Report(ref cfg) => {
                ir.push(IrInstruction::GenerateReport(cfg.clone()));
            }
            Statement::Investigation(ref block) => {
                // Expand investigation block into flat IR instructions
                for target in &block.collect {
                    ir.push(IrInstruction::Collect(target.clone()));
                }
                for target in &block.analyze {
                    ir.push(IrInstruction::Analyze(target.clone()));
                }
                for target in &block.timeline {
                    ir.push(IrInstruction::BuildTimeline(target.clone()));
                }
                if block.verify {
                    ir.push(IrInstruction::VerifyEvidenceChain);
                }
            }
            Statement::ProfileDef(ref def) => {
                // Store profile definitions in the IR program for runtime lookup
                ir.profiles.push(def.clone());
            }
            Statement::RunProfile(ref name) => {
                ir.push(IrInstruction::RunProfile(name.clone()));
            }
            Statement::RuleDef(ref rule) => {
                // Store rule definitions in the IR program
                ir.rules.push(rule.clone());
            }
            Statement::Let { name, value } => {
                let value_json = serde_json::to_string(value)
                    .map_err(|e| CompilerError::General(e.to_string()))?;
                ir.push(IrInstruction::SetVar {
                    name: name.clone(),
                    value_json,
                });
            }
            Statement::If { condition, then_block, else_block } => {
                let condition_json = serde_json::to_string(condition)
                    .map_err(|e| CompilerError::General(e.to_string()))?;

                let mut then_ir = IrProgram::new();
                for s in then_block {
                    self.compile_statement(s, &mut then_ir)?;
                }

                let mut else_ir = IrProgram::new();
                if let Some(else_stmts) = else_block {
                    for s in else_stmts {
                        self.compile_statement(s, &mut else_ir)?;
                    }
                }

                ir.push(IrInstruction::ConditionalBlock {
                    condition_json,
                    then_instructions: then_ir.instructions,
                    else_instructions: else_ir.instructions,
                });
            }
            Statement::For { variable, iterable, body } => {
                let iterable_json = serde_json::to_string(iterable)
                    .map_err(|e| CompilerError::General(e.to_string()))?;

                let mut body_ir = IrProgram::new();
                for s in body {
                    self.compile_statement(s, &mut body_ir)?;
                }

                ir.push(IrInstruction::ForLoop {
                    variable: variable.clone(),
                    iterable_json,
                    body: body_ir.instructions,
                });
            }
            Statement::Emit(ref expr) => {
                let payload = serde_json::to_string(expr)
                    .map_err(|e| CompilerError::General(e.to_string()))?;
                ir.push(IrInstruction::EmitCustom {
                    kind: "emit".into(),
                    payload_json: payload,
                });
            }
            Statement::Expr(ref expr) => {
                let payload = serde_json::to_string(expr)
                    .map_err(|e| CompilerError::General(e.to_string()))?;
                ir.push(IrInstruction::EmitCustom {
                    kind: "expr".into(),
                    payload_json: payload,
                });
            }
        }
        Ok(())
    }

    /// Emit the IR program as human-readable JOCKY IR text for debugging
    pub fn dump_ir(ir: &IrProgram) -> String {
        let mut out = String::new();
        out.push_str(&format!("// JOCKY IR v2.1 — Case: {:?}\n", ir.case_id));
        out.push_str(&format!("// Profiles defined: {}\n", ir.profiles.len()));
        out.push_str(&format!("// Detection rules: {}\n\n", ir.rules.len()));
        for (i, inst) in ir.instructions.iter().enumerate() {
            out.push_str(&format!("{:04}: {:?}\n", i, inst));
        }
        out
    }
}

pub fn compile_source(source: &str) -> Result<IrProgram, Box<dyn std::error::Error>> {
    let program = jocky_parser::parse(source)?;
    let compiler = Compiler::new();
    let ir = compiler.compile(&program)?;
    Ok(ir)
}

pub fn dump_ir(source: &str) -> Result<String, Box<dyn std::error::Error>> {
    let ir = compile_source(source)?;
    Ok(Compiler::dump_ir(&ir))
}
