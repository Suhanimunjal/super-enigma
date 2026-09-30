use thiserror::Error;
use jocky_ast::*;
use jocky_lexer::{Token, TokenKind};

#[derive(Error, Debug)]
pub enum ParserError {
    #[error("Unexpected end of file while parsing {0}")]
    UnexpectedEof(String),
    #[error("Unexpected token {0:?} at line {1}, column {2} (expected {3})")]
    UnexpectedToken(TokenKind, usize, usize, String),
    #[error("Unknown collection target '{0}' at line {1}, column {2}")]
    UnknownCollectionTarget(String, usize, usize),
    #[error("Unknown analysis target '{0}' at line {1}, column {2}")]
    UnknownAnalysisTarget(String, usize, usize),
}

pub struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    pub fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, pos: 0 }
    }

    fn peek(&self) -> &Token {
        if self.pos < self.tokens.len() {
            &self.tokens[self.pos]
        } else {
            self.tokens.last().expect("Token stream is empty")
        }
    }

    fn advance(&mut self) -> Token {
        let tok = self.peek().clone();
        if self.pos < self.tokens.len() {
            self.pos += 1;
        }
        tok
    }

    fn match_kind(&mut self, kind: TokenKind) -> bool {
        if self.peek().kind == kind {
            self.advance();
            true
        } else {
            false
        }
    }

    fn expect(&mut self, kind: TokenKind, context: &str) -> Result<Token, ParserError> {
        let tok = self.advance();
        if tok.kind == kind {
            Ok(tok)
        } else {
            Err(ParserError::UnexpectedToken(
                tok.kind,
                tok.line,
                tok.column,
                format!("{kind:?} in {context}"),
            ))
        }
    }

    fn peek_ident(&self) -> Option<&str> {
        if let TokenKind::Ident(ref s) = self.peek().kind {
            Some(s.as_str())
        } else {
            None
        }
    }

    pub fn parse_program(&mut self) -> Result<Program, ParserError> {
        let mut statements = Vec::new();
        while self.peek().kind != TokenKind::Eof {
            while self.match_kind(TokenKind::Semi) {} // skip stray semicolons
            if self.peek().kind == TokenKind::Eof { break; }
            statements.push(self.parse_statement()?);
        }
        Ok(Program { statements })
    }

    fn parse_block(&mut self) -> Result<Vec<Statement>, ParserError> {
        self.expect(TokenKind::OpenBrace, "block")?;
        let mut stmts = Vec::new();
        while self.peek().kind != TokenKind::CloseBrace && self.peek().kind != TokenKind::Eof {
            while self.match_kind(TokenKind::Semi) {}
            if self.peek().kind == TokenKind::CloseBrace { break; }
            stmts.push(self.parse_statement()?);
        }
        self.expect(TokenKind::CloseBrace, "closing brace for block")?;
        Ok(stmts)
    }

    fn parse_statement(&mut self) -> Result<Statement, ParserError> {
        match self.peek().kind.clone() {
            // ── Core forensic statements ───────────────────────────────────
            TokenKind::Case => {
                self.advance();
                let name = match self.advance() {
                    Token { kind: TokenKind::StringLit(s), .. } => s,
                    Token { kind: TokenKind::Ident(s), .. } => s,
                    tok => return Err(ParserError::UnexpectedToken(tok.kind, tok.line, tok.column, "case identifier".into())),
                };
                self.match_kind(TokenKind::Semi);
                Ok(Statement::Case(name))
            }
            TokenKind::Target => {
                self.advance();
                let selector = match self.peek().kind.clone() {
                    TokenKind::All => { self.advance(); TargetSelector::All }
                    TokenKind::StringLit(s) | TokenKind::Ident(s) => { self.advance(); TargetSelector::Host(s) }
                    ref tok => return Err(ParserError::UnexpectedToken(
                        tok.clone(), self.peek().line, self.peek().column,
                        "target specification ('all' or host name)".into(),
                    )),
                };
                self.match_kind(TokenKind::Semi);
                Ok(Statement::Target(selector))
            }
            TokenKind::Collect => {
                self.advance();
                let targets = self.parse_collection_block()?;
                self.match_kind(TokenKind::Semi);
                Ok(Statement::Collect(targets))
            }
            TokenKind::Analyze => {
                self.advance();
                let targets = self.parse_analysis_block()?;
                self.match_kind(TokenKind::Semi);
                Ok(Statement::Analyze(targets))
            }
            TokenKind::Timeline => {
                self.advance();
                let targets = self.parse_timeline_items()?;
                self.match_kind(TokenKind::Semi);
                Ok(Statement::Timeline(targets))
            }
            TokenKind::Verify => {
                self.advance();
                self.match_kind(TokenKind::Evidence);
                self.match_kind(TokenKind::Semi);
                Ok(Statement::VerifyEvidence)
            }
            TokenKind::Report => {
                self.advance();
                if self.peek().kind == TokenKind::OpenBrace {
                    let config = self.parse_report_block()?;
                    return Ok(Statement::Report(config));
                }
                let format = match self.peek().kind {
                    TokenKind::Html     => { self.advance(); ReportFormat::Html }
                    TokenKind::Pdf      => { self.advance(); ReportFormat::Pdf }
                    TokenKind::Json     => { self.advance(); ReportFormat::Json }
                    TokenKind::Markdown => { self.advance(); ReportFormat::Markdown }
                    _ => ReportFormat::Html,
                };
                let output_path = if let TokenKind::StringLit(ref s) = self.peek().kind.clone() {
                    let p = s.clone(); self.advance(); Some(p)
                } else { None };
                self.match_kind(TokenKind::Semi);
                Ok(Statement::Report(ReportConfig::with_defaults(format, output_path)))
            }

            // ── JOCKY 2.1 structured blocks ────────────────────────────────
            TokenKind::Investigation => {
                self.advance();
                let block = self.parse_investigation_block()?;
                Ok(Statement::Investigation(block))
            }
            TokenKind::Profile => {
                self.advance();
                let name = match self.advance() {
                    Token { kind: TokenKind::StringLit(s), .. } => s,
                    Token { kind: TokenKind::Ident(s), .. } => s,
                    tok => return Err(ParserError::UnexpectedToken(tok.kind, tok.line, tok.column, "profile name".into())),
                };
                if self.peek().kind == TokenKind::OpenBrace {
                    self.advance();
                    let mut col = Vec::new();
                    let mut ana = Vec::new();
                    while self.peek().kind != TokenKind::CloseBrace && self.peek().kind != TokenKind::Eof {
                        match self.peek().kind.clone() {
                            TokenKind::Collect => { self.advance(); col = self.parse_collection_block()?; }
                            TokenKind::Analyze => { self.advance(); ana = self.parse_analysis_block()?; }
                            _ => { self.advance(); }
                        }
                        self.match_kind(TokenKind::Semi);
                    }
                    self.expect(TokenKind::CloseBrace, "closing brace for profile")?;
                    Ok(Statement::ProfileDef(ProfileDefinition { name, collect: col, analyze: ana }))
                } else {
                    Ok(Statement::ProfileDef(ProfileDefinition { name, collect: vec![], analyze: vec![] }))
                }
            }
            TokenKind::Run => {
                self.advance();
                // `run profile "name"`
                if self.peek().kind == TokenKind::Profile {
                    self.advance();
                    let name = match self.advance() {
                        Token { kind: TokenKind::StringLit(s), .. } => s,
                        Token { kind: TokenKind::Ident(s), .. } => s,
                        tok => return Err(ParserError::UnexpectedToken(tok.kind, tok.line, tok.column, "profile name".into())),
                    };
                    self.match_kind(TokenKind::Semi);
                    Ok(Statement::RunProfile(name))
                } else {
                    Err(ParserError::UnexpectedEof("run target (expected 'profile')".into()))
                }
            }
            TokenKind::Rule => {
                self.advance();
                let name = match self.advance() {
                    Token { kind: TokenKind::Ident(s), .. } => s,
                    tok => return Err(ParserError::UnexpectedToken(tok.kind, tok.line, tok.column, "rule name".into())),
                };
                let rule_def = self.parse_rule_block(name)?;
                Ok(Statement::RuleDef(rule_def))
            }

            // ── Variables & control flow ────────────────────────────────────
            TokenKind::Let => {
                self.advance();
                let name = match self.advance() {
                    Token { kind: TokenKind::Ident(s), .. } => s,
                    tok => return Err(ParserError::UnexpectedToken(tok.kind, tok.line, tok.column, "variable name".into())),
                };
                self.match_kind(TokenKind::Assign); // consume '='
                let value = self.parse_expression()?;
                self.match_kind(TokenKind::Semi);
                Ok(Statement::Let { name, value })
            }
            TokenKind::If => {
                self.advance();
                let condition = self.parse_expression()?;
                let then_block = self.parse_block()?;
                let else_block = if self.peek().kind == TokenKind::Else {
                    self.advance();
                    Some(self.parse_block()?)
                } else { None };
                Ok(Statement::If { condition, then_block, else_block })
            }
            TokenKind::For => {
                self.advance();
                let variable = match self.advance() {
                    Token { kind: TokenKind::Ident(s), .. } => s,
                    tok => return Err(ParserError::UnexpectedToken(tok.kind, tok.line, tok.column, "loop variable".into())),
                };
                self.match_kind(TokenKind::In); // consume 'in'
                let iterable = self.parse_expression()?;
                let body = self.parse_block()?;
                Ok(Statement::For { variable, iterable, body })
            }
            TokenKind::Preserve => {
                self.advance();
                self.match_kind(TokenKind::Evidence);
                self.match_kind(TokenKind::Semi);
                Ok(Statement::PreserveEvidence)
            }
            TokenKind::Generate => {
                self.advance();
                let kind = if self.peek().kind == TokenKind::Alert {
                    self.advance();
                    Some("alert".to_string())
                } else if let Some(k) = self.peek_ident() {
                    let k = k.to_string(); self.advance(); Some(k)
                } else { None };
                self.match_kind(TokenKind::Semi);
                Ok(Statement::GenerateAlert(kind))
            }

            // ── Fallthrough: try as expression statement ────────────────────
            _ => {
                let tok = self.advance();
                Err(ParserError::UnexpectedToken(
                    tok.kind, tok.line, tok.column,
                    "valid JOCKY 2.1 statement (case, target, collect, analyze, timeline, verify, report, investigation, profile, run, rule, let, if, for, preserve, generate)".into(),
                ))
            }
        }
    }

    // ── Helper parsers ─────────────────────────────────────────────────────

    fn parse_collection_block(&mut self) -> Result<Vec<CollectionTarget>, ParserError> {
        if self.match_kind(TokenKind::OpenBrace) {
            let mut list = Vec::new();
            while self.peek().kind != TokenKind::CloseBrace && self.peek().kind != TokenKind::Eof {
                list.push(self.parse_collection_target()?);
                self.match_kind(TokenKind::Comma);
                self.match_kind(TokenKind::Semi);
            }
            self.expect(TokenKind::CloseBrace, "closing brace for collect block")?;
            Ok(list)
        } else {
            Ok(vec![self.parse_collection_target()?])
        }
    }

    fn parse_analysis_block(&mut self) -> Result<Vec<AnalysisTarget>, ParserError> {
        if self.match_kind(TokenKind::OpenBrace) {
            let mut list = Vec::new();
            while self.peek().kind != TokenKind::CloseBrace && self.peek().kind != TokenKind::Eof {
                list.push(self.parse_analysis_target()?);
                self.match_kind(TokenKind::Comma);
                self.match_kind(TokenKind::Semi);
            }
            self.expect(TokenKind::CloseBrace, "closing brace for analyze block")?;
            Ok(list)
        } else {
            Ok(vec![self.parse_analysis_target()?])
        }
    }

    fn parse_timeline_items(&mut self) -> Result<Vec<TimelineTarget>, ParserError> {
        let mut targets = Vec::new();
        if self.match_kind(TokenKind::OpenBrace) {
            while self.peek().kind != TokenKind::CloseBrace && self.peek().kind != TokenKind::Eof {
                if let TokenKind::Ident(ref name) = self.peek().kind.clone() {
                    targets.push(match name.as_str() {
                        "processes"             => TimelineTarget::Processes,
                        "files" | "filesystem"  => TimelineTarget::Files,
                        "network"               => TimelineTarget::Network,
                        "logs"                  => TimelineTarget::Logs,
                        "events"                => TimelineTarget::Events,
                        _                       => TimelineTarget::All,
                    });
                }
                self.advance();
                self.match_kind(TokenKind::Comma);
                self.match_kind(TokenKind::Semi);
            }
            self.expect(TokenKind::CloseBrace, "closing brace for timeline block")?;
        } else {
            targets.push(TimelineTarget::All);
        }
        Ok(targets)
    }

    fn parse_investigation_block(&mut self) -> Result<InvestigationBlock, ParserError> {
        self.expect(TokenKind::OpenBrace, "investigation block")?;
        let mut collect  = Vec::new();
        let mut analyze  = Vec::new();
        let mut timeline = Vec::new();
        let mut verify   = false;

        while self.peek().kind != TokenKind::CloseBrace && self.peek().kind != TokenKind::Eof {
            match self.peek().kind.clone() {
                TokenKind::Collect  => { self.advance(); collect  = self.parse_collection_block()?; }
                TokenKind::Analyze  => { self.advance(); analyze  = self.parse_analysis_block()?; }
                TokenKind::Timeline => { self.advance(); timeline = self.parse_timeline_items()?; }
                TokenKind::Verify   => { self.advance(); self.match_kind(TokenKind::Evidence); verify = true; }
                _                   => { self.advance(); }
            }
            self.match_kind(TokenKind::Semi);
        }
        self.expect(TokenKind::CloseBrace, "closing brace for investigation block")?;
        Ok(InvestigationBlock { collect, analyze, timeline, verify })
    }

    fn parse_report_block(&mut self) -> Result<ReportConfig, ParserError> {
        self.expect(TokenKind::OpenBrace, "report block")?;
        let mut format      = ReportFormat::Html;
        let mut output_path = None;
        let mut sections    = Vec::new();

        while self.peek().kind != TokenKind::CloseBrace && self.peek().kind != TokenKind::Eof {
            match self.peek().kind.clone() {
                TokenKind::Format => {
                    self.advance();
                    format = match self.peek().kind {
                        TokenKind::Html     => { self.advance(); ReportFormat::Html }
                        TokenKind::Pdf      => { self.advance(); ReportFormat::Pdf }
                        TokenKind::Json     => { self.advance(); ReportFormat::Json }
                        TokenKind::Markdown => { self.advance(); ReportFormat::Markdown }
                        _                   => { self.advance(); ReportFormat::Html }
                    };
                }
                TokenKind::Include => {
                    self.advance();
                    if let TokenKind::Ident(ref sec) = self.peek().kind.clone() {
                        let s = match sec.as_str() {
                            "executive_summary"   => Some(ReportSection::ExecutiveSummary),
                            "findings"            => Some(ReportSection::Findings),
                            "timeline"            => Some(ReportSection::Timeline),
                            "evidence"            => Some(ReportSection::EvidenceCollected),
                            "chain_of_custody"    => Some(ReportSection::ChainOfCustody),
                            "network_analysis"    => Some(ReportSection::NetworkAnalysis),
                            "process_analysis"    => Some(ReportSection::ProcessAnalysis),
                            "persistence_analysis"=> Some(ReportSection::PersistenceAnalysis),
                            "systems"             => Some(ReportSection::SystemsAnalyzed),
                            "integrity"           => Some(ReportSection::EvidenceIntegrity),
                            "scope"               => Some(ReportSection::Scope),
                            "appendix"            => Some(ReportSection::Appendix),
                            _                     => None,
                        };
                        if let Some(sec) = s { sections.push(sec); }
                        self.advance();
                    }
                }
                TokenKind::Ident(ref key) if key == "output" || key == "path" => {
                    self.advance();
                    if let TokenKind::StringLit(ref s) = self.peek().kind.clone() {
                        output_path = Some(s.clone());
                        self.advance();
                    }
                }
                _ => { self.advance(); }
            }
            self.match_kind(TokenKind::Semi);
        }
        self.expect(TokenKind::CloseBrace, "closing brace for report block")?;
        if sections.is_empty() { sections = ReportSection::all(); }
        Ok(ReportConfig { format, output_path, sections })
    }

    fn parse_rule_block(&mut self, name: String) -> Result<RuleDefinition, ParserError> {
        self.expect(TokenKind::OpenBrace, "rule block")?;
        let mut when_conditions = Vec::new();
        let mut severity        = Severity::Medium;
        let mut message         = String::new();

        while self.peek().kind != TokenKind::CloseBrace && self.peek().kind != TokenKind::Eof {
            match self.peek().kind.clone() {
                TokenKind::When => {
                    self.advance();
                    loop {
                        if let TokenKind::Ident(ref field_tok) = self.peek().kind.clone() {
                            let mut field = field_tok.clone();
                            self.advance();
                            // Handle dotted field: process.parent
                            if self.peek().kind == TokenKind::Dot {
                                self.advance();
                                if let TokenKind::Ident(ref sub) = self.peek().kind.clone() {
                                    field = format!("{}.{}", field, sub);
                                    self.advance();
                                }
                            }
                            let op = match self.peek().kind.clone() {
                                TokenKind::Eq         => { self.advance(); CompareOp::Eq }
                                TokenKind::Ne         => { self.advance(); CompareOp::Ne }
                                TokenKind::Lt         => { self.advance(); CompareOp::Lt }
                                TokenKind::Le         => { self.advance(); CompareOp::Le }
                                TokenKind::Gt         => { self.advance(); CompareOp::Gt }
                                TokenKind::Ge         => { self.advance(); CompareOp::Ge }
                                TokenKind::Ident(ref op_word) => {
                                    let o = match op_word.as_str() {
                                        "contains"    => CompareOp::Contains,
                                        "starts_with" => CompareOp::StartsWith,
                                        "ends_with"   => CompareOp::EndsWith,
                                        _             => CompareOp::Eq,
                                    };
                                    self.advance(); o
                                }
                                _ => CompareOp::Eq,
                            };
                            let value = self.parse_expression()?;
                            when_conditions.push(Condition { field, op, value });
                            if self.peek().kind == TokenKind::And { self.advance(); } else { break; }
                        } else { break; }
                    }
                }
                TokenKind::Severity => {
                    self.advance();
                    if let TokenKind::Ident(ref s) = self.peek().kind.clone() {
                        severity = match s.as_str() {
                            "critical" => Severity::Critical,
                            "high"     => Severity::High,
                            "medium"   => Severity::Medium,
                            "low"      => Severity::Low,
                            _          => Severity::Info,
                        };
                        self.advance();
                    }
                }
                TokenKind::Message => {
                    self.advance();
                    if let TokenKind::StringLit(ref s) = self.peek().kind.clone() {
                        message = s.clone();
                        self.advance();
                    }
                }
                _ => { self.advance(); }
            }
            self.match_kind(TokenKind::Semi);
        }
        self.expect(TokenKind::CloseBrace, "closing brace for rule block")?;
        Ok(RuleDefinition { name, when: when_conditions, severity, message })
    }

    fn parse_collection_target(&mut self) -> Result<CollectionTarget, ParserError> {
        let tok = self.advance();
        if let TokenKind::Ident(ref s) = tok.kind {
            match s.as_str() {
                "system"                          => Ok(CollectionTarget::System),
                "processes"                       => Ok(CollectionTarget::Processes),
                "users"                           => Ok(CollectionTarget::Users),
                "services"                        => Ok(CollectionTarget::Services),
                "network" | "network_connections" => Ok(CollectionTarget::Network),
                "filesystem" | "files"            => Ok(CollectionTarget::Filesystem),
                "event_logs" | "logs"             => Ok(CollectionTarget::EventLogs),
                "startup_items" | "startup"       => Ok(CollectionTarget::StartupItems),
                "modules" | "drivers"             => Ok(CollectionTarget::Modules),
                unknown                           => Err(ParserError::UnknownCollectionTarget(unknown.into(), tok.line, tok.column)),
            }
        } else {
            Err(ParserError::UnexpectedToken(tok.kind, tok.line, tok.column, "collection target name".into()))
        }
    }

    fn parse_analysis_target(&mut self) -> Result<AnalysisTarget, ParserError> {
        let tok = self.advance();
        if let TokenKind::Ident(ref s) = tok.kind {
            match s.as_str() {
                "suspicious_processes"                  => Ok(AnalysisTarget::SuspiciousProcesses),
                "suspicious_network"                    => Ok(AnalysisTarget::SuspiciousNetwork),
                "persistence"                           => Ok(AnalysisTarget::Persistence),
                "unsigned_binaries"                     => Ok(AnalysisTarget::UnsignedBinaries),
                "fileless_processes"                    => Ok(AnalysisTarget::FilelessProcesses),
                "vulnerable_drivers"                    => Ok(AnalysisTarget::VulnerableDrivers),
                "suspicious_files"                      => Ok(AnalysisTarget::SuspiciousFiles),
                ioc if ioc.starts_with("ioc:")          => Ok(AnalysisTarget::IocMatch(ioc[4..].to_string())),
                unknown => Err(ParserError::UnknownAnalysisTarget(unknown.into(), tok.line, tok.column)),
            }
        } else {
            Err(ParserError::UnexpectedToken(tok.kind, tok.line, tok.column, "analysis target name".into()))
        }
    }

    fn parse_expression(&mut self) -> Result<Expression, ParserError> {
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Expression, ParserError> {
        match self.peek().kind.clone() {
            TokenKind::StringLit(s) => { self.advance(); Ok(Expression::StringLit(s)) }
            TokenKind::IntLit(n)    => { self.advance(); Ok(Expression::IntLit(n)) }
            TokenKind::FloatLit(f)  => { self.advance(); Ok(Expression::FloatLit(f)) }
            TokenKind::Ident(ref name) => {
                match name.as_str() {
                    "true"  => { self.advance(); Ok(Expression::BoolLit(true)) }
                    "false" => { self.advance(); Ok(Expression::BoolLit(false)) }
                    "null" | "nil" => { self.advance(); Ok(Expression::Null) }
                    "HIGH" | "CRITICAL" | "MEDIUM" | "LOW" | "INFO" => {
                        let s = name.clone(); self.advance(); Ok(Expression::Identifier(s))
                    }
                    _ => {
                        let name = name.clone();
                        self.advance();
                        // Field access via dot
                        let mut expr = Expression::Identifier(name);
                        while self.peek().kind == TokenKind::Dot {
                            self.advance();
                            if let TokenKind::Ident(ref field) = self.peek().kind.clone() {
                                let field = field.clone();
                                self.advance();
                                expr = Expression::FieldAccess { object: Box::new(expr), field };
                            }
                        }
                        // Function call
                        if self.peek().kind == TokenKind::OpenParen {
                            if let Expression::Identifier(callee) = expr {
                                self.advance();
                                let mut args = Vec::new();
                                while self.peek().kind != TokenKind::CloseParen && self.peek().kind != TokenKind::Eof {
                                    args.push(self.parse_expression()?);
                                    self.match_kind(TokenKind::Comma);
                                }
                                self.expect(TokenKind::CloseParen, "function call args")?;
                                return Ok(Expression::Call { callee, arguments: args });
                            }
                        }
                        Ok(expr)
                    }
                }
            }
            TokenKind::OpenBracket => {
                self.advance();
                let mut items = Vec::new();
                while self.peek().kind != TokenKind::CloseBracket && self.peek().kind != TokenKind::Eof {
                    items.push(self.parse_expression()?);
                    self.match_kind(TokenKind::Comma);
                }
                self.expect(TokenKind::CloseBracket, "list literal")?;
                Ok(Expression::List(items))
            }
            _ => Ok(Expression::Null),
        }
    }
}

pub fn parse(source: &str) -> Result<Program, Box<dyn std::error::Error>> {
    let lexer = jocky_lexer::Lexer::new(source);
    let tokens = lexer.tokenize()?;
    let mut parser = Parser::new(tokens);
    let program = parser.parse_program()?;
    Ok(program)
}
