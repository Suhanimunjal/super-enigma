use thiserror::Error;

/// All tokens in the JOCKY 2.1 language
#[derive(Debug, Clone, PartialEq)]
pub enum TokenKind {
    // ── Core forensic keywords ──────────────────────────────────────
    Case,
    Target,
    Collect,
    Analyze,
    Timeline,
    Verify,
    Evidence,
    Report,
    All,

    // ── Report format keywords ───────────────────────────────────────
    Html,
    Pdf,
    Json,
    Markdown,

    // ── JOCKY 2.1 structured keywords ───────────────────────────────
    Investigation,
    Profile,
    Run,
    Rule,
    When,
    Severity,
    Message,
    Format,
    Include,
    Preserve,
    Generate,
    Alert,
    Let,
    If,
    Else,
    For,
    In,
    And,
    Or,
    Not,

    // ── Operators ───────────────────────────────────────────────────
    Eq,       // ==
    Ne,       // !=
    Lt,       // <
    Le,       // <=
    Gt,       // >
    Ge,       // >=
    Assign,   // =
    Dot,      // .

    // ── Literals ────────────────────────────────────────────────────
    Ident(String),
    StringLit(String),
    IntLit(i64),
    FloatLit(f64),

    // ── Punctuation ─────────────────────────────────────────────────
    OpenBrace,
    CloseBrace,
    OpenParen,
    CloseParen,
    OpenBracket,
    CloseBracket,
    Comma,
    Colon,
    Semi,
    Eof,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Token {
    pub kind: TokenKind,
    pub line: usize,
    pub column: usize,
}

#[derive(Error, Debug)]
pub enum LexerError {
    #[error("Unterminated string literal at line {0}, column {1}")]
    UnterminatedString(usize, usize),
    #[error("Unexpected character '{0}' at line {1}, column {2}")]
    UnexpectedChar(char, usize, usize),
}

pub struct Lexer<'a> {
    chars: std::iter::Peekable<std::str::CharIndices<'a>>,
    line: usize,
    column: usize,
}

impl<'a> Lexer<'a> {
    pub fn new(source: &'a str) -> Self {
        Self {
            chars: source.char_indices().peekable(),
            line: 1,
            column: 1,
        }
    }

    pub fn tokenize(mut self) -> Result<Vec<Token>, LexerError> {
        let mut tokens = Vec::new();

        while let Some(&(_idx, ch)) = self.chars.peek() {
            match ch {
                ' ' | '\t' | '\r' => {
                    self.chars.next();
                    self.column += 1;
                }
                '\n' => {
                    self.chars.next();
                    self.line += 1;
                    self.column = 1;
                }
                '#' => {
                    // Comment until newline
                    while let Some(&(_, c)) = self.chars.peek() {
                        if c == '\n' { break; }
                        self.chars.next();
                    }
                }
                '/' => {
                    let start_col = self.column;
                    self.chars.next();
                    self.column += 1;
                    if let Some(&(_, '/')) = self.chars.peek() {
                        while let Some(&(_, c)) = self.chars.peek() {
                            if c == '\n' { break; }
                            self.chars.next();
                        }
                    } else {
                        return Err(LexerError::UnexpectedChar('/', self.line, start_col));
                    }
                }
                '{' => { tokens.push(Token { kind: TokenKind::OpenBrace,   line: self.line, column: self.column }); self.chars.next(); self.column += 1; }
                '}' => { tokens.push(Token { kind: TokenKind::CloseBrace,  line: self.line, column: self.column }); self.chars.next(); self.column += 1; }
                '(' => { tokens.push(Token { kind: TokenKind::OpenParen,   line: self.line, column: self.column }); self.chars.next(); self.column += 1; }
                ')' => { tokens.push(Token { kind: TokenKind::CloseParen,  line: self.line, column: self.column }); self.chars.next(); self.column += 1; }
                '[' => { tokens.push(Token { kind: TokenKind::OpenBracket, line: self.line, column: self.column }); self.chars.next(); self.column += 1; }
                ']' => { tokens.push(Token { kind: TokenKind::CloseBracket, line: self.line, column: self.column }); self.chars.next(); self.column += 1; }
                ',' => { tokens.push(Token { kind: TokenKind::Comma, line: self.line, column: self.column }); self.chars.next(); self.column += 1; }
                ':' => { tokens.push(Token { kind: TokenKind::Colon, line: self.line, column: self.column }); self.chars.next(); self.column += 1; }
                ';' => { tokens.push(Token { kind: TokenKind::Semi,  line: self.line, column: self.column }); self.chars.next(); self.column += 1; }
                '.' => { tokens.push(Token { kind: TokenKind::Dot,   line: self.line, column: self.column }); self.chars.next(); self.column += 1; }
                '=' => {
                    let start_col = self.column;
                    self.chars.next(); self.column += 1;
                    if let Some(&(_, '=')) = self.chars.peek() {
                        self.chars.next(); self.column += 1;
                        tokens.push(Token { kind: TokenKind::Eq, line: self.line, column: start_col });
                    } else {
                        tokens.push(Token { kind: TokenKind::Assign, line: self.line, column: start_col });
                    }
                }
                '!' => {
                    let start_col = self.column;
                    self.chars.next(); self.column += 1;
                    if let Some(&(_, '=')) = self.chars.peek() {
                        self.chars.next(); self.column += 1;
                        tokens.push(Token { kind: TokenKind::Ne, line: self.line, column: start_col });
                    } else {
                        tokens.push(Token { kind: TokenKind::Not, line: self.line, column: start_col });
                    }
                }
                '<' => {
                    let start_col = self.column;
                    self.chars.next(); self.column += 1;
                    if let Some(&(_, '=')) = self.chars.peek() {
                        self.chars.next(); self.column += 1;
                        tokens.push(Token { kind: TokenKind::Le, line: self.line, column: start_col });
                    } else {
                        tokens.push(Token { kind: TokenKind::Lt, line: self.line, column: start_col });
                    }
                }
                '>' => {
                    let start_col = self.column;
                    self.chars.next(); self.column += 1;
                    if let Some(&(_, '=')) = self.chars.peek() {
                        self.chars.next(); self.column += 1;
                        tokens.push(Token { kind: TokenKind::Ge, line: self.line, column: start_col });
                    } else {
                        tokens.push(Token { kind: TokenKind::Gt, line: self.line, column: start_col });
                    }
                }
                '"' => {
                    let start_line = self.line;
                    let start_col = self.column;
                    self.chars.next();
                    self.column += 1;
                    let mut text = String::new();
                    let mut terminated = false;
                    while let Some(&(_, c)) = self.chars.peek() {
                        self.chars.next();
                        self.column += 1;
                        if c == '"' { terminated = true; break; }
                        if c == '\\' {
                            if let Some(&(_, esc)) = self.chars.peek() {
                                self.chars.next(); self.column += 1;
                                match esc {
                                    'n' => text.push('\n'),
                                    't' => text.push('\t'),
                                    'r' => text.push('\r'),
                                    '\\' => text.push('\\'),
                                    '"' => text.push('"'),
                                    other => text.push(other),
                                }
                            }
                        } else {
                            text.push(c);
                        }
                    }
                    if !terminated {
                        return Err(LexerError::UnterminatedString(start_line, start_col));
                    }
                    tokens.push(Token { kind: TokenKind::StringLit(text), line: start_line, column: start_col });
                }
                _ if ch.is_alphabetic() || ch == '_' => {
                    let start_col = self.column;
                    let mut ident = String::new();
                    while let Some(&(_, c)) = self.chars.peek() {
                        if c.is_alphanumeric() || c == '_' || c == '-' {
                            ident.push(c);
                            self.chars.next();
                            self.column += 1;
                        } else {
                            break;
                        }
                    }
                    let kind = match ident.as_str() {
                        "case"          => TokenKind::Case,
                        "target"        => TokenKind::Target,
                        "collect"       => TokenKind::Collect,
                        "analyze"       => TokenKind::Analyze,
                        "timeline"      => TokenKind::Timeline,
                        "verify"        => TokenKind::Verify,
                        "evidence"      => TokenKind::Evidence,
                        "report"        => TokenKind::Report,
                        "all"           => TokenKind::All,
                        "html"          => TokenKind::Html,
                        "pdf"           => TokenKind::Pdf,
                        "json"          => TokenKind::Json,
                        "markdown"      => TokenKind::Markdown,
                        "investigation" => TokenKind::Investigation,
                        "profile"       => TokenKind::Profile,
                        "run"           => TokenKind::Run,
                        "rule"          => TokenKind::Rule,
                        "when"          => TokenKind::When,
                        "severity"      => TokenKind::Severity,
                        "message"       => TokenKind::Message,
                        "format"        => TokenKind::Format,
                        "include"       => TokenKind::Include,
                        "preserve"      => TokenKind::Preserve,
                        "generate"      => TokenKind::Generate,
                        "alert"         => TokenKind::Alert,
                        "let"           => TokenKind::Let,
                        "if"            => TokenKind::If,
                        "else"          => TokenKind::Else,
                        "for"           => TokenKind::For,
                        "in"            => TokenKind::In,
                        "and"           => TokenKind::And,
                        "or"            => TokenKind::Or,
                        "not"           => TokenKind::Not,
                        _               => TokenKind::Ident(ident),
                    };
                    tokens.push(Token { kind, line: self.line, column: start_col });
                }
                _ if ch.is_ascii_digit() => {
                    let start_col = self.column;
                    let mut num = 0i64;
                    while let Some(&(_, c)) = self.chars.peek() {
                        if let Some(digit) = c.to_digit(10) {
                            num = num * 10 + (digit as i64);
                            self.chars.next();
                            self.column += 1;
                        } else {
                            break;
                        }
                    }
                    // Check for float
                    if let Some(&(_, '.')) = self.chars.peek() {
                        self.chars.next(); self.column += 1;
                        let mut frac = 0.0f64;
                        let mut place = 0.1f64;
                        while let Some(&(_, c)) = self.chars.peek() {
                            if let Some(digit) = c.to_digit(10) {
                                frac += digit as f64 * place;
                                place *= 0.1;
                                self.chars.next();
                                self.column += 1;
                            } else {
                                break;
                            }
                        }
                        tokens.push(Token { kind: TokenKind::FloatLit(num as f64 + frac), line: self.line, column: start_col });
                    } else {
                        tokens.push(Token { kind: TokenKind::IntLit(num), line: self.line, column: start_col });
                    }
                }
                unexpected => {
                    return Err(LexerError::UnexpectedChar(unexpected, self.line, self.column));
                }
            }
        }

        tokens.push(Token { kind: TokenKind::Eof, line: self.line, column: self.column });
        Ok(tokens)
    }
}
