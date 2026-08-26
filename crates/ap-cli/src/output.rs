use std::io::Write as _;

/// How the result is written out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    /// Lines meant for a person, in the chosen language.
    Text,
    /// One JSON document, for another program.
    Json,
}

/// What a command produced.
#[derive(Debug, Clone, PartialEq)]
pub enum Rendered {
    /// Lines already rendered from the catalogue.
    Text(Vec<String>),
    /// A document to print as JSON.
    Json(serde_json::Value),
    /// Nothing to say.
    Silent,
}

impl Rendered {
    /// One line of text.
    pub fn line(text: String) -> Self {
        Self::Text(vec![text])
    }
}

/// Writes the result to standard output.
pub fn emit(rendered: &Rendered) {
    let mut out = std::io::stdout().lock();
    match rendered {
        Rendered::Text(lines) => {
            for line in lines {
                let _ = writeln!(out, "{line}");
            }
        }
        Rendered::Json(value) => {
            let _ = writeln!(out, "{value:#}");
        }
        Rendered::Silent => {}
    }
}

/// Writes a refusal to standard error.
pub fn fail(message: &str) {
    let mut err = std::io::stderr().lock();
    let _ = writeln!(err, "{message}");
}
