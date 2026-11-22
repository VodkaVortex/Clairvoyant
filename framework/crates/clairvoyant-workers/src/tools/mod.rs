//! Binary exploitation tool adapters.
//!
//! Each tool wraps a CLI binary (checksec, objdump, strings, ROPgadget, etc.)
//! and produces structured [`WorkerEvent`] facts from its output.
//!
//! Tools are composed into a [`ToolWorker`] (see [`crate::ToolWorker`]) which
//! implements the [`crate::Worker`] trait and can be used as a `kind: tool`
//! worker in the dispatcher configuration.

use crate::{WorkerError, WorkerEvent};
use async_trait::async_trait;
use std::path::Path;
use tokio::process::Command;

pub mod checksec;
pub mod objdump;
pub mod readelf;
pub mod ropgadget;
pub mod strings;

/// Error type for tool execution failures.
#[derive(Debug, thiserror::Error)]
pub enum ToolError {
    #[error("tool '{tool}': required binary '{binary}' not found on PATH")]
    MissingBinary { tool: String, binary: String },
    #[error("tool '{tool}': {message}")]
    Failed { tool: String, message: String },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("UTF-8 error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
}

impl From<ToolError> for WorkerError {
    fn from(error: ToolError) -> Self {
        WorkerError::Failed(error.to_string())
    }
}

/// A binary exploitation analysis tool.
///
/// Each implementation wraps a specific CLI tool, runs it against a target
/// binary, parses its output, and returns structured [`WorkerEvent`] facts.
#[async_trait]
pub trait Tool: Send + Sync {
    /// Unique name for this tool (e.g., "checksec", "ropgadget").
    fn name(&self) -> &str;

    /// Human-readable description of what this tool discovers.
    fn description(&self) -> &str;

    /// CLI binary names that must be available on PATH.
    fn required_binaries(&self) -> Vec<&str>;

    /// Run the tool against a target file and return worker events.
    async fn run(&self, target: &Path) -> Result<Vec<WorkerEvent>, ToolError>;
}

/// Result summary from a tool run, used for building fact descriptions.
#[derive(Debug, Clone)]
pub struct ToolFindings {
    pub tool: String,
    pub target: String,
    pub findings: Vec<Finding>,
}

/// A single finding from a tool run.
#[derive(Debug, Clone)]
pub struct Finding {
    /// Category (e.g., "mitigation", "section", "symbol", "gadget")
    pub category: String,
    /// Human-readable description
    pub description: String,
    /// Severity or importance: "info", "low", "medium", "high", "critical"
    pub severity: String,
}

impl ToolFindings {
    pub fn new(tool: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            tool: tool.into(),
            target: target.into(),
            findings: Vec::new(),
        }
    }

    pub fn add(
        &mut self,
        category: impl Into<String>,
        description: impl Into<String>,
        severity: impl Into<String>,
    ) {
        self.findings.push(Finding {
            category: category.into(),
            description: description.into(),
            severity: severity.into(),
        });
    }

    /// Convert all findings into a single WorkerEvent::Done fact.
    pub fn to_done_event(&self) -> WorkerEvent {
        if self.findings.is_empty() {
            return WorkerEvent::Done {
                description: format!(
                    "{} analysis of {}: no significant findings",
                    self.tool, self.target
                ),
                complete: false,
            };
        }

        let mut parts: Vec<String> = Vec::new();
        parts.push(format!("{} analysis of {}:", self.tool, self.target));

        // Group findings by category
        let mut categories: std::collections::BTreeMap<&str, Vec<&Finding>> =
            std::collections::BTreeMap::new();
        for finding in &self.findings {
            categories
                .entry(finding.category.as_str())
                .or_default()
                .push(finding);
        }

        for (category, findings) in &categories {
            let items: Vec<String> = findings
                .iter()
                .map(|f| format!("[{}] {}", f.severity.to_uppercase(), f.description))
                .collect();
            parts.push(format!("  {}: {}", category, items.join("; ")));
        }

        WorkerEvent::Done {
            description: parts.join("\n"),
            complete: false,
        }
    }

    /// Convert findings into multiple WorkerEvent::Done facts, one per category.
    pub fn to_done_events(&self) -> Vec<WorkerEvent> {
        if self.findings.is_empty() {
            return vec![self.to_done_event()];
        }

        let mut categories: std::collections::BTreeMap<&str, Vec<&Finding>> =
            std::collections::BTreeMap::new();
        for finding in &self.findings {
            categories
                .entry(finding.category.as_str())
                .or_default()
                .push(finding);
        }

        categories
            .into_iter()
            .map(|(category, findings)| {
                let items: Vec<String> =
                    findings.iter().map(|f| f.description.to_string()).collect();
                WorkerEvent::Done {
                    description: format!(
                        "{}: {} analysis of {} → {}",
                        category,
                        self.tool,
                        self.target,
                        items.join("; ")
                    ),
                    complete: false,
                }
            })
            .collect()
    }
}

// --- Helper functions for running CLI tools ---

/// Run a command and return its stdout as a string.
pub(crate) async fn run_command(program: &str, args: &[&str]) -> Result<String, ToolError> {
    let output = Command::new(program)
        .args(args)
        .kill_on_drop(true)
        .output()
        .await
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ToolError::MissingBinary {
                    tool: program.to_string(),
                    binary: program.to_string(),
                }
            } else {
                ToolError::Io(e)
            }
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ToolError::Failed {
            tool: program.to_string(),
            message: format!(
                "{} exited with {}: {}",
                program,
                output.status,
                stderr.trim()
            ),
        });
    }

    Ok(String::from_utf8(output.stdout)?)
}

/// Check if a binary exists on PATH.
pub(crate) async fn check_binary(binary: &str) -> bool {
    Command::new("which")
        .arg(binary)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Try multiple command alternatives, returning the first successful result.
pub(crate) async fn try_commands(
    tool_name: &str,
    alternatives: &[(&str, Vec<&str>)],
) -> Result<String, ToolError> {
    let mut errors = Vec::new();
    for (program, args) in alternatives {
        match run_command(program, args).await {
            Ok(output) => return Ok(output),
            Err(ToolError::MissingBinary { .. }) => {
                errors.push(format!("{}: not found", program));
            }
            Err(e) => {
                errors.push(format!("{}: {}", program, e));
            }
        }
    }
    Err(ToolError::Failed {
        tool: tool_name.to_string(),
        message: format!("all alternatives failed: {}", errors.join("; ")),
    })
}
