//! Binary security mitigation checker (checksec).
//!
//! Analyzes a binary for security mitigations:
//! - NX (non-executable stack)
//! - PIE (position-independent executable)
//! - RELRO (full/partial relocation read-only)
//! - Stack Canary
//! - FORTIFY (fortified source)
//! - ASLR support
//! - RPATH/RUNPATH
//! - Symbols (stripped or not)

use super::{run_command, try_commands, Tool, ToolError, ToolFindings};
use crate::WorkerEvent;
use async_trait::async_trait;
use std::path::Path;

/// Security mitigation status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum MitigationStatus {
    Enabled,
    Disabled,
    Partial,
    Unknown,
}

impl MitigationStatus {
    #[allow(dead_code)]
    fn from_checksec_output(value: &str) -> Self {
        let lower = value.trim().to_lowercase();
        if lower.starts_with("full")
            || lower == "yes"
            || lower == "enabled"
            || lower.contains("enabled")
        {
            MitigationStatus::Enabled
        } else if lower.starts_with("partial") {
            MitigationStatus::Partial
        } else if lower.starts_with("no ")
            || lower == "no"
            || lower == "disabled"
            || lower == "none"
            || lower.starts_with("none")
        {
            MitigationStatus::Disabled
        } else {
            MitigationStatus::Unknown
        }
    }

    fn as_severity(&self, mitigation: &str) -> &str {
        match self {
            MitigationStatus::Enabled => "info",
            MitigationStatus::Disabled => match mitigation {
                "Stack Canary" | "NX" | "PIE" => "high",
                "RELRO" => "medium",
                "FORTIFY" => "low",
                _ => "medium",
            },
            MitigationStatus::Partial => "low",
            MitigationStatus::Unknown => "info",
        }
    }
}

/// The checksec tool - checks binary security mitigations.
///
/// Tries the following approaches in order:
/// 1. `checksec --file=<target>` (pwntools)
/// 2. Direct `readelf` parsing
pub struct Checksec {
    /// If true, only use readelf (skips pwntools checksec)
    pub force_readelf: bool,
}

impl Checksec {
    pub fn new() -> Self {
        Self {
            force_readelf: false,
        }
    }

    pub fn with_force_readelf(mut self) -> Self {
        self.force_readelf = true;
        self
    }
}

impl Default for Checksec {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Tool for Checksec {
    fn name(&self) -> &str {
        "checksec"
    }

    fn description(&self) -> &str {
        "Checks binary security mitigations: NX, PIE, RELRO, Stack Canary, FORTIFY, ASLR"
    }

    fn required_binaries(&self) -> Vec<&str> {
        if self.force_readelf {
            vec!["readelf"]
        } else {
            vec!["checksec", "readelf"]
        }
    }

    async fn run(&self, target: &Path) -> Result<Vec<WorkerEvent>, ToolError> {
        let target_str = target.to_string_lossy().to_string();

        if !self.force_readelf {
            // Try pwntools checksec first
            let file_arg = format!("--file={}", target_str);
            match try_commands("checksec", &[("checksec", vec![&file_arg])]).await {
                Ok(output) => {
                    return Ok(parse_checksec_output(&target_str, &output));
                }
                Err(_) => {
                    // Fall through to readelf-based detection
                }
            }
        }

        // Fall back to readelf-based detection
        parse_with_readelf(&target_str, target).await
    }
}

/// Parse the output of `checksec --file=<target>`.
///
/// Handles two formats:
/// 1. Key:value format: `RELRO:    Full RELRO`
/// 2. Table format (legacy checksec): header row + data row
fn parse_checksec_output(target: &str, output: &str) -> Vec<WorkerEvent> {
    let mut findings = ToolFindings::new("checksec", target);
    let lines: Vec<&str> = output
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect();

    if lines.is_empty() {
        findings.add("mitigation", "checksec produced no output", "info");
        return findings.to_done_events();
    }

    // Detect table format: first line contains multiple mitigation headers
    let first_line_lower = lines[0].to_lowercase();
    let is_table_format = lines.len() >= 2
        && (first_line_lower.contains("relro")
            || first_line_lower.contains("stack canary")
            || first_line_lower.contains("nx"))
        && !lines[0].contains(':');

    if is_table_format {
        parse_table_format(&mut findings, &lines);
    } else {
        parse_keyvalue_format(&mut findings, &lines);
    }

    if findings.findings.is_empty() {
        findings.add(
            "mitigation",
            "checksec output received but could not be parsed".to_string(),
            "info",
        );
    }

    findings.to_done_events()
}

/// Parse key:value format like `RELRO:    Full RELRO`
fn parse_keyvalue_format(findings: &mut ToolFindings, lines: &[&str]) {
    for &line in lines {
        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim();
            let value = value.trim();
            add_mitigation_finding(findings, key, value);
        }
    }
}

/// Parse table format with header row and data row
fn parse_table_format(findings: &mut ToolFindings, lines: &[&str]) {
    if lines.len() < 2 {
        return;
    }

    // The first line is the header, second is the data.
    // Common checksec header order (informational):
    // RELRO, STACK CANARY, NX, PIE, RPATH, RUNPATH, Symbols, FORTIFY, Fortified, Fortifiable, FILE
    //
    // Rather than parsing the table layout (which varies), scan for specific
    // patterns in the data row.

    // More robust: scan for specific patterns in the data row
    let data = lines[1].to_lowercase();

    // Detect RELRO
    if data.contains("full relro") {
        findings.add("mitigation", "RELRO: Full RELRO", "info");
    } else if data.contains("partial relro") {
        findings.add("mitigation", "RELRO: Partial RELRO", "low");
    } else if data.contains("no relro") {
        findings.add("mitigation", "RELRO: Disabled", "medium");
    }

    // Detect Stack Canary
    if data.contains("canary found") || data.contains("stack canary") {
        findings.add("mitigation", "Stack Canary: Enabled", "info");
    } else if data.contains("no canary") || data.contains("canary not found") {
        findings.add("mitigation", "Stack Canary: Disabled", "high");
    }

    // Detect NX
    if data.contains("nx enabled") {
        findings.add("mitigation", "NX: Enabled", "info");
    } else if data.contains("nx disabled") {
        findings.add("mitigation", "NX: Disabled", "high");
    }

    // Detect PIE
    if data.contains("pie enabled") {
        findings.add("mitigation", "PIE: Enabled", "info");
    } else if data.contains("dso") || data.contains("pie partial") {
        findings.add("mitigation", "PIE: Partial (DSO)", "low");
    } else if data.contains("no pie") || data.contains("pie disabled") {
        findings.add("mitigation", "PIE: Disabled", "high");
    }

    // Detect RPATH/RUNPATH
    if data.contains("no rpath") {
        findings.add("rpath", "RPATH: not set (safe)", "info");
    } else if data.contains("rpath") {
        findings.add(
            "rpath",
            "RPATH set (potential for library injection)",
            "medium",
        );
    }
    if data.contains("no runpath") {
        findings.add("rpath", "RUNPATH: not set (safe)", "info");
    } else if data.contains("runpath") {
        findings.add("rpath", "RUNPATH set", "low");
    }

    // Detect Symbols
    if data.contains("no symbols") || data.contains("stripped") {
        findings.add("symbols", "Binary is stripped (no debug symbols)", "info");
    }

    // Detect FORTIFY
    if data.contains("yes") && data.contains("fortif") {
        findings.add("mitigation", "FORTIFY: Enabled", "info");
    }
}

/// Add a mitigation finding from a key:value pair.
fn add_mitigation_finding(findings: &mut ToolFindings, key: &str, value: &str) {
    match key {
        "RELRO" => {
            let (status, desc) = if value.contains("Full") || value.contains("full") {
                (
                    MitigationStatus::Enabled,
                    format!("RELRO: Full ({})", value),
                )
            } else if value.contains("Partial") || value.contains("partial") {
                (
                    MitigationStatus::Partial,
                    format!("RELRO: Partial ({})", value),
                )
            } else {
                (
                    MitigationStatus::Disabled,
                    format!("RELRO: Disabled ({})", value),
                )
            };
            findings.add("mitigation", desc, status.as_severity("RELRO"));
        }
        "Stack" | "STACK CANARY" | "Canary" | "Stack Canary" => {
            let status = if value.contains("found")
                || value.contains("enabled")
                || value.contains("yes")
                || value.contains("Enabled")
            {
                MitigationStatus::Enabled
            } else {
                MitigationStatus::Disabled
            };
            let desc = format!("Stack Canary: {}", value);
            findings.add("mitigation", desc, status.as_severity("Stack Canary"));
        }
        "NX" => {
            let status = if value.contains("enabled")
                || value.contains("Enabled")
                || value.contains("yes")
            {
                MitigationStatus::Enabled
            } else {
                MitigationStatus::Disabled
            };
            let desc = format!("NX: {}", value);
            findings.add("mitigation", desc, status.as_severity("NX"));
        }
        "PIE" => {
            let status = if value.contains("enabled")
                || value.contains("Enabled")
                || value.contains("yes")
            {
                MitigationStatus::Enabled
            } else if value.contains("DSO") || value.contains("dso") {
                MitigationStatus::Partial
            } else {
                MitigationStatus::Disabled
            };
            let desc = format!("PIE: {}", value);
            findings.add("mitigation", desc, status.as_severity("PIE"));
        }
        "FORTIFY" | "Fortify" | "Fortified" | "FORTIFY_SOURCE" => {
            let status = if value.contains("enabled")
                || value.contains("Enabled")
                || value.contains("yes")
            {
                MitigationStatus::Enabled
            } else {
                MitigationStatus::Disabled
            };
            let desc = format!("FORTIFY: {}", value);
            findings.add("mitigation", desc, status.as_severity("FORTIFY"));
        }
        "ASLR" => {
            let status = if value.contains("enabled")
                || value.contains("Enabled")
                || value.contains("yes")
            {
                MitigationStatus::Enabled
            } else {
                MitigationStatus::Disabled
            };
            let desc = format!("ASLR: {}", value);
            findings.add("mitigation", desc, status.as_severity("ASLR"));
        }
        "RPATH" | "RUNPATH" => {
            if !value.is_empty() && value != "N/A" && !value.contains("none") {
                findings.add("rpath", format!("{}: {}", key, value), "medium");
            }
        }
        "Symbols" | "SYMBOLS" => {
            let desc = format!("Symbols: {}", value);
            findings.add("symbols", desc, "info");
        }
        _ => {
            // Catch any other mitigation lines
            let lower_key = key.to_lowercase();
            if lower_key.contains("canary")
                || lower_key.contains("nx")
                || lower_key.contains("pie")
                || lower_key.contains("aslr")
                || lower_key.contains("relro")
            {
                findings.add("mitigation", format!("{}: {}", key, value), "info");
            }
        }
    }
}

/// Fall back to `readelf`-based detection when checksec is not available.
async fn parse_with_readelf(
    target: &str,
    _target_path: &Path,
) -> Result<Vec<WorkerEvent>, ToolError> {
    let mut findings = ToolFindings::new("checksec (readelf)", target);

    // 1. Check PIE (executable vs shared object)
    let file_output = run_command("file", &[target]).await?;
    let is_pie = file_output.contains("shared object") || file_output.contains("pie executable");
    let is_executable = file_output.contains("executable");

    if is_pie {
        findings.add(
            "mitigation",
            "PIE: Enabled (position-independent executable)",
            "info",
        );
    } else if is_executable {
        findings.add("mitigation", "PIE: Disabled (non-PIE executable)", "high");
    } else {
        findings.add("mitigation", "PIE: Unknown (not an ELF executable)", "info");
    }

    // 2. Check NX via readelf -l (GNU_STACK flags)
    match run_command("readelf", &["-l", target]).await {
        Ok(output) => {
            // Check if E (execute) flag is set on GNU_STACK
            let nx_disabled = output
                .lines()
                .any(|line| line.contains("GNU_STACK") && line.contains(" E "));

            if nx_disabled {
                findings.add(
                    "mitigation",
                    "NX: Disabled (GNU_STACK has execute permission)",
                    "high",
                );
            } else if output.contains("GNU_STACK") {
                findings.add(
                    "mitigation",
                    "NX: Enabled (GNU_STACK non-executable)",
                    "info",
                );
            } else {
                findings.add("mitigation", "NX: Unknown (no GNU_STACK segment)", "info");
            }
        }
        Err(_) => {
            findings.add(
                "mitigation",
                "NX: Could not determine (readelf -l failed)",
                "info",
            );
        }
    }

    // 3. Check RELRO via readelf -d (BIND_NOW flag)
    match run_command("readelf", &["-d", target]).await {
        Ok(output) => {
            let has_bind_now =
                output.contains("BIND_NOW") || output.contains("FLAGS_1") && output.contains("NOW");
            let has_gnu_relro = output.contains("GNU_RELRO");

            if has_bind_now && has_gnu_relro {
                findings.add("mitigation", "RELRO: Full (BIND_NOW + GNU_RELRO)", "info");
            } else if has_gnu_relro {
                findings.add(
                    "mitigation",
                    "RELRO: Partial (GNU_RELRO without BIND_NOW)",
                    "low",
                );
            } else {
                findings.add(
                    "mitigation",
                    "RELRO: Disabled (no GNU_RELRO segment)",
                    "medium",
                );
            }
        }
        Err(_) => {
            findings.add(
                "mitigation",
                "RELRO: Could not determine (readelf -d failed)",
                "info",
            );
        }
    }

    // 4. Check Stack Canary via readelf -s (__stack_chk_fail symbol)
    match run_command("readelf", &["-s", target]).await {
        Ok(output) => {
            let has_canary = output.contains("__stack_chk_fail")
                || output.contains("__stack_chk_guard")
                || output.contains("__stack_smash_handler");

            if has_canary {
                findings.add(
                    "mitigation",
                    "Stack Canary: Enabled (__stack_chk_fail found)",
                    "info",
                );
            } else {
                findings.add(
                    "mitigation",
                    "Stack Canary: Disabled (no stack protection symbols)",
                    "high",
                );
            }
        }
        Err(_) => {
            findings.add(
                "mitigation",
                "Stack Canary: Could not determine (readelf -s failed)",
                "info",
            );
        }
    }

    // 5. Check FORTIFY via readelf -s.
    // __fortify_fail is the FORTIFY_SOURCE-specific failure handler.
    // __stack_chk_fail and __chk_fail are stack-smashing-protector handlers,
    // NOT FORTIFY indicators, so they are intentionally excluded here.
    match run_command("readelf", &["-s", target]).await {
        Ok(output) => {
            let has_fortify = output.contains("__fortify_fail");

            // Also check dynamic symbols for fortified functions
            let has_fortified_funcs = output.contains("__sprintf_chk")
                || output.contains("__snprintf_chk")
                || output.contains("__memcpy_chk");

            if has_fortified_funcs {
                findings.add(
                    "mitigation",
                    "FORTIFY: Enabled (fortified functions found)",
                    "info",
                );
            } else if has_fortify {
                findings.add("mitigation", "FORTIFY: Partial (some fortification)", "low");
            } else {
                findings.add(
                    "mitigation",
                    "FORTIFY: Disabled (no fortified symbols)",
                    "low",
                );
            }
        }
        Err(_) => {
            findings.add("mitigation", "FORTIFY: Could not determine", "info");
        }
    }

    // 6. Check for RPATH/RUNPATH
    if let Ok(output) = run_command("readelf", &["-d", target]).await {
        for line in output.lines() {
            let line = line.trim();
            if line.contains("RPATH") || line.contains("RUNPATH") {
                if let Some((_, value)) = parse_dynamic_tag(line) {
                    if !value.is_empty() {
                        findings.add(
                            "rpath",
                            format!(
                                "{} set: {}",
                                if line.contains("RPATH") {
                                    "RPATH"
                                } else {
                                    "RUNPATH"
                                },
                                value
                            ),
                            "medium",
                        );
                    }
                }
            }
        }
    }

    // 7. Check if stripped (via file command output)
    if file_output.contains("stripped") && !file_output.contains("not stripped") {
        findings.add("symbols", "Binary is stripped (no debug symbols)", "info");
    } else if file_output.contains("not stripped") {
        findings.add(
            "symbols",
            "Binary is not stripped (debug symbols present)",
            "low",
        );
    }

    // 8. Architecture and bits
    if let Some(arch_info) = extract_arch(&file_output) {
        findings.add("architecture", arch_info, "info");
    }

    Ok(findings.to_done_events())
}

fn parse_dynamic_tag(line: &str) -> Option<(&str, &str)> {
    let line = line.trim();
    // readelf -d outputs lines like:
    //   0x000000000000001d (RUNPATH)  Library runpath: [/some/path]
    // or with actual values in brackets/parens
    let key_end = line.find(") ")?;
    let key = &line[..=key_end];
    let value = line[key_end + 2..].trim();

    // Extract the actual path/value
    if let Some(start) = value.find('[') {
        let end = value[start..].find(']')?;
        Some((key, &value[start + 1..start + end]))
    } else {
        Some((key, value))
    }
}

fn extract_arch(file_output: &str) -> Option<String> {
    // "file" output looks like: "ELF 64-bit LSB executable, x86-64, ..."
    let lower = file_output.to_lowercase();
    let bits = if lower.contains("64-bit") {
        "64-bit"
    } else if lower.contains("32-bit") {
        "32-bit"
    } else {
        return None;
    };

    let arch = if lower.contains("x86-64") || lower.contains("x86_64") {
        "x86-64"
    } else if lower.contains("aarch64") || lower.contains("arm64") {
        "AArch64"
    } else if lower.contains("arm") {
        "ARM"
    } else if lower.contains("mips") {
        "MIPS"
    } else if lower.contains("riscv") {
        "RISC-V"
    } else if lower.contains("intel 80386") || lower.contains("i386") {
        "x86"
    } else {
        "unknown"
    };

    let endian = if lower.contains("lsb") {
        "LE"
    } else if lower.contains("msb") {
        "BE"
    } else {
        ""
    };

    Some(format!(
        "Architecture: {} {}{}",
        bits,
        arch,
        if endian.is_empty() {
            "".to_string()
        } else {
            format!(" ({})", endian)
        }
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_checksec_output_full() {
        let output = r#"
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   No Symbols        Yes    5               10              /bin/ls
"#;
        let events = parse_checksec_output("/bin/ls", output);
        assert!(!events.is_empty());

        let descriptions: Vec<String> = events
            .iter()
            .filter_map(|e| {
                if let WorkerEvent::Done { description, .. } = e {
                    Some(description.clone())
                } else {
                    None
                }
            })
            .collect();
        let combined = descriptions.join("\n");

        assert!(
            combined.contains("Full RELRO") || combined.contains("Full"),
            "should detect Full RELRO: {}",
            combined
        );
        assert!(
            combined.contains("Canary") || combined.contains("canary"),
            "should detect canary: {}",
            combined
        );
        assert!(combined.contains("NX"), "should detect NX: {}", combined);
        assert!(combined.contains("PIE"), "should detect PIE: {}", combined);
        assert!(
            combined.contains("RPATH") || combined.contains("RUNPATH"),
            "should mention RPATH: {}",
            combined
        );
        assert!(
            combined.contains("Symbols") || combined.contains("stripped"),
            "should mention symbols: {}",
            combined
        );
    }

    #[test]
    fn test_checksec_name_and_description() {
        let tool = Checksec::new();
        assert_eq!(tool.name(), "checksec");
        assert!(!tool.description().is_empty());
    }

    #[test]
    fn test_mitigation_status_parsing() {
        assert_eq!(
            MitigationStatus::from_checksec_output("Full RELRO"),
            MitigationStatus::Enabled
        );
        assert_eq!(
            MitigationStatus::from_checksec_output("No canary found"),
            MitigationStatus::Disabled
        );
        assert_eq!(
            MitigationStatus::from_checksec_output("Partial RELRO"),
            MitigationStatus::Partial
        );
    }
}
