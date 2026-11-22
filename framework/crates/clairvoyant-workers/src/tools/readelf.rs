//! ELF structure analysis for binary exploitation.
//!
//! Uses `readelf` to extract:
//! - ELF header info (type, entry point, architecture)
//! - Program headers (segments)
//! - Section headers
//! - Dynamic section entries
//! - Relocations
//! - Notes (build ID, ABI tags)
//! - Version info

use super::{run_command, Tool, ToolError, ToolFindings};
use crate::WorkerEvent;
use async_trait::async_trait;
use std::collections::BTreeMap;
use std::path::Path;

pub struct Readelf;

impl Readelf {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Readelf {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Tool for Readelf {
    fn name(&self) -> &str {
        "readelf"
    }

    fn description(&self) -> &str {
        "Analyzes ELF structure: headers, segments, dynamic entries, relocations, and notes"
    }

    fn required_binaries(&self) -> Vec<&str> {
        vec!["readelf"]
    }

    async fn run(&self, target: &Path) -> Result<Vec<WorkerEvent>, ToolError> {
        let target_str = target.to_string_lossy().to_string();
        let mut findings = ToolFindings::new("readelf", &target_str);

        // Run readelf -a (all) and parse the output
        let output = run_command("readelf", &["-a", &target_str]).await?;

        parse_readelf_all(&mut findings, &output);

        Ok(findings.to_done_events())
    }
}

fn parse_readelf_all(findings: &mut ToolFindings, output: &str) {
    let mut entry_point: Option<String> = None;
    let mut elf_type: Option<String> = None;
    let mut machine: Option<String> = None;
    let mut segments: Vec<String> = Vec::new();
    let mut dynamic_entries: BTreeMap<String, String> = BTreeMap::new();
    let mut needed_libs: Vec<String> = Vec::new();
    let mut got_relocations: usize = 0;
    let mut plt_relocations: usize = 0;
    let mut writable_sections: Vec<String> = Vec::new();

    let mut in_dynamic = false;
    let mut in_program_headers = false;
    let mut in_sections = false;

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Detect section transitions
        if line.starts_with("ELF Header:") {
            continue;
        }
        if line.starts_with("Program Headers:") {
            in_program_headers = true;
            in_dynamic = false;
            in_sections = false;
            continue;
        }
        if line.starts_with("Dynamic Section:") {
            in_dynamic = true;
            in_program_headers = false;
            in_sections = false;
            continue;
        }
        if line.starts_with("Section Headers:") {
            in_sections = true;
            in_dynamic = false;
            in_program_headers = false;
            continue;
        }
        if line.starts_with("Relocation section") {
            if line.contains(".got") || line.contains(".rel.dyn") {
                // Count relocations
                got_relocations += 1;
            }
            if line.contains(".plt") || line.contains(".rela.plt") || line.contains(".rel.plt") {
                plt_relocations += 1;
            }
            continue;
        }

        // Parse ELF header fields
        if let Some(value) = try_prefix(line, "Entry point address:") {
            entry_point = Some(value.trim().to_string());
        }
        if let Some(value) = try_prefix(line, "Type:") {
            elf_type = Some(value.trim().to_string());
        }
        if let Some(value) = try_prefix(line, "Machine:") {
            machine = Some(value.trim().to_string());
        }

        // Parse program headers
        if in_program_headers {
            if line.starts_with("Type") || line.starts_with("===") || line.starts_with("Program") {
                continue;
            }
            if line.contains("LOAD")
                || line.contains("GNU_STACK")
                || line.contains("GNU_RELRO")
                || line.contains("DYNAMIC")
                || line.contains("INTERP")
                || line.contains("NOTE")
            {
                segments.push(line.to_string());
            }
        }

        // Parse dynamic section
        if in_dynamic {
            if line.starts_with("Tag") || line.starts_with("===") {
                continue;
            }
            // Dynamic entries look like:
            //   0x0000000000000001 (NEEDED)  Shared library: [libc.so.6]
            if let Some((_, rest)) = line.split_once(')') {
                let rest = rest.trim();
                if let Some((key, value)) = rest.split_once(':') {
                    let key = key.trim();
                    let value = value.trim().trim_matches(|c| c == '[' || c == ']');
                    dynamic_entries.insert(key.to_string(), value.to_string());

                    if key == "Shared library" {
                        needed_libs.push(value.to_string());
                    }
                }
            }
        }

        // Parse section headers for writable sections
        if in_sections {
            if line.starts_with("[Nr]") || line.starts_with("===") || line.starts_with("Key") {
                continue;
            }
            if line.contains(" WA ") || line.contains(" WA,") {
                // Writiable, Alloc section
                if let Some(name) = extract_section_name(line) {
                    writable_sections.push(name);
                }
            }
        }
    }

    // Build findings
    if let Some(ep) = &entry_point {
        findings.add("entry_point", format!("Entry point: {}", ep), "info");
    }
    if let Some(et) = &elf_type {
        findings.add("elf_type", format!("ELF type: {}", et), "info");
    }
    if let Some(m) = &machine {
        findings.add("architecture", format!("Machine: {}", m), "info");
    }
    if !segments.is_empty() {
        findings.add(
            "segments",
            format!(
                "Program headers: {}",
                segments
                    .iter()
                    .map(|s| {
                        let s = s.trim();
                        // Extract just the type
                        if let Some(typ) = s.split_whitespace().find(|w| {
                            w.contains("LOAD")
                                || w.contains("GNU_")
                                || w.contains("DYNAMIC")
                                || w.contains("INTERP")
                                || w.contains("NOTE")
                                || w.contains("PHDR")
                        }) {
                            typ.to_string()
                        } else {
                            s.split_whitespace().next().unwrap_or("unknown").to_string()
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            "info",
        );
    }
    if !needed_libs.is_empty() {
        findings.add(
            "shared_libraries",
            format!(
                "NEEDED libraries ({}): {}",
                needed_libs.len(),
                needed_libs.join(", ")
            ),
            "info",
        );
    }
    if !writable_sections.is_empty() {
        findings.add(
            "writable_sections",
            format!(
                "{} writable+alloc sections: {}",
                writable_sections.len(),
                writable_sections.join(", ")
            ),
            "medium",
        );
    }
    if got_relocations > 0 || plt_relocations > 0 {
        findings.add(
            "relocations",
            format!(
                "GOT relocations: ~{}, PLT relocations: ~{}",
                got_relocations, plt_relocations
            ),
            "info",
        );
    }
    if !dynamic_entries.is_empty() {
        // Report interesting dynamic entries
        let interesting_keys = ["RUNPATH", "RPATH", "FLAGS", "FLAGS_1", "BIND_NOW"];
        let mut interesting: Vec<String> = Vec::new();
        for key in &interesting_keys {
            if let Some(value) = dynamic_entries.get(*key) {
                interesting.push(format!("{}: {}", key, value));
            }
        }
        if !interesting.is_empty() {
            findings.add(
                "dynamic_entries",
                format!("Key dynamic entries: {}", interesting.join(", ")),
                "info",
            );
        }
    }
}

fn try_prefix<'a>(line: &'a str, prefix: &str) -> Option<&'a str> {
    line.strip_prefix(prefix)
}

fn extract_section_name(line: &str) -> Option<String> {
    // Section header lines from readelf -S:
    //   [14] .got.plt          PROGBITS        0000000000004000  00003000
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() >= 2 && parts[1].starts_with('.') {
        return Some(parts[1].to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_readelf_tool_name() {
        let tool = Readelf::new();
        assert_eq!(tool.name(), "readelf");
    }

    #[test]
    fn test_extract_section_name() {
        let line = "  [14] .got.plt          PROGBITS        0000000000004000  00003000";
        assert_eq!(extract_section_name(line), Some(".got.plt".to_string()));
    }

    #[test]
    fn test_try_prefix() {
        assert_eq!(
            try_prefix("Entry point address: 0x1040", "Entry point address:"),
            Some(" 0x1040")
        );
        assert_eq!(try_prefix("not a match", "Entry point address:"), None);
    }
}
