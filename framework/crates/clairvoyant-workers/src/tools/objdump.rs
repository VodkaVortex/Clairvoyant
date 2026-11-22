//! Disassembly analysis for binary exploitation.
//!
//! Uses `objdump` to analyze:
//! - Function list and entry points (symbols)
//! - Interesting/dangerous functions (system, execve, gets, strcpy, etc.)
//! - PLT/GOT entries (useful for ROP/ret2libc)
//! - Section headers
//! - Key code patterns

use super::{run_command, Tool, ToolError, ToolFindings};
use crate::WorkerEvent;
use async_trait::async_trait;
use std::path::Path;

pub struct Objdump;

impl Objdump {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Objdump {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Tool for Objdump {
    fn name(&self) -> &str {
        "objdump"
    }

    fn description(&self) -> &str {
        "Disassembles a binary and identifies dangerous functions, PLT/GOT entries, and code patterns"
    }

    fn required_binaries(&self) -> Vec<&str> {
        vec!["objdump"]
    }

    async fn run(&self, target: &Path) -> Result<Vec<WorkerEvent>, ToolError> {
        let target_str = target.to_string_lossy().to_string();
        let mut findings = ToolFindings::new("objdump", &target_str);

        // 1. Get dynamic symbols (PLT/GOT entries)
        if let Ok(output) = run_command("objdump", &["-T", &target_str]).await {
            parse_dynamic_symbols(&mut findings, &output);
        }

        // 2. Get section headers
        if let Ok(output) = run_command("objdump", &["-h", &target_str]).await {
            parse_sections(&mut findings, &output);
        }

        // 3. Get regular symbols
        if let Ok(output) = run_command("objdump", &["-t", &target_str]).await {
            parse_symbols(&mut findings, &output);
        }

        Ok(findings.to_done_events())
    }
}

/// Known dangerous functions useful for exploitation.
const DANGEROUS_FUNCTIONS: &[&str] = &[
    // Command execution
    "system",
    "execve",
    "execvp",
    "execl",
    "execlp",
    "execle",
    "execv",
    "popen",
    "posix_spawn",
    // Memory corruption
    "gets",
    "scanf",
    "fscanf",
    "sscanf",
    "strcpy",
    "strcat",
    "sprintf",
    "vsprintf",
    "memcpy",
    "memmove",
    "bcopy",
    "read",
    "fread",
    "recv",
    "recvfrom",
    // Privilege escalation
    "setuid",
    "setgid",
    "setresuid",
    "setresgid",
    "setreuid",
    "setregid",
    "chmod",
    "chown",
    "capset",
    // File operations (useful for arbitrary read/write)
    "open",
    "fopen",
    "creat",
    "mknod",
    "write",
    "fwrite",
    "send",
    "sendto",
    // Network
    "socket",
    "connect",
    "bind",
    "listen",
    "accept",
    // Process
    "fork",
    "clone",
    "ptrace",
    "prctl",
    // Signal
    "signal",
    "sigaction",
    "kill",
    // Dynamic loading
    "dlopen",
    "dlsym",
    "dlclose",
    // Memory mapping
    "mmap",
    "mprotect",
    "brk",
    "sbrk",
    "malloc",
    "free",
];

/// Security-relevant functions.
const SECURITY_FUNCTIONS: &[&str] = &[
    "seccomp",
    "prctl",
    "capget",
    "capset",
    "sandbox_init",
    "pledge",
    "unveil",
    "setrlimit",
    "getrlimit",
];

fn parse_dynamic_symbols(findings: &mut ToolFindings, output: &str) {
    let mut dangerous: Vec<String> = Vec::new();
    let mut security: Vec<String> = Vec::new();
    let mut plt_entries: Vec<String> = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Dynamic symbol table entries
        if let Some(func_name) = extract_symbol_name(line) {
            let func_lower = func_name.to_lowercase();

            if DANGEROUS_FUNCTIONS.iter().any(|f| func_lower == *f) {
                dangerous.push(func_name.to_string());
            }

            if SECURITY_FUNCTIONS.iter().any(|f| func_lower == *f) {
                security.push(func_name.to_string());
            }

            // PLT entries typically end with @plt or are in .plt section
            if line.contains("@plt") || line.contains(".plt") {
                plt_entries.push(func_name.to_string());
            }
        }
    }

    if !dangerous.is_empty() {
        findings.add(
            "dangerous_functions",
            format!(
                "Found {} potentially exploitable functions: {}",
                dangerous.len(),
                dangerous.join(", ")
            ),
            "high",
        );
    }

    if !security.is_empty() {
        findings.add(
            "security_functions",
            format!(
                "Found {} security-relevant functions: {}",
                security.len(),
                security.join(", ")
            ),
            "info",
        );
    }

    if !plt_entries.is_empty() {
        let count = plt_entries.len();
        let sample: Vec<String> = plt_entries.iter().take(15).cloned().collect();
        let suffix = if plt_entries.len() > 15 {
            format!(" (and {} more)", plt_entries.len() - 15)
        } else {
            String::new()
        };
        findings.add(
            "plt_entries",
            format!(
                "{} PLT entries available for ret2libc/ROP{}: {}",
                count,
                suffix,
                sample.join(", ")
            ),
            "medium",
        );
    }
}

fn parse_sections(findings: &mut ToolFindings, output: &str) {
    let mut sections: Vec<String> = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Section header lines look like:
        //   .text             PROGBITS        0000000000001040  00001040
        // or with numbers first:
        //   12 .plt           00000070  0000000000001020  0000000000001020  00001020  2**4
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let name = if parts[0].starts_with('.') {
                parts[0].to_string()
            } else if parts.len() >= 2 && parts[1].starts_with('.') {
                parts[1].to_string()
            } else {
                continue;
            };

            let section_lower = name.to_lowercase();
            if is_interesting_section(&section_lower) {
                sections.push(name);
            }
        }
    }

    if !sections.is_empty() {
        findings.add(
            "sections",
            format!("Key sections: {}", sections.join(", ")),
            "info",
        );
    }
}

fn is_interesting_section(name: &str) -> bool {
    matches!(
        name,
        ".text"
            | ".plt"
            | ".plt.got"
            | ".plt.sec"
            | ".got"
            | ".got.plt"
            | ".data"
            | ".bss"
            | ".rodata"
            | ".init"
            | ".fini"
            | ".init_array"
            | ".fini_array"
            | ".ctors"
            | ".dtors"
            | ".dynamic"
            | ".dynsym"
            | ".dynstr"
            | ".rel.dyn"
            | ".rela.dyn"
            | ".rel.plt"
            | ".rela.plt"
            | ".eh_frame"
            | ".eh_frame_hdr"
            | ".gcc_except_table"
            | ".note.gnu.build-id"
            | ".note.ABI-tag"
    )
}

fn parse_symbols(findings: &mut ToolFindings, output: &str) {
    let mut function_count = 0usize;
    let mut interesting: Vec<String> = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Symbol table: look for FUNC type
        if line.contains(" F ") || line.contains(" FUNC ") {
            function_count += 1;
        }

        if let Some(name) = extract_symbol_name(line) {
            let lower = name.to_lowercase();
            // Win/flag-related functions
            if lower.contains("win")
                || lower.contains("flag")
                || lower.contains("shell")
                || lower.contains("admin")
                || lower.contains("root")
                || lower.contains("backdoor")
                || lower.contains("debug")
                || lower.contains("hidden")
            {
                interesting.push(name.to_string());
            }
        }
    }

    if function_count > 0 {
        findings.add(
            "symbols",
            format!("{} total functions defined", function_count),
            "info",
        );
    }

    if !interesting.is_empty() {
        findings.add(
            "interesting_functions",
            format!(
                "Found {} interestingly-named functions: {}",
                interesting.len(),
                interesting.join(", ")
            ),
            "medium",
        );
    }
}

fn extract_symbol_name(line: &str) -> Option<&str> {
    // Dynamic symbol table: <addr> <flags> <section> <size> <name>
    // Regular symbol table: <addr> <flags> <section> <size> <name>
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() >= 5 {
        let last = parts[parts.len() - 1];
        // Filter out addresses and common non-names
        if !last.starts_with("0x")
            && !last.starts_with("00")
            && last.len() >= 2
            && last.chars().any(|c| c.is_alphabetic())
        {
            // Handle @GLIBC version suffixes
            let name = last.split('@').next().unwrap_or(last);
            return Some(name);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dangerous_functions_list_is_non_empty() {
        assert!(!DANGEROUS_FUNCTIONS.is_empty());
        assert!(DANGEROUS_FUNCTIONS.contains(&"system"));
        assert!(DANGEROUS_FUNCTIONS.contains(&"gets"));
        assert!(DANGEROUS_FUNCTIONS.contains(&"strcpy"));
        assert!(DANGEROUS_FUNCTIONS.contains(&"mmap"));
    }

    #[test]
    fn test_objdump_tool_name() {
        let tool = Objdump::new();
        assert_eq!(tool.name(), "objdump");
    }

    #[test]
    fn test_extract_symbol_name_from_dynamic_sym() {
        // Typical objdump -T output line
        let line =
            "0000000000000000      DF *UND*  0000000000000000  GLIBC_2.34  __libc_start_main";
        let name = extract_symbol_name(line);
        assert_eq!(name, Some("__libc_start_main"));
    }

    #[test]
    fn test_extract_symbol_name_from_symtab() {
        let line = "0000000000001169 g     F .text  000000000000004b              main";
        let name = extract_symbol_name(line);
        assert_eq!(name, Some("main"));
    }

    #[test]
    fn test_is_interesting_section() {
        assert!(is_interesting_section(".text"));
        assert!(is_interesting_section(".plt"));
        assert!(is_interesting_section(".got.plt"));
        assert!(is_interesting_section(".init_array"));
        assert!(is_interesting_section(".fini_array"));
        assert!(!is_interesting_section(".comment"));
        assert!(!is_interesting_section(".shstrtab"));
    }
}
