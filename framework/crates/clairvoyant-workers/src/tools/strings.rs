//! String extraction and analysis for binary exploitation.
//!
//! Runs `strings` against a binary, then classifies interesting strings:
//! - File paths (absolute and relative)
//! - URLs and IP addresses
//! - Function names and library calls
//! - Error messages (useful for understanding binary behavior)
//! - Format strings (potential format string vulnerabilities)
//! - Hardcoded credentials or keys

use super::{run_command, Tool, ToolError, ToolFindings};
use crate::WorkerEvent;
use async_trait::async_trait;
use std::path::Path;

pub struct Strings {
    /// Minimum string length (default: 4)
    pub min_length: usize,
    /// Maximum number of findings to report (default: 50)
    pub max_findings: usize,
}

impl Strings {
    pub fn new() -> Self {
        Self {
            min_length: 4,
            max_findings: 50,
        }
    }

    pub fn with_min_length(mut self, len: usize) -> Self {
        self.min_length = len;
        self
    }
}

impl Default for Strings {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Tool for Strings {
    fn name(&self) -> &str {
        "strings"
    }

    fn description(&self) -> &str {
        "Extracts and classifies printable strings from a binary"
    }

    fn required_binaries(&self) -> Vec<&str> {
        vec!["strings"]
    }

    async fn run(&self, target: &Path) -> Result<Vec<WorkerEvent>, ToolError> {
        let target_str = target.to_string_lossy().to_string();
        let min_flag = format!("-n{}", self.min_length);

        let output = run_command("strings", &[&min_flag, &target_str]).await?;

        let findings = classify_strings(&target_str, &output, self.max_findings);
        Ok(findings.to_done_events())
    }
}

fn classify_strings(target: &str, output: &str, max_findings: usize) -> ToolFindings {
    let mut findings = ToolFindings::new("strings", target);

    let mut paths: Vec<&str> = Vec::new();
    let mut urls: Vec<&str> = Vec::new();
    let mut ip_addrs: Vec<&str> = Vec::new();
    let mut func_names: Vec<&str> = Vec::new();
    let mut error_msgs: Vec<&str> = Vec::new();
    let mut format_strings: Vec<&str> = Vec::new();
    let mut creds_keys: Vec<&str> = Vec::new();
    let mut commands: Vec<&str> = Vec::new();
    let mut lib_names: Vec<&str> = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Skip pure whitespace or non-printable-heavy lines
        if line.chars().any(|c| c.is_control() && c != '\t') {
            continue;
        }

        // Classify each string
        if looks_like_absolute_path(line) {
            paths.push(line);
        } else if looks_like_url(line) {
            urls.push(line);
        } else if looks_like_ip(line) {
            ip_addrs.push(line);
        } else if looks_like_format_string(line) {
            format_strings.push(line);
        } else if looks_like_credential_or_key(line) {
            creds_keys.push(line);
        } else if looks_like_function_name(line) {
            func_names.push(line);
        } else if looks_like_error_message(line) {
            error_msgs.push(line);
        } else if looks_like_command(line) {
            commands.push(line);
        } else if looks_like_library(line) {
            lib_names.push(line);
        }
    }

    // Build categorized findings
    add_category(&mut findings, "paths", &paths, "medium", max_findings);
    add_category(&mut findings, "urls", &urls, "low", max_findings);
    add_category(
        &mut findings,
        "ip_addresses",
        &ip_addrs,
        "low",
        max_findings,
    );
    add_category(
        &mut findings,
        "format_strings",
        &format_strings,
        "high",
        max_findings,
    );
    add_category(
        &mut findings,
        "credentials_keys",
        &creds_keys,
        "critical",
        max_findings,
    );
    add_category(
        &mut findings,
        "library_calls",
        &lib_names,
        "info",
        max_findings,
    );
    add_category(
        &mut findings,
        "error_messages",
        &error_msgs,
        "info",
        max_findings,
    );
    add_category(&mut findings, "commands", &commands, "medium", max_findings);
    add_category(
        &mut findings,
        "function_names",
        &func_names,
        "info",
        max_findings,
    );

    let all_categories: [&[&str]; 9] = [
        &paths,
        &urls,
        &ip_addrs,
        &format_strings,
        &creds_keys,
        &lib_names,
        &error_msgs,
        &commands,
        &func_names,
    ];
    let total: usize = all_categories.iter().map(|v| v.len()).sum();
    let category_count = all_categories.iter().filter(|v| !v.is_empty()).count();
    findings.add(
        "summary",
        format!(
            "Total strings extracted: {} items across {} non-empty categories",
            total, category_count
        ),
        "info",
    );

    findings
}

fn add_category(
    findings: &mut ToolFindings,
    category: &str,
    items: &[&str],
    severity: &str,
    max_per_category: usize,
) {
    if items.is_empty() {
        return;
    }

    let display_items: Vec<String> = items
        .iter()
        .take(max_per_category)
        .map(|s| s.to_string())
        .collect();

    let suffix = if items.len() > max_per_category {
        format!(" (and {} more)", items.len() - max_per_category)
    } else {
        String::new()
    };

    let description = format!(
        "{} found{}: {}",
        category.replace('_', " "),
        suffix,
        display_items.join(", ")
    );

    findings.add(category, description, severity);
}

// --- Classification helpers ---

fn looks_like_absolute_path(s: &str) -> bool {
    s.starts_with('/')
        && s.len() > 2
        && !s.contains(' ')
        && s.chars()
            .all(|c| c.is_alphanumeric() || "/._-+@".contains(c))
}

fn looks_like_url(s: &str) -> bool {
    (s.starts_with("http://") || s.starts_with("https://") || s.starts_with("ftp://"))
        && s.len() > 10
}

fn looks_like_ip(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| p.parse::<u8>().is_ok())
}

fn looks_like_format_string(s: &str) -> bool {
    // Look for printf-style format specifiers
    let has_format = s.contains("%s")
        || s.contains("%x")
        || s.contains("%n")
        || s.contains("%d")
        || s.contains("%p")
        || s.contains("%ld")
        || s.contains("%lu");

    // Must also look like a format string (short, multiple specifiers, or starts with %)
    if !has_format {
        return false;
    }

    let specifier_count = s.matches('%').count();
    specifier_count >= 2 || s.len() < 80
}

fn looks_like_credential_or_key(s: &str) -> bool {
    let lower = s.to_lowercase();
    (lower.contains("password")
        || lower.contains("passwd")
        || lower.contains("secret")
        || lower.contains("api_key")
        || lower.contains("apikey")
        || lower.contains("token")
        || lower.contains("private_key")
        || lower.contains("-----begin")
        || lower.contains("-----end"))
        && s.len() < 200
}

fn looks_like_function_name(s: &str) -> bool {
    // C function names: alphanumeric + underscore, reasonably short
    s.len() >= 3
        && s.len() <= 80
        && s.chars().all(|c| c.is_alphanumeric() || c == '_')
        && s.starts_with(|c: char| c.is_alphabetic() || c == '_')
        && !s.starts_with("__") // skip compiler internals unless short
}

fn looks_like_error_message(s: &str) -> bool {
    let lower = s.to_lowercase();
    s.len() >= 10
        && s.len() <= 200
        && (lower.contains("error")
            || lower.contains("fail")
            || lower.contains("invalid")
            || lower.contains("cannot")
            || lower.contains("denied")
            || lower.contains("not found")
            || lower.contains("permission"))
}

fn looks_like_command(s: &str) -> bool {
    let cmds = [
        "sh",
        "bash",
        "/bin/sh",
        "/bin/bash",
        "cmd",
        "cmd.exe",
        "wget",
        "curl",
        "nc",
        "netcat",
        "python",
        "perl",
        "ruby",
        "gcc",
        "g++",
        "make",
        "chmod",
        "chown",
        "sudo",
        "ping",
        "nslookup",
        "dig",
        "whoami",
        "id",
        "cat",
        "ls",
        "cp",
        "mv",
        "rm",
        "ssh",
        "scp",
        "telnet",
        "ftp",
    ];
    let lower = s.to_lowercase();
    cmds.iter()
        .any(|cmd| lower.starts_with(cmd) || lower == *cmd)
}

fn looks_like_library(s: &str) -> bool {
    s.ends_with(".so")
        || s.ends_with(".a")
        || s.ends_with(".dll")
        || s.ends_with(".dylib")
        || s.starts_with("lib")
        || s.contains(".so.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_absolute_paths() {
        assert!(looks_like_absolute_path("/etc/passwd"));
        assert!(looks_like_absolute_path("/home/user/.ssh/id_rsa"));
        assert!(looks_like_absolute_path("/usr/bin/python3"));
        assert!(!looks_like_absolute_path("relative/file.txt"));
        assert!(!looks_like_absolute_path("/a")); // too short
    }

    #[test]
    fn test_classify_urls() {
        assert!(looks_like_url("https://example.com/api"));
        assert!(looks_like_url("http://10.0.0.1:8080/login"));
        assert!(!looks_like_url("just some text"));
    }

    #[test]
    fn test_classify_ips() {
        assert!(looks_like_ip("192.168.1.1"));
        assert!(looks_like_ip("10.0.0.5"));
        assert!(!looks_like_ip("not.an.ip.address"));
        assert!(!looks_like_ip("256.1.1.1")); // invalid octet
    }

    #[test]
    fn test_classify_format_strings() {
        assert!(looks_like_format_string("Error: %s at line %d"));
        assert!(looks_like_format_string("0x%08x: %s %n")); // dangerous!
        assert!(!looks_like_format_string("100% pure"));
        assert!(!looks_like_format_string("just a long sentence with a single percent % sign that isn't a format string because it's too long and only has one specifier"));
    }

    #[test]
    fn test_classify_credentials() {
        assert!(looks_like_credential_or_key("DB_PASSWORD=secret123"));
        assert!(looks_like_credential_or_key(
            "-----BEGIN RSA PRIVATE KEY-----"
        ));
        assert!(!looks_like_credential_or_key("regular text"));
    }

    #[test]
    fn test_strings_tool_name() {
        let tool = Strings::new();
        assert_eq!(tool.name(), "strings");
    }
}
