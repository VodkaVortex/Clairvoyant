//! ROP gadget finder for binary exploitation.
//!
//! Uses `ROPgadget` or `ropper` to find ROP gadgets in a binary.
//! Reports:
//! - Total gadget count
//! - Key gadget categories (pop, ret, syscall, mov, xor, etc.)
//! - Most useful gadgets for exploitation
//! - Gadgets by register target

use super::{check_binary, run_command, Tool, ToolError, ToolFindings};
use crate::WorkerEvent;
use async_trait::async_trait;
use std::path::Path;

pub struct RopGadget {
    /// If true, prefer `ropper` over `ROPgadget`.
    pub prefer_ropper: bool,
}

impl RopGadget {
    pub fn new() -> Self {
        Self {
            prefer_ropper: false,
        }
    }

    pub fn with_prefer_ropper(mut self) -> Self {
        self.prefer_ropper = true;
        self
    }
}

impl Default for RopGadget {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Tool for RopGadget {
    fn name(&self) -> &str {
        "ropgadget"
    }

    fn description(&self) -> &str {
        "Finds ROP gadgets in a binary: pop/ret chains, syscalls, and useful primitives"
    }

    fn required_binaries(&self) -> Vec<&str> {
        vec!["ROPgadget", "ropper"]
    }

    async fn run(&self, target: &Path) -> Result<Vec<WorkerEvent>, ToolError> {
        let target_str = target.to_string_lossy().to_string();
        let mut findings = ToolFindings::new("ropgadget", &target_str);

        // Try ropper first if preferred
        if self.prefer_ropper && check_binary("ropper").await {
            match run_command("ropper", &["--file", &target_str, "--all"]).await {
                Ok(output) => {
                    parse_ropper_output(&mut findings, &output);
                    return Ok(findings.to_done_events());
                }
                Err(_) => {
                    // Fall through to ROPgadget
                }
            }
        }

        // Try ROPgadget
        if check_binary("ROPgadget").await {
            match run_command("ROPgadget", &["--binary", &target_str]).await {
                Ok(output) => {
                    parse_ropgadget_output(&mut findings, &output);
                    return Ok(findings.to_done_events());
                }
                Err(e) => {
                    // If ROPgadget fails and we haven't tried ropper, try it now
                    if !self.prefer_ropper && check_binary("ropper").await {
                        match run_command("ropper", &["--file", &target_str, "--all"]).await {
                            Ok(output) => {
                                parse_ropper_output(&mut findings, &output);
                                return Ok(findings.to_done_events());
                            }
                            Err(_) => {
                                return Err(e);
                            }
                        }
                    }
                    return Err(e);
                }
            }
        }

        Err(ToolError::Failed {
            tool: "ropgadget".to_string(),
            message: "Neither ROPgadget nor ropper found on PATH".to_string(),
        })
    }
}

fn parse_ropgadget_output(findings: &mut ToolFindings, output: &str) {
    let mut gadget_count = 0usize;
    let mut pop_gadgets: Vec<String> = Vec::new();
    let mut syscall_gadgets: Vec<String> = Vec::new();
    let mut ret_gadgets: Vec<String> = Vec::new();
    let mut xor_gadgets: Vec<String> = Vec::new();
    let mut mov_gadgets: Vec<String> = Vec::new();
    let mut xchg_gadgets: Vec<String> = Vec::new();
    let mut jmp_gadgets: Vec<String> = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // ROPgadget output format:
        //   0x0000000000001234 : pop rdi ; ret
        // Gadgets information
        // Unique gadgets found: 42

        if line.starts_with("Unique gadgets found:") {
            if let Some(count_str) = line.split(':').nth(1) {
                if let Ok(count) = count_str.trim().parse::<usize>() {
                    gadget_count = count;
                }
            }
            continue;
        }

        if !line.contains(" : ") && !line.contains(": ") {
            continue;
        }

        // Extract gadget instruction
        let gadget_part = line.split_once(" : ").map(|x| x.1).unwrap_or(line);
        let gadget_lower = gadget_part.to_lowercase();

        // Classify gadgets
        if gadget_lower.contains("syscall")
            || gadget_lower.contains("int 0x80")
            || gadget_lower.contains("svc")
        {
            syscall_gadgets.push(gadget_part.to_string());
        } else if gadget_lower.contains("pop ") {
            let reg = gadget_lower
                .split("pop ")
                .nth(1)
                .and_then(|s| s.split([';', ' ']).next())
                .unwrap_or("?")
                .to_string();
            let entry = format!("pop {} ({})", reg, line.split(" : ").next().unwrap_or("?"));
            pop_gadgets.push(entry);
        } else if gadget_lower.starts_with("ret") || gadget_lower == "ret" {
            ret_gadgets.push(gadget_part.to_string());
        } else if gadget_lower.contains("xor ") {
            xor_gadgets.push(gadget_part.to_string());
        } else if gadget_lower.contains("mov ") {
            mov_gadgets.push(gadget_part.to_string());
        } else if gadget_lower.contains("xchg ") {
            xchg_gadgets.push(gadget_part.to_string());
        } else if gadget_lower.contains("jmp ") || gadget_lower.contains("call ") {
            jmp_gadgets.push(gadget_part.to_string());
        }
    }

    // Build findings
    findings.add(
        "gadget_count",
        format!("Total unique gadgets found: {}", gadget_count),
        "info",
    );

    if !pop_gadgets.is_empty() {
        // Deduplicate by register
        let regs: Vec<&str> = pop_gadgets
            .iter()
            .filter_map(|g| g.split("pop ").nth(1))
            .filter_map(|s| s.split([';', ' ']).next())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();

        let suffix = if pop_gadgets.len() > 15 {
            format!(" ({} total)", pop_gadgets.len())
        } else {
            String::new()
        };
        findings.add(
            "pop_gadgets",
            format!("pop gadgets for registers: {}{}", regs.join(", "), suffix),
            "high",
        );
    }

    if !syscall_gadgets.is_empty() {
        findings.add(
            "syscall_gadgets",
            format!(
                "Found {} syscall/svc gadgets: {}",
                syscall_gadgets.len(),
                syscall_gadgets.join(" ; ")
            ),
            "critical",
        );
    }

    if !xor_gadgets.is_empty() {
        findings.add(
            "zero_gadgets",
            format!(
                "Found {} xor gadgets (register zeroing): {}",
                xor_gadgets.len(),
                xor_gadgets
                    .iter()
                    .take(5)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(" ; ")
            ),
            "high",
        );
    }

    if !mov_gadgets.is_empty() {
        findings.add(
            "move_gadgets",
            format!(
                "Found {} mov gadgets (register transfer): {}",
                mov_gadgets.len(),
                mov_gadgets
                    .iter()
                    .take(5)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(" ; ")
            ),
            "medium",
        );
    }

    if !xchg_gadgets.is_empty() {
        findings.add(
            "exchange_gadgets",
            format!(
                "Found {} xchg gadgets: {}",
                xchg_gadgets.len(),
                xchg_gadgets
                    .iter()
                    .take(5)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(" ; ")
            ),
            "medium",
        );
    }

    if !jmp_gadgets.is_empty() {
        findings.add(
            "jump_gadgets",
            format!(
                "Found {} jmp/call gadgets: {}",
                jmp_gadgets.len(),
                jmp_gadgets
                    .iter()
                    .take(5)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(" ; ")
            ),
            "medium",
        );
    }

    // Assess exploitation difficulty based on gadgets available
    let has_syscall = !syscall_gadgets.is_empty();
    let has_pop_rdi = pop_gadgets.iter().any(|g| g.contains("rdi"));
    let has_pop_rsi = pop_gadgets.iter().any(|g| g.contains("rsi"));
    let has_pop_rdx = pop_gadgets.iter().any(|g| g.contains("rdx"));
    let has_pop_rax = pop_gadgets.iter().any(|g| g.contains("rax"));

    if has_pop_rdi && has_syscall {
        findings.add(
            "exploit_primitive",
            "ROP chain possible: pop rdi available + syscall gadget found — arbitrary execve() chain feasible",
            "critical",
        );
    } else if has_pop_rdi && has_pop_rsi && has_pop_rdx {
        findings.add(
            "exploit_primitive",
            "ROP chain possible: pop rdi/rsi/rdx available — controlled args for function calls",
            "high",
        );
    } else if has_pop_rdi {
        findings.add(
            "exploit_primitive",
            "ROP basic: pop rdi available — can control first argument for ret2libc",
            "medium",
        );
    }

    if has_pop_rax && has_syscall {
        findings.add(
            "exploit_primitive",
            "Full syscall control: pop rax + syscall — arbitrary syscall invocation possible",
            "critical",
        );
    }
}

fn parse_ropper_output(findings: &mut ToolFindings, output: &str) {
    // Ropper output format is similar:
    //   0x0000000000001234: pop rdi; ret;
    // or with address in separate line

    let mut gadget_count = 0usize;
    let mut pop_gadgets: Vec<String> = Vec::new();
    let mut syscall_gadgets: Vec<String> = Vec::new();
    let mut ret_gadgets: Vec<String> = Vec::new();
    let mut xor_gadgets: Vec<String> = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Count gadgets
        if line.to_lowercase().contains("gadgets found")
            || line.to_lowercase().contains("gadgets information")
        {
            if let Some(count_str) = line.split_whitespace().find(|w| w.parse::<usize>().is_ok()) {
                if let Ok(count) = count_str.parse::<usize>() {
                    gadget_count += count;
                }
            }
            continue;
        }

        let gadget_lower = line.to_lowercase();

        if gadget_lower.contains("syscall") || gadget_lower.contains("int 0x80") {
            syscall_gadgets.push(line.to_string());
        } else if gadget_lower.contains("pop ") {
            pop_gadgets.push(line.to_string());
        } else if gadget_lower.starts_with("ret") || gadget_lower == "ret" {
            ret_gadgets.push(line.to_string());
        } else if gadget_lower.contains("xor ") {
            xor_gadgets.push(line.to_string());
        }
    }

    if gadget_count > 0 {
        findings.add(
            "gadget_count",
            format!("Total unique gadgets found: {}", gadget_count),
            "info",
        );
    }

    if !pop_gadgets.is_empty() {
        findings.add(
            "pop_gadgets",
            format!("Found {} pop gadgets", pop_gadgets.len()),
            "high",
        );
    }

    if !syscall_gadgets.is_empty() {
        findings.add(
            "syscall_gadgets",
            format!(
                "Found {} syscall gadgets: {}",
                syscall_gadgets.len(),
                syscall_gadgets
                    .iter()
                    .take(5)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(" ; ")
            ),
            "critical",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ropgadget_tool_name() {
        let tool = RopGadget::new();
        assert_eq!(tool.name(), "ropgadget");
    }

    #[test]
    fn test_parse_ropgadget_output_realistic() {
        let output = r#"
Gadgets information
============================================================
0x00000000000011c7 : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000000011c9 : pop r13 ; pop r14 ; pop r15 ; ret
0x00000000000011cb : pop r14 ; pop r15 ; ret
0x00000000000011cd : pop r15 ; ret
0x00000000000011c5 : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000000011c4 : pop rbp ; pop r14 ; pop r15 ; ret
0x00000000000010b6 : pop rdi ; ret
0x00000000000010b4 : pop rsi ; pop r15 ; ret
0x00000000000010b2 : pop rdx ; pop rbx ; ret
0x0000000000001147 : syscall ; ret
0x000000000000101a : ret
0x0000000000001234 : xor eax, eax ; ret

Unique gadgets found: 42
"#;

        let mut findings = ToolFindings::new("ropgadget", "/tmp/test");
        parse_ropgadget_output(&mut findings, output);

        // Check that we found key gadgets
        let events = findings.to_done_events();
        let all_text: String = events
            .iter()
            .filter_map(|e| {
                if let WorkerEvent::Done { description, .. } = e {
                    Some(description.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join("\n");

        assert!(all_text.contains("42"), "should find gadget count");
        assert!(all_text.contains("syscall"), "should find syscall gadget");
        assert!(all_text.contains("rdi"), "should find pop rdi");
        assert!(all_text.contains("rsi"), "should find pop rsi");
        assert!(all_text.contains("rdx"), "should find pop rdx");
    }

    #[test]
    fn test_parse_ropgadget_syscall_detection() {
        let output = r#"
0x0000000000001000 : syscall
0x0000000000001002 : ret

Unique gadgets found: 2
"#;

        let mut findings = ToolFindings::new("ropgadget", "/tmp/test");
        parse_ropgadget_output(&mut findings, output);

        let events = findings.to_done_events();
        let all_text: String = events
            .iter()
            .filter_map(|e| {
                if let WorkerEvent::Done { description, .. } = e {
                    Some(description.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join("\n");

        assert!(
            all_text.contains("syscall") || all_text.contains("syscall_gadgets"),
            "should detect syscall gadget"
        );
    }
}
