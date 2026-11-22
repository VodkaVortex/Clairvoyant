use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::pin::Pin;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio_stream::{wrappers::ReceiverStream, Stream, StreamExt};

pub mod tools;

pub type WorkerEventStream = Pin<Box<dyn Stream<Item = Result<WorkerEvent, WorkerError>> + Send>>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkerContext {
    pub project_id: String,
    pub intent_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkerEvent {
    ToolCall {
        name: String,
        arguments: serde_json::Value,
    },
    ToolResult {
        name: String,
        output: String,
        success: bool,
    },
    Thinking {
        text: String,
    },
    Message {
        text: String,
    },
    Done {
        description: String,
        complete: bool,
    },
    Intent {
        sources: Vec<String>,
        description: String,
    },
    Complete {
        sources: Vec<String>,
        description: String,
    },
    Error {
        message: String,
    },
}

#[derive(Debug, Error)]
pub enum WorkerError {
    #[error("worker failed: {0}")]
    Failed(String),
    #[error("invalid event json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[async_trait]
pub trait Worker: Send + Sync {
    async fn run(
        &self,
        prompt: &str,
        context: WorkerContext,
    ) -> Result<Vec<WorkerEvent>, WorkerError>;

    async fn run_stream(
        &self,
        prompt: &str,
        context: WorkerContext,
    ) -> Result<WorkerEventStream, WorkerError> {
        let events = self.run(prompt, context).await?;
        Ok(Box::pin(tokio_stream::iter(events.into_iter().map(Ok))))
    }
}

pub async fn collect_worker_stream(
    mut stream: WorkerEventStream,
) -> Result<Vec<WorkerEvent>, WorkerError> {
    let mut events = Vec::new();
    while let Some(event) = stream.next().await {
        events.push(event?);
    }
    Ok(events)
}

#[derive(Debug, Clone)]
pub struct MockWorker {
    events: Vec<WorkerEvent>,
}

impl MockWorker {
    pub fn new(events: Vec<WorkerEvent>) -> Self {
        Self { events }
    }

    pub fn fact(description: impl Into<String>) -> Self {
        Self {
            events: vec![WorkerEvent::Done {
                description: description.into(),
                complete: false,
            }],
        }
    }
}

#[async_trait]
impl Worker for MockWorker {
    async fn run(
        &self,
        _prompt: &str,
        _context: WorkerContext,
    ) -> Result<Vec<WorkerEvent>, WorkerError> {
        Ok(self.events.clone())
    }
}

#[derive(Debug, Clone)]
pub struct CommandWorker {
    program: String,
    args: Vec<String>,
    env: BTreeMap<String, String>,
    allow_legacy_output: bool,
}

impl CommandWorker {
    pub fn new(program: impl Into<String>, args: Vec<String>) -> Self {
        Self {
            program: program.into(),
            args,
            env: BTreeMap::new(),
            allow_legacy_output: false,
        }
    }

    pub fn with_env(mut self, env: BTreeMap<String, String>) -> Self {
        self.env = env;
        self
    }

    pub fn with_legacy_output(mut self) -> Self {
        self.allow_legacy_output = true;
        self
    }

    pub fn claude_code(program: Option<String>, args: Vec<String>) -> Self {
        let program = program.unwrap_or_else(|| "claude".to_string());
        if !args.is_empty() {
            let mut args = args;
            ensure_claude_args_disable_webfetch(&mut args);
            return Self::new(program, args);
        }
        Self::new(
            "/bin/sh",
            vec![
                "-lc".to_string(),
                CLAUDE_CODE_DEFAULT_WRAPPER.to_string(),
                "--".to_string(),
                program,
            ],
        )
    }

    pub fn program(&self) -> &str {
        &self.program
    }

    pub fn args(&self) -> &[String] {
        &self.args
    }

    pub fn env(&self) -> &BTreeMap<String, String> {
        &self.env
    }

    fn env_for_context(&self, context: &WorkerContext) -> BTreeMap<String, String> {
        let mut env = self.env.clone();
        env.insert("CAIRN_PROJECT_ID".to_string(), context.project_id.clone());
        if let Some(intent_id) = &context.intent_id {
            env.insert("CAIRN_INTENT_ID".to_string(), intent_id.clone());
        }
        env
    }
}

pub fn claude_args_disable_webfetch(args: &[String]) -> bool {
    args.iter().enumerate().any(|(index, arg)| {
        if let Some(value) = arg
            .strip_prefix("--disallowedTools=")
            .or_else(|| arg.strip_prefix("--disallowed-tools="))
        {
            return comma_list_has_tool(value, "WebFetch");
        }
        matches!(arg.as_str(), "--disallowedTools" | "--disallowed-tools")
            && args
                .get(index + 1)
                .is_some_and(|value| comma_list_has_tool(value, "WebFetch"))
    })
}

pub fn claude_args_allow_webfetch(args: &[String]) -> bool {
    args.iter().enumerate().any(|(index, arg)| {
        if let Some(value) = arg
            .strip_prefix("--allowedTools=")
            .or_else(|| arg.strip_prefix("--allowed-tools="))
        {
            return comma_list_has_tool(value, "WebFetch");
        }
        matches!(arg.as_str(), "--allowedTools" | "--allowed-tools")
            && args
                .get(index + 1)
                .is_some_and(|value| comma_list_has_tool(value, "WebFetch"))
    })
}

fn ensure_claude_args_disable_webfetch(args: &mut Vec<String>) {
    for index in 0..args.len() {
        let arg = args[index].clone();
        if let Some((prefix, value)) = arg
            .strip_prefix("--disallowedTools=")
            .map(|value| ("--disallowedTools=", value))
            .or_else(|| {
                arg.strip_prefix("--disallowed-tools=")
                    .map(|value| ("--disallowed-tools=", value))
            })
        {
            if !comma_list_has_tool(value, "WebFetch") {
                args[index] = append_comma_list_tool(prefix, value, "WebFetch");
            }
            return;
        }
        if matches!(arg.as_str(), "--disallowedTools" | "--disallowed-tools") {
            if let Some(value) = args.get_mut(index + 1) {
                if !comma_list_has_tool(value, "WebFetch") {
                    *value = append_comma_list_value(value, "WebFetch");
                }
            } else {
                args.push("WebFetch".to_string());
            }
            return;
        }
    }
    args.push("--disallowedTools".to_string());
    args.push("WebFetch".to_string());
}

fn comma_list_has_tool(value: &str, tool: &str) -> bool {
    value.split(',').any(|item| item.trim() == tool)
}

fn append_comma_list_tool(prefix: &str, value: &str, tool: &str) -> String {
    format!("{prefix}{}", append_comma_list_value(value, tool))
}

fn append_comma_list_value(value: &str, tool: &str) -> String {
    if value.trim().is_empty() {
        tool.to_string()
    } else {
        format!("{value},{tool}")
    }
}

const CLAUDE_CODE_DEFAULT_WRAPPER: &str = r#"set -eu
claude_bin="$1"
if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
  export ANTHROPIC_API_KEY="${ANTHROPIC_AUTH_TOKEN:-}"
fi
exec "$claude_bin" \
  --bare \
  --print \
  --input-format text \
  --output-format text \
  --no-session-persistence \
  --permission-mode bypassPermissions \
  --disallowedTools WebFetch \
  --model "$ANTHROPIC_MODEL"
"#;

#[async_trait]
impl Worker for CommandWorker {
    async fn run(
        &self,
        prompt: &str,
        context: WorkerContext,
    ) -> Result<Vec<WorkerEvent>, WorkerError> {
        collect_worker_stream(self.run_stream(prompt, context).await?).await
    }

    async fn run_stream(
        &self,
        prompt: &str,
        context: WorkerContext,
    ) -> Result<WorkerEventStream, WorkerError> {
        let worker = self.clone();
        let prompt = prompt.to_string();
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        tokio::spawn(async move {
            if let Err(error) = worker
                .run_command_streaming(prompt, context, tx.clone())
                .await
            {
                let _ = tx.send(Err(error)).await;
            }
        });
        Ok(Box::pin(ReceiverStream::new(rx)))
    }
}

impl CommandWorker {
    async fn run_command_streaming(
        self,
        prompt: String,
        context: WorkerContext,
        tx: tokio::sync::mpsc::Sender<Result<WorkerEvent, WorkerError>>,
    ) -> Result<(), WorkerError> {
        let mut command = Command::new(&self.program);
        command
            .args(&self.args)
            .envs(self.env_for_context(&context))
            .kill_on_drop(true)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = command.spawn()?;

        let mut stdin_task = child.stdin.take().map(|mut stdin| {
            tokio::spawn(async move {
                stdin.write_all(prompt.as_bytes()).await?;
                stdin.shutdown().await
            })
        });

        let stdout = child.stdout.take().ok_or_else(|| {
            WorkerError::Failed(format!("{} stdout pipe was not captured", self.program))
        })?;
        let stderr = child.stderr.take().ok_or_else(|| {
            WorkerError::Failed(format!("{} stderr pipe was not captured", self.program))
        })?;
        let stderr_task = tokio::spawn(async move {
            let mut stderr_text = String::new();
            let mut stderr = BufReader::new(stderr);
            stderr.read_to_string(&mut stderr_text).await?;
            Ok::<_, std::io::Error>(stderr_text)
        });

        let mut stdout = BufReader::new(stdout).lines();
        let mut raw_stdout = String::new();
        let mut streamed_events = 0usize;
        let mut fallback_mode = false;
        loop {
            let line = tokio::select! {
                _ = tx.closed() => {
                    if let Some(stdin_task) = stdin_task.take() {
                        stdin_task.abort();
                    }
                    stderr_task.abort();
                    let _ = child.kill().await;
                    return Ok(());
                }
                line = stdout.next_line() => line?,
            };
            let Some(line) = line else {
                break;
            };
            raw_stdout.push_str(&line);
            raw_stdout.push('\n');
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if fallback_mode {
                continue;
            }
            match serde_json::from_str::<WorkerEvent>(trimmed) {
                Ok(event) => {
                    streamed_events += 1;
                    if tx.send(Ok(event)).await.is_err() {
                        return Ok(());
                    }
                }
                Err(error) if looks_like_worker_event_line(trimmed) => return Err(error.into()),
                Err(error) if streamed_events == 0 => {
                    let _ = error;
                    fallback_mode = true;
                }
                Err(error) => {
                    let _ = tx.send(Err(error.into())).await;
                    fallback_mode = true;
                }
            }
        }

        let status = child.wait().await?;
        if let Some(stdin_task) = stdin_task {
            match stdin_task.await {
                Ok(Ok(())) => {}
                Ok(Err(error))
                    if status.success() && error.kind() == std::io::ErrorKind::BrokenPipe => {}
                Ok(Err(error)) => return Err(error.into()),
                Err(error) => {
                    return Err(WorkerError::Failed(format!("stdin task failed: {error}")))
                }
            }
        }
        let stderr = stderr_task
            .await
            .map_err(|error| WorkerError::Failed(format!("stderr task failed: {error}")))??;
        if !status.success() {
            return Err(WorkerError::Failed(format!(
                "{} exited with {}: {}",
                self.program,
                status,
                stderr.trim()
            )));
        }
        if fallback_mode && streamed_events == 0 {
            if !self.allow_legacy_output {
                let preview: String = raw_stdout
                    .lines()
                    .filter(|line| !line.trim().is_empty())
                    .take(20)
                    .collect::<Vec<_>>()
                    .join("\n");
                return Err(WorkerError::Failed(format!(
                    "worker stdout must be NDJSON WorkerEvent lines; non-event stdout is not accepted. First lines:\n{preview}"
                )));
            }
            for event in parse_worker_output(&raw_stdout)? {
                if tx.send(Ok(event)).await.is_err() {
                    return Ok(());
                }
            }
        }
        Ok(())
    }
}

// --- ToolWorker ---

/// A worker that runs binary exploitation tools against a target file.
///
/// The target file path is extracted from the worker prompt (intent description).
/// Each configured tool is run against the target, and its findings are
/// aggregated into [`WorkerEvent::Done`] facts.
#[derive(Clone)]
pub struct ToolWorker {
    tools: Vec<Arc<dyn tools::Tool>>,
    /// Optional base directory for relative paths
    workdir: Option<PathBuf>,
}

impl std::fmt::Debug for ToolWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = self.tools.iter().map(|t| t.name()).collect();
        f.debug_struct("ToolWorker")
            .field("tools", &names)
            .field("workdir", &self.workdir)
            .finish()
    }
}

impl ToolWorker {
    /// Create a new ToolWorker with the given tools.
    pub fn new(tools: Vec<Arc<dyn tools::Tool>>) -> Self {
        Self {
            tools,
            workdir: None,
        }
    }

    /// Set the working directory for resolving relative paths.
    pub fn with_workdir(mut self, workdir: PathBuf) -> Self {
        self.workdir = Some(workdir);
        self
    }

    /// Get the names of configured tools.
    pub fn tool_names(&self) -> Vec<&str> {
        self.tools.iter().map(|t| t.name()).collect()
    }

    /// Extract a target file path from the prompt text.
    ///
    /// Looks for:
    /// 1. Absolute paths (starting with `/`)
    /// 2. Paths mentioned after "target:", "file:", "binary:", "analyze "
    /// 3. Paths in the Current Intent Description section
    fn extract_target_from_prompt(&self, prompt: &str) -> Option<PathBuf> {
        // Look for patterns like:
        //   target: /path/to/binary
        //   file: /path/to/binary
        //   binary: /path/to/binary
        //   analyze /path/to/binary
        //   Current Intent Description ... /path/to/binary

        let patterns = [
            "target:",
            "Target:",
            "TARGET:",
            "file:",
            "File:",
            "FILE:",
            "binary:",
            "Binary:",
            "BINARY:",
            "analyze ",
            "Analyze ",
            "ANALYZE ",
            "analysis of ",
            "Analysis of ",
        ];

        for pattern in &patterns {
            // Require a word boundary before the pattern to avoid matching
            // "file:" inside "profile:" or "Makefile:".
            if let Some(pos) = prompt.find(pattern) {
                if pos > 0 {
                    let before = prompt.as_bytes()[pos - 1];
                    if before.is_ascii_alphanumeric() {
                        continue;
                    }
                }
                let after = &prompt[pos + pattern.len()..];
                let after = after.trim();

                // Extract the first "word" or quoted string
                if after.starts_with('"') || after.starts_with('\'') {
                    if let Some(quote) = after.chars().next() {
                        if let Some(end) = after[1..].find(quote) {
                            let path = &after[1..end + 1];
                            return self.resolve_path(path);
                        }
                    }
                }

                // Extract until whitespace, newline, or comma (NOT dot — paths have extensions)
                let end = after
                    .find(|c: char| c.is_whitespace() || c == ',' || c == '\n')
                    .unwrap_or(after.len());
                let path = &after[..end];
                // Trim trailing punctuation that isn't a path character
                let path = path.trim_end_matches(['.', ';', ')']);
                if !path.is_empty() {
                    return self.resolve_path(path);
                }
            }
        }

        // Fallback: look for any absolute path in the prompt
        for word in prompt.split_whitespace() {
            let word = word
                .trim_matches(|c: char| c == '"' || c == '\'' || c == '`' || c == ',' || c == '.');
            if word.starts_with('/') && word.len() > 2 {
                // Check it looks like a real path (contains at least one directory separator after the first)
                if word[1..].contains('/')
                    || word.ends_with(".so")
                    || word.ends_with(".elf")
                    || word.ends_with(".bin")
                    || word.ends_with(".out")
                {
                    return Some(PathBuf::from(word));
                }
            }
        }

        None
    }

    fn resolve_path(&self, path: &str) -> Option<PathBuf> {
        let path = path.trim_matches(|c: char| c == '"' || c == '\'' || c == '`');
        // Strip leading ./ for cleaner resolution
        let path = path.strip_prefix("./").unwrap_or(path);
        let path_buf = PathBuf::from(path);

        if path_buf.is_absolute() {
            Some(path_buf)
        } else if let Some(workdir) = &self.workdir {
            Some(workdir.join(path_buf))
        } else {
            // Try current directory
            Some(std::env::current_dir().ok()?.join(path_buf))
        }
    }
}

#[async_trait]
impl Worker for ToolWorker {
    async fn run(
        &self,
        prompt: &str,
        context: WorkerContext,
    ) -> Result<Vec<WorkerEvent>, WorkerError> {
        let _ = context; // ToolWorker doesn't need context beyond prompt
        let mut events: Vec<WorkerEvent> = Vec::new();

        // Try to find target path in the prompt
        let target = match self.extract_target_from_prompt(prompt) {
            Some(path) => path,
            None => {
                // No target found — report this as a finding
                events.push(WorkerEvent::Done {
                    description: format!(
                        "ToolWorker [{}]: no target file path found in prompt. Configured tools: {}",
                        self.tool_names().join(", "),
                        self.tool_names().join(", ")
                    ),
                    complete: false,
                });
                return Ok(events);
            }
        };

        // Run each tool against the target.
        // Note: we intentionally do NOT check target.exists() here to avoid
        // a TOCTOU race — tools will report file-not-found via their own
        // error handling.
        for tool in &self.tools {
            match tool.run(&target).await {
                Ok(tool_events) => {
                    events.extend(tool_events);
                }
                Err(error) => {
                    events.push(WorkerEvent::Error {
                        message: format!(
                            "ToolWorker[{}] failed on {}: {}",
                            tool.name(),
                            target.display(),
                            error
                        ),
                    });
                }
            }
        }

        if events.is_empty() {
            events.push(WorkerEvent::Done {
                description: format!(
                    "ToolWorker: tools {} ran against {} but produced no findings",
                    self.tool_names().join(", "),
                    target.display()
                ),
                complete: false,
            });
        }

        Ok(events)
    }
}

use std::sync::Arc;

pub fn parse_worker_output(input: &str) -> Result<Vec<WorkerEvent>, WorkerError> {
    if input
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .any(looks_like_worker_event_line)
    {
        return parse_ndjson_events(input);
    }
    if let Ok(events) = parse_ndjson_events(input) {
        if !events.is_empty() {
            return Ok(events);
        }
    }
    if let Some(json) = extract_json_object(input) {
        return legacy_json_to_events(&json);
    }
    let text = input.trim();
    if text.is_empty() {
        Ok(Vec::new())
    } else {
        Ok(vec![WorkerEvent::Done {
            description: text.to_string(),
            complete: false,
        }])
    }
}

pub fn parse_ndjson_events(input: &str) -> Result<Vec<WorkerEvent>, WorkerError> {
    let mut events = Vec::new();
    for line in input.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<WorkerEvent>(line) {
            Ok(event) => events.push(event),
            Err(error) => {
                // If this line looks like a WorkerEvent but failed to parse,
                // that's a real error (unknown fields, invalid enum tag, etc.)
                if looks_like_worker_event_line(line) {
                    return Err(error.into());
                }
                // Otherwise, skip non-JSON lines (tool output, prose, etc.)
                // This handles mixed output when the model uses tools before NDJSON.
            }
        }
    }
    Ok(events)
}

pub fn looks_like_worker_event_line(line: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(line)
        .ok()
        .and_then(|value| {
            value
                .get("event")
                .and_then(serde_json::Value::as_str)
                .map(|_| ())
        })
        .is_some()
}

fn legacy_json_to_events(input: &str) -> Result<Vec<WorkerEvent>, WorkerError> {
    let value: serde_json::Value = serde_json::from_str(input)?;
    if value
        .get("accepted")
        .and_then(serde_json::Value::as_bool)
        .is_some_and(|accepted| !accepted)
    {
        let reason = value
            .get("reason")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("worker rejected task");
        return Ok(vec![WorkerEvent::Error {
            message: reason.to_string(),
        }]);
    }
    let Some(data) = value.get("data") else {
        return Ok(Vec::new());
    };
    let mut events = Vec::new();
    if let Some(intents) = data.get("intents").and_then(serde_json::Value::as_array) {
        for intent in intents {
            if let Some(description) = intent
                .get("description")
                .and_then(serde_json::Value::as_str)
            {
                events.push(WorkerEvent::Intent {
                    sources: legacy_sources(intent),
                    description: description.to_string(),
                });
            }
        }
    }
    if let Some(complete) = data.get("complete") {
        if let Some(description) = complete
            .get("description")
            .and_then(serde_json::Value::as_str)
        {
            let sources = legacy_sources(complete);
            if !sources.is_empty() {
                events.push(WorkerEvent::Complete {
                    sources,
                    description: description.to_string(),
                });
            }
        }
    }
    if let Some(fact) = data.get("fact") {
        if let Some(description) = fact.get("description").and_then(serde_json::Value::as_str) {
            events.push(WorkerEvent::Done {
                description: description.to_string(),
                complete: data.get("complete").is_some(),
            });
        }
    } else if let Some(description) = data.get("description").and_then(serde_json::Value::as_str) {
        events.push(WorkerEvent::Done {
            description: description.to_string(),
            complete: false,
        });
    }
    Ok(events)
}

fn legacy_sources(value: &serde_json::Value) -> Vec<String> {
    value
        .get("sources")
        .or_else(|| value.get("from"))
        .and_then(serde_json::Value::as_array)
        .map(|sources| {
            sources
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn extract_json_object(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut start = None;
    let mut depth = 0_i32;
    let mut in_string = false;
    let mut escaped = false;
    for (idx, byte) in bytes.iter().enumerate() {
        if start.is_none() {
            if *byte == b'{' {
                start = Some(idx);
                depth = 1;
            }
            continue;
        }
        if escaped {
            escaped = false;
            continue;
        }
        match *byte {
            b'\\' if in_string => escaped = true,
            b'"' => in_string = !in_string,
            b'{' if !in_string => depth += 1,
            b'}' if !in_string => {
                depth -= 1;
                if depth == 0 {
                    let start = start?;
                    return Some(input[start..=idx].to_string());
                }
            }
            _ => {}
        }
    }
    None
}

pub fn encode_ndjson_events(events: &[WorkerEvent]) -> Result<String, WorkerError> {
    let mut output = String::new();
    for event in events {
        output.push_str(&serde_json::to_string(event)?);
        output.push('\n');
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ndjson_round_trips_worker_events() {
        let events = vec![
            WorkerEvent::Thinking { text: "hmm".into() },
            WorkerEvent::Done {
                description: "fact".into(),
                complete: false,
            },
        ];
        let encoded = encode_ndjson_events(&events).expect("encode");
        let decoded = parse_ndjson_events(&encoded).expect("decode");
        assert_eq!(decoded, events);
    }

    #[test]
    fn ndjson_rejects_unknown_event_fields() {
        let output = r#"{"event":"done","description":"fact","complete":false,"extra":1}"#;
        let error = parse_ndjson_events(output).expect_err("unknown event field should fail");
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn worker_output_rejects_unknown_event_fields() {
        let output = r#"{"event":"done","description":"fact","complete":false,"extra":1}"#;
        let error = parse_worker_output(output).expect_err("unknown event field should fail");
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn legacy_reason_json_converts_to_intent_event() {
        let output = r#"{"accepted":true,"data":{"intents":[{"sources":["f001"],"description":"try another path"}]}}"#;
        let events = parse_worker_output(output).expect("parse");
        assert_eq!(
            events,
            vec![WorkerEvent::Intent {
                sources: vec!["f001".to_string()],
                description: "try another path".to_string(),
            }]
        );
    }

    #[test]
    fn legacy_bootstrap_json_converts_to_done_event() {
        let output = r#"```json
{"accepted":true,"data":{"fact":{"description":"confirmed fact"},"complete":{"description":"goal satisfied"}}}
```"#;
        let events = parse_worker_output(output).expect("parse");
        assert_eq!(
            events,
            vec![WorkerEvent::Done {
                description: "confirmed fact".to_string(),
                complete: true,
            }]
        );
    }

    #[test]
    fn legacy_complete_without_sources_or_fact_is_ignored() {
        let output = r#"{"accepted":true,"data":{"complete":{"description":"unsupported completion without sources"}}}"#;
        let events = parse_worker_output(output).expect("parse");
        assert!(events.is_empty());
    }

    #[test]
    fn legacy_complete_with_sources_converts_to_complete_event() {
        let output = r#"{"accepted":true,"data":{"complete":{"sources":["f001"],"description":"goal satisfied"}}}"#;
        let events = parse_worker_output(output).expect("parse");
        assert_eq!(
            events,
            vec![WorkerEvent::Complete {
                sources: vec!["f001".to_string()],
                description: "goal satisfied".to_string(),
            }]
        );
    }

    #[test]
    fn legacy_bootstrap_fact_only_json_converts_to_noncomplete_done_event() {
        let output =
            r#"{"accepted":true,"data":{"fact":{"description":"partial confirmed fact"}}}"#;
        let events = parse_worker_output(output).expect("parse");
        assert_eq!(
            events,
            vec![WorkerEvent::Done {
                description: "partial confirmed fact".to_string(),
                complete: false,
            }]
        );
    }

    #[test]
    fn prose_output_is_rescued_as_description_fact() {
        let events = parse_worker_output("confirmed useful observation").expect("parse");
        assert_eq!(
            events,
            vec![WorkerEvent::Done {
                description: "confirmed useful observation".to_string(),
                complete: false,
            }]
        );
    }

    #[tokio::test]
    async fn command_worker_reads_ndjson_from_stdout() {
        let worker = CommandWorker::new(
            "sh",
            vec![
                "-c".to_string(),
                "cat >/dev/null; printf '%s\n' '{\"event\":\"done\",\"description\":\"from command\",\"complete\":false}'"
                    .to_string(),
            ],
        );
        let events = worker
            .run(
                "prompt",
                WorkerContext {
                    project_id: "proj_001".into(),
                    intent_id: Some("i001".into()),
                },
            )
            .await
            .expect("run worker");
        assert_eq!(
            events,
            vec![WorkerEvent::Done {
                description: "from command".into(),
                complete: false,
            }]
        );
    }

    #[tokio::test]
    async fn command_worker_rejects_unknown_event_fields() {
        let worker = CommandWorker::new(
            "sh",
            vec![
                "-c".to_string(),
                "cat >/dev/null; printf '%s\n' '{\"event\":\"done\",\"description\":\"from command\",\"complete\":false,\"extra\":1}'"
                    .to_string(),
            ],
        );
        let error = worker
            .run(
                "prompt",
                WorkerContext {
                    project_id: "proj_001".into(),
                    intent_id: Some("i001".into()),
                },
            )
            .await
            .expect_err("unknown event field should fail");
        assert!(error.to_string().contains("unknown field"));
    }

    #[tokio::test]
    async fn command_worker_rejects_non_event_stdout_by_default() {
        let worker = CommandWorker::new(
            "sh",
            vec![
                "-c".to_string(),
                "cat >/dev/null; printf '%s\n' 'plain prose observation'".to_string(),
            ],
        );
        let error = worker
            .run(
                "prompt",
                WorkerContext {
                    project_id: "proj_001".into(),
                    intent_id: Some("i001".into()),
                },
            )
            .await
            .expect_err("non-event stdout should fail by default");
        assert!(error.to_string().contains("must be NDJSON WorkerEvent"));
    }

    #[tokio::test]
    async fn command_worker_can_opt_into_legacy_output_rescue() {
        let worker = CommandWorker::new(
            "sh",
            vec![
                "-c".to_string(),
                "cat >/dev/null; printf '%s\n' 'legacy prose observation'".to_string(),
            ],
        )
        .with_legacy_output();
        let events = worker
            .run(
                "prompt",
                WorkerContext {
                    project_id: "proj_001".into(),
                    intent_id: Some("i001".into()),
                },
            )
            .await
            .expect("legacy rescue");
        assert_eq!(
            events,
            vec![WorkerEvent::Done {
                description: "legacy prose observation".into(),
                complete: false,
            }]
        );
    }

    #[tokio::test]
    async fn command_worker_passes_configured_environment() {
        let mut env = BTreeMap::new();
        env.insert(
            "CAIRN_WORKER_TEST_VALUE".to_string(),
            "from-env".to_string(),
        );
        let worker = CommandWorker::new(
            "sh",
            vec![
                "-c".to_string(),
                "cat >/dev/null; printf '{\"event\":\"done\",\"description\":\"%s\",\"complete\":false}\\n' \"$CAIRN_WORKER_TEST_VALUE\"".to_string(),
            ],
        )
        .with_env(env);
        let events = worker
            .run(
                "prompt",
                WorkerContext {
                    project_id: "proj_001".into(),
                    intent_id: Some("i001".into()),
                },
            )
            .await
            .expect("run worker");
        assert_eq!(
            events,
            vec![WorkerEvent::Done {
                description: "from-env".into(),
                complete: false,
            }]
        );
    }

    #[tokio::test]
    async fn command_worker_streams_ndjson_before_process_exit() {
        let worker = CommandWorker::new(
            "sh",
            vec![
                "-c".to_string(),
                "cat >/dev/null; printf '%s\n' '{\"event\":\"message\",\"text\":\"first\"}'; sleep 1; printf '%s\n' '{\"event\":\"done\",\"description\":\"last\",\"complete\":false}'"
                    .to_string(),
            ],
        );
        let mut stream = worker
            .run_stream(
                "prompt",
                WorkerContext {
                    project_id: "proj_001".into(),
                    intent_id: Some("i001".into()),
                },
            )
            .await
            .expect("stream worker");
        let started = std::time::Instant::now();
        let first = stream
            .next()
            .await
            .expect("first event")
            .expect("first event ok");
        assert!(started.elapsed() < std::time::Duration::from_millis(500));
        assert_eq!(
            first,
            WorkerEvent::Message {
                text: "first".to_string()
            }
        );
        let rest = collect_worker_stream(stream).await.expect("collect rest");
        assert_eq!(
            rest,
            vec![WorkerEvent::Done {
                description: "last".to_string(),
                complete: false,
            }]
        );
    }

    #[tokio::test]
    async fn command_worker_streams_stdout_while_prompt_pipe_is_unread() {
        let worker = CommandWorker::new(
            "sh",
            vec![
                "-c".to_string(),
                "printf '%s\n' '{\"event\":\"message\",\"text\":\"ready\"}'; sleep 1".to_string(),
            ],
        );
        let mut stream = worker
            .run_stream(
                &"x".repeat(1024 * 1024),
                WorkerContext {
                    project_id: "proj_001".into(),
                    intent_id: Some("i001".into()),
                },
            )
            .await
            .expect("stream worker");
        let started = std::time::Instant::now();
        let first = stream
            .next()
            .await
            .expect("first event")
            .expect("first event ok");
        assert!(started.elapsed() < std::time::Duration::from_millis(500));
        assert_eq!(
            first,
            WorkerEvent::Message {
                text: "ready".to_string()
            }
        );
        let rest = collect_worker_stream(stream).await.expect("collect rest");
        assert!(rest.is_empty());
    }

    #[tokio::test]
    async fn command_worker_passes_context_environment() {
        let worker = CommandWorker::new(
            "sh",
            vec![
                "-c".to_string(),
                "cat >/dev/null; printf '{\"event\":\"done\",\"description\":\"%s:%s\",\"complete\":false}\\n' \"$CAIRN_PROJECT_ID\" \"$CAIRN_INTENT_ID\"".to_string(),
            ],
        );
        let events = worker
            .run(
                "prompt",
                WorkerContext {
                    project_id: "proj_123".into(),
                    intent_id: Some("i777".into()),
                },
            )
            .await
            .expect("run worker");
        assert_eq!(
            events,
            vec![WorkerEvent::Done {
                description: "proj_123:i777".into(),
                complete: false,
            }]
        );
    }

    #[tokio::test]
    async fn dropping_command_worker_stream_kills_child_process() {
        let pid_path = std::env::temp_dir().join(format!(
            "clairvoyant-worker-child-{}-{}.pid",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or_default()
        ));
        let worker = CommandWorker::new(
            "sh",
            vec![
                "-c".to_string(),
                format!(
                    "printf '%s' $$ > '{}'; cat >/dev/null; sleep 60",
                    pid_path.display()
                ),
            ],
        );
        let stream = worker
            .run_stream(
                "prompt",
                WorkerContext {
                    project_id: "proj_001".into(),
                    intent_id: Some("i001".into()),
                },
            )
            .await
            .expect("stream worker");

        for _ in 0..50 {
            if pid_path.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let pid = std::fs::read_to_string(&pid_path)
            .expect("pid file")
            .trim()
            .to_string();
        assert!(
            process_is_alive(&pid),
            "child should be running before drop"
        );
        drop(stream);
        for _ in 0..50 {
            if !process_is_alive(&pid) {
                let _ = std::fs::remove_file(&pid_path);
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let _ = std::process::Command::new("kill")
            .arg("-9")
            .arg(&pid)
            .status();
        let _ = std::fs::remove_file(&pid_path);
        panic!("child process {pid} was still running after stream drop");
    }

    fn process_is_alive(pid: &str) -> bool {
        std::process::Command::new("kill")
            .arg("-0")
            .arg(pid)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }

    #[test]
    fn claude_code_adapter_has_expected_defaults() {
        let claude = CommandWorker::claude_code(None, Vec::new());
        assert_eq!(claude.program(), "/bin/sh");
        assert_eq!(claude.args().first().map(String::as_str), Some("-lc"));
        assert!(claude.args()[1].contains("--model \"$ANTHROPIC_MODEL\""));
        assert!(claude.args()[1].contains("--input-format text"));
        assert!(claude.args()[1].contains("--permission-mode bypassPermissions"));
        assert!(claude.args()[1].contains("--disallowedTools WebFetch"));
        assert_eq!(claude.args().last().map(String::as_str), Some("claude"));

        let custom_claude =
            CommandWorker::claude_code(None, vec!["--print".to_string(), "custom".to_string()]);
        assert_eq!(custom_claude.program(), "claude");
        assert_eq!(
            custom_claude.args(),
            ["--print", "custom", "--disallowedTools", "WebFetch"]
        );
    }

    #[test]
    fn claude_code_adapter_preserves_custom_webfetch_deny_args() {
        let claude = CommandWorker::claude_code(
            None,
            vec![
                "--print".to_string(),
                "--disallowed-tools=WebFetch,Bash".to_string(),
            ],
        );
        assert_eq!(
            claude.args(),
            ["--print", "--disallowed-tools=WebFetch,Bash"]
        );
        assert!(claude_args_disable_webfetch(claude.args()));
    }

    #[test]
    fn claude_code_adapter_merges_webfetch_into_existing_disallowed_tools_args() {
        let split = CommandWorker::claude_code(
            None,
            vec!["--disallowedTools".to_string(), "Bash".to_string()],
        );
        assert_eq!(split.args(), ["--disallowedTools", "Bash,WebFetch"]);
        assert!(claude_args_disable_webfetch(split.args()));

        let equals = CommandWorker::claude_code(
            None,
            vec!["--disallowed-tools=Bash".to_string(), "--print".to_string()],
        );
        assert_eq!(
            equals.args(),
            ["--disallowed-tools=Bash,WebFetch", "--print"]
        );
        assert!(claude_args_disable_webfetch(equals.args()));
    }

    #[test]
    fn claude_args_detect_explicit_webfetch_allow_lists() {
        assert!(claude_args_allow_webfetch(&[
            "--allowedTools".to_string(),
            "Bash,WebFetch".to_string()
        ]));
        assert!(claude_args_allow_webfetch(&[
            "--allowed-tools=WebFetch,Bash".to_string(),
            "--print".to_string()
        ]));
        assert!(!claude_args_allow_webfetch(&[
            "--allowedTools".to_string(),
            "Bash,Read".to_string()
        ]));
    }

    #[tokio::test]
    async fn claude_code_default_wrapper_passes_prompt_and_model_to_cli() {
        let dir = std::env::temp_dir().join(format!(
            "clairvoyant-claude-wrapper-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or_default()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let fake_claude = dir.join("claude");
        std::fs::write(
            &fake_claude,
            r#"#!/bin/sh
set -eu
test "$1" = "--bare"
test "$2" = "--print"
test "$3" = "--input-format"
test "$4" = "text"
test "$5" = "--output-format"
test "$6" = "text"
test "$7" = "--no-session-persistence"
test "$8" = "--permission-mode"
test "$9" = "bypassPermissions"
test "${10}" = "--disallowedTools"
test "${11}" = "WebFetch"
test "${12}" = "--model"
test "${13}" = "claude-test"
test "${ANTHROPIC_API_KEY}" = "token-test"
prompt="$(cat)"
test "$prompt" = "wrapped prompt"
printf '%s\n' '{"event":"done","description":"claude wrapper ok","complete":false}'
"#,
        )
        .expect("write fake claude");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&fake_claude, std::fs::Permissions::from_mode(0o755))
                .expect("chmod fake claude");
        }

        let mut env = BTreeMap::new();
        env.insert("ANTHROPIC_MODEL".to_string(), "claude-test".to_string());
        env.insert("ANTHROPIC_API_KEY".to_string(), "token-test".to_string());
        let worker =
            CommandWorker::claude_code(Some(fake_claude.to_string_lossy().to_string()), Vec::new())
                .with_env(env);
        let events = worker
            .run(
                "wrapped prompt",
                WorkerContext {
                    project_id: "proj_001".into(),
                    intent_id: Some("i001".into()),
                },
            )
            .await
            .expect("run claude wrapper");
        assert_eq!(
            events,
            vec![WorkerEvent::Done {
                description: "claude wrapper ok".into(),
                complete: false,
            }]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn claude_code_default_wrapper_rejects_plain_text_stdout() {
        let dir = std::env::temp_dir().join(format!(
            "clairvoyant-claude-wrapper-plain-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or_default()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let fake_claude = dir.join("claude");
        std::fs::write(
            &fake_claude,
            r#"#!/bin/sh
cat >/dev/null
printf '%s\n' 'plain text from claude'
"#,
        )
        .expect("write fake claude");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&fake_claude, std::fs::Permissions::from_mode(0o755))
                .expect("chmod fake claude");
        }

        let mut env = BTreeMap::new();
        env.insert("ANTHROPIC_MODEL".to_string(), "claude-test".to_string());
        env.insert("ANTHROPIC_API_KEY".to_string(), "token-test".to_string());
        let worker =
            CommandWorker::claude_code(Some(fake_claude.to_string_lossy().to_string()), Vec::new())
                .with_env(env);
        let error = worker
            .run(
                "wrapped prompt",
                WorkerContext {
                    project_id: "proj_001".into(),
                    intent_id: Some("i001".into()),
                },
            )
            .await
            .expect_err("plain text claude stdout should be rejected");
        assert!(error.to_string().contains("must be NDJSON WorkerEvent"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- ToolWorker tests ---

    /// A mock tool for testing ToolWorker.
    #[derive(Debug, Clone)]
    struct MockTool {
        name: &'static str,
        desc: &'static str,
        events: Vec<WorkerEvent>,
    }

    impl MockTool {
        fn new(name: &'static str, events: Vec<WorkerEvent>) -> Self {
            Self {
                name,
                desc: "mock tool for testing",
                events,
            }
        }
    }

    #[async_trait]
    impl tools::Tool for MockTool {
        fn name(&self) -> &str {
            self.name
        }

        fn description(&self) -> &str {
            self.desc
        }

        fn required_binaries(&self) -> Vec<&str> {
            vec![]
        }

        async fn run(
            &self,
            _target: &std::path::Path,
        ) -> Result<Vec<WorkerEvent>, tools::ToolError> {
            Ok(self.events.clone())
        }
    }

    #[test]
    fn tool_worker_extracts_absolute_target_from_prompt() {
        let tool: Arc<dyn tools::Tool> = Arc::new(MockTool::new(
            "mock",
            vec![WorkerEvent::Done {
                description: "mock finding".to_string(),
                complete: false,
            }],
        ));
        let worker = ToolWorker::new(vec![tool]);

        // Prompt with absolute path
        let prompt = "Current Intent Description\nanalyze /usr/bin/vuln_binary for security issues";
        let target = worker.extract_target_from_prompt(prompt);
        assert!(target.is_some(), "should extract target path");
        assert_eq!(
            target.unwrap(),
            std::path::PathBuf::from("/usr/bin/vuln_binary")
        );
    }

    #[test]
    fn tool_worker_extracts_target_with_file_prefix() {
        let tool: Arc<dyn tools::Tool> = Arc::new(MockTool::new(
            "mock",
            vec![WorkerEvent::Done {
                description: "mock finding".to_string(),
                complete: false,
            }],
        ));
        let worker = ToolWorker::new(vec![tool]);

        let prompt = "Task: analyze the binary\nfile: /home/user/target.elf\nother context...";
        let target = worker.extract_target_from_prompt(prompt);
        assert!(target.is_some());
        assert_eq!(
            target.unwrap(),
            std::path::PathBuf::from("/home/user/target.elf")
        );
    }

    #[test]
    fn tool_worker_extracts_target_with_binary_prefix() {
        let tool: Arc<dyn tools::Tool> = Arc::new(MockTool::new(
            "mock",
            vec![WorkerEvent::Done {
                description: "mock".to_string(),
                complete: false,
            }],
        ));
        let worker = ToolWorker::new(vec![tool]);

        let prompt = "binary: /opt/app/vuln.so\nPerform security analysis";
        let target = worker.extract_target_from_prompt(prompt);
        assert!(target.is_some());
        assert_eq!(
            target.unwrap(),
            std::path::PathBuf::from("/opt/app/vuln.so")
        );
    }

    #[test]
    fn tool_worker_extracts_quoted_target_path() {
        let tool: Arc<dyn tools::Tool> = Arc::new(MockTool::new("mock", vec![]));
        let worker = ToolWorker::new(vec![tool]);

        let prompt = "target: '/tmp/challenge binary/vuln'";
        let target = worker.extract_target_from_prompt(prompt);
        assert_eq!(
            target.expect("quoted target path"),
            std::path::PathBuf::from("/tmp/challenge binary/vuln")
        );
    }

    #[test]
    fn tool_worker_returns_no_target_found_when_prompt_lacks_path() {
        let tool: Arc<dyn tools::Tool> = Arc::new(MockTool::new(
            "mock",
            vec![WorkerEvent::Done {
                description: "mock".to_string(),
                complete: false,
            }],
        ));
        let worker = ToolWorker::new(vec![tool]);

        // Prompt without any file path
        let target = worker.extract_target_from_prompt("just some random text with no paths");
        assert!(
            target.is_none(),
            "should not find target in pathless prompt"
        );
    }

    #[tokio::test]
    async fn tool_worker_reports_no_target_in_prompt() {
        let tool: Arc<dyn tools::Tool> = Arc::new(MockTool::new("mock", vec![]));
        let worker = ToolWorker::new(vec![tool]);

        let events = worker
            .run(
                "random text without any target path",
                WorkerContext {
                    project_id: "proj_001".into(),
                    intent_id: Some("i001".into()),
                },
            )
            .await
            .expect("run tool worker");

        assert_eq!(events.len(), 1);
        match &events[0] {
            WorkerEvent::Done {
                description,
                complete,
            } => {
                assert!(description.contains("no target file path found"));
                assert!(!complete);
            }
            _ => panic!("expected Done event, got {:?}", events[0]),
        }
    }

    #[tokio::test]
    async fn tool_worker_reports_empty_results_when_target_is_missing() {
        let tool: Arc<dyn tools::Tool> = Arc::new(MockTool::new("mock", vec![]));
        let worker = ToolWorker::new(vec![tool]);

        let events = worker
            .run(
                "analyze /nonexistent/path/that/does/not/exist.elf for vulnerabilities",
                WorkerContext {
                    project_id: "proj_001".into(),
                    intent_id: Some("i001".into()),
                },
            )
            .await
            .expect("run tool worker");

        assert_eq!(events.len(), 1);
        match &events[0] {
            WorkerEvent::Done {
                description,
                complete,
            } => {
                // ToolWorker no longer pre-checks file existence (TOCTOU fix).
                // The tools handle missing files via their own error reporting.
                assert!(description.contains("produced no findings"));
                assert!(!complete);
            }
            _ => panic!("expected Done event about no findings, got {:?}", events[0]),
        }
    }

    #[tokio::test]
    async fn tool_worker_aggregates_multiple_tool_results() {
        let tool1: Arc<dyn tools::Tool> = Arc::new(MockTool::new(
            "checksec",
            vec![WorkerEvent::Done {
                description: "checksec: NX enabled, PIE enabled".to_string(),
                complete: false,
            }],
        ));
        let tool2: Arc<dyn tools::Tool> = Arc::new(MockTool::new(
            "strings",
            vec![WorkerEvent::Done {
                description: "strings: found 3 paths".to_string(),
                complete: false,
            }],
        ));

        let worker = ToolWorker::new(vec![tool1, tool2]);
        // Verify tool names
        assert_eq!(worker.tool_names(), vec!["checksec", "strings"]);
    }

    #[test]
    fn tool_worker_debug_format_shows_tool_names() {
        let tool: Arc<dyn tools::Tool> = Arc::new(MockTool::new("checksec", vec![]));
        let worker = ToolWorker::new(vec![tool]);
        let debug_str = format!("{:?}", worker);
        assert!(debug_str.contains("checksec"));
        assert!(debug_str.contains("ToolWorker"));
    }

    #[test]
    fn tool_worker_extracts_target_with_target_colon_prefix() {
        let tool: Arc<dyn tools::Tool> = Arc::new(MockTool::new("mock", vec![]));
        let worker = ToolWorker::new(vec![tool]);

        let prompt = "target: /bin/ls\nPlease analyze this binary";
        let target = worker.extract_target_from_prompt(prompt);
        assert!(target.is_some());
        assert_eq!(target.unwrap(), std::path::PathBuf::from("/bin/ls"));
    }

    #[test]
    fn tool_worker_extracts_relative_path_with_workdir() {
        let tool: Arc<dyn tools::Tool> = Arc::new(MockTool::new("mock", vec![]));
        let worker =
            ToolWorker::new(vec![tool]).with_workdir(std::path::PathBuf::from("/workspace"));

        let prompt = "analyze ./build/output.elf for ROP gadgets";
        let target = worker.extract_target_from_prompt(prompt);
        assert!(target.is_some());
        assert_eq!(
            target.unwrap(),
            std::path::PathBuf::from("/workspace/build/output.elf")
        );
    }
}
