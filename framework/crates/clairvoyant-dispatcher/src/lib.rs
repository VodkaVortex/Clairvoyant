use clairvoyant_core::{
    ClairvoyantRequest, ClairvoyantResponse, CompleteRequest, ConcludeRequest, CreateIntentRequest,
    HeartbeatRequest, ProjectDetail, ProjectStatus, ProjectSummary, ReasonClaimRequest,
    UpdateProjectStatusRequest,
};
use clairvoyant_runtime::{
    ContainerSpec, DockerCliRuntime, ProcessSpec, RuntimeBackend, RuntimeConfig,
};
use clairvoyant_server::ClairvoyantService;
use clairvoyant_workers::{
    collect_worker_stream, looks_like_worker_event_line, parse_worker_output, CommandWorker,
    MockWorker, ToolWorker, Worker, WorkerContext, WorkerEvent, WorkerEventStream,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::Mutex;
use tokio_stream::{wrappers::ReceiverStream, StreamExt};

const DEFAULT_BOOTSTRAP_PROMPT: &str = include_str!("../prompts/default/bootstrap.md");
const DEFAULT_BOOTSTRAP_CONCLUDE_PROMPT: &str =
    include_str!("../prompts/default/bootstrap_conclude.md");
const DEFAULT_REASON_PROMPT: &str = include_str!("../prompts/default/reason.md");
const DEFAULT_EXPLORE_PROMPT: &str = include_str!("../prompts/default/explore.md");
const DEFAULT_EXPLORE_CONCLUDE_PROMPT: &str =
    include_str!("../prompts/default/explore_conclude.md");
const CYBERGYM_BOOTSTRAP_PROMPT: &str = include_str!("../prompts/cybergym/bootstrap.md");
const CYBERGYM_BOOTSTRAP_CONCLUDE_PROMPT: &str =
    include_str!("../prompts/cybergym/bootstrap_conclude.md");
const CYBERGYM_REASON_PROMPT: &str = include_str!("../prompts/cybergym/reason.md");
const CYBERGYM_EXPLORE_PROMPT: &str = include_str!("../prompts/cybergym/explore.md");
const CYBERGYM_EXPLORE_CONCLUDE_PROMPT: &str =
    include_str!("../prompts/cybergym/explore_conclude.md");
const PYTHON_BOOTSTRAP_PROMPT: &str = include_str!("../prompts/python/bootstrap.md");
const PYTHON_BOOTSTRAP_CONCLUDE_PROMPT: &str =
    include_str!("../prompts/python/bootstrap_conclude.md");
const PYTHON_REASON_PROMPT: &str = include_str!("../prompts/python/reason.md");
const PYTHON_EXPLORE_PROMPT: &str = include_str!("../prompts/python/explore.md");
const PYTHON_EXPLORE_CONCLUDE_PROMPT: &str = include_str!("../prompts/python/explore_conclude.md");
const MOCK_BOOTSTRAP_PROMPT: &str = include_str!("../prompts/mock/bootstrap.md");
const MOCK_BOOTSTRAP_CONCLUDE_PROMPT: &str = include_str!("../prompts/mock/bootstrap_conclude.md");
const MOCK_REASON_PROMPT: &str = include_str!("../prompts/mock/reason.md");
const MOCK_EXPLORE_PROMPT: &str = include_str!("../prompts/mock/explore.md");
const MOCK_EXPLORE_CONCLUDE_PROMPT: &str = include_str!("../prompts/mock/explore_conclude.md");

mod config;

pub use config::{
    CompletedAction, ContainerConfig, DispatcherConfig, PhaseTimeoutConfig, ReasonTaskConfig,
    SchedulerRuntimeConfig, TaskConfig, TaskType, WorkerConfig, WorkerKind, WorkerSpec,
};

#[derive(Debug, Error)]
pub enum DispatcherError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("config error: {0}")]
    Config(#[from] serde_yaml::Error),
    #[error("invalid config: {0}")]
    InvalidConfig(String),
    #[error("server error: {0}")]
    Server(#[from] clairvoyant_server::ClairvoyantError),
    #[error("runtime error: {0}")]
    Runtime(#[from] clairvoyant_runtime::RuntimeError),
    #[error("worker error: {0}")]
    Worker(#[from] clairvoyant_workers::WorkerError),
    #[error("worker task join error: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("unexpected server response: {0}")]
    UnexpectedResponse(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupHealthcheckReport {
    pub checked_workers: Vec<String>,
    pub checked_container: bool,
}

pub async fn startup_healthcheck(
    config: &DispatcherConfig,
) -> Result<StartupHealthcheckReport, DispatcherError> {
    let mut checked_workers = Vec::new();
    let has_container = config.container.is_some();
    let worker_configs = worker_configs_for_healthcheck(config)?;

    for (name, worker_config) in &worker_configs {
        if !has_container {
            if let Some(program) = host_worker_program(worker_config) {
                ensure_executable_available(&program).map_err(|message| {
                    DispatcherError::InvalidConfig(format!("worker {name} {message}"))
                })?;
            }
            ensure_host_worker_capabilities(worker_config).map_err(|message| {
                DispatcherError::InvalidConfig(format!("worker {name} {message}"))
            })?;
        }
        checked_workers.push(name.clone());
    }

    if let Some(runtime_config) = config.runtime_config() {
        ensure_executable_available("docker").map_err(|message| {
            DispatcherError::InvalidConfig(format!("container runtime {message}"))
        })?;
        let runtime = DockerCliRuntime::new(runtime_config.clone());
        let image = runtime_config
            .image
            .clone()
            .filter(|image| !image.trim().is_empty())
            .ok_or_else(|| {
                DispatcherError::InvalidConfig("container image must not be empty".to_string())
            })?;
        let timeout = Duration::from_secs(config.runtime.healthcheck_timeout);
        tokio::time::timeout(
            timeout,
            runtime.run_docker_capture(vec!["image".into(), "inspect".into(), image.clone()], None),
        )
        .await
        .map_err(|_| {
            DispatcherError::InvalidConfig(format!(
                "container runtime healthcheck timed out after {}s",
                config.runtime.healthcheck_timeout
            ))
        })??;
        for (name, worker_config) in &worker_configs {
            let Some(probe) = container_worker_probe(worker_config) else {
                continue;
            };
            tokio::time::timeout(
                timeout,
                runtime.run_docker_capture(container_worker_probe_args(&image, &probe), None),
            )
            .await
            .map_err(|_| {
                DispatcherError::InvalidConfig(format!(
                    "container worker {name} executable healthcheck timed out after {}s",
                    config.runtime.healthcheck_timeout
                ))
            })?
            .map_err(|error| {
                DispatcherError::InvalidConfig(format!(
                    "container worker {name} executable healthcheck failed: {error}"
                ))
            })?;
        }
    }

    Ok(StartupHealthcheckReport {
        checked_workers,
        checked_container: has_container,
    })
}

pub fn worker_from_config(config: &DispatcherConfig) -> Result<Arc<dyn Worker>, DispatcherError> {
    let worker_config = config.primary_worker_config()?;
    let mut env = config.common_env.clone();
    env.extend(worker_config.env().clone());
    build_worker(
        &worker_config,
        config.runtime_config_with_env(Some(worker_config.env())),
        config.completed_action(),
        env,
    )
}

fn worker_configs_for_healthcheck(
    config: &DispatcherConfig,
) -> Result<Vec<(String, WorkerConfig)>, DispatcherError> {
    if config.worker.is_some() && !config.workers.is_empty() {
        return Err(DispatcherError::InvalidConfig(
            "configure either `worker` or `workers[]`, not both".to_string(),
        ));
    }
    if !config.workers.is_empty() {
        return Ok(config
            .workers
            .iter()
            .map(|worker| (worker.name.clone(), worker.to_worker_config()))
            .collect());
    }
    Ok(vec![(
        "worker".to_string(),
        config.primary_worker_config()?,
    )])
}

fn host_worker_program(worker_config: &WorkerConfig) -> Option<String> {
    match worker_config {
        WorkerConfig::Mock { .. } | WorkerConfig::Tool { .. } => None,
        WorkerConfig::Command { program, .. } => Some(program.clone()),
        WorkerConfig::ClaudeCode { program, .. } => {
            Some(program.clone().unwrap_or_else(|| "claude".to_string()))
        }
    }
}

fn ensure_host_worker_capabilities(worker_config: &WorkerConfig) -> Result<(), String> {
    if let WorkerConfig::ClaudeCode { program, .. } = worker_config {
        let program = program.clone().unwrap_or_else(|| "claude".to_string());
        ensure_claude_supports_webfetch_disable(&program)?;
    }
    Ok(())
}

fn ensure_claude_supports_webfetch_disable(program: &str) -> Result<(), String> {
    let output = std::process::Command::new(program)
        .arg("--help")
        .output()
        .map_err(|err| format!("failed to run `{program} --help`: {err}"))?;
    if !output.status.success() {
        return Err(format!("`{program} --help` exited with {}", output.status));
    }
    let help = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if help.contains("--disallowedTools") || help.contains("--disallowed-tools") {
        return Ok(());
    }
    Err(format!(
        "program `{program}` does not support --disallowedTools/--disallowed-tools required to disable WebFetch"
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ContainerWorkerProbe {
    executables: Vec<String>,
    claude_webfetch_disable_program: Option<String>,
}

fn container_worker_probe(worker_config: &WorkerConfig) -> Option<ContainerWorkerProbe> {
    let executables = container_worker_required_executables(worker_config);
    if executables.is_empty() {
        return None;
    }
    let claude_webfetch_disable_program = match worker_config {
        WorkerConfig::ClaudeCode { program, .. } => {
            Some(program.clone().unwrap_or_else(|| "claude".to_string()))
        }
        _ => None,
    };
    Some(ContainerWorkerProbe {
        executables,
        claude_webfetch_disable_program,
    })
}

fn container_worker_required_executables(worker_config: &WorkerConfig) -> Vec<String> {
    match worker_config {
        WorkerConfig::Mock { .. } | WorkerConfig::Tool { .. } => Vec::new(),
        WorkerConfig::Command { program, .. } => vec![program.clone()],
        WorkerConfig::ClaudeCode { program, args, .. } => {
            let program = program.clone().unwrap_or_else(|| "claude".to_string());
            if args.is_empty() {
                vec!["/bin/sh".to_string(), program]
            } else {
                vec![program]
            }
        }
    }
}

fn container_worker_probe_args(image: &str, probe: &ContainerWorkerProbe) -> Vec<String> {
    let mut args = vec![
        "run".to_string(),
        "--rm".to_string(),
        "--network".to_string(),
        "none".to_string(),
        "--entrypoint".to_string(),
        "/bin/sh".to_string(),
        image.to_string(),
        "-lc".to_string(),
        r#"claude_webfetch_disable_program="$1"
shift
for binary do
case "$binary" in
  */*) test -x "$binary" || { echo "missing executable: $binary" >&2; exit 127; } ;;
  *) command -v "$binary" >/dev/null 2>&1 || { echo "missing executable: $binary" >&2; exit 127; } ;;
esac
done
if [ -n "$claude_webfetch_disable_program" ]; then
  "$claude_webfetch_disable_program" --help 2>&1 | grep -Eq -- '--disallowedTools|--disallowed-tools' || {
    echo "Claude Code CLI does not support --disallowedTools/--disallowed-tools required to disable WebFetch" >&2
    exit 127
  }
fi"#
            .to_string(),
        "--".to_string(),
    ];
    args.push(
        probe
            .claude_webfetch_disable_program
            .clone()
            .unwrap_or_default(),
    );
    args.extend(probe.executables.iter().cloned());
    args
}

fn ensure_executable_available(program: &str) -> Result<(), String> {
    let program = program.trim();
    if program.is_empty() {
        return Err("program must not be empty".to_string());
    }
    if program.contains(std::path::MAIN_SEPARATOR) || Path::new(program).components().count() > 1 {
        return ensure_executable_path(Path::new(program))
            .map_err(|reason| format!("program `{program}` is not executable: {reason}"));
    }
    let Some(paths) = std::env::var_os("PATH") else {
        return Err(format!(
            "program `{program}` not found because PATH is unset"
        ));
    };
    for dir in std::env::split_paths(&paths) {
        let candidate = dir.join(program);
        if ensure_executable_path(&candidate).is_ok() {
            return Ok(());
        }
    }
    Err(format!("program `{program}` not found in PATH"))
}

fn ensure_executable_path(path: &Path) -> Result<(), &'static str> {
    let metadata = std::fs::metadata(path).map_err(|_| "missing")?;
    if !metadata.is_file() {
        return Err("not a file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err("permission bits do not include execute");
        }
    }
    Ok(())
}

pub fn workers_from_config(config: &DispatcherConfig) -> Result<WorkerSet, DispatcherError> {
    if config.worker.is_some() && !config.workers.is_empty() {
        return Err(DispatcherError::InvalidConfig(
            "configure either `worker` or `workers[]`, not both".to_string(),
        ));
    }
    if config.workers.is_empty() {
        return Ok(WorkerSet::single(worker_from_config(config)?));
    }
    let mut worker_set = WorkerSet::empty();
    for worker in &config.workers {
        let mut env = config.common_env.clone();
        env.extend(worker.env.clone());
        let entry = WorkerEntry {
            name: worker.name.clone(),
            worker: build_worker(
                &worker.to_worker_config(),
                config.runtime_config_with_env(Some(&worker.env)),
                config.completed_action(),
                env,
            )?,
            max_running: worker.max_running,
            priority: worker.priority,
        };
        for task_type in &worker.task_types {
            worker_set.push(*task_type, entry.clone());
        }
    }
    worker_set.sort();
    for task_type in [TaskType::Bootstrap, TaskType::Reason, TaskType::Explore] {
        if worker_set.entries(task_type).is_empty() {
            return Err(DispatcherError::InvalidConfig(format!(
                "no workers[] entry supports task type {task_type:?}"
            )));
        }
    }
    Ok(worker_set)
}

fn build_worker(
    worker_config: &WorkerConfig,
    runtime_config: Option<RuntimeConfig>,
    completed_action: CompletedAction,
    env: BTreeMap<String, String>,
) -> Result<Arc<dyn Worker>, DispatcherError> {
    if let Some(runtime_config) = runtime_config {
        if let Some((program, args)) = worker_command(worker_config) {
            return Ok(Arc::new(RuntimeCommandWorker::new(
                runtime_config,
                completed_action,
                program,
                args,
            )));
        }
        tracing::warn!(
            worker_kind = ?worker_config.kind(),
            "container is configured but worker kind cannot run inside a container; worker will execute on the host instead"
        );
    }
    local_worker_from_config(worker_config, env)
}

fn local_worker_from_config(
    worker_config: &WorkerConfig,
    env: BTreeMap<String, String>,
) -> Result<Arc<dyn Worker>, DispatcherError> {
    match worker_config {
        WorkerConfig::Mock { description, .. } => {
            Ok(Arc::new(MockWorker::fact(description.clone())))
        }
        WorkerConfig::Command { program, args, .. } => Ok(Arc::new(
            CommandWorker::new(program.clone(), args.clone()).with_env(env),
        )),
        WorkerConfig::ClaudeCode { program, args, .. } => Ok(Arc::new(
            CommandWorker::claude_code(program.clone(), args.clone()).with_env(env),
        )),
        WorkerConfig::Tool { tools, .. } => Ok(Arc::new(build_tool_worker(tools)?)),
    }
}

/// Build a [`ToolWorker`] from a list of tool names.
fn build_tool_worker(tool_names: &[String]) -> Result<ToolWorker, DispatcherError> {
    use clairvoyant_workers::tools::{checksec, objdump, readelf, ropgadget, strings, Tool};

    let mut tool_objs: Vec<std::sync::Arc<dyn Tool>> = Vec::new();

    for name in tool_names {
        let name_lower = name.to_lowercase().trim().to_string();
        match name_lower.as_str() {
            "checksec" => tool_objs.push(std::sync::Arc::new(checksec::Checksec::new())),
            "strings" => tool_objs.push(std::sync::Arc::new(strings::Strings::new())),
            "objdump" => tool_objs.push(std::sync::Arc::new(objdump::Objdump::new())),
            "readelf" => tool_objs.push(std::sync::Arc::new(readelf::Readelf::new())),
            "ropgadget" => tool_objs.push(std::sync::Arc::new(ropgadget::RopGadget::new())),
            "" => {
                return Err(DispatcherError::InvalidConfig(
                    "ToolWorker config contains an empty tool name".to_string(),
                ));
            }
            unknown => {
                return Err(DispatcherError::InvalidConfig(format!(
                    "ToolWorker config contains unknown tool `{unknown}`; available tools: checksec, strings, objdump, readelf, ropgadget"
                )));
            }
        }
    }

    if tool_objs.is_empty() {
        return Err(DispatcherError::InvalidConfig(
            "ToolWorker config must include at least one tool".to_string(),
        ));
    }

    Ok(ToolWorker::new(tool_objs))
}

fn worker_command(worker_config: &WorkerConfig) -> Option<(String, Vec<String>)> {
    match worker_config {
        WorkerConfig::Mock { .. } => None,
        WorkerConfig::Tool { .. } => None, // ToolWorker runs in-process, no external command
        WorkerConfig::Command { program, args, .. } => Some((program.clone(), args.clone())),
        WorkerConfig::ClaudeCode { program, args, .. } => {
            let worker = CommandWorker::claude_code(program.clone(), args.clone());
            Some((worker.program().to_string(), worker.args().to_vec()))
        }
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeCommandWorker {
    runtime: DockerCliRuntime,
    runtime_config: RuntimeConfig,
    completed_action: CompletedAction,
    program: String,
    args: Vec<String>,
}

impl RuntimeCommandWorker {
    pub fn new(
        runtime_config: RuntimeConfig,
        completed_action: CompletedAction,
        program: String,
        args: Vec<String>,
    ) -> Self {
        Self {
            runtime: DockerCliRuntime::new(runtime_config.clone()),
            runtime_config,
            completed_action,
            program,
            args,
        }
    }

    pub fn with_runtime(
        runtime: DockerCliRuntime,
        completed_action: CompletedAction,
        program: String,
        args: Vec<String>,
    ) -> Self {
        let runtime_config = runtime.config().clone();
        Self {
            runtime,
            runtime_config,
            completed_action,
            program,
            args,
        }
    }

    async fn cleanup_completed_container(
        &self,
        container_name: &str,
    ) -> Result<(), clairvoyant_workers::WorkerError> {
        match self.completed_action {
            CompletedAction::Remove => self.runtime.remove(container_name).await,
            CompletedAction::Stop => self.runtime.stop(container_name).await,
            CompletedAction::Keep => return Ok(()),
        }
        .map_err(|err| clairvoyant_workers::WorkerError::Failed(err.to_string()))
    }
}

#[async_trait::async_trait]
impl Worker for RuntimeCommandWorker {
    async fn run(
        &self,
        prompt: &str,
        context: WorkerContext,
    ) -> Result<Vec<WorkerEvent>, clairvoyant_workers::WorkerError> {
        collect_worker_stream(self.run_stream(prompt, context).await?).await
    }

    async fn run_stream(
        &self,
        prompt: &str,
        context: WorkerContext,
    ) -> Result<WorkerEventStream, clairvoyant_workers::WorkerError> {
        let mut env = BTreeMap::new();
        env.insert("CAIRN_PROJECT_ID".to_string(), context.project_id.clone());
        if let Some(intent_id) = &context.intent_id {
            env.insert("CAIRN_INTENT_ID".to_string(), intent_id.clone());
        }
        let spec = ContainerSpec::try_from_config(context.project_id, &self.runtime_config)
            .map_err(|err| clairvoyant_workers::WorkerError::Failed(err.to_string()))?;
        let rendered = spec.rendered();
        self.runtime
            .ensure_started(&spec)
            .await
            .map_err(|err| clairvoyant_workers::WorkerError::Failed(err.to_string()))?;
        let line_stream = self
            .runtime
            .exec_stream(
                &rendered.name,
                ProcessSpec {
                    program: self.program.clone(),
                    args: self.args.clone(),
                    env,
                    stdin: Some(prompt.to_string()),
                    cwd: rendered.workdir.clone(),
                },
            )
            .await
            .map_err(|err| clairvoyant_workers::WorkerError::Failed(err.to_string()))?;
        let worker = self.clone();
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        tokio::spawn(async move {
            if let Err(error) = worker
                .forward_runtime_lines(line_stream, rendered.name, tx.clone())
                .await
            {
                let _ = tx.send(Err(error)).await;
            }
        });
        Ok(Box::pin(ReceiverStream::new(rx)))
    }
}

impl RuntimeCommandWorker {
    async fn forward_runtime_lines(
        self,
        mut line_stream: clairvoyant_runtime::ProcessLineStream,
        container_name: String,
        tx: tokio::sync::mpsc::Sender<Result<WorkerEvent, clairvoyant_workers::WorkerError>>,
    ) -> Result<(), clairvoyant_workers::WorkerError> {
        let mut streamed_events = 0usize;
        let mut fallback_mode = false;
        let mut completed = false;
        let mut raw_stdout = String::new();

        loop {
            let line = tokio::select! {
                _ = tx.closed() => {
                    // Receiver dropped — break out of the loop to run cleanup.
                    break;
                }
                line = line_stream.next() => line,
            };
            let Some(line) = line else {
                break;
            };
            let line =
                line.map_err(|err| clairvoyant_workers::WorkerError::Failed(err.to_string()))?;
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
                    if worker_events_complete_project(std::slice::from_ref(&event)) {
                        completed = true;
                    }
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

        if fallback_mode && streamed_events == 0 {
            for event in parse_worker_output(&raw_stdout)? {
                if tx.send(Ok(event)).await.is_err() {
                    break;
                }
            }
        }

        if completed {
            self.cleanup_completed_container(&container_name).await?;
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct Dispatcher {
    service: ClairvoyantService,
    workers: WorkerSet,
    config: DispatcherConfig,
    reason_checkpoints: Arc<Mutex<BTreeMap<String, ReasonCheckpoint>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReasonCheckpoint {
    fact_count: usize,
    hint_count: usize,
    open_intent_count: usize,
}

#[derive(Clone)]
pub struct WorkerSet {
    bootstrap: Vec<WorkerEntry>,
    reason: Vec<WorkerEntry>,
    explore: Vec<WorkerEntry>,
}

#[derive(Clone)]
struct WorkerEntry {
    name: String,
    worker: Arc<dyn Worker>,
    max_running: usize,
    priority: i32,
}

impl WorkerSet {
    pub fn single(worker: Arc<dyn Worker>) -> Self {
        let entry = WorkerEntry {
            name: "worker".to_string(),
            worker,
            max_running: usize::MAX,
            priority: 0,
        };
        Self {
            bootstrap: vec![entry.clone()],
            reason: vec![entry.clone()],
            explore: vec![entry],
        }
    }

    fn empty() -> Self {
        Self {
            bootstrap: Vec::new(),
            reason: Vec::new(),
            explore: Vec::new(),
        }
    }

    fn push(&mut self, task_type: TaskType, entry: WorkerEntry) {
        match task_type {
            TaskType::Bootstrap => self.bootstrap.push(entry),
            TaskType::Reason => self.reason.push(entry),
            TaskType::Explore => self.explore.push(entry),
        }
    }

    fn sort(&mut self) {
        for entries in [&mut self.bootstrap, &mut self.reason, &mut self.explore] {
            entries.sort_by(|a, b| {
                a.priority
                    .cmp(&b.priority)
                    .then(a.name.as_str().cmp(b.name.as_str()))
            });
        }
    }

    fn entries(&self, task_type: TaskType) -> &[WorkerEntry] {
        match task_type {
            TaskType::Bootstrap => &self.bootstrap,
            TaskType::Reason => &self.reason,
            TaskType::Explore => &self.explore,
        }
    }

    fn for_task(&self, task_type: TaskType) -> WorkerEntry {
        self.entries(task_type)
            .first()
            .expect("worker set validated")
            .clone()
    }

    fn reserve_for_task(
        &self,
        task_type: TaskType,
        running_by_worker: &mut BTreeMap<String, usize>,
    ) -> Option<WorkerEntry> {
        for entry in self.entries(task_type) {
            let running = running_by_worker
                .get(&entry.name)
                .copied()
                .unwrap_or_default();
            if running < entry.max_running {
                running_by_worker.insert(entry.name.clone(), running + 1);
                return Some(entry.clone());
            }
        }
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchOutcome {
    NoProject,
    NoRunnableIntent,
    ReasonLeaseBusy {
        project_id: String,
    },
    CreatedBootstrapIntent {
        project_id: String,
        intent_id: String,
    },
    ConcludedIntent {
        project_id: String,
        intent_id: String,
        fact_id: String,
        completed: bool,
    },
    CreatedReasonIntent {
        project_id: String,
        intent_id: String,
    },
    CreatedReasonIntents {
        project_id: String,
        intent_ids: Vec<String>,
    },
    CompletedByReason {
        project_id: String,
        intent_id: String,
    },
    ReasonNoop {
        project_id: String,
    },
    TaskFailed {
        message: String,
    },
    TaskPanicked {
        message: String,
    },
}

impl Dispatcher {
    pub fn new(
        service: ClairvoyantService,
        worker: Arc<dyn Worker>,
        config: DispatcherConfig,
    ) -> Self {
        Self {
            service,
            workers: WorkerSet::single(worker),
            config,
            reason_checkpoints: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    pub fn with_workers(
        service: ClairvoyantService,
        workers: WorkerSet,
        config: DispatcherConfig,
    ) -> Self {
        Self {
            service,
            workers,
            config,
            reason_checkpoints: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    pub async fn run_once(&self) -> Result<DispatchOutcome, DispatcherError> {
        let projects = expect_project_summaries(
            self.service
                .handle(ClairvoyantRequest::ListProjects)
                .await?,
        )?;
        self.initialize_reason_checkpoints(&projects).await;
        let Some(project) = projects
            .into_iter()
            .find(|summary| matches!(summary.project.status, ProjectStatus::Active))
        else {
            return Ok(DispatchOutcome::NoProject);
        };

        let detail = expect_project_detail(
            self.service
                .handle(ClairvoyantRequest::GetProject {
                    project_id: project.project.id.clone(),
                })
                .await?,
        )?;

        if is_bootstrap_project(&detail, &self.config.bootstrap_intent) {
            if let Some(intent) = detail
                .intents
                .iter()
                .find(|intent| {
                    is_reserved_bootstrap_intent(intent, &self.config.bootstrap_intent)
                        && intent.worker.is_none()
                })
                .cloned()
            {
                return self
                    .run_intent_task(detail, intent, TaskKind::Bootstrap)
                    .await;
            }
            if detail.intents.is_empty() {
                self.record_reason_checkpoint(&detail).await;
                let intent = expect_intent(
                    self.service
                        .handle(ClairvoyantRequest::CreateIntent {
                            project_id: detail.project.id.clone(),
                            body: CreateIntentRequest {
                                sources: vec!["origin".to_string()],
                                description: self.config.bootstrap_intent.clone(),
                                creator: "dispatcher.bootstrap".to_string(),
                                worker: None,
                            },
                        })
                        .await?,
                )?;
                return Ok(DispatchOutcome::CreatedBootstrapIntent {
                    project_id: detail.project.id,
                    intent_id: intent.id,
                });
            }
        }

        if let Some(intent) = detail
            .intents
            .iter()
            .find(|intent| {
                intent.target_fact.is_none()
                    && intent.worker.is_none()
                    && !is_reserved_bootstrap_intent(intent, &self.config.bootstrap_intent)
            })
            .cloned()
        {
            return self
                .run_intent_task(detail, intent, TaskKind::Explore)
                .await;
        }

        let Some(trigger) = self.reason_trigger(&detail).await else {
            return Ok(DispatchOutcome::NoRunnableIntent);
        };
        self.run_reason_task(detail, trigger).await
    }

    pub async fn run_tick(&self) -> Result<Vec<DispatchOutcome>, DispatcherError> {
        let projects = expect_project_summaries(
            self.service
                .handle(ClairvoyantRequest::ListProjects)
                .await?,
        )?;
        self.initialize_reason_checkpoints(&projects).await;
        let active_projects = projects
            .into_iter()
            .filter(|summary| matches!(summary.project.status, ProjectStatus::Active))
            .take(self.config.runtime.max_running_projects)
            .collect::<Vec<_>>();
        if active_projects.is_empty() {
            return Ok(vec![DispatchOutcome::NoProject]);
        }

        let mut outcomes = Vec::new();
        let mut tasks = Vec::new();
        let mut running_by_worker = BTreeMap::new();
        for project in active_projects {
            let detail = expect_project_detail(
                self.service
                    .handle(ClairvoyantRequest::GetProject {
                        project_id: project.project.id.clone(),
                    })
                    .await?,
            )?;

            if is_bootstrap_project(&detail, &self.config.bootstrap_intent) {
                if let Some(intent) = detail
                    .intents
                    .iter()
                    .find(|intent| {
                        is_reserved_bootstrap_intent(intent, &self.config.bootstrap_intent)
                            && intent.worker.is_none()
                    })
                    .cloned()
                {
                    if tasks.len() < self.config.runtime.max_workers {
                        let Some(entry) = self
                            .workers
                            .reserve_for_task(TaskType::Bootstrap, &mut running_by_worker)
                        else {
                            continue;
                        };
                        tasks.push(DispatchTask::Intent {
                            entry,
                            detail,
                            intent,
                            kind: TaskKind::Bootstrap,
                        });
                    }
                } else if detail.intents.is_empty() {
                    let intent = expect_intent(
                        self.service
                            .handle(ClairvoyantRequest::CreateIntent {
                                project_id: detail.project.id.clone(),
                                body: CreateIntentRequest {
                                    sources: vec!["origin".to_string()],
                                    description: self.config.bootstrap_intent.clone(),
                                    creator: "dispatcher.bootstrap".to_string(),
                                    worker: None,
                                },
                            })
                            .await?,
                    )?;
                    outcomes.push(DispatchOutcome::CreatedBootstrapIntent {
                        project_id: detail.project.id,
                        intent_id: intent.id,
                    });
                }
            } else {
                let mut project_tasks = 0usize;
                if tasks.len() < self.config.runtime.max_workers {
                    if let Some(trigger) = self.reason_trigger(&detail).await {
                        if let Some(entry) = self
                            .workers
                            .reserve_for_task(TaskType::Reason, &mut running_by_worker)
                        {
                            project_tasks += 1;
                            tasks.push(DispatchTask::Reason {
                                entry,
                                detail: detail.clone(),
                                trigger,
                            });
                        }
                    }
                }
                let remaining_project_slots = self
                    .config
                    .runtime
                    .max_project_workers
                    .saturating_sub(project_tasks);
                for intent in detail
                    .intents
                    .iter()
                    .filter(|intent| {
                        intent.target_fact.is_none()
                            && intent.worker.is_none()
                            && !is_reserved_bootstrap_intent(intent, &self.config.bootstrap_intent)
                    })
                    .take(remaining_project_slots)
                    .cloned()
                {
                    if tasks.len() >= self.config.runtime.max_workers {
                        break;
                    }
                    let Some(entry) = self
                        .workers
                        .reserve_for_task(TaskType::Explore, &mut running_by_worker)
                    else {
                        break;
                    };
                    tasks.push(DispatchTask::Intent {
                        entry,
                        detail: detail.clone(),
                        intent,
                        kind: TaskKind::Explore,
                    });
                }
            }

            if tasks.len() >= self.config.runtime.max_workers {
                break;
            }
        }

        if tasks.is_empty() {
            if outcomes.is_empty() {
                outcomes.push(DispatchOutcome::NoRunnableIntent);
            }
            return Ok(outcomes);
        }

        let mut handles = Vec::with_capacity(tasks.len());
        for task in tasks {
            let dispatcher = self.clone();
            handles.push(tokio::spawn(async move {
                match task {
                    DispatchTask::Intent {
                        entry,
                        detail,
                        intent,
                        kind,
                    } => {
                        dispatcher
                            .run_intent_task_with_worker(entry, detail, intent, kind)
                            .await
                    }
                    DispatchTask::Reason {
                        entry,
                        detail,
                        trigger,
                    } => {
                        dispatcher
                            .run_reason_task_with_worker(entry, detail, trigger)
                            .await
                    }
                }
            }));
        }
        for handle in handles {
            match handle.await {
                Ok(Ok(outcome)) => outcomes.push(outcome),
                Ok(Err(err)) => {
                    tracing::warn!(error = %err, "dispatch task failed");
                    outcomes.push(DispatchOutcome::TaskFailed {
                        message: err.to_string(),
                    });
                }
                Err(join_err) => {
                    tracing::warn!(error = %join_err, "dispatch task panicked");
                    outcomes.push(DispatchOutcome::TaskPanicked {
                        message: join_err.to_string(),
                    });
                }
            }
        }
        Ok(outcomes)
    }

    pub async fn run_refill_tick(&self) -> Result<Vec<DispatchOutcome>, DispatcherError> {
        let mut outcomes = Vec::new();
        let mut handles = tokio::task::JoinSet::new();
        let mut running_by_worker = BTreeMap::new();
        let mut running_by_project = BTreeMap::new();
        let mut running_intents = BTreeSet::new();
        let mut running_reason_projects = BTreeSet::new();

        loop {
            while handles.len() < self.config.runtime.max_workers {
                match self
                    .plan_dispatch_task(
                        &mut running_by_worker,
                        &running_by_project,
                        &running_intents,
                        &running_reason_projects,
                    )
                    .await?
                {
                    PlannedDispatch::Task(task) => {
                        let worker_name = task.worker_name().to_string();
                        let project_id = task.project_id().to_string();
                        let intent_key = task.intent_key();
                        let reason_project = task.is_reason().then(|| project_id.clone());
                        increment_count(&mut running_by_project, project_id.clone());
                        if let Some(key) = &intent_key {
                            running_intents.insert(key.clone());
                        }
                        if let Some(project_id) = &reason_project {
                            running_reason_projects.insert(project_id.clone());
                        }
                        let dispatcher = self.clone();
                        handles.spawn(async move {
                            let result = dispatcher.run_dispatch_task(task).await;
                            (worker_name, project_id, intent_key, reason_project, result)
                        });
                    }
                    PlannedDispatch::Outcome(outcome) => outcomes.push(outcome),
                    PlannedDispatch::NoProject => {
                        if handles.is_empty() && outcomes.is_empty() {
                            outcomes.push(DispatchOutcome::NoProject);
                            return Ok(outcomes);
                        }
                        break;
                    }
                    PlannedDispatch::None => break,
                }
            }

            if handles.is_empty() {
                if outcomes.is_empty() {
                    outcomes.push(DispatchOutcome::NoRunnableIntent);
                }
                return Ok(outcomes);
            }

            match handles.join_next().await {
                Some(Ok((worker_name, project_id, intent_key, reason_project, result))) => {
                    decrement_count(&mut running_by_worker, &worker_name);
                    decrement_count(&mut running_by_project, &project_id);
                    if let Some(key) = intent_key {
                        running_intents.remove(&key);
                    }
                    if let Some(project_id) = reason_project {
                        running_reason_projects.remove(&project_id);
                    }
                    match result {
                        Ok(outcome) => outcomes.push(outcome),
                        Err(err) => {
                            tracing::warn!(error = %err, "dispatch task failed");
                            outcomes.push(DispatchOutcome::TaskFailed {
                                message: err.to_string(),
                            });
                        }
                    }
                }
                Some(Err(join_err)) => {
                    tracing::warn!(error = %join_err, "dispatch task panicked");
                    outcomes.push(DispatchOutcome::TaskPanicked {
                        message: join_err.to_string(),
                    });
                }
                None => {}
            }
        }
    }

    async fn plan_dispatch_task(
        &self,
        running_by_worker: &mut BTreeMap<String, usize>,
        running_by_project: &BTreeMap<String, usize>,
        running_intents: &BTreeSet<String>,
        running_reason_projects: &BTreeSet<String>,
    ) -> Result<PlannedDispatch, DispatcherError> {
        let projects = expect_project_summaries(
            self.service
                .handle(ClairvoyantRequest::ListProjects)
                .await?,
        )?;
        self.initialize_reason_checkpoints(&projects).await;
        let active_projects = projects
            .into_iter()
            .filter(|summary| matches!(summary.project.status, ProjectStatus::Active))
            .collect::<Vec<_>>();
        if active_projects.is_empty() {
            return Ok(PlannedDispatch::NoProject);
        }

        let running_project_count = running_by_project.len();
        for project in active_projects {
            let project_running = running_by_project
                .get(&project.project.id)
                .copied()
                .unwrap_or_default();
            let project_has_capacity = project_running < self.config.runtime.max_project_workers;
            if project_running == 0
                && running_project_count >= self.config.runtime.max_running_projects
            {
                continue;
            }

            let detail = expect_project_detail(
                self.service
                    .handle(ClairvoyantRequest::GetProject {
                        project_id: project.project.id.clone(),
                    })
                    .await?,
            )?;

            if is_bootstrap_project(&detail, &self.config.bootstrap_intent) {
                if project_running > 0 {
                    continue;
                }
                if let Some(intent) = detail
                    .intents
                    .iter()
                    .find(|intent| {
                        is_reserved_bootstrap_intent(intent, &self.config.bootstrap_intent)
                            && intent.worker.is_none()
                            && !running_intents
                                .contains(&intent_key(&detail.project.id, &intent.id))
                    })
                    .cloned()
                {
                    let Some(entry) = self
                        .workers
                        .reserve_for_task(TaskType::Bootstrap, running_by_worker)
                    else {
                        continue;
                    };
                    return Ok(PlannedDispatch::Task(DispatchTask::Intent {
                        entry,
                        detail,
                        intent,
                        kind: TaskKind::Bootstrap,
                    }));
                }
                if detail.intents.is_empty() {
                    self.record_reason_checkpoint(&detail).await;
                    let intent = expect_intent(
                        self.service
                            .handle(ClairvoyantRequest::CreateIntent {
                                project_id: detail.project.id.clone(),
                                body: CreateIntentRequest {
                                    sources: vec!["origin".to_string()],
                                    description: self.config.bootstrap_intent.clone(),
                                    creator: "dispatcher.bootstrap".to_string(),
                                    worker: None,
                                },
                            })
                            .await?,
                    )?;
                    return Ok(PlannedDispatch::Outcome(
                        DispatchOutcome::CreatedBootstrapIntent {
                            project_id: detail.project.id,
                            intent_id: intent.id,
                        },
                    ));
                }
                continue;
            }

            if project_has_capacity && !running_reason_projects.contains(&detail.project.id) {
                if let Some(trigger) = self.reason_trigger(&detail).await {
                    if let Some(entry) = self
                        .workers
                        .reserve_for_task(TaskType::Reason, running_by_worker)
                    {
                        return Ok(PlannedDispatch::Task(DispatchTask::Reason {
                            entry,
                            detail,
                            trigger,
                        }));
                    }
                }
            }

            if !project_has_capacity {
                continue;
            }

            if let Some(intent) = detail
                .intents
                .iter()
                .filter(|intent| {
                    intent.target_fact.is_none()
                        && intent.worker.is_none()
                        && !is_reserved_bootstrap_intent(intent, &self.config.bootstrap_intent)
                        && !running_intents.contains(&intent_key(&detail.project.id, &intent.id))
                })
                .next()
                .cloned()
            {
                let Some(entry) = self
                    .workers
                    .reserve_for_task(TaskType::Explore, running_by_worker)
                else {
                    continue;
                };
                return Ok(PlannedDispatch::Task(DispatchTask::Intent {
                    entry,
                    detail,
                    intent,
                    kind: TaskKind::Explore,
                }));
            }
        }

        Ok(PlannedDispatch::None)
    }

    async fn run_dispatch_task(
        &self,
        task: DispatchTask,
    ) -> Result<DispatchOutcome, DispatcherError> {
        match task {
            DispatchTask::Intent {
                entry,
                detail,
                intent,
                kind,
            } => {
                self.run_intent_task_with_worker(entry, detail, intent, kind)
                    .await
            }
            DispatchTask::Reason {
                entry,
                detail,
                trigger,
            } => {
                self.run_reason_task_with_worker(entry, detail, trigger)
                    .await
            }
        }
    }

    async fn run_intent_task(
        &self,
        detail: ProjectDetail,
        intent: clairvoyant_core::Intent,
        kind: TaskKind,
    ) -> Result<DispatchOutcome, DispatcherError> {
        self.run_intent_task_with_worker(
            self.workers.for_task(kind.task_type()),
            detail,
            intent,
            kind,
        )
        .await
    }

    async fn run_intent_task_with_worker(
        &self,
        entry: WorkerEntry,
        detail: ProjectDetail,
        intent: clairvoyant_core::Intent,
        kind: TaskKind,
    ) -> Result<DispatchOutcome, DispatcherError> {
        let worker = entry.worker;
        let worker_name = entry.name.as_str();
        let bundle = prompt_bundle(&self.config.runtime.prompt_group)?;
        let claimed = expect_intent(
            self.service
                .handle(ClairvoyantRequest::HeartbeatIntent {
                    project_id: detail.project.id.clone(),
                    intent_id: intent.id.clone(),
                    body: HeartbeatRequest {
                        worker: worker_name.to_string(),
                    },
                })
                .await?,
        )?;
        let prompt = render_prompt(bundle, &detail, &claimed, kind);
        let events = self
            .run_worker_with_heartbeat(WorkerRun {
                worker: Arc::clone(&worker),
                prompt,
                context: WorkerContext {
                    project_id: detail.project.id.clone(),
                    intent_id: Some(claimed.id.clone()),
                },
                lease: Lease::Intent {
                    project_id: detail.project.id.clone(),
                    intent_id: claimed.id.clone(),
                },
                timeout_secs: self.intent_timeout_secs(kind),
                worker_name: worker_name.to_string(),
                mode: WorkerStreamMode::IntentTask,
            })
            .await;

        let action = match events {
            Ok(events) => match choose_worker_action(&events) {
                Ok(WorkerAction::Fact {
                    description,
                    complete,
                }) => WorkerAction::Fact {
                    description,
                    complete,
                },
                Ok(_) => match self
                    .run_intent_conclude_fallback(
                        Arc::clone(&worker),
                        bundle,
                        &detail,
                        &claimed,
                        kind,
                        worker_name,
                    )
                    .await
                {
                    Ok(action) => action,
                    Err(error) => {
                        let _ = self
                            .release_intent(&detail.project.id, &claimed.id, worker_name)
                            .await;
                        return Err(error);
                    }
                },
                Err(error) => {
                    let _ = self
                        .release_intent(&detail.project.id, &claimed.id, worker_name)
                        .await;
                    return Err(error);
                }
            },
            Err(execute_error) => match self
                .run_intent_conclude_fallback(
                    Arc::clone(&worker),
                    bundle,
                    &detail,
                    &claimed,
                    kind,
                    worker_name,
                )
                .await
            {
                Ok(action) => action,
                Err(_) => {
                    let _ = self
                        .release_intent(&detail.project.id, &claimed.id, worker_name)
                        .await;
                    return Err(execute_error);
                }
            },
        };

        let WorkerAction::Fact {
            description,
            complete,
        } = action
        else {
            self.release_intent(&detail.project.id, &claimed.id, worker_name)
                .await?;
            return Err(clairvoyant_workers::WorkerError::Failed(
                "intent task must produce a done event".to_string(),
            )
            .into());
        };

        let concluded = match self
            .service
            .handle(ClairvoyantRequest::ConcludeIntent {
                project_id: detail.project.id.clone(),
                intent_id: claimed.id.clone(),
                body: ConcludeRequest {
                    worker: worker_name.to_string(),
                    description,
                },
            })
            .await
        {
            Ok(response) => match expect_conclude(response) {
                Ok(concluded) => concluded,
                Err(error) => {
                    let _ = self
                        .release_intent(&detail.project.id, &claimed.id, worker_name)
                        .await;
                    return Err(error);
                }
            },
            Err(error) => {
                let _ = self
                    .release_intent(&detail.project.id, &claimed.id, worker_name)
                    .await;
                return Err(error.into());
            }
        };

        if complete {
            let _ = self
                .service
                .handle(ClairvoyantRequest::CompleteProject {
                    project_id: detail.project.id.clone(),
                    body: CompleteRequest {
                        sources: vec![concluded.fact.id.clone()],
                        description: "worker reported completion".to_string(),
                        worker: worker_name.to_string(),
                    },
                })
                .await?;
        }

        Ok(DispatchOutcome::ConcludedIntent {
            project_id: detail.project.id,
            intent_id: claimed.id,
            fact_id: concluded.fact.id,
            completed: complete,
        })
    }

    async fn run_intent_conclude_fallback(
        &self,
        worker: Arc<dyn Worker>,
        bundle: PromptBundle,
        detail: &ProjectDetail,
        intent: &clairvoyant_core::Intent,
        kind: TaskKind,
        worker_name: &str,
    ) -> Result<WorkerAction, DispatcherError> {
        let prompt = render_conclude_prompt(bundle, detail, intent, kind);
        let events = self
            .run_worker_with_heartbeat(WorkerRun {
                worker,
                prompt,
                context: WorkerContext {
                    project_id: detail.project.id.clone(),
                    intent_id: Some(intent.id.clone()),
                },
                lease: Lease::Intent {
                    project_id: detail.project.id.clone(),
                    intent_id: intent.id.clone(),
                },
                timeout_secs: self.conclude_timeout_secs(kind),
                worker_name: worker_name.to_string(),
                mode: WorkerStreamMode::IntentTask,
            })
            .await?;
        match choose_worker_action(&events)? {
            WorkerAction::Fact {
                description,
                complete,
            } => Ok(WorkerAction::Fact {
                description,
                complete,
            }),
            _ => Err(clairvoyant_workers::WorkerError::Failed(
                "conclude fallback must produce a done event".to_string(),
            )
            .into()),
        }
    }

    async fn run_reason_task(
        &self,
        detail: ProjectDetail,
        trigger: String,
    ) -> Result<DispatchOutcome, DispatcherError> {
        self.run_reason_task_with_worker(self.workers.for_task(TaskType::Reason), detail, trigger)
            .await
    }

    async fn run_reason_task_with_worker(
        &self,
        entry: WorkerEntry,
        detail: ProjectDetail,
        trigger: String,
    ) -> Result<DispatchOutcome, DispatcherError> {
        let worker = entry.worker;
        let worker_name = entry.name.as_str();
        let project_id = detail.project.id.clone();
        let bundle = prompt_bundle(&self.config.runtime.prompt_group)?;
        let claim = self
            .service
            .handle(ClairvoyantRequest::ClaimProjectReason {
                project_id: project_id.clone(),
                body: ReasonClaimRequest {
                    worker: worker_name.to_string(),
                    trigger,
                },
            })
            .await;
        if is_conflict(&claim) {
            return Ok(DispatchOutcome::ReasonLeaseBusy { project_id });
        }
        claim?;

        let prompt = render_reason_prompt(bundle, &detail, self.config.tasks.reason.max_intents);
        let events = self
            .run_worker_with_heartbeat(WorkerRun {
                worker,
                prompt,
                context: WorkerContext {
                    project_id: project_id.clone(),
                    intent_id: None,
                },
                lease: Lease::Reason {
                    project_id: project_id.clone(),
                },
                timeout_secs: self.config.tasks.reason.timeout,
                worker_name: worker_name.to_string(),
                mode: WorkerStreamMode::Reason {
                    max_intents: self.config.tasks.reason.max_intents,
                },
            })
            .await;
        let events = match events {
            Ok(events) => events,
            Err(error) => {
                let _ = self.release_reason(&project_id, worker_name).await;
                return Err(error);
            }
        };
        if let Some(message) = worker_error_message(&events) {
            let _ = self.release_reason(&project_id, worker_name).await;
            return Err(clairvoyant_workers::WorkerError::Failed(message).into());
        }
        if let Some((sources, description)) = last_complete_event(&events) {
            let complete = self
                .service
                .handle(ClairvoyantRequest::CompleteProject {
                    project_id: project_id.clone(),
                    body: CompleteRequest {
                        sources,
                        description,
                        worker: worker_name.to_string(),
                    },
                })
                .await;
            let intent = match complete {
                Ok(response) => match expect_intent(response) {
                    Ok(intent) => intent,
                    Err(error) => {
                        let _ = self.release_reason(&project_id, worker_name).await;
                        return Err(error);
                    }
                },
                Err(error) => {
                    let _ = self.release_reason(&project_id, worker_name).await;
                    return Err(error.into());
                }
            };
            let _ = self.release_reason(&project_id, worker_name).await;
            self.refresh_reason_checkpoint(&project_id).await?;
            return Ok(DispatchOutcome::CompletedByReason {
                project_id,
                intent_id: intent.id,
            });
        }
        let intent_events = intent_events(&events, self.config.tasks.reason.max_intents);
        if !intent_events.is_empty() {
            let mut intent_ids = Vec::with_capacity(intent_events.len());
            for (sources, description) in intent_events {
                let intent = match self
                    .service
                    .handle(ClairvoyantRequest::CreateIntent {
                        project_id: project_id.clone(),
                        body: CreateIntentRequest {
                            sources,
                            description,
                            creator: worker_name.to_string(),
                            worker: None,
                        },
                    })
                    .await
                {
                    Ok(response) => match expect_intent(response) {
                        Ok(intent) => intent,
                        Err(error) => {
                            let _ = self.release_reason(&project_id, worker_name).await;
                            return Err(error);
                        }
                    },
                    Err(error) => {
                        let _ = self.release_reason(&project_id, worker_name).await;
                        return Err(error.into());
                    }
                };
                intent_ids.push(intent.id);
            }
            self.release_reason(&project_id, worker_name).await?;
            self.refresh_reason_checkpoint(&project_id).await?;
            if intent_ids.len() == 1 {
                Ok(DispatchOutcome::CreatedReasonIntent {
                    project_id,
                    intent_id: intent_ids.remove(0),
                })
            } else {
                Ok(DispatchOutcome::CreatedReasonIntents {
                    project_id,
                    intent_ids,
                })
            }
        } else {
            let action = match choose_worker_action(&events) {
                Ok(action) => action,
                Err(error) => {
                    let _ = self.release_reason(&project_id, worker_name).await;
                    return Err(error);
                }
            };
            self.release_reason(&project_id, worker_name).await?;
            match action {
                WorkerAction::Fact { .. } | WorkerAction::Noop => {
                    self.refresh_reason_checkpoint(&project_id).await?;
                    Ok(DispatchOutcome::ReasonNoop { project_id })
                }
                WorkerAction::DeclareIntent { .. } | WorkerAction::Complete { .. } => {
                    unreachable!("reason intent and complete events are handled above")
                }
            }
        }
    }

    async fn record_reason_checkpoint(&self, detail: &ProjectDetail) {
        self.reason_checkpoints.lock().await.insert(
            detail.project.id.clone(),
            ReasonCheckpoint::from_detail(detail),
        );
    }

    async fn initialize_reason_checkpoints(&self, summaries: &[ProjectSummary]) {
        let mut checkpoints = self.reason_checkpoints.lock().await;
        for summary in summaries {
            if !matches!(summary.project.status, ProjectStatus::Active) {
                continue;
            }
            if checkpoints.contains_key(&summary.project.id) {
                continue;
            }
            let open_intent_count =
                (summary.working_intent_count + summary.unclaimed_intent_count).max(0) as usize;
            if open_intent_count == 0 {
                continue;
            }
            checkpoints.insert(
                summary.project.id.clone(),
                ReasonCheckpoint {
                    fact_count: summary.fact_count.max(0) as usize,
                    hint_count: summary.hint_count.max(0) as usize,
                    open_intent_count,
                },
            );
        }
    }

    async fn refresh_reason_checkpoint(&self, project_id: &str) -> Result<(), DispatcherError> {
        let detail = expect_project_detail(
            self.service
                .handle(ClairvoyantRequest::GetProject {
                    project_id: project_id.to_string(),
                })
                .await?,
        )?;
        self.record_reason_checkpoint(&detail).await;
        Ok(())
    }

    async fn reason_trigger(&self, detail: &ProjectDetail) -> Option<String> {
        let current = ReasonCheckpoint::from_detail(detail);
        let checkpoints = self.reason_checkpoints.lock().await;
        let Some(previous) = checkpoints.get(&detail.project.id) else {
            return Some(format!("initial {}", reason_state_summary(detail)));
        };
        let mut changes = Vec::new();
        if current.fact_count > previous.fact_count {
            changes.push(format!(
                "facts:{}->{}",
                previous.fact_count, current.fact_count
            ));
        }
        if current.hint_count > previous.hint_count {
            changes.push(format!(
                "hints:{}->{}",
                previous.hint_count, current.hint_count
            ));
        }
        if previous.open_intent_count > 0 && current.open_intent_count == 0 {
            changes.push(format!("open_intents:{}->0", previous.open_intent_count));
        }
        if changes.is_empty() {
            None
        } else {
            Some(format!(
                "{} changes={}",
                reason_state_summary(detail),
                changes.join(",")
            ))
        }
    }

    async fn release_intent(
        &self,
        project_id: &str,
        intent_id: &str,
        worker_name: &str,
    ) -> Result<(), DispatcherError> {
        self.service
            .handle(ClairvoyantRequest::ReleaseIntent {
                project_id: project_id.to_string(),
                intent_id: intent_id.to_string(),
                body: HeartbeatRequest {
                    worker: worker_name.to_string(),
                },
            })
            .await?;
        Ok(())
    }

    async fn release_reason(
        &self,
        project_id: &str,
        worker_name: &str,
    ) -> Result<(), DispatcherError> {
        self.service
            .handle(ClairvoyantRequest::ReleaseProjectReason {
                project_id: project_id.to_string(),
                body: HeartbeatRequest {
                    worker: worker_name.to_string(),
                },
            })
            .await?;
        Ok(())
    }

    pub async fn heartbeat_reason(
        &self,
        project_id: &str,
        worker_name: &str,
    ) -> Result<(), DispatcherError> {
        self.service
            .handle(ClairvoyantRequest::HeartbeatProjectReason {
                project_id: project_id.to_string(),
                body: HeartbeatRequest {
                    worker: worker_name.to_string(),
                },
            })
            .await?;
        Ok(())
    }

    pub async fn heartbeat_intent(
        &self,
        project_id: &str,
        intent_id: &str,
        worker_name: &str,
    ) -> Result<(), DispatcherError> {
        self.service
            .handle(ClairvoyantRequest::HeartbeatIntent {
                project_id: project_id.to_string(),
                intent_id: intent_id.to_string(),
                body: HeartbeatRequest {
                    worker: worker_name.to_string(),
                },
            })
            .await?;
        Ok(())
    }

    async fn run_worker_with_heartbeat(
        &self,
        run: WorkerRun,
    ) -> Result<Vec<WorkerEvent>, DispatcherError> {
        let WorkerRun {
            worker,
            prompt,
            context,
            lease,
            timeout_secs,
            worker_name,
            mode,
        } = run;
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(self.config.runtime.interval));
        let mut worker_task = tokio::spawn(async move {
            let stream = worker.run_stream(&prompt, context).await?;
            collect_worker_stream_for_dispatch(stream, mode).await
        });
        let timeout = tokio::time::sleep(std::time::Duration::from_secs(timeout_secs));
        tokio::pin!(timeout);

        loop {
            tokio::select! {
                result = &mut worker_task => {
                    return Ok(result??);
                }
                _ = &mut timeout => {
                    worker_task.abort();
                    let _ = worker_task.await;
                    return Err(clairvoyant_workers::WorkerError::Failed(
                        format!("worker timed out after {timeout_secs}s")
                    ).into());
                }
                _ = interval.tick() => {
                    let heartbeat = match &lease {
                        Lease::Intent { project_id, intent_id } => {
                            self.heartbeat_intent(project_id, intent_id, &worker_name).await
                        }
                        Lease::Reason { project_id } => {
                            self.heartbeat_reason(project_id, &worker_name).await
                        }
                    };
                    if let Err(error) = heartbeat {
                        worker_task.abort();
                        let _ = worker_task.await;
                        // Release the lease before returning so the intent/reason
                        // is immediately available to other dispatchers.
                        let _ = match &lease {
                            Lease::Intent { project_id, intent_id } => {
                                self.release_intent(project_id, intent_id, &worker_name).await
                            }
                            Lease::Reason { project_id } => {
                                self.release_reason(project_id, &worker_name).await
                            }
                        };
                        return Err(error);
                    }
                }
            }
        }
    }

    fn intent_timeout_secs(&self, kind: TaskKind) -> u64 {
        match kind {
            TaskKind::Bootstrap => self.config.tasks.bootstrap.timeout,
            TaskKind::Explore => self.config.tasks.explore.timeout,
        }
    }

    fn conclude_timeout_secs(&self, kind: TaskKind) -> u64 {
        match kind {
            TaskKind::Bootstrap => self.config.tasks.bootstrap.conclude_timeout,
            TaskKind::Explore => self.config.tasks.explore.conclude_timeout,
        }
    }

    pub async fn stop_project(&self, project_id: String) -> Result<(), DispatcherError> {
        self.service
            .handle(ClairvoyantRequest::UpdateProjectStatus {
                project_id,
                body: UpdateProjectStatusRequest {
                    status: ProjectStatus::Stopped,
                },
            })
            .await?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TaskKind {
    Bootstrap,
    Explore,
}

#[derive(Debug, Clone, Copy)]
enum WorkerStreamMode {
    IntentTask,
    Reason { max_intents: usize },
}

struct WorkerRun {
    worker: Arc<dyn Worker>,
    prompt: String,
    context: WorkerContext,
    lease: Lease,
    timeout_secs: u64,
    worker_name: String,
    mode: WorkerStreamMode,
}

async fn collect_worker_stream_for_dispatch(
    mut stream: WorkerEventStream,
    mode: WorkerStreamMode,
) -> Result<Vec<WorkerEvent>, clairvoyant_workers::WorkerError> {
    let mut events = Vec::new();
    let mut reason_intents = 0usize;

    while let Some(event) = stream.next().await {
        let event = event?;
        let should_stop = match (&mode, &event) {
            (_, WorkerEvent::Error { .. }) => true,
            (WorkerStreamMode::IntentTask, WorkerEvent::Done { .. }) => true,
            (WorkerStreamMode::IntentTask, WorkerEvent::Intent { .. }) => true,
            (WorkerStreamMode::IntentTask, WorkerEvent::Complete { .. }) => true,
            (WorkerStreamMode::Reason { .. }, WorkerEvent::Complete { .. }) => true,
            (WorkerStreamMode::Reason { max_intents }, WorkerEvent::Intent { .. }) => {
                reason_intents += 1;
                reason_intents >= *max_intents
            }
            _ => false,
        };
        events.push(event);
        if should_stop {
            break;
        }
    }

    Ok(events)
}

#[derive(Clone)]
enum DispatchTask {
    Intent {
        entry: WorkerEntry,
        detail: ProjectDetail,
        intent: clairvoyant_core::Intent,
        kind: TaskKind,
    },
    Reason {
        entry: WorkerEntry,
        detail: ProjectDetail,
        trigger: String,
    },
}

enum PlannedDispatch {
    Task(DispatchTask),
    Outcome(DispatchOutcome),
    NoProject,
    None,
}

impl TaskKind {
    fn task_type(self) -> TaskType {
        match self {
            TaskKind::Bootstrap => TaskType::Bootstrap,
            TaskKind::Explore => TaskType::Explore,
        }
    }
}

impl DispatchTask {
    fn worker_name(&self) -> &str {
        match self {
            DispatchTask::Intent { entry, .. } | DispatchTask::Reason { entry, .. } => &entry.name,
        }
    }

    fn project_id(&self) -> &str {
        match self {
            DispatchTask::Intent { detail, .. } | DispatchTask::Reason { detail, .. } => {
                detail.project.id.as_str()
            }
        }
    }

    fn intent_key(&self) -> Option<String> {
        match self {
            DispatchTask::Intent { detail, intent, .. } => {
                Some(intent_key(&detail.project.id, &intent.id))
            }
            DispatchTask::Reason { .. } => None,
        }
    }

    fn is_reason(&self) -> bool {
        matches!(self, DispatchTask::Reason { .. })
    }
}

fn intent_key(project_id: &str, intent_id: &str) -> String {
    format!("{project_id}:{intent_id}")
}

fn increment_count(map: &mut BTreeMap<String, usize>, key: String) {
    *map.entry(key).or_default() += 1;
}

fn decrement_count(map: &mut BTreeMap<String, usize>, key: &str) {
    match map.get_mut(key) {
        Some(count) if *count > 1 => *count -= 1,
        Some(_) => {
            map.remove(key);
        }
        None => {}
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Lease {
    Intent {
        project_id: String,
        intent_id: String,
    },
    Reason {
        project_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum WorkerAction {
    Fact {
        description: String,
        complete: bool,
    },
    DeclareIntent {
        sources: Vec<String>,
        description: String,
    },
    Complete {
        sources: Vec<String>,
        description: String,
    },
    Noop,
}

fn is_conflict<T>(result: &Result<T, clairvoyant_server::ClairvoyantError>) -> bool {
    matches!(
        result,
        Err(clairvoyant_server::ClairvoyantError::Api { status: 409, .. })
    )
}

fn is_bootstrap_project(detail: &ProjectDetail, bootstrap_intent: &str) -> bool {
    detail.facts.len() == 2
        && detail.facts.iter().any(|fact| fact.id == "origin")
        && detail.facts.iter().any(|fact| fact.id == "goal")
        && detail
            .intents
            .iter()
            .all(|intent| is_reserved_bootstrap_intent(intent, bootstrap_intent))
}

fn is_reserved_bootstrap_intent(intent: &clairvoyant_core::Intent, bootstrap_intent: &str) -> bool {
    intent.description == bootstrap_intent
        && intent.creator == "dispatcher.bootstrap"
        && intent.sources == ["origin"]
        && intent.target_fact.is_none()
}

impl ReasonCheckpoint {
    fn from_detail(detail: &ProjectDetail) -> Self {
        Self {
            fact_count: detail.facts.len(),
            hint_count: detail.hints.len(),
            open_intent_count: detail
                .intents
                .iter()
                .filter(|intent| intent.target_fact.is_none())
                .count(),
        }
    }
}

fn reason_state_summary(detail: &ProjectDetail) -> String {
    let open = detail
        .intents
        .iter()
        .filter(|intent| intent.target_fact.is_none())
        .count();
    format!(
        "facts={} hints={} open_intents={open}",
        detail.facts.len(),
        detail.hints.len()
    )
}

#[derive(Debug, Clone, Copy)]
struct PromptBundle {
    bootstrap: &'static str,
    bootstrap_conclude: &'static str,
    reason: &'static str,
    explore: &'static str,
    explore_conclude: &'static str,
}

impl PromptBundle {
    fn validate_complete(self, group: &str) -> Result<Self, DispatcherError> {
        for (name, template) in [
            ("bootstrap", self.bootstrap),
            ("bootstrap_conclude", self.bootstrap_conclude),
            ("reason", self.reason),
            ("explore", self.explore),
            ("explore_conclude", self.explore_conclude),
        ] {
            if template.trim().is_empty() {
                return Err(DispatcherError::InvalidConfig(format!(
                    "prompt group {group} has empty {name} template"
                )));
            }
        }
        Ok(self)
    }
}

fn prompt_bundle(group: &str) -> Result<PromptBundle, DispatcherError> {
    match group {
        "default" => Ok(PromptBundle {
            bootstrap: DEFAULT_BOOTSTRAP_PROMPT,
            bootstrap_conclude: DEFAULT_BOOTSTRAP_CONCLUDE_PROMPT,
            reason: DEFAULT_REASON_PROMPT,
            explore: DEFAULT_EXPLORE_PROMPT,
            explore_conclude: DEFAULT_EXPLORE_CONCLUDE_PROMPT,
        }
        .validate_complete(group)?),
        "cybergym" => Ok(PromptBundle {
            bootstrap: CYBERGYM_BOOTSTRAP_PROMPT,
            bootstrap_conclude: CYBERGYM_BOOTSTRAP_CONCLUDE_PROMPT,
            reason: CYBERGYM_REASON_PROMPT,
            explore: CYBERGYM_EXPLORE_PROMPT,
            explore_conclude: CYBERGYM_EXPLORE_CONCLUDE_PROMPT,
        }
        .validate_complete(group)?),
        "python" => Ok(PromptBundle {
            bootstrap: PYTHON_BOOTSTRAP_PROMPT,
            bootstrap_conclude: PYTHON_BOOTSTRAP_CONCLUDE_PROMPT,
            reason: PYTHON_REASON_PROMPT,
            explore: PYTHON_EXPLORE_PROMPT,
            explore_conclude: PYTHON_EXPLORE_CONCLUDE_PROMPT,
        }
        .validate_complete(group)?),
        "mock" => Ok(PromptBundle {
            bootstrap: MOCK_BOOTSTRAP_PROMPT,
            bootstrap_conclude: MOCK_BOOTSTRAP_CONCLUDE_PROMPT,
            reason: MOCK_REASON_PROMPT,
            explore: MOCK_EXPLORE_PROMPT,
            explore_conclude: MOCK_EXPLORE_CONCLUDE_PROMPT,
        }
        .validate_complete(group)?),
        other => Err(DispatcherError::InvalidConfig(format!(
            "missing prompt group: {other}"
        ))),
    }
}

fn render_prompt(
    bundle: PromptBundle,
    detail: &ProjectDetail,
    intent: &clairvoyant_core::Intent,
    kind: TaskKind,
) -> String {
    let template = match kind {
        TaskKind::Bootstrap => bundle.bootstrap,
        TaskKind::Explore => bundle.explore,
    };
    render_template(
        template,
        &[
            ("project_id", detail.project.id.as_str()),
            ("intent_id", intent.id.as_str()),
            ("intent_description", intent.description.as_str()),
            ("origin", fact_description(detail, "origin").unwrap_or("")),
            ("goal", fact_description(detail, "goal").unwrap_or("")),
            ("hints", &hints_text(detail)),
            ("graph_yaml", &graph_snapshot_yaml(detail)),
        ],
    )
}

fn render_conclude_prompt(
    bundle: PromptBundle,
    detail: &ProjectDetail,
    intent: &clairvoyant_core::Intent,
    kind: TaskKind,
) -> String {
    let template = match kind {
        TaskKind::Bootstrap => bundle.bootstrap_conclude,
        TaskKind::Explore => bundle.explore_conclude,
    };
    render_template(
        template,
        &[
            ("project_id", detail.project.id.as_str()),
            ("intent_id", intent.id.as_str()),
            ("intent_description", intent.description.as_str()),
            ("origin", fact_description(detail, "origin").unwrap_or("")),
            ("goal", fact_description(detail, "goal").unwrap_or("")),
            ("hints", &hints_text(detail)),
            ("graph_yaml", &graph_snapshot_yaml(detail)),
        ],
    )
}

fn render_reason_prompt(
    bundle: PromptBundle,
    detail: &ProjectDetail,
    max_intents: usize,
) -> String {
    render_template(
        bundle.reason,
        &[
            ("project_id", detail.project.id.as_str()),
            ("origin", fact_description(detail, "origin").unwrap_or("")),
            ("goal", fact_description(detail, "goal").unwrap_or("")),
            ("hints", &hints_text(detail)),
            ("graph_yaml", &graph_snapshot_yaml(detail)),
            ("fact_ids", &valid_fact_ids_text(detail)),
            ("open_intents", &open_intents_text(detail)),
            ("max_intents", &max_intents.to_string()),
        ],
    )
}

fn render_template(template: &str, values: &[(&str, &str)]) -> String {
    // Two-pass substitution to prevent value leakage into subsequent
    // placeholders.  A value containing "{goal}" must not be re-scanned.
    let mut rendered = template.to_string();
    let mut sentinels: Vec<(String, &str)> = Vec::with_capacity(values.len());
    for (idx, (key, value)) in values.iter().enumerate() {
        let sentinel = format!("\x00TPL{}\x00", idx);
        rendered = rendered
            .replace(&format!("{{{key}}}"), &sentinel)
            .replace(&format!("{{{{{key}}}}}"), &sentinel);
        sentinels.push((sentinel, value));
    }
    for (sentinel, value) in sentinels {
        rendered = rendered.replace(&sentinel, value);
    }
    rendered
}

fn fact_description<'a>(detail: &'a ProjectDetail, id: &str) -> Option<&'a str> {
    detail
        .facts
        .iter()
        .find(|fact| fact.id == id)
        .map(|fact| fact.description.as_str())
}

fn hints_text(detail: &ProjectDetail) -> String {
    let hints = detail
        .hints
        .iter()
        .map(|hint| {
            serde_json::json!({
                "id": hint.id,
                "content": hint.content,
                "creator": hint.creator,
                "created_at": hint.created_at,
            })
        })
        .collect::<Vec<_>>();
    serde_json::to_string_pretty(&hints).unwrap_or_else(|_| "[]".to_string())
}

fn valid_fact_ids_text(detail: &ProjectDetail) -> String {
    let ids = detail
        .facts
        .iter()
        .filter(|fact| fact.id != "goal")
        .map(|fact| fact.id.as_str())
        .collect::<Vec<_>>();
    serde_json::to_string_pretty(&ids).unwrap_or_else(|_| "[]".to_string())
}

fn open_intents_text(detail: &ProjectDetail) -> String {
    let open_intents = detail
        .intents
        .iter()
        .filter(|intent| intent.target_fact.is_none())
        .map(|intent| {
            serde_json::json!({
                "id": intent.id,
                "sources": intent.sources,
                "description": intent.description,
                "creator": intent.creator,
                "worker": intent.worker,
                "created_at": intent.created_at,
            })
        })
        .collect::<Vec<_>>();
    serde_json::to_string_pretty(&open_intents).unwrap_or_else(|_| "[]".to_string())
}

fn graph_snapshot_yaml(detail: &ProjectDetail) -> String {
    serde_yaml::to_string(detail).unwrap_or_else(|_| "{}\n".to_string())
}

fn choose_worker_action(events: &[WorkerEvent]) -> Result<WorkerAction, DispatcherError> {
    for event in events.iter().rev() {
        match event {
            WorkerEvent::Done {
                description,
                complete,
            } => {
                return Ok(WorkerAction::Fact {
                    description: description.clone(),
                    complete: *complete,
                });
            }
            WorkerEvent::Intent {
                sources,
                description,
            } => {
                return Ok(WorkerAction::DeclareIntent {
                    sources: sources.clone(),
                    description: description.clone(),
                });
            }
            WorkerEvent::Complete {
                sources,
                description,
            } => {
                return Ok(WorkerAction::Complete {
                    sources: sources.clone(),
                    description: description.clone(),
                });
            }
            WorkerEvent::Error { message } => {
                return Err(clairvoyant_workers::WorkerError::Failed(message.clone()).into());
            }
            _ => {}
        }
    }
    Ok(WorkerAction::Noop)
}

fn worker_error_message(events: &[WorkerEvent]) -> Option<String> {
    events.iter().find_map(|event| match event {
        WorkerEvent::Error { message } => Some(message.clone()),
        _ => None,
    })
}

fn last_complete_event(events: &[WorkerEvent]) -> Option<(Vec<String>, String)> {
    events.iter().rev().find_map(|event| match event {
        WorkerEvent::Complete {
            sources,
            description,
        } => Some((sources.clone(), description.clone())),
        _ => None,
    })
}

fn intent_events(events: &[WorkerEvent], limit: usize) -> Vec<(Vec<String>, String)> {
    events
        .iter()
        .filter_map(|event| match event {
            WorkerEvent::Intent {
                sources,
                description,
            } => Some((sources.clone(), description.clone())),
            _ => None,
        })
        .take(limit)
        .collect()
}

fn worker_events_complete_project(events: &[WorkerEvent]) -> bool {
    events.iter().any(|event| match event {
        WorkerEvent::Done { complete, .. } => *complete,
        WorkerEvent::Complete { .. } => true,
        _ => false,
    })
}

fn expect_project_summaries(
    response: ClairvoyantResponse,
) -> Result<Vec<clairvoyant_core::ProjectSummary>, DispatcherError> {
    match response {
        ClairvoyantResponse::ProjectSummaries(projects) => Ok(projects),
        _ => Err(DispatcherError::UnexpectedResponse("project summaries")),
    }
}

fn expect_project_detail(response: ClairvoyantResponse) -> Result<ProjectDetail, DispatcherError> {
    match response {
        ClairvoyantResponse::ProjectDetail(detail) => Ok(detail),
        _ => Err(DispatcherError::UnexpectedResponse("project detail")),
    }
}

fn expect_intent(
    response: ClairvoyantResponse,
) -> Result<clairvoyant_core::Intent, DispatcherError> {
    match response {
        ClairvoyantResponse::Intent(intent) => Ok(intent),
        _ => Err(DispatcherError::UnexpectedResponse("intent")),
    }
}

fn expect_conclude(
    response: ClairvoyantResponse,
) -> Result<clairvoyant_core::ConcludeResponse, DispatcherError> {
    match response {
        ClairvoyantResponse::Conclude(response) => Ok(response),
        _ => Err(DispatcherError::UnexpectedResponse("conclude")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use clairvoyant_core::{ClairvoyantRequest, CreateProjectRequest};
    use clairvoyant_runtime::RuntimeConfig;
    use clairvoyant_workers::{MockWorker, WorkerEvent};
    use std::collections::BTreeMap;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::time::Duration;

    struct DelayWorker {
        current: Arc<AtomicUsize>,
        max_seen: Arc<AtomicUsize>,
        delay: Duration,
    }

    #[async_trait::async_trait]
    impl clairvoyant_workers::Worker for DelayWorker {
        async fn run(
            &self,
            _prompt: &str,
            _context: WorkerContext,
        ) -> Result<Vec<WorkerEvent>, clairvoyant_workers::WorkerError> {
            let running = self.current.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_seen.fetch_max(running, Ordering::SeqCst);
            tokio::time::sleep(self.delay).await;
            self.current.fetch_sub(1, Ordering::SeqCst);
            Ok(vec![WorkerEvent::Done {
                description: "delayed fact".to_string(),
                complete: false,
            }])
        }
    }

    struct FailingWorker;

    #[async_trait::async_trait]
    impl clairvoyant_workers::Worker for FailingWorker {
        async fn run(
            &self,
            _prompt: &str,
            _context: WorkerContext,
        ) -> Result<Vec<WorkerEvent>, clairvoyant_workers::WorkerError> {
            Err(clairvoyant_workers::WorkerError::Failed(
                "reason failed".to_string(),
            ))
        }
    }

    struct FactTriggeredReasonWorker {
        reason_calls: Arc<AtomicUsize>,
        explore_calls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl clairvoyant_workers::Worker for FactTriggeredReasonWorker {
        async fn run(
            &self,
            _prompt: &str,
            context: WorkerContext,
        ) -> Result<Vec<WorkerEvent>, clairvoyant_workers::WorkerError> {
            if context.intent_id.is_none() {
                self.reason_calls.fetch_add(1, Ordering::SeqCst);
                return Ok(vec![WorkerEvent::Message {
                    text: "reason observed new fact".to_string(),
                }]);
            }
            self.explore_calls.fetch_add(1, Ordering::SeqCst);
            Ok(vec![WorkerEvent::Done {
                description: "explore consumed remaining intent".to_string(),
                complete: false,
            }])
        }
    }

    async fn service() -> ClairvoyantService {
        let path = std::env::temp_dir().join(format!(
            "clairvoyant-dispatcher-{}-{}.db",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        ClairvoyantService::open(path).await.expect("open service")
    }

    async fn create_test_project(service: &ClairvoyantService, title: &str) -> String {
        match service
            .handle(ClairvoyantRequest::CreateProject {
                body: CreateProjectRequest {
                    title: title.to_string(),
                    origin: "start".to_string(),
                    goal: "finish".to_string(),
                    hints: None,
                },
            })
            .await
            .expect("create project")
        {
            ClairvoyantResponse::ProjectDetail(detail) => detail.project.id,
            other => panic!("unexpected create response {other:?}"),
        }
    }

    fn config() -> DispatcherConfig {
        DispatcherConfig {
            db_path: None,
            worker: Some(WorkerConfig::Mock {
                description: "mock fact".to_string(),
                env: BTreeMap::new(),
            }),
            workers: Vec::new(),
            common_env: BTreeMap::new(),
            runtime: SchedulerRuntimeConfig::default(),
            tasks: TaskConfig::default(),
            container: None,
            worker_name: "dispatcher".to_string(),
            bootstrap_intent: "bootstrap".to_string(),
        }
    }

    fn write_executable_script(path: &std::path::Path, script: &str) {
        let mut file = std::fs::File::create(path).expect("create script");
        file.write_all(script.as_bytes()).expect("write script");
        file.sync_all().expect("sync script");
        drop(file);
        let mut perms = std::fs::metadata(path).expect("metadata").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(path, perms).expect("chmod script");
    }

    async fn read_pid_file(path: &std::path::Path) -> String {
        for _ in 0..50 {
            if path.exists() {
                return std::fs::read_to_string(path)
                    .expect("read pid file")
                    .trim()
                    .to_string();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("pid file was not written: {}", path.display());
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

    fn detail_for_prompt_tests() -> ProjectDetail {
        ProjectDetail {
            project: clairvoyant_core::ProjectMeta {
                id: "proj_001".to_string(),
                title: "demo".to_string(),
                status: ProjectStatus::Active,
                created_at: 1,
                reason: None,
            },
            facts: vec![
                clairvoyant_core::Fact {
                    id: "origin".to_string(),
                    description: "start here".to_string(),
                },
                clairvoyant_core::Fact {
                    id: "goal".to_string(),
                    description: "finish there".to_string(),
                },
                clairvoyant_core::Fact {
                    id: "f001".to_string(),
                    description: "known fact".to_string(),
                },
            ],
            intents: vec![clairvoyant_core::Intent {
                id: "i001".to_string(),
                sources: vec!["f001".to_string()],
                target_fact: None,
                description: "open branch".to_string(),
                creator: "tester".to_string(),
                worker: None,
                last_heartbeat_at: None,
                created_at: 2,
                concluded_at: None,
            }],
            hints: vec![clairvoyant_core::Hint {
                id: "h001".to_string(),
                content: "look closely".to_string(),
                creator: "human".to_string(),
                created_at: 3,
            }],
        }
    }

    #[test]
    fn renders_bootstrap_template_with_context_bundle() {
        let detail = detail_for_prompt_tests();
        let intent = clairvoyant_core::Intent {
            id: "i000".to_string(),
            sources: vec!["origin".to_string()],
            target_fact: None,
            description: "bootstrap".to_string(),
            creator: "dispatcher.bootstrap".to_string(),
            worker: None,
            last_heartbeat_at: None,
            created_at: 1,
            concluded_at: None,
        };
        let prompt = render_prompt(
            prompt_bundle("default").expect("prompt bundle"),
            &detail,
            &intent,
            TaskKind::Bootstrap,
        );
        assert!(prompt.contains("start here"));
        assert!(prompt.contains("finish there"));
        assert!(prompt.contains("look closely"));
        assert!(!prompt.contains("{origin}"));
        assert!(!prompt.contains("{goal}"));
        assert!(!prompt.contains("{hints}"));
    }

    #[test]
    fn renders_reason_template_with_graph_and_limits() {
        let detail = detail_for_prompt_tests();
        let prompt =
            render_reason_prompt(prompt_bundle("default").expect("prompt bundle"), &detail, 2);
        assert!(prompt.contains("proj_001"));
        assert!(prompt.contains("known fact"));
        assert!(prompt.contains("f001"));
        assert!(prompt.contains("open branch"));
        assert!(prompt.contains("at most 2 high-value"));
        assert!(!prompt.contains("{graph_yaml}"));
        assert!(!prompt.contains("{fact_ids}"));
        assert!(!prompt.contains("{open_intents}"));
        assert!(!prompt.contains("{max_intents}"));
    }

    #[test]
    fn renders_explore_template_with_current_intent() {
        let detail = detail_for_prompt_tests();
        let intent = detail.intents[0].clone();
        let prompt = render_prompt(
            prompt_bundle("default").expect("prompt bundle"),
            &detail,
            &intent,
            TaskKind::Explore,
        );
        assert!(prompt.contains("proj_001"));
        assert!(prompt.contains("i001"));
        assert!(prompt.contains("open branch"));
        assert!(prompt.contains("known fact"));
        assert!(!prompt.contains("{intent_id}"));
        assert!(!prompt.contains("{intent_description}"));
        assert!(!prompt.contains("{graph_yaml}"));
    }

    #[test]
    fn renders_conclude_templates_for_bootstrap_and_explore() {
        let detail = detail_for_prompt_tests();
        let bundle = prompt_bundle("mock").expect("mock prompts");
        let bootstrap_intent = clairvoyant_core::Intent {
            id: "i000".to_string(),
            sources: vec!["origin".to_string()],
            target_fact: None,
            description: "bootstrap".to_string(),
            creator: "dispatcher.bootstrap".to_string(),
            worker: None,
            last_heartbeat_at: None,
            created_at: 1,
            concluded_at: None,
        };

        let bootstrap =
            render_conclude_prompt(bundle, &detail, &bootstrap_intent, TaskKind::Bootstrap);
        let bootstrap_json: serde_json::Value =
            serde_json::from_str(&bootstrap).expect("bootstrap conclude json");
        assert_eq!(bootstrap_json["phase"], "bootstrap_conclude");
        assert_eq!(bootstrap_json["hints"][0]["content"], "look closely");

        let explore =
            render_conclude_prompt(bundle, &detail, &detail.intents[0], TaskKind::Explore);
        let explore_json: serde_json::Value =
            serde_json::from_str(&explore).expect("explore conclude json");
        assert_eq!(explore_json["phase"], "explore_conclude");
        assert_eq!(explore_json["intent_id"], "i001");
    }

    #[test]
    fn prompt_bundle_embeds_all_phase_templates() {
        let default = prompt_bundle("default").expect("default bundle");
        assert!(default.bootstrap.contains("Origin"));
        assert!(default
            .bootstrap
            .contains(r#"{"event":"done","description":"...","complete":false}"#));
        assert!(default
            .bootstrap
            .contains("No prose, markdown, or code fences before/after"));
        assert!(default.bootstrap_conclude.contains("CONCLUDE phase"));
        assert!(default
            .reason
            .contains("Whether the current facts already satisfy Goal"));
        assert!(default.explore.contains("Current Intent"));
        assert!(default.explore_conclude.contains("conclude phase"));

        let mock = prompt_bundle("mock").expect("mock bundle");
        assert!(mock.bootstrap.contains("\"phase\": \"bootstrap\""));
        assert!(mock
            .bootstrap_conclude
            .contains("\"phase\": \"bootstrap_conclude\""));
        assert!(mock.reason.contains("\"phase\": \"reason\""));
        assert!(mock.explore.contains("\"phase\": \"explore_execute\""));
        assert!(mock
            .explore_conclude
            .contains("\"phase\": \"explore_conclude\""));

        let python = prompt_bundle("python").expect("python bundle");
        assert!(python.bootstrap.contains(r#"{"accepted": true"#));
        assert!(python.reason.contains(r#""complete": {"from": ["f001"]"#));
        assert!(python.explore.contains(r#""data": {"description": "..."}"#));

        let cybergym = prompt_bundle("cybergym").expect("cybergym bundle");
        assert!(cybergym.bootstrap.contains("Phase: bootstrap"));
        assert!(cybergym.reason.contains("Phase: reason"));
        assert!(cybergym.explore.contains("Phase: explore"));
        assert!(cybergym
            .explore_conclude
            .contains("Phase: explore_conclude"));
        assert!(!cybergym
            .reason
            .contains("Return only newline-delimited JSON"));
    }

    #[test]
    fn renders_mock_prompt_group_as_json_payloads() {
        let detail = detail_for_prompt_tests();
        let bundle = prompt_bundle("mock").expect("mock prompts");
        let bootstrap_intent = clairvoyant_core::Intent {
            id: "i000".to_string(),
            sources: vec!["origin".to_string()],
            target_fact: None,
            description: "bootstrap".to_string(),
            creator: "dispatcher.bootstrap".to_string(),
            worker: None,
            last_heartbeat_at: None,
            created_at: 1,
            concluded_at: None,
        };

        let bootstrap = render_prompt(bundle, &detail, &bootstrap_intent, TaskKind::Bootstrap);
        let bootstrap_json: serde_json::Value =
            serde_json::from_str(&bootstrap).expect("bootstrap json");
        assert_eq!(bootstrap_json["phase"], "bootstrap");
        assert_eq!(bootstrap_json["hints"][0]["content"], "look closely");

        let reason = render_reason_prompt(bundle, &detail, 3);
        let reason_json: serde_json::Value = serde_json::from_str(&reason).expect("reason json");
        assert_eq!(reason_json["phase"], "reason");
        assert_eq!(reason_json["fact_ids"][2], "f001");
        assert_eq!(reason_json["open_intents"][0]["id"], "i001");
        assert_eq!(reason_json["max_intents"], 3);

        let explore = render_prompt(bundle, &detail, &detail.intents[0], TaskKind::Explore);
        let explore_json: serde_json::Value = serde_json::from_str(&explore).expect("explore json");
        assert_eq!(explore_json["phase"], "explore_execute");
        assert_eq!(explore_json["intent_id"], "i001");
    }

    #[test]
    fn rejects_unknown_prompt_group_during_config_validation() {
        let yaml = r#"
runtime:
  prompt_group: missing
worker:
  kind: mock
  description: fact
"#;
        let config: DispatcherConfig = serde_yaml::from_str(yaml).expect("parse");
        let error = config.validate().expect_err("missing prompt group");
        assert!(error.to_string().contains("missing prompt group: missing"));
    }

    #[test]
    fn python_prompt_group_is_restricted_to_mock_workers() {
        let mock = r#"
runtime:
  prompt_group: python
worker:
  kind: mock
  description: fact
"#;
        let config: DispatcherConfig = serde_yaml::from_str(mock).expect("parse mock");
        config
            .validate()
            .expect("python prompt group is allowed for mock provenance checks");

        let command = r#"
runtime:
  prompt_group: python
worker:
  kind: command
  program: /bin/echo
"#;
        let config: DispatcherConfig = serde_yaml::from_str(command).expect("parse command");
        let error = config
            .validate()
            .expect_err("python prompt group should not be accepted for command workers")
            .to_string();
        assert!(error.contains("legacy Python JSON contract"));
        assert!(error.contains("NDJSON prompt group"));

        let mixed = r#"
runtime:
  prompt_group: python
workers:
  - name: mock-main
    type: mock
    task_types: [bootstrap]
  - name: claude-main
    type: claudecode
    task_types: [reason, explore]
    args: ["--print", "--input-format", "text", "--output-format", "text"]
"#;
        let config: DispatcherConfig = serde_yaml::from_str(mixed).expect("parse mixed");
        let error = config
            .validate()
            .expect_err("python prompt group should reject mixed real workers")
            .to_string();
        assert!(error.contains("worker claude-main"));
        assert!(error.contains("legacy Python JSON contract"));
    }

    #[test]
    fn rejects_unknown_dispatcher_config_fields() {
        let top_level = r#"
unknown: true
worker:
  kind: mock
  description: fact
"#;
        let error = serde_yaml::from_str::<DispatcherConfig>(top_level)
            .expect_err("unknown top-level config field should fail");
        assert!(error.to_string().contains("unknown"));

        let nested_worker = r#"
workers:
  - name: mock
    type: mock
    task_types: [bootstrap, reason, explore]
    unexpected: true
"#;
        let error = serde_yaml::from_str::<DispatcherConfig>(nested_worker)
            .expect_err("unknown worker field should fail");
        assert!(error.to_string().contains("unknown"));

        let nested_task = r#"
tasks:
  reason:
    timeout: 10
    max_intents: 1
    unexpected: true
worker:
  kind: mock
  description: fact
"#;
        let error = serde_yaml::from_str::<DispatcherConfig>(nested_task)
            .expect_err("unknown task field should fail");
        assert!(error.to_string().contains("unknown"));

        let nested_runtime = r#"
runtime:
  interval: 1
  unexpected: true
worker:
  kind: mock
  description: fact
"#;
        let error = serde_yaml::from_str::<DispatcherConfig>(nested_runtime)
            .expect_err("unknown runtime field should fail");
        assert!(error.to_string().contains("unknown"));

        let nested_container = r#"
container:
  image: agent
  unexpected: true
worker:
  kind: mock
  description: fact
"#;
        let error = serde_yaml::from_str::<DispatcherConfig>(nested_container)
            .expect_err("unknown container field should fail");
        assert!(error.to_string().contains("unknown"));

        let single_worker = r#"
worker:
  kind: mock
  description: fact
  unexpected: true
"#;
        let error = serde_yaml::from_str::<DispatcherConfig>(single_worker)
            .expect_err("unknown single worker field should fail");
        assert!(error.to_string().contains("unknown"));
    }

    struct BlockingWorker;

    #[async_trait::async_trait]
    impl Worker for BlockingWorker {
        async fn run(
            &self,
            _prompt: &str,
            _context: WorkerContext,
        ) -> Result<Vec<WorkerEvent>, clairvoyant_workers::WorkerError> {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            Ok(Vec::new())
        }
    }

    struct AbortObservedWorker {
        started: Arc<tokio::sync::Notify>,
        dropped: Arc<tokio::sync::Notify>,
    }

    #[async_trait::async_trait]
    impl Worker for AbortObservedWorker {
        async fn run(
            &self,
            _prompt: &str,
            _context: WorkerContext,
        ) -> Result<Vec<WorkerEvent>, clairvoyant_workers::WorkerError> {
            struct DropSignal(Arc<tokio::sync::Notify>);
            impl Drop for DropSignal {
                fn drop(&mut self) {
                    self.0.notify_one();
                }
            }

            let _drop_signal = DropSignal(Arc::clone(&self.dropped));
            self.started.notify_one();
            std::future::pending::<()>().await;
            Ok(Vec::new())
        }
    }

    struct FailThenDoneWorker {
        calls: Arc<AtomicUsize>,
        prompts: Arc<Mutex<Vec<String>>>,
        fallback_description: String,
    }

    #[async_trait::async_trait]
    impl Worker for FailThenDoneWorker {
        async fn run(
            &self,
            prompt: &str,
            _context: WorkerContext,
        ) -> Result<Vec<WorkerEvent>, clairvoyant_workers::WorkerError> {
            self.prompts
                .lock()
                .expect("prompts lock")
                .push(prompt.to_string());
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                return Err(clairvoyant_workers::WorkerError::Failed(
                    "execute failed".to_string(),
                ));
            }
            Ok(vec![WorkerEvent::Done {
                description: self.fallback_description.clone(),
                complete: false,
            }])
        }
    }

    struct NoopThenDoneWorker {
        calls: Arc<AtomicUsize>,
        prompts: Arc<Mutex<Vec<String>>>,
        fallback_description: String,
    }

    #[async_trait::async_trait]
    impl Worker for NoopThenDoneWorker {
        async fn run(
            &self,
            prompt: &str,
            _context: WorkerContext,
        ) -> Result<Vec<WorkerEvent>, clairvoyant_workers::WorkerError> {
            self.prompts
                .lock()
                .expect("prompts lock")
                .push(prompt.to_string());
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                return Ok(vec![WorkerEvent::Message {
                    text: "execute produced no fact".to_string(),
                }]);
            }
            Ok(vec![WorkerEvent::Done {
                description: self.fallback_description.clone(),
                complete: false,
            }])
        }
    }

    struct StreamOnlyWorker;

    #[async_trait::async_trait]
    impl Worker for StreamOnlyWorker {
        async fn run(
            &self,
            _prompt: &str,
            _context: WorkerContext,
        ) -> Result<Vec<WorkerEvent>, clairvoyant_workers::WorkerError> {
            Err(clairvoyant_workers::WorkerError::Failed(
                "dispatcher should use run_stream".to_string(),
            ))
        }

        async fn run_stream(
            &self,
            _prompt: &str,
            _context: WorkerContext,
        ) -> Result<WorkerEventStream, clairvoyant_workers::WorkerError> {
            Ok(Box::pin(tokio_stream::iter([Ok(WorkerEvent::Done {
                description: "streamed dispatcher fact".to_string(),
                complete: false,
            })])))
        }
    }

    struct DoneThenPendingStreamWorker;

    #[async_trait::async_trait]
    impl Worker for DoneThenPendingStreamWorker {
        async fn run(
            &self,
            _prompt: &str,
            _context: WorkerContext,
        ) -> Result<Vec<WorkerEvent>, clairvoyant_workers::WorkerError> {
            Err(clairvoyant_workers::WorkerError::Failed(
                "dispatcher should use run_stream".to_string(),
            ))
        }

        async fn run_stream(
            &self,
            _prompt: &str,
            _context: WorkerContext,
        ) -> Result<WorkerEventStream, clairvoyant_workers::WorkerError> {
            let first = tokio_stream::iter([Ok(WorkerEvent::Done {
                description: "early streamed fact".to_string(),
                complete: false,
            })]);
            Ok(Box::pin(first.chain(tokio_stream::pending())))
        }
    }

    struct DropObservedDoneStreamWorker {
        dropped: Arc<tokio::sync::Notify>,
    }

    #[async_trait::async_trait]
    impl Worker for DropObservedDoneStreamWorker {
        async fn run(
            &self,
            _prompt: &str,
            _context: WorkerContext,
        ) -> Result<Vec<WorkerEvent>, clairvoyant_workers::WorkerError> {
            Err(clairvoyant_workers::WorkerError::Failed(
                "dispatcher should use run_stream".to_string(),
            ))
        }

        async fn run_stream(
            &self,
            _prompt: &str,
            _context: WorkerContext,
        ) -> Result<WorkerEventStream, clairvoyant_workers::WorkerError> {
            Ok(Box::pin(DropObservedDoneStream {
                emitted: false,
                dropped: Arc::clone(&self.dropped),
            }))
        }
    }

    struct DropObservedDoneStream {
        emitted: bool,
        dropped: Arc<tokio::sync::Notify>,
    }

    impl tokio_stream::Stream for DropObservedDoneStream {
        type Item = Result<WorkerEvent, clairvoyant_workers::WorkerError>;

        fn poll_next(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            if self.emitted {
                return std::task::Poll::Pending;
            }
            self.emitted = true;
            std::task::Poll::Ready(Some(Ok(WorkerEvent::Done {
                description: "drop observed fact".to_string(),
                complete: false,
            })))
        }
    }

    impl Drop for DropObservedDoneStream {
        fn drop(&mut self) {
            self.dropped.notify_one();
        }
    }

    struct ReasonIntentsThenPendingStreamWorker;

    #[async_trait::async_trait]
    impl Worker for ReasonIntentsThenPendingStreamWorker {
        async fn run(
            &self,
            _prompt: &str,
            _context: WorkerContext,
        ) -> Result<Vec<WorkerEvent>, clairvoyant_workers::WorkerError> {
            Err(clairvoyant_workers::WorkerError::Failed(
                "dispatcher should use run_stream".to_string(),
            ))
        }

        async fn run_stream(
            &self,
            _prompt: &str,
            _context: WorkerContext,
        ) -> Result<WorkerEventStream, clairvoyant_workers::WorkerError> {
            let events = tokio_stream::iter([
                Ok(WorkerEvent::Intent {
                    sources: vec!["f001".to_string()],
                    description: "streamed first branch".to_string(),
                }),
                Ok(WorkerEvent::Intent {
                    sources: vec!["f001".to_string()],
                    description: "streamed second branch".to_string(),
                }),
            ]);
            Ok(Box::pin(events.chain(tokio_stream::pending())))
        }
    }

    struct DropObservedReasonIntentsStreamWorker {
        dropped: Arc<tokio::sync::Notify>,
    }

    #[async_trait::async_trait]
    impl Worker for DropObservedReasonIntentsStreamWorker {
        async fn run(
            &self,
            _prompt: &str,
            _context: WorkerContext,
        ) -> Result<Vec<WorkerEvent>, clairvoyant_workers::WorkerError> {
            Err(clairvoyant_workers::WorkerError::Failed(
                "dispatcher should use run_stream".to_string(),
            ))
        }

        async fn run_stream(
            &self,
            _prompt: &str,
            _context: WorkerContext,
        ) -> Result<WorkerEventStream, clairvoyant_workers::WorkerError> {
            Ok(Box::pin(DropObservedReasonIntentsStream {
                emitted: 0,
                dropped: Arc::clone(&self.dropped),
            }))
        }
    }

    struct DropObservedReasonIntentsStream {
        emitted: usize,
        dropped: Arc<tokio::sync::Notify>,
    }

    impl tokio_stream::Stream for DropObservedReasonIntentsStream {
        type Item = Result<WorkerEvent, clairvoyant_workers::WorkerError>;

        fn poll_next(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            if self.emitted >= 2 {
                return std::task::Poll::Pending;
            }
            self.emitted += 1;
            std::task::Poll::Ready(Some(Ok(WorkerEvent::Intent {
                sources: vec!["f001".to_string()],
                description: format!("drop observed branch {}", self.emitted),
            })))
        }
    }

    impl Drop for DropObservedReasonIntentsStream {
        fn drop(&mut self) {
            self.dropped.notify_one();
        }
    }

    #[test]
    fn parses_workers_array_config_shape() {
        let yaml = r#"
runtime:
  interval: 3
tasks:
  reason:
    max_intents: 2
workers:
  - name: claude-main
    type: claudecode
    task_types: [bootstrap, reason, explore]
    max_running: 2
    priority: 0
    env:
      ANTHROPIC_MODEL: claude-test
      ANTHROPIC_BASE_URL: https://example.invalid
      ANTHROPIC_API_KEY: placeholder
    args: ["--print", "--input-format", "text", "--output-format", "text"]
"#;
        let config: DispatcherConfig = serde_yaml::from_str(yaml).expect("parse");
        config.validate().expect("valid");
        assert_eq!(config.workers.len(), 1);
        assert_eq!(config.workers[0].kind, WorkerKind::ClaudeCode);
        assert_eq!(config.runtime.interval, 3);
        assert!(config.container.is_none());
        match config.primary_worker_config().expect("primary") {
            WorkerConfig::ClaudeCode { args, .. } => assert_eq!(
                args,
                vec![
                    "--print",
                    "--input-format",
                    "text",
                    "--output-format",
                    "text"
                ]
            ),
            other => panic!("unexpected worker config {other:?}"),
        }
    }

    #[test]
    fn rejects_unsupported_model_worker_kinds() {
        for kind in ["codex", "pi"] {
            let yaml = format!(
                r#"
worker:
  kind: {kind}
"#
            );
            let error = serde_yaml::from_str::<DispatcherConfig>(&yaml)
                .expect_err("unsupported worker kind should fail schema parsing");
            assert!(error.to_string().contains("unknown variant"));
        }
    }

    #[test]
    fn maps_container_config_to_runtime_config() {
        let yaml = r#"
common_env:
  RUN_DIR: "/runs/{project_id}"
container:
  image: " agent:{project_id} "
  network_mode: "none"
  workdir: "/work/{project_id}"
  volumes:
    - " /host/{project_id}:/runs/{project_id} "
  extra_hosts:
    - " example.com:0.0.0.0 "
worker:
  kind: mock
  description: "fact"
"#;
        let config: DispatcherConfig = serde_yaml::from_str(yaml).expect("parse");
        config.validate().expect("valid");
        let runtime = config.runtime_config().expect("runtime config");
        assert_eq!(runtime.image.as_deref(), Some("agent:{project_id}"));
        assert!(runtime.network_disabled);
        assert_eq!(runtime.network_mode.as_deref(), Some("none"));
        assert_eq!(
            runtime.volumes,
            vec!["/host/{project_id}:/runs/{project_id}"]
        );
        assert_eq!(runtime.extra_hosts, vec!["example.com:0.0.0.0"]);
        assert_eq!(
            runtime.env.get("RUN_DIR").map(String::as_str),
            Some("/runs/{project_id}")
        );
    }

    #[test]
    fn maps_worker_specific_env_to_runtime_config_when_worker_is_selected() {
        let yaml = r#"
common_env:
  SHARED: shared
container:
  image: agent
workers:
  - name: claude-main
    type: claudecode
    task_types: [bootstrap, reason, explore]
    env:
      ANTHROPIC_MODEL: claude-test
      ANTHROPIC_BASE_URL: https://example.invalid
      ANTHROPIC_API_KEY: placeholder
      WORKER_ONLY: worker
"#;
        let config: DispatcherConfig = serde_yaml::from_str(yaml).expect("parse");
        config.validate().expect("valid");

        let default_runtime = config.runtime_config().expect("runtime");
        assert_eq!(
            default_runtime.env.get("SHARED").map(String::as_str),
            Some("shared")
        );
        assert!(!default_runtime.env.contains_key("WORKER_ONLY"));

        let worker_runtime = config
            .runtime_config_for_worker("claude-main")
            .expect("worker runtime")
            .expect("runtime");
        assert_eq!(
            worker_runtime.env.get("SHARED").map(String::as_str),
            Some("shared")
        );
        assert_eq!(
            worker_runtime.env.get("WORKER_ONLY").map(String::as_str),
            Some("worker")
        );
        assert_eq!(
            worker_runtime
                .env
                .get("ANTHROPIC_MODEL")
                .map(String::as_str),
            Some("claude-test")
        );
    }

    #[test]
    fn validates_container_network_mode_explicitly() {
        for network_mode in ["none", "disabled"] {
            let yaml = format!(
                r#"
container:
  image: agent
  network_mode: "{network_mode}"
worker:
  kind: mock
  description: fact
"#
            );
            let config: DispatcherConfig = serde_yaml::from_str(&yaml).expect("parse");
            config.validate().expect("valid network mode");
            let runtime = config.runtime_config().expect("runtime");
            assert!(runtime.network_disabled);
            assert_eq!(runtime.network_mode.as_deref(), Some("none"));
        }

        for network_mode in ["bridge", "host"] {
            let yaml = format!(
                r#"
container:
  image: agent
  network_mode: "{network_mode}"
worker:
  kind: mock
  description: fact
"#
            );
            let config: DispatcherConfig = serde_yaml::from_str(&yaml).expect("parse");
            config.validate().expect("valid network mode");
            let runtime = config.runtime_config().expect("runtime");
            assert!(!runtime.network_disabled);
            assert_eq!(runtime.network_mode.as_deref(), Some(network_mode));
        }

        let custom = r#"
container:
  image: agent
  network_mode: "clairvoyant_level1_20260601_224536"
worker:
  kind: mock
  description: fact
"#;
        let config: DispatcherConfig = serde_yaml::from_str(custom).expect("parse");
        config
            .validate()
            .expect("custom docker network should be valid");
        let runtime = config.runtime_config().expect("runtime");
        assert!(!runtime.network_disabled);
        assert_eq!(
            runtime.network_mode.as_deref(),
            Some("clairvoyant_level1_20260601_224536")
        );
    }

    #[test]
    fn rejects_invalid_container_network_mode() {
        let yaml = r#"
container:
  image: agent
  network_mode: "bad network"
worker:
  kind: mock
  description: fact
"#;
        let config: DispatcherConfig = serde_yaml::from_str(yaml).expect("parse");
        let error = config
            .validate()
            .expect_err("invalid network mode should fail");
        assert!(error
            .to_string()
            .contains("must not contain whitespace or control characters"));
    }

    #[test]
    fn workers_array_must_cover_each_task_type() {
        let yaml = r#"
workers:
  - name: bootstrap-only
    type: mock
    task_types: [bootstrap]
"#;
        let config: DispatcherConfig = serde_yaml::from_str(yaml).expect("parse");
        let error = match workers_from_config(&config) {
            Ok(_) => panic!("missing reason/explore workers should fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("Reason"));
    }

    #[test]
    fn rejects_config_with_both_single_worker_and_workers_array() {
        let yaml = r#"
worker:
  kind: mock
  description: single
workers:
  - name: array
    type: mock
    task_types: [bootstrap, reason, explore]
"#;
        let config: DispatcherConfig = serde_yaml::from_str(yaml).expect("parse");
        let error = config.validate().expect_err("ambiguous worker config");
        assert!(error.to_string().contains("not both"));
        assert!(config
            .primary_worker_config()
            .expect_err("primary helper should reject ambiguity")
            .to_string()
            .contains("not both"));
        let error = match workers_from_config(&config) {
            Ok(_) => panic!("worker-set helper should reject ambiguity"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("not both"));
    }

    #[test]
    fn rejects_invalid_runtime_limits() {
        let yaml = r#"
runtime:
  max_workers: 1
  max_project_workers: 2
worker:
  kind: mock
  description: fact
"#;
        let config: DispatcherConfig = serde_yaml::from_str(yaml).expect("parse");
        let error = config.validate().expect_err("invalid runtime limits");
        assert!(error
            .to_string()
            .contains("runtime.max_project_workers cannot exceed runtime.max_workers"));
    }

    #[test]
    fn rejects_empty_container_image() {
        let yaml = r#"
container:
  image: " "
worker:
  kind: mock
  description: fact
"#;
        let config: DispatcherConfig = serde_yaml::from_str(yaml).expect("parse");
        let error = config.validate().expect_err("empty image should fail");
        assert!(error
            .to_string()
            .contains("container.image must not be empty"));
    }

    #[test]
    fn rejects_model_cli_workers_in_network_disabled_containers() {
        let yaml = r#"
common_env:
  ANTHROPIC_MODEL: claude-test
  ANTHROPIC_BASE_URL: https://example.invalid
  ANTHROPIC_API_KEY: placeholder
container:
  image: agent
  network_mode: none
workers:
  - name: claude-main
    type: claudecode
    task_types: [bootstrap, reason, explore]
"#;
        let config: DispatcherConfig = serde_yaml::from_str(yaml).expect("parse");
        let error = config
            .validate()
            .expect_err("model cli worker needs container network");
        assert!(error
            .to_string()
            .contains("model CLI workers need network egress"));

        let mock = r#"
container:
  image: agent
  network_mode: none
worker:
  kind: mock
  description: fact
"#;
        let config: DispatcherConfig = serde_yaml::from_str(mock).expect("parse");
        config.validate().expect("mock can run without network");
    }

    #[test]
    fn rejects_empty_dispatch_identity_fields() {
        let empty_worker_name = r#"
worker_name: " "
worker:
  kind: mock
  description: fact
"#;
        let config: DispatcherConfig = serde_yaml::from_str(empty_worker_name).expect("parse");
        let error = config
            .validate()
            .expect_err("empty worker_name should fail");
        assert!(error.to_string().contains("worker_name must not be empty"));

        let empty_bootstrap = r#"
bootstrap_intent: ""
worker:
  kind: mock
  description: fact
"#;
        let config: DispatcherConfig = serde_yaml::from_str(empty_bootstrap).expect("parse");
        let error = config
            .validate()
            .expect_err("empty bootstrap_intent should fail");
        assert!(error
            .to_string()
            .contains("bootstrap_intent must not be empty"));
    }

    #[test]
    fn rejects_invalid_env_map_keys() {
        let empty_common_key = r#"
common_env:
  " ": value
worker:
  kind: mock
  description: fact
"#;
        let config: DispatcherConfig = serde_yaml::from_str(empty_common_key).expect("parse");
        let error = config.validate().expect_err("empty env key should fail");
        assert!(error
            .to_string()
            .contains("common_env contains an empty environment variable name"));

        let invalid_worker_key = r#"
worker:
  kind: mock
  description: fact
  env:
    BAD=KEY: value
"#;
        let config: DispatcherConfig = serde_yaml::from_str(invalid_worker_key).expect("parse");
        let error = config
            .validate()
            .expect_err("env key containing equals should fail");
        assert!(error
            .to_string()
            .contains("worker.env.BAD=KEY must not contain `=`"));

        let invalid_array_key = r#"
workers:
  - name: mock-main
    type: mock
    task_types: [bootstrap, reason, explore]
    env:
      BAD=KEY: value
"#;
        let config: DispatcherConfig = serde_yaml::from_str(invalid_array_key).expect("parse");
        let error = config
            .validate()
            .expect_err("workers[] env key containing equals should fail");
        assert!(error
            .to_string()
            .contains("workers.mock-main.env.BAD=KEY must not contain `=`"));
    }

    #[test]
    fn rejects_empty_container_path_entries() {
        let empty_workdir = r#"
container:
  image: agent
  workdir: " "
worker:
  kind: mock
  description: fact
"#;
        let config: DispatcherConfig = serde_yaml::from_str(empty_workdir).expect("parse");
        let error = config
            .validate()
            .expect_err("empty container workdir should fail");
        assert!(error
            .to_string()
            .contains("container.workdir must not be empty"));

        let empty_volume = r#"
container:
  image: agent
  volumes:
    - " "
worker:
  kind: mock
  description: fact
"#;
        let config: DispatcherConfig = serde_yaml::from_str(empty_volume).expect("parse");
        let error = config
            .validate()
            .expect_err("empty container volume should fail");
        assert!(error
            .to_string()
            .contains("container.volumes[0] must not be empty"));

        let empty_host = r#"
container:
  image: agent
  extra_hosts:
    - ""
worker:
  kind: mock
  description: fact
"#;
        let config: DispatcherConfig = serde_yaml::from_str(empty_host).expect("parse");
        let error = config
            .validate()
            .expect_err("empty container extra_host should fail");
        assert!(error
            .to_string()
            .contains("container.extra_hosts[0] must not be empty"));
    }

    #[test]
    fn rejects_duplicate_worker_names_and_task_types() {
        let duplicate_name = r#"
workers:
  - name: same
    type: mock
    task_types: [bootstrap]
  - name: same
    type: mock
    task_types: [reason]
"#;
        let config: DispatcherConfig = serde_yaml::from_str(duplicate_name).expect("parse");
        let error = config.validate().expect_err("duplicate names");
        assert!(error.to_string().contains("worker names must be unique"));

        let duplicate_task = r#"
workers:
  - name: same
    type: mock
    task_types: [bootstrap, bootstrap]
"#;
        let config: DispatcherConfig = serde_yaml::from_str(duplicate_task).expect("parse");
        let error = config.validate().expect_err("duplicate task types");
        assert!(error.to_string().contains("task_types must be unique"));
    }

    #[test]
    fn rejects_empty_worker_programs_during_config_validation() {
        let single = r#"
worker:
  kind: command
  program: "  "
"#;
        let config: DispatcherConfig = serde_yaml::from_str(single).expect("parse");
        let error = config.validate().expect_err("empty single command program");
        assert!(error.to_string().contains("program must not be empty"));

        let array = r#"
workers:
  - name: command-main
    type: command
    task_types: [bootstrap, reason, explore]
    program: ""
"#;
        let config: DispatcherConfig = serde_yaml::from_str(array).expect("parse");
        let error = config.validate().expect_err("empty workers[] program");
        assert!(error.to_string().contains("program must not be empty"));
    }

    #[test]
    fn rejects_unknown_tool_worker_names_during_config_validation() {
        let single = r#"
worker:
  kind: tool
  tools: [checksec, typo-tool]
"#;
        let config: DispatcherConfig = serde_yaml::from_str(single).expect("parse");
        let error = config.validate().expect_err("unknown single tool");
        assert!(error
            .to_string()
            .contains("worker worker tools contains unknown tool `typo-tool`"));

        let array = r#"
workers:
  - name: tool-main
    type: tool
    task_types: [bootstrap, reason, explore]
    env:
      CAIRN_TOOLS: "checksec, ,strings"
"#;
        let config: DispatcherConfig = serde_yaml::from_str(array).expect("parse");
        let error = config.validate().expect_err("empty array tool");
        assert!(error
            .to_string()
            .contains("worker tool-main CAIRN_TOOLS contains an empty tool name"));
    }

    #[test]
    fn tool_worker_build_path_rejects_unknown_names_without_prior_validate() {
        let yaml = r#"
worker:
  kind: tool
  tools: [checksec, typo-tool]
"#;
        let config: DispatcherConfig = serde_yaml::from_str(yaml).expect("parse");
        let error = match worker_from_config(&config) {
            Ok(_) => panic!("unknown tool should fail build"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("ToolWorker config contains unknown tool `typo-tool`"));
    }

    #[test]
    fn validates_real_worker_required_env() {
        let missing = r#"
workers:
  - name: claude-main
    type: claudecode
    task_types: [bootstrap, reason, explore]
"#;
        let config: DispatcherConfig = serde_yaml::from_str(missing).expect("parse");
        let error = config.validate().expect_err("missing claude env");
        assert!(error.to_string().contains("ANTHROPIC_MODEL"));

        let valid = r#"
common_env:
  ANTHROPIC_MODEL: claude-test
  ANTHROPIC_BASE_URL: https://example.invalid
  ANTHROPIC_API_KEY: placeholder
workers:
  - name: claude-main
    type: claudecode
    task_types: [bootstrap, reason, explore]
"#;
        let config: DispatcherConfig = serde_yaml::from_str(valid).expect("parse");
        config.validate().expect("valid claude env from common_env");
    }

    #[test]
    fn validates_single_real_worker_required_env() {
        let missing = r#"
worker:
  kind: claudecode
"#;
        let config: DispatcherConfig = serde_yaml::from_str(missing).expect("parse");
        let error = config.validate().expect_err("missing single worker env");
        assert!(error.to_string().contains("ANTHROPIC_MODEL"));

        let valid = r#"
common_env:
  ANTHROPIC_MODEL: claude-test
  ANTHROPIC_BASE_URL: https://example.invalid
  ANTHROPIC_API_KEY: placeholder
worker:
  kind: claudecode
"#;
        let config: DispatcherConfig = serde_yaml::from_str(valid).expect("parse");
        config.validate().expect("valid single claude env");
    }

    #[test]
    fn validates_claude_code_accepts_api_key_or_auth_token() {
        let missing = r#"
common_env:
  ANTHROPIC_MODEL: claude-test
  ANTHROPIC_BASE_URL: https://example.invalid
worker:
  kind: claudecode
"#;
        let config: DispatcherConfig = serde_yaml::from_str(missing).expect("parse");
        let error = config.validate().expect_err("missing claude auth env");
        assert!(error
            .to_string()
            .contains("ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN"));

        for auth_key in ["ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"] {
            let yaml = format!(
                r#"
common_env:
  ANTHROPIC_MODEL: claude-test
  ANTHROPIC_BASE_URL: https://example.invalid
  {auth_key}: placeholder
worker:
  kind: claudecode
"#
            );
            let config: DispatcherConfig = serde_yaml::from_str(&yaml).expect("parse");
            config.validate().expect("valid claude auth env");
        }
    }

    #[test]
    fn rejects_claude_code_args_that_allow_webfetch() {
        let single = r#"
worker:
  kind: claudecode
  args: ["--print", "--allowedTools", "Bash,WebFetch"]
"#;
        let config: DispatcherConfig = serde_yaml::from_str(single).expect("parse");
        let error = config.validate().expect_err("allowed WebFetch should fail");
        assert!(error
            .to_string()
            .contains("worker worker args must not allow WebFetch"));

        let array = r#"
workers:
  - name: claude-main
    type: claudecode
    task_types: [bootstrap, reason, explore]
    args: ["--allowed-tools=WebFetch,Bash"]
"#;
        let config: DispatcherConfig = serde_yaml::from_str(array).expect("parse");
        let error = config
            .validate()
            .expect_err("workers[] allowed WebFetch should fail");
        assert!(error
            .to_string()
            .contains("worker claude-main args must not allow WebFetch"));
    }

    #[test]
    fn rejects_claude_code_custom_args_without_noninteractive_text_mode() {
        let missing_print = r#"
worker:
  kind: claudecode
  args: ["--input-format", "text", "--output-format", "text"]
"#;
        let config: DispatcherConfig = serde_yaml::from_str(missing_print).expect("parse");
        let error = config.validate().expect_err("missing --print should fail");
        assert!(error.to_string().contains("must include --print"));

        let json_output = r#"
workers:
  - name: claude-main
    type: claudecode
    task_types: [bootstrap, reason, explore]
    args: ["--print", "--input-format=text", "--output-format", "json"]
"#;
        let config: DispatcherConfig = serde_yaml::from_str(json_output).expect("parse");
        let error = config.validate().expect_err("non-text output should fail");
        assert!(error
            .to_string()
            .contains("must include --output-format text"));
    }

    #[test]
    fn custom_claude_code_args_can_use_local_cli_auth_without_env() {
        let yaml = r#"
worker:
  kind: claudecode
  args: ["--print", "--input-format", "text", "--output-format", "text"]
"#;
        let config: DispatcherConfig = serde_yaml::from_str(yaml).expect("parse");
        config
            .validate()
            .expect("custom claude args should allow local CLI auth");
    }

    #[test]
    fn resolves_worker_env_placeholders_before_validation() {
        let key = format!("CAIRN_TEST_ANTHROPIC_KEY_{}", std::process::id());
        std::env::set_var(&key, "resolved-secret");
        let yaml = format!(
            r#"
common_env:
  ANTHROPIC_MODEL: claude-test
  ANTHROPIC_BASE_URL: https://example.invalid
  ANTHROPIC_API_KEY: "${{{key}}}"
worker:
  kind: claudecode
"#
        );
        let mut config: DispatcherConfig = serde_yaml::from_str(&yaml).expect("parse");
        config
            .resolve_env_placeholders()
            .expect("resolve placeholders");
        config.validate().expect("valid after placeholder resolve");
        assert_eq!(
            config
                .common_env
                .get("ANTHROPIC_API_KEY")
                .map(String::as_str),
            Some("resolved-secret")
        );
    }

    #[test]
    fn rejects_missing_worker_env_placeholder() {
        let key = format!("CAIRN_TEST_MISSING_KEY_{}", std::process::id());
        std::env::remove_var(&key);
        let yaml = format!(
            r#"
common_env:
  ANTHROPIC_MODEL: claude-test
  ANTHROPIC_BASE_URL: https://example.invalid
  ANTHROPIC_API_KEY: "${{{key}}}"
worker:
  kind: claudecode
"#
        );
        let mut config: DispatcherConfig = serde_yaml::from_str(&yaml).expect("parse");
        let error = config
            .resolve_env_placeholders()
            .expect_err("missing placeholder env should fail");
        assert!(error.to_string().contains(&key));
        assert!(error.to_string().contains("not set"));
    }

    #[test]
    fn rejects_partial_env_placeholder_values() {
        let yaml = r#"
common_env:
  ANTHROPIC_MODEL: claude-test
  ANTHROPIC_BASE_URL: https://example.invalid
  ANTHROPIC_API_KEY: "prefix-${ANTHROPIC_API_KEY}"
worker:
  kind: claudecode
"#;
        let mut config: DispatcherConfig = serde_yaml::from_str(yaml).expect("parse");
        let error = config
            .resolve_env_placeholders()
            .expect_err("partial placeholder should fail");
        assert!(error.to_string().contains("whole-value form"));
    }

    #[test]
    fn runtime_only_config_ignores_unresolved_worker_secret_placeholders() {
        let path = std::env::temp_dir().join(format!(
            "clairvoyant-runtime-only-config-{}-{}.yaml",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let model_key = format!("CAIRN_TEST_MISSING_ANTHROPIC_MODEL_{}", std::process::id());
        let base_url_key = format!(
            "CAIRN_TEST_MISSING_ANTHROPIC_BASE_URL_{}",
            std::process::id()
        );
        let api_key = format!(
            "CAIRN_TEST_MISSING_ANTHROPIC_API_KEY_{}",
            std::process::id()
        );
        std::env::remove_var(&model_key);
        std::env::remove_var(&base_url_key);
        std::env::remove_var(&api_key);
        std::fs::write(
            &path,
            format!(
                r#"
common_env:
  TSEC_SERVER_HOST: cybergym:8666
container:
  image: worker-image
worker:
  kind: claudecode
  env:
    ANTHROPIC_MODEL: "${{{model_key}}}"
    ANTHROPIC_BASE_URL: "${{{base_url_key}}}"
    ANTHROPIC_API_KEY: "${{{api_key}}}"
"#
            ),
        )
        .expect("write config");
        let config = DispatcherConfig::from_path_runtime_only(&path).expect("runtime-only config");
        let runtime = config.runtime_config().expect("runtime config");
        assert_eq!(runtime.image.as_deref(), Some("worker-image"));
        assert_eq!(
            runtime.env.get("TSEC_SERVER_HOST").map(String::as_str),
            Some("cybergym:8666")
        );
        let error = DispatcherConfig::from_path(&path).expect_err("full config should fail");
        assert!(error.to_string().contains("CAIRN_TEST_MISSING"));
        assert!(error.to_string().contains("not set"));
    }

    #[tokio::test]
    async fn single_command_worker_receives_common_env() {
        let yaml = r#"
common_env:
  CAIRN_DISPATCHER_ENV_TEST: from-config
worker:
  kind: command
  program: sh
  args:
    - -c
    - "cat >/dev/null; printf '{\"event\":\"done\",\"description\":\"%s\",\"complete\":false}\\n' \"$CAIRN_DISPATCHER_ENV_TEST\""
"#;
        let config: DispatcherConfig = serde_yaml::from_str(yaml).expect("parse");
        config.validate().expect("valid config");
        let worker = worker_from_config(&config).expect("worker");
        let events = worker
            .run(
                "prompt",
                WorkerContext {
                    project_id: "proj_001".to_string(),
                    intent_id: Some("i001".to_string()),
                },
            )
            .await
            .expect("run worker");
        assert_eq!(
            events,
            vec![WorkerEvent::Done {
                description: "from-config".to_string(),
                complete: false,
            }]
        );
    }

    #[tokio::test]
    async fn single_command_worker_receives_worker_env_overrides() {
        let yaml = r#"
common_env:
  CAIRN_DISPATCHER_ENV_TEST: from-common
worker:
  kind: command
  program: sh
  env:
    CAIRN_DISPATCHER_ENV_TEST: from-worker
  args:
    - -c
    - "cat >/dev/null; printf '{\"event\":\"done\",\"description\":\"%s\",\"complete\":false}\\n' \"$CAIRN_DISPATCHER_ENV_TEST\""
"#;
        let config: DispatcherConfig = serde_yaml::from_str(yaml).expect("parse");
        config.validate().expect("valid config");
        let worker = worker_from_config(&config).expect("worker");
        let events = worker
            .run(
                "prompt",
                WorkerContext {
                    project_id: "proj_001".to_string(),
                    intent_id: Some("i001".to_string()),
                },
            )
            .await
            .expect("run worker");
        assert_eq!(
            events,
            vec![WorkerEvent::Done {
                description: "from-worker".to_string(),
                complete: false,
            }]
        );
    }

    #[tokio::test]
    async fn workers_array_command_worker_receives_worker_env_overrides() {
        let yaml = r#"
common_env:
  CAIRN_DISPATCHER_ENV_TEST: from-common
workers:
  - name: command-main
    type: command
    task_types: [bootstrap, reason, explore]
    program: sh
    env:
      CAIRN_DISPATCHER_ENV_TEST: from-worker
    args:
      - -c
      - "cat >/dev/null; printf '{\"event\":\"done\",\"description\":\"%s\",\"complete\":false}\\n' \"$CAIRN_DISPATCHER_ENV_TEST\""
"#;
        let config: DispatcherConfig = serde_yaml::from_str(yaml).expect("parse");
        config.validate().expect("valid config");
        match config.primary_worker_config().expect("primary") {
            WorkerConfig::Command { env, .. } => {
                assert_eq!(
                    env.get("CAIRN_DISPATCHER_ENV_TEST").map(String::as_str),
                    Some("from-worker")
                );
            }
            other => panic!("unexpected worker config {other:?}"),
        }

        let workers = workers_from_config(&config).expect("workers");
        let entry = workers.for_task(TaskType::Bootstrap);
        let events = entry
            .worker
            .run(
                "prompt",
                WorkerContext {
                    project_id: "proj_001".to_string(),
                    intent_id: Some("i001".to_string()),
                },
            )
            .await
            .expect("run worker");
        assert_eq!(
            events,
            vec![WorkerEvent::Done {
                description: "from-worker".to_string(),
                complete: false,
            }]
        );
    }

    #[tokio::test]
    async fn claude_code_worker_kind_executes_through_command_adapter() {
        let cases = [(
            "claudecode",
            r#"
  ANTHROPIC_MODEL: claude-test
  ANTHROPIC_BASE_URL: https://example.invalid
  ANTHROPIC_AUTH_TOKEN: placeholder
"#,
        )];

        for (kind, required_env) in cases {
            let yaml = format!(
                r#"
common_env:
  CAIRN_DISPATCHER_ENV_TEST: from-{kind}
{required_env}
worker:
  kind: {kind}
  program: sh
  args:
    - -c
    - "cat >/dev/null; printf '{{\"event\":\"done\",\"description\":\"%s:%s:%s\",\"complete\":false}}\n' \"$CAIRN_DISPATCHER_ENV_TEST\" \"$CAIRN_PROJECT_ID\" \"$CAIRN_INTENT_ID\""
"#
            );
            let config: DispatcherConfig = serde_yaml::from_str(&yaml).expect("parse");
            config.validate().expect("valid named worker config");
            let worker = worker_from_config(&config).expect("worker");
            let events = worker
                .run(
                    "prompt",
                    WorkerContext {
                        project_id: "proj_001".to_string(),
                        intent_id: Some("i001".to_string()),
                    },
                )
                .await
                .expect("run worker");
            assert_eq!(
                events,
                vec![WorkerEvent::Done {
                    description: format!("from-{kind}:proj_001:i001"),
                    complete: false,
                }],
                "named worker kind {kind} did not use command adapter correctly"
            );
        }
    }

    #[test]
    fn container_worker_preflight_checks_claude_default_wrapper_dependencies() {
        let worker = WorkerConfig::ClaudeCode {
            program: None,
            args: Vec::new(),
            env: BTreeMap::new(),
        };
        assert_eq!(
            container_worker_required_executables(&worker),
            vec!["/bin/sh".to_string(), "claude".to_string()]
        );

        let worker = WorkerConfig::ClaudeCode {
            program: Some("/opt/bin/claude".to_string()),
            args: vec!["--print".to_string()],
            env: BTreeMap::new(),
        };
        assert_eq!(
            container_worker_required_executables(&worker),
            vec!["/opt/bin/claude".to_string()]
        );
    }

    #[test]
    fn host_claude_preflight_requires_webfetch_disable_support() {
        let dir = std::env::temp_dir().join(format!(
            "clairvoyant-claude-help-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let good = dir.join("claude-good");
        let bad = dir.join("claude-bad");
        write_executable_script(
            &good,
            r#"#!/bin/sh
printf '%s\n' '--disallowedTools, --disallowed-tools <tools...>'
"#,
        );
        write_executable_script(
            &bad,
            r#"#!/bin/sh
printf '%s\n' 'Claude Code without the expected option'
"#,
        );

        ensure_claude_supports_webfetch_disable(good.to_str().expect("good path"))
            .expect("good claude help");
        let error = ensure_claude_supports_webfetch_disable(bad.to_str().expect("bad path"))
            .expect_err("missing disallowed tools support should fail");
        assert!(error.contains("disable WebFetch"));
    }

    #[test]
    fn container_worker_probe_uses_networkless_docker_run() {
        let worker = WorkerConfig::ClaudeCode {
            program: None,
            args: Vec::new(),
            env: BTreeMap::new(),
        };
        let probe = container_worker_probe(&worker).expect("probe");
        let args = container_worker_probe_args("worker-image:latest", &probe);
        assert!(args
            .windows(2)
            .any(|window| window[0] == "--network" && window[1] == "none"));
        assert!(args
            .windows(2)
            .any(|window| window[0] == "--entrypoint" && window[1] == "/bin/sh"));
        assert!(args.contains(&"worker-image:latest".to_string()));
        assert!(args.contains(&"--".to_string()));
        assert!(args.iter().any(|arg| arg.contains("--disallowedTools")));
        assert_eq!(
            probe.claude_webfetch_disable_program.as_deref(),
            Some("claude")
        );
        assert_eq!(args.last(), Some(&"claude".to_string()));
    }

    #[test]
    fn custom_claude_args_still_disable_webfetch_and_probe_capability() {
        let worker = WorkerConfig::ClaudeCode {
            program: Some("/opt/bin/claude".to_string()),
            args: vec!["--print".to_string()],
            env: BTreeMap::new(),
        };
        let (program, args) = worker_command(&worker).expect("worker command");
        assert_eq!(program, "/opt/bin/claude");
        assert_eq!(
            args,
            vec![
                "--print".to_string(),
                "--disallowedTools".to_string(),
                "WebFetch".to_string(),
            ]
        );
        let probe = container_worker_probe(&worker).expect("probe");
        assert_eq!(
            probe.claude_webfetch_disable_program.as_deref(),
            Some("/opt/bin/claude")
        );
    }

    #[tokio::test]
    async fn startup_healthcheck_checks_local_command_worker() {
        let yaml = r#"
worker:
  kind: command
  program: /bin/sh
"#;
        let config: DispatcherConfig = serde_yaml::from_str(yaml).expect("parse");
        config.validate().expect("valid config");
        let report = startup_healthcheck(&config).await.expect("healthcheck");
        assert_eq!(
            report,
            StartupHealthcheckReport {
                checked_workers: vec!["worker".to_string()],
                checked_container: false,
            }
        );
    }

    #[tokio::test]
    async fn startup_healthcheck_rejects_missing_local_command_worker() {
        let yaml = r#"
worker:
  kind: command
  program: /definitely/missing/clairvoyant-worker
"#;
        let config: DispatcherConfig = serde_yaml::from_str(yaml).expect("parse");
        config.validate().expect("valid config");
        let error = startup_healthcheck(&config)
            .await
            .expect_err("missing worker should fail healthcheck");
        assert!(error.to_string().contains("not executable"));
    }

    #[tokio::test]
    async fn startup_healthcheck_rejects_ambiguous_worker_config() {
        let yaml = r#"
worker:
  kind: mock
  description: single
workers:
  - name: array
    type: mock
    task_types: [bootstrap, reason, explore]
"#;
        let config: DispatcherConfig = serde_yaml::from_str(yaml).expect("parse");
        let error = startup_healthcheck(&config)
            .await
            .expect_err("ambiguous worker config should fail healthcheck");
        assert!(error.to_string().contains("not both"));
    }

    #[tokio::test]
    async fn startup_healthcheck_rejects_empty_container_image_without_docker() {
        let yaml = r#"
container:
  image: ""
worker:
  kind: mock
  description: fact
"#;
        let config: DispatcherConfig = serde_yaml::from_str(yaml).expect("parse");
        let error = startup_healthcheck(&config)
            .await
            .expect_err("empty image should fail before docker inspect");
        assert!(error
            .to_string()
            .contains("container image must not be empty"));
    }

    #[test]
    fn worker_env_is_merged_into_container_runtime_config() {
        let yaml = r#"
common_env:
  SHARED: "common"
container:
  image: "agent"
worker:
  kind: mock
  description: "fact"
"#;
        let config: DispatcherConfig = serde_yaml::from_str(yaml).expect("parse");
        let mut worker_env = BTreeMap::new();
        worker_env.insert("WORKER_ONLY".to_string(), "yes".to_string());
        worker_env.insert("SHARED".to_string(), "worker".to_string());
        let runtime = config
            .runtime_config_with_env(Some(&worker_env))
            .expect("runtime config");
        assert_eq!(
            runtime.env.get("WORKER_ONLY").map(String::as_str),
            Some("yes")
        );
        assert_eq!(
            runtime.env.get("SHARED").map(String::as_str),
            Some("worker")
        );
    }

    #[tokio::test]
    async fn runtime_worker_runs_command_through_container_exec() {
        let dir = std::env::temp_dir().join(format!(
            "clairvoyant-runtime-worker-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let log_path = dir.join("docker.log");
        let docker_path = dir.join("docker");
        let script = format!(
            r#"#!/bin/sh
printf '%s\n' "$*" >> '{}'
case "$1" in
  create) echo fake-id ;;
  start) echo started ;;
  exec) cat >/dev/null; printf '%s\n' '{{"event":"done","description":"from container","complete":false}}' ;;
  inspect) exit 1 ;;
  *) echo "unexpected $1" >&2; exit 2 ;;
esac
"#,
            log_path.display()
        );
        write_executable_script(&docker_path, &script);

        let runtime_config = RuntimeConfig {
            image: Some("agent-image".to_string()),
            workdir: Some(std::path::PathBuf::from("/runs/{project_id}")),
            volumes: Vec::new(),
            extra_hosts: Vec::new(),
            network_mode: Some("none".to_string()),
            network_disabled: true,
            env: BTreeMap::new(),
        };
        let runtime = DockerCliRuntime::new(runtime_config.clone())
            .with_binary("sh")
            .with_binary_args(vec![docker_path.to_string_lossy().to_string()]);
        let worker = RuntimeCommandWorker::with_runtime(
            runtime,
            CompletedAction::Stop,
            "worker-bin".to_string(),
            vec!["--ndjson".to_string()],
        );
        let events = worker
            .run(
                "prompt",
                WorkerContext {
                    project_id: "proj_001".to_string(),
                    intent_id: Some("i001".to_string()),
                },
            )
            .await
            .expect("runtime worker");

        assert_eq!(
            events,
            vec![WorkerEvent::Done {
                description: "from container".to_string(),
                complete: false
            }]
        );
        let log = std::fs::read_to_string(log_path).expect("read log");
        assert!(log.contains("create --name clairvoyant-proj_001"));
        assert!(log.contains("start clairvoyant-proj_001"));
        assert!(log.contains(
            "exec -i --workdir /runs/proj_001 --env CAIRN_INTENT_ID=i001 --env CAIRN_PROJECT_ID=proj_001 clairvoyant-proj_001 worker-bin --ndjson"
        ));
    }

    #[test]
    fn runtime_claude_worker_uses_noninteractive_default_args() {
        let claude = WorkerConfig::ClaudeCode {
            program: None,
            args: Vec::new(),
            env: BTreeMap::new(),
        };
        let (program, args) = worker_command(&claude).expect("claude command");
        assert_eq!(program, "/bin/sh");
        assert!(args
            .iter()
            .any(|arg| arg.contains("--model \"$ANTHROPIC_MODEL\"")));
        assert!(args.iter().any(|arg| arg.contains("--input-format text")));
        assert!(args
            .iter()
            .any(|arg| arg.contains("--permission-mode bypassPermissions")));
        assert!(args
            .iter()
            .any(|arg| arg.contains("--disallowedTools WebFetch")));
        assert_eq!(args.last().map(String::as_str), Some("claude"));
    }

    #[tokio::test]
    async fn runtime_worker_streams_container_exec_events_before_exit() {
        let dir = std::env::temp_dir().join(format!(
            "clairvoyant-runtime-stream-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let log_path = dir.join("docker.log");
        let docker_path = dir.join("docker");
        let script = format!(
            r#"#!/bin/sh
printf '%s\n' "$1" >> '{}'
case "$1" in
  create) echo fake-id ;;
  start) echo started ;;
  exec) cat >/dev/null; printf '%s\n' '{{"event":"message","text":"first"}}'; sleep 1; printf '%s\n' '{{"event":"done","description":"last","complete":false}}' ;;
  inspect) exit 1 ;;
  *) echo "unexpected $1" >&2; exit 2 ;;
esac
"#,
            log_path.display()
        );
        write_executable_script(&docker_path, &script);

        let runtime_config = RuntimeConfig {
            image: Some("agent-image".to_string()),
            workdir: Some(std::path::PathBuf::from("/runs/{project_id}")),
            volumes: Vec::new(),
            extra_hosts: Vec::new(),
            network_mode: Some("none".to_string()),
            network_disabled: true,
            env: BTreeMap::new(),
        };
        let runtime = DockerCliRuntime::new(runtime_config.clone())
            .with_binary("sh")
            .with_binary_args(vec![docker_path.to_string_lossy().to_string()]);
        let worker = RuntimeCommandWorker::with_runtime(
            runtime,
            CompletedAction::Stop,
            "worker-bin".to_string(),
            Vec::new(),
        );
        let mut stream = worker
            .run_stream(
                "prompt",
                WorkerContext {
                    project_id: "proj_001".to_string(),
                    intent_id: None,
                },
            )
            .await
            .expect("runtime stream");
        let started = std::time::Instant::now();
        let first = stream
            .next()
            .await
            .expect("first event")
            .expect("first event ok");
        assert!(started.elapsed() < Duration::from_millis(500));
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
                complete: false
            }]
        );
        let log = std::fs::read_to_string(log_path).expect("read log");
        assert_eq!(log, "inspect\ncreate\nstart\nexec\n");
    }

    #[tokio::test]
    async fn dropping_runtime_worker_stream_stops_container_exec_process() {
        let dir = std::env::temp_dir().join(format!(
            "clairvoyant-runtime-drop-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let pid_path = dir.join("docker-exec.pid");
        let docker_path = dir.join("docker");
        let script = format!(
            r#"#!/bin/sh
case "$1" in
  create) echo fake-id ;;
  start) echo started ;;
  exec) cat >/dev/null; printf '%s\n' "$$" > '{}'; printf '%s\n' '{{"event":"message","text":"first"}}'; sleep 60 ;;
  inspect) exit 1 ;;
  *) echo "unexpected $1" >&2; exit 2 ;;
esac
"#,
            pid_path.display()
        );
        write_executable_script(&docker_path, &script);

        let runtime_config = RuntimeConfig {
            image: Some("agent-image".to_string()),
            workdir: None,
            volumes: Vec::new(),
            extra_hosts: Vec::new(),
            network_mode: Some("none".to_string()),
            network_disabled: true,
            env: BTreeMap::new(),
        };
        let runtime = DockerCliRuntime::new(runtime_config.clone())
            .with_binary("sh")
            .with_binary_args(vec![docker_path.to_string_lossy().to_string()]);
        let worker = RuntimeCommandWorker::with_runtime(
            runtime,
            CompletedAction::Keep,
            "worker-bin".to_string(),
            Vec::new(),
        );
        let mut stream = worker
            .run_stream(
                "prompt",
                WorkerContext {
                    project_id: "proj_001".to_string(),
                    intent_id: None,
                },
            )
            .await
            .expect("runtime stream");
        let first = stream
            .next()
            .await
            .expect("first event")
            .expect("first event ok");
        assert_eq!(
            first,
            WorkerEvent::Message {
                text: "first".to_string()
            }
        );
        let pid = read_pid_file(&pid_path).await;
        assert!(process_is_alive(&pid));

        drop(stream);
        for _ in 0..100 {
            if !process_is_alive(&pid) {
                let _ = std::fs::remove_file(&pid_path);
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let _ = std::process::Command::new("kill")
            .arg("-9")
            .arg(&pid)
            .status();
        let _ = std::fs::remove_file(&pid_path);
        panic!("runtime exec process {pid} was still running after stream drop");
    }

    #[tokio::test]
    async fn runtime_worker_rejects_unknown_event_fields() {
        let dir = std::env::temp_dir().join(format!(
            "clairvoyant-runtime-strict-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let log_path = dir.join("docker.log");
        let docker_path = dir.join("docker");
        let script = format!(
            r#"#!/bin/sh
printf '%s\n' "$1" >> '{}'
case "$1" in
  create) echo fake-id ;;
  start) echo started ;;
  exec) cat >/dev/null; printf '%s\n' '{{"event":"done","description":"from container","complete":false,"extra":1}}' ;;
  inspect) exit 1 ;;
  *) echo "unexpected $1" >&2; exit 2 ;;
esac
"#,
            log_path.display()
        );
        write_executable_script(&docker_path, &script);

        let runtime_config = RuntimeConfig {
            image: Some("agent-image".to_string()),
            workdir: Some(std::path::PathBuf::from("/runs/{project_id}")),
            volumes: Vec::new(),
            extra_hosts: Vec::new(),
            network_mode: Some("none".to_string()),
            network_disabled: true,
            env: BTreeMap::new(),
        };
        let runtime = DockerCliRuntime::new(runtime_config.clone())
            .with_binary("sh")
            .with_binary_args(vec![docker_path.to_string_lossy().to_string()]);
        let worker = RuntimeCommandWorker::with_runtime(
            runtime,
            CompletedAction::Stop,
            "worker-bin".to_string(),
            Vec::new(),
        );
        let error = worker
            .run(
                "prompt",
                WorkerContext {
                    project_id: "proj_001".to_string(),
                    intent_id: None,
                },
            )
            .await
            .expect_err("invalid runtime worker event should fail");

        assert!(error.to_string().contains("unknown field"));
        let log = std::fs::read_to_string(log_path).expect("read log");
        assert_eq!(log, "inspect\ncreate\nstart\nexec\n");
    }

    #[tokio::test]
    async fn runtime_worker_rejects_non_event_stdout() {
        let dir = std::env::temp_dir().join(format!(
            "clairvoyant-runtime-prose-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let log_path = dir.join("docker.log");
        let docker_path = dir.join("docker");
        let script = format!(
            r#"#!/bin/sh
printf '%s\n' "$1" >> '{}'
case "$1" in
  create) echo fake-id ;;
  start) echo started ;;
  exec) cat >/dev/null; printf '%s\n' 'plain container prose' ;;
  inspect) exit 1 ;;
  *) echo "unexpected $1" >&2; exit 2 ;;
esac
"#,
            log_path.display()
        );
        write_executable_script(&docker_path, &script);

        let runtime_config = RuntimeConfig {
            image: Some("agent-image".to_string()),
            workdir: Some(std::path::PathBuf::from("/runs/{project_id}")),
            volumes: Vec::new(),
            extra_hosts: Vec::new(),
            network_mode: Some("none".to_string()),
            network_disabled: true,
            env: BTreeMap::new(),
        };
        let runtime = DockerCliRuntime::new(runtime_config.clone())
            .with_binary("sh")
            .with_binary_args(vec![docker_path.to_string_lossy().to_string()]);
        let worker = RuntimeCommandWorker::with_runtime(
            runtime,
            CompletedAction::Stop,
            "worker-bin".to_string(),
            Vec::new(),
        );
        let error = worker
            .run(
                "prompt",
                WorkerContext {
                    project_id: "proj_001".to_string(),
                    intent_id: None,
                },
            )
            .await
            .expect_err("non-event runtime worker output should fail");

        assert!(error.to_string().contains("must be NDJSON WorkerEvent"));
        let log = std::fs::read_to_string(log_path).expect("read log");
        assert_eq!(log, "inspect\ncreate\nstart\nexec\n");
    }

    #[tokio::test]
    async fn runtime_worker_reports_container_exec_failure_after_event() {
        let dir = std::env::temp_dir().join(format!(
            "clairvoyant-runtime-exec-fail-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let log_path = dir.join("docker.log");
        let docker_path = dir.join("docker");
        let script = format!(
            r#"#!/bin/sh
printf '%s\n' "$1" >> '{}'
case "$1" in
  create) echo fake-id ;;
  start) echo started ;;
  exec)
    cat >/dev/null
    printf '%s\n' '{{"event":"done","description":"from container","complete":false}}'
    printf '%s' exec-failed >&2
    exit 7
    ;;
  inspect) exit 1 ;;
  *) echo "unexpected $1" >&2; exit 2 ;;
esac
"#,
            log_path.display()
        );
        write_executable_script(&docker_path, &script);

        let runtime_config = RuntimeConfig {
            image: Some("agent-image".to_string()),
            workdir: Some(std::path::PathBuf::from("/runs/{project_id}")),
            volumes: Vec::new(),
            extra_hosts: Vec::new(),
            network_mode: Some("none".to_string()),
            network_disabled: true,
            env: BTreeMap::new(),
        };
        let runtime = DockerCliRuntime::new(runtime_config.clone())
            .with_binary("sh")
            .with_binary_args(vec![docker_path.to_string_lossy().to_string()]);
        let worker = RuntimeCommandWorker::with_runtime(
            runtime,
            CompletedAction::Stop,
            "worker-bin".to_string(),
            Vec::new(),
        );

        let error = worker
            .run(
                "prompt",
                WorkerContext {
                    project_id: "proj_001".to_string(),
                    intent_id: None,
                },
            )
            .await
            .expect_err("nonzero container exec should fail worker run");
        assert!(error.to_string().contains("exec-failed"));
        let log = std::fs::read_to_string(log_path).expect("read log");
        assert_eq!(log, "inspect\ncreate\nstart\nexec\n");
    }

    #[tokio::test]
    async fn runtime_worker_applies_completed_action_after_completion_event() {
        let dir = std::env::temp_dir().join(format!(
            "clairvoyant-runtime-cleanup-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let log_path = dir.join("docker.log");
        let docker_path = dir.join("docker");
        let script = format!(
            r#"#!/bin/sh
printf '%s\n' "$1" >> '{}'
case "$1" in
  create) echo fake-id ;;
  start) echo started ;;
  exec) cat >/dev/null; printf '%s\n' '{{"event":"complete","sources":["f001"],"description":"done"}}' ;;
  stop) echo stopped ;;
  inspect) exit 1 ;;
  *) echo "unexpected $1" >&2; exit 2 ;;
esac
"#,
            log_path.display()
        );
        write_executable_script(&docker_path, &script);

        let runtime_config = RuntimeConfig {
            image: Some("agent-image".to_string()),
            workdir: Some(std::path::PathBuf::from("/runs/{project_id}")),
            volumes: Vec::new(),
            extra_hosts: Vec::new(),
            network_mode: Some("none".to_string()),
            network_disabled: true,
            env: BTreeMap::new(),
        };
        let runtime = DockerCliRuntime::new(runtime_config.clone())
            .with_binary("sh")
            .with_binary_args(vec![docker_path.to_string_lossy().to_string()]);
        let worker = RuntimeCommandWorker::with_runtime(
            runtime,
            CompletedAction::Stop,
            "worker-bin".to_string(),
            Vec::new(),
        );
        let events = worker
            .run(
                "prompt",
                WorkerContext {
                    project_id: "proj_001".to_string(),
                    intent_id: None,
                },
            )
            .await
            .expect("runtime worker");

        assert_eq!(
            events,
            vec![WorkerEvent::Complete {
                sources: vec!["f001".to_string()],
                description: "done".to_string(),
            }]
        );
        let log = std::fs::read_to_string(log_path).expect("read log");
        assert_eq!(log, "inspect\ncreate\nstart\nexec\nstop\n");
    }

    #[tokio::test]
    async fn run_once_creates_bootstrap_then_concludes_it() {
        let service = service().await;
        service
            .handle(ClairvoyantRequest::CreateProject {
                body: CreateProjectRequest {
                    title: "demo".into(),
                    origin: "start".into(),
                    goal: "goal".into(),
                    hints: None,
                },
            })
            .await
            .expect("create project");
        let dispatcher = Dispatcher::new(
            service.clone(),
            Arc::new(MockWorker::fact("bootstrap fact")),
            config(),
        );

        let first = dispatcher.run_once().await.expect("first run");
        assert!(matches!(
            first,
            DispatchOutcome::CreatedBootstrapIntent {
                intent_id,
                ..
            } if intent_id == "i001"
        ));

        let second = dispatcher.run_once().await.expect("second run");
        assert!(matches!(
            second,
            DispatchOutcome::ConcludedIntent {
                fact_id,
                completed: false,
                ..
            } if fact_id == "f001"
        ));
    }

    #[tokio::test]
    async fn dispatcher_consumes_worker_event_streams() {
        let service = service().await;
        let project_id = create_test_project(&service, "stream worker").await;
        let dispatcher = Dispatcher::new(service.clone(), Arc::new(StreamOnlyWorker), config());

        dispatcher
            .run_once()
            .await
            .expect("create bootstrap intent");
        let outcome = dispatcher
            .run_once()
            .await
            .expect("conclude streamed bootstrap");
        assert!(matches!(
            outcome,
            DispatchOutcome::ConcludedIntent {
                fact_id,
                completed: false,
                ..
            } if fact_id == "f001"
        ));

        let detail = match service
            .handle(ClairvoyantRequest::GetProject { project_id })
            .await
            .expect("get project")
        {
            ClairvoyantResponse::ProjectDetail(detail) => detail,
            other => panic!("unexpected response {other:?}"),
        };
        assert_eq!(detail.facts[2].description, "streamed dispatcher fact");
    }

    #[tokio::test]
    async fn dispatcher_stops_intent_stream_after_done_event() {
        let service = service().await;
        let project_id = create_test_project(&service, "early stream done").await;
        let dispatcher = Dispatcher::new(
            service.clone(),
            Arc::new(DoneThenPendingStreamWorker),
            config(),
        );

        dispatcher
            .run_once()
            .await
            .expect("create bootstrap intent");
        let outcome = tokio::time::timeout(Duration::from_secs(1), dispatcher.run_once())
            .await
            .expect("streamed done should finish before worker stream ends")
            .expect("conclude streamed bootstrap");
        assert!(matches!(
            outcome,
            DispatchOutcome::ConcludedIntent {
                fact_id,
                completed: false,
                ..
            } if fact_id == "f001"
        ));

        let detail = match service
            .handle(ClairvoyantRequest::GetProject { project_id })
            .await
            .expect("get project")
        {
            ClairvoyantResponse::ProjectDetail(detail) => detail,
            other => panic!("unexpected response {other:?}"),
        };
        assert_eq!(detail.facts[2].description, "early streamed fact");
    }

    #[tokio::test]
    async fn dispatcher_drops_intent_stream_after_terminal_event() {
        let service = service().await;
        let project_id = create_test_project(&service, "drop stream after done").await;
        let dropped = Arc::new(tokio::sync::Notify::new());
        let dispatcher = Dispatcher::new(
            service.clone(),
            Arc::new(DropObservedDoneStreamWorker {
                dropped: Arc::clone(&dropped),
            }),
            config(),
        );

        dispatcher
            .run_once()
            .await
            .expect("create bootstrap intent");
        dispatcher
            .run_once()
            .await
            .expect("conclude streamed bootstrap");
        tokio::time::timeout(Duration::from_secs(1), dropped.notified())
            .await
            .expect("terminal event should drop worker stream");

        let detail = match service
            .handle(ClairvoyantRequest::GetProject { project_id })
            .await
            .expect("get project")
        {
            ClairvoyantResponse::ProjectDetail(detail) => detail,
            other => panic!("unexpected response {other:?}"),
        };
        assert_eq!(detail.facts[2].description, "drop observed fact");
    }

    #[tokio::test]
    async fn custom_bootstrap_intent_name_still_runs_bootstrap_task() {
        let service = service().await;
        let project_id = create_test_project(&service, "custom bootstrap").await;
        let mut config = config();
        config.bootstrap_intent = "initial survey".to_string();
        let dispatcher = Dispatcher::new(
            service.clone(),
            Arc::new(MockWorker::fact("custom bootstrap fact")),
            config,
        );

        let first = dispatcher
            .run_once()
            .await
            .expect("create bootstrap intent");
        assert!(matches!(
            first,
            DispatchOutcome::CreatedBootstrapIntent {
                intent_id,
                ..
            } if intent_id == "i001"
        ));
        let detail = match service
            .handle(ClairvoyantRequest::GetProject {
                project_id: project_id.clone(),
            })
            .await
            .expect("get project")
        {
            ClairvoyantResponse::ProjectDetail(detail) => detail,
            other => panic!("unexpected response {other:?}"),
        };
        assert_eq!(detail.intents[0].description, "initial survey");

        let second = dispatcher.run_once().await.expect("run bootstrap task");
        assert!(matches!(
            second,
            DispatchOutcome::ConcludedIntent {
                fact_id,
                completed: false,
                ..
            } if fact_id == "f001"
        ));
        let detail = match service
            .handle(ClairvoyantRequest::GetProject { project_id })
            .await
            .expect("get project")
        {
            ClairvoyantResponse::ProjectDetail(detail) => detail,
            other => panic!("unexpected response {other:?}"),
        };
        assert_eq!(detail.facts[2].description, "custom bootstrap fact");
    }

    #[tokio::test]
    async fn bootstrap_uses_conclude_fallback_after_execute_error() {
        let service = service().await;
        let project_id = create_test_project(&service, "bootstrap fallback").await;
        let calls = Arc::new(AtomicUsize::new(0));
        let prompts = Arc::new(Mutex::new(Vec::new()));
        let worker = FailThenDoneWorker {
            calls: Arc::clone(&calls),
            prompts: Arc::clone(&prompts),
            fallback_description: "fallback bootstrap fact".to_string(),
        };
        let mut config = config();
        config.runtime.prompt_group = "mock".to_string();
        let dispatcher = Dispatcher::new(service.clone(), Arc::new(worker), config);

        dispatcher
            .run_once()
            .await
            .expect("create bootstrap intent");
        let outcome = dispatcher.run_once().await.expect("run bootstrap fallback");
        assert!(matches!(
            outcome,
            DispatchOutcome::ConcludedIntent {
                fact_id,
                completed: false,
                ..
            } if fact_id == "f001"
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        let prompts = prompts.lock().expect("prompts lock").clone();
        assert!(prompts[0].contains("\"phase\": \"bootstrap\""));
        assert!(prompts[1].contains("\"phase\": \"bootstrap_conclude\""));

        let detail = match service
            .handle(ClairvoyantRequest::GetProject { project_id })
            .await
            .expect("get project")
        {
            ClairvoyantResponse::ProjectDetail(detail) => detail,
            other => panic!("unexpected response {other:?}"),
        };
        assert_eq!(detail.facts[2].description, "fallback bootstrap fact");
        assert!(detail.intents[0].worker.is_some());
    }

    #[tokio::test]
    async fn bootstrap_uses_conclude_fallback_after_execute_noop() {
        let service = service().await;
        let project_id = create_test_project(&service, "bootstrap noop fallback").await;
        let calls = Arc::new(AtomicUsize::new(0));
        let prompts = Arc::new(Mutex::new(Vec::new()));
        let worker = NoopThenDoneWorker {
            calls: Arc::clone(&calls),
            prompts: Arc::clone(&prompts),
            fallback_description: "fallback fact after noop".to_string(),
        };
        let mut config = config();
        config.runtime.prompt_group = "mock".to_string();
        let dispatcher = Dispatcher::new(service.clone(), Arc::new(worker), config);

        dispatcher
            .run_once()
            .await
            .expect("create bootstrap intent");
        let outcome = dispatcher
            .run_once()
            .await
            .expect("run bootstrap noop fallback");
        assert!(matches!(
            outcome,
            DispatchOutcome::ConcludedIntent {
                fact_id,
                completed: false,
                ..
            } if fact_id == "f001"
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        let prompts = prompts.lock().expect("prompts lock").clone();
        assert!(prompts[0].contains("\"phase\": \"bootstrap\""));
        assert!(prompts[1].contains("\"phase\": \"bootstrap_conclude\""));

        let detail = match service
            .handle(ClairvoyantRequest::GetProject { project_id })
            .await
            .expect("get project")
        {
            ClairvoyantResponse::ProjectDetail(detail) => detail,
            other => panic!("unexpected response {other:?}"),
        };
        assert_eq!(detail.facts[2].description, "fallback fact after noop");
    }

    #[tokio::test]
    async fn explore_uses_conclude_fallback_after_execute_error() {
        let service = service().await;
        let project_id = create_test_project(&service, "explore fallback").await;
        service
            .handle(ClairvoyantRequest::CreateIntent {
                project_id: project_id.clone(),
                body: CreateIntentRequest {
                    sources: vec!["origin".to_string()],
                    description: "explore branch".to_string(),
                    creator: "reasoner".to_string(),
                    worker: None,
                },
            })
            .await
            .expect("create explore intent");
        let calls = Arc::new(AtomicUsize::new(0));
        let prompts = Arc::new(Mutex::new(Vec::new()));
        let worker = FailThenDoneWorker {
            calls: Arc::clone(&calls),
            prompts: Arc::clone(&prompts),
            fallback_description: "fallback explore fact".to_string(),
        };
        let mut config = config();
        config.runtime.prompt_group = "mock".to_string();
        let dispatcher = Dispatcher::new(service.clone(), Arc::new(worker), config);

        let outcome = dispatcher.run_once().await.expect("run explore fallback");
        assert!(matches!(
            outcome,
            DispatchOutcome::ConcludedIntent {
                fact_id,
                completed: false,
                ..
            } if fact_id == "f001"
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        let prompts = prompts.lock().expect("prompts lock").clone();
        assert!(prompts[0].contains("\"phase\": \"explore_execute\""));
        assert!(prompts[1].contains("\"phase\": \"explore_conclude\""));

        let detail = match service
            .handle(ClairvoyantRequest::GetProject { project_id })
            .await
            .expect("get project")
        {
            ClairvoyantResponse::ProjectDetail(detail) => detail,
            other => panic!("unexpected response {other:?}"),
        };
        assert_eq!(detail.facts[2].description, "fallback explore fact");
    }

    #[tokio::test]
    async fn run_tick_dispatches_up_to_max_workers_concurrently() {
        let service = service().await;
        create_test_project(&service, "first").await;
        create_test_project(&service, "second").await;

        let current = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));
        let worker = DelayWorker {
            current: Arc::clone(&current),
            max_seen: Arc::clone(&max_seen),
            delay: Duration::from_millis(150),
        };
        let mut config = config();
        config.runtime.max_workers = 2;
        config.runtime.max_running_projects = 2;
        config.runtime.max_project_workers = 1;
        config.tasks.bootstrap.timeout = 2;
        let dispatcher = Dispatcher::new(service.clone(), Arc::new(worker), config);

        let created = dispatcher
            .run_tick()
            .await
            .expect("create bootstrap intents");
        assert_eq!(created.len(), 2);
        assert!(created
            .iter()
            .all(|outcome| matches!(outcome, DispatchOutcome::CreatedBootstrapIntent { .. })));

        let started = std::time::Instant::now();
        let outcomes = dispatcher.run_tick().await.expect("run bootstrap workers");
        assert!(started.elapsed() < Duration::from_millis(275));
        assert_eq!(max_seen.load(Ordering::SeqCst), 2);
        assert_eq!(outcomes.len(), 2);
        assert!(outcomes
            .iter()
            .all(|outcome| matches!(outcome, DispatchOutcome::ConcludedIntent { .. })));
    }

    #[tokio::test]
    async fn run_tick_respects_max_workers_limit() {
        let service = service().await;
        create_test_project(&service, "first").await;
        create_test_project(&service, "second").await;

        let current = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));
        let worker = DelayWorker {
            current: Arc::clone(&current),
            max_seen: Arc::clone(&max_seen),
            delay: Duration::from_millis(20),
        };
        let mut config = config();
        config.runtime.max_workers = 1;
        config.runtime.max_running_projects = 2;
        config.runtime.max_project_workers = 1;
        config.tasks.bootstrap.timeout = 2;
        let dispatcher = Dispatcher::new(service.clone(), Arc::new(worker), config);

        let created = dispatcher
            .run_tick()
            .await
            .expect("create bootstrap intents");
        assert_eq!(created.len(), 2);
        let outcomes = dispatcher.run_tick().await.expect("run one worker");
        assert_eq!(outcomes.len(), 1);
        assert_eq!(max_seen.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn refill_tick_runs_reason_after_new_fact_even_with_open_intents() {
        let service = service().await;
        let project_id = create_test_project(&service, "fact-triggered reason").await;
        let first_intent = expect_intent(
            service
                .handle(ClairvoyantRequest::CreateIntent {
                    project_id: project_id.clone(),
                    body: CreateIntentRequest {
                        sources: vec!["origin".into()],
                        description: "first explore".into(),
                        creator: "test".into(),
                        worker: None,
                    },
                })
                .await
                .expect("create first intent"),
        )
        .expect("first intent");
        let second_intent = expect_intent(
            service
                .handle(ClairvoyantRequest::CreateIntent {
                    project_id: project_id.clone(),
                    body: CreateIntentRequest {
                        sources: vec!["origin".into()],
                        description: "second explore".into(),
                        creator: "test".into(),
                        worker: None,
                    },
                })
                .await
                .expect("create second intent"),
        )
        .expect("second intent");

        let reason_calls = Arc::new(AtomicUsize::new(0));
        let explore_calls = Arc::new(AtomicUsize::new(0));
        let mut config = config();
        config.runtime.max_workers = 2;
        config.runtime.max_project_workers = 2;
        config.runtime.max_running_projects = 1;
        config.tasks.reason.max_intents = 1;
        let dispatcher = Dispatcher::new(
            service.clone(),
            Arc::new(FactTriggeredReasonWorker {
                reason_calls: Arc::clone(&reason_calls),
                explore_calls: Arc::clone(&explore_calls),
            }),
            config,
        );

        let before_fact = expect_project_detail(
            service
                .handle(ClairvoyantRequest::GetProject {
                    project_id: project_id.clone(),
                })
                .await
                .expect("get project before fact"),
        )
        .expect("detail before fact");
        dispatcher.record_reason_checkpoint(&before_fact).await;

        expect_intent(
            service
                .handle(ClairvoyantRequest::HeartbeatIntent {
                    project_id: project_id.clone(),
                    intent_id: first_intent.id.clone(),
                    body: HeartbeatRequest {
                        worker: "test".into(),
                    },
                })
                .await
                .expect("claim first intent"),
        )
        .expect("claimed first intent");
        expect_conclude(
            service
                .handle(ClairvoyantRequest::ConcludeIntent {
                    project_id: project_id.clone(),
                    intent_id: first_intent.id,
                    body: ConcludeRequest {
                        worker: "test".into(),
                        description: "new fact from first explore".into(),
                    },
                })
                .await
                .expect("conclude first intent"),
        )
        .expect("concluded first intent");

        let outcomes = dispatcher
            .run_refill_tick()
            .await
            .expect("run refill after new fact");

        assert!(reason_calls.load(Ordering::SeqCst) >= 1);
        assert_eq!(explore_calls.load(Ordering::SeqCst), 1);
        assert!(outcomes
            .iter()
            .any(|outcome| { matches!(outcome, DispatchOutcome::ReasonNoop { .. }) }));
        assert!(outcomes.iter().any(|outcome| {
            matches!(
                outcome,
                DispatchOutcome::ConcludedIntent { intent_id, .. } if intent_id == &second_intent.id
            )
        }));
    }

    #[tokio::test]
    async fn invalid_prompt_group_does_not_claim_intent() {
        let service = service().await;
        let project_id = create_test_project(&service, "invalid prompt group").await;
        let intent = expect_intent(
            service
                .handle(ClairvoyantRequest::CreateIntent {
                    project_id: project_id.clone(),
                    body: CreateIntentRequest {
                        sources: vec!["origin".into()],
                        description: "explore".into(),
                        creator: "test".into(),
                        worker: None,
                    },
                })
                .await
                .expect("create intent"),
        )
        .expect("intent");
        let detail = expect_project_detail(
            service
                .handle(ClairvoyantRequest::GetProject {
                    project_id: project_id.clone(),
                })
                .await
                .expect("get project"),
        )
        .expect("project detail");
        let mut config = config();
        config.runtime.prompt_group = "missing".into();
        let dispatcher = Dispatcher::new(
            service.clone(),
            Arc::new(MockWorker::fact("unused")),
            config,
        );
        let entry = WorkerEntry {
            name: "worker".into(),
            worker: Arc::new(MockWorker::fact("unused")),
            max_running: 1,
            priority: 0,
        };
        dispatcher
            .run_intent_task_with_worker(entry, detail, intent.clone(), TaskKind::Explore)
            .await
            .expect_err("missing prompt group should fail before claiming");

        let detail = expect_project_detail(
            service
                .handle(ClairvoyantRequest::GetProject { project_id })
                .await
                .expect("get project after error"),
        )
        .expect("project detail after error");
        let unchanged = detail
            .intents
            .iter()
            .find(|candidate| candidate.id == intent.id)
            .expect("intent remains");
        assert!(unchanged.worker.is_none());
    }

    #[tokio::test]
    async fn invalid_prompt_group_does_not_claim_reason() {
        let service = service().await;
        let project_id = create_test_project(&service, "invalid reason prompt group").await;
        let detail = expect_project_detail(
            service
                .handle(ClairvoyantRequest::GetProject {
                    project_id: project_id.clone(),
                })
                .await
                .expect("get project"),
        )
        .expect("project detail");
        let mut config = config();
        config.runtime.prompt_group = "missing".into();
        let dispatcher = Dispatcher::new(
            service.clone(),
            Arc::new(MockWorker::fact("unused")),
            config,
        );
        let entry = WorkerEntry {
            name: "worker".into(),
            worker: Arc::new(MockWorker::fact("unused")),
            max_running: 1,
            priority: 0,
        };
        dispatcher
            .run_reason_task_with_worker(entry, detail, "manual trigger".into())
            .await
            .expect_err("missing prompt group should fail before claiming reason");

        let detail = expect_project_detail(
            service
                .handle(ClairvoyantRequest::GetProject { project_id })
                .await
                .expect("get project after error"),
        )
        .expect("project detail after error");
        assert!(detail.project.reason.is_none());
    }

    #[tokio::test]
    async fn run_tick_surfaces_task_failures_as_outcomes() {
        let service = service().await;
        create_test_project(&service, "failing tick").await;
        let dispatcher = Dispatcher::new(service, Arc::new(FailingWorker), config());

        let created = dispatcher
            .run_tick()
            .await
            .expect("create bootstrap intent");
        assert_eq!(created.len(), 1);
        assert!(matches!(
            &created[0],
            DispatchOutcome::CreatedBootstrapIntent { .. }
        ));

        let failed = dispatcher.run_tick().await.expect("surface failed task");
        assert_eq!(failed.len(), 1);
        assert!(matches!(
            &failed[0],
            DispatchOutcome::TaskFailed { message } if message.contains("reason failed")
        ));
    }

    #[tokio::test]
    async fn run_tick_respects_worker_specific_max_running() {
        let service = service().await;
        create_test_project(&service, "first").await;
        create_test_project(&service, "second").await;
        let yaml = r#"
runtime:
  max_workers: 2
  max_running_projects: 2
  max_project_workers: 1
workers:
  - name: primary
    type: mock
    task_types: [bootstrap, reason, explore]
    max_running: 1
    priority: 0
    env:
      MOCK_DESCRIPTION: "primary fact"
  - name: fallback
    type: mock
    task_types: [bootstrap, reason, explore]
    max_running: 1
    priority: 1
    env:
      MOCK_DESCRIPTION: "fallback fact"
"#;
        let config: DispatcherConfig = serde_yaml::from_str(yaml).expect("parse");
        config.validate().expect("valid");
        let workers = workers_from_config(&config).expect("workers");
        let dispatcher = Dispatcher::with_workers(service.clone(), workers, config);

        let created = dispatcher
            .run_tick()
            .await
            .expect("create bootstrap intents");
        assert_eq!(created.len(), 2);
        let outcomes = dispatcher.run_tick().await.expect("run bootstrap workers");
        assert_eq!(outcomes.len(), 2);

        let mut descriptions = Vec::new();
        for project_id in ["proj_001", "proj_002"] {
            let detail = match service
                .handle(ClairvoyantRequest::GetProject {
                    project_id: project_id.to_string(),
                })
                .await
                .expect("get project")
            {
                ClairvoyantResponse::ProjectDetail(detail) => detail,
                other => panic!("unexpected response {other:?}"),
            };
            descriptions.extend(
                detail
                    .facts
                    .into_iter()
                    .map(|fact| fact.description)
                    .filter(|description| description.ends_with(" fact")),
            );
        }
        descriptions.sort();
        assert_eq!(descriptions, vec!["fallback fact", "primary fact"]);
    }

    #[tokio::test]
    async fn workers_array_selects_worker_by_task_type_and_priority() {
        let service = service().await;
        service
            .handle(ClairvoyantRequest::CreateProject {
                body: CreateProjectRequest {
                    title: "worker select".into(),
                    origin: "start".into(),
                    goal: "goal".into(),
                    hints: None,
                },
            })
            .await
            .expect("create project");
        let yaml = r#"
workers:
  - name: all-tasks
    type: mock
    task_types: [bootstrap, reason, explore]
    priority: 10
    env:
      MOCK_DESCRIPTION: "all task fact"
  - name: bootstrap-fast
    type: mock
    task_types: [bootstrap]
    priority: 0
    env:
      MOCK_DESCRIPTION: "bootstrap priority fact"
"#;
        let config: DispatcherConfig = serde_yaml::from_str(yaml).expect("parse");
        config.validate().expect("valid");
        let workers = workers_from_config(&config).expect("workers");
        let dispatcher = Dispatcher::with_workers(service.clone(), workers, config);

        dispatcher
            .run_once()
            .await
            .expect("create bootstrap intent");
        let outcome = dispatcher.run_once().await.expect("run bootstrap worker");
        let fact_id = match outcome {
            DispatchOutcome::ConcludedIntent { fact_id, .. } => fact_id,
            other => panic!("unexpected outcome {other:?}"),
        };
        let detail = match service
            .handle(ClairvoyantRequest::GetProject {
                project_id: "proj_001".to_string(),
            })
            .await
            .expect("get project")
        {
            ClairvoyantResponse::ProjectDetail(detail) => detail,
            _ => panic!("unexpected response"),
        };
        let fact = detail
            .facts
            .iter()
            .find(|fact| fact.id == fact_id)
            .expect("new fact");
        assert_eq!(fact.description, "bootstrap priority fact");
    }

    #[tokio::test]
    async fn timed_out_intent_worker_releases_lease() {
        let service = service().await;
        let project_id = match service
            .handle(ClairvoyantRequest::CreateProject {
                body: CreateProjectRequest {
                    title: "timeout".into(),
                    origin: "start".into(),
                    goal: "goal".into(),
                    hints: None,
                },
            })
            .await
            .expect("create project")
        {
            ClairvoyantResponse::ProjectDetail(detail) => detail.project.id,
            _ => panic!("unexpected response"),
        };
        let mut config = config();
        config.tasks.bootstrap.timeout = 0;
        config.tasks.bootstrap.conclude_timeout = 0;
        let dispatcher = Dispatcher::new(service.clone(), Arc::new(BlockingWorker), config);
        dispatcher.run_once().await.expect("create bootstrap");

        let error = dispatcher
            .run_once()
            .await
            .expect_err("bootstrap worker should time out");
        assert!(error.to_string().contains("worker timed out"));

        let detail = match service
            .handle(ClairvoyantRequest::GetProject { project_id })
            .await
            .expect("get project")
        {
            ClairvoyantResponse::ProjectDetail(detail) => detail,
            _ => panic!("unexpected response"),
        };
        assert_eq!(detail.intents.len(), 1);
        assert!(detail.intents[0].worker.is_none());
    }

    #[tokio::test]
    async fn invalid_worker_fact_releases_intent_lease() {
        let service = service().await;
        let project_id = match service
            .handle(ClairvoyantRequest::CreateProject {
                body: CreateProjectRequest {
                    title: "invalid worker fact".into(),
                    origin: "start".into(),
                    goal: "goal".into(),
                    hints: None,
                },
            })
            .await
            .expect("create project")
        {
            ClairvoyantResponse::ProjectDetail(detail) => detail.project.id,
            _ => panic!("unexpected response"),
        };
        let dispatcher = Dispatcher::new(
            service.clone(),
            Arc::new(MockWorker::new(vec![WorkerEvent::Done {
                description: "  ".into(),
                complete: false,
            }])),
            config(),
        );
        dispatcher.run_once().await.expect("create bootstrap");

        let error = dispatcher
            .run_once()
            .await
            .expect_err("empty worker fact should fail conclude");
        assert!(error.to_string().contains("description must not be empty"));

        let detail = match service
            .handle(ClairvoyantRequest::GetProject { project_id })
            .await
            .expect("get project")
        {
            ClairvoyantResponse::ProjectDetail(detail) => detail,
            _ => panic!("unexpected response"),
        };
        assert_eq!(detail.intents.len(), 1);
        assert!(detail.intents[0].worker.is_none());
    }

    #[tokio::test]
    async fn heartbeat_failure_aborts_running_worker_task() {
        let service = service().await;
        let project_id = match service
            .handle(ClairvoyantRequest::CreateProject {
                body: CreateProjectRequest {
                    title: "heartbeat failure".into(),
                    origin: "start".into(),
                    goal: "goal".into(),
                    hints: None,
                },
            })
            .await
            .expect("create project")
        {
            ClairvoyantResponse::ProjectDetail(detail) => detail.project.id,
            _ => panic!("unexpected response"),
        };
        let started = Arc::new(tokio::sync::Notify::new());
        let dropped = Arc::new(tokio::sync::Notify::new());
        let mut config = config();
        config.runtime.interval = 1;
        config.tasks.bootstrap.timeout = 30;
        let dispatcher = Dispatcher::new(
            service.clone(),
            Arc::new(AbortObservedWorker {
                started: Arc::clone(&started),
                dropped: Arc::clone(&dropped),
            }),
            config,
        );
        dispatcher.run_once().await.expect("create bootstrap");

        let running = tokio::spawn({
            let dispatcher = dispatcher.clone();
            async move { dispatcher.run_once().await }
        });
        tokio::time::timeout(Duration::from_secs(2), started.notified())
            .await
            .expect("worker should start");

        service
            .handle(ClairvoyantRequest::UpdateProjectStatus {
                project_id: project_id.clone(),
                body: UpdateProjectStatusRequest {
                    status: ProjectStatus::Stopped,
                },
            })
            .await
            .expect("stop project");

        let error = tokio::time::timeout(Duration::from_secs(4), running)
            .await
            .expect("dispatcher should return after heartbeat failure")
            .expect("join dispatcher")
            .expect_err("heartbeat failure should fail dispatch");
        assert!(error.to_string().contains("Project is stopped"));
        tokio::time::timeout(Duration::from_secs(1), dropped.notified())
            .await
            .expect("worker task should be aborted after heartbeat failure");
    }

    #[tokio::test]
    async fn timeout_aborts_running_worker_task() {
        let service = service().await;
        let project_id = create_test_project(&service, "timeout abort").await;
        let intent = expect_intent(
            service
                .handle(ClairvoyantRequest::CreateIntent {
                    project_id: project_id.clone(),
                    body: CreateIntentRequest {
                        sources: vec!["origin".to_string()],
                        description: "slow branch".to_string(),
                        creator: "test".to_string(),
                        worker: None,
                    },
                })
                .await
                .expect("create intent"),
        )
        .expect("intent response");
        let started = Arc::new(tokio::sync::Notify::new());
        let dropped = Arc::new(tokio::sync::Notify::new());
        let mut config = config();
        config.tasks.explore.timeout = 1;
        config.tasks.explore.conclude_timeout = 1;
        let dispatcher = Dispatcher::new(
            service.clone(),
            Arc::new(AbortObservedWorker {
                started: Arc::clone(&started),
                dropped: Arc::clone(&dropped),
            }),
            config,
        );

        let running = tokio::spawn({
            let dispatcher = dispatcher.clone();
            let detail = expect_project_detail(
                service
                    .handle(ClairvoyantRequest::GetProject {
                        project_id: project_id.clone(),
                    })
                    .await
                    .expect("get project"),
            )
            .expect("detail response");
            async move {
                dispatcher
                    .run_intent_task(detail, intent, TaskKind::Explore)
                    .await
            }
        });
        tokio::time::timeout(Duration::from_secs(2), started.notified())
            .await
            .expect("worker should start");
        let error = tokio::time::timeout(Duration::from_secs(4), running)
            .await
            .expect("dispatcher should return after timeout")
            .expect("join dispatcher")
            .expect_err("timeout should fail dispatch");
        assert!(error.to_string().contains("worker timed out"));
        tokio::time::timeout(Duration::from_secs(1), dropped.notified())
            .await
            .expect("worker task should be aborted after timeout");
    }

    #[tokio::test]
    async fn worker_complete_event_completes_project() {
        let service = service().await;
        let project_id = match service
            .handle(ClairvoyantRequest::CreateProject {
                body: CreateProjectRequest {
                    title: "demo".into(),
                    origin: "start".into(),
                    goal: "goal".into(),
                    hints: None,
                },
            })
            .await
            .expect("create project")
        {
            ClairvoyantResponse::ProjectDetail(detail) => detail.project.id,
            _ => panic!("unexpected response"),
        };
        let dispatcher = Dispatcher::new(
            service.clone(),
            Arc::new(MockWorker::new(vec![WorkerEvent::Done {
                description: "final fact".into(),
                complete: true,
            }])),
            config(),
        );
        dispatcher.run_once().await.expect("create bootstrap");
        dispatcher.run_once().await.expect("complete");
        let detail = match service
            .handle(ClairvoyantRequest::GetProject { project_id })
            .await
            .expect("get project")
        {
            ClairvoyantResponse::ProjectDetail(detail) => detail,
            _ => panic!("unexpected response"),
        };
        assert!(matches!(detail.project.status, ProjectStatus::Completed));
    }

    #[tokio::test]
    async fn reason_declares_new_intent_when_no_open_intents_exist() {
        let service = service().await;
        let project_id = match service
            .handle(ClairvoyantRequest::CreateProject {
                body: CreateProjectRequest {
                    title: "reason".into(),
                    origin: "start".into(),
                    goal: "goal".into(),
                    hints: None,
                },
            })
            .await
            .expect("create project")
        {
            ClairvoyantResponse::ProjectDetail(detail) => detail.project.id,
            _ => panic!("unexpected response"),
        };
        let dispatcher = Dispatcher::new(
            service.clone(),
            Arc::new(MockWorker::fact("initial fact")),
            config(),
        );
        dispatcher.run_once().await.expect("create bootstrap");
        dispatcher.run_once().await.expect("conclude bootstrap");

        let reason_dispatcher = Dispatcher::new(
            service.clone(),
            Arc::new(MockWorker::new(vec![WorkerEvent::Intent {
                sources: vec!["f001".into()],
                description: "follow f001".into(),
            }])),
            config(),
        );
        let outcome = reason_dispatcher.run_once().await.expect("reason");
        assert!(matches!(
            outcome,
            DispatchOutcome::CreatedReasonIntent {
                intent_id,
                ..
            } if intent_id == "i002"
        ));
        let detail = match service
            .handle(ClairvoyantRequest::GetProject { project_id })
            .await
            .expect("get project")
        {
            ClairvoyantResponse::ProjectDetail(detail) => detail,
            _ => panic!("unexpected response"),
        };
        assert_eq!(detail.intents.len(), 2);
        assert_eq!(detail.intents[1].sources, vec!["f001"]);
    }

    #[tokio::test]
    async fn reason_can_declare_multiple_intents_up_to_limit() {
        let service = service().await;
        service
            .handle(ClairvoyantRequest::CreateProject {
                body: CreateProjectRequest {
                    title: "multi reason".into(),
                    origin: "start".into(),
                    goal: "goal".into(),
                    hints: None,
                },
            })
            .await
            .expect("create project");
        let mut config = config();
        config.tasks.reason.max_intents = 2;
        let bootstrap = Dispatcher::new(
            service.clone(),
            Arc::new(MockWorker::fact("initial fact")),
            config.clone(),
        );
        bootstrap.run_once().await.expect("create bootstrap");
        bootstrap.run_once().await.expect("conclude bootstrap");

        let dispatcher = Dispatcher::new(
            service,
            Arc::new(MockWorker::new(vec![
                WorkerEvent::Intent {
                    sources: vec!["f001".into()],
                    description: "first branch".into(),
                },
                WorkerEvent::Intent {
                    sources: vec!["f001".into()],
                    description: "second branch".into(),
                },
                WorkerEvent::Intent {
                    sources: vec!["f001".into()],
                    description: "ignored branch".into(),
                },
            ])),
            config,
        );
        let outcome = dispatcher.run_once().await.expect("reason");
        assert!(matches!(
            outcome,
            DispatchOutcome::CreatedReasonIntents { intent_ids, .. } if intent_ids == ["i002", "i003"]
        ));
    }

    #[tokio::test]
    async fn dispatcher_stops_reason_stream_after_max_intents() {
        let service = service().await;
        service
            .handle(ClairvoyantRequest::CreateProject {
                body: CreateProjectRequest {
                    title: "reason stream max intents".into(),
                    origin: "start".into(),
                    goal: "goal".into(),
                    hints: None,
                },
            })
            .await
            .expect("create project");
        let mut config = config();
        config.tasks.reason.max_intents = 2;
        let bootstrap = Dispatcher::new(
            service.clone(),
            Arc::new(MockWorker::fact("initial fact")),
            config.clone(),
        );
        bootstrap.run_once().await.expect("create bootstrap");
        bootstrap.run_once().await.expect("conclude bootstrap");

        let dispatcher = Dispatcher::new(
            service,
            Arc::new(ReasonIntentsThenPendingStreamWorker),
            config,
        );
        let outcome = tokio::time::timeout(Duration::from_secs(1), dispatcher.run_once())
            .await
            .expect("reason stream should stop after max_intents")
            .expect("reason stream");
        assert!(matches!(
            outcome,
            DispatchOutcome::CreatedReasonIntents { intent_ids, .. } if intent_ids == ["i002", "i003"]
        ));
    }

    #[tokio::test]
    async fn dispatcher_drops_reason_stream_after_max_intents() {
        let service = service().await;
        service
            .handle(ClairvoyantRequest::CreateProject {
                body: CreateProjectRequest {
                    title: "drop reason stream".into(),
                    origin: "start".into(),
                    goal: "goal".into(),
                    hints: None,
                },
            })
            .await
            .expect("create project");
        let mut config = config();
        config.tasks.reason.max_intents = 2;
        let bootstrap = Dispatcher::new(
            service.clone(),
            Arc::new(MockWorker::fact("initial fact")),
            config.clone(),
        );
        bootstrap.run_once().await.expect("create bootstrap");
        bootstrap.run_once().await.expect("conclude bootstrap");

        let dropped = Arc::new(tokio::sync::Notify::new());
        let dispatcher = Dispatcher::new(
            service,
            Arc::new(DropObservedReasonIntentsStreamWorker {
                dropped: Arc::clone(&dropped),
            }),
            config,
        );
        let outcome = dispatcher.run_once().await.expect("reason stream");
        assert!(matches!(
            outcome,
            DispatchOutcome::CreatedReasonIntents { intent_ids, .. } if intent_ids == ["i002", "i003"]
        ));
        tokio::time::timeout(Duration::from_secs(1), dropped.notified())
            .await
            .expect("max_intents should drop reason worker stream");
    }

    #[tokio::test]
    async fn reason_checkpoint_skips_unchanged_project_until_hint_changes() {
        let service = service().await;
        let project_id = match service
            .handle(ClairvoyantRequest::CreateProject {
                body: CreateProjectRequest {
                    title: "reason checkpoint".into(),
                    origin: "start".into(),
                    goal: "goal".into(),
                    hints: None,
                },
            })
            .await
            .expect("create project")
        {
            ClairvoyantResponse::ProjectDetail(detail) => detail.project.id,
            _ => panic!("unexpected response"),
        };
        let bootstrap = Dispatcher::new(
            service.clone(),
            Arc::new(MockWorker::fact("initial fact")),
            config(),
        );
        bootstrap.run_once().await.expect("create bootstrap");
        bootstrap.run_once().await.expect("conclude bootstrap");

        let reason = Dispatcher::new(
            service.clone(),
            Arc::new(MockWorker::fact("reason observed no action")),
            config(),
        );
        let first = reason.run_once().await.expect("initial reason");
        assert!(matches!(first, DispatchOutcome::ReasonNoop { .. }));
        let second = reason.run_once().await.expect("unchanged reason skip");
        assert!(matches!(second, DispatchOutcome::NoRunnableIntent));

        service
            .handle(ClairvoyantRequest::CreateHint {
                project_id,
                body: clairvoyant_core::CreateHintRequest {
                    content: "new hint".into(),
                    creator: "human".into(),
                },
            })
            .await
            .expect("create hint");
        let third = reason.run_once().await.expect("hint-triggered reason");
        assert!(matches!(third, DispatchOutcome::ReasonNoop { .. }));
        let fourth = reason.run_once().await.expect("unchanged after hint");
        assert!(matches!(fourth, DispatchOutcome::NoRunnableIntent));
    }

    #[tokio::test]
    async fn reason_checkpoint_initializes_from_open_project_summary() {
        let service = service().await;
        let detail = expect_project_detail(
            service
                .handle(ClairvoyantRequest::CreateProject {
                    body: CreateProjectRequest {
                        title: "checkpoint init".into(),
                        origin: "start".into(),
                        goal: "goal".into(),
                        hints: None,
                    },
                })
                .await
                .expect("create project"),
        )
        .expect("project detail");
        service
            .handle(ClairvoyantRequest::CreateIntent {
                project_id: detail.project.id.clone(),
                body: CreateIntentRequest {
                    sources: vec!["origin".into()],
                    description: "open branch".into(),
                    creator: "test".into(),
                    worker: None,
                },
            })
            .await
            .expect("create open intent");

        let dispatcher = Dispatcher::new(
            service.clone(),
            Arc::new(MockWorker::fact("unused")),
            config(),
        );
        let summaries = expect_project_summaries(
            service
                .handle(ClairvoyantRequest::ListProjects)
                .await
                .expect("list projects"),
        )
        .expect("project summaries");
        dispatcher.initialize_reason_checkpoints(&summaries).await;
        let unchanged = expect_project_detail(
            service
                .handle(ClairvoyantRequest::GetProject {
                    project_id: detail.project.id.clone(),
                })
                .await
                .expect("get unchanged project"),
        )
        .expect("unchanged detail");
        assert!(dispatcher.reason_trigger(&unchanged).await.is_none());

        service
            .handle(ClairvoyantRequest::CreateHint {
                project_id: detail.project.id,
                body: clairvoyant_core::CreateHintRequest {
                    content: "hint".into(),
                    creator: "human".into(),
                },
            })
            .await
            .expect("create hint");
        let changed = expect_project_detail(
            service
                .handle(ClairvoyantRequest::GetProject {
                    project_id: unchanged.project.id,
                })
                .await
                .expect("get changed project"),
        )
        .expect("changed detail");
        assert!(dispatcher
            .reason_trigger(&changed)
            .await
            .is_some_and(|trigger| trigger.contains("hints:0->1")));
    }

    #[tokio::test]
    async fn reason_complete_event_completes_project() {
        let service = service().await;
        let project_id = match service
            .handle(ClairvoyantRequest::CreateProject {
                body: CreateProjectRequest {
                    title: "reason complete".into(),
                    origin: "start".into(),
                    goal: "goal".into(),
                    hints: None,
                },
            })
            .await
            .expect("create project")
        {
            ClairvoyantResponse::ProjectDetail(detail) => detail.project.id,
            _ => panic!("unexpected response"),
        };
        let bootstrap = Dispatcher::new(
            service.clone(),
            Arc::new(MockWorker::fact("initial fact")),
            config(),
        );
        bootstrap.run_once().await.expect("create bootstrap");
        bootstrap.run_once().await.expect("conclude bootstrap");

        let reason = Dispatcher::new(
            service.clone(),
            Arc::new(MockWorker::new(vec![WorkerEvent::Complete {
                sources: vec!["f001".into()],
                description: "goal satisfied".into(),
            }])),
            config(),
        );
        let outcome = reason.run_once().await.expect("reason complete");
        assert!(matches!(
            outcome,
            DispatchOutcome::CompletedByReason {
                intent_id,
                ..
            } if intent_id == "i002"
        ));
        let detail = match service
            .handle(ClairvoyantRequest::GetProject { project_id })
            .await
            .expect("get project")
        {
            ClairvoyantResponse::ProjectDetail(detail) => detail,
            _ => panic!("unexpected response"),
        };
        assert!(matches!(detail.project.status, ProjectStatus::Completed));
    }

    #[tokio::test]
    async fn reason_complete_event_with_invalid_sources_releases_reason_lease() {
        let service = service().await;
        let project_id = match service
            .handle(ClairvoyantRequest::CreateProject {
                body: CreateProjectRequest {
                    title: "reason invalid complete".into(),
                    origin: "start".into(),
                    goal: "goal".into(),
                    hints: None,
                },
            })
            .await
            .expect("create project")
        {
            ClairvoyantResponse::ProjectDetail(detail) => detail.project.id,
            _ => panic!("unexpected response"),
        };
        let bootstrap = Dispatcher::new(
            service.clone(),
            Arc::new(MockWorker::fact("initial fact")),
            config(),
        );
        bootstrap.run_once().await.expect("create bootstrap");
        bootstrap.run_once().await.expect("conclude bootstrap");

        let reason = Dispatcher::new(
            service.clone(),
            Arc::new(MockWorker::new(vec![WorkerEvent::Complete {
                sources: vec!["f404".into()],
                description: "bogus completion source".into(),
            }])),
            config(),
        );
        let error = reason
            .run_once()
            .await
            .expect_err("invalid completion source should fail");
        assert!(error.to_string().contains("Fact f404 not found"));

        let detail = match service
            .handle(ClairvoyantRequest::GetProject { project_id })
            .await
            .expect("get project")
        {
            ClairvoyantResponse::ProjectDetail(detail) => detail,
            _ => panic!("unexpected response"),
        };
        assert!(matches!(detail.project.status, ProjectStatus::Active));
        assert!(detail.project.reason.is_none());
        assert!(detail
            .intents
            .iter()
            .all(|intent| intent.target_fact.as_deref() != Some("goal")));
    }

    #[tokio::test]
    async fn reason_intent_event_with_invalid_sources_releases_reason_lease() {
        let service = service().await;
        let project_id = match service
            .handle(ClairvoyantRequest::CreateProject {
                body: CreateProjectRequest {
                    title: "reason invalid intent".into(),
                    origin: "start".into(),
                    goal: "goal".into(),
                    hints: None,
                },
            })
            .await
            .expect("create project")
        {
            ClairvoyantResponse::ProjectDetail(detail) => detail.project.id,
            _ => panic!("unexpected response"),
        };
        let bootstrap = Dispatcher::new(
            service.clone(),
            Arc::new(MockWorker::fact("initial fact")),
            config(),
        );
        bootstrap.run_once().await.expect("create bootstrap");
        bootstrap.run_once().await.expect("conclude bootstrap");

        let reason = Dispatcher::new(
            service.clone(),
            Arc::new(MockWorker::new(vec![WorkerEvent::Intent {
                sources: vec!["f404".into()],
                description: "explore missing source".into(),
            }])),
            config(),
        );
        let error = reason
            .run_once()
            .await
            .expect_err("invalid intent source should fail");
        assert!(error.to_string().contains("Fact f404 not found"));

        let detail = match service
            .handle(ClairvoyantRequest::GetProject { project_id })
            .await
            .expect("get project")
        {
            ClairvoyantResponse::ProjectDetail(detail) => detail,
            _ => panic!("unexpected response"),
        };
        assert!(matches!(detail.project.status, ProjectStatus::Active));
        assert!(detail.project.reason.is_none());
        assert!(detail
            .intents
            .iter()
            .all(|intent| intent.description != "explore missing source"));
    }

    #[tokio::test]
    async fn reason_worker_failure_releases_reason_lease() {
        let service = service().await;
        let project_id = match service
            .handle(ClairvoyantRequest::CreateProject {
                body: CreateProjectRequest {
                    title: "reason failure release".into(),
                    origin: "start".into(),
                    goal: "goal".into(),
                    hints: None,
                },
            })
            .await
            .expect("create project")
        {
            ClairvoyantResponse::ProjectDetail(detail) => detail.project.id,
            _ => panic!("unexpected response"),
        };
        let bootstrap = Dispatcher::new(
            service.clone(),
            Arc::new(MockWorker::fact("initial fact")),
            config(),
        );
        bootstrap.run_once().await.expect("create bootstrap");
        bootstrap.run_once().await.expect("conclude bootstrap");

        let reason = Dispatcher::new(service.clone(), Arc::new(FailingWorker), config());
        reason
            .run_once()
            .await
            .expect_err("reason worker failure should be returned");
        let detail = match service
            .handle(ClairvoyantRequest::GetProject { project_id })
            .await
            .expect("get project")
        {
            ClairvoyantResponse::ProjectDetail(detail) => detail,
            _ => panic!("unexpected response"),
        };
        assert!(detail.project.reason.is_none());
    }

    #[tokio::test]
    async fn reason_done_complete_true_does_not_complete_without_sources() {
        let service = service().await;
        let project_id = match service
            .handle(ClairvoyantRequest::CreateProject {
                body: CreateProjectRequest {
                    title: "reason done complete".into(),
                    origin: "start".into(),
                    goal: "goal".into(),
                    hints: None,
                },
            })
            .await
            .expect("create project")
        {
            ClairvoyantResponse::ProjectDetail(detail) => detail.project.id,
            _ => panic!("unexpected response"),
        };
        let bootstrap = Dispatcher::new(
            service.clone(),
            Arc::new(MockWorker::fact("initial fact")),
            config(),
        );
        bootstrap.run_once().await.expect("create bootstrap");
        bootstrap.run_once().await.expect("conclude bootstrap");

        let reason = Dispatcher::new(
            service.clone(),
            Arc::new(MockWorker::new(vec![WorkerEvent::Done {
                description: "goal might be satisfied but no sources were provided".into(),
                complete: true,
            }])),
            config(),
        );
        let outcome = reason.run_once().await.expect("reason noop");
        assert!(matches!(outcome, DispatchOutcome::ReasonNoop { .. }));
        let detail = match service
            .handle(ClairvoyantRequest::GetProject { project_id })
            .await
            .expect("get project")
        {
            ClairvoyantResponse::ProjectDetail(detail) => detail,
            _ => panic!("unexpected response"),
        };
        assert!(matches!(detail.project.status, ProjectStatus::Active));
        assert!(detail
            .intents
            .iter()
            .all(|intent| intent.target_fact.as_deref() != Some("goal")));
    }
}
