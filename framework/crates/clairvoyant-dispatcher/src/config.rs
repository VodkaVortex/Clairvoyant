use crate::prompt_bundle;
use crate::DispatcherError;
use clairvoyant_runtime::RuntimeConfig;
use clairvoyant_workers::claude_args_allow_webfetch;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatcherConfig {
    #[serde(default)]
    pub db_path: Option<std::path::PathBuf>,
    #[serde(default)]
    pub worker: Option<WorkerConfig>,
    #[serde(default)]
    pub workers: Vec<WorkerSpec>,
    #[serde(default)]
    pub common_env: BTreeMap<String, String>,
    #[serde(default)]
    pub runtime: SchedulerRuntimeConfig,
    #[serde(default)]
    pub tasks: TaskConfig,
    #[serde(default)]
    pub container: Option<ContainerConfig>,
    #[serde(default = "default_worker_name")]
    pub worker_name: String,
    #[serde(default = "default_bootstrap_intent")]
    pub bootstrap_intent: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkerConfig {
    Mock {
        description: String,
        #[serde(default)]
        env: BTreeMap<String, String>,
    },
    Command {
        program: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        env: BTreeMap<String, String>,
    },
    #[serde(alias = "claudecode")]
    ClaudeCode {
        program: Option<String>,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        env: BTreeMap<String, String>,
    },
    /// Binary exploitation tool worker.
    ///
    /// Runs configured tools against a target binary file extracted from
    /// the intent description.  Tools are specified as a comma-separated
    /// list in the `tools` field (defaults to all available).
    Tool {
        #[serde(default = "default_tool_list")]
        tools: Vec<String>,
        #[serde(default)]
        env: BTreeMap<String, String>,
    },
}

fn default_tool_list() -> Vec<String> {
    vec![
        "checksec".to_string(),
        "strings".to_string(),
        "objdump".to_string(),
        "readelf".to_string(),
    ]
}

impl WorkerConfig {
    pub(crate) fn kind(&self) -> WorkerKind {
        match self {
            WorkerConfig::Mock { .. } => WorkerKind::Mock,
            WorkerConfig::Command { .. } => WorkerKind::Command,
            WorkerConfig::ClaudeCode { .. } => WorkerKind::ClaudeCode,
            WorkerConfig::Tool { .. } => WorkerKind::Tool,
        }
    }

    pub(crate) fn env(&self) -> &BTreeMap<String, String> {
        match self {
            WorkerConfig::Mock { env, .. }
            | WorkerConfig::Command { env, .. }
            | WorkerConfig::ClaudeCode { env, .. }
            | WorkerConfig::Tool { env, .. } => env,
        }
    }

    fn env_mut(&mut self) -> &mut BTreeMap<String, String> {
        match self {
            WorkerConfig::Mock { env, .. }
            | WorkerConfig::Command { env, .. }
            | WorkerConfig::ClaudeCode { env, .. }
            | WorkerConfig::Tool { env, .. } => env,
        }
    }
}

fn default_bootstrap_intent() -> String {
    "bootstrap".to_string()
}

fn default_worker_name() -> String {
    "dispatcher".to_string()
}

fn resolve_env_map_placeholders(
    scope: &str,
    env: &mut BTreeMap<String, String>,
) -> Result<(), DispatcherError> {
    for (key, value) in env.iter_mut() {
        if let Some(name) = whole_env_placeholder(value) {
            let resolved = std::env::var(name).map_err(|_| {
                DispatcherError::InvalidConfig(format!(
                    "{scope}.{key} references ${{{name}}}, but that environment variable is not set"
                ))
            })?;
            if resolved.trim().is_empty() {
                return Err(DispatcherError::InvalidConfig(format!(
                    "{scope}.{key} references ${{{name}}}, but that environment variable is empty"
                )));
            }
            *value = resolved;
        } else if value.contains("${") {
            return Err(DispatcherError::InvalidConfig(format!(
                "{scope}.{key} contains an unsupported env placeholder; use the whole-value form ${{VAR}}"
            )));
        }
    }
    Ok(())
}

fn whole_env_placeholder(value: &str) -> Option<&str> {
    let inner = value.strip_prefix("${")?.strip_suffix('}')?;
    if inner.is_empty()
        || !inner
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return None;
    }
    Some(inner)
}

impl DispatcherConfig {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, DispatcherError> {
        let text = std::fs::read_to_string(path)?;
        let mut config: Self = serde_yaml::from_str(&text)?;
        config.resolve_env_placeholders()?;
        config.validate()?;
        Ok(config)
    }

    pub fn from_path_runtime_only(path: impl AsRef<Path>) -> Result<Self, DispatcherError> {
        let text = std::fs::read_to_string(path)?;
        let mut config: Self = serde_yaml::from_str(&text)?;
        resolve_env_map_placeholders("common_env", &mut config.common_env)?;
        config.validate_runtime_only()?;
        Ok(config)
    }

    pub fn resolve_env_placeholders(&mut self) -> Result<(), DispatcherError> {
        resolve_env_map_placeholders("common_env", &mut self.common_env)?;
        if let Some(worker) = &mut self.worker {
            resolve_env_map_placeholders("worker.env", worker.env_mut())?;
        }
        for worker in &mut self.workers {
            resolve_env_map_placeholders(&format!("workers.{}.env", worker.name), &mut worker.env)?;
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), DispatcherError> {
        self.validate_runtime_only()?;
        if self.worker_name.trim().is_empty() {
            return Err(DispatcherError::InvalidConfig(
                "worker_name must not be empty".to_string(),
            ));
        }
        if self.bootstrap_intent.trim().is_empty() {
            return Err(DispatcherError::InvalidConfig(
                "bootstrap_intent must not be empty".to_string(),
            ));
        }
        if self.worker.is_none() && self.workers.is_empty() {
            return Err(DispatcherError::InvalidConfig(
                "configure either `worker` or `workers[]`".to_string(),
            ));
        }
        if self.worker.is_some() && !self.workers.is_empty() {
            return Err(DispatcherError::InvalidConfig(
                "configure either `worker` or `workers[]`, not both".to_string(),
            ));
        }
        if self.tasks.bootstrap.timeout == 0
            || self.tasks.bootstrap.conclude_timeout == 0
            || self.tasks.explore.timeout == 0
            || self.tasks.explore.conclude_timeout == 0
            || self.tasks.reason.timeout == 0
            || self.tasks.reason.max_intents == 0
        {
            return Err(DispatcherError::InvalidConfig(
                "task timeouts and reason.max_intents must be >= 1".to_string(),
            ));
        }
        if let Some(worker) = &self.worker {
            self.validate_worker_config_shape("worker", worker)?;
            validate_env_map_keys("worker.env", worker.env())?;
            let mut env = self.common_env.clone();
            env.extend(worker.env().clone());
            self.validate_worker_config_env("worker", worker, &env)?;
        }
        let mut names = BTreeSet::new();
        for worker in &self.workers {
            if worker.name.trim().is_empty() {
                return Err(DispatcherError::InvalidConfig(
                    "workers[].name must not be empty".to_string(),
                ));
            }
            if !names.insert(worker.name.as_str()) {
                return Err(DispatcherError::InvalidConfig(format!(
                    "worker names must be unique: {}",
                    worker.name
                )));
            }
            if worker.max_running == 0 {
                return Err(DispatcherError::InvalidConfig(format!(
                    "worker {} max_running must be >= 1",
                    worker.name
                )));
            }
            if worker.priority < 0 {
                return Err(DispatcherError::InvalidConfig(format!(
                    "worker {} priority must be >= 0",
                    worker.name
                )));
            }
            if worker.task_types.is_empty() {
                return Err(DispatcherError::InvalidConfig(format!(
                    "worker {} task_types must not be empty",
                    worker.name
                )));
            }
            let mut task_types = BTreeSet::new();
            for task_type in &worker.task_types {
                if !task_types.insert(*task_type) {
                    return Err(DispatcherError::InvalidConfig(format!(
                        "worker {} task_types must be unique",
                        worker.name
                    )));
                }
            }
            self.validate_worker_spec_shape(worker)?;
            self.validate_worker_spec_env(worker)?;
        }
        self.validate_container_network_for_workers()?;
        self.validate_prompt_group_worker_compatibility()?;
        Ok(())
    }

    fn validate_runtime_only(&self) -> Result<(), DispatcherError> {
        if self.runtime.interval == 0 {
            return Err(DispatcherError::InvalidConfig(
                "runtime.interval must be >= 1".to_string(),
            ));
        }
        if self.runtime.max_workers == 0 {
            return Err(DispatcherError::InvalidConfig(
                "runtime.max_workers must be >= 1".to_string(),
            ));
        }
        if self.runtime.max_running_projects == 0 {
            return Err(DispatcherError::InvalidConfig(
                "runtime.max_running_projects must be >= 1".to_string(),
            ));
        }
        if self.runtime.max_project_workers == 0 {
            return Err(DispatcherError::InvalidConfig(
                "runtime.max_project_workers must be >= 1".to_string(),
            ));
        }
        if self.runtime.max_project_workers > self.runtime.max_workers {
            return Err(DispatcherError::InvalidConfig(
                "runtime.max_project_workers cannot exceed runtime.max_workers".to_string(),
            ));
        }
        if self.runtime.healthcheck_timeout == 0 {
            return Err(DispatcherError::InvalidConfig(
                "runtime.healthcheck_timeout must be >= 1".to_string(),
            ));
        }
        if self.runtime.prompt_group.trim().is_empty() {
            return Err(DispatcherError::InvalidConfig(
                "runtime.prompt_group must not be empty".to_string(),
            ));
        }
        validate_env_map_keys("common_env", &self.common_env)?;
        if let Some(container) = &self.container {
            if container.image.trim().is_empty() {
                return Err(DispatcherError::InvalidConfig(
                    "container.image must not be empty".to_string(),
                ));
            }
            if let Some(network_mode) = container.network_mode.as_deref() {
                validate_container_network_mode(network_mode)?;
            }
            if let Some(workdir) = &container.workdir {
                if workdir.to_string_lossy().trim().is_empty() {
                    return Err(DispatcherError::InvalidConfig(
                        "container.workdir must not be empty".to_string(),
                    ));
                }
            }
            for (index, volume) in container.volumes.iter().enumerate() {
                if volume.trim().is_empty() {
                    return Err(DispatcherError::InvalidConfig(format!(
                        "container.volumes[{index}] must not be empty"
                    )));
                }
            }
            for (index, host) in container.extra_hosts.iter().enumerate() {
                if host.trim().is_empty() {
                    return Err(DispatcherError::InvalidConfig(format!(
                        "container.extra_hosts[{index}] must not be empty"
                    )));
                }
            }
        }
        if self.tasks.bootstrap.timeout == 0
            || self.tasks.bootstrap.conclude_timeout == 0
            || self.tasks.explore.timeout == 0
            || self.tasks.explore.conclude_timeout == 0
            || self.tasks.reason.timeout == 0
            || self.tasks.reason.max_intents == 0
        {
            return Err(DispatcherError::InvalidConfig(
                "task timeouts and reason.max_intents must be >= 1".to_string(),
            ));
        }
        prompt_bundle(&self.runtime.prompt_group)?;
        Ok(())
    }

    fn validate_worker_spec_env(&self, worker: &WorkerSpec) -> Result<(), DispatcherError> {
        validate_env_map_keys(&format!("workers.{}.env", worker.name), &worker.env)?;
        let mut env = self.common_env.clone();
        env.extend(worker.env.clone());
        self.validate_worker_config_env(&worker.name, &worker.to_worker_config(), &env)
    }

    fn validate_worker_spec_shape(&self, worker: &WorkerSpec) -> Result<(), DispatcherError> {
        // Tool workers don't need a program
        if worker.kind == WorkerKind::Tool {
            if let Some(tools) = worker.env.get("CAIRN_TOOLS") {
                validate_tool_names(
                    &format!("worker {} CAIRN_TOOLS", worker.name),
                    &parse_tool_names(tools),
                )?;
            }
            return Ok(());
        }
        if worker.kind == WorkerKind::ClaudeCode {
            validate_claude_args_do_not_allow_webfetch(
                &format!("worker {}", worker.name),
                &worker.args,
            )?;
            validate_claude_args_noninteractive_text_mode(
                &format!("worker {}", worker.name),
                &worker.args,
            )?;
        }
        if worker
            .program
            .as_ref()
            .is_some_and(|program| program.trim().is_empty())
        {
            return Err(DispatcherError::InvalidConfig(format!(
                "worker {} program must not be empty",
                worker.name
            )));
        }
        Ok(())
    }

    fn validate_worker_config_shape(
        &self,
        name: &str,
        worker: &WorkerConfig,
    ) -> Result<(), DispatcherError> {
        let program = match worker {
            WorkerConfig::Command { program, .. } => Some(program.as_str()),
            WorkerConfig::ClaudeCode { program, .. } => program.as_deref(),
            WorkerConfig::Mock { .. } | WorkerConfig::Tool { .. } => None,
        };
        if program.is_some_and(|program| program.trim().is_empty()) {
            return Err(DispatcherError::InvalidConfig(format!(
                "worker {name} program must not be empty"
            )));
        }
        if let WorkerConfig::Tool { tools, .. } = worker {
            validate_tool_names(&format!("worker {name} tools"), tools)?;
        }
        if let WorkerConfig::ClaudeCode { args, .. } = worker {
            validate_claude_args_do_not_allow_webfetch(&format!("worker {name}"), args)?;
            validate_claude_args_noninteractive_text_mode(&format!("worker {name}"), args)?;
        }
        Ok(())
    }

    fn validate_worker_config_env(
        &self,
        name: &str,
        worker: &WorkerConfig,
        env: &BTreeMap<String, String>,
    ) -> Result<(), DispatcherError> {
        if let WorkerConfig::ClaudeCode { args, .. } = worker {
            if args.is_empty() {
                let missing = ["ANTHROPIC_MODEL", "ANTHROPIC_BASE_URL"]
                    .into_iter()
                    .filter(|key| env.get(*key).is_none_or(|value| value.trim().is_empty()))
                    .collect::<Vec<_>>();
                if !missing.is_empty() {
                    return Err(DispatcherError::InvalidConfig(format!(
                        "worker {} missing env keys: {}",
                        name,
                        missing.join(", ")
                    )));
                }
                if env
                    .get("ANTHROPIC_API_KEY")
                    .is_none_or(|value| value.trim().is_empty())
                    && env
                        .get("ANTHROPIC_AUTH_TOKEN")
                        .is_none_or(|value| value.trim().is_empty())
                {
                    return Err(DispatcherError::InvalidConfig(format!(
                        "worker {} missing env keys: ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN",
                        name
                    )));
                }
            }
        }
        Ok(())
    }

    fn validate_container_network_for_workers(&self) -> Result<(), DispatcherError> {
        let Some(container) = &self.container else {
            return Ok(());
        };
        if !container_network_disabled(container.network_mode.as_deref()) {
            return Ok(());
        }
        if let Some(worker) = &self.worker {
            if worker_kind_needs_model_network(worker.kind()) {
                return Err(DispatcherError::InvalidConfig(format!(
                    "container.network_mode `none`/`disabled` cannot be used with worker kind {:?}; model CLI workers need network egress. Use `bridge`/`host` or remove `container`.",
                    worker.kind()
                )));
            }
        }
        for worker in &self.workers {
            if worker_kind_needs_model_network(worker.kind) {
                return Err(DispatcherError::InvalidConfig(format!(
                    "container.network_mode `none`/`disabled` cannot be used with worker {} kind {:?}; model CLI workers need network egress. Use `bridge`/`host` or remove `container`.",
                    worker.name, worker.kind
                )));
            }
        }
        Ok(())
    }

    fn validate_prompt_group_worker_compatibility(&self) -> Result<(), DispatcherError> {
        if self.runtime.prompt_group != "python" {
            return Ok(());
        }
        if let Some(worker) = &self.worker {
            if worker.kind() != WorkerKind::Mock {
                return Err(DispatcherError::InvalidConfig(format!(
                    "runtime.prompt_group `python` mirrors the legacy Python JSON contract and is only valid with mock workers; worker kind {:?} requires an NDJSON prompt group",
                    worker.kind()
                )));
            }
        }
        for worker in &self.workers {
            if worker.kind != WorkerKind::Mock {
                return Err(DispatcherError::InvalidConfig(format!(
                    "runtime.prompt_group `python` mirrors the legacy Python JSON contract and is only valid with mock workers; worker {} kind {:?} requires an NDJSON prompt group",
                    worker.name, worker.kind
                )));
            }
        }
        Ok(())
    }

    pub fn primary_worker_config(&self) -> Result<WorkerConfig, DispatcherError> {
        if self.worker.is_some() && !self.workers.is_empty() {
            return Err(DispatcherError::InvalidConfig(
                "configure either `worker` or `workers[]`, not both".to_string(),
            ));
        }
        if let Some(worker) = &self.worker {
            return Ok(worker.clone());
        }
        let worker = self
            .workers
            .iter()
            .min_by_key(|worker| (worker.priority, worker.name.as_str()))
            .ok_or_else(|| {
                DispatcherError::InvalidConfig(
                    "configure either `worker` or `workers[]`".to_string(),
                )
            })?;
        Ok(worker.to_worker_config())
    }

    pub fn runtime_config(&self) -> Option<RuntimeConfig> {
        self.runtime_config_with_env(self.worker.as_ref().map(WorkerConfig::env))
    }

    pub fn runtime_config_for_worker(
        &self,
        worker_name: &str,
    ) -> Result<Option<clairvoyant_runtime::RuntimeConfig>, DispatcherError> {
        if let Some(worker) = &self.worker {
            if worker_name == "worker" || worker_name == self.worker_name {
                return Ok(self.runtime_config_with_env(Some(worker.env())));
            }
            return Err(DispatcherError::InvalidConfig(format!(
                "worker `{worker_name}` was requested, but single-worker config only exposes `worker`"
            )));
        }
        let worker = self
            .workers
            .iter()
            .find(|worker| worker.name == worker_name)
            .ok_or_else(|| {
                DispatcherError::InvalidConfig(format!(
                    "worker `{worker_name}` was requested, but no workers[] entry has that name"
                ))
            })?;
        Ok(self.runtime_config_with_env(Some(&worker.env)))
    }

    pub fn completed_action(&self) -> CompletedAction {
        self.container
            .as_ref()
            .map(|container| container.completed_action)
            .unwrap_or_default()
    }

    pub(crate) fn runtime_config_with_env(
        &self,
        worker_env: Option<&BTreeMap<String, String>>,
    ) -> Option<clairvoyant_runtime::RuntimeConfig> {
        let container = self.container.as_ref()?;
        let mut env = self.common_env.clone();
        if let Some(worker_env) = worker_env {
            env.extend(worker_env.clone());
        }
        Some(clairvoyant_runtime::RuntimeConfig {
            image: Some(container.image.trim().to_string()),
            workdir: container.workdir.clone(),
            volumes: container
                .volumes
                .iter()
                .map(|volume| volume.trim().to_string())
                .collect(),
            extra_hosts: container
                .extra_hosts
                .iter()
                .map(|host| host.trim().to_string())
                .collect(),
            network_mode: normalize_container_network_mode(container.network_mode.as_deref()),
            network_disabled: container_network_disabled(container.network_mode.as_deref()),
            env,
        })
    }
}

fn validate_env_map_keys(
    scope: &str,
    env: &BTreeMap<String, String>,
) -> Result<(), DispatcherError> {
    for key in env.keys() {
        if key.trim().is_empty() {
            return Err(DispatcherError::InvalidConfig(format!(
                "{scope} contains an empty environment variable name"
            )));
        }
        if key.contains('=') {
            return Err(DispatcherError::InvalidConfig(format!(
                "{scope}.{key} must not contain `=`"
            )));
        }
    }
    Ok(())
}

fn normalize_container_network_mode(network_mode: Option<&str>) -> Option<String> {
    network_mode.map(str::trim).map(|network_mode| {
        if network_mode == "disabled" {
            "none".to_string()
        } else {
            network_mode.to_string()
        }
    })
}

fn validate_container_network_mode(network_mode: &str) -> Result<(), DispatcherError> {
    let trimmed = network_mode.trim();
    if trimmed.is_empty() {
        return Err(DispatcherError::InvalidConfig(
            "container.network_mode must not be empty".to_string(),
        ));
    }
    if trimmed
        .chars()
        .any(|ch| ch.is_ascii_control() || ch.is_ascii_whitespace())
    {
        return Err(DispatcherError::InvalidConfig(format!(
            "container.network_mode `{trimmed}` must not contain whitespace or control characters"
        )));
    }
    Ok(())
}

fn container_network_disabled(network_mode: Option<&str>) -> bool {
    matches!(network_mode.map(str::trim), Some("none") | Some("disabled"))
}

fn worker_kind_needs_model_network(kind: WorkerKind) -> bool {
    matches!(kind, WorkerKind::ClaudeCode)
}

fn parse_tool_names(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|name| name.trim().to_string())
        .collect()
}

fn validate_tool_names(scope: &str, tools: &[String]) -> Result<(), DispatcherError> {
    if tools.is_empty() {
        return Err(DispatcherError::InvalidConfig(format!(
            "{scope} must not be empty"
        )));
    }
    for tool in tools {
        let normalized = tool.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            return Err(DispatcherError::InvalidConfig(format!(
                "{scope} contains an empty tool name"
            )));
        }
        if !valid_tool_name(&normalized) {
            return Err(DispatcherError::InvalidConfig(format!(
                "{scope} contains unknown tool `{}`; available tools: checksec, strings, objdump, readelf, ropgadget",
                tool.trim()
            )));
        }
    }
    Ok(())
}

fn valid_tool_name(name: &str) -> bool {
    matches!(
        name,
        "checksec" | "strings" | "objdump" | "readelf" | "ropgadget"
    )
}

fn validate_claude_args_do_not_allow_webfetch(
    scope: &str,
    args: &[String],
) -> Result<(), DispatcherError> {
    if claude_args_allow_webfetch(args) {
        return Err(DispatcherError::InvalidConfig(format!(
            "{scope} args must not allow WebFetch; remove WebFetch from --allowedTools/--allowed-tools"
        )));
    }
    Ok(())
}

fn validate_claude_args_noninteractive_text_mode(
    scope: &str,
    args: &[String],
) -> Result<(), DispatcherError> {
    if args.is_empty() {
        return Ok(());
    }
    if !args.iter().any(|arg| arg == "--print") {
        return Err(DispatcherError::InvalidConfig(format!(
            "{scope} custom args must include --print so Claude Code reads stdin and exits"
        )));
    }
    if !arg_option_equals(args, "--input-format", "text") {
        return Err(DispatcherError::InvalidConfig(format!(
            "{scope} custom args must include --input-format text"
        )));
    }
    if !arg_option_equals(args, "--output-format", "text") {
        return Err(DispatcherError::InvalidConfig(format!(
            "{scope} custom args must include --output-format text so stdout remains Clairvoyant NDJSON"
        )));
    }
    Ok(())
}

fn arg_option_equals(args: &[String], option: &str, expected: &str) -> bool {
    args.iter().enumerate().any(|(index, arg)| {
        if let Some(value) = arg.strip_prefix(&format!("{option}=")) {
            return value == expected;
        }
        arg == option && args.get(index + 1).is_some_and(|value| value == expected)
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerSpec {
    pub name: String,
    #[serde(alias = "type")]
    pub kind: WorkerKind,
    #[serde(default)]
    pub task_types: Vec<TaskType>,
    #[serde(default = "default_max_running")]
    pub max_running: usize,
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    pub program: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
}

impl WorkerSpec {
    pub(crate) fn to_worker_config(&self) -> WorkerConfig {
        match self.kind {
            WorkerKind::Mock => WorkerConfig::Mock {
                description: self
                    .env
                    .get("MOCK_DESCRIPTION")
                    .cloned()
                    .unwrap_or_else(|| "mock worker fact".to_string()),
                env: self.env.clone(),
            },
            WorkerKind::Command => WorkerConfig::Command {
                program: self.program.clone().unwrap_or_else(|| self.name.clone()),
                args: self.args.clone(),
                env: self.env.clone(),
            },
            WorkerKind::ClaudeCode => WorkerConfig::ClaudeCode {
                program: self.program.clone(),
                args: self.args.clone(),
                env: self.env.clone(),
            },
            WorkerKind::Tool => WorkerConfig::Tool {
                tools: self
                    .env
                    .get("CAIRN_TOOLS")
                    .map(|s| parse_tool_names(s))
                    .unwrap_or_else(default_tool_list),
                env: self.env.clone(),
            },
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkerKind {
    Mock,
    Command,
    #[serde(alias = "claudecode")]
    ClaudeCode,
    #[serde(alias = "tool")]
    Tool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum TaskType {
    Bootstrap,
    Reason,
    Explore,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulerRuntimeConfig {
    #[serde(default = "default_interval_secs")]
    pub interval: u64,
    #[serde(default = "default_max_workers")]
    pub max_workers: usize,
    #[serde(default = "default_max_running_projects")]
    pub max_running_projects: usize,
    #[serde(default = "default_max_project_workers")]
    pub max_project_workers: usize,
    #[serde(default = "default_healthcheck_timeout")]
    pub healthcheck_timeout: u64,
    #[serde(default = "default_prompt_group")]
    pub prompt_group: String,
}

impl Default for SchedulerRuntimeConfig {
    fn default() -> Self {
        Self {
            interval: default_interval_secs(),
            max_workers: default_max_workers(),
            max_running_projects: default_max_running_projects(),
            max_project_workers: default_max_project_workers(),
            healthcheck_timeout: default_healthcheck_timeout(),
            prompt_group: default_prompt_group(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskConfig {
    #[serde(default)]
    pub bootstrap: PhaseTimeoutConfig,
    #[serde(default)]
    pub reason: ReasonTaskConfig,
    #[serde(default)]
    pub explore: PhaseTimeoutConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseTimeoutConfig {
    #[serde(default = "default_task_timeout")]
    pub timeout: u64,
    #[serde(default = "default_conclude_timeout")]
    pub conclude_timeout: u64,
}

impl Default for PhaseTimeoutConfig {
    fn default() -> Self {
        Self {
            timeout: default_task_timeout(),
            conclude_timeout: default_conclude_timeout(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReasonTaskConfig {
    #[serde(default = "default_task_timeout")]
    pub timeout: u64,
    #[serde(default = "default_reason_max_intents")]
    pub max_intents: usize,
}

impl Default for ReasonTaskConfig {
    fn default() -> Self {
        Self {
            timeout: default_task_timeout(),
            max_intents: default_reason_max_intents(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerConfig {
    pub image: String,
    pub network_mode: Option<String>,
    #[serde(default)]
    pub completed_action: CompletedAction,
    pub workdir: Option<std::path::PathBuf>,
    #[serde(default)]
    pub volumes: Vec<String>,
    #[serde(default)]
    pub extra_hosts: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CompletedAction {
    Remove,
    #[default]
    Stop,
    Keep,
}

fn default_max_running() -> usize {
    1
}

fn default_interval_secs() -> u64 {
    3
}

fn default_max_workers() -> usize {
    1
}

fn default_max_running_projects() -> usize {
    1
}

fn default_max_project_workers() -> usize {
    1
}

fn default_healthcheck_timeout() -> u64 {
    20
}

fn default_prompt_group() -> String {
    "default".to_string()
}

fn default_task_timeout() -> u64 {
    300
}

fn default_conclude_timeout() -> u64 {
    90
}

fn default_reason_max_intents() -> usize {
    2
}
