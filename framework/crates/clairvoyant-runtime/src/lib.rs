use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::pin::Pin;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio_stream::{wrappers::ReceiverStream, Stream};

pub type ProcessLineStream = Pin<Box<dyn Stream<Item = Result<String, RuntimeError>> + Send>>;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    pub image: Option<String>,
    pub workdir: Option<PathBuf>,
    pub volumes: Vec<String>,
    pub extra_hosts: Vec<String>,
    pub network_mode: Option<String>,
    pub network_disabled: bool,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("task failed: {0}")]
    TaskFailed(String),
    #[error("process exited with {status}: {stderr}")]
    ProcessFailed {
        status: std::process::ExitStatus,
        stderr: String,
    },
}

pub trait RuntimeBackend: Send + Sync {
    fn config(&self) -> &RuntimeConfig;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ContainerSpec {
    pub project_id: String,
    pub name: String,
    pub image: String,
    pub workdir: Option<PathBuf>,
    #[serde(default)]
    pub volumes: Vec<String>,
    #[serde(default)]
    pub extra_hosts: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    pub network_mode: Option<String>,
    pub network_disabled: bool,
}

impl ContainerSpec {
    pub fn try_from_config(
        project_id: impl Into<String>,
        config: &RuntimeConfig,
    ) -> Result<Self, RuntimeError> {
        let project_id = project_id.into();
        if !valid_runtime_project_id(&project_id) {
            return Err(RuntimeError::TaskFailed(format!(
                "invalid project_id `{project_id}`; expected a non-empty ASCII id starting with a letter or digit and containing only letters, digits, '.', '_' or '-'"
            )));
        }
        let image = config
            .image
            .clone()
            .ok_or_else(|| RuntimeError::TaskFailed("container image is missing".to_string()))?;
        if image.trim().is_empty() {
            return Err(RuntimeError::TaskFailed(
                "container image is empty".to_string(),
            ));
        }
        if config.network_disabled {
            if let Some(network_mode) = &config.network_mode {
                if network_mode.trim() != "none" {
                    return Err(RuntimeError::TaskFailed(format!(
                        "network_disabled cannot be combined with network_mode `{network_mode}`; use network_mode `none` or remove network_mode"
                    )));
                }
            }
        }
        let network_mode = config.network_mode.as_deref().map(str::trim);
        if matches!(network_mode, Some("")) {
            return Err(RuntimeError::TaskFailed(
                "network_mode must not be empty".to_string(),
            ));
        }
        Ok(Self {
            name: format!("clairvoyant-{project_id}"),
            project_id,
            image,
            workdir: config.workdir.clone(),
            volumes: config.volumes.clone(),
            extra_hosts: config.extra_hosts.clone(),
            env: config.env.clone(),
            network_mode: network_mode.map(ToOwned::to_owned),
            network_disabled: config.network_disabled,
        })
    }

    pub fn from_config(project_id: impl Into<String>, config: &RuntimeConfig) -> Option<Self> {
        Self::try_from_config(project_id, config).ok()
    }

    pub fn rendered(&self) -> Self {
        let project_id = self.project_id.as_str();
        Self {
            project_id: self.project_id.clone(),
            name: substitute_project_id(&self.name, project_id),
            image: substitute_project_id(&self.image, project_id),
            workdir: self.workdir.as_ref().map(|path| {
                PathBuf::from(substitute_project_id(&path.to_string_lossy(), project_id))
            }),
            volumes: self
                .volumes
                .iter()
                .map(|value| substitute_project_id(value, project_id))
                .collect(),
            extra_hosts: self
                .extra_hosts
                .iter()
                .map(|value| substitute_project_id(value, project_id))
                .collect(),
            env: self
                .env
                .iter()
                .map(|(key, value)| (key.clone(), substitute_project_id(value, project_id)))
                .collect(),
            network_mode: self.network_mode.clone(),
            network_disabled: self.network_disabled,
        }
    }
}

pub fn valid_runtime_project_id(project_id: &str) -> bool {
    let mut chars = project_id.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_alphanumeric()
        && chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
}

/// Result of `docker inspect` for container state detection.
#[derive(Debug, Clone)]
struct ContainerInspectInfo {
    running: bool,
}

#[derive(Debug, Clone)]
pub struct DockerCliRuntime {
    docker: String,
    docker_args: Vec<String>,
    config: RuntimeConfig,
}

impl DockerCliRuntime {
    pub fn new(config: RuntimeConfig) -> Self {
        Self {
            docker: "docker".to_string(),
            docker_args: Vec::new(),
            config,
        }
    }

    pub fn with_binary(mut self, docker: impl Into<String>) -> Self {
        self.docker = docker.into();
        self
    }

    pub fn with_binary_args(mut self, args: Vec<String>) -> Self {
        self.docker_args = args;
        self
    }

    pub fn create_args(&self, spec: &ContainerSpec) -> Vec<String> {
        let spec = spec.rendered();
        let mut args = vec![
            "create".to_string(),
            "--name".to_string(),
            spec.name,
            "--label".to_string(),
            format!("clairvoyant.project_id={}", spec.project_id),
        ];
        let network_mode = spec.network_mode.as_deref().or(if spec.network_disabled {
            Some("none")
        } else {
            None
        });
        if let Some(network_mode) = network_mode {
            args.extend(["--network".to_string(), network_mode.to_string()]);
        }
        if let Some(workdir) = spec.workdir {
            args.extend([
                "--workdir".to_string(),
                workdir.to_string_lossy().to_string(),
            ]);
        }
        for volume in spec.volumes {
            args.extend(["--volume".to_string(), volume]);
        }
        for host in spec.extra_hosts {
            args.extend(["--add-host".to_string(), host]);
        }
        for (key, value) in spec.env {
            args.extend(["--env".to_string(), format!("{key}={value}")]);
        }
        args.push(spec.image);
        args.extend(["sleep".to_string(), "infinity".to_string()]);
        args
    }

    pub fn start_args(&self, name: &str) -> Vec<String> {
        vec!["start".to_string(), name.to_string()]
    }

    pub fn stop_args(&self, name: &str) -> Vec<String> {
        vec!["stop".to_string(), name.to_string()]
    }

    pub fn remove_args(&self, name: &str) -> Vec<String> {
        vec!["rm".to_string(), "-f".to_string(), name.to_string()]
    }

    pub fn exec_args(&self, name: &str, spec: &ProcessSpec) -> Vec<String> {
        let mut args = vec!["exec".to_string(), "-i".to_string()];
        if let Some(cwd) = &spec.cwd {
            args.extend(["--workdir".to_string(), cwd.to_string_lossy().to_string()]);
        }
        for (key, value) in &spec.env {
            args.extend(["--env".to_string(), format!("{key}={value}")]);
        }
        args.push(name.to_string());
        args.push(spec.program.clone());
        args.extend(spec.args.clone());
        args
    }

    pub async fn run_docker_capture(
        &self,
        args: Vec<String>,
        stdin: Option<String>,
    ) -> Result<ProcessOutput, RuntimeError> {
        let mut full_args = self.docker_args.clone();
        full_args.extend(args);
        LocalRuntime::new(RuntimeConfig::default())
            .run_capture(ProcessSpec {
                program: self.docker.clone(),
                args: full_args,
                env: BTreeMap::new(),
                stdin,
                cwd: None,
            })
            .await
    }

    pub async fn run_docker_stream(
        &self,
        args: Vec<String>,
        stdin: Option<String>,
    ) -> Result<ProcessLineStream, RuntimeError> {
        let mut full_args = self.docker_args.clone();
        full_args.extend(args);
        LocalRuntime::new(RuntimeConfig::default())
            .run_stream(ProcessSpec {
                program: self.docker.clone(),
                args: full_args,
                env: BTreeMap::new(),
                stdin,
                cwd: None,
            })
            .await
    }

    pub async fn create(&self, spec: &ContainerSpec) -> Result<String, RuntimeError> {
        let output = self
            .run_docker_capture(self.create_args(spec), None)
            .await?;
        Ok(output.stdout.trim().to_string())
    }

    pub async fn start(&self, name: &str) -> Result<(), RuntimeError> {
        self.run_docker_capture(self.start_args(name), None).await?;
        Ok(())
    }

    pub async fn stop(&self, name: &str) -> Result<(), RuntimeError> {
        self.run_docker_capture(self.stop_args(name), None).await?;
        Ok(())
    }

    pub async fn remove(&self, name: &str) -> Result<(), RuntimeError> {
        self.run_docker_capture(self.remove_args(name), None)
            .await?;
        Ok(())
    }

    pub async fn exec(
        &self,
        container_name: &str,
        spec: ProcessSpec,
    ) -> Result<ProcessOutput, RuntimeError> {
        let stdin = spec.stdin.clone();
        self.run_docker_capture(self.exec_args(container_name, &spec), stdin)
            .await
    }

    pub async fn exec_stream(
        &self,
        container_name: &str,
        spec: ProcessSpec,
    ) -> Result<ProcessLineStream, RuntimeError> {
        let stdin = spec.stdin.clone();
        self.run_docker_stream(self.exec_args(container_name, &spec), stdin)
            .await
    }

    pub async fn ensure_started(&self, spec: &ContainerSpec) -> Result<String, RuntimeError> {
        let rendered = spec.rendered();
        let name = rendered.name.clone();

        // Use docker inspect to determine container state deterministically,
        // avoiding fragile stderr string matching on docker create errors.
        match self.inspect(&name).await {
            Ok(info) => {
                if info.running {
                    return Ok(name);
                }
                self.start(&name).await?;
                Ok(name)
            }
            Err(error) if docker_inspect_missing_container(&error) => {
                // Container doesn't exist — create and start it.
                let id = self.create(&rendered).await?;
                if let Err(err) = self.start(&name).await {
                    let _ = self.remove(&name).await;
                    return Err(err);
                }
                Ok(id)
            }
            Err(error) => Err(error),
        }
    }

    /// Inspect a container by name. Returns container info if it exists.
    async fn inspect(&self, name: &str) -> Result<ContainerInspectInfo, RuntimeError> {
        let output = self
            .run_docker_capture(
                vec![
                    "inspect".to_string(),
                    "--format".to_string(),
                    "{{.State.Status}}".to_string(),
                    name.to_string(),
                ],
                None,
            )
            .await?;
        let status = output.stdout.trim().to_lowercase();
        Ok(ContainerInspectInfo {
            running: status == "running",
        })
    }
}

fn docker_inspect_missing_container(error: &RuntimeError) -> bool {
    let RuntimeError::ProcessFailed { stderr, .. } = error else {
        return false;
    };
    let stderr = stderr.to_ascii_lowercase();
    stderr.contains("no such object") || stderr.contains("no such container")
}

impl RuntimeBackend for DockerCliRuntime {
    fn config(&self) -> &RuntimeConfig {
        &self.config
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProcessSpec {
    pub program: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    pub stdin: Option<String>,
    pub cwd: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessOutput {
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone)]
pub struct LocalRuntime {
    config: RuntimeConfig,
}

impl LocalRuntime {
    pub fn new(config: RuntimeConfig) -> Self {
        Self { config }
    }

    pub async fn run_capture(&self, spec: ProcessSpec) -> Result<ProcessOutput, RuntimeError> {
        let mut command = Command::new(&spec.program);
        command.args(&spec.args);
        command.envs(&spec.env);
        if let Some(cwd) = &spec.cwd {
            command.current_dir(cwd);
        }
        command
            .kill_on_drop(true)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        if spec.stdin.is_some() {
            command.stdin(std::process::Stdio::piped());
        } else {
            command.stdin(std::process::Stdio::null());
        }
        let mut child = command.spawn()?;
        if let Some(stdin_text) = spec.stdin {
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(stdin_text.as_bytes()).await?;
                stdin.shutdown().await?;
            }
        }
        let output = child.wait_with_output().await?;
        // Note: from_utf8_lossy may silently replace non-UTF-8 bytes with U+FFFD.
        // Binary analysis tools (checksec, objdump, ROPgadget) may produce
        // output containing raw binary data. Callers that need byte-exact
        // output should use a binary-safe interface instead.
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        if !output.status.success() {
            return Err(RuntimeError::ProcessFailed {
                status: output.status,
                stderr,
            });
        }
        Ok(ProcessOutput { stdout, stderr })
    }

    pub async fn run_stream(&self, spec: ProcessSpec) -> Result<ProcessLineStream, RuntimeError> {
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        tokio::spawn(async move {
            if let Err(error) = run_process_line_stream(spec, tx.clone()).await {
                let _ = tx.send(Err(error)).await;
            }
        });
        Ok(Box::pin(ReceiverStream::new(rx)))
    }
}

async fn run_process_line_stream(
    spec: ProcessSpec,
    tx: tokio::sync::mpsc::Sender<Result<String, RuntimeError>>,
) -> Result<(), RuntimeError> {
    let mut command = Command::new(&spec.program);
    command.args(&spec.args);
    command.envs(&spec.env);
    if let Some(cwd) = &spec.cwd {
        command.current_dir(cwd);
    }
    command
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    if spec.stdin.is_some() {
        command.stdin(std::process::Stdio::piped());
    } else {
        command.stdin(std::process::Stdio::null());
    }
    let mut child = command.spawn()?;
    let mut stdin_task = match spec.stdin {
        Some(stdin_text) => child.stdin.take().map(|mut stdin| {
            tokio::spawn(async move {
                stdin.write_all(stdin_text.as_bytes()).await?;
                stdin.shutdown().await?;
                Ok::<_, std::io::Error>(())
            })
        }),
        None => None,
    };
    let stdout = child.stdout.take().ok_or_else(|| {
        RuntimeError::TaskFailed(format!("{} stdout pipe was not captured", spec.program))
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        RuntimeError::TaskFailed(format!("{} stderr pipe was not captured", spec.program))
    })?;
    let stderr_task = tokio::spawn(async move {
        let mut stderr_text = String::new();
        let mut stderr = BufReader::new(stderr);
        stderr.read_to_string(&mut stderr_text).await?;
        Ok::<_, std::io::Error>(stderr_text)
    });

    let mut stdout = BufReader::new(stdout).lines();
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
        if tx.send(Ok(line)).await.is_err() {
            let _ = child.kill().await;
            return Ok(());
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
                return Err(RuntimeError::TaskFailed(format!(
                    "stdin task failed: {error}"
                )))
            }
        }
    }
    let stderr = stderr_task
        .await
        .map_err(|error| RuntimeError::TaskFailed(format!("stderr task failed: {error}")))??;
    if !status.success() {
        return Err(RuntimeError::ProcessFailed { status, stderr });
    }
    Ok(())
}

impl RuntimeBackend for LocalRuntime {
    fn config(&self) -> &RuntimeConfig {
        &self.config
    }
}

pub fn substitute_project_id(value: &str, project_id: &str) -> String {
    value.replace("{project_id}", project_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_stream::StreamExt;

    fn unique_test_path(name: &str) -> PathBuf {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        std::env::temp_dir().join(format!("clairvoyant_runtime_{name}_{suffix}"))
    }

    fn write_executable_script(path: &std::path::Path, script: &str) {
        std::fs::write(path, script).expect("write script");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = std::fs::metadata(path)
                .expect("script metadata")
                .permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(path, permissions).expect("chmod script");
        }
    }

    #[tokio::test]
    async fn local_runtime_captures_process_output() {
        let runtime = LocalRuntime::new(RuntimeConfig::default());
        let output = runtime
            .run_capture(ProcessSpec {
                program: "sh".to_string(),
                args: vec!["-c".to_string(), "cat".to_string()],
                env: BTreeMap::new(),
                stdin: Some("hello".to_string()),
                cwd: None,
            })
            .await
            .expect("run");
        assert_eq!(output.stdout, "hello");
    }

    #[tokio::test]
    async fn local_runtime_passes_process_environment() {
        let runtime = LocalRuntime::new(RuntimeConfig::default());
        let mut env = BTreeMap::new();
        env.insert("CAIRN_RUNTIME_ENV_TEST".to_string(), "from-env".to_string());
        let output = runtime
            .run_capture(ProcessSpec {
                program: "sh".to_string(),
                args: vec![
                    "-c".to_string(),
                    "printf '%s' \"$CAIRN_RUNTIME_ENV_TEST\"".to_string(),
                ],
                env,
                stdin: None,
                cwd: None,
            })
            .await
            .expect("run");
        assert_eq!(output.stdout, "from-env");
    }

    #[tokio::test]
    async fn local_runtime_streams_lines_before_process_exit() {
        let runtime = LocalRuntime::new(RuntimeConfig::default());
        let mut stream = runtime
            .run_stream(ProcessSpec {
                program: "sh".to_string(),
                args: vec![
                    "-c".to_string(),
                    "cat >/dev/null; printf '%s\n' first; sleep 1; printf '%s\n' second"
                        .to_string(),
                ],
                env: BTreeMap::new(),
                stdin: Some("prompt".to_string()),
                cwd: None,
            })
            .await
            .expect("stream");
        let started = std::time::Instant::now();
        let first = stream
            .next()
            .await
            .expect("first line")
            .expect("first line ok");
        assert!(started.elapsed() < std::time::Duration::from_millis(500));
        assert_eq!(first, "first");
        let second = stream
            .next()
            .await
            .expect("second line")
            .expect("second line ok");
        assert_eq!(second, "second");
    }

    #[tokio::test]
    async fn local_runtime_stream_reports_failure_after_stdout() {
        let runtime = LocalRuntime::new(RuntimeConfig::default());
        let mut stream = runtime
            .run_stream(ProcessSpec {
                program: "sh".to_string(),
                args: vec![
                    "-c".to_string(),
                    "printf '%s\n' before-failure; printf '%s' boom >&2; exit 7".to_string(),
                ],
                env: BTreeMap::new(),
                stdin: None,
                cwd: None,
            })
            .await
            .expect("stream");
        let first = stream
            .next()
            .await
            .expect("first line")
            .expect("first line ok");
        assert_eq!(first, "before-failure");
        let error = stream
            .next()
            .await
            .expect("failure after stdout")
            .expect_err("nonzero process exit should be reported");
        assert!(error.to_string().contains("boom"));
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn local_runtime_streams_stdout_while_stdin_is_unread() {
        let runtime = LocalRuntime::new(RuntimeConfig::default());
        let mut stream = runtime
            .run_stream(ProcessSpec {
                program: "sh".to_string(),
                args: vec!["-c".to_string(), "printf '%s\n' first; sleep 1".to_string()],
                env: BTreeMap::new(),
                stdin: Some("x".repeat(1024 * 1024)),
                cwd: None,
            })
            .await
            .expect("stream");
        let started = std::time::Instant::now();
        let first = stream
            .next()
            .await
            .expect("first line")
            .expect("first line ok");
        assert!(started.elapsed() < std::time::Duration::from_millis(500));
        assert_eq!(first, "first");
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn local_runtime_closes_stdin_when_no_input_is_configured() {
        let runtime = LocalRuntime::new(RuntimeConfig::default());
        let output = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            runtime.run_capture(ProcessSpec {
                program: "cat".to_string(),
                args: Vec::new(),
                env: BTreeMap::new(),
                stdin: None,
                cwd: None,
            }),
        )
        .await
        .expect("cat should observe stdin eof")
        .expect("run");
        assert_eq!(output.stdout, "");
    }

    #[test]
    fn runtime_config_rejects_unknown_fields() {
        let error = serde_json::from_str::<RuntimeConfig>(
            r#"{"image":"agent","workdir":null,"volumes":[],"extra_hosts":[],"network_disabled":true,"unexpected":1}"#,
        )
        .expect_err("unknown runtime config field should fail");
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn container_spec_rejects_empty_image() {
        let config = RuntimeConfig {
            image: Some(" ".to_string()),
            ..RuntimeConfig::default()
        };
        assert!(ContainerSpec::from_config("proj_001", &config).is_none());
        let error = ContainerSpec::try_from_config("proj_001", &config)
            .expect_err("empty image should fail");
        assert!(error.to_string().contains("container image is empty"));
    }

    #[test]
    fn runtime_project_id_validation_accepts_safe_docker_ids() {
        for project_id in ["proj_001", "proj-001", "proj.001", "p1"] {
            assert!(
                valid_runtime_project_id(project_id),
                "{project_id} should be accepted"
            );
        }
    }

    #[test]
    fn runtime_project_id_validation_rejects_unsafe_docker_ids() {
        for project_id in ["", "../evil", "proj 001", "proj:001", "-bad", "_bad"] {
            assert!(
                !valid_runtime_project_id(project_id),
                "{project_id} should be rejected"
            );
        }
        let config = RuntimeConfig {
            image: Some("agent".to_string()),
            ..RuntimeConfig::default()
        };
        assert!(ContainerSpec::from_config("../evil", &config).is_none());
        let error = ContainerSpec::try_from_config("../evil", &config)
            .expect_err("unsafe project id should fail");
        assert!(error.to_string().contains("invalid project_id"));
    }

    #[test]
    fn container_spec_rejects_unknown_fields() {
        let error = serde_json::from_str::<ContainerSpec>(
            r#"{"project_id":"proj_001","name":"clairvoyant-proj_001","image":"agent","workdir":null,"volumes":[],"extra_hosts":[],"env":{},"network_disabled":true,"unexpected":1}"#,
        )
        .expect_err("unknown container spec field should fail");
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn process_spec_rejects_unknown_fields() {
        let error = serde_json::from_str::<ProcessSpec>(
            r#"{"program":"worker","args":[],"env":{},"stdin":null,"cwd":null,"unexpected":1}"#,
        )
        .expect_err("unknown process spec field should fail");
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn docker_create_args_apply_project_placeholders_and_network_policy() {
        let mut env = BTreeMap::new();
        env.insert("RUN_DIR".to_string(), "/runs/{project_id}".to_string());
        let config = RuntimeConfig {
            image: Some("clairvoyant-agent:{project_id}".to_string()),
            workdir: Some(PathBuf::from("/work/{project_id}")),
            volumes: vec!["/host/runs/{project_id}:/runs/{project_id}".to_string()],
            extra_hosts: vec!["example.com:0.0.0.0".to_string()],
            network_mode: Some("none".to_string()),
            network_disabled: true,
            env,
        };
        let runtime = DockerCliRuntime::new(config.clone());
        let spec = ContainerSpec::from_config("proj_123", &config).expect("spec");
        let args = runtime.create_args(&spec);
        assert!(args.contains(&"clairvoyant-proj_123".to_string()));
        assert!(args.contains(&"clairvoyant-agent:proj_123".to_string()));
        assert!(args.contains(&"/host/runs/proj_123:/runs/proj_123".to_string()));
        assert!(args.contains(&"example.com:0.0.0.0".to_string()));
        assert!(args.contains(&"--network".to_string()));
        assert!(args.contains(&"none".to_string()));
        assert!(args.contains(&"RUN_DIR=/runs/proj_123".to_string()));
    }

    #[test]
    fn docker_create_args_preserve_explicit_network_mode() {
        let config = RuntimeConfig {
            image: Some("agent".to_string()),
            network_mode: Some("host".to_string()),
            ..RuntimeConfig::default()
        };
        let runtime = DockerCliRuntime::new(config.clone());
        let spec = ContainerSpec::from_config("proj_001", &config).expect("spec");
        let args = runtime.create_args(&spec);
        let network_index = args
            .iter()
            .position(|arg| arg == "--network")
            .expect("network flag");
        assert_eq!(
            args.get(network_index + 1).map(String::as_str),
            Some("host")
        );
    }

    #[test]
    fn container_spec_rejects_network_disabled_with_non_none_network_mode() {
        let config = RuntimeConfig {
            image: Some("agent".to_string()),
            network_mode: Some("host".to_string()),
            network_disabled: true,
            ..RuntimeConfig::default()
        };
        let error = ContainerSpec::try_from_config("proj_001", &config)
            .expect_err("host networking should not override network_disabled");
        assert!(error
            .to_string()
            .contains("network_disabled cannot be combined with network_mode `host`"));

        let config = RuntimeConfig {
            network_mode: Some("none".to_string()),
            ..config
        };
        ContainerSpec::try_from_config("proj_001", &config)
            .expect("network_mode none is compatible with network_disabled");
    }

    #[test]
    fn container_spec_normalizes_and_rejects_empty_network_mode() {
        let config = RuntimeConfig {
            image: Some("agent".to_string()),
            network_mode: Some(" none ".to_string()),
            network_disabled: true,
            ..RuntimeConfig::default()
        };
        let spec = ContainerSpec::try_from_config("proj_001", &config)
            .expect("trimmed none should be accepted");
        assert_eq!(spec.network_mode.as_deref(), Some("none"));

        let config = RuntimeConfig {
            image: Some("agent".to_string()),
            network_mode: Some(" ".to_string()),
            ..RuntimeConfig::default()
        };
        let error = ContainerSpec::try_from_config("proj_001", &config)
            .expect_err("empty network mode should fail");
        assert!(error.to_string().contains("network_mode must not be empty"));
    }

    #[test]
    fn docker_exec_args_preserve_process_command() {
        let runtime = DockerCliRuntime::new(RuntimeConfig::default());
        let args = runtime.exec_args(
            "clairvoyant-proj_001",
            &ProcessSpec {
                program: "sh".to_string(),
                args: vec!["-lc".to_string(), "echo ok".to_string()],
                env: BTreeMap::new(),
                stdin: None,
                cwd: Some(PathBuf::from("/work")),
            },
        );
        assert_eq!(
            args,
            vec![
                "exec",
                "-i",
                "--workdir",
                "/work",
                "clairvoyant-proj_001",
                "sh",
                "-lc",
                "echo ok"
            ]
        );
    }

    #[test]
    fn docker_exec_args_include_process_environment_before_container_name() {
        let runtime = DockerCliRuntime::new(RuntimeConfig::default());
        let mut env = BTreeMap::new();
        env.insert("CAIRN_PROJECT_ID".to_string(), "proj_001".to_string());
        env.insert("CAIRN_INTENT_ID".to_string(), "i001".to_string());
        let args = runtime.exec_args(
            "clairvoyant-proj_001",
            &ProcessSpec {
                program: "worker".to_string(),
                args: Vec::new(),
                env,
                stdin: None,
                cwd: None,
            },
        );
        assert_eq!(
            args,
            vec![
                "exec",
                "-i",
                "--env",
                "CAIRN_INTENT_ID=i001",
                "--env",
                "CAIRN_PROJECT_ID=proj_001",
                "clairvoyant-proj_001",
                "worker"
            ]
        );
    }

    #[tokio::test]
    async fn docker_cli_runtime_executes_through_configured_binary() {
        let runtime = DockerCliRuntime::new(RuntimeConfig::default()).with_binary("sh");
        let output = runtime
            .run_docker_capture(
                vec![
                    "-c".to_string(),
                    "printf args:$1; cat".to_string(),
                    "sh".to_string(),
                    "x".to_string(),
                ],
                Some(":stdin".to_string()),
            )
            .await
            .expect("run fake docker");
        assert_eq!(output.stdout, "args:x:stdin");
    }

    #[tokio::test]
    async fn ensure_started_only_creates_after_missing_container_inspect() {
        let script = unique_test_path("fake_docker_missing");
        write_executable_script(
            &script,
            r#"#!/bin/sh
set -eu
case "$1" in
  inspect) echo "Error: No such object: $4" >&2; exit 1 ;;
  create) echo "created-container-id" ;;
  start) exit 0 ;;
  *) echo "unexpected docker command: $*" >&2; exit 99 ;;
esac
"#,
        );

        let config = RuntimeConfig {
            image: Some("agent".to_string()),
            ..RuntimeConfig::default()
        };
        let spec = ContainerSpec::try_from_config("proj_001", &config).expect("spec");
        let runtime = DockerCliRuntime::new(config).with_binary(script.to_string_lossy());

        let id = runtime.ensure_started(&spec).await.expect("ensure started");
        assert_eq!(id, "created-container-id");

        let _ = std::fs::remove_file(script);
    }

    #[tokio::test]
    async fn ensure_started_propagates_inspect_failures_other_than_missing_container() {
        let script = unique_test_path("fake_docker_inspect_failure");
        write_executable_script(
            &script,
            r#"#!/bin/sh
set -eu
case "$1" in
  inspect) echo "Cannot connect to the Docker daemon" >&2; exit 1 ;;
  create) echo "create must not be called after inspect infrastructure failure" >&2; exit 42 ;;
  *) echo "unexpected docker command: $*" >&2; exit 99 ;;
esac
"#,
        );

        let config = RuntimeConfig {
            image: Some("agent".to_string()),
            ..RuntimeConfig::default()
        };
        let spec = ContainerSpec::try_from_config("proj_001", &config).expect("spec");
        let runtime = DockerCliRuntime::new(config).with_binary(script.to_string_lossy());

        let error = runtime
            .ensure_started(&spec)
            .await
            .expect_err("inspect infrastructure failure should be returned");
        assert!(error
            .to_string()
            .contains("Cannot connect to the Docker daemon"));

        let _ = std::fs::remove_file(script);
    }
}
