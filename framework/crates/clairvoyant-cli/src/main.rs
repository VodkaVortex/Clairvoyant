use anyhow::Context;
use clairvoyant_core::{
    ClairvoyantEnvelope, ClairvoyantRequest, CompleteRequest, ConcludeRequest, CreateHintInline,
    CreateHintRequest, CreateIntentRequest, CreateProjectRequest, ExportFormat, HeartbeatRequest,
    ProjectDetail, ProjectStatus, ReasonClaimRequest, ReopenRequest, Settings,
    UpdateProjectStatusRequest, UpdateProjectTitleRequest,
};
use clairvoyant_dispatcher::{
    startup_healthcheck, workers_from_config, DispatchOutcome, Dispatcher, DispatcherConfig,
};
use clairvoyant_protocol::{read_value, write_value};
use clairvoyant_runtime::{ContainerSpec, DockerCliRuntime, ProcessSpec};
use clairvoyant_server::{static_asset, static_assets, ClairvoyantService};
use clap::{Parser, Subcommand};
use std::io::{Read, Write};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "clairvoyant")]
#[command(about = "Clairvoyant - fact-graph based collaborative exploration protocol")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Serve {
        #[arg(long)]
        db_path: Option<PathBuf>,
    },
    Dispatch {
        #[arg(long, default_value = "dispatch_default.yaml")]
        config: PathBuf,
        #[arg(long)]
        db_path: Option<PathBuf>,
        #[arg(long)]
        once: bool,
        #[arg(long, conflicts_with = "once")]
        refill_once: bool,
        #[arg(long)]
        startup_healthcheck_only: bool,
    },
    Migrate {
        #[arg(long)]
        from_python: PathBuf,
        #[arg(long)]
        to: PathBuf,
    },
    Request {
        #[arg(long)]
        db_path: Option<PathBuf>,
        #[arg(long, help = "ClairvoyantRequest JSON; use '-' to read from stdin")]
        json: String,
    },
    Observe {
        #[arg(long)]
        db_path: Option<PathBuf>,
        #[arg(long)]
        project_id: Option<String>,
    },
    Report {
        #[arg(long)]
        db_path: Option<PathBuf>,
        project_id: String,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    Settings {
        #[arg(long)]
        db_path: Option<PathBuf>,
        #[command(subcommand)]
        command: SettingsCommand,
    },
    Project {
        #[arg(long)]
        db_path: Option<PathBuf>,
        #[command(subcommand)]
        command: ProjectCommand,
    },
    Intent {
        #[arg(long)]
        db_path: Option<PathBuf>,
        #[arg(long)]
        project_id: String,
        #[command(subcommand)]
        command: IntentCommand,
    },
    Hint {
        #[arg(long)]
        db_path: Option<PathBuf>,
        #[arg(long)]
        project_id: String,
        #[command(subcommand)]
        command: HintCommand,
    },
    Reason {
        #[arg(long)]
        db_path: Option<PathBuf>,
        #[arg(long)]
        project_id: String,
        #[command(subcommand)]
        command: ReasonCommand,
    },
    Asset {
        #[arg(long)]
        path: Option<String>,
        #[arg(long)]
        list: bool,
    },
    Runtime {
        #[command(subcommand)]
        command: RuntimeCommand,
    },
}

#[derive(Debug, Subcommand)]
enum SettingsCommand {
    Get,
    Set {
        #[arg(long)]
        intent_timeout: i64,
        #[arg(long)]
        reason_timeout: i64,
    },
}

#[derive(Debug, Subcommand)]
enum ProjectCommand {
    List,
    Create {
        #[arg(long)]
        title: String,
        #[arg(long)]
        origin: String,
        #[arg(long)]
        goal: String,
        #[arg(long = "hint")]
        hints: Vec<String>,
        #[arg(long, default_value = "user")]
        hint_creator: String,
    },
    Show {
        project_id: String,
    },
    Title {
        project_id: String,
        #[arg(long)]
        title: String,
    },
    Status {
        project_id: String,
        #[arg(long)]
        status: String,
    },
    Stop {
        project_id: String,
    },
    Resume {
        project_id: String,
    },
    Delete {
        project_id: String,
    },
    Complete {
        project_id: String,
        #[arg(long, value_delimiter = ',')]
        sources: Vec<String>,
        #[arg(long)]
        description: String,
        #[arg(long)]
        worker: String,
    },
    Reopen {
        project_id: String,
        #[arg(long)]
        description: String,
        #[arg(long)]
        creator: String,
    },
    Export {
        project_id: String,
        #[arg(long, default_value = "yaml")]
        format: String,
    },
}

#[derive(Debug, Subcommand)]
enum IntentCommand {
    Create {
        #[arg(long, value_delimiter = ',')]
        sources: Vec<String>,
        #[arg(long)]
        description: String,
        #[arg(long)]
        creator: String,
        #[arg(long)]
        worker: Option<String>,
    },
    Heartbeat {
        intent_id: String,
        #[arg(long)]
        worker: String,
    },
    Release {
        intent_id: String,
        #[arg(long)]
        worker: String,
    },
    Conclude {
        intent_id: String,
        #[arg(long)]
        worker: String,
        #[arg(long)]
        description: String,
    },
}

#[derive(Debug, Subcommand)]
enum HintCommand {
    Create {
        #[arg(long)]
        content: String,
        #[arg(long)]
        creator: String,
    },
}

#[derive(Debug, Subcommand)]
enum ReasonCommand {
    Claim {
        #[arg(long)]
        worker: String,
        #[arg(long)]
        trigger: String,
    },
    Heartbeat {
        #[arg(long)]
        worker: String,
    },
    Release {
        #[arg(long)]
        worker: String,
    },
}

#[derive(Debug, Subcommand)]
enum RuntimeCommand {
    Args {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        project_id: String,
        #[arg(long)]
        worker: Option<String>,
    },
    EnsureStarted {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        project_id: String,
        #[arg(long)]
        worker: Option<String>,
    },
    Exec {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        project_id: String,
        #[arg(long)]
        worker: Option<String>,
        #[arg(long)]
        program: String,
        #[arg(last = true)]
        args: Vec<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "clairvoyant=info".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    match Cli::parse().command {
        Command::Serve { db_path } => {
            serve_stdio(db_path.unwrap_or_else(ClairvoyantService::default_db_path)).await
        }
        Command::Dispatch {
            config,
            db_path,
            once,
            refill_once,
            startup_healthcheck_only,
        } => dispatch(config, db_path, once, refill_once, startup_healthcheck_only).await,
        Command::Migrate { from_python, to } => {
            let report = ClairvoyantService::migrate_from_python_db(&from_python, &to)
                .await
                .with_context(|| {
                    format!("migrating {} to {}", from_python.display(), to.display())
                })?;
            println!(
                "migrated projects={} facts={} intents={} intent_sources={} hints={}",
                report.projects, report.facts, report.intents, report.intent_sources, report.hints
            );
            Ok(())
        }
        Command::Request { db_path, json } => {
            let request = parse_request_json(&json)?;
            run_json_request(db_path, request).await
        }
        Command::Observe {
            db_path,
            project_id,
        } => run_json_request(db_path, ClairvoyantRequest::Observe { project_id }).await,
        Command::Report {
            db_path,
            project_id,
            output,
        } => report(db_path, project_id, output).await,
        Command::Settings { db_path, command } => {
            run_json_request(db_path, settings_request(command)?).await
        }
        Command::Project { db_path, command } => {
            let request = project_request(command)?;
            if let ClairvoyantRequest::ExportProject { .. } = request {
                run_text_request(db_path, request).await
            } else {
                run_json_request(db_path, request).await
            }
        }
        Command::Intent {
            db_path,
            project_id,
            command,
        } => run_json_request(db_path, intent_request(project_id, command)).await,
        Command::Hint {
            db_path,
            project_id,
            command,
        } => run_json_request(db_path, hint_request(project_id, command)).await,
        Command::Reason {
            db_path,
            project_id,
            command,
        } => run_json_request(db_path, reason_request(project_id, command)).await,
        Command::Asset { path, list } => {
            if list {
                for asset in static_assets() {
                    println!(
                        "{}\t{}\t{}",
                        asset.path,
                        asset.content_type,
                        asset.bytes.len()
                    );
                }
                return Ok(());
            }
            let path = path.context("--path is required unless --list is set")?;
            let asset =
                static_asset(&path).with_context(|| format!("embedded asset not found: {path}"))?;
            std::io::stdout().lock().write_all(asset.bytes)?;
            Ok(())
        }
        Command::Runtime { command } => runtime_command(command).await,
    }
}

fn settings_request(command: SettingsCommand) -> anyhow::Result<ClairvoyantRequest> {
    Ok(match command {
        SettingsCommand::Get => ClairvoyantRequest::GetSettings,
        SettingsCommand::Set {
            intent_timeout,
            reason_timeout,
        } => ClairvoyantRequest::PutSettings {
            settings: Settings {
                intent_timeout,
                reason_timeout,
            },
        },
    })
}

fn project_request(command: ProjectCommand) -> anyhow::Result<ClairvoyantRequest> {
    Ok(match command {
        ProjectCommand::List => ClairvoyantRequest::ListProjects,
        ProjectCommand::Create {
            title,
            origin,
            goal,
            hints,
            hint_creator,
        } => ClairvoyantRequest::CreateProject {
            body: CreateProjectRequest {
                title,
                origin,
                goal,
                hints: if hints.is_empty() {
                    None
                } else {
                    Some(
                        hints
                            .into_iter()
                            .map(|content| CreateHintInline {
                                content,
                                creator: hint_creator.clone(),
                            })
                            .collect(),
                    )
                },
            },
        },
        ProjectCommand::Show { project_id } => ClairvoyantRequest::GetProject { project_id },
        ProjectCommand::Title { project_id, title } => ClairvoyantRequest::UpdateProjectTitle {
            project_id,
            body: UpdateProjectTitleRequest { title },
        },
        ProjectCommand::Status { project_id, status } => ClairvoyantRequest::UpdateProjectStatus {
            project_id,
            body: UpdateProjectStatusRequest {
                status: parse_project_status(&status)?,
            },
        },
        ProjectCommand::Stop { project_id } => ClairvoyantRequest::UpdateProjectStatus {
            project_id,
            body: UpdateProjectStatusRequest {
                status: ProjectStatus::Stopped,
            },
        },
        ProjectCommand::Resume { project_id } => ClairvoyantRequest::UpdateProjectStatus {
            project_id,
            body: UpdateProjectStatusRequest {
                status: ProjectStatus::Active,
            },
        },
        ProjectCommand::Delete { project_id } => ClairvoyantRequest::DeleteProject { project_id },
        ProjectCommand::Complete {
            project_id,
            sources,
            description,
            worker,
        } => ClairvoyantRequest::CompleteProject {
            project_id,
            body: CompleteRequest {
                sources,
                description,
                worker,
            },
        },
        ProjectCommand::Reopen {
            project_id,
            description,
            creator,
        } => ClairvoyantRequest::ReopenProject {
            project_id,
            body: ReopenRequest {
                description,
                creator,
            },
        },
        ProjectCommand::Export { project_id, format } => ClairvoyantRequest::ExportProject {
            project_id,
            format: parse_export_format(&format)?,
        },
    })
}

fn intent_request(project_id: String, command: IntentCommand) -> ClairvoyantRequest {
    match command {
        IntentCommand::Create {
            sources,
            description,
            creator,
            worker,
        } => ClairvoyantRequest::CreateIntent {
            project_id,
            body: CreateIntentRequest {
                sources,
                description,
                creator,
                worker,
            },
        },
        IntentCommand::Heartbeat { intent_id, worker } => ClairvoyantRequest::HeartbeatIntent {
            project_id,
            intent_id,
            body: HeartbeatRequest { worker },
        },
        IntentCommand::Release { intent_id, worker } => ClairvoyantRequest::ReleaseIntent {
            project_id,
            intent_id,
            body: HeartbeatRequest { worker },
        },
        IntentCommand::Conclude {
            intent_id,
            worker,
            description,
        } => ClairvoyantRequest::ConcludeIntent {
            project_id,
            intent_id,
            body: ConcludeRequest {
                worker,
                description,
            },
        },
    }
}

fn hint_request(project_id: String, command: HintCommand) -> ClairvoyantRequest {
    match command {
        HintCommand::Create { content, creator } => ClairvoyantRequest::CreateHint {
            project_id,
            body: CreateHintRequest { content, creator },
        },
    }
}

fn reason_request(project_id: String, command: ReasonCommand) -> ClairvoyantRequest {
    match command {
        ReasonCommand::Claim { worker, trigger } => ClairvoyantRequest::ClaimProjectReason {
            project_id,
            body: ReasonClaimRequest { worker, trigger },
        },
        ReasonCommand::Heartbeat { worker } => ClairvoyantRequest::HeartbeatProjectReason {
            project_id,
            body: HeartbeatRequest { worker },
        },
        ReasonCommand::Release { worker } => ClairvoyantRequest::ReleaseProjectReason {
            project_id,
            body: HeartbeatRequest { worker },
        },
    }
}

fn parse_project_status(value: &str) -> anyhow::Result<ProjectStatus> {
    match value {
        "active" => Ok(ProjectStatus::Active),
        "stopped" => Ok(ProjectStatus::Stopped),
        other => anyhow::bail!(
            "unsupported project status `{other}`; expected active or stopped; use `project complete` to complete a project"
        ),
    }
}

fn parse_export_format(value: &str) -> anyhow::Result<ExportFormat> {
    match value {
        "yaml" => Ok(ExportFormat::Yaml),
        "timeline" => Ok(ExportFormat::Timeline),
        other => anyhow::bail!("unsupported export format `{other}`; expected yaml or timeline"),
    }
}

async fn run_json_request(
    db_path: Option<PathBuf>,
    request: ClairvoyantRequest,
) -> anyhow::Result<()> {
    let response = handle_request(db_path, request).await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    match response {
        ClairvoyantEnvelope::Ok { .. } => Ok(()),
        ClairvoyantEnvelope::Err { error } => anyhow::bail!("{}: {}", error.status, error.message),
    }
}

async fn run_text_request(
    db_path: Option<PathBuf>,
    request: ClairvoyantRequest,
) -> anyhow::Result<()> {
    match handle_request(db_path, request).await? {
        ClairvoyantEnvelope::Ok { response } => match *response {
            clairvoyant_core::ClairvoyantResponse::Text(text) => {
                print!("{text}");
                Ok(())
            }
            other => anyhow::bail!("expected text response, got {other:?}"),
        },
        ClairvoyantEnvelope::Err { error } => anyhow::bail!("{}: {}", error.status, error.message),
    }
}

async fn report(
    db_path: Option<PathBuf>,
    project_id: String,
    output: Option<PathBuf>,
) -> anyhow::Result<()> {
    let detail = load_project_detail(db_path, project_id).await?;
    let markdown = render_markdown_report(&detail);
    if let Some(path) = output {
        std::fs::write(&path, markdown)
            .with_context(|| format!("writing report {}", path.display()))?;
    } else {
        print!("{markdown}");
    }
    Ok(())
}

async fn load_project_detail(
    db_path: Option<PathBuf>,
    project_id: String,
) -> anyhow::Result<ProjectDetail> {
    match handle_request(db_path, ClairvoyantRequest::GetProject { project_id }).await? {
        ClairvoyantEnvelope::Ok { response } => match *response {
            clairvoyant_core::ClairvoyantResponse::ProjectDetail(detail) => Ok(detail),
            other => anyhow::bail!("expected project detail response, got {other:?}"),
        },
        ClairvoyantEnvelope::Err { error } => anyhow::bail!("{}: {}", error.status, error.message),
    }
}

fn render_markdown_report(detail: &ProjectDetail) -> String {
    let mut out = String::new();
    let origin = project_fact(detail, "origin").unwrap_or("");
    let goal = project_fact(detail, "goal").unwrap_or("");
    let findings = detail
        .facts
        .iter()
        .filter(|fact| fact.id != "origin" && fact.id != "goal")
        .collect::<Vec<_>>();
    let concluded_intents = detail
        .intents
        .iter()
        .filter(|intent| intent.target_fact.is_some())
        .count();
    let open_intents = detail
        .intents
        .iter()
        .filter(|intent| intent.target_fact.is_none())
        .count();

    out.push_str("# Clairvoyant Report: ");
    out.push_str(&detail.project.title);
    out.push_str("\n\n");
    out.push_str("## Summary\n\n");
    out.push_str(&format!("- Project ID: `{}`\n", detail.project.id));
    out.push_str(&format!("- Status: `{}`\n", detail.project.status.as_str()));
    out.push_str(&format!(
        "- Created at ms: `{}`\n",
        detail.project.created_at
    ));
    out.push_str(&format!("- Total facts: `{}`\n", detail.facts.len()));
    out.push_str(&format!("- Findings: `{}`\n", findings.len()));
    out.push_str(&format!(
        "- Intents: `{}` total, `{}` concluded, `{}` open\n",
        detail.intents.len(),
        concluded_intents,
        open_intents
    ));
    out.push_str(&format!("- Hints: `{}`\n\n", detail.hints.len()));

    out.push_str("## Goal\n\n");
    push_markdown_quote(&mut out, goal);
    out.push('\n');

    out.push_str("## Origin\n\n");
    push_markdown_quote(&mut out, origin);
    out.push('\n');

    out.push_str("## Findings\n\n");
    if findings.is_empty() {
        out.push_str("_No non-origin facts have been recorded yet._\n\n");
    } else {
        for fact in findings {
            out.push_str(&format!("### `{}`\n\n", fact.id));
            push_markdown_quote(&mut out, &fact.description);
            out.push('\n');
        }
    }

    out.push_str("## Intents\n\n");
    if detail.intents.is_empty() {
        out.push_str("_No intents have been recorded yet._\n\n");
    } else {
        for intent in &detail.intents {
            let status = intent.target_fact.as_deref().unwrap_or("open");
            out.push_str(&format!(
                "- `{}` -> `{}` by `{}`",
                intent.id, status, intent.creator
            ));
            if let Some(worker) = &intent.worker {
                out.push_str(&format!("; worker `{worker}`"));
            }
            out.push('\n');
            push_markdown_indented_quote(&mut out, &intent.description);
        }
        out.push('\n');
    }

    out.push_str("## Hints\n\n");
    if detail.hints.is_empty() {
        out.push_str("_No hints._\n");
    } else {
        for hint in &detail.hints {
            out.push_str(&format!("- `{}` by `{}`\n", hint.id, hint.creator));
            push_markdown_indented_quote(&mut out, &hint.content);
        }
    }

    out
}

fn project_fact<'a>(detail: &'a ProjectDetail, id: &str) -> Option<&'a str> {
    detail
        .facts
        .iter()
        .find(|fact| fact.id == id)
        .map(|fact| fact.description.as_str())
}

fn push_markdown_quote(out: &mut String, text: &str) {
    if text.trim().is_empty() {
        out.push_str("> _empty_\n");
        return;
    }
    for line in text.lines() {
        if line.is_empty() {
            out.push_str(">\n");
        } else {
            out.push_str("> ");
            out.push_str(line);
            out.push('\n');
        }
    }
}

fn push_markdown_indented_quote(out: &mut String, text: &str) {
    if text.trim().is_empty() {
        out.push_str("  > _empty_\n");
        return;
    }
    for line in text.lines() {
        if line.is_empty() {
            out.push_str("  >\n");
        } else {
            out.push_str("  > ");
            out.push_str(line);
            out.push('\n');
        }
    }
}

async fn handle_request(
    db_path: Option<PathBuf>,
    request: ClairvoyantRequest,
) -> anyhow::Result<ClairvoyantEnvelope> {
    let db_path = db_path.unwrap_or_else(ClairvoyantService::default_db_path);
    let service = ClairvoyantService::open(&db_path)
        .await
        .with_context(|| format!("opening database {}", db_path.display()))?;
    Ok(service.handle_envelope(request).await)
}

fn parse_request_json(json: &str) -> anyhow::Result<ClairvoyantRequest> {
    let text = if json == "-" {
        let mut text = String::new();
        std::io::stdin()
            .read_to_string(&mut text)
            .context("reading request json from stdin")?;
        text
    } else {
        json.to_string()
    };
    serde_json::from_str(&text).context("parsing request json")
}

async fn serve_stdio(db_path: PathBuf) -> anyhow::Result<()> {
    let service = ClairvoyantService::open(&db_path)
        .await
        .with_context(|| format!("opening database {}", db_path.display()))?;
    service.spawn_expirer();

    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();

    loop {
        let Some(request): Option<ClairvoyantRequest> = read_value(&mut stdin)
            .await
            .context("reading request frame")?
        else {
            break;
        };
        let response = service.handle_envelope(request).await;
        write_value(&mut stdout, &response)
            .await
            .context("writing response frame")?;
    }

    Ok(())
}

async fn runtime_command(command: RuntimeCommand) -> anyhow::Result<()> {
    match command {
        RuntimeCommand::Args {
            config,
            project_id,
            worker,
        } => {
            let (runtime, spec) = docker_runtime_from_config(config, project_id, worker)?;
            println!("{}", shell_join_args(&runtime.create_args(&spec)));
            Ok(())
        }
        RuntimeCommand::EnsureStarted {
            config,
            project_id,
            worker,
        } => {
            let (runtime, spec) = docker_runtime_from_config(config, project_id, worker)?;
            let id = runtime.ensure_started(&spec).await?;
            println!("{id}");
            Ok(())
        }
        RuntimeCommand::Exec {
            config,
            project_id,
            worker,
            program,
            args,
        } => {
            let (runtime, spec) = docker_runtime_from_config(config, project_id, worker)?;
            let rendered = spec.rendered();
            let output = runtime
                .exec(
                    &rendered.name,
                    ProcessSpec {
                        program,
                        args,
                        env: std::collections::BTreeMap::new(),
                        stdin: None,
                        cwd: rendered.workdir,
                    },
                )
                .await?;
            print!("{}", output.stdout);
            eprint!("{}", output.stderr);
            Ok(())
        }
    }
}

fn docker_runtime_from_config(
    config_path: PathBuf,
    project_id: String,
    worker: Option<String>,
) -> anyhow::Result<(DockerCliRuntime, ContainerSpec)> {
    let runtime_config = if let Some(worker) = worker {
        let config = DispatcherConfig::from_path(&config_path)
            .with_context(|| format!("reading dispatcher config {}", config_path.display()))?;
        config
            .runtime_config_for_worker(&worker)?
            .context("dispatcher config has no container section")?
    } else {
        let config = DispatcherConfig::from_path_runtime_only(&config_path)
            .with_context(|| format!("reading dispatcher config {}", config_path.display()))?;
        config
            .runtime_config()
            .context("dispatcher config has no container section")?
    };
    let spec = ContainerSpec::try_from_config(project_id, &runtime_config)?;
    Ok((DockerCliRuntime::new(runtime_config), spec))
}

fn shell_join_args(args: &[String]) -> String {
    args.iter()
        .map(|arg| shell_quote_arg(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

fn shell_quote_arg(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }
    if value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'/' | b'.' | b'_' | b'-' | b':' | b'=' | b',' | b'@' | b'+'
            )
    }) {
        return value.to_string();
    }
    format!("'{}'", value.replace('\'', "'\\''"))
}

async fn dispatch(
    config_path: PathBuf,
    db_path_override: Option<PathBuf>,
    once: bool,
    refill_once: bool,
    startup_healthcheck_only: bool,
) -> anyhow::Result<()> {
    let config = DispatcherConfig::from_path(&config_path)
        .with_context(|| format!("reading dispatcher config {}", config_path.display()))?;
    let healthcheck = startup_healthcheck(&config).await?;
    if startup_healthcheck_only {
        println!(
            "healthcheck ok: workers={} container={}",
            healthcheck.checked_workers.join(","),
            healthcheck.checked_container
        );
        return Ok(());
    }
    let db_path = db_path_override
        .or_else(|| config.db_path.clone())
        .unwrap_or_else(ClairvoyantService::default_db_path);
    let service = ClairvoyantService::open(&db_path)
        .await
        .with_context(|| format!("opening database {}", db_path.display()))?;
    service.spawn_expirer();
    let workers = workers_from_config(&config)?;
    let interval_secs = config.runtime.interval;
    let dispatcher = Dispatcher::with_workers(service, workers, config);
    if once {
        let outcome = dispatcher.run_once().await?;
        println!("{outcome:?}");
        return Ok(());
    }
    if refill_once {
        let outcomes = dispatcher.run_refill_tick().await?;
        println!("{outcomes:?}");
        return Ok(());
    }

    let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
    loop {
        interval.tick().await;
        let outcomes = dispatcher.run_refill_tick().await?;
        for outcome in &outcomes {
            match outcome {
                DispatchOutcome::TaskFailed { message } => {
                    tracing::warn!(message = %message, "dispatcher task failed");
                }
                DispatchOutcome::TaskPanicked { message } => {
                    tracing::warn!(message = %message, "dispatcher task panicked");
                }
                _ => {}
            }
        }
        tracing::debug!(?outcomes, "dispatcher tick");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clairvoyant_core::{Fact, Hint, Intent, ProjectMeta};

    #[test]
    fn renders_markdown_report_from_project_detail() {
        let detail = ProjectDetail {
            project: ProjectMeta {
                id: "proj_001".to_string(),
                title: "demo audit".to_string(),
                status: ProjectStatus::Active,
                created_at: 42,
                reason: None,
            },
            facts: vec![
                Fact {
                    id: "origin".to_string(),
                    description: "target: /work/demo".to_string(),
                },
                Fact {
                    id: "goal".to_string(),
                    description: "find a PoC-backed bug".to_string(),
                },
                Fact {
                    id: "f001".to_string(),
                    description: "src/parser.c:17 copies argv into a fixed buffer".to_string(),
                },
            ],
            intents: vec![Intent {
                id: "i001".to_string(),
                sources: vec!["origin".to_string()],
                target_fact: Some("f001".to_string()),
                description: "inspect parser input boundary".to_string(),
                creator: "reasoner".to_string(),
                worker: Some("worker".to_string()),
                last_heartbeat_at: None,
                created_at: 43,
                concluded_at: Some(44),
            }],
            hints: vec![Hint {
                id: "h001".to_string(),
                content: "focus parser".to_string(),
                creator: "human".to_string(),
                created_at: 45,
            }],
        };

        let report = render_markdown_report(&detail);

        assert!(report.contains("# Clairvoyant Report: demo audit"));
        assert!(report.contains("- Findings: `1`"));
        assert!(report.contains("## Goal"));
        assert!(report.contains("find a PoC-backed bug"));
        assert!(report.contains("### `f001`"));
        assert!(report.contains("src/parser.c:17"));
        assert!(report.contains("`i001` -> `f001`"));
        assert!(report.contains("`h001` by `human`"));
    }
}
