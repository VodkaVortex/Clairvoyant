use anyhow::Context;
use async_trait::async_trait;
use clairvoyant_core::{
    ClairvoyantEnvelope, ClairvoyantRequest, ClairvoyantResponse, CreateIntentRequest,
    CreateProjectRequest, ProjectStatus,
};
use clairvoyant_dispatcher::{
    DispatchOutcome, Dispatcher, DispatcherConfig, SchedulerRuntimeConfig, WorkerConfig,
};
use clairvoyant_protocol::{ByteClient, ClairvoyantClient};
use clairvoyant_runtime::{
    ContainerSpec, DockerCliRuntime, ProcessSpec, RuntimeBackend, RuntimeConfig,
};
use clairvoyant_server::ClairvoyantService;
use clairvoyant_workers::{Worker, WorkerContext, WorkerError, WorkerEvent};
use clap::{Parser, Subcommand};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use tokio_stream::StreamExt;

#[derive(Debug, Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Smoke,
    Verify,
    /// Build a clean Linux/WSL release staging directory and zip.
    Package {
        #[arg(long, default_value = "target/release/clairvoyant")]
        binary: PathBuf,
        #[arg(long, default_value = "dist")]
        dist_dir: PathBuf,
        #[arg(long)]
        keep_staging: bool,
    },
    BenchInternal {
        #[arg(long, default_value_t = 100)]
        writes: usize,
        #[arg(long, default_value_t = 100)]
        reads: usize,
        #[arg(long, default_value_t = 100)]
        concurrency: usize,
        #[arg(long, default_value_t = 50)]
        p99_ms: u128,
        #[arg(long)]
        db_path: Option<PathBuf>,
    },
    BenchRss {
        #[arg(long, default_value_t = 5)]
        samples: usize,
        #[arg(long, default_value_t = 100)]
        interval_ms: u64,
        #[arg(long, default_value_t = 64)]
        max_rust_mb: u64,
        #[arg(long)]
        compare_command: Option<String>,
    },
    CybergymAudit {
        #[arg(long, default_value = "sub_data")]
        dataset: String,
        #[arg(long, default_value_t = 5)]
        sample: usize,
        #[arg(long)]
        write_script: Option<PathBuf>,
    },
    CybergymVerify {
        #[arg(long)]
        results_file: PathBuf,
        #[arg(long = "agent-id")]
        agent_ids: Vec<String>,
        #[arg(long, default_value = "http://localhost:8666")]
        server: String,
        #[arg(long)]
        preflight_only: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Smoke => smoke().await,
        Command::Verify => verify().await,
        Command::Package {
            binary,
            dist_dir,
            keep_staging,
        } => package_release(&binary, &dist_dir, keep_staging),
        Command::BenchInternal {
            writes,
            reads,
            concurrency,
            p99_ms,
            db_path,
        } => bench_internal(writes, reads, concurrency, p99_ms, db_path).await,
        Command::BenchRss {
            samples,
            interval_ms,
            max_rust_mb,
            compare_command,
        } => bench_rss(samples, interval_ms, max_rust_mb, compare_command).await,
        Command::CybergymAudit {
            dataset,
            sample,
            write_script,
        } => cybergym_audit(&dataset, sample, write_script.as_deref()),
        Command::CybergymVerify {
            results_file,
            agent_ids,
            server,
            preflight_only,
        } => cybergym_verify(&results_file, &agent_ids, &server, preflight_only),
    }
}

async fn verify() -> anyhow::Result<()> {
    verify_no_core_network_dependencies()?;
    verify_prompt_templates_are_simple()?;
    verify_python_prompt_mirror()?;
    verify_static_vendor_mirror()?;
    verify_no_unsupported_worker_kinds_in_checked_in_configs()?;
    verify_example_configs()?;
    run_cargo(&["fmt", "--check"])?;
    run_cargo(&["clippy", "--all-targets", "--", "-D", "warnings"])?;
    run_cargo(&["test"])?;
    smoke().await?;
    verify_release_binary()?;
    verify_release_rss_baseline().await?;
    verify_release_request_schema()?;
    verify_release_request_stdin()?;
    verify_release_migrate().await?;
    verify_release_stdio().await?;
    verify_release_dispatch_e2e()?;
    verify_runtime_example_args()?;
    verify_release_runtime_cli().await?;
    verify_dockerfile_cli_image()?;
    verify_compose_config()?;
    verify_docker_image_size().await
}

fn run_cargo(args: &[&str]) -> anyhow::Result<()> {
    let status = std::process::Command::new("cargo")
        .args(args)
        .status()
        .with_context(|| format!("running cargo {}", args.join(" ")))?;
    if !status.success() {
        anyhow::bail!("cargo {} exited with {status}", args.join(" "));
    }
    Ok(())
}

fn package_release(binary: &Path, dist_dir: &Path, keep_staging: bool) -> anyhow::Result<()> {
    const PACKAGE_NAME: &str = concat!(
        "clairvoyant-rs-",
        env!("CARGO_PKG_VERSION"),
        "-linux-x86_64"
    );
    let binary = canonicalize_required_file(binary, "release binary")?;
    ensure_linux_binary(&binary)?;

    std::fs::create_dir_all(dist_dir)
        .with_context(|| format!("creating dist dir {}", dist_dir.display()))?;
    let stage = dist_dir.join(PACKAGE_NAME);
    let zip_path = dist_dir.join(format!("{PACKAGE_NAME}.zip"));
    remove_dir_if_exists(&stage)?;
    std::fs::create_dir_all(stage.join("bin"))
        .with_context(|| format!("creating package bin dir {}", stage.join("bin").display()))?;
    std::fs::copy(&binary, stage.join("bin/clairvoyant"))
        .with_context(|| format!("copying {}", binary.display()))?;

    for file in [
        ".dockerignore",
        ".gitattributes",
        ".gitignore",
        "Cargo.lock",
        "Cargo.toml",
        "dispatch_default.yaml",
        "docker-compose.yaml",
        "docker-compose.yml",
        "Dockerfile",
        "README.md",
    ] {
        copy_file(Path::new(file), &stage.join(file))?;
    }
    for dir in ["crates", "docs", "workers", "xtask"] {
        copy_dir_recursive(Path::new(dir), &stage.join(dir))?;
    }
    write_release_manifest(&stage)?;
    create_zip_with_python(&stage, &zip_path, PACKAGE_NAME)?;
    if !keep_staging {
        remove_dir_if_exists(&stage)?;
    }
    println!("package={}", zip_path.display());
    println!(
        "staging={}",
        if keep_staging {
            stage.display().to_string()
        } else {
            "removed".to_string()
        }
    );
    Ok(())
}

fn canonicalize_required_file(path: &Path, label: &str) -> anyhow::Result<PathBuf> {
    let path = std::fs::canonicalize(path)
        .with_context(|| format!("{label} {} does not exist", path.display()))?;
    let metadata =
        std::fs::metadata(&path).with_context(|| format!("reading {}", path.display()))?;
    if !metadata.is_file() {
        anyhow::bail!("{label} {} is not a file", path.display());
    }
    Ok(path)
}

fn ensure_linux_binary(path: &Path) -> anyhow::Result<()> {
    if path.extension().is_some_and(|extension| extension == "exe") {
        anyhow::bail!(
            "refusing to package Windows .exe binary: {}",
            path.display()
        );
    }
    let mut file =
        std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut magic = [0u8; 4];
    std::io::Read::read_exact(&mut file, &mut magic)
        .with_context(|| format!("reading ELF magic from {}", path.display()))?;
    if magic != *b"\x7fELF" {
        anyhow::bail!(
            "release package is Linux/WSL-only; {} is not an ELF binary",
            path.display()
        );
    }
    Ok(())
}

fn remove_dir_if_exists(path: &Path) -> anyhow::Result<()> {
    if path.exists() {
        std::fs::remove_dir_all(path)
            .with_context(|| format!("removing existing dir {}", path.display()))?;
    }
    Ok(())
}

fn copy_file(src: &Path, dst: &Path) -> anyhow::Result<()> {
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    std::fs::copy(src, dst)
        .with_context(|| format!("copying {} to {}", src.display(), dst.display()))?;
    Ok(())
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dst).with_context(|| format!("creating {}", dst.display()))?;
    for entry in std::fs::read_dir(src).with_context(|| format!("reading {}", src.display()))? {
        let entry = entry?;
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();
        if matches!(name.as_ref(), "target" | "dist" | ".git" | "__pycache__")
            || name.ends_with(".pyc")
        {
            continue;
        }
        let src_path = entry.path();
        let dst_path = dst.join(file_name);
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else if file_type.is_file() {
            copy_file(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

fn write_release_manifest(stage: &Path) -> anyhow::Result<()> {
    let mut files = Vec::new();
    collect_manifest_files(stage, stage, &mut files)?;
    files.sort();
    let mut manifest = String::from(
        "Clairvoyant Linux/WSL release package\n\n\
         Top-level policy:\n\
         - root keeps only dispatch_default.yaml\n\
         - optional dispatcher examples live under docs/examples/dispatch/\n\
         - no Windows binaries are included\n\n\
         Files:\n",
    );
    for file in files {
        manifest.push_str(&file);
        manifest.push('\n');
    }
    std::fs::write(stage.join("RELEASE-MANIFEST.txt"), manifest)
        .with_context(|| format!("writing {}", stage.join("RELEASE-MANIFEST.txt").display()))?;
    Ok(())
}

fn collect_manifest_files(root: &Path, dir: &Path, files: &mut Vec<String>) -> anyhow::Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            collect_manifest_files(root, &path, files)?;
        } else if entry.file_type()?.is_file() {
            files.push(
                path.strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
        }
    }
    Ok(())
}

fn create_zip_with_python(stage: &Path, zip_path: &Path, package_name: &str) -> anyhow::Result<()> {
    let script = r#"
import hashlib
import pathlib
import sys
import zipfile

stage = pathlib.Path(sys.argv[1])
zip_path = pathlib.Path(sys.argv[2])
package_name = sys.argv[3]
tmp = zip_path.with_suffix(zip_path.suffix + ".tmp")
if tmp.exists():
    tmp.unlink()

def add_dir(zf, arc):
    info = zipfile.ZipInfo(arc.rstrip("/") + "/")
    info.external_attr = (0o755 << 16)
    zf.writestr(info, b"")

def add_file(zf, path, arc):
    info = zipfile.ZipInfo(arc)
    mode = 0o755 if arc == f"{package_name}/bin/clairvoyant" else 0o644
    info.external_attr = (mode << 16)
    info.compress_type = zipfile.ZIP_DEFLATED
    zf.writestr(info, path.read_bytes())

with zipfile.ZipFile(tmp, "w") as zf:
    add_dir(zf, package_name)
    for path in sorted(stage.rglob("*")):
        arc = f"{package_name}/{path.relative_to(stage).as_posix()}"
        if path.is_dir():
            add_dir(zf, arc)
        elif path.is_file():
            add_file(zf, path, arc)
if zip_path.exists():
    zip_path.unlink()
tmp.rename(zip_path)
print("sha256=" + hashlib.sha256(zip_path.read_bytes()).hexdigest().upper())
"#;
    let mut last_error = None;
    for python in ["python3", "python"] {
        let output = std::process::Command::new(python)
            .arg("-c")
            .arg(script)
            .arg(stage)
            .arg(zip_path)
            .arg(package_name)
            .output();
        match output {
            Ok(output) if output.status.success() => {
                print!("{}", String::from_utf8_lossy(&output.stdout));
                return Ok(());
            }
            Ok(output) => {
                last_error = Some(format!(
                    "{python} exited with {}: {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
            Err(error) => {
                last_error = Some(format!("{python} failed: {error}"));
            }
        }
    }
    anyhow::bail!(
        "creating release zip requires python3 or python with zipfile support: {}",
        last_error.unwrap_or_else(|| "no python candidate was tried".to_string())
    )
}

fn verify_example_configs() -> anyhow::Result<()> {
    for path in [
        "docs/examples/dispatch/dispatch_mock.yaml",
        "docs/examples/dispatch/dispatch_compose.yaml",
        "docs/examples/dispatch/dispatch_claude_local.yaml",
    ] {
        DispatcherConfig::from_path(path).with_context(|| format!("validating {path}"))?;
    }
    with_temp_env(
        &[
            ("ANTHROPIC_MODEL", "dummy-claude-model"),
            ("ANTHROPIC_BASE_URL", "https://example.invalid"),
            ("ANTHROPIC_AUTH_TOKEN", "dummy-anthropic-key"),
        ],
        || {
            DispatcherConfig::from_path("docs/examples/dispatch/dispatch_example.yaml").context(
                "validating docs/examples/dispatch/dispatch_example.yaml full worker config",
            )?;
            DispatcherConfig::from_path("docs/examples/dispatch/dispatch_claude_source.yaml")
                .context(
                "validating docs/examples/dispatch/dispatch_claude_source.yaml full worker config",
            )?;
            DispatcherConfig::from_path("docs/examples/dispatch/dispatch_binary_vuln.yaml")
                .context(
                "validating docs/examples/dispatch/dispatch_binary_vuln.yaml full worker config",
            )?;
            Ok(())
        },
    )?;
    DispatcherConfig::from_path_runtime_only("docs/examples/dispatch/dispatch_example.yaml")
        .context("validating docs/examples/dispatch/dispatch_example.yaml runtime config")?;
    DispatcherConfig::from_path_runtime_only("docs/examples/dispatch/dispatch_binary_vuln.yaml")
        .context("validating docs/examples/dispatch/dispatch_binary_vuln.yaml runtime config")?;
    DispatcherConfig::from_path_runtime_only(
        "docs/examples/dispatch/dispatch_cybergym_deepseek.yaml",
    )
    .context("validating docs/examples/dispatch/dispatch_cybergym_deepseek.yaml runtime config")?;
    Ok(())
}

fn verify_no_unsupported_worker_kinds_in_checked_in_configs() -> anyhow::Result<()> {
    for path in [
        "docs/examples/dispatch/dispatch_mock.yaml",
        "docs/examples/dispatch/dispatch_compose.yaml",
        "docs/examples/dispatch/dispatch_claude_local.yaml",
        "docs/examples/dispatch/dispatch_example.yaml",
        "docs/examples/dispatch/dispatch_claude_source.yaml",
        "docs/examples/dispatch/dispatch_binary_vuln.yaml",
        "docs/examples/dispatch/dispatch_cybergym_deepseek.yaml",
    ] {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?;
        let yaml: serde_yaml::Value =
            serde_yaml::from_str(&text).with_context(|| format!("parsing {path}"))?;
        let mut violations = Vec::new();
        collect_unsupported_worker_kind_paths(&yaml, path, &mut violations);
        if !violations.is_empty() {
            anyhow::bail!(
                "checked-in dispatcher configs must not reference unsupported model workers: {}",
                violations.join(", ")
            );
        }
    }
    Ok(())
}

fn collect_unsupported_worker_kind_paths(
    value: &serde_yaml::Value,
    path: &str,
    violations: &mut Vec<String>,
) {
    match value {
        serde_yaml::Value::Mapping(mapping) => {
            for (key, nested) in mapping {
                let key_text = key.as_str().unwrap_or("<non-string>");
                let next_path = format!("{path}.{key_text}");
                if matches!(key_text, "kind" | "type")
                    && nested
                        .as_str()
                        .is_some_and(|kind| matches!(kind, "codex" | "pi"))
                {
                    violations.push(format!(
                        "{next_path}={}",
                        nested.as_str().unwrap_or_default()
                    ));
                }
                collect_unsupported_worker_kind_paths(nested, &next_path, violations);
            }
        }
        serde_yaml::Value::Sequence(items) => {
            for (index, nested) in items.iter().enumerate() {
                collect_unsupported_worker_kind_paths(
                    nested,
                    &format!("{path}[{index}]"),
                    violations,
                );
            }
        }
        _ => {}
    }
}

fn with_temp_env<F>(vars: &[(&str, &str)], f: F) -> anyhow::Result<()>
where
    F: FnOnce() -> anyhow::Result<()>,
{
    let previous = vars
        .iter()
        .map(|(key, _)| ((*key).to_string(), std::env::var_os(key)))
        .collect::<Vec<_>>();
    for (key, value) in vars {
        std::env::set_var(key, value);
    }
    let result = f();
    for (key, value) in previous {
        match value {
            Some(value) => std::env::set_var(key, value),
            None => std::env::remove_var(key),
        }
    }
    result
}

fn verify_no_core_network_dependencies() -> anyhow::Result<()> {
    let mut files = vec![
        "Cargo.toml".to_string(),
        "Cargo.lock".to_string(),
        "xtask/Cargo.toml".to_string(),
    ];
    files.extend(
        walk_network_guard_files(std::path::Path::new("crates"))?
            .into_iter()
            .map(|path| path.display().to_string()),
    );
    for file in files {
        let path = std::path::Path::new(&file);
        if !path.exists() {
            continue;
        }
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        if let Some(needle) = forbidden_network_token(&text) {
            anyhow::bail!(
                "core network dependency check failed: {} contains `{needle}`",
                path.display()
            );
        }
    }
    Ok(())
}

fn forbidden_network_token(text: &str) -> Option<&'static str> {
    forbidden_network_needles()
        .iter()
        .copied()
        .find(|needle| text.contains(needle))
}

fn forbidden_network_needles() -> &'static [&'static str] {
    &[
        "axum",
        "bollard",
        "hyper",
        "reqwest",
        "tower",
        "std::net",
        "tokio::net",
        "TcpListener",
        "TcpSocket",
        "TcpStream",
        "UdpSocket",
        "SocketAddr",
        "ToSocketAddrs",
        "IpAddr",
        "Ipv4Addr",
        "Ipv6Addr",
    ]
}

fn walk_network_guard_files(root: &std::path::Path) -> anyhow::Result<Vec<std::path::PathBuf>> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(root).with_context(|| format!("reading {}", root.display()))? {
        let path = entry
            .with_context(|| format!("reading entry under {}", root.display()))?
            .path();
        if path.is_dir() {
            if path
                .components()
                .any(|component| component.as_os_str() == "static")
            {
                continue;
            }
            files.extend(walk_network_guard_files(&path)?);
        } else if should_scan_network_guard_file(&path) {
            files.push(path);
        }
    }
    Ok(files)
}

fn should_scan_network_guard_file(path: &std::path::Path) -> bool {
    path.file_name().and_then(|name| name.to_str()) == Some("Cargo.toml")
        || path.extension().and_then(|extension| extension.to_str()) == Some("rs")
}

fn verify_prompt_templates_are_simple() -> anyhow::Result<()> {
    for entry in walk_prompt_files(std::path::Path::new(
        "crates/clairvoyant-dispatcher/prompts",
    ))? {
        let text = std::fs::read_to_string(&entry)
            .with_context(|| format!("reading {}", entry.display()))?;
        for forbidden in ["{{", "{%"] {
            if text.contains(forbidden) {
                anyhow::bail!(
                    "prompt template {} contains `{forbidden}`; switch dispatcher rendering to minijinja before accepting Jinja syntax",
                    entry.display()
                );
            }
        }
    }
    Ok(())
}

fn verify_python_prompt_mirror() -> anyhow::Result<()> {
    let upstream = std::path::Path::new(
        "upstream_clairvoyant/clairvoyant/src/clairvoyant/dispatcher/prompts/default",
    );
    let mirror = std::path::Path::new("crates/clairvoyant-dispatcher/prompts/python");
    if !upstream.exists() {
        println!(
            "python prompt mirror check skipped: upstream prompts not found at {}",
            upstream.display()
        );
        return Ok(());
    }
    require_prompt_files_match(upstream, mirror).with_context(|| {
        format!(
            "checking python prompt mirror against {}",
            upstream.display()
        )
    })
}

fn require_prompt_files_match(
    source: &std::path::Path,
    mirror: &std::path::Path,
) -> anyhow::Result<()> {
    let mut source_files = prompt_relative_files(source)?;
    let mut mirror_files = prompt_relative_files(mirror)?;
    source_files.sort();
    mirror_files.sort();
    if source_files != mirror_files {
        anyhow::bail!(
            "prompt mirror file list differs: source={source_files:?} mirror={mirror_files:?}"
        );
    }
    for relative in source_files {
        let source_path = source.join(&relative);
        let mirror_path = mirror.join(&relative);
        let source_bytes = std::fs::read(&source_path)
            .with_context(|| format!("reading {}", source_path.display()))?;
        let mirror_bytes = std::fs::read(&mirror_path)
            .with_context(|| format!("reading {}", mirror_path.display()))?;
        if source_bytes != mirror_bytes {
            anyhow::bail!(
                "prompt mirror differs for {}: {} != {}",
                relative.display(),
                source_path.display(),
                mirror_path.display()
            );
        }
    }
    Ok(())
}

fn verify_static_vendor_mirror() -> anyhow::Result<()> {
    let upstream =
        std::path::Path::new("upstream_clairvoyant/clairvoyant/src/clairvoyant/server/static");
    let mirror = std::path::Path::new("crates/clairvoyant-server/static");
    if !upstream.exists() {
        println!(
            "static vendor mirror check skipped: upstream static assets not found at {}",
            upstream.display()
        );
        return Ok(());
    }
    require_static_vendor_files_match(upstream, mirror).with_context(|| {
        format!(
            "checking static vendor mirror against {}",
            upstream.display()
        )
    })
}

fn require_static_vendor_files_match(
    source: &std::path::Path,
    mirror: &std::path::Path,
) -> anyhow::Result<()> {
    let mut source_files = static_vendor_relative_files(source)?;
    let mut mirror_files = static_vendor_relative_files(mirror)?;
    source_files.sort();
    mirror_files.sort();
    if source_files != mirror_files {
        anyhow::bail!(
            "static vendor mirror file list differs: source={source_files:?} mirror={mirror_files:?}"
        );
    }
    for relative in source_files {
        let source_path = source.join(&relative);
        let mirror_path = mirror.join(&relative);
        let source_bytes = std::fs::read(&source_path)
            .with_context(|| format!("reading {}", source_path.display()))?;
        let mirror_bytes = std::fs::read(&mirror_path)
            .with_context(|| format!("reading {}", mirror_path.display()))?;
        if source_bytes != mirror_bytes {
            anyhow::bail!(
                "static vendor mirror differs for {}: {} != {}",
                relative.display(),
                source_path.display(),
                mirror_path.display()
            );
        }
    }
    Ok(())
}

fn static_vendor_relative_files(root: &std::path::Path) -> anyhow::Result<Vec<std::path::PathBuf>> {
    Ok(walk_static_vendor_files(root, root)?
        .into_iter()
        .map(|path| {
            path.strip_prefix(root)
                .unwrap_or(path.as_path())
                .to_path_buf()
        })
        .collect())
}

fn walk_static_vendor_files(
    root: &std::path::Path,
    current: &std::path::Path,
) -> anyhow::Result<Vec<std::path::PathBuf>> {
    let mut files = Vec::new();
    for entry in
        std::fs::read_dir(current).with_context(|| format!("reading {}", current.display()))?
    {
        let path = entry
            .with_context(|| format!("reading entry under {}", current.display()))?
            .path();
        if path.is_dir() {
            files.extend(walk_static_vendor_files(root, &path)?);
        } else if is_static_vendor_mirror_file(root, &path) {
            files.push(path);
        }
    }
    Ok(files)
}

fn is_static_vendor_mirror_file(root: &std::path::Path, path: &std::path::Path) -> bool {
    let Ok(relative) = path.strip_prefix(root) else {
        return false;
    };
    if relative == std::path::Path::new("favicon.svg") {
        return true;
    }
    relative
        .components()
        .next()
        .is_some_and(|component| component.as_os_str() == "vendor")
}

fn prompt_relative_files(root: &std::path::Path) -> anyhow::Result<Vec<std::path::PathBuf>> {
    Ok(walk_prompt_files(root)?
        .into_iter()
        .map(|path| {
            path.strip_prefix(root)
                .unwrap_or(path.as_path())
                .to_path_buf()
        })
        .collect())
}

fn walk_prompt_files(root: &std::path::Path) -> anyhow::Result<Vec<std::path::PathBuf>> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(root).with_context(|| format!("reading {}", root.display()))? {
        let path = entry
            .with_context(|| format!("reading entry under {}", root.display()))?
            .path();
        if path.is_dir() {
            files.extend(walk_prompt_files(&path)?);
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("md") {
            files.push(path);
        }
    }
    Ok(files)
}

fn verify_release_binary() -> anyhow::Result<()> {
    run_cargo(&["build", "--release", "--bin", "clairvoyant"])?;
    let output = std::process::Command::new("target/release/clairvoyant")
        .arg("--help")
        .output()
        .context("running release clairvoyant --help")?;
    if !output.status.success() {
        anyhow::bail!("release clairvoyant --help exited with {}", output.status);
    }
    let help = String::from_utf8_lossy(&output.stdout);
    for command in [
        "serve", "dispatch", "migrate", "request", "settings", "project", "intent", "hint",
        "reason", "asset", "runtime",
    ] {
        if !help.contains(command) {
            anyhow::bail!("release help is missing subcommand `{command}`");
        }
    }
    for command in ["settings", "project", "intent", "hint", "reason"] {
        let output = std::process::Command::new("target/release/clairvoyant")
            .args([command, "--help"])
            .output()
            .with_context(|| format!("running release clairvoyant {command} --help"))?;
        if !output.status.success() {
            anyhow::bail!(
                "release clairvoyant {command} --help exited with {}",
                output.status
            );
        }
    }
    let output = std::process::Command::new("target/release/clairvoyant")
        .args(["request", "--help"])
        .output()
        .context("running release clairvoyant request --help")?;
    if !output.status.success() {
        anyhow::bail!(
            "release clairvoyant request --help exited with {}",
            output.status
        );
    }
    let request_help = String::from_utf8_lossy(&output.stdout);
    if !request_help.contains("use '-' to read from stdin") {
        anyhow::bail!("release request help is missing stdin guidance: {request_help}");
    }
    let output = std::process::Command::new("target/release/clairvoyant")
        .args(["asset", "--path", "/static/index.html"])
        .output()
        .context("reading embedded index asset from release binary")?;
    if !output.status.success() {
        anyhow::bail!(
            "release clairvoyant asset exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    if !output.stdout.starts_with(b"<!DOCTYPE html>") {
        anyhow::bail!("embedded index asset did not contain the expected HTML");
    }
    let output = std::process::Command::new("target/release/clairvoyant")
        .args(["asset", "--list"])
        .output()
        .context("listing embedded assets from release binary")?;
    if !output.status.success() {
        anyhow::bail!(
            "release clairvoyant asset --list exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let asset_list = String::from_utf8_lossy(&output.stdout);
    if !asset_list.contains("vendor/cytoscape.min.js") {
        anyhow::bail!("embedded asset list is missing cytoscape: {asset_list}");
    }
    let size = std::fs::metadata("target/release/clairvoyant")
        .context("reading release binary metadata")?
        .len();
    if size > 30 * 1024 * 1024 {
        anyhow::bail!("release binary is too large: {size} bytes");
    }
    verify_release_serve_cold_start()?;
    Ok(())
}

fn verify_release_serve_cold_start() -> anyhow::Result<()> {
    let db_path = std::env::temp_dir().join(format!(
        "clairvoyant-xtask-release-startup-{}-{}.db",
        std::process::id(),
        chrono_like_timestamp()
    ));
    let started = std::time::Instant::now();
    let output = std::process::Command::new("target/release/clairvoyant")
        .args(["serve", "--db-path"])
        .arg(&db_path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .context("running release clairvoyant serve cold-start check")?;
    let elapsed = started.elapsed();
    cleanup_sqlite_files(&db_path);
    if !output.status.success() {
        anyhow::bail!(
            "release serve cold-start check exited with {}: stdout={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    if elapsed > std::time::Duration::from_millis(150) {
        anyhow::bail!("release serve cold start took {elapsed:?}, expected <= 150ms");
    }
    Ok(())
}

fn cleanup_sqlite_files(path: &std::path::Path) {
    for candidate in [
        path.to_path_buf(),
        path.with_extension("db-shm"),
        path.with_extension("db-wal"),
    ] {
        let _ = std::fs::remove_file(candidate);
    }
}

async fn verify_release_rss_baseline() -> anyhow::Result<()> {
    let db_path = std::env::temp_dir().join(format!(
        "clairvoyant-xtask-release-rss-{}-{}.db",
        std::process::id(),
        chrono_like_timestamp()
    ));
    let report = measure_process_rss(
        "release-rss",
        tokio::process::Command::new("target/release/clairvoyant")
            .arg("serve")
            .arg("--db-path")
            .arg(db_path),
        5,
        100,
    )
    .await?;
    if report.peak_kib > 64 * 1024 {
        anyhow::bail!(
            "release serve RSS peak {:.3}MiB exceeded threshold 64MiB",
            kib_to_mib(report.peak_kib)
        );
    }
    println!(
        "release rss ok: peak_mb={:.3} avg_mb={:.3}",
        kib_to_mib(report.peak_kib),
        kib_to_mib(report.avg_kib)
    );
    Ok(())
}

fn verify_release_request_schema() -> anyhow::Result<()> {
    let db_path = std::env::temp_dir().join(format!(
        "clairvoyant-xtask-release-schema-{}-{}.db",
        std::process::id(),
        chrono_like_timestamp()
    ));
    let output = std::process::Command::new("target/release/clairvoyant")
        .args(["request", "--db-path"])
        .arg(&db_path)
        .args([
            "--json",
            r#"{"op":"create_intent","project_id":"proj_001","body":{"from":["origin"],"description":"legacy intent","creator":"xtask","worker":null}}"#,
        ])
        .output()
        .context("running release request with legacy intent schema")?;
    if output.status.success() {
        anyhow::bail!(
            "release request unexpectedly accepted legacy intent schema: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.contains("unknown field `from`") {
        anyhow::bail!("release request schema stderr was unexpected: {stderr}");
    }
    Ok(())
}

fn verify_release_request_stdin() -> anyhow::Result<()> {
    let db_path = std::env::temp_dir().join(format!(
        "clairvoyant-xtask-release-stdin-{}-{}.db",
        std::process::id(),
        chrono_like_timestamp()
    ));
    let request = ClairvoyantRequest::CreateProject {
        body: CreateProjectRequest {
            title: "release stdin".to_string(),
            origin: "origin fact".to_string(),
            goal: "goal fact".to_string(),
            hints: None,
        },
    };
    let mut child = std::process::Command::new("target/release/clairvoyant")
        .args(["request", "--db-path"])
        .arg(&db_path)
        .args(["--json", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("spawning release request reading stdin")?;
    let mut stdin = child
        .stdin
        .take()
        .context("release request stdin was not piped")?;
    stdin
        .write_all(serde_json::to_string(&request)?.as_bytes())
        .context("writing release request json to stdin")?;
    drop(stdin);

    let output = child
        .wait_with_output()
        .context("waiting for release request stdin command")?;
    if !output.status.success() {
        anyhow::bail!(
            "release request stdin exited with {}: stdout={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let response = match serde_json::from_slice::<ClairvoyantEnvelope>(&output.stdout)
        .context("parsing release request stdin envelope")?
    {
        ClairvoyantEnvelope::Ok { response } => *response,
        ClairvoyantEnvelope::Err { error } => anyhow::bail!(
            "release request stdin returned error {}: {}",
            error.status,
            error.message
        ),
    };
    let ClairvoyantResponse::ProjectDetail(detail) = response else {
        anyhow::bail!("release request stdin returned unexpected response: {response:?}");
    };
    if detail.project.title != "release stdin" || detail.facts.len() != 2 {
        anyhow::bail!("release request stdin returned unexpected project detail");
    }
    Ok(())
}

async fn verify_release_migrate() -> anyhow::Result<()> {
    let dir = std::env::temp_dir().join(format!(
        "clairvoyant-xtask-release-migrate-{}-{}",
        std::process::id(),
        chrono_like_timestamp()
    ));
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let from = dir.join("python.db");
    let to = dir.join("rust.db");
    create_python_migration_fixture(&from).await?;

    let output = std::process::Command::new("target/release/clairvoyant")
        .args(["migrate", "--from-python"])
        .arg(&from)
        .arg("--to")
        .arg(&to)
        .output()
        .context("running release clairvoyant migrate")?;
    if !output.status.success() {
        anyhow::bail!(
            "release clairvoyant migrate exited with {}: stdout={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.contains("migrated projects=1 facts=3 intents=1 intent_sources=1 hints=1") {
        anyhow::bail!("unexpected release migrate output: {stdout}");
    }

    let detail = match release_request(
        &to,
        ClairvoyantRequest::GetProject {
            project_id: "proj_007".to_string(),
        },
    )? {
        ClairvoyantResponse::ProjectDetail(detail) => detail,
        other => anyhow::bail!("unexpected migrated project response: {other:?}"),
    };
    if detail.project.title != "old" {
        anyhow::bail!("migrated project title mismatch: {}", detail.project.title);
    }
    let reason = detail
        .project
        .reason
        .as_ref()
        .context("migrated project is missing reason lease")?;
    if reason.worker != "reasoner"
        || reason.trigger != "facts=3 hints=1 open_intents=0"
        || reason.started_at != 1_767_225_604_000
        || reason.last_heartbeat_at != 1_767_225_605_000
    {
        anyhow::bail!("migrated reason lease fields were not converted correctly");
    }
    if detail.intents.len() != 1
        || detail.intents[0].sources != vec!["origin".to_string()]
        || detail.intents[0].target_fact.as_deref() != Some("f001")
    {
        anyhow::bail!("migrated intent fields were not converted correctly");
    }
    if detail.hints.len() != 1 || detail.hints[0].created_at != 1_767_225_603_000 {
        anyhow::bail!("migrated hint timestamp was not converted correctly");
    }
    let settings = match release_request(&to, ClairvoyantRequest::GetSettings)? {
        ClairvoyantResponse::Settings(settings) => settings,
        other => anyhow::bail!("unexpected migrated settings response: {other:?}"),
    };
    if settings.intent_timeout != 30 || settings.reason_timeout != 45 {
        anyhow::bail!("migrated settings were not converted correctly: {settings:?}");
    }

    let next = match release_request(
        &to,
        ClairvoyantRequest::CreateIntent {
            project_id: "proj_007".to_string(),
            body: CreateIntentRequest {
                sources: vec!["f001".to_string()],
                description: "release migrate next".to_string(),
                creator: "xtask".to_string(),
                worker: None,
            },
        },
    )? {
        ClairvoyantResponse::Intent(intent) => intent,
        other => anyhow::bail!("unexpected create intent response after migrate: {other:?}"),
    };
    if next.id != "i002" {
        anyhow::bail!("migrated intent counter was not rebuilt: {}", next.id);
    }
    let next_project = match release_request(
        &to,
        ClairvoyantRequest::CreateProject {
            body: CreateProjectRequest {
                title: "release migrate next project".to_string(),
                origin: "o".to_string(),
                goal: "g".to_string(),
                hints: None,
            },
        },
    )? {
        ClairvoyantResponse::ProjectDetail(detail) => detail,
        other => anyhow::bail!("unexpected create project response after migrate: {other:?}"),
    };
    if next_project.project.id != "proj_008" {
        anyhow::bail!(
            "migrated project counter was not rebuilt: {}",
            next_project.project.id
        );
    }

    let dirty_to = dir.join("dirty-rust.db");
    let dirty_project_id = match release_request(
        &dirty_to,
        ClairvoyantRequest::CreateProject {
            body: CreateProjectRequest {
                title: "dirty".to_string(),
                origin: "o".to_string(),
                goal: "g".to_string(),
                hints: None,
            },
        },
    )? {
        ClairvoyantResponse::ProjectDetail(detail) => detail.project.id,
        other => anyhow::bail!("unexpected dirty target create response: {other:?}"),
    };
    release_request(
        &dirty_to,
        ClairvoyantRequest::DeleteProject {
            project_id: dirty_project_id,
        },
    )?;
    let rejected = std::process::Command::new("target/release/clairvoyant")
        .args(["migrate", "--from-python"])
        .arg(&from)
        .arg("--to")
        .arg(&dirty_to)
        .output()
        .context("running release clairvoyant migrate against dirty target")?;
    if rejected.status.success() {
        anyhow::bail!(
            "release migrate unexpectedly accepted dirty target: stdout={} stderr={}",
            String::from_utf8_lossy(&rejected.stdout),
            String::from_utf8_lossy(&rejected.stderr)
        );
    }
    let stderr = String::from_utf8_lossy(&rejected.stderr);
    if !stderr.contains("counters contain non-default rows") {
        anyhow::bail!("release migrate dirty-target stderr was unexpected: {stderr}");
    }

    Ok(())
}

async fn create_python_migration_fixture(path: &std::path::Path) -> anyhow::Result<()> {
    let options =
        sqlx::sqlite::SqliteConnectOptions::from_str(&format!("sqlite://{}", path.display()))
            .context("building python fixture sqlite options")?
            .create_if_missing(true);
    let old = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .with_context(|| format!("opening python fixture {}", path.display()))?;
    for statement in [
        "CREATE TABLE settings (intent_timeout INTEGER NOT NULL DEFAULT 15, reason_timeout INTEGER NOT NULL DEFAULT 15)",
        "INSERT INTO settings (rowid, intent_timeout, reason_timeout) VALUES (1, 30, 45)",
        "CREATE TABLE projects (id TEXT PRIMARY KEY, title TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL, reason_worker TEXT, reason_trigger TEXT, reason_started_at TEXT, reason_last_heartbeat_at TEXT)",
        "CREATE TABLE facts (id TEXT NOT NULL, project_id TEXT NOT NULL, description TEXT NOT NULL, PRIMARY KEY (id, project_id))",
        "CREATE TABLE intents (id TEXT NOT NULL, project_id TEXT NOT NULL, to_fact_id TEXT, description TEXT NOT NULL, creator TEXT NOT NULL, worker TEXT, last_heartbeat_at TEXT, created_at TEXT NOT NULL, concluded_at TEXT, PRIMARY KEY (id, project_id))",
        "CREATE TABLE intent_sources (intent_id TEXT NOT NULL, project_id TEXT NOT NULL, fact_id TEXT NOT NULL, PRIMARY KEY (intent_id, project_id, fact_id))",
        "CREATE TABLE hints (id TEXT NOT NULL, project_id TEXT NOT NULL, content TEXT NOT NULL, creator TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY (id, project_id))",
        "INSERT INTO projects (id, title, status, created_at, reason_worker, reason_trigger, reason_started_at, reason_last_heartbeat_at) VALUES ('proj_007', 'old', 'active', '2026-01-01T00:00:00Z', 'reasoner', 'facts=3 hints=1 open_intents=0', '2026-01-01T00:00:04Z', '2026-01-01T00:00:05Z')",
        "INSERT INTO facts (id, project_id, description) VALUES ('origin', 'proj_007', 'o'), ('goal', 'proj_007', 'g'), ('f001', 'proj_007', 'fact')",
        "INSERT INTO intents (id, project_id, to_fact_id, description, creator, worker, last_heartbeat_at, created_at, concluded_at) VALUES ('i001', 'proj_007', 'f001', 'old intent', 'w', 'w', '2026-01-01T00:00:01Z', '2026-01-01T00:00:01Z', '2026-01-01T00:00:02Z')",
        "INSERT INTO intent_sources (intent_id, project_id, fact_id) VALUES ('i001', 'proj_007', 'origin')",
        "INSERT INTO hints (id, project_id, content, creator, created_at) VALUES ('h001', 'proj_007', 'hint', 'human', '2026-01-01T00:00:03Z')",
    ] {
        sqlx::query(statement)
            .execute(&old)
            .await
            .with_context(|| format!("applying python fixture statement: {statement}"))?;
    }
    old.close().await;
    Ok(())
}

async fn verify_release_stdio() -> anyhow::Result<()> {
    let db_path = std::env::temp_dir().join(format!(
        "clairvoyant-xtask-release-stdio-{}-{}.db",
        std::process::id(),
        chrono_like_timestamp()
    ));
    let mut child = tokio::process::Command::new("target/release/clairvoyant")
        .args(["serve", "--db-path"])
        .arg(&db_path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("spawning release clairvoyant serve")?;
    let stdout = child.stdout.take().context("release serve stdout")?;
    let stdin = child.stdin.take().context("release serve stdin")?;
    let mut client = ByteClient::new(stdout, stdin);
    let project_id = match client
        .request(ClairvoyantRequest::CreateProject {
            body: CreateProjectRequest {
                title: "release stdio".into(),
                origin: "start".into(),
                goal: "finish".into(),
                hints: None,
            },
        })
        .await
        .context("creating project through release stdio")?
    {
        ClairvoyantResponse::ProjectDetail(detail) => detail.project.id,
        other => anyhow::bail!("unexpected release create response: {other:?}"),
    };
    match client
        .request(ClairvoyantRequest::ListProjects)
        .await
        .context("listing projects through release stdio")?
    {
        ClairvoyantResponse::ProjectSummaries(projects)
            if projects
                .iter()
                .any(|project| project.project.id == project_id) => {}
        other => anyhow::bail!("unexpected release list response: {other:?}"),
    }
    drop(client);
    let status = child.wait().await.context("waiting for release serve")?;
    if !status.success() {
        anyhow::bail!("release serve exited with {status}");
    }
    Ok(())
}

fn verify_release_dispatch_e2e() -> anyhow::Result<()> {
    let dir = std::env::temp_dir().join(format!(
        "clairvoyant-xtask-release-dispatch-{}-{}",
        std::process::id(),
        chrono_like_timestamp()
    ));
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let db_path = dir.join("clairvoyant.db");
    let worker_path = dir.join("worker.sh");
    let config_path = dir.join("dispatch.yaml");
    write_executable_script(
        &worker_path,
        r#"#!/bin/sh
prompt=$(cat)
case "$prompt" in
  *'"phase": "bootstrap"'*)
    printf '%s\n' '{"event":"done","description":"release cli bootstrap fact","complete":false}'
    ;;
  *'"phase": "explore_execute"'*)
    printf '%s\n' '{"event":"done","description":"release cli explored fact","complete":false}'
    ;;
  *'"phase": "reason"'*)
    case "$prompt" in
      *'"f002"'*)
        printf '%s\n' '{"event":"complete","sources":["f002"],"description":"release cli complete"}'
        ;;
      *)
        printf '%s\n' '{"event":"intent","sources":["f001"],"description":"release cli explore intent"}'
        ;;
    esac
    ;;
  *)
    printf '%s\n' "unexpected prompt: $prompt" >&2
    exit 2
    ;;
esac
"#,
    )?;
    let config = format!(
        r#"db_path: {}
runtime:
  interval: 1
  max_workers: 1
  max_running_projects: 1
  max_project_workers: 1
  prompt_group: mock
tasks:
  bootstrap:
    timeout: 10
    conclude_timeout: 10
  reason:
    timeout: 10
    max_intents: 1
  explore:
    timeout: 10
    conclude_timeout: 10
worker_name: release-cli
bootstrap_intent: bootstrap
worker:
  kind: command
  program: {}
  args: []
"#,
        db_path.display(),
        worker_path.display()
    );
    std::fs::write(&config_path, config)
        .with_context(|| format!("writing {}", config_path.display()))?;

    let healthcheck = std::process::Command::new("target/release/clairvoyant")
        .args(["dispatch", "--config"])
        .arg(&config_path)
        .arg("--startup-healthcheck-only")
        .output()
        .context("running release dispatch --startup-healthcheck-only")?;
    if !healthcheck.status.success() {
        anyhow::bail!(
            "release dispatch --startup-healthcheck-only exited with {}: stdout={} stderr={}",
            healthcheck.status,
            String::from_utf8_lossy(&healthcheck.stdout),
            String::from_utf8_lossy(&healthcheck.stderr)
        );
    }
    let healthcheck_stdout = String::from_utf8_lossy(&healthcheck.stdout);
    if !healthcheck_stdout.contains("healthcheck ok: workers=worker container=false") {
        anyhow::bail!("unexpected release healthcheck output: {healthcheck_stdout}");
    }

    let created = release_request(
        &db_path,
        ClairvoyantRequest::CreateProject {
            body: CreateProjectRequest {
                title: "release dispatch".into(),
                origin: "start".into(),
                goal: "finish".into(),
                hints: None,
            },
        },
    )?;
    let project_id = match created {
        ClairvoyantResponse::ProjectDetail(detail) => detail.project.id,
        other => anyhow::bail!("unexpected release dispatch create response: {other:?}"),
    };

    let mut outcomes = Vec::new();
    for _ in 0..5 {
        let output = std::process::Command::new("target/release/clairvoyant")
            .args(["dispatch", "--config"])
            .arg(&config_path)
            .arg("--once")
            .output()
            .context("running release dispatch --once")?;
        if !output.status.success() {
            anyhow::bail!(
                "release dispatch --once exited with {}: stdout={} stderr={}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        outcomes.push(String::from_utf8_lossy(&output.stdout).trim().to_string());
    }
    for expected in [
        "CreatedBootstrapIntent",
        "ConcludedIntent",
        "CreatedReasonIntent",
        "CompletedByReason",
    ] {
        if !outcomes.iter().any(|outcome| outcome.contains(expected)) {
            anyhow::bail!("release dispatch outcomes missing {expected}: {outcomes:?}");
        }
    }

    let detail = match release_request(
        &db_path,
        ClairvoyantRequest::GetProject {
            project_id: project_id.clone(),
        },
    )? {
        ClairvoyantResponse::ProjectDetail(detail) => detail,
        other => anyhow::bail!("unexpected release dispatch get response: {other:?}"),
    };
    if !matches!(detail.project.status, ProjectStatus::Completed) {
        anyhow::bail!(
            "release dispatch project did not complete: {:?}",
            detail.project.status
        );
    }
    if !detail
        .facts
        .iter()
        .any(|fact| fact.id == "f001" && fact.description == "release cli bootstrap fact")
    {
        anyhow::bail!("release dispatch project is missing bootstrap fact");
    }
    if !detail
        .facts
        .iter()
        .any(|fact| fact.id == "f002" && fact.description == "release cli explored fact")
    {
        anyhow::bail!("release dispatch project is missing explored fact");
    }
    Ok(())
}

fn release_request(
    db_path: &std::path::Path,
    request: ClairvoyantRequest,
) -> anyhow::Result<ClairvoyantResponse> {
    let json = serde_json::to_string(&request)?;
    let output = std::process::Command::new("target/release/clairvoyant")
        .args(["request", "--db-path"])
        .arg(db_path)
        .arg("--json")
        .arg(json)
        .output()
        .context("running release clairvoyant request")?;
    if !output.status.success() {
        anyhow::bail!(
            "release clairvoyant request exited with {}: stdout={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    match serde_json::from_slice::<ClairvoyantEnvelope>(&output.stdout)
        .context("parsing release request envelope")?
    {
        ClairvoyantEnvelope::Ok { response } => Ok(*response),
        ClairvoyantEnvelope::Err { error } => anyhow::bail!(
            "release request returned error {}: {}",
            error.status,
            error.message
        ),
    }
}

fn write_executable_script(path: &std::path::Path, script: &str) -> anyhow::Result<()> {
    std::fs::write(path, script).with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(path)
            .with_context(|| format!("reading {}", path.display()))?
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(path, permissions)
            .with_context(|| format!("chmod +x {}", path.display()))?;
    }
    Ok(())
}

fn verify_compose_config() -> anyhow::Result<()> {
    let canonical = std::fs::read_to_string("docker-compose.yml")
        .context("reading canonical docker-compose.yml")?;
    let alternate = std::fs::read_to_string("docker-compose.yaml")
        .context("reading alternate docker-compose.yaml")?;
    if canonical != alternate {
        anyhow::bail!("docker-compose.yml and docker-compose.yaml must stay identical");
    }
    let output = std::process::Command::new("docker")
        .args(["compose", "-f", "docker-compose.yml", "config"])
        .output()
        .context("running docker compose config")?;
    if !output.status.success() {
        anyhow::bail!(
            "docker compose config exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let config: serde_yaml::Value =
        serde_yaml::from_slice(&output.stdout).context("parsing docker compose config output")?;
    let services = config
        .get("services")
        .and_then(serde_yaml::Value::as_mapping)
        .context("docker compose config is missing services")?;
    for (service_name, service) in services
        .iter()
        .filter_map(|(name, service)| Some((name.as_str()?, service.as_mapping()?)))
    {
        for forbidden in ["server", "frontend", "monitor"] {
            if service_name.contains(forbidden) {
                anyhow::bail!(
                    "compose service `{service_name}` violates CLI-only deployment; remove {forbidden} service"
                );
            }
        }
        if service
            .get(serde_yaml::Value::String("ports".to_string()))
            .is_some()
        {
            anyhow::bail!("compose service `{service_name}` must not expose ports");
        }
    }
    let service = services
        .get(serde_yaml::Value::String(
            "clairvoyant-dispatcher".to_string(),
        ))
        .context("docker compose config is missing clairvoyant-dispatcher service")?;
    let service = service
        .as_mapping()
        .context("clairvoyant-dispatcher compose service is not a mapping")?;
    let command = service
        .get(serde_yaml::Value::String("command".to_string()))
        .context("clairvoyant-dispatcher compose service is missing command")?;
    let command_text = match command {
        serde_yaml::Value::Sequence(items) => items
            .iter()
            .filter_map(serde_yaml::Value::as_str)
            .collect::<Vec<_>>()
            .join(" "),
        serde_yaml::Value::String(value) => value.clone(),
        other => anyhow::bail!("unsupported compose command shape: {other:?}"),
    };
    if !command_text.contains("dispatch") {
        anyhow::bail!("compose command must run the CLI dispatcher: {command_text}");
    }
    Ok(())
}

fn verify_dockerfile_cli_image() -> anyhow::Result<()> {
    let dockerfile = std::fs::read_to_string("Dockerfile").context("reading Dockerfile")?;
    if let Some(error) = dockerfile_cli_image_error(&dockerfile) {
        anyhow::bail!("{error}");
    }
    Ok(())
}

fn dockerfile_cli_image_error(dockerfile: &str) -> Option<String> {
    if !dockerfile.contains("FROM scratch") {
        return Some(
            "Dockerfile final image must be scratch for the CLI-only delivery".to_string(),
        );
    }
    if !dockerfile.contains(r#"ENTRYPOINT ["/clairvoyant"]"#) {
        return Some(
            "Dockerfile must use the clairvoyant binary as the image entrypoint".to_string(),
        );
    }
    for forbidden in ["EXPOSE", "CMD [\"serve\"", "CMD serve"] {
        if dockerfile.contains(forbidden) {
            return Some(format!(
                "Dockerfile contains forbidden CLI-only token `{forbidden}`"
            ));
        }
    }
    None
}

fn verify_runtime_example_args() -> anyhow::Result<()> {
    let output = std::process::Command::new("target/release/clairvoyant")
        .args([
            "runtime",
            "args",
            "--config",
            "docs/examples/dispatch/dispatch_example.yaml",
            "--project-id",
            "proj_999",
        ])
        .output()
        .context("running runtime args against docs/examples/dispatch/dispatch_example.yaml")?;
    if !output.status.success() {
        anyhow::bail!(
            "runtime args exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    for expected in [
        "create",
        "clairvoyant-proj_999",
        "--network bridge",
        "--workdir /runs/proj_999",
        "/runs/proj_999:/runs/proj_999",
        "--add-host example.com:0.0.0.0",
        "--env TSEC_SERVER_HOST=cybergym:8666",
        "ghcr.io/oritera/clairvoyant-worker-container:latest",
        "sleep infinity",
    ] {
        if !stdout.contains(expected) {
            anyhow::bail!("runtime args output is missing `{expected}`: {stdout}");
        }
    }

    with_temp_env(
        &[
            ("ANTHROPIC_MODEL", "dummy-claude-model"),
            ("ANTHROPIC_BASE_URL", "https://example.invalid"),
            ("ANTHROPIC_AUTH_TOKEN", "dummy-anthropic-key"),
        ],
        || {
            let output = std::process::Command::new("target/release/clairvoyant")
                .args([
                    "runtime",
                    "args",
                    "--config",
                    "docs/examples/dispatch/dispatch_example.yaml",
                    "--project-id",
                    "proj_999",
                    "--worker",
                    "claude-main",
                ])
                .output()
                .context("running worker-specific runtime args against docs/examples/dispatch/dispatch_example.yaml")?;
            if !output.status.success() {
                anyhow::bail!(
                    "worker-specific runtime args exited with {}: {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            let stdout = String::from_utf8_lossy(&output.stdout);
            for expected in [
                "--env ANTHROPIC_MODEL=dummy-claude-model",
                "--env ANTHROPIC_BASE_URL=https://example.invalid",
                "--env ANTHROPIC_AUTH_TOKEN=dummy-anthropic-key",
                "--env TSEC_SERVER_HOST=cybergym:8666",
            ] {
                if !stdout.contains(expected) {
                    anyhow::bail!(
                        "worker-specific runtime args output is missing `{expected}`: {stdout}"
                    );
                }
            }
            Ok(())
        },
    )?;

    let invalid = std::process::Command::new("target/release/clairvoyant")
        .args([
            "runtime",
            "args",
            "--config",
            "docs/examples/dispatch/dispatch_example.yaml",
            "--project-id",
            "../bad",
        ])
        .output()
        .context("running runtime args with an invalid project id")?;
    if invalid.status.success() {
        anyhow::bail!("runtime args accepted an invalid project id");
    }
    let stderr = String::from_utf8_lossy(&invalid.stderr);
    if !stderr.contains("invalid project_id") {
        anyhow::bail!("runtime args invalid project id error was unclear: {stderr}");
    }
    Ok(())
}

async fn verify_release_runtime_cli() -> anyhow::Result<()> {
    let dir = std::env::temp_dir().join(format!(
        "clairvoyant-xtask-release-runtime-{}-{}",
        std::process::id(),
        chrono_like_timestamp()
    ));
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let config_path = dir.join("dispatch.yaml");
    std::fs::write(
        &config_path,
        r#"container:
  image: rust:1-bookworm
  network_mode: none
  workdir: /tmp
"#,
    )
    .with_context(|| format!("writing {}", config_path.display()))?;

    let project_id = format!(
        "proj_xtask_release_runtime_{}_{}",
        std::process::id(),
        chrono_like_timestamp()
    );
    let runtime = DockerCliRuntime::new(RuntimeConfig {
        image: Some("rust:1-bookworm".to_string()),
        workdir: Some(std::path::PathBuf::from("/tmp")),
        volumes: Vec::new(),
        extra_hosts: Vec::new(),
        network_mode: Some("none".to_string()),
        network_disabled: true,
        env: BTreeMap::new(),
    });
    let spec = ContainerSpec::from_config(project_id.clone(), runtime.config())
        .context("building release runtime CLI container spec")?;
    let rendered = spec.rendered();
    let _ = runtime.remove(&rendered.name).await;

    let result = async {
        let ensure = std::process::Command::new("target/release/clairvoyant")
            .args(["runtime", "ensure-started", "--config"])
            .arg(&config_path)
            .args(["--project-id", &project_id])
            .output()
            .context("running release runtime ensure-started")?;
        if !ensure.status.success() {
            anyhow::bail!(
                "release runtime ensure-started exited with {}: stdout={} stderr={}",
                ensure.status,
                String::from_utf8_lossy(&ensure.stdout),
                String::from_utf8_lossy(&ensure.stderr)
            );
        }
        if String::from_utf8_lossy(&ensure.stdout).trim().is_empty() {
            anyhow::bail!("release runtime ensure-started did not print a container id");
        }

        let exec = std::process::Command::new("target/release/clairvoyant")
            .args(["runtime", "exec", "--config"])
            .arg(&config_path)
            .args(["--project-id", &project_id, "--program", "sh", "--"])
            .args(["-c", "printf 'release-runtime-cli\\n'"])
            .output()
            .context("running release runtime exec")?;
        if !exec.status.success() {
            anyhow::bail!(
                "release runtime exec exited with {}: stdout={} stderr={}",
                exec.status,
                String::from_utf8_lossy(&exec.stdout),
                String::from_utf8_lossy(&exec.stderr)
            );
        }
        let stdout = String::from_utf8_lossy(&exec.stdout);
        if stdout != "release-runtime-cli\n" {
            anyhow::bail!("unexpected release runtime exec stdout: {stdout:?}");
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;

    let cleanup = runtime.remove(&rendered.name).await;
    result?;
    cleanup.context("removing release runtime CLI container")?;
    Ok(())
}

async fn verify_docker_image_size() -> anyhow::Result<()> {
    let output = std::process::Command::new("docker")
        .args(["build", "-q", "."])
        .output()
        .context("building Docker image")?;
    if !output.status.success() {
        anyhow::bail!(
            "docker build exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let image_id = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if image_id.is_empty() {
        anyhow::bail!("docker build did not print an image id");
    }
    let output = std::process::Command::new("docker")
        .args(["image", "inspect", &image_id, "--format", "{{.Size}}"])
        .output()
        .with_context(|| format!("inspecting Docker image {image_id}"))?;
    if !output.status.success() {
        anyhow::bail!(
            "docker image inspect exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let size_text = String::from_utf8_lossy(&output.stdout);
    let size = size_text
        .trim()
        .parse::<u64>()
        .with_context(|| format!("parsing Docker image size `{}`", size_text.trim()))?;
    if size > 30 * 1024 * 1024 {
        anyhow::bail!("Docker image is too large: {size} bytes");
    }

    let output = std::process::Command::new("docker")
        .args(["run", "--rm", &image_id, "--help"])
        .output()
        .with_context(|| format!("running Docker image {image_id}"))?;
    if !output.status.success() {
        anyhow::bail!(
            "docker run --help exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let help = String::from_utf8_lossy(&output.stdout);
    for command in [
        "serve", "dispatch", "migrate", "request", "settings", "project", "intent", "hint",
        "reason", "asset", "runtime",
    ] {
        if !help.contains(command) {
            anyhow::bail!("Docker image help output is missing subcommand `{command}`");
        }
    }

    let config_path = std::fs::canonicalize("docs/examples/dispatch/dispatch_compose.yaml")
        .context("canonicalizing dispatch config")?;
    let data_dir = std::env::temp_dir().join(format!(
        "clairvoyant-docker-dispatch-{}-{}",
        std::process::id(),
        chrono_like_timestamp()
    ));
    std::fs::create_dir_all(&data_dir)
        .with_context(|| format!("creating Docker dispatch data dir {}", data_dir.display()))?;
    let run_result = std::process::Command::new("docker")
        .args(["run", "--rm"])
        .args([
            "-v",
            &format!(
                "{}:/etc/clairvoyant/dispatch.yaml:ro",
                config_path.display()
            ),
        ])
        .args(["-v", &format!("{}:/data", data_dir.display())])
        .arg(&image_id)
        .args([
            "dispatch",
            "--config",
            "/etc/clairvoyant/dispatch.yaml",
            "--startup-healthcheck-only",
        ])
        .output()
        .with_context(|| format!("running Docker image {image_id} dispatch healthcheck"));
    let cleanup_result = std::fs::remove_dir_all(&data_dir)
        .with_context(|| format!("removing Docker dispatch data dir {}", data_dir.display()));
    let output = run_result?;
    cleanup_result?;
    if !output.status.success() {
        anyhow::bail!(
            "docker run dispatch healthcheck exited with {}: stdout={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.contains("healthcheck ok: workers=worker container=false") {
        anyhow::bail!("unexpected Docker dispatch healthcheck output: {stdout}");
    }

    verify_real_docker_runtime_exec().await?;
    println!("docker image ok: image={image_id} size={size}");
    Ok(())
}

async fn verify_real_docker_runtime_exec() -> anyhow::Result<()> {
    let project_id = format!(
        "proj_xtask_runtime_{}_{}",
        std::process::id(),
        chrono_like_timestamp()
    );
    let runtime = DockerCliRuntime::new(RuntimeConfig {
        image: Some("rust:1-bookworm".to_string()),
        workdir: None,
        volumes: Vec::new(),
        extra_hosts: Vec::new(),
        network_mode: Some("none".to_string()),
        network_disabled: true,
        env: BTreeMap::new(),
    });
    let spec = ContainerSpec::from_config(project_id, runtime.config())
        .context("building runtime smoke container spec")?;
    let rendered = spec.rendered();
    let _ = runtime.remove(&rendered.name).await;
    runtime
        .ensure_started(&spec)
        .await
        .context("starting runtime smoke container")?;

    let result = async {
        let mut stream = runtime
            .exec_stream(
                &rendered.name,
                ProcessSpec {
                    program: "sh".to_string(),
                    args: vec![
                        "-c".to_string(),
                        "printf 'first\\n'; sleep 5; printf 'second\\n'".to_string(),
                    ],
                    env: BTreeMap::new(),
                    stdin: None,
                    cwd: None,
                },
            )
            .await
            .context("starting runtime smoke exec stream")?;
        let started = std::time::Instant::now();
        let first = tokio::time::timeout(std::time::Duration::from_secs(4), stream.next())
            .await
            .context("runtime smoke did not stream first line before process exit")?
            .context("runtime smoke exec produced no first line")?
            .context("runtime smoke first line failed")?;
        if first != "first" {
            anyhow::bail!("unexpected runtime smoke first line: {first:?}");
        }
        if started.elapsed() >= std::time::Duration::from_secs(5) {
            anyhow::bail!("runtime smoke first line was buffered until process exit");
        }
        let second = tokio::time::timeout(std::time::Duration::from_secs(8), stream.next())
            .await
            .context("runtime smoke did not stream second line")?
            .context("runtime smoke exec produced no second line")?
            .context("runtime smoke second line failed")?;
        if second != "second" {
            anyhow::bail!("unexpected runtime smoke second line: {second:?}");
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;

    let cleanup = runtime.remove(&rendered.name).await;
    result?;
    cleanup.context("removing runtime smoke container")?;
    Ok(())
}

async fn smoke() -> anyhow::Result<()> {
    let db_path = std::env::temp_dir().join(format!(
        "clairvoyant-xtask-smoke-{}-{}.db",
        std::process::id(),
        chrono_like_timestamp()
    ));
    let service = ClairvoyantService::open(&db_path)
        .await
        .with_context(|| format!("open {}", db_path.display()))?;
    let project_id = match service
        .handle(ClairvoyantRequest::CreateProject {
            body: CreateProjectRequest {
                title: "xtask smoke".into(),
                origin: "start".into(),
                goal: "finish".into(),
                hints: None,
            },
        })
        .await?
    {
        ClairvoyantResponse::ProjectDetail(detail) => detail.project.id,
        other => anyhow::bail!("unexpected create response: {other:?}"),
    };

    let dispatcher = Dispatcher::new(
        service.clone(),
        Arc::new(ScriptedWorker),
        DispatcherConfig {
            db_path: Some(db_path.clone()),
            worker: Some(WorkerConfig::Mock {
                description: "xtask smoke fact".into(),
                env: BTreeMap::new(),
            }),
            workers: Vec::new(),
            common_env: BTreeMap::new(),
            runtime: SchedulerRuntimeConfig {
                prompt_group: "mock".into(),
                ..Default::default()
            },
            tasks: Default::default(),
            container: None,
            worker_name: "xtask".into(),
            bootstrap_intent: "bootstrap".into(),
        },
    );

    let first = dispatcher.run_once().await?;
    let second = dispatcher.run_once().await?;
    let third = dispatcher.run_once().await?;
    let fourth = dispatcher.run_once().await?;
    let fifth = dispatcher.run_once().await?;
    match (&first, &second, &third, &fourth, &fifth) {
        (
            DispatchOutcome::CreatedBootstrapIntent { .. },
            DispatchOutcome::ConcludedIntent { fact_id, .. },
            DispatchOutcome::CreatedReasonIntent { intent_id, .. },
            DispatchOutcome::ConcludedIntent {
                intent_id: explored_intent,
                fact_id: explored_fact,
                ..
            },
            DispatchOutcome::CompletedByReason { .. },
        ) if fact_id == "f001" && intent_id == explored_intent && explored_fact == "f002" => {}
        other => anyhow::bail!("unexpected smoke outcomes: {other:?}"),
    }
    let detail = match service
        .handle(ClairvoyantRequest::GetProject {
            project_id: project_id.clone(),
        })
        .await?
    {
        ClairvoyantResponse::ProjectDetail(detail) => detail,
        other => anyhow::bail!("unexpected get response: {other:?}"),
    };
    if !matches!(detail.project.status, ProjectStatus::Completed) {
        anyhow::bail!(
            "smoke project did not complete: {:?}",
            detail.project.status
        );
    }
    if !detail
        .facts
        .iter()
        .any(|fact| fact.id == "f001" && fact.description == "xtask bootstrap fact")
    {
        anyhow::bail!("smoke project is missing bootstrap fact");
    }
    if !detail
        .facts
        .iter()
        .any(|fact| fact.id == "f002" && fact.description == "xtask explored fact")
    {
        anyhow::bail!("smoke project is missing explored fact");
    }
    println!("smoke ok: project={project_id} db={}", db_path.display());
    Ok(())
}

async fn bench_internal(
    writes: usize,
    reads: usize,
    concurrency: usize,
    p99_ms: u128,
    db_path: Option<PathBuf>,
) -> anyhow::Result<()> {
    if writes == 0 && reads == 0 {
        anyhow::bail!("bench-internal requires at least one read or write");
    }
    if concurrency == 0 {
        anyhow::bail!("bench-internal concurrency must be >= 1");
    }

    let db_path = db_path.unwrap_or_else(|| {
        std::env::temp_dir().join(format!(
            "clairvoyant-xtask-bench-internal-{}-{}.db",
            std::process::id(),
            chrono_like_timestamp()
        ))
    });
    let service = ClairvoyantService::open(&db_path)
        .await
        .with_context(|| format!("open {}", db_path.display()))?;
    let project_id = match service
        .handle(ClairvoyantRequest::CreateProject {
            body: CreateProjectRequest {
                title: "xtask internal bench".into(),
                origin: "start".into(),
                goal: "finish".into(),
                hints: None,
            },
        })
        .await?
    {
        ClairvoyantResponse::ProjectDetail(detail) => detail.project.id,
        other => anyhow::bail!("unexpected bench create response: {other:?}"),
    };

    let total = writes + reads;
    let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));
    let mut tasks = tokio::task::JoinSet::new();
    let bench_started = std::time::Instant::now();

    for index in 0..total {
        let permit = semaphore
            .clone()
            .acquire_owned()
            .await
            .context("bench semaphore closed")?;
        let service = service.clone();
        let project_id = project_id.clone();
        tasks.spawn(async move {
            let _permit = permit;
            let started = std::time::Instant::now();
            let response = if index < writes {
                service
                    .handle(ClairvoyantRequest::CreateIntent {
                        project_id,
                        body: CreateIntentRequest {
                            sources: vec!["origin".into()],
                            description: format!("bench intent {index}"),
                            creator: "xtask.bench".into(),
                            worker: None,
                        },
                    })
                    .await
            } else {
                service.handle(ClairvoyantRequest::ListProjects).await
            };
            response?;
            Ok::<BenchSample, anyhow::Error>(BenchSample {
                kind: if index < writes {
                    BenchOpKind::Write
                } else {
                    BenchOpKind::Read
                },
                micros: started.elapsed().as_micros(),
            })
        });
    }

    let mut read_latencies = Vec::with_capacity(reads);
    let mut write_latencies = Vec::with_capacity(writes);
    while let Some(result) = tasks.join_next().await {
        let sample = result.context("bench task panicked")??;
        match sample.kind {
            BenchOpKind::Read => read_latencies.push(sample.micros),
            BenchOpKind::Write => write_latencies.push(sample.micros),
        }
    }
    read_latencies.sort_unstable();
    write_latencies.sort_unstable();

    let read_p50 = percentile_micros(&read_latencies, 50);
    let read_p95 = percentile_micros(&read_latencies, 95);
    let read_p99 = percentile_micros(&read_latencies, 99);
    let write_p50 = percentile_micros(&write_latencies, 50);
    let write_p95 = percentile_micros(&write_latencies, 95);
    let write_p99 = percentile_micros(&write_latencies, 99);
    let elapsed = bench_started.elapsed();
    println!(
        "bench-internal ok: writes={writes} reads={reads} concurrency={concurrency} total={total} elapsed_ms={} read_p50_ms={:.3} read_p95_ms={:.3} read_p99_ms={:.3} write_p50_ms={:.3} write_p95_ms={:.3} write_p99_ms={:.3} db={}",
        elapsed.as_millis(),
        micros_to_ms(read_p50),
        micros_to_ms(read_p95),
        micros_to_ms(read_p99),
        micros_to_ms(write_p50),
        micros_to_ms(write_p95),
        micros_to_ms(write_p99),
        db_path.display()
    );

    let threshold_micros = p99_ms * 1_000;
    if reads > 0 && read_p99 > threshold_micros {
        anyhow::bail!(
            "bench-internal read p99 {:.3}ms exceeded threshold {p99_ms}ms",
            micros_to_ms(read_p99)
        );
    }
    Ok(())
}

struct BenchSample {
    kind: BenchOpKind,
    micros: u128,
}

enum BenchOpKind {
    Read,
    Write,
}

fn percentile_micros(sorted: &[u128], percentile: usize) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let index = ((sorted.len() * percentile).div_ceil(100)).saturating_sub(1);
    sorted[index.min(sorted.len() - 1)]
}

fn micros_to_ms(micros: u128) -> f64 {
    micros as f64 / 1_000.0
}

async fn bench_rss(
    samples: usize,
    interval_ms: u64,
    max_rust_mb: u64,
    compare_command: Option<String>,
) -> anyhow::Result<()> {
    if samples == 0 {
        anyhow::bail!("bench-rss samples must be >= 1");
    }
    if interval_ms == 0 {
        anyhow::bail!("bench-rss interval-ms must be >= 1");
    }

    let db_path = std::env::temp_dir().join(format!(
        "clairvoyant-xtask-rss-{}-{}.db",
        std::process::id(),
        chrono_like_timestamp()
    ));
    let rust_report = measure_process_rss(
        "rust",
        tokio::process::Command::new("target/release/clairvoyant")
            .arg("serve")
            .arg("--db-path")
            .arg(db_path),
        samples,
        interval_ms,
    )
    .await?;
    println!(
        "bench-rss rust: peak_mb={:.3} avg_mb={:.3} samples={} command=target/release/clairvoyant serve",
        kib_to_mib(rust_report.peak_kib),
        kib_to_mib(rust_report.avg_kib),
        rust_report.samples
    );
    if rust_report.peak_kib > max_rust_mb * 1024 {
        anyhow::bail!(
            "bench-rss rust peak {:.3}MiB exceeded threshold {max_rust_mb}MiB",
            kib_to_mib(rust_report.peak_kib)
        );
    }

    if let Some(command) = compare_command {
        let compare_report = measure_process_rss(
            "compare",
            tokio::process::Command::new("sh").arg("-c").arg(&command),
            samples,
            interval_ms,
        )
        .await?;
        let reduction = if compare_report.peak_kib == 0 {
            0.0
        } else {
            100.0 * (compare_report.peak_kib.saturating_sub(rust_report.peak_kib)) as f64
                / compare_report.peak_kib as f64
        };
        println!(
            "bench-rss compare: peak_mb={:.3} avg_mb={:.3} samples={} command={command}",
            kib_to_mib(compare_report.peak_kib),
            kib_to_mib(compare_report.avg_kib),
            compare_report.samples
        );
        println!("bench-rss reduction_vs_compare_peak={reduction:.1}%");
    }
    Ok(())
}

async fn measure_process_rss(
    label: &str,
    command: &mut tokio::process::Command,
    samples: usize,
    interval_ms: u64,
) -> anyhow::Result<RssReport> {
    let mut child = command
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning {label} RSS process"))?;
    let pid = child
        .id()
        .with_context(|| format!("{label} RSS process had no pid"))?;
    tokio::time::sleep(std::time::Duration::from_millis(interval_ms)).await;

    let mut rss_samples = Vec::with_capacity(samples);
    for _ in 0..samples {
        rss_samples.push(read_linux_process_tree_rss_kib(pid).with_context(|| {
            format!("reading process tree RSS for {label} pid {pid} from /proc")
        })?);
        tokio::time::sleep(std::time::Duration::from_millis(interval_ms)).await;
    }

    drop(child.stdin.take());
    let status = match tokio::time::timeout(std::time::Duration::from_secs(1), child.wait()).await {
        Ok(status) => Some(status.with_context(|| format!("waiting for {label} RSS process"))?),
        Err(_) => {
            child
                .kill()
                .await
                .with_context(|| format!("terminating long-running {label} RSS process"))?;
            None
        }
    };
    if let Some(status) = status {
        if !status.success() {
            let stderr = match child.stderr.take() {
                Some(mut stderr) => {
                    let mut buf = Vec::new();
                    use tokio::io::AsyncReadExt;
                    let _ = stderr.read_to_end(&mut buf).await;
                    String::from_utf8_lossy(&buf).into_owned()
                }
                None => String::new(),
            };
            anyhow::bail!("{label} RSS process exited with {status}: {stderr}");
        }
    }

    let peak_kib = rss_samples.iter().copied().max().unwrap_or(0);
    let avg_kib = rss_samples.iter().copied().sum::<u64>() / rss_samples.len() as u64;
    Ok(RssReport {
        peak_kib,
        avg_kib,
        samples,
    })
}

fn read_linux_process_tree_rss_kib(root_pid: u32) -> anyhow::Result<u64> {
    let mut children: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    for entry in std::fs::read_dir("/proc").context("reading /proc")? {
        let entry = entry.context("reading /proc entry")?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        if let Ok(ppid) = read_linux_ppid(pid) {
            children.entry(ppid).or_default().push(pid);
        }
    }

    let mut stack = vec![root_pid];
    let mut total = 0u64;
    while let Some(pid) = stack.pop() {
        if let Ok(rss) = read_linux_rss_kib(pid) {
            total += rss;
        }
        if let Some(child_pids) = children.get(&pid) {
            stack.extend(child_pids.iter().copied());
        }
    }
    Ok(total)
}

fn read_linux_ppid(pid: u32) -> anyhow::Result<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let end = stat
        .rfind(')')
        .context("process stat did not contain command delimiter")?;
    let rest = stat[end + 1..].trim();
    let mut fields = rest.split_whitespace();
    let _state = fields.next().context("process stat missing state")?;
    let ppid = fields
        .next()
        .context("process stat missing ppid")?
        .parse::<u32>()
        .context("parsing process ppid")?;
    Ok(ppid)
}

fn read_linux_rss_kib(pid: u32) -> anyhow::Result<u64> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kib = rest
                .split_whitespace()
                .next()
                .context("VmRSS had no numeric value")?
                .parse::<u64>()
                .context("parsing VmRSS KiB value")?;
            return Ok(kib);
        }
    }
    anyhow::bail!("VmRSS not found in /proc/{pid}/status")
}

fn kib_to_mib(kib: u64) -> f64 {
    kib as f64 / 1024.0
}

struct RssReport {
    peak_kib: u64,
    avg_kib: u64,
    samples: usize,
}

fn required_env_path(name: &str) -> anyhow::Result<std::path::PathBuf> {
    std::env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(std::path::PathBuf::from)
        .with_context(|| format!("{name} must name an existing local path"))
}

fn cybergym_audit(
    dataset: &str,
    sample: usize,
    write_script: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    let Some(config) = cybergym_dataset_config(dataset) else {
        anyhow::bail!(
            "unknown dataset `{dataset}`; expected one of sub_data, sub_data2, sub_data_jit"
        );
    };
    let data_dir = config.data_dir.as_path();
    let cybergym_root = required_env_path("CYBERGYM_ROOT")?;
    let runner_root = required_env_path("CYBERAGENT_ROOT")?;
    let env_file = required_env_path("CLAIRVOYANT_ENV_FILE")?;
    let mask_map_path = cybergym_root.join("mask_map.json");
    let runner_py = runner_root.join("batch_runner_cc_docker.py");
    let cybergym_python = cybergym_root.join(".venv/bin/python");
    let prompt_file = runner_root.join("prompt/RESEARCH_WORKFLOW_PROMPT_V4_MEMORY.md");
    let verify_script = cybergym_root.join("scripts/verify_agent_result.py");
    let poc_db = cybergym_root.join("server_poc/poc.db");

    require_path(data_dir, "dataset data_dir")?;
    require_path(&mask_map_path, "mask_map")?;
    require_path(&runner_py, "CyberAgent-cc runner")?;
    require_path(&cybergym_python, "CyberGym Python interpreter")?;
    require_path(&prompt_file, "CyberAgent-cc prompt")?;
    require_path(&verify_script, "CyberGym verifier")?;
    require_path(&poc_db, "CyberGym poc.db")?;

    let mask_map: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&mask_map_path)
            .with_context(|| format!("reading {}", mask_map_path.display()))?,
    )
    .context("parsing mask_map.json")?;
    let mask_entries = mask_map
        .as_object()
        .context("mask_map.json must be a JSON object")?;

    let mut tasks = discover_cybergym_tasks(data_dir)?;
    tasks.sort();
    if tasks.len() != config.expected_tasks {
        anyhow::bail!(
            "dataset `{dataset}` task count mismatch: found {} expected {}",
            tasks.len(),
            config.expected_tasks
        );
    }
    let missing_mask = tasks
        .iter()
        .filter(|task| !mask_entries.contains_key(*task))
        .take(10)
        .cloned()
        .collect::<Vec<_>>();
    if !missing_mask.is_empty() {
        anyhow::bail!("mask_map missing dataset tasks: {missing_mask:?}");
    }

    let env_status = if env_file.exists() {
        let env_text = std::fs::read_to_string(&env_file)
            .with_context(|| format!("reading {}", env_file.display()))?;
        let has_cybergym_key = env_file_has_key(&env_text, "CYBERGYM_API_KEY");
        let has_model_key = env_file_has_key(&env_text, "DEEPSEEK_API_KEY")
            || env_file_has_key(&env_text, "ANTHROPIC_AUTH_TOKEN")
            || env_file_has_key(&env_text, "ANTHROPIC_API_KEY");
        format!(
            "present model_key={} cybergym_key={}",
            key_status(has_model_key),
            key_status(has_cybergym_key)
        )
    } else {
        "missing".to_string()
    };
    let docker_image_status = docker_image_status("cc-runner:latest");

    let samples = tasks.iter().take(sample).cloned().collect::<Vec<_>>();
    let sample_task = samples
        .first()
        .map(String::as_str)
        .unwrap_or("<dataset-empty>");
    println!(
        "cybergym-audit ok: dataset={dataset} tasks={} expected={} mask_entries={} env_status={env_status}",
        tasks.len(),
        config.expected_tasks,
        mask_entries.len()
    );
    println!("cybergym-audit docker_image={docker_image_status}");
    println!("cybergym-audit runner={}", runner_py.display());
    println!("cybergym-audit python={}", cybergym_python.display());
    println!("cybergym-audit prompt={}", prompt_file.display());
    println!("cybergym-audit verifier={}", verify_script.display());
    println!("cybergym-audit poc_db={}", poc_db.display());
    println!("cybergym-audit sample_tasks={}", samples.join(","));
    println!(
        "cybergym-audit smoke_command=cd {} && {} batch_runner_cc_docker.py --tasks-dir {} --data-dir {} --server http://localhost:8666 --difficulty level1 --mask-map {} --env-file {} --model deepseek-v4-pro --prompt-file {} --docker-image cc-runner:latest --parallel 1 --timeout 1200 --max-turns 100 --task-id {} --results-file ./batch_results_clairvoyant_smoke.json",
        runner_root.display(),
        cybergym_python.display(),
        data_dir.display(),
        data_dir.display(),
        mask_map_path.display(),
        env_file.display(),
        prompt_file.display(),
        sample_task
    );
    if let Some(script_path) = write_script {
        let script = render_cybergym_smoke_script(CybergymSmokeScript {
            dataset,
            tasks: &samples,
            runner_root: &runner_root,
            cybergym_python: &cybergym_python,
            data_dir,
            mask_map_path: &mask_map_path,
            env_file: &env_file,
            prompt_file: &prompt_file,
        })?;
        if let Some(parent) = script_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
        }
        std::fs::write(script_path, script)
            .with_context(|| format!("writing {}", script_path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = std::fs::metadata(script_path)
                .with_context(|| format!("reading {}", script_path.display()))?
                .permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(script_path, permissions)
                .with_context(|| format!("chmod +x {}", script_path.display()))?;
        }
        println!("cybergym-audit wrote_script={}", script_path.display());
    }
    Ok(())
}

struct CybergymSmokeScript<'a> {
    dataset: &'a str,
    tasks: &'a [String],
    runner_root: &'a std::path::Path,
    cybergym_python: &'a std::path::Path,
    data_dir: &'a std::path::Path,
    mask_map_path: &'a std::path::Path,
    env_file: &'a std::path::Path,
    prompt_file: &'a std::path::Path,
}

fn render_cybergym_smoke_script(input: CybergymSmokeScript<'_>) -> anyhow::Result<String> {
    if input.tasks.is_empty() {
        anyhow::bail!("cannot render CyberGym smoke script without sample tasks");
    }
    let task_list = input
        .tasks
        .iter()
        .map(|task| format!("  {}", shell_quote(task)))
        .collect::<Vec<_>>()
        .join("\n");
    Ok(format!(
        r#"#!/usr/bin/env bash
set -euo pipefail

ENV_FILE={env_file}
if [[ ! -f "$ENV_FILE" ]]; then
  echo "missing env file: $ENV_FILE" >&2
  exit 2
fi
if ! grep -Eq '^(export[[:space:]]+)?(DEEPSEEK_API_KEY|ANTHROPIC_AUTH_TOKEN|ANTHROPIC_API_KEY)=' "$ENV_FILE"; then
  echo "missing model API key in $ENV_FILE" >&2
  exit 2
fi
if ! grep -Eq '^(export[[:space:]]+)?CYBERGYM_API_KEY=' "$ENV_FILE"; then
  echo "warning: CYBERGYM_API_KEY missing; runner smoke can start, but official verification is unavailable" >&2
fi

cd {runner_root}

tasks=(
{task_list}
)

for task_id in "${{tasks[@]}}"; do
  safe_task_id="${{task_id//:/_}}"
  {cybergym_python} batch_runner_cc_docker.py \
    --tasks-dir {data_dir} \
    --data-dir {data_dir} \
    --server http://localhost:8666 \
    --difficulty level1 \
    --mask-map {mask_map} \
    --env-file "$ENV_FILE" \
    --model deepseek-v4-pro \
    --prompt-file {prompt_file} \
    --docker-image cc-runner:latest \
    --parallel 1 \
    --timeout 1200 \
    --max-turns 100 \
    --task-id "$task_id" \
    --results-file "./batch_results_clairvoyant_{dataset}_${{safe_task_id}}.json"
done
"#,
        env_file = shell_quote(input.env_file.display().to_string().as_str()),
        runner_root = shell_quote(input.runner_root.display().to_string().as_str()),
        cybergym_python = shell_quote(input.cybergym_python.display().to_string().as_str()),
        task_list = task_list,
        data_dir = shell_quote(input.data_dir.display().to_string().as_str()),
        mask_map = shell_quote(input.mask_map_path.display().to_string().as_str()),
        prompt_file = shell_quote(input.prompt_file.display().to_string().as_str()),
        dataset = input.dataset,
    ))
}

fn cybergym_verify(
    results_file: &std::path::Path,
    agent_ids: &[String],
    server: &str,
    preflight_only: bool,
) -> anyhow::Result<()> {
    let cybergym_root = required_env_path("CYBERGYM_ROOT")?;
    let env_file = required_env_path("CLAIRVOYANT_ENV_FILE")?;
    let cybergym_python = cybergym_root.join(".venv/bin/python");
    let verify_script = cybergym_root.join("scripts/verify_agent_result.py");
    let poc_db = cybergym_root.join("server_poc/poc.db");

    require_path(results_file, "CyberGym results file")?;
    require_path(&cybergym_python, "CyberGym Python interpreter")?;
    require_path(&verify_script, "CyberGym verifier")?;
    require_path(&poc_db, "CyberGym poc.db")?;
    require_path(&env_file, "fixed env file")?;

    let result_agent_ids = if agent_ids.is_empty() {
        extract_cybergym_agent_ids(results_file)?
    } else {
        dedupe_strings(agent_ids.iter().cloned())
    };
    if result_agent_ids.is_empty() {
        anyhow::bail!(
            "no agent ids found; pass --agent-id or use a CyberAgent results JSON with results[].agent_id"
        );
    }

    let env_text = std::fs::read_to_string(&env_file)
        .with_context(|| format!("reading {}", env_file.display()))?;
    let cybergym_key = env_file_value(&env_text, "CYBERGYM_API_KEY");
    println!(
        "cybergym-verify preflight: results_file={} agents={} cybergym_key={} verifier={} poc_db={}",
        results_file.display(),
        result_agent_ids.join(","),
        key_status(cybergym_key.is_some()),
        verify_script.display(),
        poc_db.display()
    );
    if preflight_only {
        return Ok(());
    }
    let Some(cybergym_key) = cybergym_key else {
        anyhow::bail!(
            "CYBERGYM_API_KEY is missing from {}; official verification cannot run",
            env_file.display()
        );
    };

    for agent_id in result_agent_ids {
        let output = std::process::Command::new(&cybergym_python)
            .arg(&verify_script)
            .args(["--server", server])
            .args(["--agent_id", &agent_id])
            .arg("--pocdb_path")
            .arg(&poc_db)
            .env("CYBERGYM_API_KEY", &cybergym_key)
            .output()
            .with_context(|| format!("running CyberGym verifier for agent {agent_id}"))?;
        println!(
            "cybergym-verify agent_id={agent_id} status={}",
            output.status
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        if !stdout.trim().is_empty() {
            println!("{stdout}");
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.trim().is_empty() {
            eprintln!("{stderr}");
        }
        if !output.status.success() {
            anyhow::bail!("CyberGym verifier failed for agent {agent_id}");
        }
    }
    Ok(())
}

fn extract_cybergym_agent_ids(results_file: &std::path::Path) -> anyhow::Result<Vec<String>> {
    let json: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(results_file)
            .with_context(|| format!("reading {}", results_file.display()))?,
    )
    .with_context(|| format!("parsing {}", results_file.display()))?;
    let Some(results) = json.get("results").and_then(serde_json::Value::as_array) else {
        anyhow::bail!(
            "{} does not contain a results array",
            results_file.display()
        );
    };
    Ok(dedupe_strings(results.iter().filter_map(|result| {
        result
            .get("agent_id")
            .and_then(serde_json::Value::as_str)
            .filter(|agent_id| !agent_id.is_empty())
            .map(ToOwned::to_owned)
    })))
}

fn dedupe_strings(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut deduped = Vec::new();
    for value in values {
        if !deduped.contains(&value) {
            deduped.push(value);
        }
    }
    deduped
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r#"'\''"#))
}

fn env_file_has_key(env_text: &str, key: &str) -> bool {
    env_text.lines().any(|line| {
        let line = line.trim_start();
        line.strip_prefix("export ")
            .unwrap_or(line)
            .starts_with(&format!("{key}="))
    })
}

fn env_file_value(env_text: &str, key: &str) -> Option<String> {
    env_text.lines().find_map(|line| {
        let line = line.trim_start();
        if line.starts_with('#') {
            return None;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let value = line.strip_prefix(&format!("{key}="))?;
        Some(unquote_env_value(value.trim()))
    })
}

fn unquote_env_value(value: &str) -> String {
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if (bytes[0] == b'\'' && bytes[value.len() - 1] == b'\'')
            || (bytes[0] == b'"' && bytes[value.len() - 1] == b'"')
        {
            return value[1..value.len() - 1].to_string();
        }
    }
    value.to_string()
}

fn key_status(present: bool) -> &'static str {
    if present {
        "present"
    } else {
        "missing"
    }
}

fn docker_image_status(image: &str) -> String {
    match std::process::Command::new("docker")
        .args(["image", "inspect", image, "--format", "{{.Id}} {{.Size}}"])
        .output()
    {
        Ok(output) if output.status.success() => {
            let info = String::from_utf8_lossy(&output.stdout);
            format!("present {}", info.trim())
        }
        Ok(_) => "missing".to_string(),
        Err(error) => format!("unknown ({error})"),
    }
}

struct CybergymDatasetConfig {
    data_dir: std::path::PathBuf,
    expected_tasks: usize,
}

fn cybergym_dataset_config(dataset: &str) -> Option<CybergymDatasetConfig> {
    let base = std::env::var_os("CYBERGYM_DATA_ROOT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("cybergym/data/subdataset"));
    let (directory, expected_tasks) = match dataset {
        "sub_data" => ("sub_data", 69),
        "sub_data2" => ("sub_data2", 88),
        "sub_data_jit" => ("sub_data_jit", 84),
        _ => return None,
    };
    Some(CybergymDatasetConfig {
        data_dir: base.join(directory),
        expected_tasks,
    })
}

fn require_path(path: &std::path::Path, label: &str) -> anyhow::Result<()> {
    if !path.exists() {
        anyhow::bail!("{label} is missing: {}", path.display());
    }
    Ok(())
}

fn discover_cybergym_tasks(data_dir: &std::path::Path) -> anyhow::Result<Vec<String>> {
    let mut tasks = Vec::new();
    for domain in
        std::fs::read_dir(data_dir).with_context(|| format!("reading {}", data_dir.display()))?
    {
        let domain =
            domain.with_context(|| format!("reading domain under {}", data_dir.display()))?;
        if !domain
            .file_type()
            .context("reading domain file type")?
            .is_dir()
        {
            continue;
        }
        let domain_name = domain.file_name().to_string_lossy().into_owned();
        for task in std::fs::read_dir(domain.path())
            .with_context(|| format!("reading {}", domain.path().display()))?
        {
            let task =
                task.with_context(|| format!("reading task under {}", domain.path().display()))?;
            let file_type = task.file_type().context("reading task file type")?;
            if !(file_type.is_dir() || file_type.is_symlink()) {
                continue;
            }
            let task_id = task.file_name().to_string_lossy().into_owned();
            if file_type.is_symlink() {
                let target = std::fs::read_link(task.path())
                    .with_context(|| format!("reading symlink {}", task.path().display()))?;
                if !target.exists() {
                    anyhow::bail!(
                        "task symlink target missing: {} -> {}",
                        task.path().display(),
                        target.display()
                    );
                }
            }
            tasks.push(format!("{domain_name}:{task_id}"));
        }
    }
    Ok(tasks)
}

#[derive(Debug)]
struct ScriptedWorker;

#[async_trait]
impl Worker for ScriptedWorker {
    async fn run(
        &self,
        prompt: &str,
        _context: WorkerContext,
    ) -> Result<Vec<WorkerEvent>, WorkerError> {
        let prompt: serde_json::Value = serde_json::from_str(prompt)?;
        match prompt.get("phase").and_then(serde_json::Value::as_str) {
            Some("bootstrap") => Ok(vec![WorkerEvent::Done {
                description: "xtask bootstrap fact".into(),
                complete: false,
            }]),
            Some("reason") => {
                let fact_ids = prompt
                    .get("fact_ids")
                    .and_then(serde_json::Value::as_array)
                    .map(|facts| {
                        facts
                            .iter()
                            .filter_map(serde_json::Value::as_str)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                if fact_ids.contains(&"f002") {
                    Ok(vec![WorkerEvent::Complete {
                        sources: vec!["f002".into()],
                        description: "xtask complete".into(),
                    }])
                } else {
                    Ok(vec![WorkerEvent::Intent {
                        sources: vec!["f001".into()],
                        description: "xtask explore intent".into(),
                    }])
                }
            }
            Some("explore_execute") => Ok(vec![WorkerEvent::Done {
                description: "xtask explored fact".into(),
                complete: false,
            }]),
            Some(phase) => Err(WorkerError::Failed(format!(
                "unexpected scripted smoke phase: {phase}"
            ))),
            None => Err(WorkerError::Failed(
                "scripted smoke prompt is missing phase".to_string(),
            )),
        }
    }
}

fn chrono_like_timestamp() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_guard_recurses_into_nested_rust_sources_and_tests() {
        let root = std::env::temp_dir().join(format!(
            "clairvoyant-xtask-network-guard-{}-{}",
            std::process::id(),
            chrono_like_timestamp()
        ));
        std::fs::create_dir_all(root.join("crate/src/nested")).expect("create nested src");
        std::fs::create_dir_all(root.join("crate/tests")).expect("create tests");
        std::fs::create_dir_all(root.join("crate/static")).expect("create static");
        std::fs::write(root.join("crate/Cargo.toml"), "[package]\nname = \"x\"\n")
            .expect("write manifest");
        std::fs::write(root.join("crate/src/lib.rs"), "").expect("write lib");
        std::fs::write(root.join("crate/src/nested/mod.rs"), "").expect("write nested module");
        std::fs::write(root.join("crate/tests/protocol.rs"), "").expect("write integration test");
        std::fs::write(root.join("crate/static/generated.rs"), "").expect("write static file");

        let mut files = walk_network_guard_files(&root)
            .expect("walk network guard files")
            .into_iter()
            .map(|path| {
                path.strip_prefix(&root)
                    .expect("strip root")
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect::<Vec<_>>();
        files.sort();

        assert_eq!(
            files,
            vec![
                "crate/Cargo.toml",
                "crate/src/lib.rs",
                "crate/src/nested/mod.rs",
                "crate/tests/protocol.rs",
            ]
        );

        std::fs::remove_dir_all(root).expect("remove temp tree");
    }

    #[test]
    fn network_guard_flags_standard_and_tokio_network_entry_points() {
        for source in [
            "use std::net::TcpListener;",
            "let _addr: std::net::SocketAddr;",
            "use tokio::net::TcpStream;",
            "use std::net::ToSocketAddrs;",
            "axum = \"0.7\"",
            "bollard = \"0.17\"",
            "hyper = \"1\"",
            "reqwest = \"0.12\"",
            "tower = \"0.5\"",
        ] {
            assert!(
                forbidden_network_token(source).is_some(),
                "source should be rejected: {source}"
            );
        }

        assert!(forbidden_network_token("use tokio::io::DuplexStream;").is_none());
    }

    #[test]
    fn cybergym_results_agent_ids_are_extracted_and_deduped() {
        let path = std::env::temp_dir().join(format!(
            "clairvoyant-xtask-cybergym-results-{}-{}.json",
            std::process::id(),
            chrono_like_timestamp()
        ));
        std::fs::write(
            &path,
            r#"{
              "results": [
                {"task_id": "arvo:1", "agent_id": "agent-a"},
                {"task_id": "arvo:2", "agent_id": "agent-b"},
                {"task_id": "arvo:3", "agent_id": "agent-a"},
                {"task_id": "arvo:4", "agent_id": ""}
              ]
            }"#,
        )
        .expect("write results fixture");

        let agent_ids = extract_cybergym_agent_ids(&path).expect("extract agent ids");

        assert_eq!(agent_ids, vec!["agent-a", "agent-b"]);
        std::fs::remove_file(path).expect("remove results fixture");
    }

    #[test]
    fn cybergym_results_without_results_array_are_rejected() {
        let path = std::env::temp_dir().join(format!(
            "clairvoyant-xtask-cybergym-bad-results-{}-{}.json",
            std::process::id(),
            chrono_like_timestamp()
        ));
        std::fs::write(&path, r#"{"agent_id": "agent-a"}"#).expect("write bad fixture");

        let error = extract_cybergym_agent_ids(&path)
            .expect_err("missing results array should be rejected")
            .to_string();

        assert!(error.contains("does not contain a results array"));
        std::fs::remove_file(path).expect("remove bad fixture");
    }

    #[test]
    fn env_file_value_reads_exported_and_quoted_values_without_printing_them() {
        let env_text = r#"
            # CYBERGYM_API_KEY=ignored
            export DEEPSEEK_API_KEY='deepseek-secret'
            CYBERGYM_API_KEY="cybergym-secret"
        "#;

        assert_eq!(
            env_file_value(env_text, "DEEPSEEK_API_KEY").as_deref(),
            Some("deepseek-secret")
        );
        assert_eq!(
            env_file_value(env_text, "CYBERGYM_API_KEY").as_deref(),
            Some("cybergym-secret")
        );
        assert_eq!(env_file_value(env_text, "ANTHROPIC_API_KEY"), None);
    }

    #[test]
    fn prompt_mirror_check_detects_file_content_drift() {
        let root = std::env::temp_dir().join(format!(
            "clairvoyant-xtask-prompt-mirror-{}-{}",
            std::process::id(),
            chrono_like_timestamp()
        ));
        let source = root.join("source");
        let mirror = root.join("mirror");
        std::fs::create_dir_all(&source).expect("create source");
        std::fs::create_dir_all(&mirror).expect("create mirror");
        std::fs::write(source.join("reason.md"), "same").expect("write source");
        std::fs::write(mirror.join("reason.md"), "same").expect("write mirror");

        require_prompt_files_match(&source, &mirror).expect("matching prompts");

        std::fs::write(mirror.join("reason.md"), "different").expect("rewrite mirror");
        let error = require_prompt_files_match(&source, &mirror)
            .expect_err("content drift should be rejected")
            .to_string();
        assert!(error.contains("prompt mirror differs"));

        std::fs::remove_dir_all(root).expect("remove prompt mirror fixture");
    }

    #[test]
    fn unsupported_worker_kind_guard_finds_codex_and_pi() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            r#"
worker:
  kind: codex
workers:
  - name: pi-worker
    type: pi
  - name: claude-main
    type: claudecode
"#,
        )
        .expect("parse fixture");
        let mut violations = Vec::new();
        collect_unsupported_worker_kind_paths(&yaml, "fixture.yaml", &mut violations);

        assert_eq!(
            violations,
            vec![
                "fixture.yaml.worker.kind=codex".to_string(),
                "fixture.yaml.workers[0].type=pi".to_string(),
            ]
        );
    }

    #[test]
    fn static_vendor_mirror_check_allows_index_divergence_only() {
        let root = std::env::temp_dir().join(format!(
            "clairvoyant-xtask-static-mirror-{}-{}",
            std::process::id(),
            chrono_like_timestamp()
        ));
        let source = root.join("source");
        let mirror = root.join("mirror");
        std::fs::create_dir_all(source.join("vendor")).expect("create source vendor");
        std::fs::create_dir_all(mirror.join("vendor")).expect("create mirror vendor");
        std::fs::write(source.join("favicon.svg"), "same").expect("write source favicon");
        std::fs::write(mirror.join("favicon.svg"), "same").expect("write mirror favicon");
        std::fs::write(source.join("vendor/lib.js"), "same").expect("write source vendor");
        std::fs::write(mirror.join("vendor/lib.js"), "same").expect("write mirror vendor");
        std::fs::write(source.join("index.html"), "old api").expect("write source index");
        std::fs::write(mirror.join("index.html"), "new api").expect("write mirror index");

        require_static_vendor_files_match(&source, &mirror).expect("matching vendor assets");

        std::fs::write(mirror.join("vendor/lib.js"), "changed").expect("rewrite mirror vendor");
        let error = require_static_vendor_files_match(&source, &mirror)
            .expect_err("vendor drift should be rejected")
            .to_string();
        assert!(error.contains("static vendor mirror differs"));

        std::fs::remove_dir_all(root).expect("remove static mirror fixture");
    }

    #[test]
    fn release_cold_start_cleanup_removes_sqlite_sidecars() {
        let root = std::env::temp_dir().join(format!(
            "clairvoyant-xtask-startup-cleanup-{}-{}",
            std::process::id(),
            chrono_like_timestamp()
        ));
        std::fs::create_dir_all(&root).expect("create cleanup fixture");
        let db = root.join("startup.db");
        for path in [
            &db,
            &db.with_extension("db-shm"),
            &db.with_extension("db-wal"),
        ] {
            std::fs::write(path, "temporary").expect("write cleanup fixture file");
        }

        cleanup_sqlite_files(&db);

        assert!(!db.exists());
        assert!(!db.with_extension("db-shm").exists());
        assert!(!db.with_extension("db-wal").exists());
        std::fs::remove_dir_all(root).expect("remove cleanup fixture");
    }

    #[test]
    fn dockerfile_cli_image_guard_rejects_exposed_http_service() {
        let dockerfile = r#"
FROM scratch
COPY clairvoyant /clairvoyant
EXPOSE 8000
ENTRYPOINT ["/clairvoyant"]
"#;

        let error = dockerfile_cli_image_error(dockerfile)
            .expect("exposed Dockerfile should violate CLI-only guard");
        assert!(error.contains("EXPOSE"));

        assert!(dockerfile_cli_image_error(
            r#"
FROM rust:1-bookworm AS builder
RUN cargo build --release --bin clairvoyant
FROM scratch
COPY --from=builder /src/target/x86_64-unknown-linux-musl/release/clairvoyant /clairvoyant
ENTRYPOINT ["/clairvoyant"]
"#
        )
        .is_none());
    }
}
