use clairvoyant_core::{
    ClairvoyantRequest, ClairvoyantResponse, CreateIntentRequest, CreateProjectRequest,
};
use clairvoyant_server::ClairvoyantService;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::str::FromStr;
use tokio::process::Command;

#[tokio::test]
async fn migrate_cli_imports_python_database_and_rebuilds_ids() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let from = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-old-{}-{nonce}.db",
        std::process::id()
    ));
    let to = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-new-{}-{nonce}.db",
        std::process::id()
    ));
    create_python_fixture(&from).await;

    let output = Command::new(env!("CARGO_BIN_EXE_clairvoyant"))
        .args(["migrate", "--from-python"])
        .arg(&from)
        .arg("--to")
        .arg(&to)
        .output()
        .await
        .expect("run migrate");
    assert!(
        output.status.success(),
        "migrate failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("migrated projects=1 facts=3 intents=1 intent_sources=1 hints=1"));

    let service = ClairvoyantService::open(&to)
        .await
        .expect("open migrated db");
    let detail = match service
        .handle(ClairvoyantRequest::GetProject {
            project_id: "proj_007".to_string(),
        })
        .await
        .expect("get migrated project")
    {
        ClairvoyantResponse::ProjectDetail(detail) => detail,
        other => panic!("unexpected response {other:?}"),
    };
    assert_eq!(detail.project.title, "old");
    let reason = detail.project.reason.expect("migrated reason lease");
    assert_eq!(reason.worker, "reasoner");
    assert_eq!(reason.trigger, "facts=3 hints=1 open_intents=0");
    assert_eq!(reason.started_at, 1_767_225_604_000);
    assert_eq!(reason.last_heartbeat_at, 1_767_225_605_000);
    assert_eq!(detail.intents[0].sources, vec!["origin"]);
    assert_eq!(detail.intents[0].target_fact.as_deref(), Some("f001"));
    assert_eq!(detail.hints[0].created_at, 1_767_225_603_000);

    let settings = match service
        .handle(ClairvoyantRequest::GetSettings)
        .await
        .expect("get migrated settings")
    {
        ClairvoyantResponse::Settings(settings) => settings,
        other => panic!("unexpected response {other:?}"),
    };
    assert_eq!(settings.intent_timeout, 30);
    assert_eq!(settings.reason_timeout, 45);

    let next = match service
        .handle(ClairvoyantRequest::CreateIntent {
            project_id: "proj_007".to_string(),
            body: CreateIntentRequest {
                sources: vec!["f001".to_string()],
                description: "next".to_string(),
                creator: "cli-test".to_string(),
                worker: None,
            },
        })
        .await
        .expect("create next intent")
    {
        ClairvoyantResponse::Intent(intent) => intent,
        other => panic!("unexpected response {other:?}"),
    };
    assert_eq!(next.id, "i002");

    let next_project = match service
        .handle(ClairvoyantRequest::CreateProject {
            body: CreateProjectRequest {
                title: "next project".to_string(),
                origin: "o".to_string(),
                goal: "g".to_string(),
                hints: None,
            },
        })
        .await
        .expect("create next project")
    {
        ClairvoyantResponse::ProjectDetail(detail) => detail,
        other => panic!("unexpected response {other:?}"),
    };
    assert_eq!(next_project.project.id, "proj_008");
}

#[tokio::test]
async fn migrate_cli_accepts_literal_url_characters_in_database_paths() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "clairvoyant-cli-migrate-url-paths-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let from = dir.join("python?source#old.db");
    let to = dir.join("rust?target#new.db");
    create_python_fixture(&from).await;

    let output = Command::new(env!("CARGO_BIN_EXE_clairvoyant"))
        .args(["migrate", "--from-python"])
        .arg(&from)
        .arg("--to")
        .arg(&to)
        .output()
        .await
        .expect("run migrate");
    assert!(
        output.status.success(),
        "migrate failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(from.exists(), "source path should be used literally");
    assert!(to.exists(), "target path should be used literally");
    let service = ClairvoyantService::open(&to)
        .await
        .expect("open migrated db");
    let detail = match service
        .handle(ClairvoyantRequest::GetProject {
            project_id: "proj_007".to_string(),
        })
        .await
        .expect("get migrated project")
    {
        ClairvoyantResponse::ProjectDetail(detail) => detail,
        other => panic!("unexpected response {other:?}"),
    };
    assert_eq!(detail.project.title, "old");
    drop(service);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn migrate_cli_rejects_dirty_target_database() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let from = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-dirty-old-{}-{nonce}.db",
        std::process::id()
    ));
    let to = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-dirty-new-{}-{nonce}.db",
        std::process::id()
    ));
    create_python_fixture(&from).await;

    let target = ClairvoyantService::open(&to).await.expect("open target");
    let project_id = match target
        .handle(ClairvoyantRequest::CreateProject {
            body: CreateProjectRequest {
                title: "temporary".to_string(),
                origin: "o".to_string(),
                goal: "g".to_string(),
                hints: None,
            },
        })
        .await
        .expect("create target project")
    {
        ClairvoyantResponse::ProjectDetail(detail) => detail.project.id,
        other => panic!("unexpected response {other:?}"),
    };
    target
        .handle(ClairvoyantRequest::DeleteProject { project_id })
        .await
        .expect("delete target project");
    drop(target);

    let output = Command::new(env!("CARGO_BIN_EXE_clairvoyant"))
        .args(["migrate", "--from-python"])
        .arg(&from)
        .arg("--to")
        .arg(&to)
        .output()
        .await
        .expect("run migrate");
    assert!(
        !output.status.success(),
        "dirty target migration unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("counters contain non-default rows"),
        "unexpected stderr: {stderr}"
    );
}

#[tokio::test]
async fn migrate_cli_rejects_bad_source_before_creating_target() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let from = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-bad-source-{}-{nonce}.db",
        std::process::id()
    ));
    let to = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-bad-target-{}-{nonce}.db",
        std::process::id()
    ));

    let options = SqliteConnectOptions::from_str(&format!("sqlite://{}", from.display()))
        .expect("options")
        .create_if_missing(true);
    let old = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("open bad source db");
    sqlx::query("CREATE TABLE settings (intent_timeout INTEGER NOT NULL DEFAULT 15)")
        .execute(&old)
        .await
        .expect("create incomplete settings table");
    old.close().await;

    let output = Command::new(env!("CARGO_BIN_EXE_clairvoyant"))
        .args(["migrate", "--from-python"])
        .arg(&from)
        .arg("--to")
        .arg(&to)
        .output()
        .await
        .expect("run migrate");
    assert!(
        !output.status.success(),
        "bad source migration unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("source database is not a Python Clairvoyant database"),
        "unexpected stderr: {stderr}"
    );
    assert!(
        stderr.contains("table settings is missing columns: reason_timeout"),
        "unexpected stderr: {stderr}"
    );
    assert!(
        !to.exists(),
        "target database was created before source preflight completed"
    );
}

#[tokio::test]
async fn migrate_cli_rejects_invalid_python_timestamp_before_creating_target() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let from = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-bad-ts-old-{}-{nonce}.db",
        std::process::id()
    ));
    let to = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-bad-ts-new-{}-{nonce}.db",
        std::process::id()
    ));
    create_python_fixture(&from).await;

    let options =
        SqliteConnectOptions::from_str(&format!("sqlite://{}", from.display())).expect("options");
    let old = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("open old db");
    sqlx::query("UPDATE projects SET created_at = 'not-a-timestamp' WHERE id = 'proj_007'")
        .execute(&old)
        .await
        .expect("corrupt timestamp");
    old.close().await;

    let output = Command::new(env!("CARGO_BIN_EXE_clairvoyant"))
        .args(["migrate", "--from-python"])
        .arg(&from)
        .arg("--to")
        .arg(&to)
        .output()
        .await
        .expect("run migrate");
    assert!(
        !output.status.success(),
        "bad timestamp migration unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid python timestamp not-a-timestamp"),
        "unexpected stderr: {stderr}"
    );

    assert!(
        !to.exists(),
        "target database was created before timestamp preflight completed"
    );
}

#[tokio::test]
async fn migrate_cli_rejects_python_intent_concluded_before_created_before_creating_target() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let from = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-bad-time-order-old-{}-{nonce}.db",
        std::process::id()
    ));
    let to = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-bad-time-order-new-{}-{nonce}.db",
        std::process::id()
    ));
    create_python_fixture(&from).await;

    let options =
        SqliteConnectOptions::from_str(&format!("sqlite://{}", from.display())).expect("options");
    let old = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("open old db");
    sqlx::query("UPDATE intents SET concluded_at = '2025-12-31T23:59:59Z' WHERE id = 'i001'")
        .execute(&old)
        .await
        .expect("corrupt timestamp order");
    old.close().await;

    let output = Command::new(env!("CARGO_BIN_EXE_clairvoyant"))
        .args(["migrate", "--from-python"])
        .arg(&from)
        .arg("--to")
        .arg(&to)
        .output()
        .await
        .expect("run migrate");
    assert!(
        !output.status.success(),
        "bad timestamp order migration unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("intent i001 concluded_at in project proj_007 before created_at"),
        "unexpected stderr: {stderr}"
    );
    assert!(
        !to.exists(),
        "target database was created before timestamp-order preflight completed"
    );
}

#[tokio::test]
async fn migrate_cli_rejects_invalid_python_project_status_before_creating_target() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let from = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-bad-status-old-{}-{nonce}.db",
        std::process::id()
    ));
    let to = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-bad-status-new-{}-{nonce}.db",
        std::process::id()
    ));
    create_python_fixture(&from).await;

    let options =
        SqliteConnectOptions::from_str(&format!("sqlite://{}", from.display())).expect("options");
    let old = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("open old db");
    sqlx::query("UPDATE projects SET status = 'archived' WHERE id = 'proj_007'")
        .execute(&old)
        .await
        .expect("corrupt project status");
    old.close().await;

    let output = Command::new(env!("CARGO_BIN_EXE_clairvoyant"))
        .args(["migrate", "--from-python"])
        .arg(&from)
        .arg("--to")
        .arg(&to)
        .output()
        .await
        .expect("run migrate");
    assert!(
        !output.status.success(),
        "bad status migration unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid project status archived for project proj_007"),
        "unexpected stderr: {stderr}"
    );
    assert!(
        !to.exists(),
        "target database was created before status preflight completed"
    );
}

#[tokio::test]
async fn migrate_cli_rejects_invalid_python_settings_before_creating_target() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let from = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-bad-settings-old-{}-{nonce}.db",
        std::process::id()
    ));
    let to = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-bad-settings-new-{}-{nonce}.db",
        std::process::id()
    ));
    create_python_fixture(&from).await;

    let options =
        SqliteConnectOptions::from_str(&format!("sqlite://{}", from.display())).expect("options");
    let old = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("open old db");
    sqlx::query("UPDATE settings SET intent_timeout = 1 WHERE rowid = 1")
        .execute(&old)
        .await
        .expect("corrupt settings");
    old.close().await;

    let output = Command::new(env!("CARGO_BIN_EXE_clairvoyant"))
        .args(["migrate", "--from-python"])
        .arg(&from)
        .arg("--to")
        .arg(&to)
        .output()
        .await
        .expect("run migrate");
    assert!(
        !output.status.success(),
        "bad settings migration unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("timeout must be >= 5"),
        "unexpected stderr: {stderr}"
    );
    assert!(
        !to.exists(),
        "target database was created before settings preflight completed"
    );
}

#[tokio::test]
async fn migrate_cli_rejects_missing_python_settings_row_before_creating_target() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let from = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-missing-settings-old-{}-{nonce}.db",
        std::process::id()
    ));
    let to = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-missing-settings-new-{}-{nonce}.db",
        std::process::id()
    ));
    create_python_fixture(&from).await;

    let options =
        SqliteConnectOptions::from_str(&format!("sqlite://{}", from.display())).expect("options");
    let old = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("open old db");
    sqlx::query("DELETE FROM settings")
        .execute(&old)
        .await
        .expect("delete settings row");
    old.close().await;

    let output = Command::new(env!("CARGO_BIN_EXE_clairvoyant"))
        .args(["migrate", "--from-python"])
        .arg(&from)
        .arg("--to")
        .arg(&to)
        .output()
        .await
        .expect("run migrate");
    assert!(
        !output.status.success(),
        "missing settings migration unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("settings table must contain exactly one row at rowid 1"),
        "unexpected stderr: {stderr}"
    );
    assert!(
        !to.exists(),
        "target database was created before settings row preflight completed"
    );
}

#[tokio::test]
async fn migrate_cli_rejects_empty_python_fact_description_before_creating_target() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let from = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-empty-fact-old-{}-{nonce}.db",
        std::process::id()
    ));
    let to = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-empty-fact-new-{}-{nonce}.db",
        std::process::id()
    ));
    create_python_fixture(&from).await;

    let options =
        SqliteConnectOptions::from_str(&format!("sqlite://{}", from.display())).expect("options");
    let old = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("open old db");
    sqlx::query(
        "UPDATE facts SET description = '   ' WHERE project_id = 'proj_007' AND id = 'origin'",
    )
    .execute(&old)
    .await
    .expect("corrupt fact description");
    old.close().await;

    let output = Command::new(env!("CARGO_BIN_EXE_clairvoyant"))
        .args(["migrate", "--from-python"])
        .arg(&from)
        .arg("--to")
        .arg(&to)
        .output()
        .await
        .expect("run migrate");
    assert!(
        !output.status.success(),
        "empty fact description migration unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("fact origin description in project proj_007 must not be empty"),
        "unexpected stderr: {stderr}"
    );
    assert!(
        !to.exists(),
        "target database was created before text preflight completed"
    );
}

#[tokio::test]
async fn migrate_cli_rejects_empty_python_intent_creator_before_creating_target() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let from = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-empty-intent-old-{}-{nonce}.db",
        std::process::id()
    ));
    let to = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-empty-intent-new-{}-{nonce}.db",
        std::process::id()
    ));
    create_python_fixture(&from).await;

    let options =
        SqliteConnectOptions::from_str(&format!("sqlite://{}", from.display())).expect("options");
    let old = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("open old db");
    sqlx::query("UPDATE intents SET creator = ' ' WHERE project_id = 'proj_007' AND id = 'i001'")
        .execute(&old)
        .await
        .expect("corrupt intent creator");
    old.close().await;

    let output = Command::new(env!("CARGO_BIN_EXE_clairvoyant"))
        .args(["migrate", "--from-python"])
        .arg(&from)
        .arg("--to")
        .arg(&to)
        .output()
        .await
        .expect("run migrate");
    assert!(
        !output.status.success(),
        "empty intent creator migration unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("intent i001 creator in project proj_007 must not be empty"),
        "unexpected stderr: {stderr}"
    );
    assert!(
        !to.exists(),
        "target database was created before text preflight completed"
    );
}

#[tokio::test]
async fn migrate_cli_rejects_empty_python_hint_content_before_creating_target() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let from = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-empty-hint-old-{}-{nonce}.db",
        std::process::id()
    ));
    let to = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-empty-hint-new-{}-{nonce}.db",
        std::process::id()
    ));
    create_python_fixture(&from).await;

    let options =
        SqliteConnectOptions::from_str(&format!("sqlite://{}", from.display())).expect("options");
    let old = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("open old db");
    sqlx::query("UPDATE hints SET content = ' ' WHERE project_id = 'proj_007' AND id = 'h001'")
        .execute(&old)
        .await
        .expect("corrupt hint content");
    old.close().await;

    let output = Command::new(env!("CARGO_BIN_EXE_clairvoyant"))
        .args(["migrate", "--from-python"])
        .arg(&from)
        .arg("--to")
        .arg(&to)
        .output()
        .await
        .expect("run migrate");
    assert!(
        !output.status.success(),
        "empty hint content migration unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("hint h001 content in project proj_007 must not be empty"),
        "unexpected stderr: {stderr}"
    );
    assert!(
        !to.exists(),
        "target database was created before text preflight completed"
    );
}

#[tokio::test]
async fn migrate_cli_rejects_malformed_python_intent_id_before_creating_target() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let from = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-bad-intent-id-old-{}-{nonce}.db",
        std::process::id()
    ));
    let to = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-bad-intent-id-new-{}-{nonce}.db",
        std::process::id()
    ));
    create_python_fixture(&from).await;

    let options =
        SqliteConnectOptions::from_str(&format!("sqlite://{}", from.display())).expect("options");
    let old = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("open old db");
    sqlx::query(
        "UPDATE intents SET id = 'intent-one' WHERE project_id = 'proj_007' AND id = 'i001'",
    )
    .execute(&old)
    .await
    .expect("corrupt intent id");
    sqlx::query(
        "UPDATE intent_sources SET intent_id = 'intent-one' WHERE project_id = 'proj_007' AND intent_id = 'i001'",
    )
    .execute(&old)
    .await
    .expect("update intent source id");
    old.close().await;

    let output = Command::new(env!("CARGO_BIN_EXE_clairvoyant"))
        .args(["migrate", "--from-python"])
        .arg(&from)
        .arg("--to")
        .arg(&to)
        .output()
        .await
        .expect("run migrate");
    assert!(
        !output.status.success(),
        "malformed intent id migration unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("intent id in project proj_007 intent-one must match i<number>"),
        "unexpected stderr: {stderr}"
    );
    assert!(
        !to.exists(),
        "target database was created before id-format preflight completed"
    );
}

#[tokio::test]
async fn migrate_cli_rejects_unpadded_python_ids_before_creating_target() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let from = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-unpadded-id-old-{}-{nonce}.db",
        std::process::id()
    ));
    let to = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-unpadded-id-new-{}-{nonce}.db",
        std::process::id()
    ));
    create_python_fixture(&from).await;
    let options = SqliteConnectOptions::new().filename(&from);
    let old = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("open old db");
    sqlx::query("UPDATE intents SET id = 'i1' WHERE project_id = 'proj_007' AND id = 'i001'")
        .execute(&old)
        .await
        .expect("corrupt intent id");
    sqlx::query(
        "UPDATE intent_sources SET intent_id = 'i1' WHERE project_id = 'proj_007' AND intent_id = 'i001'",
    )
    .execute(&old)
    .await
    .expect("corrupt intent source id");
    old.close().await;

    let output = Command::new(env!("CARGO_BIN_EXE_clairvoyant"))
        .args(["migrate", "--from-python"])
        .arg(&from)
        .arg("--to")
        .arg(&to)
        .output()
        .await
        .expect("run migrate");
    assert!(
        !output.status.success(),
        "unpadded id migration unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(
            "intent id in project proj_007 i1 must use Clairvoyant's zero-padded id format"
        ),
        "unexpected stderr: {stderr}"
    );
    assert!(
        !to.exists(),
        "target database was created before unpadded-id preflight completed"
    );
}

#[tokio::test]
async fn migrate_cli_rejects_duplicate_python_intent_source_before_creating_target() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let from = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-duplicate-source-old-{}-{nonce}.db",
        std::process::id()
    ));
    let to = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-duplicate-source-new-{}-{nonce}.db",
        std::process::id()
    ));
    create_python_fixture(&from).await;

    let options =
        SqliteConnectOptions::from_str(&format!("sqlite://{}", from.display())).expect("options");
    let old = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("open old db");
    for statement in [
        "ALTER TABLE intent_sources RENAME TO old_intent_sources",
        "CREATE TABLE intent_sources (intent_id TEXT NOT NULL, project_id TEXT NOT NULL, fact_id TEXT NOT NULL)",
        "INSERT INTO intent_sources (intent_id, project_id, fact_id) SELECT intent_id, project_id, fact_id FROM old_intent_sources",
        "INSERT INTO intent_sources (intent_id, project_id, fact_id) VALUES ('i001', 'proj_007', 'origin')",
    ] {
        sqlx::query(statement).execute(&old).await.expect(statement);
    }
    old.close().await;

    let output = Command::new(env!("CARGO_BIN_EXE_clairvoyant"))
        .args(["migrate", "--from-python"])
        .arg(&from)
        .arg("--to")
        .arg(&to)
        .output()
        .await
        .expect("run migrate");
    assert!(
        !output.status.success(),
        "duplicate source migration unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("duplicate intent source i001 -> origin in project proj_007"),
        "unexpected stderr: {stderr}"
    );
    assert!(
        !to.exists(),
        "target database was created before uniqueness preflight completed"
    );
}

#[tokio::test]
async fn migrate_cli_rejects_partial_python_reason_lease_before_creating_target() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let from = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-partial-reason-old-{}-{nonce}.db",
        std::process::id()
    ));
    let to = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-partial-reason-new-{}-{nonce}.db",
        std::process::id()
    ));
    create_python_fixture(&from).await;

    let options =
        SqliteConnectOptions::from_str(&format!("sqlite://{}", from.display())).expect("options");
    let old = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("open old db");
    sqlx::query(
        "UPDATE projects SET reason_trigger = NULL, reason_started_at = NULL, reason_last_heartbeat_at = NULL WHERE id = 'proj_007'",
    )
    .execute(&old)
    .await
    .expect("corrupt reason lease");
    old.close().await;

    let output = Command::new(env!("CARGO_BIN_EXE_clairvoyant"))
        .args(["migrate", "--from-python"])
        .arg(&from)
        .arg("--to")
        .arg(&to)
        .output()
        .await
        .expect("run migrate");
    assert!(
        !output.status.success(),
        "partial reason lease migration unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("partial reason lease for project proj_007"),
        "unexpected stderr: {stderr}"
    );
    assert!(
        !to.exists(),
        "target database was created before reason-lease preflight completed"
    );
}

#[tokio::test]
async fn migrate_cli_rejects_partial_python_intent_lease_before_creating_target() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let from = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-partial-intent-old-{}-{nonce}.db",
        std::process::id()
    ));
    let to = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-partial-intent-new-{}-{nonce}.db",
        std::process::id()
    ));
    create_python_fixture(&from).await;

    let options =
        SqliteConnectOptions::from_str(&format!("sqlite://{}", from.display())).expect("options");
    let old = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("open old db");
    sqlx::query(
        "INSERT INTO intents (id, project_id, to_fact_id, description, creator, worker, last_heartbeat_at, created_at, concluded_at) VALUES ('i002', 'proj_007', NULL, 'stuck open intent', 'w', 'w', NULL, '2026-01-01T00:00:06Z', NULL)",
    )
    .execute(&old)
    .await
    .expect("insert partial intent lease");
    sqlx::query(
        "INSERT INTO intent_sources (intent_id, project_id, fact_id) VALUES ('i002', 'proj_007', 'origin')",
    )
    .execute(&old)
    .await
    .expect("insert intent source");
    old.close().await;

    let output = Command::new(env!("CARGO_BIN_EXE_clairvoyant"))
        .args(["migrate", "--from-python"])
        .arg(&from)
        .arg("--to")
        .arg(&to)
        .output()
        .await
        .expect("run migrate");
    assert!(
        !output.status.success(),
        "partial intent lease migration unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("partial intent lease for intent i002 in project proj_007"),
        "unexpected stderr: {stderr}"
    );
    assert!(
        !to.exists(),
        "target database was created before intent-lease preflight completed"
    );
}

#[tokio::test]
async fn migrate_cli_rejects_blank_python_optional_reason_worker_before_creating_target() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let from = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-blank-reason-worker-old-{}-{nonce}.db",
        std::process::id()
    ));
    let to = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-blank-reason-worker-new-{}-{nonce}.db",
        std::process::id()
    ));
    create_python_fixture(&from).await;

    let options =
        SqliteConnectOptions::from_str(&format!("sqlite://{}", from.display())).expect("options");
    let old = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("open old db");
    sqlx::query(
        "UPDATE projects SET reason_worker = ' ', reason_trigger = NULL, reason_started_at = NULL, reason_last_heartbeat_at = NULL WHERE id = 'proj_007'",
    )
    .execute(&old)
    .await
    .expect("blank reason worker");
    old.close().await;

    let output = Command::new(env!("CARGO_BIN_EXE_clairvoyant"))
        .args(["migrate", "--from-python"])
        .arg(&from)
        .arg("--to")
        .arg(&to)
        .output()
        .await
        .expect("run migrate");
    assert!(
        !output.status.success(),
        "blank optional reason worker migration unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("project proj_007 reason_worker must be null or non-empty"),
        "unexpected stderr: {stderr}"
    );
    assert!(
        !to.exists(),
        "target database was created before optional-text preflight completed"
    );
}

#[tokio::test]
async fn migrate_cli_rejects_blank_python_optional_intent_worker_before_creating_target() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let from = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-blank-intent-worker-old-{}-{nonce}.db",
        std::process::id()
    ));
    let to = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-blank-intent-worker-new-{}-{nonce}.db",
        std::process::id()
    ));
    create_python_fixture(&from).await;

    let options =
        SqliteConnectOptions::from_str(&format!("sqlite://{}", from.display())).expect("options");
    let old = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("open old db");
    sqlx::query(
        "INSERT INTO intents (id, project_id, to_fact_id, description, creator, worker, last_heartbeat_at, created_at, concluded_at) VALUES ('i002', 'proj_007', NULL, 'open intent', 'w', ' ', NULL, '2026-01-01T00:00:06Z', NULL)",
    )
    .execute(&old)
    .await
    .expect("insert blank intent worker");
    sqlx::query(
        "INSERT INTO intent_sources (intent_id, project_id, fact_id) VALUES ('i002', 'proj_007', 'origin')",
    )
    .execute(&old)
    .await
    .expect("insert intent source");
    old.close().await;

    let output = Command::new(env!("CARGO_BIN_EXE_clairvoyant"))
        .args(["migrate", "--from-python"])
        .arg(&from)
        .arg("--to")
        .arg(&to)
        .output()
        .await
        .expect("run migrate");
    assert!(
        !output.status.success(),
        "blank optional intent worker migration unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("intent i002 worker in project proj_007 must be null or non-empty"),
        "unexpected stderr: {stderr}"
    );
    assert!(
        !to.exists(),
        "target database was created before optional-text preflight completed"
    );
}

#[tokio::test]
async fn migrate_cli_rejects_partial_python_concluded_intent_before_creating_target() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let from = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-partial-concluded-old-{}-{nonce}.db",
        std::process::id()
    ));
    let to = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-partial-concluded-new-{}-{nonce}.db",
        std::process::id()
    ));
    create_python_fixture(&from).await;

    let options =
        SqliteConnectOptions::from_str(&format!("sqlite://{}", from.display())).expect("options");
    let old = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("open old db");
    sqlx::query("UPDATE intents SET concluded_at = NULL WHERE id = 'i001'")
        .execute(&old)
        .await
        .expect("corrupt concluded state");
    old.close().await;

    let output = Command::new(env!("CARGO_BIN_EXE_clairvoyant"))
        .args(["migrate", "--from-python"])
        .arg(&from)
        .arg("--to")
        .arg(&to)
        .output()
        .await
        .expect("run migrate");
    assert!(
        !output.status.success(),
        "partial concluded intent migration unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("partial concluded state for intent i001 in project proj_007"),
        "unexpected stderr: {stderr}"
    );
    assert!(
        !to.exists(),
        "target database was created before concluded-state preflight completed"
    );
}

#[tokio::test]
async fn migrate_cli_rejects_completed_python_project_without_goal_intent_before_creating_target() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let from = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-completed-missing-goal-old-{}-{nonce}.db",
        std::process::id()
    ));
    let to = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-completed-missing-goal-new-{}-{nonce}.db",
        std::process::id()
    ));
    create_python_fixture(&from).await;

    let options =
        SqliteConnectOptions::from_str(&format!("sqlite://{}", from.display())).expect("options");
    let old = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("open old db");
    sqlx::query(
        r#"
        UPDATE projects
        SET status = 'completed',
            reason_worker = NULL,
            reason_trigger = NULL,
            reason_started_at = NULL,
            reason_last_heartbeat_at = NULL
        WHERE id = 'proj_007'
        "#,
    )
    .execute(&old)
    .await
    .expect("corrupt completion state");
    old.close().await;

    let output = Command::new(env!("CARGO_BIN_EXE_clairvoyant"))
        .args(["migrate", "--from-python"])
        .arg(&from)
        .arg("--to")
        .arg(&to)
        .output()
        .await
        .expect("run migrate");
    assert!(
        !output.status.success(),
        "completed project without goal intent migration unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("completed project proj_007 with 0 goal completion intents"),
        "unexpected stderr: {stderr}"
    );
    assert!(
        !to.exists(),
        "target database was created before completion-state preflight completed"
    );
}

#[tokio::test]
async fn migrate_cli_rejects_active_python_project_with_goal_intent_before_creating_target() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let from = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-active-with-goal-old-{}-{nonce}.db",
        std::process::id()
    ));
    let to = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-active-with-goal-new-{}-{nonce}.db",
        std::process::id()
    ));
    create_python_fixture(&from).await;

    let options =
        SqliteConnectOptions::from_str(&format!("sqlite://{}", from.display())).expect("options");
    let old = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("open old db");
    sqlx::query("UPDATE intents SET to_fact_id = 'goal' WHERE id = 'i001'")
        .execute(&old)
        .await
        .expect("corrupt completion state");
    old.close().await;

    let output = Command::new(env!("CARGO_BIN_EXE_clairvoyant"))
        .args(["migrate", "--from-python"])
        .arg(&from)
        .arg("--to")
        .arg(&to)
        .output()
        .await
        .expect("run migrate");
    assert!(
        !output.status.success(),
        "active project with goal intent migration unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("non-completed project proj_007 with 1 goal completion intents"),
        "unexpected stderr: {stderr}"
    );
    assert!(
        !to.exists(),
        "target database was created before completion-state preflight completed"
    );
}

#[tokio::test]
async fn migrate_cli_rejects_completed_python_project_with_reason_lease_before_creating_target() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let from = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-completed-reason-old-{}-{nonce}.db",
        std::process::id()
    ));
    let to = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-completed-reason-new-{}-{nonce}.db",
        std::process::id()
    ));
    create_python_fixture(&from).await;

    let options =
        SqliteConnectOptions::from_str(&format!("sqlite://{}", from.display())).expect("options");
    let old = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("open old db");
    sqlx::query("UPDATE projects SET status = 'completed' WHERE id = 'proj_007'")
        .execute(&old)
        .await
        .expect("complete project");
    sqlx::query("UPDATE intents SET to_fact_id = 'goal' WHERE id = 'i001'")
        .execute(&old)
        .await
        .expect("make completion intent");
    old.close().await;

    let output = Command::new(env!("CARGO_BIN_EXE_clairvoyant"))
        .args(["migrate", "--from-python"])
        .arg(&from)
        .arg("--to")
        .arg(&to)
        .output()
        .await
        .expect("run migrate");
    assert!(
        !output.status.success(),
        "completed project with reason lease migration unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("completed project proj_007 with an active reason lease"),
        "unexpected stderr: {stderr}"
    );
    assert!(
        !to.exists(),
        "target database was created before completed-reason preflight completed"
    );
}

#[tokio::test]
async fn migrate_cli_rejects_stopped_python_project_with_runtime_work_before_creating_target() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let from = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-stopped-reason-old-{}-{nonce}.db",
        std::process::id()
    ));
    let to = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-stopped-reason-new-{}-{nonce}.db",
        std::process::id()
    ));
    create_python_fixture(&from).await;

    let options =
        SqliteConnectOptions::from_str(&format!("sqlite://{}", from.display())).expect("options");
    let old = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("open old db");
    sqlx::query("UPDATE projects SET status = 'stopped' WHERE id = 'proj_007'")
        .execute(&old)
        .await
        .expect("stop project with reason lease");
    old.close().await;

    let output = Command::new(env!("CARGO_BIN_EXE_clairvoyant"))
        .args(["migrate", "--from-python"])
        .arg(&from)
        .arg("--to")
        .arg(&to)
        .output()
        .await
        .expect("run migrate");
    assert!(
        !output.status.success(),
        "stopped project with reason lease migration unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("stopped project proj_007 with an active reason lease"),
        "unexpected stderr: {stderr}"
    );
    assert!(
        !to.exists(),
        "target database was created before stopped-reason preflight completed"
    );

    let from_open = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-stopped-claimed-old-{}-{nonce}.db",
        std::process::id()
    ));
    let to_open = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-stopped-claimed-new-{}-{nonce}.db",
        std::process::id()
    ));
    create_python_fixture(&from_open).await;
    let options = SqliteConnectOptions::from_str(&format!("sqlite://{}", from_open.display()))
        .expect("options");
    let old = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("open old db");
    sqlx::query(
        "UPDATE projects SET status = 'stopped', reason_worker = NULL, reason_trigger = NULL, reason_started_at = NULL, reason_last_heartbeat_at = NULL WHERE id = 'proj_007'",
    )
    .execute(&old)
    .await
    .expect("stop project without reason lease");
    sqlx::query("UPDATE intents SET to_fact_id = NULL, concluded_at = NULL WHERE id = 'i001'")
        .execute(&old)
        .await
        .expect("make claimed open intent");
    old.close().await;

    let output = Command::new(env!("CARGO_BIN_EXE_clairvoyant"))
        .args(["migrate", "--from-python"])
        .arg(&from_open)
        .arg("--to")
        .arg(&to_open)
        .output()
        .await
        .expect("run migrate");
    assert!(
        !output.status.success(),
        "stopped project with claimed intent migration unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("stopped project proj_007 with claimed open intent i001"),
        "unexpected stderr: {stderr}"
    );
    assert!(
        !to_open.exists(),
        "target database was created before stopped-claimed preflight completed"
    );
}

#[tokio::test]
async fn migrate_cli_rejects_missing_python_project_goal_fact_before_creating_target() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let from = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-missing-goal-old-{}-{nonce}.db",
        std::process::id()
    ));
    let to = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-missing-goal-new-{}-{nonce}.db",
        std::process::id()
    ));
    create_python_fixture(&from).await;

    let options =
        SqliteConnectOptions::from_str(&format!("sqlite://{}", from.display())).expect("options");
    let old = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("open old db");
    sqlx::query("DELETE FROM facts WHERE project_id = 'proj_007' AND id = 'goal'")
        .execute(&old)
        .await
        .expect("delete goal fact");
    old.close().await;

    let output = Command::new(env!("CARGO_BIN_EXE_clairvoyant"))
        .args(["migrate", "--from-python"])
        .arg(&from)
        .arg("--to")
        .arg(&to)
        .output()
        .await
        .expect("run migrate");
    assert!(
        !output.status.success(),
        "missing goal fact migration unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("project proj_007 must have exactly one origin fact and one goal fact"),
        "unexpected stderr: {stderr}"
    );
    assert!(
        !to.exists(),
        "target database was created before project-fact preflight completed"
    );
}

#[tokio::test]
async fn migrate_cli_rejects_dangling_python_references_before_creating_target() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let from = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-dangling-old-{}-{nonce}.db",
        std::process::id()
    ));
    let to = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-dangling-new-{}-{nonce}.db",
        std::process::id()
    ));
    create_python_fixture(&from).await;

    let options =
        SqliteConnectOptions::from_str(&format!("sqlite://{}", from.display())).expect("options");
    let old = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("open old db");
    sqlx::query(
        "INSERT INTO intent_sources (intent_id, project_id, fact_id) VALUES ('i404', 'proj_007', 'f001')",
    )
    .execute(&old)
    .await
    .expect("insert dangling source");
    old.close().await;

    let output = Command::new(env!("CARGO_BIN_EXE_clairvoyant"))
        .args(["migrate", "--from-python"])
        .arg(&from)
        .arg("--to")
        .arg(&to)
        .output()
        .await
        .expect("run migrate");
    assert!(
        !output.status.success(),
        "dangling reference migration unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("dangling intent source for missing intent i404 in project proj_007"),
        "unexpected stderr: {stderr}"
    );
    assert!(
        !to.exists(),
        "target database was created before reference preflight completed"
    );
}

#[tokio::test]
async fn migrate_cli_rejects_dangling_python_target_fact_before_creating_target() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let from = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-dangling-target-old-{}-{nonce}.db",
        std::process::id()
    ));
    let to = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-dangling-target-new-{}-{nonce}.db",
        std::process::id()
    ));
    create_python_fixture(&from).await;

    let options =
        SqliteConnectOptions::from_str(&format!("sqlite://{}", from.display())).expect("options");
    let old = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("open old db");
    sqlx::query("UPDATE intents SET to_fact_id = 'f404' WHERE id = 'i001'")
        .execute(&old)
        .await
        .expect("corrupt target fact");
    old.close().await;

    let output = Command::new(env!("CARGO_BIN_EXE_clairvoyant"))
        .args(["migrate", "--from-python"])
        .arg(&from)
        .arg("--to")
        .arg(&to)
        .output()
        .await
        .expect("run migrate");
    assert!(
        !output.status.success(),
        "dangling target migration unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("dangling target fact for intent i001 -> f404 in project proj_007"),
        "unexpected stderr: {stderr}"
    );
    assert!(
        !to.exists(),
        "target database was created before target-fact preflight completed"
    );
}

#[tokio::test]
async fn migrate_cli_rejects_invalid_python_intent_sources_before_creating_target() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let from = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-invalid-sources-old-{}-{nonce}.db",
        std::process::id()
    ));
    let to = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-invalid-sources-new-{}-{nonce}.db",
        std::process::id()
    ));
    create_python_fixture(&from).await;

    let options =
        SqliteConnectOptions::from_str(&format!("sqlite://{}", from.display())).expect("options");
    let old = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("open old db");
    sqlx::query("DELETE FROM intent_sources WHERE intent_id = 'i001' AND project_id = 'proj_007'")
        .execute(&old)
        .await
        .expect("delete intent source");
    old.close().await;

    let output = Command::new(env!("CARGO_BIN_EXE_clairvoyant"))
        .args(["migrate", "--from-python"])
        .arg(&from)
        .arg("--to")
        .arg(&to)
        .output()
        .await
        .expect("run migrate");
    assert!(
        !output.status.success(),
        "missing source migration unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("intent i001 in project proj_007 must have at least one source fact"),
        "unexpected stderr: {stderr}"
    );
    assert!(
        !to.exists(),
        "target database was created before intent-source preflight completed"
    );

    let from_goal = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-goal-source-old-{}-{nonce}.db",
        std::process::id()
    ));
    let to_goal = std::env::temp_dir().join(format!(
        "clairvoyant-cli-python-goal-source-new-{}-{nonce}.db",
        std::process::id()
    ));
    create_python_fixture(&from_goal).await;
    let options = SqliteConnectOptions::from_str(&format!("sqlite://{}", from_goal.display()))
        .expect("options");
    let old = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("open old db");
    sqlx::query(
        "UPDATE intent_sources SET fact_id = 'goal' WHERE intent_id = 'i001' AND project_id = 'proj_007'",
    )
    .execute(&old)
    .await
    .expect("corrupt intent source");
    old.close().await;

    let output = Command::new(env!("CARGO_BIN_EXE_clairvoyant"))
        .args(["migrate", "--from-python"])
        .arg(&from_goal)
        .arg("--to")
        .arg(&to_goal)
        .output()
        .await
        .expect("run migrate");
    assert!(
        !output.status.success(),
        "goal source migration unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("intent i001 in project proj_007 uses goal as a source fact"),
        "unexpected stderr: {stderr}"
    );
    assert!(
        !to_goal.exists(),
        "target database was created before goal-source preflight completed"
    );
}

async fn create_python_fixture(path: &std::path::Path) {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true);
    let old = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("open old db");
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
        sqlx::query(statement).execute(&old).await.expect(statement);
    }
    old.close().await;
}
