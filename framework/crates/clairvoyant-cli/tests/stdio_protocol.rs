use clairvoyant_core::{
    encode_frame, ClairvoyantEnvelope, ClairvoyantRequest, ClairvoyantResponse,
    CreateProjectRequest, ProjectStatus, MAX_FRAME_BYTES,
};
use clairvoyant_protocol::{ByteClient, ClairvoyantClient, ProtocolError};
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

#[tokio::test]
async fn serve_exchanges_internal_byte_frames_over_stdio() {
    let db_path = std::env::temp_dir().join(format!(
        "clairvoyant-cli-stdio-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    ));
    let mut child = Command::new(env!("CARGO_BIN_EXE_clairvoyant"))
        .args(["serve", "--db-path"])
        .arg(&db_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn clairvoyant serve");
    let stdout = child.stdout.take().expect("child stdout");
    let stdin = child.stdin.take().expect("child stdin");
    let mut client = ByteClient::new(stdout, stdin);

    let created = client
        .request(ClairvoyantRequest::CreateProject {
            body: CreateProjectRequest {
                title: "stdio".to_string(),
                origin: "start".to_string(),
                goal: "finish".to_string(),
                hints: None,
            },
        })
        .await
        .expect("create project");
    let project_id = match created {
        ClairvoyantResponse::ProjectDetail(detail) => detail.project.id,
        other => panic!("unexpected create response {other:?}"),
    };

    let listed = client
        .request(ClairvoyantRequest::ListProjects)
        .await
        .expect("list projects");
    match listed {
        ClairvoyantResponse::ProjectSummaries(projects) => {
            assert!(projects
                .iter()
                .any(|summary| summary.project.id == project_id));
        }
        other => panic!("unexpected list response {other:?}"),
    }

    drop(client);
    let status = child.wait().await.expect("wait for clairvoyant serve");
    assert!(status.success());
}

#[tokio::test]
async fn serve_rejects_legacy_intent_schema_fields_at_frame_boundary() {
    let db_path = std::env::temp_dir().join(format!(
        "clairvoyant-cli-stdio-schema-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    ));
    let mut child = Command::new(env!("CARGO_BIN_EXE_clairvoyant"))
        .args(["serve", "--db-path"])
        .arg(&db_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn clairvoyant serve");
    let mut stdin = child.stdin.take().expect("child stdin");
    let legacy = serde_json::json!({
        "op": "create_intent",
        "project_id": "proj_001",
        "body": {
            "from": ["origin"],
            "description": "legacy",
            "creator": "cli-test",
            "worker": null
        }
    });
    stdin
        .write_all(&encode_frame(&legacy).expect("encode legacy frame"))
        .await
        .expect("write legacy frame");
    drop(stdin);

    let output = child
        .wait_with_output()
        .await
        .expect("wait for clairvoyant serve");
    assert!(
        !output.status.success(),
        "legacy frame unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unknown field `from`"), "{stderr}");
}

#[tokio::test]
async fn serve_returns_error_envelopes_without_closing_stream() {
    let db_path = std::env::temp_dir().join(format!(
        "clairvoyant-cli-stdio-error-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    ));
    let mut child = Command::new(env!("CARGO_BIN_EXE_clairvoyant"))
        .args(["serve", "--db-path"])
        .arg(&db_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn clairvoyant serve");
    let stdout = child.stdout.take().expect("child stdout");
    let stdin = child.stdin.take().expect("child stdin");
    let mut client = ByteClient::new(stdout, stdin);

    let error = client
        .request(ClairvoyantRequest::GetProject {
            project_id: "proj_missing".to_string(),
        })
        .await
        .expect_err("missing project should return server error");
    assert!(matches!(error, ProtocolError::Server { status: 404, .. }));

    let response = client
        .request(ClairvoyantRequest::ListProjects)
        .await
        .expect("stream should remain usable after API error");
    assert!(matches!(response, ClairvoyantResponse::ProjectSummaries(_)));

    drop(client);
    let status = child.wait().await.expect("wait for clairvoyant serve");
    assert!(status.success());
}

#[tokio::test]
async fn serve_rejects_oversized_frame_length_without_reading_payload() {
    let db_path = std::env::temp_dir().join(format!(
        "clairvoyant-cli-stdio-oversized-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    ));
    let mut child = Command::new(env!("CARGO_BIN_EXE_clairvoyant"))
        .args(["serve", "--db-path"])
        .arg(&db_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn clairvoyant serve");
    let mut stdin = child.stdin.take().expect("child stdin");
    stdin
        .write_all(&((MAX_FRAME_BYTES as u32) + 1).to_be_bytes())
        .await
        .expect("write oversized length");
    drop(stdin);

    let output = child
        .wait_with_output()
        .await
        .expect("wait for clairvoyant serve");
    assert!(
        !output.status.success(),
        "oversized frame unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "oversized frame should not receive a response frame"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("frame too large"), "{stderr}");
}

#[tokio::test]
async fn request_command_reads_json_from_stdin_when_json_is_dash() {
    let db_path = std::env::temp_dir().join(format!(
        "clairvoyant-cli-request-stdin-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    ));
    let mut child = Command::new(env!("CARGO_BIN_EXE_clairvoyant"))
        .args(["request", "--db-path"])
        .arg(&db_path)
        .args(["--json", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn clairvoyant request");
    let mut stdin = child.stdin.take().expect("child stdin");
    stdin
        .write_all(
            br#"{"op":"create_project","body":{"title":"stdin","origin":"start","goal":"finish","hints":null}}"#,
        )
        .await
        .expect("write request json");
    drop(stdin);

    let output = child.wait_with_output().await.expect("wait for request");
    assert!(
        output.status.success(),
        "request failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope: ClairvoyantEnvelope =
        serde_json::from_slice(&output.stdout).expect("parse request envelope");
    match envelope {
        ClairvoyantEnvelope::Ok { response } => match *response {
            ClairvoyantResponse::ProjectDetail(detail) => {
                assert_eq!(detail.project.title, "stdin");
                assert_eq!(detail.facts.len(), 2);
            }
            other => panic!("unexpected response {other:?}"),
        },
        ClairvoyantEnvelope::Err { error } => panic!("unexpected error response {error:?}"),
    }
}

#[tokio::test]
async fn structured_cli_commands_cover_project_intent_hint_and_export() {
    let db_path = std::env::temp_dir().join(format!(
        "clairvoyant-cli-structured-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    ));

    let created = run_clairvoyant([
        "project",
        "--db-path",
        db_path.to_str().expect("db path"),
        "create",
        "--title",
        "structured",
        "--origin",
        "start",
        "--goal",
        "finish",
        "--hint",
        "initial clue",
        "--hint-creator",
        "tester",
    ])
    .await;
    let envelope: ClairvoyantEnvelope = serde_json::from_slice(&created).expect("parse create");
    let project_id = match envelope {
        ClairvoyantEnvelope::Ok { response } => match *response {
            ClairvoyantResponse::ProjectDetail(detail) => {
                assert_eq!(detail.hints.len(), 1);
                assert_eq!(detail.hints[0].content, "initial clue");
                assert_eq!(detail.hints[0].creator, "tester");
                detail.project.id
            }
            other => panic!("unexpected create response {other:?}"),
        },
        ClairvoyantEnvelope::Err { error } => panic!("unexpected create error {error:?}"),
    };

    run_clairvoyant([
        "hint",
        "--db-path",
        db_path.to_str().expect("db path"),
        "--project-id",
        &project_id,
        "create",
        "--content",
        "useful hint",
        "--creator",
        "tester",
    ])
    .await;

    let intent = run_clairvoyant([
        "intent",
        "--db-path",
        db_path.to_str().expect("db path"),
        "--project-id",
        &project_id,
        "create",
        "--sources",
        "origin",
        "--description",
        "check path",
        "--creator",
        "tester",
    ])
    .await;
    let envelope: ClairvoyantEnvelope = serde_json::from_slice(&intent).expect("parse intent");
    let intent_id = match envelope {
        ClairvoyantEnvelope::Ok { response } => match *response {
            ClairvoyantResponse::Intent(intent) => intent.id,
            other => panic!("unexpected intent response {other:?}"),
        },
        ClairvoyantEnvelope::Err { error } => panic!("unexpected intent error {error:?}"),
    };

    run_clairvoyant([
        "intent",
        "--db-path",
        db_path.to_str().expect("db path"),
        "--project-id",
        &project_id,
        "conclude",
        &intent_id,
        "--worker",
        "tester",
        "--description",
        "new fact",
    ])
    .await;

    let export = run_clairvoyant([
        "project",
        "--db-path",
        db_path.to_str().expect("db path"),
        "export",
        &project_id,
        "--format",
        "timeline",
    ])
    .await;
    let export = String::from_utf8(export).expect("export utf8");
    assert!(export.contains("PROJECT CREATED"), "{export}");
    assert!(export.contains("new fact"), "{export}");
}

#[tokio::test]
async fn observe_command_reports_open_work_snapshot() {
    let db_path = std::env::temp_dir().join(format!(
        "clairvoyant-cli-observe-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    ));
    let db = db_path.to_str().expect("db path");

    let created = run_clairvoyant([
        "project",
        "--db-path",
        db,
        "create",
        "--title",
        "observed",
        "--origin",
        "start",
        "--goal",
        "finish",
    ])
    .await;
    let project_id = match serde_json::from_slice(&created).expect("parse create") {
        ClairvoyantEnvelope::Ok { response } => match *response {
            ClairvoyantResponse::ProjectDetail(detail) => detail.project.id,
            other => panic!("unexpected create response {other:?}"),
        },
        ClairvoyantEnvelope::Err { error } => panic!("unexpected create error {error:?}"),
    };

    let intent = run_clairvoyant([
        "intent",
        "--db-path",
        db,
        "--project-id",
        &project_id,
        "create",
        "--sources",
        "origin",
        "--description",
        "externally visible work",
        "--creator",
        "observer-worker",
        "--worker",
        "observer-worker",
    ])
    .await;
    let intent_id = match serde_json::from_slice(&intent).expect("parse intent") {
        ClairvoyantEnvelope::Ok { response } => match *response {
            ClairvoyantResponse::Intent(intent) => intent.id,
            other => panic!("unexpected intent response {other:?}"),
        },
        ClairvoyantEnvelope::Err { error } => panic!("unexpected intent error {error:?}"),
    };

    let observed = run_clairvoyant(["observe", "--db-path", db, "--project-id", &project_id]).await;
    let envelope: ClairvoyantEnvelope = serde_json::from_slice(&observed).expect("parse observe");
    let snapshot = match envelope {
        ClairvoyantEnvelope::Ok { response } => match *response {
            ClairvoyantResponse::Observation(snapshot) => snapshot,
            other => panic!("unexpected observe response {other:?}"),
        },
        ClairvoyantEnvelope::Err { error } => panic!("unexpected observe error {error:?}"),
    };

    assert_eq!(snapshot.project_count, 1);
    let project = snapshot.projects.first().expect("observed project");
    assert_eq!(project.project.id, project_id);
    assert_eq!(project.fact_count, 2);
    assert_eq!(project.intent_count, 1);
    assert_eq!(project.open_intent_count, 1);
    assert_eq!(project.working_intent_count, 1);
    assert_eq!(project.unclaimed_intent_count, 0);
    assert!(project.reason_heartbeat_age_ms.is_none());
    assert_eq!(project.open_intents.len(), 1);
    let open = &project.open_intents[0];
    assert_eq!(open.id, intent_id);
    assert_eq!(open.sources, vec!["origin".to_string()]);
    assert_eq!(open.worker.as_deref(), Some("observer-worker"));
    assert!(open.heartbeat_age_ms.is_some());
}

#[tokio::test]
async fn asset_command_lists_and_reads_embedded_static_files() {
    let list = run_clairvoyant(["asset", "--list"]).await;
    let list = String::from_utf8(list).expect("asset list utf8");
    assert!(list.contains("index.html\ttext/html"), "{list}");
    assert!(list.contains("vendor/cytoscape.min.js"), "{list}");

    let index = run_clairvoyant(["asset", "--path", "/static/index.html"]).await;
    assert!(index.starts_with(b"<!DOCTYPE html>"));
    let index = String::from_utf8(index).expect("index html utf8");
    assert!(index.contains("/static/vendor/cytoscape.min.js"));
}

#[tokio::test]
async fn structured_cli_commands_cover_reason_and_project_state_machine() {
    let db_path = std::env::temp_dir().join(format!(
        "clairvoyant-cli-state-machine-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    ));
    let db = db_path.to_str().expect("db path");

    let created = run_clairvoyant([
        "project",
        "--db-path",
        db,
        "create",
        "--title",
        "state",
        "--origin",
        "start",
        "--goal",
        "finish",
    ])
    .await;
    let project_id = match serde_json::from_slice(&created).expect("parse create") {
        ClairvoyantEnvelope::Ok { response } => match *response {
            ClairvoyantResponse::ProjectDetail(detail) => detail.project.id,
            other => panic!("unexpected create response {other:?}"),
        },
        ClairvoyantEnvelope::Err { error } => panic!("unexpected create error {error:?}"),
    };

    let intent = run_clairvoyant([
        "intent",
        "--db-path",
        db,
        "--project-id",
        &project_id,
        "create",
        "--sources",
        "origin",
        "--description",
        "produce a fact",
        "--creator",
        "tester",
    ])
    .await;
    let intent_id = match serde_json::from_slice(&intent).expect("parse intent") {
        ClairvoyantEnvelope::Ok { response } => match *response {
            ClairvoyantResponse::Intent(intent) => intent.id,
            other => panic!("unexpected intent response {other:?}"),
        },
        ClairvoyantEnvelope::Err { error } => panic!("unexpected intent error {error:?}"),
    };

    run_clairvoyant([
        "intent",
        "--db-path",
        db,
        "--project-id",
        &project_id,
        "conclude",
        &intent_id,
        "--worker",
        "tester",
        "--description",
        "intermediate fact",
    ])
    .await;

    run_clairvoyant([
        "project",
        "--db-path",
        db,
        "title",
        &project_id,
        "--title",
        "renamed state",
    ])
    .await;
    run_clairvoyant(["project", "--db-path", db, "stop", &project_id]).await;
    run_clairvoyant(["project", "--db-path", db, "resume", &project_id]).await;

    run_clairvoyant([
        "reason",
        "--db-path",
        db,
        "--project-id",
        &project_id,
        "claim",
        "--worker",
        "reasoner",
        "--trigger",
        "cli-test",
    ])
    .await;
    run_clairvoyant([
        "reason",
        "--db-path",
        db,
        "--project-id",
        &project_id,
        "heartbeat",
        "--worker",
        "reasoner",
    ])
    .await;
    run_clairvoyant([
        "reason",
        "--db-path",
        db,
        "--project-id",
        &project_id,
        "release",
        "--worker",
        "reasoner",
    ])
    .await;

    run_clairvoyant([
        "project",
        "--db-path",
        db,
        "complete",
        &project_id,
        "--sources",
        "f001",
        "--description",
        "solved",
        "--worker",
        "tester",
    ])
    .await;
    run_clairvoyant([
        "project",
        "--db-path",
        db,
        "reopen",
        &project_id,
        "--description",
        "needs more work",
        "--creator",
        "operator",
    ])
    .await;

    let shown = run_clairvoyant(["project", "--db-path", db, "show", &project_id]).await;
    let detail = match serde_json::from_slice(&shown).expect("parse show") {
        ClairvoyantEnvelope::Ok { response } => match *response {
            ClairvoyantResponse::ProjectDetail(detail) => detail,
            other => panic!("unexpected show response {other:?}"),
        },
        ClairvoyantEnvelope::Err { error } => panic!("unexpected show error {error:?}"),
    };
    assert_eq!(detail.project.title, "renamed state");
    assert_eq!(detail.project.status, ProjectStatus::Active);
    assert!(detail.project.reason.is_none());
    assert!(detail
        .facts
        .iter()
        .any(|fact| fact.description == "needs more work"));
    assert!(detail
        .intents
        .iter()
        .any(|intent| intent.description == "external_feedback"
            && intent.target_fact.as_deref() == Some("f002")));
}

#[tokio::test]
async fn json_cli_errors_exit_nonzero_but_keep_error_envelope() {
    let db_path = std::env::temp_dir().join(format!(
        "clairvoyant-cli-json-error-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    ));

    let output = Command::new(env!("CARGO_BIN_EXE_clairvoyant"))
        .arg("request")
        .arg("--db-path")
        .arg(&db_path)
        .arg("--json")
        .arg(r#"{"op":"get_project","project_id":"proj_missing"}"#)
        .output()
        .await
        .expect("run clairvoyant request");

    assert!(
        !output.status.success(),
        "request unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(r#""result": "err""#), "{stdout}");
    assert!(stdout.contains(r#""status": 404"#), "{stdout}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("404: Project not found"), "{stderr}");
}

#[tokio::test]
async fn dispatch_once_runs_startup_healthcheck_before_scheduler() {
    let config_path = std::env::temp_dir().join(format!(
        "clairvoyant-cli-dispatch-healthcheck-{}-{}.yaml",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    ));
    std::fs::write(
        &config_path,
        r#"
runtime:
  interval: 1
worker:
  kind: command
  program: /definitely/missing/clairvoyant-worker
"#,
    )
    .expect("write config");

    let output = Command::new(env!("CARGO_BIN_EXE_clairvoyant"))
        .args(["dispatch", "--config"])
        .arg(&config_path)
        .arg("--once")
        .output()
        .await
        .expect("run dispatch");
    assert!(
        !output.status.success(),
        "dispatch unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not executable"), "{stderr}");
}

async fn run_clairvoyant<const N: usize>(args: [&str; N]) -> Vec<u8> {
    let output = Command::new(env!("CARGO_BIN_EXE_clairvoyant"))
        .args(args)
        .output()
        .await
        .expect("run clairvoyant");
    assert!(
        output.status.success(),
        "clairvoyant failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}
