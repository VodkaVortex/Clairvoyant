use chrono::{DateTime, Local, TimeZone, Utc};
use clairvoyant_core::{
    ClairvoyantEnvelope, ClairvoyantErrorBody, ClairvoyantRequest, ClairvoyantResponse,
    CompleteRequest, ConcludeRequest, ConcludeResponse, CreateHintRequest, CreateIntentRequest,
    CreateProjectRequest, ExportFormat, Fact, HeartbeatRequest, Hint, Intent, IntentObservation,
    ObservationSnapshot, ProjectDetail, ProjectMeta, ProjectObservation, ProjectReason,
    ProjectStatus, ProjectSummary, ReasonClaimRequest, ReopenRequest, ReopenResponse, Settings,
    UpdateProjectStatusRequest, UpdateProjectTitleRequest,
};
use serde::Serialize;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{ConnectOptions, Row, SqlitePool};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::Mutex;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS settings (
    intent_timeout INTEGER NOT NULL DEFAULT 15,
    reason_timeout INTEGER NOT NULL DEFAULT 15
);

INSERT OR IGNORE INTO settings (rowid, intent_timeout, reason_timeout) VALUES (1, 15, 15);

CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at_ms INTEGER NOT NULL,
    reason_worker TEXT,
    reason_trigger TEXT,
    reason_started_at_ms INTEGER,
    reason_last_heartbeat_at_ms INTEGER
);

CREATE TABLE IF NOT EXISTS facts (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    description TEXT NOT NULL,
    PRIMARY KEY (id, project_id)
);

CREATE TABLE IF NOT EXISTS intents (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    target_fact TEXT,
    description TEXT NOT NULL,
    creator TEXT NOT NULL,
    worker TEXT,
    last_heartbeat_at_ms INTEGER,
    created_at_ms INTEGER NOT NULL,
    concluded_at_ms INTEGER,
    PRIMARY KEY (id, project_id)
);

CREATE TABLE IF NOT EXISTS intent_sources (
    intent_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    fact_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    PRIMARY KEY (intent_id, project_id, fact_id),
    FOREIGN KEY (intent_id, project_id) REFERENCES intents(id, project_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS hints (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    content TEXT NOT NULL,
    creator TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    PRIMARY KEY (id, project_id)
);

CREATE TABLE IF NOT EXISTS counters (
    name TEXT PRIMARY KEY,
    value INTEGER NOT NULL DEFAULT 0
);

INSERT OR IGNORE INTO counters (name, value) VALUES ('project', 0);

CREATE TABLE IF NOT EXISTS scoped_counters (
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    value INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (project_id, kind)
);
"#;

#[derive(Debug, Error)]
pub enum ClairvoyantError {
    #[error("{message}")]
    Api {
        status: u16,
        message: String,
        retry_after_ms: Option<u64>,
    },
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("yaml export error: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl ClairvoyantError {
    pub fn api(status: u16, message: impl Into<String>) -> Self {
        Self::Api {
            status,
            message: message.into(),
            retry_after_ms: None,
        }
    }

    pub fn into_body(self) -> ClairvoyantErrorBody {
        match self {
            Self::Api {
                status,
                message,
                retry_after_ms,
            } => ClairvoyantErrorBody {
                status,
                message,
                retry_after_ms,
            },
            Self::Db(err) if is_busy_error(&err) => ClairvoyantErrorBody {
                status: 503,
                message: "database is busy".to_string(),
                retry_after_ms: Some(250),
            },
            other => ClairvoyantErrorBody {
                status: 500,
                message: other.to_string(),
                retry_after_ms: None,
            },
        }
    }
}

pub type Result<T> = std::result::Result<T, ClairvoyantError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StaticAsset {
    pub path: &'static str,
    pub content_type: &'static str,
    pub bytes: &'static [u8],
}

static STATIC_ASSETS: &[StaticAsset] = &[
    StaticAsset {
        path: "favicon.svg",
        content_type: "image/svg+xml",
        bytes: include_bytes!("../static/favicon.svg"),
    },
    StaticAsset {
        path: "index.html",
        content_type: "text/html; charset=utf-8",
        bytes: include_bytes!("../static/index.html"),
    },
    StaticAsset {
        path: "vendor/alpine.min.js",
        content_type: "text/javascript; charset=utf-8",
        bytes: include_bytes!("../static/vendor/alpine.min.js"),
    },
    StaticAsset {
        path: "vendor/cola.min.js",
        content_type: "text/javascript; charset=utf-8",
        bytes: include_bytes!("../static/vendor/cola.min.js"),
    },
    StaticAsset {
        path: "vendor/cytoscape-cola.js",
        content_type: "text/javascript; charset=utf-8",
        bytes: include_bytes!("../static/vendor/cytoscape-cola.js"),
    },
    StaticAsset {
        path: "vendor/cytoscape-dagre.js",
        content_type: "text/javascript; charset=utf-8",
        bytes: include_bytes!("../static/vendor/cytoscape-dagre.js"),
    },
    StaticAsset {
        path: "vendor/cytoscape-elk.js",
        content_type: "text/javascript; charset=utf-8",
        bytes: include_bytes!("../static/vendor/cytoscape-elk.js"),
    },
    StaticAsset {
        path: "vendor/cytoscape-klay.js",
        content_type: "text/javascript; charset=utf-8",
        bytes: include_bytes!("../static/vendor/cytoscape-klay.js"),
    },
    StaticAsset {
        path: "vendor/cytoscape.min.js",
        content_type: "text/javascript; charset=utf-8",
        bytes: include_bytes!("../static/vendor/cytoscape.min.js"),
    },
    StaticAsset {
        path: "vendor/dagre.min.js",
        content_type: "text/javascript; charset=utf-8",
        bytes: include_bytes!("../static/vendor/dagre.min.js"),
    },
    StaticAsset {
        path: "vendor/elk.bundled.js",
        content_type: "text/javascript; charset=utf-8",
        bytes: include_bytes!("../static/vendor/elk.bundled.js"),
    },
    StaticAsset {
        path: "vendor/klay.js",
        content_type: "text/javascript; charset=utf-8",
        bytes: include_bytes!("../static/vendor/klay.js"),
    },
    StaticAsset {
        path: "vendor/tailwindcss.js",
        content_type: "text/javascript; charset=utf-8",
        bytes: include_bytes!("../static/vendor/tailwindcss.js"),
    },
];

pub fn static_assets() -> &'static [StaticAsset] {
    STATIC_ASSETS
}

pub fn static_asset(path: &str) -> Option<StaticAsset> {
    let normalized = path.trim_start_matches('/');
    let asset_path = match normalized {
        "" | "static" | "static/" | "static/index.html" | "index.html" => "index.html",
        other => other.strip_prefix("static/").unwrap_or(other),
    };
    STATIC_ASSETS
        .iter()
        .copied()
        .find(|asset| asset.path == asset_path)
}

fn sqlite_file_options(path: &Path) -> SqliteConnectOptions {
    SqliteConnectOptions::new().filename(path)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationReport {
    pub projects: u64,
    pub facts: u64,
    pub intents: u64,
    pub intent_sources: u64,
    pub hints: u64,
}

#[derive(Clone)]
pub struct ClairvoyantService {
    pool: SqlitePool,
    write_lock: Arc<Mutex<()>>,
}

impl ClairvoyantService {
    pub async fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_busy_timeout(path, Duration::from_millis(5000)).await
    }

    async fn open_with_busy_timeout(
        path: impl AsRef<Path>,
        busy_timeout: Duration,
    ) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let options = sqlite_file_options(path)
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .busy_timeout(busy_timeout)
            .disable_statement_logging();

        let pool = SqlitePoolOptions::new()
            .min_connections(1)
            .max_connections(16)
            .connect_with(options)
            .await?;

        for statement in SCHEMA.split(';') {
            let statement = statement.trim();
            if !statement.is_empty() {
                with_busy_retry(|| async { sqlx::query(statement).execute(&pool).await }).await?;
            }
        }

        Ok(Self {
            pool,
            write_lock: Arc::new(Mutex::new(())),
        })
    }

    pub fn default_db_path() -> PathBuf {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        home.join(".local/share/clairvoyant/clairvoyant-rs.db")
    }

    pub fn spawn_expirer(&self) {
        let service = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            loop {
                interval.tick().await;
                if let Err(err) = service.expire_leases(None).await {
                    tracing::warn!(error = %err, "lease expiration failed");
                }
            }
        });
    }

    pub async fn migrate_from_python_db(
        from_path: impl AsRef<Path>,
        to_path: impl AsRef<Path>,
    ) -> Result<MigrationReport> {
        let source_options = sqlite_file_options(from_path.as_ref())
            .foreign_keys(true)
            .disable_statement_logging();
        let source = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(source_options)
            .await?;
        validate_python_source_schema(&source).await?;
        validate_python_source_settings(&source).await?;
        validate_python_source_required_text(&source).await?;
        validate_python_source_id_formats(&source).await?;
        validate_python_source_uniqueness(&source).await?;
        validate_python_source_timestamps(&source).await?;
        validate_python_source_leases(&source).await?;
        validate_python_source_references(&source).await?;
        validate_python_source_intent_sources(&source).await?;
        validate_python_source_project_facts(&source).await?;
        validate_python_source_project_runtime_state(&source).await?;
        validate_python_source_completion_state(&source).await?;
        let target = Self::open(to_path).await?;
        target.ensure_empty_for_migration().await?;
        target.copy_python_data(&source).await
    }

    async fn ensure_empty_for_migration(&self) -> Result<()> {
        for table in [
            "projects",
            "facts",
            "intents",
            "intent_sources",
            "hints",
            "scoped_counters",
        ] {
            let count: i64 = sqlx::query(&format!("SELECT COUNT(*) AS count FROM {table}"))
                .fetch_one(&self.pool)
                .await?
                .get("count");
            if count != 0 {
                return Err(ClairvoyantError::api(
                    409,
                    format!(
                        "target database is not empty; table {table} has {count} rows, refusing to migrate over existing data"
                    ),
                ));
            }
        }
        let dirty_counter_count: i64 = sqlx::query(
            "SELECT COUNT(*) AS count FROM counters WHERE NOT (name = 'project' AND value = 0)",
        )
        .fetch_one(&self.pool)
        .await?
        .get("count");
        if dirty_counter_count != 0 {
            return Err(ClairvoyantError::api(
                409,
                "target database is not empty; counters contain non-default rows, refusing to migrate over existing data",
            ));
        }
        Ok(())
    }

    async fn copy_python_data(&self, source: &SqlitePool) -> Result<MigrationReport> {
        let _guard = self.write_lock.lock().await;
        let mut tx = begin_immediate(&self.pool).await?;

        if let Some(settings) =
            sqlx::query("SELECT intent_timeout, reason_timeout FROM settings WHERE rowid = 1")
                .fetch_optional(source)
                .await?
        {
            sqlx::query(
                "UPDATE settings SET intent_timeout = ?, reason_timeout = ? WHERE rowid = 1",
            )
            .bind(settings.get::<i64, _>("intent_timeout"))
            .bind(settings.get::<i64, _>("reason_timeout"))
            .execute(&mut *tx)
            .await?;
        }

        let project_rows = sqlx::query("SELECT * FROM projects ORDER BY created_at")
            .fetch_all(source)
            .await?;
        for row in &project_rows {
            sqlx::query(
                r#"
                INSERT INTO projects
                    (id, title, status, created_at_ms, reason_worker, reason_trigger, reason_started_at_ms, reason_last_heartbeat_at_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(row.get::<String, _>("id"))
            .bind(row.get::<String, _>("title"))
            .bind(row.get::<String, _>("status"))
            .bind(parse_python_ts(row.get::<String, _>("created_at"))?)
            .bind(row.get::<Option<String>, _>("reason_worker"))
            .bind(row.get::<Option<String>, _>("reason_trigger"))
            .bind(parse_python_ts_opt(row.get::<Option<String>, _>("reason_started_at"))?)
            .bind(parse_python_ts_opt(row.get::<Option<String>, _>("reason_last_heartbeat_at"))?)
            .execute(&mut *tx)
            .await?;
        }

        let fact_rows = sqlx::query("SELECT id, project_id, description FROM facts ORDER BY rowid")
            .fetch_all(source)
            .await?;
        for row in &fact_rows {
            sqlx::query("INSERT INTO facts (id, project_id, description) VALUES (?, ?, ?)")
                .bind(row.get::<String, _>("id"))
                .bind(row.get::<String, _>("project_id"))
                .bind(row.get::<String, _>("description"))
                .execute(&mut *tx)
                .await?;
        }

        let intent_rows = sqlx::query("SELECT * FROM intents ORDER BY created_at")
            .fetch_all(source)
            .await?;
        for row in &intent_rows {
            sqlx::query(
                r#"
                INSERT INTO intents
                    (id, project_id, target_fact, description, creator, worker, last_heartbeat_at_ms, created_at_ms, concluded_at_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(row.get::<String, _>("id"))
            .bind(row.get::<String, _>("project_id"))
            .bind(row.get::<Option<String>, _>("to_fact_id"))
            .bind(row.get::<String, _>("description"))
            .bind(row.get::<String, _>("creator"))
            .bind(row.get::<Option<String>, _>("worker"))
            .bind(parse_python_ts_opt(row.get::<Option<String>, _>("last_heartbeat_at"))?)
            .bind(parse_python_ts(row.get::<String, _>("created_at"))?)
            .bind(parse_python_ts_opt(row.get::<Option<String>, _>("concluded_at"))?)
            .execute(&mut *tx)
            .await?;
        }

        let source_rows =
            sqlx::query("SELECT intent_id, project_id, fact_id FROM intent_sources ORDER BY rowid")
                .fetch_all(source)
                .await?;
        let mut source_ordinals: std::collections::HashMap<(String, String), i64> =
            std::collections::HashMap::new();
        for row in &source_rows {
            let intent_id = row.get::<String, _>("intent_id");
            let project_id = row.get::<String, _>("project_id");
            let ordinal = source_ordinals
                .entry((intent_id.clone(), project_id.clone()))
                .and_modify(|value| *value += 1)
                .or_insert(0);
            sqlx::query(
                "INSERT INTO intent_sources (intent_id, project_id, fact_id, ordinal) VALUES (?, ?, ?, ?)",
            )
            .bind(intent_id)
            .bind(project_id)
            .bind(row.get::<String, _>("fact_id"))
            .bind(*ordinal)
            .execute(&mut *tx)
            .await?;
        }

        let hint_rows = sqlx::query(
            "SELECT id, project_id, content, creator, created_at FROM hints ORDER BY created_at",
        )
        .fetch_all(source)
        .await?;
        for row in &hint_rows {
            sqlx::query(
                "INSERT INTO hints (id, project_id, content, creator, created_at_ms) VALUES (?, ?, ?, ?, ?)",
            )
            .bind(row.get::<String, _>("id"))
            .bind(row.get::<String, _>("project_id"))
            .bind(row.get::<String, _>("content"))
            .bind(row.get::<String, _>("creator"))
            .bind(parse_python_ts(row.get::<String, _>("created_at"))?)
            .execute(&mut *tx)
            .await?;
        }

        rebuild_counters(&mut tx).await?;
        tx.commit().await?;

        Ok(MigrationReport {
            projects: project_rows.len() as u64,
            facts: fact_rows.len() as u64,
            intents: intent_rows.len() as u64,
            intent_sources: source_rows.len() as u64,
            hints: hint_rows.len() as u64,
        })
    }

    pub async fn handle_envelope(&self, request: ClairvoyantRequest) -> ClairvoyantEnvelope {
        match self.handle(request).await {
            Ok(response) => ClairvoyantEnvelope::Ok {
                response: Box::new(response),
            },
            Err(error) => ClairvoyantEnvelope::Err {
                error: error.into_body(),
            },
        }
    }

    pub async fn handle(&self, request: ClairvoyantRequest) -> Result<ClairvoyantResponse> {
        match request {
            ClairvoyantRequest::GetSettings => {
                Ok(ClairvoyantResponse::Settings(self.get_settings().await?))
            }
            ClairvoyantRequest::PutSettings { settings } => Ok(ClairvoyantResponse::Settings(
                self.put_settings(settings).await?,
            )),
            ClairvoyantRequest::ListProjects => Ok(ClairvoyantResponse::ProjectSummaries(
                self.list_projects().await?,
            )),
            ClairvoyantRequest::Observe { project_id } => Ok(ClairvoyantResponse::Observation(
                self.observe(project_id.as_deref()).await?,
            )),
            ClairvoyantRequest::CreateProject { body } => Ok(ClairvoyantResponse::ProjectDetail(
                self.create_project(body).await?,
            )),
            ClairvoyantRequest::GetProject { project_id } => Ok(
                ClairvoyantResponse::ProjectDetail(self.get_project(&project_id).await?),
            ),
            ClairvoyantRequest::DeleteProject { project_id } => {
                self.delete_project(&project_id).await?;
                Ok(ClairvoyantResponse::Empty)
            }
            ClairvoyantRequest::UpdateProjectTitle { project_id, body } => {
                Ok(ClairvoyantResponse::ProjectMeta(
                    self.update_project_title(&project_id, body).await?,
                ))
            }
            ClairvoyantRequest::UpdateProjectStatus { project_id, body } => {
                Ok(ClairvoyantResponse::ProjectMeta(
                    self.update_project_status(&project_id, body).await?,
                ))
            }
            ClairvoyantRequest::ClaimProjectReason { project_id, body } => {
                Ok(ClairvoyantResponse::ProjectMeta(
                    self.claim_project_reason(&project_id, body).await?,
                ))
            }
            ClairvoyantRequest::HeartbeatProjectReason { project_id, body } => {
                Ok(ClairvoyantResponse::ProjectMeta(
                    self.heartbeat_project_reason(&project_id, body).await?,
                ))
            }
            ClairvoyantRequest::ReleaseProjectReason { project_id, body } => {
                Ok(ClairvoyantResponse::ProjectMeta(
                    self.release_project_reason(&project_id, body).await?,
                ))
            }
            ClairvoyantRequest::CompleteProject { project_id, body } => Ok(
                ClairvoyantResponse::Intent(self.complete_project(&project_id, body).await?),
            ),
            ClairvoyantRequest::ReopenProject { project_id, body } => Ok(
                ClairvoyantResponse::Reopen(self.reopen_project(&project_id, body).await?),
            ),
            ClairvoyantRequest::CreateHint { project_id, body } => Ok(ClairvoyantResponse::Hint(
                self.create_hint(&project_id, body).await?,
            )),
            ClairvoyantRequest::CreateIntent { project_id, body } => Ok(
                ClairvoyantResponse::Intent(self.create_intent(&project_id, body).await?),
            ),
            ClairvoyantRequest::HeartbeatIntent {
                project_id,
                intent_id,
                body,
            } => Ok(ClairvoyantResponse::Intent(
                self.heartbeat_intent(&project_id, &intent_id, body).await?,
            )),
            ClairvoyantRequest::ReleaseIntent {
                project_id,
                intent_id,
                body,
            } => Ok(ClairvoyantResponse::Intent(
                self.release_intent(&project_id, &intent_id, body).await?,
            )),
            ClairvoyantRequest::ConcludeIntent {
                project_id,
                intent_id,
                body,
            } => Ok(ClairvoyantResponse::Conclude(
                self.conclude_intent(&project_id, &intent_id, body).await?,
            )),
            ClairvoyantRequest::ExportProject { project_id, format } => Ok(
                ClairvoyantResponse::Text(self.export_project(&project_id, format).await?),
            ),
        }
    }

    async fn get_settings(&self) -> Result<Settings> {
        let row =
            sqlx::query("SELECT intent_timeout, reason_timeout FROM settings WHERE rowid = 1")
                .fetch_one(&self.pool)
                .await?;
        Ok(Settings {
            intent_timeout: row.get("intent_timeout"),
            reason_timeout: row.get("reason_timeout"),
        })
    }

    async fn put_settings(&self, settings: Settings) -> Result<Settings> {
        validate_timeout(settings.intent_timeout)?;
        validate_timeout(settings.reason_timeout)?;
        let _guard = self.write_lock.lock().await;
        with_busy_retry(|| async {
            sqlx::query(
                "UPDATE settings SET intent_timeout = ?, reason_timeout = ? WHERE rowid = 1",
            )
            .bind(settings.intent_timeout)
            .bind(settings.reason_timeout)
            .execute(&self.pool)
            .await
        })
        .await?;
        Ok(settings)
    }

    async fn list_projects(&self) -> Result<Vec<ProjectSummary>> {
        let rows = sqlx::query(
            r#"
            SELECT p.*,
                (SELECT COUNT(*) FROM facts WHERE project_id = p.id) AS fact_count,
                (SELECT COUNT(*) FROM intents WHERE project_id = p.id) AS intent_count,
                (SELECT COUNT(*) FROM intents WHERE project_id = p.id AND concluded_at_ms IS NULL AND worker IS NOT NULL) AS working_intent_count,
                (SELECT COUNT(*) FROM intents WHERE project_id = p.id AND concluded_at_ms IS NULL AND worker IS NULL) AS unclaimed_intent_count,
                (SELECT COUNT(*) FROM hints WHERE project_id = p.id) AS hint_count
            FROM projects p
            ORDER BY p.created_at_ms
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                Ok(ProjectSummary {
                    project: project_meta_from_row(&row)?,
                    fact_count: row.get("fact_count"),
                    intent_count: row.get("intent_count"),
                    working_intent_count: row.get("working_intent_count"),
                    unclaimed_intent_count: row.get("unclaimed_intent_count"),
                    hint_count: row.get("hint_count"),
                })
            })
            .collect()
    }

    async fn observe(&self, project_id: Option<&str>) -> Result<ObservationSnapshot> {
        let generated_at = now_ms();
        let details = if let Some(project_id) = project_id {
            vec![self.get_project(project_id).await?]
        } else {
            let summaries = self.list_projects().await?;
            let mut details = Vec::with_capacity(summaries.len());
            for summary in summaries {
                details.push(self.get_project(&summary.project.id).await?);
            }
            details
        };
        let projects = details
            .into_iter()
            .map(|detail| project_observation(detail, generated_at))
            .collect::<Vec<_>>();
        Ok(ObservationSnapshot {
            generated_at,
            project_count: projects.len(),
            projects,
        })
    }

    async fn create_project(&self, body: CreateProjectRequest) -> Result<ProjectDetail> {
        validate_non_empty("title", &body.title)?;
        validate_non_empty("origin", &body.origin)?;
        validate_non_empty("goal", &body.goal)?;

        let _guard = self.write_lock.lock().await;
        let mut tx = begin_immediate(&self.pool).await?;
        let pid = next_project_id(&mut tx).await?;
        let now = now_ms();

        sqlx::query(
            "INSERT INTO projects (id, title, status, created_at_ms) VALUES (?, ?, 'active', ?)",
        )
        .bind(&pid)
        .bind(body.title.trim())
        .bind(now)
        .execute(&mut *tx)
        .await?;
        sqlx::query("INSERT INTO facts (id, project_id, description) VALUES (?, ?, ?)")
            .bind("origin")
            .bind(&pid)
            .bind(body.origin.trim())
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO facts (id, project_id, description) VALUES (?, ?, ?)")
            .bind("goal")
            .bind(&pid)
            .bind(body.goal.trim())
            .execute(&mut *tx)
            .await?;

        let mut hints = Vec::new();
        if let Some(inline_hints) = body.hints {
            for hint in inline_hints {
                validate_non_empty("content", &hint.content)?;
                validate_non_empty("creator", &hint.creator)?;
                let hid = next_scoped_id(&mut tx, "hint", "h", &pid).await?;
                sqlx::query(
                    "INSERT INTO hints (id, project_id, content, creator, created_at_ms) VALUES (?, ?, ?, ?, ?)",
                )
                .bind(&hid)
                .bind(&pid)
                .bind(hint.content.trim())
                .bind(hint.creator.trim())
                .bind(now)
                .execute(&mut *tx)
                .await?;
                hints.push(Hint {
                    id: hid,
                    content: hint.content.trim().to_string(),
                    creator: hint.creator.trim().to_string(),
                    created_at: now,
                });
            }
        }

        tx.commit().await?;
        Ok(ProjectDetail {
            project: ProjectMeta {
                id: pid,
                title: body.title.trim().to_string(),
                status: ProjectStatus::Active,
                created_at: now,
                reason: None,
            },
            facts: vec![
                Fact {
                    id: "origin".to_string(),
                    description: body.origin.trim().to_string(),
                },
                Fact {
                    id: "goal".to_string(),
                    description: body.goal.trim().to_string(),
                },
            ],
            intents: Vec::new(),
            hints,
        })
    }

    async fn get_project(&self, project_id: &str) -> Result<ProjectDetail> {
        let project = get_project_or_404(&self.pool, project_id).await?;
        let facts =
            sqlx::query("SELECT id, description FROM facts WHERE project_id = ? ORDER BY rowid")
                .bind(project_id)
                .fetch_all(&self.pool)
                .await?
                .into_iter()
                .map(|row| Fact {
                    id: row.get("id"),
                    description: row.get("description"),
                })
                .collect();
        let hints = sqlx::query(
            "SELECT id, content, creator, created_at_ms FROM hints WHERE project_id = ? ORDER BY created_at_ms",
        )
        .bind(project_id)
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|row| Hint {
            id: row.get("id"),
            content: row.get("content"),
            creator: row.get("creator"),
            created_at: row.get("created_at_ms"),
        })
        .collect();
        let intents = self.build_intents(project_id).await?;
        Ok(ProjectDetail {
            project,
            facts,
            intents,
            hints,
        })
    }

    async fn delete_project(&self, project_id: &str) -> Result<()> {
        let _guard = self.write_lock.lock().await;
        get_project_or_404(&self.pool, project_id).await?;
        with_busy_retry(|| async {
            sqlx::query("DELETE FROM projects WHERE id = ?")
                .bind(project_id)
                .execute(&self.pool)
                .await
        })
        .await?;
        Ok(())
    }

    async fn update_project_title(
        &self,
        project_id: &str,
        body: UpdateProjectTitleRequest,
    ) -> Result<ProjectMeta> {
        validate_non_empty("title", &body.title)?;
        let _guard = self.write_lock.lock().await;
        get_project_or_404(&self.pool, project_id).await?;
        with_busy_retry(|| async {
            sqlx::query("UPDATE projects SET title = ? WHERE id = ?")
                .bind(body.title.trim())
                .bind(project_id)
                .execute(&self.pool)
                .await
        })
        .await?;
        get_project_or_404(&self.pool, project_id).await
    }

    async fn update_project_status(
        &self,
        project_id: &str,
        body: UpdateProjectStatusRequest,
    ) -> Result<ProjectMeta> {
        if matches!(body.status, ProjectStatus::Completed) {
            return Err(ClairvoyantError::api(
                400,
                "Use complete_project to mark projects completed",
            ));
        }
        let _guard = self.write_lock.lock().await;
        let row = get_project_row_or_404(&self.pool, project_id).await?;
        let current = status_from_str(row.get("status"))?;
        if matches!(current, ProjectStatus::Completed) {
            return Err(ClairvoyantError::api(
                409,
                "Completed projects cannot change status",
            ));
        }
        if current.as_str() == body.status.as_str() {
            return project_meta_from_row(&row);
        }
        with_busy_retry(|| async {
            sqlx::query("UPDATE projects SET status = ? WHERE id = ?")
                .bind(body.status.as_str())
                .bind(project_id)
                .execute(&self.pool)
                .await
        })
        .await?;
        if matches!(body.status, ProjectStatus::Stopped) {
            with_busy_retry(|| async {
                sqlx::query(
                    "UPDATE intents SET worker = NULL, last_heartbeat_at_ms = NULL WHERE project_id = ? AND concluded_at_ms IS NULL",
                )
                .bind(project_id)
                .execute(&self.pool)
                .await
            })
            .await?;
            clear_project_reason(&self.pool, project_id).await?;
        }
        get_project_or_404(&self.pool, project_id).await
    }

    async fn claim_project_reason(
        &self,
        project_id: &str,
        body: ReasonClaimRequest,
    ) -> Result<ProjectMeta> {
        validate_non_empty("worker", &body.worker)?;
        validate_non_empty("trigger", &body.trigger)?;
        let _guard = self.write_lock.lock().await;
        check_project_active(&self.pool, project_id).await?;
        let row = get_project_row_or_404(&self.pool, project_id).await?;
        let current_worker: Option<String> = row.get("reason_worker");
        let worker = body.worker.trim();
        if let Some(current_worker) = current_worker {
            if current_worker != worker {
                return Err(ClairvoyantError::api(
                    409,
                    format!("Project reason is currently claimed by {current_worker}"),
                ));
            }
            return project_meta_from_row(&row);
        }
        let now = now_ms();
        with_busy_retry(|| async {
            sqlx::query(
                r#"
                UPDATE projects
                SET reason_worker = ?,
                    reason_trigger = ?,
                    reason_started_at_ms = ?,
                    reason_last_heartbeat_at_ms = ?
                WHERE id = ?
                "#,
            )
            .bind(body.worker.trim())
            .bind(body.trigger.trim())
            .bind(now)
            .bind(now)
            .bind(project_id)
            .execute(&self.pool)
            .await
        })
        .await?;
        get_project_or_404(&self.pool, project_id).await
    }

    async fn heartbeat_project_reason(
        &self,
        project_id: &str,
        body: HeartbeatRequest,
    ) -> Result<ProjectMeta> {
        validate_non_empty("worker", &body.worker)?;
        let _guard = self.write_lock.lock().await;
        check_project_active(&self.pool, project_id).await?;
        let row = get_project_row_or_404(&self.pool, project_id).await?;
        let current_worker: Option<String> = row.get("reason_worker");
        let worker = body.worker.trim();
        match current_worker {
            None => {
                return Err(ClairvoyantError::api(
                    409,
                    "Project reason is not currently claimed",
                ))
            }
            Some(current) if current != worker => {
                return Err(ClairvoyantError::api(
                    409,
                    format!("Project reason is currently claimed by {current}"),
                ));
            }
            Some(_) => {}
        }
        with_busy_retry(|| async {
            sqlx::query("UPDATE projects SET reason_last_heartbeat_at_ms = ? WHERE id = ?")
                .bind(now_ms())
                .bind(project_id)
                .execute(&self.pool)
                .await
        })
        .await?;
        get_project_or_404(&self.pool, project_id).await
    }

    async fn release_project_reason(
        &self,
        project_id: &str,
        body: HeartbeatRequest,
    ) -> Result<ProjectMeta> {
        validate_non_empty("worker", &body.worker)?;
        let _guard = self.write_lock.lock().await;
        check_project_active(&self.pool, project_id).await?;
        let row = get_project_row_or_404(&self.pool, project_id).await?;
        let current_worker: Option<String> = row.get("reason_worker");
        let worker = body.worker.trim();
        if let Some(current) = current_worker {
            if current != worker {
                return Err(ClairvoyantError::api(
                    409,
                    format!("Project reason is currently claimed by {current}"),
                ));
            }
            clear_project_reason(&self.pool, project_id).await?;
        }
        get_project_or_404(&self.pool, project_id).await
    }

    async fn complete_project(&self, project_id: &str, body: CompleteRequest) -> Result<Intent> {
        validate_non_empty("description", &body.description)?;
        validate_non_empty("worker", &body.worker)?;
        validate_fact_ids(&body.sources)?;
        validate_goal_not_in_sources(&body.sources)?;
        let _guard = self.write_lock.lock().await;
        check_project_active(&self.pool, project_id).await?;
        validate_facts_exist(&self.pool, project_id, &body.sources).await?;

        let mut tx = begin_immediate(&self.pool).await?;
        let now = now_ms();
        let iid = next_scoped_id(&mut tx, "intent", "i", project_id).await?;
        sqlx::query(
            "INSERT INTO intents (id, project_id, target_fact, description, creator, worker, last_heartbeat_at_ms, created_at_ms, concluded_at_ms) VALUES (?, ?, 'goal', ?, ?, ?, ?, ?, ?)",
        )
        .bind(&iid)
        .bind(project_id)
        .bind(body.description.trim())
        .bind(body.worker.trim())
        .bind(body.worker.trim())
        .bind(now)
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        insert_sources(&mut tx, &iid, project_id, &body.sources).await?;
        sqlx::query(
            r#"
            UPDATE projects
            SET status = 'completed',
                reason_worker = NULL,
                reason_trigger = NULL,
                reason_started_at_ms = NULL,
                reason_last_heartbeat_at_ms = NULL
            WHERE id = ?
            "#,
        )
        .bind(project_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE intents SET worker = NULL, last_heartbeat_at_ms = NULL WHERE project_id = ? AND target_fact IS NULL",
        )
        .bind(project_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        self.intent_by_id(project_id, &iid).await
    }

    async fn reopen_project(
        &self,
        project_id: &str,
        body: ReopenRequest,
    ) -> Result<ReopenResponse> {
        validate_non_empty("description", &body.description)?;
        validate_non_empty("creator", &body.creator)?;
        let _guard = self.write_lock.lock().await;
        check_project_completed(&self.pool, project_id).await?;
        let completion = get_completion_intent(&self.pool, project_id).await?;
        let completion_id: String = completion.get("id");
        let sources = sources_for_intent(&self.pool, project_id, &completion_id).await?;
        if sources.is_empty() {
            return Err(ClairvoyantError::api(
                409,
                "Completion intent is missing its source facts",
            ));
        }

        let mut tx = begin_immediate(&self.pool).await?;
        let now = now_ms();
        let fact_id = next_scoped_id(&mut tx, "fact", "f", project_id).await?;
        let intent_id = next_scoped_id(&mut tx, "intent", "i", project_id).await?;
        sqlx::query("DELETE FROM intents WHERE id = ? AND project_id = ?")
            .bind(&completion_id)
            .bind(project_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO facts (id, project_id, description) VALUES (?, ?, ?)")
            .bind(&fact_id)
            .bind(project_id)
            .bind(body.description.trim())
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO intents (id, project_id, target_fact, description, creator, worker, last_heartbeat_at_ms, created_at_ms, concluded_at_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&intent_id)
        .bind(project_id)
        .bind(&fact_id)
        .bind("external_feedback")
        .bind(body.creator.trim())
        .bind(body.creator.trim())
        .bind(now)
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        insert_sources(&mut tx, &intent_id, project_id, &sources).await?;
        sqlx::query(
            "UPDATE projects SET status = 'active', reason_worker = NULL, reason_trigger = NULL, reason_started_at_ms = NULL, reason_last_heartbeat_at_ms = NULL WHERE id = ?",
        )
        .bind(project_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(ReopenResponse {
            project: get_project_or_404(&self.pool, project_id).await?,
            fact: Fact {
                id: fact_id,
                description: body.description.trim().to_string(),
            },
            intent: self.intent_by_id(project_id, &intent_id).await?,
        })
    }

    async fn create_hint(&self, project_id: &str, body: CreateHintRequest) -> Result<Hint> {
        validate_non_empty("content", &body.content)?;
        validate_non_empty("creator", &body.creator)?;
        let _guard = self.write_lock.lock().await;
        check_project_active(&self.pool, project_id).await?;
        let mut tx = begin_immediate(&self.pool).await?;
        let now = now_ms();
        let hid = next_scoped_id(&mut tx, "hint", "h", project_id).await?;
        sqlx::query("INSERT INTO hints (id, project_id, content, creator, created_at_ms) VALUES (?, ?, ?, ?, ?)")
            .bind(&hid)
            .bind(project_id)
            .bind(body.content.trim())
            .bind(body.creator.trim())
            .bind(now)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(Hint {
            id: hid,
            content: body.content.trim().to_string(),
            creator: body.creator.trim().to_string(),
            created_at: now,
        })
    }

    async fn create_intent(&self, project_id: &str, body: CreateIntentRequest) -> Result<Intent> {
        validate_non_empty("description", &body.description)?;
        validate_non_empty("creator", &body.creator)?;
        if let Some(worker) = &body.worker {
            validate_non_empty("worker", worker)?;
            if worker.trim() != body.creator.trim() {
                return Err(ClairvoyantError::api(
                    400,
                    "worker must be null or equal to creator",
                ));
            }
        }
        validate_fact_ids(&body.sources)?;
        validate_goal_not_in_sources(&body.sources)?;

        let _guard = self.write_lock.lock().await;
        check_project_active(&self.pool, project_id).await?;
        validate_facts_exist(&self.pool, project_id, &body.sources).await?;
        let mut tx = begin_immediate(&self.pool).await?;
        let now = now_ms();
        let iid = next_scoped_id(&mut tx, "intent", "i", project_id).await?;
        let claimed = body.worker.is_some();
        sqlx::query(
            "INSERT INTO intents (id, project_id, target_fact, description, creator, worker, last_heartbeat_at_ms, created_at_ms, concluded_at_ms) VALUES (?, ?, NULL, ?, ?, ?, ?, ?, NULL)",
        )
        .bind(&iid)
        .bind(project_id)
        .bind(body.description.trim())
        .bind(body.creator.trim())
        .bind(body.worker.as_ref().map(|w| w.trim()))
        .bind(if claimed { Some(now) } else { None })
        .bind(now)
        .execute(&mut *tx)
        .await?;
        insert_sources(&mut tx, &iid, project_id, &body.sources).await?;
        tx.commit().await?;
        self.intent_by_id(project_id, &iid).await
    }

    async fn heartbeat_intent(
        &self,
        project_id: &str,
        intent_id: &str,
        body: HeartbeatRequest,
    ) -> Result<Intent> {
        validate_non_empty("worker", &body.worker)?;
        let _guard = self.write_lock.lock().await;
        check_project_active(&self.pool, project_id).await?;
        get_open_intent(&self.pool, project_id, intent_id, &body.worker).await?;
        with_busy_retry(|| async {
            sqlx::query("UPDATE intents SET worker = ?, last_heartbeat_at_ms = ? WHERE id = ? AND project_id = ?")
                .bind(body.worker.trim())
                .bind(now_ms())
                .bind(intent_id)
                .bind(project_id)
                .execute(&self.pool)
                .await
        })
        .await?;
        self.intent_by_id(project_id, intent_id).await
    }

    async fn release_intent(
        &self,
        project_id: &str,
        intent_id: &str,
        body: HeartbeatRequest,
    ) -> Result<Intent> {
        validate_non_empty("worker", &body.worker)?;
        let _guard = self.write_lock.lock().await;
        check_project_active(&self.pool, project_id).await?;
        let row = get_open_intent(&self.pool, project_id, intent_id, &body.worker).await?;
        let current_worker: Option<String> = row.get("worker");
        if current_worker.as_deref() == Some(body.worker.trim()) {
            with_busy_retry(|| async {
                sqlx::query("UPDATE intents SET worker = NULL, last_heartbeat_at_ms = NULL WHERE id = ? AND project_id = ?")
                    .bind(intent_id)
                    .bind(project_id)
                    .execute(&self.pool)
                    .await
            })
            .await?;
        }
        self.intent_by_id(project_id, intent_id).await
    }

    async fn conclude_intent(
        &self,
        project_id: &str,
        intent_id: &str,
        body: ConcludeRequest,
    ) -> Result<ConcludeResponse> {
        validate_non_empty("worker", &body.worker)?;
        validate_non_empty("description", &body.description)?;
        let _guard = self.write_lock.lock().await;
        check_project_active(&self.pool, project_id).await?;
        let intent_row = get_open_intent(&self.pool, project_id, intent_id, &body.worker).await?;
        // When the intent is unclaimed, require the worker to match the creator.
        // This prevents arbitrary workers from concluding intents they didn't create.
        let current_worker: Option<String> = intent_row.get("worker");
        if current_worker.is_none() {
            let creator: String = intent_row.get("creator");
            if body.worker.trim() != creator.trim() {
                return Err(ClairvoyantError::api(
                    409,
                    format!("Intent is unclaimed; only the creator ({creator}) may conclude it"),
                ));
            }
        }

        let mut tx = begin_immediate(&self.pool).await?;
        let now = now_ms();
        let fid = next_scoped_id(&mut tx, "fact", "f", project_id).await?;
        sqlx::query("INSERT INTO facts (id, project_id, description) VALUES (?, ?, ?)")
            .bind(&fid)
            .bind(project_id)
            .bind(body.description.trim())
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "UPDATE intents SET target_fact = ?, worker = ?, last_heartbeat_at_ms = ?, concluded_at_ms = ? WHERE id = ? AND project_id = ?",
        )
        .bind(&fid)
        .bind(body.worker.trim())
        .bind(now)
        .bind(now)
        .bind(intent_id)
        .bind(project_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        Ok(ConcludeResponse {
            fact: Fact {
                id: fid,
                description: body.description.trim().to_string(),
            },
            intent: self.intent_by_id(project_id, intent_id).await?,
        })
    }

    async fn export_project(&self, project_id: &str, format: ExportFormat) -> Result<String> {
        let detail = self.get_project(project_id).await?;
        match format {
            ExportFormat::Yaml => export_yaml(&detail),
            ExportFormat::Timeline => Ok(export_timeline(&detail)),
        }
    }

    async fn build_intents(&self, project_id: &str) -> Result<Vec<Intent>> {
        let rows = sqlx::query("SELECT * FROM intents WHERE project_id = ? ORDER BY created_at_ms")
            .bind(project_id)
            .fetch_all(&self.pool)
            .await?;
        // Batch-fetch all sources for this project to avoid N+1 queries.
        let all_sources = sqlx::query(
            "SELECT intent_id, fact_id FROM intent_sources WHERE project_id = ? ORDER BY ordinal",
        )
        .bind(project_id)
        .fetch_all(&self.pool)
        .await?;
        let mut sources_by_intent: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        for source_row in &all_sources {
            let intent_id: String = source_row.get("intent_id");
            let fact_id: String = source_row.get("fact_id");
            sources_by_intent
                .entry(intent_id)
                .or_default()
                .push(fact_id);
        }

        let mut intents = Vec::with_capacity(rows.len());
        for row in rows {
            intents.push(intent_from_row_with_sources(&row, &sources_by_intent)?);
        }
        Ok(intents)
    }

    async fn intent_by_id(&self, project_id: &str, intent_id: &str) -> Result<Intent> {
        let row = get_intent_row_or_404(&self.pool, project_id, intent_id).await?;
        intent_from_row(&self.pool, project_id, &row).await
    }

    async fn expire_leases(&self, project_id: Option<&str>) -> Result<()> {
        let _guard = self.write_lock.lock().await;
        self.expire_leases_inner(project_id).await
    }

    async fn expire_leases_inner(&self, project_id: Option<&str>) -> Result<()> {
        let settings = self.get_settings().await?;
        let now = now_ms();
        let intent_cutoff = now - settings.intent_timeout * 1000;
        let reason_cutoff = now - settings.reason_timeout * 1000;

        if let Some(project_id) = project_id {
            with_busy_retry(|| async {
                sqlx::query(
                    "UPDATE intents SET worker = NULL, last_heartbeat_at_ms = NULL WHERE project_id = ? AND target_fact IS NULL AND worker IS NOT NULL AND last_heartbeat_at_ms IS NOT NULL AND last_heartbeat_at_ms < ?",
                )
                .bind(project_id)
                .bind(intent_cutoff)
                .execute(&self.pool)
                .await
            })
            .await?;
            with_busy_retry(|| async {
                sqlx::query(
                    "UPDATE projects SET reason_worker = NULL, reason_trigger = NULL, reason_started_at_ms = NULL, reason_last_heartbeat_at_ms = NULL WHERE id = ? AND reason_worker IS NOT NULL AND reason_last_heartbeat_at_ms IS NOT NULL AND reason_last_heartbeat_at_ms < ?",
                )
                .bind(project_id)
                .bind(reason_cutoff)
                .execute(&self.pool)
                .await
            })
            .await?;
        } else {
            with_busy_retry(|| async {
                sqlx::query(
                    "UPDATE intents SET worker = NULL, last_heartbeat_at_ms = NULL WHERE target_fact IS NULL AND worker IS NOT NULL AND last_heartbeat_at_ms IS NOT NULL AND last_heartbeat_at_ms < ?",
                )
                .bind(intent_cutoff)
                .execute(&self.pool)
                .await
            })
            .await?;
            with_busy_retry(|| async {
                sqlx::query(
                    "UPDATE projects SET reason_worker = NULL, reason_trigger = NULL, reason_started_at_ms = NULL, reason_last_heartbeat_at_ms = NULL WHERE reason_worker IS NOT NULL AND reason_last_heartbeat_at_ms IS NOT NULL AND reason_last_heartbeat_at_ms < ?",
                )
                .bind(reason_cutoff)
                .execute(&self.pool)
                .await
            })
            .await?;
        }
        Ok(())
    }
}

async fn next_project_id(tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>) -> Result<String> {
    sqlx::query("UPDATE counters SET value = value + 1 WHERE name = 'project'")
        .execute(&mut **tx)
        .await?;
    let row = sqlx::query("SELECT value FROM counters WHERE name = 'project'")
        .fetch_one(&mut **tx)
        .await?;
    let value: i64 = row.get("value");
    Ok(format!("proj_{value:03}"))
}

async fn next_scoped_id(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    kind: &str,
    prefix: &str,
    project_id: &str,
) -> Result<String> {
    sqlx::query("INSERT OR IGNORE INTO scoped_counters (project_id, kind, value) VALUES (?, ?, 0)")
        .bind(project_id)
        .bind(kind)
        .execute(&mut **tx)
        .await?;
    sqlx::query("UPDATE scoped_counters SET value = value + 1 WHERE project_id = ? AND kind = ?")
        .bind(project_id)
        .bind(kind)
        .execute(&mut **tx)
        .await?;
    let row = sqlx::query("SELECT value FROM scoped_counters WHERE project_id = ? AND kind = ?")
        .bind(project_id)
        .bind(kind)
        .fetch_one(&mut **tx)
        .await?;
    let value: i64 = row.get("value");
    Ok(format!("{prefix}{value:03}"))
}

async fn insert_sources(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    intent_id: &str,
    project_id: &str,
    sources: &[String],
) -> Result<()> {
    for (ordinal, source) in sources.iter().enumerate() {
        sqlx::query(
            "INSERT INTO intent_sources (intent_id, project_id, fact_id, ordinal) VALUES (?, ?, ?, ?)",
        )
        .bind(intent_id)
        .bind(project_id)
        .bind(source.trim())
        .bind(ordinal as i64)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

async fn rebuild_counters(tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>) -> Result<()> {
    let project_rows = sqlx::query("SELECT id FROM projects")
        .fetch_all(&mut **tx)
        .await?;
    let project_max = project_rows
        .iter()
        .filter_map(|row| parse_prefixed_number(row.get::<String, _>("id").as_str(), "proj_"))
        .max()
        .unwrap_or(0);
    sqlx::query("UPDATE counters SET value = ? WHERE name = 'project'")
        .bind(project_max)
        .execute(&mut **tx)
        .await?;

    let project_ids = sqlx::query("SELECT id FROM projects")
        .fetch_all(&mut **tx)
        .await?;
    for project in project_ids {
        let project_id: String = project.get("id");
        for (kind, table, prefix) in [
            ("fact", "facts", "f"),
            ("intent", "intents", "i"),
            ("hint", "hints", "h"),
        ] {
            let query = format!("SELECT id FROM {table} WHERE project_id = ?");
            let rows = sqlx::query(&query)
                .bind(&project_id)
                .fetch_all(&mut **tx)
                .await?;
            let value = rows
                .iter()
                .filter_map(|row| {
                    parse_prefixed_number(row.get::<String, _>("id").as_str(), prefix)
                })
                .max()
                .unwrap_or(0);
            sqlx::query(
                "INSERT OR REPLACE INTO scoped_counters (project_id, kind, value) VALUES (?, ?, ?)",
            )
            .bind(&project_id)
            .bind(kind)
            .bind(value)
            .execute(&mut **tx)
            .await?;
        }
    }
    Ok(())
}

async fn validate_python_source_schema(source: &SqlitePool) -> Result<()> {
    for (table, required_columns) in [
        ("settings", &["intent_timeout", "reason_timeout"][..]),
        (
            "projects",
            &[
                "id",
                "title",
                "status",
                "created_at",
                "reason_worker",
                "reason_trigger",
                "reason_started_at",
                "reason_last_heartbeat_at",
            ][..],
        ),
        ("facts", &["id", "project_id", "description"][..]),
        (
            "intents",
            &[
                "id",
                "project_id",
                "to_fact_id",
                "description",
                "creator",
                "worker",
                "last_heartbeat_at",
                "created_at",
                "concluded_at",
            ][..],
        ),
        (
            "intent_sources",
            &["intent_id", "project_id", "fact_id"][..],
        ),
        (
            "hints",
            &["id", "project_id", "content", "creator", "created_at"][..],
        ),
    ] {
        let rows = sqlx::query(&format!("PRAGMA table_info({table})"))
            .fetch_all(source)
            .await?;
        if rows.is_empty() {
            return Err(ClairvoyantError::api(
                400,
                format!(
                    "source database is not a Python Clairvoyant database; missing table {table}"
                ),
            ));
        }
        let columns = rows
            .into_iter()
            .map(|row| row.get::<String, _>("name"))
            .collect::<std::collections::BTreeSet<_>>();
        let missing = required_columns
            .iter()
            .copied()
            .filter(|column| !columns.contains(*column))
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            return Err(ClairvoyantError::api(
                400,
                format!(
                    "source database is not a Python Clairvoyant database; table {table} is missing columns: {}",
                    missing.join(", ")
                ),
            ));
        }
    }
    Ok(())
}

async fn validate_python_source_settings(source: &SqlitePool) -> Result<()> {
    let rows = sqlx::query("SELECT rowid, intent_timeout, reason_timeout FROM settings")
        .fetch_all(source)
        .await?;
    if rows.len() != 1 || rows[0].get::<i64, _>("rowid") != 1 {
        return Err(ClairvoyantError::api(
            400,
            "source database settings table must contain exactly one row at rowid 1",
        ));
    }
    validate_timeout(rows[0].get::<i64, _>("intent_timeout"))?;
    validate_timeout(rows[0].get::<i64, _>("reason_timeout"))?;
    Ok(())
}

async fn validate_python_source_required_text(source: &SqlitePool) -> Result<()> {
    for row in sqlx::query("SELECT id, title FROM projects")
        .fetch_all(source)
        .await?
    {
        let id = row.get::<String, _>("id");
        validate_non_empty("project id", &id)?;
        validate_non_empty("project title", &row.get::<String, _>("title"))?;
    }
    for row in sqlx::query("SELECT id, project_id, description FROM facts")
        .fetch_all(source)
        .await?
    {
        let id = row.get::<String, _>("id");
        let project_id = row.get::<String, _>("project_id");
        validate_non_empty("fact id", &id)?;
        validate_non_empty(
            &format!("fact {id} description in project {project_id}"),
            &row.get::<String, _>("description"),
        )?;
    }
    for row in sqlx::query("SELECT id, project_id, description, creator FROM intents")
        .fetch_all(source)
        .await?
    {
        let id = row.get::<String, _>("id");
        let project_id = row.get::<String, _>("project_id");
        validate_non_empty("intent id", &id)?;
        validate_non_empty(
            &format!("intent {id} description in project {project_id}"),
            &row.get::<String, _>("description"),
        )?;
        validate_non_empty(
            &format!("intent {id} creator in project {project_id}"),
            &row.get::<String, _>("creator"),
        )?;
    }
    for row in sqlx::query("SELECT id, project_id, content, creator FROM hints")
        .fetch_all(source)
        .await?
    {
        let id = row.get::<String, _>("id");
        let project_id = row.get::<String, _>("project_id");
        validate_non_empty("hint id", &id)?;
        validate_non_empty(
            &format!("hint {id} content in project {project_id}"),
            &row.get::<String, _>("content"),
        )?;
        validate_non_empty(
            &format!("hint {id} creator in project {project_id}"),
            &row.get::<String, _>("creator"),
        )?;
    }
    Ok(())
}

async fn validate_python_source_id_formats(source: &SqlitePool) -> Result<()> {
    for row in sqlx::query("SELECT id FROM projects")
        .fetch_all(source)
        .await?
    {
        let id = row.get::<String, _>("id");
        validate_prefixed_id("project id", &id, "proj_")?;
    }
    for row in sqlx::query("SELECT id, project_id FROM facts")
        .fetch_all(source)
        .await?
    {
        let id = row.get::<String, _>("id");
        if id != "origin" && id != "goal" {
            validate_prefixed_id(
                &format!("fact id in project {}", row.get::<String, _>("project_id")),
                &id,
                "f",
            )?;
        }
    }
    for row in sqlx::query("SELECT id, project_id FROM intents")
        .fetch_all(source)
        .await?
    {
        validate_prefixed_id(
            &format!(
                "intent id in project {}",
                row.get::<String, _>("project_id")
            ),
            &row.get::<String, _>("id"),
            "i",
        )?;
    }
    for row in sqlx::query("SELECT id, project_id FROM hints")
        .fetch_all(source)
        .await?
    {
        validate_prefixed_id(
            &format!("hint id in project {}", row.get::<String, _>("project_id")),
            &row.get::<String, _>("id"),
            "h",
        )?;
    }
    Ok(())
}

async fn validate_python_source_uniqueness(source: &SqlitePool) -> Result<()> {
    if let Some(row) = sqlx::query(
        "SELECT id, COUNT(*) AS count FROM projects GROUP BY id HAVING COUNT(*) > 1 LIMIT 1",
    )
    .fetch_optional(source)
    .await?
    {
        return Err(ClairvoyantError::api(
            400,
            format!(
                "source database has duplicate project id {}",
                row.get::<String, _>("id")
            ),
        ));
    }
    if let Some(row) = sqlx::query(
        "SELECT project_id, id, COUNT(*) AS count FROM facts GROUP BY project_id, id HAVING COUNT(*) > 1 LIMIT 1",
    )
    .fetch_optional(source)
    .await?
    {
        return Err(ClairvoyantError::api(
            400,
            format!(
                "source database has duplicate fact {} in project {}",
                row.get::<String, _>("id"),
                row.get::<String, _>("project_id")
            ),
        ));
    }
    if let Some(row) = sqlx::query(
        "SELECT project_id, id, COUNT(*) AS count FROM intents GROUP BY project_id, id HAVING COUNT(*) > 1 LIMIT 1",
    )
    .fetch_optional(source)
    .await?
    {
        return Err(ClairvoyantError::api(
            400,
            format!(
                "source database has duplicate intent {} in project {}",
                row.get::<String, _>("id"),
                row.get::<String, _>("project_id")
            ),
        ));
    }
    if let Some(row) = sqlx::query(
        "SELECT project_id, intent_id, fact_id, COUNT(*) AS count FROM intent_sources GROUP BY project_id, intent_id, fact_id HAVING COUNT(*) > 1 LIMIT 1",
    )
    .fetch_optional(source)
    .await?
    {
        return Err(ClairvoyantError::api(
            400,
            format!(
                "source database has duplicate intent source {} -> {} in project {}",
                row.get::<String, _>("intent_id"),
                row.get::<String, _>("fact_id"),
                row.get::<String, _>("project_id")
            ),
        ));
    }
    if let Some(row) = sqlx::query(
        "SELECT project_id, id, COUNT(*) AS count FROM hints GROUP BY project_id, id HAVING COUNT(*) > 1 LIMIT 1",
    )
    .fetch_optional(source)
    .await?
    {
        return Err(ClairvoyantError::api(
            400,
            format!(
                "source database has duplicate hint {} in project {}",
                row.get::<String, _>("id"),
                row.get::<String, _>("project_id")
            ),
        ));
    }
    Ok(())
}

async fn validate_python_source_leases(source: &SqlitePool) -> Result<()> {
    for row in sqlx::query(
        "SELECT id, reason_worker, reason_trigger, reason_started_at, reason_last_heartbeat_at FROM projects",
    )
    .fetch_all(source)
    .await?
    {
        let id = row.get::<String, _>("id");
        let reason_worker = row.get::<Option<String>, _>("reason_worker");
        let reason_trigger = row.get::<Option<String>, _>("reason_trigger");
        validate_optional_non_blank(
            &format!("project {id} reason_worker"),
            &reason_worker,
        )?;
        validate_optional_non_blank(
            &format!("project {id} reason_trigger"),
            &reason_trigger,
        )?;
        let fields = [
            optional_text_present(&reason_worker),
            optional_text_present(&reason_trigger),
            parse_python_ts_opt(row.get::<Option<String>, _>("reason_started_at"))?.is_some(),
            parse_python_ts_opt(row.get::<Option<String>, _>("reason_last_heartbeat_at"))?
                .is_some(),
        ];
        let present = fields.iter().filter(|present| **present).count();
        if present != 0 && present != fields.len() {
            return Err(ClairvoyantError::api(
                400,
                format!(
                    "source database has partial reason lease for project {id}; reason_worker, reason_trigger, reason_started_at, and reason_last_heartbeat_at must be all set or all empty"
                ),
            ));
        }
    }
    for row in sqlx::query(
        "SELECT id, project_id, to_fact_id, worker, last_heartbeat_at, concluded_at FROM intents",
    )
    .fetch_all(source)
    .await?
    {
        let target_fact = row.get::<Option<String>, _>("to_fact_id");
        let target_present = optional_text_present(&target_fact);
        let concluded_present =
            parse_python_ts_opt(row.get::<Option<String>, _>("concluded_at"))?.is_some();
        let id = row.get::<String, _>("id");
        let project_id = row.get::<String, _>("project_id");
        let worker = row.get::<Option<String>, _>("worker");
        validate_optional_non_blank(
            &format!("intent {id} worker in project {project_id}"),
            &worker,
        )?;
        validate_optional_non_blank(
            &format!("intent {id} target fact in project {project_id}"),
            &target_fact,
        )?;
        if target_present != concluded_present {
            return Err(ClairvoyantError::api(
                400,
                format!(
                    "source database has partial concluded state for intent {id} in project {project_id}; to_fact_id and concluded_at must be both set or both empty"
                ),
            ));
        }
        if target_present {
            continue;
        }
        let fields = [
            optional_text_present(&worker),
            parse_python_ts_opt(row.get::<Option<String>, _>("last_heartbeat_at"))?.is_some(),
        ];
        let present = fields.iter().filter(|present| **present).count();
        if present != 0 && present != fields.len() {
            return Err(ClairvoyantError::api(
                400,
                format!(
                    "source database has partial intent lease for intent {id} in project {project_id}; worker and last_heartbeat_at must be both set or both empty for open intents"
                ),
            ));
        }
    }
    Ok(())
}

async fn validate_python_source_timestamps(source: &SqlitePool) -> Result<()> {
    for row in sqlx::query(
        "SELECT id, status, created_at, reason_started_at, reason_last_heartbeat_at FROM projects",
    )
    .fetch_all(source)
    .await?
    {
        let id = row.get::<String, _>("id");
        let status = row.get::<String, _>("status");
        let created_at = parse_python_ts(row.get::<String, _>("created_at"))?;
        let reason_started_at =
            parse_python_ts_opt(row.get::<Option<String>, _>("reason_started_at"))?;
        let reason_last_heartbeat_at =
            parse_python_ts_opt(row.get::<Option<String>, _>("reason_last_heartbeat_at"))?;
        if let Some(reason_started_at) = reason_started_at {
            validate_timestamp_not_before(
                &format!("project {id} reason_started_at"),
                reason_started_at,
                "created_at",
                created_at,
            )?;
        }
        if let (Some(reason_started_at), Some(reason_last_heartbeat_at)) =
            (reason_started_at, reason_last_heartbeat_at)
        {
            validate_timestamp_not_before(
                &format!("project {id} reason_last_heartbeat_at"),
                reason_last_heartbeat_at,
                "reason_started_at",
                reason_started_at,
            )?;
        }
        validate_non_empty("project id", &id)?;
        if !valid_project_status(&status) {
            return Err(ClairvoyantError::api(
                400,
                format!("source database has invalid project status {status} for project {id}"),
            ));
        }
    }
    for row in sqlx::query(
        "SELECT id, project_id, last_heartbeat_at, created_at, concluded_at FROM intents",
    )
    .fetch_all(source)
    .await?
    {
        let id = row.get::<String, _>("id");
        let project_id = row.get::<String, _>("project_id");
        let last_heartbeat_at =
            parse_python_ts_opt(row.get::<Option<String>, _>("last_heartbeat_at"))?;
        let created_at = parse_python_ts(row.get::<String, _>("created_at"))?;
        let concluded_at = parse_python_ts_opt(row.get::<Option<String>, _>("concluded_at"))?;
        if let Some(last_heartbeat_at) = last_heartbeat_at {
            validate_timestamp_not_before(
                &format!("intent {id} last_heartbeat_at in project {project_id}"),
                last_heartbeat_at,
                "created_at",
                created_at,
            )?;
        }
        if let Some(concluded_at) = concluded_at {
            validate_timestamp_not_before(
                &format!("intent {id} concluded_at in project {project_id}"),
                concluded_at,
                "created_at",
                created_at,
            )?;
        }
        validate_non_empty("intent id", &id)?;
    }
    for row in sqlx::query("SELECT id, created_at FROM hints")
        .fetch_all(source)
        .await?
    {
        let id = row.get::<String, _>("id");
        parse_python_ts(row.get::<String, _>("created_at"))?;
        validate_non_empty("hint id", &id)?;
    }
    Ok(())
}

async fn validate_python_source_references(source: &SqlitePool) -> Result<()> {
    if let Some(row) = sqlx::query(
        r#"
        SELECT f.id, f.project_id
        FROM facts f
        LEFT JOIN projects p ON p.id = f.project_id
        WHERE p.id IS NULL
        LIMIT 1
        "#,
    )
    .fetch_optional(source)
    .await?
    {
        return Err(ClairvoyantError::api(
            400,
            format!(
                "source database has dangling fact {} for missing project {}",
                row.get::<String, _>("id"),
                row.get::<String, _>("project_id")
            ),
        ));
    }
    if let Some(row) = sqlx::query(
        r#"
        SELECT i.id, i.project_id
        FROM intents i
        LEFT JOIN projects p ON p.id = i.project_id
        WHERE p.id IS NULL
        LIMIT 1
        "#,
    )
    .fetch_optional(source)
    .await?
    {
        return Err(ClairvoyantError::api(
            400,
            format!(
                "source database has dangling intent {} for missing project {}",
                row.get::<String, _>("id"),
                row.get::<String, _>("project_id")
            ),
        ));
    }
    if let Some(row) = sqlx::query(
        r#"
        SELECT h.id, h.project_id
        FROM hints h
        LEFT JOIN projects p ON p.id = h.project_id
        WHERE p.id IS NULL
        LIMIT 1
        "#,
    )
    .fetch_optional(source)
    .await?
    {
        return Err(ClairvoyantError::api(
            400,
            format!(
                "source database has dangling hint {} for missing project {}",
                row.get::<String, _>("id"),
                row.get::<String, _>("project_id")
            ),
        ));
    }
    if let Some(row) = sqlx::query(
        r#"
        SELECT s.intent_id, s.project_id
        FROM intent_sources s
        LEFT JOIN intents i ON i.id = s.intent_id AND i.project_id = s.project_id
        WHERE i.id IS NULL
        LIMIT 1
        "#,
    )
    .fetch_optional(source)
    .await?
    {
        return Err(ClairvoyantError::api(
            400,
            format!(
                "source database has dangling intent source for missing intent {} in project {}",
                row.get::<String, _>("intent_id"),
                row.get::<String, _>("project_id")
            ),
        ));
    }
    if let Some(row) = sqlx::query(
        r#"
        SELECT s.intent_id, s.project_id, s.fact_id
        FROM intent_sources s
        LEFT JOIN facts f ON f.id = s.fact_id AND f.project_id = s.project_id
        WHERE f.id IS NULL
        LIMIT 1
        "#,
    )
    .fetch_optional(source)
    .await?
    {
        return Err(ClairvoyantError::api(
            400,
            format!(
                "source database has dangling intent source {} -> {} in project {}",
                row.get::<String, _>("intent_id"),
                row.get::<String, _>("fact_id"),
                row.get::<String, _>("project_id")
            ),
        ));
    }
    if let Some(row) = sqlx::query(
        r#"
        SELECT i.id, i.project_id, i.to_fact_id
        FROM intents i
        LEFT JOIN facts f ON f.id = i.to_fact_id AND f.project_id = i.project_id
        WHERE i.to_fact_id IS NOT NULL
          AND TRIM(i.to_fact_id) != ''
          AND f.id IS NULL
        LIMIT 1
        "#,
    )
    .fetch_optional(source)
    .await?
    {
        return Err(ClairvoyantError::api(
            400,
            format!(
                "source database has dangling target fact for intent {} -> {} in project {}",
                row.get::<String, _>("id"),
                row.get::<String, _>("to_fact_id"),
                row.get::<String, _>("project_id")
            ),
        ));
    }
    Ok(())
}

async fn validate_python_source_intent_sources(source: &SqlitePool) -> Result<()> {
    if let Some(row) = sqlx::query(
        r#"
        SELECT i.id, i.project_id
        FROM intents i
        LEFT JOIN intent_sources s ON s.intent_id = i.id AND s.project_id = i.project_id
        GROUP BY i.id, i.project_id
        HAVING COUNT(s.fact_id) = 0
        LIMIT 1
        "#,
    )
    .fetch_optional(source)
    .await?
    {
        return Err(ClairvoyantError::api(
            400,
            format!(
                "source database intent {} in project {} must have at least one source fact",
                row.get::<String, _>("id"),
                row.get::<String, _>("project_id")
            ),
        ));
    }
    if let Some(row) = sqlx::query(
        r#"
        SELECT intent_id, project_id
        FROM intent_sources
        WHERE fact_id = 'goal'
        LIMIT 1
        "#,
    )
    .fetch_optional(source)
    .await?
    {
        return Err(ClairvoyantError::api(
            400,
            format!(
                "source database intent {} in project {} uses goal as a source fact",
                row.get::<String, _>("intent_id"),
                row.get::<String, _>("project_id")
            ),
        ));
    }
    Ok(())
}

async fn validate_python_source_project_facts(source: &SqlitePool) -> Result<()> {
    for row in sqlx::query(
        r#"
        SELECT p.id,
               SUM(CASE WHEN f.id = 'origin' THEN 1 ELSE 0 END) AS origin_count,
               SUM(CASE WHEN f.id = 'goal' THEN 1 ELSE 0 END) AS goal_count
        FROM projects p
        LEFT JOIN facts f ON f.project_id = p.id
        GROUP BY p.id
        "#,
    )
    .fetch_all(source)
    .await?
    {
        let id = row.get::<String, _>("id");
        let origin_count = row.get::<i64, _>("origin_count");
        let goal_count = row.get::<i64, _>("goal_count");
        if origin_count != 1 || goal_count != 1 {
            return Err(ClairvoyantError::api(
                400,
                format!(
                    "source database project {id} must have exactly one origin fact and one goal fact; found origin={origin_count} goal={goal_count}"
                ),
            ));
        }
    }
    Ok(())
}

async fn validate_python_source_project_runtime_state(source: &SqlitePool) -> Result<()> {
    if let Some(row) = sqlx::query(
        r#"
        SELECT id, status
        FROM projects
        WHERE status != 'active'
          AND (
            reason_worker IS NOT NULL
            OR reason_trigger IS NOT NULL
            OR reason_started_at IS NOT NULL
            OR reason_last_heartbeat_at IS NOT NULL
          )
        LIMIT 1
        "#,
    )
    .fetch_optional(source)
    .await?
    {
        return Err(ClairvoyantError::api(
            400,
            format!(
                "source database has {} project {} with an active reason lease",
                row.get::<String, _>("status"),
                row.get::<String, _>("id")
            ),
        ));
    }
    if let Some(row) = sqlx::query(
        r#"
        SELECT i.id, i.project_id, p.status
        FROM intents i
        JOIN projects p ON p.id = i.project_id
        WHERE p.status != 'active'
          AND i.to_fact_id IS NULL
          AND i.worker IS NOT NULL
        LIMIT 1
        "#,
    )
    .fetch_optional(source)
    .await?
    {
        return Err(ClairvoyantError::api(
            400,
            format!(
                "source database has {} project {} with claimed open intent {}",
                row.get::<String, _>("status"),
                row.get::<String, _>("project_id"),
                row.get::<String, _>("id")
            ),
        ));
    }
    Ok(())
}

async fn validate_python_source_completion_state(source: &SqlitePool) -> Result<()> {
    for row in sqlx::query(
        r#"
        SELECT p.id, p.status, COUNT(i.id) AS completion_count
        FROM projects p
        LEFT JOIN intents i ON i.project_id = p.id AND i.to_fact_id = 'goal'
        GROUP BY p.id, p.status
        "#,
    )
    .fetch_all(source)
    .await?
    {
        let id = row.get::<String, _>("id");
        let status = row.get::<String, _>("status");
        let completion_count = row.get::<i64, _>("completion_count");
        match (status.as_str(), completion_count) {
            ("completed", 1) => {}
            ("completed", count) => {
                return Err(ClairvoyantError::api(
                    400,
                    format!(
                        "source database has completed project {id} with {count} goal completion intents; expected exactly 1"
                    ),
                ));
            }
            (_, 0) => {}
            (_, count) => {
                return Err(ClairvoyantError::api(
                    400,
                    format!(
                        "source database has non-completed project {id} with {count} goal completion intents; expected 0"
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn parse_prefixed_number(value: &str, prefix: &str) -> Option<i64> {
    value.strip_prefix(prefix)?.parse().ok()
}

fn parse_python_ts(value: String) -> Result<i64> {
    parse_python_ts_opt(Some(value))?
        .ok_or_else(|| ClairvoyantError::api(400, "missing required timestamp during migration"))
}

fn parse_python_ts_opt(value: Option<String>) -> Result<Option<i64>> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.trim().is_empty() {
        return Ok(None);
    }
    DateTime::parse_from_rfc3339(&value.replace('Z', "+00:00"))
        .map(|dt| Some(dt.timestamp_millis()))
        .map_err(|err| {
            ClairvoyantError::api(400, format!("invalid python timestamp {value}: {err}"))
        })
}

fn validate_timestamp_not_before(
    field: &str,
    value_ms: i64,
    lower_bound_field: &str,
    lower_bound_ms: i64,
) -> Result<()> {
    if value_ms < lower_bound_ms {
        return Err(ClairvoyantError::api(
            400,
            format!("source database has {field} before {lower_bound_field}"),
        ));
    }
    Ok(())
}

async fn get_project_row_or_404(
    pool: &SqlitePool,
    project_id: &str,
) -> Result<sqlx::sqlite::SqliteRow> {
    sqlx::query("SELECT * FROM projects WHERE id = ?")
        .bind(project_id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| ClairvoyantError::api(404, "Project not found"))
}

async fn get_project_or_404(pool: &SqlitePool, project_id: &str) -> Result<ProjectMeta> {
    let row = get_project_row_or_404(pool, project_id).await?;
    project_meta_from_row(&row)
}

async fn check_project_active(pool: &SqlitePool, project_id: &str) -> Result<()> {
    let row = get_project_row_or_404(pool, project_id).await?;
    let status: String = row.get("status");
    if status != "active" {
        return Err(ClairvoyantError::api(403, format!("Project is {status}")));
    }
    Ok(())
}

async fn check_project_completed(pool: &SqlitePool, project_id: &str) -> Result<()> {
    let row = get_project_row_or_404(pool, project_id).await?;
    let status: String = row.get("status");
    if status != "completed" {
        return Err(ClairvoyantError::api(403, format!("Project is {status}")));
    }
    Ok(())
}

async fn get_intent_row_or_404(
    pool: &SqlitePool,
    project_id: &str,
    intent_id: &str,
) -> Result<sqlx::sqlite::SqliteRow> {
    sqlx::query("SELECT * FROM intents WHERE id = ? AND project_id = ?")
        .bind(intent_id)
        .bind(project_id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| ClairvoyantError::api(404, "Intent not found"))
}

/// Validate that an intent is open (not yet concluded) and either unclaimed
/// or claimed by the requesting worker.  Used by heartbeat, release, and conclude.
async fn get_open_intent(
    pool: &SqlitePool,
    project_id: &str,
    intent_id: &str,
    worker: &str,
) -> Result<sqlx::sqlite::SqliteRow> {
    let row = get_intent_row_or_404(pool, project_id, intent_id).await?;
    let target_fact: Option<String> = row.get("target_fact");
    if target_fact.is_some() {
        return Err(ClairvoyantError::api(409, "Intent already concluded"));
    }
    let current_worker: Option<String> = row.get("worker");
    if let Some(current_worker) = current_worker {
        if current_worker != worker.trim() {
            return Err(ClairvoyantError::api(
                409,
                format!("Intent is currently claimed by {current_worker}"),
            ));
        }
    }
    Ok(row)
}

async fn get_completion_intent(
    pool: &SqlitePool,
    project_id: &str,
) -> Result<sqlx::sqlite::SqliteRow> {
    let rows = sqlx::query("SELECT * FROM intents WHERE project_id = ? AND target_fact = 'goal'")
        .bind(project_id)
        .fetch_all(pool)
        .await?;
    match rows.len() {
        0 => Err(ClairvoyantError::api(
            409,
            "Completed project is missing its completion intent",
        )),
        1 => Ok(rows.into_iter().next().expect("length checked")),
        _ => Err(ClairvoyantError::api(
            409,
            "Completed project has multiple completion intents",
        )),
    }
}

async fn clear_project_reason(pool: &SqlitePool, project_id: &str) -> Result<()> {
    with_busy_retry(|| async {
        sqlx::query(
            "UPDATE projects SET reason_worker = NULL, reason_trigger = NULL, reason_started_at_ms = NULL, reason_last_heartbeat_at_ms = NULL WHERE id = ?",
        )
        .bind(project_id)
        .execute(pool)
        .await
    })
    .await?;
    Ok(())
}

async fn validate_facts_exist(
    pool: &SqlitePool,
    project_id: &str,
    fact_ids: &[String],
) -> Result<()> {
    for fact_id in fact_ids {
        let exists = sqlx::query("SELECT 1 FROM facts WHERE id = ? AND project_id = ?")
            .bind(fact_id.trim())
            .bind(project_id)
            .fetch_optional(pool)
            .await?
            .is_some();
        if !exists {
            return Err(ClairvoyantError::api(
                404,
                format!("Fact {} not found", fact_id.trim()),
            ));
        }
    }
    Ok(())
}

async fn sources_for_intent(
    pool: &SqlitePool,
    project_id: &str,
    intent_id: &str,
) -> Result<Vec<String>> {
    let rows = sqlx::query(
        "SELECT fact_id FROM intent_sources WHERE intent_id = ? AND project_id = ? ORDER BY ordinal",
    )
    .bind(intent_id)
    .bind(project_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|row| row.get("fact_id")).collect())
}

async fn intent_from_row(
    pool: &SqlitePool,
    project_id: &str,
    row: &sqlx::sqlite::SqliteRow,
) -> Result<Intent> {
    let id: String = row.get("id");
    let sources = sources_for_intent(pool, project_id, &id).await?;
    Ok(intent_from_row_fields(row, id, sources))
}

/// Build an Intent from a row and pre-fetched sources map (batched path).
fn intent_from_row_with_sources(
    row: &sqlx::sqlite::SqliteRow,
    sources_by_intent: &std::collections::HashMap<String, Vec<String>>,
) -> Result<Intent> {
    let id: String = row.get("id");
    let sources = sources_by_intent.get(&id).cloned().unwrap_or_default();
    Ok(intent_from_row_fields(row, id, sources))
}

fn intent_from_row_fields(
    row: &sqlx::sqlite::SqliteRow,
    id: String,
    sources: Vec<String>,
) -> Intent {
    Intent {
        id,
        sources,
        target_fact: row.get("target_fact"),
        description: row.get("description"),
        creator: row.get("creator"),
        worker: row.get("worker"),
        last_heartbeat_at: row.get("last_heartbeat_at_ms"),
        created_at: row.get("created_at_ms"),
        concluded_at: row.get("concluded_at_ms"),
    }
}

fn project_meta_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<ProjectMeta> {
    Ok(ProjectMeta {
        id: row.get("id"),
        title: row.get("title"),
        status: status_from_str(row.get::<String, _>("status"))?,
        created_at: row.get("created_at_ms"),
        reason: project_reason_from_row(row),
    })
}

fn project_reason_from_row(row: &sqlx::sqlite::SqliteRow) -> Option<ProjectReason> {
    let worker: Option<String> = row.get("reason_worker");
    let trigger: Option<String> = row.get("reason_trigger");
    let started_at: Option<i64> = row.get("reason_started_at_ms");
    let last_heartbeat_at: Option<i64> = row.get("reason_last_heartbeat_at_ms");
    Some(ProjectReason {
        worker: worker?,
        trigger: trigger?,
        started_at: started_at?,
        last_heartbeat_at: last_heartbeat_at?,
    })
}

fn status_from_str(value: String) -> Result<ProjectStatus> {
    match value.as_str() {
        "active" => Ok(ProjectStatus::Active),
        "stopped" => Ok(ProjectStatus::Stopped),
        "completed" => Ok(ProjectStatus::Completed),
        _ => Err(ClairvoyantError::api(
            500,
            format!("Invalid project status {value}"),
        )),
    }
}

fn valid_project_status(value: &str) -> bool {
    matches!(value, "active" | "stopped" | "completed")
}

fn validate_prefixed_id(field: &str, value: &str, prefix: &str) -> Result<()> {
    let Some(suffix) = value.strip_prefix(prefix) else {
        return Err(ClairvoyantError::api(
            400,
            format!("{field} {value} must match {prefix}<number>"),
        ));
    };
    let Some(number) = parse_prefixed_number(value, prefix) else {
        return Err(ClairvoyantError::api(
            400,
            format!("{field} {value} must match {prefix}<number>"),
        ));
    };
    let canonical = suffix.len() >= 3
        && suffix.bytes().all(|byte| byte.is_ascii_digit())
        && (suffix.len() == 3 || !suffix.starts_with('0'));
    if !canonical {
        return Err(ClairvoyantError::api(
            400,
            format!(
                "{field} {value} must use Clairvoyant's zero-padded id format such as {prefix}001"
            ),
        ));
    }
    if number <= 0 {
        return Err(ClairvoyantError::api(
            400,
            format!("{field} {value} must use a positive numeric suffix"),
        ));
    }
    Ok(())
}

fn optional_text_present(value: &Option<String>) -> bool {
    value
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
}

fn validate_optional_non_blank(field: &str, value: &Option<String>) -> Result<()> {
    if value
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err(ClairvoyantError::api(
            400,
            format!("{field} must be null or non-empty"),
        ));
    }
    Ok(())
}

fn validate_non_empty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(ClairvoyantError::api(
            400,
            format!("{field} must not be empty"),
        ));
    }
    Ok(())
}

fn validate_timeout(value: i64) -> Result<()> {
    if value < 5 {
        return Err(ClairvoyantError::api(400, "timeout must be >= 5"));
    }
    Ok(())
}

fn validate_fact_ids(fact_ids: &[String]) -> Result<()> {
    if fact_ids.is_empty() {
        return Err(ClairvoyantError::api(400, "sources must not be empty"));
    }
    let mut seen = std::collections::BTreeSet::new();
    for fact_id in fact_ids {
        let fact_id = fact_id.trim();
        if fact_id.is_empty() {
            return Err(ClairvoyantError::api(400, "fact ids must not be empty"));
        }
        if !seen.insert(fact_id.to_string()) {
            return Err(ClairvoyantError::api(
                400,
                format!("duplicate source fact id {fact_id}"),
            ));
        }
    }
    Ok(())
}

fn validate_goal_not_in_sources(fact_ids: &[String]) -> Result<()> {
    if fact_ids.iter().any(|id| id.trim() == "goal") {
        return Err(ClairvoyantError::api(400, "goal cannot be used in sources"));
    }
    Ok(())
}

fn now_ms() -> i64 {
    Utc::now().timestamp_millis()
}

fn project_observation(detail: ProjectDetail, generated_at: i64) -> ProjectObservation {
    let fact_count = detail.facts.len();
    let hint_count = detail.hints.len();
    let intent_count = detail.intents.len();
    let open_intents = detail
        .intents
        .iter()
        .filter(|intent| intent.target_fact.is_none())
        .map(|intent| IntentObservation {
            id: intent.id.clone(),
            sources: intent.sources.clone(),
            description: intent.description.clone(),
            creator: intent.creator.clone(),
            worker: intent.worker.clone(),
            last_heartbeat_at: intent.last_heartbeat_at,
            created_at: intent.created_at,
            age_ms: generated_at.saturating_sub(intent.created_at),
            heartbeat_age_ms: intent
                .last_heartbeat_at
                .map(|last_heartbeat_at| generated_at.saturating_sub(last_heartbeat_at)),
        })
        .collect::<Vec<_>>();
    let working_intent_count = open_intents
        .iter()
        .filter(|intent| intent.worker.is_some())
        .count();
    let unclaimed_intent_count = open_intents
        .iter()
        .filter(|intent| intent.worker.is_none())
        .count();
    let reason_heartbeat_age_ms = detail
        .project
        .reason
        .as_ref()
        .map(|reason| generated_at.saturating_sub(reason.last_heartbeat_at));
    ProjectObservation {
        project: detail.project,
        fact_count,
        intent_count,
        open_intent_count: open_intents.len(),
        working_intent_count,
        unclaimed_intent_count,
        hint_count,
        reason_heartbeat_age_ms,
        open_intents,
    }
}

fn format_export_timestamp(value: i64) -> String {
    Local
        .timestamp_millis_opt(value)
        .single()
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| value.to_string())
}

fn export_yaml(detail: &ProjectDetail) -> Result<String> {
    #[derive(Serialize)]
    struct ExportProject<'a> {
        project: ExportProjectHead<'a>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        hints: Vec<ExportHint<'a>>,
        facts: &'a [Fact],
        #[serde(skip_serializing_if = "Vec::is_empty")]
        intents: Vec<ExportIntent<'a>>,
    }
    #[derive(Serialize)]
    struct ExportProjectHead<'a> {
        title: &'a str,
        origin: String,
        goal: String,
    }
    #[derive(Serialize)]
    struct ExportHint<'a> {
        content: &'a str,
        creator: &'a str,
        created_at: String,
    }
    #[derive(Serialize)]
    struct ExportIntent<'a> {
        sources: &'a [String],
        target_fact: &'a Option<String>,
        description: &'a str,
        creator: &'a str,
        worker: &'a Option<String>,
        created_at: String,
        concluded_at: Option<String>,
    }

    let origin = detail
        .facts
        .iter()
        .find(|fact| fact.id == "origin")
        .map(|fact| fact.description.clone())
        .unwrap_or_default();
    let goal = detail
        .facts
        .iter()
        .find(|fact| fact.id == "goal")
        .map(|fact| fact.description.clone())
        .unwrap_or_default();
    let export = ExportProject {
        project: ExportProjectHead {
            title: &detail.project.title,
            origin,
            goal,
        },
        hints: detail
            .hints
            .iter()
            .map(|hint| ExportHint {
                content: &hint.content,
                creator: &hint.creator,
                created_at: format_export_timestamp(hint.created_at),
            })
            .collect(),
        facts: &detail.facts,
        intents: detail
            .intents
            .iter()
            .map(|intent| ExportIntent {
                sources: &intent.sources,
                target_fact: &intent.target_fact,
                description: &intent.description,
                creator: &intent.creator,
                worker: &intent.worker,
                created_at: format_export_timestamp(intent.created_at),
                concluded_at: intent.concluded_at.map(format_export_timestamp),
            })
            .collect(),
    };
    Ok(serde_yaml::to_string(&export)?)
}

fn export_timeline(detail: &ProjectDetail) -> String {
    let facts_by_id = detail
        .facts
        .iter()
        .map(|fact| (fact.id.as_str(), fact.description.as_str()))
        .collect::<std::collections::HashMap<_, _>>();
    let mut events: Vec<(i64, usize, String)> = Vec::new();
    let mut order = 0;
    events.push((
        detail.project.created_at,
        order,
        format!(
            "[{}] PROJECT CREATED\n  origin: {}\n  goal: {}",
            format_export_timestamp(detail.project.created_at),
            facts_by_id.get("origin").copied().unwrap_or(""),
            facts_by_id.get("goal").copied().unwrap_or("")
        ),
    ));
    order += 1;

    for hint in &detail.hints {
        events.push((
            hint.created_at,
            order,
            format!(
                "[{}] HINT by {}\n  {}",
                format_export_timestamp(hint.created_at),
                hint.creator,
                hint.content
            ),
        ));
        order += 1;
    }

    for intent in &detail.intents {
        let from_str = intent.sources.join(", ");
        let mut meta = format!("  from: {from_str}");
        if intent.worker.is_some() && intent.concluded_at.is_none() {
            meta.push_str(&format!(
                "\n  worker: {} (in progress)",
                intent.worker.as_deref().unwrap_or_default()
            ));
        }
        events.push((
            intent.created_at,
            order,
            format!(
                "[{}] INTENT DECLARED {} by {}\n{}\n  {}",
                format_export_timestamp(intent.created_at),
                intent.id,
                intent.creator,
                meta,
                intent.description
            ),
        ));
        order += 1;

        let Some(concluded_at) = intent.concluded_at else {
            continue;
        };
        let Some(target_fact) = &intent.target_fact else {
            continue;
        };
        let actor = intent.worker.as_deref().unwrap_or(&intent.creator);
        let block = if target_fact == "goal" {
            format!(
                "[{}] PROJECT COMPLETED by {}\n  via: {} from {}",
                format_export_timestamp(concluded_at),
                actor,
                intent.id,
                from_str
            )
        } else {
            format!(
                "[{}] INTENT CONCLUDED {} by {}\n  from: {}\n  produced: {}\n  {}",
                format_export_timestamp(concluded_at),
                intent.id,
                actor,
                from_str,
                target_fact,
                facts_by_id.get(target_fact.as_str()).copied().unwrap_or("")
            )
        };
        events.push((concluded_at, order, block));
        order += 1;
    }

    events.sort_by_key(|(timestamp, order, _)| (*timestamp, *order));
    let mut output = events
        .into_iter()
        .map(|(_, _, text)| text)
        .collect::<Vec<_>>()
        .join("\n\n");
    output.push('\n');
    output
}

fn is_busy_error(error: &sqlx::Error) -> bool {
    match error {
        sqlx::Error::Database(db) => {
            if db
                .code()
                .as_deref()
                .is_some_and(|code| matches!(code, "5" | "6" | "SQLITE_BUSY" | "SQLITE_LOCKED"))
            {
                return true;
            }
            let message = db.message().to_ascii_lowercase();
            message.contains("busy") || message.contains("locked")
        }
        _ => false,
    }
}

async fn begin_immediate(pool: &SqlitePool) -> Result<sqlx::Transaction<'static, sqlx::Sqlite>> {
    with_busy_retry(|| pool.begin_with("BEGIN IMMEDIATE"))
        .await
        .map_err(ClairvoyantError::Db)
}

async fn with_busy_retry<F, Fut, T>(mut op: F) -> std::result::Result<T, sqlx::Error>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = std::result::Result<T, sqlx::Error>>,
{
    let mut delay = Duration::from_millis(20);
    for attempt in 0..4 {
        match op().await {
            Ok(value) => return Ok(value),
            Err(err) if attempt < 3 && is_busy_error(&err) => {
                let jitter = Duration::from_millis(((attempt * 17 + 11) % 19) as u64);
                tokio::time::sleep(delay + jitter).await;
                delay *= 2;
            }
            Err(err) => return Err(err),
        }
    }
    unreachable!("retry loop always returns")
}

#[cfg(test)]
mod tests {
    use super::*;
    use clairvoyant_core::{
        ClairvoyantRequest, ClairvoyantResponse, CompleteRequest, CreateHintRequest,
        CreateIntentRequest, CreateProjectRequest, ExportFormat, HeartbeatRequest, ReopenRequest,
        Settings,
    };
    use std::str::FromStr;

    async fn test_service(name: &str) -> ClairvoyantService {
        let unique = format!(
            "clairvoyant-rs-{name}-{}-{}.db",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        );
        let path = std::env::temp_dir().join(unique);
        ClairvoyantService::open(path).await.expect("open test db")
    }

    #[tokio::test]
    async fn opens_sqlite_paths_with_literal_url_characters() {
        let dir = std::env::temp_dir().join(format!(
            "clairvoyant-rs-url-path-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join("clairvoyant?literal#path.db");
        let service = ClairvoyantService::open(&path)
            .await
            .expect("open db with literal url characters");
        let detail = expect_detail(
            service
                .handle(ClairvoyantRequest::CreateProject {
                    body: CreateProjectRequest {
                        title: "literal path".into(),
                        origin: "origin".into(),
                        goal: "goal".into(),
                        hints: None,
                    },
                })
                .await
                .expect("create project"),
        );
        assert_eq!(detail.project.id, "proj_001");
        assert!(path.exists(), "database path should be used literally");
        drop(service);
        let _ = std::fs::remove_dir_all(dir);
    }

    fn expect_detail(response: ClairvoyantResponse) -> ProjectDetail {
        match response {
            ClairvoyantResponse::ProjectDetail(detail) => detail,
            other => panic!("expected project detail, got {other:?}"),
        }
    }

    fn expect_intent(response: ClairvoyantResponse) -> Intent {
        match response {
            ClairvoyantResponse::Intent(intent) => intent,
            other => panic!("expected intent, got {other:?}"),
        }
    }

    fn expect_reopen(response: ClairvoyantResponse) -> ReopenResponse {
        match response {
            ClairvoyantResponse::Reopen(reopen) => reopen,
            other => panic!("expected reopen, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn project_intent_complete_reopen_export_flow() {
        let service = test_service("flow").await;

        let detail = expect_detail(
            service
                .handle(ClairvoyantRequest::CreateProject {
                    body: CreateProjectRequest {
                        title: "demo".into(),
                        origin: "start".into(),
                        goal: "finish".into(),
                        hints: None,
                    },
                })
                .await
                .expect("create project"),
        );
        let project_id = detail.project.id;
        assert_eq!(project_id, "proj_001");

        let intent = expect_intent(
            service
                .handle(ClairvoyantRequest::CreateIntent {
                    project_id: project_id.clone(),
                    body: CreateIntentRequest {
                        sources: vec!["origin".into()],
                        description: "inspect".into(),
                        creator: "worker-a".into(),
                        worker: None,
                    },
                })
                .await
                .expect("create intent"),
        );
        assert_eq!(intent.id, "i001");
        assert_eq!(intent.sources, vec!["origin"]);
        assert!(intent.target_fact.is_none());

        let claimed = expect_intent(
            service
                .handle(ClairvoyantRequest::HeartbeatIntent {
                    project_id: project_id.clone(),
                    intent_id: intent.id.clone(),
                    body: HeartbeatRequest {
                        worker: "worker-a".into(),
                    },
                })
                .await
                .expect("heartbeat intent"),
        );
        assert_eq!(claimed.worker.as_deref(), Some("worker-a"));

        let concluded = match service
            .handle(ClairvoyantRequest::ConcludeIntent {
                project_id: project_id.clone(),
                intent_id: intent.id.clone(),
                body: ConcludeRequest {
                    worker: "worker-a".into(),
                    description: "found fact".into(),
                },
            })
            .await
            .expect("conclude intent")
        {
            ClairvoyantResponse::Conclude(response) => response,
            other => panic!("expected conclude response, got {other:?}"),
        };
        assert_eq!(concluded.fact.id, "f001");
        assert_eq!(concluded.intent.target_fact.as_deref(), Some("f001"));

        let complete = expect_intent(
            service
                .handle(ClairvoyantRequest::CompleteProject {
                    project_id: project_id.clone(),
                    body: CompleteRequest {
                        sources: vec!["f001".into()],
                        description: "done".into(),
                        worker: "worker-a".into(),
                    },
                })
                .await
                .expect("complete project"),
        );
        assert_eq!(complete.target_fact.as_deref(), Some("goal"));

        let reopened = expect_reopen(
            service
                .handle(ClairvoyantRequest::ReopenProject {
                    project_id: project_id.clone(),
                    body: ReopenRequest {
                        description: "needs more".into(),
                        creator: "human".into(),
                    },
                })
                .await
                .expect("reopen project"),
        );
        assert!(matches!(reopened.project.status, ProjectStatus::Active));
        assert_eq!(reopened.fact.id, "f002");
        assert_eq!(reopened.intent.target_fact.as_deref(), Some("f002"));

        let yaml = match service
            .handle(ClairvoyantRequest::ExportProject {
                project_id,
                format: ExportFormat::Yaml,
            })
            .await
            .expect("export")
        {
            ClairvoyantResponse::Text(text) => text,
            other => panic!("expected text, got {other:?}"),
        };
        assert!(yaml.contains("sources:"));
        assert!(yaml.contains("target_fact:"));
    }

    #[tokio::test]
    async fn lease_expiration_releases_intent_claims_without_request_side_sweep() {
        let service = test_service("leases").await;
        service
            .handle(ClairvoyantRequest::PutSettings {
                settings: Settings {
                    intent_timeout: 5,
                    reason_timeout: 5,
                },
            })
            .await
            .expect("settings");
        let detail = expect_detail(
            service
                .handle(ClairvoyantRequest::CreateProject {
                    body: CreateProjectRequest {
                        title: "lease".into(),
                        origin: "o".into(),
                        goal: "g".into(),
                        hints: None,
                    },
                })
                .await
                .expect("create project"),
        );
        let project_id = detail.project.id;
        let intent = expect_intent(
            service
                .handle(ClairvoyantRequest::CreateIntent {
                    project_id: project_id.clone(),
                    body: CreateIntentRequest {
                        sources: vec!["origin".into()],
                        description: "claimed".into(),
                        creator: "w1".into(),
                        worker: Some("w1".into()),
                    },
                })
                .await
                .expect("create intent"),
        );

        sqlx::query("UPDATE intents SET last_heartbeat_at_ms = ? WHERE project_id = ? AND id = ?")
            .bind(now_ms() - 10_000)
            .bind(&project_id)
            .bind(&intent.id)
            .execute(&service.pool)
            .await
            .expect("age heartbeat");

        service
            .expire_leases(Some(&project_id))
            .await
            .expect("expire leases");
        let expired = service
            .intent_by_id(&project_id, &intent.id)
            .await
            .expect("reload intent");
        assert!(expired.worker.is_none());
        assert!(expired.last_heartbeat_at.is_none());
    }

    #[tokio::test]
    async fn stale_leases_are_not_expired_on_request_path() {
        let service = test_service("request-no-expire").await;
        service
            .handle(ClairvoyantRequest::PutSettings {
                settings: Settings {
                    intent_timeout: 5,
                    reason_timeout: 5,
                },
            })
            .await
            .expect("settings");
        let detail = expect_detail(
            service
                .handle(ClairvoyantRequest::CreateProject {
                    body: CreateProjectRequest {
                        title: "request path".into(),
                        origin: "o".into(),
                        goal: "g".into(),
                        hints: None,
                    },
                })
                .await
                .expect("create project"),
        );
        let project_id = detail.project.id;
        let intent = expect_intent(
            service
                .handle(ClairvoyantRequest::CreateIntent {
                    project_id: project_id.clone(),
                    body: CreateIntentRequest {
                        sources: vec!["origin".into()],
                        description: "claimed".into(),
                        creator: "w1".into(),
                        worker: Some("w1".into()),
                    },
                })
                .await
                .expect("create intent"),
        );
        sqlx::query("UPDATE intents SET last_heartbeat_at_ms = ? WHERE project_id = ? AND id = ?")
            .bind(now_ms() - 10_000)
            .bind(&project_id)
            .bind(&intent.id)
            .execute(&service.pool)
            .await
            .expect("age intent heartbeat");

        let error = service
            .handle(ClairvoyantRequest::HeartbeatIntent {
                project_id: project_id.clone(),
                intent_id: intent.id.clone(),
                body: HeartbeatRequest {
                    worker: "w2".into(),
                },
            })
            .await
            .expect_err("request path must not expire stale claim");
        assert!(error.to_string().contains("currently claimed by w1"));

        service
            .expire_leases(Some(&project_id))
            .await
            .expect("background-style expiration");
        let reclaimed = expect_intent(
            service
                .handle(ClairvoyantRequest::HeartbeatIntent {
                    project_id,
                    intent_id: intent.id,
                    body: HeartbeatRequest {
                        worker: "w2".into(),
                    },
                })
                .await
                .expect("claim after explicit expiration"),
        );
        assert_eq!(reclaimed.worker.as_deref(), Some("w2"));
    }

    #[tokio::test]
    async fn concurrent_internal_writes_do_not_surface_busy_errors() {
        let service = test_service("concurrent").await;
        let detail = expect_detail(
            service
                .handle(ClairvoyantRequest::CreateProject {
                    body: CreateProjectRequest {
                        title: "concurrent".into(),
                        origin: "o".into(),
                        goal: "g".into(),
                        hints: None,
                    },
                })
                .await
                .expect("create project"),
        );
        let project_id = detail.project.id;
        let mut tasks = Vec::new();
        for idx in 0..100 {
            let service = service.clone();
            let project_id = project_id.clone();
            tasks.push(tokio::spawn(async move {
                service
                    .handle_envelope(ClairvoyantRequest::CreateHint {
                        project_id,
                        body: CreateHintRequest {
                            content: format!("hint {idx}"),
                            creator: "test".into(),
                        },
                    })
                    .await
            }));
        }

        for task in tasks {
            match task.await.expect("join") {
                clairvoyant_core::ClairvoyantEnvelope::Ok { .. } => {}
                clairvoyant_core::ClairvoyantEnvelope::Err { error } => {
                    panic!("write failed: {error:?}");
                }
            }
        }

        let detail = expect_detail(
            service
                .handle(ClairvoyantRequest::GetProject { project_id })
                .await
                .expect("get project"),
        );
        assert_eq!(detail.hints.len(), 100);
    }

    #[tokio::test]
    async fn concurrent_internal_reads_and_writes_do_not_surface_busy_errors() {
        let service = test_service("concurrent-read-write").await;
        let detail = expect_detail(
            service
                .handle(ClairvoyantRequest::CreateProject {
                    body: CreateProjectRequest {
                        title: "concurrent mixed".into(),
                        origin: "o".into(),
                        goal: "g".into(),
                        hints: None,
                    },
                })
                .await
                .expect("create project"),
        );
        let project_id = detail.project.id;
        let mut tasks = Vec::new();
        for idx in 0..100 {
            let service = service.clone();
            let project_id = project_id.clone();
            tasks.push(tokio::spawn(async move {
                service
                    .handle_envelope(ClairvoyantRequest::CreateHint {
                        project_id,
                        body: CreateHintRequest {
                            content: format!("mixed hint {idx}"),
                            creator: "test".into(),
                        },
                    })
                    .await
            }));
        }
        for idx in 0..100 {
            let service = service.clone();
            let project_id = project_id.clone();
            tasks.push(tokio::spawn(async move {
                if idx % 2 == 0 {
                    service
                        .handle_envelope(ClairvoyantRequest::ListProjects)
                        .await
                } else {
                    service
                        .handle_envelope(ClairvoyantRequest::GetProject { project_id })
                        .await
                }
            }));
        }

        for task in tasks {
            match task.await.expect("join") {
                clairvoyant_core::ClairvoyantEnvelope::Ok { .. } => {}
                clairvoyant_core::ClairvoyantEnvelope::Err { error } => {
                    panic!("mixed read/write failed: {error:?}");
                }
            }
        }

        let detail = expect_detail(
            service
                .handle(ClairvoyantRequest::GetProject { project_id })
                .await
                .expect("get project"),
        );
        assert_eq!(detail.hints.len(), 100);
    }

    #[tokio::test]
    async fn write_retries_external_sqlite_busy_until_lock_released() {
        let path = std::env::temp_dir().join(format!(
            "clairvoyant-rs-external-busy-{}-{}.db",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let service = ClairvoyantService::open_with_busy_timeout(&path, Duration::from_millis(10))
            .await
            .expect("open service");
        let locker_options =
            SqliteConnectOptions::from_str(&format!("sqlite://{}", path.display()))
                .expect("locker options")
                .foreign_keys(true)
                .busy_timeout(Duration::from_millis(10))
                .disable_statement_logging();
        let locker = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(locker_options)
            .await
            .expect("open locker");
        let mut lock_tx = locker
            .begin_with("BEGIN IMMEDIATE")
            .await
            .expect("hold write lock");
        sqlx::query("UPDATE settings SET intent_timeout = intent_timeout WHERE rowid = 1")
            .execute(&mut *lock_tx)
            .await
            .expect("activate write lock");

        let service_for_task = service.clone();
        let write = tokio::spawn(async move {
            service_for_task
                .handle(ClairvoyantRequest::PutSettings {
                    settings: Settings {
                        intent_timeout: 30,
                        reason_timeout: 30,
                    },
                })
                .await
        });
        tokio::time::sleep(Duration::from_millis(60)).await;
        lock_tx.commit().await.expect("release write lock");

        match write.await.expect("join").expect("write after retry") {
            ClairvoyantResponse::Settings(settings) => {
                assert_eq!(settings.intent_timeout, 30);
                assert_eq!(settings.reason_timeout, 30);
            }
            other => panic!("expected settings, got {other:?}"),
        }
        locker.close().await;
    }

    #[tokio::test]
    async fn exhausted_sqlite_busy_retry_returns_503_retry_after_envelope() {
        let path = std::env::temp_dir().join(format!(
            "clairvoyant-rs-external-busy-exhausted-{}-{}.db",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let service = ClairvoyantService::open_with_busy_timeout(&path, Duration::from_millis(1))
            .await
            .expect("open service");
        let locker_options =
            SqliteConnectOptions::from_str(&format!("sqlite://{}", path.display()))
                .expect("locker options")
                .foreign_keys(true)
                .busy_timeout(Duration::from_millis(1))
                .disable_statement_logging();
        let locker = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(locker_options)
            .await
            .expect("open locker");
        let mut lock_tx = locker
            .begin_with("BEGIN IMMEDIATE")
            .await
            .expect("hold write lock");
        sqlx::query("UPDATE settings SET intent_timeout = intent_timeout WHERE rowid = 1")
            .execute(&mut *lock_tx)
            .await
            .expect("activate write lock");

        match service
            .handle_envelope(ClairvoyantRequest::PutSettings {
                settings: Settings {
                    intent_timeout: 30,
                    reason_timeout: 30,
                },
            })
            .await
        {
            ClairvoyantEnvelope::Err { error } => {
                assert_eq!(error.status, 503);
                assert_eq!(error.message, "database is busy");
                assert_eq!(error.retry_after_ms, Some(250));
            }
            ClairvoyantEnvelope::Ok { response } => {
                panic!("busy write unexpectedly succeeded: {response:?}")
            }
        }

        lock_tx.commit().await.expect("release write lock");
        locker.close().await;
    }

    #[test]
    fn static_frontend_assets_are_embedded() {
        assert_eq!(static_assets().len(), 13);
        let index = static_asset("/").expect("index asset");
        assert_eq!(index.path, "index.html");
        assert_eq!(index.content_type, "text/html; charset=utf-8");
        assert!(index.bytes.starts_with(b"<!DOCTYPE html>"));

        let cytoscape =
            static_asset("/static/vendor/cytoscape.min.js").expect("cytoscape vendor asset");
        assert_eq!(cytoscape.content_type, "text/javascript; charset=utf-8");
        assert!(cytoscape.bytes.len() > 100_000);
        assert!(static_asset("/static/missing.js").is_none());
    }

    #[tokio::test]
    async fn migrate_python_db_maps_fields_and_rebuilds_counters() {
        let from = std::env::temp_dir().join(format!(
            "clairvoyant-python-old-{}-{}.db",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let to = std::env::temp_dir().join(format!(
            "clairvoyant-python-new-{}-{}.db",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let options = SqliteConnectOptions::from_str(&format!("sqlite://{}", from.display()))
            .expect("options")
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

        let report = ClairvoyantService::migrate_from_python_db(&from, &to)
            .await
            .expect("migrate");
        assert_eq!(report.projects, 1);
        assert_eq!(report.facts, 3);
        assert_eq!(report.intents, 1);
        assert_eq!(report.intent_sources, 1);
        assert_eq!(report.hints, 1);

        let service = ClairvoyantService::open(&to).await.expect("open migrated");
        let settings = service.get_settings().await.expect("settings");
        assert_eq!(settings.intent_timeout, 30);
        assert_eq!(settings.reason_timeout, 45);

        let detail = expect_detail(
            service
                .handle(ClairvoyantRequest::GetProject {
                    project_id: "proj_007".into(),
                })
                .await
                .expect("get project"),
        );
        let reason = detail.project.reason.expect("reason lease");
        assert_eq!(reason.worker, "reasoner");
        assert_eq!(reason.trigger, "facts=3 hints=1 open_intents=0");
        assert_eq!(reason.started_at, 1_767_225_604_000);
        assert_eq!(reason.last_heartbeat_at, 1_767_225_605_000);
        assert_eq!(detail.intents[0].sources, vec!["origin"]);
        assert_eq!(detail.intents[0].target_fact.as_deref(), Some("f001"));
        assert_eq!(detail.hints[0].created_at, 1_767_225_603_000);

        let next = expect_intent(
            service
                .handle(ClairvoyantRequest::CreateIntent {
                    project_id: "proj_007".into(),
                    body: CreateIntentRequest {
                        sources: vec!["f001".into()],
                        description: "next".into(),
                        creator: "w".into(),
                        worker: None,
                    },
                })
                .await
                .expect("create next intent"),
        );
        assert_eq!(next.id, "i002");

        let next_project = expect_detail(
            service
                .handle(ClairvoyantRequest::CreateProject {
                    body: CreateProjectRequest {
                        title: "new".into(),
                        origin: "o".into(),
                        goal: "g".into(),
                        hints: None,
                    },
                })
                .await
                .expect("create next project"),
        );
        assert_eq!(next_project.project.id, "proj_008");
    }

    #[tokio::test]
    async fn migration_rejects_target_with_only_counter_history() {
        let from = std::env::temp_dir().join(format!(
            "clairvoyant-python-empty-{}-{}.db",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let to = std::env::temp_dir().join(format!(
            "clairvoyant-python-dirty-target-{}-{}.db",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let source_options =
            SqliteConnectOptions::from_str(&format!("sqlite://{}", from.display()))
                .expect("source options")
                .create_if_missing(true);
        let source = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(source_options)
            .await
            .expect("create source db");
        for statement in [
            "CREATE TABLE settings (intent_timeout INTEGER NOT NULL DEFAULT 15, reason_timeout INTEGER NOT NULL DEFAULT 15)",
            "INSERT INTO settings (rowid, intent_timeout, reason_timeout) VALUES (1, 15, 15)",
            "CREATE TABLE projects (id TEXT PRIMARY KEY, title TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL, reason_worker TEXT, reason_trigger TEXT, reason_started_at TEXT, reason_last_heartbeat_at TEXT)",
            "CREATE TABLE facts (id TEXT NOT NULL, project_id TEXT NOT NULL, description TEXT NOT NULL, PRIMARY KEY (id, project_id))",
            "CREATE TABLE intents (id TEXT NOT NULL, project_id TEXT NOT NULL, to_fact_id TEXT, description TEXT NOT NULL, creator TEXT NOT NULL, worker TEXT, last_heartbeat_at TEXT, created_at TEXT NOT NULL, concluded_at TEXT, PRIMARY KEY (id, project_id))",
            "CREATE TABLE intent_sources (intent_id TEXT NOT NULL, project_id TEXT NOT NULL, fact_id TEXT NOT NULL, PRIMARY KEY (intent_id, project_id, fact_id))",
            "CREATE TABLE hints (id TEXT NOT NULL, project_id TEXT NOT NULL, content TEXT NOT NULL, creator TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY (id, project_id))",
        ] {
            sqlx::query(statement).execute(&source).await.expect(statement);
        }
        source.close().await;

        let target = ClairvoyantService::open(&to).await.expect("open target");
        let project_id = expect_detail(
            target
                .handle(ClairvoyantRequest::CreateProject {
                    body: CreateProjectRequest {
                        title: "temporary".into(),
                        origin: "o".into(),
                        goal: "g".into(),
                        hints: None,
                    },
                })
                .await
                .expect("create project"),
        )
        .project
        .id;
        target
            .handle(ClairvoyantRequest::DeleteProject { project_id })
            .await
            .expect("delete project");
        drop(target);

        let error = ClairvoyantService::migrate_from_python_db(&from, &to)
            .await
            .expect_err("dirty target should be rejected");
        match error {
            ClairvoyantError::Api {
                status, message, ..
            } => {
                assert_eq!(status, 409);
                assert!(message.contains("counters contain non-default rows"));
            }
            other => panic!("unexpected error {other:?}"),
        }
    }

    #[tokio::test]
    async fn internal_request_surface_covers_server_protocol_paths() {
        let service = test_service("protocol-surface").await;

        match service
            .handle(ClairvoyantRequest::GetSettings)
            .await
            .expect("get settings")
        {
            ClairvoyantResponse::Settings(settings) => {
                assert_eq!(settings.intent_timeout, 15);
                assert_eq!(settings.reason_timeout, 15);
            }
            other => panic!("unexpected response {other:?}"),
        }
        service
            .handle(ClairvoyantRequest::PutSettings {
                settings: Settings {
                    intent_timeout: 10,
                    reason_timeout: 11,
                },
            })
            .await
            .expect("put settings");

        let detail = expect_detail(
            service
                .handle(ClairvoyantRequest::CreateProject {
                    body: CreateProjectRequest {
                        title: "surface".into(),
                        origin: "origin".into(),
                        goal: "goal".into(),
                        hints: Some(vec![clairvoyant_core::CreateHintInline {
                            content: "inline".into(),
                            creator: "human".into(),
                        }]),
                    },
                })
                .await
                .expect("create project"),
        );
        let project_id = detail.project.id;
        assert_eq!(detail.hints.len(), 1);

        let fetched = expect_detail(
            service
                .handle(ClairvoyantRequest::GetProject {
                    project_id: project_id.clone(),
                })
                .await
                .expect("get project"),
        );
        assert_eq!(fetched.project.id, project_id);

        match service
            .handle(ClairvoyantRequest::ListProjects)
            .await
            .expect("list projects")
        {
            ClairvoyantResponse::ProjectSummaries(projects) => {
                assert_eq!(projects.len(), 1);
                assert_eq!(projects[0].hint_count, 1);
            }
            other => panic!("unexpected response {other:?}"),
        }

        match service
            .handle(ClairvoyantRequest::UpdateProjectTitle {
                project_id: project_id.clone(),
                body: UpdateProjectTitleRequest {
                    title: "renamed".into(),
                },
            })
            .await
            .expect("title")
        {
            ClairvoyantResponse::ProjectMeta(project) => assert_eq!(project.title, "renamed"),
            other => panic!("unexpected response {other:?}"),
        }

        service
            .handle(ClairvoyantRequest::CreateHint {
                project_id: project_id.clone(),
                body: CreateHintRequest {
                    content: "later".into(),
                    creator: "human".into(),
                },
            })
            .await
            .expect("create hint");

        match service
            .handle(ClairvoyantRequest::ClaimProjectReason {
                project_id: project_id.clone(),
                body: ReasonClaimRequest {
                    worker: "reasoner".into(),
                    trigger: "test".into(),
                },
            })
            .await
            .expect("claim reason")
        {
            ClairvoyantResponse::ProjectMeta(project) => {
                assert_eq!(project.reason.expect("reason").worker, "reasoner");
            }
            other => panic!("unexpected response {other:?}"),
        }
        service
            .handle(ClairvoyantRequest::HeartbeatProjectReason {
                project_id: project_id.clone(),
                body: HeartbeatRequest {
                    worker: " reasoner ".into(),
                },
            })
            .await
            .expect("heartbeat reason");
        service
            .handle(ClairvoyantRequest::ReleaseProjectReason {
                project_id: project_id.clone(),
                body: HeartbeatRequest {
                    worker: " reasoner ".into(),
                },
            })
            .await
            .expect("release reason");

        let intent = expect_intent(
            service
                .handle(ClairvoyantRequest::CreateIntent {
                    project_id: project_id.clone(),
                    body: CreateIntentRequest {
                        sources: vec!["origin".into()],
                        description: "explore".into(),
                        creator: "worker".into(),
                        worker: None,
                    },
                })
                .await
                .expect("create intent"),
        );
        service
            .handle(ClairvoyantRequest::HeartbeatIntent {
                project_id: project_id.clone(),
                intent_id: intent.id.clone(),
                body: HeartbeatRequest {
                    worker: "worker".into(),
                },
            })
            .await
            .expect("heartbeat intent");
        let released = expect_intent(
            service
                .handle(ClairvoyantRequest::ReleaseIntent {
                    project_id: project_id.clone(),
                    intent_id: intent.id.clone(),
                    body: HeartbeatRequest {
                        worker: "worker".into(),
                    },
                })
                .await
                .expect("release intent"),
        );
        assert!(released.worker.is_none());
        assert!(released.last_heartbeat_at.is_none());
        service
            .handle(ClairvoyantRequest::ConcludeIntent {
                project_id: project_id.clone(),
                intent_id: intent.id,
                body: ConcludeRequest {
                    worker: "worker".into(),
                    description: "fact".into(),
                },
            })
            .await
            .expect("conclude intent");

        match service
            .handle(ClairvoyantRequest::ExportProject {
                project_id: project_id.clone(),
                format: ExportFormat::Timeline,
            })
            .await
            .expect("timeline")
        {
            ClairvoyantResponse::Text(text) => assert!(text.contains("INTENT CONCLUDED")),
            other => panic!("unexpected response {other:?}"),
        }

        let completion = expect_intent(
            service
                .handle(ClairvoyantRequest::CompleteProject {
                    project_id: project_id.clone(),
                    body: CompleteRequest {
                        sources: vec!["f001".into()],
                        description: "complete through protocol surface".into(),
                        worker: "worker".into(),
                    },
                })
                .await
                .expect("complete project"),
        );
        assert_eq!(completion.target_fact.as_deref(), Some("goal"));

        let reopened = expect_reopen(
            service
                .handle(ClairvoyantRequest::ReopenProject {
                    project_id: project_id.clone(),
                    body: ReopenRequest {
                        description: "reopen through protocol surface".into(),
                        creator: "human".into(),
                    },
                })
                .await
                .expect("reopen project"),
        );
        assert_eq!(reopened.project.status, ProjectStatus::Active);
        assert_eq!(reopened.intent.target_fact.as_deref(), Some("f002"));

        match service
            .handle(ClairvoyantRequest::ExportProject {
                project_id: project_id.clone(),
                format: ExportFormat::Yaml,
            })
            .await
            .expect("yaml")
        {
            ClairvoyantResponse::Text(text) => {
                assert!(text.contains("target_fact"));
                assert!(text.contains("reopen through protocol surface"));
            }
            other => panic!("unexpected response {other:?}"),
        }

        service
            .handle(ClairvoyantRequest::UpdateProjectStatus {
                project_id: project_id.clone(),
                body: UpdateProjectStatusRequest {
                    status: ProjectStatus::Stopped,
                },
            })
            .await
            .expect("stop project");
        service
            .handle(ClairvoyantRequest::UpdateProjectStatus {
                project_id: project_id.clone(),
                body: UpdateProjectStatusRequest {
                    status: ProjectStatus::Active,
                },
            })
            .await
            .expect("resume project");
        service
            .handle(ClairvoyantRequest::DeleteProject { project_id })
            .await
            .expect("delete project");
    }

    #[tokio::test]
    async fn status_update_cannot_bypass_completion_state_machine() {
        let service = test_service("status-complete-bypass").await;
        let detail = expect_detail(
            service
                .handle(ClairvoyantRequest::CreateProject {
                    body: CreateProjectRequest {
                        title: "status complete bypass".into(),
                        origin: "origin".into(),
                        goal: "goal".into(),
                        hints: None,
                    },
                })
                .await
                .expect("create project"),
        );
        let project_id = detail.project.id;

        let error = service
            .handle(ClairvoyantRequest::UpdateProjectStatus {
                project_id: project_id.clone(),
                body: UpdateProjectStatusRequest {
                    status: ProjectStatus::Completed,
                },
            })
            .await
            .expect_err("status endpoint must not complete project directly");
        match error {
            ClairvoyantError::Api {
                status, message, ..
            } => {
                assert_eq!(status, 400);
                assert!(message.contains("complete_project"));
            }
            other => panic!("unexpected error {other:?}"),
        }

        let detail = expect_detail(
            service
                .handle(ClairvoyantRequest::GetProject { project_id })
                .await
                .expect("get project"),
        );
        assert!(matches!(detail.project.status, ProjectStatus::Active));
        assert!(detail
            .intents
            .iter()
            .all(|intent| intent.target_fact.as_deref() != Some("goal")));
    }

    #[tokio::test]
    async fn create_intent_rejects_duplicate_sources_before_db_insert() {
        let service = test_service("duplicate-sources").await;
        let detail = expect_detail(
            service
                .handle(ClairvoyantRequest::CreateProject {
                    body: CreateProjectRequest {
                        title: "duplicate sources".into(),
                        origin: "origin".into(),
                        goal: "goal".into(),
                        hints: None,
                    },
                })
                .await
                .expect("create project"),
        );

        let error = service
            .handle(ClairvoyantRequest::CreateIntent {
                project_id: detail.project.id,
                body: CreateIntentRequest {
                    sources: vec!["origin".into(), "origin".into()],
                    description: "duplicate source intent".into(),
                    creator: "worker-a".into(),
                    worker: None,
                },
            })
            .await
            .expect_err("duplicate sources should be rejected before insert");
        match error {
            ClairvoyantError::Api {
                status, message, ..
            } => {
                assert_eq!(status, 400);
                assert!(message.contains("duplicate source fact id origin"));
            }
            other => panic!("unexpected error {other:?}"),
        }
    }

    #[tokio::test]
    async fn complete_project_rejects_duplicate_sources_before_db_insert() {
        let service = test_service("duplicate-complete-sources").await;
        let detail = expect_detail(
            service
                .handle(ClairvoyantRequest::CreateProject {
                    body: CreateProjectRequest {
                        title: "duplicate complete sources".into(),
                        origin: "origin".into(),
                        goal: "goal".into(),
                        hints: None,
                    },
                })
                .await
                .expect("create project"),
        );

        let error = service
            .handle(ClairvoyantRequest::CompleteProject {
                project_id: detail.project.id,
                body: CompleteRequest {
                    sources: vec!["origin".into(), "origin".into()],
                    description: "duplicate source completion".into(),
                    worker: "worker-a".into(),
                },
            })
            .await
            .expect_err("duplicate completion sources should be rejected before insert");
        match error {
            ClairvoyantError::Api {
                status, message, ..
            } => {
                assert_eq!(status, 400);
                assert!(message.contains("duplicate source fact id origin"));
            }
            other => panic!("unexpected error {other:?}"),
        }
    }

    #[tokio::test]
    async fn complete_project_releases_open_intent_claims() {
        let service = test_service("complete-releases-open-intents").await;
        let detail = expect_detail(
            service
                .handle(ClairvoyantRequest::CreateProject {
                    body: CreateProjectRequest {
                        title: "release open claims".into(),
                        origin: "origin".into(),
                        goal: "goal".into(),
                        hints: None,
                    },
                })
                .await
                .expect("create project"),
        );
        let project_id = detail.project.id;
        let open_intent = expect_intent(
            service
                .handle(ClairvoyantRequest::CreateIntent {
                    project_id: project_id.clone(),
                    body: CreateIntentRequest {
                        sources: vec!["origin".into()],
                        description: "still running".into(),
                        creator: "worker-a".into(),
                        worker: Some("worker-a".into()),
                    },
                })
                .await
                .expect("create claimed intent"),
        );
        assert_eq!(open_intent.worker.as_deref(), Some("worker-a"));
        assert!(open_intent.last_heartbeat_at.is_some());

        let completion = expect_intent(
            service
                .handle(ClairvoyantRequest::CompleteProject {
                    project_id: project_id.clone(),
                    body: CompleteRequest {
                        sources: vec!["origin".into()],
                        description: "complete while another intent is open".into(),
                        worker: "worker-a".into(),
                    },
                })
                .await
                .expect("complete project"),
        );
        assert_eq!(completion.target_fact.as_deref(), Some("goal"));

        let detail = expect_detail(
            service
                .handle(ClairvoyantRequest::GetProject { project_id })
                .await
                .expect("get completed project"),
        );
        assert!(matches!(detail.project.status, ProjectStatus::Completed));
        let original = detail
            .intents
            .iter()
            .find(|intent| intent.id == open_intent.id)
            .expect("original intent remains");
        assert!(original.target_fact.is_none());
        assert!(original.worker.is_none());
        assert!(original.last_heartbeat_at.is_none());
    }

    #[tokio::test]
    async fn stopping_project_releases_open_intent_claim_heartbeats() {
        let service = test_service("stop-releases-open-intents").await;
        let detail = expect_detail(
            service
                .handle(ClairvoyantRequest::CreateProject {
                    body: CreateProjectRequest {
                        title: "stop releases claims".into(),
                        origin: "origin".into(),
                        goal: "goal".into(),
                        hints: None,
                    },
                })
                .await
                .expect("create project"),
        );
        let project_id = detail.project.id;
        let open_intent = expect_intent(
            service
                .handle(ClairvoyantRequest::CreateIntent {
                    project_id: project_id.clone(),
                    body: CreateIntentRequest {
                        sources: vec!["origin".into()],
                        description: "claimed work".into(),
                        creator: "worker-a".into(),
                        worker: Some("worker-a".into()),
                    },
                })
                .await
                .expect("create claimed intent"),
        );
        assert_eq!(open_intent.worker.as_deref(), Some("worker-a"));
        assert!(open_intent.last_heartbeat_at.is_some());

        service
            .handle(ClairvoyantRequest::UpdateProjectStatus {
                project_id: project_id.clone(),
                body: UpdateProjectStatusRequest {
                    status: ProjectStatus::Stopped,
                },
            })
            .await
            .expect("stop project");

        let detail = expect_detail(
            service
                .handle(ClairvoyantRequest::GetProject { project_id })
                .await
                .expect("get stopped project"),
        );
        let stopped_intent = detail
            .intents
            .iter()
            .find(|intent| intent.id == open_intent.id)
            .expect("open intent remains");
        assert!(stopped_intent.worker.is_none());
        assert!(stopped_intent.last_heartbeat_at.is_none());
    }

    #[tokio::test]
    async fn complete_project_requires_existing_non_goal_sources_and_active_project() {
        let service = test_service("complete-strict-sources").await;
        let detail = expect_detail(
            service
                .handle(ClairvoyantRequest::CreateProject {
                    body: CreateProjectRequest {
                        title: "strict completion".into(),
                        origin: "origin".into(),
                        goal: "goal".into(),
                        hints: None,
                    },
                })
                .await
                .expect("create project"),
        );
        let project_id = detail.project.id;

        let goal_error = service
            .handle(ClairvoyantRequest::CompleteProject {
                project_id: project_id.clone(),
                body: CompleteRequest {
                    sources: vec!["goal".into()],
                    description: "bogus direct goal completion".into(),
                    worker: "worker-a".into(),
                },
            })
            .await
            .expect_err("goal cannot be used as completion source");
        match goal_error {
            ClairvoyantError::Api {
                status, message, ..
            } => {
                assert_eq!(status, 400);
                assert!(message.contains("goal cannot be used in sources"));
            }
            other => panic!("unexpected error {other:?}"),
        }

        let missing_error = service
            .handle(ClairvoyantRequest::CompleteProject {
                project_id: project_id.clone(),
                body: CompleteRequest {
                    sources: vec!["f404".into()],
                    description: "missing source completion".into(),
                    worker: "worker-a".into(),
                },
            })
            .await
            .expect_err("missing fact cannot be used as completion source");
        match missing_error {
            ClairvoyantError::Api {
                status, message, ..
            } => {
                assert_eq!(status, 404);
                assert!(message.contains("Fact f404 not found"));
            }
            other => panic!("unexpected error {other:?}"),
        }

        let detail = expect_detail(
            service
                .handle(ClairvoyantRequest::GetProject {
                    project_id: project_id.clone(),
                })
                .await
                .expect("get project"),
        );
        assert!(matches!(detail.project.status, ProjectStatus::Active));
        assert!(detail
            .intents
            .iter()
            .all(|intent| intent.target_fact.as_deref() != Some("goal")));

        let intent = expect_intent(
            service
                .handle(ClairvoyantRequest::CreateIntent {
                    project_id: project_id.clone(),
                    body: CreateIntentRequest {
                        sources: vec!["origin".into()],
                        description: "produce evidence".into(),
                        creator: "worker-a".into(),
                        worker: Some("worker-a".into()),
                    },
                })
                .await
                .expect("create claimed intent"),
        );
        let concluded = match service
            .handle(ClairvoyantRequest::ConcludeIntent {
                project_id: project_id.clone(),
                intent_id: intent.id,
                body: ConcludeRequest {
                    worker: "worker-a".into(),
                    description: "verified fix_exit_code=0 and vul_exit_code!=0".into(),
                },
            })
            .await
            .expect("conclude evidence intent")
        {
            ClairvoyantResponse::Conclude(response) => response,
            other => panic!("unexpected conclude response {other:?}"),
        };

        service
            .handle(ClairvoyantRequest::CompleteProject {
                project_id: project_id.clone(),
                body: CompleteRequest {
                    sources: vec![concluded.fact.id],
                    description: "strict completion evidence".into(),
                    worker: "worker-a".into(),
                },
            })
            .await
            .expect("complete project with evidence fact");

        let duplicate_error = service
            .handle(ClairvoyantRequest::CompleteProject {
                project_id,
                body: CompleteRequest {
                    sources: vec!["origin".into()],
                    description: "duplicate completion".into(),
                    worker: "worker-a".into(),
                },
            })
            .await
            .expect_err("completed project cannot be completed twice");
        match duplicate_error {
            ClairvoyantError::Api {
                status, message, ..
            } => {
                assert_eq!(status, 403);
                assert!(message.contains("Project is completed"));
            }
            other => panic!("unexpected error {other:?}"),
        }
    }
}
