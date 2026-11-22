use serde::{Deserialize, Serialize};
use std::convert::TryInto;

pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub intent_timeout: i64,
    pub reason_timeout: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fact {
    pub id: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    pub id: String,
    pub sources: Vec<String>,
    pub target_fact: Option<String>,
    pub description: String,
    pub creator: String,
    pub worker: Option<String>,
    pub last_heartbeat_at: Option<i64>,
    pub created_at: i64,
    pub concluded_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hint {
    pub id: String,
    pub content: String,
    pub creator: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectReason {
    pub worker: String,
    pub trigger: String,
    pub started_at: i64,
    pub last_heartbeat_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProjectStatus {
    Active,
    Stopped,
    Completed,
}

impl ProjectStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Stopped => "stopped",
            Self::Completed => "completed",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectMeta {
    pub id: String,
    pub title: String,
    pub status: ProjectStatus,
    pub created_at: i64,
    pub reason: Option<ProjectReason>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectSummary {
    #[serde(flatten)]
    pub project: ProjectMeta,
    pub fact_count: i64,
    pub intent_count: i64,
    pub working_intent_count: i64,
    pub unclaimed_intent_count: i64,
    pub hint_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectDetail {
    pub project: ProjectMeta,
    pub facts: Vec<Fact>,
    pub intents: Vec<Intent>,
    pub hints: Vec<Hint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentObservation {
    pub id: String,
    pub sources: Vec<String>,
    pub description: String,
    pub creator: String,
    pub worker: Option<String>,
    pub last_heartbeat_at: Option<i64>,
    pub created_at: i64,
    pub age_ms: i64,
    pub heartbeat_age_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectObservation {
    #[serde(flatten)]
    pub project: ProjectMeta,
    pub fact_count: usize,
    pub intent_count: usize,
    pub open_intent_count: usize,
    pub working_intent_count: usize,
    pub unclaimed_intent_count: usize,
    pub hint_count: usize,
    pub reason_heartbeat_age_ms: Option<i64>,
    pub open_intents: Vec<IntentObservation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationSnapshot {
    pub generated_at: i64,
    pub project_count: usize,
    pub projects: Vec<ProjectObservation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateHintInline {
    pub content: String,
    pub creator: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateProjectRequest {
    pub title: String,
    pub origin: String,
    pub goal: String,
    pub hints: Option<Vec<CreateHintInline>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateHintRequest {
    pub content: String,
    pub creator: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateIntentRequest {
    pub sources: Vec<String>,
    pub description: String,
    pub creator: String,
    pub worker: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeartbeatRequest {
    pub worker: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReasonClaimRequest {
    pub worker: String,
    pub trigger: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConcludeRequest {
    pub worker: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompleteRequest {
    pub sources: Vec<String>,
    pub description: String,
    pub worker: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConcludeResponse {
    pub fact: Fact,
    pub intent: Intent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateProjectStatusRequest {
    pub status: ProjectStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateProjectTitleRequest {
    pub title: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReopenRequest {
    pub description: String,
    pub creator: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReopenResponse {
    pub project: ProjectMeta,
    pub fact: Fact,
    pub intent: Intent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportFormat {
    Yaml,
    Timeline,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClairvoyantRequest {
    GetSettings,
    PutSettings {
        settings: Settings,
    },
    ListProjects,
    Observe {
        project_id: Option<String>,
    },
    CreateProject {
        body: CreateProjectRequest,
    },
    GetProject {
        project_id: String,
    },
    DeleteProject {
        project_id: String,
    },
    UpdateProjectTitle {
        project_id: String,
        body: UpdateProjectTitleRequest,
    },
    UpdateProjectStatus {
        project_id: String,
        body: UpdateProjectStatusRequest,
    },
    ClaimProjectReason {
        project_id: String,
        body: ReasonClaimRequest,
    },
    HeartbeatProjectReason {
        project_id: String,
        body: HeartbeatRequest,
    },
    ReleaseProjectReason {
        project_id: String,
        body: HeartbeatRequest,
    },
    CompleteProject {
        project_id: String,
        body: CompleteRequest,
    },
    ReopenProject {
        project_id: String,
        body: ReopenRequest,
    },
    CreateHint {
        project_id: String,
        body: CreateHintRequest,
    },
    CreateIntent {
        project_id: String,
        body: CreateIntentRequest,
    },
    HeartbeatIntent {
        project_id: String,
        intent_id: String,
        body: HeartbeatRequest,
    },
    ReleaseIntent {
        project_id: String,
        intent_id: String,
        body: HeartbeatRequest,
    },
    ConcludeIntent {
        project_id: String,
        intent_id: String,
        body: ConcludeRequest,
    },
    ExportProject {
        project_id: String,
        format: ExportFormat,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ClairvoyantResponse {
    Settings(Settings),
    Observation(ObservationSnapshot),
    ProjectSummaries(Vec<ProjectSummary>),
    ProjectDetail(ProjectDetail),
    ProjectMeta(ProjectMeta),
    Intent(Intent),
    Hint(Hint),
    Conclude(ConcludeResponse),
    Reopen(ReopenResponse),
    Text(String),
    Empty,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClairvoyantErrorBody {
    pub status: u16,
    pub message: String,
    pub retry_after_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClairvoyantEnvelope {
    Ok { response: Box<ClairvoyantResponse> },
    Err { error: ClairvoyantErrorBody },
}

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("frame too short")]
    TooShort,
    #[error("frame too large: {0} bytes")]
    TooLarge(usize),
    #[error("invalid json: {0}")]
    Json(#[from] serde_json::Error),
}

pub fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, FrameError> {
    let payload = serde_json::to_vec(value)?;
    if payload.len() > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge(payload.len()));
    }
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

pub fn decode_frame<T: for<'de> Deserialize<'de>>(frame: &[u8]) -> Result<T, FrameError> {
    if frame.len() < 4 {
        return Err(FrameError::TooShort);
    }
    let len = u32::from_be_bytes(frame[..4].try_into().expect("slice length checked")) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge(len));
    }
    if frame.len() < 4 + len {
        return Err(FrameError::TooShort);
    }
    Ok(serde_json::from_slice(&frame[4..4 + len])?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trips_request() {
        let request = ClairvoyantRequest::GetSettings;
        let frame = encode_frame(&request).expect("encode");
        let decoded: ClairvoyantRequest = decode_frame(&frame).expect("decode");
        assert!(matches!(decoded, ClairvoyantRequest::GetSettings));
    }

    #[test]
    fn frame_rejects_short_input() {
        let err = decode_frame::<ClairvoyantRequest>(&[0, 0]).expect_err("short frame");
        assert!(matches!(err, FrameError::TooShort));
    }

    #[test]
    fn request_rejects_unknown_top_level_fields() {
        let error = serde_json::from_str::<ClairvoyantRequest>(
            r#"{"op":"get_project","project_id":"proj_001","extra":true}"#,
        )
        .expect_err("unknown request field should fail");
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn request_rejects_unknown_body_fields() {
        let error = serde_json::from_str::<ClairvoyantRequest>(
            r#"{"op":"create_project","body":{"title":"t","origin":"o","goal":"g","hints":null,"extra":true}}"#,
        )
        .expect_err("unknown request body field should fail");
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn intent_request_rejects_legacy_from_field() {
        let error = serde_json::from_str::<ClairvoyantRequest>(
            r#"{"op":"create_intent","project_id":"proj_001","body":{"from":["origin"],"description":"legacy","creator":"test","worker":null}}"#,
        )
        .expect_err("legacy from field should fail");
        assert!(error.to_string().contains("unknown field `from`"));
    }

    #[test]
    fn intent_response_rejects_legacy_to_fact_id_field() {
        let error = serde_json::from_str::<ClairvoyantResponse>(
            r#"{"kind":"intent","value":{"id":"i001","sources":["origin"],"to_fact_id":null,"description":"legacy","creator":"test","worker":null,"last_heartbeat_at":null,"created_at":1,"concluded_at":null}}"#,
        )
        .expect_err("legacy to_fact_id field should fail");
        assert!(error.to_string().contains("unknown field `to_fact_id`"));
    }

    #[test]
    fn response_rejects_unknown_top_level_fields() {
        let error = serde_json::from_str::<ClairvoyantResponse>(
            r#"{"kind":"settings","value":{"intent_timeout":10,"reason_timeout":11},"extra":true}"#,
        )
        .expect_err("unknown response field should fail");
        assert!(!error.to_string().is_empty());
    }

    #[test]
    fn project_summary_rejects_unknown_fields() {
        let error = serde_json::from_str::<ClairvoyantResponse>(
            r#"{"kind":"project_summaries","value":[{"id":"proj_001","title":"demo","status":"active","created_at":1,"reason":null,"fact_count":2,"intent_count":0,"working_intent_count":0,"unclaimed_intent_count":0,"hint_count":0,"extra":true}]}"#,
        )
        .expect_err("unknown project summary field should fail");
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn envelope_rejects_unknown_top_level_fields() {
        let error = serde_json::from_str::<ClairvoyantEnvelope>(
            r#"{"result":"err","error":{"status":503,"message":"busy","retry_after_ms":100},"extra":true}"#,
        )
        .expect_err("unknown envelope field should fail");
        assert!(!error.to_string().is_empty());
    }
}
