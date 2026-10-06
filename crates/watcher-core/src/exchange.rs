use crate::body::BodyHandle;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExchangeId(pub Uuid);

impl ExchangeId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for ExchangeId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ExchangeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    Pending,
    PausedRequest,
    PausedResponse,
    Complete,
    Failed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Exchange {
    pub id: ExchangeId,
    pub started_unix_ms: u64,
    pub method: String,
    pub url: String,
    pub host: String,
    pub path: String,
    pub status: Option<u16>,
    pub http_version: String,
    pub request_headers: Vec<(String, String)>,
    pub response_headers: Vec<(String, String)>,
    pub request_body: BodyHandle,
    pub response_body: BodyHandle,
    pub pinned: bool,
    pub error: Option<String>,
    pub phase: Phase,
    pub duration_ms: Option<u64>,
    pub ttfb_ms: Option<u64>,
    pub download_ms: Option<u64>,
    pub protocol_note: String,
    pub timing_notes: String,
}

impl Exchange {
    pub fn size_bytes(&self) -> u64 {
        self.request_body.len() + self.response_body.len()
    }

    pub fn row_label(&self) -> String {
        let status = self
            .status
            .map(|code| code.to_string())
            .unwrap_or_else(|| match self.phase {
                Phase::PausedRequest => "pause".into(),
                Phase::PausedResponse => "pause".into(),
                Phase::Pending => "...".into(),
                Phase::Failed => "err".into(),
                Phase::Complete => "-".into(),
            });
        let mark = if self.pinned { "P" } else { " " };
        format!(
            "{mark} {} {status} {}{}",
            self.method, self.host, self.path
        )
    }
}
