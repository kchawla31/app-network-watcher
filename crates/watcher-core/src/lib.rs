//! Capture model for App Network Watcher.
//!
//! The proxy and the desktop UI share a [`Session`]. Bodies larger than
//! [`BODY_MEMORY_LIMIT`] are written under the session directory and read back
//! when the inspector opens them.

mod body;
mod ca;
mod exchange;
mod export_code;
mod filter;
mod har;
mod openapi;
mod rules;
mod session;
mod settings;
mod snippets;

pub use body::{
    caching_notes, compression_notes, decode_for_display, BodyHandle, BodyStore, BODY_MEMORY_LIMIT,
};
pub use ca::CertificateAuthority;
pub use exchange::{Exchange, ExchangeId, Phase};
pub use export_code::{export_request, ExportKind};
pub use filter::{matches_filter, FilterAlias};
pub use har::{export_har, import_har};
pub use openapi::validate_openapi;
pub use rules::{
    apply_header_edits, rule_from_exchange, Action, BreakpointDecision, RequestSnap, ResponseSnap,
    Rule, RuleSet,
};
pub use session::{now_ms, Session, SessionStats};
pub use settings::{HttpVersion, Settings, UpstreamTls};
pub use snippets::{
    debug_only_network_security_config, manifest_attribute, release_network_security_config,
};

pub fn qr_payload(host: &str, port: u16, fingerprint: &str) -> String {
    format!("watcher://connect?host={host}&port={port}&fp={fingerprint}")
}

pub fn parse_qr_payload(payload: &str) -> Option<(String, u16, String)> {
    let rest = payload.trim().strip_prefix("watcher://connect?")?;
    let mut host = None;
    let mut port = None;
    let mut fp = None;
    for part in rest.split('&') {
        let (key, value) = part.split_once('=')?;
        match key {
            "host" => host = Some(value.to_string()),
            "port" => port = value.parse().ok(),
            "fp" => fp = Some(value.to_string()),
            _ => {}
        }
    }
    Some((host?, port?, fp?))
}

pub fn local_lan_ip() -> Option<String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    let addr = socket.local_addr().ok()?;
    Some(addr.ip().to_string())
}

pub fn app_data_dir() -> std::path::PathBuf {
    if let Ok(dir) = std::env::var("WATCHER_DATA_DIR") {
        return std::path::PathBuf::from(dir);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let home = std::path::PathBuf::from(home);
    if cfg!(target_os = "macos") {
        home.join("Library/Application Support/app-network-watcher")
    } else {
        home.join(".local/share/app-network-watcher")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Message(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
