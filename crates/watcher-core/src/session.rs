use crate::body::{caching_notes, compression_notes, decode_for_display, BodyStore};
use crate::ca::CertificateAuthority;
use crate::exchange::{Exchange, ExchangeId};
use crate::filter::FilterAlias;
use crate::rules::{BreakpointDecision, RuleSet};
use crate::settings::Settings;
use crate::{Error, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use tokio::sync::{broadcast, oneshot};

const MAX_EXCHANGES: usize = 5000;

pub struct Session {
    inner: Arc<Inner>,
}

struct Inner {
    dir: PathBuf,
    ca: CertificateAuthority,
    bodies: BodyStore,
    exchanges: Mutex<Vec<Exchange>>,
    rules: RwLock<RuleSet>,
    settings: RwLock<Settings>,
    aliases: RwLock<Vec<FilterAlias>>,
    breakpoints: Mutex<Vec<(ExchangeId, oneshot::Sender<BreakpointDecision>)>>,
    stats: Mutex<SessionStats>,
    status: Mutex<String>,
    events: broadcast::Sender<ExchangeId>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SessionStats {
    pub tls_hellos: u64,
    pub http_exchanges: u64,
}

impl Clone for Session {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl Session {
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        let ca = CertificateAuthority::load_or_create(dir.join("ca"))?;
        let bodies = BodyStore::new(dir.join("bodies"))?;
        let rules = read_json(dir.join("rules.json")).unwrap_or_default();
        let settings = read_json(dir.join("settings.json")).unwrap_or_default();
        let aliases = read_json(dir.join("filters.json")).unwrap_or_default();
        let (events, _) = broadcast::channel(256);
        Ok(Self {
            inner: Arc::new(Inner {
                dir,
                ca,
                bodies,
                exchanges: Mutex::new(Vec::new()),
                rules: RwLock::new(rules),
                settings: RwLock::new(settings),
                aliases: RwLock::new(aliases),
                breakpoints: Mutex::new(Vec::new()),
                stats: Mutex::new(SessionStats::default()),
                status: Mutex::new("Manual proxy is idle.".into()),
                events,
            }),
        })
    }

    pub fn dir(&self) -> &Path {
        &self.inner.dir
    }

    pub fn ca(&self) -> &CertificateAuthority {
        &self.inner.ca
    }

    pub fn bodies(&self) -> &BodyStore {
        &self.inner.bodies
    }

    pub fn settings(&self) -> Settings {
        read_lock(&self.inner.settings).clone()
    }

    pub fn update_settings(&self, settings: Settings) -> Result<()> {
        *write_lock(&self.inner.settings) = settings.clone();
        write_json(self.inner.dir.join("settings.json"), &settings)
    }

    pub fn rules(&self) -> RuleSet {
        read_lock(&self.inner.rules).clone()
    }

    pub fn update_rules(&self, rules: RuleSet) -> Result<()> {
        *write_lock(&self.inner.rules) = rules.clone();
        write_json(self.inner.dir.join("rules.json"), &rules)
    }

    pub fn aliases(&self) -> Vec<FilterAlias> {
        read_lock(&self.inner.aliases).clone()
    }

    pub fn update_aliases(&self, aliases: Vec<FilterAlias>) -> Result<()> {
        *write_lock(&self.inner.aliases) = aliases.clone();
        write_json(self.inner.dir.join("filters.json"), &aliases)
    }

    pub fn status(&self) -> String {
        lock(&self.inner.status).clone()
    }

    pub fn set_status(&self, status: impl Into<String>) {
        *lock(&self.inner.status) = status.into();
    }

    pub fn stats(&self) -> SessionStats {
        *lock(&self.inner.stats)
    }

    pub fn bump_tls_hello(&self, host: &str) {
        lock(&self.inner.stats).tls_hellos += 1;
        self.set_status(format!(
            "TLS client hello for {host}. If calls do not follow, the app rejected the CA. That happens on release builds that do not trust user CAs, and on apps that pin certificates."
        ));
    }

    pub fn exchanges(&self) -> Vec<Exchange> {
        lock(&self.inner.exchanges).clone()
    }

    pub fn upsert(&self, exchange: Exchange) {
        let id = exchange.id;
        {
            let mut exchanges = lock(&self.inner.exchanges);
            if let Some(existing) = exchanges.iter_mut().find(|item| item.id == id) {
                let pinned = existing.pinned;
                *existing = exchange;
                existing.pinned = existing.pinned || pinned;
            } else {
                exchanges.push(exchange);
                lock(&self.inner.stats).http_exchanges += 1;
                trim(&mut exchanges);
            }
        }
        let _ = self.inner.events.send(id);
    }

    pub fn set_pinned(&self, id: ExchangeId, pinned: bool) {
        if let Some(exchange) = lock(&self.inner.exchanges)
            .iter_mut()
            .find(|item| item.id == id)
        {
            exchange.pinned = pinned;
        }
    }

    pub fn delete(&self, id: ExchangeId) {
        lock(&self.inner.exchanges).retain(|item| item.id != id);
    }

    pub fn clear_unpinned(&self) {
        lock(&self.inner.exchanges).retain(|item| item.pinned);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ExchangeId> {
        self.inner.events.subscribe()
    }

    pub fn park_breakpoint(
        &self,
        id: ExchangeId,
        sender: oneshot::Sender<BreakpointDecision>,
    ) {
        lock(&self.inner.breakpoints).push((id, sender));
    }

    pub fn resume(&self, id: ExchangeId, decision: BreakpointDecision) -> bool {
        let mut parked = lock(&self.inner.breakpoints);
        let Some(index) = parked.iter().position(|(parked_id, _)| *parked_id == id) else {
            return false;
        };
        let (_, sender) = parked.remove(index);
        sender.send(decision).is_ok()
    }

    pub fn read_body_text(&self, handle: &crate::body::BodyHandle) -> Result<String> {
        let bytes = self.inner.bodies.read(handle)?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    pub fn display_body(
        &self,
        headers: &[(String, String)],
        handle: &crate::body::BodyHandle,
    ) -> Result<(String, String)> {
        let raw = self.inner.bodies.read(handle)?;
        let (decoded, warning) = decode_for_display(headers, &raw);
        let text = String::from_utf8_lossy(&decoded).into_owned();
        let notes = format!(
            "{}\n{}",
            compression_notes(headers, raw.len(), Some(decoded.len())),
            caching_notes(headers)
        );
        let warning = warning.unwrap_or_default();
        Ok((text, if warning.is_empty() { notes } else { format!("{warning}\n{notes}") }))
    }
}

fn trim(exchanges: &mut Vec<Exchange>) {
    if exchanges.len() <= MAX_EXCHANGES {
        return;
    }
    let overflow = exchanges.len() - MAX_EXCHANGES;
    let mut removed = 0;
    exchanges.retain(|exchange| {
        if removed >= overflow || exchange.pinned {
            true
        } else {
            removed += 1;
            false
        }
    });
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|err| err.into_inner())
}

fn read_lock<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(|err| err.into_inner())
}

fn write_lock<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write().unwrap_or_else(|err| err.into_inner())
}

fn read_json<T: serde::de::DeserializeOwned>(path: PathBuf) -> Result<T> {
    if !path.exists() {
        return Err(Error::Message(format!("{} is missing", path.display())));
    }
    let text = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

fn write_json<T: serde::Serialize>(path: PathBuf, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let text = serde_json::to_string_pretty(value)?;
    fs::write(path, text)?;
    Ok(())
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body::BodyHandle;
    use crate::exchange::Phase;

    #[test]
    fn pinned_rows_survive_clear_and_rules_persist() {
        let dir = tempfile::tempdir().unwrap();
        let session = Session::open(dir.path()).unwrap();
        let mut exchange = Exchange {
            id: ExchangeId::new(),
            started_unix_ms: now_ms(),
            method: "GET".into(),
            url: "http://127.0.0.1/hello".into(),
            host: "127.0.0.1".into(),
            path: "/hello".into(),
            status: Some(200),
            http_version: "HTTP/1.1".into(),
            request_headers: vec![],
            response_headers: vec![],
            request_body: BodyHandle::Empty,
            response_body: BodyHandle::Inline(b"hi".to_vec()),
            pinned: true,
            error: None,
            phase: Phase::Complete,
            duration_ms: Some(3),
            ttfb_ms: Some(2),
            download_ms: Some(1),
            protocol_note: "http".into(),
            timing_notes: String::new(),
        };
        session.upsert(exchange.clone());
        exchange.id = ExchangeId::new();
        exchange.pinned = false;
        exchange.path = "/other".into();
        session.upsert(exchange);
        session.clear_unpinned();
        let left = session.exchanges();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].path, "/hello");

        let mut rules = session.rules();
        rules.rules.push(crate::rules::Rule::new(
            "sample",
            crate::rules::Action::Passthrough,
        ));
        session.update_rules(rules).unwrap();
        let reopened = Session::open(dir.path()).unwrap();
        assert_eq!(reopened.rules().rules.len(), 1);
        assert_eq!(reopened.ca().fingerprint, session.ca().fingerprint);
    }
}
