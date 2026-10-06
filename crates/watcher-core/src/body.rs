use crate::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use uuid::Uuid;

/// Bodies at or below this size stay in memory. Larger bodies are files.
pub const BODY_MEMORY_LIMIT: usize = 10 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum BodyHandle {
    Empty,
    Inline(Vec<u8>),
    File { path: PathBuf, len: u64 },
}

impl BodyHandle {
    pub fn len(&self) -> u64 {
        match self {
            Self::Empty => 0,
            Self::Inline(bytes) => bytes.len() as u64,
            Self::File { len, .. } => *len,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

pub struct BodyStore {
    dir: PathBuf,
    limit: usize,
    seq: AtomicU64,
}

impl BodyStore {
    pub fn new(dir: impl Into<PathBuf>) -> Result<Self> {
        Self::with_limit(dir, BODY_MEMORY_LIMIT)
    }

    pub fn with_limit(dir: impl Into<PathBuf>, limit: usize) -> Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        Ok(Self {
            dir,
            limit,
            seq: AtomicU64::new(1),
        })
    }

    pub fn limit(&self) -> usize {
        self.limit
    }

    pub fn put(&self, bytes: &[u8]) -> Result<BodyHandle> {
        if bytes.is_empty() {
            return Ok(BodyHandle::Empty);
        }
        if bytes.len() <= self.limit {
            return Ok(BodyHandle::Inline(bytes.to_vec()));
        }
        let name = format!(
            "{}-{}.body",
            self.seq.fetch_add(1, Ordering::Relaxed),
            Uuid::new_v4()
        );
        let path = self.dir.join(name);
        fs::write(&path, bytes)?;
        Ok(BodyHandle::File {
            path,
            len: bytes.len() as u64,
        })
    }

    pub fn read(&self, handle: &BodyHandle) -> Result<Vec<u8>> {
        match handle {
            BodyHandle::Empty => Ok(Vec::new()),
            BodyHandle::Inline(bytes) => Ok(bytes.clone()),
            BodyHandle::File { path, .. } => Ok(fs::read(path)?),
        }
    }

    pub fn preview(&self, handle: &BodyHandle, max: usize) -> Result<Vec<u8>> {
        let bytes = self.read(handle)?;
        if bytes.len() <= max {
            Ok(bytes)
        } else {
            Ok(bytes[..max].to_vec())
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

pub fn decode_for_display(headers: &[(String, String)], raw: &[u8]) -> (Vec<u8>, Option<String>) {
    let encoding = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-encoding"))
        .map(|(_, value)| value.to_ascii_lowercase());
    let Some(encoding) = encoding else {
        return (raw.to_vec(), None);
    };
    if encoding.contains("identity") || encoding.is_empty() {
        return (raw.to_vec(), None);
    }
    match decode_one(encoding.trim(), raw) {
        Some(decoded) => (decoded, None),
        None => (
            raw.to_vec(),
            Some(format!("could not decode content-encoding {encoding}")),
        ),
    }
}

fn decode_one(encoding: &str, raw: &[u8]) -> Option<Vec<u8>> {
    use std::io::Read;
    if encoding.contains("gzip") || encoding.contains("x-gzip") {
        let mut decoder = flate2::read::GzDecoder::new(raw);
        let mut out = Vec::new();
        decoder.read_to_end(&mut out).ok()?;
        return Some(out);
    }
    if encoding.contains("deflate") {
        let mut decoder = flate2::read::ZlibDecoder::new(raw);
        let mut out = Vec::new();
        decoder.read_to_end(&mut out).ok()?;
        return Some(out);
    }
    None
}

pub fn compression_notes(
    headers: &[(String, String)],
    raw_len: usize,
    decoded_len: Option<usize>,
) -> String {
    let encoding = header(headers, "content-encoding").unwrap_or_else(|| "identity".into());
    let decoded = decoded_len.unwrap_or(raw_len);
    let ratio = if decoded == 0 {
        0.0
    } else {
        raw_len as f64 / decoded as f64
    };
    format!(
        "content-encoding: {encoding}; on the wire: {raw_len} bytes; decoded: {decoded} bytes; ratio: {ratio:.2}"
    )
}

pub fn caching_notes(headers: &[(String, String)]) -> String {
    let mut parts = Vec::new();
    for name in ["cache-control", "etag", "expires", "age", "vary", "pragma"] {
        if let Some(value) = header(headers, name) {
            parts.push(format!("{name}: {value}"));
        }
    }
    if parts.is_empty() {
        "No cache headers on this response.".into()
    } else {
        parts.join("\n")
    }
}

pub fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_bodies_stay_inline_and_large_bodies_are_files() {
        let dir = tempfile::tempdir().unwrap();
        let store = BodyStore::with_limit(dir.path(), 8).unwrap();
        assert_eq!(BODY_MEMORY_LIMIT, 10 * 1024 * 1024);
        let small = store.put(b"hello").unwrap();
        assert!(matches!(small, BodyHandle::Inline(_)));
        assert_eq!(store.read(&small).unwrap(), b"hello");

        let large = store.put(b"0123456789abcdef").unwrap();
        match &large {
            BodyHandle::File { path, len } => {
                assert_eq!(*len, 16);
                assert!(path.exists());
            }
            other => panic!("expected file, got {other:?}"),
        }
        assert_eq!(store.read(&large).unwrap(), b"0123456789abcdef");
    }

    #[test]
    fn gzip_round_trip_notes() {
        use std::io::Write;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(b"{\"ok\":true}").unwrap();
        let raw = encoder.finish().unwrap();
        let headers = vec![("Content-Encoding".into(), "gzip".into())];
        let (decoded, err) = decode_for_display(&headers, &raw);
        assert!(err.is_none());
        assert_eq!(decoded, b"{\"ok\":true}");
        let notes = compression_notes(&headers, raw.len(), Some(decoded.len()));
        assert!(notes.contains("gzip"));
        assert!(caching_notes(&[("Cache-Control".into(), "no-store".into())]).contains("no-store"));
    }
}
