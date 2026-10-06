use std::collections::BTreeSet;

use serde_json::Value;
use watcher_core::{matches_filter, Exchange, ExchangeId, FilterAlias, Session};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    Success,
    Redirect,
    Client,
    Server,
    Muted,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrafficRow {
    pub id: ExchangeId,
    pub time: String,
    pub method: String,
    pub status: String,
    pub host: String,
    pub path: String,
    pub duration: String,
    pub size: String,
    pub tone: Tone,
    pub pinned: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JsonLine {
    pub path: String,
    pub depth: usize,
    pub expandable: bool,
    pub text: String,
}

pub fn traffic_rows(
    exchanges: &[Exchange],
    query: &str,
    aliases: &[FilterAlias],
) -> Vec<TrafficRow> {
    exchanges
        .iter()
        .filter(|exchange| matches_filter(query, aliases, exchange, ""))
        .map(row_from)
        .collect()
}

pub fn move_id(rows: &[TrafficRow], current: Option<ExchangeId>, delta: i32) -> Option<ExchangeId> {
    if rows.is_empty() {
        return None;
    }
    let current_index = current.and_then(|id| rows.iter().position(|row| row.id == id));
    let next = match current_index {
        Some(index) => index as i32 + delta,
        None => {
            if delta < 0 {
                rows.len() as i32 - 1
            } else {
                0
            }
        }
    };
    let next = next.clamp(0, rows.len() as i32 - 1) as usize;
    Some(rows[next].id)
}

pub fn header_block(headers: &[(String, String)]) -> String {
    headers
        .iter()
        .map(|(name, value)| format!("{name}: {value}"))
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn parse_header_block(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                return None;
            }
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_string(), value.trim().to_string()))
        })
        .collect()
}

pub fn request_text(session: &Session, exchange: &Exchange) -> String {
    session
        .display_body(&exchange.request_headers, &exchange.request_body)
        .map(|(text, _)| text)
        .unwrap_or_else(|err| format!("body could not be read: {err}"))
}

pub fn response_text(session: &Session, exchange: &Exchange) -> (String, String) {
    match session.display_body(&exchange.response_headers, &exchange.response_body) {
        Ok((text, notes)) => (text, notes),
        Err(err) => (format!("body could not be read: {err}"), String::new()),
    }
}

pub fn json_lines(text: &str, collapsed: &BTreeSet<String>) -> Option<Vec<JsonLine>> {
    let value: Value = serde_json::from_str(text.trim()).ok()?;
    if !value.is_object() && !value.is_array() {
        return None;
    }
    let mut lines = Vec::new();
    walk(&value, "$", "$", 0, collapsed, &mut lines);
    Some(lines)
}

pub fn qr_blocks(payload: &str) -> String {
    let Ok(code) = qrcode::QrCode::new(payload.as_bytes()) else {
        return "QR could not be built.".into();
    };
    let width = code.width();
    let mut out = String::new();
    for y in 0..width {
        for x in 0..width {
            let dark = matches!(code[(x, y)], qrcode::Color::Dark);
            out.push_str(if dark { "██" } else { "  " });
        }
        out.push('\n');
    }
    out
}

fn row_from(exchange: &Exchange) -> TrafficRow {
    TrafficRow {
        id: exchange.id,
        time: clock(exchange.started_unix_ms),
        method: exchange.method.clone(),
        status: exchange
            .status
            .map(|code| code.to_string())
            .unwrap_or_else(|| "-".into()),
        host: exchange.host.clone(),
        path: exchange.path.clone(),
        duration: exchange
            .duration_ms
            .map(|ms| format!("{ms} ms"))
            .unwrap_or_else(|| "-".into()),
        size: size_label(exchange.size_bytes()),
        tone: tone_of(exchange.status),
        pinned: exchange.pinned,
    }
}

fn tone_of(status: Option<u16>) -> Tone {
    match status {
        Some(code) if (200..300).contains(&code) => Tone::Success,
        Some(code) if (300..400).contains(&code) => Tone::Redirect,
        Some(code) if (400..500).contains(&code) => Tone::Client,
        Some(code) if (500..600).contains(&code) => Tone::Server,
        _ => Tone::Muted,
    }
}

fn clock(unix_ms: u64) -> String {
    let seconds = unix_ms / 1000;
    let millis = unix_ms % 1000;
    let hour = (seconds / 3600) % 24;
    let minute = (seconds / 60) % 60;
    let second = seconds % 60;
    format!("{hour:02}:{minute:02}:{second:02}.{millis:03}")
}

fn size_label(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

fn walk(
    value: &Value,
    path: &str,
    label: &str,
    depth: usize,
    collapsed: &BTreeSet<String>,
    out: &mut Vec<JsonLine>,
) {
    match value {
        Value::Object(map) => {
            let folded = collapsed.contains(path);
            out.push(JsonLine {
                path: path.to_string(),
                depth,
                expandable: true,
                text: if folded {
                    format!("{label} {{…}} {} keys", map.len())
                } else {
                    format!("{label} {{")
                },
            });
            if !folded {
                for (key, child) in map {
                    let child_path = format!("{path}.{key}");
                    if child.is_object() || child.is_array() {
                        walk(child, &child_path, key, depth + 1, collapsed, out);
                    } else {
                        out.push(JsonLine {
                            path: child_path,
                            depth: depth + 1,
                            expandable: false,
                            text: format!("{key}: {child}"),
                        });
                    }
                }
                out.push(JsonLine {
                    path: format!("{path}."),
                    depth,
                    expandable: false,
                    text: "}".into(),
                });
            }
        }
        Value::Array(items) => {
            let folded = collapsed.contains(path);
            out.push(JsonLine {
                path: path.to_string(),
                depth,
                expandable: true,
                text: if folded {
                    format!("{label} […] {} items", items.len())
                } else {
                    format!("{label} [")
                },
            });
            if !folded {
                for (index, child) in items.iter().enumerate() {
                    let child_path = format!("{path}[{index}]");
                    if child.is_object() || child.is_array() {
                        walk(
                            child,
                            &child_path,
                            &index.to_string(),
                            depth + 1,
                            collapsed,
                            out,
                        );
                    } else {
                        out.push(JsonLine {
                            path: child_path,
                            depth: depth + 1,
                            expandable: false,
                            text: child.to_string(),
                        });
                    }
                }
                out.push(JsonLine {
                    path: format!("{path}."),
                    depth,
                    expandable: false,
                    text: "]".into(),
                });
            }
        }
        other => out.push(JsonLine {
            path: path.to_string(),
            depth,
            expandable: false,
            text: format!("{label}: {other}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use watcher_core::{BodyHandle, Exchange, ExchangeId, Phase};

    fn sample(path: &str, status: u16) -> Exchange {
        Exchange {
            id: ExchangeId::new(),
            started_unix_ms: 1_700_000_000_000,
            method: "POST".into(),
            url: format!("http://api.test{path}"),
            host: "api.test".into(),
            path: path.into(),
            status: Some(status),
            http_version: "HTTP/1.1".into(),
            request_headers: vec![("Content-Type".into(), "application/json".into())],
            response_headers: vec![],
            request_body: BodyHandle::Inline(b"{\"a\":1}".to_vec()),
            response_body: BodyHandle::Inline(br#"{"ok":true,"nested":{"n":1}}"#.to_vec()),
            pinned: false,
            error: None,
            phase: Phase::Complete,
            duration_ms: Some(12),
            ttfb_ms: Some(9),
            download_ms: Some(3),
            protocol_note: "http".into(),
            timing_notes: "notes".into(),
        }
    }

    #[test]
    fn filter_hides_rows_and_arrows_move_the_selection() {
        let exchanges = vec![sample("/a", 200), sample("/b", 404)];
        let rows = traffic_rows(&exchanges, "status:404", &[]);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].path, "/b");
        assert_eq!(rows[0].tone, Tone::Client);
        let all = traffic_rows(&exchanges, "", &[]);
        let first = move_id(&all, None, 1);
        let second = move_id(&all, first, 1);
        assert_eq!(second, Some(all[1].id));
        assert_eq!(move_id(&all, second, -1), first);
    }

    #[test]
    fn json_collapse_hides_children() {
        let text = r#"{"ok":true,"nested":{"n":1}}"#;
        let open = json_lines(text, &BTreeSet::new()).unwrap();
        assert!(open.iter().any(|line| line.text.contains("n: 1")));
        let mut collapsed = BTreeSet::new();
        collapsed.insert("$.nested".into());
        let folded = json_lines(text, &collapsed).unwrap();
        assert!(folded.iter().any(|line| line.text.contains("{…}")));
        assert!(!folded.iter().any(|line| line.text.contains("n: 1")));
    }

    #[test]
    fn qr_payload_renders_a_grid() {
        let grid = qr_blocks("watcher://connect?host=127.0.0.1&port=8080&fp=ab");
        assert!(grid.lines().count() > 10);
        assert!(grid.contains('█'));
    }
}
