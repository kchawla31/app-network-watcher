use crate::body::BodyStore;
use crate::exchange::{Exchange, ExchangeId, Phase};
use crate::{Error, Result};
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn export_har(exchanges: &[Exchange], bodies: &BodyStore) -> Result<Value> {
    let mut entries = Vec::new();
    for exchange in exchanges {
        let request_body = String::from_utf8_lossy(&bodies.read(&exchange.request_body)?).into_owned();
        let response_body = String::from_utf8_lossy(&bodies.read(&exchange.response_body)?).into_owned();
        entries.push(json!({
            "startedDateTime": millis_to_iso(exchange.started_unix_ms),
            "time": exchange.duration_ms.unwrap_or(0),
            "request": {
                "method": exchange.method,
                "url": exchange.url,
                "httpVersion": exchange.http_version,
                "headers": header_json(&exchange.request_headers),
                "queryString": [],
                "headersSize": -1,
                "bodySize": exchange.request_body.len(),
                "postData": {
                    "mimeType": header_value(&exchange.request_headers, "content-type").unwrap_or("application/octet-stream"),
                    "text": request_body
                }
            },
            "response": {
                "status": exchange.status.unwrap_or(0),
                "statusText": "",
                "httpVersion": exchange.http_version,
                "headers": header_json(&exchange.response_headers),
                "content": {
                    "size": exchange.response_body.len(),
                    "mimeType": header_value(&exchange.response_headers, "content-type").unwrap_or(""),
                    "text": response_body
                },
                "redirectURL": "",
                "headersSize": -1,
                "bodySize": exchange.response_body.len()
            },
            "cache": {},
            "timings": {
                "send": 0,
                "wait": exchange.ttfb_ms.unwrap_or(0),
                "receive": exchange.download_ms.unwrap_or(0)
            }
        }));
    }
    Ok(json!({
        "log": {
            "version": "1.2",
            "creator": {"name": "App Network Watcher", "version": "0.1.0"},
            "entries": entries
        }
    }))
}

pub fn import_har(value: &Value, bodies: &BodyStore) -> Result<Vec<Exchange>> {
    let entries = value
        .pointer("/log/entries")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::Message("HAR file has no log.entries array.".into()))?;
    let mut exchanges = Vec::new();
    for entry in entries {
        let method = entry
            .pointer("/request/method")
            .and_then(Value::as_str)
            .unwrap_or("GET")
            .to_string();
        let url = entry
            .pointer("/request/url")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let (host, path) = split_url(&url);
        let status = entry.pointer("/response/status").and_then(Value::as_u64).map(|code| code as u16);
        let request_text = entry
            .pointer("/request/postData/text")
            .and_then(Value::as_str)
            .unwrap_or("");
        let response_text = entry
            .pointer("/response/content/text")
            .and_then(Value::as_str)
            .unwrap_or("");
        exchanges.push(Exchange {
            id: ExchangeId::new(),
            started_unix_ms: now_ms(),
            method,
            url,
            host,
            path,
            status,
            http_version: entry
                .pointer("/request/httpVersion")
                .and_then(Value::as_str)
                .unwrap_or("HTTP/1.1")
                .to_string(),
            request_headers: read_headers(entry.pointer("/request/headers")),
            response_headers: read_headers(entry.pointer("/response/headers")),
            request_body: bodies.put(request_text.as_bytes())?,
            response_body: bodies.put(response_text.as_bytes())?,
            pinned: false,
            error: None,
            phase: Phase::Complete,
            duration_ms: entry.get("time").and_then(Value::as_u64),
            ttfb_ms: entry.pointer("/timings/wait").and_then(Value::as_u64),
            download_ms: entry.pointer("/timings/receive").and_then(Value::as_u64),
            protocol_note: "har".into(),
            timing_notes: "Imported from HAR.".into(),
        });
    }
    Ok(exchanges)
}

fn header_json(headers: &[(String, String)]) -> Value {
    Value::Array(
        headers
            .iter()
            .map(|(name, value)| json!({"name": name, "value": value}))
            .collect(),
    )
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn read_headers(value: Option<&Value>) -> Vec<(String, String)> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    Some((
                        item.get("name")?.as_str()?.to_string(),
                        item.get("value")?.as_str()?.to_string(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn split_url(url: &str) -> (String, String) {
    let rest = url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(url);
    let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
    let path = if path.is_empty() {
        "/".into()
    } else {
        format!("/{path}")
    };
    (host.to_string(), path)
}

fn millis_to_iso(millis: u64) -> String {
    let format = time::format_description::well_known::Rfc3339;
    let offset = time::UtcOffset::UTC;
    match time::OffsetDateTime::from_unix_timestamp((millis / 1000) as i64) {
        Ok(dt) => dt.to_offset(offset).format(&format).unwrap_or_else(|_| "1970-01-01T00:00:00Z".into()),
        Err(_) => "1970-01-01T00:00:00Z".into(),
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exchange::Phase;

    #[test]
    fn har_round_trip_keeps_method_url_status_and_body() {
        let dir = tempfile::tempdir().unwrap();
        let bodies = BodyStore::new(dir.path()).unwrap();
        let exchange = Exchange {
            id: ExchangeId::new(),
            started_unix_ms: 1_700_000_000_000,
            method: "POST".into(),
            url: "https://api.example.com/items?x=1".into(),
            host: "api.example.com".into(),
            path: "/items?x=1".into(),
            status: Some(201),
            http_version: "HTTP/1.1".into(),
            request_headers: vec![("Content-Type".into(), "application/json".into())],
            response_headers: vec![("Content-Type".into(), "application/json".into())],
            request_body: bodies.put(br#"{"name":"a"}"#).unwrap(),
            response_body: bodies.put(br#"{"id":1}"#).unwrap(),
            pinned: false,
            error: None,
            phase: Phase::Complete,
            duration_ms: Some(20),
            ttfb_ms: Some(15),
            download_ms: Some(5),
            protocol_note: "https".into(),
            timing_notes: String::new(),
        };
        let har = export_har(&[exchange], &bodies).unwrap();
        let imported = import_har(&har, &bodies).unwrap();
        assert_eq!(imported[0].method, "POST");
        assert_eq!(imported[0].url, "https://api.example.com/items?x=1");
        assert_eq!(imported[0].status, Some(201));
        assert_eq!(bodies.read(&imported[0].response_body).unwrap(), br#"{"id":1}"#);
    }
}
