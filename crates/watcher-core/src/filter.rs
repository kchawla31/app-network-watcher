use crate::exchange::Exchange;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FilterAlias {
    pub name: String,
    pub query: String,
}

pub fn matches_filter(
    query: &str,
    aliases: &[FilterAlias],
    exchange: &Exchange,
    body_preview: &str,
) -> bool {
    let query = query.trim();
    if query.is_empty() {
        return true;
    }
    let query = if let Some(name) = query.strip_prefix("alias:") {
        match aliases.iter().find(|alias| alias.name == name) {
            Some(alias) => alias.query.as_str(),
            None => return false,
        }
    } else {
        query
    };
    let mut free = Vec::new();
    for token in query.split_whitespace() {
        if let Some((key, value)) = token.split_once(':') {
            let value = value.to_ascii_lowercase();
            let ok = match key.to_ascii_lowercase().as_str() {
                "status" => exchange
                    .status
                    .map(|code| code.to_string() == value)
                    .unwrap_or(false),
                "method" => exchange.method.to_ascii_lowercase() == value,
                "host" => exchange.host.to_ascii_lowercase().contains(&value),
                "path" => exchange.path.to_ascii_lowercase().contains(&value),
                _ => {
                    free.push(token.to_ascii_lowercase());
                    continue;
                }
            };
            if !ok {
                return false;
            }
        } else {
            free.push(token.to_ascii_lowercase());
        }
    }
    if free.is_empty() {
        return true;
    }
    let haystack = format!(
        "{} {} {} {} {}\n{}\n{}",
        exchange.method,
        exchange.status.unwrap_or(0),
        exchange.host,
        exchange.path,
        exchange.url,
        exchange
            .request_headers
            .iter()
            .chain(exchange.response_headers.iter())
            .map(|(name, value)| format!("{name}: {value}"))
            .collect::<Vec<_>>()
            .join("\n"),
        body_preview
    )
    .to_ascii_lowercase();
    free.iter().all(|word| haystack.contains(word))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body::BodyHandle;
    use crate::exchange::{ExchangeId, Phase};

    fn sample() -> Exchange {
        Exchange {
            id: ExchangeId::new(),
            started_unix_ms: 0,
            method: "GET".into(),
            url: "https://api.example.com/items".into(),
            host: "api.example.com".into(),
            path: "/items".into(),
            status: Some(404),
            http_version: "HTTP/1.1".into(),
            request_headers: vec![],
            response_headers: vec![("Content-Type".into(), "application/json".into())],
            request_body: BodyHandle::Empty,
            response_body: BodyHandle::Empty,
            pinned: false,
            error: None,
            phase: Phase::Complete,
            duration_ms: Some(12),
            ttfb_ms: Some(10),
            download_ms: Some(2),
            protocol_note: "https".into(),
            timing_notes: String::new(),
        }
    }

    #[test]
    fn structured_filter_and_alias() {
        let exchange = sample();
        assert!(matches_filter("status:404 method:GET", &[], &exchange, ""));
        assert!(!matches_filter("status:200", &[], &exchange, ""));
        assert!(matches_filter("missing-item", &[], &exchange, "{\"missing-item\":true}"));
        let aliases = vec![FilterAlias {
            name: "errors".into(),
            query: "status:404".into(),
        }];
        assert!(matches_filter("alias:errors", &aliases, &exchange, ""));
    }
}
