use crate::exchange::Exchange;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub enabled: bool,
    pub name: String,
    pub method: Option<String>,
    pub host_contains: Option<String>,
    pub path_prefix: Option<String>,
    pub action: Action,
}

impl Rule {
    pub fn new(name: impl Into<String>, action: Action) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            enabled: true,
            name: name.into(),
            method: None,
            host_contains: None,
            path_prefix: None,
            action,
        }
    }

    pub fn matches(&self, snap: &RequestSnap) -> bool {
        if !self.enabled {
            return false;
        }
        if let Some(method) = &self.method {
            if !snap.method.eq_ignore_ascii_case(method) {
                return false;
            }
        }
        if let Some(host) = &self.host_contains {
            if !snap.host.to_ascii_lowercase().contains(&host.to_ascii_lowercase()) {
                return false;
            }
        }
        if let Some(prefix) = &self.path_prefix {
            if !snap.path.starts_with(prefix) {
                return false;
            }
        }
        true
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Action {
    Passthrough,
    Breakpoint { request: bool, response: bool },
    Mock {
        status: u16,
        headers: Vec<(String, String)>,
        body: String,
    },
    Transform {
        request_headers: Vec<(String, String)>,
        response_headers: Vec<(String, String)>,
        request_body: Option<String>,
        response_body: Option<String>,
    },
    Error { status: u16, body: String },
    Timeout { delay_ms: u64, status: u16 },
    Redirect { location: String, status: u16 },
}

#[derive(Clone, Debug, Default)]
pub struct RequestSnap {
    pub method: String,
    pub url: String,
    pub host: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub http_version: String,
}

#[derive(Clone, Debug, Default)]
pub struct ResponseSnap {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub http_version: String,
}

#[derive(Clone, Debug)]
pub enum BreakpointDecision {
    Forward {
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    },
    Respond {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    },
    Fail { message: String },
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
}

impl RuleSet {
    pub fn first_match(&self, snap: &RequestSnap) -> Option<&Rule> {
        self.rules.iter().find(|rule| rule.matches(snap))
    }

    pub fn move_rule(&mut self, id: &str, up: bool) {
        let Some(index) = self.rules.iter().position(|rule| rule.id == id) else {
            return;
        };
        if up && index > 0 {
            self.rules.swap(index, index - 1);
        } else if !up && index + 1 < self.rules.len() {
            self.rules.swap(index, index + 1);
        }
    }
}

pub fn apply_header_edits(headers: &mut Vec<(String, String)>, edits: &[(String, String)]) {
    for (name, value) in edits {
        headers.retain(|(existing, _)| !existing.eq_ignore_ascii_case(name));
        if !value.is_empty() {
            headers.push((name.clone(), value.clone()));
        }
    }
}

pub fn rule_from_exchange(exchange: &Exchange, response_body: &str) -> Rule {
    let mut rule = Rule::new(
        format!("{} {}", exchange.method, exchange.path),
        Action::Mock {
            status: exchange.status.unwrap_or(200),
            headers: exchange
                .response_headers
                .iter()
                .filter(|(name, _)| !name.eq_ignore_ascii_case("content-length"))
                .cloned()
                .collect(),
            body: response_body.to_string(),
        },
    );
    rule.method = Some(exchange.method.clone());
    rule.host_contains = Some(exchange.host.clone());
    let path = exchange.path.split('?').next().unwrap_or(&exchange.path);
    rule.path_prefix = Some(path.to_string());
    rule
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_matching_rule_wins() {
        let snap = RequestSnap {
            method: "POST".into(),
            host: "api.example.com".into(),
            path: "/v1/items".into(),
            ..RequestSnap::default()
        };
        let mut set = RuleSet::default();
        set.rules.push(Rule::new("skip", Action::Passthrough));
        set.rules[0].method = Some("GET".into());
        set.rules.push(Rule::new(
            "mock",
            Action::Mock {
                status: 201,
                headers: vec![],
                body: "ok".into(),
            },
        ));
        set.rules[1].path_prefix = Some("/v1".into());
        assert_eq!(set.first_match(&snap).unwrap().name, "mock");
    }

    #[test]
    fn empty_header_value_removes_the_header() {
        let mut headers = vec![("X-Test".into(), "1".into())];
        apply_header_edits(&mut headers, &[("X-Test".into(), String::new())]);
        assert!(headers.is_empty());
    }
}
