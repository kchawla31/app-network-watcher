use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HttpVersion {
    Auto,
    Http1,
    Http2,
}

impl Default for HttpVersion {
    fn default() -> Self {
        Self::Auto
    }
}

impl HttpVersion {
    pub fn label(self) -> &'static str {
        match self {
            Self::Auto => "Auto",
            Self::Http1 => "HTTP/1.1",
            Self::Http2 => "HTTP/2",
        }
    }

    pub fn alpn(self) -> Vec<Vec<u8>> {
        match self {
            Self::Http1 => vec![b"http/1.1".to_vec()],
            Self::Http2 | Self::Auto => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpstreamTls {
    pub accept_invalid_certs: bool,
    pub extra_ca_pem: Option<String>,
    pub client_cert_pem: Option<String>,
    pub client_key_pem: Option<String>,
}

impl Default for UpstreamTls {
    fn default() -> Self {
        Self {
            accept_invalid_certs: false,
            extra_ca_pem: None,
            client_cert_pem: None,
            client_key_pem: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Settings {
    pub port: u16,
    pub http_version: HttpVersion,
    pub passthrough_hosts: Vec<String>,
    pub intercept_only: Vec<String>,
    pub upstream_proxy: Option<String>,
    pub upstream_tls: UpstreamTls,
    pub dark_theme: bool,
    pub advertise_host: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            port: 8080,
            http_version: HttpVersion::Auto,
            passthrough_hosts: Vec::new(),
            intercept_only: Vec::new(),
            upstream_proxy: None,
            upstream_tls: UpstreamTls::default(),
            dark_theme: true,
            advertise_host: "127.0.0.1".into(),
        }
    }
}

impl Settings {
    pub fn host_is_intercepted(&self, host: &str) -> bool {
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if self
            .passthrough_hosts
            .iter()
            .any(|item| host_matches(&host, item))
        {
            return false;
        }
        if self.intercept_only.is_empty() {
            return true;
        }
        self.intercept_only
            .iter()
            .any(|item| host_matches(&host, item))
    }
}

fn host_matches(host: &str, pattern: &str) -> bool {
    let pattern = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
    if pattern.is_empty() {
        return false;
    }
    host == pattern || host.ends_with(&format!(".{pattern}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http2_preference_offers_h2() {
        assert!(HttpVersion::Http2
            .alpn()
            .iter()
            .any(|proto| proto == b"h2"));
        assert!(!HttpVersion::Http1
            .alpn()
            .iter()
            .any(|proto| proto == b"h2"));
    }

    #[test]
    fn whitelist_and_passthrough() {
        let mut settings = Settings::default();
        assert!(settings.host_is_intercepted("api.example.com"));
        settings.passthrough_hosts.push("skip.test".into());
        assert!(!settings.host_is_intercepted("skip.test"));
        assert!(!settings.host_is_intercepted("a.skip.test"));
        settings.intercept_only.push("example.com".into());
        assert!(settings.host_is_intercepted("api.example.com"));
        assert!(!settings.host_is_intercepted("other.test"));
    }
}
