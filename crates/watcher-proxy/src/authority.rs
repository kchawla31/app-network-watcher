use hudsucker::certificate_authority::CertificateAuthority;
use hudsucker::rcgen::{CertificateParams, Issuer, KeyPair};
use hudsucker::rustls::crypto::aws_lc_rs::default_provider;
use hudsucker::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use hudsucker::rustls::server::ServerConfig;
use http::uri::Authority;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use watcher_core::HttpVersion;

pub struct WatcherAuthority {
    issuer: Issuer<'static, KeyPair>,
    cache: Mutex<HashMap<String, Arc<ServerConfig>>>,
    alpn: Vec<Vec<u8>>,
}

impl WatcherAuthority {
    pub fn new(cert_pem: &str, key_pem: &str, version: HttpVersion) -> Result<Self, String> {
        let cert_pem: &'static str = Box::leak(cert_pem.to_string().into_boxed_str());
        let key_pair = KeyPair::from_pem(key_pem).map_err(|err| err.to_string())?;
        let issuer = Issuer::from_ca_cert_pem(cert_pem, key_pair).map_err(|err| err.to_string())?;
        Ok(Self {
            issuer,
            cache: Mutex::new(HashMap::new()),
            alpn: version.alpn(),
        })
    }
}

impl CertificateAuthority for WatcherAuthority {
    async fn gen_server_config(&self, authority: &Authority) -> Arc<ServerConfig> {
        let host = authority.host().to_string();
        if let Some(config) = self
            .cache
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .get(&host)
            .cloned()
        {
            return config;
        }
        let config = Arc::new(mint(&self.issuer, &host, &self.alpn));
        self.cache
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .insert(host, Arc::clone(&config));
        config
    }
}

fn mint(issuer: &Issuer<'static, KeyPair>, host: &str, alpn: &[Vec<u8>]) -> ServerConfig {
    let leaf = KeyPair::generate().expect("leaf key");
    let params = CertificateParams::new(vec![host.to_string()]).unwrap_or_else(|_| {
        CertificateParams::new(vec!["localhost".to_string()]).expect("localhost params")
    });
    let cert = params
        .signed_by(&leaf, issuer)
        .expect("sign intercepted certificate");
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf.serialize_der()));
    let provider = default_provider();
    let mut config = ServerConfig::builder_with_provider(provider.into())
        .with_safe_default_protocol_versions()
        .expect("tls versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("server config");
    config.alpn_protocols = alpn.to_vec();
    config
}
