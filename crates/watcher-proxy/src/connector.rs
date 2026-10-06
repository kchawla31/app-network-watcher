use hudsucker::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use hudsucker::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use hudsucker::rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme,
};
use hyper::Uri;
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::rt::TokioIo;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tower_service::Service;
use watcher_core::{HttpVersion, Settings};

#[derive(Clone)]
pub struct WatcherConnector {
    tls: Arc<ClientConfig>,
    upstream_proxy: Option<String>,
}

impl WatcherConnector {
    pub fn new(settings: &Settings) -> Result<Self, String> {
        let tls = build_client_config(settings)?;
        Ok(Self {
            tls: Arc::new(tls),
            upstream_proxy: settings.upstream_proxy.clone(),
        })
    }
}

pub fn build_client_config(settings: &Settings) -> Result<ClientConfig, String> {
    let provider = hudsucker::rustls::crypto::aws_lc_rs::default_provider();
    let versions = settings.http_version.alpn();
    let config = if settings.upstream_tls.accept_invalid_certs {
        let verifier = Arc::new(AcceptInvalid { provider: provider.clone() });
        let mut config = ClientConfig::builder_with_provider(provider.into())
            .with_safe_default_protocol_versions()
            .map_err(|err| err.to_string())?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        config.alpn_protocols = versions;
        config
    } else {
        let mut roots = RootCertStore::empty();
        let loaded = rustls_native_certs::load_native_certs();
        for cert in loaded.certs {
            let _ = roots.add(cert);
        }
        for err in loaded.errors {
            eprintln!("native root: {err}");
        }
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if let Some(pem) = &settings.upstream_tls.extra_ca_pem {
            for der in pem_certs(pem) {
                let _ = roots.add(der);
            }
        }
        let builder = ClientConfig::builder_with_provider(provider.into())
            .with_safe_default_protocol_versions()
            .map_err(|err| err.to_string())?
            .with_root_certificates(roots);
        let mut config = if let (Some(cert), Some(key)) = (
            &settings.upstream_tls.client_cert_pem,
            &settings.upstream_tls.client_key_pem,
        ) {
            let certs = pem_certs(cert);
            let key = pem_key(key)?;
            builder
                .with_client_auth_cert(certs, key)
                .map_err(|err| err.to_string())?
        } else {
            builder.with_no_client_auth()
        };
        config.alpn_protocols = versions;
        config
    };
    let _ = HttpVersion::Auto;
    Ok(config)
}

fn pem_certs(pem: &str) -> Vec<CertificateDer<'static>> {
    let mut out = Vec::new();
    for der in split_pem(pem, "CERTIFICATE") {
        out.push(CertificateDer::from(der));
    }
    out
}

fn pem_key(pem: &str) -> Result<hudsucker::rustls::pki_types::PrivateKeyDer<'static>, String> {
    let pkcs8 = split_pem(pem, "PRIVATE KEY");
    if let Some(der) = pkcs8.into_iter().next() {
        return Ok(hudsucker::rustls::pki_types::PrivateKeyDer::Pkcs8(
            der.into(),
        ));
    }
    Err("client key PEM is missing".into())
}

fn split_pem(pem: &str, label: &str) -> Vec<Vec<u8>> {
    let begin = format!("BEGIN {label}");
    let end = format!("END {label}");
    let mut out = Vec::new();
    let mut collecting = false;
    let mut b64 = String::new();
    for line in pem.lines() {
        if line.contains(&begin) {
            collecting = true;
            b64.clear();
            continue;
        }
        if line.contains(&end) {
            if let Ok(der) = base64_decode(&b64) {
                out.push(der);
            }
            collecting = false;
            continue;
        }
        if collecting {
            b64.push_str(line.trim());
        }
    }
    out
}

fn base64_decode(input: &str) -> Result<Vec<u8>, ()> {
    fn val(byte: u8) -> Result<u8, ()> {
        match byte {
            b'A'..=b'Z' => Ok(byte - b'A'),
            b'a'..=b'z' => Ok(byte - b'a' + 26),
            b'0'..=b'9' => Ok(byte - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(()),
        }
    }
    let bytes = input.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let b0 = bytes[i];
        let b1 = bytes[i + 1];
        let b2 = *bytes.get(i + 2).unwrap_or(&b'=');
        let b3 = *bytes.get(i + 3).unwrap_or(&b'=');
        let n = (u32::from(val(b0)?) << 18)
            | (u32::from(if b1 == b'=' { 0 } else { val(b1)? }) << 12)
            | (u32::from(if b2 == b'=' { 0 } else { val(b2)? }) << 6)
            | u32::from(if b3 == b'=' { 0 } else { val(b3)? });
        out.push((n >> 16) as u8);
        if b2 != b'=' {
            out.push((n >> 8) as u8);
        }
        if b3 != b'=' {
            out.push(n as u8);
        }
        i += 4;
    }
    Ok(out)
}

#[derive(Debug)]
struct AcceptInvalid {
    provider: hudsucker::rustls::crypto::CryptoProvider,
}

impl ServerCertVerifier for AcceptInvalid {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        hudsucker::rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        hudsucker::rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub struct ProxyStream {
    inner: Pin<Box<dyn AsyncReadWrite>>,
}

trait AsyncReadWrite: AsyncRead + AsyncWrite + Send {}
impl<T: AsyncRead + AsyncWrite + Send> AsyncReadWrite for T {}

impl AsyncRead for ProxyStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.inner.as_mut().poll_read(cx, buf)
    }
}

impl AsyncWrite for ProxyStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.inner.as_mut().poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner.as_mut().poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner.as_mut().poll_shutdown(cx)
    }
}

impl Connection for ProxyStream {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

impl Service<Uri> for WatcherConnector {
    type Response = TokioIo<ProxyStream>;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let tls = Arc::clone(&self.tls);
        let upstream = self.upstream_proxy.clone();
        Box::pin(async move { connect_uri(uri, tls, upstream).await })
    }
}

async fn connect_uri(
    uri: Uri,
    tls: Arc<ClientConfig>,
    upstream: Option<String>,
) -> Result<TokioIo<ProxyStream>, Box<dyn std::error::Error + Send + Sync>> {
    let https = uri.scheme_str() == Some("https");
    let host = uri
        .host()
        .ok_or("request has no host")?
        .to_string();
    let port = uri.port_u16().unwrap_or(if https { 443 } else { 80 });
    let tcp = if let Some(proxy) = upstream.as_deref() {
        let proxy_stream = TcpStream::connect(proxy).await?;
        if https {
            connect_tunnel(proxy_stream, &host, port).await?
        } else {
            proxy_stream
        }
    } else {
        TcpStream::connect((host.as_str(), port)).await?
    };
    let stream: Pin<Box<dyn AsyncReadWrite>> = if https {
        let connector = TlsConnector::from(tls);
        let name = ServerName::try_from(host).map_err(|err| err.to_string())?;
        let tls_stream = connector.connect(name, tcp).await?;
        Box::pin(tls_stream)
    } else if upstream.is_some() {
        Box::pin(AbsoluteForm::new(tcp, format!("http://{host}:{port}")))
    } else {
        Box::pin(tcp)
    };
    Ok(TokioIo::new(ProxyStream { inner: stream }))
}

async fn connect_tunnel(
    mut stream: TcpStream,
    host: &str,
    port: u16,
) -> Result<TcpStream, Box<dyn std::error::Error + Send + Sync>> {
    let request = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n");
    tokio::io::AsyncWriteExt::write_all(&mut stream, request.as_bytes()).await?;
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut byte).await?;
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > 64 * 1024 {
            return Err("upstream proxy response is too large".into());
        }
    }
    let text = String::from_utf8_lossy(&buf);
    if !text.contains(" 200 ") && !text.starts_with("HTTP/1.1 200") && !text.starts_with("HTTP/1.0 200") {
        return Err(format!("upstream proxy CONNECT failed: {}", text.trim()).into());
    }
    Ok(stream)
}

struct AbsoluteForm<S> {
    inner: S,
    prefix: String,
    pending: Vec<u8>,
    done: bool,
}

impl<S> AbsoluteForm<S> {
    fn new(inner: S, prefix: String) -> Self {
        Self {
            inner,
            prefix,
            pending: Vec::new(),
            done: false,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for AbsoluteForm<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for AbsoluteForm<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.done {
            return Pin::new(&mut self.inner).poll_write(cx, buf);
        }
        self.pending.extend_from_slice(buf);
        let Some(end) = self.pending.windows(2).position(|w| w == b"\r\n") else {
            return Poll::Ready(Ok(buf.len()));
        };
        let line = String::from_utf8_lossy(&self.pending[..end]).into_owned();
        let rest = self.pending[end..].to_vec();
        let rewritten = rewrite_request_line(&line, &self.prefix);
        let mut out = rewritten.into_bytes();
        out.extend_from_slice(&rest);
        self.done = true;
        self.pending.clear();
        match Pin::new(&mut self.inner).poll_write(cx, &out) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(buf.len())),
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn rewrite_request_line(line: &str, origin: &str) -> String {
    let mut parts = line.split_whitespace();
    let Some(method) = parts.next() else {
        return line.to_string();
    };
    let Some(target) = parts.next() else {
        return line.to_string();
    };
    let version = parts.next().unwrap_or("HTTP/1.1");
    if target.starts_with("http://") || target.starts_with("https://") {
        return line.to_string();
    }
    let path = if target.starts_with('/') {
        target
    } else {
        "/"
    };
    format!("{method} {origin}{path} {version}")
}

#[allow(dead_code)]
fn _std_io_used() {
    let _ = io::empty();
    let _ = io::sink();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_form_rewrites_origin_form() {
        let line = rewrite_request_line("GET /v1/items?x=1 HTTP/1.1", "http://api.test:80");
        assert_eq!(line, "GET http://api.test:80/v1/items?x=1 HTTP/1.1");
    }
}
