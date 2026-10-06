//! Send one edited request through the local proxy so it shows up in the log.
//! Nothing is sent anywhere except to the proxy on this machine.

use hudsucker::rustls::client::ClientConfig;
use hudsucker::rustls::pki_types::{CertificateDer, ServerName};
use hudsucker::rustls::RootCertStore;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::install_crypto;

pub async fn send_edited(
    proxy_port: u16,
    ca_der: &[u8],
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<(), String> {
    let target: http::Uri = url
        .parse()
        .map_err(|err| format!("URL is not usable: {err}"))?;
    let scheme = target.scheme_str().unwrap_or("http");
    let host = target
        .host()
        .ok_or_else(|| "URL is missing a host".to_string())?
        .to_string();
    let port = target
        .port_u16()
        .unwrap_or(if scheme == "https" { 443 } else { 80 });
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .map_err(|err| format!("could not reach the local proxy: {err}"))?;
    stream
        .set_nodelay(true)
        .map_err(|err| err.to_string())?;
    if scheme == "https" {
        write_connect(&mut stream, &host, port).await?;
        let tls = tls_stream(stream, ca_der, &host).await?;
        let (mut reader, mut writer) = tokio::io::split(tls);
        let request = origin_request(method, &target, &host, port, headers, body);
        writer
            .write_all(&request)
            .await
            .map_err(|err| err.to_string())?;
        // Leave the write side open. A write shutdown is a half-close, and the
        // proxy's HTTP/1 server drops the call before it is logged.
        let response = read_response(&mut reader).await?;
        if response.is_empty() {
            return Err("proxy closed without a response".into());
        }
        return Ok(());
    }
    let request = absolute_request(method, url, &host, port, headers, body);
    stream
        .write_all(&request)
        .await
        .map_err(|err| err.to_string())?;
    let response = read_response(&mut stream).await?;
    if response.is_empty() {
        return Err("proxy closed without a response".into());
    }
    Ok(())
}

async fn write_connect(stream: &mut TcpStream, host: &str, port: u16) -> Result<(), String> {
    let connect = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n");
    stream
        .write_all(connect.as_bytes())
        .await
        .map_err(|err| err.to_string())?;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        let n = stream
            .read(&mut tmp)
            .await
            .map_err(|err| err.to_string())?;
        if n == 0 {
            return Err("proxy closed the CONNECT tunnel".into());
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 16 * 1024 {
            return Err("CONNECT response was too large".into());
        }
    }
    let text = String::from_utf8_lossy(&buf);
    let status = text.lines().next().unwrap_or("");
    if !status.contains(" 200 ") && !status.ends_with(" 200") {
        return Err(format!("proxy refused the tunnel: {status}"));
    }
    Ok(())
}

async fn tls_stream(
    stream: TcpStream,
    ca_der: &[u8],
    host: &str,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    install_crypto();
    let provider = hudsucker::rustls::crypto::aws_lc_rs::default_provider();
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca_der.to_vec()))
        .map_err(|err| format!("CA was rejected: {err}"))?;
    let mut config = ClientConfig::builder_with_provider(provider.into())
        .with_safe_default_protocol_versions()
        .map_err(|err| err.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let name = ServerName::try_from(host.to_string()).map_err(|err| err.to_string())?;
    TlsConnector::from(std::sync::Arc::new(config))
        .connect(name, stream)
        .await
        .map_err(|err| format!("TLS to the intercepted host failed: {err}"))
}

fn absolute_request(
    method: &str,
    url: &str,
    host: &str,
    port: u16,
    headers: &[(String, String)],
    body: &[u8],
) -> Vec<u8> {
    let host_header = if port == 80 {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };
    assemble(method, url, &host_header, headers, body)
}

fn origin_request(
    method: &str,
    target: &http::Uri,
    host: &str,
    port: u16,
    headers: &[(String, String)],
    body: &[u8],
) -> Vec<u8> {
    let path = target
        .path_and_query()
        .map(|item| item.as_str())
        .filter(|item| !item.is_empty())
        .unwrap_or("/");
    let host_header = if (port == 443 && target.scheme_str() == Some("https")) || port == 80 {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };
    assemble(method, path, &host_header, headers, body)
}

fn assemble(
    method: &str,
    target: &str,
    host_header: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Vec<u8> {
    let mut head = format!("{method} {target} HTTP/1.1\r\nHost: {host_header}\r\n");
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("host") || name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str(&format!("Content-Length: {}\r\nConnection: close\r\n\r\n", body.len()));
    let mut bytes = head.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

async fn read_response(reader: &mut (impl AsyncReadExt + Unpin)) -> Result<Vec<u8>, String> {
    let mut collected = Vec::new();
    let mut buf = [0u8; 8192];
    let read = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => return Ok(()),
                Err(err) => return Err(err.to_string()),
                Ok(n) => {
                    collected.extend_from_slice(&buf[..n]);
                    if response_complete(&collected) {
                        return Ok(());
                    }
                    if collected.len() > 2 * 1024 * 1024 {
                        return Ok(());
                    }
                }
            }
        }
    })
    .await;
    match read {
        Ok(Ok(())) => Ok(collected),
        Ok(Err(err)) => Err(err),
        Err(_) if response_complete(&collected) => Ok(collected),
        Err(_) => Err("timed out waiting for the proxy response".into()),
    }
}

fn response_complete(buf: &[u8]) -> bool {
    let Some(header_end) = buf.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let header_text = String::from_utf8_lossy(&buf[..header_end]);
    let body = &buf[header_end + 4..];
    let mut content_length = None;
    let mut chunked = false;
    for line in header_text.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.trim().parse::<usize>().ok();
        }
        if name.eq_ignore_ascii_case("transfer-encoding")
            && value.to_ascii_lowercase().contains("chunked")
        {
            chunked = true;
        }
    }
    if chunked {
        return body.windows(5).any(|window| window == b"0\r\n\r\n");
    }
    match content_length {
        Some(len) => body.len() >= len,
        None => false,
    }
}
