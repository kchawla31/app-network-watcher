use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use watcher_core::{Action, Phase, Rule, Session};
use watcher_proxy::{install_crypto, RunningProxy};

#[tokio::test]
async fn captures_http_and_https_method_url_status_and_body() {
    install_crypto();
    let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_port = http_listener.local_addr().unwrap().port();
    tokio::spawn(serve_http(http_listener));

    let (https_port, server_pem) = spawn_https().await;

    let dir = tempfile::tempdir().unwrap();
    let session = Session::open(dir.path()).unwrap();
    let mut settings = session.settings();
    settings.port = 0;
    settings.upstream_tls.accept_invalid_certs = true;
    settings.http_version = watcher_core::HttpVersion::Http2;
    session.update_settings(settings).unwrap();
    let proxy = RunningProxy::start(session.clone()).await.unwrap();
    let port = proxy.port();

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(format!("http://127.0.0.1:{port}")).unwrap())
        .add_root_certificate(
            reqwest::Certificate::from_pem(session.ca().cert_pem.as_bytes()).unwrap(),
        )
        .build()
        .unwrap();

    let http_response = client
        .post(format!("http://127.0.0.1:{http_port}/hello"))
        .body("http-body")
        .send()
        .await
        .unwrap();
    assert_eq!(http_response.status(), 200);
    assert_eq!(http_response.text().await.unwrap(), "http-body");

    let https_response = client
        .post(format!("https://127.0.0.1:{https_port}/secure"))
        .body("https-body")
        .send()
        .await
        .unwrap();
    assert_eq!(https_response.status(), 200);
    assert_eq!(https_response.text().await.unwrap(), "https-body");

    let http_row = wait_for(&session, "/hello").await;
    assert_eq!(http_row.method, "POST");
    assert!(http_row.url.contains("/hello"));
    assert_eq!(http_row.status, Some(200));
    assert_eq!(
        session.bodies().read(&http_row.request_body).unwrap(),
        b"http-body"
    );
    assert_eq!(
        session.bodies().read(&http_row.response_body).unwrap(),
        b"http-body"
    );

    let https_row = wait_for(&session, "/secure").await;
    assert_eq!(https_row.method, "POST");
    assert!(https_row.url.starts_with("https://127.0.0.1"));
    assert_eq!(https_row.status, Some(200));
    assert_eq!(
        session.bodies().read(&https_row.response_body).unwrap(),
        b"https-body"
    );
    assert!(
        https_row.http_version == "HTTP/2" || https_row.http_version == "HTTP/1.1",
        "unexpected version {}",
        https_row.http_version
    );
    let _ = server_pem;

    proxy.shutdown().await;
}

#[tokio::test]
async fn mock_breakpoint_and_passthrough() {
    install_crypto();
    let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_port = http_listener.local_addr().unwrap().port();
    tokio::spawn(serve_http(http_listener));
    let (https_port, server_pem) = spawn_https().await;

    let dir = tempfile::tempdir().unwrap();
    let session = Session::open(dir.path()).unwrap();
    let mut settings = session.settings();
    settings.port = 0;
    settings.upstream_tls.accept_invalid_certs = true;
    session.update_settings(settings).unwrap();

    let mut mock = Rule::new(
        "mock",
        Action::Mock {
            status: 201,
            headers: vec![("content-type".into(), "text/plain".into())],
            body: "mocked".into(),
        },
    );
    mock.path_prefix = Some("/mocked".into());
    let mut pause = Rule::new(
        "pause",
        Action::Breakpoint {
            request: true,
            response: false,
        },
    );
    pause.path_prefix = Some("/pause".into());
    let mut rules = session.rules();
    rules.rules.push(mock);
    rules.rules.push(pause);
    session.update_rules(rules).unwrap();

    let proxy = RunningProxy::start(session.clone()).await.unwrap();
    let port = proxy.port();
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(format!("http://127.0.0.1:{port}")).unwrap())
        .add_root_certificate(
            reqwest::Certificate::from_pem(session.ca().cert_pem.as_bytes()).unwrap(),
        )
        .build()
        .unwrap();

    let mocked = client
        .get(format!("http://127.0.0.1:{http_port}/mocked"))
        .send()
        .await
        .unwrap();
    assert_eq!(mocked.status(), 201);
    assert_eq!(mocked.text().await.unwrap(), "mocked");

    let session_for_pause = session.clone();
    let paused = tokio::spawn(async move {
        client
            .post(format!("http://127.0.0.1:{http_port}/pause"))
            .body("original")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap()
    });
    let paused_row = wait_phase(&session_for_pause, "/pause", Phase::PausedRequest).await;
    assert!(session_for_pause.resume(
        paused_row.id,
        watcher_core::BreakpointDecision::Forward {
            headers: vec![("content-type".into(), "text/plain".into())],
            body: b"edited".to_vec(),
        }
    ));
    assert_eq!(paused.await.unwrap(), "edited");

    proxy.shutdown().await;

    let dir = tempfile::tempdir().unwrap();
    let session = Session::open(dir.path()).unwrap();
    let mut settings = session.settings();
    settings.port = 0;
    settings.passthrough_hosts = vec!["127.0.0.1".into()];
    settings.upstream_tls.accept_invalid_certs = true;
    session.update_settings(settings).unwrap();
    let proxy = RunningProxy::start(session.clone()).await.unwrap();
    let client = reqwest::Client::builder()
        .proxy(
            reqwest::Proxy::all(format!("http://127.0.0.1:{}", proxy.port())).unwrap(),
        )
        .add_root_certificate(reqwest::Certificate::from_pem(server_pem.as_bytes()).unwrap())
        .build()
        .unwrap();
    let response = client
        .post(format!("https://127.0.0.1:{https_port}/tunneled"))
        .body("plain")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "plain");
    proxy.shutdown().await;
}

async fn wait_for(session: &Session, path: &str) -> watcher_core::Exchange {
    wait_phase(session, path, Phase::Complete).await
}

async fn wait_phase(session: &Session, path: &str, phase: Phase) -> watcher_core::Exchange {
    for _ in 0..80 {
        if let Some(exchange) = session
            .exchanges()
            .into_iter()
            .find(|exchange| exchange.path.starts_with(path) && exchange.phase == phase)
        {
            return exchange;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no {path} in {phase:?}: {:?}", session.exchanges());
}

async fn serve_http(listener: TcpListener) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            break;
        };
        tokio::spawn(async move {
            let service = service_fn(echo);
            let _ = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

async fn echo(req: Request<hyper::body::Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let body = req.into_body().collect().await?.to_bytes();
    Ok(Response::new(Full::new(body)))
}

async fn spawn_https() -> (u16, String) {
    let key = KeyPair::generate().unwrap();
    let params = CertificateParams::new(vec!["127.0.0.1".to_string()]).unwrap();
    let cert = params.self_signed(&key).unwrap();
    let pem = cert.pem();
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(stream) = acceptor.accept(stream).await else {
                    return;
                };
                let service = service_fn(echo);
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (port, pem)
}

#[allow(dead_code)]
async fn _unused_io() {
    let mut buf = [0u8; 1];
    let _ = tokio::io::empty().read(&mut buf).await;
    let _ = tokio::io::sink().write_all(b"").await;
}
