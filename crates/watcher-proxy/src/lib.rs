//! MITM proxy used by the desktop app. Capture stays on this machine.

mod authority;
mod client;
mod connector;
mod handler;

pub use client::send_edited;

use crate::authority::WatcherAuthority;
use crate::connector::WatcherConnector;
use crate::handler::{CaptureHandler, WsCapture};
use hudsucker::{rustls, Proxy};
use std::net::SocketAddr;
use std::sync::Once;
use tokio::net::TcpListener;
use tokio::sync::watch;
use watcher_core::Session;

static CRYPTO: Once = Once::new();

pub fn install_crypto() {
    CRYPTO.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("{0}")]
    Message(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub struct RunningProxy {
    port: u16,
    shutdown: watch::Sender<bool>,
    join: tokio::task::JoinHandle<()>,
    session: Session,
}

impl RunningProxy {
    pub async fn start(session: Session) -> Result<Self, ProxyError> {
        install_crypto();
        let settings = session.settings();
        let listener = match TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], settings.port))).await {
            Ok(listener) => listener,
            Err(_) if settings.port != 0 => TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], 0))).await?,
            Err(err) => return Err(err.into()),
        };
        let port = listener.local_addr()?.port();
        let mut settings = settings;
        settings.port = port;
        let _ = session.update_settings(settings.clone());

        let ca = WatcherAuthority::new(
            &session.ca().cert_pem,
            &session.ca().key_pem,
            settings.http_version,
        )
        .map_err(ProxyError::Message)?;
        let connector = WatcherConnector::new(&settings)
            .map_err(|err| ProxyError::Message(err))?;

        let (shutdown, mut shutdown_rx) = watch::channel(false);
        let shutdown_fut = async move {
            loop {
                if *shutdown_rx.borrow() {
                    break;
                }
                if shutdown_rx.changed().await.is_err() {
                    break;
                }
            }
        };

        // Half-close stays on. Clients that finish the request and shut down
        // the write side, then wait for the response, must still be logged.
        let mut server = hudsucker::hyper_util::server::conn::auto::Builder::new(
            hudsucker::hyper_util::rt::TokioExecutor::new(),
        );
        server
            .http1()
            .title_case_headers(true)
            .preserve_header_case(true)
            .half_close(true);

        let proxy = Proxy::builder()
            .with_listener(listener)
            .with_ca(ca)
            .with_http_connector(connector)
            .with_http_handler(CaptureHandler::new(session.clone()))
            .with_websocket_handler(WsCapture::new(session.clone()))
            .with_server(server)
            .with_graceful_shutdown(shutdown_fut)
            .build()
            .map_err(|err| ProxyError::Message(err.to_string()))?;

        let join = tokio::spawn(async move {
            if let Err(err) = proxy.start().await {
                eprintln!("proxy stopped: {err}");
            }
        });
        session.set_status(format!(
            "Manual proxy listening on port {port}. Point a client at 127.0.0.1:{port}. The socket is open on this computer's interfaces so a phone on the same network can reach it. Captured traffic stays on this machine."
        ));
        Ok(Self {
            port,
            shutdown,
            join,
            session,
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn session(&self) -> &Session {
        &self.session
    }

    pub async fn shutdown(self) {
        let _ = self.shutdown.send(true);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), self.join).await;
    }
}
