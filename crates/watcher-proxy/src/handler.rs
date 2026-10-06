use http_body_util::BodyExt;
use hudsucker::hyper::header::{HeaderMap, HeaderName, HeaderValue};
use hudsucker::hyper::{Request, Response, StatusCode, Uri, Version};
use hudsucker::tokio_tungstenite::tungstenite::Message;
use hudsucker::{Body, HttpContext, HttpHandler, RequestOrResponse, WebSocketContext, WebSocketHandler};
use std::time::Instant;
use watcher_core::{
    apply_header_edits, caching_notes, compression_notes, now_ms, Action, BodyHandle,
    BreakpointDecision, Exchange, ExchangeId, Phase, RequestSnap, Session,
};

#[derive(Clone)]
pub struct CaptureHandler {
    session: Session,
    id: Option<ExchangeId>,
    started: Option<Instant>,
    started_unix_ms: u64,
    action: Option<Action>,
    version: String,
    method: String,
    url: String,
    host: String,
    path: String,
    request_headers: Vec<(String, String)>,
    request_body: BodyHandle,
}

impl CaptureHandler {
    pub fn new(session: Session) -> Self {
        Self {
            session,
            id: None,
            started: None,
            started_unix_ms: 0,
            action: None,
            version: "HTTP/1.1".into(),
            method: String::new(),
            url: String::new(),
            host: String::new(),
            path: String::new(),
            request_headers: Vec::new(),
            request_body: BodyHandle::Empty,
        }
    }
}

impl HttpHandler for CaptureHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        if req.method() == hudsucker::hyper::Method::CONNECT {
            return req.into();
        }
        let started = Instant::now();
        let version = version_string(req.version());
        let method = req.method().to_string();
        let url = req.uri().to_string();
        let host = req.uri().host().unwrap_or("").to_string();
        let path = path_of(req.uri());
        if !self.session.settings().host_is_intercepted(&host) {
            return req.into();
        }
        let (parts, body) = req.into_parts();
        let bytes = match body.collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(err) => {
                return error_response(format!("could not read the request body: {err}")).into();
            }
        };
        let mut headers = header_pairs(&parts.headers);
        let mut body_bytes = bytes.to_vec();
        let snap = RequestSnap {
            method: method.clone(),
            url: url.clone(),
            host: host.clone(),
            path: path.clone(),
            headers: headers.clone(),
            body: body_bytes.clone(),
            http_version: version.clone(),
        };
        let rule = self.session.rules().first_match(&snap).cloned();
        if let Some(rule) = &rule {
            if let Action::Transform {
                request_headers,
                request_body,
                ..
            } = &rule.action
            {
                apply_header_edits(&mut headers, request_headers);
                if let Some(replacement) = request_body {
                    body_bytes = replacement.as_bytes().to_vec();
                }
            }
        }
        self.started = Some(started);
        self.started_unix_ms = now_ms();
        self.version = version;
        self.method = method;
        self.url = url;
        self.host = host;
        self.path = path;
        self.request_headers = headers.clone();
        self.request_body = self
            .session
            .bodies()
            .put(&body_bytes)
            .unwrap_or(BodyHandle::Inline(body_bytes.clone()));
        self.action = rule.as_ref().map(|rule| rule.action.clone());

        if let Some(rule) = &rule {
            match &rule.action {
                Action::Mock {
                    status,
                    headers: mock_headers,
                    body,
                } => {
                    let response_body = body.as_bytes().to_vec();
                    self.finish(
                        Some(*status),
                        mock_headers.clone(),
                        &response_body,
                        None,
                        started.elapsed().as_millis() as u64,
                        started.elapsed().as_millis() as u64,
                        0,
                        Phase::Complete,
                    );
                    return respond(*status, mock_headers.clone(), response_body).into();
                }
                Action::Error { status, body } => {
                    let response_body = body.as_bytes().to_vec();
                    self.finish(
                        Some(*status),
                        vec![],
                        &response_body,
                        None,
                        started.elapsed().as_millis() as u64,
                        started.elapsed().as_millis() as u64,
                        0,
                        Phase::Complete,
                    );
                    return respond(*status, vec![], response_body).into();
                }
                Action::Redirect { location, status } => {
                    let headers = vec![("location".into(), location.clone())];
                    self.finish(
                        Some(*status),
                        headers.clone(),
                        b"",
                        None,
                        started.elapsed().as_millis() as u64,
                        0,
                        0,
                        Phase::Complete,
                    );
                    return respond(*status, headers, Vec::new()).into();
                }
                Action::Timeout { delay_ms, status } => {
                    tokio::time::sleep(std::time::Duration::from_millis(*delay_ms)).await;
                    let body = b"injected timeout".to_vec();
                    self.finish(
                        Some(*status),
                        vec![],
                        &body,
                        None,
                        started.elapsed().as_millis() as u64,
                        started.elapsed().as_millis() as u64,
                        0,
                        Phase::Complete,
                    );
                    return respond(*status, vec![], body).into();
                }
                Action::Breakpoint { request: true, .. } => {
                    let id = ExchangeId::new();
                    self.id = Some(id);
                    self.finish_paused(id, Phase::PausedRequest, None, vec![], b"");
                    let (tx, rx) = tokio::sync::oneshot::channel();
                    self.session.park_breakpoint(id, tx);
                    match rx.await {
                        Ok(BreakpointDecision::Forward {
                            headers: edited,
                            body,
                        }) => {
                            self.request_headers = edited.clone();
                            self.request_body = self
                                .session
                                .bodies()
                                .put(&body)
                                .unwrap_or(BodyHandle::Inline(body.clone()));
                            let version = parts.version;
                            let mut req = rebuild_request(parts, &edited, body);
                            *req.version_mut() = version;
                            return req.into();
                        }
                        Ok(BreakpointDecision::Respond {
                            status,
                            headers: response_headers,
                            body,
                        }) => {
                            self.finish(
                                Some(status),
                                response_headers.clone(),
                                &body,
                                None,
                                started.elapsed().as_millis() as u64,
                                started.elapsed().as_millis() as u64,
                                0,
                                Phase::Complete,
                            );
                            return respond(status, response_headers, body).into();
                        }
                        Ok(BreakpointDecision::Fail { message }) => {
                            self.finish(
                                Some(502),
                                vec![],
                                message.as_bytes(),
                                Some(message.clone()),
                                started.elapsed().as_millis() as u64,
                                0,
                                0,
                                Phase::Failed,
                            );
                            return error_response(message).into();
                        }
                        Err(_) => {
                            let text = "breakpoint closed before a decision".to_string();
                            self.finish(
                                Some(502),
                                vec![],
                                text.as_bytes(),
                                Some(text.clone()),
                                started.elapsed().as_millis() as u64,
                                0,
                                0,
                                Phase::Failed,
                            );
                            return error_response(text).into();
                        }
                    }
                }
                _ => {}
            }
        }

        let id = ExchangeId::new();
        self.id = Some(id);
        self.publish_pending(id);
        rebuild_request(parts, &self.request_headers, body_bytes).into()
    }

    async fn handle_response(
        &mut self,
        _ctx: &HttpContext,
        res: Response<Body>,
    ) -> Response<Body> {
        let ttfb = self
            .started
            .map(|started| started.elapsed().as_millis() as u64)
            .unwrap_or(0);
        let (parts, body) = res.into_parts();
        let read_at = Instant::now();
        let bytes = match body.collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(err) => {
                let text = format!("could not read the response body: {err}");
                self.finish(
                    Some(parts.status.as_u16()),
                    header_pairs(&parts.headers),
                    text.as_bytes(),
                    Some(text.clone()),
                    ttfb,
                    ttfb,
                    0,
                    Phase::Failed,
                );
                return error_response(text);
            }
        };
        let download = read_at.elapsed().as_millis() as u64;
        let mut headers = header_pairs(&parts.headers);
        let mut body_bytes = bytes.to_vec();
        if let Some(Action::Transform {
            response_headers,
            response_body,
            ..
        }) = &self.action
        {
            apply_header_edits(&mut headers, response_headers);
            if let Some(replacement) = response_body {
                body_bytes = replacement.as_bytes().to_vec();
            }
        }
        if let Some(Action::Breakpoint {
            response: true, ..
        }) = &self.action
        {
            let id = self.id.unwrap_or_else(ExchangeId::new);
            self.id = Some(id);
            self.finish(
                Some(parts.status.as_u16()),
                headers.clone(),
                &body_bytes,
                None,
                ttfb + download,
                ttfb,
                download,
                Phase::PausedResponse,
            );
            let (tx, rx) = tokio::sync::oneshot::channel();
            self.session.park_breakpoint(id, tx);
            if let Ok(decision) = rx.await {
                match decision {
                    BreakpointDecision::Forward {
                        headers: edited,
                        body,
                    }
                    | BreakpointDecision::Respond {
                        headers: edited,
                        body,
                        ..
                    } => {
                        headers = edited;
                        body_bytes = body;
                    }
                    BreakpointDecision::Fail { message } => {
                        self.finish(
                            Some(502),
                            vec![],
                            message.as_bytes(),
                            Some(message.clone()),
                            ttfb,
                            ttfb,
                            0,
                            Phase::Failed,
                        );
                        return error_response(message);
                    }
                }
            }
        }
        self.finish(
            Some(parts.status.as_u16()),
            headers.clone(),
            &body_bytes,
            None,
            ttfb + download,
            ttfb,
            download,
            Phase::Complete,
        );
        respond(parts.status.as_u16(), headers, body_bytes)
    }

    async fn handle_error(
        &mut self,
        _ctx: &HttpContext,
        err: hyper_util::client::legacy::Error,
    ) -> Response<Body> {
        let raw = err.to_string();
        let lower = raw.to_ascii_lowercase();
        let text = if lower.contains("certificate")
            || lower.contains("tls")
            || lower.contains("handshake")
            || lower.contains("unknownissuer")
        {
            format!("{raw}\nThe app rejected the certificate or the upstream TLS check failed. Certificate pinning is not bypassed. A release build captures only after it trusts this CA, or after you install the CA into an emulator or already-rooted system store.")
        } else {
            raw
        };
        self.finish(
            Some(502),
            vec![],
            text.as_bytes(),
            Some(text.clone()),
            self.started
                .map(|started| started.elapsed().as_millis() as u64)
                .unwrap_or(0),
            0,
            0,
            Phase::Failed,
        );
        error_response(text)
    }

    async fn should_intercept_connect(
        &mut self,
        _ctx: &HttpContext,
        req: &Request<Body>,
    ) -> bool {
        let host = req.uri().host().unwrap_or("");
        self.session.settings().host_is_intercepted(host)
    }

    async fn should_intercept_tls(
        &mut self,
        _ctx: &HttpContext,
        client_hello: hudsucker::rustls::server::ClientHello<'_>,
    ) -> bool {
        let host = client_hello
            .server_name()
            .map(|name| name.to_string())
            .unwrap_or_default();
        let intercept = self.session.settings().host_is_intercepted(&host);
        if intercept {
            self.session.bump_tls_hello(if host.is_empty() {
                "unknown host"
            } else {
                &host
            });
        }
        intercept
    }
}

impl CaptureHandler {
    fn publish_pending(&self, id: ExchangeId) {
        self.session.upsert(Exchange {
            id,
            started_unix_ms: self.started_unix_ms,
            method: self.method.clone(),
            url: self.url.clone(),
            host: self.host.clone(),
            path: self.path.clone(),
            status: None,
            http_version: self.version.clone(),
            request_headers: self.request_headers.clone(),
            response_headers: Vec::new(),
            request_body: self.request_body.clone(),
            response_body: BodyHandle::Empty,
            pinned: false,
            error: None,
            phase: Phase::Pending,
            duration_ms: None,
            ttfb_ms: None,
            download_ms: None,
            protocol_note: protocol_note(&self.url),
            timing_notes: String::new(),
        });
    }

    fn finish_paused(
        &self,
        id: ExchangeId,
        phase: Phase,
        status: Option<u16>,
        response_headers: Vec<(String, String)>,
        response_body: &[u8],
    ) {
        let response_body = self
            .session
            .bodies()
            .put(response_body)
            .unwrap_or(BodyHandle::Inline(response_body.to_vec()));
        self.session.upsert(Exchange {
            id,
            started_unix_ms: self.started_unix_ms,
            method: self.method.clone(),
            url: self.url.clone(),
            host: self.host.clone(),
            path: self.path.clone(),
            status,
            http_version: self.version.clone(),
            request_headers: self.request_headers.clone(),
            response_headers,
            request_body: self.request_body.clone(),
            response_body,
            pinned: false,
            error: None,
            phase,
            duration_ms: None,
            ttfb_ms: None,
            download_ms: None,
            protocol_note: protocol_note(&self.url),
            timing_notes: "Paused. Edit the call, then forward it or answer it.".into(),
        });
    }

    fn finish(
        &self,
        status: Option<u16>,
        response_headers: Vec<(String, String)>,
        response_body: &[u8],
        error: Option<String>,
        duration_ms: u64,
        ttfb_ms: u64,
        download_ms: u64,
        phase: Phase,
    ) {
        let id = self.id.unwrap_or_else(ExchangeId::new);
        let stored = self
            .session
            .bodies()
            .put(response_body)
            .unwrap_or(BodyHandle::Inline(response_body.to_vec()));
        let (decoded, _) = watcher_core::decode_for_display(&response_headers, response_body);
        let timing_notes = format!(
            "{}\n{}\nConnect and TLS durations are not reported by the capture engine. Total, time to first byte, and download are measured around the proxied message.",
            compression_notes(&response_headers, response_body.len(), Some(decoded.len())),
            caching_notes(&response_headers)
        );
        let pinned = self
            .session
            .exchanges()
            .into_iter()
            .find(|item| item.id == id)
            .map(|item| item.pinned)
            .unwrap_or(false);
        self.session.upsert(Exchange {
            id,
            started_unix_ms: self.started_unix_ms,
            method: self.method.clone(),
            url: self.url.clone(),
            host: self.host.clone(),
            path: self.path.clone(),
            status,
            http_version: self.version.clone(),
            request_headers: self.request_headers.clone(),
            response_headers,
            request_body: self.request_body.clone(),
            response_body: stored,
            pinned,
            error,
            phase,
            duration_ms: Some(duration_ms),
            ttfb_ms: Some(ttfb_ms),
            download_ms: Some(download_ms),
            protocol_note: protocol_note(&self.url),
            timing_notes,
        });
    }
}

#[derive(Clone)]
pub struct WsCapture {
    session: Session,
}

impl WsCapture {
    pub fn new(session: Session) -> Self {
        Self { session }
    }
}

impl WebSocketHandler for WsCapture {
    async fn handle_message(
        &mut self,
        ctx: &WebSocketContext,
        message: Message,
    ) -> Option<Message> {
        let (direction, url) = match ctx {
            WebSocketContext::ClientToServer { dst, .. } => ("client", dst.to_string()),
            WebSocketContext::ServerToClient { src, .. } => ("server", src.to_string()),
        };
        let preview = match &message {
            Message::Text(text) => text.as_str().as_bytes().to_vec(),
            Message::Binary(bytes) => bytes.to_vec(),
            Message::Ping(bytes) | Message::Pong(bytes) => bytes.to_vec(),
            Message::Close(_) => b"close".to_vec(),
            Message::Frame(_) => b"frame".to_vec(),
        };
        let host = url.split("://").nth(1).unwrap_or(&url);
        let host = host.split('/').next().unwrap_or(host).to_string();
        let body = self
            .session
            .bodies()
            .put(&preview)
            .unwrap_or(BodyHandle::Inline(preview.clone()));
        self.session.upsert(Exchange {
            id: ExchangeId::new(),
            started_unix_ms: now_ms(),
            method: "WS".into(),
            url: url.clone(),
            host,
            path: format!("/{direction}"),
            status: Some(101),
            http_version: "WebSocket".into(),
            request_headers: vec![],
            response_headers: vec![],
            request_body: if direction == "client" {
                body.clone()
            } else {
                BodyHandle::Empty
            },
            response_body: if direction == "server" {
                body
            } else {
                BodyHandle::Empty
            },
            pinned: false,
            error: None,
            phase: Phase::Complete,
            duration_ms: Some(0),
            ttfb_ms: Some(0),
            download_ms: Some(0),
            protocol_note: "websocket".into(),
            timing_notes: format!("{direction} websocket message, {} bytes", preview.len()),
        });
        Some(message)
    }
}

fn rebuild_request(
    mut parts: http::request::Parts,
    headers: &[(String, String)],
    body: Vec<u8>,
) -> Request<Body> {
    parts.headers = header_map(headers);
    if let Ok(value) = HeaderValue::from_str(&body.len().to_string()) {
        parts.headers.insert(http::header::CONTENT_LENGTH, value);
    }
    Request::from_parts(parts, Body::from(body))
}

fn respond(status: u16, headers: Vec<(String, String)>, body: Vec<u8>) -> Response<Body> {
    let mut response = Response::new(Body::from(body.clone()));
    *response.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
    *response.headers_mut() = header_map(&headers);
    if let Ok(value) = HeaderValue::from_str(&body.len().to_string()) {
        response
            .headers_mut()
            .insert(http::header::CONTENT_LENGTH, value);
    }
    response
}

fn error_response(message: String) -> Response<Body> {
    respond(502, vec![("content-type".into(), "text/plain".into())], message.into_bytes())
}

fn header_pairs(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            (
                name.to_string(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect()
}

fn header_map(headers: &[(String, String)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        if let (Ok(name), Ok(value)) = (
            HeaderName::try_from(name.as_str()),
            HeaderValue::try_from(value.as_str()),
        ) {
            map.append(name, value);
        }
    }
    map
}

fn path_of(uri: &Uri) -> String {
    let path = uri.path();
    let path = if path.is_empty() { "/" } else { path };
    match uri.query() {
        Some(query) => format!("{path}?{query}"),
        None => path.to_string(),
    }
}

fn version_string(version: Version) -> String {
    match version {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_11 => "HTTP/1.1",
        Version::HTTP_2 => "HTTP/2",
        Version::HTTP_3 => "HTTP/3",
        _ => "HTTP",
    }
    .into()
}

fn protocol_note(url: &str) -> String {
    if url.starts_with("https://") {
        "https".into()
    } else if url.starts_with("wss://") || url.starts_with("ws://") {
        "websocket".into()
    } else {
        "http".into()
    }
}


