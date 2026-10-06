use std::io::{Read, Write};
use std::net::TcpListener;
use watcher_desktop::{request_text, response_text, traffic_rows, Session};
use watcher_proxy::{send_edited, RunningProxy};

#[tokio::test]
async fn manual_proxy_request_appears_in_the_table() {
    let dir = tempfile::tempdir().unwrap();
    let session = Session::open(dir.path()).unwrap();
    let mut settings = session.settings();
    settings.port = 0;
    session.update_settings(settings).unwrap();
    let echo = spawn_echo();
    let proxy = RunningProxy::start(session.clone()).await.unwrap();
    send_edited(
        proxy.port(),
        &session.ca().cert_der,
        "POST",
        &format!("http://127.0.0.1:{echo}/hello"),
        &[("Content-Type".into(), "application/json".into())],
        br#"{"hello":true}"#,
    )
    .await
    .expect("request through the manual proxy");

    let mut matched = None;
    for _ in 0..50 {
        let rows = traffic_rows(&session.exchanges(), "", &[]);
        if let Some(row) = rows
            .iter()
            .find(|row| row.method == "POST" && row.path == "/hello" && row.status == "200")
        {
            matched = Some(row.clone());
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let row = matched.unwrap_or_else(|| {
        let dump = session
            .exchanges()
            .iter()
            .map(|item| {
                format!(
                    "{} {} {:?} {} {} err={:?}",
                    item.method, item.host, item.status, item.path, item.url, item.error
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        panic!("missing row\nstatus: {}\nrows:\n{dump}", session.status())
    });
    let exchange = session
        .exchanges()
        .into_iter()
        .find(|item| item.id == row.id)
        .unwrap();
    assert!(
        exchange
            .request_headers
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("content-type") && value.contains("json"))
    );
    assert!(request_text(&session, &exchange).contains("hello"));
    let (body, _notes) = response_text(&session, &exchange);
    assert!(body.contains("echo"));
    proxy.shutdown().await;
}

fn spawn_echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for _ in 0..4 {
            let Ok((mut socket, _)) = listener.accept() else {
                break;
            };
            let _ = socket.set_read_timeout(Some(std::time::Duration::from_secs(2)));
            let mut buf = Vec::new();
            let mut tmp = [0u8; 1024];
            loop {
                match socket.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => {
                        buf.extend_from_slice(&tmp[..n]);
                        if request_complete(&buf) {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let body = b"echo";
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = socket.write_all(head.as_bytes());
            let _ = socket.write_all(body);
        }
    });
    port
}

fn request_complete(buf: &[u8]) -> bool {
    let Some(header_end) = buf.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let headers = String::from_utf8_lossy(&buf[..header_end]);
    let body = &buf[header_end + 4..];
    for line in headers.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            return value
                .trim()
                .parse::<usize>()
                .map(|len| body.len() >= len)
                .unwrap_or(false);
        }
    }
    true
}
