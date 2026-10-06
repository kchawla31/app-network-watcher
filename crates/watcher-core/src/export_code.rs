use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExportKind {
    Curl,
    Fetch,
    PythonRequests,
    OkHttp,
}

pub fn export_request(
    kind: ExportKind,
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: &str,
) -> String {
    match kind {
        ExportKind::Curl => curl(method, url, headers, body),
        ExportKind::Fetch => fetch(method, url, headers, body),
        ExportKind::PythonRequests => python(method, url, headers, body),
        ExportKind::OkHttp => okhttp(method, url, headers, body),
    }
}

fn shell(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn curl(method: &str, url: &str, headers: &[(String, String)], body: &str) -> String {
    let mut parts = vec![format!("curl -X {} {}", shell(method), shell(url))];
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        parts.push(format!("-H {}", shell(&format!("{name}: {value}"))));
    }
    if !body.is_empty() {
        parts.push(format!("--data {}", shell(body)));
    }
    parts.join(" \\\n  ")
}

fn fetch(method: &str, url: &str, headers: &[(String, String)], body: &str) -> String {
    let headers = headers
        .iter()
        .filter(|(name, _)| !name.eq_ignore_ascii_case("content-length"))
        .map(|(name, value)| format!("    {}: {}", js(name), js(value)))
        .collect::<Vec<_>>()
        .join(",\n");
    let body_line = if body.is_empty() {
        String::new()
    } else {
        format!(",\n  body: {}", js(body))
    };
    format!(
        "fetch({}, {{\n  method: {},\n  headers: {{\n{headers}\n  }}{body_line}\n}})",
        js(url),
        js(method)
    )
}

fn python(method: &str, url: &str, headers: &[(String, String)], body: &str) -> String {
    let headers = headers
        .iter()
        .filter(|(name, _)| !name.eq_ignore_ascii_case("content-length"))
        .map(|(name, value)| format!("    {}: {}", py(name), py(value)))
        .collect::<Vec<_>>()
        .join(",\n");
    let data = if body.is_empty() {
        "None".into()
    } else {
        py(body)
    };
    format!(
        "import requests\n\nresponse = requests.request(\n    {},\n    {},\n    headers={{\n{headers}\n    }},\n    data={data},\n)\nprint(response.status_code)\nprint(response.text)\n",
        py(method),
        py(url)
    )
}

fn okhttp(method: &str, url: &str, headers: &[(String, String)], body: &str) -> String {
    let mut builder = String::from("val request = Request.Builder()\n");
    builder.push_str(&format!("    .url({})\n", kotlin(url)));
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        builder.push_str(&format!(
            "    .header({}, {})\n",
            kotlin(name),
            kotlin(value)
        ));
    }
    if body.is_empty() {
        builder.push_str(&format!("    .method({}, null)\n", kotlin(method)));
    } else {
        builder.push_str(&format!(
            "    .method({}, \"{}\".toRequestBody(\"application/json\".toMediaType()))\n",
            kotlin(method),
            body.replace('\\', "\\\\").replace('"', "\\\"")
        ));
    }
    builder.push_str("    .build()\n");
    builder
}

fn js(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".into())
}

fn py(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".into())
}

fn kotlin(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn curl_and_okhttp_include_method_and_url() {
        let headers = vec![("Accept".into(), "application/json".into())];
        let curl = export_request(ExportKind::Curl, "POST", "https://example.com/v1", &headers, "{\"a\":1}");
        assert!(curl.contains("POST"));
        assert!(curl.contains("https://example.com/v1"));
        assert!(curl.contains("Accept"));
        let ok = export_request(ExportKind::OkHttp, "GET", "https://example.com/v1", &headers, "");
        assert!(ok.contains("https://example.com/v1"));
        let fetch = export_request(ExportKind::Fetch, "PUT", "https://example.com/v1", &headers, "x");
        assert!(fetch.contains("fetch("));
        let python = export_request(
            ExportKind::PythonRequests,
            "DELETE",
            "https://example.com/v1",
            &headers,
            "",
        );
        assert!(python.contains("requests.request"));
    }
}
