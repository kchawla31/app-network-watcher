use serde_json::Value;

/// Check one call against a user-supplied OpenAPI 3 document.
/// Returns human-readable problems. An empty list means the call matches.
pub fn validate_openapi(spec: &Value, method: &str, path: &str, status: Option<u16>) -> Vec<String> {
    let mut problems = Vec::new();
    let Some(paths) = spec.get("paths").and_then(Value::as_object) else {
        problems.push("OpenAPI document has no paths object.".into());
        return problems;
    };
    let path = path.split('?').next().unwrap_or(path);
    let Some((template, item)) = find_path(paths, path) else {
        problems.push(format!("No OpenAPI path matches {path}."));
        return problems;
    };
    let Some(item) = item.as_object() else {
        problems.push(format!("Path {template} is not an object."));
        return problems;
    };
    let method_key = method.to_ascii_lowercase();
    let Some(operation) = item.get(&method_key) else {
        problems.push(format!("{method} is not documented on {template}."));
        return problems;
    };
    if let Some(status) = status {
        let responses = operation.get("responses").and_then(Value::as_object);
        match responses {
            None => problems.push(format!("{method} {template} documents no responses.")),
            Some(responses) => {
                let code = status.to_string();
                let class = format!("{}XX", status / 100);
                if !responses.contains_key(&code)
                    && !responses.contains_key(&class)
                    && !responses.contains_key("default")
                {
                    problems.push(format!(
                        "Status {status} is not documented for {method} {template}."
                    ));
                }
            }
        }
    }
    problems
}

fn find_path<'a>(
    paths: &'a serde_json::Map<String, Value>,
    actual: &str,
) -> Option<(&'a str, &'a Value)> {
    if let Some((template, item)) = paths.get_key_value(actual) {
        return Some((template.as_str(), item));
    }
    paths
        .iter()
        .find(|(template, _)| path_matches(template, actual))
        .map(|(template, item)| (template.as_str(), item))
}

fn path_matches(template: &str, actual: &str) -> bool {
    let template: Vec<&str> = template.split('/').collect();
    let actual: Vec<&str> = actual.split('/').collect();
    if template.len() != actual.len() {
        return false;
    }
    template.iter().zip(actual).all(|(expected, got)| {
        expected == &got || (expected.starts_with('{') && expected.ends_with('}') && !got.is_empty())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_templated_path_and_rejects_unknown_status() {
        let spec = serde_json::json!({
            "openapi": "3.0.3",
            "paths": {
                "/items/{id}": {
                    "get": { "responses": { "200": { "description": "ok" } } }
                }
            }
        });
        assert!(validate_openapi(&spec, "GET", "/items/15", Some(200)).is_empty());
        let problems = validate_openapi(&spec, "GET", "/items/15", Some(500));
        assert!(problems.iter().any(|item| item.contains("500")));
        assert!(validate_openapi(&spec, "POST", "/items/15", None)
            .iter()
            .any(|item| item.contains("POST")));
    }
}
