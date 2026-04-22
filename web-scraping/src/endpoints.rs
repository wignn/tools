use regex::Regex;
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::LazyLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointFinding {
    pub url: String,
    pub endpoint_type: EndpointType,
    pub source: String,
    pub method: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EndpointType {
    ApiEndpoint,
    FormAction,
    WebSocket,
    GraphQL,
    InternalLink,
    ExternalLink,
    ScriptSource,
    StyleSource,
    ImageSource,
    SourceMap,
}

static JS_URL_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:fetch|axios\.\w+|\.get|\.post|\.put|\.delete|\.patch|XMLHttpRequest)\s*\(\s*["'`](/[^\s"'`]+|https?://[^\s"'`]+)["'`]"#).unwrap()
});

static JS_STRING_URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"["'`]((?:/api/|/v[0-9]+/|/graphql|/rest/|/webhook)[^\s"'`]*)["'`]"#).unwrap()
});

static GENERIC_URL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"["'`](https?://[^\s"'`<>]{10,})["'`]"#).unwrap());

static WS_URL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"["'`](wss?://[^\s"'`<>]+)["'`]"#).unwrap());

static SOURCEMAP_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"//[#@]\s*sourceMappingURL\s*=\s*(\S+)").unwrap());

pub struct EndpointScanner;

impl EndpointScanner {
    pub fn scan(body: &str, base_url: &str) -> Vec<EndpointFinding> {
        let mut findings = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();

        Self::scan_html_elements(body, base_url, &mut findings, &mut seen);
        Self::scan_js_patterns(body, base_url, &mut findings, &mut seen);
        Self::scan_websockets(body, &mut findings, &mut seen);
        Self::scan_sourcemaps(body, base_url, &mut findings, &mut seen);

        findings
    }

    fn scan_html_elements(
        body: &str,
        base_url: &str,
        findings: &mut Vec<EndpointFinding>,
        seen: &mut HashSet<String>,
    ) {
        let document = Html::parse_document(body);

        let link_sel = Selector::parse("a[href]").unwrap();
        for el in document.select(&link_sel) {
            if let Some(href) = el.value().attr("href") {
                let resolved = Self::resolve_url(href, base_url);
                if seen.insert(resolved.clone()) {
                    let ep_type = if Self::looks_like_api(&resolved) {
                        EndpointType::ApiEndpoint
                    } else if resolved.starts_with("http") && !resolved.contains(base_url) {
                        EndpointType::ExternalLink
                    } else {
                        EndpointType::InternalLink
                    };
                    findings.push(EndpointFinding {
                        url: resolved,
                        endpoint_type: ep_type,
                        source: "HTML <a>".to_string(),
                        method: Some("GET".to_string()),
                    });
                }
            }
        }

        let form_sel = Selector::parse("form[action]").unwrap();
        for el in document.select(&form_sel) {
            if let Some(action) = el.value().attr("action") {
                let resolved = Self::resolve_url(action, base_url);
                let method = el.value().attr("method").unwrap_or("GET").to_uppercase();
                if seen.insert(format!("{}:{}", method, resolved)) {
                    findings.push(EndpointFinding {
                        url: resolved,
                        endpoint_type: EndpointType::FormAction,
                        source: "HTML <form>".to_string(),
                        method: Some(method),
                    });
                }
            }
        }

        let script_sel = Selector::parse("script[src]").unwrap();
        for el in document.select(&script_sel) {
            if let Some(src) = el.value().attr("src") {
                let resolved = Self::resolve_url(src, base_url);
                if seen.insert(resolved.clone()) {
                    findings.push(EndpointFinding {
                        url: resolved,
                        endpoint_type: EndpointType::ScriptSource,
                        source: "HTML <script>".to_string(),
                        method: None,
                    });
                }
            }
        }

        let link_css_sel = Selector::parse("link[href]").unwrap();
        for el in document.select(&link_css_sel) {
            if let Some(href) = el.value().attr("href") {
                let resolved = Self::resolve_url(href, base_url);
                if seen.insert(resolved.clone()) {
                    findings.push(EndpointFinding {
                        url: resolved,
                        endpoint_type: EndpointType::StyleSource,
                        source: "HTML <link>".to_string(),
                        method: None,
                    });
                }
            }
        }
    }

    fn scan_js_patterns(
        body: &str,
        base_url: &str,
        findings: &mut Vec<EndpointFinding>,
        seen: &mut HashSet<String>,
    ) {
        for cap in JS_URL_PATTERN.captures_iter(body) {
            if let Some(url) = cap.get(1) {
                let resolved = Self::resolve_url(url.as_str(), base_url);
                if seen.insert(resolved.clone()) {
                    findings.push(EndpointFinding {
                        url: resolved,
                        endpoint_type: EndpointType::ApiEndpoint,
                        source: "JavaScript fetch/axios".to_string(),
                        method: Self::detect_method(cap.get(0).map(|m| m.as_str()).unwrap_or("")),
                    });
                }
            }
        }

        for cap in JS_STRING_URL.captures_iter(body) {
            if let Some(url) = cap.get(1) {
                let resolved = Self::resolve_url(url.as_str(), base_url);
                if seen.insert(resolved.clone()) {
                    let ep_type = if resolved.contains("graphql") {
                        EndpointType::GraphQL
                    } else {
                        EndpointType::ApiEndpoint
                    };
                    findings.push(EndpointFinding {
                        url: resolved,
                        endpoint_type: ep_type,
                        source: "JavaScript string".to_string(),
                        method: None,
                    });
                }
            }
        }

        for cap in GENERIC_URL.captures_iter(body) {
            if let Some(url) = cap.get(1) {
                let u = url.as_str();
                if Self::looks_like_api(u) && seen.insert(u.to_string()) {
                    findings.push(EndpointFinding {
                        url: u.to_string(),
                        endpoint_type: EndpointType::ApiEndpoint,
                        source: "Inline URL".to_string(),
                        method: None,
                    });
                }
            }
        }
    }

    fn scan_websockets(
        body: &str,
        findings: &mut Vec<EndpointFinding>,
        seen: &mut HashSet<String>,
    ) {
        for cap in WS_URL.captures_iter(body) {
            if let Some(url) = cap.get(1) {
                let u = url.as_str().to_string();
                if seen.insert(u.clone()) {
                    findings.push(EndpointFinding {
                        url: u,
                        endpoint_type: EndpointType::WebSocket,
                        source: "WebSocket URL".to_string(),
                        method: None,
                    });
                }
            }
        }
    }

    fn scan_sourcemaps(
        body: &str,
        base_url: &str,
        findings: &mut Vec<EndpointFinding>,
        seen: &mut HashSet<String>,
    ) {
        for cap in SOURCEMAP_PATTERN.captures_iter(body) {
            if let Some(map_url) = cap.get(1) {
                let resolved = Self::resolve_url(map_url.as_str(), base_url);
                if seen.insert(resolved.clone()) {
                    findings.push(EndpointFinding {
                        url: resolved,
                        endpoint_type: EndpointType::SourceMap,
                        source: "Source map reference".to_string(),
                        method: None,
                    });
                }
            }
        }
    }

    fn resolve_url(url: &str, base: &str) -> String {
        if url.starts_with("http://")
            || url.starts_with("https://")
            || url.starts_with("ws://")
            || url.starts_with("wss://")
        {
            return url.to_string();
        }
        if url.starts_with("//") {
            return format!("https:{}", url);
        }
        let base_trimmed = base.trim_end_matches('/');
        if url.starts_with('/') {
            if let Ok(parsed) = url::Url::parse(base_trimmed) {
                return format!(
                    "{}://{}{}",
                    parsed.scheme(),
                    parsed.host_str().unwrap_or(""),
                    url
                );
            }
        }
        format!("{}/{}", base_trimmed, url)
    }

    fn looks_like_api(url: &str) -> bool {
        let lower = url.to_lowercase();
        lower.contains("/api/")
            || lower.contains("/v1/")
            || lower.contains("/v2/")
            || lower.contains("/v3/")
            || lower.contains("/graphql")
            || lower.contains("/rest/")
            || lower.contains("/webhook")
            || lower.contains("/rpc/")
            || lower.contains("/ws/")
            || lower.contains(".json")
            || lower.contains("/auth/")
    }

    fn detect_method(context: &str) -> Option<String> {
        let lower = context.to_lowercase();
        if lower.contains(".post") || lower.contains("post(") {
            Some("POST".to_string())
        } else if lower.contains(".put") || lower.contains("put(") {
            Some("PUT".to_string())
        } else if lower.contains(".delete") || lower.contains("delete(") {
            Some("DELETE".to_string())
        } else if lower.contains(".patch") || lower.contains("patch(") {
            Some("PATCH".to_string())
        } else {
            Some("GET".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_html_links() {
        let html = r#"<html><body><a href="/about">About</a><a href="https://external.com">Ext</a></body></html>"#;
        let findings = EndpointScanner::scan(html, "https://example.com");
        assert!(findings
            .iter()
            .any(|f| f.endpoint_type == EndpointType::InternalLink));
        assert!(findings
            .iter()
            .any(|f| f.endpoint_type == EndpointType::ExternalLink));
    }

    #[test]
    fn test_form_action() {
        let html = r#"<form action="/api/login" method="POST"><input type="submit"></form>"#;
        let findings = EndpointScanner::scan(html, "https://example.com");
        assert!(findings
            .iter()
            .any(|f| f.endpoint_type == EndpointType::FormAction
                && f.method == Some("POST".to_string())));
    }

    #[test]
    fn test_script_sources() {
        let html = r#"<script src="/static/app.js"></script>"#;
        let findings = EndpointScanner::scan(html, "https://example.com");
        assert!(findings
            .iter()
            .any(|f| f.endpoint_type == EndpointType::ScriptSource));
    }

    #[test]
    fn test_js_api_detection() {
        let html = r#"<script>fetch("/api/v1/users").then(r => r.json())</script>"#;
        let findings = EndpointScanner::scan(html, "https://example.com");
        assert!(findings
            .iter()
            .any(|f| f.endpoint_type == EndpointType::ApiEndpoint));
    }

    #[test]
    fn test_websocket_detection() {
        let html = r#"<script>new WebSocket("wss://api.example.com/ws/live")</script>"#;
        let findings = EndpointScanner::scan(html, "https://example.com");
        assert!(findings
            .iter()
            .any(|f| f.endpoint_type == EndpointType::WebSocket));
    }

    #[test]
    fn test_graphql_detection() {
        let html = r#"<script>const endpoint = "/graphql";</script>"#;
        let findings = EndpointScanner::scan(html, "https://example.com");
        assert!(findings
            .iter()
            .any(|f| f.endpoint_type == EndpointType::GraphQL));
    }

    #[test]
    fn test_sourcemap_detection() {
        let html = "//# sourceMappingURL=app.js.map";
        let findings = EndpointScanner::scan(html, "https://example.com");
        assert!(findings
            .iter()
            .any(|f| f.endpoint_type == EndpointType::SourceMap));
    }
}
