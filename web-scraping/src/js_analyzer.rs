use crate::secrets::Severity;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::LazyLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsFinding {
    pub finding_type: JsFindingType,
    pub value: String,
    pub context: String,
    pub severity: Severity,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JsFindingType {
    HardcodedEndpoint,
    EnvironmentVariable,
    DebugFlag,
    ConfigObject,
    InlineCredential,
    SourceMapRef,
    DangerousFunction,
}

static ENV_VAR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:process\.env|import\.meta\.env)\.([A-Z_][A-Z0-9_]*)"#).unwrap()
});

static CONFIG_OBJ: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:config|settings|options)\s*[=:]\s*\{([^}]{10,300})\}"#).unwrap()
});

static DEBUG_FLAG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:debug|dev_?mode|is_?dev|testing|verbose)\s*[=:]\s*(?:true|1|"true")"#)
        .unwrap()
});

static DANGEROUS_FN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:eval|Function|setTimeout|setInterval)\s*\(\s*["'`]"#).unwrap()
});

static HARDCODED_URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"["'`](https?://(?:api\.|staging\.|dev\.|test\.|internal\.)[^\s"'`]+)["'`]"#)
        .unwrap()
});

pub struct JsAnalyzer;

impl JsAnalyzer {
    pub fn scan(body: &str, source: &str) -> Vec<JsFinding> {
        let mut findings = Vec::new();
        let mut seen = HashSet::new();

        for cap in ENV_VAR.captures_iter(body) {
            let var_name = cap.get(1).map(|m| m.as_str()).unwrap_or("");
            let key = format!("env:{}", var_name);
            if seen.insert(key) {
                let severity = if Self::is_sensitive_env(var_name) {
                    Severity::Medium
                } else {
                    Severity::Info
                };
                findings.push(JsFinding {
                    finding_type: JsFindingType::EnvironmentVariable,
                    value: var_name.to_string(),
                    context: Self::ctx(body, cap.get(0).unwrap().start()),
                    severity,
                    source: source.to_string(),
                });
            }
        }

        for cap in DEBUG_FLAG.captures_iter(body) {
            let m = cap.get(0).unwrap().as_str();
            if seen.insert(format!("debug:{}", m)) {
                findings.push(JsFinding {
                    finding_type: JsFindingType::DebugFlag,
                    value: m.to_string(),
                    context: Self::ctx(body, cap.get(0).unwrap().start()),
                    severity: Severity::Medium,
                    source: source.to_string(),
                });
            }
        }

        for cap in CONFIG_OBJ.captures_iter(body) {
            let content = cap.get(1).map(|m| m.as_str()).unwrap_or("");
            if Self::looks_sensitive_config(content)
                && seen.insert(format!("cfg:{}", &content[..20.min(content.len())]))
            {
                findings.push(JsFinding {
                    finding_type: JsFindingType::ConfigObject,
                    value: Self::truncate(content, 100),
                    context: Self::ctx(body, cap.get(0).unwrap().start()),
                    severity: Severity::Medium,
                    source: source.to_string(),
                });
            }
        }

        for cap in DANGEROUS_FN.captures_iter(body) {
            let m = cap.get(0).unwrap().as_str();
            if seen.insert(format!("fn:{}", m)) {
                findings.push(JsFinding {
                    finding_type: JsFindingType::DangerousFunction,
                    value: m.to_string(),
                    context: Self::ctx(body, cap.get(0).unwrap().start()),
                    severity: Severity::Low,
                    source: source.to_string(),
                });
            }
        }

        for cap in HARDCODED_URL.captures_iter(body) {
            if let Some(url) = cap.get(1) {
                let u = url.as_str();
                if seen.insert(format!("url:{}", u)) {
                    findings.push(JsFinding {
                        finding_type: JsFindingType::HardcodedEndpoint,
                        value: u.to_string(),
                        context: Self::ctx(body, cap.get(0).unwrap().start()),
                        severity: Severity::Medium,
                        source: source.to_string(),
                    });
                }
            }
        }

        findings
    }

    fn is_sensitive_env(name: &str) -> bool {
        let n = name.to_uppercase();
        n.contains("KEY")
            || n.contains("SECRET")
            || n.contains("TOKEN")
            || n.contains("PASSWORD")
            || n.contains("AUTH")
            || n.contains("CREDENTIAL")
            || n.contains("DATABASE")
            || n.contains("DB_")
            || n.contains("PRIVATE")
    }

    fn looks_sensitive_config(content: &str) -> bool {
        let lower = content.to_lowercase();
        lower.contains("key")
            || lower.contains("secret")
            || lower.contains("token")
            || lower.contains("password")
            || lower.contains("auth")
            || lower.contains("endpoint")
            || lower.contains("url")
            || lower.contains("host")
            || lower.contains("port")
    }

    fn ctx(body: &str, pos: usize) -> String {
        let start = pos.saturating_sub(30);
        let end = (pos + 60).min(body.len());
        let s = body.floor_char_boundary(start);
        let e = body.floor_char_boundary(end);
        body[s..e].replace('\n', " ").trim().to_string()
    }

    fn truncate(s: &str, max: usize) -> String {
        if s.len() > max {
            format!("{}…", &s[..s.floor_char_boundary(max - 1)])
        } else {
            s.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_env_var_detection() {
        let js = r#"const url = process.env.API_SECRET_KEY;"#;
        let f = JsAnalyzer::scan(js, "app.js");
        assert!(f.iter().any(
            |x| matches!(x.finding_type, JsFindingType::EnvironmentVariable)
                && x.severity == Severity::Medium
        ));
    }

    #[test]
    fn test_debug_flag() {
        let js = r#"const debug = true;"#;
        let f = JsAnalyzer::scan(js, "app.js");
        assert!(f
            .iter()
            .any(|x| matches!(x.finding_type, JsFindingType::DebugFlag)));
    }

    #[test]
    fn test_hardcoded_url() {
        let js = r#"const api = "https://api.internal.example.com/v1/users";"#;
        let f = JsAnalyzer::scan(js, "app.js");
        assert!(f
            .iter()
            .any(|x| matches!(x.finding_type, JsFindingType::HardcodedEndpoint)));
    }

    #[test]
    fn test_clean_js() {
        let js = r#"function add(a, b) { return a + b; }"#;
        let f = JsAnalyzer::scan(js, "app.js");
        assert!(f.is_empty());
    }
}
