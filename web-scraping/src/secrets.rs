use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretFinding {
    pub secret_type: String,
    pub matched_value: String,
    pub context: String,
    pub severity: Severity,
    pub line_number: Option<usize>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

struct SecretPattern {
    name: &'static str,
    pattern: Regex,
    severity: Severity,
}

static SECRET_PATTERNS: LazyLock<Vec<SecretPattern>> = LazyLock::new(|| {
    vec![
        SecretPattern {
            name: "AWS Access Key",
            pattern: Regex::new(r"(?i)(AKIA[0-9A-Z]{16})").unwrap(),
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "AWS Secret Key",
            pattern: Regex::new(r#"(?i)(?:aws_secret_access_key|aws_secret|secret_key)\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?"#).unwrap(),
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "Google API Key",
            pattern: Regex::new(r"AIza[0-9A-Za-z\-_]{35}").unwrap(),
            severity: Severity::High,
        },
        SecretPattern {
            name: "Google OAuth Token",
            pattern: Regex::new(r"ya29\.[0-9A-Za-z\-_]+").unwrap(),
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "Firebase Key",
            pattern: Regex::new(r#"(?i)(?:firebase|firebaseConfig)[\s\S]{0,100}apiKey\s*[=:]\s*["']([A-Za-z0-9\-_]{20,})["']"#).unwrap(),
            severity: Severity::High,
        },
        SecretPattern {
            name: "Stripe Secret Key",
            pattern: Regex::new(r"sk_live_[0-9a-zA-Z]{24,}").unwrap(),
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "Stripe Publishable Key",
            pattern: Regex::new(r"pk_live_[0-9a-zA-Z]{24,}").unwrap(),
            severity: Severity::Medium,
        },
        SecretPattern {
            name: "GitHub Token",
            pattern: Regex::new(r"gh[pousr]_[A-Za-z0-9_]{36,}").unwrap(),
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "GitHub Classic Token",
            pattern: Regex::new(r"ghp_[A-Za-z0-9]{36}").unwrap(),
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "Slack Webhook",
            pattern: Regex::new(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+").unwrap(),
            severity: Severity::High,
        },
        SecretPattern {
            name: "Slack Bot Token",
            pattern: Regex::new(r"xoxb-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24,}").unwrap(),
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "Twilio API Key",
            pattern: Regex::new(r"SK[0-9a-fA-F]{32}").unwrap(),
            severity: Severity::High,
        },
        SecretPattern {
            name: "SendGrid API Key",
            pattern: Regex::new(r"SG\.[a-zA-Z0-9\-_]{22,}\.[a-zA-Z0-9\-_]{43,}").unwrap(),
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "Mailgun API Key",
            pattern: Regex::new(r"key-[0-9a-zA-Z]{32}").unwrap(),
            severity: Severity::High,
        },
        SecretPattern {
            name: "JWT Token",
            pattern: Regex::new(r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+").unwrap(),
            severity: Severity::High,
        },
        SecretPattern {
            name: "Private Key",
            pattern: Regex::new(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----").unwrap(),
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "Heroku API Key",
            pattern: Regex::new(r#"(?i)heroku[\s\S]{0,20}[=:]\s*["']?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}["']?"#).unwrap(),
            severity: Severity::High,
        },
        SecretPattern {
            name: "Generic API Key",
            pattern: Regex::new(r#"(?i)(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*["']([A-Za-z0-9\-_]{16,})["']"#).unwrap(),
            severity: Severity::Medium,
        },
        SecretPattern {
            name: "Generic Secret",
            pattern: Regex::new(r#"(?i)(?:secret|password|passwd|pwd|token|auth[_-]?token|access[_-]?token)\s*[=:]\s*["']([^\s"']{8,})["']"#).unwrap(),
            severity: Severity::Medium,
        },
        SecretPattern {
            name: "Database URL",
            pattern: Regex::new(r#"(?i)(?:mongodb|postgres|mysql|redis|amqp)://[^\s"'<>]{10,}"#).unwrap(),
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "Authorization Header",
            pattern: Regex::new(r#"(?i)(?:Authorization|Bearer)\s*[=:]\s*["']?(Bearer\s+)?[A-Za-z0-9\-_\.]{20,}["']?"#).unwrap(),
            severity: Severity::High,
        },
        SecretPattern {
            name: "Supabase Key",
            pattern: Regex::new(r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+").unwrap(),
            severity: Severity::High,
        },
        SecretPattern {
            name: "Vercel Token",
            pattern: Regex::new(r#"(?i)vercel[\s\S]{0,20}token\s*[=:]\s*["']?([A-Za-z0-9]{24,})["']?"#).unwrap(),
            severity: Severity::High,
        },
        SecretPattern {
            name: "OpenAI API Key",
            pattern: Regex::new(r"sk-[A-Za-z0-9]{32,}").unwrap(),
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "Discord Bot Token",
            pattern: Regex::new(r"[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27,}").unwrap(),
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "Telegram Bot Token",
            pattern: Regex::new(r"[0-9]{8,10}:[A-Za-z0-9_-]{35}").unwrap(),
            severity: Severity::High,
        },
    ]
});

static HTML_COMMENT_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"<!--([\s\S]*?)-->").unwrap());

pub struct SecretScanner;

impl SecretScanner {
    pub fn scan(body: &str, source: &str) -> Vec<SecretFinding> {
        let mut findings = Vec::new();

        for pattern in SECRET_PATTERNS.iter() {
            for mat in pattern.pattern.find_iter(body) {
                let matched = mat.as_str();
                let line_num = body[..mat.start()].matches('\n').count() + 1;
                let context = Self::extract_context(body, mat.start(), mat.end());

                let masked = Self::mask_secret(matched);

                findings.push(SecretFinding {
                    secret_type: pattern.name.to_string(),
                    matched_value: masked,
                    context,
                    severity: pattern.severity.clone(),
                    line_number: Some(line_num),
                    source: source.to_string(),
                });
            }
        }

        for cap in HTML_COMMENT_PATTERN.captures_iter(body) {
            let comment = cap.get(1).map(|m| m.as_str()).unwrap_or("");
            if Self::looks_sensitive(comment) {
                let line_num = body[..cap.get(0).unwrap().start()].matches('\n').count() + 1;
                findings.push(SecretFinding {
                    secret_type: "Sensitive HTML Comment".to_string(),
                    matched_value: Self::truncate(comment.trim(), 100),
                    context: Self::truncate(comment.trim(), 200),
                    severity: Severity::Low,
                    line_number: Some(line_num),
                    source: source.to_string(),
                });
            }
        }

        findings
    }

    fn looks_sensitive(comment: &str) -> bool {
        let lower = comment.to_lowercase();
        let keywords = [
            "todo",
            "fixme",
            "hack",
            "debug",
            "password",
            "secret",
            "api_key",
            "apikey",
            "token",
            "credential",
            "admin",
            "internal",
            "private",
            "config",
            "database",
            "db_",
            "user:",
            "pass:",
            "login",
            "auth",
        ];
        keywords.iter().any(|kw| lower.contains(kw))
    }

    fn extract_context(body: &str, start: usize, end: usize) -> String {
        let ctx_start = start.saturating_sub(40);
        let ctx_end = (end + 40).min(body.len());
        let safe_start = body.floor_char_boundary(ctx_start);
        let safe_end = body.floor_char_boundary(ctx_end);
        body[safe_start..safe_end]
            .replace('\n', " ")
            .trim()
            .to_string()
    }

    fn mask_secret(secret: &str) -> String {
        if secret.len() <= 8 {
            return "*".repeat(secret.len());
        }
        let visible = 4.min(secret.len() / 4);
        format!(
            "{}{}{}",
            &secret[..visible],
            "*".repeat(secret.len() - visible * 2),
            &secret[secret.len() - visible..]
        )
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
    fn test_aws_key_detection() {
        let html = r#"<script>var key = "AKIAIOSFODNN7EXAMPLE";</script>"#;
        let findings = SecretScanner::scan(html, "test.html");
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.secret_type == "AWS Access Key"));
    }

    #[test]
    fn test_google_api_key() {
        let html = r#"<script>const key = "AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe";</script>"#;
        let findings = SecretScanner::scan(html, "test.html");
        assert!(findings.iter().any(|f| f.secret_type == "Google API Key"));
    }

    #[test]
    fn test_stripe_key() {
        let html = r#"Stripe.setPublishableKey('pk_live_TYooMQauvdEDq54NiTphI7jx');"#;
        let findings = SecretScanner::scan(html, "test.html");
        assert!(findings.iter().any(|f| f.secret_type.contains("Stripe")));
    }

    #[test]
    fn test_github_token() {
        let html = r#"token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh1234";"#;
        let findings = SecretScanner::scan(html, "test.html");
        assert!(findings.iter().any(|f| f.secret_type.contains("GitHub")));
    }

    #[test]
    fn test_generic_api_key() {
        let html = r#"api_key = "";"#;
        let findings = SecretScanner::scan(html, "test.html");
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_sensitive_comment() {
        let html = r#"<!-- TODO: remove hardcoded admin password before deploy -->"#;
        let findings = SecretScanner::scan(html, "test.html");
        assert!(findings
            .iter()
            .any(|f| f.secret_type == "Sensitive HTML Comment"));
    }

    #[test]
    fn test_database_url() {
        let html = r#"const db = "mongodb://admin:password123@localhost:27017/prod";"#;
        let findings = SecretScanner::scan(html, "test.html");
        assert!(findings.iter().any(|f| f.secret_type == "Database URL"));
    }

    #[test]
    fn test_no_false_positive_on_clean_html() {
        let html = r#"<html><body><h1>Hello World</h1><p>Normal page content.</p></body></html>"#;
        let findings = SecretScanner::scan(html, "test.html");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_secret_masking() {
        let masked = SecretScanner::mask_secret("AKIAIOSFODNN7EXAMPLE");
        assert!(masked.starts_with("AKIA"));
        assert!(masked.contains('*'));
        assert!(masked.ends_with("MPLE"));
    }

    #[test]
    fn test_jwt_detection() {
        let html = r#"token: """#;
        let findings = SecretScanner::scan(html, "test.html");
        assert!(findings
            .iter()
            .any(|f| f.secret_type.contains("JWT") || f.secret_type.contains("Supabase")));
    }
}
