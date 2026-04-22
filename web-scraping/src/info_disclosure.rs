use crate::fetcher::Fetcher;
use crate::secrets::Severity;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::sleep;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfoDisclosureFinding {
    pub path: String,
    pub status: u16,
    pub finding_type: String,
    pub severity: Severity,
    pub description: String,
}

const PROBE_PATHS: &[(&str, &str, Severity)] = &[
    ("/.env", "Environment File", Severity::Critical),
    ("/.env.local", "Environment File", Severity::Critical),
    ("/.env.production", "Environment File", Severity::Critical),
    ("/.git/config", "Git Config", Severity::Critical),
    ("/.git/HEAD", "Git HEAD", Severity::Critical),
    ("/.gitignore", "Gitignore", Severity::Low),
    ("/robots.txt", "Robots.txt", Severity::Info),
    ("/sitemap.xml", "Sitemap", Severity::Info),
    ("/.well-known/security.txt", "Security.txt", Severity::Info),
    ("/wp-admin/", "WordPress Admin", Severity::Medium),
    ("/wp-login.php", "WordPress Login", Severity::Medium),
    ("/admin", "Admin Panel", Severity::Medium),
    ("/admin/", "Admin Panel", Severity::Medium),
    ("/dashboard", "Dashboard", Severity::Medium),
    ("/debug", "Debug Page", Severity::High),
    ("/debug/", "Debug Page", Severity::High),
    ("/phpinfo.php", "PHP Info", Severity::High),
    ("/server-status", "Apache Status", Severity::High),
    ("/server-info", "Apache Info", Severity::High),
    ("/api", "API Root", Severity::Low),
    ("/api/", "API Root", Severity::Low),
    ("/api/docs", "API Docs", Severity::Medium),
    ("/api/v1", "API v1", Severity::Low),
    ("/swagger.json", "Swagger Spec", Severity::Medium),
    ("/swagger-ui/", "Swagger UI", Severity::Medium),
    ("/openapi.json", "OpenAPI Spec", Severity::Medium),
    ("/graphql", "GraphQL", Severity::Medium),
    ("/graphiql", "GraphiQL IDE", Severity::High),
    ("/.DS_Store", "macOS DS_Store", Severity::Low),
    ("/backup", "Backup Directory", Severity::High),
    ("/backup.sql", "SQL Backup", Severity::Critical),
    ("/dump.sql", "SQL Dump", Severity::Critical),
    ("/config.json", "Config File", Severity::High),
    ("/config.yml", "Config File", Severity::High),
    ("/package.json", "Node Package", Severity::Low),
    ("/composer.json", "PHP Composer", Severity::Low),
    ("/.htaccess", "Apache Config", Severity::Medium),
    ("/web.config", "IIS Config", Severity::Medium),
    ("/crossdomain.xml", "Flash Crossdomain", Severity::Low),
    ("/elmah.axd", "ELMAH Logs", Severity::High),
    ("/trace.axd", ".NET Trace", Severity::High),
];

pub struct InfoDisclosureScanner;

impl InfoDisclosureScanner {
    pub async fn scan(fetcher: &Fetcher, base_url: &str) -> Vec<InfoDisclosureFinding> {
        let mut findings = Vec::new();
        let base = base_url.trim_end_matches('/');

        for (path, finding_type, severity) in PROBE_PATHS {
            let url = format!("{}{}", base, path);
            if let Some(status) = fetcher.head_check(&url).await {
                if Self::is_interesting(status, path) {
                    findings.push(InfoDisclosureFinding {
                        path: path.to_string(),
                        status,
                        finding_type: finding_type.to_string(),
                        severity: if status == 200 {
                            severity.clone()
                        } else {
                            Severity::Info
                        },
                        description: Self::describe(status, path, finding_type),
                    });
                }
            }
            sleep(Duration::from_millis(100)).await;
        }

        findings
    }

    fn is_interesting(status: u16, path: &str) -> bool {
        match status {
            200 => true,
            301 | 302 | 307 | 308 => true,
            403 => {
                matches!(
                    path,
                    "/.env"
                        | "/.env.local"
                        | "/.env.production"
                        | "/.git/config"
                        | "/.git/HEAD"
                        | "/admin"
                        | "/admin/"
                        | "/debug"
                        | "/debug/"
                )
            }
            _ => false,
        }
    }

    fn describe(status: u16, path: &str, finding_type: &str) -> String {
        match status {
            200 => format!("{} is publicly accessible at {}", finding_type, path),
            301 | 302 | 307 | 308 => format!(
                "{} redirects ({}), may exist behind auth",
                finding_type, status
            ),
            403 => format!(
                "{} returns 403 Forbidden — exists but restricted",
                finding_type
            ),
            _ => format!("{}: HTTP {}", finding_type, status),
        }
    }
}
