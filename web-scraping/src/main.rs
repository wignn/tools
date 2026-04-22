mod anti_bot;
mod browser_fetcher;
mod config;
mod endpoints;
mod fetcher;
mod headers;
mod info_disclosure;
mod js_analyzer;
mod proxy;
mod rate_limiter;
mod retry;
mod scanner;
mod secrets;
mod user_agent;

use crate::config::ScannerConfig;
use crate::headers::HeaderStatus;
use crate::scanner::{ScanReport, Scanner};
use crate::secrets::Severity;
use chrono::Utc;
use std::env;
use std::fs;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .compact()
        .with_target(false)
        .init();

    let urls: Vec<String> = env::args().skip(1).collect();
    if urls.is_empty() {
        print_usage();
        return;
    }

    let config = ScannerConfig::default();
    let scanner = Scanner::new(&config);

    print_banner();
    println!("  \x1b[90mTargets:\x1b[0m  {} URL(s)", urls.len());
    println!(
        "  \x1b[90mStarted:\x1b[0m  {}",
        Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    );
    println!();

    let output_dir = PathBuf::from("output");
    fs::create_dir_all(&output_dir).ok();

    for (i, url) in urls.iter().enumerate() {
        println!(
            "  \x1b[90m⏳ Scanning [{}/{}] {}\x1b[0m",
            i + 1,
            urls.len(),
            url
        );
        let report = scanner.scan(url).await;

        let ts = Utc::now().format("%Y%m%d_%H%M%S");
        let domain = extract_domain(url);
        let path = output_dir.join(format!("{}_{}.json", domain, ts));
        let json = serde_json::to_string_pretty(&report).unwrap();
        fs::write(&path, &json).ok();

        print_report(&report, i + 1, urls.len());
        println!("  \x1b[90mReport saved: {}\x1b[0m", path.display());
        println!();
    }
}

fn print_banner() {
    println!();
    println!("  \x1b[1;36m╔══════════════════════════════════════════════════╗\x1b[0m");
    println!("  \x1b[1;36m║\x1b[0m   \x1b[1;37m🔒  Web Security Recon Scanner\x1b[0m                  \x1b[1;36m║\x1b[0m");
    println!("  \x1b[1;36m╚══════════════════════════════════════════════════╝\x1b[0m");
    println!();
}

fn print_usage() {
    print_banner();
    println!("  \x1b[1;37mUsage:\x1b[0m  \x1b[36mweb-recon\x1b[0m \x1b[33m<url>\x1b[0m \x1b[90m[url2] ...\x1b[0m");
    println!();
    println!("  \x1b[1;37mScans for:\x1b[0m");
    println!("    \x1b[33m🔑\x1b[0m  Exposed API keys, tokens, credentials");
    println!("    \x1b[33m🌐\x1b[0m  Hidden API endpoints & source maps");
    println!("    \x1b[33m🛡️\x1b[0m   Security header misconfigurations");
    println!("    \x1b[33m📂\x1b[0m  Exposed sensitive files (.env, .git, etc.)");
    println!("    \x1b[33m⚙️\x1b[0m   JavaScript secrets & debug flags");
    println!();
    println!("  \x1b[1;37mExamples:\x1b[0m");
    println!("    \x1b[36m$\x1b[0m web-recon https://example.com");
    println!("    \x1b[36m$\x1b[0m web-recon https://site1.com https://site2.com");
    println!();
}

fn print_report(report: &ScanReport, idx: usize, total: usize) {
    println!();
    let g = &report.risk_score;
    let grade_color = match g.grade.as_str() {
        "A+" | "A" => "\x1b[1;32m",
        "B" => "\x1b[1;33m",
        "C" => "\x1b[1;33m",
        "D" => "\x1b[1;31m",
        _ => "\x1b[1;31m",
    };

    println!("  \x1b[1;36m┌──────────────────────────────────────────────────┐\x1b[0m");
    println!(
        "  \x1b[1;36m│\x1b[0m  \x1b[1;37m[{}/{}]\x1b[0m  {}                      ",
        idx, total, report.target_url
    );
    println!("  \x1b[1;36m└──────────────────────────────────────────────────┘\x1b[0m");

    if let Some(ref err) = report.error {
        println!("  \x1b[1;31m  ✗ Error: {}\x1b[0m", err);
        return;
    }

    if let Some(ref fi) = report.fetch_info {
        println!("  \x1b[90m│\x1b[0m  \x1b[36mHTTP {}\x1b[0m  \x1b[90m•\x1b[0m  {}ms  \x1b[90m•\x1b[0m  {}  \x1b[90m•\x1b[0m  \x1b[33m{}\x1b[0m",
            fi.status, fi.latency_ms, format_bytes(fi.content_length), fi.method);
    }

    println!();
    println!("  \x1b[90m│\x1b[0m  \x1b[1;37mRisk Score:\x1b[0m  {}{}\x1b[0m  ({}pts)  \x1b[31m{}C\x1b[0m \x1b[33m{}H\x1b[0m \x1b[35m{}M\x1b[0m \x1b[90m{}L {}I\x1b[0m",
        grade_color, g.grade, g.total, g.critical, g.high, g.medium, g.low, g.info);

    // Secrets
    if !report.secrets.is_empty() {
        println!();
        println!(
            "  \x1b[90m│\x1b[0m  \x1b[1;31m🔑 Secrets Found: {}\x1b[0m",
            report.secrets.len()
        );
        for s in &report.secrets {
            let sev = severity_badge(&s.severity);
            println!(
                "  \x1b[90m│\x1b[0m    {} \x1b[37m{}\x1b[0m",
                sev, s.secret_type
            );
            println!(
                "  \x1b[90m│\x1b[0m      \x1b[90mValue:\x1b[0m  {}",
                s.matched_value
            );
            if let Some(ln) = s.line_number {
                println!("  \x1b[90m│\x1b[0m      \x1b[90mLine:\x1b[0m   {}", ln);
            }
        }
    }

    // Headers
    let header_issues: Vec<_> = report
        .headers
        .iter()
        .filter(|h| matches!(h.status, HeaderStatus::Fail | HeaderStatus::Warning))
        .collect();
    if !header_issues.is_empty() {
        println!();
        println!(
            "  \x1b[90m│\x1b[0m  \x1b[1;33m�️  Header Issues: {}\x1b[0m",
            header_issues.len()
        );
        for h in &header_issues {
            let icon = match h.status {
                HeaderStatus::Fail => "\x1b[31m✗\x1b[0m",
                HeaderStatus::Warning => "\x1b[33m⚠\x1b[0m",
                _ => " ",
            };
            println!(
                "  \x1b[90m│\x1b[0m    {} \x1b[37m{}\x1b[0m  \x1b[90m{}\x1b[0m",
                icon, h.check, h.details
            );
            if !h.recommendation.is_empty() {
                println!(
                    "  \x1b[90m│\x1b[0m      \x1b[36m→\x1b[0m {}",
                    h.recommendation
                );
            }
        }
    }

    let header_passes: Vec<_> = report
        .headers
        .iter()
        .filter(|h| h.status == HeaderStatus::Pass)
        .collect();
    if !header_passes.is_empty() {
        println!();
        println!(
            "  \x1b[90m│\x1b[0m  \x1b[1;32m✓ Headers OK: {}\x1b[0m",
            header_passes.len()
        );
        for h in &header_passes {
            println!(
                "  \x1b[90m│\x1b[0m    \x1b[32m✓\x1b[0m \x1b[37m{}\x1b[0m",
                h.check
            );
        }
    }

    // Info Disclosure
    if !report.info_disclosure.is_empty() {
        println!();
        println!(
            "  \x1b[90m│\x1b[0m  \x1b[1;35m📂 Exposed Paths: {}\x1b[0m",
            report.info_disclosure.len()
        );
        for d in &report.info_disclosure {
            let sev = severity_badge(&d.severity);
            println!(
                "  \x1b[90m│\x1b[0m    {} \x1b[37m{}\x1b[0m  \x1b[90m[{}]\x1b[0m  {}",
                sev, d.path, d.status, d.description
            );
        }
    }

    // Endpoints
    if !report.endpoints.is_empty() {
        let apis: Vec<_> = report
            .endpoints
            .iter()
            .filter(|e| {
                matches!(
                    e.endpoint_type,
                    crate::endpoints::EndpointType::ApiEndpoint
                        | crate::endpoints::EndpointType::GraphQL
                        | crate::endpoints::EndpointType::WebSocket
                        | crate::endpoints::EndpointType::FormAction
                        | crate::endpoints::EndpointType::SourceMap
                )
            })
            .collect();
        if !apis.is_empty() {
            println!();
            println!(
                "  \x1b[90m│\x1b[0m  \x1b[1;36m🌐 Interesting Endpoints: {}\x1b[0m",
                apis.len()
            );
            for e in apis.iter().take(20) {
                let method = e.method.as_deref().unwrap_or("");
                println!("  \x1b[90m│\x1b[0m    \x1b[33m{:>6}\x1b[0m  \x1b[37m{}\x1b[0m  \x1b[90m({})\x1b[0m",
                    method, e.url, e.source);
            }
            if apis.len() > 20 {
                println!(
                    "  \x1b[90m│\x1b[0m    \x1b[90m... and {} more (see JSON report)\x1b[0m",
                    apis.len() - 20
                );
            }
        }
    }

    // JS Findings
    if !report.js_findings.is_empty() {
        println!();
        println!(
            "  \x1b[90m│\x1b[0m  \x1b[1;33m⚙️  JavaScript Issues: {}\x1b[0m",
            report.js_findings.len()
        );
        for j in report.js_findings.iter().take(10) {
            let sev = severity_badge(&j.severity);
            println!(
                "  \x1b[90m│\x1b[0m    {} \x1b[37m{:?}\x1b[0m  \x1b[90m{}\x1b[0m",
                sev,
                j.finding_type,
                truncate(&j.value, 60)
            );
        }
    }

    println!();
    println!(
        "  \x1b[90m│\x1b[0m  \x1b[90mScan time: {}ms\x1b[0m",
        report.scan_duration_ms
    );
}

fn severity_badge(sev: &Severity) -> String {
    match sev {
        Severity::Critical => "\x1b[1;41;37m CRIT \x1b[0m".to_string(),
        Severity::High => "\x1b[1;31m HIGH \x1b[0m".to_string(),
        Severity::Medium => "\x1b[1;33m MED  \x1b[0m".to_string(),
        Severity::Low => "\x1b[90m LOW  \x1b[0m".to_string(),
        Severity::Info => "\x1b[36m INFO \x1b[0m".to_string(),
    }
}

fn format_bytes(b: usize) -> String {
    if b >= 1_048_576 {
        format!("{:.1} MB", b as f64 / 1_048_576.0)
    } else if b >= 1024 {
        format!("{:.1} KB", b as f64 / 1024.0)
    } else {
        format!("{} B", b)
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}…", &s[..s.floor_char_boundary(max - 1)])
    } else {
        s.to_string()
    }
}

fn extract_domain(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.replace('.', "_")))
        .unwrap_or_else(|| "unknown".to_string())
}
