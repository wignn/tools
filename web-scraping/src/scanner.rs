use crate::browser_fetcher::{BrowserConfig, BrowserFetcher};
use crate::config::ScannerConfig;
use crate::endpoints::{EndpointFinding, EndpointScanner};
use crate::fetcher::Fetcher;
use crate::headers::{HeaderFinding, HeaderScanner};
use crate::info_disclosure::{InfoDisclosureFinding, InfoDisclosureScanner};
use crate::js_analyzer::{JsAnalyzer, JsFinding};
use crate::secrets::{SecretFinding, SecretScanner, Severity};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{error, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub target_url: String,
    pub timestamp: String,
    pub scan_duration_ms: u64,
    pub fetch_info: Option<FetchInfo>,
    pub risk_score: RiskScore,
    pub secrets: Vec<SecretFinding>,
    pub endpoints: Vec<EndpointFinding>,
    pub headers: Vec<HeaderFinding>,
    pub info_disclosure: Vec<InfoDisclosureFinding>,
    pub js_findings: Vec<JsFinding>,
    pub summary: ScanSummary,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchInfo {
    pub status: u16,
    pub latency_ms: u64,
    pub content_length: usize,
    pub attempts: u32,
    pub method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    pub total: u32,
    pub grade: String,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub total_findings: usize,
    pub secrets_found: usize,
    pub endpoints_found: usize,
    pub header_issues: usize,
    pub exposed_paths: usize,
    pub js_issues: usize,
}

pub struct Scanner {
    fetcher: Arc<Fetcher>,
    config: ScannerConfig,
}

impl Scanner {
    pub fn new(config: &ScannerConfig) -> Self {
        Self {
            fetcher: Arc::new(Fetcher::new(config)),
            config: config.clone(),
        }
    }

    pub async fn scan(&self, url: &str) -> ScanReport {
        let start = std::time::Instant::now();
        info!(url = %url, "Starting security scan");
        let fetch_result = match self.fetcher.fetch(url).await {
            Ok(r) => {
                info!("Direct fetch succeeded");
                r
            }
            Err(e) => {
                warn!(url = %url, error = %e, "Direct fetch failed, trying headless Chrome...");
                let browser_config = BrowserConfig::default();
                match BrowserFetcher::fetch(url, &browser_config) {
                    Ok(r) => {
                        info!("Browser bypass succeeded");
                        r
                    }
                    Err(browser_err) => {
                        error!(url = %url, error = %browser_err, "Browser fallback also failed");
                        return self.error_report(
                            url,
                            start,
                            format!("Direct: {} | Browser: {}", e, browser_err),
                        );
                    }
                }
            }
        };

        let fi = FetchInfo {
            status: fetch_result.status,
            latency_ms: fetch_result.latency_ms,
            content_length: fetch_result.content_length,
            attempts: fetch_result.attempts,
            method: fetch_result.detection.clone(),
        };

        let opts = &self.config.scan_options;

        let secrets = if opts.scan_secrets {
            SecretScanner::scan(&fetch_result.body, url)
        } else {
            vec![]
        };

        let endpoints = if opts.scan_endpoints {
            EndpointScanner::scan(&fetch_result.body, url)
        } else {
            vec![]
        };

        let headers = if opts.scan_headers {
            HeaderScanner::scan(&fetch_result.headers, fetch_result.status)
        } else {
            vec![]
        };

        let info_disclosure = if opts.scan_info_disclosure {
            InfoDisclosureScanner::scan(&self.fetcher, url).await
        } else {
            vec![]
        };

        let js_findings = if opts.scan_javascript {
            JsAnalyzer::scan(&fetch_result.body, url)
        } else {
            vec![]
        };

        let header_issues = headers
            .iter()
            .filter(|h| {
                matches!(
                    h.status,
                    crate::headers::HeaderStatus::Fail | crate::headers::HeaderStatus::Warning
                )
            })
            .count();

        let summary = ScanSummary {
            total_findings: secrets.len()
                + header_issues
                + info_disclosure.len()
                + js_findings.len(),
            secrets_found: secrets.len(),
            endpoints_found: endpoints.len(),
            header_issues,
            exposed_paths: info_disclosure.len(),
            js_issues: js_findings.len(),
        };

        let risk_score = Self::calculate_risk(&secrets, &headers, &info_disclosure, &js_findings);

        info!(
            url = %url,
            findings = summary.total_findings,
            grade = %risk_score.grade,
            duration_ms = start.elapsed().as_millis() as u64,
            "Scan complete"
        );

        ScanReport {
            target_url: url.to_string(),
            timestamp: Utc::now().to_rfc3339(),
            scan_duration_ms: start.elapsed().as_millis() as u64,
            fetch_info: Some(fi),
            risk_score,
            secrets,
            endpoints,
            headers,
            info_disclosure,
            js_findings,
            summary,
            error: None,
        }
    }

    fn error_report(&self, url: &str, start: std::time::Instant, error: String) -> ScanReport {
        ScanReport {
            target_url: url.to_string(),
            timestamp: Utc::now().to_rfc3339(),
            scan_duration_ms: start.elapsed().as_millis() as u64,
            fetch_info: None,
            risk_score: RiskScore {
                total: 0,
                grade: "?".into(),
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
                info: 0,
            },
            secrets: vec![],
            endpoints: vec![],
            headers: vec![],
            info_disclosure: vec![],
            js_findings: vec![],
            summary: ScanSummary {
                total_findings: 0,
                secrets_found: 0,
                endpoints_found: 0,
                header_issues: 0,
                exposed_paths: 0,
                js_issues: 0,
            },
            error: Some(error),
        }
    }

    fn calculate_risk(
        secrets: &[SecretFinding],
        headers: &[HeaderFinding],
        info_disc: &[InfoDisclosureFinding],
        js: &[JsFinding],
    ) -> RiskScore {
        let mut critical = 0usize;
        let mut high = 0usize;
        let mut medium = 0usize;
        let mut low = 0usize;
        let mut info_count = 0usize;

        for s in secrets {
            match s.severity {
                Severity::Critical => critical += 1,
                Severity::High => high += 1,
                Severity::Medium => medium += 1,
                Severity::Low => low += 1,
                Severity::Info => info_count += 1,
            }
        }
        for h in headers {
            match h.severity {
                Severity::Critical => critical += 1,
                Severity::High => high += 1,
                Severity::Medium => medium += 1,
                Severity::Low => low += 1,
                Severity::Info => info_count += 1,
            }
        }
        for d in info_disc {
            match d.severity {
                Severity::Critical => critical += 1,
                Severity::High => high += 1,
                Severity::Medium => medium += 1,
                Severity::Low => low += 1,
                Severity::Info => info_count += 1,
            }
        }
        for j in js {
            match j.severity {
                Severity::Critical => critical += 1,
                Severity::High => high += 1,
                Severity::Medium => medium += 1,
                Severity::Low => low += 1,
                Severity::Info => info_count += 1,
            }
        }

        let total = (critical * 40) + (high * 15) + (medium * 5) + (low * 1);
        let grade = match total {
            0 => "A+",
            1..=10 => "A",
            11..=25 => "B",
            26..=50 => "C",
            51..=100 => "D",
            _ => "F",
        }
        .to_string();

        RiskScore {
            total: total as u32,
            grade,
            critical,
            high,
            medium,
            low,
            info: info_count,
        }
    }
}
