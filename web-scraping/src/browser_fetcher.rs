use headless_chrome::protocol::cdp::Network;
use headless_chrome::{Browser, LaunchOptions};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, info, warn};

use crate::fetcher::FetchResult;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserConfig {
    pub headless: bool,
    pub timeout_secs: u64,
    pub wait_after_load_ms: u64,
}

impl Default for BrowserConfig {
    fn default() -> Self {
        Self {
            headless: true,
            timeout_secs: 30,
            wait_after_load_ms: 5000,
        }
    }
}

pub struct BrowserFetcher;

impl BrowserFetcher {
    pub fn fetch(url: &str, config: &BrowserConfig) -> Result<FetchResult, String> {
        info!(url = %url, "Launching headless Chrome for Cloudflare bypass");

        let launch_options = LaunchOptions {
            headless: config.headless,
            args: vec![
                std::ffi::OsStr::new("--disable-blink-features=AutomationControlled"),
                std::ffi::OsStr::new("--disable-features=IsolateOrigins,site-per-process"),
                std::ffi::OsStr::new("--no-sandbox"),
                std::ffi::OsStr::new("--disable-setuid-sandbox"),
                std::ffi::OsStr::new("--disable-dev-shm-usage"),
                std::ffi::OsStr::new("--disable-gpu"),
                std::ffi::OsStr::new("--window-size=1920,1080"),
            ],
            sandbox: false,
            idle_browser_timeout: Duration::from_secs(config.timeout_secs + 10),
            ..LaunchOptions::default()
        };

        let browser = Browser::new(launch_options).map_err(|e| {
            format!(
                "Failed to launch Chrome: {}. Make sure Chrome/Chromium is installed.",
                e
            )
        })?;

        let tab = browser
            .new_tab()
            .map_err(|e| format!("Failed to create tab: {}", e))?;

        // Inject stealth JS before navigation
        tab.evaluate(
            r#"
            Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
            Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
            Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
            window.chrome = { runtime: {} };
            "#,
            false,
        )
        .ok();

        debug!(url = %url, "Navigating to URL");
        let start = std::time::Instant::now();

        tab.navigate_to(url)
            .map_err(|e| format!("Navigation failed: {}", e))?;

        tab.wait_until_navigated()
            .map_err(|e| format!("Wait failed: {}", e))?;

        // Wait extra for Cloudflare challenge to resolve
        info!(
            "Waiting {}ms for Cloudflare challenge resolution...",
            config.wait_after_load_ms
        );
        std::thread::sleep(Duration::from_millis(config.wait_after_load_ms));

        // Check if still on challenge page, wait more if needed
        let mut attempts = 0;
        loop {
            let title = tab.get_title().unwrap_or_default();
            let check_body = tab.get_content().unwrap_or_default();

            if !title.contains("Just a moment")
                && !title.contains("Checking")
                && !check_body.contains("cf-challenge")
                && !check_body.contains("challenge-platform")
            {
                debug!("Cloudflare challenge appears resolved");
                break;
            }

            attempts += 1;
            if attempts > 6 {
                warn!("Still on challenge page after multiple waits");
                break;
            }
            debug!(attempt = attempts, "Still on challenge page, waiting...");
            std::thread::sleep(Duration::from_millis(3000));
        }

        let latency_ms = start.elapsed().as_millis() as u64;

        let body = tab
            .get_content()
            .map_err(|e| format!("Failed to get page content: {}", e))?;

        // Get response headers from the performance log
        let mut headers: Vec<(String, String)> = Vec::new();
        let mut status = 200u16;

        // Try to get response info via CDP
        if let Ok(response_data) = tab.evaluate(
            r#"
            (function() {
                var entries = performance.getEntriesByType('navigation');
                if (entries.length > 0) {
                    return JSON.stringify({
                        status: entries[0].responseStatus || 200,
                        type: entries[0].type
                    });
                }
                return JSON.stringify({ status: 200, type: 'navigate' });
            })()
            "#,
            false,
        ) {
            if let Some(val) = response_data.value {
                if let Some(s) = val.as_str() {
                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(s) {
                        status = parsed["status"].as_u64().unwrap_or(200) as u16;
                    }
                }
            }
        }

        // Collect cookies as header-like entries for analysis
        if let Ok(cookies) = tab.get_cookies() {
            for cookie in &cookies {
                headers.push(("set-cookie-name".to_string(), cookie.name.clone()));
            }
        }

        let content_length = body.len();

        info!(
            url = %url,
            status = status,
            body_len = content_length,
            latency_ms = latency_ms,
            "Browser fetch complete"
        );

        Ok(FetchResult {
            url: url.to_string(),
            status,
            headers,
            body,
            proxy_used: Some("headless-chrome".to_string()),
            attempts: 1,
            latency_ms,
            detection: "BrowserBypass".to_string(),
            content_length,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = BrowserConfig::default();
        assert!(config.headless);
        assert_eq!(config.timeout_secs, 30);
    }
}
