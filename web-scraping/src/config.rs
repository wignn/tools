use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerConfig {
    pub max_concurrency: usize,
    pub default_rate_limit: RateLimitConfig,
    pub per_domain_rate_limits: HashMap<String, RateLimitConfig>,
    pub retry_policy: RetryPolicyConfig,
    pub proxies: Vec<String>,
    pub custom_headers: HashMap<String, String>,
    pub request_timeout_secs: u64,
    pub scan_options: ScanOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub requests_per_second: u32,
    pub burst_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicyConfig {
    pub max_retries: u32,
    pub base_delay_ms: u64,
    pub max_delay_ms: u64,
    pub jitter_factor: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOptions {
    pub scan_secrets: bool,
    pub scan_endpoints: bool,
    pub scan_headers: bool,
    pub scan_info_disclosure: bool,
    pub scan_javascript: bool,
    pub follow_links: bool,
    pub max_depth: usize,
    pub max_pages: usize,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            max_concurrency: 10,
            default_rate_limit: RateLimitConfig {
                requests_per_second: 5,
                burst_size: 10,
            },
            per_domain_rate_limits: HashMap::new(),
            retry_policy: RetryPolicyConfig {
                max_retries: 2,
                base_delay_ms: 1000,
                max_delay_ms: 10000,
                jitter_factor: 0.3,
            },
            proxies: Vec::new(),
            custom_headers: HashMap::new(),
            request_timeout_secs: 15,
            scan_options: ScanOptions::default(),
        }
    }
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            scan_secrets: true,
            scan_endpoints: true,
            scan_headers: true,
            scan_info_disclosure: true,
            scan_javascript: true,
            follow_links: false,
            max_depth: 1,
            max_pages: 50,
        }
    }
}

impl ScannerConfig {
    pub fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.request_timeout_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ScannerConfig::default();
        assert_eq!(config.max_concurrency, 10);
        assert!(config.scan_options.scan_secrets);
        assert!(config.scan_options.scan_headers);
    }

    #[test]
    fn test_config_serialization() {
        let config = ScannerConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let deser: ScannerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.max_concurrency, config.max_concurrency);
    }
}
