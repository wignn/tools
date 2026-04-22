use crate::anti_bot::{AntiBot, Detection};
use crate::config::ScannerConfig;
use crate::proxy::ProxyPool;
use crate::rate_limiter::RateLimiter;
use crate::retry::RetryPolicy;
use crate::user_agent::UserAgentRotator;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, ACCEPT, ACCEPT_LANGUAGE, USER_AGENT};
use reqwest::{Client, Proxy};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};
use url::Url;

#[derive(Debug, Error)]
pub enum FetchError {
    #[error("HTTP request failed: {0}")]
    RequestFailed(#[from] reqwest::Error),

    #[error("Blocked after {attempts} attempts")]
    Blocked { attempts: u32 },

    #[error("Captcha detected: {captcha_type:?}")]
    CaptchaDetected {
        captcha_type: crate::anti_bot::CaptchaType,
    },

    #[error("Rate limited, retry exhausted after {attempts} attempts")]
    RateLimitExhausted { attempts: u32 },

    #[error("Invalid URL: {0}")]
    InvalidUrl(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchResult {
    pub url: String,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub proxy_used: Option<String>,
    pub attempts: u32,
    pub latency_ms: u64,
    pub detection: String,
    pub content_length: usize,
}

pub struct Fetcher {
    proxy_pool: Arc<ProxyPool>,
    ua_rotator: Arc<UserAgentRotator>,
    rate_limiter: Arc<RateLimiter>,
    retry_policy: RetryPolicy,
    timeout: Duration,
    custom_headers: HeaderMap,
}

impl Fetcher {
    pub fn new(config: &ScannerConfig) -> Self {
        let proxy_pool = Arc::new(ProxyPool::new(config.proxies.clone()));
        let ua_rotator = Arc::new(UserAgentRotator::new());

        let mut rate_limiter = RateLimiter::new(
            config.default_rate_limit.requests_per_second,
            config.default_rate_limit.burst_size,
        );
        for (domain, rl) in &config.per_domain_rate_limits {
            rate_limiter.set_domain_limit(domain.clone(), rl.requests_per_second, rl.burst_size);
        }

        let retry_policy = RetryPolicy::new(
            config.retry_policy.max_retries,
            config.retry_policy.base_delay_ms,
            config.retry_policy.max_delay_ms,
            config.retry_policy.jitter_factor,
        );

        let mut custom_headers = HeaderMap::new();
        for (key, value) in &config.custom_headers {
            if let (Ok(name), Ok(val)) = (key.parse::<HeaderName>(), HeaderValue::from_str(value)) {
                custom_headers.insert(name, val);
            }
        }

        Self {
            proxy_pool,
            ua_rotator,
            rate_limiter: Arc::new(rate_limiter),
            retry_policy,
            timeout: config.request_timeout(),
            custom_headers,
        }
    }

    fn build_client(&self, proxy_url: Option<&str>) -> Result<Client, FetchError> {
        let mut builder = Client::builder()
            .timeout(self.timeout)
            .redirect(reqwest::redirect::Policy::limited(10))
            .cookie_store(true);

        if let Some(proxy_url) = proxy_url {
            let proxy = Proxy::all(proxy_url).map_err(FetchError::RequestFailed)?;
            builder = builder.proxy(proxy);
        }

        builder.build().map_err(FetchError::RequestFailed)
    }

    fn build_headers(&self) -> HeaderMap {
        let mut headers = self.custom_headers.clone();
        let ua = self.ua_rotator.rotate();
        headers.insert(USER_AGENT, HeaderValue::from_str(ua).unwrap());
        headers.insert(
            ACCEPT,
            HeaderValue::from_static(
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            ),
        );
        headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
        headers
    }

    pub fn extract_domain(url_str: &str) -> Result<String, FetchError> {
        let parsed =
            Url::parse(url_str).map_err(|_| FetchError::InvalidUrl(url_str.to_string()))?;
        parsed
            .host_str()
            .map(|h| h.to_string())
            .ok_or_else(|| FetchError::InvalidUrl(url_str.to_string()))
    }

    pub async fn fetch(&self, url: &str) -> Result<FetchResult, FetchError> {
        let domain = Self::extract_domain(url)?;
        let start = Instant::now();
        let max_attempts = self.retry_policy.max_retries + 1;
        let mut attempt = 0u32;

        loop {
            attempt += 1;
            self.rate_limiter.acquire(&domain).await;

            let proxy_entry = if !self.proxy_pool.is_empty() {
                self.proxy_pool.next()
            } else {
                None
            };

            let proxy_url = proxy_entry.as_ref().map(|p| p.url.as_str());
            let client = self.build_client(proxy_url)?;
            let headers = self.build_headers();
            let last_proxy = proxy_url.map(|s| s.to_string());

            debug!(url = %url, attempt = attempt, proxy = ?proxy_url, "Fetching");

            let response = match client.get(url).headers(headers).send().await {
                Ok(resp) => resp,
                Err(err) => {
                    if let Some(ref proxy_url) = last_proxy {
                        self.proxy_pool.report_failure(proxy_url);
                    }
                    if attempt >= max_attempts {
                        return Err(FetchError::RequestFailed(err));
                    }
                    let delay = self.retry_policy.compute_delay(attempt - 1);
                    warn!(attempt = attempt, error = %err, "Request failed, retrying");
                    sleep(delay).await;
                    continue;
                }
            };

            let status = response.status();
            let resp_headers: Vec<(String, String)> = response
                .headers()
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();
            let raw_headers = response.headers().clone();
            let body = response.text().await.unwrap_or_default();

            let detection = AntiBot::analyze(status, &raw_headers, &body);
            let detection_label = format!("{:?}", detection);

            match &detection {
                Detection::Clean => {
                    if let Some(ref proxy_url) = last_proxy {
                        self.proxy_pool.report_success(proxy_url);
                    }
                    let latency = start.elapsed().as_millis() as u64;
                    info!(url = %url, status = status.as_u16(), latency_ms = latency, "Fetch OK");
                    return Ok(FetchResult {
                        url: url.to_string(),
                        status: status.as_u16(),
                        content_length: body.len(),
                        headers: resp_headers,
                        body,
                        proxy_used: last_proxy,
                        attempts: attempt,
                        latency_ms: latency,
                        detection: detection_label,
                    });
                }
                Detection::RateLimited { retry_after_secs } => {
                    if let Some(ref px) = last_proxy {
                        self.proxy_pool.report_failure(px);
                    }
                    if attempt >= max_attempts {
                        return Err(FetchError::RateLimitExhausted { attempts: attempt });
                    }
                    let delay = retry_after_secs
                        .map(Duration::from_secs)
                        .unwrap_or_else(|| self.retry_policy.compute_delay(attempt - 1));
                    warn!(attempt = attempt, "Rate limited, backing off");
                    sleep(delay).await;
                }
                Detection::Blocked => {
                    if let Some(ref px) = last_proxy {
                        self.proxy_pool.report_failure(px);
                    }
                    if attempt >= max_attempts {
                        return Err(FetchError::Blocked { attempts: attempt });
                    }
                    sleep(self.retry_policy.compute_delay(attempt - 1)).await;
                }
                Detection::CaptchaDetected { captcha_type } => {
                    if let Some(ref px) = last_proxy {
                        self.proxy_pool.report_failure(px);
                    }
                    error!(captcha_type = ?captcha_type, url = %url, "Captcha detected");
                    return Err(FetchError::CaptchaDetected {
                        captcha_type: captcha_type.clone(),
                    });
                }
                Detection::SoftBlock { .. } => {
                    if attempt >= max_attempts {
                        return Err(FetchError::Blocked { attempts: attempt });
                    }
                    sleep(self.retry_policy.compute_delay(attempt - 1)).await;
                }
            }
        }
    }

    pub async fn head_check(&self, url: &str) -> Option<u16> {
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::limited(3))
            .build()
            .ok()?;
        let headers = self.build_headers();
        let resp = client.get(url).headers(headers).send().await.ok()?;
        Some(resp.status().as_u16())
    }
}
