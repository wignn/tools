use regex::Regex;
use reqwest::header::HeaderMap;
use reqwest::StatusCode;
use std::sync::LazyLock;
use tracing::{debug, warn};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Detection {
    Clean,
    RateLimited { retry_after_secs: Option<u64> },
    Blocked,
    CaptchaDetected { captcha_type: CaptchaType },
    SoftBlock { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptchaType {
    ReCaptcha,
    HCaptcha,
    Cloudflare,
    DataDome,
    Unknown,
}

static CAPTCHA_PATTERNS: LazyLock<Vec<(Regex, CaptchaType)>> = LazyLock::new(|| {
    vec![
        (
            Regex::new(r"(?i)google\.com/recaptcha").unwrap(),
            CaptchaType::ReCaptcha,
        ),
        (
            Regex::new(r"(?i)www\.google\.com/recaptcha").unwrap(),
            CaptchaType::ReCaptcha,
        ),
        (
            Regex::new(r"(?i)g-recaptcha").unwrap(),
            CaptchaType::ReCaptcha,
        ),
        (
            Regex::new(r"(?i)grecaptcha").unwrap(),
            CaptchaType::ReCaptcha,
        ),
        (
            Regex::new(r"(?i)hcaptcha\.com").unwrap(),
            CaptchaType::HCaptcha,
        ),
        (Regex::new(r"(?i)h-captcha").unwrap(), CaptchaType::HCaptcha),
        (
            Regex::new(r"(?i)cf-challenge").unwrap(),
            CaptchaType::Cloudflare,
        ),
        (
            Regex::new(r"(?i)cloudflare").unwrap(),
            CaptchaType::Cloudflare,
        ),
        (
            Regex::new(r"(?i)cf-chl-bypass").unwrap(),
            CaptchaType::Cloudflare,
        ),
        (Regex::new(r"(?i)__cf_bm").unwrap(), CaptchaType::Cloudflare),
        (
            Regex::new(r"(?i)cdn-cgi/challenge-platform").unwrap(),
            CaptchaType::Cloudflare,
        ),
        (Regex::new(r"(?i)datadome").unwrap(), CaptchaType::DataDome),
        (Regex::new(r"(?i)captcha").unwrap(), CaptchaType::Unknown),
    ]
});

static SOFT_BLOCK_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"(?i)access\s+denied").unwrap(),
        Regex::new(r"(?i)please\s+verify\s+you\s+are\s+a?\s*human").unwrap(),
        Regex::new(r"(?i)unusual\s+traffic").unwrap(),
        Regex::new(r"(?i)automated\s+access").unwrap(),
        Regex::new(r"(?i)bot\s+detected").unwrap(),
        Regex::new(r"(?i)suspicious\s+activity").unwrap(),
        Regex::new(r"(?i)rate\s+limit\s+exceeded").unwrap(),
        Regex::new(r"(?i)too\s+many\s+requests").unwrap(),
    ]
});

pub struct AntiBot;

impl AntiBot {
    pub fn analyze(status: StatusCode, headers: &HeaderMap, body: &str) -> Detection {
        if status == StatusCode::TOO_MANY_REQUESTS {
            let retry_after = headers
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok());
            warn!(retry_after = ?retry_after, "Rate limited (429)");
            return Detection::RateLimited {
                retry_after_secs: retry_after,
            };
        }

        if status == StatusCode::FORBIDDEN {
            for (pattern, captcha_type) in CAPTCHA_PATTERNS.iter() {
                if pattern.is_match(body) {
                    warn!(captcha_type = ?captcha_type, "Captcha detected on 403 page");
                    return Detection::CaptchaDetected {
                        captcha_type: captcha_type.clone(),
                    };
                }
            }
            warn!("Blocked (403) without captcha");
            return Detection::Blocked;
        }

        if status.is_success() {
            for (pattern, captcha_type) in CAPTCHA_PATTERNS.iter() {
                if pattern.is_match(body) {
                    if matches!(captcha_type, CaptchaType::Unknown) {
                        continue;
                    }
                    warn!(captcha_type = ?captcha_type, "Captcha detected on 200 page");
                    return Detection::CaptchaDetected {
                        captcha_type: captcha_type.clone(),
                    };
                }
            }

            for pattern in SOFT_BLOCK_PATTERNS.iter() {
                if pattern.is_match(body) {
                    let reason = pattern.to_string();
                    debug!(pattern = %reason, "Soft block pattern matched");
                    return Detection::SoftBlock { reason };
                }
            }
        }

        if status.is_server_error() {
            return Detection::SoftBlock {
                reason: format!("Server error: {}", status),
            };
        }

        Detection::Clean
    }

    pub fn should_retry(detection: &Detection) -> bool {
        matches!(
            detection,
            Detection::RateLimited { .. } | Detection::SoftBlock { .. }
        )
    }

    pub fn should_rotate_proxy(detection: &Detection) -> bool {
        matches!(
            detection,
            Detection::Blocked | Detection::CaptchaDetected { .. } | Detection::RateLimited { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_headers() -> HeaderMap {
        HeaderMap::new()
    }

    #[test]
    fn test_clean_response() {
        let result = AntiBot::analyze(StatusCode::OK, &empty_headers(), "<html>normal page</html>");
        assert_eq!(result, Detection::Clean);
    }

    #[test]
    fn test_rate_limited() {
        let result = AntiBot::analyze(
            StatusCode::TOO_MANY_REQUESTS,
            &empty_headers(),
            "rate limited",
        );
        assert!(matches!(result, Detection::RateLimited { .. }));
        assert!(AntiBot::should_retry(&result));
    }

    #[test]
    fn test_blocked_403() {
        let result = AntiBot::analyze(StatusCode::FORBIDDEN, &empty_headers(), "you are blocked");
        assert_eq!(result, Detection::Blocked);
        assert!(AntiBot::should_rotate_proxy(&result));
    }

    #[test]
    fn test_cloudflare_challenge() {
        let body = r#"<html><body>Checking if the site connection is secure. cf-challenge-platform</body></html>"#;
        let result = AntiBot::analyze(StatusCode::FORBIDDEN, &empty_headers(), body);
        assert!(matches!(
            result,
            Detection::CaptchaDetected {
                captcha_type: CaptchaType::Cloudflare
            }
        ));
    }

    #[test]
    fn test_recaptcha_detection() {
        let body = r#"<div class="g-recaptcha" data-sitekey="abc"></div>"#;
        let result = AntiBot::analyze(StatusCode::FORBIDDEN, &empty_headers(), body);
        assert!(matches!(
            result,
            Detection::CaptchaDetected {
                captcha_type: CaptchaType::ReCaptcha
            }
        ));
    }

    #[test]
    fn test_hcaptcha_detection() {
        let body = r#"<script src="https://hcaptcha.com/1/api.js"></script>"#;
        let result = AntiBot::analyze(StatusCode::FORBIDDEN, &empty_headers(), body);
        assert!(matches!(
            result,
            Detection::CaptchaDetected {
                captcha_type: CaptchaType::HCaptcha
            }
        ));
    }

    #[test]
    fn test_soft_block_on_200() {
        let body = "Access Denied. Please verify you are a human.";
        let result = AntiBot::analyze(StatusCode::OK, &empty_headers(), body);
        assert!(matches!(result, Detection::SoftBlock { .. }));
    }

    #[test]
    fn test_server_error() {
        let result = AntiBot::analyze(StatusCode::INTERNAL_SERVER_ERROR, &empty_headers(), "error");
        assert!(matches!(result, Detection::SoftBlock { .. }));
    }

    #[test]
    fn test_retry_decisions() {
        assert!(AntiBot::should_retry(&Detection::RateLimited {
            retry_after_secs: None
        }));
        assert!(AntiBot::should_retry(&Detection::SoftBlock {
            reason: "test".into()
        }));
        assert!(!AntiBot::should_retry(&Detection::Blocked));
        assert!(!AntiBot::should_retry(&Detection::Clean));
    }
}
