use crate::secrets::Severity;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderFinding {
    pub check: String,
    pub status: HeaderStatus,
    pub severity: Severity,
    pub details: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HeaderStatus {
    Pass,
    Fail,
    Warning,
    Info,
}

pub struct HeaderScanner;

impl HeaderScanner {
    pub fn scan(headers: &[(String, String)], status_code: u16) -> Vec<HeaderFinding> {
        let mut f = Vec::new();
        Self::check_hsts(headers, &mut f);
        Self::check_csp(headers, &mut f);
        Self::check_x_content_type(headers, &mut f);
        Self::check_x_frame_options(headers, &mut f);
        Self::check_permissions_policy(headers, &mut f);
        Self::check_referrer_policy(headers, &mut f);
        Self::check_server_disclosure(headers, &mut f);
        Self::check_powered_by(headers, &mut f);
        Self::check_cors(headers, &mut f);
        Self::check_cookies(headers, &mut f);
        if status_code >= 500 {
            f.push(HeaderFinding {
                check: "Server Error".into(),
                status: HeaderStatus::Warning,
                severity: Severity::Medium,
                details: format!("Status {}", status_code),
                recommendation: "May leak stack traces".into(),
            });
        }
        f
    }

    fn get<'a>(h: &'a [(String, String)], name: &str) -> Option<&'a str> {
        h.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn check_hsts(h: &[(String, String)], f: &mut Vec<HeaderFinding>) {
        match Self::get(h, "strict-transport-security") {
            Some(v) => f.push(HeaderFinding {
                check: "HSTS".into(),
                status: HeaderStatus::Pass,
                severity: Severity::Info,
                details: v.to_string(),
                recommendation: String::new(),
            }),
            None => f.push(HeaderFinding {
                check: "HSTS".into(),
                status: HeaderStatus::Fail,
                severity: Severity::High,
                details: "Missing".into(),
                recommendation:
                    "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains".into(),
            }),
        }
    }

    fn check_csp(h: &[(String, String)], f: &mut Vec<HeaderFinding>) {
        match Self::get(h, "content-security-policy") {
            Some(v) => {
                let mut issues = Vec::new();
                if v.contains("unsafe-inline") {
                    issues.push("unsafe-inline");
                }
                if v.contains("unsafe-eval") {
                    issues.push("unsafe-eval");
                }
                if issues.is_empty() {
                    f.push(HeaderFinding {
                        check: "CSP".into(),
                        status: HeaderStatus::Pass,
                        severity: Severity::Info,
                        details: if v.len() > 80 {
                            format!("{}…", &v[..80])
                        } else {
                            v.to_string()
                        },
                        recommendation: String::new(),
                    });
                } else {
                    f.push(HeaderFinding {
                        check: "CSP".into(),
                        status: HeaderStatus::Warning,
                        severity: Severity::Medium,
                        details: format!("Weak: {}", issues.join(", ")),
                        recommendation: "Remove unsafe-inline/unsafe-eval".into(),
                    });
                }
            }
            None => f.push(HeaderFinding {
                check: "CSP".into(),
                status: HeaderStatus::Fail,
                severity: Severity::Medium,
                details: "Missing".into(),
                recommendation: "Add Content-Security-Policy header".into(),
            }),
        }
    }

    fn check_x_content_type(h: &[(String, String)], f: &mut Vec<HeaderFinding>) {
        match Self::get(h, "x-content-type-options") {
            Some(v) if v.eq_ignore_ascii_case("nosniff") => f.push(HeaderFinding {
                check: "X-Content-Type-Options".into(),
                status: HeaderStatus::Pass,
                severity: Severity::Info,
                details: "nosniff".into(),
                recommendation: String::new(),
            }),
            _ => f.push(HeaderFinding {
                check: "X-Content-Type-Options".into(),
                status: HeaderStatus::Fail,
                severity: Severity::Medium,
                details: "Missing".into(),
                recommendation: "Add: X-Content-Type-Options: nosniff".into(),
            }),
        }
    }

    fn check_x_frame_options(h: &[(String, String)], f: &mut Vec<HeaderFinding>) {
        let csp = Self::get(h, "content-security-policy").unwrap_or("");
        if csp.contains("frame-ancestors") {
            return;
        }
        if Self::get(h, "x-frame-options").is_none() {
            f.push(HeaderFinding {
                check: "X-Frame-Options".into(),
                status: HeaderStatus::Fail,
                severity: Severity::Medium,
                details: "Missing".into(),
                recommendation: "Add: X-Frame-Options: DENY".into(),
            });
        }
    }

    fn check_permissions_policy(h: &[(String, String)], f: &mut Vec<HeaderFinding>) {
        if Self::get(h, "permissions-policy").is_none() {
            f.push(HeaderFinding {
                check: "Permissions-Policy".into(),
                status: HeaderStatus::Warning,
                severity: Severity::Low,
                details: "Missing".into(),
                recommendation: "Add Permissions-Policy header".into(),
            });
        }
    }

    fn check_referrer_policy(h: &[(String, String)], f: &mut Vec<HeaderFinding>) {
        if Self::get(h, "referrer-policy").is_none() {
            f.push(HeaderFinding {
                check: "Referrer-Policy".into(),
                status: HeaderStatus::Warning,
                severity: Severity::Low,
                details: "Missing".into(),
                recommendation: "Add: Referrer-Policy: strict-origin-when-cross-origin".into(),
            });
        }
    }

    fn check_server_disclosure(h: &[(String, String)], f: &mut Vec<HeaderFinding>) {
        if let Some(v) = Self::get(h, "server") {
            if v.chars().any(|c| c.is_ascii_digit()) {
                f.push(HeaderFinding {
                    check: "Server Disclosure".into(),
                    status: HeaderStatus::Warning,
                    severity: Severity::Low,
                    details: format!("Server: {}", v),
                    recommendation: "Remove version from Server header".into(),
                });
            }
        }
    }

    fn check_powered_by(h: &[(String, String)], f: &mut Vec<HeaderFinding>) {
        if let Some(v) = Self::get(h, "x-powered-by") {
            f.push(HeaderFinding {
                check: "X-Powered-By".into(),
                status: HeaderStatus::Fail,
                severity: Severity::Medium,
                details: format!("Exposes: {}", v),
                recommendation: "Remove X-Powered-By header".into(),
            });
        }
    }

    fn check_cors(h: &[(String, String)], f: &mut Vec<HeaderFinding>) {
        if let Some(v) = Self::get(h, "access-control-allow-origin") {
            if v == "*" {
                f.push(HeaderFinding {
                    check: "CORS".into(),
                    status: HeaderStatus::Warning,
                    severity: Severity::Medium,
                    details: "Wildcard origin: *".into(),
                    recommendation: "Restrict to specific domains".into(),
                });
            }
        }
    }

    fn check_cookies(h: &[(String, String)], f: &mut Vec<HeaderFinding>) {
        for (_, val) in h
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
        {
            let lower = val.to_lowercase();
            let mut issues = Vec::new();
            if !lower.contains("httponly") {
                issues.push("no HttpOnly");
            }
            if !lower.contains("secure") {
                issues.push("no Secure");
            }
            if !lower.contains("samesite") {
                issues.push("no SameSite");
            }
            if !issues.is_empty() {
                let name = val.split('=').next().unwrap_or("?");
                f.push(HeaderFinding {
                    check: "Cookie Security".into(),
                    status: HeaderStatus::Warning,
                    severity: Severity::Medium,
                    details: format!("'{}': {}", name, issues.join(", ")),
                    recommendation: "Add HttpOnly, Secure, SameSite flags".into(),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn h(p: &[(&str, &str)]) -> Vec<(String, String)> {
        p.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn test_missing_hsts() {
        let f = HeaderScanner::scan(&h(&[]), 200);
        assert!(f
            .iter()
            .any(|x| x.check == "HSTS" && x.status == HeaderStatus::Fail));
    }

    #[test]
    fn test_server_disclosure() {
        let f = HeaderScanner::scan(&h(&[("server", "Apache/2.4.41")]), 200);
        assert!(f.iter().any(|x| x.check == "Server Disclosure"));
    }

    #[test]
    fn test_x_powered_by() {
        let f = HeaderScanner::scan(&h(&[("x-powered-by", "Express")]), 200);
        assert!(f.iter().any(|x| x.check == "X-Powered-By"));
    }

    #[test]
    fn test_cors_wildcard() {
        let f = HeaderScanner::scan(&h(&[("access-control-allow-origin", "*")]), 200);
        assert!(f
            .iter()
            .any(|x| x.check == "CORS" && x.status == HeaderStatus::Warning));
    }
}
