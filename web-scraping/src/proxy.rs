use rand::seq::SliceRandom;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

const COOLDOWN_DURATION: Duration = Duration::from_secs(60);
const MAX_CONSECUTIVE_FAILURES: u32 = 5;

#[derive(Debug, Clone)]
pub struct ProxyEntry {
    pub url: String,
    pub consecutive_failures: u32,
    pub total_requests: u64,
    pub total_failures: u64,
    pub last_used: Option<Instant>,
    pub cooldown_until: Option<Instant>,
}

impl ProxyEntry {
    pub fn new(url: String) -> Self {
        Self {
            url,
            consecutive_failures: 0,
            total_requests: 0,
            total_failures: 0,
            last_used: None,
            cooldown_until: None,
        }
    }

    pub fn is_available(&self) -> bool {
        if self.consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
            return false;
        }
        match self.cooldown_until {
            Some(until) => Instant::now() >= until,
            None => true,
        }
    }

    pub fn health_weight(&self) -> f64 {
        if self.total_requests == 0 {
            return 1.0;
        }
        let success_rate = 1.0 - (self.total_failures as f64 / self.total_requests as f64);
        let recency_penalty = if self.consecutive_failures > 0 {
            0.5_f64.powi(self.consecutive_failures as i32)
        } else {
            1.0
        };
        success_rate * recency_penalty
    }
}

pub struct ProxyPool {
    proxies: Mutex<Vec<ProxyEntry>>,
}

impl ProxyPool {
    pub fn new(proxy_urls: Vec<String>) -> Self {
        let proxies = proxy_urls.into_iter().map(ProxyEntry::new).collect();
        Self {
            proxies: Mutex::new(proxies),
        }
    }

    pub fn next(&self) -> Option<ProxyEntry> {
        let mut proxies = self.proxies.lock().unwrap();
        let available: Vec<usize> = proxies
            .iter()
            .enumerate()
            .filter(|(_, p)| p.is_available())
            .map(|(i, _)| i)
            .collect();

        if available.is_empty() {
            warn!("No available proxies in pool");
            return None;
        }

        let weights: Vec<f64> = available
            .iter()
            .map(|&i| proxies[i].health_weight())
            .collect();
        let total_weight: f64 = weights.iter().sum();

        if total_weight <= 0.0 {
            let &idx = available.choose(&mut rand::thread_rng())?;
            proxies[idx].last_used = Some(Instant::now());
            proxies[idx].total_requests += 1;
            return Some(proxies[idx].clone());
        }

        let mut rng = rand::thread_rng();
        let threshold: f64 = rand::Rng::gen_range(&mut rng, 0.0..total_weight);
        let mut cumulative = 0.0;

        for (wi, &idx) in available.iter().enumerate() {
            cumulative += weights[wi];
            if cumulative >= threshold {
                proxies[idx].last_used = Some(Instant::now());
                proxies[idx].total_requests += 1;
                debug!(proxy = %proxies[idx].url, weight = weights[wi], "Selected proxy");
                return Some(proxies[idx].clone());
            }
        }

        None
    }

    pub fn report_success(&self, proxy_url: &str) {
        let mut proxies = self.proxies.lock().unwrap();
        if let Some(proxy) = proxies.iter_mut().find(|p| p.url == proxy_url) {
            proxy.consecutive_failures = 0;
            proxy.cooldown_until = None;
            debug!(proxy = %proxy_url, "Proxy success reported");
        }
    }

    pub fn report_failure(&self, proxy_url: &str) {
        let mut proxies = self.proxies.lock().unwrap();
        if let Some(proxy) = proxies.iter_mut().find(|p| p.url == proxy_url) {
            proxy.consecutive_failures += 1;
            proxy.total_failures += 1;
            if proxy.consecutive_failures >= 3 {
                proxy.cooldown_until = Some(Instant::now() + COOLDOWN_DURATION);
                warn!(
                    proxy = %proxy_url,
                    failures = proxy.consecutive_failures,
                    "Proxy placed in cooldown"
                );
            }
        }
    }

    pub fn available_count(&self) -> usize {
        let proxies = self.proxies.lock().unwrap();
        proxies.iter().filter(|p| p.is_available()).count()
    }

    pub fn is_empty(&self) -> bool {
        let proxies = self.proxies.lock().unwrap();
        proxies.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_pool_creation() {
        let pool = ProxyPool::new(vec![
            "http://proxy1:8080".to_string(),
            "http://proxy2:8080".to_string(),
        ]);
        assert_eq!(pool.available_count(), 2);
    }

    #[test]
    fn test_proxy_selection() {
        let pool = ProxyPool::new(vec!["http://proxy1:8080".to_string()]);
        let proxy = pool.next();
        assert!(proxy.is_some());
        assert_eq!(proxy.unwrap().url, "http://proxy1:8080");
    }

    #[test]
    fn test_proxy_failure_tracking() {
        let pool = ProxyPool::new(vec!["http://proxy1:8080".to_string()]);
        pool.report_failure("http://proxy1:8080");
        pool.report_failure("http://proxy1:8080");
        pool.report_failure("http://proxy1:8080");
        assert_eq!(pool.available_count(), 0);
    }

    #[test]
    fn test_proxy_recovery() {
        let pool = ProxyPool::new(vec!["http://proxy1:8080".to_string()]);
        pool.report_failure("http://proxy1:8080");
        pool.report_success("http://proxy1:8080");
        assert_eq!(pool.available_count(), 1);
    }

    #[test]
    fn test_empty_pool() {
        let pool = ProxyPool::new(vec![]);
        assert!(pool.next().is_none());
        assert!(pool.is_empty());
    }

    #[test]
    fn test_health_weight() {
        let mut entry = ProxyEntry::new("http://test:8080".to_string());
        assert_eq!(entry.health_weight(), 1.0);

        entry.total_requests = 10;
        entry.total_failures = 2;
        let weight = entry.health_weight();
        assert!(weight > 0.7 && weight <= 0.8);
    }
}
