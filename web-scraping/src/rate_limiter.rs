use governor::{Quota, RateLimiter as GovRateLimiter};
use nonzero_ext::nonzero;
use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};
use tracing::debug;

type Limiter = GovRateLimiter<
    governor::state::NotKeyed,
    governor::state::InMemoryState,
    governor::clock::DefaultClock,
>;

pub struct RateLimiter {
    default_rps: NonZeroU32,
    default_burst: NonZeroU32,
    domain_limiters: Arc<Mutex<HashMap<String, Arc<Limiter>>>>,
    domain_overrides: HashMap<String, (NonZeroU32, NonZeroU32)>,
}

impl RateLimiter {
    pub fn new(default_rps: u32, default_burst: u32) -> Self {
        Self {
            default_rps: NonZeroU32::new(default_rps).unwrap_or(nonzero!(5u32)),
            default_burst: NonZeroU32::new(default_burst).unwrap_or(nonzero!(10u32)),
            domain_limiters: Arc::new(Mutex::new(HashMap::new())),
            domain_overrides: HashMap::new(),
        }
    }

    pub fn set_domain_limit(&mut self, domain: String, rps: u32, burst: u32) {
        let rps = NonZeroU32::new(rps).unwrap_or(nonzero!(1u32));
        let burst = NonZeroU32::new(burst).unwrap_or(nonzero!(1u32));
        self.domain_overrides.insert(domain, (rps, burst));
    }

    fn get_or_create_limiter(&self, domain: &str) -> Arc<Limiter> {
        let mut limiters = self.domain_limiters.lock().unwrap();
        if let Some(limiter) = limiters.get(domain) {
            return Arc::clone(limiter);
        }

        let (rps, burst) = self
            .domain_overrides
            .get(domain)
            .copied()
            .unwrap_or((self.default_rps, self.default_burst));

        let quota = Quota::per_second(rps).allow_burst(burst);
        let limiter = Arc::new(GovRateLimiter::direct(quota));
        limiters.insert(domain.to_string(), Arc::clone(&limiter));
        debug!(domain = %domain, rps = %rps, burst = %burst, "Created rate limiter");
        limiter
    }

    pub async fn acquire(&self, domain: &str) {
        let limiter = self.get_or_create_limiter(domain);
        limiter.until_ready().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_creation() {
        let limiter = RateLimiter::new(10, 20);
        assert_eq!(limiter.default_rps.get(), 10);
        assert_eq!(limiter.default_burst.get(), 20);
    }

    #[test]
    fn test_domain_override() {
        let mut limiter = RateLimiter::new(10, 20);
        limiter.set_domain_limit("slow.com".to_string(), 1, 2);
        assert!(limiter.domain_overrides.contains_key("slow.com"));
    }

    #[tokio::test]
    async fn test_acquire_passes() {
        let limiter = RateLimiter::new(100, 100);
        limiter.acquire("example.com").await;
    }

    #[test]
    fn test_limiter_reuse() {
        let limiter = RateLimiter::new(5, 10);
        let l1 = limiter.get_or_create_limiter("example.com");
        let l2 = limiter.get_or_create_limiter("example.com");
        assert!(Arc::ptr_eq(&l1, &l2));
    }
}
