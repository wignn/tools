use crate::anti_bot::Detection;
use rand::Rng;
use std::future::Future;
use std::time::Duration;
use thiserror::Error;
use tokio::time::sleep;
use tracing::{debug, warn};

#[derive(Debug, Clone)]
pub struct RetryPolicy {
    pub max_retries: u32,
    pub base_delay: Duration,
    pub max_delay: Duration,
    pub jitter_factor: f64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(30),
            jitter_factor: 0.3,
        }
    }
}

#[derive(Debug, Error)]
pub enum RetryError<E: std::fmt::Debug> {
    #[error("Max retries ({max_retries}) exhausted after {attempts} attempts: {last_error:?}")]
    Exhausted {
        attempts: u32,
        max_retries: u32,
        last_error: E,
    },

    #[error("Non-retryable error: {0:?}")]
    NonRetryable(E),
}

impl RetryPolicy {
    pub fn new(max_retries: u32, base_delay_ms: u64, max_delay_ms: u64, jitter: f64) -> Self {
        Self {
            max_retries,
            base_delay: Duration::from_millis(base_delay_ms),
            max_delay: Duration::from_millis(max_delay_ms),
            jitter_factor: jitter.clamp(0.0, 1.0),
        }
    }

    pub fn compute_delay(&self, attempt: u32) -> Duration {
        let base_ms = self.base_delay.as_millis() as f64;
        let exponential = base_ms * 2.0_f64.powi(attempt as i32);
        let capped = exponential.min(self.max_delay.as_millis() as f64);

        let mut rng = rand::thread_rng();
        let jitter_range = capped * self.jitter_factor;
        let jitter = rng.gen_range(-jitter_range..=jitter_range);
        let final_ms = (capped + jitter).max(0.0) as u64;

        Duration::from_millis(final_ms)
    }

    pub async fn execute<F, Fut, T, E>(&self, mut operation: F) -> Result<T, RetryError<E>>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T, E>>,
        E: std::fmt::Debug,
    {
        let mut attempt = 0;

        loop {
            match operation().await {
                Ok(result) => {
                    if attempt > 0 {
                        debug!(attempt = attempt, "Succeeded after retry");
                    }
                    return Ok(result);
                }
                Err(err) => {
                    attempt += 1;
                    if attempt > self.max_retries {
                        warn!(
                            attempts = attempt,
                            max_retries = self.max_retries,
                            "Retries exhausted"
                        );
                        return Err(RetryError::Exhausted {
                            attempts: attempt,
                            max_retries: self.max_retries,
                            last_error: err,
                        });
                    }

                    let delay = self.compute_delay(attempt - 1);
                    debug!(
                        attempt = attempt,
                        delay_ms = delay.as_millis() as u64,
                        "Retrying after error"
                    );
                    sleep(delay).await;
                }
            }
        }
    }

    pub fn delay_for_detection(&self, detection: &Detection, attempt: u32) -> Option<Duration> {
        match detection {
            Detection::RateLimited { retry_after_secs } => {
                let base = retry_after_secs
                    .map(Duration::from_secs)
                    .unwrap_or_else(|| self.compute_delay(attempt));
                Some(base)
            }
            Detection::SoftBlock { .. } => Some(self.compute_delay(attempt)),
            Detection::Blocked | Detection::CaptchaDetected { .. } => None,
            Detection::Clean => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exponential_backoff_growth() {
        let policy = RetryPolicy::new(5, 1000, 60000, 0.0);
        let d0 = policy.compute_delay(0).as_millis();
        let d1 = policy.compute_delay(1).as_millis();
        let d2 = policy.compute_delay(2).as_millis();
        assert_eq!(d0, 1000);
        assert_eq!(d1, 2000);
        assert_eq!(d2, 4000);
    }

    #[test]
    fn test_delay_capping() {
        let policy = RetryPolicy::new(10, 1000, 5000, 0.0);
        let d10 = policy.compute_delay(10);
        assert!(d10.as_millis() <= 5000);
    }

    #[test]
    fn test_jitter_applied() {
        let policy = RetryPolicy::new(3, 1000, 30000, 0.5);
        let delays: Vec<u128> = (0..20)
            .map(|_| policy.compute_delay(2).as_millis())
            .collect();
        let all_same = delays.iter().all(|&d| d == delays[0]);
        assert!(!all_same, "Jitter should produce varying delays");
    }

    #[tokio::test]
    async fn test_retry_success_first_try() {
        let policy = RetryPolicy::default();
        let result: Result<i32, RetryError<&str>> =
            policy.execute(|| async { Ok::<i32, &str>(42) }).await;
        assert_eq!(result.unwrap(), 42);
    }

    #[tokio::test]
    async fn test_retry_exhaustion() {
        let policy = RetryPolicy::new(2, 10, 100, 0.0);
        let result: Result<i32, RetryError<&str>> =
            policy.execute(|| async { Err::<i32, &str>("fail") }).await;
        assert!(matches!(
            result,
            Err(RetryError::Exhausted { attempts: 3, .. })
        ));
    }

    #[tokio::test]
    async fn test_retry_eventual_success() {
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let policy = RetryPolicy::new(3, 10, 100, 0.0);
        let c = counter.clone();
        let result: Result<i32, RetryError<&str>> = policy
            .execute(|| {
                let c = c.clone();
                async move {
                    let n = c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if n < 2 {
                        Err("not yet")
                    } else {
                        Ok(99)
                    }
                }
            })
            .await;
        assert_eq!(result.unwrap(), 99);
        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 3);
    }

    #[test]
    fn test_delay_for_rate_limited() {
        let policy = RetryPolicy::default();
        let d = policy.delay_for_detection(
            &Detection::RateLimited {
                retry_after_secs: Some(10),
            },
            0,
        );
        assert_eq!(d.unwrap(), Duration::from_secs(10));
    }

    #[test]
    fn test_delay_for_blocked_is_none() {
        let policy = RetryPolicy::default();
        let d = policy.delay_for_detection(&Detection::Blocked, 0);
        assert!(d.is_none());
    }
}
