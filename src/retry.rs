use std::{
    sync::atomic::{AtomicI64, Ordering},
    time::Duration,
};

use axum::http::{Method, StatusCode};

use crate::config::RetryConfig;

/// One retry costs a full token; a request deposits a fraction of one.
///
/// This is the Envoy-style retry budget: retries are allowed only as a
/// percentage of the traffic that is actually succeeding, so a total upstream
/// outage cannot be amplified into a retry storm.
const TOKEN: i64 = 1_000;
const MAX_TOKENS: i64 = 10_000;

pub(crate) struct RetryPolicy {
    pub(crate) max_attempts: u32,
    pub(crate) base_delay: Duration,
    budget: RetryBudget,
}

impl RetryPolicy {
    pub(crate) fn new(config: &RetryConfig) -> Self {
        Self {
            max_attempts: config.max_attempts,
            base_delay: config.base_delay,
            budget: RetryBudget::new(config.budget_ratio),
        }
    }

    /// Called once per proxied request, whether or not it is retried.
    pub(crate) fn deposit(&self) {
        self.budget.deposit();
    }

    /// Withdraws one retry from the budget. False means "do not retry, serve
    /// what you have" so the gateway sheds instead of amplifying.
    pub(crate) fn try_retry(&self) -> bool {
        self.budget.try_withdraw()
    }

    /// Exponential backoff with full jitter, capped at one second.
    pub(crate) fn delay(&self, attempt: u32) -> Duration {
        let exponent = attempt.saturating_sub(1).min(4);
        let ceiling = self
            .base_delay
            .saturating_mul(1 << exponent)
            .min(Duration::from_secs(1));

        let jitter = fastrand::f64();

        ceiling.mul_f64(jitter)
    }

    pub(crate) fn should_retry_status(status: StatusCode) -> bool {
        matches!(
            status,
            StatusCode::BAD_GATEWAY | StatusCode::SERVICE_UNAVAILABLE | StatusCode::GATEWAY_TIMEOUT
        )
    }
}

/// A retry is only safe when the request can be sent again unchanged.
///
/// Bodies stream, so a request with a body cannot be replayed without
/// buffering it. `Idempotency-Key` opts a bodiless POST into retries.
pub(crate) fn is_replayable(method: &Method, has_body: bool, has_idempotency_key: bool) -> bool {
    if has_body {
        return false;
    }

    match *method {
        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE => true,
        Method::PUT | Method::DELETE => true,
        Method::POST => has_idempotency_key,
        _ => false,
    }
}

struct RetryBudget {
    balance: AtomicI64,
    per_request: i64,
}

impl RetryBudget {
    fn new(ratio: f64) -> Self {
        Self {
            balance: AtomicI64::new(0),
            per_request: (ratio * TOKEN as f64) as i64,
        }
    }

    fn deposit(&self) {
        let mut current = self.balance.load(Ordering::Relaxed);

        loop {
            let next = (current + self.per_request).min(MAX_TOKENS);

            match self.balance.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(observed) => current = observed,
            }
        }
    }

    fn try_withdraw(&self) -> bool {
        let mut current = self.balance.load(Ordering::Relaxed);

        loop {
            if current < TOKEN {
                return false;
            }

            match self.balance.compare_exchange_weak(
                current,
                current - TOKEN,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(observed) => current = observed,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(attempts: u32, ratio: f64) -> RetryPolicy {
        RetryPolicy::new(&RetryConfig {
            max_attempts: attempts,
            base_delay: Duration::from_millis(10),
            budget_ratio: ratio,
        })
    }

    #[test]
    fn only_idempotent_requests_without_bodies_are_replayable() {
        assert!(is_replayable(&Method::GET, false, false));
        assert!(is_replayable(&Method::PUT, false, false));
        assert!(is_replayable(&Method::DELETE, false, false));

        assert!(
            !is_replayable(&Method::GET, true, false),
            "body cannot be replayed"
        );
        assert!(
            !is_replayable(&Method::POST, false, false),
            "POST is not idempotent"
        );
        assert!(is_replayable(&Method::POST, false, true), "explicit opt-in");
        assert!(
            !is_replayable(&Method::POST, true, true),
            "still cannot replay a body"
        );
    }

    #[test]
    fn retries_only_transient_upstream_failures() {
        assert!(RetryPolicy::should_retry_status(StatusCode::BAD_GATEWAY));
        assert!(RetryPolicy::should_retry_status(
            StatusCode::SERVICE_UNAVAILABLE
        ));
        assert!(RetryPolicy::should_retry_status(
            StatusCode::GATEWAY_TIMEOUT
        ));

        assert!(!RetryPolicy::should_retry_status(
            StatusCode::INTERNAL_SERVER_ERROR
        ));
        assert!(!RetryPolicy::should_retry_status(
            StatusCode::TOO_MANY_REQUESTS
        ));
        assert!(!RetryPolicy::should_retry_status(StatusCode::NOT_FOUND));
    }

    #[test]
    fn budget_accrues_before_allowing_a_retry() {
        let policy = policy(2, 0.2);

        assert!(!policy.try_retry(), "no traffic yet, no retries");

        for _ in 0..5 {
            policy.deposit();
        }

        assert!(policy.try_retry(), "five requests fund one retry");
        assert!(!policy.try_retry(), "budget spent");
    }

    #[test]
    fn budget_is_capped() {
        let policy = policy(2, 100.0);

        for _ in 0..1_000 {
            policy.deposit();
        }

        let mut allowed = 0;

        while policy.try_retry() {
            allowed += 1;
        }

        assert_eq!(allowed, (MAX_TOKENS / TOKEN) as usize);
    }

    #[test]
    fn backoff_grows_and_is_bounded() {
        let policy = policy(5, 0.2);

        for attempt in 1..=6 {
            let delay = policy.delay(attempt);
            assert!(delay <= Duration::from_secs(1));
        }

        assert!(policy.delay(1) <= Duration::from_millis(10));
    }
}
