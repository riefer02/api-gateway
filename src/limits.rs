use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use crate::config::{LimitsConfig, RateLimitBackend};

/// Upstreams tracked by the in-process registries. The control plane can create
/// and delete them indefinitely; these maps must not grow with that history.
const MAX_TRACKED_UPSTREAMS: usize = 4_096;

/// Outcome of one rate-limit decision, rendered into response headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Decision {
    Allowed {
        remaining: u32,
        reset_after: Duration,
    },
    Denied {
        retry_after: Duration,
    },
}

/// In-process token buckets, sharded to avoid a global lock.
///
/// One bucket per key (`ip:<addr>`, `tenant:<id>`). Capacity equals the
/// per-minute allowance, so a client may burst a minute's worth and then is
/// paced. Per replica: N replicas enforce N times the configured rate, which
/// is documented in the README.
pub(crate) struct RateLimiter {
    shards: Vec<Mutex<Shard>>,
    capacity: f64,
    refill_per_second: f64,
    max_buckets_per_shard: usize,
}

struct Shard {
    buckets: HashMap<String, Bucket>,
    last_swept: Instant,
}

struct Bucket {
    tokens: f64,
    updated_at: Instant,
}

impl RateLimiter {
    pub(crate) fn new(per_minute: u32) -> Self {
        let capacity = f64::from(per_minute);

        Self::with_rates(capacity, capacity / 60.0)
    }

    /// Explicit capacity and refill rate. `new` derives the rate from the
    /// per-minute allowance; tests use this to observe a refill quickly.
    pub(crate) fn with_rates(capacity: f64, refill_per_second: f64) -> Self {
        const SHARDS: usize = 16;

        Self {
            shards: (0..SHARDS)
                .map(|_| {
                    Mutex::new(Shard {
                        buckets: HashMap::new(),
                        last_swept: Instant::now(),
                    })
                })
                .collect(),
            capacity,
            refill_per_second,
            max_buckets_per_shard: 4_096,
        }
    }

    pub(crate) fn check(&self, key: &str) -> Decision {
        let now = Instant::now();
        let mut shard = self
            .shard(key)
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // Sweep on time, never on occupancy: a full shard of live buckets must
        // not turn every request into a full scan.
        if now.saturating_duration_since(shard.last_swept) > Duration::from_secs(30) {
            evict_idle(&mut shard.buckets, now);
            shard.last_swept = now;
        }

        // A caller-controlled key (especially a source IP) must not grow the
        // map without bound between sweeps.
        if shard.buckets.len() >= self.max_buckets_per_shard {
            evict_idle(&mut shard.buckets, now);

            if shard.buckets.len() >= self.max_buckets_per_shard
                && let Some(oldest) = shard.buckets.keys().next().cloned()
            {
                shard.buckets.remove(&oldest);
            }
        }

        let bucket = shard
            .buckets
            .entry(key.to_owned())
            .or_insert(Bucket {
                tokens: self.capacity,
                updated_at: now,
            });

        let elapsed = now
            .saturating_duration_since(bucket.updated_at)
            .as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.refill_per_second).min(self.capacity);
        bucket.updated_at = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;

            Decision::Allowed {
                remaining: bucket.tokens as u32,
                reset_after: self.time_to_full(bucket.tokens),
            }
        } else {
            Decision::Denied {
                retry_after: self.time_until_one_token(bucket.tokens),
            }
        }
    }

    fn time_to_full(&self, tokens: f64) -> Duration {
        let missing = (self.capacity - tokens).max(0.0);
        Duration::from_secs_f64(missing / self.refill_per_second)
    }

    pub(crate) fn limit(&self) -> u32 {
        self.capacity as u32
    }

    fn time_until_one_token(&self, tokens: f64) -> Duration {
        let missing = (1.0 - tokens).max(0.0);
        Duration::from_secs_f64(missing / self.refill_per_second).max(Duration::from_secs(1))
    }

    fn shard(&self, key: &str) -> &Mutex<Shard> {
        // FNV-1a: stable and cheap; shard choice only needs to be uniform.
        let mut hash = 0xcbf2_9ce4_8422_2325_u64;

        for byte in key.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }

        &self.shards[(hash as usize) % self.shards.len()]
    }
}

fn evict_idle(shard: &mut HashMap<String, Bucket>, now: Instant) {
    let idle = Duration::from_secs(600);

    shard.retain(|_, bucket| now.saturating_duration_since(bucket.updated_at) < idle);
}

/// The limits the gateway enforces, each disabled by setting it to zero.
pub(crate) struct RateLimits {
    pub(crate) ip: Option<RateLimiter>,
    pub(crate) tenant: Option<RateLimiter>,
    pub(crate) user: Option<RateLimiter>,
    /// Keyed by `tenant:tool`. Bounds one tenant monopolising a single tool,
    /// which the tenant-wide limit cannot see.
    pub(crate) tool: Option<RateLimiter>,
}

impl RateLimits {
    pub(crate) fn new(config: &LimitsConfig) -> Self {
        // One place to add a distributed backend later: the config already
        // rejects anything but `local`, so this match stays exhaustive.
        let limiter = |per_minute: u32| -> Option<RateLimiter> {
            match config.backend {
                RateLimitBackend::Local => (per_minute > 0).then(|| RateLimiter::new(per_minute)),
            }
        };

        Self {
            ip: limiter(config.ip_per_minute),
            tenant: limiter(config.tenant_per_minute),
            user: limiter(config.user_per_minute),
            tool: limiter(config.tool_per_minute),
        }
    }
}

/// Per-upstream circuit breaker.
///
/// Consecutive failures open the circuit for a cooldown; the first request
/// after the cooldown is a half-open probe that either closes or re-opens it.
pub(crate) struct BreakerRegistry {
    breakers: Mutex<HashMap<String, Breaker>>,
    failure_threshold: u32,
    cooldown: Duration,
}

struct Breaker {
    state: State,
}

enum State {
    Closed { failures: u32 },
    Open { until: Instant },
    HalfOpen { probing: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BreakerRejection {
    pub(crate) retry_after: Duration,
}

impl BreakerRegistry {
    pub(crate) fn new(config: &LimitsConfig) -> Self {
        Self {
            breakers: Mutex::new(HashMap::new()),
            failure_threshold: config.circuit_failure_threshold,
            cooldown: config.circuit_cooldown,
        }
    }

    /// Allows the request, or rejects it while the circuit is open.
    pub(crate) fn check(&self, upstream: &str) -> Result<(), BreakerRejection> {
        let mut breakers = self.lock();

        // Upstream ids come from the control plane and change over time; the
        // registry must not grow with history. Resetting loses breaker state,
        // which is the safe direction: it forgets an outage rather than
        // remembering an id that no longer exists.
        if breakers.len() >= MAX_TRACKED_UPSTREAMS && !breakers.contains_key(upstream) {
            breakers.clear();
            tracing::warn!("breaker registry reached its cap; state reset");
        }

        let breaker = breakers
            .entry(upstream.to_owned())
            .or_insert_with(|| Breaker {
                state: State::Closed { failures: 0 },
            });

        match &mut breaker.state {
            State::Closed { .. } => Ok(()),
            // Exactly one request probes a recovered upstream; the rest are
            // rejected until the probe resolves. Otherwise a thundering herd
            // hits the upstream the moment the cooldown expires.
            State::HalfOpen { probing } => {
                if *probing {
                    Err(BreakerRejection {
                        retry_after: Duration::from_secs(1),
                    })
                } else {
                    *probing = true;
                    Ok(())
                }
            }
            State::Open { until } => {
                let now = Instant::now();

                if now >= *until {
                    breaker.state = State::HalfOpen { probing: true };
                    Ok(())
                } else {
                    Err(BreakerRejection {
                        retry_after: until.saturating_duration_since(now),
                    })
                }
            }
        }
    }

    pub(crate) fn record_success(&self, upstream: &str) {
        let mut breakers = self.lock();

        if let Some(breaker) = breakers.get_mut(upstream) {
            breaker.state = State::Closed { failures: 0 };
            return;
        }

        breakers.insert(
            upstream.to_owned(),
            Breaker {
                state: State::Closed { failures: 0 },
            },
        );
    }

    /// The request ended without an outcome (deadline or client disconnect).
    /// A half-open probe must be released or the circuit sticks, but a healthy
    /// upstream must not be charged for a caller that walked away.
    pub(crate) fn record_abandoned(&self, upstream: &str) {
        let mut breakers = self.lock();

        let Some(breaker) = breakers.get_mut(upstream) else {
            return;
        };

        if let State::HalfOpen { probing: true } = breaker.state {
            breaker.state = State::Open {
                until: Instant::now() + self.cooldown,
            };
        }
    }

    pub(crate) fn record_failure(&self, upstream: &str) {
        let mut breakers = self.lock();

        if breakers.len() >= MAX_TRACKED_UPSTREAMS && !breakers.contains_key(upstream) {
            breakers.clear();
            tracing::warn!("breaker registry reached its cap; state reset");
        }

        let breaker = breakers
            .entry(upstream.to_owned())
            .or_insert(Breaker {
                state: State::Closed { failures: 0 },
            });

        breaker.state = match breaker.state {
            State::Closed { failures } if failures + 1 >= self.failure_threshold => State::Open {
                until: Instant::now() + self.cooldown,
            },
            State::Closed { failures } => State::Closed {
                failures: failures + 1,
            },
            State::HalfOpen { .. } | State::Open { .. } => State::Open {
                until: Instant::now() + self.cooldown,
            },
        };
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Breaker>> {
        self.breakers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Records the eventual outcome of one request against the breaker, and fails
/// the breaker if the request is cancelled before it can report. Without this,
/// a probe killed by a deadline or a client disconnect would leave the circuit
/// half-open forever.
pub(crate) struct BreakerGuard<'a> {
    registry: &'a BreakerRegistry,
    upstream: &'a str,
    armed: bool,
}

impl<'a> BreakerGuard<'a> {
    pub(crate) fn new(registry: &'a BreakerRegistry, upstream: &'a str) -> Self {
        Self {
            registry,
            upstream,
            armed: true,
        }
    }

    pub(crate) fn record_success(&mut self) {
        self.registry
            .record_success(self.upstream);
        self.armed = false;
    }

    pub(crate) fn record_failure(&mut self) {
        self.registry
            .record_failure(self.upstream);
        self.armed = false;
    }
}

impl Drop for BreakerGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            // The request ended without an outcome: release a half-open probe
            // without charging a healthy upstream for a caller that walked away.
            self.registry
                .record_abandoned(self.upstream);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> LimitsConfig {
        LimitsConfig {
            ip_per_minute: 60,
            tenant_per_minute: 600,
            user_per_minute: 60,
            tool_per_minute: 0,
            circuit_failure_threshold: 2,
            circuit_cooldown: Duration::from_millis(50),
            backend: crate::config::RateLimitBackend::Local,
        }
    }

    fn routing(max_concurrency: usize, queue_timeout: Duration) -> crate::config::RoutingConfig {
        crate::config::RoutingConfig {
            allow_hosts: Vec::new(),
            refresh_interval: Duration::from_secs(2),
            egress: crate::net::Egress::AllowAll,
            pool_max_idle_per_host: 64,
            max_concurrency,
            queue_timeout,
        }
    }

    #[tokio::test]
    async fn a_bulkhead_admits_its_limit_and_then_sheds() {
        let bulkhead = BulkheadRegistry::new(&routing(1, Duration::ZERO)).expect("enabled");

        let first = bulkhead
            .acquire("upstream")
            .await
            .expect("first permit");

        assert!(
            bulkhead
                .acquire("upstream")
                .await
                .is_err(),
            "the second request must be refused while the first is in flight"
        );

        drop(first);

        assert!(
            bulkhead
                .acquire("upstream")
                .await
                .is_ok(),
            "the permit must be reusable once released"
        );
    }

    #[tokio::test]
    async fn a_bulkhead_queues_for_at_most_its_timeout() {
        let bulkhead =
            BulkheadRegistry::new(&routing(1, Duration::from_millis(20))).expect("enabled");
        let _held = bulkhead
            .acquire("upstream")
            .await
            .expect("first permit");

        assert!(
            bulkhead
                .acquire("upstream")
                .await
                .is_err()
        );
    }

    #[test]
    fn a_zero_concurrency_bulkhead_is_disabled() {
        assert!(BulkheadRegistry::new(&routing(0, Duration::ZERO)).is_none());
    }

    #[test]
    fn the_tool_limiter_exists_only_when_configured() {
        let mut config = limits();
        assert!(RateLimits::new(&config).tool.is_none());

        config.tool_per_minute = 5;
        assert_eq!(
            RateLimits::new(&config)
                .tool
                .as_ref()
                .map(RateLimiter::limit),
            Some(5)
        );
    }

    #[test]
    fn allows_a_burst_then_denies() {
        let limiter = RateLimiter::new(2);

        assert!(matches!(limiter.check("ip:a"), Decision::Allowed { .. }));
        assert!(matches!(limiter.check("ip:a"), Decision::Allowed { .. }));
        assert!(matches!(limiter.check("ip:a"), Decision::Denied { .. }));
    }

    #[test]
    fn keys_are_isolated() {
        let limiter = RateLimiter::new(1);

        assert!(matches!(limiter.check("ip:a"), Decision::Allowed { .. }));
        assert!(matches!(limiter.check("ip:b"), Decision::Allowed { .. }));
        assert!(matches!(limiter.check("ip:a"), Decision::Denied { .. }));
    }

    #[test]
    fn refills_over_time() {
        // One token, refilled a thousand times a second.
        let limiter = RateLimiter::with_rates(1.0, 1_000.0);

        assert!(matches!(limiter.check("ip:a"), Decision::Allowed { .. }));
        assert!(matches!(limiter.check("ip:a"), Decision::Denied { .. }));

        std::thread::sleep(Duration::from_millis(10));

        assert!(matches!(limiter.check("ip:a"), Decision::Allowed { .. }));
    }

    #[test]
    fn breaker_opens_after_consecutive_failures() {
        let registry = BreakerRegistry::new(&limits());

        registry.record_failure("upstream");
        assert!(registry.check("upstream").is_ok());

        registry.record_failure("upstream");
        let rejection = registry
            .check("upstream")
            .expect_err("circuit open");
        assert!(rejection.retry_after <= Duration::from_millis(50));
    }

    #[test]
    fn breaker_half_opens_after_cooldown() {
        let registry = BreakerRegistry::new(&limits());

        registry.record_failure("upstream");
        registry.record_failure("upstream");

        std::thread::sleep(Duration::from_millis(60));

        assert!(
            registry.check("upstream").is_ok(),
            "half-open probe allowed"
        );
    }

    #[test]
    fn only_one_half_open_probe_is_allowed() {
        let registry = BreakerRegistry::new(&limits());

        registry.record_failure("upstream");
        registry.record_failure("upstream");

        std::thread::sleep(Duration::from_millis(60));

        assert!(registry.check("upstream").is_ok(), "first probe allowed");
        assert!(
            registry.check("upstream").is_err(),
            "second probe rejected while the first is in flight"
        );

        registry.record_success("upstream");
        assert!(registry.check("upstream").is_ok(), "circuit closed again");
    }

    #[test]
    fn success_closes_the_breaker() {
        let registry = BreakerRegistry::new(&limits());

        registry.record_failure("upstream");
        registry.record_failure("upstream");
        registry.record_success("upstream");

        assert!(registry.check("upstream").is_ok());
        registry.record_failure("upstream");
        assert!(registry.check("upstream").is_ok(), "counter restarted");
    }
}

/// Per-upstream concurrency, the sibling of the circuit breaker.
///
/// The breaker reacts to an upstream that is already failing; a bulkhead keeps
/// one slow upstream from consuming the whole replica's connection budget while
/// it fails slowly. Permits are held until the response body finishes, not just
/// until the headers arrive, so a long stream counts as the concurrency it is.
pub(crate) struct BulkheadRegistry {
    bulkheads: Mutex<HashMap<String, Arc<tokio::sync::Semaphore>>>,
    permits: usize,
    queue_timeout: Duration,
}

impl BulkheadRegistry {
    pub(crate) fn new(config: &crate::config::RoutingConfig) -> Option<Self> {
        (config.max_concurrency > 0).then(|| Self {
            bulkheads: Mutex::new(HashMap::new()),
            permits: config.max_concurrency,
            queue_timeout: config.queue_timeout,
        })
    }

    /// Acquires a permit for one upstream, waiting up to the configured queue
    /// timeout. The returned permit must be held for the life of the response.
    pub(crate) async fn acquire(
        &self,
        upstream: &str,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, BulkheadRejection> {
        let semaphore = {
            let mut bulkheads = self
                .bulkheads
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());

            // Same reasoning as the breaker registry: in-flight permits keep
            // their own Arc, so dropping an idle entry is safe.
            if bulkheads.len() >= MAX_TRACKED_UPSTREAMS && !bulkheads.contains_key(upstream) {
                bulkheads.clear();
                tracing::warn!("bulkhead registry reached its cap; state reset");
            }

            Arc::clone(
                bulkheads
                    .entry(upstream.to_owned())
                    .or_insert_with(|| Arc::new(tokio::sync::Semaphore::new(self.permits))),
            )
        };

        if self.queue_timeout.is_zero() {
            return semaphore
                .try_acquire_owned()
                .map_err(|_| BulkheadRejection {
                    retry_after: Duration::from_secs(1),
                });
        }

        match tokio::time::timeout(self.queue_timeout, semaphore.acquire_owned()).await {
            Ok(Ok(permit)) => Ok(permit),
            // Closed means the registry was dropped; treat it as saturated
            // rather than as a panic.
            Ok(Err(_)) => Err(BulkheadRejection {
                retry_after: Duration::from_secs(1),
            }),
            Err(_) => Err(BulkheadRejection {
                retry_after: self
                    .queue_timeout
                    .max(Duration::from_secs(1)),
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BulkheadRejection {
    pub(crate) retry_after: Duration,
}
