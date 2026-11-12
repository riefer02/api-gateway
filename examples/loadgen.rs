//! Closed-loop load generator used by `scripts/bench.sh`.
//!
//! Usage: loadgen <url> [seconds] [concurrency] [bearer-token]
//!
//! Prints one line: `requests=… rps=… p50=…ms p95=…ms p99=…ms errors=…`.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use tokio::sync::Mutex;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);

    let url = args
        .next()
        .ok_or("usage: loadgen <url> [seconds] [concurrency] [bearer-token]")?;

    let seconds = parse_arg::<u64>(args.next(), 10)?;
    let concurrency = parse_arg::<usize>(args.next(), 50)?;
    let token = args.next();

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .pool_max_idle_per_host(concurrency)
        .build()?;

    let deadline = Instant::now() + Duration::from_secs(seconds);
    let latencies = Arc::new(Mutex::new(Vec::<f64>::with_capacity(1 << 16)));
    let errors = Arc::new(AtomicU64::new(0));

    let mut workers = Vec::with_capacity(concurrency);

    for _ in 0..concurrency {
        let client = client.clone();
        let url = url.clone();
        let token = token.clone();
        let latencies = Arc::clone(&latencies);
        let errors = Arc::clone(&errors);

        workers.push(tokio::spawn(async move {
            let mut local = Vec::new();

            while Instant::now() < deadline {
                let mut request = client.get(&url);

                if let Some(token) = &token {
                    request = request.bearer_auth(token);
                }

                let started = Instant::now();

                match request.send().await {
                    // Drain the body: a gateway that streams slowly is not fast.
                    Ok(response) if response.status().is_success() => {
                        if response.bytes().await.is_ok() {
                            local.push(started.elapsed().as_secs_f64());
                        } else {
                            errors.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Ok(_) | Err(_) => {
                        errors.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }

            latencies.lock().await.extend(local);
        }));
    }

    for worker in workers {
        worker.await?;
    }

    let collected = Arc::try_unwrap(latencies)
        .map_err(|_| "a worker outlived the run")?
        .into_inner();

    let mut values = collected;
    values.sort_by(f64::total_cmp);

    if values.is_empty() {
        println!("requests=0 errors={}", errors.load(Ordering::Relaxed));
        return Ok(());
    }

    let count = values.len();
    let seconds = seconds as f64;

    println!(
        "requests={count} rps={:.0} p50={:.2}ms p95={:.2}ms p99={:.2}ms errors={}",
        count as f64 / seconds,
        percentile(&values, 0.50) * 1_000.0,
        percentile(&values, 0.95) * 1_000.0,
        percentile(&values, 0.99) * 1_000.0,
        errors.load(Ordering::Relaxed),
    );

    Ok(())
}

fn percentile(sorted: &[f64], quantile: f64) -> f64 {
    let index = ((sorted.len() - 1) as f64 * quantile).round() as usize;

    sorted[index]
}

fn parse_arg<T: std::str::FromStr>(
    value: Option<String>,
    default: T,
) -> Result<T, Box<dyn std::error::Error>> {
    match value {
        Some(value) => Ok(value
            .parse()
            .map_err(|_| "invalid numeric argument")?),
        None => Ok(default),
    }
}
