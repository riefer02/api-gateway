//! Minimal upstream used by `scripts/bench.sh`.
//!
//! Answers every path with a small JSON body so measurements reflect the
//! gateway, not the internet.

use axum::{Json, Router};
use serde::Serialize;

#[derive(Serialize)]
struct Echo {
    ok: bool,
    path: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let port = std::env::var("STUB_PORT").unwrap_or_else(|_| "18080".to_owned());

    let app = Router::new().fallback(|uri: axum::http::Uri| async move {
        Json(Echo {
            ok: true,
            path: uri.path().to_owned(),
        })
    });

    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}")).await?;
    eprintln!("stub upstream listening on 127.0.0.1:{port}");

    axum::serve(listener, app).await?;

    Ok(())
}
