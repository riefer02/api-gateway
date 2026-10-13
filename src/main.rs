use axum::{Router, routing::get};
use tower_http::trace::TraceLayer;

mod config;
use config::Config;
mod observability;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    let config = Config::from_env()?;

    observability::init(config.log_level.as_str());

    let addr = format!("{}:{}", config.host, config.port);
    let app = Router::new()
        .route("/", get(|| async { "Hello, world!" }))
        .layer(TraceLayer::new_for_http());

    println!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap();

    axum::serve(listener, app)
        .await
        .unwrap();
    Ok(())
}
