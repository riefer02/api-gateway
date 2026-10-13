use axum::{routing::get, Router};

mod config;
use config::Config;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();

    let config = Config::from_env()?;
    let addr = format!("{}:{}", config.host, config.port);
    let app = Router::new().route("/", get(|| async { "Hello, world!" }));

    println!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap();

    axum::serve(listener, app)
        .await
        .unwrap();
    Ok(())
}
