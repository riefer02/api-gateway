mod app;
mod config;
mod routes;

use config::Config;
mod observability;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    let config = Config::from_env()?;

    observability::init(config.log_level.as_str());

    let addr = format!("{}:{}", config.host, config.port);
    let app = app::build_app();

    println!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap();

    axum::serve(listener, app)
        .await
        .unwrap();
    Ok(())
}
