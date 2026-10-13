pub fn init(filter: &str) {
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();
}
