use axum::Json;
use serde::Serialize;

#[derive(Serialize)]
pub(super) struct ServiceInfo {
    service: &'static str,
    version: &'static str,
    status: &'static str,
}

pub(super) async fn index() -> Json<ServiceInfo> {
    Json(ServiceInfo {
        service: env!("CARGO_PKG_NAME"),
        version: env!("CARGO_PKG_VERSION"),
        status: "ok",
    })
}
