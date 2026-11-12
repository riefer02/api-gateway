use opentelemetry::{KeyValue, trace::TracerProvider as _};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{Resource, trace::SdkTracerProvider};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::TelemetryConfig;

/// Owns the tracer provider so it can be flushed before the process exits.
pub struct TelemetryGuard {
    provider: Option<SdkTracerProvider>,
}

impl TelemetryGuard {
    pub fn shutdown(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match self.provider {
            Some(provider) => Ok(provider.shutdown()?),
            None => Ok(()),
        }
    }
}

pub fn init(
    config: &TelemetryConfig,
    environment: &str,
) -> Result<TelemetryGuard, Box<dyn std::error::Error + Send + Sync>> {
    let filter = EnvFilter::try_new(&config.log_level)?;
    let fmt_layer = tracing_subscriber::fmt::layer();

    let Some(endpoint) = config.otlp_endpoint.as_deref() else {
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt_layer)
            .try_init()?;

        tracing::info!("OTLP export disabled; logs only");

        return Ok(TelemetryGuard { provider: None });
    };

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()?;

    let provider = SdkTracerProvider::builder()
        .with_resource(
            Resource::builder()
                .with_service_name("api-gateway")
                .with_attribute(KeyValue::new("service.version", env!("CARGO_PKG_VERSION")))
                .with_attribute(KeyValue::new(
                    "deployment.environment.name",
                    environment.to_owned(),
                ))
                .build(),
        )
        .with_batch_exporter(exporter)
        .build();

    let tracer = provider.tracer("api-gateway");
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .with(tracing_opentelemetry::layer().with_tracer(tracer))
        .try_init()?;

    opentelemetry::global::set_text_map_propagator(
        opentelemetry_sdk::propagation::TraceContextPropagator::new(),
    );

    tracing::info!(%endpoint, "OTLP tracing enabled");

    Ok(TelemetryGuard {
        provider: Some(provider),
    })
}
