//! HTTP API for receiving browser timing data from the extension.

use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use murmur_core::telemetry::TelemetryEmitter;
use murmur_core::{NavigationTiming, ResourceTiming};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tracing::{debug, info};

/// Shared state for API handlers.
#[derive(Clone)]
pub struct ApiState {
    pub telemetry: Arc<TelemetryEmitter>,
}

/// Create the API router.
pub fn router(state: ApiState) -> Router {
    // CORS configuration for browser extension
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/health", get(health_check))
        .route("/api/v1/timing", post(receive_timing))
        .route("/api/v1/resources", post(receive_resources))
        .layer(cors)
        .with_state(state)
}

/// Health check endpoint.
async fn health_check() -> &'static str {
    "ok"
}

/// Batch of resource timings from a single page.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceTimingBatch {
    /// Page URL these resources belong to.
    pub page_url: String,

    /// Timestamp of collection.
    pub timestamp: i64,

    /// Resource timing entries.
    pub resources: Vec<ResourceTiming>,
}

/// Receive navigation timing data from browser extension.
async fn receive_timing(
    State(state): State<ApiState>,
    Json(timing): Json<NavigationTiming>,
) -> StatusCode {
    debug!(
        url = %timing.url,
        dns_ms = timing.dns_ms,
        tcp_ms = timing.tcp_ms,
        tls_ms = timing.tls_ms,
        ttfb_ms = timing.ttfb_ms,
        dcl_ms = timing.dom_content_loaded_ms,
        "received navigation timing"
    );

    // Extract hostname from URL
    let host = extract_host(&timing.url);

    // Emit metrics via OTEL
    state.telemetry.emit_navigation_timing(&timing, &host);

    info!(
        url = %timing.url,
        ttfb_ms = timing.ttfb_ms,
        load_ms = timing.load_ms,
        "navigation timing recorded"
    );

    StatusCode::ACCEPTED
}

/// Receive resource timing data from browser extension.
async fn receive_resources(
    State(state): State<ApiState>,
    Json(batch): Json<ResourceTimingBatch>,
) -> StatusCode {
    debug!(
        page_url = %batch.page_url,
        resource_count = batch.resources.len(),
        "received resource timing batch"
    );

    let page_host = extract_host(&batch.page_url);

    // Emit metrics for each resource
    for resource in &batch.resources {
        let resource_host = extract_host(&resource.url);
        state
            .telemetry
            .emit_resource_timing(resource, &page_host, &resource_host);
    }

    info!(
        page_url = %batch.page_url,
        count = batch.resources.len(),
        "resource timings recorded"
    );

    StatusCode::ACCEPTED
}

/// Extract hostname from URL.
fn extract_host(url: &str) -> String {
    if let Some(rest) = url.strip_prefix("https://") {
        rest.split('/').next().unwrap_or(rest).to_string()
    } else if let Some(rest) = url.strip_prefix("http://") {
        rest.split('/').next().unwrap_or(rest).to_string()
    } else {
        url.split('/').next().unwrap_or(url).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_host_works() {
        assert_eq!(extract_host("https://example.com/path"), "example.com");
        assert_eq!(extract_host("http://example.com:8080/"), "example.com:8080");
        assert_eq!(extract_host("example.com"), "example.com");
    }
}
