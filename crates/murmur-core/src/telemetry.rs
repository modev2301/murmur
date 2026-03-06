//! Telemetry and OpenTelemetry integration.
//!
//! Murmur emits metrics directly via the OpenTelemetry SDK to any OTLP-compatible
//! collector. This module handles metric registration, emission, and the exporter
//! lifecycle.
//!
//! We use the OpenTelemetry SDK directly rather than a bridge crate like
//! `metrics-exporter-opentelemetry` for direct control over OTEL semantics.

use crate::config::CollectorConfig;
use crate::types::ProbeResult;
use opentelemetry::metrics::{Counter, Histogram, MeterProvider, Unit};
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::runtime::Tokio;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// Metric names — the six probe metrics that matter first.
pub mod metric_names {
    /// DNS resolution time in milliseconds.
    pub const PROBE_DNS_MS: &str = "murmur.probe.dns_ms";
    /// TCP connect time in milliseconds.
    pub const PROBE_TCP_MS: &str = "murmur.probe.tcp_ms";
    /// TLS handshake time in milliseconds.
    pub const PROBE_TLS_MS: &str = "murmur.probe.tls_ms";
    /// Time to first byte in milliseconds.
    pub const PROBE_TTFB_MS: &str = "murmur.probe.ttfb_ms";
    /// Total probe duration in milliseconds.
    pub const PROBE_TOTAL_MS: &str = "murmur.probe.total_ms";
    /// Probe success/failure counter.
    pub const PROBE_SUCCESS: &str = "murmur.probe.success";

    // Agent self-instrumentation metrics
    /// Agent uptime in seconds (gauge).
    pub const AGENT_UPTIME_SECONDS: &str = "murmur.agent.uptime_seconds";
    /// Total probes executed (counter).
    pub const AGENT_PROBES_TOTAL: &str = "murmur.agent.probes_total";
    /// Currently active targets (gauge).
    pub const AGENT_TARGETS_ACTIVE: &str = "murmur.agent.targets_active";
    /// Discovered endpoints from DNS observation (gauge).
    pub const AGENT_ENDPOINTS_DISCOVERED: &str = "murmur.agent.endpoints_discovered";
    /// Connection pool size (gauge).
    pub const AGENT_POOL_CONNECTIONS: &str = "murmur.agent.pool_connections";
    /// TLS sessions resumed (counter).
    pub const AGENT_TLS_SESSIONS_RESUMED: &str = "murmur.agent.tls_sessions_resumed";
}

/// Telemetry emitter for probe results.
///
/// Manages the OpenTelemetry meter provider and instruments for recording
/// probe metrics.
pub struct TelemetryEmitter {
    _provider: SdkMeterProvider,
    dns_histogram: Histogram<f64>,
    tcp_histogram: Histogram<f64>,
    tls_histogram: Histogram<f64>,
    ttfb_histogram: Histogram<f64>,
    total_histogram: Histogram<f64>,
    success_counter: Counter<u64>,
    agent_version: &'static str,
}

impl TelemetryEmitter {
    /// Create a new telemetry emitter connected to an OTLP collector.
    ///
    /// Returns `None` if the exporter fails to initialize (collector unreachable).
    pub fn new(config: &CollectorConfig) -> Option<Arc<Self>> {
        info!(
            endpoint = %config.endpoint,
            "initializing OTLP exporter"
        );

        // Build the OTLP exporter
        let exporter = match opentelemetry_otlp::new_exporter()
            .tonic()
            .with_endpoint(&config.endpoint)
            .with_timeout(Duration::from_secs(10))
            .build_metrics_exporter(
                Box::new(opentelemetry_sdk::metrics::reader::DefaultAggregationSelector::new()),
                Box::new(opentelemetry_sdk::metrics::reader::DefaultTemporalitySelector::new()),
            ) {
            Ok(exp) => exp,
            Err(e) => {
                error!(error = %e, "failed to create OTLP exporter");
                return None;
            }
        };

        // Build the meter provider with periodic reader
        let reader = opentelemetry_sdk::metrics::PeriodicReader::builder(exporter, Tokio)
            .with_interval(Duration::from_secs(config.export_interval_seconds))
            .build();

        let provider = SdkMeterProvider::builder().with_reader(reader).build();

        // Create a meter for our metrics
        let meter = provider.meter("murmur");

        // Create the six instruments
        let dns_histogram = meter
            .f64_histogram(metric_names::PROBE_DNS_MS)
            .with_description("DNS resolution time in milliseconds")
            .with_unit(Unit::new("ms"))
            .init();

        let tcp_histogram = meter
            .f64_histogram(metric_names::PROBE_TCP_MS)
            .with_description("TCP connection time in milliseconds")
            .with_unit(Unit::new("ms"))
            .init();

        let tls_histogram = meter
            .f64_histogram(metric_names::PROBE_TLS_MS)
            .with_description("TLS handshake time in milliseconds")
            .with_unit(Unit::new("ms"))
            .init();

        let ttfb_histogram = meter
            .f64_histogram(metric_names::PROBE_TTFB_MS)
            .with_description("Time to first byte in milliseconds")
            .with_unit(Unit::new("ms"))
            .init();

        let total_histogram = meter
            .f64_histogram(metric_names::PROBE_TOTAL_MS)
            .with_description("Total probe duration in milliseconds")
            .with_unit(Unit::new("ms"))
            .init();

        let success_counter = meter
            .u64_counter(metric_names::PROBE_SUCCESS)
            .with_description("Probe success/failure count")
            .init();

        info!(
            endpoint = %config.endpoint,
            export_interval_seconds = config.export_interval_seconds,
            "OTLP exporter initialized"
        );

        Some(Arc::new(Self {
            _provider: provider,
            dns_histogram,
            tcp_histogram,
            tls_histogram,
            ttfb_histogram,
            total_histogram,
            success_counter,
            agent_version: env!("CARGO_PKG_VERSION"),
        }))
    }

    /// Create a no-op emitter for testing or when collector is unavailable.
    pub fn noop() -> Arc<Self> {
        let provider = SdkMeterProvider::builder().build();
        let meter = provider.meter("murmur-noop");

        Arc::new(Self {
            _provider: provider,
            dns_histogram: meter.f64_histogram("noop").init(),
            tcp_histogram: meter.f64_histogram("noop").init(),
            tls_histogram: meter.f64_histogram("noop").init(),
            ttfb_histogram: meter.f64_histogram("noop").init(),
            total_histogram: meter.f64_histogram("noop").init(),
            success_counter: meter.u64_counter("noop").init(),
            agent_version: env!("CARGO_PKG_VERSION"),
        })
    }

    /// Emit metrics for a probe result.
    pub fn emit_probe_result(&self, result: &ProbeResult) {
        let target_url = result.target.url.as_str();
        let target_host = extract_host(target_url);
        let target_name = result.target.name.as_deref().unwrap_or(target_host);

        // Common attributes for all metrics
        let base_attrs = [
            KeyValue::new("target.url", target_url.to_string()),
            KeyValue::new("target.host", target_host.to_string()),
            KeyValue::new("probe.type", "http"),
            KeyValue::new("agent.version", self.agent_version),
        ];

        // Record timing histograms (only if we have the data)
        if let Some(dns_ms) = result.timing.dns_ms {
            self.dns_histogram.record(dns_ms as f64, &base_attrs);
        }

        if let Some(tcp_ms) = result.timing.tcp_connect_ms {
            self.tcp_histogram.record(tcp_ms as f64, &base_attrs);
        }

        if let Some(tls_ms) = result.timing.tls_handshake_ms {
            self.tls_histogram.record(tls_ms as f64, &base_attrs);
        }

        if let Some(ttfb_ms) = result.timing.ttfb_ms {
            self.ttfb_histogram.record(ttfb_ms as f64, &base_attrs);
        }

        self.total_histogram
            .record(result.timing.total_ms as f64, &base_attrs);

        // Record success counter with additional attributes
        let error_kind = if result.success {
            "none"
        } else {
            categorize_error(result.error.as_deref().unwrap_or("unknown"))
        };

        let success_attrs = [
            KeyValue::new("target.url", target_url.to_string()),
            KeyValue::new("target.host", target_host.to_string()),
            KeyValue::new("probe.type", "http"),
            KeyValue::new("agent.version", self.agent_version),
            KeyValue::new("success", result.success.to_string()),
            KeyValue::new("error_kind", error_kind),
        ];

        self.success_counter.add(1, &success_attrs);

        if result.success {
            debug!(
                target = target_name,
                total_ms = result.timing.total_ms,
                dns_ms = ?result.timing.dns_ms,
                tcp_ms = ?result.timing.tcp_connect_ms,
                tls_ms = ?result.timing.tls_handshake_ms,
                ttfb_ms = ?result.timing.ttfb_ms,
                "probe metrics emitted"
            );
        } else {
            warn!(
                target = target_name,
                error = ?result.error,
                error_kind = error_kind,
                "probe failure recorded"
            );
        }
    }
}

/// Extract hostname from a URL.
fn extract_host(url: &str) -> &str {
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);

    without_scheme
        .split('/')
        .next()
        .unwrap_or(without_scheme)
        .split(':')
        .next()
        .unwrap_or(without_scheme)
}

/// Categorize an error message into a type for metric labeling.
fn categorize_error(error: &str) -> &'static str {
    let lower = error.to_lowercase();
    if lower.contains("dns") || lower.contains("resolution") {
        "dns"
    } else if lower.contains("timeout") || lower.contains("timed out") {
        "timeout"
    } else if lower.contains("tls") || lower.contains("certificate") || lower.contains("handshake")
    {
        "tls"
    } else if lower.contains("tcp")
        || lower.contains("connection refused")
        || lower.contains("connection reset")
    {
        "tcp"
    } else if lower.contains("http") {
        "http"
    } else {
        "other"
    }
}

/// Agent self-instrumentation metrics.
///
/// Tracks the agent's own health and performance, separate from probe metrics.
/// These metrics help operators understand the agent's resource usage and behavior.
pub struct AgentMetrics {
    /// When the agent started.
    start_time: std::time::Instant,
    /// Uptime gauge (reported as seconds).
    uptime_gauge: Histogram<f64>,
    /// Total probes executed counter.
    probes_counter: Counter<u64>,
    /// Active targets gauge.
    targets_gauge: Histogram<f64>,
    /// Discovered endpoints gauge.
    discovered_gauge: Histogram<f64>,
    /// Pool connections gauge.
    pool_gauge: Histogram<f64>,
    /// TLS sessions resumed counter.
    sessions_resumed_counter: Counter<u64>,
    /// Agent version.
    agent_version: &'static str,
}

impl AgentMetrics {
    /// Create agent metrics from an existing meter provider.
    pub fn new(provider: &SdkMeterProvider) -> Self {
        let meter = provider.meter("murmur-agent");

        // Note: OpenTelemetry SDK uses histograms/counters; for gauges we record
        // the current value as a histogram observation. This is a common pattern
        // when true gauge instruments aren't available.
        let uptime_gauge = meter
            .f64_histogram(metric_names::AGENT_UPTIME_SECONDS)
            .with_description("Agent uptime in seconds")
            .with_unit(Unit::new("s"))
            .init();

        let probes_counter = meter
            .u64_counter(metric_names::AGENT_PROBES_TOTAL)
            .with_description("Total probes executed")
            .init();

        let targets_gauge = meter
            .f64_histogram(metric_names::AGENT_TARGETS_ACTIVE)
            .with_description("Currently active probe targets")
            .init();

        let discovered_gauge = meter
            .f64_histogram(metric_names::AGENT_ENDPOINTS_DISCOVERED)
            .with_description("Endpoints discovered via DNS observation")
            .init();

        let pool_gauge = meter
            .f64_histogram(metric_names::AGENT_POOL_CONNECTIONS)
            .with_description("Connections in the connection pool")
            .init();

        let sessions_resumed_counter = meter
            .u64_counter(metric_names::AGENT_TLS_SESSIONS_RESUMED)
            .with_description("TLS sessions resumed")
            .init();

        Self {
            start_time: std::time::Instant::now(),
            uptime_gauge,
            probes_counter,
            targets_gauge,
            discovered_gauge,
            pool_gauge,
            sessions_resumed_counter,
            agent_version: env!("CARGO_PKG_VERSION"),
        }
    }

    /// Create a no-op agent metrics for testing.
    pub fn noop() -> Self {
        let provider = SdkMeterProvider::builder().build();
        Self::new(&provider)
    }

    /// Get the agent version.
    fn base_attributes(&self) -> [KeyValue; 1] {
        [KeyValue::new("agent.version", self.agent_version)]
    }

    /// Record that a probe was executed.
    pub fn record_probe(&self) {
        self.probes_counter.add(1, &self.base_attributes());
    }

    /// Record a TLS session resumption.
    pub fn record_session_resumed(&self) {
        self.sessions_resumed_counter
            .add(1, &self.base_attributes());
    }

    /// Record current state metrics (call periodically).
    pub fn record_state(
        &self,
        active_targets: usize,
        discovered_endpoints: usize,
        pool_connections: usize,
    ) {
        let attrs = self.base_attributes();

        // Record uptime
        let uptime_secs = self.start_time.elapsed().as_secs_f64();
        self.uptime_gauge.record(uptime_secs, &attrs);

        // Record gauges
        self.targets_gauge.record(active_targets as f64, &attrs);
        self.discovered_gauge
            .record(discovered_endpoints as f64, &attrs);
        self.pool_gauge.record(pool_connections as f64, &attrs);

        debug!(
            uptime_secs = uptime_secs,
            active_targets = active_targets,
            discovered_endpoints = discovered_endpoints,
            pool_connections = pool_connections,
            "agent state metrics recorded"
        );
    }

    /// Get uptime in seconds.
    pub fn uptime_seconds(&self) -> f64 {
        self.start_time.elapsed().as_secs_f64()
    }
}

/// Initialize tracing subscriber with the configured format.
pub fn init_tracing(format: &str, level: &str) {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));

    match format {
        "json" => {
            tracing_subscriber::fmt()
                .json()
                .with_env_filter(filter)
                .init();
        }
        _ => {
            tracing_subscriber::fmt().with_env_filter(filter).init();
        }
    }

    info!(format = format, level = level, "tracing initialized");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_host_from_https_url() {
        assert_eq!(extract_host("https://example.com/path"), "example.com");
        assert_eq!(extract_host("https://example.com:443/path"), "example.com");
    }

    #[test]
    fn extract_host_from_http_url() {
        assert_eq!(extract_host("http://localhost:8080/health"), "localhost");
    }

    #[test]
    fn categorize_error_dns() {
        assert_eq!(categorize_error("DNS resolution failed"), "dns");
    }

    #[test]
    fn categorize_error_timeout() {
        assert_eq!(categorize_error("connection timed out"), "timeout");
    }

    #[test]
    fn categorize_error_tls() {
        assert_eq!(categorize_error("TLS handshake failed"), "tls");
    }

    #[test]
    fn categorize_error_tcp() {
        assert_eq!(categorize_error("TCP connection refused"), "tcp");
    }
}
