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
use opentelemetry_sdk::resource::Resource;
use opentelemetry_sdk::runtime::Tokio;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
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
    /// Network jitter (stddev of recent RTTs) in milliseconds.
    pub const PROBE_JITTER_MS: &str = "murmur.probe.jitter_ms";
    /// Packet loss percentage (0-100) from ping sequence to probe target.
    pub const PROBE_PACKET_LOSS_PCT: &str = "murmur.probe.packet_loss_pct";

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

    // Browser Navigation Timing metrics
    /// Browser DNS time in milliseconds.
    pub const BROWSER_DNS_MS: &str = "murmur.browser.dns_ms";
    /// Browser TCP time in milliseconds.
    pub const BROWSER_TCP_MS: &str = "murmur.browser.tcp_ms";
    /// Browser TLS time in milliseconds.
    pub const BROWSER_TLS_MS: &str = "murmur.browser.tls_ms";
    /// Browser TTFB in milliseconds.
    pub const BROWSER_TTFB_MS: &str = "murmur.browser.ttfb_ms";
    /// DOM Content Loaded time in milliseconds.
    pub const BROWSER_DCL_MS: &str = "murmur.browser.dom_content_loaded_ms";
    /// Page load time in milliseconds.
    pub const BROWSER_LOAD_MS: &str = "murmur.browser.load_ms";
    /// Largest Contentful Paint in milliseconds.
    pub const BROWSER_LCP_MS: &str = "murmur.browser.lcp_ms";
    /// First Contentful Paint in milliseconds.
    pub const BROWSER_FCP_MS: &str = "murmur.browser.fcp_ms";
    /// Cumulative Layout Shift.
    pub const BROWSER_CLS: &str = "murmur.browser.cls";
    /// First Input Delay in milliseconds.
    pub const BROWSER_FID_MS: &str = "murmur.browser.fid_ms";

    // Browser Resource Timing metrics
    /// Resource duration in milliseconds.
    pub const RESOURCE_DURATION_MS: &str = "murmur.resource.duration_ms";
    /// Resource transfer size in bytes.
    pub const RESOURCE_SIZE_BYTES: &str = "murmur.resource.size_bytes";
    /// Resource count per page.
    pub const RESOURCE_COUNT: &str = "murmur.resource.count";

    // Gateway / ICMP metrics
    /// Gateway RTT in milliseconds.
    pub const GATEWAY_RTT_MS: &str = "murmur.gateway.rtt_ms";
    /// Gateway packet loss percentage.
    pub const GATEWAY_PACKET_LOSS: &str = "murmur.gateway.packet_loss";
    /// Ping RTT to arbitrary host in milliseconds.
    pub const PING_RTT_MS: &str = "murmur.ping.rtt_ms";

    // Traceroute metrics
    /// Number of hops to destination.
    pub const TRACEROUTE_HOPS: &str = "murmur.traceroute.hops";
    /// Traceroute total latency in milliseconds.
    pub const TRACEROUTE_LATENCY_MS: &str = "murmur.traceroute.latency_ms";
    /// Per-hop RTT in milliseconds.
    pub const TRACEROUTE_HOP_RTT_MS: &str = "murmur.traceroute.hop_rtt_ms";
}

/// Telemetry emitter for probe results.
///
/// Manages the OpenTelemetry meter provider and instruments for recording
/// probe metrics.
pub struct TelemetryEmitter {
    _provider: SdkMeterProvider,
    // Probe metrics
    dns_histogram: Histogram<f64>,
    tcp_histogram: Histogram<f64>,
    tls_histogram: Histogram<f64>,
    ttfb_histogram: Histogram<f64>,
    total_histogram: Histogram<f64>,
    success_counter: Counter<u64>,
    jitter_histogram: Histogram<f64>,
    packet_loss_histogram: Histogram<f64>,
    /// Per-target ring buffer of last N total_ms for jitter (sample stddev).
    probe_rtt_window: Mutex<HashMap<String, Vec<f64>>>,
    // Browser Navigation Timing metrics
    browser_dns_histogram: Histogram<f64>,
    browser_tcp_histogram: Histogram<f64>,
    browser_tls_histogram: Histogram<f64>,
    browser_ttfb_histogram: Histogram<f64>,
    browser_dcl_histogram: Histogram<f64>,
    browser_load_histogram: Histogram<f64>,
    browser_lcp_histogram: Histogram<f64>,
    browser_fcp_histogram: Histogram<f64>,
    browser_cls_histogram: Histogram<f64>,
    browser_fid_histogram: Histogram<f64>,
    // Browser Resource Timing metrics
    resource_duration_histogram: Histogram<f64>,
    resource_size_histogram: Histogram<f64>,
    resource_counter: Counter<u64>,
    agent_version: &'static str,
}

impl TelemetryEmitter {
    /// Create a new telemetry emitter connected to an OTLP collector.
    ///
    /// If `resource_attrs` is provided (e.g. from `murmur_sysinfo::ResourceAttributes::to_attributes()`),
    /// those attributes are attached to the OTEL resource so every metric carries host/wifi/VPN context.
    ///
    /// Returns `None` if the exporter fails to initialize (collector unreachable).
    pub fn new(
        config: &CollectorConfig,
        resource_attrs: Option<HashMap<String, String>>,
    ) -> Option<Arc<Self>> {
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

        let provider_builder = SdkMeterProvider::builder().with_reader(reader);
        let provider = if let Some(attrs) = resource_attrs {
            let kvs: Vec<KeyValue> = attrs
                .into_iter()
                .map(|(k, v)| KeyValue::new(k, v))
                .collect();
            let resource = Resource::new(kvs);
            provider_builder.with_resource(resource).build()
        } else {
            provider_builder.build()
        };

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

        let jitter_histogram = meter
            .f64_histogram(metric_names::PROBE_JITTER_MS)
            .with_description("Network jitter (sample stddev of recent total RTTs) in milliseconds")
            .with_unit(Unit::new("ms"))
            .init();

        let packet_loss_histogram = meter
            .f64_histogram(metric_names::PROBE_PACKET_LOSS_PCT)
            .with_description("Packet loss percentage (0-100) from ping sequence to probe target")
            .with_unit(Unit::new("%"))
            .init();

        // Browser Navigation Timing instruments
        let browser_dns_histogram = meter
            .f64_histogram(metric_names::BROWSER_DNS_MS)
            .with_description("Browser DNS resolution time in milliseconds")
            .with_unit(Unit::new("ms"))
            .init();

        let browser_tcp_histogram = meter
            .f64_histogram(metric_names::BROWSER_TCP_MS)
            .with_description("Browser TCP connection time in milliseconds")
            .with_unit(Unit::new("ms"))
            .init();

        let browser_tls_histogram = meter
            .f64_histogram(metric_names::BROWSER_TLS_MS)
            .with_description("Browser TLS handshake time in milliseconds")
            .with_unit(Unit::new("ms"))
            .init();

        let browser_ttfb_histogram = meter
            .f64_histogram(metric_names::BROWSER_TTFB_MS)
            .with_description("Browser time to first byte in milliseconds")
            .with_unit(Unit::new("ms"))
            .init();

        let browser_dcl_histogram = meter
            .f64_histogram(metric_names::BROWSER_DCL_MS)
            .with_description("DOM Content Loaded time in milliseconds")
            .with_unit(Unit::new("ms"))
            .init();

        let browser_load_histogram = meter
            .f64_histogram(metric_names::BROWSER_LOAD_MS)
            .with_description("Page load time in milliseconds")
            .with_unit(Unit::new("ms"))
            .init();

        let browser_lcp_histogram = meter
            .f64_histogram(metric_names::BROWSER_LCP_MS)
            .with_description("Largest Contentful Paint in milliseconds")
            .with_unit(Unit::new("ms"))
            .init();

        let browser_fcp_histogram = meter
            .f64_histogram(metric_names::BROWSER_FCP_MS)
            .with_description("First Contentful Paint in milliseconds")
            .with_unit(Unit::new("ms"))
            .init();

        let browser_cls_histogram = meter
            .f64_histogram(metric_names::BROWSER_CLS)
            .with_description("Cumulative Layout Shift score")
            .init();

        let browser_fid_histogram = meter
            .f64_histogram(metric_names::BROWSER_FID_MS)
            .with_description("First Input Delay in milliseconds")
            .with_unit(Unit::new("ms"))
            .init();

        // Browser Resource Timing instruments
        let resource_duration_histogram = meter
            .f64_histogram(metric_names::RESOURCE_DURATION_MS)
            .with_description("Resource fetch duration in milliseconds")
            .with_unit(Unit::new("ms"))
            .init();

        let resource_size_histogram = meter
            .f64_histogram(metric_names::RESOURCE_SIZE_BYTES)
            .with_description("Resource transfer size in bytes")
            .with_unit(Unit::new("bytes"))
            .init();

        let resource_counter = meter
            .u64_counter(metric_names::RESOURCE_COUNT)
            .with_description("Resources loaded per page")
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
            jitter_histogram,
            packet_loss_histogram,
            probe_rtt_window: Mutex::new(HashMap::new()),
            browser_dns_histogram,
            browser_tcp_histogram,
            browser_tls_histogram,
            browser_ttfb_histogram,
            browser_dcl_histogram,
            browser_load_histogram,
            browser_lcp_histogram,
            browser_fcp_histogram,
            browser_cls_histogram,
            browser_fid_histogram,
            resource_duration_histogram,
            resource_size_histogram,
            resource_counter,
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
            jitter_histogram: meter.f64_histogram("noop").init(),
            packet_loss_histogram: meter.f64_histogram("noop").init(),
            probe_rtt_window: Mutex::new(HashMap::new()),
            browser_dns_histogram: meter.f64_histogram("noop").init(),
            browser_tcp_histogram: meter.f64_histogram("noop").init(),
            browser_tls_histogram: meter.f64_histogram("noop").init(),
            browser_ttfb_histogram: meter.f64_histogram("noop").init(),
            browser_dcl_histogram: meter.f64_histogram("noop").init(),
            browser_load_histogram: meter.f64_histogram("noop").init(),
            browser_lcp_histogram: meter.f64_histogram("noop").init(),
            browser_fcp_histogram: meter.f64_histogram("noop").init(),
            browser_cls_histogram: meter.f64_histogram("noop").init(),
            browser_fid_histogram: meter.f64_histogram("noop").init(),
            resource_duration_histogram: meter.f64_histogram("noop").init(),
            resource_size_histogram: meter.f64_histogram("noop").init(),
            resource_counter: meter.u64_counter("noop").init(),
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

        // Update per-target RTT window and emit jitter (sample stddev of recent total_ms)
        const RTT_WINDOW_SIZE: usize = 10;
        let total_ms = result.timing.total_ms as f64;
        let jitter_ms = match self.probe_rtt_window.lock() {
            Ok(mut guard) => {
                let buf = guard.entry(target_url.to_string()).or_default();
                buf.push(total_ms);
                if buf.len() > RTT_WINDOW_SIZE {
                    buf.remove(0);
                }
                sample_stddev_ms(buf)
            }
            Err(e) => {
                tracing::warn!(error = %e, "probe_rtt_window lock poisoned, skipping jitter");
                None
            }
        };
        if let Some(jitter) = jitter_ms {
            self.jitter_histogram.record(jitter, &base_attrs);
        }

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

    /// Emit packet loss percentage from a ping sequence to a probe target.
    pub fn emit_packet_loss(&self, target_url: &str, target_host: &str, loss_pct: f64) {
        let attrs = [
            KeyValue::new("target.url", target_url.to_string()),
            KeyValue::new("target.host", target_host.to_string()),
            KeyValue::new("probe.type", "ping"),
            KeyValue::new("agent.version", self.agent_version),
        ];
        self.packet_loss_histogram.record(loss_pct, &attrs);
    }

    /// Emit metrics for browser Navigation Timing data.
    ///
    /// This is called when the browser extension sends timing data to the agent.
    pub fn emit_navigation_timing(&self, timing: &NavigationTiming, host: &str) {
        let base_attrs = [
            KeyValue::new("page.url", timing.url.clone()),
            KeyValue::new("page.host", host.to_string()),
            KeyValue::new("source", "browser"),
            KeyValue::new("agent.version", self.agent_version),
        ];

        // Record timing histograms
        self.browser_dns_histogram
            .record(timing.dns_ms, &base_attrs);
        self.browser_tcp_histogram
            .record(timing.tcp_ms, &base_attrs);
        self.browser_tls_histogram
            .record(timing.tls_ms, &base_attrs);
        self.browser_ttfb_histogram
            .record(timing.ttfb_ms, &base_attrs);
        self.browser_dcl_histogram
            .record(timing.dom_content_loaded_ms, &base_attrs);
        self.browser_load_histogram
            .record(timing.load_ms, &base_attrs);

        // Record Web Vitals (if present)
        if let Some(lcp) = timing.lcp_ms {
            self.browser_lcp_histogram.record(lcp, &base_attrs);
        }
        if let Some(fcp) = timing.fcp_ms {
            self.browser_fcp_histogram.record(fcp, &base_attrs);
        }
        if let Some(cls) = timing.cls {
            self.browser_cls_histogram.record(cls, &base_attrs);
        }
        if let Some(fid) = timing.fid_ms {
            self.browser_fid_histogram.record(fid, &base_attrs);
        }

        debug!(
            url = %timing.url,
            dns_ms = timing.dns_ms,
            tcp_ms = timing.tcp_ms,
            tls_ms = timing.tls_ms,
            ttfb_ms = timing.ttfb_ms,
            dcl_ms = timing.dom_content_loaded_ms,
            load_ms = timing.load_ms,
            "browser navigation timing emitted"
        );
    }

    /// Emit metrics for browser Resource Timing data.
    pub fn emit_resource_timing(
        &self,
        resource: &ResourceTiming,
        page_host: &str,
        resource_host: &str,
    ) {
        let base_attrs = [
            KeyValue::new("resource.url", resource.url.clone()),
            KeyValue::new("resource.host", resource_host.to_string()),
            KeyValue::new("resource.type", resource.initiator_type.clone()),
            KeyValue::new("page.host", page_host.to_string()),
            KeyValue::new("from_cache", resource.from_cache.to_string()),
            KeyValue::new("source", "browser"),
            KeyValue::new("agent.version", self.agent_version),
        ];

        self.resource_duration_histogram
            .record(resource.duration_ms, &base_attrs);
        self.resource_size_histogram
            .record(resource.transfer_size as f64, &base_attrs);
        self.resource_counter.add(1, &base_attrs);
    }
}

/// Navigation Timing data from browser extension.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NavigationTiming {
    /// Page URL.
    pub url: String,
    /// DNS lookup time in milliseconds.
    pub dns_ms: f64,
    /// TCP connection time in milliseconds.
    pub tcp_ms: f64,
    /// TLS handshake time in milliseconds.
    pub tls_ms: f64,
    /// Time to First Byte in milliseconds.
    pub ttfb_ms: f64,
    /// DOM Content Loaded time in milliseconds.
    pub dom_content_loaded_ms: f64,
    /// Load event time in milliseconds.
    pub load_ms: f64,
    /// Largest Contentful Paint in milliseconds.
    pub lcp_ms: Option<f64>,
    /// First Contentful Paint in milliseconds.
    pub fcp_ms: Option<f64>,
    /// Cumulative Layout Shift score.
    pub cls: Option<f64>,
    /// First Input Delay in milliseconds.
    pub fid_ms: Option<f64>,
    /// Timestamp of the navigation.
    pub timestamp: i64,
    /// User agent string.
    pub user_agent: Option<String>,
    /// Connection type.
    pub connection_type: Option<String>,
    /// Effective connection type.
    pub effective_type: Option<String>,
    /// Round-trip time estimate in milliseconds.
    pub rtt_ms: Option<f64>,
    /// Downlink speed estimate in Mbps.
    pub downlink_mbps: Option<f64>,
}

/// Resource Timing data from browser extension.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ResourceTiming {
    /// Resource URL.
    pub url: String,
    /// Initiator type.
    pub initiator_type: String,
    /// Transfer size in bytes.
    pub transfer_size: u64,
    /// Encoded body size in bytes.
    pub encoded_body_size: u64,
    /// Decoded body size in bytes.
    pub decoded_body_size: u64,
    /// DNS lookup time in milliseconds.
    pub dns_ms: f64,
    /// TCP connection time in milliseconds.
    pub tcp_ms: f64,
    /// TLS handshake time in milliseconds.
    pub tls_ms: f64,
    /// Time to First Byte in milliseconds.
    pub ttfb_ms: f64,
    /// Total fetch duration in milliseconds.
    pub duration_ms: f64,
    /// Start time relative to navigation start.
    pub start_time_ms: f64,
    /// Whether the resource was served from cache.
    pub from_cache: bool,
    /// Protocol used.
    pub protocol: Option<String>,
}

/// Extract hostname from a URL.
/// Sample standard deviation of a slice (returns None if n < 2).
fn sample_stddev_ms(v: &[f64]) -> Option<f64> {
    if v.len() < 2 {
        return None;
    }
    let n = v.len() as f64;
    let mean = v.iter().sum::<f64>() / n;
    let variance = v.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0);
    Some(variance.sqrt())
}

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
