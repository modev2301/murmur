//! Core types for probe results and targets.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;

/// A target endpoint to probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeTarget {
    /// Unique identifier for this target (usually the URL or hostname).
    pub id: String,

    /// The URL or hostname to probe.
    pub url: String,

    /// Optional friendly name for display.
    pub name: Option<String>,

    /// Tags for grouping and filtering.
    #[serde(default)]
    pub tags: Vec<String>,
}

impl ProbeTarget {
    /// Create a new probe target from a URL.
    pub fn new(url: impl Into<String>) -> Self {
        let url = url.into();
        Self {
            id: url.clone(),
            url,
            name: None,
            tags: Vec::new(),
        }
    }

    /// Set the target name.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Add a tag.
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }
}

/// Detailed timing breakdown for a probe.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TimingBreakdown {
    /// Time to resolve DNS (milliseconds).
    pub dns_ms: Option<u64>,

    /// Time to establish TCP connection (milliseconds).
    pub tcp_connect_ms: Option<u64>,

    /// Time for TLS handshake (milliseconds).
    pub tls_handshake_ms: Option<u64>,

    /// Time to first byte after request sent (milliseconds).
    pub ttfb_ms: Option<u64>,

    /// Total time for the complete probe (milliseconds).
    pub total_ms: u64,
}

impl TimingBreakdown {
    /// Calculate time to first byte (sum of all network layers).
    pub fn time_to_first_byte(&self) -> u64 {
        self.dns_ms.unwrap_or(0)
            + self.tcp_connect_ms.unwrap_or(0)
            + self.tls_handshake_ms.unwrap_or(0)
            + self.ttfb_ms.unwrap_or(0)
    }

    /// Set DNS timing.
    pub fn with_dns(mut self, duration: Duration) -> Self {
        self.dns_ms = Some(duration.as_millis() as u64);
        self
    }

    /// Set TCP connect timing.
    pub fn with_tcp(mut self, duration: Duration) -> Self {
        self.tcp_connect_ms = Some(duration.as_millis() as u64);
        self
    }

    /// Set TLS handshake timing.
    pub fn with_tls(mut self, duration: Duration) -> Self {
        self.tls_handshake_ms = Some(duration.as_millis() as u64);
        self
    }

    /// Set time to first byte.
    pub fn with_ttfb(mut self, duration: Duration) -> Self {
        self.ttfb_ms = Some(duration.as_millis() as u64);
        self
    }

    /// Set total time.
    pub fn with_total(mut self, duration: Duration) -> Self {
        self.total_ms = duration.as_millis() as u64;
        self
    }
}

/// The result of a probe measurement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    /// The target that was probed.
    pub target: ProbeTarget,

    /// Whether the probe succeeded.
    pub success: bool,

    /// Timestamp when the probe was executed.
    pub timestamp: DateTime<Utc>,

    /// Detailed timing breakdown.
    pub timing: TimingBreakdown,

    /// Resolved IP address (if DNS resolution occurred).
    pub resolved_ip: Option<IpAddr>,

    /// TLS certificate info (if TLS was used).
    pub tls_info: Option<TlsInfo>,

    /// HTTP status code (if HTTP probe).
    pub http_status: Option<u16>,

    /// Error message if the probe failed.
    pub error: Option<String>,
}

impl ProbeResult {
    /// Create a successful probe result.
    pub fn success(target: ProbeTarget, timing: TimingBreakdown) -> Self {
        Self {
            target,
            success: true,
            timestamp: Utc::now(),
            timing,
            resolved_ip: None,
            tls_info: None,
            http_status: None,
            error: None,
        }
    }

    /// Create a failed probe result.
    pub fn failure(
        target: ProbeTarget,
        error: impl Into<String>,
        total_duration: Duration,
    ) -> Self {
        Self {
            target,
            success: false,
            timestamp: Utc::now(),
            timing: TimingBreakdown {
                total_ms: total_duration.as_millis() as u64,
                ..Default::default()
            },
            resolved_ip: None,
            tls_info: None,
            http_status: None,
            error: Some(error.into()),
        }
    }

    /// Set the resolved IP address.
    pub fn with_resolved_ip(mut self, ip: IpAddr) -> Self {
        self.resolved_ip = Some(ip);
        self
    }

    /// Set TLS information.
    pub fn with_tls_info(mut self, info: TlsInfo) -> Self {
        self.tls_info = Some(info);
        self
    }

    /// Set HTTP status code.
    pub fn with_http_status(mut self, status: u16) -> Self {
        self.http_status = Some(status);
        self
    }
}

/// TLS certificate and connection information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsInfo {
    /// TLS protocol version (e.g., "TLSv1.3").
    pub version: String,

    /// Cipher suite used.
    pub cipher: String,

    /// Whether TLS session was resumed.
    pub session_resumed: bool,

    /// Certificate expiration date.
    pub cert_expires: Option<DateTime<Utc>>,

    /// Certificate subject common name.
    pub cert_subject: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timing_breakdown_ttfb_calculation() {
        let timing = TimingBreakdown {
            dns_ms: Some(10),
            tcp_connect_ms: Some(20),
            tls_handshake_ms: Some(30),
            ttfb_ms: Some(40),
            total_ms: 100,
        };
        assert_eq!(timing.time_to_first_byte(), 100);
    }

    #[test]
    fn probe_target_builder() {
        let target = ProbeTarget::new("https://example.com")
            .with_name("Example Site")
            .with_tag("production");

        assert_eq!(target.url, "https://example.com");
        assert_eq!(target.name, Some("Example Site".to_string()));
        assert_eq!(target.tags, vec!["production"]);
    }
}
