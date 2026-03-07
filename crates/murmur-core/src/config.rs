//! Configuration loading and validation.
//!
//! Configuration follows a layered approach:
//! 1. Compiled defaults (always safe)
//! 2. Config file (/etc/murmur/config.toml)
//! 3. Environment variables (MURMUR_*)

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// Default probe interval in seconds.
const DEFAULT_PROBE_INTERVAL_SECS: u64 = 60;

/// Default probe timeout in seconds.
const DEFAULT_PROBE_TIMEOUT_SECS: u64 = 30;

/// Default DNS timeout in seconds.
const DEFAULT_DNS_TIMEOUT_SECS: u64 = 5;

/// Default TCP connect timeout in seconds.
const DEFAULT_TCP_TIMEOUT_SECS: u64 = 10;

/// Default TLS handshake timeout in seconds.
const DEFAULT_TLS_TIMEOUT_SECS: u64 = 10;

/// Default OTEL collector endpoint.
const DEFAULT_COLLECTOR_ENDPOINT: &str = "http://localhost:4317";

/// Agent configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentConfig {
    /// Probe settings.
    pub probe: ProbeConfig,

    /// Collector settings.
    pub collector: CollectorConfig,

    /// Logging settings.
    pub logging: LoggingConfig,
}

impl AgentConfig {
    /// Load configuration from file and environment.
    ///
    /// Priority (highest wins):
    /// 1. Environment variables (MURMUR_*)
    /// 2. Config file
    /// 3. Compiled defaults
    pub fn load(config_path: Option<PathBuf>) -> Result<Self> {
        let mut builder = config::Config::builder();

        // Set defaults
        builder = builder
            .set_default("probe.interval_seconds", DEFAULT_PROBE_INTERVAL_SECS as i64)
            .map_err(|e| Error::config(e.to_string()))?
            .set_default("probe.timeout_seconds", DEFAULT_PROBE_TIMEOUT_SECS as i64)
            .map_err(|e| Error::config(e.to_string()))?
            .set_default("probe.dns_timeout_seconds", DEFAULT_DNS_TIMEOUT_SECS as i64)
            .map_err(|e| Error::config(e.to_string()))?
            .set_default("probe.tcp_timeout_seconds", DEFAULT_TCP_TIMEOUT_SECS as i64)
            .map_err(|e| Error::config(e.to_string()))?
            .set_default("probe.tls_timeout_seconds", DEFAULT_TLS_TIMEOUT_SECS as i64)
            .map_err(|e| Error::config(e.to_string()))?
            .set_default("collector.endpoint", DEFAULT_COLLECTOR_ENDPOINT)
            .map_err(|e| Error::config(e.to_string()))?
            .set_default("logging.format", "json")
            .map_err(|e| Error::config(e.to_string()))?
            .set_default("logging.level", "info")
            .map_err(|e| Error::config(e.to_string()))?;

        // Add config file if specified or use default path
        let config_file = config_path.unwrap_or_else(|| PathBuf::from("/etc/murmur/config.toml"));
        builder = builder.add_source(
            config::File::from(config_file)
                .format(config::FileFormat::Toml)
                .required(false),
        );

        // Add environment variables
        builder = builder.add_source(
            config::Environment::with_prefix("MURMUR")
                .separator("_")
                .try_parsing(true),
        );

        let config = builder.build().map_err(|e| Error::config(e.to_string()))?;

        let mut agent_config: AgentConfig = config
            .try_deserialize()
            .map_err(|e| Error::config(e.to_string()))?;

        // Environment overrides: the config crate's Environment with separator "_" turns
        // MURMUR_PROBE_INTERVAL_SECONDS into "probe.interval.seconds" (three levels), not
        // "probe.interval_seconds", so env vars don't override. Apply them explicitly.
        if let Ok(s) = std::env::var("MURMUR_PROBE_INTERVAL_SECONDS") {
            if let Ok(n) = s.parse::<u64>() {
                agent_config.probe.interval_seconds = n;
            }
        }
        if let Ok(s) = std::env::var("MURMUR_PROBE_TIMEOUT_SECONDS") {
            if let Ok(n) = s.parse::<u64>() {
                agent_config.probe.timeout_seconds = n;
            }
        }
        // Ensure timeout < interval (validation requirement); cap if env only set interval
        if agent_config.probe.timeout_seconds >= agent_config.probe.interval_seconds {
            agent_config.probe.timeout_seconds =
                agent_config.probe.interval_seconds.saturating_sub(1).max(1);
        }
        // Ensure sum of individual timeouts does not exceed total timeout (scale down if needed)
        let sum_timeouts = agent_config.probe.dns_timeout_seconds
            + agent_config.probe.tcp_timeout_seconds
            + agent_config.probe.tls_timeout_seconds;
        if sum_timeouts > agent_config.probe.timeout_seconds
            && agent_config.probe.timeout_seconds > 0
        {
            let t = agent_config.probe.timeout_seconds;
            let sum = sum_timeouts;
            agent_config.probe.dns_timeout_seconds =
                (agent_config.probe.dns_timeout_seconds * t / sum).max(1);
            agent_config.probe.tcp_timeout_seconds =
                (agent_config.probe.tcp_timeout_seconds * t / sum).max(1);
            agent_config.probe.tls_timeout_seconds =
                (agent_config.probe.tls_timeout_seconds * t / sum).max(1);
        }
        if let Ok(s) = std::env::var("MURMUR_COLLECTOR_ENDPOINT") {
            if !s.is_empty() {
                agent_config.collector.endpoint = s;
            }
        }

        // Validate before returning
        agent_config.validate()?;

        Ok(agent_config)
    }

    /// Validate the configuration.
    ///
    /// Fails fast with a clear error message rather than silently using
    /// invalid values.
    pub fn validate(&self) -> Result<()> {
        // Probe interval must be positive
        if self.probe.interval_seconds == 0 {
            return Err(Error::config(
                "probe.interval_seconds must be greater than 0",
            ));
        }

        // Timeout must be less than interval (otherwise probes pile up)
        if self.probe.timeout_seconds >= self.probe.interval_seconds {
            return Err(Error::config(format!(
                "probe.timeout_seconds ({}) must be less than probe.interval_seconds ({})",
                self.probe.timeout_seconds, self.probe.interval_seconds
            )));
        }

        // Individual timeouts should sum to less than total timeout
        let sum_timeouts = self.probe.dns_timeout_seconds
            + self.probe.tcp_timeout_seconds
            + self.probe.tls_timeout_seconds;
        if sum_timeouts > self.probe.timeout_seconds {
            return Err(Error::config(format!(
                "sum of individual timeouts ({sum_timeouts}s) exceeds total probe timeout ({}s)",
                self.probe.timeout_seconds
            )));
        }

        // Collector endpoint must be a valid URL
        if self.collector.endpoint.is_empty() {
            return Err(Error::config("collector.endpoint cannot be empty"));
        }
        if !self.collector.endpoint.starts_with("http://")
            && !self.collector.endpoint.starts_with("https://")
        {
            return Err(Error::config(format!(
                "collector.endpoint must be an HTTP(S) URL, got: {}",
                self.collector.endpoint
            )));
        }

        Ok(())
    }
}

/// Probe-specific configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProbeConfig {
    /// Interval between probe runs (seconds).
    pub interval_seconds: u64,

    /// Total timeout for a single probe (seconds).
    pub timeout_seconds: u64,

    /// DNS resolution timeout (seconds).
    pub dns_timeout_seconds: u64,

    /// TCP connect timeout (seconds).
    pub tcp_timeout_seconds: u64,

    /// TLS handshake timeout (seconds).
    pub tls_timeout_seconds: u64,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            interval_seconds: DEFAULT_PROBE_INTERVAL_SECS,
            timeout_seconds: DEFAULT_PROBE_TIMEOUT_SECS,
            dns_timeout_seconds: DEFAULT_DNS_TIMEOUT_SECS,
            tcp_timeout_seconds: DEFAULT_TCP_TIMEOUT_SECS,
            tls_timeout_seconds: DEFAULT_TLS_TIMEOUT_SECS,
        }
    }
}

impl ProbeConfig {
    /// Get the probe interval as a Duration.
    pub fn interval(&self) -> Duration {
        Duration::from_secs(self.interval_seconds)
    }

    /// Get the total probe timeout as a Duration.
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_seconds)
    }

    /// Get the DNS timeout as a Duration.
    pub fn dns_timeout(&self) -> Duration {
        Duration::from_secs(self.dns_timeout_seconds)
    }

    /// Get the TCP timeout as a Duration.
    pub fn tcp_timeout(&self) -> Duration {
        Duration::from_secs(self.tcp_timeout_seconds)
    }

    /// Get the TLS timeout as a Duration.
    pub fn tls_timeout(&self) -> Duration {
        Duration::from_secs(self.tls_timeout_seconds)
    }
}

/// OTEL collector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CollectorConfig {
    /// OTEL collector endpoint (gRPC).
    pub endpoint: String,

    /// Whether to use TLS for collector connection.
    pub tls: bool,

    /// Batch size for metric export.
    pub batch_size: usize,

    /// Export interval in seconds.
    pub export_interval_seconds: u64,
}

impl Default for CollectorConfig {
    fn default() -> Self {
        Self {
            endpoint: DEFAULT_COLLECTOR_ENDPOINT.to_string(),
            tls: false,
            batch_size: 512,
            export_interval_seconds: 10,
        }
    }
}

/// Logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    /// Log format: "json" or "pretty".
    pub format: String,

    /// Log level: "trace", "debug", "info", "warn", "error".
    pub level: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            format: "json".to_string(),
            level: "info".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        let config = AgentConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn zero_interval_is_invalid() {
        let mut config = AgentConfig::default();
        config.probe.interval_seconds = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn timeout_exceeding_interval_is_invalid() {
        let mut config = AgentConfig::default();
        config.probe.interval_seconds = 30;
        config.probe.timeout_seconds = 30; // Equal, not less
        assert!(config.validate().is_err());
    }

    #[test]
    fn empty_collector_endpoint_is_invalid() {
        let mut config = AgentConfig::default();
        config.collector.endpoint = String::new();
        assert!(config.validate().is_err());
    }

    #[test]
    fn non_http_collector_endpoint_is_invalid() {
        let mut config = AgentConfig::default();
        config.collector.endpoint = "grpc://localhost:4317".to_string();
        assert!(config.validate().is_err());
    }
}
