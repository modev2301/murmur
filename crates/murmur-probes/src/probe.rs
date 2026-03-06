//! Core probe trait and configuration.
//!
//! Probes follow the component lifecycle pattern from vector:
//! 1. `initialize()` - validate config, establish connections, allocate resources
//! 2. `measure()` - execute a single measurement (called repeatedly)
//! 3. `shutdown()` - flush buffers, close connections cleanly

use async_trait::async_trait;
use murmur_core::{ProbeResult, ProbeTarget};
use std::time::Duration;
use tokio::sync::broadcast;

/// Configuration for probe execution.
#[derive(Debug, Clone)]
pub struct ProbeConfig {
    /// Total timeout for the probe.
    pub timeout: Duration,
    /// DNS resolution timeout.
    pub dns_timeout: Duration,
    /// TCP connection timeout.
    pub tcp_timeout: Duration,
    /// TLS handshake timeout.
    pub tls_timeout: Duration,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            dns_timeout: Duration::from_secs(5),
            tcp_timeout: Duration::from_secs(10),
            tls_timeout: Duration::from_secs(10),
        }
    }
}

impl ProbeConfig {
    /// Create a new probe config with the specified total timeout.
    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            timeout,
            ..Default::default()
        }
    }
}

/// Context passed to probes during execution.
pub struct ProbeContext {
    /// Shutdown signal receiver.
    pub shutdown: broadcast::Receiver<()>,
}

impl ProbeContext {
    /// Create a new probe context.
    pub fn new(shutdown: broadcast::Receiver<()>) -> Self {
        Self { shutdown }
    }
}

/// Trait for all probe types.
///
/// Probes measure network path quality to a target endpoint. Each probe type
/// focuses on a specific layer of the network stack (DNS, TCP, TLS, HTTP).
///
/// # Lifecycle
///
/// Probes follow a three-phase lifecycle modeled after vector's component pattern:
///
/// 1. **Initialize** - Called once before measurements begin. Use this to
///    validate configuration, establish connection pools, or allocate resources
///    that should be reused across measurements.
///
/// 2. **Measure** - Called repeatedly at the configured interval. Each call
///    should execute a single measurement and return quickly. Must respect
///    configured timeouts.
///
/// 3. **Shutdown** - Called once when the agent is stopping. Use this to
///    flush any buffered data and release resources cleanly.
///
/// # Error Handling
///
/// Measurement failures should be returned as `ProbeResult::failure()`, not
/// as errors. The probe should continue operating after a failed measurement.
/// Only unrecoverable errors (like invalid configuration) should cause the
/// probe to stop.
#[async_trait]
pub trait Probe: Send + Sync {
    /// The name of this probe type (e.g., "dns", "tcp", "http").
    fn name(&self) -> &'static str;

    /// Initialize the probe before measurements begin.
    ///
    /// This is called once during agent startup. Use it to:
    /// - Validate configuration
    /// - Establish connection pools
    /// - Pre-allocate buffers
    /// - Perform any one-time setup
    ///
    /// The default implementation does nothing.
    async fn initialize(&mut self) -> Result<(), murmur_core::Error> {
        Ok(())
    }

    /// Execute a measurement against the target.
    ///
    /// Returns a `ProbeResult` with timing breakdown and success/failure status.
    /// The probe should respect the configured timeouts and return a timeout
    /// error rather than blocking indefinitely.
    ///
    /// # Arguments
    ///
    /// * `target` - The endpoint to probe
    /// * `config` - Timeout configuration for this measurement
    async fn measure(&self, target: &ProbeTarget, config: &ProbeConfig) -> ProbeResult;

    /// Shutdown the probe and release resources.
    ///
    /// This is called once during agent shutdown. Use it to:
    /// - Close connection pools
    /// - Flush any buffered data
    /// - Release allocated resources
    ///
    /// The default implementation does nothing.
    async fn shutdown(&mut self) {
        // Default: no cleanup needed
    }
}
