//! DNS observer implementation.

use crate::error::{DnsObserverError, DnsObserverErrorKind, Result};
use crate::parser::parse_dns_packet;
use crate::types::{DiscoveredEndpoint, EndpointTracker};
use pcap::{Capture, Device};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, error, info};

/// DNS observer for passively discovering probe targets.
///
/// Captures DNS queries on the network to learn what endpoints are being
/// accessed, then provides those as potential probe targets.
pub struct DnsObserver {
    /// The pcap capture handle.
    device_name: String,

    /// Endpoint tracker shared with readers.
    tracker: Arc<RwLock<EndpointTracker>>,

    /// Broadcast channel for discovered endpoints.
    endpoint_tx: broadcast::Sender<DiscoveredEndpoint>,

    /// Confidence threshold for promoting endpoints to probe targets.
    confidence_threshold: f64,
}

impl DnsObserver {
    /// Create a new DNS observer.
    ///
    /// # Arguments
    ///
    /// * `interface` - Network interface name, or None for default
    /// * `confidence_threshold` - Minimum confidence (0.0-1.0) for probe targets
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No network interfaces are available
    /// - The specified interface doesn't exist
    /// - Packet capture initialization fails (usually permissions)
    pub fn new(interface: Option<&str>, confidence_threshold: f64) -> Result<Self> {
        let device = match interface {
            Some(name) => {
                Device::list()
                    .map_err(|e| DnsObserverError::capture(e.to_string()))?
                    .into_iter()
                    .find(|d| d.name == name)
                    .ok_or_else(|| {
                        DnsObserverError::new(DnsObserverErrorKind::InterfaceNotFound {
                            name: name.to_string(),
                        })
                    })?
            }
            None => Device::lookup()
                .map_err(|e| DnsObserverError::capture(e.to_string()))?
                .ok_or_else(DnsObserverError::no_interfaces)?,
        };

        info!(interface = %device.name, "DNS observer initialized");

        let (endpoint_tx, _) = broadcast::channel(256);

        Ok(Self {
            device_name: device.name,
            tracker: Arc::new(RwLock::new(EndpointTracker::new())),
            endpoint_tx,
            confidence_threshold,
        })
    }

    /// Subscribe to discovered endpoints.
    ///
    /// Returns a receiver that will get new endpoints as they're discovered.
    pub fn subscribe(&self) -> broadcast::Receiver<DiscoveredEndpoint> {
        self.endpoint_tx.subscribe()
    }

    /// Get a reference to the endpoint tracker for reading current state.
    pub fn tracker(&self) -> Arc<RwLock<EndpointTracker>> {
        self.tracker.clone()
    }

    /// Get current probe targets (endpoints above confidence threshold).
    pub async fn get_probe_targets(&self) -> Vec<DiscoveredEndpoint> {
        let tracker = self.tracker.read().await;
        tracker
            .get_probe_targets(self.confidence_threshold)
            .into_iter()
            .cloned()
            .collect()
    }

    /// Run the DNS observer.
    ///
    /// This method blocks and runs until an error occurs or the process is
    /// terminated. It should be spawned as a background task.
    ///
    /// # Errors
    ///
    /// Returns an error if packet capture fails, typically due to:
    /// - Insufficient permissions
    /// - Interface going down
    /// - System resource exhaustion
    pub async fn run(self) -> Result<()> {
        // Open capture on the device
        let mut cap = Capture::from_device(self.device_name.as_str())
            .map_err(map_pcap_error)?
            .promisc(false)
            .snaplen(512) // Enough for DNS packets
            .timeout(100) // 100ms timeout for non-blocking
            .open()
            .map_err(map_pcap_error)?;

        // Apply BPF filter for DNS traffic only
        cap.filter("udp port 53", true)
            .map_err(|e| DnsObserverError::capture(format!("failed to set BPF filter: {e}")))?;

        info!("DNS observation started");

        // Prune timer
        let mut last_prune = Instant::now();
        let prune_interval = Duration::from_secs(300); // Prune every 5 minutes
        let max_endpoint_age = Duration::from_secs(3600); // Keep endpoints for 1 hour

        loop {
            // Try to get next packet (non-blocking due to timeout)
            match cap.next_packet() {
                Ok(packet) => {
                    let timestamp = Instant::now();

                    // Parse the DNS packet
                    match parse_dns_packet(packet.data, timestamp) {
                        Ok(Some(query)) => {
                            debug!(
                                hostname = %query.hostname,
                                query_type = ?query.query_type,
                                "DNS query observed"
                            );

                            // Record in tracker
                            let mut tracker = self.tracker.write().await;
                            tracker.record_query(&query);

                            // If this endpoint crosses the threshold, broadcast it
                            if let Some(endpoint) = tracker
                                .get_probe_targets(self.confidence_threshold)
                                .into_iter()
                                .find(|e| e.hostname == query.hostname)
                            {
                                // Ignore send errors (no subscribers)
                                let _ = self.endpoint_tx.send(endpoint.clone());
                            }
                        }
                        Ok(None) => {
                            // Not a DNS query we care about
                        }
                        Err(e) => {
                            debug!(error = %e, "failed to parse packet");
                        }
                    }
                }
                Err(pcap::Error::TimeoutExpired) => {
                    // Normal timeout, continue
                }
                Err(e) => {
                    error!(error = %e, "packet capture error");
                    return Err(DnsObserverError::capture(e.to_string()));
                }
            }

            // Periodic maintenance
            if last_prune.elapsed() > prune_interval {
                let mut tracker = self.tracker.write().await;
                let before = tracker.len();
                tracker.prune_old(max_endpoint_age);
                let after = tracker.len();

                if before != after {
                    info!(pruned = before - after, remaining = after, "pruned old endpoints");
                }

                last_prune = Instant::now();
            }

            // Yield to other tasks
            tokio::task::yield_now().await;
        }
    }

    /// List available network interfaces.
    pub fn list_interfaces() -> Result<Vec<String>> {
        Device::list()
            .map_err(|e| DnsObserverError::capture(e.to_string()))
            .map(|devices| devices.into_iter().map(|d| d.name).collect())
    }
}

/// Map pcap errors to our error type with helpful messages.
fn map_pcap_error(err: pcap::Error) -> DnsObserverError {
    let msg = err.to_string();

    // Check for permission-related errors
    if msg.contains("permission")
        || msg.contains("Operation not permitted")
        || msg.contains("access denied")
        || msg.contains("EPERM")
    {
        #[cfg(target_os = "linux")]
        let guidance = "Run as root or set capabilities: sudo setcap cap_net_raw,cap_net_admin=eip <binary>";

        #[cfg(target_os = "macos")]
        let guidance = "Run as root or add user to access_bpf group";

        #[cfg(target_os = "windows")]
        let guidance = "Run as Administrator with Npcap installed";

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        let guidance = "Run with elevated privileges";

        return DnsObserverError::permission(format!("{msg}. {guidance}"));
    }

    DnsObserverError::capture(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_interfaces_works() {
        // This test requires pcap to be available
        let result = DnsObserver::list_interfaces();
        // Don't assert success since CI might not have pcap
        if let Ok(interfaces) = result {
            println!("Available interfaces: {:?}", interfaces);
        }
    }
}
