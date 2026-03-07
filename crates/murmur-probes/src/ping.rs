//! ICMP Ping probe for measuring gateway and host RTT.
//!
//! Requires elevated privileges (root on Linux/macOS, Administrator on Windows)
//! or appropriate capabilities (CAP_NET_RAW on Linux).

use crate::{Probe, ProbeConfig};
use async_trait::async_trait;
use murmur_core::types::{ProbeResult, ProbeTarget, TimingBreakdown};
use std::net::IpAddr;
use std::time::{Duration, Instant};
use surge_ping::{Client, Config, PingIdentifier, PingSequence, ICMP};
use tracing::{debug, warn};

/// ICMP Ping probe.
///
/// Measures round-trip time to a host using ICMP echo requests.
/// Useful for measuring gateway latency and basic connectivity.
pub struct PingProbe {
    client_v4: Option<Client>,
    client_v6: Option<Client>,
}

impl PingProbe {
    /// Create a new ping probe.
    ///
    /// Returns None if ICMP sockets cannot be created (insufficient privileges).
    pub fn new() -> Option<Self> {
        let config_v4 = Config::builder().kind(ICMP::V4).build();
        let config_v6 = Config::builder().kind(ICMP::V6).build();

        let client_v4 = Client::new(&config_v4).ok();
        let client_v6 = Client::new(&config_v6).ok();

        if client_v4.is_none() && client_v6.is_none() {
            warn!("failed to create ICMP clients - elevated privileges required");
            return None;
        }

        debug!(
            ipv4 = client_v4.is_some(),
            ipv6 = client_v6.is_some(),
            "ping probe initialized"
        );

        Some(Self {
            client_v4,
            client_v6,
        })
    }

    /// Ping a specific IP address.
    pub async fn ping_ip(&self, addr: IpAddr, timeout: Duration) -> PingResult {
        let start = Instant::now();

        let client = match addr {
            IpAddr::V4(_) => self.client_v4.as_ref(),
            IpAddr::V6(_) => self.client_v6.as_ref(),
        };

        let Some(client) = client else {
            return PingResult {
                addr,
                rtt: None,
                success: false,
                error: Some("ICMP client not available for this address family".to_string()),
            };
        };

        let mut pinger = client.pinger(addr, PingIdentifier(rand_u16())).await;
        pinger.timeout(timeout);

        match pinger.ping(PingSequence(0), &[]).await {
            Ok((_, rtt)) => {
                debug!(addr = %addr, rtt_ms = rtt.as_millis(), "ping successful");
                PingResult {
                    addr,
                    rtt: Some(rtt),
                    success: true,
                    error: None,
                }
            }
            Err(e) => {
                debug!(addr = %addr, error = %e, elapsed_ms = start.elapsed().as_millis(), "ping failed");
                PingResult {
                    addr,
                    rtt: None,
                    success: false,
                    error: Some(e.to_string()),
                }
            }
        }
    }

    /// Ping the default gateway.
    pub async fn ping_gateway(&self, timeout: Duration) -> Option<PingResult> {
        let gateway = get_default_gateway()?;
        let addr: IpAddr = gateway.parse().ok()?;
        Some(self.ping_ip(addr, timeout).await)
    }

    /// Resolve a probe target's host and run a ping sequence; returns stats or None if resolve fails.
    pub async fn ping_target_stats(
        &self,
        target: &ProbeTarget,
        count: usize,
        timeout: Duration,
    ) -> Option<PingStatistics> {
        let host = host_from_url(&target.url);
        if host.is_empty() {
            return None;
        }
        let addr = resolve_hostname(host).await?;
        Some(self.ping_stats(addr, count, timeout).await)
    }

    /// Ping multiple times and return statistics.
    pub async fn ping_stats(
        &self,
        addr: IpAddr,
        count: usize,
        timeout: Duration,
    ) -> PingStatistics {
        let mut rtts = Vec::with_capacity(count);
        let mut success_count = 0;

        for _ in 0..count {
            let result = self.ping_ip(addr, timeout).await;
            if result.success {
                success_count += 1;
                if let Some(rtt) = result.rtt {
                    rtts.push(rtt);
                }
            }
            // Small delay between pings
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let packet_loss = if count > 0 {
            ((count - success_count) as f64 / count as f64) * 100.0
        } else {
            100.0
        };

        if rtts.is_empty() {
            return PingStatistics {
                addr,
                packets_sent: count,
                packets_received: success_count,
                packet_loss_percent: packet_loss,
                min_rtt: None,
                max_rtt: None,
                avg_rtt: None,
                stddev_rtt: None,
            };
        }

        let min = rtts.iter().min().copied();
        let max = rtts.iter().max().copied();
        let sum: Duration = rtts.iter().sum();
        let avg = sum / rtts.len() as u32;

        // Calculate standard deviation
        let avg_ms = avg.as_secs_f64() * 1000.0;
        let variance: f64 = rtts
            .iter()
            .map(|rtt| {
                let diff = rtt.as_secs_f64() * 1000.0 - avg_ms;
                diff * diff
            })
            .sum::<f64>()
            / rtts.len() as f64;
        let stddev = Duration::from_secs_f64(variance.sqrt() / 1000.0);

        PingStatistics {
            addr,
            packets_sent: count,
            packets_received: success_count,
            packet_loss_percent: packet_loss,
            min_rtt: min,
            max_rtt: max,
            avg_rtt: Some(avg),
            stddev_rtt: Some(stddev),
        }
    }
}

/// Result of a single ping.
#[derive(Debug, Clone)]
pub struct PingResult {
    /// Target IP address.
    pub addr: IpAddr,
    /// Round-trip time (if successful).
    pub rtt: Option<Duration>,
    /// Whether the ping succeeded.
    pub success: bool,
    /// Error message (if failed).
    pub error: Option<String>,
}

/// Statistics from multiple pings.
#[derive(Debug, Clone)]
pub struct PingStatistics {
    /// Target IP address.
    pub addr: IpAddr,
    /// Number of packets sent.
    pub packets_sent: usize,
    /// Number of packets received.
    pub packets_received: usize,
    /// Packet loss percentage (0-100).
    pub packet_loss_percent: f64,
    /// Minimum RTT.
    pub min_rtt: Option<Duration>,
    /// Maximum RTT.
    pub max_rtt: Option<Duration>,
    /// Average RTT.
    pub avg_rtt: Option<Duration>,
    /// Standard deviation of RTT.
    pub stddev_rtt: Option<Duration>,
}

#[async_trait]
impl Probe for PingProbe {
    fn name(&self) -> &'static str {
        "ping"
    }

    async fn measure(&self, target: &ProbeTarget, config: &ProbeConfig) -> ProbeResult {
        let start = Instant::now();

        // Parse target as IP address or resolve hostname
        let addr: IpAddr = match target.url.parse() {
            Ok(ip) => ip,
            Err(_) => {
                // Try to resolve hostname
                match resolve_hostname(&target.url).await {
                    Some(ip) => ip,
                    None => {
                        return ProbeResult::failure(
                            target.clone(),
                            format!("failed to resolve hostname: {}", target.url),
                            start.elapsed(),
                        );
                    }
                }
            }
        };

        let result = self.ping_ip(addr, config.timeout).await;
        let total = start.elapsed();

        if result.success {
            let timing = TimingBreakdown::default().with_total(result.rtt.unwrap_or(total));
            ProbeResult::success(target.clone(), timing).with_resolved_ip(addr)
        } else {
            ProbeResult::failure(
                target.clone(),
                result.error.unwrap_or_else(|| "ping failed".to_string()),
                total,
            )
        }
    }
}

/// Get default gateway IP address.
#[cfg(target_os = "macos")]
fn get_default_gateway() -> Option<String> {
    use std::process::Command;

    let output = Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;

    if output.status.success() {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            if line.trim().starts_with("gateway:") {
                return line.split(':').nth(1).map(|s| s.trim().to_string());
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn get_default_gateway() -> Option<String> {
    use std::process::Command;

    let output = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .ok()?;

    if output.status.success() {
        let text = String::from_utf8_lossy(&output.stdout);
        let parts: Vec<&str> = text.split_whitespace().collect();
        if parts.len() >= 3 && parts[0] == "default" && parts[1] == "via" {
            return Some(parts[2].to_string());
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn get_default_gateway() -> Option<String> {
    use std::process::Command;

    let output = Command::new("cmd")
        .args(["/C", "route", "print", "0.0.0.0"])
        .output()
        .ok()?;

    if output.status.success() {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 && parts[0] == "0.0.0.0" && parts[1] == "0.0.0.0" {
                return Some(parts[2].to_string());
            }
        }
    }
    None
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn get_default_gateway() -> Option<String> {
    None
}

/// Extract host from URL (e.g. "https://www.google.com/path" -> "www.google.com").
fn host_from_url(url: &str) -> &str {
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

/// Resolve hostname to IP address.
async fn resolve_hostname(hostname: &str) -> Option<IpAddr> {
    use hickory_resolver::TokioAsyncResolver;

    let resolver = TokioAsyncResolver::tokio_from_system_conf().ok()?;
    let response = resolver.lookup_ip(hostname).await.ok()?;
    response.iter().next()
}

/// Generate a random u16 for ping identifier.
fn rand_u16() -> u16 {
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    (now.as_nanos() & 0xFFFF) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_detection() {
        let gateway = get_default_gateway();
        println!("Gateway: {:?}", gateway);
        // May or may not find a gateway depending on environment
    }
}
