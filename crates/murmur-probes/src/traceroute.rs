//! Traceroute probe for path visualization.
//!
//! Traces the network path to a destination by sending packets with
//! incrementing TTL values, recording the responding router at each hop.
//! IPv4: raw ICMP (Linux) or UDP probes + raw ICMP recv (macOS). See the
//! `traceroute_raw` module for platform-specific send/recv logic.
//!
//! Requires elevated privileges (root on Linux/macOS, Administrator on Windows).

#[path = "traceroute_raw.rs"]
mod traceroute_raw;

use crate::ProbeConfig;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::{Duration, Instant};
use surge_ping::{Client, Config, PingIdentifier, PingSequence, ICMP};
use tracing::{debug, warn};

/// Maximum number of hops to trace.
pub const MAX_HOPS: u8 = 30;

/// Default number of probes per hop.
pub const DEFAULT_PROBES_PER_HOP: usize = 3;

/// Traceroute probe for path visualization.
///
/// IPv4: raw ICMP socket per hop; captures "Time Exceeded" from each router.
/// IPv6: falls back to surge-ping (only destination hop visible).
pub struct TracerouteProbe {
    _marker: std::marker::PhantomData<()>,
}

impl TracerouteProbe {
    /// Create a new traceroute probe.
    ///
    /// Returns None if ICMP sockets cannot be created (insufficient privileges).
    pub fn new() -> Option<Self> {
        let kind = ICMP::V4;
        let config = Config::builder().kind(kind).ttl(1).build();
        if Client::new(&config).is_err() {
            let config6 = Config::builder().kind(ICMP::V6).ttl(1).build();
            if Client::new(&config6).is_err() {
                warn!("failed to create ICMP socket - elevated privileges required");
                return None;
            }
        }
        debug!("traceroute probe initialized");
        Some(Self {
            _marker: std::marker::PhantomData,
        })
    }

    /// Trace the path to a destination.
    ///
    /// IPv4 on Linux: raw ICMP (Echo Request + TTL), receive Time Exceeded / Echo Reply.
    /// IPv4 on macOS: UDP to port 33434 + raw ICMP recv (Time Exceeded / Port Unreachable),
    /// same as system traceroute.
    /// IPv6: surge-ping (only final hop has an address).
    pub async fn trace(&self, dest: IpAddr, config: &ProbeConfig) -> TracerouteResult {
        let start = Instant::now();

        match dest {
            IpAddr::V4(dest_v4) => {
                #[cfg(target_os = "macos")]
                let use_udp = true;
                #[cfg(not(target_os = "macos"))]
                let use_udp = false;

                if use_udp {
                    // macOS: UDP traceroute (send UDP, recv ICMP Time Exceeded / Port Unreachable).
                    let timeout = config.timeout;
                    let probes = DEFAULT_PROBES_PER_HOP;
                    let (hops, destination_reached) = tokio::task::spawn_blocking(move || {
                        traceroute_raw::trace_udp_v4(dest_v4, timeout, probes)
                    })
                    .await
                    .unwrap_or((Vec::new(), false));

                    let n_hops = hops.len();
                    return TracerouteResult {
                        destination: dest,
                        destination_reached,
                        hops,
                        total_duration: start.elapsed(),
                        error: if destination_reached {
                            None
                        } else if n_hops >= MAX_HOPS as usize {
                            Some(format!(
                                "destination not reached within {} hops",
                                MAX_HOPS
                            ))
                        } else {
                            None
                        },
                    };
                }

                // Linux (and other): raw ICMP per hop.
                let mut hops = Vec::with_capacity(MAX_HOPS as usize);
                let ident = rand_u16();
                for ttl in 1..=MAX_HOPS {
                    let timeout = config.timeout;
                    let probes = DEFAULT_PROBES_PER_HOP;
                    let hop = tokio::task::spawn_blocking(move || {
                        traceroute_raw::trace_hop_raw_v4(dest_v4, ttl, timeout, probes, ident)
                    })
                    .await
                    .unwrap_or_else(|_| TracerouteHop {
                        ttl,
                        addr: None,
                        hostname: None,
                        min_rtt: None,
                        max_rtt: None,
                        avg_rtt: None,
                        rtts: None,
                        packet_loss: 100.0,
                        probes_sent: probes,
                        probes_received: 0,
                    });

                    let reached = hop.addr.map(|a| a == dest).unwrap_or(false);
                    hops.push(hop);

                    if reached {
                        debug!(ttl = ttl, destination = %dest, "destination reached");
                        return TracerouteResult {
                            destination: dest,
                            destination_reached: true,
                            hops,
                            total_duration: start.elapsed(),
                            error: None,
                        };
                    }
                }

                return TracerouteResult {
                    destination: dest,
                    destination_reached: false,
                    hops,
                    total_duration: start.elapsed(),
                    error: Some(format!(
                        "destination not reached within {} hops",
                        MAX_HOPS
                    )),
                };
            }
            IpAddr::V6(_) => {
                let mut hops = Vec::with_capacity(MAX_HOPS as usize);
                let kind = ICMP::V6;
                for ttl in 1..=MAX_HOPS {
                    let hop = Self::probe_hop_with_ttl(
                        dest,
                        kind,
                        ttl,
                        DEFAULT_PROBES_PER_HOP,
                        config.timeout,
                    )
                    .await;

                    let reached = hop.addr.map(|a| a == dest).unwrap_or(false);
                    hops.push(hop);

                    if reached {
                        debug!(ttl = ttl, destination = %dest, "destination reached");
                        return TracerouteResult {
                            destination: dest,
                            destination_reached: true,
                            hops,
                            total_duration: start.elapsed(),
                            error: None,
                        };
                    }
                }
                warn!(destination = %dest, max_hops = MAX_HOPS, "max hops reached without finding destination");
                return TracerouteResult {
                    destination: dest,
                    destination_reached: false,
                    hops,
                    total_duration: start.elapsed(),
                    error: Some(format!(
                        "destination not reached within {} hops",
                        MAX_HOPS
                    )),
                };
            }
        }
    }

    /// Probe a single hop by creating a client with that TTL.
    /// Only the destination sends Echo Reply; intermediate "Time Exceeded"
    /// replies are not matched by surge-ping, so we get timeouts for those.
    async fn probe_hop_with_ttl(
        dest: IpAddr,
        kind: ICMP,
        ttl: u8,
        probes: usize,
        timeout: Duration,
    ) -> TracerouteHop {
        let mut rtts = Vec::with_capacity(probes);
        let mut responding_addr: Option<IpAddr> = None;

        let config = Config::builder()
            .kind(kind)
            .ttl(ttl as u32)
            .build();

        let Ok(client) = Client::new(&config) else {
            return TracerouteHop {
                ttl,
                addr: None,
                hostname: None,
                min_rtt: None,
                max_rtt: None,
                avg_rtt: None,
                rtts: None,
                packet_loss: 100.0,
                probes_sent: probes,
                probes_received: 0,
            };
        };

        for seq in 0..probes {
            let mut pinger = client.pinger(dest, PingIdentifier(rand_u16())).await;
            pinger.timeout(timeout);

            match pinger.ping(PingSequence(seq as u16), &[]).await {
                Ok((packet, rtt)) => {
                    // Reply only comes from the host that echoes; at TTL=n that's
                    // the destination when we've reached it (or a router that
                    // echoes, rare). surge-ping gives us the reply packet source.
                    let reply_src = match &packet {
                        surge_ping::IcmpPacket::V4(p) => IpAddr::V4(p.get_source()),
                        surge_ping::IcmpPacket::V6(p) => IpAddr::V6(p.get_source()),
                    };
                    if responding_addr.is_none() {
                        responding_addr = Some(reply_src);
                    }
                    rtts.push(rtt);
                }
                Err(_) => {
                    // Timeout or TTL exceeded from an intermediate hop (not delivered by surge-ping)
                }
            }
        }

        let (min_rtt, max_rtt, avg_rtt) = if rtts.is_empty() {
            (None, None, None)
        } else {
            let min = rtts.iter().min().copied();
            let max = rtts.iter().max().copied();
            let sum: Duration = rtts.iter().sum();
            let avg = Some(sum / rtts.len() as u32);
            (min, max, avg)
        };

        TracerouteHop {
            ttl,
            addr: responding_addr,
            hostname: None,
            min_rtt,
            max_rtt,
            avg_rtt,
            rtts: None,
            packet_loss: if probes > 0 {
                ((probes - rtts.len()) as f64 / probes as f64) * 100.0
            } else {
                100.0
            },
            probes_sent: probes,
            probes_received: rtts.len(),
        }
    }

    /// Trace with reverse DNS resolution for hostnames.
    pub async fn trace_with_dns(&self, dest: IpAddr, config: &ProbeConfig) -> TracerouteResult {
        let mut result = self.trace(dest, config).await;

        // Resolve hostnames for each hop
        for hop in &mut result.hops {
            if let Some(addr) = hop.addr {
                hop.hostname = reverse_dns(addr).await;
            }
        }

        result
    }
}

/// A single hop in a traceroute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracerouteHop {
    /// TTL value (hop number).
    pub ttl: u8,

    /// IP address of the router at this hop (None if no response).
    pub addr: Option<IpAddr>,

    /// Hostname of the router (from reverse DNS).
    pub hostname: Option<String>,

    /// Minimum RTT to this hop.
    pub min_rtt: Option<Duration>,

    /// Maximum RTT to this hop.
    pub max_rtt: Option<Duration>,

    /// Average RTT to this hop.
    pub avg_rtt: Option<Duration>,

    /// Per-probe RTTs in order (probe 0, 1, 2) for display. None = no reply.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtts: Option<Vec<Option<Duration>>>,

    /// Packet loss percentage (0-100).
    pub packet_loss: f64,

    /// Number of probes sent.
    pub probes_sent: usize,

    /// Number of probes that received responses.
    pub probes_received: usize,
}

impl TracerouteHop {
    /// Check if this hop responded.
    pub fn responded(&self) -> bool {
        self.addr.is_some()
    }

    /// Get average RTT in milliseconds.
    pub fn avg_rtt_ms(&self) -> Option<f64> {
        self.avg_rtt.map(|d| d.as_secs_f64() * 1000.0)
    }
}

/// Result of a complete traceroute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracerouteResult {
    /// Destination IP address.
    pub destination: IpAddr,

    /// Whether the destination was reached.
    pub destination_reached: bool,

    /// Hops along the path.
    pub hops: Vec<TracerouteHop>,

    /// Total duration of the traceroute.
    pub total_duration: Duration,

    /// Error message if traceroute failed.
    pub error: Option<String>,
}

impl TracerouteResult {
    /// Get the number of hops to destination.
    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }

    /// Get total path latency (sum of avg RTTs).
    pub fn total_latency(&self) -> Duration {
        self.hops
            .iter()
            .filter_map(|h| h.avg_rtt)
            .fold(Duration::ZERO, |acc, rtt| acc + rtt)
    }

    /// Hops that did not respond to any probe (router silent; common in traceroute).
    pub fn non_responding_hops(&self) -> Vec<&TracerouteHop> {
        self.hops
            .iter()
            .filter(|h| h.probes_received == 0)
            .collect()
    }

    /// Hops that responded at least once but had packet loss above the threshold.
    /// Excludes hops that did not respond at all (use `non_responding_hops` for those).
    pub fn lossy_hops(&self, threshold: f64) -> Vec<&TracerouteHop> {
        self.hops
            .iter()
            .filter(|h| h.probes_received > 0 && h.packet_loss > threshold)
            .collect()
    }

    /// Convert to a path string like system traceroute (hop, IP/hostname, three RTTs).
    pub fn to_path_string(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!("Traceroute to {}", self.destination));
        lines.push(String::new());

        for hop in &self.hops {
            let addr_str = hop
                .addr
                .map(|a| a.to_string())
                .unwrap_or_else(|| "*".to_string());

            let hostname_str = hop
                .hostname
                .as_ref()
                .map(|h| format!(" ({})", h))
                .unwrap_or_default();

            let rtt_str = if let Some(rtts) = &hop.rtts {
                rtts.iter()
                    .map(|r| {
                        r.map(|d| format!("{:.3} ms", d.as_secs_f64() * 1000.0))
                            .unwrap_or_else(|| "*".to_string())
                    })
                    .collect::<Vec<_>>()
                    .join("  ")
            } else {
                hop.avg_rtt_ms()
                    .map(|ms| format!("{:.3} ms", ms))
                    .unwrap_or_else(|| "*".to_string())
            };

            lines.push(format!(
                "{:2}  {}{}  {}",
                hop.ttl,
                addr_str,
                hostname_str,
                rtt_str
            ));
        }

        if self.destination_reached {
            lines.push(String::new());
            lines.push(format!(
                "Destination reached in {} hops, total latency: {:.2}ms",
                self.hop_count(),
                self.total_latency().as_secs_f64() * 1000.0
            ));
        }

        lines.join("\n")
    }
}

/// Reverse DNS lookup.
async fn reverse_dns(addr: IpAddr) -> Option<String> {
    use hickory_resolver::TokioAsyncResolver;

    let resolver = TokioAsyncResolver::tokio_from_system_conf().ok()?;
    let response = resolver.reverse_lookup(addr).await.ok()?;
    response.iter().next().map(|name| name.to_string())
}

/// Generate a random u16 for ping identifier.
fn rand_u16() -> u16 {
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    ((now.as_nanos() >> 16) & 0xFFFF) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traceroute_hop_display() {
        let hop = TracerouteHop {
            ttl: 1,
            addr: Some("192.168.1.1".parse().unwrap()),
            hostname: Some("gateway.local".to_string()),
            min_rtt: Some(Duration::from_micros(500)),
            max_rtt: Some(Duration::from_millis(2)),
            avg_rtt: Some(Duration::from_millis(1)),
            rtts: None,
            packet_loss: 0.0,
            probes_sent: 3,
            probes_received: 3,
        };

        assert!(hop.responded());
        assert!((hop.avg_rtt_ms().unwrap() - 1.0).abs() < 0.01);
    }
}
