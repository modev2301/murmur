//! TCP connection probe.
//!
//! Measures TCP connection establishment time.

use crate::{Probe, ProbeConfig};
use async_trait::async_trait;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use murmur_core::{ProbeResult, ProbeTarget, TimingBreakdown};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, instrument};

/// TCP connection probe.
pub struct TcpProbe {
    resolver: Arc<TokioAsyncResolver>,
}

impl TcpProbe {
    /// Create a new TCP probe.
    pub fn new() -> Self {
        let resolver = TokioAsyncResolver::tokio_from_system_conf()
            .unwrap_or_else(|_| TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default()));
        Self {
            resolver: Arc::new(resolver),
        }
    }

    /// Parse a target URL into host and port.
    fn parse_target(url: &str) -> (&str, u16) {
        let (scheme, rest) = if let Some(stripped) = url.strip_prefix("https://") {
            ("https", stripped)
        } else if let Some(stripped) = url.strip_prefix("http://") {
            ("http", stripped)
        } else {
            ("", url)
        };

        let host_port = rest.split('/').next().unwrap_or(rest);

        if let Some(colon_pos) = host_port.rfind(':') {
            let host = &host_port[..colon_pos];
            let port_str = &host_port[colon_pos + 1..];
            if let Ok(port) = port_str.parse::<u16>() {
                return (host, port);
            }
        }

        // Default ports based on scheme
        let default_port = match scheme {
            "https" => 443,
            "http" => 80,
            _ => 80,
        };

        (host_port.split(':').next().unwrap_or(host_port), default_port)
    }
}

impl Default for TcpProbe {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Probe for TcpProbe {
    fn name(&self) -> &'static str {
        "tcp"
    }

    #[instrument(skip(self, config), fields(target = %target.url))]
    async fn measure(&self, target: &ProbeTarget, config: &ProbeConfig) -> ProbeResult {
        let (hostname, port) = Self::parse_target(&target.url);
        let overall_start = Instant::now();

        // Phase 1: DNS resolution
        debug!(hostname = hostname, "resolving DNS");
        let dns_start = Instant::now();

        let dns_result = timeout(config.dns_timeout, self.resolver.lookup_ip(hostname)).await;

        let dns_elapsed = dns_start.elapsed();

        let resolved_ip = match dns_result {
            Ok(Ok(lookup)) => {
                if let Some(ip) = lookup.iter().next() {
                    debug!(hostname = hostname, ip = %ip, "DNS resolved");
                    ip
                } else {
                    return ProbeResult::failure(
                        target.clone(),
                        format!("DNS lookup returned no addresses for {hostname}"),
                        overall_start.elapsed(),
                    );
                }
            }
            Ok(Err(e)) => {
                return ProbeResult::failure(
                    target.clone(),
                    format!("DNS resolution failed for {hostname}: {e}"),
                    overall_start.elapsed(),
                );
            }
            Err(_) => {
                return ProbeResult::failure(
                    target.clone(),
                    format!(
                        "DNS resolution timed out after {}ms for {hostname}",
                        config.dns_timeout.as_millis()
                    ),
                    overall_start.elapsed(),
                );
            }
        };

        // Phase 2: TCP connection
        let addr = SocketAddr::new(resolved_ip, port);
        debug!(addr = %addr, "connecting TCP");
        let tcp_start = Instant::now();

        let tcp_result = timeout(config.tcp_timeout, TcpStream::connect(addr)).await;

        let tcp_elapsed = tcp_start.elapsed();
        let total_elapsed = overall_start.elapsed();

        match tcp_result {
            Ok(Ok(_stream)) => {
                debug!(
                    addr = %addr,
                    tcp_ms = tcp_elapsed.as_millis(),
                    total_ms = total_elapsed.as_millis(),
                    "TCP connection succeeded"
                );

                let timing = TimingBreakdown::default()
                    .with_dns(dns_elapsed)
                    .with_tcp(tcp_elapsed)
                    .with_total(total_elapsed);

                ProbeResult::success(target.clone(), timing)
                    .with_resolved_ip(resolved_ip)
            }
            Ok(Err(e)) => {
                debug!(addr = %addr, error = %e, "TCP connection failed");
                ProbeResult::failure(
                    target.clone(),
                    format!("TCP connection failed to {addr}: {e}"),
                    total_elapsed,
                )
            }
            Err(_) => {
                debug!(
                    addr = %addr,
                    timeout_ms = config.tcp_timeout.as_millis(),
                    "TCP connection timed out"
                );
                ProbeResult::failure(
                    target.clone(),
                    format!(
                        "TCP connection timed out after {}ms to {addr}",
                        config.tcp_timeout.as_millis()
                    ),
                    total_elapsed,
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_target_https() {
        assert_eq!(TcpProbe::parse_target("https://example.com"), ("example.com", 443));
        assert_eq!(TcpProbe::parse_target("https://example.com:8443"), ("example.com", 8443));
        assert_eq!(TcpProbe::parse_target("https://example.com/path"), ("example.com", 443));
    }

    #[test]
    fn parse_target_http() {
        assert_eq!(TcpProbe::parse_target("http://example.com"), ("example.com", 80));
        assert_eq!(TcpProbe::parse_target("http://example.com:8080"), ("example.com", 8080));
    }

    #[test]
    fn parse_target_bare() {
        assert_eq!(TcpProbe::parse_target("example.com"), ("example.com", 80));
        assert_eq!(TcpProbe::parse_target("example.com:9000"), ("example.com", 9000));
    }
}
