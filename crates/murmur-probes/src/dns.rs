//! DNS resolution probe.
//!
//! Measures DNS resolution time for hostnames.

use crate::{Probe, ProbeConfig};
use async_trait::async_trait;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use murmur_core::{ProbeResult, ProbeTarget, TimingBreakdown};
use std::sync::Arc;
use std::time::Instant;
use tokio::time::timeout;
use tracing::{debug, instrument};

/// DNS resolution probe.
pub struct DnsProbe {
    resolver: Arc<TokioAsyncResolver>,
}

impl DnsProbe {
    /// Create a new DNS probe with system resolver configuration.
    pub fn new() -> Self {
        let resolver = TokioAsyncResolver::tokio_from_system_conf().unwrap_or_else(|_| {
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())
        });
        Self {
            resolver: Arc::new(resolver),
        }
    }

    /// Create a DNS probe with a custom resolver.
    pub fn with_resolver(resolver: TokioAsyncResolver) -> Self {
        Self {
            resolver: Arc::new(resolver),
        }
    }

    /// Extract hostname from a URL or use the string directly.
    fn extract_hostname(url: &str) -> &str {
        // Try to parse as URL first
        if let Some(stripped) = url.strip_prefix("https://") {
            stripped
                .split('/')
                .next()
                .unwrap_or(stripped)
                .split(':')
                .next()
                .unwrap_or(stripped)
        } else if let Some(stripped) = url.strip_prefix("http://") {
            stripped
                .split('/')
                .next()
                .unwrap_or(stripped)
                .split(':')
                .next()
                .unwrap_or(stripped)
        } else {
            // Assume it's just a hostname
            url.split(':').next().unwrap_or(url)
        }
    }
}

impl Default for DnsProbe {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Probe for DnsProbe {
    fn name(&self) -> &'static str {
        "dns"
    }

    #[instrument(skip(self, config), fields(target = %target.url))]
    async fn measure(&self, target: &ProbeTarget, config: &ProbeConfig) -> ProbeResult {
        let hostname = Self::extract_hostname(&target.url);
        let start = Instant::now();

        debug!(hostname = hostname, "starting DNS resolution");

        let result = timeout(config.dns_timeout, self.resolver.lookup_ip(hostname)).await;

        let elapsed = start.elapsed();

        match result {
            Ok(Ok(lookup)) => {
                let ips: Vec<_> = lookup.iter().collect();
                if let Some(first_ip) = ips.first() {
                    debug!(
                        hostname = hostname,
                        ip = %first_ip,
                        elapsed_ms = elapsed.as_millis(),
                        "DNS resolution succeeded"
                    );

                    let timing = TimingBreakdown::default()
                        .with_dns(elapsed)
                        .with_total(elapsed);

                    ProbeResult::success(target.clone(), timing).with_resolved_ip(*first_ip)
                } else {
                    ProbeResult::failure(
                        target.clone(),
                        format!("DNS lookup returned no addresses for {hostname}"),
                        elapsed,
                    )
                }
            }
            Ok(Err(e)) => {
                debug!(
                    hostname = hostname,
                    error = %e,
                    elapsed_ms = elapsed.as_millis(),
                    "DNS resolution failed"
                );
                ProbeResult::failure(
                    target.clone(),
                    format!("DNS resolution failed for {hostname}: {e}"),
                    elapsed,
                )
            }
            Err(_) => {
                debug!(
                    hostname = hostname,
                    timeout_ms = config.dns_timeout.as_millis(),
                    "DNS resolution timed out"
                );
                ProbeResult::failure(
                    target.clone(),
                    format!(
                        "DNS resolution timed out after {}ms for {hostname}",
                        config.dns_timeout.as_millis()
                    ),
                    elapsed,
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_hostname_from_https_url() {
        assert_eq!(
            DnsProbe::extract_hostname("https://example.com/path"),
            "example.com"
        );
        assert_eq!(
            DnsProbe::extract_hostname("https://example.com:443/path"),
            "example.com"
        );
    }

    #[test]
    fn extract_hostname_from_http_url() {
        assert_eq!(
            DnsProbe::extract_hostname("http://example.com/path"),
            "example.com"
        );
    }

    #[test]
    fn extract_hostname_bare() {
        assert_eq!(DnsProbe::extract_hostname("example.com"), "example.com");
        assert_eq!(
            DnsProbe::extract_hostname("example.com:8080"),
            "example.com"
        );
    }
}
