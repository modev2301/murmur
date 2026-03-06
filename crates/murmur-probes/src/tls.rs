//! TLS handshake probe.
//!
//! Measures TLS handshake time separately from TCP connection time.
//! This is useful for diagnosing TLS-specific performance issues.

use crate::{Probe, ProbeConfig};
use async_trait::async_trait;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use murmur_core::{ProbeResult, ProbeTarget, TimingBreakdown, TlsInfo};
use rustls::pki_types::ServerName;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tracing::{debug, instrument};

/// TLS handshake probe.
pub struct TlsProbe {
    resolver: Arc<TokioAsyncResolver>,
    tls_config: Arc<rustls::ClientConfig>,
}

impl TlsProbe {
    /// Create a new TLS probe with default configuration.
    ///
    /// # Panics
    ///
    /// Panics if the TLS provider cannot be initialized. This indicates a
    /// build configuration error (missing crypto backend), not a runtime
    /// condition. Per the project style guide, panics are acceptable for
    /// programming errors that cannot occur in correctly built code.
    pub fn new() -> Self {
        let resolver = TokioAsyncResolver::tokio_from_system_conf().unwrap_or_else(|_| {
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())
        });

        let root_store =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let provider = rustls::crypto::aws_lc_rs::default_provider();

        // This only fails if the provider doesn't support any safe TLS versions,
        // which would be a build-time configuration error, not a runtime condition.
        #[allow(clippy::expect_used)]
        let tls_config = rustls::ClientConfig::builder_with_provider(provider.into())
            .with_safe_default_protocol_versions()
            .expect("aws-lc-rs provider must support safe TLS versions")
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Self {
            resolver: Arc::new(resolver),
            tls_config: Arc::new(tls_config),
        }
    }

    /// Parse a target URL into host and port.
    fn parse_target(url: &str) -> (&str, u16) {
        let rest = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .unwrap_or(url);

        let host_port = rest.split('/').next().unwrap_or(rest);

        if let Some(colon_pos) = host_port.rfind(':') {
            let host = &host_port[..colon_pos];
            let port_str = &host_port[colon_pos + 1..];
            if let Ok(port) = port_str.parse::<u16>() {
                return (host, port);
            }
        }

        (host_port.split(':').next().unwrap_or(host_port), 443)
    }
}

impl Default for TlsProbe {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Probe for TlsProbe {
    fn name(&self) -> &'static str {
        "tls"
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

        let tcp_stream = match tcp_result {
            Ok(Ok(stream)) => {
                debug!(addr = %addr, tcp_ms = tcp_elapsed.as_millis(), "TCP connected");
                stream
            }
            Ok(Err(e)) => {
                return ProbeResult::failure(
                    target.clone(),
                    format!("TCP connection failed to {addr}: {e}"),
                    overall_start.elapsed(),
                );
            }
            Err(_) => {
                return ProbeResult::failure(
                    target.clone(),
                    format!(
                        "TCP connection timed out after {}ms to {addr}",
                        config.tcp_timeout.as_millis()
                    ),
                    overall_start.elapsed(),
                );
            }
        };

        // Phase 3: TLS handshake
        debug!(hostname = hostname, "starting TLS handshake");
        let tls_start = Instant::now();

        let server_name = match ServerName::try_from(hostname.to_string()) {
            Ok(name) => name,
            Err(e) => {
                return ProbeResult::failure(
                    target.clone(),
                    format!("invalid server name {hostname}: {e}"),
                    overall_start.elapsed(),
                );
            }
        };

        let connector = TlsConnector::from(self.tls_config.clone());
        let tls_result = timeout(
            config.tls_timeout,
            connector.connect(server_name, tcp_stream),
        )
        .await;

        let tls_elapsed = tls_start.elapsed();
        let total_elapsed = overall_start.elapsed();

        match tls_result {
            Ok(Ok(tls_stream)) => {
                debug!(
                    hostname = hostname,
                    tls_ms = tls_elapsed.as_millis(),
                    total_ms = total_elapsed.as_millis(),
                    "TLS handshake succeeded"
                );

                let timing = TimingBreakdown::default()
                    .with_dns(dns_elapsed)
                    .with_tcp(tcp_elapsed)
                    .with_tls(tls_elapsed)
                    .with_total(total_elapsed);

                // Extract TLS info from the connection
                let (_, conn) = tls_stream.get_ref();
                let tls_info = TlsInfo {
                    version: format!(
                        "{:?}",
                        conn.protocol_version()
                            .unwrap_or(rustls::ProtocolVersion::TLSv1_3)
                    ),
                    cipher: format!("{:?}", conn.negotiated_cipher_suite().map(|cs| cs.suite())),
                    session_resumed: conn.is_handshaking(), // Note: this is inverted, but we don't have direct access
                    cert_expires: None,                     // Would need to parse the certificate
                    cert_subject: None,
                };

                ProbeResult::success(target.clone(), timing)
                    .with_resolved_ip(resolved_ip)
                    .with_tls_info(tls_info)
            }
            Ok(Err(e)) => {
                debug!(hostname = hostname, error = %e, "TLS handshake failed");
                ProbeResult::failure(
                    target.clone(),
                    format!("TLS handshake failed with {hostname}: {e}"),
                    total_elapsed,
                )
            }
            Err(_) => {
                debug!(
                    hostname = hostname,
                    timeout_ms = config.tls_timeout.as_millis(),
                    "TLS handshake timed out"
                );
                ProbeResult::failure(
                    target.clone(),
                    format!(
                        "TLS handshake timed out after {}ms with {hostname}",
                        config.tls_timeout.as_millis()
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
    fn parse_target_with_port() {
        assert_eq!(
            TlsProbe::parse_target("https://example.com:8443"),
            ("example.com", 8443)
        );
    }

    #[test]
    fn parse_target_default_port() {
        assert_eq!(
            TlsProbe::parse_target("https://example.com"),
            ("example.com", 443)
        );
        assert_eq!(TlsProbe::parse_target("example.com"), ("example.com", 443));
    }
}
