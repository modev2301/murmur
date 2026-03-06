//! HTTP/HTTPS probe with detailed timing breakdown.
//!
//! Measures each layer of the network stack separately:
//! - DNS resolution time
//! - TCP connection time
//! - TLS handshake time (for HTTPS)
//! - Time to first byte (application response)
//!
//! This granularity is what makes Murmur useful — 361ms total tells you
//! something is slow, but 45ms TLS tells you exactly what's slow.

use crate::{Probe, ProbeConfig};
use async_trait::async_trait;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use murmur_core::{ProbeResult, ProbeTarget, TimingBreakdown, TlsInfo};
use rustls::pki_types::ServerName;
use std::io::Write as IoWrite;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tracing::{debug, instrument};

/// HTTP/HTTPS probe with full timing breakdown.
pub struct HttpProbe {
    resolver: Arc<TokioAsyncResolver>,
    tls_config: Arc<rustls::ClientConfig>,
}

impl HttpProbe {
    /// Create a new HTTP probe.
    ///
    /// # Panics
    ///
    /// Panics if the TLS provider cannot be initialized. This indicates a
    /// build configuration error (missing crypto backend), not a runtime
    /// condition. Per the project style guide, panics are acceptable for
    /// programming errors that cannot occur in correctly built code.
    pub fn new() -> Self {
        // Use system DNS configuration instead of hardcoded Google DNS
        let resolver = TokioAsyncResolver::tokio_from_system_conf().unwrap_or_else(|_| {
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())
        });

        let root_store =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        // Use the default crypto provider (aws-lc-rs)
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

    /// Create an HTTP probe without connection pooling (for fresh measurements).
    pub fn new_no_pool() -> Self {
        Self::new()
    }

    /// Parse a URL into components.
    fn parse_url(url: &str) -> (bool, &str, u16, &str) {
        let (is_https, rest) = if let Some(stripped) = url.strip_prefix("https://") {
            (true, stripped)
        } else if let Some(stripped) = url.strip_prefix("http://") {
            (false, stripped)
        } else {
            (true, url) // Default to HTTPS
        };

        let (host_port, path) = if let Some(slash_pos) = rest.find('/') {
            (&rest[..slash_pos], &rest[slash_pos..])
        } else {
            (rest, "/")
        };

        let (host, port) = if let Some(colon_pos) = host_port.rfind(':') {
            let h = &host_port[..colon_pos];
            let p = host_port[colon_pos + 1..]
                .parse()
                .unwrap_or(if is_https { 443 } else { 80 });
            (h, p)
        } else {
            (host_port, if is_https { 443 } else { 80 })
        };

        (is_https, host, port, path)
    }

    /// Build an HTTP/1.1 request.
    fn build_request(host: &str, path: &str) -> Vec<u8> {
        let mut request = Vec::new();
        write!(
            request,
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             User-Agent: murmur/{}\r\n\
             Accept: */*\r\n\
             Connection: close\r\n\
             \r\n",
            path,
            host,
            env!("CARGO_PKG_VERSION")
        )
        .ok();
        request
    }

    /// Parse HTTP status code from response.
    fn parse_status(response: &[u8]) -> Option<u16> {
        let response_str = std::str::from_utf8(response).ok()?;
        let status_line = response_str.lines().next()?;
        let parts: Vec<&str> = status_line.split_whitespace().collect();
        if parts.len() >= 2 {
            parts[1].parse().ok()
        } else {
            None
        }
    }
}

impl Default for HttpProbe {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Probe for HttpProbe {
    fn name(&self) -> &'static str {
        "http"
    }

    #[instrument(skip(self, config), fields(target = %target.url))]
    async fn measure(&self, target: &ProbeTarget, config: &ProbeConfig) -> ProbeResult {
        let (is_https, hostname, port, path) = Self::parse_url(&target.url);
        let overall_start = Instant::now();

        // ========================================
        // Phase 1: DNS Resolution
        // ========================================
        debug!(hostname = hostname, "resolving DNS");
        let dns_start = Instant::now();

        let dns_result = timeout(config.dns_timeout, self.resolver.lookup_ip(hostname)).await;

        let dns_duration = dns_start.elapsed();

        let resolved_ip = match dns_result {
            Ok(Ok(lookup)) => {
                if let Some(ip) = lookup.iter().next() {
                    debug!(
                        hostname = hostname,
                        ip = %ip,
                        dns_ms = dns_duration.as_millis(),
                        "DNS resolved"
                    );
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

        // ========================================
        // Phase 2: TCP Connection
        // ========================================
        let addr = SocketAddr::new(resolved_ip, port);
        debug!(addr = %addr, "connecting TCP");
        let tcp_start = Instant::now();

        let tcp_result = timeout(config.tcp_timeout, TcpStream::connect(addr)).await;

        let tcp_duration = tcp_start.elapsed();

        let tcp_stream = match tcp_result {
            Ok(Ok(stream)) => {
                debug!(
                    addr = %addr,
                    tcp_ms = tcp_duration.as_millis(),
                    "TCP connected"
                );
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

        // ========================================
        // Phase 3: TLS Handshake (if HTTPS)
        // ========================================
        let (tls_duration, tls_info, mut stream): (
            _,
            Option<TlsInfo>,
            Box<dyn AsyncReadWriteUnpin>,
        ) = if is_https {
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

            let tls_dur = tls_start.elapsed();

            match tls_result {
                Ok(Ok(tls_stream)) => {
                    debug!(
                        hostname = hostname,
                        tls_ms = tls_dur.as_millis(),
                        "TLS handshake completed"
                    );

                    let (_, conn) = tls_stream.get_ref();
                    let info = TlsInfo {
                        version: format!(
                            "{:?}",
                            conn.protocol_version()
                                .unwrap_or(rustls::ProtocolVersion::TLSv1_3)
                        ),
                        cipher: format!(
                            "{:?}",
                            conn.negotiated_cipher_suite().map(|cs| cs.suite())
                        ),
                        session_resumed: false,
                        cert_expires: None,
                        cert_subject: None,
                    };

                    (
                        Some(tls_dur),
                        Some(info),
                        Box::new(tls_stream) as Box<dyn AsyncReadWriteUnpin>,
                    )
                }
                Ok(Err(e)) => {
                    return ProbeResult::failure(
                        target.clone(),
                        format!("TLS handshake failed with {hostname}: {e}"),
                        overall_start.elapsed(),
                    );
                }
                Err(_) => {
                    return ProbeResult::failure(
                        target.clone(),
                        format!(
                            "TLS handshake timed out after {}ms with {hostname}",
                            config.tls_timeout.as_millis()
                        ),
                        overall_start.elapsed(),
                    );
                }
            }
        } else {
            (
                None,
                None,
                Box::new(tcp_stream) as Box<dyn AsyncReadWriteUnpin>,
            )
        };

        // ========================================
        // Phase 4: HTTP Request/Response (TTFB)
        // ========================================
        debug!(path = path, "sending HTTP request");
        let http_start = Instant::now();

        let request = Self::build_request(hostname, path);

        // Send request
        if let Err(e) = stream.write_all(&request).await {
            return ProbeResult::failure(
                target.clone(),
                format!("failed to send HTTP request: {e}"),
                overall_start.elapsed(),
            );
        }

        // Read response (just enough to get status)
        let mut response_buf = vec![0u8; 1024];
        let read_result = timeout(
            config.timeout.saturating_sub(overall_start.elapsed()),
            stream.read(&mut response_buf),
        )
        .await;

        let ttfb_duration = http_start.elapsed();
        let total_duration = overall_start.elapsed();

        let http_status = match read_result {
            Ok(Ok(n)) if n > 0 => {
                response_buf.truncate(n);
                Self::parse_status(&response_buf)
            }
            Ok(Ok(_)) => {
                return ProbeResult::failure(
                    target.clone(),
                    "connection closed before response".to_string(),
                    total_duration,
                );
            }
            Ok(Err(e)) => {
                return ProbeResult::failure(
                    target.clone(),
                    format!("failed to read HTTP response: {e}"),
                    total_duration,
                );
            }
            Err(_) => {
                return ProbeResult::failure(
                    target.clone(),
                    format!(
                        "HTTP response timed out after {}ms",
                        config.timeout.as_millis()
                    ),
                    total_duration,
                );
            }
        };

        // ========================================
        // Build Result with Full Timing Breakdown
        // ========================================
        debug!(
            dns_ms = dns_duration.as_millis(),
            tcp_ms = tcp_duration.as_millis(),
            tls_ms = tls_duration.map(|d| d.as_millis() as u64),
            ttfb_ms = ttfb_duration.as_millis(),
            total_ms = total_duration.as_millis(),
            status = http_status,
            "HTTP probe completed"
        );

        let mut timing = TimingBreakdown::default()
            .with_dns(dns_duration)
            .with_tcp(tcp_duration)
            .with_ttfb(ttfb_duration)
            .with_total(total_duration);

        if let Some(tls_dur) = tls_duration {
            timing = timing.with_tls(tls_dur);
        }

        let success = http_status
            .map(|s| (200..400).contains(&s))
            .unwrap_or(false);

        let mut result = if success {
            ProbeResult::success(target.clone(), timing)
        } else {
            ProbeResult::failure(
                target.clone(),
                format!("HTTP request returned status {}", http_status.unwrap_or(0)),
                total_duration,
            )
        };

        result = result.with_resolved_ip(resolved_ip);

        if let Some(status) = http_status {
            result = result.with_http_status(status);
        }

        if let Some(info) = tls_info {
            result = result.with_tls_info(info);
        }

        result
    }
}

/// Trait alias for async read+write+unpin.
trait AsyncReadWriteUnpin: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> AsyncReadWriteUnpin for T {}

/// Builder for creating HTTP probes with custom settings.
pub struct HttpProbeBuilder {
    // Reserved for future customization
}

impl HttpProbeBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self {}
    }

    /// Build the HTTP probe.
    pub fn build(self) -> HttpProbe {
        HttpProbe::new()
    }
}

impl Default for HttpProbeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_url_https() {
        let (is_https, host, port, path) = HttpProbe::parse_url("https://example.com/api/v1");
        assert!(is_https);
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
        assert_eq!(path, "/api/v1");
    }

    #[test]
    fn parse_url_http_with_port() {
        let (is_https, host, port, path) = HttpProbe::parse_url("http://localhost:8080/health");
        assert!(!is_https);
        assert_eq!(host, "localhost");
        assert_eq!(port, 8080);
        assert_eq!(path, "/health");
    }

    #[test]
    fn parse_url_root_path() {
        let (is_https, host, port, path) = HttpProbe::parse_url("https://example.com");
        assert!(is_https);
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
        assert_eq!(path, "/");
    }

    #[test]
    fn builder_defaults() {
        let probe = HttpProbeBuilder::new().build();
        assert_eq!(probe.name(), "http");
    }
}
