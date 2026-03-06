//! Error types for Murmur.
//!
//! Library crates use explicit error types with `thiserror` for rich context.
//! Binary crates use `anyhow` for convenient error propagation.

use std::fmt;
use std::time::Duration;

/// The main error type for Murmur operations.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
}

impl Error {
    /// Create a new error from a kind.
    pub fn new(kind: ErrorKind) -> Self {
        Self { kind }
    }

    /// Get the kind of this error.
    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }

    /// Create a DNS resolution error.
    pub fn dns(host: impl Into<String>, source: impl Into<String>) -> Self {
        Self::new(ErrorKind::DnsResolution {
            host: host.into(),
            source: source.into(),
        })
    }

    /// Create a TCP connection error.
    pub fn tcp_connect(host: impl Into<String>, source: impl Into<String>) -> Self {
        Self::new(ErrorKind::TcpConnect {
            host: host.into(),
            source: source.into(),
        })
    }

    /// Create a timeout error.
    pub fn timeout(operation: impl Into<String>, timeout: Duration) -> Self {
        Self::new(ErrorKind::Timeout {
            operation: operation.into(),
            timeout_ms: timeout.as_millis() as u64,
        })
    }

    /// Create a TLS handshake error.
    pub fn tls(host: impl Into<String>, source: impl Into<String>) -> Self {
        Self::new(ErrorKind::TlsHandshake {
            host: host.into(),
            source: source.into(),
        })
    }

    /// Create an HTTP error.
    pub fn http(url: impl Into<String>, status: Option<u16>, source: impl Into<String>) -> Self {
        Self::new(ErrorKind::Http {
            url: url.into(),
            status,
            source: source.into(),
        })
    }

    /// Create a configuration error.
    pub fn config(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Config {
            message: message.into(),
        })
    }
}

/// The kind of error that occurred.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ErrorKind {
    /// DNS resolution failed for a host.
    DnsResolution {
        /// The hostname that failed to resolve.
        host: String,
        /// The underlying error message.
        source: String,
    },

    /// TCP connection failed.
    TcpConnect {
        /// The target host.
        host: String,
        /// The underlying error message.
        source: String,
    },

    /// Operation timed out.
    Timeout {
        /// Description of the operation that timed out.
        operation: String,
        /// The timeout duration in milliseconds.
        timeout_ms: u64,
    },

    /// TLS handshake failed.
    TlsHandshake {
        /// The target host.
        host: String,
        /// The underlying error message.
        source: String,
    },

    /// HTTP request failed.
    Http {
        /// The request URL.
        url: String,
        /// HTTP status code if available.
        status: Option<u16>,
        /// The underlying error message.
        source: String,
    },

    /// Configuration is invalid.
    Config {
        /// Description of the configuration error.
        message: String,
    },

    /// Collector is unreachable.
    CollectorUnreachable {
        /// The collector endpoint.
        endpoint: String,
        /// The underlying error message.
        source: String,
    },

    /// Internal error (programming bug or unexpected state).
    Internal {
        /// Description of the internal error.
        message: String,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            ErrorKind::DnsResolution { host, source } => {
                write!(f, "DNS resolution failed for {host}: {source}")
            }
            ErrorKind::TcpConnect { host, source } => {
                write!(f, "TCP connection failed to {host}: {source}")
            }
            ErrorKind::Timeout {
                operation,
                timeout_ms,
            } => {
                write!(f, "{operation} timed out after {timeout_ms}ms")
            }
            ErrorKind::TlsHandshake { host, source } => {
                write!(f, "TLS handshake failed with {host}: {source}")
            }
            ErrorKind::Http {
                url,
                status,
                source,
            } => {
                if let Some(code) = status {
                    write!(
                        f,
                        "HTTP request to {url} failed with status {code}: {source}"
                    )
                } else {
                    write!(f, "HTTP request to {url} failed: {source}")
                }
            }
            ErrorKind::Config { message } => {
                write!(f, "configuration error: {message}")
            }
            ErrorKind::CollectorUnreachable { endpoint, source } => {
                write!(f, "collector at {endpoint} is unreachable: {source}")
            }
            ErrorKind::Internal { message } => {
                write!(f, "internal error: {message}")
            }
        }
    }
}

impl std::error::Error for Error {}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self { kind }
    }
}

/// A specialized `Result` type for Murmur operations.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_dns() {
        let err = Error::dns("example.com", "NXDOMAIN");
        assert_eq!(
            err.to_string(),
            "DNS resolution failed for example.com: NXDOMAIN"
        );
    }

    #[test]
    fn error_display_timeout() {
        let err = Error::timeout("TCP connect", Duration::from_secs(10));
        assert_eq!(err.to_string(), "TCP connect timed out after 10000ms");
    }

    #[test]
    fn error_display_http_with_status() {
        let err = Error::http("https://example.com", Some(503), "service unavailable");
        assert_eq!(
            err.to_string(),
            "HTTP request to https://example.com failed with status 503: service unavailable"
        );
    }
}
