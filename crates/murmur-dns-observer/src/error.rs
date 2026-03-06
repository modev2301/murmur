//! Error types for DNS observation.

use std::fmt;

/// Error type for DNS observer operations.
#[derive(Debug)]
pub struct DnsObserverError {
    kind: DnsObserverErrorKind,
}

impl DnsObserverError {
    /// Create a new error.
    pub fn new(kind: DnsObserverErrorKind) -> Self {
        Self { kind }
    }

    /// Get the error kind.
    pub fn kind(&self) -> &DnsObserverErrorKind {
        &self.kind
    }

    /// Create a capture error.
    pub fn capture(msg: impl Into<String>) -> Self {
        Self::new(DnsObserverErrorKind::Capture {
            message: msg.into(),
        })
    }

    /// Create a permission error.
    pub fn permission(msg: impl Into<String>) -> Self {
        Self::new(DnsObserverErrorKind::InsufficientPermissions {
            message: msg.into(),
        })
    }

    /// Create a no interfaces error.
    pub fn no_interfaces() -> Self {
        Self::new(DnsObserverErrorKind::NoInterfaces)
    }

    /// Create a parse error.
    pub fn parse(msg: impl Into<String>) -> Self {
        Self::new(DnsObserverErrorKind::Parse {
            message: msg.into(),
        })
    }
}

/// The kind of DNS observer error.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum DnsObserverErrorKind {
    /// Failed to initialize packet capture.
    Capture {
        /// Error message from pcap.
        message: String,
    },

    /// Insufficient permissions for packet capture.
    InsufficientPermissions {
        /// Platform-specific guidance on how to fix.
        message: String,
    },

    /// No network interfaces available.
    NoInterfaces,

    /// Failed to parse DNS packet.
    Parse {
        /// Parse error details.
        message: String,
    },

    /// Interface not found.
    InterfaceNotFound {
        /// The interface name that wasn't found.
        name: String,
    },
}

impl fmt::Display for DnsObserverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            DnsObserverErrorKind::Capture { message } => {
                write!(f, "packet capture failed: {message}")
            }
            DnsObserverErrorKind::InsufficientPermissions { message } => {
                write!(f, "insufficient permissions for DNS observation: {message}")
            }
            DnsObserverErrorKind::NoInterfaces => {
                write!(f, "no network interfaces available for capture")
            }
            DnsObserverErrorKind::Parse { message } => {
                write!(f, "failed to parse DNS packet: {message}")
            }
            DnsObserverErrorKind::InterfaceNotFound { name } => {
                write!(f, "network interface not found: {name}")
            }
        }
    }
}

impl std::error::Error for DnsObserverError {}

/// Result type for DNS observer operations.
pub type Result<T> = std::result::Result<T, DnsObserverError>;
