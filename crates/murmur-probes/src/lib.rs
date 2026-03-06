//! Murmur Probes - Network probe implementations.
//!
//! This crate provides probe implementations for measuring network path quality:
//! - DNS resolution probes
//! - TCP connection probes
//! - TLS handshake probes
//! - HTTP/HTTPS probes with full timing breakdown
//!
//! All probes implement the `Probe` trait and can be used interchangeably.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod dns;
pub mod http;
pub mod pool;
pub mod tcp;
pub mod tls;

mod probe;
pub use probe::{Probe, ProbeConfig, ProbeContext};
