//! Passive DNS observation for auto-discovering probe targets.
//!
//! This crate captures DNS queries to learn what endpoints matter from real
//! traffic. Instead of requiring a static URL list, Murmur watches what the
//! system actually resolves and probes those endpoints.
//!
//! # Privilege Requirements
//!
//! DNS observation requires elevated privileges on all platforms:
//! - **Linux**: root or `CAP_NET_RAW` capability
//! - **macOS**: root or `access_bpf` group membership
//! - **Windows**: Administrator + Npcap installed
//!
//! # Example
//!
//! ```ignore
//! use murmur_dns_observer::DnsObserver;
//!
//! let observer = DnsObserver::new(None)?; // Use default interface
//! let mut rx = observer.subscribe();
//!
//! // Start observing in background
//! tokio::spawn(observer.run());
//!
//! // Receive discovered endpoints
//! while let Some(endpoint) = rx.recv().await {
//!     println!("Discovered: {}", endpoint.hostname);
//! }
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod observer;
mod parser;
mod types;

pub use error::{DnsObserverError, Result};
pub use observer::DnsObserver;
pub use types::{DiscoveredEndpoint, DnsQuery};
