//! Murmur Core - Shared types, configuration, and telemetry for the Murmur agent.
//!
//! This crate provides the foundational types used across all Murmur components:
//! - Error types with rich context for debugging
//! - Configuration loading and validation
//! - OpenTelemetry metric emission
//! - Probe result types and timing data

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod config;
pub mod error;
pub mod telemetry;
pub mod types;

pub use config::AgentConfig;
pub use error::{Error, ErrorKind, Result};
pub use telemetry::AgentMetrics;
pub use types::{ProbeResult, ProbeTarget, TimingBreakdown, TlsInfo};
