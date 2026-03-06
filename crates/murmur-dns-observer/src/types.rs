//! Types for DNS observation.

use std::collections::HashSet;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// A DNS query observed on the network.
#[derive(Debug, Clone)]
pub struct DnsQuery {
    /// The hostname being queried.
    pub hostname: String,

    /// Query type (A, AAAA, etc.).
    pub query_type: QueryType,

    /// Source port (can be used to correlate with process via `listeners` crate).
    pub source_port: u16,

    /// Timestamp when the query was observed.
    pub timestamp: Instant,
}

/// DNS query types we care about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(clippy::upper_case_acronyms)]
pub enum QueryType {
    /// IPv4 address lookup.
    A,
    /// IPv6 address lookup.
    AAAA,
    /// Other query type (ignored for endpoint discovery).
    Other,
}

impl QueryType {
    /// Create from DNS QTYPE value.
    pub fn from_qtype(qtype: u16) -> Self {
        match qtype {
            1 => QueryType::A,
            28 => QueryType::AAAA,
            _ => QueryType::Other,
        }
    }
}

/// An endpoint discovered through DNS observation.
#[derive(Debug, Clone)]
pub struct DiscoveredEndpoint {
    /// The hostname that was resolved.
    pub hostname: String,

    /// Resolved IP addresses (if we saw the response).
    pub resolved_ips: Vec<IpAddr>,

    /// Number of times this hostname was queried.
    pub query_count: u64,

    /// When this endpoint was first seen.
    pub first_seen: Instant,

    /// When this endpoint was last seen.
    pub last_seen: Instant,

    /// Confidence score (0.0 - 1.0) based on query frequency and recency.
    pub confidence: f64,

    /// Process name that queried this endpoint (if determinable).
    pub process_name: Option<String>,
}

impl DiscoveredEndpoint {
    /// Create a new discovered endpoint from a DNS query.
    pub fn from_query(query: &DnsQuery) -> Self {
        Self {
            hostname: query.hostname.clone(),
            resolved_ips: Vec::new(),
            query_count: 1,
            first_seen: query.timestamp,
            last_seen: query.timestamp,
            confidence: 0.5,
            process_name: None,
        }
    }

    /// Update this endpoint with a new query observation.
    pub fn update_from_query(&mut self, query: &DnsQuery) {
        self.query_count += 1;
        self.last_seen = query.timestamp;
        self.recalculate_confidence();
    }

    /// Add a resolved IP address.
    pub fn add_resolved_ip(&mut self, ip: IpAddr) {
        if !self.resolved_ips.contains(&ip) {
            self.resolved_ips.push(ip);
        }
    }

    /// Set the process name.
    pub fn set_process_name(&mut self, name: String) {
        self.process_name = Some(name);
    }

    /// Recalculate confidence based on query frequency and recency.
    fn recalculate_confidence(&mut self) {
        // Higher query count = higher confidence (capped)
        let count_factor = (self.query_count as f64 / 10.0).min(1.0);

        // More recent = higher confidence
        let age = self.last_seen.elapsed();
        let recency_factor = if age < Duration::from_secs(60) {
            1.0
        } else if age < Duration::from_secs(300) {
            0.8
        } else if age < Duration::from_secs(3600) {
            0.5
        } else {
            0.2
        };

        self.confidence = (count_factor * 0.6 + recency_factor * 0.4).min(1.0);
    }

    /// Check if this endpoint should be probed based on confidence threshold.
    pub fn should_probe(&self, threshold: f64) -> bool {
        self.confidence >= threshold
    }

    /// Convert to a probe target URL.
    pub fn to_probe_url(&self) -> String {
        format!("https://{}", self.hostname)
    }
}

/// Endpoint discovery state tracker.
#[derive(Debug, Default)]
pub struct EndpointTracker {
    /// Known endpoints by hostname.
    endpoints: std::collections::HashMap<String, DiscoveredEndpoint>,

    /// Hostnames to ignore (internal, infrastructure, etc.).
    ignore_list: HashSet<String>,
}

impl EndpointTracker {
    /// Create a new endpoint tracker.
    pub fn new() -> Self {
        let mut tracker = Self::default();

        // Default ignore patterns for infrastructure/internal domains
        tracker.add_ignore_pattern("localhost");
        tracker.add_ignore_pattern("local");
        tracker.add_ignore_pattern("internal");
        tracker.add_ignore_pattern("localdomain");

        tracker
    }

    /// Add a hostname pattern to ignore.
    pub fn add_ignore_pattern(&mut self, pattern: &str) {
        self.ignore_list.insert(pattern.to_string());
    }

    /// Check if a hostname should be ignored.
    fn should_ignore(&self, hostname: &str) -> bool {
        let lower = hostname.to_lowercase();

        // Exact match
        if self.ignore_list.contains(&lower) {
            return true;
        }

        // Suffix match
        for pattern in &self.ignore_list {
            if lower.ends_with(&format!(".{pattern}")) {
                return true;
            }
        }

        // Ignore IP addresses
        if hostname.parse::<IpAddr>().is_ok() {
            return true;
        }

        false
    }

    /// Record a DNS query.
    pub fn record_query(&mut self, query: &DnsQuery) {
        if self.should_ignore(&query.hostname) {
            return;
        }

        // Only track A and AAAA queries (actual hostname lookups)
        if query.query_type == QueryType::Other {
            return;
        }

        if let Some(endpoint) = self.endpoints.get_mut(&query.hostname) {
            endpoint.update_from_query(query);
        } else {
            self.endpoints.insert(
                query.hostname.clone(),
                DiscoveredEndpoint::from_query(query),
            );
        }
    }

    /// Get endpoints that should be probed (above confidence threshold).
    pub fn get_probe_targets(&self, confidence_threshold: f64) -> Vec<&DiscoveredEndpoint> {
        self.endpoints
            .values()
            .filter(|e| e.should_probe(confidence_threshold))
            .collect()
    }

    /// Get all tracked endpoints.
    pub fn all_endpoints(&self) -> impl Iterator<Item = &DiscoveredEndpoint> {
        self.endpoints.values()
    }

    /// Get endpoint count.
    pub fn len(&self) -> usize {
        self.endpoints.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
    }

    /// Prune old endpoints that haven't been seen recently.
    pub fn prune_old(&mut self, max_age: Duration) {
        let now = Instant::now();
        self.endpoints
            .retain(|_, e| now.duration_since(e.last_seen) < max_age);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_type_from_qtype() {
        assert_eq!(QueryType::from_qtype(1), QueryType::A);
        assert_eq!(QueryType::from_qtype(28), QueryType::AAAA);
        assert_eq!(QueryType::from_qtype(5), QueryType::Other);
    }

    #[test]
    fn endpoint_tracker_ignores_localhost() {
        let mut tracker = EndpointTracker::new();
        let query = DnsQuery {
            hostname: "localhost".to_string(),
            query_type: QueryType::A,
            source_port: 12345,
            timestamp: Instant::now(),
        };

        tracker.record_query(&query);
        assert!(tracker.is_empty());
    }

    #[test]
    fn endpoint_tracker_records_real_hostname() {
        let mut tracker = EndpointTracker::new();
        let query = DnsQuery {
            hostname: "api.example.com".to_string(),
            query_type: QueryType::A,
            source_port: 12345,
            timestamp: Instant::now(),
        };

        tracker.record_query(&query);
        assert_eq!(tracker.len(), 1);
    }

    #[test]
    fn endpoint_confidence_increases_with_queries() {
        let mut tracker = EndpointTracker::new();
        let mut query = DnsQuery {
            hostname: "api.example.com".to_string(),
            query_type: QueryType::A,
            source_port: 12345,
            timestamp: Instant::now(),
        };

        // First query
        tracker.record_query(&query);
        let initial_confidence = tracker
            .endpoints
            .get("api.example.com")
            .map(|e| e.confidence);

        // More queries
        for _ in 0..5 {
            query.timestamp = Instant::now();
            tracker.record_query(&query);
        }

        let final_confidence = tracker
            .endpoints
            .get("api.example.com")
            .map(|e| e.confidence);

        assert!(final_confidence > initial_confidence);
    }
}
