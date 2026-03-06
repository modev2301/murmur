//! DNS packet parsing.

use crate::error::{DnsObserverError, Result};
use crate::types::{DnsQuery, QueryType};
use etherparse::TransportSlice;
use std::time::Instant;

/// Parse a DNS query from raw packet data.
///
/// Expects the packet data starting from the Ethernet header.
pub fn parse_dns_packet(data: &[u8], timestamp: Instant) -> Result<Option<DnsQuery>> {
    // Parse headers using etherparse
    let headers = match etherparse::SlicedPacket::from_ethernet(data) {
        Ok(h) => h,
        Err(e) => {
            return Err(DnsObserverError::parse(format!(
                "failed to parse packet headers: {e}"
            )));
        }
    };

    // Get source port and payload from transport layer
    let (source_port, dns_data) = match &headers.transport {
        Some(TransportSlice::Udp(udp)) => (udp.source_port(), udp.payload()),
        Some(TransportSlice::Tcp(tcp)) => (tcp.source_port(), tcp.payload()),
        _ => return Ok(None), // Not TCP/UDP, skip
    };

    // DNS packets need at least 12 bytes for header
    if dns_data.len() < 12 {
        return Ok(None);
    }

    // Parse DNS packet
    let dns_packet = match dns_parser::Packet::parse(dns_data) {
        Ok(p) => p,
        Err(_) => return Ok(None), // Not a valid DNS packet
    };

    // We only care about queries (QR=0), not responses
    if dns_packet.header.query {
        // Get the first question (if any)
        if let Some(question) = dns_packet.questions.first() {
            let hostname = question.qname.to_string();

            // Remove trailing dot if present
            let hostname = hostname.trim_end_matches('.').to_string();

            // Skip empty hostnames
            if hostname.is_empty() {
                return Ok(None);
            }

            let query_type = QueryType::from_qtype(question.qtype as u16);

            return Ok(Some(DnsQuery {
                hostname,
                query_type,
                source_port,
                timestamp,
            }));
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    // DNS parsing is tricky to unit test without real packet captures
    // Integration tests with actual pcap files would be better

    #[test]
    fn query_type_mapping() {
        assert_eq!(QueryType::from_qtype(1), QueryType::A);
        assert_eq!(QueryType::from_qtype(28), QueryType::AAAA);
        assert_eq!(QueryType::from_qtype(15), QueryType::Other); // MX
    }
}
