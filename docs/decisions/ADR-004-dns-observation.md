# ADR-004: Passive DNS Observation for Target Discovery

## Status

Accepted

## Context

Murmur needs to know which endpoints to probe. The traditional approach requires users to manually configure a list of URLs. This has several drawbacks:

1. Manual configuration doesn't capture all the endpoints that actually matter
2. Users often don't know all the dependencies their applications have
3. Static lists become stale as infrastructure changes
4. It's friction that delays time-to-value

The alternative is to discover endpoints automatically by observing DNS queries on the network. When the system resolves a hostname, that's a strong signal that something cares about that endpoint.

## Decision

Implement passive DNS observation using packet capture (libpcap/Npcap) with the following design:

### Approach

Use the `pcap` crate with a BPF filter (`udp port 53`) to capture DNS queries. Parse packets with `etherparse` for headers and `dns-parser` for DNS payloads.

### Tracking

- **EndpointTracker**: Maintains discovered hostnames with:
  - Query count (how often it's resolved)
  - First/last seen timestamps
  - Confidence score based on frequency and recency
  - Resolved IP addresses (from responses)

- **Confidence Scoring**: Endpoints build confidence over time. Higher query frequency and more recent queries increase confidence. Endpoints are promoted to probe targets when they cross a configurable threshold.

- **Pruning**: Old endpoints (not seen in 1 hour) are pruned to prevent unbounded growth.

### Ignore List

Automatically ignores:
- `localhost`, `local`, `internal`, `localdomain` and their subdomains
- IP address literals
- Infrastructure domains can be added via configuration

### Platform Support

| Platform | Implementation | Requirement |
|----------|----------------|-------------|
| Linux | libpcap | root or `CAP_NET_RAW` |
| macOS | libpcap | root or `access_bpf` group |
| Windows | Npcap | Administrator |

### Not Implemented (Future Work)

- **Process correlation**: The `listeners` crate could correlate DNS queries to process names (which app made the query), but has Rust version compatibility issues. Deferred.
- **DNS-over-HTTPS/TLS observation**: Encrypted DNS bypasses this. Would require endpoint-specific integration.

## Consequences

### Positive

- Zero-config discovery of actual dependencies
- Captures the real traffic patterns, not guessed ones
- Adapts automatically as infrastructure changes
- Can be combined with static config for important endpoints

### Negative

- Requires elevated privileges (acceptable for infrastructure tooling)
- Won't capture DNS-over-HTTPS/TLS queries
- Windows requires Npcap installation
- Cannot determine query purpose (background refresh vs user-initiated)

### Neutral

- CI needs platform-specific handling for libpcap installation
- Binary size increases slightly due to pcap/parsing dependencies

## Implementation Notes

```rust
// Basic usage
let observer = DnsObserver::new(None, 0.7)?; // 70% confidence threshold
let mut rx = observer.subscribe();
tokio::spawn(observer.run());

// Get current high-confidence targets
let targets = observer.get_probe_targets().await;
for target in targets {
    println!("{} (confidence: {:.0}%)", target.hostname, target.confidence * 100.0);
}
```

The observer broadcasts discovered endpoints over a Tokio channel, allowing the agent to react to new discoveries in real-time rather than polling.
