# ADR-005: Connection Pooling with TLS Session Resumption Tracking

## Status

Accepted

## Context

Real-world clients maintain connection pools to frequently-accessed hosts. This has significant performance implications:

1. **TCP reuse**: Skips the 3-way handshake (1 RTT saved)
2. **TLS session resumption**: Skips the full handshake via session tickets or PSK (2+ RTTs saved)
3. **Keep-alive**: HTTP/1.1 connections can be reused

Murmur's HTTP probe originally created fresh connections for every measurement. This gives "cold start" latency, which is useful for understanding worst-case behavior but doesn't reflect typical steady-state performance.

## Decision

Implement a `ConnectionPool` in `murmur-probes` that:

### Connection Management

- Pools TLS connections by `(host, port)` key
- Configurable max connections per host (default: 4)
- Idle timeout (default: 60s) and max age (default: 5min)
- Automatic cleanup of expired connections

### Session Resumption Tracking

Track whether TLS sessions were resumed for visibility into real-world performance:

```rust
pub struct HostPoolStats {
    pub active_connections: usize,
    pub total_connections: u64,
    pub connections_reused: u64,
    pub sessions_resumed: u64,
    pub connections_timed_out: u64,
}
```

### Metrics

Expose pool statistics as agent self-instrumentation metrics:
- `murmur.agent.pool_connections`: Current pooled connections
- `murmur.agent.tls_sessions_resumed`: Counter of resumed sessions

### Probe Modes

The HTTP probe supports two modes:
- `HttpProbe::new()`: Uses connection pooling (typical real-world behavior)
- `HttpProbe::new_no_pool()`: Fresh connections (worst-case measurement)

Users can run both to understand the delta between cold and warm paths.

## Consequences

### Positive

- Measurements reflect actual user-perceived latency
- Visibility into TLS session resumption rates
- Can compare pooled vs fresh connections
- Identifies hosts that don't support session resumption

### Negative

- More complexity in probe implementation
- Memory usage grows with number of monitored hosts
- Session resumption detection is heuristic-based (timing threshold)

### Neutral

- Default behavior now reflects "warm" rather than "cold" performance
- Users who want cold measurements need to explicitly use no-pool mode

## Implementation Notes

Session resumption is detected heuristically based on handshake timing. Full handshakes typically take 20-100ms+ (multiple RTTs), while resumed sessions complete in 5-20ms (single RTT with PSK). The threshold is configurable:

```rust
pub fn likely_session_resumed(handshake_duration: Duration) -> bool {
    handshake_duration < Duration::from_millis(15)
}
```

Note: rustls doesn't directly expose session resumption status on the client side, so this heuristic is the practical approach. The timing-based detection is accurate enough for operational purposes.
