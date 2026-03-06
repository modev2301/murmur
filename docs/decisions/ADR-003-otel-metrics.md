# ADR-003: Direct OpenTelemetry SDK for Metrics

## Status

Accepted

## Context

Murmur needs to emit metrics to an OTEL collector. Two approaches:

1. **Use `metrics` crate + `metrics-exporter-opentelemetry` bridge**
   - Easier short-term (already using `metrics` crate)
   - Adds a translation layer between two metric systems
   - Bridge may lag behind OTEL SDK features

2. **Use OpenTelemetry SDK directly**
   - One less dependency
   - Direct control over OTEL semantics (histograms, attributes)
   - Standard approach used by Vector and other production agents

The current code uses the `metrics` crate for recording, but nothing is
actually exporting yet.

## Decision

Use OpenTelemetry SDK directly. Remove the `metrics` crate dependency.

Reasons:
- OTEL is the target output format — no translation layer needed
- Direct control over histogram bucket boundaries for timing data
- Cleaner dependency graph
- Follows Vector's approach

## Consequences

### Positive

- Single metrics system, no bridge
- Direct access to OTEL features (exemplars, resource attributes)
- Smaller dependency footprint long-term

### Negative

- Slightly more verbose API than `metrics` crate macros
- Must manage meter provider lifecycle explicitly

### Neutral

- Similar patterns to what we learned from Vector

## Implementation Notes

Start with exactly these six metrics:

```
murmur.probe.dns_ms        # histogram
murmur.probe.tcp_ms        # histogram
murmur.probe.tls_ms        # histogram
murmur.probe.ttfb_ms       # histogram
murmur.probe.total_ms      # histogram
murmur.probe.success       # counter
```

Required attributes on every metric:
- `target.url`
- `target.host`
- `probe.type`
- `agent.version`

Success counter additionally needs:
- `success` (true/false)
- `error_kind` (timeout/dns/tls/http/none)
