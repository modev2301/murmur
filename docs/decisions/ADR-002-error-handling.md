# ADR-002: Error Handling Strategy

## Status

Accepted

## Context

A network monitoring agent encounters many error conditions:
- DNS resolution failures
- TCP connection timeouts
- TLS handshake failures
- HTTP errors
- Configuration errors
- Collector unreachability

We need an error handling strategy that:
1. Provides rich context for debugging
2. Distinguishes retriable from fatal errors
3. Works well with async code
4. Keeps binary size reasonable

We studied ripgrep's error handling extensively. It uses a struct + enum kind
pattern rather than thiserror, providing fine-grained control over error
presentation.

## Decision

**Library crates (murmur-core, murmur-probes):**

Use the struct + enum kind pattern:

```rust
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ErrorKind {
    DnsResolution { host: String, source: String },
    TcpConnect { host: String, source: String },
    Timeout { operation: String, timeout_ms: u64 },
    // ...
}
```

Benefits:
- Each variant carries the context needed for a useful error message
- `#[non_exhaustive]` allows adding variants without breaking changes
- Explicit control over Display formatting
- Errors can be categorized for metrics (dns, timeout, tls, etc.)

**Binary crates (murmur-agent, murmur-cli):**

Use `anyhow` for convenient error propagation:

```rust
async fn run_probe(target: &str) -> anyhow::Result<ProbeResult> {
    let config = load_config()
        .context("failed to load configuration")?;
    // ...
}
```

Benefits:
- Easy to add context at each call site
- Automatic error chain formatting
- Simple `?` propagation

**Rules:**
- Never use `.unwrap()` or `.expect()` in production code paths
- Never silently discard errors with `let _ =`
- Always add context when propagating errors up the stack

## Consequences

### Positive

- Errors carry enough context for debugging without stack traces
- Error types are explicit and documented
- Can categorize errors for metrics (dns, timeout, tls, http, etc.)
- Binary crates have ergonomic error handling

### Negative

- More boilerplate than pure thiserror
- Must maintain Display implementations manually
- Two different patterns to learn (library vs binary)

### Neutral

- Consistent with ripgrep's approach
- Standard in production Rust projects

## References

- ripgrep error handling: `crates/grep-regex/src/error.rs`
- anyhow crate: https://docs.rs/anyhow
- thiserror crate: https://docs.rs/thiserror
