# ADR-001: Workspace Structure with Separate Crates

## Status

Accepted

## Context

Murmur needs to support multiple deployment targets:
- Native background agent (Mac, Windows, Linux)
- CLI tool for diagnostics
- Future: WASM module for browser-based probing

A monolithic crate structure would force all code to compile for all targets,
increasing binary size and compilation time. It would also make it harder to
reason about dependencies and maintain clean boundaries between components.

We studied Vector's architecture extensively, which uses a similar multi-crate
workspace structure for its telemetry agent.

## Decision

Organize the codebase as a Cargo workspace with four crates:

```
crates/
├── murmur-core/     # Shared types, config, OTEL, errors
├── murmur-probes/   # Probe implementations
├── murmur-agent/    # Native agent binary
└── murmur-cli/      # CLI tool
```

**murmur-core** contains:
- Error types (struct + enum kind pattern from ripgrep)
- Configuration loading and validation
- Probe result types and timing breakdown
- Telemetry emission helpers

**murmur-probes** contains:
- Probe trait definition
- DNS, TCP, TLS, HTTP probe implementations
- Designed to compile to both native and WASM

**murmur-agent** contains:
- Main agent binary
- Graceful shutdown coordination
- Probe scheduling
- Target discovery (future: DNS observation)

**murmur-cli** contains:
- Diagnostic commands
- Configuration validation
- Manual probe execution

All dependency versions are managed in the workspace `Cargo.toml` to ensure
consistency across crates.

## Consequences

### Positive

- Clear separation of concerns
- Each crate can have minimal dependencies for its purpose
- murmur-probes can be compiled to WASM without pulling in agent code
- Faster incremental compilation during development
- Easier to test components in isolation

### Negative

- More files to navigate
- Must ensure public APIs between crates are stable
- Slightly more complex CI configuration

### Neutral

- Follows established patterns from Vector and other production Rust projects
- Standard Cargo workspace tooling works seamlessly

## References

- Vector source structure: https://github.com/vectordotdev/vector
- Cargo workspaces: https://doc.rust-lang.org/book/ch14-03-cargo-workspaces.html
