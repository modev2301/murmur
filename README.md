# Murmur

Murmur measures where latency actually comes from — DNS, TCP, TLS, and TTFB — from wherever you deploy it.

```
$ murmur probe https://api.example.com

  DNS:   12ms
  TCP:   23ms
  TLS:   45ms  ← TLS handshake is 45% of your latency
  TTFB: 281ms
  Total: 361ms
```

Most monitoring tools tell you an endpoint is slow. Murmur tells you which layer is slow and by how much. Deploy it alongside your existing collector — Murmur feeds it, not replaces it.

## Features

- **Granular timing breakdowns** — DNS, TCP, TLS, TTFB measured separately
- **OpenTelemetry native** — Emits metrics directly via OTLP to any collector
- **Passive DNS discovery** — Automatically discovers endpoints from network traffic
- **Connection pooling** — Tracks TLS session resumption for warm vs cold measurements
- **Cross-platform** — Linux, macOS, Windows

## Quick Start

### Installation

```bash
cargo install murmur-cli
```

Or build from source:

```bash
git clone https://github.com/murmur/murmur
cd murmur
cargo build --release
```

### Run a probe

```bash
murmur probe https://api.example.com
```

### Run the agent

The agent probes targets on an interval and exports metrics to an OTLP collector:

```bash
# Start with defaults (probes every 60s, exports to localhost:4317)
murmur-agent

# Or with configuration
MURMUR_PROBE_INTERVAL_SECONDS=30 \
MURMUR_COLLECTOR_ENDPOINT=http://otel-collector:4317 \
murmur-agent
```

## Requirements

### Rust Version

Murmur requires Rust 1.75 or later.

### DNS Observation (Optional)

The DNS observation feature requires elevated privileges to capture network traffic:

| Platform | Requirement |
|----------|-------------|
| Linux | `CAP_NET_RAW` capability or root |
| macOS | root or membership in `access_bpf` group |
| Windows | Administrator with [Npcap](https://npcap.com) installed |

On Linux, you can grant capabilities without running as root:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip /path/to/murmur-agent
```

DNS observation is not required for basic probing. If the agent lacks permissions, it runs without auto-discovery and uses configured targets only.

### Build Dependencies

- **Linux:** `libpcap-dev` (for DNS observation)
- **macOS:** libpcap is included with the OS
- **Windows:** Npcap or WinPcap SDK

## Configuration

Configuration follows a layered approach:

1. Compiled defaults
2. Config file (`/etc/murmur/config.toml` or `~/.config/murmur/config.toml`)
3. Environment variables (`MURMUR_*`)

Example config:

```toml
[probe]
interval_seconds = 60
timeout_seconds = 30
targets = [
    "https://api.example.com",
    "https://cdn.example.com/health",
]

[collector]
endpoint = "http://localhost:4317"
export_interval_seconds = 15

[logging]
format = "json"  # or "pretty"
level = "info"
```

## Metrics

Murmur emits these metrics to your OTLP collector:

| Metric | Type | Description |
|--------|------|-------------|
| `murmur.probe.dns_ms` | histogram | DNS resolution time |
| `murmur.probe.tcp_ms` | histogram | TCP connect time |
| `murmur.probe.tls_ms` | histogram | TLS handshake time |
| `murmur.probe.ttfb_ms` | histogram | Time to first byte |
| `murmur.probe.total_ms` | histogram | Total probe duration |
| `murmur.probe.success` | counter | Success/failure count |

All metrics include `target.url`, `target.host`, `probe.type`, and `agent.version` attributes.

## Architecture

```
murmur/
├── crates/
│   ├── murmur-core/         # Shared types, config, telemetry
│   ├── murmur-probes/       # DNS, TCP, TLS, HTTP probe implementations
│   ├── murmur-dns-observer/ # Passive DNS capture for auto-discovery
│   ├── murmur-agent/        # Background agent binary
│   └── murmur-cli/          # CLI tool (murmur command)
└── docs/
    └── decisions/           # Architecture Decision Records
```

## Documentation

- [ADR-001: Workspace Structure](docs/decisions/ADR-001-workspace-structure.md)
- [ADR-002: Error Handling](docs/decisions/ADR-002-error-handling.md)
- [ADR-003: OpenTelemetry Metrics](docs/decisions/ADR-003-otel-metrics.md)
- [ADR-004: DNS Observation](docs/decisions/ADR-004-dns-observation.md)
- [ADR-005: Connection Pooling](docs/decisions/ADR-005-connection-pooling.md)

## Contributing

Contributions are welcome. Please run the following before submitting a PR:

```bash
cargo fmt --all
cargo clippy --workspace -- -D warnings
cargo test --workspace
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
