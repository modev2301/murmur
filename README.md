# Murmur

[![CI](https://github.com/modev2301/murmur/actions/workflows/ci.yml/badge.svg)](https://github.com/modev2301/murmur/actions)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)

*Most outages start as a murmur. Murmur hears them first.*

Network experience monitoring: agent, probes, and OpenTelemetry metrics. Captures probe timing (DNS, TCP, TLS, TTFB), packet loss, jitter, gateway RTT, and system/network context (WiFi, VPN, proxy). Optional Chrome extension sends browser timing and Web Vitals to the agent.

## What’s in the repo

| Crate / area | Description |
|--------------|-------------|
| **murmur-agent** | Background agent: runs HTTP probes, ICMP ping (packet loss), emits OTEL metrics, hosts HTTP API for the extension |
| **murmur-cli** | CLI: `murmur probe <url>`, `murmur config`, `murmur version` |
| **murmur-core** | Config, OTEL telemetry, types |
| **murmur-probes** | Probes: HTTP, DNS, TCP, TLS, ICMP ping, traceroute |
| **murmur-sysinfo** | Host/network context: hostname, arch, CPU, memory, gateway, interface, WiFi (SSID, BSSID, signal quality), VPN (when default route is VPN), proxy |
| **murmur-dns-observer** | DNS observation (packet capture) |
| **murmur-wasm** | WASM-related utilities |
| **extension/** | Chrome extension: Navigation/Resource timing, Web Vitals → agent |

## Quick start

```bash
# Build
cargo build --release --package murmur-cli --package murmur-agent

# Run agent (probes + extension API); needs an OTEL collector on localhost:4317 or set MURMUR_COLLECTOR_ENDPOINT
./target/release/murmur-agent

# Single probe from CLI
./target/release/murmur probe https://www.google.com
./target/release/murmur probe api.github.com -t http
```

## Configuration

- **Config file (optional):** `/etc/murmur/config.toml`
- **Environment (override config):**
  - `MURMUR_PROBE_INTERVAL_SECONDS` – probe interval (default 60)
  - `MURMUR_PROBE_TIMEOUT_SECONDS` – per-probe timeout (must be &lt; interval)
  - `MURMUR_COLLECTOR_ENDPOINT` – OTLP gRPC endpoint (default `http://localhost:4317`)

The agent uses built-in default probe targets (e.g. google.com, cloudflare.com, api.github.com). Config file can set `probe.interval_seconds`, `probe.timeout_seconds`, and `collector.endpoint`.

## Metrics (OpenTelemetry)

Emitted by the agent (with resource attributes from sysinfo: host, arch, cpu_cores, memory, gateway, interface, wifi.*, vpn.*, proxy.*):

| Metric | Type | Description |
|--------|------|-------------|
| `murmur.probe.dns_ms` | histogram | DNS resolution time |
| `murmur.probe.tcp_ms` | histogram | TCP connect time |
| `murmur.probe.tls_ms` | histogram | TLS handshake time |
| `murmur.probe.ttfb_ms` | histogram | Time to first byte |
| `murmur.probe.total_ms` | histogram | Total probe time |
| `murmur.probe.jitter_ms` | histogram | Jitter (stddev of recent RTTs) |
| `murmur.probe.packet_loss_pct` | histogram | Packet loss % (from ICMP ping) |
| `murmur.probe.success` | counter | Probe success/failure |
| `murmur.gateway.rtt_ms` | histogram | Gateway RTT (when available) |
| `murmur.gateway.packet_loss` | histogram | Gateway packet loss |

## Seeing packet loss and jitter locally

Without running a full collector, you can see the same kind of values the agent sends:

```bash
# Packet loss % and jitter (stddev of RTTs) for a target; needs sudo for ICMP
sudo cargo run -p murmur-probes --example show_packet_loss_jitter

# Optional: override target (hostname or IP)
PING_TARGET=google.com sudo cargo run -p murmur-probes --example show_packet_loss_jitter
```

Gateway ping stats (including packet loss and RTT stddev):

```bash
sudo cargo run -p murmur-probes --example ping_gateway
```

## Other examples

```bash
# System / network / WiFi / VPN / proxy summary
cargo run -p murmur-sysinfo --example show

# Traceroute
sudo cargo run -p murmur-probes --example traceroute -- api.github.com

# Detailed probe (single target)
cargo run -p murmur-probes --example probe_detailed -- https://www.google.com
```

## Chrome extension

The extension sends Navigation Timing, Resource Timing, and Web Vitals to the agent at `http://127.0.0.1:9876`. The agent then exports those (and probe metrics) to your OTEL collector.

- **Install:** Load the `extension/` folder as an unpacked extension in Chrome; start the agent first.
- **Details:** See [extension/README.md](extension/README.md).

## Installation (Linux / macOS)

```bash
./install.sh
```

Installs `murmur` and `murmur-agent` to `/usr/local/bin` (override with `INSTALL_DIR`). On Linux, sets `CAP_NET_RAW` and `CAP_NET_ADMIN` so the agent can run ICMP and packet capture without root. Optional: creates `/etc/murmur/config.toml.example` and, on Linux, a systemd service.

**Requirements:** Rust toolchain, and on Linux, `libpcap` (e.g. `libpcap-dev`). On macOS, ICMP still needs `sudo` for the examples; the installed agent may need to run with appropriate privileges if you use ICMP.

## Development

```bash
cargo build
cargo test
```

- **Lints:** `unsafe_code`, `unwrap_used`, `expect_used`, `panic`, `todo`, `unimplemented` are restricted by workspace lints.
- **Docs:** ADRs and decisions live under [docs/decisions/](docs/decisions/).

## Contributing

Contributions are welcome. Please open an issue or pull request. By contributing, you agree that your contributions may be dual-licensed under MIT and Apache-2.0.

## Security

To report a security vulnerability, please open a [private security advisory](https://github.com/modev2301/murmur/security/advisories/new) on GitHub (or contact the maintainers directly). Do not open a public issue.

## License

**Murmur** is dual-licensed under either of

- **[MIT License](LICENSE-MIT)**  
- **[Apache License, Version 2.0](LICENSE-APACHE)**

at your option.
