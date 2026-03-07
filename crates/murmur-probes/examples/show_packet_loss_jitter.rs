//! Show packet loss and jitter for a target (same metrics the agent exports to OTEL).
//!
//! Run with: cargo run -p murmur-probes --example show_packet_loss_jitter
//! Optional: PING_TARGET=google.com (or 8.8.8.8) to override default.
//!
//! Requires elevated privileges (sudo or CAP_NET_RAW) for ICMP.

use murmur_core::ProbeTarget;
use murmur_probes::ping::PingProbe;
use std::time::Duration;

const DEFAULT_TARGET: &str = "8.8.8.8";
const PING_COUNT: usize = 10;
const PING_TIMEOUT_SECS: u64 = 2;

#[tokio::main]
async fn main() {
    let target_url = std::env::var("PING_TARGET")
        .unwrap_or_else(|_| format!("https://{}/", DEFAULT_TARGET));
    let target = ProbeTarget::new(&target_url);

    println!("=== Packet loss & jitter ===\n");
    println!("Target:  {} ({} pings, {}s timeout)\n", target.url, PING_COUNT, PING_TIMEOUT_SECS);

    let probe = match PingProbe::new() {
        Some(p) => p,
        None => {
            eprintln!("Failed to create ping probe.");
            eprintln!("Requires elevated privileges: sudo or CAP_NET_RAW");
            eprintln!("  sudo cargo run -p murmur-probes --example show_packet_loss_jitter");
            return;
        }
    };

    let timeout = Duration::from_secs(PING_TIMEOUT_SECS);
    let stats = match probe.ping_target_stats(&target, PING_COUNT, timeout).await {
        Some(s) => s,
        None => {
            eprintln!("Could not resolve host or ping failed.");
            return;
        }
    };

    println!("Packet loss:  {:.1}%", stats.packet_loss_percent);
    let jitter_ms = stats
        .stddev_rtt
        .map(|d| d.as_secs_f64() * 1000.0)
        .unwrap_or(0.0);
    println!("Jitter:       {:.2} ms", jitter_ms);

    if let Some(min) = stats.min_rtt {
        println!("Min RTT:      {:.2} ms", min.as_secs_f64() * 1000.0);
    }
    if let Some(avg) = stats.avg_rtt {
        println!("Avg RTT:      {:.2} ms", avg.as_secs_f64() * 1000.0);
    }
    if let Some(max) = stats.max_rtt {
        println!("Max RTT:      {:.2} ms", max.as_secs_f64() * 1000.0);
    }
    println!("\n(These match murmur.probe.packet_loss_pct and murmur.probe.jitter_ms in OTEL.)");
}
