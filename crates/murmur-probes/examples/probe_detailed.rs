//! Run with: cargo run -p murmur-probes --example probe_detailed -- https://example.com

use murmur_core::ProbeTarget;
use murmur_probes::http::HttpProbe;
use murmur_probes::{Probe, ProbeConfig};
use std::env;
use std::time::Duration;

#[tokio::main]
async fn main() {
    let url = env::args()
        .nth(1)
        .unwrap_or_else(|| "https://www.google.com".to_string());

    println!("=== Detailed HTTP Probe ===\n");
    println!("Target: {}\n", url);

    let probe = HttpProbe::new();
    let target = ProbeTarget::new(&url);
    let config = ProbeConfig {
        timeout: Duration::from_secs(30),
        dns_timeout: Duration::from_secs(5),
        tcp_timeout: Duration::from_secs(10),
        tls_timeout: Duration::from_secs(10),
    };

    let start = std::time::Instant::now();
    let result = probe.measure(&target, &config).await;
    let elapsed = start.elapsed();

    // Timing breakdown
    println!("=== Timing Breakdown ===");
    if let Some(dns) = result.timing.dns_ms {
        let pct = (dns as f64 / result.timing.total_ms as f64) * 100.0;
        println!("  DNS:    {:>6}ms  ({:>5.1}%)", dns, pct);
    }
    if let Some(tcp) = result.timing.tcp_connect_ms {
        let pct = (tcp as f64 / result.timing.total_ms as f64) * 100.0;
        println!("  TCP:    {:>6}ms  ({:>5.1}%)", tcp, pct);
    }
    if let Some(tls) = result.timing.tls_handshake_ms {
        let pct = (tls as f64 / result.timing.total_ms as f64) * 100.0;
        println!("  TLS:    {:>6}ms  ({:>5.1}%)", tls, pct);
    }
    if let Some(ttfb) = result.timing.ttfb_ms {
        let pct = (ttfb as f64 / result.timing.total_ms as f64) * 100.0;
        println!("  TTFB:   {:>6}ms  ({:>5.1}%)", ttfb, pct);
    }
    println!("  ─────────────────────");
    println!("  Total:  {:>6}ms  (100.0%)", result.timing.total_ms);

    // Result
    println!("\n=== Result ===");
    println!(
        "  Success:    {}",
        if result.success { "yes" } else { "no" }
    );
    if let Some(ip) = result.resolved_ip {
        println!("  Resolved:   {}", ip);
    }
    if let Some(status) = result.http_status {
        println!("  HTTP:       {}", status);
    }
    if let Some(err) = &result.error {
        println!("  Error:      {}", err);
    }

    // TLS info
    if let Some(tls) = &result.tls_info {
        println!("\n=== TLS Info ===");
        println!("  Version:    {}", tls.version);
        println!("  Cipher:     {}", tls.cipher);
        println!("  Resumed:    {}", tls.session_resumed);
    }

    // Bottleneck analysis
    println!("\n=== Analysis ===");
    let dns = result.timing.dns_ms.unwrap_or(0);
    let tcp = result.timing.tcp_connect_ms.unwrap_or(0);
    let tls = result.timing.tls_handshake_ms.unwrap_or(0);
    let ttfb = result.timing.ttfb_ms.unwrap_or(0);

    let max_phase = [("DNS", dns), ("TCP", tcp), ("TLS", tls), ("TTFB", ttfb)]
        .into_iter()
        .max_by_key(|(_, v)| *v)
        .unwrap_or(("TTFB", ttfb));

    if max_phase.1 > 0 {
        let pct = (max_phase.1 as f64 / result.timing.total_ms as f64) * 100.0;
        println!("  Slowest:    {} ({:.1}% of total)", max_phase.0, pct);

        match max_phase.0 {
            "DNS" => println!("  Suggestion: Try a faster DNS resolver (1.1.1.1, 8.8.8.8)"),
            "TCP" => println!("  Suggestion: Server may be geographically distant or congested"),
            "TLS" => println!("  Suggestion: Consider TLS session resumption or HTTP/2"),
            "TTFB" => println!("  Suggestion: Server processing time is the bottleneck"),
            _ => {}
        }
    }

    println!("\n  Measured in {:.2}ms", elapsed.as_secs_f64() * 1000.0);
}
