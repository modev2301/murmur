//! Run with: cargo run -p murmur-probes --example ping_gateway
//!
//! Note: Requires elevated privileges (sudo or CAP_NET_RAW)

use murmur_probes::ping::PingProbe;
use std::time::Duration;

#[tokio::main]
async fn main() {
    println!("=== Gateway Ping ===\n");

    let probe = match PingProbe::new() {
        Some(p) => p,
        None => {
            eprintln!("Failed to create ping probe.");
            eprintln!("This requires elevated privileges:");
            eprintln!("  Linux:  sudo or CAP_NET_RAW capability");
            eprintln!("  macOS:  sudo");
            eprintln!("  Windows: Run as Administrator");
            eprintln!("\nTry: sudo cargo run -p murmur-probes --example ping_gateway");
            return;
        }
    };

    // Single gateway ping
    println!("Pinging default gateway...\n");
    
    match probe.ping_gateway(Duration::from_secs(5)).await {
        Some(result) => {
            println!("Gateway:  {}", result.addr);
            if result.success {
                println!("RTT:      {:.2}ms", result.rtt.unwrap().as_secs_f64() * 1000.0);
                println!("Status:   OK");
            } else {
                println!("Status:   FAILED");
                if let Some(err) = result.error {
                    println!("Error:    {}", err);
                }
            }
        }
        None => {
            println!("Could not determine default gateway.");
        }
    }

    // Gateway ping statistics (5 pings)
    println!("\n=== Gateway Ping Statistics (5 pings) ===\n");
    
    if let Some(result) = probe.ping_gateway(Duration::from_secs(2)).await {
        let stats = probe.ping_stats(result.addr, 5, Duration::from_secs(2)).await;
        
        println!("Target:       {}", stats.addr);
        println!("Packets:      {} sent, {} received", stats.packets_sent, stats.packets_received);
        println!("Packet Loss:  {:.1}%", stats.packet_loss_percent);
        
        if let Some(min) = stats.min_rtt {
            println!("Min RTT:      {:.2}ms", min.as_secs_f64() * 1000.0);
        }
        if let Some(avg) = stats.avg_rtt {
            println!("Avg RTT:      {:.2}ms", avg.as_secs_f64() * 1000.0);
        }
        if let Some(max) = stats.max_rtt {
            println!("Max RTT:      {:.2}ms", max.as_secs_f64() * 1000.0);
        }
        if let Some(stddev) = stats.stddev_rtt {
            println!("Std Dev:      {:.2}ms", stddev.as_secs_f64() * 1000.0);
        }
    }
}
