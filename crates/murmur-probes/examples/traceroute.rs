//! Run with: cargo run -p murmur-probes --example traceroute -- google.com
//!
//! Note: Requires elevated privileges (sudo or CAP_NET_RAW)

use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use murmur_probes::traceroute::TracerouteProbe;
use murmur_probes::ProbeConfig;
use std::env;
use std::net::IpAddr;
use std::time::Duration;

#[tokio::main]
async fn main() {
    let target = env::args().nth(1).unwrap_or_else(|| "8.8.8.8".to_string());
    
    // Try to parse as IP first, then resolve as hostname
    let addr: IpAddr = match target.parse() {
        Ok(ip) => ip,
        Err(_) => {
            println!("Resolving {}...", target);
            let resolver = TokioAsyncResolver::tokio_from_system_conf()
                .unwrap_or_else(|_| TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default()));
            
            match resolver.lookup_ip(&target).await {
                Ok(lookup) => {
                    match lookup.iter().next() {
                        Some(ip) => {
                            println!("Resolved to {}\n", ip);
                            ip
                        }
                        None => {
                            eprintln!("No IP addresses found for {}", target);
                            return;
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to resolve {}: {}", target, e);
                    return;
                }
            }
        }
    };

    println!("=== Traceroute to {} ===\n", addr);

    let probe = match TracerouteProbe::new() {
        Some(p) => p,
        None => {
            eprintln!("Failed to create traceroute probe.");
            eprintln!("This requires elevated privileges:");
            eprintln!("  Linux:  sudo or CAP_NET_RAW capability");
            eprintln!("  macOS:  sudo");
            eprintln!("  Windows: Run as Administrator");
            eprintln!("\nTry: sudo cargo run -p murmur-probes --example traceroute -- {}", addr);
            return;
        }
    };

    // Per-hop timeout: each non-responsive hop waits this long before moving on.
    // 1s default keeps interval/agent runs fast (e.g. 3 silent hops × 1s = 3s, not 6s).
    let config = ProbeConfig {
        timeout: Duration::from_secs(1),
        dns_timeout: Duration::from_secs(5),
        tcp_timeout: Duration::from_secs(5),
        tls_timeout: Duration::from_secs(5),
    };

    let result = probe.trace(addr, &config).await;

    // Print results
    println!("{}", result.to_path_string());
    
    // Summary (total time = sum of responsive hop RTTs, not wall clock)
    println!("\n=== Summary ===");
    println!("Hops:         {}", result.hop_count());
    println!("Reached:      {}", if result.destination_reached { "yes" } else { "no" });
    println!(
        "Total time:   {:.2}ms",
        result.total_latency().as_secs_f64() * 1000.0
    );
    
    let silent = result.non_responding_hops();
    if !silent.is_empty() {
        println!("\nHops that did not respond:");
        println!("  {}", silent.iter().map(|h| h.ttl.to_string()).collect::<Vec<_>>().join(", "));
    }

    let lossy = result.lossy_hops(50.0);
    if !lossy.is_empty() {
        println!("\nHops with >50% packet loss (partial response):");
        for hop in lossy {
            println!("  Hop {}: {:.1}% loss", hop.ttl, hop.packet_loss);
        }
    }
}
