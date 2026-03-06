//! Murmur CLI - Management and diagnostic tool.
//!
//! Provides commands for testing probes, checking configuration,
//! and diagnosing network issues.

use anyhow::Result;
use clap::{Parser, Subcommand};
use murmur_core::telemetry::init_tracing;
use murmur_core::{AgentConfig, ProbeTarget};
use murmur_probes::{dns::DnsProbe, http::HttpProbe, tcp::TcpProbe, tls::TlsProbe, Probe, ProbeConfig};
use std::time::Duration;

#[derive(Parser)]
#[command(name = "murmur")]
#[command(version, about = "Murmur network experience agent CLI", long_about = None)]
struct Cli {
    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a probe against a target
    Probe {
        /// Target URL or hostname
        target: String,

        /// Probe type: dns, tcp, tls, http
        #[arg(short = 't', long, default_value = "http")]
        probe_type: String,

        /// Timeout in seconds
        #[arg(long, default_value = "30")]
        timeout: u64,
    },

    /// Validate configuration
    Config {
        /// Path to config file (optional)
        #[arg(short, long)]
        path: Option<String>,
    },

    /// Show version and build info
    Version,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize tracing based on verbosity
    let level = if cli.verbose { "debug" } else { "info" };
    init_tracing("pretty", level);

    match cli.command {
        Commands::Probe {
            target,
            probe_type,
            timeout,
        } => {
            run_probe(&target, &probe_type, timeout).await?;
        }
        Commands::Config { path } => {
            validate_config(path)?;
        }
        Commands::Version => {
            print_version();
        }
    }

    Ok(())
}

/// Run a single probe against a target.
async fn run_probe(target: &str, probe_type: &str, timeout_secs: u64) -> Result<()> {
    let target = ProbeTarget::new(target);
    let config = ProbeConfig {
        timeout: Duration::from_secs(timeout_secs),
        dns_timeout: Duration::from_secs(5),
        tcp_timeout: Duration::from_secs(10),
        tls_timeout: Duration::from_secs(10),
    };

    println!("Probing {} with {} probe...\n", target.url, probe_type);

    let result = match probe_type {
        "dns" => {
            let probe = DnsProbe::new();
            probe.measure(&target, &config).await
        }
        "tcp" => {
            let probe = TcpProbe::new();
            probe.measure(&target, &config).await
        }
        "tls" => {
            let probe = TlsProbe::new();
            probe.measure(&target, &config).await
        }
        "http" | "https" => {
            let probe = HttpProbe::new();
            probe.measure(&target, &config).await
        }
        _ => {
            anyhow::bail!("unknown probe type: {}. Valid types: dns, tcp, tls, http", probe_type);
        }
    };

    // Print results
    println!("Target:    {}", result.target.url);
    println!("Success:   {}", if result.success { "yes" } else { "no" });
    println!("Timestamp: {}", result.timestamp);
    println!();

    println!("Timing:");
    if let Some(dns_ms) = result.timing.dns_ms {
        println!("  DNS:       {}ms", dns_ms);
    }
    if let Some(tcp_ms) = result.timing.tcp_connect_ms {
        println!("  TCP:       {}ms", tcp_ms);
    }
    if let Some(tls_ms) = result.timing.tls_handshake_ms {
        println!("  TLS:       {}ms", tls_ms);
    }
    if let Some(ttfb_ms) = result.timing.ttfb_ms {
        println!("  TTFB:      {}ms", ttfb_ms);
    }
    println!("  Total:     {}ms", result.timing.total_ms);
    println!();

    if let Some(ip) = result.resolved_ip {
        println!("Resolved IP: {}", ip);
    }

    if let Some(status) = result.http_status {
        println!("HTTP Status: {}", status);
    }

    if let Some(tls_info) = &result.tls_info {
        println!();
        println!("TLS Info:");
        println!("  Version:   {}", tls_info.version);
        println!("  Cipher:    {}", tls_info.cipher);
        println!("  Resumed:   {}", tls_info.session_resumed);
    }

    if let Some(error) = &result.error {
        println!();
        println!("Error: {}", error);
    }

    Ok(())
}

/// Validate configuration file.
fn validate_config(path: Option<String>) -> Result<()> {
    let config_path = path.map(std::path::PathBuf::from);

    match AgentConfig::load(config_path.clone()) {
        Ok(config) => {
            println!("Configuration is valid.\n");
            println!("Probe Settings:");
            println!("  Interval:     {}s", config.probe.interval_seconds);
            println!("  Timeout:      {}s", config.probe.timeout_seconds);
            println!("  DNS Timeout:  {}s", config.probe.dns_timeout_seconds);
            println!("  TCP Timeout:  {}s", config.probe.tcp_timeout_seconds);
            println!("  TLS Timeout:  {}s", config.probe.tls_timeout_seconds);
            println!();
            println!("Collector Settings:");
            println!("  Endpoint:     {}", config.collector.endpoint);
            println!("  TLS:          {}", config.collector.tls);
            println!("  Batch Size:   {}", config.collector.batch_size);
            println!();
            println!("Logging Settings:");
            println!("  Format:       {}", config.logging.format);
            println!("  Level:        {}", config.logging.level);
            Ok(())
        }
        Err(e) => {
            eprintln!("Configuration error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Print version information.
fn print_version() {
    println!("murmur {}", env!("CARGO_PKG_VERSION"));
    println!();
    println!("A lightweight, zero-config network experience agent.");
    println!();
    println!("Features:");
    println!("  - Passive DNS observation for endpoint discovery");
    println!("  - Real network path quality measurement");
    println!("  - OpenTelemetry metric emission");
    println!("  - Cross-platform support (Mac, Windows, Linux)");
}
