//! Murmur Agent - Native background service for network monitoring.
//!
//! The agent runs continuously, observing network conditions and emitting
//! telemetry in OpenTelemetry format.

use anyhow::{Context, Result};
use murmur_core::telemetry::{init_tracing, TelemetryEmitter};
use murmur_core::{AgentConfig, ProbeTarget};
use murmur_probes::{dns::DnsProbe, http::HttpProbe, tcp::TcpProbe, tls::TlsProbe, Probe, ProbeConfig};
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use tokio::sync::{broadcast, mpsc};
use tracing::{error, info, warn};

/// Channel buffer size for probe results.
const RESULT_CHANNEL_SIZE: usize = 1024;

/// Main entry point for the Murmur agent.
#[tokio::main]
async fn main() -> Result<()> {
    // Load configuration
    let config = AgentConfig::load(None).context("failed to load configuration")?;

    // Initialize tracing
    init_tracing(&config.logging.format, &config.logging.level);

    info!(
        version = env!("CARGO_PKG_VERSION"),
        probe_interval_seconds = config.probe.interval_seconds,
        collector_endpoint = %config.collector.endpoint,
        "murmur agent starting"
    );

    // Create shutdown channel (broadcast for one-to-many signaling)
    let (shutdown_tx, _) = broadcast::channel::<()>(1);

    // Create probe result channel (mpsc for many-to-one collection)
    let (result_tx, result_rx) = mpsc::channel(RESULT_CHANNEL_SIZE);

    // Initialize telemetry emitter
    let telemetry = TelemetryEmitter::new(&config.collector).unwrap_or_else(|| {
        warn!("failed to connect to OTLP collector, running without telemetry export");
        TelemetryEmitter::noop()
    });

    // Start the collector task
    let collector_telemetry = telemetry.clone();
    let collector_shutdown = shutdown_tx.subscribe();
    let collector_handle = tokio::spawn(async move {
        run_collector(result_rx, collector_telemetry, collector_shutdown).await;
    });

    // Create probe config from agent config
    let probe_config = ProbeConfig {
        timeout: config.probe.timeout(),
        dns_timeout: config.probe.dns_timeout(),
        tcp_timeout: config.probe.tcp_timeout(),
        tls_timeout: config.probe.tls_timeout(),
    };

    // Start the probe scheduler
    let probe_interval = config.probe.interval();
    let scheduler_shutdown = shutdown_tx.subscribe();
    let scheduler_handle = tokio::spawn(async move {
        run_scheduler(
            result_tx,
            probe_config,
            probe_interval,
            scheduler_shutdown,
        )
        .await;
    });

    // Wait for shutdown signal
    info!("agent running, press Ctrl+C to stop");

    tokio::select! {
        _ = signal::ctrl_c() => {
            info!("received shutdown signal");
        }
    }

    // Signal shutdown to all tasks
    info!("initiating graceful shutdown");
    drop(shutdown_tx);

    // Wait for tasks to complete with a timeout
    let shutdown_timeout = Duration::from_secs(30);
    tokio::select! {
        _ = async {
            let _ = scheduler_handle.await;
            let _ = collector_handle.await;
        } => {
            info!("all tasks completed");
        }
        _ = tokio::time::sleep(shutdown_timeout) => {
            warn!(timeout_seconds = shutdown_timeout.as_secs(), "shutdown timeout exceeded");
        }
    }

    info!("murmur agent stopped");
    Ok(())
}

/// Collect probe results and emit telemetry.
async fn run_collector(
    mut result_rx: mpsc::Receiver<murmur_core::ProbeResult>,
    telemetry: Arc<TelemetryEmitter>,
    mut shutdown: broadcast::Receiver<()>,
) {
    info!("collector started");

    loop {
        tokio::select! {
            biased;

            _ = shutdown.recv() => {
                info!("collector received shutdown signal");
                break;
            }

            Some(result) = result_rx.recv() => {
                telemetry.emit_probe_result(&result);
            }
        }
    }

    // Drain remaining results
    while let Ok(result) = result_rx.try_recv() {
        telemetry.emit_probe_result(&result);
    }

    info!("collector stopped");
}

/// Schedule and run probes at regular intervals.
async fn run_scheduler(
    result_tx: mpsc::Sender<murmur_core::ProbeResult>,
    probe_config: ProbeConfig,
    interval: Duration,
    mut shutdown: broadcast::Receiver<()>,
) {
    info!(interval_seconds = interval.as_secs(), "scheduler started");

    // TODO: In production, targets would be discovered from DNS observations
    // For now, we use a static list for demonstration
    let targets = get_default_targets();

    // Create probe instances
    // DNS, TCP, and TLS probes available for more granular measurements
    let _dns_probe = DnsProbe::new();
    let _tcp_probe = TcpProbe::new();
    let _tls_probe = TlsProbe::new();
    let http_probe = HttpProbe::new();

    let mut interval_timer = tokio::time::interval(interval);
    interval_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            biased;

            _ = shutdown.recv() => {
                info!("scheduler received shutdown signal");
                break;
            }

            _ = interval_timer.tick() => {
                info!(target_count = targets.len(), "starting probe cycle");

                for target in &targets {
                    // Run HTTP probe (most comprehensive)
                    let result = http_probe.measure(target, &probe_config).await;

                    if result_tx.send(result).await.is_err() {
                        error!("failed to send probe result, channel closed");
                        return;
                    }
                }

                info!("probe cycle completed");
            }
        }
    }

    info!("scheduler stopped");
}

/// Get default probe targets for demonstration.
/// In production, these would be discovered from DNS observations.
fn get_default_targets() -> Vec<ProbeTarget> {
    vec![
        ProbeTarget::new("https://www.google.com")
            .with_name("Google")
            .with_tag("search"),
        ProbeTarget::new("https://www.cloudflare.com")
            .with_name("Cloudflare")
            .with_tag("cdn"),
        ProbeTarget::new("https://api.github.com")
            .with_name("GitHub API")
            .with_tag("api"),
    ]
}
