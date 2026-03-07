//! Run with: cargo run -p murmur-sysinfo --example show

use murmur_sysinfo::{detect_proxy, detect_vpn, get_system_info, get_wifi_info, NetworkInfo};

#[tokio::main]
async fn main() {
    println!("=== System Info ===");
    let sys = get_system_info();
    println!("Hostname:    {}", sys.hostname);
    println!("OS:          {} {}", sys.os_name, sys.os_version);
    println!("Kernel:      {}", sys.kernel_version.unwrap_or_default());
    println!(
        "Model:       {}",
        sys.machine_model.unwrap_or_else(|| "unknown".into())
    );
    println!("Arch:        {}", sys.arch);
    println!("CPU Cores:   {}", sys.cpu_cores);
    println!("Memory:      {} GB", sys.total_memory_bytes / 1_073_741_824);
    println!();

    println!("=== Network ===");
    let net = NetworkInfo::collect().await;
    println!(
        "Public IP:   {}",
        net.public_ip.unwrap_or_else(|| "unknown".into())
    );
    println!(
        "Local IP:    {}",
        net.local_ip.unwrap_or_else(|| "unknown".into())
    );
    println!(
        "Gateway:     {}",
        net.gateway.unwrap_or_else(|| "unknown".into())
    );
    println!(
        "Interface:   {}",
        net.interface.unwrap_or_else(|| "unknown".into())
    );
    println!();

    println!("=== WiFi ===");
    if let Some(wifi) = get_wifi_info() {
        println!("SSID:        {}", wifi.ssid);
        println!(
            "BSSID:       {}",
            wifi.bssid.unwrap_or_else(|| "unknown".into())
        );
        println!("Signal:      {} dBm", wifi.signal_strength.unwrap_or(0));
        println!("Quality:     {}%", wifi.signal_quality.unwrap_or(0));
        println!("Channel:     {}", wifi.channel.unwrap_or(0));
        println!("TX Rate:     {} Mbps", wifi.tx_rate_mbps.unwrap_or(0.0));
        println!("Interface:   {}", wifi.interface);
    } else {
        println!("Not connected to WiFi (or using Ethernet)");
    }
    println!();

    println!("=== VPN ===");
    if let Some(vpn) = detect_vpn() {
        println!("Detected:    yes");
        println!("Interface:   {}", vpn.interface);
        println!(
            "Provider:    {}",
            vpn.provider.unwrap_or_else(|| "unknown".into())
        );
    } else {
        println!("Detected:    no");
    }
    println!();

    println!("=== Proxy ===");
    if let Some(proxy) = detect_proxy() {
        println!("Detected:    yes");
        println!(
            "HTTP:        {}",
            proxy.http_proxy.unwrap_or_else(|| "none".into())
        );
        println!(
            "HTTPS:       {}",
            proxy.https_proxy.unwrap_or_else(|| "none".into())
        );
    } else {
        println!("Detected:    no");
    }
}
