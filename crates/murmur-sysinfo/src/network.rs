//! Network information collection.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use tracing::{debug, warn};

/// Network information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    /// Public IP address.
    pub public_ip: Option<String>,

    /// Local/private IP address.
    pub local_ip: Option<String>,

    /// Default gateway IP.
    pub gateway: Option<String>,

    /// Primary network interface name.
    pub interface: Option<String>,
}

impl NetworkInfo {
    /// Collect network information.
    pub async fn collect() -> Self {
        let public_ip = get_public_ip().await;
        let local_ip = get_local_ip();
        let gateway = get_default_gateway();
        let interface = get_primary_interface();

        debug!(
            public_ip = ?public_ip,
            local_ip = ?local_ip,
            gateway = ?gateway,
            "network info collected"
        );

        Self {
            public_ip,
            local_ip,
            gateway,
            interface,
        }
    }
}

/// VPN detection info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnInfo {
    /// VPN interface name (e.g., "utun0", "tun0", "wg0").
    pub interface: String,

    /// Detected VPN provider (if identifiable).
    pub provider: Option<String>,

    /// VPN gateway IP.
    pub gateway: Option<String>,
}

/// Proxy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// HTTP proxy URL.
    pub http_proxy: Option<String>,

    /// HTTPS proxy URL.
    pub https_proxy: Option<String>,

    /// No-proxy list.
    pub no_proxy: Option<String>,
}

/// Get public IP address via external service.
pub async fn get_public_ip() -> Option<String> {
    // Try multiple services for redundancy
    let services = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
    ];

    for service in services {
        match reqwest::get(service).await {
            Ok(resp) => {
                if let Ok(ip) = resp.text().await {
                    let ip = ip.trim().to_string();
                    if !ip.is_empty() && ip.parse::<IpAddr>().is_ok() {
                        debug!(service = service, ip = %ip, "public IP fetched");
                        return Some(ip);
                    }
                }
            }
            Err(e) => {
                debug!(service = service, error = %e, "failed to fetch public IP");
            }
        }
    }

    warn!("could not determine public IP from any service");
    None
}

/// Get local IP address.
fn get_local_ip() -> Option<String> {
    // Connect to a public IP to determine which local interface would be used
    use std::net::UdpSocket;

    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    let addr = socket.local_addr().ok()?;
    Some(addr.ip().to_string())
}

/// Get default gateway.
#[cfg(target_os = "macos")]
fn get_default_gateway() -> Option<String> {
    use std::process::Command;

    let output = Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;

    if output.status.success() {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            if line.trim().starts_with("gateway:") {
                return line.split(':').nth(1).map(|s| s.trim().to_string());
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn get_default_gateway() -> Option<String> {
    use std::process::Command;

    let output = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .ok()?;

    if output.status.success() {
        let text = String::from_utf8_lossy(&output.stdout);
        // Format: "default via 192.168.1.1 dev eth0"
        let parts: Vec<&str> = text.split_whitespace().collect();
        if parts.len() >= 3 && parts[0] == "default" && parts[1] == "via" {
            return Some(parts[2].to_string());
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn get_default_gateway() -> Option<String> {
    use std::process::Command;

    let output = Command::new("cmd")
        .args(["/C", "route", "print", "0.0.0.0"])
        .output()
        .ok()?;

    if output.status.success() {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            if line.contains("0.0.0.0") && line.contains("0.0.0.0") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    return Some(parts[2].to_string());
                }
            }
        }
    }
    None
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn get_default_gateway() -> Option<String> {
    None
}

/// Get primary network interface name.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn get_primary_interface() -> Option<String> {
    use std::process::Command;

    #[cfg(target_os = "macos")]
    {
        let output = Command::new("route")
            .args(["-n", "get", "default"])
            .output()
            .ok()?;

        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                if line.trim().starts_with("interface:") {
                    return line.split(':').nth(1).map(|s| s.trim().to_string());
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        let output = Command::new("ip")
            .args(["route", "show", "default"])
            .output()
            .ok()?;

        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            let parts: Vec<&str> = text.split_whitespace().collect();
            if let Some(idx) = parts.iter().position(|&s| s == "dev") {
                return parts.get(idx + 1).map(|s| s.to_string());
            }
        }
    }

    None
}

#[cfg(target_os = "windows")]
fn get_primary_interface() -> Option<String> {
    // Windows doesn't have a simple way to get this
    None
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn get_primary_interface() -> Option<String> {
    None
}

/// Detect VPN connection.
///
/// Reports VPN only when the default-route (primary) interface is a VPN interface.
/// Same logic on macOS (`route get default`) and Linux (`ip route show default`):
/// if the interface used for default traffic is a VPN (utun/tun/tap/wg), we report it;
/// otherwise we do not (e.g. Tailscale installed but disconnected → no VPN).
///
/// Split-tunnel setups where the default route stays on the physical interface
/// are reported as no VPN.
pub fn detect_vpn() -> Option<VpnInfo> {
    let primary = get_primary_interface()?;
    let mut vpn_interfaces = find_vpn_interfaces();
    let provider = detect_vpn_provider();

    // If we found interfaces but no provider from interface name, use process-based provider
    if provider.is_some() {
        for (_, p) in vpn_interfaces.iter_mut() {
            if p.is_none() {
                *p = provider.clone();
            }
        }
    }

    // Only report VPN when traffic is actually going through a VPN interface
    let (interface, p) = vpn_interfaces.iter().find(|(iface, _)| *iface == primary)?;
    Some(VpnInfo {
        interface: interface.clone(),
        provider: p.clone(),
        gateway: None,
    })
}

/// Detect VPN provider from running processes (and on macOS, Tailscale.app).
/// Priority order: Tailscale, GlobalProtect, Cisco, OpenConnect, WireGuard, OpenVPN, Zscaler.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn detect_vpn_provider() -> Option<String> {
    let ps_output = std::process::Command::new("ps")
        .args(["-eo", "comm="])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&ps_output.stdout).to_lowercase();

    // Check in priority order (process name substrings)
    let checks: &[(&[&str], &str)] = &[
        (&["tailscaled", "tailscale"], "Tailscale"),
        (&["globalprotect", "pangps"], "Palo Alto GlobalProtect"),
        (&["vpnagentd", "ciscod"], "Cisco AnyConnect"),
        (&["openconnect"], "OpenConnect"),
        (&["wg-quick", "wireguard-go"], "WireGuard"),
        (&["openvpn"], "OpenVPN"),
        (&["zscaler"], "Zscaler"),
    ];
    for (process_names, provider) in checks {
        if process_names.iter().any(|&p| text.contains(p)) {
            return Some(provider.to_string());
        }
    }

    #[cfg(target_os = "macos")]
    {
        if std::path::Path::new("/Applications/Tailscale.app").exists() {
            return Some("Tailscale".to_string());
        }
    }

    None
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn detect_vpn_provider() -> Option<String> {
    None
}

/// Find VPN-like interfaces.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn find_vpn_interfaces() -> Vec<(String, Option<String>)> {
    use std::process::Command;

    let mut vpn_interfaces = Vec::new();

    #[cfg(target_os = "macos")]
    {
        let output = Command::new("ifconfig").output();

        if let Ok(output) = output {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                // Look for utun interfaces (macOS VPN)
                if line.starts_with("utun") {
                    let iface = line.split(':').next().unwrap_or("").to_string();
                    if !iface.is_empty() {
                        vpn_interfaces.push((iface, None));
                    }
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                // Common VPN interface patterns
                if name.starts_with("tun")
                    || name.starts_with("tap")
                    || name.starts_with("wg")
                    || name.starts_with("vpn")
                {
                    let provider = if name.starts_with("wg") {
                        Some("WireGuard".to_string())
                    } else {
                        None
                    };
                    vpn_interfaces.push((name, provider));
                }
            }
        }
    }

    vpn_interfaces
}

#[cfg(target_os = "windows")]
fn find_vpn_interfaces() -> Vec<(String, Option<String>)> {
    // Windows VPN detection would need WMI or similar
    Vec::new()
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn find_vpn_interfaces() -> Vec<(String, Option<String>)> {
    Vec::new()
}

/// Detect system proxy configuration.
pub fn detect_proxy() -> Option<ProxyConfig> {
    let http_proxy = std::env::var("HTTP_PROXY")
        .or_else(|_| std::env::var("http_proxy"))
        .ok();

    let https_proxy = std::env::var("HTTPS_PROXY")
        .or_else(|_| std::env::var("https_proxy"))
        .ok();

    let no_proxy = std::env::var("NO_PROXY")
        .or_else(|_| std::env::var("no_proxy"))
        .ok();

    // Also check system proxy settings
    let system_proxy = get_system_proxy();

    let http_proxy = http_proxy.or(system_proxy.clone());
    let https_proxy = https_proxy.or(system_proxy);

    if http_proxy.is_some() || https_proxy.is_some() {
        Some(ProxyConfig {
            http_proxy,
            https_proxy,
            no_proxy,
        })
    } else {
        None
    }
}

/// Get system proxy (platform-specific).
#[cfg(target_os = "macos")]
fn get_system_proxy() -> Option<String> {
    use std::process::Command;

    let output = Command::new("scutil").args(["--proxy"]).output().ok()?;

    if output.status.success() {
        let text = String::from_utf8_lossy(&output.stdout);
        // Parse scutil output for HTTPProxy
        let mut proxy_host = None;
        let mut proxy_port = None;

        for line in text.lines() {
            let line = line.trim();
            if line.starts_with("HTTPProxy :") {
                proxy_host = line.split(':').nth(1).map(|s| s.trim().to_string());
            } else if line.starts_with("HTTPPort :") {
                proxy_port = line.split(':').nth(1).map(|s| s.trim().to_string());
            }
        }

        if let (Some(host), Some(port)) = (proxy_host, proxy_port) {
            if !host.is_empty() && host != "0" {
                return Some(format!("http://{host}:{port}"));
            }
        }
    }
    None
}

#[cfg(not(target_os = "macos"))]
fn get_system_proxy() -> Option<String> {
    // Linux and Windows would need different approaches
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_local_ip_works() {
        let ip = get_local_ip();
        // Should get some local IP in most environments
        println!("Local IP: {:?}", ip);
    }

    #[test]
    fn detect_proxy_works() {
        let proxy = detect_proxy();
        println!("Proxy config: {:?}", proxy);
    }
}
