//! System information collection for Murmur.
//!
//! Collects resource attributes about the host system:
//! - OS, hostname, machine model
//! - Public IP address
//! - WiFi connection details (signal, SSID, BSSID, channel)
//! - VPN detection and gateway measurement
//! - Proxy detection

#![deny(unsafe_code)]
#![warn(missing_docs)]

mod network;
mod system;
mod wifi;

pub use network::{detect_proxy, detect_vpn, get_public_ip, NetworkInfo, ProxyConfig, VpnInfo};
pub use system::{get_system_info, SystemInfo};
pub use wifi::{get_wifi_info, WifiInfo};

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Complete system context as OTEL resource attributes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceAttributes {
    /// System information.
    pub system: SystemInfo,

    /// Network information.
    pub network: NetworkInfo,

    /// WiFi information (if connected via WiFi).
    pub wifi: Option<WifiInfo>,

    /// VPN information (if VPN detected).
    pub vpn: Option<VpnInfo>,

    /// Proxy configuration (if detected).
    pub proxy: Option<ProxyConfig>,
}

impl ResourceAttributes {
    /// Collect all resource attributes.
    pub async fn collect() -> Self {
        let system = get_system_info();
        let network = NetworkInfo::collect().await;
        let wifi = get_wifi_info();
        let vpn = detect_vpn();
        let proxy = detect_proxy();

        Self {
            system,
            network,
            wifi,
            vpn,
            proxy,
        }
    }

    /// Convert to OTEL-style key-value pairs.
    pub fn to_attributes(&self) -> HashMap<String, String> {
        let mut attrs = HashMap::new();

        // System attributes
        attrs.insert("host.name".to_string(), self.system.hostname.clone());
        attrs.insert("os.type".to_string(), self.system.os_type.clone());
        attrs.insert("os.version".to_string(), self.system.os_version.clone());
        attrs.insert("host.arch".to_string(), self.system.arch.clone());
        attrs.insert("host.cpu_cores".to_string(), self.system.cpu_cores.to_string());
        attrs.insert("host.memory_total_bytes".to_string(), self.system.total_memory_bytes.to_string());
        if let Some(ref model) = self.system.machine_model {
            attrs.insert("host.model".to_string(), model.clone());
        }

        // Network attributes
        if let Some(ref ip) = self.network.public_ip {
            attrs.insert("host.ip.public".to_string(), ip.clone());
        }
        if let Some(ref ip) = self.network.local_ip {
            attrs.insert("host.ip.local".to_string(), ip.clone());
        }
        if let Some(ref gw) = self.network.gateway {
            attrs.insert("network.gateway".to_string(), gw.clone());
        }
        if let Some(ref iface) = self.network.interface {
            attrs.insert("network.interface".to_string(), iface.clone());
        }

        // WiFi attributes
        if let Some(ref wifi) = self.wifi {
            attrs.insert("network.type".to_string(), "wifi".to_string());
            attrs.insert("wifi.ssid".to_string(), wifi.ssid.clone());
            if let Some(ref bssid) = wifi.bssid {
                attrs.insert("wifi.bssid".to_string(), bssid.clone());
            }
            if let Some(signal) = wifi.signal_strength {
                attrs.insert("wifi.signal_dbm".to_string(), signal.to_string());
            }
            if let Some(quality) = wifi.signal_quality {
                attrs.insert("wifi.signal_quality_pct".to_string(), quality.to_string());
            }
            if let Some(channel) = wifi.channel {
                attrs.insert("wifi.channel".to_string(), channel.to_string());
            }
            if let Some(tx) = wifi.tx_rate_mbps {
                attrs.insert("wifi.tx_rate_mbps".to_string(), tx.to_string());
            }
            if let Some(rx) = wifi.rx_rate_mbps {
                attrs.insert("wifi.rx_rate_mbps".to_string(), rx.to_string());
            }
        }

        // VPN attributes
        if let Some(ref vpn) = self.vpn {
            attrs.insert("vpn.detected".to_string(), "true".to_string());
            attrs.insert("vpn.interface".to_string(), vpn.interface.clone());
            if let Some(ref provider) = vpn.provider {
                attrs.insert("vpn.provider".to_string(), provider.clone());
            }
            if let Some(ref gw) = vpn.gateway {
                attrs.insert("vpn.gateway".to_string(), gw.clone());
            }
        }

        // Proxy attributes
        if let Some(ref proxy) = self.proxy {
            attrs.insert("proxy.detected".to_string(), "true".to_string());
            if let Some(ref http) = proxy.http_proxy {
                attrs.insert("proxy.http".to_string(), http.clone());
            }
            if let Some(ref https) = proxy.https_proxy {
                attrs.insert("proxy.https".to_string(), https.clone());
            }
        }

        attrs
    }
}
