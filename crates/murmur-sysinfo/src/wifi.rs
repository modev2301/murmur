//! WiFi information collection.

use serde::{Deserialize, Serialize};
use tracing::debug;

/// WiFi connection information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiInfo {
    /// SSID (network name).
    pub ssid: String,

    /// BSSID (access point MAC address).
    pub bssid: Option<String>,

    /// Signal strength in dBm (negative value, closer to 0 is better).
    pub signal_strength: Option<i32>,

    /// Signal quality as percentage (0-100).
    pub signal_quality: Option<u8>,

    /// Channel number.
    pub channel: Option<u32>,

    /// Frequency in MHz.
    pub frequency_mhz: Option<u32>,

    /// Transmit rate in Mbps.
    pub tx_rate_mbps: Option<f64>,

    /// Receive rate in Mbps.
    pub rx_rate_mbps: Option<f64>,

    /// Security type (e.g., "WPA2", "WPA3").
    pub security: Option<String>,

    /// Interface name.
    pub interface: String,
}

/// Get WiFi information for the current connection.
pub fn get_wifi_info() -> Option<WifiInfo> {
    #[cfg(target_os = "macos")]
    {
        get_wifi_info_macos()
    }

    #[cfg(target_os = "linux")]
    {
        get_wifi_info_linux()
    }

    #[cfg(target_os = "windows")]
    {
        get_wifi_info_windows()
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        None
    }
}

#[cfg(target_os = "macos")]
fn get_wifi_info_macos() -> Option<WifiInfo> {
    // Use system_profiler (airport is deprecated on modern macOS)
    if let Some(info) = get_wifi_via_system_profiler() {
        return Some(info);
    }

    // Fallback to airport (older macOS)
    if let Some(info) = get_wifi_via_airport() {
        return Some(info);
    }

    // Last resort: just SSID from networksetup
    get_wifi_via_networksetup()
}

#[cfg(target_os = "macos")]
fn get_wifi_via_airport() -> Option<WifiInfo> {
    use std::process::Command;

    let output = Command::new(
        "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport",
    )
    .args(["-I"])
    .output()
    .ok()?;

    if !output.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&output.stdout);
    
    // Check if WiFi is off or not associated
    if text.contains("AirPort: Off") || text.contains("state: init") {
        return None;
    }

    let mut ssid = None;
    let mut bssid = None;
    let mut signal_strength = None;
    let mut channel = None;
    let mut tx_rate = None;

    for line in text.lines() {
        let line = line.trim();
        // Handle both " SSID:" and "SSID:" formats
        if line.contains("SSID:") && !line.contains("BSSID") {
            ssid = line.split(':').nth(1).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        } else if line.contains("BSSID:") {
            // BSSID has colons in the value, so rejoin after first split
            let parts: Vec<&str> = line.splitn(2, ':').collect();
            if parts.len() == 2 {
                bssid = Some(parts[1].trim().to_string()).filter(|s| !s.is_empty());
            }
        } else if line.contains("agrCtlRSSI:") {
            signal_strength = line
                .split(':')
                .nth(1)
                .and_then(|s| s.trim().parse().ok());
        } else if line.contains("channel:") {
            // Format: "channel: 36,1" or "channel: 6"
            if let Some(ch_str) = line.split(':').nth(1) {
                channel = ch_str.trim().split(',').next().and_then(|s| s.parse().ok());
            }
        } else if line.contains("lastTxRate:") {
            tx_rate = line
                .split(':')
                .nth(1)
                .and_then(|s| s.trim().parse().ok());
        }
    }

    let ssid = ssid?;

    let signal_quality = signal_strength.map(|dbm| {
        if dbm >= -50 {
            100
        } else if dbm <= -100 {
            0
        } else {
            ((dbm + 100) * 2) as u8
        }
    });

    debug!(
        ssid = %ssid,
        signal = ?signal_strength,
        channel = ?channel,
        "WiFi info collected via airport"
    );

    Some(WifiInfo {
        ssid,
        bssid,
        signal_strength,
        signal_quality,
        channel,
        frequency_mhz: channel.map(channel_to_frequency),
        tx_rate_mbps: tx_rate,
        rx_rate_mbps: None,
        security: None,
        interface: "en0".to_string(),
    })
}

#[cfg(target_os = "macos")]
fn get_wifi_via_networksetup() -> Option<WifiInfo> {
    use std::process::Command;

    // Get current WiFi network name
    let output = Command::new("networksetup")
        .args(["-getairportnetwork", "en0"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&output.stdout);
    
    // Format: "Current Wi-Fi Network: NetworkName" or "You are not associated with an AirPort network."
    if text.contains("not associated") || text.contains("Wi-Fi power is currently off") {
        return None;
    }

    let ssid = text
        .split(':')
        .nth(1)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())?;

    debug!(ssid = %ssid, "WiFi info collected via networksetup");

    Some(WifiInfo {
        ssid,
        bssid: None,
        signal_strength: None,
        signal_quality: None,
        channel: None,
        frequency_mhz: None,
        tx_rate_mbps: None,
        rx_rate_mbps: None,
        security: None,
        interface: "en0".to_string(),
    })
}

#[cfg(target_os = "macos")]
fn get_wifi_via_system_profiler() -> Option<WifiInfo> {
    use std::process::Command;

    // First get SSID from networksetup (more reliable)
    let ssid = get_ssid_from_networksetup()?;

    // Then get details from system_profiler
    let output = Command::new("system_profiler")
        .args(["SPAirPortDataType"])
        .output()
        .ok()?;

    if !output.status.success() {
        // Return with just SSID if system_profiler fails
        return Some(WifiInfo {
            ssid,
            bssid: None,
            signal_strength: None,
            signal_quality: None,
            channel: None,
            frequency_mhz: None,
            tx_rate_mbps: None,
            rx_rate_mbps: None,
            security: None,
            interface: "en0".to_string(),
        });
    }

    let text = String::from_utf8_lossy(&output.stdout);
    
    // Find "Current Network Information:" and extract first network's details
    let mut in_current_network = false;
    let mut bssid = None;
    let mut channel = None;
    let mut signal_strength = None;
    let mut tx_rate = None;
    let mut found_first = false;

    for line in text.lines() {
        let line = line.trim();
        
        if line.contains("Current Network Information") {
            in_current_network = true;
            continue;
        }
        
        if !in_current_network {
            continue;
        }

        // Stop after "Supported Channels:" which marks end of current network section
        if line.starts_with("Supported Channels:") && found_first {
            break;
        }

        // BSSID (MAC of access point): "BSSID: aa:bb:cc:dd:ee:ff" or "MAC Address: ..."
        if (line.starts_with("BSSID:") || line.starts_with("MAC Address:")) && bssid.is_none() {
            let value = line
                .splitn(2, ':')
                .nth(1)
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty() && s.contains(':'));
            if value.as_ref().map_or(false, |s| s.len() >= 17) {
                bssid = value;
            }
        }

        // Parse channel: "Channel: 161 (5GHz, 80MHz)"
        if line.starts_with("Channel:") && channel.is_none() {
            if let Some(ch_part) = line.strip_prefix("Channel:") {
                let ch_str = ch_part.trim();
                // Extract just the number before the space/parenthesis
                channel = ch_str
                    .split(|c: char| c.is_whitespace() || c == '(')
                    .next()
                    .and_then(|s| s.parse().ok());
                found_first = true;
            }
        }

        // Parse signal: "Signal / Noise: -40 dBm / -87 dBm"
        if line.starts_with("Signal / Noise:") && signal_strength.is_none() {
            if let Some(sig_part) = line.strip_prefix("Signal / Noise:") {
                // Get first number (signal)
                signal_strength = sig_part
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse().ok());
            }
        }

        // Parse transmit rate: "Transmit Rate: 866"
        if line.starts_with("Transmit Rate:") && tx_rate.is_none() {
            if let Some(rate_part) = line.strip_prefix("Transmit Rate:") {
                tx_rate = rate_part.trim().parse().ok();
            }
        }
    }

    let signal_quality = signal_strength.map(|dbm: i32| {
        if dbm >= -50 {
            100
        } else if dbm <= -100 {
            0
        } else {
            ((dbm + 100) * 2) as u8
        }
    });

    debug!(
        ssid = %ssid,
        signal = ?signal_strength,
        channel = ?channel,
        tx_rate = ?tx_rate,
        "WiFi info collected via system_profiler"
    );

    Some(WifiInfo {
        ssid,
        bssid,
        signal_strength,
        signal_quality,
        channel,
        frequency_mhz: channel.map(channel_to_frequency),
        tx_rate_mbps: tx_rate,
        rx_rate_mbps: None,
        security: None,
        interface: "en0".to_string(),
    })
}

#[cfg(target_os = "macos")]
fn get_ssid_from_networksetup() -> Option<String> {
    use std::process::Command;

    let output = Command::new("networksetup")
        .args(["-getairportnetwork", "en0"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&output.stdout);
    
    if text.contains("not associated") || text.contains("Wi-Fi power is currently off") {
        return None;
    }

    text.split(':')
        .nth(1)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(target_os = "linux")]
fn get_wifi_info_linux() -> Option<WifiInfo> {
    use std::process::Command;

    // Find wireless interface
    let iface = find_wireless_interface()?;

    // Use iwconfig or iw to get WiFi info
    let output = Command::new("iwconfig").arg(&iface).output().ok()?;

    if !output.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let mut ssid = None;
    let mut signal_strength = None;
    let mut tx_rate = None;
    let mut frequency = None;

    for line in text.lines() {
        let line = line.trim();

        // ESSID:"NetworkName"
        if let Some(start) = line.find("ESSID:\"") {
            if let Some(end) = line[start + 7..].find('"') {
                ssid = Some(line[start + 7..start + 7 + end].to_string());
            }
        }

        // Signal level=-XX dBm
        if let Some(start) = line.find("Signal level=") {
            let rest = &line[start + 13..];
            if let Some(space) = rest.find(' ') {
                signal_strength = rest[..space].parse().ok();
            }
        }

        // Bit Rate=XX Mb/s
        if let Some(start) = line.find("Bit Rate=") {
            let rest = &line[start + 9..];
            if let Some(space) = rest.find(' ') {
                tx_rate = rest[..space].parse().ok();
            }
        }

        // Frequency:X.XXX GHz
        if let Some(start) = line.find("Frequency:") {
            let rest = &line[start + 10..];
            if let Some(space) = rest.find(' ') {
                if let Ok(ghz) = rest[..space].parse::<f64>() {
                    frequency = Some((ghz * 1000.0) as u32);
                }
            }
        }
    }

    let ssid = ssid?;

    let signal_quality = signal_strength.map(|dbm: i32| {
        if dbm >= -50 {
            100
        } else if dbm <= -100 {
            0
        } else {
            ((dbm + 100) * 2) as u8
        }
    });

    debug!(
        ssid = %ssid,
        signal = ?signal_strength,
        interface = %iface,
        "WiFi info collected"
    );

    Some(WifiInfo {
        ssid,
        bssid: None,
        signal_strength,
        signal_quality,
        channel: frequency.map(frequency_to_channel),
        frequency_mhz: frequency,
        tx_rate_mbps: tx_rate,
        rx_rate_mbps: None,
        security: None,
        interface: iface,
    })
}

#[cfg(target_os = "linux")]
fn find_wireless_interface() -> Option<String> {
    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let wireless_path = format!("/sys/class/net/{}/wireless", name);
            if std::path::Path::new(&wireless_path).exists() {
                return Some(name);
            }
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn get_wifi_info_windows() -> Option<WifiInfo> {
    use std::process::Command;

    let output = Command::new("netsh")
        .args(["wlan", "show", "interfaces"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let mut ssid = None;
    let mut bssid = None;
    let mut signal_quality = None;
    let mut channel = None;
    let mut tx_rate = None;
    let mut rx_rate = None;
    let mut interface = None;

    for line in text.lines() {
        let line = line.trim();

        if line.starts_with("Name") {
            interface = line.split(':').nth(1).map(|s| s.trim().to_string());
        } else if line.starts_with("SSID") && !line.starts_with("BSSID") {
            ssid = line.split(':').nth(1).map(|s| s.trim().to_string());
        } else if line.starts_with("BSSID") {
            bssid = line
                .split(':')
                .skip(1)
                .collect::<Vec<_>>()
                .join(":")
                .trim()
                .to_string()
                .into();
        } else if line.starts_with("Signal") {
            // Signal: XX%
            signal_quality = line
                .split(':')
                .nth(1)
                .and_then(|s| s.trim().trim_end_matches('%').parse().ok());
        } else if line.starts_with("Channel") {
            channel = line.split(':').nth(1).and_then(|s| s.trim().parse().ok());
        } else if line.starts_with("Receive rate") {
            rx_rate = line.split(':').nth(1).and_then(|s| s.trim().parse().ok());
        } else if line.starts_with("Transmit rate") {
            tx_rate = line.split(':').nth(1).and_then(|s| s.trim().parse().ok());
        }
    }

    let ssid = ssid?;

    // Convert quality percentage to approximate dBm
    let signal_strength = signal_quality.map(|q: u8| -100 + (q as i32 / 2));

    Some(WifiInfo {
        ssid,
        bssid,
        signal_strength,
        signal_quality,
        channel,
        frequency_mhz: channel.map(channel_to_frequency),
        tx_rate_mbps: tx_rate,
        rx_rate_mbps: rx_rate,
        security: None,
        interface: interface.unwrap_or_else(|| "WiFi".to_string()),
    })
}

/// Convert WiFi channel to frequency in MHz.
fn channel_to_frequency(channel: u32) -> u32 {
    match channel {
        // 2.4 GHz band
        1..=13 => 2407 + (channel * 5),
        14 => 2484,
        // 5 GHz band
        36 => 5180,
        40 => 5200,
        44 => 5220,
        48 => 5240,
        52 => 5260,
        56 => 5280,
        60 => 5300,
        64 => 5320,
        100 => 5500,
        104 => 5520,
        108 => 5540,
        112 => 5560,
        116 => 5580,
        120 => 5600,
        124 => 5620,
        128 => 5640,
        132 => 5660,
        136 => 5680,
        140 => 5700,
        144 => 5720,
        149 => 5745,
        153 => 5765,
        157 => 5785,
        161 => 5805,
        165 => 5825,
        // 6 GHz band (WiFi 6E)
        _ if channel > 190 => 5950 + (channel - 191) * 5,
        _ => 0,
    }
}

/// Convert frequency in MHz to WiFi channel.
#[cfg(target_os = "linux")]
fn frequency_to_channel(freq: u32) -> u32 {
    match freq {
        // 2.4 GHz
        2412 => 1,
        2417 => 2,
        2422 => 3,
        2427 => 4,
        2432 => 5,
        2437 => 6,
        2442 => 7,
        2447 => 8,
        2452 => 9,
        2457 => 10,
        2462 => 11,
        2467 => 12,
        2472 => 13,
        2484 => 14,
        // 5 GHz (approximate)
        f if (5170..=5330).contains(&f) => (f - 5000) / 5,
        f if (5490..=5730).contains(&f) => (f - 5000) / 5,
        f if (5735..=5835).contains(&f) => (f - 5000) / 5,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_frequency_conversion() {
        assert_eq!(channel_to_frequency(1), 2412);
        assert_eq!(channel_to_frequency(6), 2437);
        assert_eq!(channel_to_frequency(11), 2462);
        assert_eq!(channel_to_frequency(36), 5180);
        assert_eq!(channel_to_frequency(149), 5745);
    }

    #[test]
    fn get_wifi_info_runs() {
        // This might return None if not on WiFi, but shouldn't panic
        let info = get_wifi_info();
        println!("WiFi info: {:?}", info);
    }
}
