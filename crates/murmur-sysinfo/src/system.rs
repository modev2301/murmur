//! System information collection.

use serde::{Deserialize, Serialize};
use sysinfo::System;
use tracing::debug;

/// Basic system information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    /// Hostname.
    pub hostname: String,

    /// OS type (e.g., "Linux", "Darwin", "Windows").
    pub os_type: String,

    /// OS version.
    pub os_version: String,

    /// OS name (e.g., "Ubuntu 22.04", "macOS Sonoma").
    pub os_name: String,

    /// Kernel version.
    pub kernel_version: Option<String>,

    /// Machine model (e.g., "MacBookPro18,3").
    pub machine_model: Option<String>,

    /// CPU architecture.
    pub arch: String,

    /// Number of CPU cores.
    pub cpu_cores: usize,

    /// Total memory in bytes.
    pub total_memory_bytes: u64,
}

/// Get system information.
pub fn get_system_info() -> SystemInfo {
    let mut sys = System::new_all();
    sys.refresh_all();

    let hostname = System::host_name().unwrap_or_else(|| "unknown".to_string());
    let os_type = std::env::consts::OS.to_string();
    let os_version = System::os_version().unwrap_or_else(|| "unknown".to_string());
    let os_name = System::name().unwrap_or_else(|| os_type.clone());
    let kernel_version = System::kernel_version();
    let arch = std::env::consts::ARCH.to_string();
    let cpu_cores = sys.cpus().len();
    let total_memory_bytes = sys.total_memory();

    let machine_model = get_machine_model();

    debug!(
        hostname = %hostname,
        os = %os_name,
        arch = %arch,
        cores = cpu_cores,
        "system info collected"
    );

    SystemInfo {
        hostname,
        os_type,
        os_version,
        os_name,
        kernel_version,
        machine_model,
        arch,
        cpu_cores,
        total_memory_bytes,
    }
}

/// Get machine model (platform-specific).
#[cfg(target_os = "macos")]
fn get_machine_model() -> Option<String> {
    use std::process::Command;

    let output = Command::new("sysctl")
        .args(["-n", "hw.model"])
        .output()
        .ok()?;

    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
fn get_machine_model() -> Option<String> {
    // Try DMI product name
    std::fs::read_to_string("/sys/class/dmi/id/product_name")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(target_os = "windows")]
fn get_machine_model() -> Option<String> {
    use std::process::Command;

    let output = Command::new("wmic")
        .args(["csproduct", "get", "name"])
        .output()
        .ok()?;

    if output.status.success() {
        let text = String::from_utf8_lossy(&output.stdout);
        text.lines()
            .nth(1)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    } else {
        None
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn get_machine_model() -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_system_info_works() {
        let info = get_system_info();
        assert!(!info.hostname.is_empty());
        assert!(!info.os_type.is_empty());
        assert!(info.cpu_cores > 0);
        assert!(info.total_memory_bytes > 0);
    }
}
