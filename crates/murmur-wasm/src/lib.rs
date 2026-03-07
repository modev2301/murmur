//! Murmur WASM - WebAssembly probe runtime.
//!
//! This crate provides browser-side probes that can measure network timing
//! from within a web page. It uses the Fetch API and Performance APIs to
//! capture timing data.
//!
//! ## Capabilities
//!
//! In WASM, we can:
//! - Make HTTP/HTTPS requests via Fetch API
//! - Measure request timing (DNS, TCP, TLS, TTFB)
//! - Access Navigation Timing and Resource Timing APIs
//! - Read network connection information
//!
//! We cannot:
//! - Make raw TCP/UDP connections
//! - Send ICMP packets (ping/traceroute)
//! - Access low-level network interfaces
//!
//! ## Usage
//!
//! ```javascript
//! import init, { probe_url, get_timing } from 'murmur-wasm';
//!
//! await init();
//! const result = await probe_url('https://example.com');
//! console.log(result);
//! ```

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};

/// Probe result from a WASM fetch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmProbeResult {
    /// Target URL.
    pub url: String,
    /// Whether the probe succeeded.
    pub success: bool,
    /// HTTP status code (if request completed).
    pub status: Option<u16>,
    /// Error message (if failed).
    pub error: Option<String>,
    /// Total duration in milliseconds.
    pub total_ms: f64,
    /// DNS lookup time in milliseconds (if available from Resource Timing).
    pub dns_ms: Option<f64>,
    /// TCP connection time in milliseconds.
    pub tcp_ms: Option<f64>,
    /// TLS handshake time in milliseconds.
    pub tls_ms: Option<f64>,
    /// Time to First Byte in milliseconds.
    pub ttfb_ms: Option<f64>,
    /// Response size in bytes.
    pub size_bytes: Option<u64>,
    /// Protocol used (e.g., "h2", "http/1.1").
    pub protocol: Option<String>,
}

/// Probe a URL using the Fetch API.
#[wasm_bindgen]
pub async fn probe_url(url: &str) -> JsValue {
    let result = probe_url_internal(url).await;
    serde_wasm_bindgen::to_value(&result).unwrap_or(JsValue::NULL)
}

async fn probe_url_internal(url: &str) -> WasmProbeResult {
    let start = now();

    let opts = RequestInit::new();
    opts.set_method("GET");
    opts.set_mode(RequestMode::Cors);

    let request = match Request::new_with_str_and_init(url, &opts) {
        Ok(req) => req,
        Err(e) => {
            return WasmProbeResult {
                url: url.to_string(),
                success: false,
                status: None,
                error: Some(format!("failed to create request: {:?}", e)),
                total_ms: now() - start,
                dns_ms: None,
                tcp_ms: None,
                tls_ms: None,
                ttfb_ms: None,
                size_bytes: None,
                protocol: None,
            };
        }
    };

    let window = match web_sys::window() {
        Some(w) => w,
        None => {
            return WasmProbeResult {
                url: url.to_string(),
                success: false,
                status: None,
                error: Some("no window object available".to_string()),
                total_ms: now() - start,
                dns_ms: None,
                tcp_ms: None,
                tls_ms: None,
                ttfb_ms: None,
                size_bytes: None,
                protocol: None,
            };
        }
    };

    let resp_value = match JsFuture::from(window.fetch_with_request(&request)).await {
        Ok(v) => v,
        Err(e) => {
            return WasmProbeResult {
                url: url.to_string(),
                success: false,
                status: None,
                error: Some(format!("fetch failed: {:?}", e)),
                total_ms: now() - start,
                dns_ms: None,
                tcp_ms: None,
                tls_ms: None,
                ttfb_ms: None,
                size_bytes: None,
                protocol: None,
            };
        }
    };

    let response: Response = match resp_value.dyn_into() {
        Ok(r) => r,
        Err(_) => {
            return WasmProbeResult {
                url: url.to_string(),
                success: false,
                status: None,
                error: Some("fetch returned non-Response value".to_string()),
                total_ms: now() - start,
                dns_ms: None,
                tcp_ms: None,
                tls_ms: None,
                ttfb_ms: None,
                size_bytes: None,
                protocol: None,
            };
        }
    };

    let status = response.status();
    let total_ms = now() - start;

    // Try to get timing from Resource Timing API
    let timing = get_resource_timing(url);

    WasmProbeResult {
        url: url.to_string(),
        success: (200..400).contains(&status),
        status: Some(status),
        error: None,
        total_ms,
        dns_ms: timing.as_ref().and_then(|t| t.dns_ms),
        tcp_ms: timing.as_ref().and_then(|t| t.tcp_ms),
        tls_ms: timing.as_ref().and_then(|t| t.tls_ms),
        ttfb_ms: timing.as_ref().and_then(|t| t.ttfb_ms),
        size_bytes: timing.as_ref().and_then(|t| t.size_bytes),
        protocol: timing.and_then(|t| t.protocol),
    }
}

/// Resource timing data extracted from Performance API.
struct ResourceTimingData {
    dns_ms: Option<f64>,
    tcp_ms: Option<f64>,
    tls_ms: Option<f64>,
    ttfb_ms: Option<f64>,
    size_bytes: Option<u64>,
    protocol: Option<String>,
}

/// Get resource timing for a URL from the Performance API.
fn get_resource_timing(url: &str) -> Option<ResourceTimingData> {
    let window = web_sys::window()?;
    let performance = window.performance()?;
    let entries = performance.get_entries_by_name(url);

    if entries.length() == 0 {
        return None;
    }

    // Get the most recent entry
    let entry = entries.get(entries.length() - 1);
    let resource: web_sys::PerformanceResourceTiming = entry.dyn_into().ok()?;

    let dns_start = resource.domain_lookup_start();
    let dns_end = resource.domain_lookup_end();
    let connect_start = resource.connect_start();
    let connect_end = resource.connect_end();
    let secure_start = resource.secure_connection_start();
    let response_start = resource.response_start();

    let dns_ms = if dns_end > dns_start {
        Some(dns_end - dns_start)
    } else {
        None
    };

    let tcp_ms = if secure_start > 0.0 && secure_start > connect_start {
        Some(secure_start - connect_start)
    } else if connect_end > connect_start {
        Some(connect_end - connect_start)
    } else {
        None
    };

    let tls_ms = if secure_start > 0.0 && connect_end > secure_start {
        Some(connect_end - secure_start)
    } else {
        None
    };

    let ttfb_ms = if response_start > 0.0 {
        Some(response_start)
    } else {
        None
    };

    let size_bytes = {
        let size = resource.transfer_size();
        if size > 0.0 {
            Some(size as u64)
        } else {
            None
        }
    };

    let protocol = {
        let proto = resource.next_hop_protocol();
        if proto.is_empty() {
            None
        } else {
            Some(proto)
        }
    };

    Some(ResourceTimingData {
        dns_ms,
        tcp_ms,
        tls_ms,
        ttfb_ms,
        size_bytes,
        protocol,
    })
}

/// Get navigation timing data for the current page.
#[wasm_bindgen]
pub fn get_navigation_timing() -> JsValue {
    let timing = get_navigation_timing_internal();
    serde_wasm_bindgen::to_value(&timing).unwrap_or(JsValue::NULL)
}

/// Navigation timing data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmNavigationTiming {
    /// Page URL.
    pub url: String,
    /// DNS lookup time in milliseconds.
    pub dns_ms: f64,
    /// TCP connection time in milliseconds.
    pub tcp_ms: f64,
    /// TLS handshake time in milliseconds.
    pub tls_ms: f64,
    /// Time to First Byte in milliseconds.
    pub ttfb_ms: f64,
    /// DOM Content Loaded time in milliseconds.
    pub dom_content_loaded_ms: f64,
    /// Page load time in milliseconds.
    pub load_ms: f64,
}

fn get_navigation_timing_internal() -> Option<WasmNavigationTiming> {
    let window = web_sys::window()?;
    let performance = window.performance()?;
    let entries = performance.get_entries_by_type("navigation");

    if entries.length() == 0 {
        return None;
    }

    let entry = entries.get(0);
    let nav: web_sys::PerformanceNavigationTiming = entry.dyn_into().ok()?;

    let dns_start = nav.domain_lookup_start();
    let dns_end = nav.domain_lookup_end();
    let connect_start = nav.connect_start();
    let connect_end = nav.connect_end();
    let secure_start = nav.secure_connection_start();
    let response_start = nav.response_start();
    let dom_content_loaded = nav.dom_content_loaded_event_end();
    let load_end = nav.load_event_end();

    let dns_ms = (dns_end - dns_start).max(0.0);
    let tcp_ms = if secure_start > 0.0 {
        (secure_start - connect_start).max(0.0)
    } else {
        (connect_end - connect_start).max(0.0)
    };
    let tls_ms = if secure_start > 0.0 {
        (connect_end - secure_start).max(0.0)
    } else {
        0.0
    };
    let ttfb_ms = response_start.max(0.0);
    let dom_content_loaded_ms = dom_content_loaded.max(0.0);
    let load_ms = load_end.max(0.0);

    Some(WasmNavigationTiming {
        url: window.location().href().ok()?,
        dns_ms,
        tcp_ms,
        tls_ms,
        ttfb_ms,
        dom_content_loaded_ms,
        load_ms,
    })
}

/// Get all resource timing entries.
#[wasm_bindgen]
pub fn get_resource_timings() -> JsValue {
    let timings = get_resource_timings_internal();
    serde_wasm_bindgen::to_value(&timings).unwrap_or(JsValue::NULL)
}

/// Resource timing entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmResourceTiming {
    /// Resource URL.
    pub url: String,
    /// Initiator type.
    pub initiator_type: String,
    /// Duration in milliseconds.
    pub duration_ms: f64,
    /// Transfer size in bytes.
    pub size_bytes: u64,
    /// Whether it was cached.
    pub from_cache: bool,
    /// Protocol used.
    pub protocol: Option<String>,
}

fn get_resource_timings_internal() -> Vec<WasmResourceTiming> {
    let Some(window) = web_sys::window() else {
        return Vec::new();
    };
    let Some(performance) = window.performance() else {
        return Vec::new();
    };

    let entries = performance.get_entries_by_type("resource");
    let mut results = Vec::with_capacity(entries.length() as usize);

    for i in 0..entries.length() {
        let entry = entries.get(i);
        if let Ok(resource) = entry.dyn_into::<web_sys::PerformanceResourceTiming>() {
            let transfer_size = resource.transfer_size() as u64;
            let decoded_size = resource.decoded_body_size() as u64;

            results.push(WasmResourceTiming {
                url: resource.name(),
                initiator_type: resource.initiator_type(),
                duration_ms: resource.duration(),
                size_bytes: transfer_size,
                from_cache: transfer_size == 0 && decoded_size > 0,
                protocol: {
                    let p = resource.next_hop_protocol();
                    if p.is_empty() {
                        None
                    } else {
                        Some(p)
                    }
                },
            });
        }
    }

    results
}

// JavaScript bindings for Network Information API (not in web-sys)
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(thread_local_v2, js_namespace = navigator, js_name = connection)]
    static CONNECTION: JsValue;

    #[wasm_bindgen(catch, js_namespace = ["navigator", "connection"], js_name = type)]
    fn connection_type() -> Result<JsValue, JsValue>;

    #[wasm_bindgen(catch, js_namespace = ["navigator", "connection"], js_name = effectiveType)]
    fn effective_type() -> Result<JsValue, JsValue>;

    #[wasm_bindgen(catch, js_namespace = ["navigator", "connection"], js_name = rtt)]
    fn connection_rtt() -> Result<JsValue, JsValue>;

    #[wasm_bindgen(catch, js_namespace = ["navigator", "connection"], js_name = downlink)]
    fn connection_downlink() -> Result<JsValue, JsValue>;

    #[wasm_bindgen(catch, js_namespace = ["navigator", "connection"], js_name = saveData)]
    fn connection_save_data() -> Result<JsValue, JsValue>;
}

/// Get network connection information.
///
/// Uses the Network Information API when available (Chrome, Edge, Opera).
/// Returns empty values on unsupported browsers (Firefox, Safari).
#[wasm_bindgen]
pub fn get_connection_info() -> JsValue {
    let info = get_connection_info_internal();
    serde_wasm_bindgen::to_value(&info).unwrap_or(JsValue::NULL)
}

/// Network connection information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmConnectionInfo {
    /// Connection type (e.g., "wifi", "cellular", "ethernet").
    pub connection_type: Option<String>,
    /// Effective connection type (e.g., "4g", "3g", "2g", "slow-2g").
    pub effective_type: Option<String>,
    /// Estimated round-trip time in milliseconds.
    pub rtt_ms: Option<u32>,
    /// Estimated downlink speed in Mbps.
    pub downlink_mbps: Option<f64>,
    /// Whether data saver is enabled.
    pub save_data: bool,
    /// Whether the API is supported.
    pub api_supported: bool,
}

fn get_connection_info_internal() -> WasmConnectionInfo {
    // Check if Network Information API is available
    let conn = CONNECTION.with(JsValue::clone);
    if conn.is_undefined() || conn.is_null() {
        return WasmConnectionInfo {
            connection_type: None,
            effective_type: None,
            rtt_ms: None,
            downlink_mbps: None,
            save_data: false,
            api_supported: false,
        };
    }

    let connection_type = connection_type().ok().and_then(|v| v.as_string());

    let effective_type = effective_type().ok().and_then(|v| v.as_string());

    let rtt_ms = connection_rtt()
        .ok()
        .and_then(|v| v.as_f64())
        .map(|v| v as u32);

    let downlink_mbps = connection_downlink().ok().and_then(|v| v.as_f64());

    let save_data = connection_save_data()
        .ok()
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    WasmConnectionInfo {
        connection_type,
        effective_type,
        rtt_ms,
        downlink_mbps,
        save_data,
        api_supported: true,
    }
}

/// Get high-resolution timestamp.
fn now() -> f64 {
    web_sys::window()
        .and_then(|w| w.performance())
        .map(|p| p.now())
        .unwrap_or(0.0)
}

/// Console log helper for debugging.
#[wasm_bindgen]
pub fn log(s: &str) {
    web_sys::console::log_1(&s.into());
}
