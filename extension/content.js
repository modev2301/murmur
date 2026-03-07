// Murmur Extension - Content Script
// Captures Navigation Timing and Resource Timing from the page

(function() {
  'use strict';

  // Only run in top frame
  if (window.self !== window.top) {
    return;
  }

  // Wait for page load to capture complete timing data
  window.addEventListener('load', () => {
    // Small delay to ensure all metrics are available
    setTimeout(captureAndSendTiming, 1000);
  });

  // Observe LCP for Web Vitals
  let lcpValue = null;
  let fcpValue = null;
  let clsValue = 0;
  let fidValue = null;

  // Observe Largest Contentful Paint
  if (typeof PerformanceObserver !== 'undefined') {
    try {
      const lcpObserver = new PerformanceObserver((entryList) => {
        const entries = entryList.getEntries();
        if (entries.length > 0) {
          lcpValue = entries[entries.length - 1].startTime;
        }
      });
      lcpObserver.observe({ type: 'largest-contentful-paint', buffered: true });
    } catch (e) {
      // LCP not supported
    }

    // Observe First Contentful Paint
    try {
      const fcpObserver = new PerformanceObserver((entryList) => {
        const entries = entryList.getEntries();
        for (const entry of entries) {
          if (entry.name === 'first-contentful-paint') {
            fcpValue = entry.startTime;
          }
        }
      });
      fcpObserver.observe({ type: 'paint', buffered: true });
    } catch (e) {
      // FCP not supported
    }

    // Observe Cumulative Layout Shift
    try {
      const clsObserver = new PerformanceObserver((entryList) => {
        for (const entry of entryList.getEntries()) {
          if (!entry.hadRecentInput) {
            clsValue += entry.value;
          }
        }
      });
      clsObserver.observe({ type: 'layout-shift', buffered: true });
    } catch (e) {
      // CLS not supported
    }

    // Observe First Input Delay
    try {
      const fidObserver = new PerformanceObserver((entryList) => {
        const entries = entryList.getEntries();
        if (entries.length > 0) {
          fidValue = entries[0].processingStart - entries[0].startTime;
        }
      });
      fidObserver.observe({ type: 'first-input', buffered: true });
    } catch (e) {
      // FID not supported
    }
  }

  function captureAndSendTiming() {
    const timing = captureNavigationTiming();
    if (timing) {
      chrome.runtime.sendMessage({
        type: 'navigation_timing',
        data: timing
      }).catch(() => {});
    }

    const resources = captureResourceTiming();
    if (resources && resources.resources.length > 0) {
      chrome.runtime.sendMessage({
        type: 'resource_timing',
        data: resources
      }).catch(() => {});
    }
  }

  function captureNavigationTiming() {
    const perf = performance;
    const timing = perf.timing || {};
    const navEntry = perf.getEntriesByType('navigation')[0];

    if (!navEntry && !timing.navigationStart) {
      return null;
    }

    // Use Navigation Timing Level 2 if available, fall back to Level 1
    const t = navEntry || timing;
    const start = navEntry ? 0 : timing.navigationStart;

    // Calculate timing phases
    const dnsStart = navEntry ? t.domainLookupStart : (t.domainLookupStart - start);
    const dnsEnd = navEntry ? t.domainLookupEnd : (t.domainLookupEnd - start);
    const connectStart = navEntry ? t.connectStart : (t.connectStart - start);
    const connectEnd = navEntry ? t.connectEnd : (t.connectEnd - start);
    const secureStart = navEntry ? t.secureConnectionStart : (t.secureConnectionStart - start);
    const responseStart = navEntry ? t.responseStart : (t.responseStart - start);
    const domContentLoaded = navEntry ? t.domContentLoadedEventEnd : (t.domContentLoadedEventEnd - start);
    const loadEnd = navEntry ? t.loadEventEnd : (t.loadEventEnd - start);

    const data = {
      url: window.location.href,
      dns_ms: Math.max(0, dnsEnd - dnsStart),
      tcp_ms: Math.max(0, (secureStart > 0 ? secureStart : connectEnd) - connectStart),
      tls_ms: secureStart > 0 ? Math.max(0, connectEnd - secureStart) : 0,
      ttfb_ms: Math.max(0, responseStart),
      dom_content_loaded_ms: Math.max(0, domContentLoaded),
      load_ms: Math.max(0, loadEnd),
      lcp_ms: lcpValue,
      fcp_ms: fcpValue,
      cls: clsValue > 0 ? clsValue : null,
      fid_ms: fidValue,
      timestamp: Date.now(),
      user_agent: navigator.userAgent,
      connection_type: null,
      effective_type: null,
      rtt_ms: null,
      downlink_mbps: null
    };

    // Add Network Information API data if available
    const connection = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
    if (connection) {
      data.connection_type = connection.type || null;
      data.effective_type = connection.effectiveType || null;
      data.rtt_ms = connection.rtt || null;
      data.downlink_mbps = connection.downlink || null;
    }

    return data;
  }

  function captureResourceTiming() {
    const entries = performance.getEntriesByType('resource');
    if (!entries || entries.length === 0) {
      return null;
    }

    const resources = entries.map(entry => {
      const dnsTime = entry.domainLookupEnd - entry.domainLookupStart;
      const connectTime = entry.secureConnectionStart > 0
        ? entry.secureConnectionStart - entry.connectStart
        : entry.connectEnd - entry.connectStart;
      const tlsTime = entry.secureConnectionStart > 0
        ? entry.connectEnd - entry.secureConnectionStart
        : 0;
      const ttfb = entry.responseStart - entry.requestStart;

      return {
        url: entry.name,
        initiator_type: entry.initiatorType || 'other',
        transfer_size: entry.transferSize || 0,
        encoded_body_size: entry.encodedBodySize || 0,
        decoded_body_size: entry.decodedBodySize || 0,
        dns_ms: Math.max(0, dnsTime),
        tcp_ms: Math.max(0, connectTime),
        tls_ms: Math.max(0, tlsTime),
        ttfb_ms: Math.max(0, ttfb),
        duration_ms: Math.max(0, entry.duration),
        start_time_ms: entry.startTime,
        from_cache: entry.transferSize === 0 && entry.decodedBodySize > 0,
        protocol: entry.nextHopProtocol || null
      };
    });

    return {
      page_url: window.location.href,
      timestamp: Date.now(),
      resources: resources
    };
  }
})();
