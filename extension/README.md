# Murmur Chrome Extension

Captures browser performance timing data and sends it to the local Murmur agent. The agent also runs network probes and emits metrics (including packet loss and jitter) to your OpenTelemetry collector. See the [main README](../README.md) for agent setup, configuration, and how to view packet loss and jitter locally.

## What it captures

**Navigation Timing (per page load):**
- DNS resolution time
- TCP connection time
- TLS handshake time
- Time to First Byte (TTFB)
- DOM Content Loaded
- Page load time

**Web Vitals:**
- Largest Contentful Paint (LCP)
- First Contentful Paint (FCP)
- Cumulative Layout Shift (CLS)
- First Input Delay (FID)

**Resource Timing (per resource):**
- Individual timing breakdown for each resource
- Transfer sizes
- Cache hit detection
- Protocol used (h2, http/1.1, etc.)

## Installation

1. Start the Murmur agent:
   ```bash
   murmur-agent
   ```

2. Load the extension in Chrome:
   - Navigate to `chrome://extensions`
   - Enable "Developer mode"
   - Click "Load unpacked"
   - Select the `extension` folder

3. The extension icon shows connection status:
   - Green: Connected to agent
   - Red: Agent not running

## How it works

1. Content script runs on every page
2. After page load, captures Navigation Timing API data
3. Captures all Resource Timing entries
4. Sends data to agent at `http://127.0.0.1:9876`
5. Agent forwards metrics to configured OTEL collector

## Privacy

- All data is sent only to `127.0.0.1` (localhost)
- No data leaves your machine unless you configure the agent to export
- Toggle capture on/off in the popup
