// Murmur Extension - Popup Script

document.addEventListener('DOMContentLoaded', () => {
  const statusDot = document.getElementById('statusDot');
  const statusText = document.getElementById('statusText');
  const enableToggle = document.getElementById('enableToggle');
  const sentCount = document.getElementById('sentCount');
  const queueCount = document.getElementById('queueCount');
  const queueStat = document.getElementById('queueStat');
  const flushBtn = document.getElementById('flushBtn');
  const clearBtn = document.getElementById('clearBtn');

  // Get current status
  refreshStatus();

  // Refresh every 2 seconds while popup is open
  const refreshInterval = setInterval(refreshStatus, 2000);

  function refreshStatus() {
    chrome.runtime.sendMessage({ type: 'get_status' }, (response) => {
      if (chrome.runtime.lastError) {
        console.error(chrome.runtime.lastError);
        return;
      }
      if (response) {
        updateUI(response);
      }
    });
  }

  // Handle toggle change
  enableToggle.addEventListener('change', () => {
    chrome.runtime.sendMessage({
      type: 'set_enabled',
      enabled: enableToggle.checked
    });
  });

  // Handle flush button
  flushBtn.addEventListener('click', async () => {
    flushBtn.disabled = true;
    flushBtn.textContent = 'Sending...';
    
    chrome.runtime.sendMessage({ type: 'flush_queue' }, (response) => {
      flushBtn.textContent = 'Send Queue';
      refreshStatus();
    });
  });

  // Handle clear button
  clearBtn.addEventListener('click', () => {
    if (confirm('Clear all queued timing data?')) {
      chrome.runtime.sendMessage({ type: 'clear_queue' }, () => {
        refreshStatus();
      });
    }
  });

  function updateUI(status) {
    enableToggle.checked = status.enabled;

    // Connection status
    if (status.connected) {
      statusDot.classList.add('connected');
      statusText.textContent = 'Connected to agent';
    } else {
      statusDot.classList.remove('connected');
      statusText.textContent = 'Agent not running';
    }

    // Stats
    sentCount.textContent = formatNumber(status.stats?.sent || 0);
    queueCount.textContent = formatNumber(status.queueLength || 0);

    // Highlight queue if items are waiting
    if (status.queueLength > 0) {
      queueStat.classList.add('warning');
    } else {
      queueStat.classList.remove('warning');
    }

    // Button states
    flushBtn.disabled = !status.connected || status.queueLength === 0;
    clearBtn.disabled = status.queueLength === 0;
  }

  function formatNumber(n) {
    if (n >= 1000) {
      return (n / 1000).toFixed(1) + 'k';
    }
    return String(n);
  }

  // Cleanup interval when popup closes
  window.addEventListener('unload', () => {
    clearInterval(refreshInterval);
  });
});
