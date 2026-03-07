// Murmur Extension - Background Service Worker
// Receives timing data from content scripts and forwards to local agent
// Includes offline handling with queue buffering and retry logic

const AGENT_URL = 'http://127.0.0.1:9876';
const MAX_QUEUE_SIZE = 100;
const RETRY_INTERVAL_MS = 5000;
const MAX_RETRIES = 3;

// Extension state
let enabled = true;
let connected = false;
let queue = [];
let retryTimer = null;
let stats = {
  sent: 0,
  queued: 0,
  dropped: 0,
  errors: 0
};

// Initialize on startup
init();

async function init() {
  // Load persisted state
  const stored = await chrome.storage.local.get(['enabled', 'queue', 'stats']);
  if (stored.enabled !== undefined) enabled = stored.enabled;
  if (stored.queue) queue = stored.queue;
  if (stored.stats) stats = { ...stats, ...stored.stats };

  // Check connection immediately
  await checkConnection();

  // Set up periodic connection check
  setInterval(checkConnection, 30000);

  // Process any queued items
  if (queue.length > 0 && connected) {
    processQueue();
  }
}

async function checkConnection() {
  const wasConnected = connected;

  try {
    const response = await fetch(`${AGENT_URL}/health`, {
      method: 'GET',
      signal: AbortSignal.timeout(3000)
    });
    connected = response.ok;
  } catch (e) {
    connected = false;
  }

  // Update icon
  updateIcon();

  // Connection state changed
  if (connected && !wasConnected) {
    console.log('[Murmur] Agent connected');
    processQueue();
  } else if (!connected && wasConnected) {
    console.log('[Murmur] Agent disconnected, queueing enabled');
  }
}

function updateIcon() {
  const iconSet = connected ? {
    '16': 'icons/icon16.png',
    '48': 'icons/icon48.png',
    '128': 'icons/icon128.png'
  } : {
    '16': 'icons/icon16-disconnected.png',
    '48': 'icons/icon48-disconnected.png',
    '128': 'icons/icon128-disconnected.png'
  };

  chrome.action.setIcon({ path: iconSet }).catch(() => {});

  // Update badge with queue count when offline
  if (!connected && queue.length > 0) {
    chrome.action.setBadgeText({ text: String(queue.length) });
    chrome.action.setBadgeBackgroundColor({ color: '#6c757d' });
  } else {
    chrome.action.setBadgeText({ text: '' });
  }
}

// Message handler
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message).then(sendResponse);
  return true; // Keep channel open for async response
});

async function handleMessage(message) {
  switch (message.type) {
    case 'navigation_timing':
      return handleTimingData('timing', message.data);

    case 'resource_timing':
      return handleTimingData('resources', message.data);

    case 'get_status':
      return {
        enabled,
        connected,
        queueLength: queue.length,
        stats
      };

    case 'set_enabled':
      enabled = message.enabled;
      await chrome.storage.local.set({ enabled });
      return { enabled };

    case 'flush_queue':
      if (connected) {
        await processQueue();
        return { status: 'flushed', remaining: queue.length };
      }
      return { status: 'offline', queued: queue.length };

    case 'clear_queue':
      const cleared = queue.length;
      queue = [];
      await persistQueue();
      return { status: 'cleared', count: cleared };

    default:
      return { status: 'unknown_message_type' };
  }
}

async function handleTimingData(type, data) {
  if (!enabled) {
    return { status: 'disabled' };
  }

  const item = { type, data, timestamp: Date.now(), retries: 0 };

  if (connected) {
    try {
      await sendToAgent(item);
      stats.sent++;
      return { status: 'sent' };
    } catch (e) {
      // Failed to send, queue it
      enqueue(item);
      return { status: 'queued', error: e.message };
    }
  } else {
    enqueue(item);
    return { status: 'queued', queueLength: queue.length };
  }
}

function enqueue(item) {
  // Drop oldest items if queue is full
  while (queue.length >= MAX_QUEUE_SIZE) {
    queue.shift();
    stats.dropped++;
  }

  queue.push(item);
  stats.queued++;
  persistQueue();
  updateIcon();

  // Schedule retry if not already scheduled
  if (!retryTimer) {
    retryTimer = setTimeout(() => {
      retryTimer = null;
      if (connected) processQueue();
      else checkConnection();
    }, RETRY_INTERVAL_MS);
  }
}

async function processQueue() {
  if (queue.length === 0 || !connected) return;

  console.log(`[Murmur] Processing ${queue.length} queued items`);

  const toProcess = [...queue];
  queue = [];

  for (const item of toProcess) {
    try {
      await sendToAgent(item);
      stats.sent++;
    } catch (e) {
      item.retries++;
      if (item.retries < MAX_RETRIES) {
        queue.push(item);
      } else {
        stats.dropped++;
        console.warn(`[Murmur] Dropped item after ${MAX_RETRIES} retries`);
      }
    }
  }

  await persistQueue();
  updateIcon();
}

async function sendToAgent(item) {
  const endpoint = item.type === 'timing'
    ? `${AGENT_URL}/api/v1/timing`
    : `${AGENT_URL}/api/v1/resources`;

  const response = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(item.data),
    signal: AbortSignal.timeout(5000)
  });

  if (!response.ok) {
    stats.errors++;
    throw new Error(`HTTP ${response.status}`);
  }
}

async function persistQueue() {
  try {
    await chrome.storage.local.set({ queue, stats });
  } catch (e) {
    console.error('[Murmur] Failed to persist queue:', e);
  }
}

// Clean up on extension suspend (service worker going idle)
self.addEventListener('beforeunload', () => {
  persistQueue();
});
