//! Connection pooling with TLS session resumption tracking.
//!
//! This module provides connection reuse and tracks whether TLS sessions
//! were resumed (using session tickets). This is valuable for understanding
//! real-world performance where clients typically maintain connection pools.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio_rustls::client::TlsStream;
use tracing::{debug, info};

/// Key for pooled connections.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct ConnectionKey {
    /// Host name (for SNI/TLS session key).
    pub host: String,
    /// Port number.
    pub port: u16,
}

impl ConnectionKey {
    /// Create a new connection key.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }
}

/// A pooled TLS connection.
pub struct PooledConnection {
    /// The underlying TLS stream.
    pub stream: TlsStream<TcpStream>,
    /// When this connection was established.
    pub created_at: Instant,
    /// When this connection was last used.
    pub last_used: Instant,
    /// Whether TLS session resumption was used.
    pub session_resumed: bool,
    /// Remote address.
    pub remote_addr: SocketAddr,
}

/// Configuration for the connection pool.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Maximum connections per host.
    pub max_connections_per_host: usize,
    /// Maximum idle time before a connection is closed.
    pub max_idle_time: Duration,
    /// Maximum total age of a connection.
    pub max_age: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_connections_per_host: 4,
            max_idle_time: Duration::from_secs(60),
            max_age: Duration::from_secs(300),
        }
    }
}

/// Pool statistics for a single host.
#[derive(Debug, Clone, Default)]
pub struct HostPoolStats {
    /// Number of connections currently in the pool.
    pub active_connections: usize,
    /// Total connections opened.
    pub total_connections: u64,
    /// Connections reused from pool.
    pub connections_reused: u64,
    /// TLS sessions resumed.
    pub sessions_resumed: u64,
    /// Connections that timed out.
    pub connections_timed_out: u64,
}

/// Connection pool with TLS session resumption tracking.
///
/// The pool maintains idle connections organized by host and tracks whether
/// TLS session resumption was used when reconnecting. This gives visibility
/// into real-world performance characteristics.
pub struct ConnectionPool {
    /// Pool configuration.
    config: PoolConfig,
    /// Pooled connections by host key.
    pools: RwLock<HashMap<ConnectionKey, Vec<PooledConnection>>>,
    /// Statistics per host.
    stats: RwLock<HashMap<ConnectionKey, HostPoolStats>>,
    /// TLS client config with session store.
    tls_config: Arc<rustls::ClientConfig>,
}

impl ConnectionPool {
    /// Create a new connection pool.
    ///
    /// # Panics
    ///
    /// Panics if the TLS provider cannot be initialized. This indicates a
    /// build configuration error, not a runtime condition.
    pub fn new(config: PoolConfig) -> Self {
        let root_store =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let provider = rustls::crypto::aws_lc_rs::default_provider();

        // Build config with session resumption enabled (default)
        #[allow(clippy::expect_used)]
        let tls_config = rustls::ClientConfig::builder_with_provider(provider.into())
            .with_safe_default_protocol_versions()
            .expect("aws-lc-rs provider must support safe TLS versions")
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Self {
            config,
            pools: RwLock::new(HashMap::new()),
            stats: RwLock::new(HashMap::new()),
            tls_config: Arc::new(tls_config),
        }
    }

    /// Create a pool with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(PoolConfig::default())
    }

    /// Get the TLS configuration for new connections.
    pub fn tls_config(&self) -> Arc<rustls::ClientConfig> {
        self.tls_config.clone()
    }

    /// Try to get an idle connection from the pool.
    pub async fn get(&self, key: &ConnectionKey) -> Option<PooledConnection> {
        let mut pools = self.pools.write().await;
        let connections = pools.get_mut(key)?;

        // Find a valid connection (not too old, not too idle)
        let now = Instant::now();
        let mut valid_idx = None;

        for (i, conn) in connections.iter().enumerate().rev() {
            let idle_time = now.duration_since(conn.last_used);
            let age = now.duration_since(conn.created_at);

            if idle_time < self.config.max_idle_time && age < self.config.max_age {
                valid_idx = Some(i);
                break;
            }
        }

        if let Some(idx) = valid_idx {
            let conn = connections.remove(idx);
            debug!(
                host = %key.host,
                port = key.port,
                session_resumed = conn.session_resumed,
                "reusing pooled connection"
            );

            // Update stats
            let mut stats = self.stats.write().await;
            let host_stats = stats.entry(key.clone()).or_default();
            host_stats.connections_reused += 1;
            if conn.session_resumed {
                host_stats.sessions_resumed += 1;
            }

            Some(conn)
        } else {
            None
        }
    }

    /// Return a connection to the pool.
    pub async fn put(&self, key: ConnectionKey, mut conn: PooledConnection) {
        conn.last_used = Instant::now();

        let mut pools = self.pools.write().await;
        let connections = pools.entry(key.clone()).or_default();

        // Don't exceed max connections per host
        if connections.len() < self.config.max_connections_per_host {
            connections.push(conn);
            debug!(
                host = %key.host,
                port = key.port,
                pool_size = connections.len(),
                "returned connection to pool"
            );
        } else {
            debug!(
                host = %key.host,
                port = key.port,
                "pool full, connection dropped"
            );
        }
    }

    /// Record a new connection (for stats tracking).
    pub async fn record_new_connection(&self, key: &ConnectionKey, session_resumed: bool) {
        let mut stats = self.stats.write().await;
        let host_stats = stats.entry(key.clone()).or_default();
        host_stats.total_connections += 1;
        if session_resumed {
            host_stats.sessions_resumed += 1;
        }
    }

    /// Get statistics for a host.
    pub async fn stats(&self, key: &ConnectionKey) -> HostPoolStats {
        let stats = self.stats.read().await;
        stats.get(key).cloned().unwrap_or_default()
    }

    /// Get statistics for all hosts.
    pub async fn all_stats(&self) -> HashMap<ConnectionKey, HostPoolStats> {
        let stats = self.stats.read().await;
        stats.clone()
    }

    /// Clean up expired connections.
    pub async fn cleanup(&self) {
        let now = Instant::now();
        let mut pools = self.pools.write().await;
        let mut stats = self.stats.write().await;

        for (key, connections) in pools.iter_mut() {
            let before = connections.len();
            connections.retain(|conn| {
                let idle_time = now.duration_since(conn.last_used);
                let age = now.duration_since(conn.created_at);
                idle_time < self.config.max_idle_time && age < self.config.max_age
            });
            let removed = before - connections.len();

            if removed > 0 {
                let host_stats = stats.entry(key.clone()).or_default();
                host_stats.connections_timed_out += removed as u64;
                host_stats.active_connections = connections.len();

                info!(
                    host = %key.host,
                    removed = removed,
                    remaining = connections.len(),
                    "cleaned up expired connections"
                );
            }
        }

        // Remove empty pools
        pools.retain(|_, conns| !conns.is_empty());
    }

    /// Get the current pool size for a host.
    pub async fn pool_size(&self, key: &ConnectionKey) -> usize {
        let pools = self.pools.read().await;
        pools.get(key).map(|c| c.len()).unwrap_or(0)
    }

    /// Get total number of pooled connections across all hosts.
    pub async fn total_pooled(&self) -> usize {
        let pools = self.pools.read().await;
        pools.values().map(|c| c.len()).sum()
    }
}

/// Determine if TLS session was resumed by checking handshake timing.
///
/// Session resumption typically completes much faster than a full handshake
/// because it skips certificate validation and key exchange.
///
/// Note: This is a heuristic. The actual way to check is through the TLS
/// connection state, but rustls doesn't expose this directly on the client side.
pub fn likely_session_resumed(handshake_duration: Duration) -> bool {
    // Full handshakes typically take 20-100ms+ depending on RTT
    // Session resumption (PSK) typically takes 5-20ms
    // This threshold may need tuning based on real-world data
    handshake_duration < Duration::from_millis(15)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_key_equality() {
        let k1 = ConnectionKey::new("example.com", 443);
        let k2 = ConnectionKey::new("example.com", 443);
        let k3 = ConnectionKey::new("example.com", 80);

        assert_eq!(k1, k2);
        assert_ne!(k1, k3);
    }

    #[test]
    fn session_resumption_heuristic() {
        assert!(likely_session_resumed(Duration::from_millis(5)));
        assert!(likely_session_resumed(Duration::from_millis(10)));
        assert!(!likely_session_resumed(Duration::from_millis(50)));
        assert!(!likely_session_resumed(Duration::from_millis(100)));
    }

    #[tokio::test]
    async fn pool_stats_tracking() {
        let pool = ConnectionPool::with_defaults();
        let key = ConnectionKey::new("example.com", 443);

        // Initial stats should be empty
        let stats = pool.stats(&key).await;
        assert_eq!(stats.total_connections, 0);

        // Record a connection
        pool.record_new_connection(&key, false).await;
        let stats = pool.stats(&key).await;
        assert_eq!(stats.total_connections, 1);
        assert_eq!(stats.sessions_resumed, 0);

        // Record a resumed connection
        pool.record_new_connection(&key, true).await;
        let stats = pool.stats(&key).await;
        assert_eq!(stats.total_connections, 2);
        assert_eq!(stats.sessions_resumed, 1);
    }
}
