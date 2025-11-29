//! RTMP TCP Listener and Connection Handling
//!
//! Provides the main entry point for the RTMP server, accepting
//! connections and spawning session handlers.

use std::sync::Arc;
use tokio::net::TcpListener;

use super::session::RtmpSession;
use super::DEFAULT_RTMP_PORT;

/// RTMP server configuration and state
pub struct RtmpServer {
    /// Port to listen on
    pub port: u16,
    /// Redis client for manifest caching
    pub redis_client: Arc<redis::Client>,
    /// KAS EC private key (32 bytes)
    pub kas_private_key: [u8; 32],
}

/// RTMP server error
#[derive(Debug)]
pub enum ServerError {
    BindError(std::io::Error),
    AcceptError(std::io::Error),
}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerError::BindError(e) => write!(f, "Failed to bind RTMP port: {}", e),
            ServerError::AcceptError(e) => write!(f, "Failed to accept connection: {}", e),
        }
    }
}

impl std::error::Error for ServerError {}

impl RtmpServer {
    /// Create a new RTMP server with default configuration
    pub fn new(redis_client: Arc<redis::Client>, kas_private_key: [u8; 32]) -> Self {
        RtmpServer {
            port: DEFAULT_RTMP_PORT,
            redis_client,
            kas_private_key,
        }
    }

    /// Create a new RTMP server with custom port
    pub fn with_port(
        port: u16,
        redis_client: Arc<redis::Client>,
        kas_private_key: [u8; 32],
    ) -> Self {
        RtmpServer {
            port,
            redis_client,
            kas_private_key,
        }
    }

    /// Run the RTMP server
    ///
    /// This method runs indefinitely, accepting connections and spawning
    /// session handlers for each.
    pub async fn run(self) -> Result<(), ServerError> {
        let addr = format!("0.0.0.0:{}", self.port);
        let listener = TcpListener::bind(&addr)
            .await
            .map_err(ServerError::BindError)?;

        log::info!("NTDF-RTMP server listening on {}", addr);
        log::info!("Protocol: NTDF-RTMP (NanoTDF over RTMP)");
        log::info!("Features: End-to-end encryption, manifest caching for late joiners");

        // Wrap shared state in Arc for cloning to spawned tasks
        let redis_client = self.redis_client;
        let kas_private_key = self.kas_private_key;

        loop {
            match listener.accept().await {
                Ok((socket, addr)) => {
                    log::debug!("Accepted RTMP connection from {}", addr);

                    // Clone shared state for this connection
                    let redis = redis_client.clone();
                    let kas_key = kas_private_key;

                    // Spawn session handler
                    tokio::spawn(async move {
                        let session = RtmpSession::new(redis, kas_key);

                        if let Err(e) = session.handle_connection(socket).await {
                            log::error!("RTMP session error from {}: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    log::error!("Failed to accept RTMP connection: {}", e);
                    // Continue accepting other connections
                }
            }
        }
    }

    /// Run the RTMP server with graceful shutdown support
    pub async fn run_with_shutdown(
        self,
        mut shutdown: tokio::sync::broadcast::Receiver<()>,
    ) -> Result<(), ServerError> {
        let addr = format!("0.0.0.0:{}", self.port);
        let listener = TcpListener::bind(&addr)
            .await
            .map_err(ServerError::BindError)?;

        log::info!(
            "NTDF-RTMP server listening on {} (with graceful shutdown)",
            addr
        );

        let redis_client = self.redis_client;
        let kas_private_key = self.kas_private_key;

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((socket, addr)) => {
                            log::debug!("Accepted RTMP connection from {}", addr);

                            let redis = redis_client.clone();
                            let kas_key = kas_private_key;

                            tokio::spawn(async move {
                                let session = RtmpSession::new(redis, kas_key);
                                if let Err(e) = session.handle_connection(socket).await {
                                    log::error!("RTMP session error from {}: {}", addr, e);
                                }
                            });
                        }
                        Err(e) => {
                            log::error!("Failed to accept RTMP connection: {}", e);
                        }
                    }
                }
                _ = shutdown.recv() => {
                    log::info!("RTMP server shutting down");
                    break;
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_default_port() {
        let kas_key = [0u8; 32];
        // We can't actually create a redis client in unit tests
        // but we can test the port logic
        assert_eq!(DEFAULT_RTMP_PORT, 1935);
    }

    #[test]
    fn test_server_error_display() {
        let bind_err = ServerError::BindError(std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            "port in use",
        ));
        assert!(bind_err.to_string().contains("Failed to bind"));

        let accept_err = ServerError::AcceptError(std::io::Error::new(
            std::io::ErrorKind::Other,
            "accept failed",
        ));
        assert!(accept_err.to_string().contains("Failed to accept"));
    }
}
