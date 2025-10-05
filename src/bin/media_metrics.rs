use async_nats::Client as NatsClient;
use log::{error, info};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;

/// Media-specific event types for analytics
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MediaEvent {
    KeyRequest {
        session_id: String,
        user_id: String,
        asset_id: String,
        segment_index: Option<u32>,
        result: KeyRequestResult,
        latency_ms: u64,
        timestamp: i64,
    },
    SessionStart {
        session_id: String,
        user_id: String,
        asset_id: String,
        client_ip: String,
        geo_region: Option<String>,
        user_agent: Option<String>,
        timestamp: i64,
    },
    SessionEnd {
        session_id: String,
        user_id: String,
        asset_id: String,
        duration_seconds: i64,
        reason: SessionEndReason,
        timestamp: i64,
    },
    PolicyDenial {
        session_id: Option<String>,
        user_id: String,
        asset_id: String,
        denial_reason: String,
        timestamp: i64,
    },
    ConcurrencyLimit {
        user_id: String,
        current_streams: u32,
        max_streams: u32,
        timestamp: i64,
    },
    RentalWindow {
        user_id: String,
        asset_id: String,
        action: RentalAction,
        timestamp: i64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyRequestResult {
    Success,
    PolicyDenied,
    AuthenticationFailed,
    InvalidRequest,
    InternalError,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionEndReason {
    UserTerminated,
    Timeout,
    Error,
    PolicyViolation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RentalAction {
    FirstPlay,
    Expired,
    AccessGranted,
}

/// Performance metrics collector
#[derive(Debug, Clone)]
pub struct PerformanceMetrics {
    pub key_delivery_p50_ms: f64,
    pub key_delivery_p95_ms: f64,
    pub key_delivery_p99_ms: f64,
    pub total_key_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub policy_denials: u64,
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        Self {
            key_delivery_p50_ms: 0.0,
            key_delivery_p95_ms: 0.0,
            key_delivery_p99_ms: 0.0,
            total_key_requests: 0,
            successful_requests: 0,
            failed_requests: 0,
            policy_denials: 0,
        }
    }
}

/// Media metrics publisher
pub struct MediaMetrics {
    nats_client: Option<Arc<NatsClient>>,
    metrics_subject: String,
    enable_analytics: bool,
    // In-memory sliding window for latency tracking (last 1000 requests)
    latency_window: Arc<tokio::sync::Mutex<Vec<u64>>>,
    max_window_size: usize,
}

impl MediaMetrics {
    pub fn new(
        nats_client: Option<Arc<NatsClient>>,
        metrics_subject: String,
        enable_analytics: bool,
    ) -> Self {
        Self {
            nats_client,
            metrics_subject,
            enable_analytics,
            latency_window: Arc::new(tokio::sync::Mutex::new(Vec::with_capacity(1000))),
            max_window_size: 1000,
        }
    }

    /// Publish a media event to NATS for analytics
    pub async fn publish_event(&self, event: MediaEvent) {
        if !self.enable_analytics {
            return;
        }

        if let Some(ref client) = self.nats_client {
            match serde_json::to_vec(&event) {
                Ok(payload) => {
                    let subject = format!("{}.{}", self.metrics_subject, event.event_type());
                    if let Err(e) = client.publish(subject, payload.into()).await {
                        error!("Failed to publish media event: {}", e);
                    }
                }
                Err(e) => error!("Failed to serialize media event: {}", e),
            }
        }
    }

    /// Record key request latency
    pub async fn record_key_request_latency(&self, latency_ms: u64) {
        let mut window = self.latency_window.lock().await;
        window.push(latency_ms);

        // Keep only the last N requests
        if window.len() > self.max_window_size {
            window.remove(0);
        }
    }

    /// Get current performance metrics
    pub async fn get_metrics(&self) -> PerformanceMetrics {
        let window = self.latency_window.lock().await;
        if window.is_empty() {
            return PerformanceMetrics::default();
        }

        let mut sorted = window.clone();
        sorted.sort_unstable();

        let p50_idx = (sorted.len() as f64 * 0.50) as usize;
        let p95_idx = (sorted.len() as f64 * 0.95) as usize;
        let p99_idx = (sorted.len() as f64 * 0.99) as usize;

        PerformanceMetrics {
            key_delivery_p50_ms: sorted.get(p50_idx).copied().unwrap_or(0) as f64,
            key_delivery_p95_ms: sorted.get(p95_idx).copied().unwrap_or(0) as f64,
            key_delivery_p99_ms: sorted.get(p99_idx).copied().unwrap_or(0) as f64,
            total_key_requests: sorted.len() as u64,
            successful_requests: 0, // These would be tracked separately in production
            failed_requests: 0,
            policy_denials: 0,
        }
    }

    /// Log structured event to stdout
    pub fn log_event(&self, event: &MediaEvent) {
        match event {
            MediaEvent::KeyRequest {
                session_id,
                user_id,
                result,
                latency_ms,
                ..
            } => {
                info!(
                    "KEY_REQUEST session={} user={} result={:?} latency_ms={}",
                    session_id, user_id, result, latency_ms
                );
            }
            MediaEvent::SessionStart {
                session_id,
                user_id,
                asset_id,
                ..
            } => {
                info!(
                    "SESSION_START session={} user={} asset={}",
                    session_id, user_id, asset_id
                );
            }
            MediaEvent::SessionEnd {
                session_id,
                user_id,
                duration_seconds,
                reason,
                ..
            } => {
                info!(
                    "SESSION_END session={} user={} duration={}s reason={:?}",
                    session_id, user_id, duration_seconds, reason
                );
            }
            MediaEvent::PolicyDenial {
                user_id,
                asset_id,
                denial_reason,
                ..
            } => {
                info!(
                    "POLICY_DENIAL user={} asset={} reason={}",
                    user_id, asset_id, denial_reason
                );
            }
            MediaEvent::ConcurrencyLimit {
                user_id,
                current_streams,
                max_streams,
                ..
            } => {
                info!(
                    "CONCURRENCY_LIMIT user={} current={} max={}",
                    user_id, current_streams, max_streams
                );
            }
            MediaEvent::RentalWindow {
                user_id,
                asset_id,
                action,
                ..
            } => {
                info!(
                    "RENTAL_WINDOW user={} asset={} action={:?}",
                    user_id, asset_id, action
                );
            }
        }
    }
}

impl MediaEvent {
    fn event_type(&self) -> &str {
        match self {
            Self::KeyRequest { .. } => "key_request",
            Self::SessionStart { .. } => "session_start",
            Self::SessionEnd { .. } => "session_end",
            Self::PolicyDenial { .. } => "policy_denial",
            Self::ConcurrencyLimit { .. } => "concurrency_limit",
            Self::RentalWindow { .. } => "rental_window",
        }
    }
}

/// Timer for measuring request latency
pub struct RequestTimer {
    start: Instant,
}

impl RequestTimer {
    pub fn start() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    pub fn elapsed_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_latency_tracking() {
        let metrics = MediaMetrics::new(None, "test.metrics".to_string(), false);

        // Record some latencies
        metrics.record_key_request_latency(10).await;
        metrics.record_key_request_latency(20).await;
        metrics.record_key_request_latency(30).await;
        metrics.record_key_request_latency(100).await;

        let perf = metrics.get_metrics().await;
        assert_eq!(perf.total_key_requests, 4);
        assert!(perf.key_delivery_p50_ms > 0.0);
        assert!(perf.key_delivery_p95_ms >= perf.key_delivery_p50_ms);
    }

    #[test]
    fn test_request_timer() {
        let timer = RequestTimer::start();
        std::thread::sleep(Duration::from_millis(10));
        let elapsed = timer.elapsed_ms();
        assert!(elapsed >= 10);
    }

    #[test]
    fn test_event_serialization() {
        let event = MediaEvent::KeyRequest {
            session_id: "test-session".to_string(),
            user_id: "user-1".to_string(),
            asset_id: "asset-1".to_string(),
            segment_index: Some(42),
            result: KeyRequestResult::Success,
            latency_ms: 15,
            timestamp: Utc::now().timestamp(),
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("key_request"));
        assert!(json.contains("test-session"));
    }
}
