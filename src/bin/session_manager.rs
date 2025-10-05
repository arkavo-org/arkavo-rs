use chrono::Utc;
use log::info;
use redis::{AsyncCommands, Client as RedisClient};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Maximum allowed concurrent streams per user (global default)
const DEFAULT_MAX_CONCURRENT_STREAMS: u32 = 5;

/// Session heartbeat timeout (seconds) - sessions expire if no heartbeat
const SESSION_HEARTBEAT_TIMEOUT: i64 = 300; // 5 minutes

/// Session state
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SessionState {
    Starting,
    Playing,
    Paused,
    Stopped,
}

/// Playback session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybackSession {
    pub session_id: String,
    pub user_id: String,
    pub asset_id: String,
    pub segment_index: Option<u32>,
    pub state: SessionState,
    pub start_timestamp: i64,          // Unix timestamp
    pub first_play_timestamp: Option<i64>,
    pub last_heartbeat_timestamp: i64,
    pub client_ip: String,
    pub geo_region: Option<String>,    // ISO 3166-1 alpha-2
    pub user_agent: Option<String>,
}

impl PlaybackSession {
    pub fn new(
        session_id: String,
        user_id: String,
        asset_id: String,
        client_ip: String,
    ) -> Self {
        let now = Utc::now().timestamp();
        Self {
            session_id,
            user_id,
            asset_id,
            segment_index: None,
            state: SessionState::Starting,
            start_timestamp: now,
            first_play_timestamp: None,
            last_heartbeat_timestamp: now,
            client_ip,
            geo_region: None,
            user_agent: None,
        }
    }

    pub fn is_expired(&self, current_timestamp: i64) -> bool {
        (current_timestamp - self.last_heartbeat_timestamp) > SESSION_HEARTBEAT_TIMEOUT
    }
}

/// Session manager for tracking active playback sessions
pub struct SessionManager {
    redis_client: Arc<RedisClient>,
    max_concurrent_streams: u32,
}

impl SessionManager {
    pub fn new(redis_client: Arc<RedisClient>, max_concurrent_streams: Option<u32>) -> Self {
        Self {
            redis_client,
            max_concurrent_streams: max_concurrent_streams
                .unwrap_or(DEFAULT_MAX_CONCURRENT_STREAMS),
        }
    }

    /// Create a new playback session
    pub async fn create_session(
        &self,
        session: PlaybackSession,
    ) -> Result<(), SessionManagerError> {
        // Check concurrency limit
        let active_count = self.get_active_session_count(&session.user_id).await?;
        if active_count >= self.max_concurrent_streams {
            return Err(SessionManagerError::ConcurrencyLimitExceeded {
                current: active_count,
                max: self.max_concurrent_streams,
            });
        }

        // Store session in Redis with TTL
        let mut conn = self.redis_client.get_multiplexed_async_connection().await?;
        let session_key = self.session_key(&session.session_id);
        let user_sessions_key = self.user_sessions_key(&session.user_id);

        let session_json = serde_json::to_string(&session)?;

        // Store session data with TTL
        let _: () = conn
            .set_ex(&session_key, session_json, SESSION_HEARTBEAT_TIMEOUT as u64)
            .await?;

        // Add to user's active sessions set
        let _: () = conn.sadd(&user_sessions_key, &session.session_id).await?;
        let _: () = conn
            .expire(&user_sessions_key, SESSION_HEARTBEAT_TIMEOUT)
            .await?;

        info!(
            "Created session {} for user {} on asset {}",
            session.session_id, session.user_id, session.asset_id
        );

        Ok(())
    }

    /// Update session with heartbeat
    pub async fn heartbeat(
        &self,
        session_id: &str,
        state: Option<SessionState>,
        segment_index: Option<u32>,
    ) -> Result<PlaybackSession, SessionManagerError> {
        let mut conn = self.redis_client.get_multiplexed_async_connection().await?;
        let session_key = self.session_key(session_id);

        // Get current session
        let session_json: Option<String> = conn.get(&session_key).await?;
        let mut session: PlaybackSession = match session_json {
            Some(json) => serde_json::from_str(&json)?,
            None => return Err(SessionManagerError::SessionNotFound),
        };

        // Update session
        let now = Utc::now().timestamp();
        session.last_heartbeat_timestamp = now;

        if let Some(new_state) = state {
            // Track first play timestamp
            if new_state == SessionState::Playing && session.first_play_timestamp.is_none() {
                session.first_play_timestamp = Some(now);
            }
            session.state = new_state;
        }

        if let Some(idx) = segment_index {
            session.segment_index = Some(idx);
        }

        // Update in Redis
        let session_json = serde_json::to_string(&session)?;
        let _: () = conn
            .set_ex(&session_key, session_json, SESSION_HEARTBEAT_TIMEOUT as u64)
            .await?;

        // Refresh user sessions set TTL
        let user_sessions_key = self.user_sessions_key(&session.user_id);
        let _: () = conn
            .expire(&user_sessions_key, SESSION_HEARTBEAT_TIMEOUT)
            .await?;

        Ok(session)
    }

    /// Get session information
    pub async fn get_session(
        &self,
        session_id: &str,
    ) -> Result<Option<PlaybackSession>, SessionManagerError> {
        let mut conn = self.redis_client.get_multiplexed_async_connection().await?;
        let session_key = self.session_key(session_id);

        let session_json: Option<String> = conn.get(&session_key).await?;
        match session_json {
            Some(json) => {
                let session: PlaybackSession = serde_json::from_str(&json)?;
                Ok(Some(session))
            }
            None => Ok(None),
        }
    }

    /// Terminate a session
    pub async fn terminate_session(&self, session_id: &str) -> Result<(), SessionManagerError> {
        let mut conn = self.redis_client.get_multiplexed_async_connection().await?;

        // Get session to find user_id
        if let Some(session) = self.get_session(session_id).await? {
            let session_key = self.session_key(session_id);
            let user_sessions_key = self.user_sessions_key(&session.user_id);

            // Remove from user's active sessions
            let _: () = conn.srem(&user_sessions_key, session_id).await?;

            // Delete session data
            let _: () = conn.del(&session_key).await?;

            info!(
                "Terminated session {} for user {}",
                session_id, session.user_id
            );
        }

        Ok(())
    }

    /// Get count of active sessions for a user
    pub async fn get_active_session_count(
        &self,
        user_id: &str,
    ) -> Result<u32, SessionManagerError> {
        let mut conn = self.redis_client.get_multiplexed_async_connection().await?;
        let user_sessions_key = self.user_sessions_key(user_id);

        // Get all session IDs for this user
        let session_ids: Vec<String> = conn.smembers(&user_sessions_key).await?;

        // Filter out expired sessions
        let mut active_count = 0;
        let now = Utc::now().timestamp();

        for session_id in session_ids {
            if let Ok(Some(session)) = self.get_session(&session_id).await {
                if !session.is_expired(now) && session.state != SessionState::Stopped {
                    active_count += 1;
                } else {
                    // Clean up expired session
                    let _ = self.terminate_session(&session_id).await;
                }
            }
        }

        Ok(active_count)
    }

    /// Get all active sessions for a user
    pub async fn get_user_sessions(
        &self,
        user_id: &str,
    ) -> Result<Vec<PlaybackSession>, SessionManagerError> {
        let mut conn = self.redis_client.get_multiplexed_async_connection().await?;
        let user_sessions_key = self.user_sessions_key(user_id);

        let session_ids: Vec<String> = conn.smembers(&user_sessions_key).await?;
        let mut sessions = Vec::new();
        let now = Utc::now().timestamp();

        for session_id in session_ids {
            if let Ok(Some(session)) = self.get_session(&session_id).await {
                if !session.is_expired(now) {
                    sessions.push(session);
                } else {
                    // Clean up expired session
                    let _ = self.terminate_session(&session_id).await;
                }
            }
        }

        Ok(sessions)
    }

    /// Clean up expired sessions for a user
    pub async fn cleanup_expired_sessions(&self, user_id: &str) -> Result<u32, SessionManagerError> {
        let sessions = self.get_user_sessions(user_id).await?;
        let now = Utc::now().timestamp();
        let mut cleaned = 0;

        for session in sessions {
            if session.is_expired(now) {
                self.terminate_session(&session.session_id).await?;
                cleaned += 1;
            }
        }

        if cleaned > 0 {
            info!("Cleaned up {} expired sessions for user {}", cleaned, user_id);
        }

        Ok(cleaned)
    }

    /// Store first-play timestamp for rental tracking
    pub async fn record_first_play(
        &self,
        user_id: &str,
        asset_id: &str,
    ) -> Result<i64, SessionManagerError> {
        let mut conn = self.redis_client.get_multiplexed_async_connection().await?;
        let key = self.first_play_key(user_id, asset_id);
        let now = Utc::now().timestamp();

        // Use SET NX to only set if not exists
        let result: Option<String> = conn.get(&key).await?;
        if result.is_some() {
            // Already exists, return existing timestamp
            let timestamp: i64 = result.unwrap().parse().unwrap_or(now);
            return Ok(timestamp);
        }

        // Set with 30-day TTL (typical rental window)
        let _: () = conn.set_ex(&key, now, 30 * 24 * 60 * 60).await?;
        Ok(now)
    }

    /// Get first-play timestamp for rental window validation
    pub async fn get_first_play(
        &self,
        user_id: &str,
        asset_id: &str,
    ) -> Result<Option<i64>, SessionManagerError> {
        let mut conn = self.redis_client.get_multiplexed_async_connection().await?;
        let key = self.first_play_key(user_id, asset_id);

        let result: Option<String> = conn.get(&key).await?;
        Ok(result.and_then(|s| s.parse().ok()))
    }

    // Redis key constructors
    fn session_key(&self, session_id: &str) -> String {
        format!("session:{}", session_id)
    }

    fn user_sessions_key(&self, user_id: &str) -> String {
        format!("user:{}:sessions", user_id)
    }

    fn first_play_key(&self, user_id: &str, asset_id: &str) -> String {
        format!("rental:{}:{}", user_id, asset_id)
    }
}

#[derive(Debug)]
pub enum SessionManagerError {
    RedisError(redis::RedisError),
    SerializationError(serde_json::Error),
    SessionNotFound,
    ConcurrencyLimitExceeded { current: u32, max: u32 },
}

impl std::fmt::Display for SessionManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RedisError(e) => write!(f, "Redis error: {}", e),
            Self::SerializationError(e) => write!(f, "Serialization error: {}", e),
            Self::SessionNotFound => write!(f, "Session not found"),
            Self::ConcurrencyLimitExceeded { current, max } => {
                write!(f, "Concurrency limit exceeded: {}/{}", current, max)
            }
        }
    }
}

impl std::error::Error for SessionManagerError {}

impl From<redis::RedisError> for SessionManagerError {
    fn from(err: redis::RedisError) -> Self {
        Self::RedisError(err)
    }
}

impl From<serde_json::Error> for SessionManagerError {
    fn from(err: serde_json::Error) -> Self {
        Self::SerializationError(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_expiry() {
        let now = Utc::now().timestamp();
        let mut session = PlaybackSession::new(
            "test-session".to_string(),
            "user-1".to_string(),
            "asset-1".to_string(),
            "192.168.1.1".to_string(),
        );

        // Fresh session should not be expired
        assert!(!session.is_expired(now));

        // Session older than timeout should be expired
        session.last_heartbeat_timestamp = now - SESSION_HEARTBEAT_TIMEOUT - 1;
        assert!(session.is_expired(now));
    }

    #[test]
    fn test_first_play_tracking() {
        let now = Utc::now().timestamp();
        let mut session = PlaybackSession::new(
            "test-session".to_string(),
            "user-1".to_string(),
            "asset-1".to_string(),
            "192.168.1.1".to_string(),
        );

        assert!(session.first_play_timestamp.is_none());

        // Simulate starting playback
        session.state = SessionState::Playing;
        session.first_play_timestamp = Some(now);

        assert_eq!(session.first_play_timestamp, Some(now));
    }
}
