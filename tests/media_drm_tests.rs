use chrono::Utc;
/// Integration tests for Media DRM functionality
/// Tests session management, policy enforcement, and key delivery
///
/// These tests require Redis to be running on localhost:6379
/// Tests use #[serial] attribute to prevent parallel execution conflicts
use nanotdf::session_manager::{PlaybackSession, SessionManager, SessionState};
use redis::Client as RedisClient;
use serial_test::serial;
use std::sync::Arc;

// Helper function to create Redis client for tests
fn create_test_redis_client() -> RedisClient {
    RedisClient::open("redis://127.0.0.1:6379").expect("Failed to create Redis client")
}

// Helper function to clean up test data
async fn cleanup_test_data(redis_client: &RedisClient, user_id: &str) {
    let mut conn = redis_client
        .get_multiplexed_async_connection()
        .await
        .expect("Failed to get Redis connection");

    use redis::AsyncCommands;

    // Clean up all sessions for test user
    let user_sessions_key = format!("user:{}:sessions", user_id);
    let _: Result<(), redis::RedisError> = conn.del(&user_sessions_key).await;

    // Clean up individual session keys (cover various test patterns)
    let session_patterns = vec![
        format!("session:test-session-{}", user_id),
        format!("session:test-session-*{}*", user_id),
        "session:test-session-1".to_string(),
        "session:test-session-cleanup".to_string(),
        "session:test-session-states".to_string(),
        "session:test-session-timeout".to_string(),
        "session:bench-heartbeat-session".to_string(),
    ];

    for pattern in session_patterns {
        let _: Result<(), redis::RedisError> = conn.del(&pattern).await;
    }

    // Clean up numbered session keys
    for i in 0..10 {
        let session_key = format!("session:test-session-{}-{}", user_id, i);
        let _: Result<(), redis::RedisError> = conn.del(&session_key).await;

        let session_key2 = format!("session:test-session-multi-{}", i);
        let _: Result<(), redis::RedisError> = conn.del(&session_key2).await;

        let session_key3 = format!("session:test-session-concurrency-{}", i);
        let _: Result<(), redis::RedisError> = conn.del(&session_key3).await;
    }

    // Clean up rental tracking keys (cover various test patterns)
    let rental_patterns = vec![
        format!("rental:{}:test-asset-rental", user_id),
        format!("rental:{}:test-asset-firstplay", user_id),
    ];

    for pattern in rental_patterns {
        let _: Result<(), redis::RedisError> = conn.del(&pattern).await;
    }

    for i in 0..10 {
        let rental_key = format!("rental:{}:test-asset-{}", user_id, i);
        let _: Result<(), redis::RedisError> = conn.del(&rental_key).await;
    }

    // Clean up benchmark session keys
    for i in 0..100 {
        let bench_key = format!("session:bench-session-{}", i);
        let _: Result<(), redis::RedisError> = conn.del(&bench_key).await;
    }
}

#[tokio::test]
#[serial]
async fn test_session_lifecycle() {
    let redis_client = create_test_redis_client();
    let user_id = "test-user-lifecycle";

    // Clean up before test
    cleanup_test_data(&redis_client, user_id).await;

    let session_manager = Arc::new(SessionManager::new(Arc::new(redis_client.clone()), Some(5)));

    // 1. Create a session
    let session = PlaybackSession::new(
        "test-session-1".to_string(),
        user_id.to_string(),
        "test-asset-1".to_string(),
        "127.0.0.1".to_string(),
    );

    session_manager
        .create_session(session.clone())
        .await
        .expect("Failed to create session");

    // 2. Verify session exists
    let retrieved = session_manager
        .get_session("test-session-1")
        .await
        .expect("Failed to get session");
    assert!(retrieved.is_some(), "Session should exist");
    assert_eq!(retrieved.unwrap().user_id, user_id);

    // 3. Send heartbeat
    let updated = session_manager
        .heartbeat("test-session-1", Some(SessionState::Playing), Some(5))
        .await
        .expect("Failed to send heartbeat");
    assert_eq!(updated.state, SessionState::Playing);
    assert_eq!(updated.segment_index, Some(5));

    // 4. Get active session count
    let count = session_manager
        .get_active_session_count(user_id)
        .await
        .expect("Failed to get session count");
    assert_eq!(count, 1, "Should have 1 active session");

    // 5. Terminate session
    session_manager
        .terminate_session("test-session-1")
        .await
        .expect("Failed to terminate session");

    // 6. Verify session no longer exists
    let after_terminate = session_manager
        .get_session("test-session-1")
        .await
        .expect("Failed to get session");
    assert!(after_terminate.is_none(), "Session should be deleted");

    // Clean up after test
    cleanup_test_data(&redis_client, user_id).await;
}

#[tokio::test]
#[serial]
async fn test_concurrency_limits() {
    let redis_client = create_test_redis_client();
    let user_id = "test-user-concurrency";

    // Clean up before test
    cleanup_test_data(&redis_client, user_id).await;

    let max_streams = 3;
    let session_manager = Arc::new(SessionManager::new(
        Arc::new(redis_client.clone()),
        Some(max_streams),
    ));

    // 1. Create max allowed concurrent sessions
    for i in 0..max_streams {
        let session = PlaybackSession::new(
            format!("test-session-concurrency-{}", i),
            user_id.to_string(),
            format!("test-asset-{}", i),
            "127.0.0.1".to_string(),
        );

        session_manager
            .create_session(session)
            .await
            .expect(&format!("Failed to create session {}", i));
    }

    // 2. Verify we have max sessions
    let count = session_manager
        .get_active_session_count(user_id)
        .await
        .expect("Failed to get session count");
    assert_eq!(count, max_streams, "Should have max concurrent sessions");

    // 3. Attempt to create one more - should fail
    let excess_session = PlaybackSession::new(
        "test-session-concurrency-excess".to_string(),
        user_id.to_string(),
        "test-asset-excess".to_string(),
        "127.0.0.1".to_string(),
    );

    let result = session_manager.create_session(excess_session).await;
    assert!(result.is_err(), "Should reject session over limit");

    // 4. Terminate one session
    session_manager
        .terminate_session("test-session-concurrency-0")
        .await
        .expect("Failed to terminate session");

    // 5. Verify new session can now be created
    let new_session = PlaybackSession::new(
        "test-session-concurrency-new".to_string(),
        user_id.to_string(),
        "test-asset-new".to_string(),
        "127.0.0.1".to_string(),
    );

    session_manager
        .create_session(new_session)
        .await
        .expect("Should be able to create session after terminating one");

    // Clean up
    cleanup_test_data(&redis_client, user_id).await;
}

#[tokio::test]
#[serial]
async fn test_rental_window_enforcement() {
    let redis_client = create_test_redis_client();
    let user_id = "test-user-rental";
    let asset_id = "test-asset-rental";

    // Clean up before test
    cleanup_test_data(&redis_client, user_id).await;

    let session_manager = Arc::new(SessionManager::new(Arc::new(redis_client.clone()), Some(5)));

    // 1. Record first play
    let first_play = session_manager
        .record_first_play(user_id, asset_id)
        .await
        .expect("Failed to record first play");

    // 2. Verify first play timestamp was recorded
    let retrieved = session_manager
        .get_first_play(user_id, asset_id)
        .await
        .expect("Failed to get first play");
    assert!(retrieved.is_some(), "First play should be recorded");
    assert_eq!(retrieved.unwrap(), first_play);

    // 3. Record first play again - should return same timestamp
    let second_call = session_manager
        .record_first_play(user_id, asset_id)
        .await
        .expect("Failed to record first play second time");
    assert_eq!(
        first_play, second_call,
        "First play timestamp should not change"
    );

    // Clean up
    cleanup_test_data(&redis_client, user_id).await;
}

#[tokio::test]
#[serial]
async fn test_session_heartbeat_timeout() {
    let redis_client = create_test_redis_client();
    let user_id = "test-user-timeout";

    // Clean up before test
    cleanup_test_data(&redis_client, user_id).await;

    let session_manager = Arc::new(SessionManager::new(Arc::new(redis_client.clone()), Some(5)));

    // 1. Create session
    let mut session = PlaybackSession::new(
        "test-session-timeout".to_string(),
        user_id.to_string(),
        "test-asset-timeout".to_string(),
        "127.0.0.1".to_string(),
    );

    session_manager
        .create_session(session.clone())
        .await
        .expect("Failed to create session");

    // 2. Verify session is not expired when fresh
    let now = Utc::now().timestamp();
    assert!(
        !session.is_expired(now),
        "Fresh session should not be expired"
    );

    // 3. Simulate session being old (older than 300 seconds timeout)
    session.last_heartbeat_timestamp = now - 301;
    assert!(
        session.is_expired(now),
        "Session should be expired after timeout"
    );

    // Clean up
    cleanup_test_data(&redis_client, user_id).await;
}

#[tokio::test]
#[serial]
async fn test_first_play_tracking() {
    let redis_client = create_test_redis_client();
    let user_id = "test-user-firstplay";
    let asset_id = "test-asset-firstplay";

    // Clean up before test
    cleanup_test_data(&redis_client, user_id).await;

    let session_manager = Arc::new(SessionManager::new(Arc::new(redis_client.clone()), Some(5)));

    // 1. Before first play - should be None
    let before = session_manager
        .get_first_play(user_id, asset_id)
        .await
        .expect("Failed to get first play");
    assert!(
        before.is_none(),
        "Should have no first play before recording"
    );

    // 2. Record first play
    let timestamp = session_manager
        .record_first_play(user_id, asset_id)
        .await
        .expect("Failed to record first play");

    // 3. Verify timestamp is recorded
    let after = session_manager
        .get_first_play(user_id, asset_id)
        .await
        .expect("Failed to get first play");
    assert!(after.is_some(), "Should have first play timestamp");
    assert_eq!(after.unwrap(), timestamp);

    // 4. Record first play again
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    let second = session_manager
        .record_first_play(user_id, asset_id)
        .await
        .expect("Failed to record first play second time");

    // 5. Verify timestamp doesn't change
    assert_eq!(
        timestamp, second,
        "First play timestamp should remain the same"
    );

    // Clean up
    cleanup_test_data(&redis_client, user_id).await;
}

#[tokio::test]
#[serial]
async fn test_session_state_transitions() {
    let redis_client = create_test_redis_client();
    let user_id = "test-user-states";

    // Clean up before test
    cleanup_test_data(&redis_client, user_id).await;

    let session_manager = Arc::new(SessionManager::new(Arc::new(redis_client.clone()), Some(5)));

    // Create session
    let session = PlaybackSession::new(
        "test-session-states".to_string(),
        user_id.to_string(),
        "test-asset-states".to_string(),
        "127.0.0.1".to_string(),
    );

    session_manager
        .create_session(session.clone())
        .await
        .expect("Failed to create session");

    // 1. Initial state should be Starting
    let retrieved = session_manager
        .get_session("test-session-states")
        .await
        .expect("Failed to get session")
        .expect("Session should exist");
    assert_eq!(retrieved.state, SessionState::Starting);

    // 2. Transition to Playing
    let updated = session_manager
        .heartbeat("test-session-states", Some(SessionState::Playing), None)
        .await
        .expect("Failed to update to Playing");
    assert_eq!(updated.state, SessionState::Playing);
    assert!(
        updated.first_play_timestamp.is_some(),
        "First play timestamp should be set when transitioning to Playing"
    );

    // 3. Transition to Paused
    let paused = session_manager
        .heartbeat("test-session-states", Some(SessionState::Paused), None)
        .await
        .expect("Failed to update to Paused");
    assert_eq!(paused.state, SessionState::Paused);

    // 4. Transition back to Playing (first_play_timestamp should not change)
    let first_play_ts = paused.first_play_timestamp;
    let playing_again = session_manager
        .heartbeat("test-session-states", Some(SessionState::Playing), None)
        .await
        .expect("Failed to update to Playing again");
    assert_eq!(playing_again.state, SessionState::Playing);
    assert_eq!(
        playing_again.first_play_timestamp, first_play_ts,
        "First play timestamp should not change"
    );

    // 5. Transition to Stopped
    let stopped = session_manager
        .heartbeat("test-session-states", Some(SessionState::Stopped), None)
        .await
        .expect("Failed to update to Stopped");
    assert_eq!(stopped.state, SessionState::Stopped);

    // Clean up
    cleanup_test_data(&redis_client, user_id).await;
}

#[tokio::test]
#[serial]
async fn test_get_user_sessions() {
    let redis_client = create_test_redis_client();
    let user_id = "test-user-sessions";

    // Clean up before test
    cleanup_test_data(&redis_client, user_id).await;

    let session_manager = Arc::new(SessionManager::new(Arc::new(redis_client.clone()), Some(5)));

    // Create multiple sessions
    for i in 0..3 {
        let session = PlaybackSession::new(
            format!("test-session-multi-{}", i),
            user_id.to_string(),
            format!("test-asset-{}", i),
            "127.0.0.1".to_string(),
        );
        session_manager
            .create_session(session)
            .await
            .expect(&format!("Failed to create session {}", i));
    }

    // Get all user sessions
    let sessions = session_manager
        .get_user_sessions(user_id)
        .await
        .expect("Failed to get user sessions");

    assert_eq!(sessions.len(), 3, "Should have 3 active sessions");

    // Verify all sessions belong to the user
    for session in &sessions {
        assert_eq!(session.user_id, user_id);
    }

    // Clean up
    cleanup_test_data(&redis_client, user_id).await;
}

#[tokio::test]
#[serial]
async fn test_cleanup_expired_sessions() {
    let redis_client = create_test_redis_client();
    let user_id = "test-user-cleanup";

    // Clean up before test
    cleanup_test_data(&redis_client, user_id).await;

    let session_manager = Arc::new(SessionManager::new(Arc::new(redis_client.clone()), Some(5)));

    // Create a session
    let session = PlaybackSession::new(
        "test-session-cleanup".to_string(),
        user_id.to_string(),
        "test-asset-cleanup".to_string(),
        "127.0.0.1".to_string(),
    );

    session_manager
        .create_session(session)
        .await
        .expect("Failed to create session");

    // Run cleanup (should not remove fresh session)
    let cleaned = session_manager
        .cleanup_expired_sessions(user_id)
        .await
        .expect("Failed to cleanup");
    assert_eq!(cleaned, 0, "Should not clean up fresh sessions");

    // Verify session still exists
    let count = session_manager
        .get_active_session_count(user_id)
        .await
        .expect("Failed to get count");
    assert_eq!(count, 1, "Session should still be active");

    // Clean up
    cleanup_test_data(&redis_client, user_id).await;
}

// Unit tests for media policy contract
#[cfg(test)]
mod policy_tests {
    // These tests are in the contract file itself
    // src/bin/contracts/media_policy_contract.rs
    // They test:
    // - Subscription requirements
    // - Concurrency limits
    // - Rental windows
    // - HDCP requirements
    // - Device security levels
    // - Geo restrictions
}

// Performance benchmarks
#[cfg(test)]
mod benchmarks {
    use super::*;

    #[tokio::test]
    #[serial]
    async fn benchmark_session_creation() {
        let redis_client = create_test_redis_client();
        let user_id = "test-user-benchmark";

        cleanup_test_data(&redis_client, user_id).await;

        let session_manager = Arc::new(SessionManager::new(
            Arc::new(redis_client.clone()),
            Some(100),
        ));

        let start = std::time::Instant::now();
        let iterations = 50;

        for i in 0..iterations {
            let session = PlaybackSession::new(
                format!("bench-session-{}", i),
                user_id.to_string(),
                format!("bench-asset-{}", i),
                "127.0.0.1".to_string(),
            );

            session_manager
                .create_session(session)
                .await
                .expect("Failed to create session");
        }

        let elapsed = start.elapsed();
        let avg_latency = elapsed.as_millis() as f64 / iterations as f64;

        println!(
            "Created {} sessions in {:?}ms (avg: {:.2}ms per session)",
            iterations,
            elapsed.as_millis(),
            avg_latency
        );

        assert!(avg_latency < 10.0, "Session creation should average < 10ms");

        cleanup_test_data(&redis_client, user_id).await;
    }

    #[tokio::test]
    #[serial]
    async fn benchmark_heartbeat_latency() {
        let redis_client = create_test_redis_client();
        let user_id = "test-user-heartbeat-bench";

        cleanup_test_data(&redis_client, user_id).await;

        let session_manager =
            Arc::new(SessionManager::new(Arc::new(redis_client.clone()), Some(5)));

        // Create session
        let session = PlaybackSession::new(
            "bench-heartbeat-session".to_string(),
            user_id.to_string(),
            "bench-heartbeat-asset".to_string(),
            "127.0.0.1".to_string(),
        );

        session_manager
            .create_session(session)
            .await
            .expect("Failed to create session");

        // Benchmark heartbeats
        let iterations = 100;
        let start = std::time::Instant::now();

        for i in 0..iterations {
            session_manager
                .heartbeat(
                    "bench-heartbeat-session",
                    Some(SessionState::Playing),
                    Some(i),
                )
                .await
                .expect("Failed to send heartbeat");
        }

        let elapsed = start.elapsed();
        let avg_latency = elapsed.as_millis() as f64 / iterations as f64;

        println!(
            "Sent {} heartbeats in {:?}ms (avg: {:.2}ms per heartbeat)",
            iterations,
            elapsed.as_millis(),
            avg_latency
        );

        assert!(avg_latency < 5.0, "Heartbeat should average < 5ms");

        cleanup_test_data(&redis_client, user_id).await;
    }
}
