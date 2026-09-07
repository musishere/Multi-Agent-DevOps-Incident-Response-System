//! Write-side tools for the Remediation/Communication sub-agents.
//!
//! Before anything else, each remediation action checks its own recent
//! history for loop detection: the same (service, action) pair attempted
//! again within `DUPLICATE_WINDOW_MINUTES` of a still-standing attempt is
//! suppressed instead of re-run — a retrying agent (or a human mashing
//! the same button) doesn't get to restart the same pod five times in a
//! row. Only past that check does `permissions::check_*` decide `Auto`
//! (logged `completed`) vs `Confirm` (logged `pending_confirmation`).
//! There's still no real pod/infra execution, sandboxing, or a genuine
//! idempotency check *inside* the infrastructure call itself — see spec's
//! Harness Engineering section — but repeated *requests* are now
//! code-enforced, not left to the model to not-do.

use crate::permissions::{self, Tier};
use crate::tools;
use chrono::{Duration, Utc};
use sqlx::PgPool;

/// How long a completed or still-pending action suppresses a repeat of
/// the exact same (service, action) pair.
const DUPLICATE_WINDOW_MINUTES: i64 = 15;

/// Executes a free-form remediation action against a service.
/// `criticality` is the service's tier ("critical"/"medium"/"low"); the
/// caller looks it up, since this function only decides what to do with it.
pub async fn execute_remediation(
    pool: &PgPool,
    service: &str,
    criticality: &str,
    action: &str,
) -> Result<Tier, sqlx::Error> {
    guarded(pool, service, action, || {
        permissions::check_execute_remediation(action, criticality)
    })
    .await
}

/// Scales a service by a signed percentage.
pub async fn scale_service(pool: &PgPool, service: &str, target_percent: i32) -> Result<Tier, sqlx::Error> {
    let action = format!("scale_service {target_percent:+}%");
    guarded(pool, service, &action, || permissions::check_scale_service(target_percent)).await
}

/// Rolls a service's deployment back to its last known-good version.
pub async fn rollback_deployment(pool: &PgPool, service: &str) -> Result<Tier, sqlx::Error> {
    guarded(pool, service, "rollback_deployment", permissions::check_rollback_deployment).await
}

/// Deletes a named infrastructure resource.
pub async fn delete_resource(pool: &PgPool, service: &str, resource: &str) -> Result<Tier, sqlx::Error> {
    let action = format!("delete_resource {resource}");
    guarded(pool, service, &action, permissions::check_delete_resource).await
}

/// Runs the loop-detection check first; only if it's not a duplicate does
/// it fall through to `decide_tier` (the actual permission check) and persist.
async fn guarded(
    pool: &PgPool,
    service: &str,
    action: &str,
    decide_tier: impl FnOnce() -> Tier,
) -> Result<Tier, sqlx::Error> {
    if let Some(duplicate) = check_recent_duplicate(pool, service, action).await? {
        persist(pool, service, action, &duplicate).await?;
        return Ok(duplicate);
    }
    let tier = decide_tier();
    persist(pool, service, action, &tier).await?;
    Ok(tier)
}

/// Looks for a still-standing (`completed` or `pending_confirmation`)
/// attempt of the exact same action against the exact same service within
/// the last `DUPLICATE_WINDOW_MINUTES`. Anchored to that original attempt's
/// timestamp, not the latest retry, so a fast-repeating loop can't keep
/// pushing the window forward.
async fn check_recent_duplicate(
    pool: &PgPool,
    service: &str,
    action: &str,
) -> Result<Option<Tier>, sqlx::Error> {
    let cutoff = Utc::now() - Duration::minutes(DUPLICATE_WINDOW_MINUTES);
    let history = tools::get_remediation_log_for_service(pool, service).await?;

    let existing = history.iter().find(|entry| {
        entry.action == action
            && entry.timestamp >= cutoff
            && matches!(entry.status.as_str(), "completed" | "pending_confirmation")
    });

    Ok(existing.map(|entry| {
        let minutes_ago = (Utc::now() - entry.timestamp).num_minutes();
        Tier::Duplicate(format!(
            "'{action}' on {service} was already attempted {minutes_ago} minute(s) ago \
             (status: {}) — refusing to repeat within the {DUPLICATE_WINDOW_MINUTES}-minute window",
            entry.status
        ))
    }))
}

/// Records the action with a status that reflects the verdict:
/// `completed` if it actually ran, `pending_confirmation` if a permission
/// guardrail blocked it, `duplicate_suppressed` if loop detection did.
async fn persist(pool: &PgPool, service: &str, action: &str, tier: &Tier) -> Result<(), sqlx::Error> {
    let status = match tier {
        Tier::Auto => "completed",
        Tier::Confirm(_) => "pending_confirmation",
        Tier::Duplicate(_) => "duplicate_suppressed",
    };
    sqlx::query(
        "INSERT INTO remediation_log (service, action, status, timestamp)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(service)
    .bind(action)
    .bind(status)
    .bind(Utc::now())
    .execute(pool)
    .await?;
    Ok(())
}

/// Posts a status update against an incident.
pub async fn post_incident_update(
    pool: &PgPool,
    incident_id: &str,
    message: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO incident_updates (incident_id, message, posted_at)
         VALUES ($1, $2, $3)",
    )
    .bind(incident_id)
    .bind(message)
    .bind(Utc::now())
    .execute(pool)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::{get_incident_updates, get_remediation_log_for_service};

    async fn test_pool() -> PgPool {
        dotenvy::dotenv().ok();
        let url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set (see .env)");
        PgPool::connect(&url).await.expect("connect to test db")
    }

    async fn cleanup(pool: &PgPool, service: &str) {
        sqlx::query("DELETE FROM remediation_log WHERE service = $1")
            .bind(service)
            .execute(pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn repeating_the_same_completed_action_is_suppressed_as_duplicate() {
        let pool = test_pool().await;
        let service = "test-skeleton-loop-completed";

        let first = execute_remediation(&pool, service, "low", "restart_pod").await.unwrap();
        assert_eq!(first, Tier::Auto);

        // Same service, same action, retried immediately — this is exactly
        // the "agent keeps restarting the same pod" failure mode.
        let second = execute_remediation(&pool, service, "low", "restart_pod").await.unwrap();
        assert!(matches!(second, Tier::Duplicate(_)));

        let log = get_remediation_log_for_service(&pool, service).await.unwrap();
        assert_eq!(log.len(), 2);
        // Most recent first: the duplicate attempt, then the original.
        assert_eq!(log[0].status, "duplicate_suppressed");
        assert_eq!(log[1].status, "completed");

        cleanup(&pool, service).await;
    }

    #[tokio::test]
    async fn repeating_a_still_pending_action_is_also_suppressed() {
        let pool = test_pool().await;
        let service = "test-skeleton-loop-pending";

        // rollback_deployment is always Confirm, i.e. always leaves a
        // pending_confirmation row — spamming it shouldn't pile up more.
        let first = rollback_deployment(&pool, service).await.unwrap();
        assert!(matches!(first, Tier::Confirm(_)));

        let second = rollback_deployment(&pool, service).await.unwrap();
        assert!(matches!(second, Tier::Duplicate(_)));

        let log = get_remediation_log_for_service(&pool, service).await.unwrap();
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].status, "duplicate_suppressed");
        assert_eq!(log[1].status, "pending_confirmation");

        cleanup(&pool, service).await;
    }

    #[tokio::test]
    async fn different_actions_on_the_same_service_do_not_collide() {
        let pool = test_pool().await;
        let service = "test-skeleton-loop-different-actions";

        let restart = execute_remediation(&pool, service, "low", "restart_pod").await.unwrap();
        let scale = scale_service(&pool, service, 10).await.unwrap();
        assert_eq!(restart, Tier::Auto);
        assert_eq!(scale, Tier::Auto); // not suppressed — different action

        let log = get_remediation_log_for_service(&pool, service).await.unwrap();
        assert_eq!(log.len(), 2);
        assert!(log.iter().all(|entry| entry.status == "completed"));

        cleanup(&pool, service).await;
    }

    #[tokio::test]
    async fn same_action_on_different_services_do_not_collide() {
        let pool = test_pool().await;
        let (service_a, service_b) = ("test-skeleton-loop-svc-a", "test-skeleton-loop-svc-b");

        let a = execute_remediation(&pool, service_a, "low", "restart_pod").await.unwrap();
        let b = execute_remediation(&pool, service_b, "low", "restart_pod").await.unwrap();
        assert_eq!(a, Tier::Auto);
        assert_eq!(b, Tier::Auto); // not suppressed — different service

        cleanup(&pool, service_a).await;
        cleanup(&pool, service_b).await;
    }

    #[tokio::test]
    async fn restart_pod_on_non_critical_service_is_auto_approved() {
        let pool = test_pool().await;
        let service = "test-skeleton-restart-low";
        let tier = execute_remediation(&pool, service, "low", "restart_pod").await.unwrap();
        assert_eq!(tier, Tier::Auto);

        let log = get_remediation_log_for_service(&pool, service).await.unwrap();
        assert_eq!(log[0].action, "restart_pod");
        assert_eq!(log[0].status, "completed");

        cleanup(&pool, service).await;
    }

    #[tokio::test]
    async fn restart_pod_on_critical_service_requires_confirmation() {
        let pool = test_pool().await;
        let service = "test-skeleton-restart-critical";
        let tier = execute_remediation(&pool, service, "critical", "restart_pod").await.unwrap();
        assert!(matches!(tier, Tier::Confirm(_)));

        let log = get_remediation_log_for_service(&pool, service).await.unwrap();
        assert_eq!(log[0].status, "pending_confirmation");

        cleanup(&pool, service).await;
    }

    #[tokio::test]
    async fn scale_service_within_range_is_auto_approved() {
        let pool = test_pool().await;
        let service = "test-skeleton-scale-ok";
        let tier = scale_service(&pool, service, 20).await.unwrap();
        assert_eq!(tier, Tier::Auto);

        let log = get_remediation_log_for_service(&pool, service).await.unwrap();
        assert_eq!(log[0].action, "scale_service +20%");
        assert_eq!(log[0].status, "completed");

        cleanup(&pool, service).await;
    }

    #[tokio::test]
    async fn scale_service_outside_range_requires_confirmation() {
        let pool = test_pool().await;
        let service = "test-skeleton-scale-big";
        let tier = scale_service(&pool, service, -50).await.unwrap();
        assert!(matches!(tier, Tier::Confirm(_)));

        let log = get_remediation_log_for_service(&pool, service).await.unwrap();
        assert_eq!(log[0].action, "scale_service -50%");
        assert_eq!(log[0].status, "pending_confirmation");

        cleanup(&pool, service).await;
    }

    #[tokio::test]
    async fn rollback_deployment_always_requires_confirmation() {
        let pool = test_pool().await;
        let service = "test-skeleton-rollback";
        let tier = rollback_deployment(&pool, service).await.unwrap();
        assert!(matches!(tier, Tier::Confirm(_)));

        let log = get_remediation_log_for_service(&pool, service).await.unwrap();
        assert_eq!(log[0].action, "rollback_deployment");
        assert_eq!(log[0].status, "pending_confirmation");

        cleanup(&pool, service).await;
    }

    #[tokio::test]
    async fn delete_resource_always_requires_confirmation() {
        let pool = test_pool().await;
        let service = "test-skeleton-delete";
        let tier = delete_resource(&pool, service, "checkout-service-prod-cache").await.unwrap();
        assert!(matches!(tier, Tier::Confirm(_)));

        let log = get_remediation_log_for_service(&pool, service).await.unwrap();
        assert_eq!(log[0].action, "delete_resource checkout-service-prod-cache");
        assert_eq!(log[0].status, "pending_confirmation");

        cleanup(&pool, service).await;
    }

    #[tokio::test]
    async fn post_incident_update_logs_the_message() {
        let pool = test_pool().await;
        let incident_id = "TEST-SKELETON-INC";
        post_incident_update(&pool, incident_id, "investigating").await.unwrap();

        let updates = get_incident_updates(&pool, incident_id).await.unwrap();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].message, "investigating");

        sqlx::query("DELETE FROM incident_updates WHERE incident_id = $1")
            .bind(incident_id)
            .execute(&pool)
            .await
            .unwrap();
    }
}
