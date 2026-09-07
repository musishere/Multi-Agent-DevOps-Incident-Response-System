//! Write-side tools for the Remediation/Communication sub-agents.
//!
//! Skeletons only: they log the action/update and nothing else. No
//! permission/risk-tier gating, no actual pod/infra execution, no
//! idempotency or loop-detection checks yet — see spec's Harness
//! Engineering section. The guardrail layer sits in front of
//! `execute_remediation` and decides whether to call it at all; this
//! function itself doesn't yet know or care what `action` means.

use chrono::Utc;
use sqlx::PgPool;

/// Executes a remediation action against a service and records it.
// ponytail: doesn't actually touch infrastructure yet, and has no
// permission-tier/sandboxing/idempotency checks. Add the guardrail layer
// (confirm-required tiers, sandboxed exec, loop detection) in front of
// this before it's allowed to do anything real.
pub async fn execute_remediation(
    pool: &PgPool,
    service: &str,
    action: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO remediation_log (service, action, status, timestamp)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(service)
    .bind(action)
    .bind("completed")
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

    #[tokio::test]
    async fn execute_remediation_logs_the_action() {
        let pool = test_pool().await;
        let service = "test-skeleton-service";
        execute_remediation(&pool, service, "restart_pod").await.unwrap();

        let log = get_remediation_log_for_service(&pool, service).await.unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].action, "restart_pod");

        sqlx::query("DELETE FROM remediation_log WHERE service = $1")
            .bind(service)
            .execute(&pool)
            .await
            .unwrap();
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
