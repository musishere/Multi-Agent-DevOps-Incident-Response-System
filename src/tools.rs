//! Read-only data-access "tools" — one `get_*` per table, the building
//! blocks the Diagnostic sub-agent's `metrics_query`/`log_query`/etc. will
//! wrap later.

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct Service {
    pub service_name: String,
    pub criticality: String,
    pub owner_team: String,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct Metric {
    pub id: i32,
    pub service: String,
    pub p99_latency_ms: i32,
    pub error_rate: f32,
    pub cpu_percent: i32,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct Log {
    pub id: i32,
    pub svc_name: String,
    pub level: String,
    pub message: String,
    pub err_count: i32,
    pub date: String,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct Incident {
    pub incident_id: String,
    pub service: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct IncidentUpdate {
    pub id: i32,
    pub incident_id: String,
    pub message: String,
    pub posted_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct RemediationLogEntry {
    pub id: i32,
    pub service: String,
    pub action: String,
    pub status: String,
    pub timestamp: DateTime<Utc>,
}

/// All known services (small reference table, no filter needed).
pub async fn get_services(pool: &PgPool) -> Result<Vec<Service>, sqlx::Error> {
    sqlx::query_as("SELECT service_name, criticality, owner_team FROM services ORDER BY service_name")
        .fetch_all(pool)
        .await
}

/// Metrics for one service, oldest first.
pub async fn get_metrics_for_service(
    pool: &PgPool,
    service: &str,
) -> Result<Vec<Metric>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, service, p99_latency_ms, error_rate, cpu_percent, timestamp
         FROM metrics WHERE service = $1 ORDER BY timestamp",
    )
    .bind(service)
    .fetch_all(pool)
    .await
}

/// Legacy log export rows for one service (svc_name, not service — different schema).
pub async fn get_logs_for_service(pool: &PgPool, svc_name: &str) -> Result<Vec<Log>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, svc_name, level, message, err_count, date
         FROM logs WHERE svc_name = $1 ORDER BY id",
    )
    .bind(svc_name)
    .fetch_all(pool)
    .await
}

/// Incidents for one service, most recent first.
pub async fn get_incidents_for_service(
    pool: &PgPool,
    service: &str,
) -> Result<Vec<Incident>, sqlx::Error> {
    sqlx::query_as(
        "SELECT incident_id, service, status, created_at
         FROM incidents WHERE service = $1 ORDER BY created_at DESC",
    )
    .bind(service)
    .fetch_all(pool)
    .await
}

/// Status updates posted for one incident, oldest first.
pub async fn get_incident_updates(
    pool: &PgPool,
    incident_id: &str,
) -> Result<Vec<IncidentUpdate>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, incident_id, message, posted_at
         FROM incident_updates WHERE incident_id = $1 ORDER BY posted_at",
    )
    .bind(incident_id)
    .fetch_all(pool)
    .await
}

/// Remediation actions taken for one service, most recent first.
pub async fn get_remediation_log_for_service(
    pool: &PgPool,
    service: &str,
) -> Result<Vec<RemediationLogEntry>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, service, action, status, timestamp
         FROM remediation_log WHERE service = $1 ORDER BY timestamp DESC",
    )
    .bind(service)
    .fetch_all(pool)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_pool() -> PgPool {
        dotenvy::dotenv().ok();
        let url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set (see .env)");
        PgPool::connect(&url).await.expect("connect to test db")
    }

    // These assume `cargo run --bin seed` has already been run against DATABASE_URL.

    #[tokio::test]
    async fn get_services_returns_all_four_with_correct_tiers() {
        let pool = test_pool().await;
        let services = get_services(&pool).await.unwrap();
        assert_eq!(services.len(), 4);
        assert!(services.iter().any(|s| s.service_name == "checkout-service"
            && s.criticality == "critical"
            && s.owner_team == "payments"));
        assert!(services.iter().any(|s| s.service_name == "recommendation-service"
            && s.criticality == "medium"));
        assert_eq!(services.iter().filter(|s| s.criticality == "low").count(), 2);
    }

    #[tokio::test]
    async fn get_metrics_for_service_returns_baseline_then_spike_in_order() {
        let pool = test_pool().await;
        let metrics = get_metrics_for_service(&pool, "checkout-service").await.unwrap();
        assert_eq!(metrics.len(), 4); // 3 baseline rows + 1 spike, seeded for checkout-service
        // ORDER BY timestamp means the spike (most recent) is last.
        let last = metrics.last().unwrap();
        assert!(last.p99_latency_ms > 2000 && last.error_rate > 0.05 && last.cpu_percent > 90);
        assert!(metrics[..metrics.len() - 1]
            .iter()
            .all(|m| m.p99_latency_ms < 250 && m.error_rate < 0.01));
        assert!(metrics.windows(2).all(|w| w[0].timestamp <= w[1].timestamp));
    }

    #[tokio::test]
    async fn get_metrics_for_service_unknown_service_is_empty() {
        let pool = test_pool().await;
        let metrics = get_metrics_for_service(&pool, "nonexistent-service").await.unwrap();
        assert!(metrics.is_empty());
    }

    #[tokio::test]
    async fn get_logs_for_service_includes_info_and_incident_rows() {
        let pool = test_pool().await;
        let logs = get_logs_for_service(&pool, "checkout-service").await.unwrap();
        assert_eq!(logs.len(), 3); // 1 INFO baseline + 2 incident rows
        assert!(logs.iter().any(|l| l.level == "INFO"));
        assert!(logs.iter().any(|l| l.level == "ERROR" && l.message.contains("payment-gateway")));
        assert!(logs.iter().any(|l| l.level == "WARN" && l.message.contains("connection pool exhausted")));
    }

    #[tokio::test]
    async fn get_logs_for_service_unknown_service_is_empty() {
        let pool = test_pool().await;
        let logs = get_logs_for_service(&pool, "nonexistent-service").await.unwrap();
        assert!(logs.is_empty());
    }

    #[tokio::test]
    async fn get_incidents_for_service_finds_old_resolved_incident() {
        let pool = test_pool().await;
        let incidents = get_incidents_for_service(&pool, "recommendation-service").await.unwrap();
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].status, "resolved");
        assert_eq!(incidents[0].incident_id, "INC-2031");
    }

    #[tokio::test]
    async fn get_incidents_for_service_with_no_incidents_is_empty() {
        let pool = test_pool().await;
        // checkout-service has a live metrics/log spike but no incidents row yet.
        let incidents = get_incidents_for_service(&pool, "checkout-service").await.unwrap();
        assert!(incidents.is_empty());
    }

    #[tokio::test]
    async fn get_incident_updates_is_empty_for_seeded_incident() {
        let pool = test_pool().await;
        assert!(get_incident_updates(&pool, "INC-2031").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn get_remediation_log_for_service_is_empty() {
        let pool = test_pool().await;
        assert!(get_remediation_log_for_service(&pool, "checkout-service").await.unwrap().is_empty());
    }
}
