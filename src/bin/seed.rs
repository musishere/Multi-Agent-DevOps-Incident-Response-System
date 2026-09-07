use chrono::{Duration, Utc};
use sqlx::postgres::PgPoolOptions;

#[tokio::main]
async fn main() -> Result<(), sqlx::Error> {
    dotenvy::dotenv().ok();
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set (see .env)");

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;

    sqlx::migrate!("./migrations").run(&pool).await?;

    // Wipe existing seed data so this script is safely re-runnable.
    sqlx::query(
        "TRUNCATE TABLE incident_updates, remediation_log, incidents, logs, metrics, services
         RESTART IDENTITY CASCADE",
    )
    .execute(&pool)
    .await?;

    seed_services(&pool).await?;
    let spike_at = seed_metrics(&pool).await?;
    seed_logs(&pool, spike_at).await?;
    seed_incidents(&pool).await?;
    // incident_updates and remediation_log are left empty per spec.

    println!("Seed complete.");
    Ok(())
}

async fn seed_services(pool: &sqlx::PgPool) -> Result<(), sqlx::Error> {
    let services = [
        ("checkout-service", "critical", "payments"),
        ("recommendation-service", "medium", "ml-platform"),
        ("internal-admin-tool", "low", "platform"),
        ("email-notification-service", "low", "platform"),
    ];
    for (name, criticality, owner_team) in services {
        sqlx::query(
            "INSERT INTO services (service_name, criticality, owner_team) VALUES ($1, $2, $3)",
        )
        .bind(name)
        .bind(criticality)
        .bind(owner_team)
        .execute(pool)
        .await?;
    }
    Ok(())
}

/// Seeds baseline metrics for all services plus one incident spike for
/// checkout-service. Returns the spike's timestamp so `seed_logs` can line
/// up its error rows on the same day.
async fn seed_metrics(pool: &sqlx::PgPool) -> Result<chrono::DateTime<Utc>, sqlx::Error> {
    let now = Utc::now();

    // (service, p99_latency_ms, error_rate, cpu_percent, minutes_ago)
    let baseline: [(&str, i32, f32, i32, i64); 14] = [
        ("checkout-service", 180, 0.001, 32, 260),
        ("checkout-service", 210, 0.002, 38, 200),
        ("checkout-service", 195, 0.0015, 40, 140),
        ("recommendation-service", 160, 0.001, 35, 250),
        ("recommendation-service", 220, 0.001, 42, 190),
        ("recommendation-service", 190, 0.0012, 30, 130),
        ("recommendation-service", 205, 0.001, 37, 70),
        ("internal-admin-tool", 150, 0.0005, 31, 240),
        ("internal-admin-tool", 175, 0.0008, 33, 180),
        ("internal-admin-tool", 160, 0.0005, 29, 100),
        ("email-notification-service", 200, 0.001, 40, 230),
        ("email-notification-service", 230, 0.0015, 44, 170),
        ("email-notification-service", 215, 0.001, 36, 90),
        ("email-notification-service", 190, 0.001, 41, 50),
    ];
    for (service, latency, error_rate, cpu, minutes_ago) in baseline {
        let ts = now - Duration::minutes(minutes_ago);
        sqlx::query(
            "INSERT INTO metrics (service, p99_latency_ms, error_rate, cpu_percent, timestamp)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(service)
        .bind(latency)
        .bind(error_rate)
        .bind(cpu)
        .bind(ts)
        .execute(pool)
        .await?;
    }

    // The incident: checkout-service latency/error/cpu spike.
    let spike_at = now - Duration::minutes(40);
    sqlx::query(
        "INSERT INTO metrics (service, p99_latency_ms, error_rate, cpu_percent, timestamp)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind("checkout-service")
    .bind(2100_i32)
    .bind(0.08_f32)
    .bind(92_i32)
    .bind(spike_at)
    .execute(pool)
    .await?;

    Ok(spike_at)
}

async fn seed_logs(pool: &sqlx::PgPool, spike_at: chrono::DateTime<Utc>) -> Result<(), sqlx::Error> {
    // Legacy log export only carries a date (MM/DD/YYYY), no time-of-day.
    let spike_date = spike_at.format("%m/%d/%Y").to_string();

    let normal: [(&str, &str, &str, i32); 4] = [
        ("checkout-service", "INFO", "health check passed", 0),
        (
            "recommendation-service",
            "INFO",
            "model refresh completed",
            0,
        ),
        (
            "internal-admin-tool",
            "INFO",
            "nightly batch job completed",
            0,
        ),
        ("email-notification-service", "INFO", "queue drained", 0),
    ];
    for (svc_name, level, message, err_count) in normal {
        sqlx::query(
            "INSERT INTO logs (svc_name, level, message, err_count, date)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(svc_name)
        .bind(level)
        .bind(message)
        .bind(err_count)
        .bind(&spike_date)
        .execute(pool)
        .await?;
    }

    // These two explain the metrics spike: same service, same day.
    let incident_logs: [(&str, &str, i32); 2] = [
        ("ERROR", "connection timeout to payment-gateway", 47),
        (
            "WARN",
            "connection pool exhausted, 0 available connections",
            112,
        ),
    ];
    for (level, message, err_count) in incident_logs {
        sqlx::query(
            "INSERT INTO logs (svc_name, level, message, err_count, date)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind("checkout-service")
        .bind(level)
        .bind(message)
        .bind(err_count)
        .bind(&spike_date)
        .execute(pool)
        .await?;
    }

    Ok(())
}

async fn seed_incidents(pool: &sqlx::PgPool) -> Result<(), sqlx::Error> {
    let now = Utc::now();
    let old_incidents: [(&str, &str, &str, i64); 2] = [
        ("INC-2031", "recommendation-service", "resolved", 6 * 24 * 60),
        ("INC-2032", "internal-admin-tool", "resolved", 10 * 24 * 60),
    ];
    for (incident_id, service, status, minutes_ago) in old_incidents {
        sqlx::query(
            "INSERT INTO incidents (incident_id, service, status, created_at)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(incident_id)
        .bind(service)
        .bind(status)
        .bind(now - Duration::minutes(minutes_ago))
        .execute(pool)
        .await?;
    }
    Ok(())
}
