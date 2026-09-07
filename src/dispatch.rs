//! Maps a tool-call name + JSON args (as received from the model) to the
//! matching function in `tools`/`runbooks`/`actions`, and serializes the
//! result back to JSON for the tool-result message.

use serde_json::{json, Value};
use sqlx::PgPool;

use crate::permissions::Tier;
use crate::{actions, runbooks, tools};

pub async fn execute_tool(pool: &PgPool, name: &str, args: &Value) -> Result<Value, String> {
    let db_err = |e: sqlx::Error| e.to_string();

    match name {
        "get_services" => tools::get_services(pool).await.map(|v| json!(v)).map_err(db_err),

        "get_metrics_for_service" => {
            let service = arg_str(args, "service")?;
            tools::get_metrics_for_service(pool, service)
                .await
                .map(|v| json!(v))
                .map_err(db_err)
        }

        "get_logs_for_service" => {
            let service = arg_str(args, "service")?;
            tools::get_logs_for_service(pool, service)
                .await
                .map(|v| json!(v))
                .map_err(db_err)
        }

        "get_incidents_for_service" => {
            let service = arg_str(args, "service")?;
            tools::get_incidents_for_service(pool, service)
                .await
                .map(|v| json!(v))
                .map_err(db_err)
        }

        "get_incident_updates" => {
            let incident_id = arg_str(args, "incident_id")?;
            tools::get_incident_updates(pool, incident_id)
                .await
                .map(|v| json!(v))
                .map_err(db_err)
        }

        "get_remediation_log_for_service" => {
            let service = arg_str(args, "service")?;
            tools::get_remediation_log_for_service(pool, service)
                .await
                .map(|v| json!(v))
                .map_err(db_err)
        }

        "search_runbooks" => {
            let query = arg_str(args, "query")?;
            runbooks::search_runbooks(query)
                .map(|v| json!(v))
                .map_err(|e| e.to_string())
        }

        "execute_remediation" => {
            let service = arg_str(args, "service")?;
            let action = arg_str(args, "action")?;
            let criticality = service_criticality(pool, service).await?;
            let tier = actions::execute_remediation(pool, service, &criticality, action)
                .await
                .map_err(db_err)?;
            Ok(tier_result(tier))
        }

        "scale_service" => {
            let service = arg_str(args, "service")?;
            let target_percent = arg_i64(args, "target_percent")? as i32;
            let tier = actions::scale_service(pool, service, target_percent)
                .await
                .map_err(db_err)?;
            Ok(tier_result(tier))
        }

        "rollback_deployment" => {
            let service = arg_str(args, "service")?;
            let tier = actions::rollback_deployment(pool, service).await.map_err(db_err)?;
            Ok(tier_result(tier))
        }

        "delete_resource" => {
            let service = arg_str(args, "service")?;
            let resource = arg_str(args, "resource")?;
            let tier = actions::delete_resource(pool, service, resource)
                .await
                .map_err(db_err)?;
            Ok(tier_result(tier))
        }

        "post_incident_update" => {
            let incident_id = arg_str(args, "incident_id")?;
            let message = arg_str(args, "message")?;
            actions::post_incident_update(pool, incident_id, message)
                .await
                .map(|_| json!({ "status": "posted" }))
                .map_err(db_err)
        }

        other => Err(format!("unknown tool: {other}")),
    }
}

fn arg_str<'a>(args: &'a Value, key: &str) -> Result<&'a str, String> {
    args.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing required string arg: {key}"))
}

fn arg_i64(args: &Value, key: &str) -> Result<i64, String> {
    args.get(key)
        .and_then(Value::as_i64)
        .ok_or_else(|| format!("missing required integer arg: {key}"))
}

/// Looks up a service's criticality tier for the permission layer.
/// An unknown service defaults to "critical" — fail-safe, not an oversight.
async fn service_criticality(pool: &PgPool, service: &str) -> Result<String, String> {
    tools::get_service(pool, service)
        .await
        .map(|found| found.map(|s| s.criticality).unwrap_or_else(|| "critical".to_string()))
        .map_err(|e| e.to_string())
}

fn tier_result(tier: Tier) -> Value {
    match tier {
        Tier::Auto => json!({ "status": "logged" }),
        Tier::Confirm(reason) => json!({ "status": "confirmation_required", "reason": reason }),
        Tier::Duplicate(reason) => json!({ "status": "duplicate_suppressed", "reason": reason }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_pool() -> PgPool {
        dotenvy::dotenv().ok();
        let url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set (see .env)");
        PgPool::connect(&url).await.expect("connect to test db")
    }

    #[tokio::test]
    async fn dispatches_read_tool_by_name() {
        let pool = test_pool().await;
        let result = execute_tool(&pool, "get_services", &json!({})).await.unwrap();
        assert_eq!(result.as_array().unwrap().len(), 4);
    }

    #[tokio::test]
    async fn missing_arg_is_an_error_not_a_panic() {
        let pool = test_pool().await;
        let result = execute_tool(&pool, "get_metrics_for_service", &json!({})).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn dispatches_the_new_remediation_tools_by_name() {
        let pool = test_pool().await;
        let service = "test-dispatch-remediation";

        let scale = execute_tool(&pool, "scale_service", &json!({"service": service, "target_percent": -10}))
            .await
            .unwrap();
        assert_eq!(scale["status"], "logged"); // -10% is within the auto range

        let rollback = execute_tool(&pool, "rollback_deployment", &json!({"service": service}))
            .await
            .unwrap();
        assert_eq!(rollback["status"], "confirmation_required"); // never auto

        let delete = execute_tool(
            &pool,
            "delete_resource",
            &json!({"service": service, "resource": "stale-cache-volume"}),
        )
        .await
        .unwrap();
        assert_eq!(delete["status"], "confirmation_required"); // never auto

        let log = tools::get_remediation_log_for_service(&pool, service).await.unwrap();
        assert_eq!(log.len(), 3);

        sqlx::query("DELETE FROM remediation_log WHERE service = $1")
            .bind(service)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn execute_remediation_gates_restart_pod_by_real_service_criticality() {
        let pool = test_pool().await;

        // checkout-service is seeded as criticality = "critical".
        let blocked = execute_tool(
            &pool,
            "execute_remediation",
            &json!({"service": "checkout-service", "action": "restart_pod"}),
        )
        .await
        .unwrap();
        assert_eq!(blocked["status"], "confirmation_required");

        // recommendation-service is seeded as criticality = "medium".
        let allowed = execute_tool(
            &pool,
            "execute_remediation",
            &json!({"service": "recommendation-service", "action": "restart_pod"}),
        )
        .await
        .unwrap();
        assert_eq!(allowed["status"], "logged");

        sqlx::query("DELETE FROM remediation_log WHERE service IN ($1, $2)")
            .bind("checkout-service")
            .bind("recommendation-service")
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn unknown_tool_name_is_an_error() {
        let pool = test_pool().await;
        let result = execute_tool(&pool, "delete_everything", &json!({})).await;
        assert!(result.is_err());
    }
}
