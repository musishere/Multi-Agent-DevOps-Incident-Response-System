//! Maps a tool-call name + JSON args (as received from the model) to the
//! matching function in `tools`/`runbooks`/`actions`, and serializes the
//! result back to JSON for the tool-result message.

use serde_json::{json, Value};
use sqlx::PgPool;

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
            let svc_name = arg_str(args, "svc_name")?;
            tools::get_logs_for_service(pool, svc_name)
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
            actions::execute_remediation(pool, service, action)
                .await
                .map(|_| json!({ "status": "logged" }))
                .map_err(db_err)
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
    async fn unknown_tool_name_is_an_error() {
        let pool = test_pool().await;
        let result = execute_tool(&pool, "delete_everything", &json!({})).await;
        assert!(result.is_err());
    }
}
