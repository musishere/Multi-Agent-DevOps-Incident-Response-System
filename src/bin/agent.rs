//! Interactive CLI entry point for one incident. All the actual phase
//! logic lives in `incident_response_system::pipeline` — this binary just
//! wires up config/args and calls it. See `pipeline.rs` for how the
//! Diagnose -> Remediate -> Communicate loop, guardrails, and tracing work.

use incident_response_system::pipeline::run_incident;
use sqlx::postgres::PgPoolOptions;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    let api_key = env::var("GROQ_API_KEY").expect("GROQ_API_KEY must be set (see .env)");
    let model = env::var("GROQ_MODEL").unwrap_or_else(|_| "openai/gpt-oss-120b".to_string());
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set (see .env)");

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;

    let alert = env::args()
        .nth(1)
        .unwrap_or_else(|| "API latency spike on checkout-service, p99 > 2000ms for 5 minutes.".to_string());

    // SECURITY TEST ONLY: forces a specific search_runbooks result into
    // Diagnose's context before the model's first turn, bypassing the
    // model's own decision to search. See pipeline::run_incident's doc
    // comment. Leave unset for normal use.
    let injected_runbook_query = env::var("INJECT_RUNBOOK_QUERY").ok();

    let client = reqwest::Client::new();
    run_incident(&pool, &client, &api_key, &model, &alert, injected_runbook_query.as_deref()).await?;
    Ok(())
}
