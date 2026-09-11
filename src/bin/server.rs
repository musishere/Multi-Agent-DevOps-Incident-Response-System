//! HTTP API + single-page frontend for triggering an incident. Thin wrapper
//! around `pipeline::run_incident` — same guardrails, same tracing, same
//! everything as the CLI (`bin/agent.rs`); this just exposes it over HTTP so
//! it can be triggered from a browser instead of a terminal.
//!
//! `POST /api/incidents` blocks until the pipeline finishes (or gives up) and
//! returns the full outcome — no job queue/polling, since a single incident
//! run is the whole request. That's the deliberate simplification: fine for
//! one operator triggering one incident at a time, not for concurrent load.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Json};
use axum::routing::{get, post};
use axum::Router;
use incident_response_system::pipeline::run_incident;
use incident_response_system::tools;
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::env;
use std::sync::Arc;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::GovernorLayer;

#[derive(Clone)]
struct AppState {
    pool: PgPool,
    client: reqwest::Client,
    api_key: String,
    model: String,
}

#[derive(Deserialize)]
struct TriggerRequest {
    alert: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    let state = AppState {
        pool: PgPoolOptions::new()
            .max_connections(5)
            .connect(&env::var("DATABASE_URL").expect("DATABASE_URL must be set (see .env)"))
            .await?,
        client: reqwest::Client::new(),
        api_key: env::var("GROQ_API_KEY").expect("GROQ_API_KEY must be set (see .env)"),
        model: env::var("GROQ_MODEL").unwrap_or_else(|_| "openai/gpt-oss-120b".to_string()),
    };

    // Per-peer-IP token buckets (429 + Retry-After when exceeded, not a
    // silent delay). The expensive route gets its own, much stricter,
    // bucket: each /api/incidents call drives several Groq requests against
    // an already-tight free-tier TPM budget, so back-to-back triggers are
    // far more costly than a rapid GET on a read-only route.
    let incidents_limit = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(10)
            .burst_size(1)
            .finish()
            .expect("valid governor config"),
    );
    let reads_limit = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(1)
            .burst_size(20)
            .finish()
            .expect("valid governor config"),
    );

    let incidents_routes = Router::new()
        .route("/api/incidents", post(trigger_incident))
        .layer(GovernorLayer::new(incidents_limit));

    let read_routes = Router::new()
        .route("/", get(index))
        .route("/api/services", get(list_services))
        .route("/api/incidents/{id}/trace", get(get_trace))
        .layer(GovernorLayer::new(reads_limit));

    let app = incidents_routes.merge(read_routes).with_state(state);

    let addr = "127.0.0.1:3000";
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("IncidentIQ listening on http://{addr}");
    // GovernorLayer's per-peer-IP key extractor reads the connection's
    // SocketAddr from request extensions — into_make_service alone doesn't
    // populate that; without connect_info every request fails extraction.
    axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await?;
    Ok(())
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../../static/index.html"))
}

async fn list_services(State(state): State<AppState>) -> impl IntoResponse {
    match tools::get_services(&state.pool).await {
        Ok(services) => Json(json!(services)).into_response(),
        Err(e) => error_response(e.to_string()),
    }
}

async fn trigger_incident(State(state): State<AppState>, Json(req): Json<TriggerRequest>) -> impl IntoResponse {
    let outcome = run_incident(&state.pool, &state.client, &state.api_key, &state.model, &req.alert, None).await;
    match outcome {
        Ok(outcome) => Json(json!(outcome)).into_response(),
        Err(e) => error_response(e.to_string()),
    }
}

async fn get_trace(Path(incident_id): Path<String>) -> impl IntoResponse {
    // incident_id comes straight from the URL and feeds a filesystem path
    // below — reject anything that isn't our own generated shape before it
    // ever reaches std::fs, rather than trusting the caller.
    let is_safe = !incident_id.is_empty()
        && incident_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    if !is_safe {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid incident id" }))).into_response();
    }

    match std::fs::read_to_string(format!("traces/{incident_id}.jsonl")) {
        Ok(content) => {
            let events: Vec<Value> = content.lines().filter_map(|line| serde_json::from_str(line).ok()).collect();
            Json(json!(events)).into_response()
        }
        Err(_) => (StatusCode::NOT_FOUND, Json(json!({ "error": "trace not found" }))).into_response(),
    }
}

fn error_response(message: String) -> axum::response::Response {
    (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": message }))).into_response()
}
