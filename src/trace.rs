//! Structured JSON tracing across sub-agent handoffs. One JSON object per
//! event, appended to `traces/<incident_id>.jsonl` — `phase` on each event
//! *is* the sub-agent identity (Diagnose/Remediate/Communicate), so the
//! trace shows which sub-agent did what without a separate mapping.
//!
//! Flat file, not a DB table: nothing queries traces across incidents yet,
//! so a table would be speculative. Add one (same event shape) if that
//! changes.

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceEventKind {
    /// The scope guardrail rejected the alert before the model was ever called.
    Refused,
    ModelCall,
    ModelResponse,
    ToolCall,
    ToolResult,
    /// A sub-agent handoff: `detail` carries `from`/`to` and the summary
    /// that crossed the boundary.
    PhaseTransition,
}

#[derive(Debug, Serialize)]
pub struct TraceEvent {
    pub timestamp: DateTime<Utc>,
    pub incident_id: String,
    pub phase: String,
    pub event: TraceEventKind,
    pub detail: Value,
}

pub struct Tracer {
    incident_id: String,
    file: File,
}

impl Tracer {
    pub fn new(incident_id: &str) -> io::Result<Self> {
        fs::create_dir_all("traces")?;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(format!("traces/{incident_id}.jsonl"))?;
        Ok(Tracer { incident_id: incident_id.to_string(), file })
    }

    /// Appends one event and flushes immediately, so a crash mid-run still
    /// leaves a readable partial trace. A write failure here (e.g. disk
    /// full) is reported to stderr but never aborts the incident run —
    /// tracing is an observability side channel, not load-bearing.
    pub fn record(&mut self, phase: &str, event: TraceEventKind, detail: Value) {
        let event = TraceEvent {
            timestamp: Utc::now(),
            incident_id: self.incident_id.clone(),
            phase: phase.to_string(),
            event,
            detail,
        };
        let line = serde_json::to_string(&event).expect("TraceEvent always serializes");
        if let Err(e) = writeln!(self.file, "{line}").and_then(|_| self.file.flush()) {
            eprintln!("warning: failed to write trace event: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::BufRead;

    #[test]
    fn records_events_as_valid_jsonl() {
        let incident_id = "TEST-TRACE-001";
        let path = format!("traces/{incident_id}.jsonl");
        let _ = fs::remove_file(&path); // start clean

        let mut tracer = Tracer::new(incident_id).unwrap();
        tracer.record("Diagnose", TraceEventKind::ModelCall, json!({"model": "test-model"}));
        tracer.record(
            "Diagnose",
            TraceEventKind::ToolCall,
            json!({"name": "get_metrics_for_service", "args": {"service": "checkout-service"}}),
        );

        let file = File::open(&path).unwrap();
        let lines: Vec<String> = io::BufReader::new(file).lines().map(|l| l.unwrap()).collect();
        assert_eq!(lines.len(), 2);

        let first: Value = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(first["incident_id"], incident_id);
        assert_eq!(first["phase"], "Diagnose");
        assert_eq!(first["event"], "model_call");

        let second: Value = serde_json::from_str(&lines[1]).unwrap();
        assert_eq!(second["event"], "tool_call");
        assert_eq!(second["detail"]["name"], "get_metrics_for_service");

        fs::remove_file(&path).unwrap();
    }
}
