//! The permission/guardrail layer — decides whether a remediation action
//! is auto-approved or needs human confirmation. This is what actually
//! gates the model's tool calls; the model can "decide" to call anything,
//! but only an `Auto` verdict here ever touches `remediation_log` as
//! `completed` — see `actions.rs`, which is the only caller.
//!
//! `Duplicate` is a distinct verdict from loop detection (`actions.rs`
//! checks recent history before consulting `check_*` at all) — it means
//! "this exact action was already attempted recently," not "denied."

const SCALE_AUTO_RANGE_PERCENT: i32 = 20;

#[derive(Debug, PartialEq)]
pub enum Tier {
    Auto,
    Confirm(String),
    Duplicate(String),
}

/// restart_pod (via execute_remediation): auto unless the service is critical.
/// Any action other than "restart_pod" is unrecognized here and always
/// requires confirmation — a fail-safe default, not an oversight.
pub fn check_execute_remediation(action: &str, criticality: &str) -> Tier {
    if action != "restart_pod" {
        return Tier::Confirm(format!(
            "unrecognized remediation action '{action}' requires confirmation"
        ));
    }
    if criticality == "critical" {
        Tier::Confirm("restart_pod on a critical service requires confirmation".into())
    } else {
        Tier::Auto
    }
}

/// scale_service: auto within ±20%, confirm outside it.
pub fn check_scale_service(target_percent: i32) -> Tier {
    if target_percent.abs() <= SCALE_AUTO_RANGE_PERCENT {
        Tier::Auto
    } else {
        Tier::Confirm(format!(
            "scale_service change of {target_percent:+}% is outside the auto-approved ±{SCALE_AUTO_RANGE_PERCENT}% range"
        ))
    }
}

/// rollback_deployment: never auto (high blast radius).
pub fn check_rollback_deployment() -> Tier {
    Tier::Confirm("rollback_deployment always requires confirmation (high blast radius)".into())
}

/// delete_resource: never auto (highest stakes; spec also calls for a
/// sandboxed dry-run first, not yet built).
pub fn check_delete_resource() -> Tier {
    Tier::Confirm("delete_resource always requires confirmation plus a sandboxed dry-run".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restart_pod_is_auto_unless_critical() {
        assert_eq!(check_execute_remediation("restart_pod", "low"), Tier::Auto);
        assert_eq!(check_execute_remediation("restart_pod", "medium"), Tier::Auto);
        assert!(matches!(
            check_execute_remediation("restart_pod", "critical"),
            Tier::Confirm(_)
        ));
    }

    #[test]
    fn unrecognized_action_always_needs_confirmation() {
        assert!(matches!(
            check_execute_remediation("wipe_database", "low"),
            Tier::Confirm(_)
        ));
    }

    #[test]
    fn scale_service_within_range_is_auto() {
        assert_eq!(check_scale_service(20), Tier::Auto);
        assert_eq!(check_scale_service(-20), Tier::Auto);
        assert_eq!(check_scale_service(0), Tier::Auto);
    }

    #[test]
    fn scale_service_outside_range_needs_confirmation() {
        assert!(matches!(check_scale_service(21), Tier::Confirm(_)));
        assert!(matches!(check_scale_service(-50), Tier::Confirm(_)));
    }

    #[test]
    fn rollback_and_delete_are_never_auto() {
        assert!(matches!(check_rollback_deployment(), Tier::Confirm(_)));
        assert!(matches!(check_delete_resource(), Tier::Confirm(_)));
    }
}
