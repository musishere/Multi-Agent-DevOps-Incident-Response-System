# Runbook: Elevated Error Rate After a Recent Deploy

**Symptoms**
- Error rate climbs shortly after a new deploy lands (check deploy timestamps against
  the start of the error window)
- Latency may or may not move — a bad deploy can break correctness without
  necessarily being slow
- Logs often show application-level errors (stack traces, 5xx from the service
  itself) rather than upstream timeouts

**Fix**
- `rollback_deployment` to the last known-good version. This is always a
  confirm-required action regardless of service criticality — a rollback has a
  large blast radius and isn't something to automate away.
- Do not attempt a `restart_pod` here — restarting a bad build just restarts the
  bug, it doesn't fix it.
- Notify the owning team once the rollback is confirmed, since they'll need to
  investigate the bad deploy before re-attempting it.
