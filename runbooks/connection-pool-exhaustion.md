# Runbook: Connection Pool Exhaustion (payment-gateway dependency)

**Symptoms:**
- p99 latency spikes well above baseline (2000ms+)
- Elevated error rate (5-10%)
- Logs show `connection pool exhausted, 0 available connections`
- Logs show `connection timeout to payment-gateway`
- CPU also elevated (requests piling up waiting on the pool)

**Likely cause:**
The service's connection pool to an upstream dependency (commonly payment-gateway)
has been fully checked out, usually because the upstream is slow/unresponsive and
connections aren't being released in time.

**Fix:**
1. Restart the affected pods to reset pool state and shed the backlog.
2. Confirm the upstream dependency (payment-gateway) is healthy before restarting,
   if possible — restarting into a still-degraded upstream will just refill the pool again.
3. If this recurs within 1 hour, escalate to the owning team instead of restarting
   again — repeated restarts without fixing the upstream is a loop, not a fix.
