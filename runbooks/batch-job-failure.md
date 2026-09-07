RUNBOOK: BATCH / NIGHTLY JOB FAILURE (low-criticality internal tools)

Applies to: internal-admin-tool, email-notification-service, and other
low-criticality services where a scheduled job (nightly batch, queue drain,
report generation) fails or reports errors in the logs export.

Symptoms:
* logs show ERROR or WARN entries tied to a scheduled job rather than live
  request traffic
* metrics for the service often look completely normal, since these jobs
  don't necessarily show up as request latency/cpu at all

Fix:
* re-run the job manually if it supports a manual trigger
* if it does not, this is generally low urgency given the service's
  criticality tier - a next-scheduled-run retry is often acceptable
* do not treat this with the same urgency as a critical-service incident;
  paging on-call for a low-criticality batch job failure is generally
  overkill unless it's been failing repeatedly across multiple runs
