high cpu / scaling runbook

when cpu_percent sits above ~80% for a sustained period without an obvious error
spike alongside it, this is usually just under-provisioning for current traffic,
not a bug. check whether error_rate and latency are still roughly normal - if so,
this is a scaling problem, not a diagnosis problem.

fix: scale_service up within the safe auto-approved range first (+20%). if that
range isn't enough to bring cpu back under ~60%, that's outside the automatic
threshold and needs a human to confirm the larger scale-up, since we don't want
an agent unilaterally provisioning a big chunk of new infra.

note: don't restart pods for pure cpu pressure with no errors - a restart doesn't
fix a capacity problem, it just causes a short blip while the same load comes
right back.
