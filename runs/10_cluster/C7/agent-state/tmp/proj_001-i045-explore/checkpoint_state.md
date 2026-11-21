# i045 progress
- Mapped 2839 irq registration sites -> 2790 with extracted handler names
- Extracted lock acquisitions inside handler bodies: 354 sites / 272 handlers
- Handler-side PLAIN spin_lock: 157 distinct locks (cross.tsv)
- Confirmed mtk_star_emac.c identical bug to s01 finding (s02 = older kernel ~6.5): handler 782 plain + NAPI 1185/1351 plain, zero irqsave anywhere on priv->lock.
- Next: triage remaining top candidates for a *process-context* plain holder (stronger than NAPI softirq side).
