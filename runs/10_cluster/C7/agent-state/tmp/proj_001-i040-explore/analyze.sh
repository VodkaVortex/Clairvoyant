#!/bin/bash
# For each driver file with tasklet_init/tasklet_schedule, list spin_lock variants used
S11=/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s11
cd $S11
for f in $(/usr/bin/rg -l "tasklet_init\(|tasklet_setup\(" -g '*.c' drivers/net drivers/staging); do
  # only files that also acquire some lock with plain spin_lock(
  if /usr/bin/rg -q "spin_lock\(" "$f"; then
    plain=$(/usr/bin/rg -c "spin_lock\(" "$f")
    bh=$(/usr/bin/rg -c "spin_lock_bh\(" "$f" || echo 0)
    echo "$plain plain, $bh bh : $f"
  fi
done | sort -t' ' -k1 -rn | head -50
