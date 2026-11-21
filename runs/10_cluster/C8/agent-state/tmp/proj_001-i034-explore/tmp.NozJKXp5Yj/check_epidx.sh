#!/bin/bash
cd /mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C8/public/snapshots/s09
for hit in $(/usr/bin/rg -l "endpoint\[" drivers/media/usb/ | grep -v cx231xx); do
  /usr/bin/rg -n "endpoint\[[0-9a-zA-Z_]+\]" "$hit" | while IFS=: read -r ln rest; do
    start=$((ln-25)); [ $start -lt 1 ] && start=1
    if ! sed -n "${start},${ln}p" "$hit" | grep -q "bNumEndpoints"; then
      echo "NO-CHECK-IN-CONTEXT: $hit:$ln"
    fi
  done
done
