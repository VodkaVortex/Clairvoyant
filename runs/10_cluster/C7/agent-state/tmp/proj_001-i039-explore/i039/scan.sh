#!/bin/bash
# Enumerate NAPI poll functions and tasklet callbacks in s10 that contain plain spin_lock
cd /mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s10

echo "=== NAPI poll functions (netif_napi_add / netif_napi_add_weight) ==="
grep -rn "netif_napi_add\|netif_napi_add_weight" drivers/net net --include=*.c 2>/dev/null | grep -v "Documentation" | sed 's/:.*netif_napi_add.*(\s*/ POLLFN: /' | awk -F'POLLFN: ' '{print $2}' | grep -oE "[a-zA-Z0-9_]+\(" | tr -d '(' | sort -u > "$TMPDIR/i039/pollfns.txt"
wc -l "$TMPDIR/i039/pollfns.txt"

echo "=== tasklet callback functions (tasklet_init / tasklet_setup / DECLARE_TASKLET) ==="
grep -rhoE "tasklet_init\([^,]+,\s*[a-zA-Z0-9_]+|tasklet_setup\([^,]+,\s*[a-zA-Z0-9_]+" drivers/net net --include=*.c 2>/dev/null | grep -oE ",\s*[a-zA-Z0-9_]+$" | tr -d ', ' | sort -u > "$TMPDIR/i039/taskletfns.txt"
grep -rhoE "DECLARE_TASKLET\(\s*[a-zA-Z0-9_]+\s*,\s*[a-zA-Z0-9_]+" drivers/net net --include=*.c 2>/dev/null | grep -oE ",\s*[a-zA-Z0-9_]+$" | tr -d ', ' >> "$TMPDIR/i039/taskletfns.txt"
sort -u "$TMPDIR/i039/taskletfns.txt" -o "$TMPDIR/i039/taskletfns.txt"
wc -l "$TMPDIR/i039/taskletfns.txt"
