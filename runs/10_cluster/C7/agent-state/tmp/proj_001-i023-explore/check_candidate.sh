#!/bin/bash
F="/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s08/$1"
echo "=== $1 lock=$2"
echo "--- plain:"; /usr/bin/grep -n "spin_lock($2" "$F" 2>/dev/null || echo none
echo "--- bh:"; /usr/bin/grep -n "spin_lock_bh($2" "$F" 2>/dev/null || echo none
echo "--- irqsave:"; /usr/bin/grep -n "spin_lock_irqsave($2" "$F" 2>/dev/null || echo none
