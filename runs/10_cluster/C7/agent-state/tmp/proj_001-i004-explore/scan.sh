#!/bin/bash
# For each driver file with ndo_start_xmit and plain spin_lock, check whether
# the same lock variable name is locked plain in some function AND also referenced
# in the xmit path (or vice versa) -> candidates.
SNAP=/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s03
cd "$SNAP"
while read f; do
  # lock vars taken with plain spin_lock in this file
  vars=$(grep -oE "spin_lock\(&[A-Za-z0-9_>.-]+" "$f" | sed 's/spin_lock(&//' | sort -u)
  for v in $vars; do
    # count of plain locks on this var
    n=$(grep -cE "spin_lock\(&$v" "$f")
    # any bh variant used on this var?
    bh=$(grep -cE "spin_lock_bh\(&$v" "$f")
    irq=$(grep -cE "spin_lock_irq(save)?\(&$v" "$f")
    if [ "$bh" = "0" ]; then
      echo "$f | var=$v plain=$n bh=$bh irqsave=$irq"
    fi
  done
done < "$1"
