#!/bin/bash
# For each memdup_user call site, print the following 40 lines and flag string ops
cd /mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C10/public/snapshots/s03
while IFS=: read -r file line rest; do
  [ -z "$file" ] && continue
  start=$((line))
  end=$((line+40))
  body=$(sed -n "${start},${end}p" "$file")
  hits=$(echo "$body" | grep -nE 'sscanf|simple_strtol|simple_strtoul|simple_strtoull|strlen|strcmp|strchr|strscpy|strcpy|strcat|strstr|strsep|strnlen|kstrtoul|kstrtol|kstrtoint|match_token' | head -5)
  if [ -n "$hits" ]; then
    echo "=== $file:$line ==="
    echo "$hits"
  fi
done < $TMPDIR/s03_memdup_user.txt
