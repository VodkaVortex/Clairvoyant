#!/usr/bin/env bash
set -uo pipefail

export CLAUDE_CODE_MAX_RETRIES=0

ROOT="/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster"
RUNNER="/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/run.py"
PREPARED="/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/benchmark_curated/prepared"
WORKSPACES="/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/benchmark_curated/workspaces"
REPO="/mnt/raid/home/yangshuangning/linux"
LOG_DIR="$ROOT/_rerun_logs_round3"

mkdir -p "$LOG_DIR"

run_one() {
    local label="$1"
    local workers="$2"
    local timeout="$3"
    local seed
    local rc

    seed="$(jq -r '.seed.hexsha' "$ROOT/$label/private/evaluation/manifest.json")"
    printf '[%s] START %s workers=%s timeout=%ss\n' "$(date --iso-8601=seconds)" "$label" "$workers" "$timeout"
    python3 -B "$RUNNER" run \
        --repo "$REPO" \
        --prepared-root "$PREPARED" \
        --workspaces-root "$WORKSPACES" \
        --seed "$seed" \
        --output "$ROOT/$label" \
        --model GLM-5.3 \
        --effort low \
        --workers "$workers" \
        --max-intents 16 \
        --worker-max-turns 100 \
        --worker-timeout 3600 \
        --timeout "$timeout" \
        >>"$LOG_DIR/$label.log" 2>&1
    rc=$?
    printf '[%s] DONE %s rc=%s\n' "$(date --iso-8601=seconds)" "$label" "$rc"
    return "$rc"
}

run_batch() {
    local spec
    local label
    local workers
    local timeout
    local rc=0
    local index
    local -a pids=()
    local -a labels=()

    for spec in "$@"; do
        IFS=: read -r label workers timeout <<<"$spec"
        run_one "$label" "$workers" "$timeout" &
        pids+=("$!")
        labels+=("$label")
    done
    for index in "${!pids[@]}"; do
        if ! wait "${pids[$index]}"; then
            printf '[%s] FAILED %s\n' "$(date --iso-8601=seconds)" "${labels[$index]}"
            rc=1
        fi
    done
    return "$rc"
}

printf '[%s] RERUN START total_open=52 max_concurrency=8\n' "$(date --iso-8601=seconds)"
overall=0

# One lower-pressure batch: 1 + 3 + 2 + 2 = 8 workers.
run_batch \
    C6:1:28800 \
    C7:3:28800 \
    C8:2:28800 \
    C9:2:28800 || overall=1

printf '[%s] RERUN END rc=%s\n' "$(date --iso-8601=seconds)" "$overall"
exit "$overall"
