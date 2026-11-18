#!/usr/bin/env bash
set -uo pipefail

PROM_URL="http://10.10.3.1:3002/api/datasources/proxy/uid/ddyfngn31dg5cf/api/v1/query"
RUN_ROOT="/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster"
RUN_START_UTC="2026-11-15T14:11:29"
INTERVAL_SECONDS=30
LOG_DIR="$RUN_ROOT/_monitor_logs"
LOG_FILE="$LOG_DIR/sglang_watch_$(date -u +%Y%m%dT%H%M%SZ).log"

mkdir -p "$LOG_DIR"

query_value() {
    local query="$1"
    local response
    response="$(curl -fsS --max-time 10 --get --data-urlencode "query=$query" "$PROM_URL" 2>/dev/null)" || {
        printf 'nan'
        return
    }
    jq -r '.data.result[0].value[1] // "nan"' <<<"$response" 2>/dev/null || printf 'nan'
}

is_gt() {
    awk -v left="$1" -v right="$2" 'BEGIN { exit !(left + 0 > right + 0) }'
}

is_ge() {
    awk -v left="$1" -v right="$2" 'BEGIN { exit !(left + 0 >= right + 0) }'
}

running_query='sum(sglang:num_running_reqs{model_name="GLM-5.3"})'
queued_query='sum(sglang:num_queue_reqs{model_name="GLM-5.3"})'
grammar_query='sum(sglang:num_grammar_queue_reqs{model_name="GLM-5.3"})'
prefill_query='sum(sglang:num_prefill_inflight_queue_reqs{model_name="GLM-5.3"})'
decode_query='sum(sglang:num_decode_transfer_queue_reqs{model_name="GLM-5.3"})'
kv_query='avg(sglang:token_usage{model_name="GLM-5.3"})'
e2e_query='sum(rate(sglang:e2e_request_latency_seconds_sum{model_name="GLM-5.3"}[5m])) / sum(rate(sglang:e2e_request_latency_seconds_count{model_name="GLM-5.3"}[5m]))'

baseline_total=""
previous_errors=0

printf 'monitor_start=%s interval_seconds=%s run_start_utc=%s\n' \
    "$(date --iso-8601=seconds)" "$INTERVAL_SECONDS" "$RUN_START_UTC" | tee -a "$LOG_FILE"

while tmux has-session -t clairvoyant-open-8 2>/dev/null || pgrep -f '/clairvoyant_variant_search/worker.py --role' >/dev/null; do
    timestamp="$(date --iso-8601=seconds)"
    local_workers="$(pgrep -fc '^/usr/bin/python3 .*/clairvoyant_variant_search/worker.py --role' || true)"
    local_claude="$(pgrep -fc '^/mnt/raid/home/yangshuangning/claude-code-2[.]1[.]88/claude --bare' || true)"
    running="$(query_value "$running_query")"
    queued="$(query_value "$queued_query")"
    grammar="$(query_value "$grammar_query")"
    prefill="$(query_value "$prefill_query")"
    decode="$(query_value "$decode_query")"
    kv="$(query_value "$kv_query")"
    e2e="$(query_value "$e2e_query")"
    api_errors="$(rg --no-filename 'API error \(attempt' \
        "$RUN_ROOT"/{C6,C7,C8,C9}/agent-state/worker-logs/*.debug.log 2>/dev/null \
        | awk -v start="$RUN_START_UTC" '$0 >= start { count++ } END { print count + 0 }')"

    alerts=()
    total="nan"
    if [[ "$running" != "nan" && "$queued" != "nan" ]]; then
        total="$(awk -v a="$running" -v b="$queued" 'BEGIN { printf "%.0f", a + b }')"
        if [[ -z "$baseline_total" ]]; then
            baseline_total="$total"
        fi
        if is_ge "$total" "$((baseline_total + 16))" && (( local_claude <= 8 )); then
            alerts+=("GHOST_GROWTH")
        fi
    fi
    if [[ "$queued" != "nan" ]] && is_gt "$queued" 20; then
        alerts+=("QUEUE_GT_20")
    fi
    if [[ "$e2e" != "nan" ]] && is_gt "$e2e" 120; then
        alerts+=("E2E_GT_120S")
    fi
    if [[ "$kv" != "nan" ]] && is_ge "$kv" 0.95; then
        alerts+=("KV_NEAR_FULL")
    fi
    if (( api_errors > previous_errors )) && [[ "$total" != "nan" ]] \
            && is_ge "$total" "$((baseline_total + 8))"; then
        alerts+=("ERROR_WITH_GROWTH")
    fi
    previous_errors="$api_errors"

    alert_text="none"
    if ((${#alerts[@]})); then
        alert_text="$(IFS=,; printf '%s' "${alerts[*]}")"
    fi
    printf '%s workers=%s claude=%s running=%s queued=%s total=%s grammar=%s prefill_inflight=%s decode_transfer=%s e2e_s=%s kv_ratio=%s api_errors=%s alert=%s\n' \
        "$timestamp" "$local_workers" "$local_claude" "$running" "$queued" "$total" \
        "$grammar" "$prefill" "$decode" "$e2e" "$kv" "$api_errors" "$alert_text" \
        | tee -a "$LOG_FILE"

    sleep "$INTERVAL_SECONDS"
done

printf 'monitor_end=%s reason=experiment_session_ended\n' "$(date --iso-8601=seconds)" | tee -a "$LOG_FILE"
