import os, re, json
ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s01"
data = json.load(open(os.path.join(os.environ['TMPDIR'],'i016','timer_callbacks.json')))
print(list(data["timer_callbacks"].items())[:5])
# test: find definition of ath10k_htt_rx_ring_refill_retry
target = "ath10k_htt_rx_ring_refill_retry"
out = os.popen(f"grep -rn '{target}' {ROOT}/drivers/net/wireless/ath/ath10k/htt_rx.c").read()
print(out[:600])
