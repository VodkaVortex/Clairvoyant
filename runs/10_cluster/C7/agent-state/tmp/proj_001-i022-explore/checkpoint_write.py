import json, os, sys
cp_path = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/agent-state/checkpoints/i022.json"
state = {
  "intent_id": "i022",
  "branch": "timer-dwork-softirq-lock",
  "snapshot": "s07",
  "status": "in_progress",
  "note": "Initial checkpoint before first search. Plan: enumerate timer_list/timer_setup/hrtimer/DEFERRABLE callbacks in snapshots/s07, find those acquiring plain spin_lock, then check process-context sites of the same lock object.",
  "candidates": [],
  "timestamp": "init"
}
os.makedirs(os.path.dirname(cp_path), exist_ok=True)
tmp = cp_path + ".tmp"
with open(tmp, "w") as f:
    json.dump(state, f, indent=2)
os.replace(tmp, cp_path)
print("wrote", cp_path)
