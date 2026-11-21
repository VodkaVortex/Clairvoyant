import json, os
ckpt = {
  "intent_id": "i031",
  "branch": "tasklet-napi-softirq-lock",
  "snapshot": "s02",
  "status": "in_progress",
  "phase": "initial checkpoint before search",
  "plan": [
    "verify sibling-branch bug families in s02: fs_enet tx_lock (NAPI vs close), altera_tse tx_lock (NAPI vs shutdown), cassini tx_lock[] (NAPI vs workqueue reset)",
    "enumerate tasklet_schedule/tasklet_init callbacks and NAPI poll fns taking plain spin_lock",
    "rank files by plain spin_lock density among tasklet/NAPI-containing files",
    "triage up to 12 candidates, classify reported/safe/unresolved"
  ],
  "candidates": []
}
path = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/agent-state/checkpoints/i031.json"
os.makedirs(os.path.dirname(path), exist_ok=True)
with open(path, "w") as f:
    json.dump(ckpt, f, indent=2)
print("written", path)
