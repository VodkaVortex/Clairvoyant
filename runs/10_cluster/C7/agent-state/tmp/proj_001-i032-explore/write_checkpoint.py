import json, os
ckpt = {
  "intent_id": "i032",
  "branch": "tasklet-napi-softirq-lock",
  "snapshot": "s03",
  "status": "in_progress",
  "plan": [
    "Verify known family shapes in s03: fs_enet tx_lock (NAPI poll vs close), altera_tse tx_lock, cassini tx_lock[], bcm63xx_enet rx_lock",
    "Enumerate tasklet_schedule/tasklet_setup + napi_schedule trigger sites in s03, rank files by plain spin_lock density",
    "Deep-read strongest candidates; classify reported/safe/unresolved",
    "Write final artifact and conclude"
  ],
  "candidates": []
}
path = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/agent-state/checkpoints/i032.json"
os.makedirs(os.path.dirname(path), exist_ok=True)
tmp = path + ".tmp"
with open(tmp, "w") as f:
    json.dump(ckpt, f, indent=2)
os.replace(tmp, path)
print("checkpoint written:", path)
