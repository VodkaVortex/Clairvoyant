import json, os, datetime
ckpt = {
  "intent_id": "i041",
  "branch": "tasklet-napi-softirq-lock",
  "snapshot": "s12",
  "status": "in_progress",
  "updated": datetime.datetime.now().isoformat(),
  "phase": "initial checkpoint before first search",
  "plan": [
    "enumerate tasklet_schedule/tasklet_hi_schedule sites + tasklet callback bodies in drivers/ and net/",
    "enumerate NAPI poll registrations via netif_napi_add and napi_schedule sites",
    "intersect with plain spin_lock( users reachable from process context (workqueue, ioctl, open/close, firmware ops)",
    "deep-read strongest candidates; record lock name, softirq-side and process-side chains with file:line"
  ],
  "candidates": [],
  "findings": [],
  "notes": [
    "s12 is an older kernel tree (~5.10-era APIs); staging ks7010 absent in s12 (verified: no drivers/staging/ks7010)",
    "exclude xmit-callback and timer-callback paths (branches 1-2)"
  ]
}
path = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/agent-state/checkpoints/i041.json"
os.makedirs(os.path.dirname(path), exist_ok=True)
tmp = path + ".tmp"
with open(tmp, "w") as f:
    json.dump(ckpt, f, indent=2)
os.replace(tmp, path)
print("wrote", path)
