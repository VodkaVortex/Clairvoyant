import json
cp = {
  "version": 1,
  "intent_id": "i039",
  "branch": "tasklet-napi-softirq-lock",
  "status": "in_progress",
  "snapshot": "s10",
  "stage": "initial - invariant derived",
  "invariant": "A spinlock reachable from a tasklet callback (tasklet_schedule/tasklet_hi_schedule body), NAPI poll (napi_schedule), or other NET_RX/NET_TX softirq callback must be acquired with spin_lock_bh()/local_bh_disable() at every BH-enabled process-context site (workers, ioctls, open/close, config, firmware); plain spin_lock on the process side allows a same-CPU softirq to spin forever against a preempted holder.",
  "exclusions": "ks7010 seed demo; xmit-callback paths (branch1, mwl8k stream_lock already found in s10, fact f004); timer/dwork callbacks (branch2, facts f023).",
  "candidates": [],
  "queries_planned": [
    "rg tasklet_init/DECLARE_TASKLET/tasklet_setup files",
    "rg netif_napi_add/napi_schedule files",
    "pair tasklet/poll bodies with lock exprs; find plain spin_lock process-context partners"
  ]
}
path = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/agent-state/checkpoints/i039.json"
with open(path, "w") as f:
    json.dump(cp, f, indent=2)
print("wrote", path)
