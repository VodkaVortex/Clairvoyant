import json, os, tempfile

cp = {
  "version": 1,
  "intent_id": "i032",
  "branch": "tasklet-napi-softirq-lock",
  "snapshot": "s03",
  "status": "in_progress",
  "progress": "Initial checkpoint written before first search. Plan: enumerate tasklet_schedule/tasklet_hi_schedule callback bodies and NAPI poll functions in snapshots/s03 containing plain spin_lock, pair with process-context plain holders of the same lock objects. Known family leads from sibling snapshots: fs_enet tx_lock, altera_tse tx_lock, cassini tx_lock[]. Prior s03 xmit pass (fact f003) mapped fs_enet (NAPI poll line 99 vs close 765), enic, ftgmac100, ftmac100, ks8851, wl3501_cs, ipw2100; unresolved: mvneta pp->lock, ixgbe fdir_perfect_lock, bcm63xx_enet tx_lock.",
  "candidates": [],
  "timestamp": "2026-11-16"
}

path = os.environ["W"] + "/agent-state/checkpoints/i032.json"
d = os.path.dirname(path)
fd, tmp = tempfile.mkstemp(dir=d)
with os.fdopen(fd, "w") as f:
    json.dump(cp, f, indent=2)
os.replace(tmp, path)
print("checkpoint written:", path)
