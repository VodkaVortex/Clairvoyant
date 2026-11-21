import json, os, sys

ckpt_path = sys.argv[1]
state = {
  "version": 1,
  "intent_id": "i028",
  "branch": "timer-dwork-softirq-lock",
  "snapshot": "s13",
  "status": "in_progress",
  "progress": [
    "initial checkpoint written before first search",
    "plan: enumerate timer_list/hrtimer/delayed_work callbacks in snapshots/s13 whose bodies take plain spin_lock; pair each lock with process-context acquisition sites (workers, ioctls, open/close, config, firmware); triage top candidates incl. br_multicast multicast_lock, libiscsi frwd_lock, qdisc root_lock timers, cxgb4 ptp_lock, hostap ap_handle_timer"
  ],
  "candidates": [],
  "findings": []
}
os.makedirs(os.path.dirname(ckpt_path), exist_ok=True)
tmp = ckpt_path + ".tmp"
with open(tmp, "w") as f:
    json.dump(state, f, indent=2)
os.replace(tmp, ckpt_path)
print("wrote", ckpt_path)
