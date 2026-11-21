import json, os
ckpt = {
  "intent_id": "i041",
  "branch": "tasklet-napi-softirq-lock",
  "snapshot": "s12",
  "status": "in_progress",
  "phase": "initial - invariant derived, starting scan of s12",
  "invariant": "Lock shared between process-context code and tasklet/NAPI/NET-softirq callback code where the process side uses plain spin_lock() (no spin_lock_bh/local_bh_disable), so a same-CPU softirq can spin forever against a holder that cannot resume.",
  "plan": [
    "Enumerate tasklet_init/DECLARE_TASKLET/tasklet_schedule sites and NAPI poll registrations in s12",
    "Extract lock usage per softirq callback body and per driver directory",
    "Find locks used in both softirq callbacks and process-context functions with plain spin_lock on process side",
    "Deep-read strongest candidates; classify reported/safe/unresolved"
  ],
  "candidates_classified": [],
  "notes": []
}
out = os.environ.get("CKPT")
with open(out, "w") as f:
    json.dump(ckpt, f, indent=2)
print("wrote", out)
