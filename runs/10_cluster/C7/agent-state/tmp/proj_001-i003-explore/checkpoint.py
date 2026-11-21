import json, os, sys
ckpt = sys.argv[1]
data = {
  "intent_id": "i003",
  "snapshot": "s02",
  "branch": "xmit-softirq-lock",
  "status": "in_progress",
  "notes": [
    "seed ks7010 in s02 already fixed: tx_dev_lock uses spin_lock_bh (ks7010_sdio.c:398) - confirmed not reportable",
    "Candidates inspected so far: cw1200 queue/ps_state locks all use spin_lock_bh; wsm_cmd.lock/event_queue_lock/bss_loss_lock use plain spin_lock - need context analysis",
    "wilc1000 txq_spinlock uses irqsave everywhere - safe",
    "rtl8192e/rtl8712/gdm724x: no shared plain spin_lock xmit-path issues found yet"
  ]
}
with open(ckpt, "w") as f:
    json.dump(data, f, indent=2)
