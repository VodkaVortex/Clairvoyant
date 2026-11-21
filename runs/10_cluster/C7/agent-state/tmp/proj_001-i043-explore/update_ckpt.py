import json
ckpt = {
  "version": 1,
  "intent_id": "i043",
  "branch": "tasklet-napi-softirq-lock",
  "status": "finalizing",
  "snapshot": "s14",
  "progress": [
    {"step": "scan", "note": "Enumerated tasklet_init/tasklet_setup + netif_napi_add files in drivers/net, drivers/staging, drivers/atm, drivers/tty, drivers/usb, net; extracted callback bodies; correlated plain spin_lock expressions."},
    {"step": "candidates", "note": "18 raw hits triaged; solos-pci cli_queue_lock (console_show vs solos_bh), sc92031 priv->lock (tx_timeout/tasklet vs sc92031_tasklet), timbuart port->lock (line 92/1228-shaped process sites vs timbuart_tasklet), ath5k rxbuflock/block (softirq-side plain only), cxgb*/sge (txq restart tasklets), atmel serial port->lock (mixed) classified."}
  ],
  "candidates": [
    {"path": "drivers/atm/solos-pci.c", "line": 461, "status": "reported", "note": "console_show (sysfs DEVICE_ATTR_RW console, process context) takes cli_queue_lock with plain spin_lock at 461 while tasklet solos_bh (tasklet_init 1311, scheduled from hardirq solos_irq 762) takes the same lock at 868; missing spin_lock_bh."},
    {"path": "drivers/net/ethernet/silan/sc92031.c", "line": 1096, "status": "reported", "note": "sc92031_tx_timeout (ndo_tx_timeout, watchdog work context) plain spin_lock(&priv->lock) at 1096; tasklet sc92031_tasklet (tasklet_init 1461, scheduled from hardirq 895) takes same lock at 843; also plain site 949 in _sc92031_tx (ndo_start_xmit NET_TX softirq side - xmit branch overlap)."},
    {"path": "drivers/tty/serial/timbuart.c", "line": 92, "status": "reported", "note": "timbuart_enable_ms/putchar-adjacent process-side plain spin_lock(&port->lock) at 92 (and 1228-shaped flip push at 96-98) vs timbuart_tasklet (tasklet_init 454) taking uart->port.lock at 180 in tasklet softirq."}
  ]
}
open("/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/agent-state/checkpoints/i043.json","w").write(json.dumps(ckpt, indent=1))
