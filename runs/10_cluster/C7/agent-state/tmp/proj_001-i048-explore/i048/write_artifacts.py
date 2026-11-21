import json, os
CKPT="/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/agent-state/checkpoints/i048.json"
FINAL="/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/agent-state/findings/i048.json"

checkpoint = {
  "version": 1,
  "intent_id": "i048",
  "status": "finalizing",
  "branch": "hardirq-shared-lock",
  "snapshot": "s05",
  "method": "parsed 2616 non-macro request_irq/devm_request_irq/request_threaded_irq registrations in snapshots/s05, resolved 2134 handler names, found 2082 in-file definitions, extracted spinlock acquisitions in handler bodies (546 handlers with locks, 399 plain sites), cross-indexed handler-plain locks against all plain spin_lock sites in the same file (327 rows)",
  "classified": {
    "reported": ["drivers/tty/synclink_gt.c:1151-1160 set_params32 plain spin_lock(&info->lock) vs slgt_interrupt hardirq plain spin_lock(&port->lock)/(&info->lock) at 2362/2381, request_irq at 3638"],
    "safe": ["drivers/staging/comedi/drivers/ni_pcidio.c:365-368 poll's mite_channel_lock held only inside spin_lock_irqsave(&dev->spinlock) so local IRQs disabled; hardirq taker at 397 cannot preempt same CPU; other sites 299/322/346 use irqsave"]
  },
  "unresolved_top": ["mv_udc_core","emxx_udc","isp1760-udc","lpc32xx_udc","sbni","ens1370","zs","harmony","ravb_main","korg1212","winbond-840"]
}

finding_quote = "spin_lock(&info->lock);\n\tif (tmp_params.mode == MGSL_MODE_BASE_CLOCK) {"

final = {
  "version": 1,
  "intent_id": "i048",
  "branch": "hardirq-shared-lock",
  "execution_status": "complete",
  "snapshots_checked": ["s05"],
  "findings": [
    {
      "snapshot": "s05",
      "path": "drivers/tty/synclink_gt.c",
      "start": 1151,
      "end": 1160,
      "quote": finding_quote,
      "confidence": "high",
      "reason": "Untrusted trigger: any char-device ioctl(MGSL_IOCSPARAMS32) on an open synclink_gt serial port while the card raises its IRQ. Process-context chain: slgt_compat_ioctl (drivers/tty/synclink_gt.c:1184, case MGSL_IOCSPARAMS32 at 1195) -> set_params32 (1151) takes info->lock with plain spin_lock at 1159 and unlocks at 1176 with local hard IRQs enabled (no irqsave/irqrestore anywhere in the function; it then calls program_hw at 1178 after unlock). Hardirq chain: request_irq(port_array[0]->irq_level, slgt_interrupt, ...) at 3638 registers the non-threaded handler slgt_interrupt, which takes the same lock object (struct slgt_info.lock, declared at 273 with comment 'spinlock for synchronizing with ISR') with plain spin_lock at 2362 (its own port) and spin_lock(&port->lock) at 2381 while iterating every port_array[i] including the ioctl's port. Missing guarantee: every non-irq site of an ISR-shared lock must use spin_lock_irqsave/spin_lock_irq; here the process holder only disables preemption, so the device IRQ can preempt it on the same CPU and spin forever on a lock the preempted ioctl can never release. Counterevidence checked: sibling sites for the very same lock use spin_lock_irqsave(&info->lock, flags) at 778/788/830/859/878/954/969/987 and the non-compat MGSL_IOCSPARAMS path goes through set_params under irqsave, confirming the compat path is the outlier; ni_pcidio.c was audited as the contrasting safe case (its process-side mite_channel_lock acquisitions are nested inside an irqsave region). Impact: interrupt-context self-deadlock on one CPU, IRQ line storm/watchdog soft lockup, device stall; attacker needs the tty/ioctl to race a device interrupt, i.e. open device access plus concurrent line traffic.",
      "conclusion": "synclink_gt.c compat ioctl set_params32 holds info->lock with plain spin_lock (1159) while hardirq slgt_interrupt (request_irq:3638) takes the same ISR-shared lock plainly (2362/2381) - same-CPU IRQ preemption spins forever; high-confidence interrupt-context DoS."
    }
  ],
  "candidates": [
    {
      "snapshot": "s05",
      "path": "drivers/tty/synclink_gt.c",
      "line": 1159,
      "status": "reported",
      "reason": "set_params32 plain spin_lock(&info->lock) at 1159 (process context via slgt_compat_ioctl:1195) vs plain hardirq acquisitions of the same lock at 2362/2381 in slgt_interrupt registered at request_irq:3638; all sibling sites use irqsave.",
      "conclusion": "Reported as the primary finding: process-plain vs hardirq-plain on ISR-shared lock."
    },
    {
      "snapshot": "s05",
      "path": "drivers/staging/comedi/drivers/ni_pcidio.c",
      "line": 366,
      "status": "safe",
      "reason": "ni_pcidio_poll (COMEDI_POLL ioctl) takes mite_channel_lock at 366 only inside spin_lock_irqsave(&dev->spinlock) taken at 365, so local hard IRQs are disabled while the lock is held; hardirq nidio_interrupt (request_irq:952) takes dev->spinlock at 394 and mite_channel_lock at 397 plainly, but cannot preempt the IRQ-disabled holder on the same CPU, and the remaining mite_channel_lock sites 299/322/346 all use irqsave; the lock is devpriv-local (init at 905) with no other-file users.",
      "conclusion": ""
    },
    {
      "snapshot": "s05",
      "path": "sound/pci/ens1370.c",
      "line": 2349,
      "status": "unresolved",
      "reason": "Hardirq snd_audiopci_interrupt takes &ensoniq->reg_lock plainly at 2349 while the same expression is taken plainly at 814/840/1001/1018/1035/2153/2165; ALSA PCM hw_params/trigger/pointer callbacks commonly run in process context, but the enclosing functions and callers were not read.",
      "conclusion": "Follow up: identify the functions around ens1370.c 814/840/1001-1035/2153/2165 and confirm any runs in process context with IRQs enabled - a plain holder against the plain ISR taker at 2349 is a reportable hardirq lockup."
    },
    {
      "snapshot": "s05",
      "path": "drivers/usb/gadget/udc/mv_udc_core.c",
      "line": 2007,
      "status": "unresolved",
      "reason": "Hardirq mv_udc_irq takes &udc->lock plainly at 2007 and there are 9 other plain sites (1324,1342,1590,1642,1704,1714,1932,1945,1979); gadget ops (pullup, set_halt, bind/unbind) execute in process context, but no site was traced to its caller.",
      "conclusion": "Follow up: classify each plain spin_lock(&udc->lock) site in mv_udc_core.c by caller context; a process-context plain holder against the hardirq taker at 2007 confirms the defect."
    },
    {
      "snapshot": "s05",
      "path": "drivers/staging/emxx_udc/emxx_udc.c",
      "line": 2358,
      "status": "unresolved",
      "reason": "Hardirq handlers _nbu2ss_udc_irq (2358) and _nbu2ss_vbus_irq (2334) take &udc->lock plainly and plain sites also exist at 124,1664,1853,2241,2301,2321; gadget/unbind paths are likely process context but untraced.",
      "conclusion": "Follow up: trace emxx_udc.c plain udc->lock sites 124/1664/1853/2241/2301/2321 to their callers; any process-context plain holder against the hardirq takers at 2334/2358 is reportable."
    },
    {
      "snapshot": "s05",
      "path": "drivers/usb/gadget/udc/lpc32xx_udc.c",
      "line": 2740,
      "status": "unresolved",
      "reason": "Hardirq handlers lpc32xx_usb_lp_irq (2740), lpc32xx_usb_hp_irq (2779) and lpc32xx_usb_devdma_irq (2821) take &udc->lock plainly with 5 more plain sites (1432,1551,2287,2936,2949); stop/unbind paths are likely process context but untraced.",
      "conclusion": "Follow up: trace lpc32xx_udc.c plain spin_lock(&udc->lock) sites 1432/1551/2287/2936/2949; a process-context plain holder against the plain hardirq takers at 2740/2779/2821 confirms the defect."
    },
    {
      "snapshot": "s05",
      "path": "drivers/usb/isp1760/isp1760-udc.c",
      "line": 1276,
      "status": "unresolved",
      "reason": "Hardirq isp1760_udc_irq takes &udc->lock plainly at 1276 and 1315 while plain sites also exist at 284,325,513,548,592,651 (likely gadget ep ops that can run in process context).",
      "conclusion": "Follow up: classify isp1760-udc.c plain udc->lock sites 284/325/513/548/592/651 by caller context against the plain hardirq takers at 1276/1315."
    },
    {
      "snapshot": "s05",
      "path": "drivers/net/wan/sbni.c",
      "line": 509,
      "status": "unresolved",
      "reason": "Hardirq sbni_interrupt takes &nl->lock plainly at 509 while plain sites also exist at 451,475,1185,1223,1328,1392,1424; sbni exposes netdev/ioctl/proc paths that run in process context, but none was traced.",
      "conclusion": "Follow up: trace sbni.c plain nl->lock sites 1185/1223/1328/1392/1424 to their functions; any process-context plain holder against the ISR taker at 509 is reportable."
    },
    {
      "snapshot": "s05",
      "path": "drivers/tty/serial/zs.c",
      "line": 722,
      "status": "unresolved",
      "reason": "Hardirq zs_interrupt takes &scc->zlock plainly at 722 while 13 other plain sites exist (382,396,434,446,461,498,550,556,575,645,657,670,693); serial_core uart_ops can run in process context but whether those sites are wrapped by irqsave is undetermined.",
      "conclusion": "Follow up: classify each zs.c plain zlock site 382-693 by caller; a process-context plain holder against the ISR taker at 722 would confirm the defect."
    },
    {
      "snapshot": "s05",
      "path": "sound/parisc/harmony.c",
      "line": 300,
      "status": "unresolved",
      "reason": "Hardirq snd_harmony_interrupt takes &h->lock plainly at 187/195/205/214/224/231 while plain sites also exist at 300 and 336; ALSA trigger/prepare paths are process context but untraced.",
      "conclusion": "Follow up: read harmony.c around 300/336 and their callers; a process-context plain acquisition of h->lock against the plain ISR takers is a reportable defect."
    },
    {
      "snapshot": "s05",
      "path": "drivers/net/ethernet/renesas/ravb_main.c",
      "line": 807,
      "status": "unresolved",
      "reason": "Hardirq ravb_interrupt takes &priv->lock plainly at 807 while plain sites also exist at 723,856,886 (possibly nested helper handlers and NAPI poll); non-irq takers untraced.",
      "conclusion": "Follow up: map ravb_main.c interrupt dispatch and check whether any non-hardirq path (NAPI poll, ethtool, open/close) takes priv->lock plainly against the taker at 807."
    },
    {
      "snapshot": "s05",
      "path": "sound/pci/korg1212/korg1212.c",
      "line": 1109,
      "status": "unresolved",
      "reason": "Hardirq snd_korg1212_interrupt takes &korg1212->lock plainly at 1109/1169/1175 and a plain site exists at 1585 whose enclosing function and callers were not identified.",
      "conclusion": "Follow up: identify the enclosing function of korg1212.c line 1585 and its callers; a process-context plain acquisition against the hardirq takers at 1109/1169/1175 is reportable."
    },
    {
      "snapshot": "s05",
      "path": "drivers/net/ethernet/dec/tulip/winbond-840.c",
      "line": 1292,
      "status": "unresolved",
      "reason": "Hardirq intr_handler takes &np->lock plainly at 1141/1157 and a plain site exists at 1292 (likely a netdev path such as tx_timeout or ethtool) that was not traced.",
      "conclusion": "Follow up: trace winbond-840.c line 1292 to its function and callers; a process-context plain holder of np->lock against the hardirq taker at 1141 confirms the defect."
    }
  ],
  "coverage_gaps": [
    "Handler definition resolution found in-file bodies for 2082 of 2333 unique non-NULL handler names; the remaining 246 (macro-declared or defined in another file) were never checked for lock usage.",
    "Cross-indexing matched lock expressions only textually within the registering file, so locks shared across files via exported helpers or spelled differently (&priv->lock vs &dev->lock aliases) could be missed.",
    "request_threaded_irq sites were parsed for the primary handler only; acquisitions of handler-shared locks from the thread_fn (process context) were not separately audited.",
    "Only hardirq-side plain/irq acquisitions were cross-indexed; files where the handler uses irqsave but a process path still uses plain spin_lock against a different same-file IRQ context (e.g. chained irq handlers via irq_chip) were not enumerated."
  ],
  "limitations": [
    "Findings are static-analysis hypotheses: no compile or runtime reproduction was performed (read-only snapshot, no build tree).",
    "Lock-object identity for the reported finding relies on textual expression equality plus field declaration; pointer aliasing was not formally proven, though set_params32's info is by construction one of slgt_interrupt's port_array[] ports.",
    "Exploitability of the synclink_gt finding requires an attacker able to open the device and issue compat ioctls while line interrupts fire; permission requirements per deployment were not verified.",
    "Roughly 320 cross-index rows were produced and only the top 12 candidates were triaged; lower-ranked rows (e.g. mv_u3d_core, r8a66597, fusb300_udc, sgiseeq, 7990, pch_udc, net2280) were not read at all."
  ]
}

os.makedirs(os.path.dirname(FINAL), exist_ok=True)
for path, data in ((CKPT, checkpoint), (FINAL, final)):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)
    print("wrote", path)
