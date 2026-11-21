# i024 candidate log

## snapshot: s09, branch: timer-dwork-softirq-lock

### Candidate 1: drivers/usb/usbip/vudc_transfer.c v_timer (timer softirq) vs plain spin_lock(&udc->lock_tx) in v_recv_cmd_unlink kthread
- TIMER SIDE: timer_setup(&t->timer, v_timer, 0) vudc_transfer.c:450; v_timer body (302-442) runs in TIMER_SOFTIRQ.
  - Takes udc->lock with spin_lock_irqsave (line 313) -> HARDIRQ-safe on the main lock.
  - BUT takes udc->lock_tx with PLAIN spin_lock at line 419 (unlock 429), inside return_urb path.
- PROCESS SIDE: vudc_rx.c v_recv_cmd_unlink (62-86) runs in the vudc_rx kthread (v_rx_loop -> v_rx_pdu -> v_recv_cmd_unlink).
  - Line 79: spin_lock(&udc->lock_tx) PLAIN, held across v_enqueue_ret_unlink + wake_up, unlock line 82.
  - This is the kthread/process-context holder.
- Mechanism: TIMER softirq on same CPU as vudc_rx kthread: kthread holds lock_tx (plain), gets
  preempted by timer softirq (timer preempts BH-disabled-less process context), v_timer runs,
  reaches return_urb (urb->unlinked set by CMD_UNLINK - attacker controlled), spins on
  spin_lock(&udc->lock_tx) at 419 forever; holder never resumes -> soft lockup.
- lock_tx otherwise used: vudc_tx.c:191/213 spin_lock_irqsave (kthread), vudc_transfer.c:419 plain (timer).
  Zero spin_lock_bh on lock_tx in the driver. Mixed discipline: irqsave in tx kthread, plain in
  rx kthread and timer -> the lock is shared with a context that must not be preempted, but the
  process-context site (vudc_rx.c:79) uses plain spin_lock: the missing BH/IRQ-disable guarantee.
- Note asymmetry: v_timer's udc->lock acquisition IS irqsave; only lock_tx is plain in the timer.
- STATUS: pending final check of whether timer callback can really run while kthread preempted
  (TIMER softirq vs plain process context: YES, plain spin_lock does not prevent TIMER_SOFTIRQ).
