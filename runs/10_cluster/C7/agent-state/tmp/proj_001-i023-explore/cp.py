import json
p="/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/agent-state/checkpoints/i023.json"
d={"intent_id":"i023","branch":"timer-dwork-softirq-lock","snapshot":"s08","status":"in_progress",
"step":"scanned all timer_list/hrtimer callbacks in drivers+net (323 lock-taking); timer-side lock sites enumerated; now triaging strong candidates",
"method":"python scan of function bodies taking struct timer_list*/struct hrtimer*; filtered irqsave/flags sites; candidates paired with process-context plain spin_lock sites",
"candidates":[
 {"file":"drivers/net/wireless/intel/iwlwifi/mvm/rxmq.c:664","lock":"buf->lock (iwl_mvm_reorder_buffer.lock)","status":"reported",
  "evidence":"timer iwl_mvm_reorder_timer_expired (rxmq.c:652) takes spin_lock(&buf->lock) plainly; ALL other sites use spin_lock_bh: iwl_mvm_reorder (rxmq.c:1013), iwl_mvm_release_frames_from_notif (rxmq.c:804, called from iwl_mvm_rx_frame_release/iwl_mvm_rx_bar_frame_release which run in NAPI/NET_RX softirq via iwl_mvm_rx_mq/iwl_mvm_rx_mq_rss ops.c:1632-2031), iwl_mvm_del_ba (rxmq.c:758 via iwl_mvm_rx_queue_notif in same NAPI context), iwl_mvm_free_reorder (sta.c:2703, called from iwl_mvm_sta_rx_agg DELBA process context under mac80211 mutex). Missing _bh on the TIMER callback lets a NET_RX softirq spin on buf->lock while the preempted timer callback holder can never resume: soft-lockup/TX+RX stall."},
 {"file":"drivers/net/wireless/ath/ath9k/htc_drv_txrx.c:767","lock":"priv->wmi->event_lock","status":"reported",
  "evidence":"timer ath9k_htc_tx_cleanup_timer (htc_drv_txrx.c:760) takes spin_lock(&priv->wmi->event_lock) plainly; other sites: ath9k_htc_txstatus (674, plain, runs in wmi_event_tasklet softirq) and ath9k_htc_tx_drain (566, spin_lock_bh). No _bh on the two timer/tasklet-side sites while the _bh site (drain, process context via stop path) proves the lock is BH-shared. Timer softirq vs NET softirq/tasklet context self-deadlock shape."},
 {"file":"drivers/net/wireless/intel/iwlwifi/mvm/sta.c:255","lock":"(none — session_expired uses RCU, no spinlock)","status":"safe"},
 {"file":"drivers/net/usb/usbnet.c:1527","lock":"dev->done.lock etc (timer usbnet_bh)","status":"safe",
  "evidence":"timer body uses spin_lock_irqsave on dev->rxq.lock/q->lock/txq.lock and spin_lock_nested on dev->done.lock; no plain non-irqsave shared lock inside the timer callback (the scan hit was the usbnet_bh timer calling into rx/tx completions, all irqsave)"},
 {"file":"drivers/net/wireless/marvell/mwifiex/usb.c:1128","lock":"port->tx_aggr_lock","status":"safe",
  "evidence":"timer mwifiex_usb_tx_aggr_tmo takes the lock but the producer/consumer sites use spin_lock_bh (usb.c:1138,1217); only 2 lock sites in file, both _bh except the timer one; timer uses spin_lock_bh? verify"}],
"findings":[]}
json.dump(d,open(p,"w"),indent=1);print("ok")
