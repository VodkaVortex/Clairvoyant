#!/bin/bash
ROOT=/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C7/public/snapshots/s13
echo "=== 1. rxe_do_task: tasklet registration and state_lock process sites ==="
grep -rn "tasklet_setup\|tasklet_init" $ROOT/drivers/infiniband/sw/rxe/rxe_task.c
grep -rn "rxe_do_task" $ROOT/drivers/infiniband/sw/rxe/ | head
echo "--- state_lock sites ---"
grep -rn "state_lock" $ROOT/drivers/infiniband/sw/rxe/*.c $ROOT/drivers/infiniband/sw/rxe/*.h
echo
echo "=== 2. ath9k_tasklet: registration ==="
grep -rn "tasklet_init\|tasklet_setup\|tasklet_schedule" $ROOT/drivers/net/wireless/ath/ath9k/main.c | head
echo "--- sc_pcu_lock sites in ath9k ---"
grep -rn "sc_pcu_lock" $ROOT/drivers/net/wireless/ath/ath9k/*.c $ROOT/drivers/net/wireless/ath/ath9k/*.h
echo
echo "=== 3. cc_lock sites ==="
grep -rn "cc_lock" $ROOT/drivers/net/wireless/ath/ath9k/*.c $ROOT/drivers/net/wireless/ath/ath9k/*.h
