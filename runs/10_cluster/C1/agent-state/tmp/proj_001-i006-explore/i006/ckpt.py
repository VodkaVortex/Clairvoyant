import json, sys
p = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C1/agent-state/checkpoints/i006.json"
d = {
  "intent_id": "i006",
  "branch": "drm-userif-divisor",
  "snapshot": "s01",
  "status": "in_progress",
  "progress": [
    "Enumerated all 9 '8 * speed' tach sites in s01. vega10_thermal.c:320 (seed site, unfixed: speed==0 + ulMinRPM/ulMaxRPM only), smu7_thermal.c:280 (same raw-input-only checks), vega20_thermal.c:204 (only !speed), smu_v11_0.c:1217 (only speed==0), arcturus_ppt.c:1273 and smu_v13_0.c:1236 (both have !speed||speed>UINT_MAX/8 fix). radeon si/ci_dpm.c and amdgpu legacy si_dpm.c are inside #if 0 dead blocks.",
    "Verified reachability chain: hwmon fan1_target sysfs store amdgpu_hwmon_set_fan1_target (amdgpu_pm.c:2845 kstrtou32) -> amdgpu_dpm_set_fan_speed_rpm -> smu_set_fan_speed_rpm (amdgpu_smu.c:2714, rejects only U32_MAX) / pp_dpm_set_fan_speed_rpm (amd_powerplay.c:581, rejects only U32_MAX) -> ppt_funcs/hwmgr_func dispatch.",
    "Now broadening: scanning all numeric sysfs/debugfs/ioctl stores in s01 DRM tree for scaled-divisor patterns beyond fan RPM."
  ],
  "candidates": [
    {"path": "drivers/gpu/drm/amd/pm/powerplay/hwmgr/vega10_thermal.c", "line": 320, "status": "pending", "reason": "seed site unfixed in s01: raw-input-only checks (speed==0, ulMin/ulMaxRPM) before / (8*speed)"},
    {"path": "drivers/gpu/drm/amd/pm/powerplay/hwmgr/vega20_thermal.c", "line": 204, "status": "pending", "reason": "only !speed check before / (8*speed); reachable via pp_dpm_set_fan_speed_rpm"},
    {"path": "drivers/gpu/drm/amd/pm/swsmu/smu11/smu_v11_0.c", "line": 1217, "status": "pending", "reason": "only speed==0 check; reachable via navi10/sienna_cichlid ppt_funcs"},
    {"path": "drivers/gpu/drm/amd/pm/powerplay/hwmgr/smu7_thermal.c", "line": 280, "status": "pending", "reason": "raw-input-only checks; ulMin/ulMaxRPM firmware-derived gating to verify"},
    {"path": "drivers/gpu/drm/amd/pm/swsmu/smu11/arcturus_ppt.c", "line": 1273, "status": "safe", "reason": "has !speed || speed > UINT_MAX/8 guard"},
    {"path": "drivers/gpu/drm/amd/pm/swsmu/smu13/smu_v13_0.c", "line": 1236, "status": "safe", "reason": "has !speed || speed > UINT_MAX/8 guard"},
    {"path": "drivers/gpu/drm/amd/pm/legacy-dpm/si_dpm.c", "line": 6722, "status": "safe", "reason": "entire function inside #if 0 dead block (starts line 6681)"},
    {"path": "drivers/gpu/drm/radeon/si_dpm.c", "line": 6199, "status": "safe", "reason": "inside #if 0 dead block; radeon hwmon exposes no fan rpm store"},
    {"path": "drivers/gpu/drm/radeon/ci_dpm.c", "line": 1172, "status": "safe", "reason": "inside #if 0 dead block"}
  ],
  "findings": []
}
with open(p, "w") as f:
    json.dump(d, f, indent=2)
print("ok")
