import json, os

quote = "tach_period = 60 * crystal_clock_freq * 10000 / (8 * speed);"

findings = [
  {
    "snapshot": "s01",
    "path": "drivers/gpu/drm/amd/pm/swsmu/smu11/smu_v11_0.c",
    "start": 1195,
    "end": 1217,
    "quote": quote,
    "confidence": "high",
    "reason": ("Untrusted source: hwmon sysfs fan1_target store amdgpu_hwmon_set_fan1_target (drivers/gpu/drm/amd/pm/amdgpu_pm.c:2845 kstrtou32, call at :2862, gated only on pwm_mode==AMD_FAN_CTRL_MANUAL) passes the raw u32 to amdgpu_dpm_set_fan_speed_rpm -> smu_set_fan_speed_rpm (amdgpu_smu.c:2714-2728) which rejects ONLY speed==U32_MAX, then dispatches to ppt_funcs .set_fan_speed_rpm = smu_v11_0_set_fan_speed_rpm (registered navi10_ppt.c:3589 for Navi10/Navi14 and sienna_cichlid_ppt.c:3199 for Sienna Cichlid). Violated invariant: the only validation in smu_v11_0_set_fan_speed_rpm is 'if (speed == 0) return -EINVAL;' (line 1207) on the RAW input, while the value actually divided at line 1217 is the fixed-width u32 expression (8 * speed); for speed in {0x20000000, 0x40000000, 0x60000000} (each nonzero and != U32_MAX, so every check passes) the product wraps modulo 2^32 to exactly 0, so a validated nonzero user input becomes a zero divisor at the exact division width. Unsafe use: line 1217 'tach_period = 60 * crystal_clock_freq * 10000 / (8 * speed);' executes a 32-bit division by the wrapped-to-zero denominator while programming CG_TACH_CTRL TARGET_PERIOD, giving a kernel divide-by-zero oops / stalled PM programming (same reliability-bug consequence class as the seed vega10 CVE, structurally identical expression). Counterevidence checked: siblings arcturus_ppt.c:1269 and smu_v13_0.c:1229 in this same snapshot carry 'if (!speed || speed > UINT_MAX/8) return -EINVAL;' proving the guard is the upstream fix and its absence here is a genuine gap, not an unreachable path; the swsmu dispatcher rejects only U32_MAX; no clamp exists between the sysfs store and the division.")
  },
  {
    "snapshot": "s01",
    "path": "drivers/gpu/drm/amd/pm/powerplay/hwmgr/vega20_thermal.c",
    "start": 188,
    "end": 204,
    "quote": quote,
    "confidence": "high",
    "reason": ("Untrusted source: same hwmon fan1_target sysfs chain, powerplay leg: amdgpu_hwmon_set_fan1_target -> amdgpu_dpm_set_fan_speed_rpm -> pp_dpm_set_fan_speed_rpm (amd_powerplay.c:581-596, rejects ONLY rpm==U32_MAX) -> .set_fan_speed_rpm = vega20_fan_ctrl_set_fan_speed_rpm (vega20_hwmgr.c:4433). Violated invariant: vega20_fan_ctrl_set_fan_speed_rpm validates only 'if (!speed) return -EINVAL;' (line 194-195) and, unlike vega10, consults no ulMinRPM/ulMaxRPM limits at all, so ANY nonzero speed reaches line 204 where the divisor is the u32 expression (8 * speed); for speed in {0x20000000, 0x40000000, 0x60000000} (all pass speed!=0 and rpm!=U32_MAX) the product wraps to 0 and the division faults. Unsafe use: line 204 'tach_period = 60 * crystal_clock_freq * 10000 / (8 * speed);' in uint32_t width while programming mmCG_TACH_CTRL TARGET_PERIOD - integer divide by zero, kernel oops/DoS. Counterevidence checked: no UINT_MAX/8 guard anywhere in the file; sibling implementations arcturus_ppt.c:1269 and smu_v13_0.c:1229 in s01 carry the guard; the only upstream checks (speed==0 at function, U32_MAX at dispatcher) validate f's input, not f's output at division width.")
  },
  {
    "snapshot": "s01",
    "path": "drivers/gpu/drm/amd/pm/powerplay/hwmgr/smu7_thermal.c",
    "start": 262,
    "end": 280,
    "quote": quote,
    "confidence": "medium",
    "reason": ("Untrusted source: hwmon fan1_target sysfs chain via pp_dpm_set_fan_speed_rpm (amd_powerplay.c:581-596, rejects only U32_MAX) -> .set_fan_speed_rpm = smu7_fan_ctrl_set_fan_speed_rpm (smu7_hwmgr.c:5771) for CIK/VI powerplay ASICs. Violated invariant: the check set at lines 267-272 is exactly the seed's pre-patch set - bNoFan, ucTachometerPulsesPerRevolution==0, speed==0, and (speed < fanInfo.ulMinRPM) || (speed > fanInfo.ulMaxRPM) - all validating only the RAW input; the divisor at line 280 is the u32 expression (8 * speed), unproven nonzero at division width. ulMinRPM/ulMaxRPM come from the VBIOS thermal-controller table as ucFanMinRPM/ucFanMaxRPM (u8) * 100UL (process_pptables_v1_0.c:934-936, processpptables.c:1000-1003), i.e. max 25500 on well-formed tables, which bounds 8*speed far below 2^32; HOWEVER when the table reports ucFanMinRPM=ucFanMaxRPM=0 (zeroed/malformed VBIOS fan limits on a board that still reports a fan and tachometer), the bounds check degenerates to speed<0||speed>0 which is false for every speed, so speed=0x20000000 passes and 8*speed wraps to 0 at line 280 -> kernel divide-by-zero oops during CG_TACH_CTRL TARGET_PERIOD programming. This mirrors upstream's own judgment that the min/max checks were insufficient (the vega10 seed fix added the explicit UINT_MAX/8 bound precisely because table-derived limits cannot be trusted). Medium confidence because the wrap is gated on firmware-derived limits that normally block it, the same gating under which upstream still shipped the seed fix.")
  }
]

candidates = [
  {"snapshot": "s01", "path": "drivers/gpu/drm/amd/pm/swsmu/smu11/smu_v11_0.c", "line": 1217, "status": "reported",
   "reason": "smu_v11_0_set_fan_speed_rpm: only 'if (speed == 0)' (line 1207) before '/ (8 * speed)' at 1217 in u32; reachable from hwmon fan1_target (amdgpu_pm.c:2862) via smu_set_fan_speed_rpm (amdgpu_smu.c:2714, rejects only U32_MAX) and ppt_funcs registration navi10_ppt.c:3589 / sienna_cichlid_ppt.c:3199."},
  {"snapshot": "s01", "path": "drivers/gpu/drm/amd/pm/powerplay/hwmgr/vega20_thermal.c", "line": 204, "status": "reported",
   "reason": "vega20_fan_ctrl_set_fan_speed_rpm: only '!speed' (line 194), no min/max limits at all, before '/ (8 * speed)' at 204; reachable via pp_dpm_set_fan_speed_rpm (amd_powerplay.c:581, rejects only U32_MAX) and .set_fan_speed_rpm registration vega20_hwmgr.c:4433."},
  {"snapshot": "s01", "path": "drivers/gpu/drm/amd/pm/powerplay/hwmgr/smu7_thermal.c", "line": 280, "status": "reported",
   "reason": "smu7_fan_ctrl_set_fan_speed_rpm: seed-identical raw-input-only check set (speed==0 plus firmware u8-derived ulMin/ulMaxRPM at process_pptables_v1_0.c:934-936) before '/ (8 * speed)' at 280; wrap reachable when VBIOS fan RPM limits are zeroed while fan/tach present; otherwise blocked by max 25500 bound."},
  {"snapshot": "s01", "path": "drivers/gpu/drm/amd/pm/powerplay/hwmgr/vega10_thermal.c", "line": 320, "status": "unresolved",
   "reason": "The seed site itself, present UNFIXED in s01 (lines 309-313: speed==0 + ulMinRPM/ulMaxRPM only, no UINT_MAX/8 bound) before the identical division at 320. Confirmed vulnerable-by-reading but deliberately NOT reported as a finding because it is the seed demonstration location; its unpatched presence here validates that s01 predates the fix and motivates the sibling variants reported above."},
  {"snapshot": "s01", "path": "drivers/gpu/drm/amd/pm/swsmu/smu11/arcturus_ppt.c", "line": 1273, "status": "safe",
   "reason": "arcturus_set_fan_speed_rpm has 'if (!speed || speed > UINT_MAX/8) return -EINVAL;' (lines 1269-1270) before the identical '/ (8 * speed)' at 1273; the scaled divisor is proven nonzero at division width."},
  {"snapshot": "s01", "path": "drivers/gpu/drm/amd/pm/swsmu/smu13/smu_v13_0.c", "line": 1236, "status": "safe",
   "reason": "smu_v13_0_set_fan_speed_rpm has 'if (!speed || speed > UINT_MAX/8) return -EINVAL;' before '/ (8 * speed)' at 1236; used by smu_v13_0_0_ppt.c:3201 and smu_v13_0_7_ppt.c:2787."},
  {"snapshot": "s01", "path": "drivers/gpu/drm/amd/pm/legacy-dpm/si_dpm.c", "line": 6722, "status": "safe",
   "reason": "si_fan_ctrl_set_fan_speed_rpm is entirely inside an '#if 0' dead-code block beginning at line 6681 (ending '#endif' after line 6729), so the '/ (8 * speed)' at 6722 is never compiled."},
  {"snapshot": "s01", "path": "drivers/gpu/drm/radeon/si_dpm.c", "line": 6199, "status": "safe",
   "reason": "si_fan_ctrl_set_fan_speed_rpm is inside an '#if 0' dead block; additionally radeon's hwmon exposes only temp/pwm/freq attributes (no fan rpm store), so no user path exists even if compiled."},
  {"snapshot": "s01", "path": "drivers/gpu/drm/radeon/ci_dpm.c", "line": 1172, "status": "safe",
   "reason": "ci_fan_ctrl_set_fan_speed_rpm is inside an '#if 0' dead block (lines 1131-1181); unreachable from any user interface."},
  {"snapshot": "s01", "path": "drivers/gpu/drm/amd/pm/powerplay/hwmgr/smu7_hwmgr.c", "line": 5542, "status": "safe",
   "reason": "smu7_odn_edit_dpm_table (and vega10_hwmgr.c:5642) scales user input 'input_clk = input[i+1] * 100' in u32, but the wrapped product is re-validated by smu7_check_clk_voltage_valid / vega10_check_clk_voltage_valid against golden-table min/max and firmware overdrive limits before being stored in DPM tables, and the value is never used as a divisor; the only divisions nearby are by constants."},
  {"snapshot": "s01", "path": "drivers/gpu/drm/amd/pm/powerplay/hwmgr/smu7_hwmgr.c", "line": 5100, "status": "safe",
   "reason": "get_sclk_od/get_mclk_od (and vega10_hwmgr.c:5159/5212, vega20_hwmgr.c:1516/1551) use DIV_ROUND_UP(value * 100, golden_value) where the divisor golden_value is the firmware golden-table top DPM clock level, not a user-supplied value; the user value sits in the numerator, and the set-side handlers clamp value to <=20 (smu7/vega10) or divide only by the constant 100 (vega20_set_sclk_od:1504 od_sclk /= 100), so no user-derived zero/wrapped divisor exists."},
  {"snapshot": "s01", "path": "drivers/gpu/drm/amd/pm/swsmu/smu11/navi10_ppt.c", "line": 2625, "status": "safe",
   "reason": "navi10_od_edit_dpm_table (pp_od_clk_voltage sysfs path) range-checks every input[i+1] via navi10_od_setting_check_range against od_settings board limits and cross-checks against od_table GfxclkFmin/Fmax before storing into u16 table fields; no input value is used as a divisor or scaled into one; the analogous arcturus/sienna_cichlid profile-mode inputs are copied into an activity-monitor struct without kernel-side division."}
]

limitations = [
  "No compile or runtime reproduction was performed against real SMU/powerplay hardware: the wrap is established arithmetically (8 * 0x20000000 == 8 * 0x40000000 == 8 * 0x60000000 == 0 mod 2^32) and by source comparison with the two sibling implementations in s01 that carry the '!speed || speed > UINT_MAX/8' guard; no kernel oops trace was produced.",
  "Reachability requires the hwmon fan1_target node (root-owned 0644 on typical distros, the same trust boundary as the seed CVE) plus pwm1_enable set to AMD_FAN_CTRL_MANUAL (amdgpu_hwmon_set_fan1_target returns -ENODATA otherwise); the amdgpu_hwmon_is_visible APU-hiding rules were not re-verified line-by-line in this session.",
  "The smu7_thermal.c:280 and vega10_thermal.c:320 wraps are gated by firmware-derived ulMinRPM/ulMaxRPM (u8*100 <= 25500, process_pptables_v1_0.c:934-936 / processpptables.c:1000-1003 / vega10_processpptables.c:216-217,260-261): on well-formed tables the bound blocks the wrap; the zero-divisor is reachable only when the VBIOS thermal-controller table reports zeroed RPM limits while still declaring a fan and tachometer - firmware-dependent, hence medium confidence.",
  "Whether smu12 (renoir/vangogh) or other swsmu ASICs register additional .set_fan_speed_rpm implementations beyond the generic smu_v11_0/smu_v13_0 and the five powerplay/legacy entries enumerated here was not exhaustively confirmed; the grep covered drivers/gpu/drm/amd/pm registrations found (amdgpu_smu.c:3731, amd_powerplay.c:1588, smu7/vega10/vega20_hwmgr, arcturus/navi10/sienna_cichlid/smu_v13_0_0/smu_v13_0_7).",
  "The search broadened beyond fan RPM into pp_od_clk_voltage, pp_sclk_od/pp_mclk_od, power profile mode, smartshift bias and fan1_enable sysfs handlers (all pass-through or range-checked, no user-derived divisor) and pattern-scanned parenthesized scaled divisors across drivers/gpu/drm; AMD display DML hits are floating-point (no integer divide-by-zero) and i915 intel_dram.c:313 guards with '?: 1'. Non-fan DRM ioctl surfaces (i915/xe/msm/panfrost ioctls, nouveau debugfs) were only keyword-scanned, not exhaustively audited."
]

artifact = {
  "version": 1,
  "intent_id": "i006",
  "branch": "drm-userif-divisor",
  "execution_status": "complete",
  "snapshots_checked": ["s01"],
  "findings": findings,
  "candidates": candidates,
  "limitations": limitations
}

out = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C1/agent-state/findings/i006.json"
os.makedirs(os.path.dirname(out), exist_ok=True)
with open(out, "w") as f:
    json.dump(artifact, f, indent=2)
print("artifact written:", out)

# refresh checkpoint to final state
ck = {
  "intent_id": "i006",
  "branch": "drm-userif-divisor",
  "snapshot": "s01",
  "status": "complete",
  "progress": [
    "Enumerated all 9 '/ (8 * speed)' tach sites in s01; verified reachability chain amdgpu_pm.c:2845/2862 -> amdgpu_dpm.c:1495 -> amdgpu_smu.c:2714 (U32_MAX only) / amd_powerplay.c:581 (U32_MAX only) -> ppt_funcs/hwmgr_func registrations.",
    "Reported 3 variant findings: smu_v11_0.c:1217 (only speed==0), vega20_thermal.c:204 (only !speed), smu7_thermal.c:280 (seed-identical raw-input checks, firmware-gated).",
    "Classified safe: arcturus_ppt.c:1273 and smu_v13_0.c:1236 (both have UINT_MAX/8 guard), amdgpu legacy si_dpm.c:6722 and radeon si_dpm.c:6199 / ci_dpm.c:1172 (#if 0 dead blocks), smu7/vega10 OD input scaling (re-validated, never divisors), sclk/mclk OD DIV_ROUND_UP (firmware divisor, user value is numerator), navi10 od_edit (range-checked).",
    "vega10_thermal.c:320 (seed site, unfixed in s01) left unresolved/unreported per seed-exclusion rule.",
    "Final artifact written to findings/i006.json."
  ],
  "candidates": [{"path": c["path"], "line": c["line"], "status": c["status"]} for c in candidates],
  "findings": [{"path": f["path"], "start": f["start"], "end": f["end"], "confidence": f["confidence"]} for f in findings]
}
ckp = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C1/agent-state/checkpoints/i006.json"
with open(ckp, "w") as f:
    json.dump(ck, f, indent=2)
print("checkpoint written:", ckp)
