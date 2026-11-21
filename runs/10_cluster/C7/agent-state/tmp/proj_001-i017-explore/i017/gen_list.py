import os, re

root = "."
patterns = {
    "timer_setup": re.compile(r"timer_setup\s*\("),
    "setup_timer": re.compile(r"setup_timer\s*\("),
    "DEFINE_TIMER": re.compile(r"DEFINE_TIMER\s*\("),
    "hrtimer_init": re.compile(r"hrtimer_init\s*\("),
    "delayed_work": re.compile(r"INIT_DELAYED_WORK|DECLARE_DELAYED_WORK"),
    "spin_lock_plain": re.compile(r"(?<![a-zA-Z0-9_])spin_lock\s*\("),
    "spin_lock_bh": re.compile(r"spin_lock_bh|spin_lock_irqsave|spin_lock_irq\(|spin_lock_irqrestore|spin_lock_nested|local_bh_disable"),
}
results = {}
for dirpath, dirnames, filenames in os.walk(root):
    for fn in filenames:
        if not (fn.endswith(".c") or fn.endswith(".h")):
            continue
        p = os.path.join(dirpath, fn)
        try:
            with open(p, "r", errors="ignore") as f:
                text = f.read()
        except OSError:
            continue
        counts = {}
        for k, pat in patterns.items():
            counts[k] = len(pat.findall(text))
        if counts["timer_setup"] or counts["setup_timer"] or counts["DEFINE_TIMER"] or counts["hrtimer_init"] or counts["delayed_work"]:
            results[p] = counts
for p, c in sorted(results.items()):
    print(f"{p}\tT={c['timer_setup']}\tST={c['setup_timer']}\tDT={c['DEFINE_TIMER']}\tHRT={c['hrtimer_init']}\tDW={c['delayed_work']}\tPL={c['spin_lock_plain']}\tBH={c['spin_lock_bh']}")
