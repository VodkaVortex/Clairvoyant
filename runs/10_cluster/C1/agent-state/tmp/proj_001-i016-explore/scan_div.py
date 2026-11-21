import re, os, subprocess, sys, json

ROOT = "/mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search/runs/10_cluster/C1/public/snapshots/s03"
# Candidate denominator tokens: identifiers; exclude pure constants
den_id = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')
# Match expressions containing '/' or '%' not inside comment-only line
DIV = re.compile(r'(?<![/\\*])(?<!//)(?<![!%<>=])/|(?<![%/])%')

results = []
keywords = ['pptable', 'powerplay', 'vbios', 'bios', 'acpi', 'smbios', 'edid', 'dtb', 'device_tree', 'of_', 'eeprom', 'eprom', 'rom_', '_rom', 'parser', 'parse_', '_parse', 'table']

for dirpath, dirnames, files in os.walk(ROOT):
    # prune
    rel = os.path.relpath(dirpath, ROOT)
    parts = rel.split(os.sep)
    if any(p in ('.git','Documentation','tools','samples','usr') for p in parts):
        continue
    if parts[0] == 'drivers' and len(parts)>1 and parts[1] not in ('gpu','clk','pinctrl','media','net','iio','hwmon','thermal','staging','misc','mfd','platform','ata','usb','firewire','infiniband','scsi','spi','i2c','watchdog','tty','video','fbdev','firmware','char','nvme','target','bcachefs','cpufreq','cpuidle','devfreq','opp','power','regulator','reset','rpmsg','soc','sound','vdpa','wwan','accel','auxdisplay','counter','dax','dma','edac','extcon','gnss','gpio','greybus','hid','hsi','hv','i3c','idle','industrialio','interconnect','irqchip','leds','lightnvm','mailbox','mc','mem','memory','message','mmc','most','mtd','nfc','nubus','nvdimm','parport','pci','pmdomain','powercap','pps','ptp','pwm','rapidio','remoteproc','rxrpc','s390','sbus','sh','sfi','smi','spi','spm','ssb','tee','thunderbolt','tty','uio','vfio','virtio','w1','zorro'):
        continue
    for fn in files:
        if not fn.endswith(('.c','.h')):
            continue
        path = os.path.join(dirpath, fn)
        rpath = os.path.relpath(path, ROOT)
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                text = f.read()
        except OSError:
            continue
        if '/' not in text and '%' not in text:
            continue
        # must mention firmware-ish keyword
        tl = rpath.lower()
        if not any(k in tl for k in keywords):
            continue
        # crude per-line scan
        for i, line in enumerate(text.splitlines(), 1):
            ls = line.strip()
            if ls.startswith('*') or ls.startswith('/*') or ls.startswith('//') or ls.startswith('#'):
                continue
            # find arithmetic div or mod
            for m in re.finditer(r'(?<=[\w\)\]])\s*[/%]\s*(?=[A-Za-z_(])', line):
                # extract char after operator
                rest = line[m.end():].lstrip()
                if not rest:
                    continue
                # parse next token
                tm = re.match(r'([A-Za-z_][A-Za-z0-9_]*)', rest)
                if tm and not tm.group(1) in ('usr','dev','NULL'):
                    results.append((rpath, i, line.rstrip()))
                break

for rpath, i, line in results:
    print(f"{rpath}:{i}: {line.strip()[:180]}")
print("TOTAL", len(results))
