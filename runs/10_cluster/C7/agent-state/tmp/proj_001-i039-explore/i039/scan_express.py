import subprocess, re, os
S="snapshots/s10"
# 1) find files with tasklet callback plain spin_lock
out = subprocess.run(["grep","-rln","--include=*.c","tasklet_init", "drivers","net","sound","block"],cwd=S2,capture_output=True,text=True).stdout.split()
