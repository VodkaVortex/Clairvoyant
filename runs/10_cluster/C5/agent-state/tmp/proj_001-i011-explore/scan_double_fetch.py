#!/usr/bin/env python3
"""Heuristic double-fetch scanner for Linux kernel snapshots.

Finds functions that contain >=2 fetch-family calls (get_user/put_user side,
copy_from_user, strncpy_from_user, etc.) AND a shared user-pointer token
appearing in >=2 fetch calls within the same function. Prints candidates.
"""
import os, re, sys, json

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."
FETCH = re.compile(
    r'\b(get_user|__get_user|unsafe_get_user|copy_from_user|__copy_from_user|'
    r'strncpy_from_user|strndup_user|memdup_user|vmemdup_user|vzalloc_user|'
    r'get_user_pages|import_ubuf|import_iovec|iovec_from_user|'
    r'copy_struct_from_user|check_zeroed_user|copy_from_user_ptrace|'
    r'peek_user|compat_get_user|__compat_get_user|copy_sigset_from_user)\s*\(')
# functions that legitimately re-fetch: put_user/copy_to_user excluded.

FUNC = re.compile(r'^(?:[A-Za-z_][\w]*\s+)+([A-Za-z_][\w]*)\s*\(')

SKIP_DIRS = {"Documentation", "tools", "samples", "usr", "rust", "scripts", ".git"}

def cfiles(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for f in filenames:
            if f.endswith((".c", ".h")):
                yield os.path.join(dirpath, f)

def split_functions(src):
    """Yield (name, startline, text) for each top-level-ish function."""
    lines = src.split("\n")
    n = len(lines)
    i = 0
    while i < n:
        m = FUNC.match(lines[i])
        if m and not lines[i].rstrip().endswith(";"):
            # find opening brace at col 0 or end of signature line
            depth = 0
            started = False
            j = i
            sig = m.group(1)
            # Heuristic: function body starts at first '{' at line start
            while j < n:
                s = lines[j]
                if not started:
                    if s.startswith("{"):
                        started = True
                        depth = 1
                    elif re.match(r'^[A-Za-z_].*\)\s*$', s) or s.rstrip().endswith(";"):
                        break
                    j += 1
                    continue
                depth += s.count("{") - s.count("}")
                if depth <= 0:
                    yield sig, i + 1, "\n".join(lines[i:j+1])
                    i = j
                    break
                j += 1
            if not started:
                pass
        i += 1

results = []
for path in cfiles(ROOT):
    try:
        src = open(path, "r", encoding="utf-8", errors="replace").read()
    except OSError:
        continue
    if "copy_from_user" not in src and "get_user" not in src and "strncpy_from_user" not in src:
        continue
    for name, ln, body in split_functions(src):
        fetches = FETCH.findall(body)
        if len(fetches) < 2:
            continue
        # collect call sites with their argument snippets
        sites = []
        for m in FETCH.finditer(body):
            # grab ~120 chars after the call
            tail = body[m.end():m.end()+140]
            sites.append((m.group(1), tail))
        # find shared tokens: identifiers appearing in >=2 fetch arg lists
        from collections import Counter
        token_hits = Counter()
        for _, tail in sites:
            ids = set(re.findall(r'[A-Za-z_][\w]*(?:\s*->\s*[A-Za-z_][\w]*)*', tail))
            for t in ids:
                if t in ("sizeof", "struct", "const", "unsigned", "void", "char", "int", "u32", "u64", "u16", "len", "size", "user"):
                    continue
                token_hits[t] += 1
        shared = [t for t, c in token_hits.items() if c >= 2]
        if not shared:
            continue
        results.append({
            "file": os.path.relpath(path, ROOT),
            "func": name,
            "line": ln,
            "nfetch": len(sites),
            "shared_tokens": shared[:8],
        })

results.sort(key=lambda r: (r["nfetch"], len(r["shared_tokens"])), reverse=True)
json.dump(results, open(sys.argv[2], "w"), indent=1)
print(f"total candidate functions: {len(results)}")
