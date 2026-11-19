# Curated 10-cluster dataset

This directory contains the compact definition of the benchmark used by the
published Clairvoyant run: 10 seed vulnerabilities and 64 target variants.
Linux source trees are not vendored in this repository; every dataset member
is identified by its upstream Git commit SHA.

## Clusters and current result

| Cluster | Root-cause family | Members | Exact / targets | Hit rate |
| --- | --- | ---: | ---: | ---: |
| **C1** | Constant-multiplier wrap-to-zero divisor | 1 seed + 4 targets | **4 / 4** | **100%** |
| **C2** | One-byte tail read in a length-coded option parser | 1 + 3 | **3 / 3** | **100%** |
| **C3** | Mandatory netlink attributes checked with `AND` instead of `OR` | 1 + 3 | **3 / 3** | **100%** |
| **C4** | `proc_dointvec` failure ignored before post-processing | 1 + 2 | **0 / 2** | **0%** |
| **C5** | Double-fetch from attacker-writable memory after validation | 1 + 4 | **1 / 4** | **25%** |
| **C6** | Stale skb-derived pointer after head reallocation | 1 + 5 | **1 / 5** | **20%** |
| **C7** | Lock acquisition without bottom-half exclusion | 1 + 14 | **1 / 14** | **7.14%** |
| **C8** | Fixed USB endpoint index without endpoint-count validation | 1 + 12 | **6 / 12** | **50%** |
| **C9** | Unchecked allocation multiplication arithmetic | 1 + 13 | **0 / 13** | **0%** |
| **C10** | Non-NUL-terminated user buffer consumed as a C string | 1 + 4 | **4 / 4** | **100%** |
| **Total** | 10 families | **10 seeds + 64 targets** | **23 / 64** | **35.94%** |

## Files

- `selection.csv`: the 10 vulnerability patterns and their cluster labels;
- `members.csv`: all 74 commits, including the seed/target role;
- `seeds.csv`: one seed SHA and the expected target count per cluster.

## Download the source data

Clone the upstream Linux repository as a partial clone. Git fetches file blobs
on demand when a selected commit is materialized:

```bash
git clone --filter=blob:none --no-checkout \
  https://github.com/torvalds/linux.git linux
```

To materialize one member as an independent source snapshot, copy its SHA from
`members.csv` and run:

```bash
sha=4e3d9508c056d7e0a56b58d5c81253e2a0d22b6c
mkdir -p "snapshots/$sha"
git -C linux archive "$sha" | tar -x -C "snapshots/$sha"
```

Repeat that operation for the seed and target SHAs required by the cluster.
The extracted snapshots contain source files but no Git metadata.
