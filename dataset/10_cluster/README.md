# Curated 10-cluster dataset

This directory contains the compact definition of the benchmark used by the
published Clairvoyant run: 10 seed vulnerabilities and 64 target variants.
Linux source trees are not vendored in this repository; every dataset member
is identified by its upstream Git commit SHA.

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
