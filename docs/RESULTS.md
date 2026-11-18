# Result snapshot

Snapshot time: **2026-11-18 18:19 HKT**.

## Aggregate

The current exact-hunk historical location recall is **22/64 (34.375%)**.
The earlier recorded value was **20/64 (31.25%)**, so the current run adds two
exact targets, an improvement of **3.125 percentage points**. Both new exact
targets are in C8, whose count moved from 3/12 to 5/12.

## Per-cluster metrics

| Cluster | Exact / measurable | Recall | Accepted findings | Run status |
|---|---:|---:|---:|---|
| C1 | 4 / 4 | 100% | 24 | budget_exhausted, provisional |
| C2 | 3 / 3 | 100% | 16 | finished |
| C3 | 3 / 3 | 100% | 21 | budget_exhausted, provisional |
| C4 | 0 / 2 | 0% | 20 | finished |
| C5 | 1 / 4 | 25% | 14 | finished |
| C6 | 1 / 5 | 20% | 50 | budget_exhausted, provisional |
| C7 | 1 / 14 | 7.143% | 62 | running snapshot |
| C8 | 5 / 12 | 41.667% | 133 | running snapshot |
| C9 | 0 / 13 | 0% | 57 | running snapshot |
| C10 | 4 / 4 | 100% | 51 | budget_exhausted, provisional |

At export time the active rerun had this durable progress:

- C7: 44 done, 3 leased, 10 open;
- C8: 43 done, 2 leased, 4 open;
- C9: 52 done, 2 leased, 12 open.

Because C7–C9 were still running, the 22/64 value is a provisional lower-bound
snapshot, not the final rerun result.

## Interpretation

An accepted finding is a structurally valid, source-backed location emitted by
an Explore artifact. An exact hit is stricter: the frozen evaluator associates
at least one accepted finding with the historical target's changed function or
exact hunk. Multiple findings may map to one target and therefore do not increase
the numerator beyond one.

No source quotes or raw reasons are included in this repository. Exact-hit
metadata is in `results/exact_hits.csv`; aggregate and per-cluster machine-readable
summaries are in `results/`.
