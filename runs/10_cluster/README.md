# Clairvoyant curated 10-cluster run

This directory records the initial large-scale Clairvoyant run and subsequent
resume rounds on the curated 10-cluster benchmark. The current aggregate
exact-hunk result is **20/64 (31.25%)**, up from the initial 17/64 archive.
The databases currently contain 237 concluded Intents and 49 open Intents; the
open set is C7=20, C8=17, and C9=12. Evaluations whose `run_status` is
`budget_exhausted` remain provisional.

| Cluster | Exact / targets |
| --- | ---: |
| C1 | 4 / 4 |
| C2 | 3 / 3 |
| C3 | 3 / 3 |
| C4 | 0 / 2 |
| C5 | 1 / 4 |
| C6 | 1 / 5 |
| C7 | 1 / 14 |
| C8 | 3 / 12 |
| C9 | 0 / 13 |
| C10 | 4 / 4 |

## Latest open-Intent resume

The latest bounded resume used eight local workers split C6=1, C7=3, C8=2,
and C9=2, with `CLAUDE_CODE_MAX_RETRIES=0` and an eight-hour outer budget. It
concluded four Intents: C6/i022, C6/i023, C8/i012, and C8/i035. All four
cluster runners ended at their wall-clock budget.

The run recorded 286 client connection resets. The first reset occurred on the
initial request, before retry amplification: an 80,645-token request waited
200.696 seconds without a first stream chunk. Failed requests had a median
context size of 93,064 tokens because Explore dispatches included the full,
accumulated Fact graph (roughly 326--347 KB for the largest C7--C9 prompts).
During the run, SGLang queue depth averaged 16.7 and peaked at 46; average
time-to-first-token was 57.8 seconds, of which 53.2 seconds was queue time.
Framework redispatch after a reset and delayed backend cancellation amplified
the initial long-context/token-capacity problem but did not cause the first
timeout.

The archive includes evaluator outputs, structured findings, checkpoints,
terminal events, dispatcher prompts, project exports, and each SQLite
blackboard. Large or reproducible local material is intentionally excluded:

- materialized Linux source snapshots under `public/snapshots/`;
- hidden Git snapshot metadata under `private/snapshot-git/`;
- Claude configuration, MCP runtime files, and temporary analysis products;
- raw worker stream/debug logs (retained only in the local experiment copy).

The benchmark definition and preparation metadata are stored in
`benchmark_curated/` at the repository's `experiments/` level.
