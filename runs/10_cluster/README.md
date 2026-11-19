# Clairvoyant curated 10-cluster run

This directory records the current large-scale Clairvoyant run on the curated
10-cluster benchmark. The frozen evaluator reports **23/64 exact-hunk hits
(35.94%)**, up from the initial 17/64 archive and the previous 20/64 result.
All 300 persisted Intents are concluded; no open or leased Intent remains.
Evaluations whose saved `run_status` is `budget_exhausted` remain marked
provisional even though their databases now contain no open Intent.

| Cluster | Intents | Findings | Exact / targets |
| --- | ---: | ---: | ---: |
| C1 | 17 / 17 | 24 | 4 / 4 |
| C2 | 14 / 14 | 16 | 3 / 3 |
| C3 | 19 / 19 | 21 | 3 / 3 |
| C4 | 10 / 10 | 20 | 0 / 2 |
| C5 | 18 / 18 | 14 | 1 / 4 |
| C6 | 26 / 26 | 50 | 1 / 5 |
| C7 | 58 / 58 | 92 | 1 / 14 |
| C8 | 50 / 50 | 153 | 6 / 12 |
| C9 | 67 / 67 | 84 | 0 / 13 |
| C10 | 21 / 21 | 51 | 4 / 4 |
| **Total** | **300 / 300** | **525** | **23 / 64** |

The 525 findings are model-submitted candidates, not 525 confirmed
vulnerabilities. Only the 23 targets matched by the frozen evaluator count as
exact-hunk hits.

## Final open-Intent resume

The final resume reused the original C7--C9 databases and checkpoints and ran
only open Intents through Clairvoyant's native refill mechanism. It did not
rerun already concluded work. Aggregate concurrency was 16 workers, split
C7=5, C8=3, and C9=8. The final databases contain C7=58, C8=50, and C9=67
concluded Intents with zero open Intents.

Explore evidence remains in structured artifacts while database Facts use
short cards. Explore workers receive complete cards only from the same
snapshot or the same branch, plus the Fact that directly triggered the current
Intent. This avoids sending the full accumulated Fact graph to every worker.

During the monitored 16-worker run, SGLang queue depth averaged 3.25 and had a
median of zero. It was zero in 62.3% of samples and peaked briefly at 38. The
queue was therefore not a sustained runtime bottleneck.

Relative to the 20/64 archive, the three additional exact hits are all in C8:
usbvision in s10, ath9k_htc in s11, and hid-thrustmaster in s12. The latest
22-to-23 improvement is the s12 hid-thrustmaster finding from Intent i048.

The archive includes evaluator outputs, structured findings, checkpoints,
terminal events, dispatcher prompts, project exports, and each SQLite Fact
graph. Large or reproducible local material is intentionally excluded:

- materialized Linux source snapshots under `public/snapshots/`;
- hidden Git snapshot metadata under `private/snapshot-git/`;
- Claude configuration, MCP runtime files, and temporary analysis products;
- raw worker stream/debug logs retained only in the local experiment copy.

The benchmark definition can be downloaded from the organization repository's
[`experiments/benchmark_curated`](https://github.com/Yuuoniy/vuln_variant_search/tree/vodkavortex/seed-family-search/experiments/benchmark_curated)
directory; it is not duplicated in this repository.
