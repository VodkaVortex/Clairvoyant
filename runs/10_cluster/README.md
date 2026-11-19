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
