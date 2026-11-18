# Clairvoyant seed22 run4

This is the accepted GLM-5.3 Clairvoyant run for seed
`22ba97ea9cc1f63a0d0244fae38057ed452b6ac7`.

## Result

- Status: finished (non-provisional)
- Exact hunk recall: 2/4 (50%)
- Located recall: 2/4 (50%)
- Exact matches:
  - `2c054e17d9d4`: `net/packet/af_packet.c:tpacket_snd()`
  - `849b1664dbda`: `include/net/xdp_sock_drv.h:xsk_tx_metadata_request()`

The run used GLM-5.3 with 16 concurrent explore workers, at most 16 intents per
reasoning round, a 100-turn worker cap, a 3600-second worker timeout, and a
5400-second run timeout.

## Recorded artifacts

- `evaluation.json`, `evaluation.csv`, `findings.json`, and
  `artifact_validation.json`: frozen evaluator outputs.
- `public/*.json` and `public/TASK.md`: public model input metadata.
- `private/evaluation/manifest.json`: frozen evaluation manifest.
- `agent-state/clairvoyant.db`, `project.yaml`, `timeline.txt`, dispatcher
  prompts, checkpoints, findings, and terminal events: scheduler audit state.
- `agent-state/worker-logs/*.stream.jsonl`: raw observable Claude Code/GLM
  trajectories, including model messages, tool calls, and tool results.

The four materialized Linux source snapshots (`public/snapshots/`) and their
detached Git metadata (`private/snapshot-git/`) are intentionally omitted. They
are multi-gigabyte reproducible inputs rather than run results and can be
regenerated with `python3 run.py prepare`. Claude Code's machine-local config,
SDK debug logs, and worker scratch files are also omitted.
