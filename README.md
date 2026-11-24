# Clairvoyant

**Fact-guided, resumable Linux vulnerability-variant search.** Clairvoyant
turns one known vulnerability into a durable `Intent → Fact → Intent` graph,
then searches independent Linux snapshots for variants of the same root-cause
mechanism. Full source evidence is preserved in artifacts, while short Fact
cards carry only the information needed to plan the next search.

## Result at a glance

| Cluster | Root-cause family | Primary consequence | Exact / targets | Hit rate |
| --- | --- | --- | ---: | ---: |
| **C1** | Constant-multiplier wrap-to-zero divisor | Kernel crash | **4 / 4** | **100%** |
| **C2** | One-byte tail read in a length-coded option parser | Parser OOB/crash | **3 / 3** | **100%** |
| **C3** | Mandatory netlink attributes checked with `AND` instead of `OR` | NULL dereference/crash | **3 / 3** | **100%** |
| **C4** | `proc_dointvec` failure ignored before post-processing | Corruption/crash | **0 / 2** | **0%** |
| **C5** | Double-fetch from attacker-writable memory after validation | OOB/state corruption | **1 / 4** | **25%** |
| **C6** | Stale skb-derived pointer after head reallocation | UAF/OOB access | **1 / 5** | **20%** |
| **C7** | Process-context lock acquisition without bottom-half exclusion | Deadlock | **1 / 14** | **7.14%** |
| **C8** | Fixed USB endpoint index without endpoint-count validation | OOB/NULL dereference | **6 / 12** | **50%** |
| **C9** | Unchecked count-times-element-size allocation arithmetic | Heap corruption/crash | **0 / 13** | **0%** |
| **C10** | User buffer consumed as a C string without NUL termination | OOB read/info leak | **4 / 4** | **100%** |
| **Total** | 10 root-cause families | 64 hidden targets | **23 / 64** | **35.94%** |

## Search architecture

```mermaid
flowchart LR
    Seed[Seed vulnerability] --> Bootstrap[Bootstrap: pattern + branches]
    Bootstrap --> Registry[(branches.json)]
    Registry --> Schedule[Adapter: one Intent per branch x snapshot]
    Schedule --> Explore[Explore worker]
    Explore --> Artifact[Artifact: full evidence]
    Artifact --> Done[Done]
    Done --> Fact1[Short Fact card]
    Fact1 --> Reason[Reason: propose new branches]
    Reason --> Registry
```

Bootstrap returns the mechanism pattern and its search branches as structured
JSON. The adapter (`worker.py`) stores every branch definition once in
`agent-state/branches.json` and, without a model call, creates one Intent per
registered branch and snapshot. Each Explore worker receives the pattern, its
branch definition verbatim, its snapshot assignment, and the relevant Fact
cards, so no model rewrites a branch between Bootstrap and Explore.

Reason only discovers branches. Reason keeps the dispatcher's original triggers
(new Facts, new hints, or the last open Intent concluding); each call may
register new branches justified by the concluded Facts, which the adapter then
schedules on every snapshot. When Reason proposes no new branch and no Intent
is still open, the adapter completes the project. `--reason-fact-batch N` (default 1)
makes Reason call the model only after N new Facts; a new hint or the last
open Intent concluding still calls it immediately. Reason may
cite several earlier Facts for a new branch, so the persistent search history
is still a directed acyclic graph.

## Repository map

- [`dataset/10_cluster`](dataset/10_cluster): 10 cluster definitions, 10 seed
  SHAs, 64 target SHAs, and source-download instructions;
- [`runs/10_cluster`](runs/10_cluster): current databases, artifacts, findings,
  evaluator reports, checkpoints, dispatcher prompts, raw worker streams,
  Claude Code session histories, and worker-generated intermediate analysis;
- [`framework`](framework): the Clairvoyant Rust workspace, including the CLI,
  dispatcher, runtime, server, protocol, workers, and development tasks;
- `worker.py`, `done_tool.py`, `prompts/`: the Clairvoyant adapter and worker
  protocol.

The run dataset intentionally omits only the materialized Linux snapshot trees
(`public/snapshots`) and their local Git object stores (`private/snapshot-git`).
Those sources can be reconstructed from [`dataset/10_cluster`](dataset/10_cluster).
All non-source execution state is retained so that Intent creation, model tool
use, timeout/retry behavior, Fact generation, and final evaluation can be
analyzed after the run.

## Security and evaluation boundary

- Workers receive only the public seed and opaque source snapshots.
- Historical revisions, hidden targets, and the evaluation manifest remain
  outside the Landlock allow-list.
- Worker-visible snapshots contain source files but no `.git` directory.
- The frozen evaluator runs only after search and independently checks exact
  source locations.
- This benchmark measures historical location recovery, not exploitability or
  independent confirmation of a new vulnerability.

## Preflight

```bash
cd Clairvoyant
python3 run.py doctor
```

After exporting the key, verify the Claude Code → GLM-5.3 Messages transport
with one small, tool-free request:

```bash
export GLM_API_KEY='...'
python3 run.py api-smoke --model GLM-5.3
```

## Prepare one cluster without API calls

This materializes one C/header tree for each hidden peer snapshot. The initial
TOCTOU cluster has four snapshots and needs several GiB of disk.

```bash
python3 run.py prepare \
  --seed 22ba97ea9cc1 \
  --output runs/seed22_clairvoyant
```

## Run/resume one cluster

Claude Code speaks the Anthropic Messages protocol. Set
`GLM_ANTHROPIC_BASE_URL` or pass `--base-url` when using an
Anthropic-compatible gateway.

```bash
export GLM_API_KEY='...'
python3 run.py run \
  --seed 22ba97ea9cc1 \
  --output runs/seed22_clairvoyant \
  --model GLM-5.3 \
  --effort low \
  --workers 16 \
  --max-intents 16 \
  --reason-fact-batch 1 \
  --worker-max-turns 100 \
  --timeout 7200
```

Re-running the same command resumes the Clairvoyant database and existing
artifacts. Runs created before the branch registry existed (no
`agent-state/branches.json`) are not rescheduled by Reason; their Explore
workers still use the stored Intent text. Re-evaluate without model calls using:

```bash
python3 run.py evaluate --output runs/seed22_clairvoyant
```

Important outputs:

- `agent-state/clairvoyant.db`: durable fact graph;
- `agent-state/timeline.txt`: intent/fact audit trail;
- `agent-state/worker-logs/`: raw Claude Code stdout/stderr;
- `agent-state/claude-config/`: per-worker Claude Code session histories;
- `agent-state/tmp*/`: worker-generated intermediate scans and analysis files;
- `agent-state/checkpoints/`: incremental per-intent recovery records;
- `agent-state/findings/`: per-intent structured artifacts;
- `findings.json`, `evaluation.json`, `evaluation.csv`: frozen benchmark result;
- `artifact_validation.json`: rejected or accepted source citations.

