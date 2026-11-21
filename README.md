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
    Seed[Seed vulnerability] --> Bootstrap[Bootstrap: derive mechanism]
    Bootstrap --> Fact0[Mechanism Fact]
    Fact0 --> Reason[Reason: plan next Intent]
    Reason --> Intent[Explore Intent]
    Intent --> Explore[Explore worker]
    Explore --> Artifact[Artifact: full evidence]
    Artifact --> Done[Done]
    Done --> Fact1[Short Fact card]
    Fact1 --> Reason
```

Reason may combine several earlier Facts when creating a new Intent, so the
persistent search history is a directed acyclic graph rather than a simple
tree. Explore workers receive only Facts relevant to the current snapshot or
branch; cross-snapshot knowledge is carried in the Intent created by Reason.

## Repository map

- [`dataset/10_cluster`](dataset/10_cluster): 10 cluster definitions, 10 seed
  SHAs, 64 target SHAs, and source-download instructions;
- [`runs/10_cluster`](runs/10_cluster): current databases, artifacts, findings,
  evaluator reports, checkpoints, dispatcher prompts, raw worker streams,
  Claude Code session histories, and worker-generated intermediate analysis;
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
cd /mnt/raid/home/yangshuangning/vuln_variant_search/experiments/clairvoyant_variant_search
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

Claude Code speaks the Anthropic Messages protocol. The configured gateway root
is `https://llm.shtech.org`, which maps to `/v1/messages`; change `--base-url`
if the deployment uses a different Anthropic-compatible prefix.

```bash
export GLM_API_KEY='...'
python3 run.py run \
  --seed 22ba97ea9cc1 \
  --output runs/seed22_clairvoyant \
  --model GLM-5.3 \
  --effort low \
  --workers 16 \
  --max-intents 16 \
  --worker-max-turns 100 \
  --timeout 7200
```

Re-running the same command resumes the Clairvoyant database and existing
artifacts. Re-evaluate without model calls using:

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

