# Clairvoyant single-cluster Linux variant search

This adapter keeps the frozen benchmark and Clairvoyant core unchanged. It uses
Clairvoyant for durable `Project → Intent → Fact` scheduling and Claude Code for
each worker's tool loop, served by GLM-5.3.

## Search architecture

Bootstrap returns a structured mechanism `pattern` and up to four semantic
search branches. The adapter stores each branch definition verbatim in
`agent-state/branches.json` and automatically schedules one Intent for every
registered branch × snapshot pair. Explore receives the pattern, the original
branch definition, its single-snapshot assignment, relevant Fact cards, and
its recovery/output paths.

Reason discovers branches rather than constructing snapshot Intents itself.
When concluded Facts expose a genuinely new mechanism shape, Reason emits a
`branch` event and the adapter expands it across every snapshot. When all
registered pairs have concluded and Reason proposes no new branch, the adapter
completes the project. `--reason-fact-batch N` controls how many new Facts can
accumulate between Reason model calls; the default of 1 preserves immediate
fact-driven planning.

Finding conclusions, unresolved candidates, coverage gaps, and limitations are
carried in bounded Fact cards for later Reason calls. Full evidence remains in
the per-Intent JSON artifacts.

The Rust Framework remains an external local workspace. By default,
`build_clairvoyant.sh` builds `/mnt/raid/home/yangshuangning/Clairvoyant`; set
`CLAIRVOYANT_SOURCE` only when intentionally selecting another local checkout.

The compact ten-cluster definitions published with the newer architecture are
under `dataset/10_cluster/`; materialized Linux source snapshots are not stored
there.

## Security/evaluation boundary

- The model receives the public seed and opaque source trees only.
- Historical revisions, hidden targets, and the evaluation manifest stay under
  `private/`, outside the Landlock allow-list.
- Snapshot workspaces contain C/header files but no `.git` directory.
- Bootstrap has `Read`, `Grep`, `Glob`, and `Bash`; explore additionally has
  `Write`. Bash can run local compilation, tests, and static analysis. Source
  snapshots remain read-only and generated files go under each worker's
  private temporary directory. Edit, WebFetch, and NotebookEdit are disabled.
- The original frozen evaluator runs after Clairvoyant exits. Model-reported
  completion never counts as a hit.

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
  --reason-fact-batch 1 \
  --worker-max-turns 100 \
  --timeout 28800
```

Re-running the same command resumes the Clairvoyant database and existing
artifacts. Runs created before branch registries existed continue to use their
stored Intent descriptions, but Reason does not retroactively reschedule their
matrix. Re-evaluate without model calls using:

```bash
python3 run.py evaluate --output runs/seed22_clairvoyant
```

Important outputs:

- `agent-state/clairvoyant.db`: durable fact graph;
- `agent-state/branches.json`: mechanism pattern and registered branch definitions;
- `agent-state/timeline.txt`: intent/fact audit trail;
- `agent-state/worker-logs/`: raw Claude Code stdout/stderr;
- `agent-state/checkpoints/`: incremental per-intent recovery records;
- `agent-state/findings/`: per-intent structured artifacts;
- `findings.json`, `evaluation.json`, `evaluation.csv`: frozen benchmark result;
- `artifact_validation.json`: rejected or accepted source citations.

