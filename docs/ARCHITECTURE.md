# Architecture

## Responsibilities

Clairvoyant owns durable project state: Projects, Intents, Facts, leases,
heartbeats, and resumable scheduling. Claude Code supplies the model tool loop.
The adapter in `adapter/worker.py` translates between those two systems and
enforces the source/evaluation boundary.

The work is divided into three roles:

1. **Bootstrap** derives a transferable mechanism profile from the seed.
2. **Reason** plans narrowly scoped work. One `(snapshot, branch)` pair becomes
   one Intent.
3. **Explore** searches only its assigned opaque snapshot and writes one
   structured artifact before calling the terminal Done MCP tool.

## Evidence and signal are separate

The artifact is the evidence record. It retains source locations, literal
quotes, full reasoning, candidates, coverage gaps, and limitations for later
verification and evaluation.

The database Fact is a short decision card. It contains only:

- intent, snapshot, branch, and execution status;
- each usable finding's location, confidence, and one-line conclusion;
- unresolved candidate locations and one-line follow-up conclusions;
- concrete coverage gaps;
- the artifact path.

Quotes, long reasons, and generic limitations are not copied into Facts. Short
fields are accepted only as complete single lines of at most 300 characters.
An unusable short field drops that complete card entry rather than truncating a
sentence or rejecting Done. The total card budget is 8192 UTF-8 bytes; complete
finding lines are removed before follow-up lines if the budget is exceeded.

## Done path

The Explore model writes the artifact and supplies the one-line conclusions.
`adapter/done_tool.py` then:

1. validates only the artifact's completion identity and top-level structure;
2. constructs the short Fact card directly from the artifact;
3. atomically writes a terminal Done event.

The Done MCP is standalone inside Landlock and does not import `worker.py`.
After observing a terminal event, `worker.py` forwards its card unchanged; it
does not rebuild or semantically revalidate the card. This prevents a successful
Done call from being reversed by a second validation layer.

If a worker times out and fallback card construction fails, an existing artifact
whose `execution_status` is `complete` is preserved. Only the absence of a
complete artifact permits synthesis of a `timed_out` artifact.

## Explore Fact selection

Explore never receives the entire Fact graph. The adapter selects full short
cards using these rules:

| Existing Fact | Supplied to current Explore? |
|---|---:|
| Same snapshot, any branch | Yes |
| Different snapshot, same branch | Yes |
| Different snapshot and different branch | No |
| Fact that directly triggered the current Intent | Always |

The bootstrap mechanism summary is supplied separately. Stable prompt content
comes first, followed by the current intent, relevant cards, and recovery/output
paths so request-prefix caching remains useful.

## Sandboxing and evaluation boundary

Landlock exposes the assigned public snapshot read-only and the per-run state
directory read-write. Hidden revisions, target manifests, Git metadata, and the
frozen evaluator remain outside the model allow-list. Generated files live in a
private temporary directory.

The model cannot declare benchmark success. After artifacts are produced, the
frozen evaluator independently verifies source locations and computes historical
location recall. Exact-hunk recall is a location-recovery metric, not an
exploitability claim.

## Recovery

Intent state, Facts, artifacts, and checkpoints are durable. Stopping and
resuming a dispatcher does not reopen completed Intents. An in-flight model
request cannot resume from a partial token stream, but the Intent can restart
from its durable checkpoint and existing artifact. Leases left by an interrupted
dispatcher are explicitly released before native `project resume` and dispatch.
