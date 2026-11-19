# Curated ten-cluster benchmark selection

This directory records the working cluster-level selection derived from the
frozen vulnerability catalog. It does not modify the source catalog or the
existing 10-family benchmark.

`selection.csv` defines the ten vulnerability patterns. `members.csv` freezes
the exact commit membership and the seed/target role used by each curated
cluster. `seeds.csv` is the compact execution index: one seed and the expected
target count for every cluster.

The curated benchmark contains 74 commits: 10 seeds and 64 hidden targets.
Every cluster has exactly one seed. Except for C5, seeds are selected
deterministically by sorting member SHAs and choosing the first commit that is
present in the Linux repository and whose full patch is at most 100,000 bytes.
All 74 members satisfy that usability check. This is the same mechanical policy
used by the existing large-scale benchmark and does not select seeds according
to model results.

The role column in `members.csv` has two values: `seed` is public model input;
`target` is hidden during search and used only by the frozen evaluator.

## C5 replacement

C5 is `rootcause-007b7fa54011`, attacker-writable memory double-fetch after
validation. Its fixed seed is `22ba97ea9cc1`; the other four members are hidden
targets. It replaces the previous working choice `rootcause-7860b770fb0d`
(KVM guest-memory double-fetch), which remains unchanged in the source catalog
but is not part of this curated ten-cluster selection.

The C5 inclusion invariant is: the attacker retains write access to the source
memory, the kernel validates one read or copy, and a later read or copy from the
same logical object controls consumption. The repair must ensure that the value
validated is the value consumed by using a kernel-owned snapshot or a single
cached read.
