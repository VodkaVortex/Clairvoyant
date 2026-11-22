# Clairvoyant

This directory contains the Rust workspace used by the vulnerability-variant
search experiments in this repository. The command-line entry point is the
`clairvoyant-cli` package, which builds the `clairvoyant` binary.

Build it through the experiment wrapper:

```bash
experiments/clairvoyant_variant_search/build_clairvoyant.sh
```

Build artifacts and the isolated Rust toolchain are kept under ignored
directories in `experiments/`.

The optional CyberGym development commands in `xtask` read local paths from
`CYBERGYM_ROOT`, `CYBERGYM_DATA_ROOT`, `CYBERAGENT_ROOT`, and
`CLAIRVOYANT_ENV_FILE`. No machine-specific paths or credentials are stored in
the repository.
