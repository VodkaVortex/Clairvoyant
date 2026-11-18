#!/usr/bin/env bash
set -euo pipefail

experiments_dir="$(cd "$(dirname "$0")/.." && pwd)"
cargo_home="$experiments_dir/.clairvoyant-cargo"
rustup_home="$experiments_dir/.clairvoyant-rustup"
target_dir="$experiments_dir/.clairvoyant-build"
source_dir="${CLAIRVOYANT_SOURCE:-/mnt/raid/home/yangshuangning/Clairvoyant}"

if [[ ! -x "$cargo_home/bin/cargo" ]]; then
  echo "isolated cargo is missing: $cargo_home/bin/cargo" >&2
  echo "install Rust first or set up the experiments-local toolchain" >&2
  exit 2
fi

env CARGO_HOME="$cargo_home" RUSTUP_HOME="$rustup_home" CARGO_TARGET_DIR="$target_dir" \
  "$cargo_home/bin/cargo" build --release --manifest-path "$source_dir/Cargo.toml" \
  -p clairvoyant-cli

echo "$target_dir/release/clairvoyant"

