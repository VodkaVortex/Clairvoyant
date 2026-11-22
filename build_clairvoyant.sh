#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")" && pwd)"
cargo_home="$repo_root/.clairvoyant-cargo"
rustup_home="$repo_root/.clairvoyant-rustup"
target_dir="$repo_root/.clairvoyant-build"
source_dir="${CLAIRVOYANT_SOURCE:-$repo_root/framework}"

if [[ ! -x "$cargo_home/bin/cargo" ]]; then
  echo "isolated cargo is missing: $cargo_home/bin/cargo" >&2
  echo "install Rust first or set up the experiments-local toolchain" >&2
  exit 2
fi

env CARGO_HOME="$cargo_home" RUSTUP_HOME="$rustup_home" CARGO_TARGET_DIR="$target_dir" \
  "$cargo_home/bin/cargo" build --release --manifest-path "$source_dir/Cargo.toml" \
  -p clairvoyant-cli

echo "$target_dir/release/clairvoyant"

