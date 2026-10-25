#!/usr/bin/env bash
#
# Solana FHE Starter: set up, build, and check, in one step.
#
# Installs the toolchains this project needs if they are missing (Rust, and the
# Solana CLI that provides cargo-build-sbf), builds the program and the client,
# and runs both test suites. Every install command is printed before it runs.
#
#   ./setup.sh          install what is missing, then build and test
#   ./setup.sh --build  skip installation, only build and test
#
# Afterwards:  scripts/demo.sh

set -euo pipefail

BUILD_ONLY=0
for arg in "$@"; do
  case "$arg" in
    --build) BUILD_ONLY=1 ;;
    -h|--help) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "setup: unknown argument: $arg" >&2; exit 2 ;;
  esac
done

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }
run()  { printf '  $ %s\n' "$*"; "$@"; }

OS="$(uname -s)"
case "$OS" in
  Darwin|Linux) ;;
  *) echo "setup: this script covers macOS and Linux. On Windows, use WSL." >&2; exit 1 ;;
esac

have() { command -v "$1" >/dev/null 2>&1; }

# Toolchains installed by a previous run of this script live here.
[ -x "$HOME/.cargo/bin/cargo" ] && PATH="$HOME/.cargo/bin:$PATH"
[ -d "$HOME/.local/share/solana/install/active_release/bin" ] &&
  PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"
export PATH

# ------------------------------------------------------------------ toolchain

if [ "$BUILD_ONLY" -eq 0 ]; then
  if have cargo; then
    say "Rust $(cargo --version | awk '{print $2}') found"
  else
    say "Installing Rust (needed to build the program and the core crate)"
    run sh -c 'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal'
    PATH="$HOME/.cargo/bin:$PATH"
  fi

  if have cargo-build-sbf; then
    say "Solana $(solana --version | awk '{print $2}') found"
  else
    say "Installing the Solana CLI (provides cargo-build-sbf, the SBF linker)"
    run sh -c 'curl -sSfL https://release.anza.xyz/stable/install | sh'
    PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"
    note "Add this to your shell profile to keep the toolchain on PATH:"
    note "  export PATH=\"\$HOME/.local/share/solana/install/active_release/bin:\$PATH\""
  fi
fi

have cargo          || { echo "setup: cargo is still missing" >&2; exit 1; }
have cargo-build-sbf || { echo "setup: cargo-build-sbf is still missing" >&2; exit 1; }
have node           || { echo "setup: Node 20 or newer is required: https://nodejs.org" >&2; exit 1; }

# ---------------------------------------------------------------------- build

say "Installing client dependencies"
# --include=dev, because a NODE_ENV=production environment would otherwise skip
# the test and build toolchain.
run npm install --prefix cli --include=dev --no-audit --no-fund

say "Building the program for SBF"
run sh -c 'cd programs/fhe-vault && cargo build-sbf'

# The SBF build writes a fresh program keypair if none exists, which would
# disagree with declare_id!. Keep the two in step.
if [ ! -f target/deploy/fhe_vault-keypair.json ]; then
  note "no program keypair found; generate one with:"
  note "  solana-keygen new -o target/deploy/fhe_vault-keypair.json"
fi

say "Running the Rust tests"
run cargo test

say "Type checking and testing the client"
run npm run --prefix cli typecheck
run npm run --prefix cli test

say "Done"
note "Run the end-to-end demo:  scripts/demo.sh"
