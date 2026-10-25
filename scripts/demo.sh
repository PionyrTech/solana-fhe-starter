#!/usr/bin/env bash
#
# The end-to-end demo: a local validator, the program deployed to it, and an
# addition performed on a ciphertext inside the program.
#
# Starts a throwaway validator, deploys, runs the demo tier and then the standard
# tier, prints the compute units each one costs, and cleans up. Nothing touches
# devnet or mainnet and nothing leaves the machine.
#
#   scripts/demo.sh              both tiers
#   scripts/demo.sh --demo-only  skip the standard tier

set -euo pipefail

DEMO_ONLY=0
for arg in "$@"; do
  case "$arg" in
    --demo-only) DEMO_ONLY=1 ;;
    -h|--help) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "demo: unknown argument: $arg" >&2; exit 2 ;;
  esac
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

[ -x "$HOME/.cargo/bin/cargo" ] && PATH="$HOME/.cargo/bin:$PATH"
PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"
export PATH

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }

have() { command -v "$1" >/dev/null 2>&1; }
have solana-test-validator || { echo "demo: run ./setup.sh first" >&2; exit 1; }

LEDGER="${TMPDIR:-/tmp}/solana-fhe-starter-ledger"
RPC="http://127.0.0.1:8899"
WALLET="$HOME/.config/solana/id.json"
PROGRAM_KEYPAIR="$ROOT/target/deploy/fhe_vault-keypair.json"
PROGRAM_ID="$(grep -o 'declare_id!("[^"]*")' programs/fhe-vault/src/lib.rs | sed 's/.*"\(.*\)".*/\1/')"

VALIDATOR_PID=""
cleanup() {
  if [ -n "$VALIDATOR_PID" ] && kill -0 "$VALIDATOR_PID" 2>/dev/null; then
    say "Stopping the validator"
    kill "$VALIDATOR_PID" 2>/dev/null || true
    wait "$VALIDATOR_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# ------------------------------------------------------------------ validator

if solana --url "$RPC" cluster-version >/dev/null 2>&1; then
  say "Using the validator already listening on $RPC"
else
  say "Starting a throwaway validator"
  rm -rf "$LEDGER"
  solana-test-validator --reset --ledger "$LEDGER" >/dev/null 2>&1 &
  VALIDATOR_PID=$!
  for _ in $(seq 1 60); do
    solana --url "$RPC" cluster-version >/dev/null 2>&1 && break
    sleep 1
  done
  solana --url "$RPC" cluster-version >/dev/null 2>&1 ||
    { echo "demo: the validator did not come up" >&2; exit 1; }
  note "validator up (pid $VALIDATOR_PID)"
fi

solana config set --url "$RPC" --keypair "$WALLET" >/dev/null

# --------------------------------------------------------------------- wallet

if [ ! -f "$WALLET" ]; then
  say "Creating a local test wallet at $WALLET"
  solana-keygen new --no-bip39-passphrase --silent -o "$WALLET"
  chmod 600 "$WALLET"
fi
solana --url "$RPC" airdrop 500 >/dev/null 2>&1 || true

# ------------------------------------------------------------ program keypair

# cargo-build-sbf writes a keypair if none exists, and that key would disagree
# with the declare_id! in the source. Keep the deployed address and the source
# address the same one.
if [ ! -f "$PROGRAM_KEYPAIR" ]; then
  say "Generating a program keypair and syncing declare_id!"
  solana-keygen new --no-bip39-passphrase --silent -o "$PROGRAM_KEYPAIR"
  sed -i.bak "s/declare_id!(\"[^\"]*\")/declare_id!(\"$(solana-keygen pubkey "$PROGRAM_KEYPAIR")\")/" \
    programs/fhe-vault/src/lib.rs
  rm -f programs/fhe-vault/src/lib.rs.bak
  ( cd programs/fhe-vault && cargo build-sbf >/dev/null )
fi
PROGRAM_ID="$(solana-keygen pubkey "$PROGRAM_KEYPAIR")"

# ---------------------------------------------------------------------- build

say "Building the program"
( cd programs/fhe-vault && cargo build-sbf 2>&1 | tail -2 )

if solana --url "$RPC" program show "$PROGRAM_ID" >/dev/null 2>&1; then
  note "program $PROGRAM_ID is already deployed"
else
  say "Deploying $PROGRAM_ID"
  solana --url "$RPC" program deploy \
    --program-id "$PROGRAM_KEYPAIR" target/deploy/fhe_vault.so 2>&1 | tail -2
fi

# ----------------------------------------------------------------------- demo

run_tier() {
  local tier="$1" slots="$2"
  say "End-to-end run, $tier tier"
  ( cd cli && npx tsx src/cli.ts keygen "keys-${tier}.json" --params "$tier" )
  ( cd cli && npx tsx src/cli.ts onchain "keys-${tier}.json" --params "$tier" --slots "$slots" )
}

run_tier demo 7,3,200,54

if [ "$DEMO_ONLY" -eq 0 ]; then
  run_tier standard 1000,2000,3000,4000
fi

say "Done"
note "The secret keys are cli/keys-demo.json and cli/keys-standard.json."
note "They are gitignored. They are test keys; do not reuse them anywhere real."
