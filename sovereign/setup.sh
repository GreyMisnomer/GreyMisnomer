#!/usr/bin/env bash
set -euo pipefail

# GreyMisnomer Sovereign Instance Generator
# Bootstraps an independent sovereign registry with isolated authority and sequencer keys.

CHAIN_NAME="${1:-CCTS-India-Alpha}"
OUT_DIR="${2:-sovereign_instance}"

echo "══════════════════════════════════════════════════════════════════════"
echo "  GreyMisnomer Sovereign Registry Instance Bootstrapper               "
echo "══════════════════════════════════════════════════════════════════════"
echo "  Chain Name: $CHAIN_NAME"
echo "  Target Dir: $OUT_DIR"
echo "══════════════════════════════════════════════════════════════════════"

mkdir -p "$OUT_DIR"

# 1. Build CLI if not available
if ! command -v grey-misnomer-cli &> /dev/null; then
  echo "[1/4] Building grey-misnomer-cli from source..."
  cargo build --release -p grey-misnomer-cli
  CLI_BIN="target/release/grey-misnomer-cli"
else
  CLI_BIN="grey-misnomer-cli"
fi

# 2. Bootstrap the sovereign ledger
echo "[2/4] Generating genesis event and initial ledger state..."
$CLI_BIN init --chain-name "$CHAIN_NAME" --out "$OUT_DIR"

# 3. Create checkpoints directory
mkdir -p "$OUT_DIR/checkpoints"

echo "[3/4] Initializing local health check..."
$CLI_BIN status "$OUT_DIR/events.jsonl"

echo "[4/4] Sovereign instance generated successfully in: $OUT_DIR"
echo ""
echo "Next steps:"
echo "  1. Copy $OUT_DIR/events.jsonl and $OUT_DIR/manifest.json into your repository root."
echo "  2. Keep your authority and sequencer keys secure (store in .gmkey format)."
echo "  3. Commit and push to GitHub, then enable GitHub Pages in repo settings."
echo "══════════════════════════════════════════════════════════════════════"
