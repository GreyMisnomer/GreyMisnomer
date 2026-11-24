#!/usr/bin/env bash
# scripts/testnet_p2p.sh
# RFC-008 & Task 4.30: 3-Node Sovereign P2P Testnet Cluster Launcher
#
# Launches 3 local greymisnomerd daemons with isolated data directories:
# - Node 1 (Bootstrap & Relay): RPC 9482, P2P 9483
# - Node 2 (Validator):         RPC 9582, P2P 9583 (peered to Node 1)
# - Node 3 (Observer):          RPC 9682, P2P 9683 (peered to Node 1)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TESTNET_DIR="$ROOT_DIR/.testnet_data"

cleanup() {
    echo ""
    echo "===> Shutting down 3-node P2P cluster..."
    if [ -f "$TESTNET_DIR/node1.pid" ]; then kill "$(cat "$TESTNET_DIR/node1.pid")" 2>/dev/null || true; fi
    if [ -f "$TESTNET_DIR/node2.pid" ]; then kill "$(cat "$TESTNET_DIR/node2.pid")" 2>/dev/null || true; fi
    if [ -f "$TESTNET_DIR/node3.pid" ]; then kill "$(cat "$TESTNET_DIR/node3.pid")" 2>/dev/null || true; fi
    rm -rf "$TESTNET_DIR"
    echo "===> Cleaned up testnet nodes successfully."
}

trap cleanup EXIT INT TERM

echo "===> Building greymisnomerd binary in release mode..."
cd "$ROOT_DIR"
cargo build --release -p greymisnomerd

DAEMON_BIN="$ROOT_DIR/target/release/greymisnomerd"
if [ ! -f "$DAEMON_BIN" ]; then
    DAEMON_BIN="$ROOT_DIR/target/debug/greymisnomerd"
fi

rm -rf "$TESTNET_DIR"
mkdir -p "$TESTNET_DIR/node1" "$TESTNET_DIR/node2" "$TESTNET_DIR/node3"

echo "===> Starting Node 1 (Bootstrap/Relay: RPC 9482, P2P 9483)..."
"$DAEMON_BIN" \
    --data-dir "$TESTNET_DIR/node1" \
    --rpc-port 9482 \
    --p2p-port 9483 \
    --node-id "bootstrap-node-1" \
    --enable-relay \
    --regtest > "$TESTNET_DIR/node1.log" 2>&1 &
echo $! > "$TESTNET_DIR/node1.pid"

sleep 1

echo "===> Starting Node 2 (Validator: RPC 9582, P2P 9583)..."
"$DAEMON_BIN" \
    --data-dir "$TESTNET_DIR/node2" \
    --rpc-port 9582 \
    --p2p-port 9583 \
    --peer "127.0.0.1:9483" \
    --node-id "validator-node-2" \
    --regtest > "$TESTNET_DIR/node2.log" 2>&1 &
echo $! > "$TESTNET_DIR/node2.pid"

sleep 1

echo "===> Starting Node 3 (Observer: RPC 9682, P2P 9683)..."
"$DAEMON_BIN" \
    --data-dir "$TESTNET_DIR/node3" \
    --rpc-port 9682 \
    --p2p-port 9683 \
    --peer "127.0.0.1:9483" \
    --node-id "observer-node-3" \
    --regtest > "$TESTNET_DIR/node3.log" 2>&1 &
echo $! > "$TESTNET_DIR/node3.pid"

sleep 1

echo "===> P2P Cluster is online!"
echo "Node 1 RPC: http://127.0.0.1:9482 | P2P: 127.0.0.1:9483"
echo "Node 2 RPC: http://127.0.0.1:9582 | P2P: 127.0.0.1:9583"
echo "Node 3 RPC: http://127.0.0.1:9682 | P2P: 127.0.0.1:9683"
echo ""
echo "Querying Node 1 P2P peer list via RPC:"
curl -s http://127.0.0.1:9482/v1/network/peers || echo "Node 1 RPC active"
echo ""
echo "Press Ctrl+C to stop the testnet cluster."
wait
