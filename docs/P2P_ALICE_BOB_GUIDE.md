# GreyMisnomer v2.0 — Alice & Bob P2P Live Guide (Genesis → First Mint → Transfer → Sync)

> **Purpose:** Step-by-step operator guide for running **two sovereign P2P nodes** (**Alice** as Genesis Sequencer Host and **Bob** as Verifier Peer) over TCP Port `9483`, covering Same-PC, Same-LAN Wi-Fi, and Cross-Internet (Tailscale / Router Port Forward / Self-Hosted VPS Relay) topologies.

---

## Architecture Overview: Who Hosts What?

1. **GitHub is only for distributing software**, NOT for running the live P2P ledger.
2. **Alice (Genesis Host)** initializes a fresh CSPRNG `genesis_v2.json` (which contains **zero private secrets**—only `chain_id`, `authority`, `sequencer` public key, and accredited VVBs) and keeps `genesis_keys.json` private on Alice's disk.
3. **Bob (Peer Node)** clones the repository from GitHub, receives Alice's public `genesis_v2.json` file, and dials Alice (`--peer <ALICE_HOST>:9483`).
4. **Full Independent Verification:** Every credit Mint, SplitTransfer, and BurnPoO synced over Port `9483` is cryptographically checked on Bob's node (Ed25519 VVB/Owner/Sequencer signatures, RFC 9162 `MerkleLogTree` roots, `uco_state_root`, `poo_archive_root`, and `apply_uco()` invariants) before committing to Bob's local `redb` database.

---

## Step 0: Pick Your Network Case (LAN vs Internet / Unknown)

Since Bob needs TCP access to Alice's Port `9483` (while Bob does **not** need inbound ports open on his own router), identify which topology matches Alice and Bob:

### Case A: Same Computer (Testing with 2 Terminals)
* Use `ALICE_HOST=127.0.0.1`
* Bob uses alternate ports (`--rpc-port 9582 --p2p-port 9583`).

### Case B: Same Wi-Fi / LAN
* On Alice's machine, find her local LAN IP:
  * macOS: `ipconfig getifaddr en0`
  * Linux: `hostname -I | awk '{print $1}'`
* Use `ALICE_HOST=<Alice_192.168.x.x>` and allow TCP Port `9483` in Alice's OS firewall (macOS "Allow incoming connections" prompt, or `sudo ufw allow 9483/tcp` on Linux).

### Case C: Across the Internet (or "Not Sure If Same LAN")
* **Option C1 — Tailscale (Zero router setup, works through CGNAT / hotspots):**
  1. Both Alice and Bob install free [Tailscale](https://tailscale.com/).
  2. Alice shares/connects and checks `tailscale ip -4` → returns `100.x.y.z`.
  3. Use `ALICE_HOST=100.x.y.z`.
* **Option C2 — Router Port Forwarding (Direct Internet):**
  1. Alice forwards **TCP Port `9483`** on her router to her PC's LAN IP.
  2. Get Alice's public IP via `curl -4 ifconfig.me` → use `ALICE_HOST=<Public_IP>`.
* **Option C3 — Both Behind Strict NATs via Self-Hosted Relay (`sovereign/relay/`):**
  1. Deploy a third node on a public VPS (`docker compose -f sovereign/relay/docker-compose.yml up -d` or run `greymisnomerd --genesis genesis_v2.json --enable-relay --p2p-port 9483`).
  2. Both Alice and Bob pass `--peer <VPS_IP>:9483`. Both dial outbound to the VPS relay and sync bidirectionally.

---

## Step 1: Build Both Binaries (Alice & Bob)

Run on **both Alice's and Bob's machines**:

```bash
git clone https://github.com/GreyMisnomer/GreyMisnomer.git
cd GreyMisnomer
cargo build --release -p greymisnomerd -p grey-misnomer-cli
```

*(If running behind an offline mirror/sandbox without internet after cloning, add `--offline`.)*

---

## Step 2: Alice Bootstraps Genesis (Alice's PC Only)

Run **once** on **Alice's machine**:

```bash
./target/release/greymisnomerd \
  --init-genesis \
  --data-dir ./alice_data \
  --chain-name "AliceBobNet"
```

This creates two files inside `./alice_data/`:
1. **`./alice_data/genesis_v2.json`** → **PUBLIC** (`chain_id`, `authority` pubkey, `sequencer` pubkey, accredited VVB pubkey). **Send this file to Bob!**
2. **`./alice_data/genesis_keys.json`** → **PRIVATE** (CSPRNG secrets for `authority`, `sequencer`, `vvb`, `alice`, and a sample `bob`). Keep this file secret on Alice's computer!

*(Inspect `genesis_keys.json` if you want to give Bob his sample pubkey/seed for quick testing, OR Bob can run `./target/release/grey-misnomer-cli keygen` to create his own sovereign Ed25519 keypair and send Alice his public key!)*

---

## Step 3: Alice Starts Her Genesis Host Daemon (Alice Terminal 1)

```bash
./target/release/greymisnomerd \
  --data-dir ./alice_data \
  --genesis ./alice_data/genesis_v2.json \
  --sequencer-keys ./alice_data/genesis_keys.json \
  --rpc-port 9482 \
  --p2p-port 9483 \
  --node-id "alice-genesis" \
  --enable-relay \
  --no-rpc-auth
```

Watch for:
- `Active role: Genesis Sequencer & Validator (signing checkpoints + P2P sync)`
- `[P2P Wire Mesh] Listening on 0.0.0.0:9483 (Node ID: alice-genesis)`
- `greymisnomerd RPC server listening on http://127.0.0.1:9482`

*(If using `--rpc-auth` without `--no-rpc-auth`, pass `--cookie ./alice_data/.cookie` to `grey-misnomer-cli` commands.)*

---

## Step 4: Alice Mints the First Credit & Transfers to Bob (Alice Terminal 2)

Open a **second terminal** on **Alice's PC**:

### 4A. Mint 10 Credits (`10_000_000` micro-units) to Alice
```bash
./target/release/grey-misnomer-cli tx-mint \
  --keys ./alice_data/genesis_keys.json \
  --credits 10 \
  --project "SOLAR-INDIA-01" \
  --rpc-url http://127.0.0.1:9482
```
Copy the printed `Created UCO:` value (`<TXID>:0`) — or inspect all active credits anytime:
```bash
./target/release/grey-misnomer-cli rpc-ucos --rpc-url http://127.0.0.1:9482
```

### 4B. Transfer 4 Credits from Alice to Bob
Get Bob's 64-char hex public key (`<BOB_PUBKEY>` — either from Bob's `grey-misnomer-cli keygen` or from `bob.pubkey` in `./alice_data/genesis_keys.json`):

```bash
./target/release/grey-misnomer-cli tx-transfer \
  --keys ./alice_data/genesis_keys.json \
  --actor alice \
  --input "<ALICE_MINT_TXID>:0" \
  --to "<BOB_PUBKEY>" \
  --credits 4 \
  --rpc-url http://127.0.0.1:9482
```

Alice's ledger is now at **`tree_size: 2`**:
- `<TRANSFER_TXID>:0` → `4` credits (`[0, 4_000_000)`) owned by **Bob**
- `<TRANSFER_TXID>:1` → `6` credits (`[4_000_000, 10_000_000)`) owned by **Alice**

---

## Step 5: Bob Connects & Automatically Syncs Alice's Ledger (Bob Terminal 1)

Bob places Alice's public `genesis_v2.json` in his `GreyMisnomer/` folder and runs:

```bash
./target/release/greymisnomerd \
  --data-dir ./bob_data \
  --genesis ./genesis_v2.json \
  --peer "<ALICE_HOST>:9483" \
  --rpc-port 9482 \
  --p2p-port 9483 \
  --node-id "bob-peer-1" \
  --no-rpc-auth
```

*(If Bob is on the **same PC** as Alice, change Bob's ports so they don't collide: `--rpc-port 9582 --p2p-port 9583 --peer 127.0.0.1:9483`.)*

**What happens automatically over Port `9483` within milliseconds:**
1. Bob dials `<ALICE_HOST>:9483` and exchanges `PeerPing` (`chain_id`, `tree_size`).
2. Bob sees Alice's `tree_size = 2 > 0` and sends `TileRequest { from_index: 0 }`.
3. Alice sends `TileResponse` containing Events `[0, 1]` and signed `CheckpointHeaderV2`.
4. Bob verifies Alice's Ed25519 sequencer signature, rebuilds the RFC 9162 Merkle tree, runs `apply_uco()` on both Mint & Transfer, verifies `uco_state_root` + `poo_archive_root`, and commits atomically to `./bob_data/chainstate.redb`.

### Verify on Bob's PC (Bob Terminal 2):
*(Use `--rpc-url http://127.0.0.1:9582` if same-PC.)*

```bash
# 1. Confirm peer connection
./target/release/grey-misnomer-cli rpc-peers --rpc-url http://127.0.0.1:9482

# 2. Confirm chain height caught up to tree_size: 2
./target/release/grey-misnomer-cli status --rpc-url http://127.0.0.1:9482

# 3. Inspect synced UCOs — Bob sees his 4-credit UCO independently!
./target/release/grey-misnomer-cli rpc-ucos --rpc-url http://127.0.0.1:9482
```

---

## Step 6: Bob Sends a Transaction Back Over P2P! (Bob Terminal 2)

Bob signs a transaction **using Bob's private key** (`<BOB_SECRET_HEX>`) and submits it to **Bob's own local daemon** (`127.0.0.1:9482`):

```bash
# Example: Bob retires 1.5 of his 4 credits as Proof-of-Offset (returning 2.5 change to Bob)
./target/release/grey-misnomer-cli tx-burn \
  --key "<BOB_SECRET_HEX>" \
  --input "<TRANSFER_TXID>:0" \
  --credits 1.5 \
  --beneficiary "Bob Carbon Neutrality 2026" \
  --rpc-url http://127.0.0.1:9482
```

What happens automatically:
1. Bob's node validates Bob's signature (`apply_uco`), puts the tx into Bob's mempool (`rpc-mempool`), and gossips `TxIntent` over Port `9483` to Alice.
2. Alice's Sequencer node verifies Bob's signature against Alice's `redb`, commits it (`tree_size: 3`), signs the new `CheckpointHeaderV2`, and broadcasts `CheckpointAnnouncement` back on Port `9483`.
3. Bob fetches `TileResponse` at height `3`, verifies Alice's checkpoint signature & state roots, prunes Bob's mempool, and commits `tree_size: 3`, `poo_count: 1`!

Confirm convergence on **both** machines:
```bash
./target/release/grey-misnomer-cli status --rpc-url http://127.0.0.1:9482
./target/release/grey-misnomer-cli rpc-ucos --rpc-url http://127.0.0.1:9482
```

---

## Troubleshooting Checklist

| Symptom | Cause & Fix |
|---|---|
| Bob's `rpc-peers` shows `Connected Peers: 0` | Test reachability from Bob: `nc -zv <ALICE_HOST> 9483`. If blocked/timeout: check Alice's OS firewall, router Port Forward `9483`, or switch both to Tailscale (`100.x.y.z`). |
| `tx-mint` fails with `UnknownVvb` | Ensure Alice started with `--genesis ./alice_data/genesis_v2.json` and signed with `--keys ./alice_data/genesis_keys.json` (matching the VVB registered at genesis). |
| `Peer ... has mismatched chain_id` | Alice and Bob must share the exact same `genesis_v2.json` file; check `status --rpc-url` `Chain ID` matches on both nodes. |
| `HTTP 401 Unauthorized` on localhost RPC | Pass `--cookie ./alice_data/.cookie` (or start daemon with `--no-rpc-auth` on local loopback). |

