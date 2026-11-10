# GreyMisnomer v2.0 Architectural Specification: Evolution from Static Transparency Log to Verifiable Tlog Tiles, Hybrid UCOs, C2SP Witnesses & Sovereign P2P Protocol

**Document Identifier:** RFC-GM-002  
**Author:** Prabhat Vilas Karlekar  
**Current Baseline Version:** GreyMisnomer 1.3.0 (`RFC-001` – `RFC-006`)  
**Target Architecture:** GreyMisnomer 2.0 (Stages 3.5 – 6; primary core upgrade defined in [`RFC-007`](rfc/rfc-007.md), subsequent wire/aggregation specs as `RFC-008+` in [`docs/rfc/`](rfc/))  
**Status:** Architectural Blueprint & Protocol Specification  
**Companion Design Workspace:** `GreyMisnomer_r1/09_SOVEREIGN_PROTOCOL_EVOLUTION.md` (extended prose edition)

---

## Master Architectural Index (What, Why, Where, How, When)

| Question | Architectural Answer | Primary Document Section |
| :--- | :--- | :--- |
| **WHAT is being built?** | A coinless, verifiable ecological ledger transitioning from a linear transparency log to **RFC 9162 immutable Merkle tiles**, **hybrid UCOs with explicit serial intervals**, **3-root light-client checkpoints**, **C2SP `tlog-cosignature` witnesses**, **hardened MRV oracle quorums**, and a native Rust mirror/verifier/P2P daemon (`greymisnomerd`). | [Section 4: The 4-Layer Architecture](#4-greymisnomer-20-architecture-the-4-layer-bitcoin-style-stack) |
| **WHY is it necessary?** | An empirical systems audit of v1.3.0 uncovered four concrete gaps: (1) $\approx O(n^{2.4})$ replay/cloning bottlenecks, (2) a stale `.ots` proof (`571e3f` vs `54b2a0`) checked only for file existence, (3) public-string key derivation (`from_seed_str`) in `generate_ledger`/`wasm`, and (4) single-sequencer split-view risk & GitHub Pages 1 GB / commercial limits. | [Section 2: Trust & Code Audit](#2-trust-model--baseline-audit-bitcoin-vs-greymisnomer-130) |
| **WHERE does state live and run?** | Immutable static Merkle tiles (`/tile/...`) hosted on any untrusted mirror (GitHub Read-Only, S3, IPFS, Archive.org), synchronized into embedded pure-Rust **`redb`** inside local `greymisnomerd` nodes listening on unclaimed **Local RPC Port `9482`** and (Stage 4.5+) **P2P Wire Port `9483`**. | [Section 4.2: Layer 2 Daemon](#42-layer-2-verifiable-tile-mirror--daemon-greymisnomerd) |
| **HOW does it function?** | Fix baseline perf/OTS/keys first (Stage 3.5); adopt RFC 9162 Merkle tiles + C2SP $k$-of-$n$ witness cosigning + MRV $k$-of-$n$ VVB challenge/buffer-pool rules + Bitcoin `.ots` digest-checked CI checkpoints (Stage 4); then layer `libp2p` gossip & anti-spam (Stage 4.5), optional FROST aggregation (Stage 5), and mobile UniFFI SPV / optional zkVM proofs (Stage 6). | [Section 6: Re-Ordered Engineering Roadmap](#6-re-ordered-engineering-roadmap-stages-35-through-6) |
| **WHEN will it be delivered?** | Strictly dependency-ordered: **Stage 3.5** (Perf, OTS & Real Keys) $\to$ **Stage 4** (`RFC-007` UCO + Tiles + Witnesses + Mirror Daemon `:9482` + Tauri Desktop) $\to$ **Stage 4.5** (`libp2p` `:9483` + Relays + Anti-Spam) $\to$ **Stage 5** (Optional FROST / Proposer Rotation) $\to$ **Stage 6** (UniFFI SPV, Optional zkVM, CCTS Audit Mirror). | [Section 6](#6-re-ordered-engineering-roadmap-stages-35-through-6) |

---

## 1. Executive Abstract & Architectural Thesis

GreyMisnomer 1.3.0 established a zero-cost, mathematically deterministic prototype for carbon registries by combining an append-only event log (`events.jsonl`), numbered checkpoints (`checkpoints/5.json`), and OpenTimestamps proofs (`events.jsonl.ots`) with a pure Rust core (`src/core`), CLI (`src/cli`), and WebAssembly verifier (`src/wasm` and `docs/app.html`).

While hosting static artifacts on GitHub Pages successfully demonstrated client-side verification with zero SaaS hosting bills, **a linear log controlled by one sequencer—and audited only passively on load—is neither split-view resistant nor permissionlessly survivable**, and independent benchmarking exposed concrete implementation gaps in v1.3.0 that must be fixed *before* databases, P2P meshes, or zkVMs are added.

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                          V1.3.0 BASELINE TO V2.0 TARGET SHIFT                          │
├───────────────────────────────────────────┬────────────────────────────────────────────┤
│   GreyMisnomer 1.3.0 (Verified Audit)     │     GreyMisnomer 2.0 (RFC-007 + Daemon)    │
├───────────────────────────────────────────┼────────────────────────────────────────────┤
│ • O(n^2.4) whole-state clone on replay    │ • O(1)/O(log n) in-place & serial cursors  │
│ • Stale .ots checked only by file exists  │ • Blocking CI SHA-256 + Bitcoin .ots check │
│ • Public-string keys (from_seed_str)      │ • CSPRNG + .gmkey everywhere (fresh genesis│
│ • Monolithic events.jsonl & Pages runtime │ • RFC 9162 Immutable Tiles on dumb mirrors │
│ • Single sequencer (split-view risk)      │ • C2SP tlog-cosignature (k-of-n witnesses) │
│ • Single-VVB PoI with immediate burn      │ • k-of-n VVBs, challenge window, buffer    │
│ • Browser-only / Litecoin port collision  │ • greymisnomerd SDK (:9482 RPC / :9483 P2P)│
└───────────────────────────────────────────┴────────────────────────────────────────────┘
```

Crucially, Bitcoin's trust guarantees rest on three pillars: **(1) anyone can verify every rule**, **(2) nobody can show conflicting histories (split view) or censor**, and **(3) data survives without permission**. You achieve (2) and (3) **immediately** via **RFC 9162 Merkle tiles + C2SP `tlog-cosignature` witnesses + multi-mirror content-addressed MRV blobs**, without requiring complex multi-round BFT consensus or premature zkVMs first.

---

## 2. Trust Model & Baseline Audit: Bitcoin vs. GreyMisnomer 1.3.0

### 2.1 Verified v1.3.0 Implementation Gaps (Must Fix in Stage 3.5 First)

1. **Superlinear $\approx O(n^{2.4})$ Replay & State-Cloning (`src/core`):**
   * `replay_log_with_anchor` (`src/core/src/event_log.rs`) executes `state = apply(&state, &entry.event)?`, cloning the entire `RegistryState` on every event, and then invokes `state.check_invariants()` containing $O(n^2)$ pairwise range loops (`check_invariant_3`, `4`, `5`) after *every single event* — measured at `0.26s` (1k mints), `6.5s` (4k), `40s` (8k).
   * *Fix First:* Use incremental `apply_in_place(&mut state, &event)`, monotonic per-`(project_id, vintage_year)` serial cursors ($O(1)$ overlap check), and $O(n \log n)$ sweep-line invariant audits.
2. **Stale `.ots` Proof & Existence-Only Check (`src/cli`, `docs/js/app.js`, `.github/workflows/pages.yml`):**
   * Current [`events.jsonl`](../events.jsonl) hashes to SHA-256 `54b2a0346481ad90...`, whereas [`events.jsonl.ots`](../events.jsonl.ots) attests `571e3f6330935384...` (BTC blocks `971952–971961`). Yet `src/cli/src/main.rs` prints `[OTS: Bitcoin-Anchored ✅]` on `ots_path.exists()`, `docs/js/app.js` checks only `fetch(..., { method: 'HEAD' })`, and `pages.yml` skips re-stamping when `.ots` already exists.
   * *Fix First:* Parse and compare exact SHA-256 digests in CLI/WASM, stamp immutable **checkpoints** (not mutating logs), and fail CI if digest verification mismatches.
3. **Public-String Key Derivation (`src/cli/src/bin/generate_ledger.rs`, `src/wasm/src/lib.rs`):**
   * Live alpha genesis/demo actors are generated via `Keypair::from_seed_str("authority-demo-key-2026")` (plus sequencer, VVB, Tata Solar, Infosys strings) and `WasmRegistry::resolve_owner()` calls `Keypair::from_seed_str(owner_str)`. Anyone can forge signatures.
   * *Fix First:* Gate `from_seed_str` behind `#[cfg(test)]` / `--regtest` / explicit test fixtures; mandate CSPRNG `.gmkey` keys everywhere else; start v2.0 from a **fresh CSPRNG Genesis Anchor (`chain_id_v2`)** instead of claiming cryptographic continuity over compromised demo seeds and stale `.ots` proofs.
4. **GitHub Pages Platform Bounds & Port Collisions:**
   * GitHub Pages enforces a [1 GB limit and excludes commercial/transactional apps](https://docs.github.com/en/pages/getting-started-with-github-pages/github-pages-limits) — suitable strictly as a **read-only static tile mirror**.
   * `9332`/`9333` are **Litecoin's defaults** — GreyMisnomer reallocates to unclaimed defaults **`9482` (Local RPC)** and **`9483` (P2P Wire)**.

### 2.2 Seven-Dimension Systems Comparison

| Protocol Dimension | Bitcoin Network Model | GreyMisnomer 1.3.0 Baseline | Core Vulnerability in Baseline | GreyMisnomer 2.0 Architecture (`RFC-007+`) |
| :--- | :--- | :--- | :--- | :--- |
| **1. History Non-Equivocation** | Proof of Work longest chain | Single Ed25519 Sequencer Key | Split-view attack possible; compromised key captures registry | **C2SP `tlog-cosignature` ($k$-of-$n$ witnesses)** enforcing RFC 9162 consistency proofs; optional FROST aggregation later |
| **2. Distribution & Liveness** | Dedicated TCP P2P mesh (`8333`) | Mutable `events.jsonl` on GitHub Pages + Actions | GitHub censorship, API limits, Pages 1 GB / transactional limits | **RFC 9162 Immutable Static Tiles** across untrusted mirrors (GitHub read-only, S3, IPFS, IA) + Stage 4.5 `libp2p` mesh (`9483`) |
| **3. State Enforcement** | Active P2P socket-level block drop | Passive client-side audit on browser load | Invalid commits sit in git without active node rejection | `greymisnomerd` validates every tile/tx via `apply_uco()` (`redb`); Stage 4.5 drops invalid gossip & bans peers |
| **4. Data Availability** | Full nodes validate full history | Unpinned IPFS gateways + missing/stale `.ots` | Cryptographic Tombstone (`ots` digest mismatch; unpinned PDFs lost) | **$\ge 2$ Independent MRV Mirrors** checked by BLAKE3 (`RFC-003`) + self-hosted `iroh`/CAS fallback (no reliance on rate-limited n0 public relays) |
| **5. Light Verification & State** | LevelDB UTXO set + 80-byte headers | Flat `events.jsonl` $\approx O(n^{2.4})$ clone replay | Crashes client RAM at scale; SPV blind to spentness | **`redb`** indexed UCOs + **3-Root Checkpoint Header** (`events_root`, `uco_state_root`, `poo_archive_root`) giving $O(\log N)$ spentness & PoO proofs |
| **6. Timestamp Finality** | Cumulative PoW blocks | Stale `events.jsonl.ots` (`571e3f` vs `54b2a0`) | False positive `"Bitcoin-Anchored ✅"` in CLI/UI | Digest-verified **OpenTimestamps on Checkpoints** checked as a hard failing gate in CLI & CI |
| **7. Asset Origin Truth (Oracle)** | Closed-loop digital currency | Single VVB signature, instant retirement | Fraudulent physical claims burned immediately & irreversibly | **$k$-of-$n$ VVB + telemetry oracles**, VVB accreditation/revocation log events, **challenge window** pre-retirement, **buffer pool** revocation |

---

## 3. Monetary & Ecological Economics: Can Carbon Credits Function as a Pegged Climate Currency?

From strict monetary economics, protocol design, and Indian tax law ([RFC-004](rfc-004.md) cites India's **30% flat VDA tax + 1% TDS**; Verra also [halted legacy tokenization bridging in 2022](https://reccessary.com/en/news/Verra-halts-tokenization-of-carbon-credits-avoid-double-counting) over double-counting), **raw carbon credits cannot function as a circulating fiat-pegged currency**:

1. **Supply Set by MRV, Not Monetary Policy (Dual Moving-Target Paradox):** Issuance tracks audited physical tonnes ($\text{tCO}_2\text{e}$), while fiat value reflects marginal abatement costs. Hard pegs collapse without infinite central bank reserves.
2. **Gresham's Law ("Bad Carbon Drives Out Good Carbon"):** Heterogeneous durability (Direct Air Capture at $\$600\text{/t}$ vs. cookstoves/avoidance at $\$5\text{/t}$) causes flat-rate currency pegs to attract only the lowest-quality credits.
3. **Consumable UTXO Paradox:** Currencies circulate forever ($A \to B \to C$); carbon credits must be **permanently burned (PoO)** once claimed.
4. **Strict Registry-Market Separation & Two-Tier Ecological Architecture:**
   * *Tier 1 (GreyMisnomer Core):* Non-fungible, **serial-range-locked UCOs** (`[start_micro_unit, end_micro_unit)`) tracking physical provenance from PoI mint to PoO retirement.
   * *Tier 2 (Optional Statutory Compliance Reserve Interface):* Jurisdictional authorities (e.g., BEE under CCTS) can inspect locked/escrowed Tier-1 UCOs (`EscrowLock`) against external statutory floor compliance instruments without ever putting a speculative coin on Layer 1.

---

## 4. GreyMisnomer 2.0 Architecture: The 4-Layer Bitcoin-Style Stack

```
                    ┌─────────────────────────────────────────┐
                    │         greymisnomerd (Daemon)          │
                    │  Pure Rust · Tile Verifier & Local Node │
                    └────────────────────┬────────────────────┘
                                         │
         ┌───────────────────────────────┼───────────────────────────────┐
         ▼                               ▼                               ▼
 [Tile Mirrors & Wire P2P]       [Core State Engine]             [Local RPC & SDK]
 RFC 9162 Static Tiles           Hybrid UCO w/ [start, end)      HTTP/WS Port 9482
 + Stage 4.5 libp2p :9483        Domain-Separated BLAKE3/3-Root  Axum + BigInt-Safe JSON
 >=2 MRV Mirrors / Self Relay    redb ACID + Serial Cursors      WASM / Tauri / UniFFI
         │                               │                               │
         ▼                               ▼                               ▼
 C2SP Witnesses (k-of-n)         OpenTimestamps (.ots)           Desktop, Mobile SPV,
 (NGOs, Labs, Grid, VVBs)        Verified Against Checkpoints    & Web Explorer Clients
```

### 4.1 Layer 1: Pure Verification Engine & Hybrid UCO State Machine (`grey-misnomer-core`)

All floating-point math remains strictly prohibited; integer accounting preserves exact v1.3.0 resolution (`MICRO_UNITS_PER_CREDIT = 1_000_000`, where $1\text{ tCO}_2\text{e} = 1,000\text{ kg} = 1,000,000\text{ micro-units}$, i.e., $1\text{ gCO}_2\text{e}$), guarded by JavaScript safety limit `MAX_UCO_MICRO_UNITS = 9_000_000_000_000_000` ($\le 2^{53}-1$) and base-10 string `u64` serialization over JSON-RPC. Complete Rust definitions live in [`RFC-007 §3`](rfc/rfc-007.md#3-protocol-architecture-hybrid-uco-model-with-serial-intervals):

* **Hybrid UCOs (Not Amount-Only UTXOs):** Every [`UnretiredCreditOutput`](rfc/rfc-007.md#31-preserving-micro_units_per_credit-and-explicit-serial-ranges) binds `outpoint (txid, vout)`, `batch_id`, `project_id`, `vintage_year`, explicit half-open serial range `[start_micro_unit, end_micro_unit)`, `micro_units`, `owner`, `op_index`, `methodology_hash`, `mrv_data_root`, `challenge_until_epoch`, and optional `locked_escrow_program`.
* **Monotonic Per-`(project_id, vintage_year)` Serial Cursor:** Allocates `[cursor, cursor + amount)` in $O(1)$ at mint instead of global $O(n)$ range scans.
* **Contiguous Partition Conservation:** Splits of $[A, C)$ into $[A, B)$ and $[B, C)$ enforce $A < B < C$, pairwise disjoint intervals, `MAX_TX_OUTPUTS = 16` fan-out cap, and exact conservation $\sum \text{In} == \sum \text{Out}$.
* **Domain-Separated Hashes & 3-Root Checkpoints:** Every [`CheckpointHeaderV2`](rfc/rfc-007.md#42-three-root-checkpoint-header-solving-bitcoin-spvs-blind-spot) commits to:
  1. `events_root` (RFC 9162 log tree with `0x00` leaf / `0x01` node separation),
  2. `uco_state_root` (`"GM-v2-UCO:"` canonical Merkle tree of active unspent UCOs — allowing SPV clients to prove unspentness in $O(\log N)$!), and
  3. `poo_archive_root` (`"GM-v2-POO:"` cumulative Merkle accumulator of `ProofOfOffsetCommitment` receipts).

### 4.2 Layer 2: Verifiable Tile Mirror & Daemon (`greymisnomerd`)

* **Stage 4 First Role (Mirror, Verifier & Monitor):** Syncs immutable RFC 9162 tiles (`/tile/<level>/<index>`) from untrusted HTTP/S3/IPFS/IA mirrors, verifies append-only consistency proofs, checks C2SP witness cosignatures and `.ots` digests, validates every event via `apply_in_place` / `apply_uco` into **`redb`**, and exposes verified $O(1)$/`O(\log N)$ endpoints on **Port `9482`** (`127.0.0.1:9482`: `/v1/chain/status`, `/v1/uco/:outpoint`, `/v1/proof/spv/:outpoint`, `/v1/proof/poi/:root`, `/v1/checkpoint/latest`, `WS /v1/events/subscribe`).
* **Stage 4.5 Wire P2P Upgrade (Port `9483`):** Layers native `rust-libp2p` GossipSub + Kademlia DHT over TCP/QUIC Port **`9483`** with socket-level invalid-tx peer banning, `MAX_TX_OUTPUTS = 16` + optional 16-bit BLAKE3 hashcash anti-spam (`~20 ms` CPU, zero coin), and **self-hosted relay fallbacks** alongside $\ge 2$ independent MRV evidence mirrors (never relying solely on n0's rate-limited public `iroh` relays).

### 4.3 Layer 3: C2SP Witness Cosigning, Hardened Oracles & Bitcoin `.ots`

* **Immediate Split-View Protection via [C2SP `tlog-cosignature`](https://github.com/C2SP/C2SP/blob/main/tlog-cosignature.md):** $k$-of-$n$ independent witnesses verify append-only consistency proofs before cosigning each checkpoint header, blocking split-view attacks without BFT or DKG coordination overhead. *(Optional `frost-ed25519` aggregation remains a Stage 5 governance extension only if an institutional committee adopts threshold signing and formal membership resharing rules.)*
* **MRV Oracle Defense:** Mandates $k$-of-$n$ VVB + telemetry attestations, on-log accreditation/revocation events, a pre-retirement `challenge_until_epoch` dispute window, and buffer-pool-backed `RevokeWithBuffer` handling.
* **OpenTimestamps Finality Gate:** Stamps immutable `CheckpointHeaderV2` digests (not mutating JSONL logs) and fails CLI/CI verification whenever the `.ots` digest mismatches.

### 4.4 Layer 4: Multi-Platform Client SDK Ecosystem

* **Unified SDK (`grey-misnomer-core`):** Every runtime shares identical transition & SPV verification math: **Tauri v2 Desktop** (bundled with local `greymisnomerd` on `:9482`), **UniFFI Mobile SPV** (Swift/Kotlin verifying 3-root `<300 B` headers & QR PoO Merkle branches in $O(\log N)$ offline!), and **WebAssembly Explorer** (`docs/app.html` talking to `:9482` or read-only tile mirrors).
* **Premature zkVM Deferral:** Because 3-root Merkle SPV already proves membership, unspentness, and offset receipts in $O(\log N)$ (`<1 KB` proof), full **SP1 / RISC Zero zkVM** epoch compression is deliberately deferred to **Stage 6**, after real ledger scale justifies it.

---

## 5. Threat Model & Failure Mode Analysis

| Threat / Failure Scenario | GreyMisnomer 1.3.0 Vulnerability | GreyMisnomer 2.0 Defense Mechanism (`RFC-007+`) |
| :--- | :--- | :--- |
| **Superlinear Log Verification DoS** | $\approx O(n^{2.4})$ replay (`apply` clone + $O(n^2)$ per-step invariant loops). | `apply_in_place` + monotonic per-`(project, vintage)` serial cursors + `redb` $O(1)$ lookups + $O(\log N)$ SPV. |
| **Stale / Unverified `.ots` Bitcoin Claim** | CLI & JS report `"Bitcoin-Anchored ✅"` on `exists()` / `HEAD` despite `571e3f` vs `54b2a0` mismatch. | Strict SHA-256 digest verification against immutable checkpoints; failing CI gate on mismatch. |
| **Predictable Key Forgery** | Production alpha keys derived from public strings (`"authority-demo-key-2026"` / `owner_str`). | CSPRNG `.gmkey` keys only in release/WASM; `from_seed_str` gated to tests/`--regtest`; fresh v2 CSPRNG genesis. |
| **Split-View / Equivocating Sequencer** | Single sequencer signs conflicting histories to different auditors. | **$k$-of-$n$ C2SP `tlog-cosignature` witnesses** refuse to cosign inconsistent checkpoints. |
| **GitHub Ban / Pages 1 GB & Policy Limits** | Single host acts as primary database & transactional coordinator. | Read-only static **RFC 9162 tiles** mirrored across S3, IPFS, IA & Pages + Stage 4.5 `libp2p` `:9483`. |
| **Corrupt VVB or Missing MRV Evidence** | Single VVB mints fraudulent credit with instant retirement and unpinned PDFs. | $k$-of-$n$ VVBs + `challenge_until_epoch` window + buffer pool revocation + BLAKE3 checks on $\ge 2$ mirrors. |
| **Coinless P2P UTXO / Dust Flood (Stage 4.5)** | Unchecked split fan-out bloats state at $0 gas cost. | `MAX_TX_OUTPUTS = 16`, minimum change rules, per-key rate limits, optional 16-bit BLAKE3 stamp. |

---

## 6. Re-Ordered Engineering Roadmap (Stages 3.5 through 6)

```
┌────────────────────────────────────────────────────────────────────────┐
│ STAGE 3 (Baseline v0.3.0): Static Log, WASM, CLI Releases, Regtest     │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ STAGE 3.5 (IMMEDIATE PREREQUISITES — Fix Verified Baseline Defects)   │
│ • Fix O(n^2.4) apply/clone & O(n^2) replay loops; monotonic cursors   │
│ • Verify exact .ots SHA-256 digests in CLI/WASM & enforce in CI       │
│ • Disable public-string keys (`from_seed_str`) in release & WASM      │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ STAGE 4 (RFC-007: Core v2, Tiles, C2SP Witnesses & Local Daemon :9482) │
│ • Hybrid UCO ([start, end), MAX_UCO_MICRO_UNITS, domain prefixes)      │
│ • RFC 9162 Merkle log, 3-root CheckpointHeaderV2, immutable tiles     │
│ • C2SP tlog-cosignature witnesses + MRV quorum/challenge/buffer pool   │
│ • Fresh CSPRNG genesis + redb + greymisnomerd (:9482) + Tauri Desktop │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ STAGE 4.5 (P2P Wire Mesh on Unclaimed Port 9483 & Anti-Spam)          │
│ • libp2p GossipSub/Kademlia (:9483) + self-hosted relays (not n0-only)│
│ • Wire-level invariant drop/ban + MAX_TX_OUTPUTS=16 + 16-bit PoW stamp│
│ • >=2 mirror MRV evidence availability enforcement & 3-node testnet   │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ STAGE 5 (Only If Committee Governance Requires: FROST & BFT Ordering)  │
│ • Optional frost-ed25519 signature aggregation + proposer rotation     │
│ • Automated daemon OTS pipeline + multi-oracle & slashing enforcement │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ STAGE 6 (Mobile UniFFI SPV, Optional zkVM & CCTS Public Audit Bridge)  │
│ • UniFFI Mobile SPV verifying <300B 3-root headers in O(log N) offline │
│ • Optional SP1/RISC Zero zkVM batch proofs once ledger scale demands   │
│ • EscrowLock / CCTS public audit mirror alongside BEE's ICM Portal     │
└────────────────────────────────────────────────────────────────────────┘
```

### 6.1 Institutional Positioning & Open Governance Decisions

* **CCTS Strategy:** Because India's BEE operates the official [Indian Carbon Market Portal](https://icapcarbonaction.com/en/news/compliance-obligations-under-indias-carbon-credit-trading-scheme-enter-force-seven-sectors), GreyMisnomer's immediately adoptable institutional role is an **independent cryptographic public audit log, tile mirror, and verification SDK** alongside statutory portals (rather than attempting to displace government infrastructure).
* **Zero-Protocol-Budget Model:** All dependencies across Stages 3.5–6 (`redb`, `axum`, `rust-libp2p`, `frost-ed25519`, `Tauri v2`, `UniFFI`, `SP1`/`RISC Zero`) are `$0` FOSS software run on users' and witness operators' own hardware.
* **Open Governance Decisions (Before Stage 4 Genesis):** **(1)** Who operates the initial sequencer/log ingestion host? **(2)** Which 3–5 independent institutions run the initial C2SP `tlog-cosignature` witness nodes?

---

## 7. Document Charter & Engineering Commitment

All future RFCs ([`RFC-007`](rfc-007.md), `RFC-008+`), pull requests, and binaries MUST uphold four non-negotiable engineering axioms:

1. **Measure & Fix Foundations First:** Zero-alloc/incremental `apply_in_place`, verified `.ots` digests, and CSPRNG keys before layers of distributed systems complexity.
2. **Coinless Determinism & Serial Continuity:** Preserve `MICRO_UNITS_PER_CREDIT = 1_000_000`, half-open serial bounds `[start, end)`, `MAX_UCO_MICRO_UNITS` JS safety, and zero speculative L1 tokens.
3. **Sovereign Non-Equivocation Over Web2 Trust:** Untrusted static tile mirrors + C2SP $k$-of-$n$ witness cosignatures + domain-separated 3-root Merkle proofs.
4. **Thermodynamic Proof-of-Work Anchor:** Immutable checkpoints anchored cleanly into Bitcoin via digest-verified OpenTimestamps.
