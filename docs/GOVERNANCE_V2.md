# GreyMisnomer v2.0 Governance Charter

> **Status:** Pre-Genesis Draft
> **Created:** 2026-11-24
> **Author:** Prabhat Vilas Karlekar (`@PrabhatKarlekar`)
> **Related:** [RFC-007](rfc/rfc-007.md), [RFC-GM-002 / SOVEREIGN_PROTOCOL_EVOLUTION.md](SOVEREIGN_PROTOCOL_EVOLUTION.md)

---

## 1. Purpose

This document records the governance decisions required by [RFC-007 §8.3](rfc/rfc-007.md) before launching a cryptographically clean v2.0 genesis chain. It establishes:

1. The identity and operational policy of the **v2.0 Sequencer Operator**.
2. The initial roster of **3–5 independent C2SP `tlog-cosignature` Witnesses**.
3. The CSPRNG v2.0 genesis readiness acknowledgment (no continuity claim over v1.3 demo seeds).

---

## 2. v2.0 Sequencer Operator

### 2.1 Role

The Sequencer Operator runs the primary v2.0 log ingestion endpoint. It:

- Receives signed transaction intents from authorized submitters.
- Orders events into the append-only RFC 9162 Merkle log.
- Produces signed `CheckpointHeaderV2` checkpoints at configurable size boundaries.
- Publishes immutable static tiles to configured mirror endpoints.
- Submits checkpoints to C2SP Witnesses for cosigning.
- Stamps checkpoints via OpenTimestamps for Bitcoin-anchored temporal proof.

### 2.2 Designated Operator

| Field | Value |
|-------|-------|
| **Entity** | GreyMisnomer Open Governance (Sole Maintainer Phase) |
| **Operator** | Prabhat Vilas Karlekar (`@PrabhatKarlekar`) |
| **Key Type** | CSPRNG Ed25519 (generated via `grey-misnomer-cli keygen`) |
| **Key Storage** | Encrypted `.gmkey` file (AES-256-GCM, PBKDF2-HMAC-SHA256 100k rounds) |
| **Public Key** | *To be generated at v2.0 Genesis Ceremony (Task 4.18)* |
| **Rotation Policy** | Authority can rotate sequencer key via signed `SequencerRotate` event |

### 2.3 Operational Policy

- The sequencer MUST NOT refuse valid, properly signed transaction intents without documented protocol-level rejection reason.
- The sequencer MUST produce checkpoints at least every 256 events or 24 hours (whichever comes first).
- The sequencer MUST submit every checkpoint to all registered witnesses before publishing tiles.
- The sequencer MUST NOT publish two different checkpoints for the same `tree_size`.
- Equivocation (presenting different `events_root` values for the same `tree_size` to different parties) is a detectable protocol violation that witnesses will refuse to cosign.

### 2.4 Transition to Multi-Operator Governance

When institutional adoption warrants, the single-operator phase transitions to a multi-party governance committee:

1. **Stage 5 (Future):** FROST Ed25519 threshold signing enables `t`-of-`n` sequencer committee operation.
2. **Stage 5+ (Future):** Proposer rotation protocol distributes sequencing authority across geographically and organizationally diverse operators.

---

## 3. Initial C2SP `tlog-cosignature` Witness Roster

### 3.1 Role

Each Witness independently verifies RFC 9162 consistency proofs and cosigns valid checkpoint extensions. A verifier node rejects any checkpoint with fewer than `k` valid distinct witness cosignatures.

### 3.2 Witness Selection Criteria

Witnesses MUST be:

- **Organizationally independent** from the sequencer operator.
- **Geopolitically diverse** (not all in the same legal jurisdiction).
- **Technically capable** of running a lightweight Ed25519 cosigning service (~64 bytes state per tracked chain).
- **Committed to uptime** (a witness that goes offline reduces the pool but does not halt the chain).

### 3.3 Initial Witness Roster (Pre-Genesis Candidates)

> [!NOTE]
> The following are **candidate slots** to be filled before v2.0 Genesis Ceremony (Task 4.18). During development and regtest, witness keys are CSPRNG-generated test instances. Production witnesses require formal commitment from independent entities.

| Slot | Candidate Category | Status | Public Key |
|------|--------------------|--------|------------|
| W1 | Environmental NGO / Climate Research Lab | 🟡 Seeking | *TBD at Genesis* |
| W2 | Academic University Climate or CS Department | 🟡 Seeking | *TBD at Genesis* |
| W3 | Open-Source Foundation / Auditing Group | 🟡 Seeking | *TBD at Genesis* |
| W4 | Renewable Energy Industry Association | 🟡 Seeking | *TBD at Genesis* |
| W5 | Independent Developer / Community Operator | 🟡 Seeking | *TBD at Genesis* |

### 3.4 Witness Quorum Configuration

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| `n` (total witnesses) | 3–5 (initial) | Minimal viable non-equivocation defense |
| `k` (required cosignatures) | ⌈n/2⌉ + 1 | Simple majority + 1 prevents minority fork |
| Witness key type | CSPRNG Ed25519 | Matches sequencer/authority key type |
| Witness state | `(last_tree_size, last_events_root)` per chain | ~64 bytes per tracked registry |
| Consistency proof | RFC 9162 `consistency_proof(old_size, new_size)` | O(log N) verification |

### 3.5 Regtest / Development Witnesses

For `--regtest` and CI testing, 3 ephemeral CSPRNG witness instances are auto-generated:

```
grey-misnomer-cli keygen --label "regtest-witness-1"
grey-misnomer-cli keygen --label "regtest-witness-2"
grey-misnomer-cli keygen --label "regtest-witness-3"
```

These are explicitly non-production keys and carry no governance authority.

---

## 4. CSPRNG v2.0 Genesis Readiness

### 4.1 Acknowledgment

v1.3.0 alpha used publicly derivable seed strings (`"authority-demo-key-2026"`, etc.) as documented in [RFC-007 §2.3](rfc/rfc-007.md). These keys are **publicly known** and provide **zero real authorization security**.

v2.0 performs a **clean cryptographic genesis break**:

- All v2.0 Authority, Sequencer, VVB, and Witness keys MUST be generated via OS/WebCrypto CSPRNG (`Keypair::generate()`).
- The v1.3 → v2.0 state converter exists only as a deterministic test/importer utility (`src/core/src/migrate.rs`).
- No `.ots` continuity is claimed between v1.3 demo log and v2.0 genesis.

### 4.2 Genesis Ceremony Checklist (Task 4.18)

- [ ] Generate fresh CSPRNG Authority keypair → encrypted `.gmkey`
- [ ] Generate fresh CSPRNG Sequencer keypair → encrypted `.gmkey`
- [ ] Generate fresh CSPRNG Witness keypairs (3–5) → distributed to independent operators
- [ ] Compute `chain_id_v2 = BLAKE3("GM/v1/chain" || genesis_body_bytes)`
- [ ] Mint genesis UCOs with verified MRV attestations
- [ ] Wait out challenge interval
- [ ] Publish immutable tiles to ≥2 mirrors
- [ ] Collect k-of-n C2SP witness cosignatures
- [ ] Stamp checkpoint via OpenTimestamps
- [ ] Verify `.ots` SHA-256 digest match

---

## 5. CCTS / BEE Alignment Notice

India's Bureau of Energy Efficiency (BEE) operates the statutory **Indian Carbon Market Portal** under the Carbon Credit Trading Scheme (CCTS). GreyMisnomer v2.0 positions itself as an **independent cryptographic public audit log and open verification SDK** alongside statutory portals — not as a replacement for sovereign regulatory infrastructure.

Future `Two-Tier EscrowLock` (Stage 6) can interface with CCTS statutory requirements while maintaining protocol-level independence.

---

← Back to [README](../README.md) | See [RFC-007](rfc/rfc-007.md) | See [SOVEREIGN_PROTOCOL_EVOLUTION.md](SOVEREIGN_PROTOCOL_EVOLUTION.md)

