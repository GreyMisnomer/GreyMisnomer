# RFC-003: MRV Data Commitment & Merkle Root Format

**Status:** Draft  
**Created:** 2026-04-14  
**Author:** @PrabhatKarlekar  
**Related Issues:** #3 (RFC-001), #4 (RFC-002)  
**Target Phase:** Year 0-1

---

## 1. Problem Statement

Raw MRV (Measurement, Reporting, Verification) data is voluminous, sensitive, and lives off-chain.  
Directly storing raw data on-chain is impossible due to cost and privacy concerns.

Without a cryptographic commitment:
- PoI (RFC-001) cannot verifiably link to real MRV data.
- Auditors and regulators cannot independently verify claims.
- The registry cannot prove that claimed reductions actually occurred.

> [!CAUTION]
> Without a commitment scheme, Proof-of-Integrity (PoI) becomes a trusted assertion rather than a verifiable mathematical proof.

---

## 2. Proposed Solution

Use a **Merkle Tree** to create a single cryptographic commitment (the Merkle Root) for each batch of MRV data.

- Raw data stays off-chain.
- Only the Merkle Root + metadata is referenced in the PoI.
- Inclusion proofs allow selective verification without revealing the entire dataset.

**This enables:**
- Privacy-preserving validation
- Efficient on-chain PoI
- Independent auditability
- Scalability to millions of data points (IoT, satellite, meters)

---

## 3. Detailed Specification

### 3.1 Data Flow

```mermaid
flowchart TD
    A[Raw MRV data collected<br>(sensors/satellites)] --> B[Normalize & hash<br>leaf-by-leaf]
    B --> C[Build Merkle Tree<br>Compute Merkle Root]
    C --> D[Embed Merkle Root + metadata<br>into PoI Object]
    D --> E[Submit PoI to Registry<br>for on-chain verification]
```

### 3.2 Merkle Tree Construction
- **Leaf nodes:** `Hash` of each normalized MRV record.
- **Internal nodes:** `Hash(left_child || right_child)`.
- **Merkle Root:** Top hash of the tree.

> [!NOTE]
> **Recommended hash (Phase Alpha):** BLAKE3 — fast, secure, and Rust-native.

### 3.3 On-chain Commitment (minimal)
```json
{
  "proof_type": "PoI",
  "mrv_commitment": {
    "merkle_root": "0x...",
    "data_hash_algorithm": "BLAKE3",
    "leaf_count": 1248,
    "timestamp": "2026-01-01T12:00:00Z"
  }
}
```

---

## 4. Core Invariants

> [!IMPORTANT]
> 1. Every PoI must contain a valid Merkle Root that commits to the underlying MRV dataset.
> 2. The Merkle Root must be computed from the exact dataset approved by the VVB.
> 3. Inclusion proofs must be verifiable against the root without revealing the full dataset.
> 4. Once a PoI is minted, the committed MRV data cannot be altered retroactively.

---

## 5. Integration with Previous RFCs

- **RFC-001 (Two-Proof Model):** The `data_root` field in PoI is the Merkle Root defined here.
- **RFC-002 (Serialization):** The verified MRV dataset (via Merkle Root) directly determines the authorized serialization range size.

**The Full Protocol Chain:**
`MRV Data → Merkle Root → PoI → Serialized Credits → PoO`

---

## 6. Alternatives Considered

- **Single hash of entire dataset** → Rejected (no selective disclosure).
- **Store raw data on-chain** → Rejected (cost + privacy violation).
- **IPFS + hash only** → Rejected (no efficient inclusion proofs).
- **Full ZK-SNARK of dataset** → Deferred to Phase Beta (too heavy for Phase Alpha).

*Merkle Tree chosen because it is simple, auditable, supports selective proofs, and is well-understood by regulators.*

---

## 7. Open Questions

1. Which hash function should be used for production (BLAKE3 vs SHA-256 vs Poseidon for future ZK integration)?
2. Should we support incremental Merkle Tree updates for continuous MRV?
3. How to handle extremely large datasets (millions of leaves)?
4. Should the Merkle Root be stored on-chain or only inside the PoI object?

---

## 8. Implementation Notes (Phase Alpha)

**Location:** `src/core/mrv/`

**Rust types to define:**
```rust
struct MRVRecord {
    // normalized key-value pairs from sensors, satellite, meters, etc.
}

struct MerkleTree {
    root: [u8; 32],           // BLAKE3 hash
    leaf_count: u64,
}

struct MRVCommitment {
    merkle_root: [u8; 32],
    data_hash_algorithm: String,
    timestamp: u64,
}
```

**Required functions:**
```rust
fn hash_record(record: &MRVRecord) -> [u8; 32]
fn build_merkle_tree(records: &[MRVRecord]) -> MerkleTree
fn generate_inclusion_proof(index: usize) -> Vec<[u8; 32]>
fn verify_inclusion_proof(record: &MRVRecord, proof: &[[u8; 32]], root: &[u8; 32]) -> bool
```

**Tests required:**
- Root computation is deterministic.
- Inclusion proof verification succeeds.
- Tampered leaf → proof fails.
- Empty dataset handling.

**Dependencies:** None (pure Rust in Phase Alpha)

---

## 9. References

- `architecture/desgin_document_v2.pdf` — MRV & Data Acquisition Layer, Merkle Root sections.
- `architecture/qna_document_v1.pdf` — Data Commitment & hashing discussions.
- **RFC-001 (Two-Proof Model)**
- **RFC-002 (Serialization)**
