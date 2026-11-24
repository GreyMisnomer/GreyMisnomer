//! RFC-007 §3.1 & §4.4: Pure `apply_uco()` State Transition Engine.
//!
//! Evaluates state transitions over Hybrid Unretired Credit Outputs (UCOs):
//! - `UcoMint`: Allocates contiguous `[start, end)` intervals advancing monotonic cursors in O(1).
//! - `UcoSplitTransfer`: Enforces exact disjoint partitioning of input serial intervals.
//! - `UcoBurn`: Validates challenge window, escrow locks, and emits `ProofOfOffsetCommitment`.
//!
//! Stateless and pure: operates on any store implementing `UcoStoreRead` and provides
//! a standard in-memory `UcoState`.

use crate::auth::{enc_bytes32, enc_pubkey, enc_str, enc_u64, PubKey, Signature};
use crate::error::RegistryError;
use crate::uco::{
    OutPoint, PoOClaimType, ProofOfOffsetCommitment, UnretiredCreditOutput, MAX_TX_OUTPUTS,
    MAX_UCO_MICRO_UNITS,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

// ---------------------------------------------------------------------------
// Domain Separator Constants for v2 Transactions
// ---------------------------------------------------------------------------

pub const DOMAIN_TX_MINT: &str = "GM-v2-TX-MINT:";
pub const DOMAIN_TX_TRANSFER: &str = "GM-v2-TX-TRANSFER:";
pub const DOMAIN_TX_BURN: &str = "GM-v2-TX-BURN:";

// ---------------------------------------------------------------------------
// Transaction Types
// ---------------------------------------------------------------------------

/// Intent to mint new UCO supply from verified MRV telemetry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UcoMintTx {
    pub project_id: String,
    pub batch_id: String,
    pub vintage_year: u16,
    pub micro_units: u64,
    pub initial_owner: PubKey,
    #[serde(with = "crate::auth::hex_bytes32")]
    pub methodology_hash: [u8; 32],
    #[serde(with = "crate::auth::hex_bytes32")]
    pub mrv_data_root: [u8; 32],
    #[serde(default)]
    pub mrv_blob_mirrors: Vec<String>,
    pub challenge_window_epochs: u64,
    /// Signatures from accredited VVBs certifying the MRV issuance
    pub vvb_signatures: Vec<(PubKey, Signature)>,
}

impl UcoMintTx {
    /// Canonical signing preimage for VVB attestation.
    pub fn signing_preimage(&self, chain_id: &[u8; 32]) -> Vec<u8> {
        let mut buf = Vec::new();
        enc_str(DOMAIN_TX_MINT, &mut buf);
        enc_bytes32(chain_id, &mut buf);
        enc_str(&self.project_id, &mut buf);
        enc_str(&self.batch_id, &mut buf);
        enc_u64(self.vintage_year as u64, &mut buf);
        enc_u64(self.micro_units, &mut buf);
        enc_pubkey(&self.initial_owner, &mut buf);
        enc_bytes32(&self.methodology_hash, &mut buf);
        enc_bytes32(&self.mrv_data_root, &mut buf);
        enc_u64(self.challenge_window_epochs, &mut buf);
        buf
    }

    /// Computes the unique deterministic transaction ID.
    pub fn txid(&self, chain_id: &[u8; 32]) -> [u8; 32] {
        let preimage = self.signing_preimage(chain_id);
        *blake3::hash(&preimage).as_bytes()
    }
}

/// Specification for an output created during `UcoSplitTransfer`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UcoTransferOutputSpec {
    pub owner: PubKey,
    pub start_micro_unit: u64,
    pub end_micro_unit: u64,
    pub micro_units: u64,
    #[serde(default)]
    pub locked_escrow_program: Option<String>,
}

/// Intent to split, merge, or transfer UCO outputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UcoSplitTransferTx {
    pub inputs: Vec<OutPoint>,
    pub outputs: Vec<UcoTransferOutputSpec>,
    /// One signature per input in `inputs`, signed by the owner of that input
    pub input_signatures: Vec<Signature>,
}

impl UcoSplitTransferTx {
    /// Canonical signing preimage for input owners.
    pub fn signing_preimage(&self, chain_id: &[u8; 32], input_op_indices: &[u64]) -> Vec<u8> {
        let mut buf = Vec::new();
        enc_str(DOMAIN_TX_TRANSFER, &mut buf);
        enc_bytes32(chain_id, &mut buf);
        enc_u64(self.inputs.len() as u64, &mut buf);
        for (i, op) in self.inputs.iter().enumerate() {
            enc_bytes32(&op.txid, &mut buf);
            enc_u64(op.vout as u64, &mut buf);
            let op_idx = input_op_indices.get(i).copied().unwrap_or(0);
            enc_u64(op_idx, &mut buf);
        }
        enc_u64(self.outputs.len() as u64, &mut buf);
        for out in &self.outputs {
            enc_pubkey(&out.owner, &mut buf);
            enc_u64(out.start_micro_unit, &mut buf);
            enc_u64(out.end_micro_unit, &mut buf);
            enc_u64(out.micro_units, &mut buf);
            if let Some(escrow) = &out.locked_escrow_program {
                enc_str(escrow, &mut buf);
            } else {
                enc_str("", &mut buf);
            }
        }
        buf
    }

    /// Computes the unique deterministic transaction ID.
    pub fn txid(&self, chain_id: &[u8; 32], input_op_indices: &[u64]) -> [u8; 32] {
        let preimage = self.signing_preimage(chain_id, input_op_indices);
        *blake3::hash(&preimage).as_bytes()
    }
}

/// Intent to permanently retire a UCO into a ProofOfOffsetCommitment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UcoBurnTx {
    pub input: OutPoint,
    pub start_micro_unit: u64,
    pub end_micro_unit: u64,
    pub micro_units: u64,
    pub beneficiary: String,
    pub claim_type: PoOClaimType,
    pub owner_sig: Signature,
    /// If partial burn, specify the recipient of the unretired change output
    pub change_owner: Option<PubKey>,
}

impl UcoBurnTx {
    /// Canonical signing preimage for retirement authorization.
    pub fn signing_preimage(&self, chain_id: &[u8; 32], op_index: u64) -> Vec<u8> {
        let mut buf = Vec::new();
        enc_str(DOMAIN_TX_BURN, &mut buf);
        enc_bytes32(chain_id, &mut buf);
        enc_bytes32(&self.input.txid, &mut buf);
        enc_u64(self.input.vout as u64, &mut buf);
        enc_u64(op_index, &mut buf);
        enc_u64(self.start_micro_unit, &mut buf);
        enc_u64(self.end_micro_unit, &mut buf);
        enc_u64(self.micro_units, &mut buf);
        enc_str(&self.beneficiary, &mut buf);
        enc_str(&self.claim_type.to_string(), &mut buf);
        buf
    }

    /// Computes the unique deterministic transaction ID.
    pub fn txid(&self, chain_id: &[u8; 32], op_index: u64) -> [u8; 32] {
        let preimage = self.signing_preimage(chain_id, op_index);
        *blake3::hash(&preimage).as_bytes()
    }
}

/// Unified v2 transaction enumeration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UcoTransaction {
    Mint(UcoMintTx),
    SplitTransfer(UcoSplitTransferTx),
    Burn(UcoBurnTx),
}

// ---------------------------------------------------------------------------
// Transition Delta & Store Abstraction
// ---------------------------------------------------------------------------

/// State mutations produced by evaluating a valid UCO transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UcoTransitionDelta {
    pub txid: [u8; 32],
    pub spent_outpoints: Vec<OutPoint>,
    pub created_ucos: Vec<UnretiredCreditOutput>,
    pub retired_poos: Vec<ProofOfOffsetCommitment>,
    pub updated_cursors: Vec<((String, u16), u64)>,
    pub used_data_roots: Vec<[u8; 32]>,
}

/// Read-only interface required by the stateless `apply_uco()` transition engine.
pub trait UcoStoreRead {
    fn chain_id(&self) -> [u8; 32];
    fn current_epoch(&self) -> u64;
    fn get_uco(&self, outpoint: &OutPoint) -> Option<&UnretiredCreditOutput>;
    fn get_serial_cursor(&self, project_id: &str, vintage_year: u16) -> u64;
    fn is_vvb_active(&self, vvb: &PubKey) -> bool;
    fn is_mrv_root_used(&self, root: &[u8; 32]) -> bool;
}

// ---------------------------------------------------------------------------
// Canonical In-Memory UcoState
// ---------------------------------------------------------------------------

/// In-memory state machine implementing `UcoStoreRead` for testing, CLI, and WASM.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UcoState {
    #[serde(with = "crate::auth::hex_bytes32")]
    pub chain_id: [u8; 32],
    pub current_epoch: u64,
    pub unspent_outputs: BTreeMap<OutPoint, UnretiredCreditOutput>,
    pub serial_cursors: BTreeMap<(String, u16), u64>,
    pub poo_archive: Vec<ProofOfOffsetCommitment>,
    pub active_vvbs: BTreeMap<PubKey, String>,
    pub used_data_roots: BTreeSet<[u8; 32]>,
}

impl UcoState {
    pub fn new(chain_id: [u8; 32]) -> Self {
        Self {
            chain_id,
            current_epoch: 0,
            unspent_outputs: BTreeMap::new(),
            serial_cursors: BTreeMap::new(),
            poo_archive: Vec::new(),
            active_vvbs: BTreeMap::new(),
            used_data_roots: BTreeSet::new(),
        }
    }

    /// Mutates the state in-place by applying a valid transaction.
    pub fn apply_in_place(
        &mut self,
        tx: &UcoTransaction,
    ) -> Result<UcoTransitionDelta, RegistryError> {
        let delta = apply_uco(self, tx)?;
        self.commit_delta(&delta);
        Ok(delta)
    }

    /// Commits a computed delta directly into the state.
    pub fn commit_delta(&mut self, delta: &UcoTransitionDelta) {
        for spent in &delta.spent_outpoints {
            self.unspent_outputs.remove(spent);
        }
        for uco in &delta.created_ucos {
            self.unspent_outputs.insert(uco.outpoint, uco.clone());
        }
        for poo in &delta.retired_poos {
            self.poo_archive.push(poo.clone());
        }
        for ((proj, vin), cursor) in &delta.updated_cursors {
            self.serial_cursors.insert((proj.clone(), *vin), *cursor);
        }
        for root in &delta.used_data_roots {
            self.used_data_roots.insert(*root);
        }
    }
}

impl UcoStoreRead for UcoState {
    fn chain_id(&self) -> [u8; 32] {
        self.chain_id
    }

    fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    fn get_uco(&self, outpoint: &OutPoint) -> Option<&UnretiredCreditOutput> {
        self.unspent_outputs.get(outpoint)
    }

    fn get_serial_cursor(&self, project_id: &str, vintage_year: u16) -> u64 {
        self.serial_cursors
            .get(&(project_id.to_string(), vintage_year))
            .copied()
            .unwrap_or(0)
    }

    fn is_vvb_active(&self, vvb: &PubKey) -> bool {
        self.active_vvbs.contains_key(vvb)
    }

    fn is_mrv_root_used(&self, root: &[u8; 32]) -> bool {
        self.used_data_roots.contains(root)
    }
}

// ---------------------------------------------------------------------------
// Pure State Transition Evaluator: apply_uco()
// ---------------------------------------------------------------------------

/// Pure transition rule evaluator.
///
/// Validates transaction invariants against `store` without modifying it,
/// returning the exact delta to be applied.
pub fn apply_uco<S: UcoStoreRead>(
    store: &S,
    tx: &UcoTransaction,
) -> Result<UcoTransitionDelta, RegistryError> {
    match tx {
        UcoTransaction::Mint(mint) => apply_mint(store, mint),
        UcoTransaction::SplitTransfer(transfer) => apply_split_transfer(store, transfer),
        UcoTransaction::Burn(burn) => apply_burn(store, burn),
    }
}

// ---------------------------------------------------------------------------
// Handler: UcoMint
// ---------------------------------------------------------------------------

fn apply_mint<S: UcoStoreRead>(
    store: &S,
    tx: &UcoMintTx,
) -> Result<UcoTransitionDelta, RegistryError> {
    // 1. Basic mass & JS-safe bounds
    if tx.micro_units == 0 {
        return Err(RegistryError::InvalidRange);
    }
    if tx.micro_units > MAX_UCO_MICRO_UNITS {
        return Err(RegistryError::ExceedsJsSafeMax {
            value: tx.micro_units,
            max: MAX_UCO_MICRO_UNITS,
        });
    }

    // 2. Prevent duplicate MRV data root (Bug 9 / RFC-001 Invariant 1)
    if store.is_mrv_root_used(&tx.mrv_data_root) {
        return Err(RegistryError::DuplicateDataRoot);
    }

    // 3. VVB signature verification
    if tx.vvb_signatures.is_empty() {
        return Err(RegistryError::MissingPoI);
    }
    let chain_id = store.chain_id();
    let preimage = tx.signing_preimage(&chain_id);
    for (vvb_key, sig) in &tx.vvb_signatures {
        if !store.is_vvb_active(vvb_key) {
            return Err(RegistryError::UnknownVvb {
                vvb: vvb_key.to_hex(),
            });
        }
        vvb_key
            .verify_strict(&preimage, sig)
            .map_err(|_| RegistryError::BadSignature)?;
    }

    // 4. Monotonic cursor allocation in O(1)
    let current_cursor = store.get_serial_cursor(&tx.project_id, tx.vintage_year);
    let start_micro_unit = current_cursor;
    let end_micro_unit = start_micro_unit
        .checked_add(tx.micro_units)
        .ok_or(RegistryError::Overflow)?;

    if end_micro_unit > MAX_UCO_MICRO_UNITS {
        return Err(RegistryError::ExceedsJsSafeMax {
            value: end_micro_unit,
            max: MAX_UCO_MICRO_UNITS,
        });
    }

    let txid = tx.txid(&chain_id);
    let outpoint = OutPoint::new(txid, 0);

    let challenge_until_epoch = if tx.challenge_window_epochs > 0 {
        store
            .current_epoch()
            .checked_add(tx.challenge_window_epochs)
            .ok_or(RegistryError::Overflow)?
    } else {
        0
    };

    let uco = UnretiredCreditOutput {
        outpoint,
        batch_id: tx.batch_id.clone(),
        project_id: tx.project_id.clone(),
        vintage_year: tx.vintage_year,
        start_micro_unit,
        end_micro_unit,
        micro_units: tx.micro_units,
        owner: tx.initial_owner,
        op_index: 0,
        methodology_hash: tx.methodology_hash,
        mrv_data_root: tx.mrv_data_root,
        mrv_blob_mirrors: tx.mrv_blob_mirrors.clone(),
        challenge_until_epoch,
        locked_escrow_program: None,
    };
    uco.validate()?;

    Ok(UcoTransitionDelta {
        txid,
        spent_outpoints: Vec::new(),
        created_ucos: vec![uco],
        retired_poos: Vec::new(),
        updated_cursors: vec![((tx.project_id.clone(), tx.vintage_year), end_micro_unit)],
        used_data_roots: vec![tx.mrv_data_root],
    })
}

// ---------------------------------------------------------------------------
// Handler: UcoSplitTransfer
// ---------------------------------------------------------------------------

fn apply_split_transfer<S: UcoStoreRead>(
    store: &S,
    tx: &UcoSplitTransferTx,
) -> Result<UcoTransitionDelta, RegistryError> {
    // 1. Anti-spam output limits
    if tx.inputs.is_empty() {
        return Err(RegistryError::NotFound {
            id: "inputs cannot be empty".to_string(),
        });
    }
    if tx.outputs.is_empty() {
        return Err(RegistryError::InvalidRange);
    }
    if tx.outputs.len() > MAX_TX_OUTPUTS {
        return Err(RegistryError::OutputFanoutExceeded {
            count: tx.outputs.len(),
            max: MAX_TX_OUTPUTS,
        });
    }

    // 2. Reject duplicate input OutPoints within the same tx
    let mut seen_inputs = BTreeSet::new();
    for input in &tx.inputs {
        if !seen_inputs.insert(input) {
            return Err(RegistryError::RangeOverlap);
        }
    }

    // 3. Resolve inputs from store and verify homogenous batch attributes
    let mut resolved_inputs = Vec::with_capacity(tx.inputs.len());
    let mut input_op_indices = Vec::with_capacity(tx.inputs.len());
    for op in &tx.inputs {
        let uco = store
            .get_uco(op)
            .ok_or_else(|| RegistryError::OutpointNotFound {
                outpoint: op.to_string(),
            })?;
        resolved_inputs.push(uco);
        input_op_indices.push(uco.op_index);
    }

    let first = resolved_inputs[0];
    for uco in &resolved_inputs[1..] {
        if uco.project_id != first.project_id
            || uco.vintage_year != first.vintage_year
            || uco.batch_id != first.batch_id
            || uco.methodology_hash != first.methodology_hash
            || uco.mrv_data_root != first.mrv_data_root
        {
            return Err(RegistryError::InvalidStateTransition {
                from: format!("mixed batch inputs: {} vs {}", first.batch_id, uco.batch_id),
                to: "UcoSplitTransfer".to_string(),
            });
        }
    }

    // 4. Verify input signatures
    if tx.input_signatures.len() != tx.inputs.len() {
        return Err(RegistryError::BadSignature);
    }
    let chain_id = store.chain_id();
    let preimage = tx.signing_preimage(&chain_id, &input_op_indices);
    for (uco, sig) in resolved_inputs.iter().zip(&tx.input_signatures) {
        uco.owner
            .verify_strict(&preimage, sig)
            .map_err(|_| RegistryError::BadSignature)?;
    }

    // 5. Partition split verification:
    // multiset of output intervals must be pairwise disjoint and exactly cover input intervals.
    verify_partition(&resolved_inputs, &tx.outputs)?;

    // 6. Generate output UCOs
    let txid = tx.txid(&chain_id, &input_op_indices);
    let mut created_ucos = Vec::with_capacity(tx.outputs.len());
    for (vout, out_spec) in tx.outputs.iter().enumerate() {
        let outpoint = OutPoint::new(txid, vout as u32);
        let uco = UnretiredCreditOutput {
            outpoint,
            batch_id: first.batch_id.clone(),
            project_id: first.project_id.clone(),
            vintage_year: first.vintage_year,
            start_micro_unit: out_spec.start_micro_unit,
            end_micro_unit: out_spec.end_micro_unit,
            micro_units: out_spec.micro_units,
            owner: out_spec.owner,
            op_index: 0,
            methodology_hash: first.methodology_hash,
            mrv_data_root: first.mrv_data_root,
            mrv_blob_mirrors: first.mrv_blob_mirrors.clone(),
            challenge_until_epoch: first.challenge_until_epoch,
            locked_escrow_program: out_spec.locked_escrow_program.clone(),
        };
        uco.validate()?;
        created_ucos.push(uco);
    }

    Ok(UcoTransitionDelta {
        txid,
        spent_outpoints: tx.inputs.clone(),
        created_ucos,
        retired_poos: Vec::new(),
        updated_cursors: Vec::new(),
        used_data_roots: Vec::new(),
    })
}

// ---------------------------------------------------------------------------
// Handler: UcoBurn
// ---------------------------------------------------------------------------

fn apply_burn<S: UcoStoreRead>(
    store: &S,
    tx: &UcoBurnTx,
) -> Result<UcoTransitionDelta, RegistryError> {
    // 1. Resolve input UCO
    let uco = store
        .get_uco(&tx.input)
        .ok_or_else(|| RegistryError::OutpointNotFound {
            outpoint: tx.input.to_string(),
        })?;

    // 2. Pre-retirement challenge window guard (RFC-007 §6)
    if store.current_epoch() < uco.challenge_until_epoch {
        return Err(RegistryError::ChallengeWindowActive {
            current: store.current_epoch(),
            challenge_until: uco.challenge_until_epoch,
        });
    }

    // 3. Escrow lock guard
    if let Some(escrow) = &uco.locked_escrow_program {
        return Err(RegistryError::EscrowLocked {
            program: escrow.clone(),
        });
    }

    // 4. Validate burn interval containment
    if tx.start_micro_unit >= tx.end_micro_unit {
        return Err(RegistryError::InvalidRange);
    }
    let burn_width = tx
        .end_micro_unit
        .checked_sub(tx.start_micro_unit)
        .ok_or(RegistryError::Overflow)?;
    if burn_width != tx.micro_units {
        return Err(RegistryError::UcoIntervalMismatch {
            expected: burn_width,
            found: tx.micro_units,
        });
    }
    if tx.start_micro_unit < uco.start_micro_unit || tx.end_micro_unit > uco.end_micro_unit {
        return Err(RegistryError::BurnRangeNotFound {
            start: tx.start_micro_unit,
            end: tx.end_micro_unit,
        });
    }

    // 5. Verify owner signature
    let chain_id = store.chain_id();
    let preimage = tx.signing_preimage(&chain_id, uco.op_index);
    uco.owner
        .verify_strict(&preimage, &tx.owner_sig)
        .map_err(|_| RegistryError::BadSignature)?;

    let txid = tx.txid(&chain_id, uco.op_index);

    // 6. Create immutable ProofOfOffsetCommitment
    let poo = ProofOfOffsetCommitment {
        consumed_outpoint: tx.input,
        batch_id: uco.batch_id.clone(),
        project_id: uco.project_id.clone(),
        vintage_year: uco.vintage_year,
        start_micro_unit: tx.start_micro_unit,
        end_micro_unit: tx.end_micro_unit,
        micro_units: tx.micro_units,
        beneficiary: tx.beneficiary.clone(),
        claim_type: tx.claim_type.clone(),
        retirement_epoch: store.current_epoch(),
        owner_sig: tx.owner_sig,
    };
    poo.validate()?;

    // 7. Handle change outputs for partial retirement:
    // If the input was [A, C) and burned interval is [A, B), change is [B, C).
    // If burned interval is [B, C), change is [A, B).
    // If burned interval is strictly inside [A, D) at [B, C), change outputs are [A, B) and [C, D).
    let mut created_ucos = Vec::new();
    let change_recipient = tx.change_owner.unwrap_or(uco.owner);

    let mut vout_counter = 0u32;
    // Left change [uco.start, tx.start)
    if uco.start_micro_unit < tx.start_micro_unit {
        let left_units = tx.start_micro_unit - uco.start_micro_unit;
        let left_uco = UnretiredCreditOutput {
            outpoint: OutPoint::new(txid, vout_counter),
            batch_id: uco.batch_id.clone(),
            project_id: uco.project_id.clone(),
            vintage_year: uco.vintage_year,
            start_micro_unit: uco.start_micro_unit,
            end_micro_unit: tx.start_micro_unit,
            micro_units: left_units,
            owner: change_recipient,
            op_index: 0,
            methodology_hash: uco.methodology_hash,
            mrv_data_root: uco.mrv_data_root,
            mrv_blob_mirrors: uco.mrv_blob_mirrors.clone(),
            challenge_until_epoch: uco.challenge_until_epoch,
            locked_escrow_program: None,
        };
        left_uco.validate()?;
        created_ucos.push(left_uco);
        vout_counter += 1;
    }

    // Right change [tx.end, uco.end)
    if tx.end_micro_unit < uco.end_micro_unit {
        let right_units = uco.end_micro_unit - tx.end_micro_unit;
        let right_uco = UnretiredCreditOutput {
            outpoint: OutPoint::new(txid, vout_counter),
            batch_id: uco.batch_id.clone(),
            project_id: uco.project_id.clone(),
            vintage_year: uco.vintage_year,
            start_micro_unit: tx.end_micro_unit,
            end_micro_unit: uco.end_micro_unit,
            micro_units: right_units,
            owner: change_recipient,
            op_index: 0,
            methodology_hash: uco.methodology_hash,
            mrv_data_root: uco.mrv_data_root,
            mrv_blob_mirrors: uco.mrv_blob_mirrors.clone(),
            challenge_until_epoch: uco.challenge_until_epoch,
            locked_escrow_program: None,
        };
        right_uco.validate()?;
        created_ucos.push(right_uco);
    }

    Ok(UcoTransitionDelta {
        txid,
        spent_outpoints: vec![tx.input],
        created_ucos,
        retired_poos: vec![poo],
        updated_cursors: Vec::new(),
        used_data_roots: Vec::new(),
    })
}

// ---------------------------------------------------------------------------
// Helper: Disjoint Partition Verification
// ---------------------------------------------------------------------------

/// Normalizes a list of half-open intervals `[start, end)` by sorting and
/// collapsing adjacent or overlapping intervals.
fn normalize_intervals(mut intervals: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    if intervals.is_empty() {
        return Vec::new();
    }
    intervals.sort_by_key(|&(s, _)| s);

    let mut merged = Vec::with_capacity(intervals.len());
    let (mut cur_s, mut cur_e) = intervals[0];

    for &(s, e) in &intervals[1..] {
        if s <= cur_e {
            cur_e = cur_e.max(e);
        } else {
            merged.push((cur_s, cur_e));
            cur_s = s;
            cur_e = e;
        }
    }
    merged.push((cur_s, cur_e));
    merged
}

/// Verifies that `outputs` form an exact disjoint partition of `inputs`.
fn verify_partition(
    inputs: &[&UnretiredCreditOutput],
    outputs: &[UcoTransferOutputSpec],
) -> Result<(), RegistryError> {
    // 1. Verify every output has valid intervals and sum matches width
    let mut total_out_units = 0u64;
    for out in outputs {
        if out.start_micro_unit >= out.end_micro_unit {
            return Err(RegistryError::InvalidRange);
        }
        let width = out
            .end_micro_unit
            .checked_sub(out.start_micro_unit)
            .ok_or(RegistryError::Overflow)?;
        if width != out.micro_units {
            return Err(RegistryError::UcoIntervalMismatch {
                expected: width,
                found: out.micro_units,
            });
        }
        total_out_units = total_out_units
            .checked_add(out.micro_units)
            .ok_or(RegistryError::Overflow)?;
    }

    // 2. Total units must match exactly
    let mut total_in_units = 0u64;
    for inp in inputs {
        total_in_units = total_in_units
            .checked_add(inp.micro_units)
            .ok_or(RegistryError::Overflow)?;
    }
    if total_in_units != total_out_units {
        return Err(RegistryError::DisjointPartitionViolation);
    }

    // 3. Verify outputs are pairwise disjoint
    let mut sorted_outs = outputs.to_vec();
    sorted_outs.sort_by_key(|o| o.start_micro_unit);
    for window in sorted_outs.windows(2) {
        if window[0].end_micro_unit > window[1].start_micro_unit {
            return Err(RegistryError::RangeOverlap);
        }
    }

    // 4. Normalized union of inputs must exactly match normalized union of outputs
    let in_intervals: Vec<(u64, u64)> = inputs
        .iter()
        .map(|i| (i.start_micro_unit, i.end_micro_unit))
        .collect();
    let out_intervals: Vec<(u64, u64)> = outputs
        .iter()
        .map(|o| (o.start_micro_unit, o.end_micro_unit))
        .collect();

    let norm_in = normalize_intervals(in_intervals);
    let norm_out = normalize_intervals(out_intervals);

    if norm_in != norm_out {
        return Err(RegistryError::DisjointPartitionViolation);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Keypair;

    fn setup_test_state() -> (UcoState, Keypair, Keypair) {
        let chain_id = [0x99u8; 32];
        let mut state = UcoState::new(chain_id);
        let vvb = Keypair::generate();
        let owner = Keypair::generate();
        state
            .active_vvbs
            .insert(vvb.pubkey(), "TUV-Nord".to_string());
        (state, vvb, owner)
    }

    fn sample_mint_tx(vvb: &Keypair, owner: &Keypair, units: u64) -> UcoMintTx {
        let chain_id = [0x99u8; 32];
        let mut tx = UcoMintTx {
            project_id: "PROJ-SOLAR-01".to_string(),
            batch_id: "BATCH-2026-A".to_string(),
            vintage_year: 2026,
            micro_units: units,
            initial_owner: owner.pubkey(),
            methodology_hash: [0x11; 32],
            mrv_data_root: [0x22; 32],
            mrv_blob_mirrors: vec!["https://mirror.example.com/blob".to_string()],
            challenge_window_epochs: 10,
            vvb_signatures: Vec::new(),
        };
        let preimage = tx.signing_preimage(&chain_id);
        tx.vvb_signatures.push((vvb.pubkey(), vvb.sign(&preimage)));
        tx
    }

    #[test]
    fn test_mint_allocates_cursor_monotonically() {
        let (mut state, vvb, owner) = setup_test_state();

        // 1st mint of 1,000,000 units
        let tx1 = sample_mint_tx(&vvb, &owner, 1_000_000);
        let delta1 = state.apply_in_place(&UcoTransaction::Mint(tx1)).unwrap();

        assert_eq!(delta1.created_ucos.len(), 1);
        let uco1 = &delta1.created_ucos[0];
        assert_eq!(uco1.start_micro_unit, 0);
        assert_eq!(uco1.end_micro_unit, 1_000_000);
        assert_eq!(uco1.micro_units, 1_000_000);
        assert_eq!(state.get_serial_cursor("PROJ-SOLAR-01", 2026), 1_000_000);

        // 2nd mint of 500,000 units on same project/vintage (with different data root)
        let mut tx2 = sample_mint_tx(&vvb, &owner, 500_000);
        tx2.mrv_data_root = [0x33; 32];
        tx2.vvb_signatures.clear();
        let preimage2 = tx2.signing_preimage(&state.chain_id);
        tx2.vvb_signatures
            .push((vvb.pubkey(), vvb.sign(&preimage2)));

        let delta2 = state.apply_in_place(&UcoTransaction::Mint(tx2)).unwrap();
        let uco2 = &delta2.created_ucos[0];
        assert_eq!(uco2.start_micro_unit, 1_000_000);
        assert_eq!(uco2.end_micro_unit, 1_500_000);
        assert_eq!(uco2.micro_units, 500_000);
        assert_eq!(state.get_serial_cursor("PROJ-SOLAR-01", 2026), 1_500_000);
    }

    #[test]
    fn test_mint_rejects_duplicate_data_root() {
        let (mut state, vvb, owner) = setup_test_state();
        let tx1 = sample_mint_tx(&vvb, &owner, 1_000_000);
        state
            .apply_in_place(&UcoTransaction::Mint(tx1.clone()))
            .unwrap();

        // Attempt second mint with identical mrv_data_root
        let err = state
            .apply_in_place(&UcoTransaction::Mint(tx1))
            .unwrap_err();
        assert_eq!(err, RegistryError::DuplicateDataRoot);
    }

    #[test]
    fn test_mint_rejects_unregistered_vvb() {
        let (mut state, _vvb, owner) = setup_test_state();
        let fake_vvb = Keypair::generate();
        let tx = sample_mint_tx(&fake_vvb, &owner, 1_000_000);
        let err = state.apply_in_place(&UcoTransaction::Mint(tx)).unwrap_err();
        assert!(matches!(err, RegistryError::UnknownVvb { .. }));
    }

    #[test]
    fn test_mint_rejects_exceeding_js_safe_max() {
        let (mut state, vvb, owner) = setup_test_state();
        let mut tx = sample_mint_tx(&vvb, &owner, MAX_UCO_MICRO_UNITS + 1);
        tx.vvb_signatures.clear();
        let p = tx.signing_preimage(&state.chain_id);
        tx.vvb_signatures.push((vvb.pubkey(), vvb.sign(&p)));

        let err = state.apply_in_place(&UcoTransaction::Mint(tx)).unwrap_err();
        assert!(matches!(err, RegistryError::ExceedsJsSafeMax { .. }));
    }

    #[test]
    fn test_split_transfer_single_input_two_outputs() {
        let (mut state, vvb, owner) = setup_test_state();
        let mint_tx = sample_mint_tx(&vvb, &owner, 1_000_000);
        let mint_delta = state
            .apply_in_place(&UcoTransaction::Mint(mint_tx))
            .unwrap();
        let input_op = mint_delta.created_ucos[0].outpoint;

        let buyer = Keypair::generate();

        // Split [0, 1_000_000) -> [0, 400_000) (buyer) + [400_000, 1_000_000) (change)
        let mut transfer_tx = UcoSplitTransferTx {
            inputs: vec![input_op],
            outputs: vec![
                UcoTransferOutputSpec {
                    owner: buyer.pubkey(),
                    start_micro_unit: 0,
                    end_micro_unit: 400_000,
                    micro_units: 400_000,
                    locked_escrow_program: None,
                },
                UcoTransferOutputSpec {
                    owner: owner.pubkey(),
                    start_micro_unit: 400_000,
                    end_micro_unit: 1_000_000,
                    micro_units: 600_000,
                    locked_escrow_program: None,
                },
            ],
            input_signatures: Vec::new(),
        };

        let preimage = transfer_tx.signing_preimage(&state.chain_id, &[0]);
        transfer_tx.input_signatures.push(owner.sign(&preimage));

        let delta = state
            .apply_in_place(&UcoTransaction::SplitTransfer(transfer_tx))
            .unwrap();

        assert_eq!(delta.spent_outpoints, vec![input_op]);
        assert_eq!(delta.created_ucos.len(), 2);
        assert!(!state.unspent_outputs.contains_key(&input_op));
        assert_eq!(state.unspent_outputs.len(), 2);
    }

    #[test]
    fn test_split_transfer_rejects_overlapping_outputs() {
        let (mut state, vvb, owner) = setup_test_state();
        let mint_tx = sample_mint_tx(&vvb, &owner, 1_000_000);
        let mint_delta = state
            .apply_in_place(&UcoTransaction::Mint(mint_tx))
            .unwrap();
        let input_op = mint_delta.created_ucos[0].outpoint;

        // Overlapping outputs: [0, 600_000) and [500_000, 1_000_000)
        let mut transfer_tx = UcoSplitTransferTx {
            inputs: vec![input_op],
            outputs: vec![
                UcoTransferOutputSpec {
                    owner: owner.pubkey(),
                    start_micro_unit: 0,
                    end_micro_unit: 600_000,
                    micro_units: 600_000,
                    locked_escrow_program: None,
                },
                UcoTransferOutputSpec {
                    owner: owner.pubkey(),
                    start_micro_unit: 500_000,
                    end_micro_unit: 1_000_000,
                    micro_units: 500_000,
                    locked_escrow_program: None,
                },
            ],
            input_signatures: Vec::new(),
        };

        let preimage = transfer_tx.signing_preimage(&state.chain_id, &[0]);
        transfer_tx.input_signatures.push(owner.sign(&preimage));

        let err = state
            .apply_in_place(&UcoTransaction::SplitTransfer(transfer_tx))
            .unwrap_err();
        assert_eq!(err, RegistryError::DisjointPartitionViolation);
    }

    #[test]
    fn test_split_transfer_rejects_fanout_exceeded() {
        let (state, _vvb, owner) = setup_test_state();
        let outputs: Vec<UcoTransferOutputSpec> = (0..MAX_TX_OUTPUTS + 1)
            .map(|i| UcoTransferOutputSpec {
                owner: owner.pubkey(),
                start_micro_unit: (i as u64) * 100,
                end_micro_unit: (i as u64 + 1) * 100,
                micro_units: 100,
                locked_escrow_program: None,
            })
            .collect();

        let transfer_tx = UcoSplitTransferTx {
            inputs: vec![OutPoint::new([0x11; 32], 0)],
            outputs,
            input_signatures: vec![Signature::default()],
        };

        let err = apply_uco(&state, &UcoTransaction::SplitTransfer(transfer_tx)).unwrap_err();
        assert!(matches!(err, RegistryError::OutputFanoutExceeded { .. }));
    }

    #[test]
    fn test_burn_full_interval_after_challenge_window() {
        let (mut state, vvb, owner) = setup_test_state();
        let mint_tx = sample_mint_tx(&vvb, &owner, 1_000_000);
        let mint_delta = state
            .apply_in_place(&UcoTransaction::Mint(mint_tx))
            .unwrap();
        let input_op = mint_delta.created_ucos[0].outpoint;

        // Challenge window is 10 epochs. Advance current_epoch to 10.
        state.current_epoch = 10;

        let mut burn_tx = UcoBurnTx {
            input: input_op,
            start_micro_unit: 0,
            end_micro_unit: 1_000_000,
            micro_units: 1_000_000,
            beneficiary: "Acme Corp Scope 1".to_string(),
            claim_type: PoOClaimType::Voluntary,
            owner_sig: Signature::default(),
            change_owner: None,
        };
        let preimage = burn_tx.signing_preimage(&state.chain_id, 0);
        burn_tx.owner_sig = owner.sign(&preimage);

        let delta = state
            .apply_in_place(&UcoTransaction::Burn(burn_tx))
            .unwrap();

        assert_eq!(delta.retired_poos.len(), 1);
        assert_eq!(delta.created_ucos.len(), 0); // full burn, no change
        assert!(!state.unspent_outputs.contains_key(&input_op));
        assert_eq!(state.poo_archive.len(), 1);
    }

    #[test]
    fn test_burn_rejects_active_challenge_window() {
        let (mut state, vvb, owner) = setup_test_state();
        let mint_tx = sample_mint_tx(&vvb, &owner, 1_000_000);
        let mint_delta = state
            .apply_in_place(&UcoTransaction::Mint(mint_tx))
            .unwrap();
        let input_op = mint_delta.created_ucos[0].outpoint;

        // State epoch is 5 (< challenge_until_epoch = 10)
        state.current_epoch = 5;

        let mut burn_tx = UcoBurnTx {
            input: input_op,
            start_micro_unit: 0,
            end_micro_unit: 1_000_000,
            micro_units: 1_000_000,
            beneficiary: "Premature Burn".to_string(),
            claim_type: PoOClaimType::Voluntary,
            owner_sig: Signature::default(),
            change_owner: None,
        };
        let preimage = burn_tx.signing_preimage(&state.chain_id, 0);
        burn_tx.owner_sig = owner.sign(&preimage);

        let err = state
            .apply_in_place(&UcoTransaction::Burn(burn_tx))
            .unwrap_err();
        assert!(matches!(err, RegistryError::ChallengeWindowActive { .. }));
    }

    #[test]
    fn test_burn_partial_emits_change_output() {
        let (mut state, vvb, owner) = setup_test_state();
        let mint_tx = sample_mint_tx(&vvb, &owner, 1_000_000);
        let mint_delta = state
            .apply_in_place(&UcoTransaction::Mint(mint_tx))
            .unwrap();
        let input_op = mint_delta.created_ucos[0].outpoint;

        state.current_epoch = 10;

        // Burn middle portion: [200_000, 700_000) (500_000 units)
        // Expected change outputs: [0, 200_000) and [700_000, 1_000_000)
        let mut burn_tx = UcoBurnTx {
            input: input_op,
            start_micro_unit: 200_000,
            end_micro_unit: 700_000,
            micro_units: 500_000,
            beneficiary: "Partial Retirement".to_string(),
            claim_type: PoOClaimType::NetZero,
            owner_sig: Signature::default(),
            change_owner: None,
        };
        let preimage = burn_tx.signing_preimage(&state.chain_id, 0);
        burn_tx.owner_sig = owner.sign(&preimage);

        let delta = state
            .apply_in_place(&UcoTransaction::Burn(burn_tx))
            .unwrap();

        assert_eq!(delta.retired_poos.len(), 1);
        assert_eq!(delta.created_ucos.len(), 2); // left and right change!
        assert_eq!(delta.created_ucos[0].start_micro_unit, 0);
        assert_eq!(delta.created_ucos[0].end_micro_unit, 200_000);
        assert_eq!(delta.created_ucos[1].start_micro_unit, 700_000);
        assert_eq!(delta.created_ucos[1].end_micro_unit, 1_000_000);
        assert_eq!(state.unspent_outputs.len(), 2);
    }
}
