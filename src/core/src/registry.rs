use crate::auth::{
    build_authority_event_preimage, build_authority_rotate_payload, build_burn_preimage,
    build_genesis_preimage, build_mint_preimage, build_sequencer_rotate_payload,
    build_transfer_preimage, build_vvb_register_payload, build_vvb_revoke_payload,
    compute_chain_id, compute_poi_hash, MintAttestationParams, PubKey, Signature,
};
use crate::credit::{normalize_slices, CreditBatch, CreditStatus, SerialSlice};
use crate::error::RegistryError;
use crate::poi::PoI;
use crate::poo::{ClaimType, PoO, PoOStatus};
use crate::serial::SerialRange;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Operational status and metadata for an accredited Validation & Verification Body (RFC-005).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VvbInfo {
    pub label: String,
    pub active: bool,
}

/// The canonical, immutable state of the protocol registry.
/// Purely functional: state transitions produce a new `RegistryState`.
#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryState {
    /// Domain-separated unique 32-byte identifier for this registry instance
    #[serde(with = "crate::auth::hex_bytes32")]
    pub chain_id: [u8; 32],
    /// Accredited administrative root authority for registry governance & VVB lifecycle
    pub authority: PubKey,
    /// Authorized sequencer key designated to sequence and sign checkpoints
    pub sequencer: PubKey,
    /// Monotonically increasing sequence counter for authority actions (replay protection)
    pub authority_index: u64,
    /// Whitelist of registered Validation & Verification Bodies authorized to attest mints
    pub vvbs: BTreeMap<PubKey, VvbInfo>,
    /// Active and retired credit batches representing all issued supply
    pub credits: Vec<CreditBatch>,
    /// Globally immutable append-only record of all retired/burned ranges (Invariant 4 & 5)
    pub burned_ranges: Vec<SerialRange>,
    /// Set of all MRV data roots (merkle roots) that have been minted, preventing double-counting (Bug 9)
    pub used_data_roots: BTreeSet<[u8; 32]>,
}

/// The discrete events that cause state transitions in the GreyMisnomer protocol (RFC-005).
/// Serializable to and from JSON/JSONL for event logging and deterministic replayability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum RegistryEvent {
    #[serde(rename = "genesis")]
    Genesis {
        chain_name: String,
        authority: PubKey,
        sequencer: PubKey,
        #[serde(with = "crate::auth::hex_bytes32")]
        nonce: [u8; 32],
        created_at: u64,
        authority_sig: Signature,
    },
    #[serde(rename = "vvb_register")]
    VvbRegister {
        authority_index: u64,
        vvb: PubKey,
        label: String,
        authority_sig: Signature,
    },
    #[serde(rename = "vvb_revoke")]
    VvbRevoke {
        authority_index: u64,
        vvb: PubKey,
        authority_sig: Signature,
    },
    #[serde(rename = "mint")]
    Mint {
        project_id: String,
        credit_id: String,
        range_start: u64,
        range_end: u64,
        cc_mint_amount: u64,
        #[serde(with = "crate::auth::hex_bytes32")]
        merkle_root: [u8; 32],
        leaf_count: u64,
        mrv_timestamp: u64,
        methodology_hash: String,
        jurisdiction: String,
        market_scope: String,
        valid_from: u64,
        valid_until: u64,
        initial_owner: PubKey,
        vvb: PubKey,
        vvb_sig: Signature,
    },
    #[serde(rename = "transfer")]
    Transfer {
        credit_id: String,
        op_index: u64,
        new_owner: PubKey,
        owner_sig: Signature,
    },
    #[serde(rename = "burn")]
    Burn {
        credit_id: String,
        op_index: u64,
        range_start: u64,
        range_end: u64,
        beneficiary: String,
        claim_type: ClaimType,
        owner_sig: Signature,
    },
    #[serde(rename = "authority_rotate")]
    AuthorityRotate {
        authority_index: u64,
        new_authority: PubKey,
        authority_sig: Signature,
    },
    #[serde(rename = "sequencer_rotate")]
    SequencerRotate {
        authority_index: u64,
        new_sequencer: PubKey,
        authority_sig: Signature,
    },
}

impl RegistryEvent {
    /// Computes the exact canonical binary body bytes for entry hash commitments (RFC-005 §3.6).
    pub fn to_body_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            RegistryEvent::Genesis {
                chain_name,
                authority,
                sequencer,
                nonce,
                created_at,
                authority_sig,
            } => {
                crate::auth::enc_tag(0, &mut buf);
                crate::auth::enc_str(chain_name, &mut buf);
                crate::auth::enc_pubkey(authority, &mut buf);
                crate::auth::enc_pubkey(sequencer, &mut buf);
                crate::auth::enc_bytes32(nonce, &mut buf);
                crate::auth::enc_u64(*created_at, &mut buf);
                crate::auth::enc_sig(authority_sig, &mut buf);
            }
            RegistryEvent::VvbRegister {
                authority_index,
                vvb,
                label,
                authority_sig,
            } => {
                crate::auth::enc_tag(1, &mut buf);
                crate::auth::enc_u64(*authority_index, &mut buf);
                crate::auth::enc_pubkey(vvb, &mut buf);
                crate::auth::enc_str(label, &mut buf);
                crate::auth::enc_sig(authority_sig, &mut buf);
            }
            RegistryEvent::VvbRevoke {
                authority_index,
                vvb,
                authority_sig,
            } => {
                crate::auth::enc_tag(2, &mut buf);
                crate::auth::enc_u64(*authority_index, &mut buf);
                crate::auth::enc_pubkey(vvb, &mut buf);
                crate::auth::enc_sig(authority_sig, &mut buf);
            }
            RegistryEvent::Mint {
                project_id,
                credit_id,
                range_start,
                range_end,
                cc_mint_amount,
                merkle_root,
                leaf_count,
                mrv_timestamp,
                methodology_hash,
                jurisdiction,
                market_scope,
                valid_from,
                valid_until,
                initial_owner,
                vvb,
                vvb_sig,
            } => {
                crate::auth::enc_tag(3, &mut buf);
                crate::auth::enc_str(project_id, &mut buf);
                crate::auth::enc_str(credit_id, &mut buf);
                crate::auth::enc_u64(*range_start, &mut buf);
                crate::auth::enc_u64(*range_end, &mut buf);
                crate::auth::enc_u64(*cc_mint_amount, &mut buf);
                crate::auth::enc_bytes32(merkle_root, &mut buf);
                crate::auth::enc_u64(*leaf_count, &mut buf);
                crate::auth::enc_u64(*mrv_timestamp, &mut buf);
                crate::auth::enc_str(methodology_hash, &mut buf);
                crate::auth::enc_str(jurisdiction, &mut buf);
                crate::auth::enc_str(market_scope, &mut buf);
                crate::auth::enc_u64(*valid_from, &mut buf);
                crate::auth::enc_u64(*valid_until, &mut buf);
                crate::auth::enc_pubkey(initial_owner, &mut buf);
                crate::auth::enc_pubkey(vvb, &mut buf);
                crate::auth::enc_sig(vvb_sig, &mut buf);
            }
            RegistryEvent::Transfer {
                credit_id,
                op_index,
                new_owner,
                owner_sig,
            } => {
                crate::auth::enc_tag(4, &mut buf);
                crate::auth::enc_str(credit_id, &mut buf);
                crate::auth::enc_u64(*op_index, &mut buf);
                crate::auth::enc_pubkey(new_owner, &mut buf);
                crate::auth::enc_sig(owner_sig, &mut buf);
            }
            RegistryEvent::Burn {
                credit_id,
                op_index,
                range_start,
                range_end,
                beneficiary,
                claim_type,
                owner_sig,
            } => {
                crate::auth::enc_tag(5, &mut buf);
                crate::auth::enc_str(credit_id, &mut buf);
                crate::auth::enc_u64(*op_index, &mut buf);
                crate::auth::enc_u64(*range_start, &mut buf);
                crate::auth::enc_u64(*range_end, &mut buf);
                crate::auth::enc_str(beneficiary, &mut buf);
                crate::auth::enc_str(claim_type.as_str(), &mut buf);
                crate::auth::enc_sig(owner_sig, &mut buf);
            }
            RegistryEvent::AuthorityRotate {
                authority_index,
                new_authority,
                authority_sig,
            } => {
                crate::auth::enc_tag(6, &mut buf);
                crate::auth::enc_u64(*authority_index, &mut buf);
                crate::auth::enc_pubkey(new_authority, &mut buf);
                crate::auth::enc_sig(authority_sig, &mut buf);
            }
            RegistryEvent::SequencerRotate {
                authority_index,
                new_sequencer,
                authority_sig,
            } => {
                crate::auth::enc_tag(7, &mut buf);
                crate::auth::enc_u64(*authority_index, &mut buf);
                crate::auth::enc_pubkey(new_sequencer, &mut buf);
                crate::auth::enc_sig(authority_sig, &mut buf);
            }
        }
        buf
    }
}

/// Pure state transition function: apply(state, event) -> Result<RegistryState, RegistryError>
///
/// Guaranteed properties:
/// 1. Pure: No I/O, no system time, no global mutable state, no side effects.
/// 2. Deterministic: Given the identical state and event, it always produces the identical new state or error.
/// 3. Invariant-preserving: Valid state + valid event => valid new state satisfying all protocol and authorization invariants.
pub fn apply(state: &RegistryState, event: &RegistryEvent) -> Result<RegistryState, RegistryError> {
    match event {
        RegistryEvent::Genesis { .. } => apply_genesis(state, event),
        RegistryEvent::VvbRegister { .. } => apply_vvb_register(state, event),
        RegistryEvent::VvbRevoke { .. } => apply_vvb_revoke(state, event),
        RegistryEvent::Mint { .. } => apply_mint(state, event),
        RegistryEvent::Transfer { .. } => apply_transfer(state, event),
        RegistryEvent::Burn { .. } => apply_burn(state, event),
        RegistryEvent::AuthorityRotate { .. } => apply_authority_rotate(state, event),
        RegistryEvent::SequencerRotate { .. } => apply_sequencer_rotate(state, event),
    }
}

fn apply_mint(
    state: &RegistryState,
    event: &RegistryEvent,
) -> Result<RegistryState, RegistryError> {
    let RegistryEvent::Mint {
        project_id,
        credit_id,
        range_start,
        range_end,
        cc_mint_amount,
        merkle_root,
        leaf_count,
        mrv_timestamp,
        methodology_hash,
        jurisdiction,
        market_scope,
        valid_from,
        valid_until,
        initial_owner,
        vvb,
        vvb_sig,
    } = event
    else {
        return Err(RegistryError::CorruptedState);
    };

    // 1. VVB must be active and registered (RFC-005 Invariant 1)
    if !state.is_vvb_active(vvb) {
        if state.vvbs.contains_key(vvb) {
            return Err(RegistryError::VvbRevoked { vvb: vvb.to_hex() });
        } else {
            return Err(RegistryError::UnknownVvb { vvb: vvb.to_hex() });
        }
    }

    // 2. Validate serial range
    let range = SerialRange::new(*range_start, *range_end)?;
    let range_size = range.size()?;

    // RFC-005 §3.5: range.size() == cc_mint_amount
    if range_size != *cc_mint_amount {
        return Err(RegistryError::SupplyExceeded);
    }

    // 3. Strict Ed25519 verification of VVB attestation signature (Invariant A1, A3)
    let mint_params = MintAttestationParams {
        chain_id: &state.chain_id,
        project_id,
        credit_id,
        range_start: *range_start,
        range_end: *range_end,
        cc_mint_amount: *cc_mint_amount,
        merkle_root,
        leaf_count: *leaf_count,
        mrv_timestamp: *mrv_timestamp,
        methodology_hash,
        jurisdiction,
        market_scope,
        valid_from: *valid_from,
        valid_until: *valid_until,
        initial_owner,
    };
    let mint_msg = build_mint_preimage(&mint_params);
    vvb.verify_strict(&mint_msg, vvb_sig)?;

    // 4. Invariant 4: Global burned range check
    for burned in &state.burned_ranges {
        if burned.overlaps(&range) {
            return Err(RegistryError::BurnIrreversible);
        }
    }

    // 5. Invariant 3: Global active slice overlap check
    for existing in &state.credits {
        for slice in &existing.slices {
            if slice.status == CreditStatus::Active && slice.range.overlaps(&range) {
                return Err(RegistryError::RangeOverlap);
            }
        }
    }

    // 6. Check unique credit_id
    if state.credits.iter().any(|c| c.credit_id == *credit_id) {
        return Err(RegistryError::DuplicateCreditId);
    }

    // 7. Check unique MRV data root (Bug 9)
    if state.used_data_roots.contains(merkle_root) {
        return Err(RegistryError::DuplicateDataRoot);
    }

    // 8. Compute poi_hash and check Invariant 7 (poi_hash uniqueness)
    let poi_hash = compute_poi_hash(&mint_msg, vvb_sig);
    if state.credits.iter().any(|c| c.poi_hash == poi_hash) {
        return Err(RegistryError::PoIAlreadyUsed);
    }

    let batch = CreditBatch {
        project_id: project_id.clone(),
        credit_id: credit_id.clone(),
        original_range: range,
        slices: vec![SerialSlice {
            range,
            status: CreditStatus::Active,
        }],
        owner: *initial_owner,
        op_index: 0,
        vvb: *vvb,
        poi_hash,
    };

    let mut new_state = state.clone();
    new_state.used_data_roots.insert(*merkle_root);
    new_state.credits.push(batch);
    Ok(new_state)
}

fn apply_transfer(
    state: &RegistryState,
    event: &RegistryEvent,
) -> Result<RegistryState, RegistryError> {
    let RegistryEvent::Transfer {
        credit_id,
        op_index,
        new_owner,
        owner_sig,
    } = event
    else {
        return Err(RegistryError::CorruptedState);
    };

    let credit = state
        .credits
        .iter()
        .find(|c| c.credit_id == *credit_id)
        .ok_or_else(|| RegistryError::NotFound {
            id: credit_id.clone(),
        })?;

    if !credit.is_active() {
        return Err(RegistryError::InvalidStateTransition {
            from: "Retired/Expired".to_string(),
            to: "Active".to_string(),
        });
    }

    // Check op_index
    if *op_index != credit.op_index {
        return Err(RegistryError::BadOpIndex {
            expected: credit.op_index,
            found: *op_index,
        });
    }

    // Prevent transferring to self
    if new_owner == &credit.owner {
        return Err(RegistryError::OwnerMismatch {
            expected: format!("different owner from {}", credit.owner),
            found: credit.owner.to_hex(),
        });
    }

    // Verify strict Ed25519 detached signature under current batch.owner (Invariant A1, A3)
    let transfer_msg = build_transfer_preimage(&state.chain_id, credit_id, *op_index, new_owner);
    credit.owner.verify_strict(&transfer_msg, owner_sig)?;

    let mut new_state = state.clone();
    let target = new_state
        .credits
        .iter_mut()
        .find(|c| c.credit_id == *credit_id)
        .unwrap();
    target.owner = *new_owner;
    target.op_index += 1;
    Ok(new_state)
}

fn apply_genesis(
    state: &RegistryState,
    event: &RegistryEvent,
) -> Result<RegistryState, RegistryError> {
    let RegistryEvent::Genesis {
        chain_name,
        authority,
        sequencer,
        nonce,
        created_at,
        authority_sig,
    } = event
    else {
        return Err(RegistryError::CorruptedState);
    };

    if state.chain_id != [0u8; 32] {
        return Err(RegistryError::InvalidStateTransition {
            from: "Genesis".to_string(),
            to: "Duplicate Genesis".to_string(),
        });
    }

    let genesis_msg = build_genesis_preimage(chain_name, authority, sequencer, nonce, *created_at);
    authority.verify_strict(&genesis_msg, authority_sig)?;

    let chain_id = compute_chain_id(&event.to_body_bytes());

    let mut new_state = state.clone();
    new_state.chain_id = chain_id;
    new_state.authority = *authority;
    new_state.sequencer = *sequencer;
    new_state.authority_index = 0;
    Ok(new_state)
}

fn apply_vvb_register(
    state: &RegistryState,
    event: &RegistryEvent,
) -> Result<RegistryState, RegistryError> {
    let RegistryEvent::VvbRegister {
        authority_index,
        vvb,
        label,
        authority_sig,
    } = event
    else {
        return Err(RegistryError::CorruptedState);
    };

    if *authority_index != state.authority_index {
        return Err(RegistryError::BadAuthorityIndex {
            expected: state.authority_index,
            found: *authority_index,
        });
    }

    let payload = build_vvb_register_payload(vvb, label);
    let msg =
        build_authority_event_preimage("vvb-register", &state.chain_id, *authority_index, &payload);
    state.authority.verify_strict(&msg, authority_sig)?;

    let mut new_state = state.clone();
    new_state.authority_index += 1;
    new_state.vvbs.insert(
        *vvb,
        VvbInfo {
            label: label.clone(),
            active: true,
        },
    );
    Ok(new_state)
}

fn apply_vvb_revoke(
    state: &RegistryState,
    event: &RegistryEvent,
) -> Result<RegistryState, RegistryError> {
    let RegistryEvent::VvbRevoke {
        authority_index,
        vvb,
        authority_sig,
    } = event
    else {
        return Err(RegistryError::CorruptedState);
    };

    if *authority_index != state.authority_index {
        return Err(RegistryError::BadAuthorityIndex {
            expected: state.authority_index,
            found: *authority_index,
        });
    }

    let payload = build_vvb_revoke_payload(vvb);
    let msg =
        build_authority_event_preimage("vvb-revoke", &state.chain_id, *authority_index, &payload);
    state.authority.verify_strict(&msg, authority_sig)?;

    if !state.vvbs.contains_key(vvb) {
        return Err(RegistryError::UnknownVvb { vvb: vvb.to_hex() });
    }

    let mut new_state = state.clone();
    new_state.authority_index += 1;
    if let Some(info) = new_state.vvbs.get_mut(vvb) {
        info.active = false;
    }
    Ok(new_state)
}

fn apply_authority_rotate(
    state: &RegistryState,
    event: &RegistryEvent,
) -> Result<RegistryState, RegistryError> {
    let RegistryEvent::AuthorityRotate {
        authority_index,
        new_authority,
        authority_sig,
    } = event
    else {
        return Err(RegistryError::CorruptedState);
    };

    if *authority_index != state.authority_index {
        return Err(RegistryError::BadAuthorityIndex {
            expected: state.authority_index,
            found: *authority_index,
        });
    }

    let payload = build_authority_rotate_payload(new_authority);
    let msg = build_authority_event_preimage(
        "authority-rotate",
        &state.chain_id,
        *authority_index,
        &payload,
    );
    state.authority.verify_strict(&msg, authority_sig)?;

    let mut new_state = state.clone();
    new_state.authority_index += 1;
    new_state.authority = *new_authority;
    Ok(new_state)
}

fn apply_sequencer_rotate(
    state: &RegistryState,
    event: &RegistryEvent,
) -> Result<RegistryState, RegistryError> {
    let RegistryEvent::SequencerRotate {
        authority_index,
        new_sequencer,
        authority_sig,
    } = event
    else {
        return Err(RegistryError::CorruptedState);
    };

    if *authority_index != state.authority_index {
        return Err(RegistryError::BadAuthorityIndex {
            expected: state.authority_index,
            found: *authority_index,
        });
    }

    let payload = build_sequencer_rotate_payload(new_sequencer);
    let msg = build_authority_event_preimage(
        "sequencer-rotate",
        &state.chain_id,
        *authority_index,
        &payload,
    );
    state.authority.verify_strict(&msg, authority_sig)?;

    let mut new_state = state.clone();
    new_state.authority_index += 1;
    new_state.sequencer = *new_sequencer;
    Ok(new_state)
}

fn apply_burn(
    state: &RegistryState,
    event: &RegistryEvent,
) -> Result<RegistryState, RegistryError> {
    let RegistryEvent::Burn {
        credit_id,
        op_index,
        range_start,
        range_end,
        beneficiary,
        claim_type,
        owner_sig,
    } = event
    else {
        return Err(RegistryError::CorruptedState);
    };

    let batch = state
        .credits
        .iter()
        .find(|b| b.credit_id == *credit_id)
        .ok_or_else(|| RegistryError::NotFound {
            id: credit_id.clone(),
        })?;

    if !batch.is_active() {
        return Err(RegistryError::InvalidStateTransition {
            from: "Retired/Expired".to_string(),
            to: "Burned".to_string(),
        });
    }

    // Check op_index
    if *op_index != batch.op_index {
        return Err(RegistryError::BadOpIndex {
            expected: batch.op_index,
            found: *op_index,
        });
    }

    let burn_range = SerialRange::new(*range_start, *range_end)?;

    // Invariant 5: Prevent double burning through historic overlap tracking
    for burned in &state.burned_ranges {
        if burned.overlaps(&burn_range) {
            return Err(RegistryError::PoOAlreadyIssued);
        }
    }

    // Find the active slice that strictly contains the burn envelope
    let slice_idx = batch
        .slices
        .iter()
        .position(|s| s.status == CreditStatus::Active && s.range.contains(&burn_range))
        .ok_or(RegistryError::BurnRangeNotFound {
            start: burn_range.start,
            end: burn_range.end,
        })?;

    // Verify strict Ed25519 signature under current batch.owner (Invariant A1, A3)
    let burn_msg = build_burn_preimage(
        &state.chain_id,
        credit_id,
        *op_index,
        *range_start,
        *range_end,
        beneficiary,
        claim_type.as_str(),
    );
    batch.owner.verify_strict(&burn_msg, owner_sig)?;

    let mut new_state = state.clone();
    let target_batch = new_state
        .credits
        .iter_mut()
        .find(|b| b.credit_id == *credit_id)
        .unwrap();

    // Excise target slice
    let target_slice = target_batch.slices.remove(slice_idx);

    // Run algorithmic slice split tracking active remainders
    let remainders = target_slice.range.slice(&burn_range)?;

    // Persist remainders to the batch's active state
    for r in remainders {
        target_batch.slices.push(SerialSlice {
            range: r,
            status: CreditStatus::Active,
        });
    }

    // Push the executed burn footprint onto the batch tracking object
    target_batch.slices.push(SerialSlice {
        range: burn_range,
        status: CreditStatus::Retired,
    });

    // Normalize slices to merge adjacent fragments and prevent infinite fragmentation
    normalize_slices(&mut target_batch.slices);

    // Fail-fast internal validation guard to prevent silent state corruption (Bug 15)
    if !target_batch.validate_internal() {
        return Err(RegistryError::CorruptedState);
    }

    // Increment per-credit op_index (RFC-005)
    target_batch.op_index += 1;

    // Lock globally
    new_state.burned_ranges.push(burn_range);

    Ok(new_state)
}

impl RegistryState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Evaluates the pure transition function for an event against this state.
    pub fn apply(&self, event: &RegistryEvent) -> Result<Self, RegistryError> {
        apply(self, event)
    }

    /// Checks if a VVB is registered and currently active.
    pub fn is_vvb_active(&self, vvb: &PubKey) -> bool {
        self.vvbs.get(vvb).map(|info| info.active).unwrap_or(false)
    }

    /// Registers a new active VVB or updates an existing one.
    pub fn register_vvb(&mut self, vvb: PubKey, label: String) {
        self.vvbs.insert(
            vvb,
            VvbInfo {
                label,
                active: true,
            },
        );
    }

    /// Revokes an existing VVB.
    pub fn revoke_vvb(&mut self, vvb: &PubKey) -> Result<(), RegistryError> {
        if let Some(info) = self.vvbs.get_mut(vvb) {
            info.active = false;
            Ok(())
        } else {
            Err(RegistryError::UnknownVvb { vvb: vvb.to_hex() })
        }
    }

    /// Finds a credit batch by credit_id.
    pub fn get_credit(&self, credit_id: &str) -> Option<&CreditBatch> {
        self.credits.iter().find(|c| c.credit_id == credit_id)
    }

    /// Finds a mutable credit batch by credit_id.
    pub fn get_credit_mut(&mut self, credit_id: &str) -> Option<&mut CreditBatch> {
        self.credits.iter_mut().find(|c| c.credit_id == credit_id)
    }

    // Validates a Proof-of-Integrity (PoI) before minting. Ensures the PoI hasn't been used and is semantically valid.
    pub fn validate_poi(&self, poi: &PoI) -> Result<(), RegistryError> {
        if poi.is_used() {
            return Err(RegistryError::PoIAlreadyUsed);
        }

        if !poi.is_valid_for_minting() {
            return Err(RegistryError::MissingPoI);
        }

        Ok(())
    }

    // ── Invariant Verification Engine (RFC-001 §5) ──────────────────────────────

    /// Invariant 1: PoI is Mandatory for Minting.
    /// Verifies that the registry enforces PoI validation and that every minted batch
    /// has non-empty identity and valid metadata.
    pub fn check_invariant_1(&self) -> bool {
        let dummy_range = match SerialRange::new(0, 0) {
            Ok(r) => r,
            Err(_) => return false,
        };
        let invalid_poi = crate::poi::PoI {
            project_id: "DUMMY".to_string(),
            mrv_commitment: crate::mrv::MRVCommitment {
                merkle_root: [0u8; 32],
                hash_algorithm: "BLAKE3".to_string(),
                leaf_count: 0,
                timestamp: 0,
            },
            methodology_hash: "0x0".to_string(),
            vvb_signature: "0x0".to_string(),
            serialization_range: dummy_range,
            amount_tco2e: 1,
            jurisdiction: "IN".to_string(),
            market_scope: crate::project::MarketScope::Vcm,
            credit_id: "DUMMY".to_string(),
            valid_from: 0,
            valid_until: 100,
            poi_valid: false,
            cc_mint_amount: 1,
            owner: "dummy".to_string(),
            status: crate::poi::PoIStatus::Valid,
        };
        if self.validate_poi(&invalid_poi).is_ok() {
            return false;
        }

        for batch in &self.credits {
            if batch.credit_id.is_empty()
                || batch.project_id.is_empty()
                || batch.owner == PubKey([0u8; 32])
                || batch.vvb == PubKey([0u8; 32])
                || !self.vvbs.contains_key(&batch.vvb)
                || batch.poi_hash == [0u8; 32]
            {
                return false;
            }
        }
        true
    }

    /// Invariant 2: Supply Authorized Cap Limit & Conservation.
    /// Verifies that for every batch: slices are internally valid, and
    /// active + retired == original_range.size().
    pub fn check_invariant_2(&self) -> bool {
        for batch in &self.credits {
            if !batch.validate_internal() {
                return false;
            }
            let original_size = match batch.original_range.size() {
                Ok(s) => s,
                Err(_) => return false,
            };
            let mut active_sum: u64 = 0;
            let mut retired_sum: u64 = 0;
            for slice in &batch.slices {
                let sz = match slice.range.size() {
                    Ok(s) => s,
                    Err(_) => return false,
                };
                match slice.status {
                    CreditStatus::Active => {
                        active_sum = match active_sum.checked_add(sz) {
                            Some(v) => v,
                            None => return false,
                        };
                    }
                    CreditStatus::Retired => {
                        retired_sum = match retired_sum.checked_add(sz) {
                            Some(v) => v,
                            None => return false,
                        };
                    }
                    CreditStatus::Expired => {}
                }
            }
            let total = match active_sum.checked_add(retired_sum) {
                Some(v) => v,
                None => return false,
            };
            if total != original_size {
                return false;
            }
        }
        true
    }

    /// Invariant 3: Global Serialization Locking Uniqueness.
    /// Verifies that no two active serial ranges overlap anywhere in the registry.
    pub fn check_invariant_3(&self) -> bool {
        let mut active_ranges: Vec<SerialRange> = Vec::new();
        for batch in &self.credits {
            for slice in &batch.slices {
                if slice.status == CreditStatus::Active {
                    active_ranges.push(slice.range);
                }
            }
        }
        for (i, r1) in active_ranges.iter().enumerate() {
            for r2 in active_ranges.iter().skip(i + 1) {
                if r1.overlaps(r2) {
                    return false;
                }
            }
        }
        true
    }

    /// Invariant 4: Burn Irreversibility.
    /// Verifies that no range recorded in burned_ranges overlaps with any Active slice.
    pub fn check_invariant_4(&self) -> bool {
        for burned in &self.burned_ranges {
            for batch in &self.credits {
                for slice in &batch.slices {
                    if slice.status == CreditStatus::Active && slice.range.overlaps(burned) {
                        return false;
                    }
                }
            }
        }
        true
    }

    /// Invariant 5: PoO Uniqueness (Double-spending prevented).
    /// Verifies that all burned ranges on record are pairwise disjoint.
    pub fn check_invariant_5(&self) -> bool {
        for (i, b1) in self.burned_ranges.iter().enumerate() {
            for b2 in self.burned_ranges.iter().skip(i + 1) {
                if b1.overlaps(b2) {
                    return false;
                }
            }
        }
        true
    }

    /// Invariant 6: PoO Non-Transferability.
    /// Verifies that fully retired batches cannot be marked active or transferred.
    pub fn check_invariant_6(&self) -> bool {
        for batch in &self.credits {
            let active_count = batch
                .slices
                .iter()
                .filter(|s| s.status == CreditStatus::Active)
                .count();
            if active_count == 0 && batch.is_active() {
                return false;
            }
        }
        true
    }

    /// Invariant 7: PoI Single-use Consumed State.
    /// Verifies that every minted batch has a registered unique data root,
    /// and that spent PoIs are strictly rejected.
    pub fn check_invariant_7(&self) -> bool {
        if self.credits.len() != self.used_data_roots.len() {
            return false;
        }
        let mut seen_poi = BTreeSet::new();
        for batch in &self.credits {
            if batch.poi_hash == [0u8; 32] || !seen_poi.insert(batch.poi_hash) {
                return false;
            }
        }
        let dummy_range = match SerialRange::new(0, 0) {
            Ok(r) => r,
            Err(_) => return false,
        };
        let spent_poi = crate::poi::PoI {
            project_id: "DUMMY".to_string(),
            mrv_commitment: crate::mrv::MRVCommitment {
                merkle_root: [0u8; 32],
                hash_algorithm: "BLAKE3".to_string(),
                leaf_count: 0,
                timestamp: 0,
            },
            methodology_hash: "0x0".to_string(),
            vvb_signature: "0x0".to_string(),
            serialization_range: dummy_range,
            amount_tco2e: 1,
            jurisdiction: "IN".to_string(),
            market_scope: crate::project::MarketScope::Vcm,
            credit_id: "DUMMY".to_string(),
            valid_from: 0,
            valid_until: 100,
            poi_valid: true,
            cc_mint_amount: 1,
            owner: "dummy".to_string(),
            status: crate::poi::PoIStatus::Used,
        };
        if self.validate_poi(&spent_poi).is_ok() {
            return false;
        }
        true
    }

    /// Invariant A1: Signature Validity & Non-Zero Identity Keys (RFC-005 §3.8).
    /// Verifies that all batches are bound to valid, non-zero owner and VVB identity keys.
    pub fn check_invariant_a1(&self) -> bool {
        for batch in &self.credits {
            if batch.owner == PubKey([0u8; 32]) || batch.vvb == PubKey([0u8; 32]) {
                return false;
            }
        }
        true
    }

    /// Invariant A2: Operation Index Contiguity (RFC-005 §3.8).
    /// Verifies that batch op_index reflects contiguous state transitions without gaps.
    pub fn check_invariant_a2(&self) -> bool {
        for batch in &self.credits {
            let retired_count = batch
                .slices
                .iter()
                .filter(|s| s.status == CreditStatus::Retired)
                .count() as u64;
            if batch.op_index < retired_count {
                return false;
            }
        }
        true
    }

    /// Invariant A3: Domain Separation & Chain Binding (RFC-005 §3.8).
    /// Verifies that if any credits exist, the registry is bound to a non-zero chain_id and authority.
    pub fn check_invariant_a3(&self) -> bool {
        if !self.credits.is_empty()
            && (self.chain_id == [0u8; 32] || self.authority == PubKey([0u8; 32]))
        {
            return false;
        }
        true
    }

    /// Evaluates all protocol and authorization invariants against current registry state.
    pub fn check_invariants(&self) -> InvariantReport {
        let inv1 = self.check_invariant_1();
        let inv2 = self.check_invariant_2();
        let inv3 = self.check_invariant_3();
        let inv4 = self.check_invariant_4();
        let inv5 = self.check_invariant_5();
        let inv6 = self.check_invariant_6();
        let inv7 = self.check_invariant_7();
        let inv_a1 = self.check_invariant_a1();
        let inv_a2 = self.check_invariant_a2();
        let inv_a3 = self.check_invariant_a3();
        let all_passed =
            inv1 && inv2 && inv3 && inv4 && inv5 && inv6 && inv7 && inv_a1 && inv_a2 && inv_a3;
        InvariantReport {
            inv1_poi_mandatory: inv1,
            inv2_supply_cap: inv2,
            inv3_serial_uniqueness: inv3,
            inv4_burn_irreversibility: inv4,
            inv5_poo_uniqueness: inv5,
            inv6_poo_non_transferable: inv6,
            inv7_poi_single_use: inv7,
            inva1_signature_validity: inv_a1,
            inva2_op_index_contiguity: inv_a2,
            inva3_chain_id_binding: inv_a3,
            all_passed,
        }
    }
}

/// Comprehensive report of all protocol invariants (RFC-001 §5) and authorization invariants (RFC-005 §3.8).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InvariantReport {
    pub inv1_poi_mandatory: bool,
    pub inv2_supply_cap: bool,
    pub inv3_serial_uniqueness: bool,
    pub inv4_burn_irreversibility: bool,
    pub inv5_poo_uniqueness: bool,
    pub inv6_poo_non_transferable: bool,
    pub inv7_poi_single_use: bool,
    #[serde(default)]
    pub inva1_signature_validity: bool,
    #[serde(default)]
    pub inva2_op_index_contiguity: bool,
    #[serde(default)]
    pub inva3_chain_id_binding: bool,
    pub all_passed: bool,
}

/// The stateful Registry wrapper that manages state transitions via pure `apply()`.
/// Implements `Deref` and `DerefMut` to `RegistryState` for seamless inspection.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Registry {
    pub state: RegistryState,
}

impl std::ops::Deref for Registry {
    type Target = RegistryState;
    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl std::ops::DerefMut for Registry {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.state
    }
}

impl Registry {
    /// Instantiates an empty protocol Registry
    pub fn new() -> Self {
        Self::default()
    }

    /// Instantiates a Registry initialized from an existing state
    pub fn from_state(state: RegistryState) -> Self {
        Self { state }
    }

    /// Applies a discrete protocol event to transition the registry's state
    pub fn apply_event(&mut self, event: &RegistryEvent) -> Result<(), RegistryError> {
        self.state = apply(&self.state, event)?;
        Ok(())
    }

    /// Applies a Mint event and returns the newly minted CreditBatch
    pub fn mint(&mut self, event: &RegistryEvent) -> Result<CreditBatch, RegistryError> {
        self.apply_event(event)?;
        let batch = self.credits.last().unwrap().clone();
        Ok(batch)
    }

    /// Applies a Transfer event to transition ownership
    pub fn transfer(&mut self, event: &RegistryEvent) -> Result<(), RegistryError> {
        self.apply_event(event)
    }

    /// Applies a Burn event and generates the settlement PoO receipt
    pub fn burn(&mut self, event: &RegistryEvent) -> Result<PoO, RegistryError> {
        let RegistryEvent::Burn {
            credit_id,
            range_start,
            range_end,
            beneficiary,
            claim_type,
            ..
        } = event
        else {
            return Err(RegistryError::CorruptedState);
        };
        let burn_range = SerialRange::new(*range_start, *range_end)?;
        let old_batch = self
            .credits
            .iter()
            .find(|b| b.credit_id == *credit_id)
            .ok_or_else(|| RegistryError::NotFound {
                id: credit_id.clone(),
            })?
            .clone();

        self.apply_event(event)?;

        let burn_size = burn_range.size()?;
        let poo = PoO {
            project_id: old_batch.project_id,
            credit_id: credit_id.clone(),
            serialization_range: burn_range,
            market_scope: crate::project::MarketScope::Vcm,
            cc_amount: burn_size,
            burn_tx_hash: format!("burn_{}_{}", credit_id, burn_range.start),
            timestamp: 0,
            beneficiary: beneficiary.clone(),
            owner: old_batch.owner.to_hex(),
            claim_type: *claim_type,
            amount_tco2e: burn_size,
            status: PoOStatus::Finalized,
        };

        Ok(poo)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Keypair;

    fn setup_test_registry() -> (Registry, Keypair, Keypair, Keypair) {
        let authority = Keypair::generate();
        let sequencer = Keypair::generate();
        let vvb = Keypair::generate();
        let mut registry = Registry::new();

        let nonce = [42u8; 32];
        let created_at = 1_700_000_000;
        let genesis_msg = build_genesis_preimage(
            "GreyMisnomer-Test",
            &authority.pubkey(),
            &sequencer.pubkey(),
            &nonce,
            created_at,
        );
        let authority_sig = authority.sign(&genesis_msg);
        let genesis_event = RegistryEvent::Genesis {
            chain_name: "GreyMisnomer-Test".to_string(),
            authority: authority.pubkey(),
            sequencer: sequencer.pubkey(),
            nonce,
            created_at,
            authority_sig,
        };
        registry.apply_event(&genesis_event).unwrap();

        let vvb_payload = build_vvb_register_payload(&vvb.pubkey(), "TUV-Nord");
        let vvb_msg =
            build_authority_event_preimage("vvb-register", &registry.chain_id, 0, &vvb_payload);
        let vvb_sig = authority.sign(&vvb_msg);
        let vvb_event = RegistryEvent::VvbRegister {
            authority_index: 0,
            vvb: vvb.pubkey(),
            label: "TUV-Nord".to_string(),
            authority_sig: vvb_sig,
        };
        registry.apply_event(&vvb_event).unwrap();

        (registry, authority, sequencer, vvb)
    }

    fn make_mint_event(
        registry: &Registry,
        vvb: &Keypair,
        credit_id: &str,
        start: u64,
        end: u64,
        owner: &PubKey,
    ) -> RegistryEvent {
        let mut root = [0u8; 32];
        let bytes = credit_id.as_bytes();
        let len = bytes.len().min(32);
        root[..len].copy_from_slice(&bytes[..len]);
        let amount = end - start + 1;

        let params = MintAttestationParams {
            chain_id: &registry.chain_id,
            project_id: "PRJ-001",
            credit_id,
            range_start: start,
            range_end: end,
            cc_mint_amount: amount,
            merkle_root: &root,
            leaf_count: 1,
            mrv_timestamp: 1_700_000_000,
            methodology_hash: "0xhash",
            jurisdiction: "IN",
            market_scope: "VCM",
            valid_from: 0,
            valid_until: 9_999_999_999,
            initial_owner: owner,
        };
        let msg = build_mint_preimage(&params);
        let vvb_sig = vvb.sign(&msg);

        RegistryEvent::Mint {
            project_id: "PRJ-001".to_string(),
            credit_id: credit_id.to_string(),
            range_start: start,
            range_end: end,
            cc_mint_amount: amount,
            merkle_root: root,
            leaf_count: 1,
            mrv_timestamp: 1_700_000_000,
            methodology_hash: "0xhash".to_string(),
            jurisdiction: "IN".to_string(),
            market_scope: "VCM".to_string(),
            valid_from: 0,
            valid_until: 9_999_999_999,
            initial_owner: *owner,
            vvb: vvb.pubkey(),
            vvb_sig,
        }
    }

    fn make_transfer_event(
        registry: &Registry,
        owner_key: &Keypair,
        credit_id: &str,
        op_index: u64,
        new_owner: &PubKey,
    ) -> RegistryEvent {
        let msg = build_transfer_preimage(&registry.chain_id, credit_id, op_index, new_owner);
        let sig = owner_key.sign(&msg);
        RegistryEvent::Transfer {
            credit_id: credit_id.to_string(),
            op_index,
            new_owner: *new_owner,
            owner_sig: sig,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn make_burn_event(
        registry: &Registry,
        owner_key: &Keypair,
        credit_id: &str,
        op_index: u64,
        start: u64,
        end: u64,
        beneficiary: &str,
        claim_type: ClaimType,
    ) -> RegistryEvent {
        let msg = build_burn_preimage(
            &registry.chain_id,
            credit_id,
            op_index,
            start,
            end,
            beneficiary,
            claim_type.as_str(),
        );
        let sig = owner_key.sign(&msg);
        RegistryEvent::Burn {
            credit_id: credit_id.to_string(),
            op_index,
            range_start: start,
            range_end: end,
            beneficiary: beneficiary.to_string(),
            claim_type,
            owner_sig: sig,
        }
    }

    #[test]
    fn cannot_mint_with_forged_signature() {
        let (mut registry, _, _, vvb) = setup_test_registry();
        let alice = Keypair::generate();
        let mut event = make_mint_event(&registry, &vvb, "CC-1", 0, 99, &alice.pubkey());
        if let RegistryEvent::Mint {
            ref mut vvb_sig, ..
        } = event
        {
            vvb_sig.0[0] ^= 0xff; // Corrupt signature
        }
        let result = registry.mint(&event);
        assert_eq!(result.unwrap_err(), RegistryError::BadSignature);
    }

    #[test]
    fn cannot_mint_unregistered_vvb() {
        let (mut registry, _, _, _) = setup_test_registry();
        let rogue_vvb = Keypair::generate();
        let alice = Keypair::generate();
        let event = make_mint_event(&registry, &rogue_vvb, "CC-1", 0, 99, &alice.pubkey());
        let result = registry.mint(&event);
        assert!(matches!(
            result.unwrap_err(),
            RegistryError::UnknownVvb { .. }
        ));
    }

    #[test]
    fn cannot_mint_revoked_vvb() {
        let (mut registry, authority, _, vvb) = setup_test_registry();
        let alice = Keypair::generate();

        // Revoke VVB
        let revoke_payload = build_vvb_revoke_payload(&vvb.pubkey());
        let revoke_msg =
            build_authority_event_preimage("vvb-revoke", &registry.chain_id, 1, &revoke_payload);
        let revoke_sig = authority.sign(&revoke_msg);
        let revoke_event = RegistryEvent::VvbRevoke {
            authority_index: 1,
            vvb: vvb.pubkey(),
            authority_sig: revoke_sig,
        };
        registry.apply_event(&revoke_event).unwrap();

        let event = make_mint_event(&registry, &vvb, "CC-1", 0, 99, &alice.pubkey());
        let result = registry.mint(&event);
        assert!(matches!(
            result.unwrap_err(),
            RegistryError::VvbRevoked { .. }
        ));
    }

    #[test]
    fn cannot_mint_overlapping_range() {
        let (mut registry, _, _, vvb) = setup_test_registry();
        let alice = Keypair::generate();
        let bob = Keypair::generate();

        let ev_a = make_mint_event(&registry, &vvb, "CC-1", 0, 49, &alice.pubkey());
        let ev_b = make_mint_event(&registry, &vvb, "CC-2", 40, 100, &bob.pubkey());

        registry.mint(&ev_a).unwrap();
        let result = registry.mint(&ev_b);
        assert_eq!(result.unwrap_err(), RegistryError::RangeOverlap);
    }

    #[test]
    fn cannot_mint_beyond_authorized_supply() {
        let (mut registry, _, _, vvb) = setup_test_registry();
        let alice = Keypair::generate();
        let mut event = make_mint_event(&registry, &vvb, "CC-1", 0, 99, &alice.pubkey());
        if let RegistryEvent::Mint {
            ref mut cc_mint_amount,
            ..
        } = event
        {
            *cc_mint_amount = 50; // Mismatch with range.size() == 100
        }
        let result = registry.mint(&event);
        assert_eq!(result.unwrap_err(), RegistryError::SupplyExceeded);
    }

    #[test]
    fn cannot_remint_burned_range() {
        let (mut registry, _, _, vvb) = setup_test_registry();
        let alice = Keypair::generate();
        let ev_mint = make_mint_event(&registry, &vvb, "CC-1", 0, 99, &alice.pubkey());
        registry.mint(&ev_mint).unwrap();

        let ev_burn = make_burn_event(
            &registry,
            &alice,
            "CC-1",
            0,
            0,
            99,
            "Corp_X",
            ClaimType::CorporateNetZero,
        );
        registry.burn(&ev_burn).unwrap();

        let bob = Keypair::generate();
        let ev_remint = make_mint_event(&registry, &vvb, "CC-2", 0, 99, &bob.pubkey());
        let result = registry.mint(&ev_remint);
        assert_eq!(result.unwrap_err(), RegistryError::BurnIrreversible);
    }

    #[test]
    fn test_valid_transfer() {
        let (mut registry, _, _, vvb) = setup_test_registry();
        let alice = Keypair::generate();
        let bob = Keypair::generate();

        let ev_mint = make_mint_event(&registry, &vvb, "CC-1", 0, 99, &alice.pubkey());
        registry.mint(&ev_mint).unwrap();

        let ev_xfer = make_transfer_event(&registry, &alice, "CC-1", 0, &bob.pubkey());
        registry.transfer(&ev_xfer).unwrap();

        assert_eq!(registry.credits[0].owner, bob.pubkey());
        assert_eq!(registry.credits[0].op_index, 1);
    }

    #[test]
    fn cannot_transfer_with_bad_op_index() {
        let (mut registry, _, _, vvb) = setup_test_registry();
        let alice = Keypair::generate();
        let bob = Keypair::generate();

        let ev_mint = make_mint_event(&registry, &vvb, "CC-1", 0, 99, &alice.pubkey());
        registry.mint(&ev_mint).unwrap();

        // Pass op_index: 5 when expected is 0
        let ev_xfer = make_transfer_event(&registry, &alice, "CC-1", 5, &bob.pubkey());
        let result = registry.transfer(&ev_xfer);
        assert_eq!(
            result.unwrap_err(),
            RegistryError::BadOpIndex {
                expected: 0,
                found: 5
            }
        );
    }

    #[test]
    fn cannot_transfer_with_forged_signature() {
        let (mut registry, _, _, vvb) = setup_test_registry();
        let alice = Keypair::generate();
        let bob = Keypair::generate();

        let ev_mint = make_mint_event(&registry, &vvb, "CC-1", 0, 99, &alice.pubkey());
        registry.mint(&ev_mint).unwrap();

        let mut ev_xfer = make_transfer_event(&registry, &alice, "CC-1", 0, &bob.pubkey());
        if let RegistryEvent::Transfer {
            ref mut owner_sig, ..
        } = ev_xfer
        {
            owner_sig.0[0] ^= 0xff;
        }
        let result = registry.transfer(&ev_xfer);
        assert_eq!(result.unwrap_err(), RegistryError::BadSignature);
    }

    #[test]
    fn cannot_transfer_to_self() {
        let (mut registry, _, _, vvb) = setup_test_registry();
        let alice = Keypair::generate();

        let ev_mint = make_mint_event(&registry, &vvb, "CC-1", 0, 99, &alice.pubkey());
        registry.mint(&ev_mint).unwrap();

        let ev_xfer = make_transfer_event(&registry, &alice, "CC-1", 0, &alice.pubkey());
        let result = registry.transfer(&ev_xfer);
        assert!(matches!(
            result.unwrap_err(),
            RegistryError::OwnerMismatch { .. }
        ));
    }

    #[test]
    fn burn_marks_credit_retired_and_issues_poo() {
        let (mut registry, _, _, vvb) = setup_test_registry();
        let alice = Keypair::generate();

        let ev_mint = make_mint_event(&registry, &vvb, "CC-1", 0, 99, &alice.pubkey());
        registry.mint(&ev_mint).unwrap();

        let ev_burn = make_burn_event(
            &registry,
            &alice,
            "CC-1",
            0,
            0,
            99,
            "Corp_X",
            ClaimType::CorporateNetZero,
        );
        let poo = registry.burn(&ev_burn).unwrap();

        assert!(poo.is_finalized());
        assert_eq!(poo.beneficiary, "Corp_X");
        assert_eq!(registry.burned_ranges.len(), 1);
        assert_eq!(registry.credits[0].op_index, 1);
    }

    #[test]
    fn cannot_burn_with_bad_op_index() {
        let (mut registry, _, _, vvb) = setup_test_registry();
        let alice = Keypair::generate();

        let ev_mint = make_mint_event(&registry, &vvb, "CC-1", 0, 99, &alice.pubkey());
        registry.mint(&ev_mint).unwrap();

        let ev_burn = make_burn_event(
            &registry,
            &alice,
            "CC-1",
            99, // Bad op_index
            0,
            99,
            "Corp_X",
            ClaimType::CorporateNetZero,
        );
        let result = registry.burn(&ev_burn);
        assert_eq!(
            result.unwrap_err(),
            RegistryError::BadOpIndex {
                expected: 0,
                found: 99
            }
        );
    }

    #[test]
    fn cannot_burn_twice() {
        let (mut registry, _, _, vvb) = setup_test_registry();
        let alice = Keypair::generate();

        let ev_mint = make_mint_event(&registry, &vvb, "CC-1", 0, 99, &alice.pubkey());
        registry.mint(&ev_mint).unwrap();

        let ev_burn1 = make_burn_event(
            &registry,
            &alice,
            "CC-1",
            0,
            0,
            99,
            "Corp_X",
            ClaimType::CorporateNetZero,
        );
        registry.burn(&ev_burn1).unwrap();

        let ev_burn2 = make_burn_event(
            &registry,
            &alice,
            "CC-1",
            1,
            0,
            99,
            "Corp_Y",
            ClaimType::CorporateNetZero,
        );
        let result = registry.burn(&ev_burn2);
        assert!(result.is_err());
    }

    #[test]
    fn test_partial_burn_middle_slice() {
        let (mut registry, _, _, vvb) = setup_test_registry();
        let alice = Keypair::generate();

        let ev_mint = make_mint_event(&registry, &vvb, "CC-1", 0, 999, &alice.pubkey());
        registry.mint(&ev_mint).unwrap();

        let ev_burn = make_burn_event(
            &registry,
            &alice,
            "CC-1",
            0,
            200,
            399,
            "Corp_X",
            ClaimType::CorporateNetZero,
        );
        let poo = registry.burn(&ev_burn).unwrap();

        assert_eq!(poo.cc_amount, 200);
        assert_eq!(registry.burned_ranges.len(), 1);
        assert_eq!(
            registry.burned_ranges[0],
            SerialRange::new(200, 399).unwrap()
        );

        let batch = registry.credits.first().unwrap();
        assert_eq!(batch.slices.len(), 3);

        let active_slices: Vec<_> = batch
            .slices
            .iter()
            .filter(|s| s.status == CreditStatus::Active)
            .collect();
        assert_eq!(active_slices.len(), 2);
        assert!(active_slices
            .iter()
            .any(|s| s.range == SerialRange::new(0, 199).unwrap()));
        assert!(active_slices
            .iter()
            .any(|s| s.range == SerialRange::new(400, 999).unwrap()));

        let retired_slices: Vec<_> = batch
            .slices
            .iter()
            .filter(|s| s.status == CreditStatus::Retired)
            .collect();
        assert_eq!(retired_slices.len(), 1);
        assert_eq!(retired_slices[0].range, SerialRange::new(200, 399).unwrap());
    }

    #[test]
    fn normalization_merges_adjacent_slices() {
        let (mut registry, _, _, vvb) = setup_test_registry();
        let alice = Keypair::generate();

        let ev_mint = make_mint_event(&registry, &vvb, "CC-1", 0, 999, &alice.pubkey());
        registry.mint(&ev_mint).unwrap();

        let ev_burn1 = make_burn_event(
            &registry,
            &alice,
            "CC-1",
            0,
            200,
            299,
            "A",
            ClaimType::CorporateNetZero,
        );
        registry.burn(&ev_burn1).unwrap();

        let ev_burn2 = make_burn_event(
            &registry,
            &alice,
            "CC-1",
            1,
            300,
            399,
            "B",
            ClaimType::CorporateNetZero,
        );
        registry.burn(&ev_burn2).unwrap();

        let batch = registry.credits.first().unwrap();
        let retired: Vec<_> = batch
            .slices
            .iter()
            .filter(|s| s.status == CreditStatus::Retired)
            .collect();
        assert_eq!(retired.len(), 1);
        assert_eq!(retired[0].range, SerialRange::new(200, 399).unwrap());
    }

    #[test]
    fn cannot_mint_duplicate_credit_id() {
        let (mut registry, _, _, vvb) = setup_test_registry();
        let alice = Keypair::generate();
        let bob = Keypair::generate();

        let ev_a = make_mint_event(&registry, &vvb, "CC-1", 0, 49, &alice.pubkey());
        let ev_b = make_mint_event(&registry, &vvb, "CC-1", 50, 99, &bob.pubkey());

        registry.mint(&ev_a).unwrap();
        let result = registry.mint(&ev_b);
        assert_eq!(result.unwrap_err(), RegistryError::DuplicateCreditId);
    }

    #[test]
    fn cannot_mint_duplicate_data_root() {
        let (mut registry, _, _, vvb) = setup_test_registry();
        let alice = Keypair::generate();
        let bob = Keypair::generate();

        let ev_a = make_mint_event(&registry, &vvb, "CC-1", 0, 49, &alice.pubkey());
        let mut ev_b = make_mint_event(&registry, &vvb, "CC-2", 50, 99, &bob.pubkey());

        if let (
            RegistryEvent::Mint {
                merkle_root: root_a,
                ..
            },
            RegistryEvent::Mint {
                ref mut merkle_root,
                ref mut vvb_sig,
                project_id,
                credit_id,
                range_start,
                range_end,
                cc_mint_amount,
                leaf_count,
                mrv_timestamp,
                methodology_hash,
                jurisdiction,
                market_scope,
                valid_from,
                valid_until,
                initial_owner,
                ..
            },
        ) = (&ev_a, &mut ev_b)
        {
            *merkle_root = *root_a;
            let params = MintAttestationParams {
                chain_id: &registry.chain_id,
                project_id,
                credit_id,
                range_start: *range_start,
                range_end: *range_end,
                cc_mint_amount: *cc_mint_amount,
                merkle_root,
                leaf_count: *leaf_count,
                mrv_timestamp: *mrv_timestamp,
                methodology_hash,
                jurisdiction,
                market_scope,
                valid_from: *valid_from,
                valid_until: *valid_until,
                initial_owner,
            };
            let msg = build_mint_preimage(&params);
            *vvb_sig = vvb.sign(&msg);
        }

        registry.mint(&ev_a).unwrap();
        let result = registry.mint(&ev_b);
        assert_eq!(result.unwrap_err(), RegistryError::DuplicateDataRoot);
    }

    #[test]
    fn test_authority_rotation_lifecycle() {
        let (mut registry, authority, _, _) = setup_test_registry();
        let new_authority = Keypair::generate();

        let rotate_payload = build_authority_rotate_payload(&new_authority.pubkey());
        let rotate_msg = build_authority_event_preimage(
            "authority-rotate",
            &registry.chain_id,
            1,
            &rotate_payload,
        );
        let rotate_sig = authority.sign(&rotate_msg);
        let rotate_event = RegistryEvent::AuthorityRotate {
            authority_index: 1,
            new_authority: new_authority.pubkey(),
            authority_sig: rotate_sig,
        };
        registry.apply_event(&rotate_event).unwrap();
        assert_eq!(registry.authority, new_authority.pubkey());
        assert_eq!(registry.authority_index, 2);

        // Subsequent registration signed by OLD authority fails
        let vvb2 = Keypair::generate();
        let vvb2_payload = build_vvb_register_payload(&vvb2.pubkey(), "VVB-2");
        let vvb2_msg =
            build_authority_event_preimage("vvb-register", &registry.chain_id, 2, &vvb2_payload);
        let stale_sig = authority.sign(&vvb2_msg);
        let stale_event = RegistryEvent::VvbRegister {
            authority_index: 2,
            vvb: vvb2.pubkey(),
            label: "VVB-2".to_string(),
            authority_sig: stale_sig,
        };
        assert_eq!(
            registry.apply_event(&stale_event).unwrap_err(),
            RegistryError::BadSignature
        );

        // Signed by NEW authority succeeds
        let valid_sig = new_authority.sign(&vvb2_msg);
        let valid_event = RegistryEvent::VvbRegister {
            authority_index: 2,
            vvb: vvb2.pubkey(),
            label: "VVB-2".to_string(),
            authority_sig: valid_sig,
        };
        registry.apply_event(&valid_event).unwrap();
        assert!(registry.is_vvb_active(&vvb2.pubkey()));
    }

    #[test]
    fn test_bad_authority_index() {
        let (mut registry, authority, _, _) = setup_test_registry();
        let new_auth = Keypair::generate();
        let payload = build_authority_rotate_payload(&new_auth.pubkey());
        let msg = build_authority_event_preimage(
            "authority-rotate",
            &registry.chain_id,
            99, // Bad index
            &payload,
        );
        let sig = authority.sign(&msg);
        let event = RegistryEvent::AuthorityRotate {
            authority_index: 99,
            new_authority: new_auth.pubkey(),
            authority_sig: sig,
        };
        let result = registry.apply_event(&event);
        assert_eq!(
            result.unwrap_err(),
            RegistryError::BadAuthorityIndex {
                expected: 1,
                found: 99
            }
        );
    }

    #[test]
    fn test_invariants_pass_normal_lifecycle() {
        let (mut registry, _, _, vvb) = setup_test_registry();
        let alice = Keypair::generate();

        let initial_rep = registry.check_invariants();
        assert!(initial_rep.all_passed);

        let ev_mint = make_mint_event(&registry, &vvb, "CC-INVARIANT-1", 100, 199, &alice.pubkey());
        registry.mint(&ev_mint).unwrap();

        let mint_rep = registry.check_invariants();
        assert!(mint_rep.all_passed);
        assert!(mint_rep.inv1_poi_mandatory);
        assert!(mint_rep.inv2_supply_cap);
        assert!(mint_rep.inv3_serial_uniqueness);
        assert!(mint_rep.inv4_burn_irreversibility);
        assert!(mint_rep.inv5_poo_uniqueness);
        assert!(mint_rep.inv6_poo_non_transferable);
        assert!(mint_rep.inv7_poi_single_use);
        assert!(mint_rep.inva1_signature_validity);
        assert!(mint_rep.inva2_op_index_contiguity);
        assert!(mint_rep.inva3_chain_id_binding);

        let ev_burn = make_burn_event(
            &registry,
            &alice,
            "CC-INVARIANT-1",
            0,
            120,
            149,
            "CorpBeneficiary",
            ClaimType::CorporateNetZero,
        );
        registry.burn(&ev_burn).unwrap();
        let burn_rep = registry.check_invariants();
        assert!(burn_rep.all_passed);
    }

    #[test]
    fn test_pure_apply_full_lifecycle() {
        let (registry, _, _, vvb) = setup_test_registry();
        let alice = Keypair::generate();
        let bob = Keypair::generate();

        // Step 1: Mint
        let ev_mint = make_mint_event(&registry, &vvb, "CC-CYCLE", 100, 199, &alice.pubkey());
        let s1 = apply(&registry.state, &ev_mint).unwrap();
        assert_eq!(s1.credits[0].owner, alice.pubkey());
        assert_eq!(s1.credits[0].op_index, 0);
        assert!(s1.check_invariants().all_passed);

        // Step 2: Transfer
        let ev_xfer = make_transfer_event(&registry, &alice, "CC-CYCLE", 0, &bob.pubkey());
        let s2 = apply(&s1, &ev_xfer).unwrap();
        assert_eq!(s2.credits[0].owner, bob.pubkey());
        assert_eq!(s2.credits[0].op_index, 1);
        assert_eq!(s1.credits[0].owner, alice.pubkey()); // s1 untouched
        assert!(s2.check_invariants().all_passed);

        // Step 3: Burn
        let ev_burn = make_burn_event(
            &registry,
            &bob,
            "CC-CYCLE",
            1,
            120,
            149,
            "GreenCorp",
            ClaimType::CorporateNetZero,
        );
        let s3 = apply(&s2, &ev_burn).unwrap();
        assert_eq!(s3.burned_ranges.len(), 1);
        assert_eq!(s3.burned_ranges[0], SerialRange::new(120, 149).unwrap());
        assert_eq!(s3.credits[0].op_index, 2);
        assert!(s3.check_invariants().all_passed);
    }

    #[test]
    fn test_event_serde_roundtrip() {
        let alice = Keypair::generate();
        let bob = Keypair::generate();
        let (registry, _, _, vvb) = setup_test_registry();

        let ev_mint = make_mint_event(&registry, &vvb, "CC-SERDE", 100, 199, &alice.pubkey());
        let ev_xfer = make_transfer_event(&registry, &alice, "CC-SERDE", 0, &bob.pubkey());
        let ev_burn = make_burn_event(
            &registry,
            &alice,
            "CC-SERDE",
            0,
            100,
            150,
            "ACME Corp",
            ClaimType::Compliance,
        );

        let events = vec![ev_mint, ev_xfer, ev_burn];

        for ev in &events {
            let json = serde_json::to_string(ev).unwrap();
            let deserialized: RegistryEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(ev, &deserialized);
        }
    }
}
