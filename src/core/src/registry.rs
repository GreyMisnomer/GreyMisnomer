use crate::auth::PubKey;
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

/// The discrete events that cause state transitions in the GreyMisnomer protocol.
/// Serializable to and from JSON/JSONL for event logging and deterministic replayability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum RegistryEvent {
    #[serde(rename = "mint")]
    Mint { poi: Box<PoI>, owner: String },
    #[serde(rename = "transfer")]
    Transfer {
        credit_id: String,
        new_owner: String,
    },
    #[serde(rename = "burn", alias = "retire")]
    Burn {
        credit_id: String,
        burn_range: SerialRange,
        beneficiary: String,
        claim_type: ClaimType,
    },
}

/// Pure state transition function: apply(state, event) -> Result<RegistryState, RegistryError>
///
/// Guaranteed properties:
/// 1. Pure: No I/O, no system time, no global mutable state, no side effects.
/// 2. Deterministic: Given the identical state and event, it always produces the identical new state or error.
/// 3. Invariant-preserving: Valid state + valid event => valid new state satisfying all 7 protocol invariants.
pub fn apply(state: &RegistryState, event: &RegistryEvent) -> Result<RegistryState, RegistryError> {
    match event {
        RegistryEvent::Mint { poi, owner } => apply_mint(state, poi, owner),
        RegistryEvent::Transfer {
            credit_id,
            new_owner,
        } => apply_transfer(state, credit_id, new_owner),
        RegistryEvent::Burn {
            credit_id,
            burn_range,
            beneficiary: _,
            claim_type: _,
        } => apply_burn(state, credit_id, *burn_range),
    }
}

fn apply_mint(
    state: &RegistryState,
    poi: &PoI,
    owner: &str,
) -> Result<RegistryState, RegistryError> {
    state.validate_poi(poi)?;

    // Prevent historic replay! (Invariant 4 logic mapping)
    for burned in &state.burned_ranges {
        if burned.overlaps(&poi.serialization_range) {
            return Err(RegistryError::BurnIrreversible);
        }
    }

    // Enforce Invariant 3: Global Serialization lock against overlaps
    for existing in &state.credits {
        for slice in &existing.slices {
            if slice.status == CreditStatus::Active
                && slice.range.overlaps(&poi.serialization_range)
            {
                return Err(RegistryError::RangeOverlap);
            }
        }
    }

    // Enforce Invariant 2: The range must not exceed the PoI auth cap
    if poi.serialization_range.size()? > poi.cc_mint_amount {
        return Err(RegistryError::SupplyExceeded);
    }

    // Prevent duplicate credit_id (Bug 3)
    if state.credits.iter().any(|c| c.credit_id == poi.credit_id) {
        return Err(RegistryError::DuplicateCreditId);
    }

    // Prevent duplicate data_root (Bug 9: double-counting prevention)
    if state
        .used_data_roots
        .contains(&poi.mrv_commitment.merkle_root)
    {
        return Err(RegistryError::DuplicateDataRoot);
    }

    let owner_pk = PubKey::from_hex(owner).unwrap_or_else(|_| {
        let hash = blake3::hash(owner.as_bytes());
        PubKey(*hash.as_bytes())
    });
    let vvb_pk = PubKey::from_hex(&poi.vvb_signature).unwrap_or_else(|_| {
        let hash = blake3::hash(poi.vvb_signature.as_bytes());
        PubKey(*hash.as_bytes())
    });
    let poi_hash = *blake3::hash(poi.credit_id.as_bytes()).as_bytes();

    let batch = CreditBatch {
        project_id: poi.project_id.clone(),
        credit_id: poi.credit_id.clone(),
        original_range: poi.serialization_range,
        slices: vec![SerialSlice {
            range: poi.serialization_range,
            status: CreditStatus::Active,
        }],
        owner: owner_pk,
        op_index: 0,
        vvb: vvb_pk,
        poi_hash,
    };

    let mut new_state = state.clone();
    new_state
        .used_data_roots
        .insert(poi.mrv_commitment.merkle_root);
    new_state.credits.push(batch);
    Ok(new_state)
}

fn apply_transfer(
    state: &RegistryState,
    credit_id: &str,
    new_owner: &str,
) -> Result<RegistryState, RegistryError> {
    let credit = state
        .credits
        .iter()
        .find(|c| c.credit_id == credit_id)
        .ok_or_else(|| RegistryError::NotFound {
            id: credit_id.to_string(),
        })?;

    if !credit.is_active() {
        return Err(RegistryError::InvalidStateTransition {
            from: "Retired/Expired".to_string(),
            to: "Active".to_string(),
        });
    }

    let mut new_state = state.clone();
    let target = new_state
        .credits
        .iter_mut()
        .find(|c| c.credit_id == credit_id)
        .unwrap();
    let new_owner_pk = PubKey::from_hex(new_owner).unwrap_or_else(|_| {
        let hash = blake3::hash(new_owner.as_bytes());
        PubKey(*hash.as_bytes())
    });
    target.owner = new_owner_pk;
    target.op_index += 1;
    Ok(new_state)
}

fn apply_burn(
    state: &RegistryState,
    credit_id: &str,
    burn_range: SerialRange,
) -> Result<RegistryState, RegistryError> {
    let batch = state
        .credits
        .iter()
        .find(|b| b.credit_id == credit_id)
        .ok_or_else(|| RegistryError::NotFound {
            id: credit_id.to_string(),
        })?;

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

    let mut new_state = state.clone();
    let target_batch = new_state
        .credits
        .iter_mut()
        .find(|b| b.credit_id == credit_id)
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

    /// Evaluates all 7 RFC-001 protocol invariants against current registry state.
    pub fn check_invariants(&self) -> InvariantReport {
        let inv1 = self.check_invariant_1();
        let inv2 = self.check_invariant_2();
        let inv3 = self.check_invariant_3();
        let inv4 = self.check_invariant_4();
        let inv5 = self.check_invariant_5();
        let inv6 = self.check_invariant_6();
        let inv7 = self.check_invariant_7();
        let all_passed = inv1 && inv2 && inv3 && inv4 && inv5 && inv6 && inv7;
        InvariantReport {
            inv1_poi_mandatory: inv1,
            inv2_supply_cap: inv2,
            inv3_serial_uniqueness: inv3,
            inv4_burn_irreversibility: inv4,
            inv5_poo_uniqueness: inv5,
            inv6_poo_non_transferable: inv6,
            inv7_poi_single_use: inv7,
            all_passed,
        }
    }
}

/// Comprehensive report of all 7 protocol invariants from RFC-001 §5.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InvariantReport {
    pub inv1_poi_mandatory: bool,
    pub inv2_supply_cap: bool,
    pub inv3_serial_uniqueness: bool,
    pub inv4_burn_irreversibility: bool,
    pub inv5_poo_uniqueness: bool,
    pub inv6_poo_non_transferable: bool,
    pub inv7_poi_single_use: bool,
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

    /// Mint logic: constructs a Mint event, applies it to state, marks PoI as used, and returns the new CreditBatch
    pub fn mint(&mut self, poi: &mut PoI, owner: String) -> Result<CreditBatch, RegistryError> {
        let event = RegistryEvent::Mint {
            poi: Box::new(poi.clone()),
            owner,
        };
        let new_state = apply(&self.state, &event)?;
        self.state = new_state;
        poi.status = crate::poi::PoIStatus::Used;
        let batch = self.credits.last().unwrap().clone();
        Ok(batch)
    }

    /// Transfer logic: constructs a Transfer event and applies it to state
    pub fn transfer(&mut self, credit_id: &str, new_owner: String) -> Result<(), RegistryError> {
        let event = RegistryEvent::Transfer {
            credit_id: credit_id.to_string(),
            new_owner,
        };
        self.state = apply(&self.state, &event)?;
        Ok(())
    }

    /// Partial burn logic: constructs a Burn event, applies it to state, and generates the settlement PoO
    pub fn burn(
        &mut self,
        credit_id: &str,
        burn_range: SerialRange,
        beneficiary: String,
        claim_type: ClaimType,
    ) -> Result<PoO, RegistryError> {
        let event = RegistryEvent::Burn {
            credit_id: credit_id.to_string(),
            burn_range,
            beneficiary: beneficiary.clone(),
            claim_type,
        };
        let new_state = apply(&self.state, &event)?;

        let batch = self
            .credits
            .iter()
            .find(|b| b.credit_id == credit_id)
            .ok_or_else(|| RegistryError::NotFound {
                id: credit_id.to_string(),
            })?
            .clone();

        self.state = new_state;

        let burn_size = burn_range.size()?;
        let poo = PoO {
            project_id: batch.project_id,
            credit_id: credit_id.to_string(),
            serialization_range: burn_range,
            market_scope: crate::project::MarketScope::Vcm,
            cc_amount: burn_size,
            burn_tx_hash: format!("mock_burn_{}_{}", credit_id, burn_range.start),
            timestamp: 0,
            beneficiary,
            owner: batch.owner.to_hex(),
            claim_type,
            amount_tco2e: burn_size,
            status: PoOStatus::Finalized,
        };

        Ok(poo)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mrv::MRVCommitment;
    use crate::poi::PoIStatus;
    use crate::project::MarketScope;

    fn test_pk(name: &str) -> PubKey {
        PubKey::from_hex(name).unwrap_or_else(|_| {
            let hash = blake3::hash(name.as_bytes());
            PubKey(*hash.as_bytes())
        })
    }

    fn make_poi(credit_id: &str, start: u64, end: u64) -> PoI {
        let mut root = [0u8; 32];
        let bytes = credit_id.as_bytes();
        let len = bytes.len().min(32);
        root[..len].copy_from_slice(&bytes[..len]);

        PoI {
            project_id: "PRJ-001".to_string(),
            mrv_commitment: MRVCommitment {
                merkle_root: root,
                hash_algorithm: "BLAKE3".to_string(),
                leaf_count: 1,
                timestamp: 0,
            },
            methodology_hash: "0xhash".to_string(),
            vvb_signature: "0xsig".to_string(),
            serialization_range: SerialRange::new(start, end).unwrap(),
            amount_tco2e: end - start + 1,
            jurisdiction: "IN".to_string(),
            market_scope: MarketScope::Vcm,
            credit_id: credit_id.to_string(),
            valid_from: 0,
            valid_until: 9_999_999_999,
            poi_valid: true,
            cc_mint_amount: end - start + 1,
            owner: "0xOwner".to_string(),
            status: PoIStatus::Valid,
        }
    }

    #[test]
    fn cannot_mint_without_valid_poi() {
        let mut registry = Registry::new();
        let mut poi = make_poi("CC-1", 0, 99);
        poi.poi_valid = false;
        let result = registry.mint(&mut poi, "Alice".to_string());
        assert_eq!(result.unwrap_err(), RegistryError::MissingPoI);
    }

    #[test]
    fn cannot_reuse_spent_poi() {
        let mut registry = Registry::new();
        let mut poi = make_poi("CC-1", 0, 99);
        registry.mint(&mut poi, "Alice".to_string()).unwrap();
        let result = registry.mint(&mut poi, "Alice".to_string());
        assert_eq!(result.unwrap_err(), RegistryError::PoIAlreadyUsed);
    }

    #[test]
    fn cannot_mint_overlapping_range() {
        let mut registry = Registry::new();
        let mut poi_a = make_poi("CC-1", 0, 49);
        let mut poi_b = make_poi("CC-2", 40, 100);
        registry.mint(&mut poi_a, "Alice".to_string()).unwrap();
        let result = registry.mint(&mut poi_b, "Bob".to_string());
        assert_eq!(result.unwrap_err(), RegistryError::RangeOverlap);
    }

    #[test]
    fn cannot_mint_beyond_authorized_supply() {
        let mut r = Registry::new();
        let mut poi = make_poi("CC-1", 0, 99);
        poi.cc_mint_amount = 5;
        let result = r.mint(&mut poi, "Alice".to_string());
        assert_eq!(result.unwrap_err(), RegistryError::SupplyExceeded);
    }

    #[test]
    fn cannot_remint_burned_range() {
        let mut registry = Registry::new();
        let mut poi = make_poi("CC-1", 0, 99);
        registry.mint(&mut poi, "Alice".to_string()).unwrap();
        registry
            .burn(
                "CC-1",
                SerialRange::new(0, 99).unwrap(),
                "Corp_X".to_string(),
                ClaimType::CorporateNetZero,
            )
            .unwrap();

        let mut new_poi = make_poi("CC-2", 0, 99);
        let result = registry.mint(&mut new_poi, "Bob".to_string());
        assert_eq!(result.unwrap_err(), RegistryError::BurnIrreversible);
    }

    #[test]
    fn test_valid_transfer() {
        let mut registry = Registry::new();
        let mut poi = make_poi("CC-1", 0, 99);
        registry.mint(&mut poi, "Alice".to_string()).unwrap();
        registry.transfer("CC-1", "Bob".to_string()).unwrap();
        assert_eq!(registry.credits[0].owner, test_pk("Bob"));
        assert_eq!(registry.credits[0].op_index, 1);
    }

    #[test]
    fn burn_marks_credit_retired_and_issues_poo() {
        let mut registry = Registry::new();
        let mut poi = make_poi("CC-1", 0, 99);
        registry.mint(&mut poi, "Alice".to_string()).unwrap();
        let poo = registry
            .burn(
                "CC-1",
                SerialRange::new(0, 99).unwrap(),
                "Corp_X".to_string(),
                ClaimType::CorporateNetZero,
            )
            .unwrap();
        assert!(poo.is_finalized());
        assert_eq!(poo.beneficiary, "Corp_X");
        assert_eq!(registry.burned_ranges.len(), 1);
    }

    #[test]
    fn cannot_burn_twice() {
        let mut registry = Registry::new();
        let mut poi = make_poi("CC-1", 0, 99);
        registry.mint(&mut poi, "Alice".to_string()).unwrap();
        registry
            .burn(
                "CC-1",
                SerialRange::new(0, 99).unwrap(),
                "Corp_X".to_string(),
                ClaimType::CorporateNetZero,
            )
            .unwrap();
        let result = registry.burn(
            "CC-1",
            SerialRange::new(0, 99).unwrap(),
            "Corp_Y".to_string(),
            ClaimType::CorporateNetZero,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_partial_burn_middle_slice() {
        let mut registry = Registry::new();
        let mut poi = make_poi("CC-1", 0, 999);
        registry.mint(&mut poi, "Alice".to_string()).unwrap();

        let burn_range = SerialRange::new(200, 399).unwrap();
        let poo = registry
            .burn(
                "CC-1",
                burn_range,
                "Corp_X".to_string(),
                ClaimType::CorporateNetZero,
            )
            .unwrap();

        assert_eq!(poo.cc_amount, 200);
        assert_eq!(registry.burned_ranges.len(), 1);
        assert_eq!(registry.burned_ranges[0], burn_range);

        let batch = registry.credits.first().unwrap();
        // Since it's normalized, left is active, middle is retired, right is active. Total 3 slices.
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
        assert_eq!(retired_slices[0].range, burn_range);
    }

    #[test]
    fn normalization_merges_adjacent_slices() {
        let mut registry = Registry::new();
        let mut poi = make_poi("CC-1", 0, 999);

        registry.mint(&mut poi, "Alice".to_string()).unwrap();

        // Burn two adjacent ranges
        registry
            .burn(
                "CC-1",
                SerialRange::new(200, 299).unwrap(),
                "A".to_string(),
                ClaimType::CorporateNetZero,
            )
            .unwrap();
        registry
            .burn(
                "CC-1",
                SerialRange::new(300, 399).unwrap(),
                "B".to_string(),
                ClaimType::CorporateNetZero,
            )
            .unwrap();

        let batch = registry.credits.first().unwrap();

        let retired: Vec<_> = batch
            .slices
            .iter()
            .filter(|s| s.status == CreditStatus::Retired)
            .collect();

        // After normalization -> should merge into ONE slice
        assert_eq!(retired.len(), 1);
        assert_eq!(retired[0].range, SerialRange::new(200, 399).unwrap());
    }

    #[test]
    fn cannot_mint_duplicate_credit_id() {
        let mut registry = Registry::new();
        let mut poi_a = make_poi("CC-1", 0, 49);
        let mut poi_b = make_poi("CC-1", 50, 99); // Non-overlapping serials, but duplicate credit_id!

        registry.mint(&mut poi_a, "Alice".to_string()).unwrap();
        let result = registry.mint(&mut poi_b, "Bob".to_string());
        assert_eq!(result.unwrap_err(), RegistryError::DuplicateCreditId);
    }

    #[test]
    fn cannot_mint_duplicate_data_root() {
        let mut registry = Registry::new();
        let mut poi_a = make_poi("CC-1", 0, 49);
        let mut poi_b = make_poi("CC-2", 50, 99); // different credit_id, non-overlapping serials!
        poi_b.mrv_commitment.merkle_root = poi_a.mrv_commitment.merkle_root; // but same MRV data root!

        registry.mint(&mut poi_a, "Alice".to_string()).unwrap();
        let result = registry.mint(&mut poi_b, "Bob".to_string());
        assert_eq!(result.unwrap_err(), RegistryError::DuplicateDataRoot);
    }

    #[test]
    fn test_invariants_pass_normal_lifecycle() {
        let mut registry = Registry::new();
        // Empty registry passes invariants
        let initial_rep = registry.check_invariants();
        assert!(initial_rep.all_passed);

        // Mint a batch
        let mut poi = make_poi("CC-INVARIANT-1", 100, 199);
        registry.mint(&mut poi, "OwnerA".to_string()).unwrap();
        let mint_rep = registry.check_invariants();
        assert!(mint_rep.all_passed);
        assert!(mint_rep.inv1_poi_mandatory);
        assert!(mint_rep.inv2_supply_cap);
        assert!(mint_rep.inv3_serial_uniqueness);
        assert!(mint_rep.inv4_burn_irreversibility);
        assert!(mint_rep.inv5_poo_uniqueness);
        assert!(mint_rep.inv6_poo_non_transferable);
        assert!(mint_rep.inv7_poi_single_use);

        // Burn part of batch
        let burn_range = SerialRange::new(120, 149).unwrap();
        registry
            .burn(
                "CC-INVARIANT-1",
                burn_range,
                "CorpBeneficiary".to_string(),
                ClaimType::CorporateNetZero,
            )
            .unwrap();
        let burn_rep = registry.check_invariants();
        assert!(burn_rep.all_passed);
    }

    #[test]
    fn test_invariant_3_detects_active_overlap() {
        let mut registry = Registry::new();
        let mut poi_a = make_poi("CC-A", 100, 199);
        registry.mint(&mut poi_a, "OwnerA".to_string()).unwrap();

        // Artificially inject an overlapping active slice to test detection
        registry.credits[0].slices.push(SerialSlice {
            range: SerialRange::new(150, 250).unwrap(),
            status: CreditStatus::Active,
        });

        assert!(!registry.check_invariant_3());
        assert!(!registry.check_invariants().all_passed);
    }

    #[test]
    fn test_invariant_4_detects_burned_in_active() {
        let mut registry = Registry::new();
        let mut poi_a = make_poi("CC-A", 100, 199);
        registry.mint(&mut poi_a, "OwnerA".to_string()).unwrap();

        // Record 150-160 as burned, while it's still in the active batch
        registry
            .burned_ranges
            .push(SerialRange::new(150, 160).unwrap());

        assert!(!registry.check_invariant_4());
        assert!(!registry.check_invariants().all_passed);
    }

    #[test]
    fn test_invariant_5_detects_burned_overlap() {
        let mut registry = Registry::new();
        registry
            .burned_ranges
            .push(SerialRange::new(100, 200).unwrap());
        registry
            .burned_ranges
            .push(SerialRange::new(150, 250).unwrap());

        assert!(!registry.check_invariant_5());
        assert!(!registry.check_invariants().all_passed);
    }

    // ── Pure apply(state, event) tests ──────────────────────────────────────────

    #[test]
    fn test_pure_apply_immutability() {
        let s0 = RegistryState::new();
        let poi = make_poi("CC-PURE-1", 1000, 1999);
        let event = RegistryEvent::Mint {
            poi: Box::new(poi),
            owner: "Alice".to_string(),
        };

        // s0 must remain completely empty after applying
        let s1 = apply(&s0, &event).unwrap();
        assert!(s0.credits.is_empty());
        assert!(s0.used_data_roots.is_empty());
        assert_eq!(s1.credits.len(), 1);
        assert_eq!(s1.used_data_roots.len(), 1);
        assert_eq!(s1.credits[0].credit_id, "CC-PURE-1");
    }

    #[test]
    fn test_pure_apply_full_lifecycle() {
        let s0 = RegistryState::new();
        let poi = make_poi("CC-CYCLE", 100, 199);

        // Step 1: Mint
        let mint_event = RegistryEvent::Mint {
            poi: Box::new(poi),
            owner: "Alice".to_string(),
        };
        let s1 = apply(&s0, &mint_event).unwrap();
        assert_eq!(s1.credits[0].owner, test_pk("Alice"));
        assert_eq!(s1.credits[0].op_index, 0);
        assert!(s1.check_invariants().all_passed);

        // Step 2: Transfer
        let xfer_event = RegistryEvent::Transfer {
            credit_id: "CC-CYCLE".to_string(),
            new_owner: "Bob".to_string(),
        };
        let s2 = apply(&s1, &xfer_event).unwrap();
        assert_eq!(s2.credits[0].owner, test_pk("Bob"));
        assert_eq!(s2.credits[0].op_index, 1);
        assert_eq!(s1.credits[0].owner, test_pk("Alice")); // s1 untouched
        assert!(s2.check_invariants().all_passed);

        // Step 3: Burn
        let burn_event = RegistryEvent::Burn {
            credit_id: "CC-CYCLE".to_string(),
            burn_range: SerialRange::new(120, 149).unwrap(),
            beneficiary: "GreenCorp".to_string(),
            claim_type: ClaimType::CorporateNetZero,
        };
        let s3 = apply(&s2, &burn_event).unwrap();
        assert_eq!(s3.burned_ranges.len(), 1);
        assert_eq!(s3.burned_ranges[0], SerialRange::new(120, 149).unwrap());
        assert_eq!(s3.credits[0].op_index, 2);
        assert!(s3.check_invariants().all_passed);
    }

    #[test]
    fn test_pure_apply_rejects_invalid_event() {
        let s0 = RegistryState::new();
        let mut poi = make_poi("CC-ERR", 100, 199);
        poi.status = PoIStatus::Used; // Invalid: already used

        let event = RegistryEvent::Mint {
            poi: Box::new(poi),
            owner: "Alice".to_string(),
        };
        let err = apply(&s0, &event).unwrap_err();
        assert_eq!(err, RegistryError::PoIAlreadyUsed);
    }

    #[test]
    fn test_event_serde_roundtrip() {
        let poi = make_poi("CC-SERDE", 100, 199);
        let events = vec![
            RegistryEvent::Mint {
                poi: Box::new(poi),
                owner: "Alice".to_string(),
            },
            RegistryEvent::Transfer {
                credit_id: "CC-SERDE".to_string(),
                new_owner: "Bob".to_string(),
            },
            RegistryEvent::Burn {
                credit_id: "CC-SERDE".to_string(),
                burn_range: SerialRange::new(100, 150).unwrap(),
                beneficiary: "ACME Corp".to_string(),
                claim_type: ClaimType::Compliance,
            },
        ];

        for ev in &events {
            let json = serde_json::to_string(ev).unwrap();
            let deserialized: RegistryEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(ev, &deserialized);
        }
    }

    #[test]
    fn test_state_machine_replay_equivalence() {
        let mut registry = Registry::new();
        let poi = make_poi("CC-REPLAY", 500, 599);

        let mint_ev = RegistryEvent::Mint {
            poi: Box::new(poi.clone()),
            owner: "Alice".to_string(),
        };
        let xfer_ev = RegistryEvent::Transfer {
            credit_id: "CC-REPLAY".to_string(),
            new_owner: "Bob".to_string(),
        };
        let burn_ev = RegistryEvent::Burn {
            credit_id: "CC-REPLAY".to_string(),
            burn_range: SerialRange::new(520, 549).unwrap(),
            beneficiary: "ZeroNet".to_string(),
            claim_type: ClaimType::Payg,
        };

        // Execute via stateful methods on Registry
        let mut poi_mut = poi;
        registry.mint(&mut poi_mut, "Alice".to_string()).unwrap();
        registry.transfer("CC-REPLAY", "Bob".to_string()).unwrap();
        registry
            .burn(
                "CC-REPLAY",
                SerialRange::new(520, 549).unwrap(),
                "ZeroNet".to_string(),
                ClaimType::Payg,
            )
            .unwrap();

        // Replay independently via pure apply()
        let s0 = RegistryState::new();
        let s1 = apply(&s0, &mint_ev).unwrap();
        let s2 = apply(&s1, &xfer_ev).unwrap();
        let s3 = apply(&s2, &burn_ev).unwrap();

        // Both states must be identical
        assert_eq!(registry.state, s3);
    }

    #[test]
    fn test_trust_roots_and_replay_counters() {
        let mut state = RegistryState::new();
        state.chain_id = [42u8; 32];
        state.authority = test_pk("AuthorityKey");
        state.sequencer = test_pk("SequencerKey");
        assert_eq!(state.authority_index, 0);

        let vvb = test_pk("VVB-Alpha");
        assert!(!state.is_vvb_active(&vvb));

        // Register VVB
        state.register_vvb(vvb, "TUV SUD India".to_string());
        assert!(state.is_vvb_active(&vvb));

        // Revoke VVB
        assert!(state.revoke_vvb(&vvb).is_ok());
        assert!(!state.is_vvb_active(&vvb));

        // Unknown VVB revoke returns error
        let unknown = test_pk("UnknownVVB");
        assert!(matches!(
            state.revoke_vvb(&unknown),
            Err(RegistryError::UnknownVvb { .. })
        ));
    }
}
