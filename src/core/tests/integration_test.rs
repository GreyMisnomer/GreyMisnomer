// Integration test: full Phase Alpha happy path
//
// Proves the complete protocol chain from RFC-003 → RFC-001 → RFC-002:
//   MRV Data → Merkle Root → MRVCommitment → PoI → Mint → Transfer → Burn → PoO
//
// This is the canonical end-to-end test for Phase Alpha.
// Every protocol invariant from RFC-001 §5 is exercised at least once.

use grey_misnomer_core::{
    mrv::{self, MRVRecord},
    poi::{PoI, PoIStatus},
    poo::ClaimType,
    project::MarketScope,
    registry::Registry,
    serial::SerialRange,
    credit::CreditStatus,
    error::RegistryError,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_mrv_records() -> Vec<MRVRecord> {
    // Simulate a month of daily solar generation readings
    (0..30)
        .map(|day| MRVRecord {
            timestamp: 1_700_000_000 + day * 86_400,
            value: 1_250.0 + (day as f64 * 3.5), // kWh — slight daily variation
            unit: "kWh".to_string(),
            source: format!("SOLAR-SENSOR-{:03}", day % 4),
        })
        .collect()
}

fn make_poi(commitment: grey_misnomer_core::mrv::MRVCommitment) -> PoI {
    PoI {
        project_id: "PRJ-SOLAR-2026-001".to_string(),
        mrv_commitment: commitment,
        methodology_hash: "SHA256(VM0042-v4.0)".to_string(),
        vvb_signature: "0xVVB_SIG_MOCK".to_string(),
        serialization_range: SerialRange::new(1_000_000, 1_000_999).unwrap(), // 1000 credits
        amount_tco2e: 1000,
        jurisdiction: "IN-MH".to_string(),
        market_scope: MarketScope::Vcm,
        credit_id: "CC-SOLAR-2026-001".to_string(),
        valid_from: 1_700_000_000,
        valid_until: 9_999_999_999,
        poi_valid: true,
        cc_mint_amount: 1000,
        owner: "0xProjectOwner".to_string(),
        status: PoIStatus::Valid,
    }
}

// ---------------------------------------------------------------------------
// Test 1: Full happy path — end-to-end chain
// ---------------------------------------------------------------------------

#[test]
fn full_protocol_chain_mrv_to_poo() {
    // Step 1: Collect and hash MRV records (RFC-003)
    let records = make_mrv_records();
    assert_eq!(records.len(), 30, "Should have 30 daily records");

    // Step 2: Build Merkle commitment
    let commitment = mrv::commit(&records, 1_700_000_000);
    assert_eq!(commitment.leaf_count, 30);
    assert_eq!(commitment.hash_algorithm, "BLAKE3");
    assert_ne!(commitment.merkle_root, [0u8; 32], "Root must not be zero hash");

    // Step 3: Verify a sample inclusion proof — proves data integrity before PoI is issued
    let proof = mrv::generate_inclusion_proof(&records, 0).unwrap();
    assert!(
        mrv::verify_inclusion_proof(&records[0], &proof, &commitment.merkle_root),
        "First record inclusion proof must verify"
    );
    let proof_last = mrv::generate_inclusion_proof(&records, 29).unwrap();
    assert!(
        mrv::verify_inclusion_proof(&records[29], &proof_last, &commitment.merkle_root),
        "Last record inclusion proof must verify"
    );

    // Step 4: Construct PoI binding the MRV commitment (RFC-001)
    let mut poi = make_poi(commitment);
    assert!(poi.is_valid_for_minting(), "PoI must be valid before first use");

    // Step 5: Registry mints credits — range 1_000_000..1_000_999 locked (RFC-002)
    let mut registry = Registry::new();
    let batch = registry
        .mint(&mut poi, "0xProjectOwner".to_string())
        .expect("Mint must succeed with valid PoI");

    assert_eq!(batch.credit_id, "CC-SOLAR-2026-001");
    assert_eq!(batch.original_range.size(), 1000);
    assert_eq!(batch.owner, "0xProjectOwner");

    // Invariant 7: PoI is now consumed
    assert!(poi.is_used(), "PoI must be USED after mint");

    // Step 6: Transfer to a buyer (RFC-002 lifecycle)
    registry
        .transfer("CC-SOLAR-2026-001", "0xBuyer".to_string())
        .expect("Transfer must succeed for active credit");
    assert_eq!(registry.credits[0].owner, "0xBuyer");

    // Step 7: Buyer retires — burn produces PoO (RFC-001 §3.2)
    let poo = registry
        .burn(
            "CC-SOLAR-2026-001",
            SerialRange::new(1_000_000, 1_000_999).unwrap(),
            "AcmeCorp_NetZero_2026".to_string(),
            ClaimType::CorporateNetZero,
        )
        .expect("Burn must succeed for active credit");

    // Validate PoO fields
    assert!(poo.is_finalized(), "PoO must be FINALIZED after burn");
    assert_eq!(poo.project_id, "PRJ-SOLAR-2026-001");
    assert_eq!(poo.credit_id, "CC-SOLAR-2026-001");
    assert_eq!(poo.beneficiary, "AcmeCorp_NetZero_2026");
    assert_eq!(poo.claim_type, ClaimType::CorporateNetZero);
    assert_eq!(poo.cc_amount, 1000);
    assert!(poo.amounts_are_consistent(), "PoO amounts must be internally consistent");

    // Invariant 4: burned range is permanently recorded
    assert_eq!(registry.burned_ranges.len(), 1);
}

// ---------------------------------------------------------------------------
// Test 2: Tampered MRV data must not verify against committed root
// ---------------------------------------------------------------------------

#[test]
fn tampered_mrv_does_not_verify() {
    let records = make_mrv_records();
    let commitment = mrv::commit(&records, 0);

    let proof = mrv::generate_inclusion_proof(&records, 5).unwrap();

    // Attacker alters one record's value
    let tampered = MRVRecord {
        timestamp: records[5].timestamp,
        value: 999_999.0, // fabricated
        unit: records[5].unit.clone(),
        source: records[5].source.clone(),
    };

    assert!(
        !mrv::verify_inclusion_proof(&tampered, &proof, &commitment.merkle_root),
        "Tampered record must NOT verify — data integrity enforcement"
    );
}

// ---------------------------------------------------------------------------
// Test 3: PoI can only authorize its stated supply (Invariant 2)
// ---------------------------------------------------------------------------

#[test]
fn poi_cannot_authorize_more_than_supply() {
    let records = make_mrv_records();
    let commitment = mrv::commit(&records, 0);
    let mut poi = make_poi(commitment);

    // Range is 1000 units but we set cc_mint_amount cap to 500
    poi.cc_mint_amount = 500;

    let mut registry = Registry::new();
    let result = registry.mint(&mut poi, "0xOwner".to_string());
    assert!(result.is_err(), "Mint must fail when range exceeds authorized supply");
}

// ---------------------------------------------------------------------------
// Test 4: Same PoI cannot authorize a second mint (Invariant 7)
// ---------------------------------------------------------------------------

#[test]
fn spent_poi_cannot_mint_again() {
    let records = make_mrv_records();
    let commitment = mrv::commit(&records, 0);
    let mut poi = make_poi(commitment);

    let mut registry = Registry::new();
    registry.mint(&mut poi, "0xOwner".to_string()).unwrap();

    let second = registry.mint(&mut poi, "0xOwner".to_string());
    assert!(second.is_err(), "USED PoI must be rejected on second mint attempt");
}

// ---------------------------------------------------------------------------
// Test 5: Burned range cannot be re-minted from a different PoI (Invariant 4)
// ---------------------------------------------------------------------------

#[test]
fn burned_range_cannot_be_reminted() {
    let records = make_mrv_records();
    let commitment_a = mrv::commit(&records, 0);
    let mut poi_a = make_poi(commitment_a);

    let mut registry = Registry::new();
    registry.mint(&mut poi_a, "0xOwner".to_string()).unwrap();
    registry
        .burn(
            "CC-SOLAR-2026-001",
            SerialRange::new(1_000_000, 1_000_999).unwrap(),
            "Corp".to_string(),
            ClaimType::CorporateNetZero,
        )
        .unwrap();

    // New PoI with the same serial range
    let commitment_b = mrv::commit(&records, 999);
    let mut poi_b = make_poi(commitment_b);
    poi_b.credit_id = "CC-SOLAR-2026-002".to_string(); // different credit_id, same range

    let result = registry.mint(&mut poi_b, "0xOwner2".to_string());
    assert!(result.is_err(), "Burned range must be permanently blocked from re-mint");
}

// ---------------------------------------------------------------------------
// Test 6: Partial retirement — two sequential burns on the same batch
// ---------------------------------------------------------------------------

#[test]
fn partial_retirement_two_sequential_burns() {
    let records = make_mrv_records();
    let commitment = mrv::commit(&records, 0);
    let mut poi = make_poi(commitment);

    let mut registry = Registry::new();
    registry.mint(&mut poi, "0xOwner".to_string()).unwrap();

    // First partial burn: left edge (200 credits)
    let burn_1 = SerialRange::new(1_000_000, 1_000_199).unwrap();
    let poo_1 = registry
        .burn("CC-SOLAR-2026-001", burn_1, "BuyerA".to_string(), ClaimType::CorporateNetZero)
        .expect("First partial burn must succeed");

    assert!(poo_1.is_finalized());
    assert_eq!(poo_1.cc_amount, 200);
    assert_eq!(poo_1.beneficiary, "BuyerA");
    assert!(poo_1.amounts_are_consistent());
    assert_eq!(registry.burned_ranges.len(), 1);

    // Second partial burn: middle of remainder (300 credits)
    // Remaining active slice is [1_000_200, 1_000_999]
    let burn_2 = SerialRange::new(1_000_500, 1_000_799).unwrap();
    let poo_2 = registry
        .burn("CC-SOLAR-2026-001", burn_2, "BuyerB".to_string(), ClaimType::CorporateNetZero)
        .expect("Second partial burn must succeed");

    assert!(poo_2.is_finalized());
    assert_eq!(poo_2.cc_amount, 300);
    assert_eq!(poo_2.beneficiary, "BuyerB");
    assert!(poo_2.amounts_are_consistent());
    assert_eq!(registry.burned_ranges.len(), 2);

    let batch = registry.credits.first().unwrap();
    // 2 active (left and right of the second burn), 2 retired
    assert_eq!(batch.slices.len(), 4);
    
    let active_slices: Vec<_> = batch.slices.iter().filter(|s| s.status == CreditStatus::Active).collect();
    assert_eq!(active_slices.len(), 2);
    // Note: slice sorting might be required for robust equality check depending on order slices are pushed.
    assert!(active_slices.iter().any(|s| s.range == SerialRange::new(1_000_200, 1_000_499).unwrap()));
    assert!(active_slices.iter().any(|s| s.range == SerialRange::new(1_000_800, 1_000_999).unwrap()));

    let retired_slices: Vec<_> = batch.slices.iter().filter(|s| s.status == CreditStatus::Retired).collect();
    assert_eq!(retired_slices.len(), 2);
    assert!(retired_slices.iter().any(|s| s.range == SerialRange::new(1_000_000, 1_000_199).unwrap()));
    assert!(retired_slices.iter().any(|s| s.range == SerialRange::new(1_000_500, 1_000_799).unwrap()));
}

// ---------------------------------------------------------------------------
// Test 7: Verify BurnRangeNotFound is returned when burn targets non-active/missing slice
// ---------------------------------------------------------------------------

#[test]
fn partial_burn_missing_slice_returns_not_found() {
    let records = make_mrv_records();
    let commitment = mrv::commit(&records, 0);
    let mut poi = make_poi(commitment);

    let mut registry = Registry::new();
    registry.mint(&mut poi, "0xOwner".to_string()).unwrap();

    // Burn exactly [1_000_000, 1_000_499]
    let burn_1 = SerialRange::new(1_000_000, 1_000_499).unwrap();
    registry.burn("CC-SOLAR-2026-001", burn_1, "Corp".to_string(), ClaimType::CorporateNetZero).unwrap();

    // Try to burn from the retired slice -> should be PoOAlreadyIssued
    let burn_overlap = SerialRange::new(1_000_100, 1_000_200).unwrap();
    let err1 = registry.burn("CC-SOLAR-2026-001", burn_overlap, "Corp".to_string(), ClaimType::CorporateNetZero).unwrap_err();
    assert_eq!(err1, RegistryError::PoOAlreadyIssued);

    // Try to burn a boundary crossing range -> should be PoOAlreadyIssued
    let burn_cross = SerialRange::new(1_000_400, 1_000_600).unwrap();
    let err2 = registry.burn("CC-SOLAR-2026-001", burn_cross, "Corp".to_string(), ClaimType::CorporateNetZero).unwrap_err();
    assert_eq!(err2, RegistryError::PoOAlreadyIssued);

    // Try to burn an active but uncontained/disjoint range -> should be BurnRangeNotFound
    let burn_missing = SerialRange::new(2_000_000, 2_000_100).unwrap();
    let err3 = registry.burn("CC-SOLAR-2026-001", burn_missing, "Corp".to_string(), ClaimType::CorporateNetZero).unwrap_err();
    assert_eq!(err3, RegistryError::BurnRangeNotFound { start: 2_000_000, end: 2_000_100 });
}
