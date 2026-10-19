// Integration test: full Phase Alpha happy path (RFC-005)
//
// Proves the complete protocol chain from RFC-003 → RFC-001 → RFC-002 → RFC-005:
//   MRV Data → Merkle Root → Attestation & Signature → Mint → Signed Transfer → Signed Burn → PoO
//
// This is the canonical end-to-end test for Phase Alpha / Stage 1.5.
// Every protocol and authorization invariant (RFC-001 §5, RFC-005 §3.8) is exercised.

use grey_misnomer_core::{
    auth::{
        build_authority_event_preimage, build_burn_preimage, build_genesis_preimage,
        build_mint_preimage, build_transfer_preimage, build_vvb_register_payload, Keypair,
        MintAttestationParams, PubKey,
    },
    credit::CreditStatus,
    error::RegistryError,
    mrv::{self, MRVRecord},
    poo::ClaimType,
    registry::{Registry, RegistryEvent},
    serial::SerialRange,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_mrv_records() -> Vec<MRVRecord> {
    // Simulate a month of daily solar generation readings
    (0..30)
        .map(|day| MRVRecord {
            timestamp: 1_700_000_000 + day * 86_400,
            value: 1_250_000_000 + (day * 3_500_000), // micro-units (1,250 kWh)
            unit: "kWh".to_string(),
            source: format!("SOLAR-SENSOR-{:03}", day % 4),
        })
        .collect()
}

fn setup_registry() -> (Registry, Keypair, Keypair, Keypair) {
    let authority = Keypair::from_seed_str("authority-test");
    let sequencer = Keypair::from_seed_str("sequencer-test");
    let vvb = Keypair::from_seed_str("vvb-test");
    let mut registry = Registry::new();

    let nonce = [42u8; 32];
    let created_at = 1_700_000_000;
    let genesis_msg = build_genesis_preimage(
        "GreyMisnomer-Integration",
        &authority.pubkey(),
        &sequencer.pubkey(),
        &nonce,
        created_at,
    );
    let authority_sig = authority.sign(&genesis_msg);
    let genesis_event = RegistryEvent::Genesis {
        chain_name: "GreyMisnomer-Integration".to_string(),
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
    merkle_root: &[u8; 32],
    owner: &PubKey,
) -> RegistryEvent {
    let amount = end - start + 1;
    let params = MintAttestationParams {
        chain_id: &registry.chain_id,
        project_id: "PRJ-SOLAR-2026-001",
        credit_id,
        range_start: start,
        range_end: end,
        cc_mint_amount: amount,
        merkle_root,
        leaf_count: 30,
        mrv_timestamp: 1_700_000_000,
        methodology_hash: "SHA256(VM0042-v4.0)",
        jurisdiction: "IN-MH",
        market_scope: "VCM",
        valid_from: 1_700_000_000,
        valid_until: 9_999_999_999,
        initial_owner: owner,
    };
    let msg = build_mint_preimage(&params);
    let vvb_sig = vvb.sign(&msg);

    RegistryEvent::Mint {
        project_id: "PRJ-SOLAR-2026-001".to_string(),
        credit_id: credit_id.to_string(),
        range_start: start,
        range_end: end,
        cc_mint_amount: amount,
        merkle_root: *merkle_root,
        leaf_count: 30,
        mrv_timestamp: 1_700_000_000,
        methodology_hash: "SHA256(VM0042-v4.0)".to_string(),
        jurisdiction: "IN-MH".to_string(),
        market_scope: "VCM".to_string(),
        valid_from: 1_700_000_000,
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
    let owner_sig = owner_key.sign(&msg);
    RegistryEvent::Transfer {
        credit_id: credit_id.to_string(),
        op_index,
        new_owner: *new_owner,
        owner_sig,
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
    let owner_sig = owner_key.sign(&msg);
    RegistryEvent::Burn {
        credit_id: credit_id.to_string(),
        op_index,
        range_start: start,
        range_end: end,
        beneficiary: beneficiary.to_string(),
        claim_type,
        owner_sig,
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
    assert_ne!(
        commitment.merkle_root, [0u8; 32],
        "Root must not be zero hash"
    );

    // Step 3: Verify a sample inclusion proof
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

    // Step 4: Setup initialized registry with Genesis and accredited VVB
    let (mut registry, _, _, vvb) = setup_registry();
    let project_owner = Keypair::from_seed_str("project-owner");
    let buyer = Keypair::from_seed_str("buyer-key");

    // Step 5: Mint credits bound to MRV commitment with strict VVB signature
    let mint_event = make_mint_event(
        &registry,
        &vvb,
        "CC-SOLAR-2026-001",
        1_000_000,
        1_000_999,
        &commitment.merkle_root,
        &project_owner.pubkey(),
    );
    let batch = registry
        .mint(&mint_event)
        .expect("Mint must succeed with valid VVB attestation");

    assert_eq!(batch.credit_id, "CC-SOLAR-2026-001");
    assert_eq!(batch.original_range.size().unwrap(), 1000);
    assert_eq!(batch.owner, project_owner.pubkey());
    assert_eq!(batch.op_index, 0);
    assert_eq!(batch.vvb, vvb.pubkey());
    assert_ne!(batch.poi_hash, [0u8; 32]);

    // Step 6: Transfer to buyer with Ed25519 owner authorization
    let xfer_event = make_transfer_event(
        &registry,
        &project_owner,
        "CC-SOLAR-2026-001",
        0,
        &buyer.pubkey(),
    );
    registry
        .transfer(&xfer_event)
        .expect("Transfer must succeed for authorized owner");
    assert_eq!(registry.credits[0].owner, buyer.pubkey());
    assert_eq!(registry.credits[0].op_index, 1);

    // Step 7: Buyer retires — burn produces PoO (RFC-001 §3.2)
    let burn_event = make_burn_event(
        &registry,
        &buyer,
        "CC-SOLAR-2026-001",
        1,
        1_000_000,
        1_000_999,
        "AcmeCorp_NetZero_2026",
        ClaimType::CorporateNetZero,
    );
    let poo = registry
        .burn(&burn_event)
        .expect("Burn must succeed for authorized owner");

    // Validate PoO fields
    assert!(poo.is_finalized(), "PoO must be FINALIZED after burn");
    assert_eq!(poo.project_id, "PRJ-SOLAR-2026-001");
    assert_eq!(poo.credit_id, "CC-SOLAR-2026-001");
    assert_eq!(poo.beneficiary, "AcmeCorp_NetZero_2026");
    assert_eq!(poo.claim_type, ClaimType::CorporateNetZero);
    assert_eq!(poo.cc_amount, 1000);
    assert!(
        poo.amounts_are_consistent(),
        "PoO amounts must be internally consistent"
    );

    // Step 8: Assert all protocol and authorization invariants hold
    let rep = registry.check_invariants();
    assert!(rep.all_passed);
    assert!(rep.inv1_poi_mandatory);
    assert!(rep.inv2_supply_cap);
    assert!(rep.inv3_serial_uniqueness);
    assert!(rep.inv4_burn_irreversibility);
    assert!(rep.inv5_poo_uniqueness);
    assert!(rep.inv6_poo_non_transferable);
    assert!(rep.inv7_poi_single_use);
    assert!(rep.inva1_signature_validity);
    assert!(rep.inva2_op_index_contiguity);
    assert!(rep.inva3_chain_id_binding);
}

// ---------------------------------------------------------------------------
// Test 2: Tampered MRV data fails inclusion proof
// ---------------------------------------------------------------------------

#[test]
fn tampered_mrv_does_not_verify() {
    let records = make_mrv_records();
    let commitment = mrv::commit(&records, 0);

    let proof = mrv::generate_inclusion_proof(&records, 5).unwrap();

    let tampered = MRVRecord {
        timestamp: records[5].timestamp,
        value: 999_999_000_000,
        unit: records[5].unit.clone(),
        source: records[5].source.clone(),
    };

    assert!(
        !mrv::verify_inclusion_proof(&tampered, &proof, &commitment.merkle_root),
        "Tampered record must NOT verify — data integrity enforcement"
    );
}

// ---------------------------------------------------------------------------
// Test 3: Mint cannot authorize more than serial range supply (Invariant 2)
// ---------------------------------------------------------------------------

#[test]
fn poi_cannot_authorize_more_than_supply() {
    let (mut registry, _, _, vvb) = setup_registry();
    let owner = Keypair::from_seed_str("owner-key");
    let records = make_mrv_records();
    let commitment = mrv::commit(&records, 0);

    let mut mint_ev = make_mint_event(
        &registry,
        &vvb,
        "CC-SOLAR-2026-001",
        1_000_000,
        1_000_999,
        &commitment.merkle_root,
        &owner.pubkey(),
    );
    if let RegistryEvent::Mint {
        ref mut cc_mint_amount,
        ..
    } = mint_ev
    {
        *cc_mint_amount = 500; // mismatch with range (1000)
    }

    let result = registry.mint(&mint_ev);
    assert!(
        result.is_err(),
        "Mint must fail when range does not match cc_mint_amount"
    );
}

// ---------------------------------------------------------------------------
// Test 4: Same data root / PoI cannot authorize a second mint (Invariant 7)
// ---------------------------------------------------------------------------

#[test]
fn spent_poi_cannot_mint_again() {
    let (mut registry, _, _, vvb) = setup_registry();
    let owner = Keypair::from_seed_str("owner-key");
    let records = make_mrv_records();
    let commitment = mrv::commit(&records, 0);

    let mint_ev1 = make_mint_event(
        &registry,
        &vvb,
        "CC-SOLAR-2026-001",
        1_000_000,
        1_000_999,
        &commitment.merkle_root,
        &owner.pubkey(),
    );
    registry.mint(&mint_ev1).unwrap();

    let mint_ev2 = make_mint_event(
        &registry,
        &vvb,
        "CC-SOLAR-2026-002",
        2_000_000,
        2_000_999,
        &commitment.merkle_root, // Duplicate MRV root
        &owner.pubkey(),
    );
    let second = registry.mint(&mint_ev2);
    assert_eq!(second.unwrap_err(), RegistryError::DuplicateDataRoot);
}

// ---------------------------------------------------------------------------
// Test 5: Burned range cannot be re-minted (Invariant 4)
// ---------------------------------------------------------------------------

#[test]
fn burned_range_cannot_be_reminted() {
    let (mut registry, _, _, vvb) = setup_registry();
    let owner = Keypair::from_seed_str("owner-key");
    let records = make_mrv_records();
    let commitment_a = mrv::commit(&records, 0);

    let mint_a = make_mint_event(
        &registry,
        &vvb,
        "CC-SOLAR-2026-001",
        1_000_000,
        1_000_999,
        &commitment_a.merkle_root,
        &owner.pubkey(),
    );
    registry.mint(&mint_a).unwrap();

    let burn_ev = make_burn_event(
        &registry,
        &owner,
        "CC-SOLAR-2026-001",
        0,
        1_000_000,
        1_000_999,
        "Corp",
        ClaimType::CorporateNetZero,
    );
    registry.burn(&burn_ev).unwrap();

    let commitment_b = mrv::commit(&records, 999);
    let mint_b = make_mint_event(
        &registry,
        &vvb,
        "CC-SOLAR-2026-002",
        1_000_000,
        1_000_999, // Same burned range
        &commitment_b.merkle_root,
        &owner.pubkey(),
    );
    let result = registry.mint(&mint_b);
    assert_eq!(result.unwrap_err(), RegistryError::BurnIrreversible);
}

// ---------------------------------------------------------------------------
// Test 6: Partial retirement — two sequential burns on the same batch
// ---------------------------------------------------------------------------

#[test]
fn partial_retirement_two_sequential_burns() {
    let (mut registry, _, _, vvb) = setup_registry();
    let owner = Keypair::from_seed_str("owner-key");
    let records = make_mrv_records();
    let commitment = mrv::commit(&records, 0);

    let mint_ev = make_mint_event(
        &registry,
        &vvb,
        "CC-SOLAR-2026-001",
        1_000_000,
        1_000_999,
        &commitment.merkle_root,
        &owner.pubkey(),
    );
    registry.mint(&mint_ev).unwrap();

    // First partial burn: left edge (200 credits)
    let burn_ev1 = make_burn_event(
        &registry,
        &owner,
        "CC-SOLAR-2026-001",
        0,
        1_000_000,
        1_000_199,
        "BuyerA",
        ClaimType::CorporateNetZero,
    );
    let poo_1 = registry
        .burn(&burn_ev1)
        .expect("First partial burn must succeed");

    assert!(poo_1.is_finalized());
    assert_eq!(poo_1.cc_amount, 200);
    assert_eq!(poo_1.beneficiary, "BuyerA");
    assert!(poo_1.amounts_are_consistent());
    assert_eq!(registry.burned_ranges.len(), 1);

    // Second partial burn: middle of remainder (300 credits)
    let burn_ev2 = make_burn_event(
        &registry,
        &owner,
        "CC-SOLAR-2026-001",
        1, // op_index incremented
        1_000_500,
        1_000_799,
        "BuyerB",
        ClaimType::CorporateNetZero,
    );
    let poo_2 = registry
        .burn(&burn_ev2)
        .expect("Second partial burn must succeed");

    assert!(poo_2.is_finalized());
    assert_eq!(poo_2.cc_amount, 300);
    assert_eq!(poo_2.beneficiary, "BuyerB");
    assert!(poo_2.amounts_are_consistent());
    assert_eq!(registry.burned_ranges.len(), 2);

    let batch = registry.credits.first().unwrap();
    assert_eq!(batch.slices.len(), 4);

    let active_slices: Vec<_> = batch
        .slices
        .iter()
        .filter(|s| s.status == CreditStatus::Active)
        .collect();
    assert_eq!(active_slices.len(), 2);
    assert!(active_slices
        .iter()
        .any(|s| s.range == SerialRange::new(1_000_200, 1_000_499).unwrap()));
    assert!(active_slices
        .iter()
        .any(|s| s.range == SerialRange::new(1_000_800, 1_000_999).unwrap()));

    let retired_slices: Vec<_> = batch
        .slices
        .iter()
        .filter(|s| s.status == CreditStatus::Retired)
        .collect();
    assert_eq!(retired_slices.len(), 2);
    assert!(retired_slices
        .iter()
        .any(|s| s.range == SerialRange::new(1_000_000, 1_000_199).unwrap()));
    assert!(retired_slices
        .iter()
        .any(|s| s.range == SerialRange::new(1_000_500, 1_000_799).unwrap()));
}

// ---------------------------------------------------------------------------
// Test 7: Verify BurnRangeNotFound is returned when burn targets non-active/missing slice
// ---------------------------------------------------------------------------

#[test]
fn partial_burn_missing_slice_returns_not_found() {
    let (mut registry, _, _, vvb) = setup_registry();
    let owner = Keypair::from_seed_str("owner-key");
    let records = make_mrv_records();
    let commitment = mrv::commit(&records, 0);

    let mint_ev = make_mint_event(
        &registry,
        &vvb,
        "CC-SOLAR-2026-001",
        1_000_000,
        1_000_999,
        &commitment.merkle_root,
        &owner.pubkey(),
    );
    registry.mint(&mint_ev).unwrap();

    // Burn exactly [1_000_000, 1_000_499]
    let burn_ev1 = make_burn_event(
        &registry,
        &owner,
        "CC-SOLAR-2026-001",
        0,
        1_000_000,
        1_000_499,
        "Corp",
        ClaimType::CorporateNetZero,
    );
    registry.burn(&burn_ev1).unwrap();

    // Try to burn from the retired slice -> should be PoOAlreadyIssued
    let burn_overlap = make_burn_event(
        &registry,
        &owner,
        "CC-SOLAR-2026-001",
        1,
        1_000_100,
        1_000_200,
        "Corp",
        ClaimType::CorporateNetZero,
    );
    let err1 = registry.burn(&burn_overlap).unwrap_err();
    assert_eq!(err1, RegistryError::PoOAlreadyIssued);

    // Try to burn a boundary crossing range -> should be PoOAlreadyIssued
    let burn_cross = make_burn_event(
        &registry,
        &owner,
        "CC-SOLAR-2026-001",
        1,
        1_000_400,
        1_000_600,
        "Corp",
        ClaimType::CorporateNetZero,
    );
    let err2 = registry.burn(&burn_cross).unwrap_err();
    assert_eq!(err2, RegistryError::PoOAlreadyIssued);

    // Try to burn an active but uncontained/disjoint range -> should be BurnRangeNotFound
    let burn_missing = make_burn_event(
        &registry,
        &owner,
        "CC-SOLAR-2026-001",
        1,
        2_000_000,
        2_000_100,
        "Corp",
        ClaimType::CorporateNetZero,
    );
    let err3 = registry.burn(&burn_missing).unwrap_err();
    assert_eq!(
        err3,
        RegistryError::BurnRangeNotFound {
            start: 2_000_000,
            end: 2_000_100
        }
    );
}
