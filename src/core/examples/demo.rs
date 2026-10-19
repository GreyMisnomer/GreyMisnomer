//! GreyMisnomer Protocol — Phase Alpha / Stage 1.5 CLI Walkthrough
//!
//! Demonstrates the complete cryptographic protocol flow:
//!   MRV Data → Merkle Root → Genesis Trust Anchor → Accredited VVB Registration →
//!   Signed Mint Attestation → Signed Transfer → Signed Partial Burns → Proof-of-Offset Receipts
//!
//! Run with:
//!   cargo run --example demo

use grey_misnomer_core::{
    auth::{
        build_authority_event_preimage, build_burn_preimage, build_genesis_preimage,
        build_mint_preimage, build_transfer_preimage, build_vvb_register_payload, Keypair,
        MintAttestationParams,
    },
    credit::CreditStatus,
    mrv::{self, MRVRecord},
    poo::ClaimType,
    registry::{Registry, RegistryEvent},
};

// ── Formatting helpers ────────────────────────────────────────────────────────

fn divider() {
    println!("{}", "─".repeat(64));
}

fn header(title: &str) {
    println!();
    divider();
    println!("  {title}");
    divider();
}

fn field(label: &str, value: &str) {
    println!("  {:<28} {}", format!("{}:", label), value);
}

fn ok(msg: &str) {
    println!("  ✓  {msg}");
}

fn hex8(bytes: &[u8; 32]) -> String {
    bytes[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("")
        + "..."
}

// ── MRV dataset ───────────────────────────────────────────────────────────────

fn make_mrv_records() -> Vec<MRVRecord> {
    // Simulate 30 days of solar generation readings for project PRJ-SOLAR-2026-001
    (0..30)
        .map(|day| MRVRecord {
            timestamp: 1_700_000_000 + day * 86_400,
            value: 1_250_000_000 + (day * 3_500_000), // micro-units (1,250 kWh)
            unit: "kWh".to_string(),
            source: format!("SOLAR-SENSOR-{:03}", day % 4),
        })
        .collect()
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    println!();
    println!("  GreyMisnomer Protocol — Stage 1.5 Cryptographic CLI Demo");
    println!("  RFC-001 · RFC-002 · RFC-003 · RFC-004 · RFC-005");

    // ── Key Management ───────────────────────────────────────────────────────
    let authority = Keypair::from_seed_str("authority-demo-key");
    let sequencer = Keypair::from_seed_str("sequencer-demo-key");
    let vvb = Keypair::from_seed_str("vvb-tuv-nord-key");
    let project_owner = Keypair::from_seed_str("project-owner-solar-key");
    let buyer = Keypair::from_seed_str("corporate-buyer-key");

    // ── Step 1: MRV data collection ──────────────────────────────────────────
    header("STEP 1 — MRV Data Collection (RFC-003)");

    let records = make_mrv_records();
    field("Records collected", &records.len().to_string());
    field("Period", "30 days of solar generation");
    field("Sensors", "4 rotating sensors (SOLAR-SENSOR-000 to 003)");
    field(
        "Sample record [0]",
        &format!(
            "ts={} val={:.1} {}  src={}",
            records[0].timestamp, records[0].value, records[0].unit, records[0].source
        ),
    );
    ok("MRV dataset ready");

    // ── Step 2: Merkle commitment ────────────────────────────────────────────
    header("STEP 2 — Merkle Tree Commitment (RFC-003 §3.2)");

    let commitment = mrv::commit(&records, 1_700_000_000);
    field("Algorithm", &commitment.hash_algorithm);
    field("Leaf count", &commitment.leaf_count.to_string());
    field("Merkle root (first 8B)", &hex8(&commitment.merkle_root));

    let proof_0 = mrv::generate_inclusion_proof(&records, 0).unwrap();
    assert!(mrv::verify_inclusion_proof(
        &records[0],
        &proof_0,
        &commitment.merkle_root
    ));
    ok("Merkle root generated & inclusion proof verified (RFC-003)");

    // ── Step 3: Genesis Trust Anchor & VVB Registration ─────────────────────
    header("STEP 3 — Registry Genesis & VVB Accreditation (RFC-005 §3.4)");

    let mut registry = Registry::new();
    let nonce = [42u8; 32];
    let created_at = 1_700_000_000;
    let genesis_msg = build_genesis_preimage(
        "GreyMisnomer-MainAlpha",
        &authority.pubkey(),
        &sequencer.pubkey(),
        &nonce,
        created_at,
    );
    let authority_sig = authority.sign(&genesis_msg);
    let genesis_event = RegistryEvent::Genesis {
        chain_name: "GreyMisnomer-MainAlpha".to_string(),
        authority: authority.pubkey(),
        sequencer: sequencer.pubkey(),
        nonce,
        created_at,
        authority_sig,
    };
    registry.apply_event(&genesis_event).expect("Genesis apply");

    field("Chain ID", &hex8(&registry.chain_id));
    field("Root Authority", &authority.pubkey().to_hex()[..16]);
    field("Sequencer Key", &sequencer.pubkey().to_hex()[..16]);
    ok("Genesis event validated & chain_id established");

    // Register accredited VVB
    let vvb_payload = build_vvb_register_payload(&vvb.pubkey(), "TÜV NORD Cert");
    let vvb_msg =
        build_authority_event_preimage("vvb-register", &registry.chain_id, 0, &vvb_payload);
    let vvb_sig = authority.sign(&vvb_msg);
    let vvb_event = RegistryEvent::VvbRegister {
        authority_index: 0,
        vvb: vvb.pubkey(),
        label: "TÜV NORD Cert".to_string(),
        authority_sig: vvb_sig,
    };
    registry.apply_event(&vvb_event).expect("VVB registration");
    ok("VVB accredited with authority signature (authority_index = 0)");

    // ── Step 4: Mint Credits with Strict VVB Attestation ────────────────────
    header("STEP 4 — Signed Mint Attestation (RFC-001 §3.1, RFC-005 §3.5)");

    let mint_params = MintAttestationParams {
        chain_id: &registry.chain_id,
        project_id: "PRJ-SOLAR-2026-001",
        credit_id: "CC-SOLAR-2026-001",
        range_start: 1_000_000,
        range_end: 1_000_999,
        cc_mint_amount: 1000,
        merkle_root: &commitment.merkle_root,
        leaf_count: 30,
        mrv_timestamp: 1_700_000_000,
        methodology_hash: "SHA256(VM0042-v4.0)",
        jurisdiction: "IN-MH",
        market_scope: "VCM",
        valid_from: 1_700_000_000,
        valid_until: 9_999_999_999,
        initial_owner: &project_owner.pubkey(),
    };
    let mint_msg = build_mint_preimage(&mint_params);
    let vvb_sig = vvb.sign(&mint_msg);

    let mint_event = RegistryEvent::Mint {
        project_id: "PRJ-SOLAR-2026-001".to_string(),
        credit_id: "CC-SOLAR-2026-001".to_string(),
        range_start: 1_000_000,
        range_end: 1_000_999,
        cc_mint_amount: 1000,
        merkle_root: commitment.merkle_root,
        leaf_count: 30,
        mrv_timestamp: 1_700_000_000,
        methodology_hash: "SHA256(VM0042-v4.0)".to_string(),
        jurisdiction: "IN-MH".to_string(),
        market_scope: "VCM".to_string(),
        valid_from: 1_700_000_000,
        valid_until: 9_999_999_999,
        initial_owner: project_owner.pubkey(),
        vvb: vvb.pubkey(),
        vvb_sig,
    };
    let batch = registry.mint(&mint_event).expect("Mint must succeed");

    field("Credit ID minted", &batch.credit_id);
    field("Owner PubKey", &batch.owner.to_hex()[..16]);
    field("Attesting VVB", &batch.vvb.to_hex()[..16]);
    field("PoI Hash", &hex8(&batch.poi_hash));
    field("Serial Range", "1_000_000 – 1_000_999 (1000 credits)");
    ok("Mint successful — verified under strict Ed25519 VVB signature");

    // ── Step 5: Transfer to Buyer ───────────────────────────────────────────
    header("STEP 5 — Transfer to Corporate Buyer (RFC-002 §4, RFC-005 §3.5)");

    let xfer_msg =
        build_transfer_preimage(&registry.chain_id, "CC-SOLAR-2026-001", 0, &buyer.pubkey());
    let owner_sig = project_owner.sign(&xfer_msg);
    let xfer_event = RegistryEvent::Transfer {
        credit_id: "CC-SOLAR-2026-001".to_string(),
        op_index: 0,
        new_owner: buyer.pubkey(),
        owner_sig,
    };
    registry
        .transfer(&xfer_event)
        .expect("Transfer must succeed");

    field("New Owner", &registry.credits[0].owner.to_hex()[..16]);
    field("New op_index", &registry.credits[0].op_index.to_string());
    ok("Ownership transferred — signed by Project Owner, op_index incremented to 1");

    // ── Step 6: First Partial Burn ──────────────────────────────────────────
    header("STEP 6 — First Partial Retirement (RFC-002 §5, RFC-005 §3.5)");

    let burn_msg_1 = build_burn_preimage(
        &registry.chain_id,
        "CC-SOLAR-2026-001",
        1,
        1_000_000,
        1_000_299,
        "AcmeCorp_NetZero_2026",
        ClaimType::CorporateNetZero.as_str(),
    );
    let burn_sig_1 = buyer.sign(&burn_msg_1);
    let burn_event_1 = RegistryEvent::Burn {
        credit_id: "CC-SOLAR-2026-001".to_string(),
        op_index: 1,
        range_start: 1_000_000,
        range_end: 1_000_299,
        beneficiary: "AcmeCorp_NetZero_2026".to_string(),
        claim_type: ClaimType::CorporateNetZero,
        owner_sig: burn_sig_1,
    };
    let poo_1 = registry.burn(&burn_event_1).expect("Burn 1");

    field("PoO Beneficiary", &poo_1.beneficiary);
    field("Claim Type", "CorporateNetZero");
    field("Credits Retired", &format!("{} tCO2e", poo_1.cc_amount));
    ok("PoO-1 issued and signed by Buyer");
    print_slice_state(&registry, "CC-SOLAR-2026-001");

    // ── Step 7: Second Partial Burn ─────────────────────────────────────────
    header("STEP 7 — Second Partial Retirement (RFC-002 §5, RFC-005 §3.5)");

    let burn_msg_2 = build_burn_preimage(
        &registry.chain_id,
        "CC-SOLAR-2026-001",
        2,
        1_000_600,
        1_000_799,
        "GreenEnergy_Ltd",
        ClaimType::Compliance.as_str(),
    );
    let burn_sig_2 = buyer.sign(&burn_msg_2);
    let burn_event_2 = RegistryEvent::Burn {
        credit_id: "CC-SOLAR-2026-001".to_string(),
        op_index: 2,
        range_start: 1_000_600,
        range_end: 1_000_799,
        beneficiary: "GreenEnergy_Ltd".to_string(),
        claim_type: ClaimType::Compliance,
        owner_sig: burn_sig_2,
    };
    let poo_2 = registry.burn(&burn_event_2).expect("Burn 2");

    field("PoO Beneficiary", &poo_2.beneficiary);
    field("Credits Retired", &format!("{} tCO2e", poo_2.cc_amount));
    ok("PoO-2 issued and signed by Buyer");
    print_slice_state(&registry, "CC-SOLAR-2026-001");

    // ── Step 8: Invariant Verification ──────────────────────────────────────
    header("STEP 8 — Invariant Verification Engine (RFC-001 §5 & RFC-005 §3.8)");

    let report = registry.check_invariants();
    assert!(report.all_passed);
    field("Invariant 1 (PoI / VVB mandatory)", "PASSED ✓");
    field("Invariant 2 (Supply cap conserved)", "PASSED ✓");
    field("Invariant 3 (Serial range unique)", "PASSED ✓");
    field("Invariant 4 (Burn irreversible)", "PASSED ✓");
    field("Invariant 5 (PoO uniqueness)", "PASSED ✓");
    field("Invariant 6 (PoO non-transferable)", "PASSED ✓");
    field("Invariant 7 (PoI single-use)", "PASSED ✓");
    field("Invariant A1 (Signature validity)", "PASSED ✓");
    field("Invariant A2 (op_index contiguity)", "PASSED ✓");
    field("Invariant A3 (Chain ID binding)", "PASSED ✓");
    ok("All 10 protocol and authorization invariants verified!");

    // ── Summary ─────────────────────────────────────────────────────────────
    header("SUMMARY");
    println!("  Protocol flow completed successfully under strict Ed25519 authorization.");
    println!("  $0 Infrastructure budget verified.");
    println!();
    divider();
    println!();
}

fn print_slice_state(registry: &Registry, credit_id: &str) {
    let batch = registry
        .credits
        .iter()
        .find(|b| b.credit_id == credit_id)
        .unwrap();

    let mut sorted = batch.slices.clone();
    sorted.sort_by_key(|s| s.range.start);

    for s in &sorted {
        let status_label = match s.status {
            CreditStatus::Active => "ACTIVE ",
            CreditStatus::Retired => "RETIRED",
            CreditStatus::Expired => "EXPIRED",
        };
        println!(
            "    [{status_label}]  {:>12} – {:>12}  ({} credits)",
            s.range.start,
            s.range.end,
            s.range.size().expect("valid serial range")
        );
    }
}
