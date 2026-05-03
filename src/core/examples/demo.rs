//! GreyMisnomer Protocol — Phase Alpha Demo
//!
//! Runs the complete protocol flow end-to-end and prints each step to stdout.
//! This is a human-readable walkthrough, not a benchmark or stress test.
//!
//! Run with:
//!   cargo run --example demo

use grey_misnomer_core::{
    credit::CreditStatus,
    mrv::{self, MRVRecord},
    poi::{PoI, PoIStatus},
    poo::ClaimType,
    project::MarketScope,
    registry::Registry,
    serial::SerialRange,
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
    // Show first 8 bytes as hex — enough to distinguish roots without flooding the terminal
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
            value: 1_250.0 + (day as f64 * 3.5), // kWh — slight daily ramp
            unit: "kWh".to_string(),
            source: format!("SOLAR-SENSOR-{:03}", day % 4),
        })
        .collect()
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    println!();
    println!("  GreyMisnomer Protocol — Phase Alpha CLI Demo");
    println!("  RFC-001 · RFC-002 · RFC-003");

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
    field(
        "Sample record [29]",
        &format!(
            "ts={} val={:.1} {}  src={}",
            records[29].timestamp, records[29].value, records[29].unit, records[29].source
        ),
    );
    ok("MRV dataset ready");

    // ── Step 2: Merkle commitment ────────────────────────────────────────────
    header("STEP 2 — Merkle Tree Commitment (RFC-003 §3.2)");

    let commitment = mrv::commit(&records, 1_700_000_000);
    field("Algorithm", &commitment.hash_algorithm);
    field("Leaf count", &commitment.leaf_count.to_string());
    field("Merkle root (first 8B)", &hex8(&commitment.merkle_root));
    field("Timestamp", &commitment.timestamp.to_string());

    // Spot-check inclusion proofs
    let proof_first = mrv::generate_inclusion_proof(&records, 0).unwrap();
    let proof_last = mrv::generate_inclusion_proof(&records, 29).unwrap();
    assert!(mrv::verify_inclusion_proof(&records[0], &proof_first, &commitment.merkle_root));
    assert!(mrv::verify_inclusion_proof(&records[29], &proof_last, &commitment.merkle_root));
    ok("Inclusion proof [0]  → verified");
    ok("Inclusion proof [29] → verified");

    // Demonstrate tamper detection
    let tampered = MRVRecord {
        timestamp: records[5].timestamp,
        value: 999_999.0, // fabricated
        unit: records[5].unit.clone(),
        source: records[5].source.clone(),
    };
    let proof_5 = mrv::generate_inclusion_proof(&records, 5).unwrap();
    assert!(!mrv::verify_inclusion_proof(&tampered, &proof_5, &commitment.merkle_root));
    ok("Tampered record [5]  → REJECTED by Merkle proof ✗");

    // ── Step 3: Proof-of-Integrity ───────────────────────────────────────────
    header("STEP 3 — Proof-of-Integrity (PoI) Construction (RFC-001 §3.1)");

    let mut poi = PoI {
        project_id: "PRJ-SOLAR-2026-001".to_string(),
        mrv_commitment: commitment,
        methodology_hash: "SHA256(VM0042-v4.0)".to_string(),
        vvb_signature: "0xVVB_SIG_MOCK_A1B2C3".to_string(),
        serialization_range: SerialRange::new(1_000_000, 1_000_999).unwrap(),
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
    };

    field("Project ID", &poi.project_id);
    field("Credit ID", &poi.credit_id);
    field("Serial range", &format!("{} – {}", poi.serialization_range.start, poi.serialization_range.end));
    field("Authorized supply", &format!("{} tCO2e", poi.cc_mint_amount));
    field("Jurisdiction", &poi.jurisdiction);
    field("VVB signature", &poi.vvb_signature);
    field("Status", "VALID");
    ok("PoI constructed and ready for minting");

    // ── Step 4: Mint ─────────────────────────────────────────────────────────
    header("STEP 4 — Mint (RFC-001 §3.1 → RFC-002)");

    let mut registry = Registry::new();
    let batch = registry
        .mint(&mut poi, "0xProjectOwner".to_string())
        .expect("Mint must succeed");

    field("Credit ID minted", &batch.credit_id);
    field("Owner", &batch.owner);
    field("Original range", &format!("{} – {} ({} credits)",
        batch.original_range.start, batch.original_range.end, batch.original_range.size()));
    field("Active slices", &batch.slices.len().to_string());
    field("PoI status after mint", "USED");
    assert!(poi.is_used());
    ok("Mint successful — PoI consumed (Invariant 7)");
    ok("Serial range locked globally (Invariant 3)");

    // Demonstrate PoI single-use enforcement
    let replay = registry.mint(&mut poi, "0xAttacker".to_string());
    assert!(replay.is_err());
    ok("Replay attempt rejected — PoI already USED ✗");

    // ── Step 5: Transfer ─────────────────────────────────────────────────────
    header("STEP 5 — Transfer to Buyer (RFC-002 §4)");

    registry
        .transfer("CC-SOLAR-2026-001", "0xBuyer".to_string())
        .expect("Transfer must succeed");

    field("Previous owner", "0xProjectOwner");
    field("New owner", &registry.credits[0].owner);
    ok("Ownership transferred — credit still Active");

    // ── Step 6: First partial burn ───────────────────────────────────────────
    header("STEP 6 — First Partial Retirement (RFC-002 §5)");
    println!("  Retiring left edge: 1_000_000 – 1_000_299 (300 credits)");
    println!();

    let burn_1 = SerialRange::new(1_000_000, 1_000_299).unwrap();
    let poo_1 = registry
        .burn(
            "CC-SOLAR-2026-001",
            burn_1,
            "AcmeCorp_NetZero_2026".to_string(),
            ClaimType::CorporateNetZero,
        )
        .expect("First burn must succeed");

    field("PoO status", "FINALIZED");
    field("Beneficiary", &poo_1.beneficiary);
    field("Claim type", "CorporateNetZero");
    field("Credits retired", &format!("{} tCO2e", poo_1.cc_amount));
    field("Burn tx hash", &poo_1.burn_tx_hash);
    assert!(poo_1.amounts_are_consistent());
    ok("PoO-1 issued and amounts consistent");

    // Print slice state
    println!();
    println!("  Slice state after first burn:");
    print_slice_state(&registry, "CC-SOLAR-2026-001");

    // ── Step 7: Second partial burn ──────────────────────────────────────────
    header("STEP 7 — Second Partial Retirement (RFC-002 §5)");
    println!("  Retiring middle section: 1_000_600 – 1_000_799 (200 credits)");
    println!("  Source slice: [1_000_300 – 1_000_999] (active remainder from Step 6)");
    println!();

    let burn_2 = SerialRange::new(1_000_600, 1_000_799).unwrap();
    let poo_2 = registry
        .burn(
            "CC-SOLAR-2026-001",
            burn_2,
            "GreenEnergy_Ltd".to_string(),
            ClaimType::Compliance,
        )
        .expect("Second burn must succeed");

    field("PoO status", "FINALIZED");
    field("Beneficiary", &poo_2.beneficiary);
    field("Claim type", "Compliance");
    field("Credits retired", &format!("{} tCO2e", poo_2.cc_amount));
    field("Burn tx hash", &poo_2.burn_tx_hash);
    assert!(poo_2.amounts_are_consistent());
    ok("PoO-2 issued and amounts consistent");

    println!();
    println!("  Slice state after second burn:");
    print_slice_state(&registry, "CC-SOLAR-2026-001");

    // ── Step 8: Invariant verification ───────────────────────────────────────
    header("STEP 8 — Invariant Verification");

    let batch = registry.credits.first().unwrap();

    // Supply conservation
    let active_total: u64 = batch
        .slices
        .iter()
        .filter(|s| s.status == CreditStatus::Active)
        .map(|s| s.range.size())
        .sum();
    let retired_total: u64 = batch
        .slices
        .iter()
        .filter(|s| s.status == CreditStatus::Retired)
        .map(|s| s.range.size())
        .sum();

    field("Original supply", &format!("{} credits", batch.original_range.size()));
    field("Active remaining", &format!("{} credits", active_total));
    field("Retired total", &format!("{} credits", retired_total));
    field(
        "Conservation check",
        &format!("{} + {} = {}", active_total, retired_total, active_total + retired_total),
    );

    assert_eq!(
        active_total + retired_total,
        batch.original_range.size(),
        "Supply conservation violated"
    );
    ok("Supply conservation holds (active + retired = original)");

    // Internal consistency
    assert!(batch.validate_internal(), "Internal state corrupted");
    ok("CreditBatch internal validation passed (no overlaps, all within original_range)");

    // original_range immutability
    assert_eq!(batch.original_range, SerialRange::new(1_000_000, 1_000_999).unwrap());
    ok("original_range unchanged — audit trail intact (Invariant anchor)");

    // Double-burn prevention
    let double_burn = registry.burn(
        "CC-SOLAR-2026-001",
        burn_1,
        "Attacker".to_string(),
        ClaimType::CorporateNetZero,
    );
    assert!(double_burn.is_err());
    ok("Double-burn on retired range rejected (Invariant 5) ✗");

    // Burned range re-mint prevention
    let mut poi_b = PoI {
        project_id: "PRJ-SOLAR-2026-001".to_string(),
        mrv_commitment: mrv::commit(&records, 9999),
        methodology_hash: "SHA256(VM0042-v4.0)".to_string(),
        vvb_signature: "0xVVB_SIG_MOCK_NEW".to_string(),
        serialization_range: SerialRange::new(1_000_000, 1_000_999).unwrap(),
        amount_tco2e: 1000,
        jurisdiction: "IN-MH".to_string(),
        market_scope: MarketScope::Vcm,
        credit_id: "CC-SOLAR-2026-FAKE".to_string(),
        valid_from: 0,
        valid_until: 9_999_999_999,
        poi_valid: true,
        cc_mint_amount: 1000,
        owner: "0xAttacker".to_string(),
        status: PoIStatus::Valid,
    };
    let remint = registry.mint(&mut poi_b, "0xAttacker".to_string());
    assert!(remint.is_err());
    ok("Re-mint of burned range blocked (Invariant 4) ✗");

    // ── Summary ───────────────────────────────────────────────────────────────
    header("SUMMARY");

    println!("  Protocol flow completed successfully.");
    println!();
    println!("  MRV records hashed        : {} leaves → Merkle root", records.len());
    println!("  Credits minted            : 1000 tCO2e (range 1_000_000–1_000_999)");
    println!("  Ownership transfers       : 1  (ProjectOwner → Buyer)");
    println!("  Partial retirements       : 2");
    println!("    PoO-1  300 tCO2e        → AcmeCorp_NetZero_2026  [CorporateNetZero]");
    println!("    PoO-2  200 tCO2e        → GreenEnergy_Ltd         [Compliance]");
    println!("  Credits still active      : {} tCO2e", active_total);
    println!("  Burned ranges on record   : {}", registry.burned_ranges.len());
    println!();
    println!("  All RFC-001 invariants enforced at runtime.");
    println!("  Supply conserved. Audit trail intact.");
    println!();
    divider();
    println!();
}

// ── Print slice state ─────────────────────────────────────────────────────────

fn print_slice_state(registry: &Registry, credit_id: &str) {
    let batch = registry
        .credits
        .iter()
        .find(|b| b.credit_id == credit_id)
        .unwrap();

    // Sort by start for display
    let mut sorted = batch.slices.clone();
    sorted.sort_by_key(|s| s.range.start);

    for s in &sorted {
        let status_label = match s.status {
            CreditStatus::Active  => "ACTIVE ",
            CreditStatus::Retired => "RETIRED",
            CreditStatus::Expired => "EXPIRED",
        };
        println!(
            "    [{status_label}]  {:>12} – {:>12}  ({} credits)",
            s.range.start, s.range.end, s.range.size()
        );
    }
}
