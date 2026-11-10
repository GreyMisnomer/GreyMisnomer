//! Synthetic event-log replay benchmark (Stage 3.5 — Task 3.16)
//!
//! Run with:
//!   cargo run --release -p grey-misnomer-core --example bench_replay

use grey_misnomer_core::{
    auth::{
        build_authority_event_preimage, build_genesis_preimage, build_mint_preimage,
        build_vvb_register_payload, compute_chain_id, Keypair, MintAttestationParams,
    },
    event_log::{render_canonical_line, replay_log, EventEntry, GENESIS_PREV_HASH},
    registry::RegistryEvent,
};
use std::time::Instant;

fn generate_mint_log(mint_count: usize) -> Vec<String> {
    let authority = Keypair::from_seed_str("bench-authority");
    let sequencer = Keypair::from_seed_str("bench-sequencer");
    let vvb = Keypair::from_seed_str("bench-vvb");
    let owner = Keypair::from_seed_str("bench-owner");

    let nonce = [7u8; 32];
    let created_at = 1_700_000_000;
    let genesis_msg = build_genesis_preimage(
        "BenchNet",
        &authority.pubkey(),
        &sequencer.pubkey(),
        &nonce,
        created_at,
    );
    let genesis_ev = RegistryEvent::Genesis {
        chain_name: "BenchNet".to_string(),
        authority: authority.pubkey(),
        sequencer: sequencer.pubkey(),
        nonce,
        created_at,
        authority_sig: authority.sign(&genesis_msg),
    };
    let chain_id = compute_chain_id(&genesis_ev.to_body_bytes());

    let mut lines = Vec::with_capacity(mint_count + 2);
    let e0 = EventEntry::new(0, GENESIS_PREV_HASH.to_string(), genesis_ev).unwrap();
    let mut prev_hash = e0.hash.clone();
    lines.push(render_canonical_line(&e0));

    let vvb_payload = build_vvb_register_payload(&vvb.pubkey(), "Bench-VVB");
    let vvb_msg = build_authority_event_preimage("vvb-register", &chain_id, 0, &vvb_payload);
    let vvb_ev = RegistryEvent::VvbRegister {
        authority_index: 0,
        vvb: vvb.pubkey(),
        label: "Bench-VVB".to_string(),
        authority_sig: authority.sign(&vvb_msg),
    };
    let e1 = EventEntry::new(1, prev_hash, vvb_ev).unwrap();
    prev_hash = e1.hash.clone();
    lines.push(render_canonical_line(&e1));

    let owner_pk = owner.pubkey();
    let vvb_pk = vvb.pubkey();
    let meth = "VM0042".to_string();
    let jur = "IN".to_string();
    let scope = "Vcm".to_string();

    for i in 0..mint_count {
        let seq = (i + 2) as u64;
        let project_id = format!("PRJ-{:05}", i % 16);
        let credit_id = format!("CC-{:07}", i);
        let range_start = (i as u64) * 1_000;
        let range_end = range_start + 999;
        let cc_mint_amount = 1_000u64;
        let merkle_root: [u8; 32] = *blake3::hash(&(i as u64).to_be_bytes()).as_bytes();
        let params = MintAttestationParams {
            chain_id: &chain_id,
            project_id: &project_id,
            credit_id: &credit_id,
            range_start,
            range_end,
            cc_mint_amount,
            merkle_root: &merkle_root,
            leaf_count: 10,
            mrv_timestamp: 1_700_000_000 + seq,
            methodology_hash: &meth,
            jurisdiction: &jur,
            market_scope: &scope,
            valid_from: 1_700_000_000,
            valid_until: 1_800_000_000,
            initial_owner: &owner_pk,
        };
        let sig = vvb.sign(&build_mint_preimage(&params));
        let mint_ev = RegistryEvent::Mint {
            project_id,
            credit_id,
            range_start,
            range_end,
            cc_mint_amount,
            merkle_root,
            leaf_count: 10,
            mrv_timestamp: 1_700_000_000 + seq,
            methodology_hash: meth.clone(),
            jurisdiction: jur.clone(),
            market_scope: scope.clone(),
            valid_from: 1_700_000_000,
            valid_until: 1_800_000_000,
            initial_owner: owner_pk,
            vvb: vvb_pk,
            vvb_sig: sig,
        };
        let entry = EventEntry::new(seq, prev_hash, mint_ev).unwrap();
        prev_hash = entry.hash.clone();
        lines.push(render_canonical_line(&entry));
    }
    lines
}

fn main() {
    println!("GreyMisnomer Core Replay Benchmark (Mints + Genesis + VVBRegister)");
    for &n in &[1_000usize, 4_000, 8_000] {
        let lines = generate_mint_log(n);
        let t0 = Instant::now();
        let summary = replay_log(lines.iter()).expect("benchmark replay should pass");
        let elapsed = t0.elapsed();
        assert_eq!(summary.events_count, (n + 2) as u64);
        assert!(summary.invariant_report.all_passed);
        println!(
            "  N = {:>5} mints ({:>5} events): {:.4} s",
            n,
            summary.events_count,
            elapsed.as_secs_f64()
        );
    }
}
