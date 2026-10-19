use grey_misnomer_core::{
    auth::{
        build_authority_event_preimage, build_burn_preimage, build_genesis_preimage,
        build_mint_preimage, build_transfer_preimage, build_vvb_register_payload, Keypair,
        MintAttestationParams,
    },
    checkpoint::Checkpoint,
    event_log::EventEntry,
    poo::ClaimType,
    registry::{apply, RegistryEvent, RegistryState},
};
use std::fs;

fn main() {
    println!("Generating canonical RFC-005 events.jsonl and checkpoints...");

    let authority = Keypair::from_seed_str("authority-demo-key-2026");
    let sequencer = Keypair::from_seed_str("sequencer-demo-key-2026");
    let vvb = Keypair::from_seed_str("vvb-tuv-nord-key-2026");
    let tata_solar = Keypair::from_seed_str("tata-solar-project-owner-2026");
    let infosys = Keypair::from_seed_str("infosys-corporate-buyer-2026");

    let mut state = RegistryState::new();
    let mut entries = Vec::new();

    // ── Seq 0: Genesis ────────────────────────────────────────────────────────
    let nonce = [42u8; 32];
    let created_at = 1_700_000_000;
    let genesis_msg = build_genesis_preimage(
        "GreyMisnomer-Alpha",
        &authority.pubkey(),
        &sequencer.pubkey(),
        &nonce,
        created_at,
    );
    let genesis_event = RegistryEvent::Genesis {
        chain_name: "GreyMisnomer-Alpha".to_string(),
        authority: authority.pubkey(),
        sequencer: sequencer.pubkey(),
        nonce,
        created_at,
        authority_sig: authority.sign(&genesis_msg),
    };
    state = apply(&state, &genesis_event).expect("apply genesis");
    let entry_0 = EventEntry::new(
        0,
        "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        genesis_event,
    )
    .expect("entry 0");
    entries.push(entry_0);

    // ── Seq 1: VvbRegister ───────────────────────────────────────────────────
    let vvb_payload = build_vvb_register_payload(&vvb.pubkey(), "TUV NORD Carbon Bureau");
    let vvb_msg = build_authority_event_preimage("vvb-register", &state.chain_id, 0, &vvb_payload);
    let vvb_event = RegistryEvent::VvbRegister {
        authority_index: 0,
        vvb: vvb.pubkey(),
        label: "TUV NORD Carbon Bureau".to_string(),
        authority_sig: authority.sign(&vvb_msg),
    };
    state = apply(&state, &vvb_event).expect("apply vvb_register");
    let entry_1 = EventEntry::new(1, entries[0].hash.clone(), vvb_event).expect("entry 1");
    entries.push(entry_1);

    // ── Seq 2: Mint 1000 credits ─────────────────────────────────────────────
    let mut merkle_root = [0u8; 32];
    merkle_root[0..20].copy_from_slice(b"CC-IN-SOLAR-2026-001");

    let mint_params = MintAttestationParams {
        chain_id: &state.chain_id,
        project_id: "PRJ-001",
        credit_id: "CC-IN-SOLAR-2026-001",
        range_start: 1_000_000,
        range_end: 1_000_999,
        cc_mint_amount: 1000,
        merkle_root: &merkle_root,
        leaf_count: 30,
        mrv_timestamp: 1_700_000_000,
        methodology_hash: "0xMETH01",
        jurisdiction: "IN",
        market_scope: "Vcm",
        valid_from: 1_700_000_000,
        valid_until: 1_730_000_000,
        initial_owner: &tata_solar.pubkey(),
    };
    let mint_msg = build_mint_preimage(&mint_params);
    let mint_event = RegistryEvent::Mint {
        project_id: "PRJ-001".to_string(),
        credit_id: "CC-IN-SOLAR-2026-001".to_string(),
        range_start: 1_000_000,
        range_end: 1_000_999,
        cc_mint_amount: 1000,
        merkle_root,
        leaf_count: 30,
        mrv_timestamp: 1_700_000_000,
        methodology_hash: "0xMETH01".to_string(),
        jurisdiction: "IN".to_string(),
        market_scope: "Vcm".to_string(),
        valid_from: 1_700_000_000,
        valid_until: 1_730_000_000,
        initial_owner: tata_solar.pubkey(),
        vvb: vvb.pubkey(),
        vvb_sig: vvb.sign(&mint_msg),
    };
    state = apply(&state, &mint_event).expect("apply mint");
    let entry_2 = EventEntry::new(2, entries[1].hash.clone(), mint_event).expect("entry 2");
    entries.push(entry_2);

    // ── Seq 3: Transfer to Infosys ───────────────────────────────────────────
    let transfer_msg = build_transfer_preimage(
        &state.chain_id,
        "CC-IN-SOLAR-2026-001",
        0,
        &infosys.pubkey(),
    );
    let transfer_event = RegistryEvent::Transfer {
        credit_id: "CC-IN-SOLAR-2026-001".to_string(),
        op_index: 0,
        new_owner: infosys.pubkey(),
        owner_sig: tata_solar.sign(&transfer_msg),
    };
    state = apply(&state, &transfer_event).expect("apply transfer");
    let entry_3 = EventEntry::new(3, entries[2].hash.clone(), transfer_event).expect("entry 3");
    entries.push(entry_3);

    // ── Seq 4: Burn 200 credits ──────────────────────────────────────────────
    let burn_msg = build_burn_preimage(
        &state.chain_id,
        "CC-IN-SOLAR-2026-001",
        1,
        1_000_200,
        1_000_399,
        "Infosys Bangalore Campus Scope 2 Offset",
        ClaimType::CorporateNetZero.as_str(),
    );
    let burn_event = RegistryEvent::Burn {
        credit_id: "CC-IN-SOLAR-2026-001".to_string(),
        op_index: 1,
        range_start: 1_000_200,
        range_end: 1_000_399,
        beneficiary: "Infosys Bangalore Campus Scope 2 Offset".to_string(),
        claim_type: ClaimType::CorporateNetZero,
        owner_sig: infosys.sign(&burn_msg),
    };
    state = apply(&state, &burn_event).expect("apply burn");
    let entry_4 = EventEntry::new(4, entries[3].hash.clone(), burn_event).expect("entry 4");
    entries.push(entry_4);

    // Check invariants
    let report = state.check_invariants();
    assert!(report.all_passed, "all invariants must pass");
    println!("✓ 5 events generated, all 10 invariants satisfied!");

    // Render canonical lines
    let mut log_content = String::new();
    for e in &entries {
        log_content.push_str(&grey_misnomer_core::event_log::render_canonical_line(e));
        log_content.push('\n');
    }

    // Write to events.jsonl and docs/events.jsonl
    fs::write("events.jsonl", &log_content).expect("write events.jsonl");
    fs::write("docs/events.jsonl", &log_content).expect("write docs/events.jsonl");
    println!("✓ Written canonical events.jsonl and docs/events.jsonl");

    // Create signed Checkpoint at size 5
    let mut head_bytes = [0u8; 32];
    hex::decode_to_slice(&entries.last().unwrap().hash, &mut head_bytes).unwrap();
    let cp = Checkpoint::new(state.chain_id, 5, head_bytes, 1_700_000_000, &sequencer);
    let cp_json = format!("{}\n", cp.to_canonical_json());

    fs::create_dir_all("checkpoints").unwrap();
    fs::create_dir_all("docs/checkpoints").unwrap();
    fs::write("checkpoints/5.json", &cp_json).expect("write checkpoints/5.json");
    fs::write("docs/checkpoints/5.json", &cp_json).expect("write docs/checkpoints/5.json");
    println!("✓ Written signed checkpoints/5.json and docs/checkpoints/5.json");

    // Create canonical distribution manifest (RFC-006 §5.2)
    let manifest = grey_misnomer_core::manifest::Manifest {
        manifest_version: 1,
        chain_id: hex::encode(state.chain_id),
        log_size: entries.len() as u64,
        head_hash: entries.last().unwrap().hash.clone(),
        updated_at: "2026-10-19T08:24:11Z".to_string(),
        latest_checkpoint: grey_misnomer_core::manifest::ManifestCheckpoint {
            size: 5,
            path: "checkpoints/5.json".to_string(),
            signature: cp.sig.to_hex(),
        },
        mirrors: grey_misnomer_core::manifest::ManifestMirrors {
            git: "https://github.com/GreyMisnomer/GreyMisnomer".to_string(),
            github_pages: "https://greymisnomer.github.io/GreyMisnomer".to_string(),
            ipfs: grey_misnomer_core::manifest::ManifestIpfs {
                events_cid: Some("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi".to_string()),
                checkpoints_cid: Some("bafybeihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku".to_string()),
                gateways: grey_misnomer_core::manifest::Manifest::default_gateways(),
            },
            archive_org: grey_misnomer_core::manifest::ManifestArchiveOrg {
                snapshot_url: Some("https://web.archive.org/web/20261019082411/https://greymisnomer.github.io/GreyMisnomer/events.jsonl".to_string()),
            },
        },
    };
    let manifest_json = format!("{}\n", manifest.to_json_pretty().unwrap());
    fs::write("manifest.json", &manifest_json).expect("write manifest.json");
    fs::write("docs/manifest.json", &manifest_json).expect("write docs/manifest.json");
    println!("✓ Written canonical distribution manifest.json and docs/manifest.json");

    // Write checkpoint manifest for backward compatibility
    let cp_manifest = serde_json::json!({
        "checkpoints": [
            {
                "size": 5,
                "file": "checkpoints/5.json",
                "head_hash": entries.last().unwrap().hash,
                "timestamp": 1_700_000_000,
                "sequencer": sequencer.pubkey().to_hex(),
            }
        ]
    });
    fs::write(
        "docs/checkpoints/manifest.json",
        serde_json::to_string_pretty(&cp_manifest).unwrap(),
    )
    .unwrap();
    println!("✓ Written docs/checkpoints/manifest.json");

    println!("All done!");
}
