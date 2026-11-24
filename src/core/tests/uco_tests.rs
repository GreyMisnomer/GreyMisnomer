//! RFC-007 Exhaustive Integration Test Suite:
//! Hybrid UCO State Machine, Monotonic Allocation, Disjoint Partition Splits,
//! Challenge Windows, Escrow Locks, Buffer Pool Revocation, and v1->v2 Migration.

use grey_misnomer_core::auth::{Keypair, Signature};
use grey_misnomer_core::credit::CreditBatch;
use grey_misnomer_core::error::RegistryError;
use grey_misnomer_core::migrate::migrate_v1_to_v2;
use grey_misnomer_core::oracle::{apply_revoke_with_buffer, BufferPool, RevokeWithBufferTx};
use grey_misnomer_core::registry::{RegistryState, VvbInfo};
use grey_misnomer_core::serial::SerialRange;
use grey_misnomer_core::uco::{OutPoint, PoOClaimType, MAX_TX_OUTPUTS, MAX_UCO_MICRO_UNITS};
use grey_misnomer_core::uco_engine::{
    apply_uco, UcoBurnTx, UcoMintTx, UcoSplitTransferTx, UcoState, UcoTransaction,
    UcoTransferOutputSpec,
};

fn setup_fixture() -> (UcoState, Keypair, Keypair, Keypair) {
    let chain_id = [0x77u8; 32];
    let mut state = UcoState::new(chain_id);
    let vvb = Keypair::generate();
    let alice = Keypair::generate();
    let bob = Keypair::generate();

    state
        .active_vvbs
        .insert(vvb.pubkey(), "TUV-Nord-Certified".to_string());

    (state, vvb, alice, bob)
}

#[test]
fn test_e2e_uco_mint_split_and_burn_lifecycle() {
    let (mut state, vvb, alice, bob) = setup_fixture();

    // 1. Mint 2,000,000 micro-units (2 credits) to Alice with 5 epoch challenge window
    let mut mint_tx = UcoMintTx {
        project_id: "SOLAR-RAJASTHAN-01".to_string(),
        batch_id: "BATCH-2026-001".to_string(),
        vintage_year: 2026,
        micro_units: 2_000_000,
        initial_owner: alice.pubkey(),
        methodology_hash: [0xAA; 32],
        mrv_data_root: [0xBB; 32],
        mrv_blob_mirrors: vec!["ipfs://bafy...".to_string()],
        challenge_window_epochs: 5,
        vvb_signatures: Vec::new(),
    };
    let mint_preimage = mint_tx.signing_preimage(&state.chain_id);
    mint_tx
        .vvb_signatures
        .push((vvb.pubkey(), vvb.sign(&mint_preimage)));

    let mint_delta = state
        .apply_in_place(&UcoTransaction::Mint(mint_tx))
        .unwrap();
    assert_eq!(mint_delta.created_ucos.len(), 1);
    let alice_uco_op = mint_delta.created_ucos[0].outpoint;
    assert_eq!(mint_delta.created_ucos[0].start_micro_unit, 0);
    assert_eq!(mint_delta.created_ucos[0].end_micro_unit, 2_000_000);

    // 2. Alice splits [0, 2_000_000) into:
    //    - 800,000 units to Bob: [0, 800_000)
    //    - 1,200,000 units back to Alice: [800_000, 2_000_000)
    let mut split_tx = UcoSplitTransferTx {
        inputs: vec![alice_uco_op],
        outputs: vec![
            UcoTransferOutputSpec {
                owner: bob.pubkey(),
                start_micro_unit: 0,
                end_micro_unit: 800_000,
                micro_units: 800_000,
                locked_escrow_program: None,
            },
            UcoTransferOutputSpec {
                owner: alice.pubkey(),
                start_micro_unit: 800_000,
                end_micro_unit: 2_000_000,
                micro_units: 1_200_000,
                locked_escrow_program: None,
            },
        ],
        input_signatures: Vec::new(),
    };
    let split_preimage = split_tx.signing_preimage(&state.chain_id, &[0]);
    split_tx.input_signatures.push(alice.sign(&split_preimage));

    let split_delta = state
        .apply_in_place(&UcoTransaction::SplitTransfer(split_tx))
        .unwrap();
    assert_eq!(split_delta.created_ucos.len(), 2);
    let bob_uco_op = split_delta.created_ucos[0].outpoint;
    let alice_change_op = split_delta.created_ucos[1].outpoint;

    // 3. Bob attempts to retire immediately at epoch 0 -> FAILS due to challenge window (ends at epoch 5)
    let mut burn_tx = UcoBurnTx {
        input: bob_uco_op,
        start_micro_unit: 0,
        end_micro_unit: 800_000,
        micro_units: 800_000,
        beneficiary: "Bob Logistics ESG".to_string(),
        claim_type: PoOClaimType::Voluntary,
        owner_sig: Signature::default(),
        change_owner: None,
    };
    let burn_preimage = burn_tx.signing_preimage(&state.chain_id, 0);
    burn_tx.owner_sig = bob.sign(&burn_preimage);

    let err = state
        .apply_in_place(&UcoTransaction::Burn(burn_tx.clone()))
        .unwrap_err();
    assert!(matches!(err, RegistryError::ChallengeWindowActive { .. }));

    // 4. Advance epoch past challenge window
    state.current_epoch = 6;

    // Bob burns successfully
    let burn_delta = state
        .apply_in_place(&UcoTransaction::Burn(burn_tx))
        .unwrap();
    assert_eq!(burn_delta.retired_poos.len(), 1);
    assert_eq!(burn_delta.retired_poos[0].micro_units, 800_000);
    assert_eq!(burn_delta.retired_poos[0].beneficiary, "Bob Logistics ESG");

    // Alice still holds her 1,200,000 unspent units
    assert!(state.unspent_outputs.contains_key(&alice_change_op));
    assert_eq!(
        state
            .unspent_outputs
            .get(&alice_change_op)
            .unwrap()
            .micro_units,
        1_200_000
    );
    assert_eq!(state.poo_archive.len(), 1);
}

#[test]
fn test_uco_partition_split_conservation_multi_input() {
    let (mut state, vvb, alice, bob) = setup_fixture();

    // Mint a 1,000,000 unit batch for Alice: [0, 1_000_000)
    let mut mint = UcoMintTx {
        project_id: "WIND-01".to_string(),
        batch_id: "BATCH-WIND-A".to_string(),
        vintage_year: 2026,
        micro_units: 1_000_000,
        initial_owner: alice.pubkey(),
        methodology_hash: [0x11; 32],
        mrv_data_root: [0x22; 32],
        mrv_blob_mirrors: vec![],
        challenge_window_epochs: 0,
        vvb_signatures: Vec::new(),
    };
    let p1 = mint.signing_preimage(&state.chain_id);
    mint.vvb_signatures.push((vvb.pubkey(), vvb.sign(&p1)));
    let delta_mint = state.apply_in_place(&UcoTransaction::Mint(mint)).unwrap();
    let initial_op = delta_mint.created_ucos[0].outpoint;

    // First split [0, 1_000_000) into two inputs: [0, 500_000) and [500_000, 1_000_000)
    let mut initial_split = UcoSplitTransferTx {
        inputs: vec![initial_op],
        outputs: vec![
            UcoTransferOutputSpec {
                owner: alice.pubkey(),
                start_micro_unit: 0,
                end_micro_unit: 500_000,
                micro_units: 500_000,
                locked_escrow_program: None,
            },
            UcoTransferOutputSpec {
                owner: alice.pubkey(),
                start_micro_unit: 500_000,
                end_micro_unit: 1_000_000,
                micro_units: 500_000,
                locked_escrow_program: None,
            },
        ],
        input_signatures: Vec::new(),
    };
    let p_init = initial_split.signing_preimage(&state.chain_id, &[0]);
    initial_split.input_signatures.push(alice.sign(&p_init));
    let delta_init = state
        .apply_in_place(&UcoTransaction::SplitTransfer(initial_split))
        .unwrap();
    let op1 = delta_init.created_ucos[0].outpoint;
    let op2 = delta_init.created_ucos[1].outpoint;

    // Now combine both inputs [0, 500_000) and [500_000, 1_000_000)
    // and split into 3 outputs: [0, 300_000), [300_000, 700_000), [700_000, 1_000_000)
    let mut merge_split_tx = UcoSplitTransferTx {
        inputs: vec![op1, op2],
        outputs: vec![
            UcoTransferOutputSpec {
                owner: bob.pubkey(),
                start_micro_unit: 0,
                end_micro_unit: 300_000,
                micro_units: 300_000,
                locked_escrow_program: None,
            },
            UcoTransferOutputSpec {
                owner: bob.pubkey(),
                start_micro_unit: 300_000,
                end_micro_unit: 700_000,
                micro_units: 400_000,
                locked_escrow_program: None,
            },
            UcoTransferOutputSpec {
                owner: alice.pubkey(),
                start_micro_unit: 700_000,
                end_micro_unit: 1_000_000,
                micro_units: 300_000,
                locked_escrow_program: None,
            },
        ],
        input_signatures: Vec::new(),
    };

    let preimage = merge_split_tx.signing_preimage(&state.chain_id, &[0, 0]);
    merge_split_tx.input_signatures.push(alice.sign(&preimage));
    merge_split_tx.input_signatures.push(alice.sign(&preimage));

    let split_delta = state
        .apply_in_place(&UcoTransaction::SplitTransfer(merge_split_tx))
        .unwrap();

    assert_eq!(split_delta.created_ucos.len(), 3);
    assert_eq!(state.unspent_outputs.len(), 3);
    let total_unspent: u64 = state.unspent_outputs.values().map(|u| u.micro_units).sum();
    assert_eq!(total_unspent, 1_000_000);
}

#[test]
fn test_escrow_lock_blocks_retirement() {
    let (mut state, vvb, alice, _bob) = setup_fixture();

    let mut mint = UcoMintTx {
        project_id: "P-ESCROW".to_string(),
        batch_id: "B-ESCROW-1".to_string(),
        vintage_year: 2026,
        micro_units: 1_000_000,
        initial_owner: alice.pubkey(),
        methodology_hash: [0x11; 32],
        mrv_data_root: [0x44; 32],
        mrv_blob_mirrors: vec![],
        challenge_window_epochs: 0,
        vvb_signatures: Vec::new(),
    };
    let p = mint.signing_preimage(&state.chain_id);
    mint.vvb_signatures.push((vvb.pubkey(), vvb.sign(&p)));
    let delta = state.apply_in_place(&UcoTransaction::Mint(mint)).unwrap();
    let op = delta.created_ucos[0].outpoint;

    // Split and lock output under a Tier-2 statutory program
    let mut lock_tx = UcoSplitTransferTx {
        inputs: vec![op],
        outputs: vec![UcoTransferOutputSpec {
            owner: alice.pubkey(),
            start_micro_unit: 0,
            end_micro_unit: 1_000_000,
            micro_units: 1_000_000,
            locked_escrow_program: Some("CCTS-Statutory-Compliance-2026".to_string()),
        }],
        input_signatures: Vec::new(),
    };
    let lock_p = lock_tx.signing_preimage(&state.chain_id, &[0]);
    lock_tx.input_signatures.push(alice.sign(&lock_p));

    let locked_delta = state
        .apply_in_place(&UcoTransaction::SplitTransfer(lock_tx))
        .unwrap();
    let locked_op = locked_delta.created_ucos[0].outpoint;

    // Attempt to burn locked UCO -> must fail with EscrowLocked
    let mut burn_tx = UcoBurnTx {
        input: locked_op,
        start_micro_unit: 0,
        end_micro_unit: 1_000_000,
        micro_units: 1_000_000,
        beneficiary: "Attempted Escrow Burn".to_string(),
        claim_type: PoOClaimType::Compliance,
        owner_sig: Signature::default(),
        change_owner: None,
    };
    let burn_p = burn_tx.signing_preimage(&state.chain_id, 0);
    burn_tx.owner_sig = alice.sign(&burn_p);

    let err = state
        .apply_in_place(&UcoTransaction::Burn(burn_tx))
        .unwrap_err();
    assert!(matches!(err, RegistryError::EscrowLocked { .. }));
}

#[test]
fn test_migrate_v1_to_v2_and_execute_v2_transactions() {
    let authority = Keypair::generate();
    let sequencer = Keypair::generate();
    let vvb = Keypair::generate();
    let alice = Keypair::generate();
    let bob = Keypair::generate();

    let mut v1 = RegistryState::default();
    v1.chain_id = [0x55; 32];
    v1.authority = authority.pubkey();
    v1.sequencer = sequencer.pubkey();
    v1.vvbs.insert(
        vvb.pubkey(),
        VvbInfo {
            label: "VVB-ALPHA".to_string(),
            active: true,
        },
    );

    // Mint 500 credits in v1 (500,000,000 micro-units)
    let batch = CreditBatch::new(
        "PROJ-HYDRO".to_string(),
        "CC-HYDRO-2026".to_string(),
        SerialRange::new(1, 500).unwrap(),
        alice.pubkey(),
        vvb.pubkey(),
        [0x99; 32],
    );
    v1.credits.push(batch);

    // Convert to v2
    let mut v2 = migrate_v1_to_v2(&v1, 2026).unwrap();

    assert_eq!(v2.unspent_outputs.len(), 1);
    let (migrated_op, migrated_uco) = v2.unspent_outputs.iter().next().unwrap();
    let migrated_op = *migrated_op;
    assert_eq!(migrated_uco.micro_units, 500_000_000);

    // Now execute a native v2 SplitTransfer on top of the migrated state!
    let mut transfer_tx = UcoSplitTransferTx {
        inputs: vec![migrated_op],
        outputs: vec![
            UcoTransferOutputSpec {
                owner: bob.pubkey(),
                start_micro_unit: 0,
                end_micro_unit: 200_000_000,
                micro_units: 200_000_000,
                locked_escrow_program: None,
            },
            UcoTransferOutputSpec {
                owner: alice.pubkey(),
                start_micro_unit: 200_000_000,
                end_micro_unit: 500_000_000,
                micro_units: 300_000_000,
                locked_escrow_program: None,
            },
        ],
        input_signatures: Vec::new(),
    };
    let p = transfer_tx.signing_preimage(&v2.chain_id, &[0]);
    transfer_tx.input_signatures.push(alice.sign(&p));

    let delta = v2
        .apply_in_place(&UcoTransaction::SplitTransfer(transfer_tx))
        .unwrap();

    assert_eq!(delta.created_ucos.len(), 2);
    assert_eq!(v2.unspent_outputs.len(), 2);
    assert!(!v2.unspent_outputs.contains_key(&migrated_op));
}

#[test]
fn test_buffer_pool_fraud_revocation_e2e() {
    let authority = Keypair::generate();
    let (mut state, vvb, alice, _bob) = setup_fixture();

    let mut mint = UcoMintTx {
        project_id: "PROJ-REVOKE".to_string(),
        batch_id: "BATCH-REVOKE-1".to_string(),
        vintage_year: 2026,
        micro_units: 1_000_000,
        initial_owner: alice.pubkey(),
        methodology_hash: [0x11; 32],
        mrv_data_root: [0x55; 32],
        mrv_blob_mirrors: vec![],
        challenge_window_epochs: 0,
        vvb_signatures: Vec::new(),
    };
    let p = mint.signing_preimage(&state.chain_id);
    mint.vvb_signatures.push((vvb.pubkey(), vvb.sign(&p)));
    let delta = state.apply_in_place(&UcoTransaction::Mint(mint)).unwrap();
    let op = delta.created_ucos[0].outpoint;

    let mut pool = BufferPool::new();
    pool.deposit("PROJ-REVOKE", 500_000).unwrap();

    // Revoke the batch
    let mut revoke_tx = RevokeWithBufferTx {
        batch_id: "BATCH-REVOKE-1".to_string(),
        project_id: "PROJ-REVOKE".to_string(),
        authority_index: 1,
        batch_total_units: 1_000_000,
        authority_sig: Signature::default(),
    };
    let rp = revoke_tx.signing_preimage(&state.chain_id);
    revoke_tx.authority_sig = authority.sign(&rp);

    let (canceled, shortfall) = apply_revoke_with_buffer(
        &mut state.unspent_outputs,
        &mut pool,
        &revoke_tx,
        &authority.pubkey(),
        &state.chain_id,
    )
    .unwrap();

    assert_eq!(canceled, vec![op]);
    assert_eq!(shortfall, 0); // All 1,000,000 were active so no shortfall
    assert!(!state.unspent_outputs.contains_key(&op));
}

#[test]
fn test_js_safe_max_and_fanout_caps() {
    let (state, _vvb, alice, _bob) = setup_fixture();

    // Test fanout > MAX_TX_OUTPUTS
    let dummy_op = OutPoint::new([0x99; 32], 0);
    let too_many_outputs: Vec<UcoTransferOutputSpec> = (0..MAX_TX_OUTPUTS + 1)
        .map(|i| UcoTransferOutputSpec {
            owner: alice.pubkey(),
            start_micro_unit: i as u64 * 10,
            end_micro_unit: (i as u64 + 1) * 10,
            micro_units: 10,
            locked_escrow_program: None,
        })
        .collect();

    let tx = UcoSplitTransferTx {
        inputs: vec![dummy_op],
        outputs: too_many_outputs,
        input_signatures: vec![Signature::default()],
    };

    let err = apply_uco(&state, &UcoTransaction::SplitTransfer(tx)).unwrap_err();
    assert!(matches!(err, RegistryError::OutputFanoutExceeded { .. }));

    // Test micro_units > MAX_UCO_MICRO_UNITS
    let mut bad_mint = UcoMintTx {
        project_id: "P-OVERFLOW".to_string(),
        batch_id: "B-OVERFLOW".to_string(),
        vintage_year: 2026,
        micro_units: MAX_UCO_MICRO_UNITS + 1,
        initial_owner: alice.pubkey(),
        methodology_hash: [0; 32],
        mrv_data_root: [0; 32],
        mrv_blob_mirrors: vec![],
        challenge_window_epochs: 0,
        vvb_signatures: vec![],
    };
    bad_mint.micro_units = MAX_UCO_MICRO_UNITS + 1;
    let err_mint = apply_uco(&state, &UcoTransaction::Mint(bad_mint)).unwrap_err();
    assert!(matches!(err_mint, RegistryError::ExceedsJsSafeMax { .. }));
}
