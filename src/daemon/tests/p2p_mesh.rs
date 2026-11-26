//! src/daemon/tests/p2p_mesh.rs
//! RFC-008 & Task 4.30: 3-Node P2P Wire Mesh, Invariant Rejection & Anti-Spam Integration Tests.
//!
//! Verifies:
//! 1. 3-node P2P wire mesh startup, mutual handshakes, and peer discovery.
//! 2. Transaction intent propagation and mempool synchronization across the mesh.
//! 3. Active socket invariant rejection: double-spend conflict detection.
//! 4. Peer reputation scoring, automated penalization, and banning.
//! 5. Structural anti-spam enforcement: fanout limit (<= 16 outputs) and JS-safe micro-unit caps.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::sleep;

use grey_misnomer_core::auth::{Keypair, Signature};
use grey_misnomer_core::uco::{MAX_TX_OUTPUTS, MAX_UCO_MICRO_UNITS};
use grey_misnomer_core::uco_engine::{
    UcoMintTx, UcoSplitTransferTx, UcoState, UcoTransaction, UcoTransferOutputSpec,
};
use greymisnomerd::mempool::{Mempool, MempoolError};
use greymisnomerd::p2p::{P2pConfig, P2pMesh};

#[tokio::test]
async fn test_3_node_p2p_mesh_discovery_and_tx_gossip() {
    let chain_id = [0x99u8; 32];

    // Shared mock chainstate
    let vvb_key = Keypair::generate();
    let mut state = UcoState::new(chain_id);
    state
        .active_vvbs
        .insert(vvb_key.pubkey(), "VVB-P2P-Verified".to_string());
    let shared_store = Arc::new(state);

    // Setup 3 mempools
    let mp1 = Arc::new(Mutex::new(Mempool::new(0)));
    let mp2 = Arc::new(Mutex::new(Mempool::new(0)));
    let mp3 = Arc::new(Mutex::new(Mempool::new(0)));

    // Configure 3 nodes on ephemeral ports
    let cfg1 = P2pConfig {
        listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        node_id: "node-1-relay".to_string(),
        bootstrap_peers: Vec::new(),
        enable_relay: true,
    };
    let node1 = Arc::new(P2pMesh::new(
        cfg1,
        Arc::clone(&mp1),
        Arc::clone(&shared_store),
    ));
    let bound_addr1 = node1.clone().start().await.expect("start node 1");

    let cfg2 = P2pConfig {
        listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        node_id: "node-2-validator".to_string(),
        bootstrap_peers: vec![bound_addr1],
        enable_relay: false,
    };
    let node2 = Arc::new(P2pMesh::new(
        cfg2,
        Arc::clone(&mp2),
        Arc::clone(&shared_store),
    ));
    let _bound_addr2 = node2.clone().start().await.expect("start node 2");

    let cfg3 = P2pConfig {
        listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        node_id: "node-3-observer".to_string(),
        bootstrap_peers: vec![bound_addr1],
        enable_relay: false,
    };
    let node3 = Arc::new(P2pMesh::new(
        cfg3,
        Arc::clone(&mp3),
        Arc::clone(&shared_store),
    ));
    let _bound_addr3 = node3.clone().start().await.expect("start node 3");

    // Connect to Node 1
    let _ = node2.connect_to_peer(bound_addr1).await;
    let _ = node3.connect_to_peer(bound_addr1).await;

    // Allow connections and handshakes to establish
    sleep(Duration::from_millis(150)).await;

    // 1. Verify Node 1 has connected peers
    let n1_peers = node1.peer_count().await;
    assert!(
        n1_peers >= 1,
        "Node 1 should have connected peers, found {n1_peers}"
    );

    // 2. Broadcast a valid UcoMintTx from Node 2
    let owner_key = Keypair::generate();
    let mut mint_tx = UcoMintTx {
        project_id: "PROJ-P2P-TEST".to_string(),
        batch_id: "BATCH-2026-P2P".to_string(),
        vintage_year: 2026,
        micro_units: 1_000_000,
        initial_owner: owner_key.pubkey(),
        methodology_hash: [0xaa; 32],
        mrv_data_root: [0xbb; 32],
        mrv_blob_mirrors: vec!["ipfs://bafybeidqq".to_string()],
        challenge_window_epochs: 0,
        vvb_signatures: Vec::new(),
    };
    let preimage = mint_tx.signing_preimage(&chain_id);
    mint_tx
        .vvb_signatures
        .push((vvb_key.pubkey(), vvb_key.sign(&preimage)));

    let uco_tx = UcoTransaction::Mint(mint_tx);
    let broadcast_res = node2.broadcast_tx(&uco_tx).await;
    assert!(broadcast_res.is_ok());

    // Allow propagation across TCP mesh
    sleep(Duration::from_millis(150)).await;

    // 3. Verify Node 1 received the transaction into its mempool
    let mp1_len = mp1.lock().await.len();
    assert_eq!(
        mp1_len, 1,
        "Node 1 should have 1 pending transaction in mempool"
    );

    // Clean shutdown
    node1.shutdown();
    node2.shutdown();
    node3.shutdown();
}

#[tokio::test]
async fn test_p2p_active_conflict_rejection_and_peer_ban() {
    let chain_id = [0x88u8; 32];
    let mut mempool = Mempool::new(0);

    let vvb = Keypair::generate();
    let alice = Keypair::generate();
    let bob = Keypair::generate();
    let mallory = Keypair::generate();

    let mut store = UcoState::new(chain_id);
    store
        .active_vvbs
        .insert(vvb.pubkey(), "Certified".to_string());

    // Mint initial credits to Alice
    let mut initial_mint = UcoMintTx {
        project_id: "PROJ-BAN-TEST".to_string(),
        batch_id: "BATCH-001".to_string(),
        vintage_year: 2026,
        micro_units: 5_000_000,
        initial_owner: alice.pubkey(),
        methodology_hash: [0x11; 32],
        mrv_data_root: [0x22; 32],
        mrv_blob_mirrors: vec![],
        challenge_window_epochs: 0,
        vvb_signatures: Vec::new(),
    };
    let preimage = initial_mint.signing_preimage(&chain_id);
    initial_mint
        .vvb_signatures
        .push((vvb.pubkey(), vvb.sign(&preimage)));

    let delta = store
        .apply_in_place(&UcoTransaction::Mint(initial_mint))
        .expect("initial mint");
    let alice_op = delta.created_ucos[0].outpoint;

    // 1. Submit honest split-transfer from Alice to Bob
    let mut tx1 = UcoSplitTransferTx {
        inputs: vec![alice_op],
        outputs: vec![UcoTransferOutputSpec {
            owner: bob.pubkey(),
            start_micro_unit: 0,
            end_micro_unit: 5_000_000,
            micro_units: 5_000_000,
            locked_escrow_program: None,
        }],
        input_signatures: Vec::new(),
    };
    let split_preimage = tx1.signing_preimage(&chain_id, &[0]);
    tx1.input_signatures.push(alice.sign(&split_preimage));

    let honest_peer = "192.168.1.100:9483";
    let res1 = mempool.submit_tx(
        UcoTransaction::SplitTransfer(tx1),
        honest_peer,
        0,
        100,
        &store,
    );
    assert!(res1.is_ok());
    assert_eq!(mempool.len(), 1);
    assert!(mempool.peer_score(honest_peer) > 100);

    // 2. Mallory attempts double-spend with conflicting OutPoint
    let mut malicious_tx = UcoSplitTransferTx {
        inputs: vec![alice_op], // Same input!
        outputs: vec![UcoTransferOutputSpec {
            owner: mallory.pubkey(),
            start_micro_unit: 0,
            end_micro_unit: 5_000_000,
            micro_units: 5_000_000,
            locked_escrow_program: None,
        }],
        input_signatures: Vec::new(),
    };
    let mal_preimage = malicious_tx.signing_preimage(&chain_id, &[0]);
    malicious_tx
        .input_signatures
        .push(alice.sign(&mal_preimage));

    let mallory_peer = "10.0.0.66:9483";

    // First conflict attempt: should penalize 100 points
    let err = mempool
        .submit_tx(
            UcoTransaction::SplitTransfer(malicious_tx.clone()),
            mallory_peer,
            0,
            101,
            &store,
        )
        .unwrap_err();
    assert!(matches!(err, MempoolError::ConflictWithPendingTx { .. }));
    assert!(mempool.peer_score(mallory_peer) <= 0);

    // Second violation: Mallory is now banned
    mempool.penalize_peer(mallory_peer, 100);
    assert!(mempool.is_peer_banned(mallory_peer));

    // Subsequent transactions from banned peer are rejected immediately
    let banned_err = mempool
        .submit_tx(
            UcoTransaction::SplitTransfer(malicious_tx),
            mallory_peer,
            0,
            102,
            &store,
        )
        .unwrap_err();
    assert_eq!(
        banned_err,
        MempoolError::PeerBanned(mallory_peer.to_string())
    );
}

#[tokio::test]
async fn test_p2p_structural_anti_spam_invariants() {
    let chain_id = [0x77u8; 32];
    let store = UcoState::new(chain_id);
    let mut mempool = Mempool::new(0);

    let spammer = "spammer-node:9483";
    let owner = Keypair::generate();

    // 1. Fanout violation: > 16 outputs in split transfer
    let mut excess_outputs = Vec::new();
    for i in 0..17 {
        excess_outputs.push(UcoTransferOutputSpec {
            owner: owner.pubkey(),
            start_micro_unit: i * 100,
            end_micro_unit: (i + 1) * 100,
            micro_units: 100,
            locked_escrow_program: None,
        });
    }

    let fanout_tx = UcoTransaction::SplitTransfer(UcoSplitTransferTx {
        inputs: vec![grey_misnomer_core::uco::OutPoint::new([0x33; 32], 0)],
        outputs: excess_outputs,
        input_signatures: vec![Signature::default()],
    });

    let err = mempool
        .submit_tx(fanout_tx, spammer, 0, 100, &store)
        .unwrap_err();
    assert_eq!(
        err,
        MempoolError::FanoutLimitExceeded {
            count: 17,
            max: MAX_TX_OUTPUTS,
        }
    );

    // 2. Micro-units overflow beyond MAX_UCO_MICRO_UNITS
    let excessive_mint = UcoMintTx {
        project_id: "PROJ-SPAM".to_string(),
        batch_id: "BATCH-SPAM".to_string(),
        vintage_year: 2026,
        micro_units: MAX_UCO_MICRO_UNITS + 1,
        initial_owner: owner.pubkey(),
        methodology_hash: [0x55; 32],
        mrv_data_root: [0x66; 32],
        mrv_blob_mirrors: vec![],
        challenge_window_epochs: 0,
        vvb_signatures: vec![],
    };

    let err2 = mempool
        .submit_tx(
            UcoTransaction::Mint(excessive_mint),
            spammer,
            0,
            101,
            &store,
        )
        .unwrap_err();
    assert_eq!(err2, MempoolError::AmountExceedsMaxCap);
}

#[tokio::test]
async fn test_alice_bob_genesis_mint_transfer_catchup_and_reverse_burn_p2p() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use grey_misnomer_core::uco::PoOClaimType;
    use grey_misnomer_core::uco_engine::UcoBurnTx;
    use greymisnomerd::genesis::{apply_genesis_to_storage, generate_genesis_v2};
    use greymisnomerd::rpc::{build_router, AppState, ChainStatusResponse, TxSubmitResponse};
    use greymisnomerd::storage::ChainStorage;
    use http_body_util::BodyExt;
    use tokio::sync::broadcast;
    use tower::ServiceExt;

    let temp_root = std::env::temp_dir().join(format!("gm_alice_bob_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_root);
    let alice_db_path = temp_root.join("alice/chainstate.redb");
    let bob_db_path = temp_root.join("bob/chainstate.redb");
    std::fs::create_dir_all(alice_db_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(bob_db_path.parent().unwrap()).unwrap();

    // 1. Alice creates fresh CSPRNG v2 Genesis (she holds private keys; Bob only gets public genesis)
    let (genesis, keys) = generate_genesis_v2("AliceBobNet", None);
    let seq_kp = Arc::new(keys.sequencer.to_keypair().unwrap());
    let vvb_kp = keys.vvb.to_keypair().unwrap();
    let alice_kp = keys.alice.to_keypair().unwrap();
    let bob_kp = keys.bob.to_keypair().unwrap();

    // 2. Start Alice Node (Genesis Sequencer + Relay)
    let alice_storage = ChainStorage::open(&alice_db_path).unwrap();
    apply_genesis_to_storage(&alice_storage, &genesis).unwrap();
    let (alice_evt, _) = broadcast::channel(32);
    let alice_mp = Arc::new(Mutex::new(Mempool::new(0)));
    let alice_mesh = Arc::new(
        P2pMesh::new(
            P2pConfig {
                listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
                node_id: "alice-genesis".to_string(),
                bootstrap_peers: Vec::new(),
                enable_relay: true,
            },
            alice_mp,
            Arc::new(alice_storage.clone()),
        )
        .with_chain_sync(alice_storage.clone(), alice_evt.clone())
        .with_sequencer_key(Arc::clone(&seq_kp)),
    );
    let alice_p2p_addr = alice_mesh.clone().start().await.unwrap();

    let alice_app = build_router(
        AppState::new(alice_storage.clone(), alice_evt, true, None, 9482)
            .with_p2p_mesh(Arc::clone(&alice_mesh))
            .with_sequencer_key(Arc::clone(&seq_kp)),
    );

    // 3. Before Bob even joins, Alice mints 10 credits (10_000_000 micro-units) to Alice
    let mut mint = UcoMintTx {
        project_id: "SOLAR-RAJASTHAN-01".to_string(),
        batch_id: "BATCH-01".to_string(),
        vintage_year: 2026,
        micro_units: 10_000_000,
        initial_owner: alice_kp.pubkey(),
        methodology_hash: [0x11; 32],
        mrv_data_root: [0x22; 32],
        mrv_blob_mirrors: vec!["ipfs://mrv-alpha".to_string()],
        challenge_window_epochs: 0,
        vvb_signatures: Vec::new(),
    };
    let mint_pre = mint.signing_preimage(&genesis.chain_id);
    mint.vvb_signatures
        .push((vvb_kp.pubkey(), vvb_kp.sign(&mint_pre)));

    let resp = alice_app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/tx/submit")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&UcoTransaction::Mint(mint)).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let mint_res: TxSubmitResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(mint_res.status, "committed");
    assert_eq!(mint_res.tree_size, Some("1".to_string()));

    let mint_outpoint = grey_misnomer_core::uco::OutPoint::new(
        hex::decode(&mint_res.txid).unwrap().try_into().unwrap(),
        0,
    );

    // 4. Alice transfers 4 credits to Bob, leaving 6 change credits to Alice -> tree_size = 2
    let mut split = UcoSplitTransferTx {
        inputs: vec![mint_outpoint],
        outputs: vec![
            UcoTransferOutputSpec {
                owner: bob_kp.pubkey(),
                start_micro_unit: 0,
                end_micro_unit: 4_000_000,
                micro_units: 4_000_000,
                locked_escrow_program: None,
            },
            UcoTransferOutputSpec {
                owner: alice_kp.pubkey(),
                start_micro_unit: 4_000_000,
                end_micro_unit: 10_000_000,
                micro_units: 6_000_000,
                locked_escrow_program: None,
            },
        ],
        input_signatures: Vec::new(),
    };
    let split_pre = split.signing_preimage(&genesis.chain_id, &[0]);
    split.input_signatures.push(alice_kp.sign(&split_pre));

    let resp2 = alice_app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/tx/submit")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&UcoTransaction::SplitTransfer(split)).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);
    let body2 = resp2.into_body().collect().await.unwrap().to_bytes();
    let split_res: TxSubmitResponse = serde_json::from_slice(&body2).unwrap();
    assert_eq!(split_res.tree_size, Some("2".to_string()));
    let bob_outpoint = grey_misnomer_core::uco::OutPoint::new(
        hex::decode(&split_res.txid).unwrap().try_into().unwrap(),
        0,
    );

    // 5. NOW Bob initializes with ONLY public genesis_v2.json (no private sequencer/VVB keys!) and dials Alice
    let bob_storage = ChainStorage::open(&bob_db_path).unwrap();
    apply_genesis_to_storage(&bob_storage, &genesis).unwrap();
    let (bob_evt, _) = broadcast::channel(32);
    let bob_mp = Arc::new(Mutex::new(Mempool::new(0)));
    let bob_mesh = Arc::new(
        P2pMesh::new(
            P2pConfig {
                listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
                node_id: "bob-peer".to_string(),
                bootstrap_peers: vec![alice_p2p_addr],
                enable_relay: false,
            },
            bob_mp,
            Arc::new(bob_storage.clone()),
        )
        .with_chain_sync(bob_storage.clone(), bob_evt.clone()),
    );
    let _bob_p2p_addr = bob_mesh.clone().start().await.unwrap();
    let bob_app = build_router(
        AppState::new(bob_storage.clone(), bob_evt, false, None, 9582)
            .with_p2p_mesh(Arc::clone(&bob_mesh)),
    );

    // Wait for automatic P2P catch-up (PeerPing -> TileRequest -> TileResponse -> verify -> redb)
    let mut synced = false;
    for _ in 0..30 {
        if bob_storage.read_tx().unwrap().tree_size() == 2 {
            synced = true;
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    assert!(
        synced,
        "Bob failed to sync Alice's committed history over port 9483"
    );

    // Verify Bob independently holds both active UCOs and exact same checkpoint
    let bob_status_resp = bob_app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/chain/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bob_status: ChainStatusResponse = serde_json::from_slice(
        &bob_status_resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes(),
    )
    .unwrap();
    assert_eq!(bob_status.tree_size, "2");
    assert_eq!(bob_status.active_ucos_count, "2");

    // 6. Now Bob submits a Burn transaction of 1.5 credits (returning 2.5 change) to BOB's own localhost RPC!
    let mut burn = UcoBurnTx {
        input: bob_outpoint,
        start_micro_unit: 0,
        end_micro_unit: 1_500_000,
        micro_units: 1_500_000,
        beneficiary: "Bob Steel Carbon Retirement".to_string(),
        claim_type: PoOClaimType::Voluntary,
        owner_sig: Signature::default(),
        change_owner: Some(bob_kp.pubkey()),
    };
    let burn_pre = burn.signing_preimage(&genesis.chain_id, 0);
    burn.owner_sig = bob_kp.sign(&burn_pre);

    let bob_burn_resp = bob_app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/tx/submit")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&UcoTransaction::Burn(burn)).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bob_burn_resp.status(), StatusCode::OK);
    let bob_burn_res: TxSubmitResponse = serde_json::from_slice(
        &bob_burn_resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes(),
    )
    .unwrap();
    assert_eq!(bob_burn_res.status, "validated_pending");

    // Bob gossips TxIntent -> Alice auto-sequences -> Alice announces tree_size 3 -> Bob syncs!
    let mut both_at_3 = false;
    for _ in 0..40 {
        if alice_storage.read_tx().unwrap().tree_size() == 3
            && bob_storage.read_tx().unwrap().tree_size() == 3
        {
            both_at_3 = true;
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    assert!(
        both_at_3,
        "Alice and Bob did not converge to tree_size 3 after Bob's P2P Burn"
    );

    let a_rtx = alice_storage.read_tx().unwrap();
    let b_rtx = bob_storage.read_tx().unwrap();
    assert_eq!(a_rtx.poo_count(), 1);
    assert_eq!(b_rtx.poo_count(), 1);
    assert_eq!(
        a_rtx.get_latest_checkpoint().unwrap(),
        b_rtx.get_latest_checkpoint().unwrap()
    );

    alice_mesh.shutdown();
    bob_mesh.shutdown();
    let _ = std::fs::remove_dir_all(&temp_root);
}

#[tokio::test]
async fn test_nat_relay_star_topology_ledger_convergence() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use greymisnomerd::genesis::{apply_genesis_to_storage, generate_genesis_v2};
    use greymisnomerd::rpc::{build_router, AppState};
    use greymisnomerd::storage::ChainStorage;
    use tokio::sync::broadcast;
    use tower::ServiceExt;

    let temp_root = std::env::temp_dir().join(format!("gm_relay_star_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_root);

    let (genesis, keys) = generate_genesis_v2("RelayStarNet", None);
    let seq_kp = Arc::new(keys.sequencer.to_keypair().unwrap());
    let vvb_kp = keys.vvb.to_keypair().unwrap();
    let alice_kp = keys.alice.to_keypair().unwrap();

    let relay_db = temp_root.join("relay/chainstate.redb");
    let alice_db = temp_root.join("alice/chainstate.redb");
    let bob_db = temp_root.join("bob/chainstate.redb");
    std::fs::create_dir_all(relay_db.parent().unwrap()).unwrap();
    std::fs::create_dir_all(alice_db.parent().unwrap()).unwrap();
    std::fs::create_dir_all(bob_db.parent().unwrap()).unwrap();

    let relay_storage = ChainStorage::open(&relay_db).unwrap();
    let alice_storage = ChainStorage::open(&alice_db).unwrap();
    let bob_storage = ChainStorage::open(&bob_db).unwrap();
    apply_genesis_to_storage(&relay_storage, &genesis).unwrap();
    apply_genesis_to_storage(&alice_storage, &genesis).unwrap();
    apply_genesis_to_storage(&bob_storage, &genesis).unwrap();

    // 1. Public Relay (no private sequencer keys) opens port
    let (relay_evt, _) = broadcast::channel(32);
    let relay_mesh = Arc::new(
        P2pMesh::new(
            P2pConfig {
                listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
                node_id: "vps-relay".to_string(),
                bootstrap_peers: Vec::new(),
                enable_relay: true,
            },
            Arc::new(Mutex::new(Mempool::new(0))),
            Arc::new(relay_storage.clone()),
        )
        .with_chain_sync(relay_storage.clone(), relay_evt),
    );
    let relay_addr = relay_mesh.clone().start().await.unwrap();

    // 2. Both NATed Alice and NATed Bob connect outbound to Relay
    let (alice_evt, _) = broadcast::channel(32);
    let alice_mesh = Arc::new(
        P2pMesh::new(
            P2pConfig {
                listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
                node_id: "alice-nat".to_string(),
                bootstrap_peers: vec![relay_addr],
                enable_relay: false,
            },
            Arc::new(Mutex::new(Mempool::new(0))),
            Arc::new(alice_storage.clone()),
        )
        .with_chain_sync(alice_storage.clone(), alice_evt.clone())
        .with_sequencer_key(Arc::clone(&seq_kp)),
    );
    let _ = alice_mesh.clone().start().await.unwrap();

    let (bob_evt, _) = broadcast::channel(32);
    let bob_mesh = Arc::new(
        P2pMesh::new(
            P2pConfig {
                listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
                node_id: "bob-nat".to_string(),
                bootstrap_peers: vec![relay_addr],
                enable_relay: false,
            },
            Arc::new(Mutex::new(Mempool::new(0))),
            Arc::new(bob_storage.clone()),
        )
        .with_chain_sync(bob_storage.clone(), bob_evt),
    );
    let _ = bob_mesh.clone().start().await.unwrap();

    sleep(Duration::from_millis(150)).await;

    // 3. Alice mints via Alice's RPC -> pushes through Relay -> Bob receives & verifies!
    let alice_app = build_router(
        AppState::new(alice_storage.clone(), alice_evt, true, None, 9482)
            .with_p2p_mesh(Arc::clone(&alice_mesh))
            .with_sequencer_key(Arc::clone(&seq_kp)),
    );
    let mut mint = UcoMintTx {
        project_id: "SOLAR-NAT-01".to_string(),
        batch_id: "BATCH-NAT".to_string(),
        vintage_year: 2026,
        micro_units: 5_000_000,
        initial_owner: alice_kp.pubkey(),
        methodology_hash: [0x11; 32],
        mrv_data_root: [0x99; 32],
        mrv_blob_mirrors: vec!["ipfs://nat-mrv".to_string()],
        challenge_window_epochs: 0,
        vvb_signatures: Vec::new(),
    };
    let pre = mint.signing_preimage(&genesis.chain_id);
    mint.vvb_signatures
        .push((vvb_kp.pubkey(), vvb_kp.sign(&pre)));

    let resp = alice_app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/tx/submit")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&UcoTransaction::Mint(mint)).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let mut converged = false;
    for _ in 0..40 {
        if relay_storage.read_tx().unwrap().tree_size() == 1
            && bob_storage.read_tx().unwrap().tree_size() == 1
        {
            converged = true;
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    assert!(
        converged,
        "Relay star topology failed to converge Alice -> Relay -> Bob"
    );

    relay_mesh.shutdown();
    alice_mesh.shutdown();
    bob_mesh.shutdown();
    let _ = std::fs::remove_dir_all(&temp_root);
}
