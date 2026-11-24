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
