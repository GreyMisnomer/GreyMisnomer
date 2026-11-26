//! RFC-008 §9 & Stage 4.6: Shared Transaction Sequencing, Verification & Sync Commit Engine.
//!
//! Eliminates code duplication between localhost RPC transaction commits (`rpc.rs`)
//! and P2P network block/tile synchronization (`p2p.rs`), ensuring both paths enforce:
//! 1. Exact cumulative RFC 9162 `MerkleLogTree` roots (`events_root`) and consistency proofs.
//! 2. Real active-UCO (`uco_state_root`) and retired-PoO (`poo_archive_root`) SPV roots.
//! 3. Strict Ed25519 sequencer signatures (`CheckpointHeaderV2::verify_sequencer_sig`).
//! 4. Pure `apply_uco()` validation across all transitions before atomic `redb` commits.

use crate::storage::{
    BatchOverlayStore, BatchTransition, ChainStorage, StorageError, StorageReadTx,
};
use grey_misnomer_core::auth::{enc_pubkey, enc_str, Keypair, Signature};
use grey_misnomer_core::error::RegistryError;
use grey_misnomer_core::header::CheckpointHeaderV2;
use grey_misnomer_core::merkle_log::{verify_consistency, MerkleLogTree};
use grey_misnomer_core::spv::{compute_poo_archive_root, compute_uco_state_root};
use grey_misnomer_core::uco::{OutPoint, ProofOfOffsetCommitment, UnretiredCreditOutput};
use grey_misnomer_core::uco_engine::{apply_uco, UcoStoreRead, UcoTransaction};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::broadcast;

#[derive(Debug, Error)]
pub enum ChainCommitError {
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("Protocol rule violation: {0}")]
    Registry(#[from] RegistryError),
    #[error("JSON codec error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Chain ID mismatch: expected {expected}, found {found}")]
    ChainIdMismatch { expected: String, found: String },
    #[error("Unauthorized or missing sequencer signature: {0}")]
    UnauthorizedSequencer(String),
    #[error("Invalid checkpoint or root commitment: {0}")]
    InvalidCheckpoint(String),
    #[error("Append-only consistency proof failed between tree sizes {old_size} -> {new_size}")]
    ConsistencyFailed { old_size: u64, new_size: u64 },
}

/// Computes `active_validators_hash` deterministically over the sequencer + accredited VVBs.
pub fn compute_active_validators_hash(rtx: &StorageReadTx) -> Result<[u8; 32], StorageError> {
    let mut preimage = Vec::new();
    enc_str("GM-v2-VALIDATORS:", &mut preimage);
    if let Some(seq) = rtx.get_sequencer_pubkey() {
        enc_pubkey(&seq, &mut preimage);
    }
    let mut vvbs = rtx.list_vvbs()?;
    vvbs.sort_by_key(|a| a.0);
    for (pk, label) in vvbs {
        enc_pubkey(&pk, &mut preimage);
        enc_str(&label, &mut preimage);
    }
    Ok(*blake3::hash(&preimage).as_bytes())
}

pub struct ComputedRoots {
    pub old_events_root: [u8; 32],
    pub new_events_root: [u8; 32],
    pub uco_state_root: [u8; 32],
    pub poo_archive_root: [u8; 32],
    pub log_tree: MerkleLogTree,
}

/// Computes cumulative `(events_root, uco_state_root, poo_archive_root)` and builds `old_log_root`.
pub fn compute_roots_for_batch(
    rtx: &StorageReadTx,
    transitions: &[BatchTransition],
) -> Result<ComputedRoots, ChainCommitError> {
    let local_size = rtx.tree_size();
    let mut log_tree = MerkleLogTree::new();
    for i in 0..local_size {
        let ev = rtx.get_event(i)?.ok_or_else(|| {
            StorageError::Corrupted(format!("missing historical event at index {i}"))
        })?;
        log_tree.append(&ev);
    }
    let old_events_root = log_tree.root();

    for bt in transitions {
        log_tree.append(&bt.event_raw_bytes);
    }
    let new_events_root = log_tree.root();

    // Compute resulting unspent UCO map sorted by OutPoint
    let mut uco_map: BTreeMap<OutPoint, UnretiredCreditOutput> = BTreeMap::new();
    for uco in rtx.list_unspent_outputs()? {
        uco_map.insert(uco.outpoint, uco);
    }
    // Compute resulting cumulative PoO archive
    let poo_count = rtx.poo_count();
    let mut poo_vec: Vec<ProofOfOffsetCommitment> = Vec::with_capacity(poo_count as usize);
    for idx in 0..poo_count {
        if let Some(p) = rtx.get_poo(idx)? {
            poo_vec.push(p);
        }
    }

    for bt in transitions {
        for spent in &bt.delta.spent_outpoints {
            uco_map.remove(spent);
        }
        for created in &bt.delta.created_ucos {
            uco_map.insert(created.outpoint, created.clone());
        }
        for retired in &bt.delta.retired_poos {
            poo_vec.push(retired.clone());
        }
    }

    let uco_state_root = compute_uco_state_root(&uco_map);
    let poo_archive_root = compute_poo_archive_root(&poo_vec);

    Ok(ComputedRoots {
        old_events_root,
        new_events_root,
        uco_state_root,
        poo_archive_root,
        log_tree,
    })
}

/// Formats the canonical 4-line v2 checkpoint note string matching `ParsedCheckpoint::parse`.
pub fn format_checkpoint_note(header: &CheckpointHeaderV2) -> String {
    format!(
        "greymisnomer/v2\n{}\n{}\n{}\n",
        header.tree_size,
        hex::encode(header.events_root),
        hex::encode(header.to_canonical_bytes())
    )
}

/// Parses a `CheckpointHeaderV2` from line 4 (index 3) of a canonical checkpoint note.
pub fn parse_header_from_checkpoint_note(
    note_bytes: &[u8],
) -> Result<CheckpointHeaderV2, ChainCommitError> {
    let text = std::str::from_utf8(note_bytes)
        .map_err(|e| ChainCommitError::InvalidCheckpoint(format!("UTF-8 error: {e}")))?;
    let hex_line = text
        .lines()
        .nth(3)
        .ok_or_else(|| ChainCommitError::InvalidCheckpoint("missing header line 4".to_string()))?
        .trim();
    let raw = hex::decode(hex_line)
        .map_err(|e| ChainCommitError::InvalidCheckpoint(format!("bad header hex: {e}")))?;
    let arr: &[u8; CheckpointHeaderV2::BYTE_SIZE] = raw.as_slice().try_into().map_err(|_| {
        ChainCommitError::InvalidCheckpoint("unexpected header binary length".to_string())
    })?;
    CheckpointHeaderV2::from_canonical_bytes(arr)
        .map_err(|e| ChainCommitError::InvalidCheckpoint(e.to_string()))
}

/// Evaluates, sequences, commits, and optionally signs a single `UcoTransaction` atomically.
pub fn sequence_and_commit_tx(
    storage: &ChainStorage,
    event_tx: &broadcast::Sender<String>,
    tx: &UcoTransaction,
    sequencer_kp: Option<&Keypair>,
) -> Result<([u8; 32], CheckpointHeaderV2, Option<Signature>), ChainCommitError> {
    let rtx = storage.read_tx()?;
    let current_size = rtx.tree_size();
    let delta = apply_uco(&rtx, tx)?;
    let txid = delta.txid;

    let ev_raw = serde_json::to_vec(tx)?;
    let mirrors = match tx {
        UcoTransaction::Mint(m) => Some((m.mrv_data_root, m.mrv_blob_mirrors.clone())),
        _ => None,
    };

    let bt = BatchTransition {
        delta,
        event_leaf_index: current_size,
        event_raw_bytes: ev_raw,
        mrv_mirrors: mirrors,
    };

    let roots = compute_roots_for_batch(&rtx, std::slice::from_ref(&bt))?;
    let active_validators_hash = compute_active_validators_hash(&rtx)?;

    let new_size = current_size + 1;
    let timestamp_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;

    let header = CheckpointHeaderV2 {
        version: 2,
        chain_id: rtx.chain_id(),
        tree_size: new_size,
        timestamp_ns,
        events_root: roots.new_events_root,
        uco_state_root: roots.uco_state_root,
        poo_archive_root: roots.poo_archive_root,
        active_validators_hash,
    };

    let note = format_checkpoint_note(&header);
    let sig = sequencer_kp.map(|kp| kp.sign(&header.signing_hash()));

    drop(rtx);

    storage.commit_batch_with_sig(&[bt], Some((&header, note.as_bytes())), None, sig.as_ref())?;

    let broadcast_msg = serde_json::json!({
        "event": "tx_committed",
        "txid": hex::encode(txid),
        "tree_size": new_size.to_string(),
    })
    .to_string();
    let _ = event_tx.send(broadcast_msg);

    Ok((txid, header, sig))
}

/// Validates and atomically commits a synced event batch received over P2P `TileResponse`.
pub fn apply_verified_p2p_sync(
    storage: &ChainStorage,
    event_tx: &broadcast::Sender<String>,
    from_index: u64,
    events: &[Vec<u8>],
    header: &CheckpointHeaderV2,
    sequencer_sig: &Signature,
) -> Result<(u64, Vec<[u8; 32]>), ChainCommitError> {
    let rtx = storage.read_tx()?;
    let expected_chain = rtx.chain_id();
    if header.chain_id != expected_chain {
        return Err(ChainCommitError::ChainIdMismatch {
            expected: hex::encode(expected_chain),
            found: hex::encode(header.chain_id),
        });
    }

    let sequencer_pub = rtx.get_sequencer_pubkey().ok_or_else(|| {
        ChainCommitError::UnauthorizedSequencer(
            "no sequencer public key registered in genesis chainstate".to_string(),
        )
    })?;

    header
        .verify_sequencer_sig(&sequencer_pub, sequencer_sig)
        .map_err(|e| {
            ChainCommitError::UnauthorizedSequencer(format!(
                "invalid checkpoint sequencer signature: {e}"
            ))
        })?;

    let local_size = rtx.tree_size();
    if header.tree_size <= local_size {
        return Ok((local_size, Vec::new()));
    }

    let end_index = from_index
        .checked_add(events.len() as u64)
        .ok_or_else(|| ChainCommitError::InvalidCheckpoint("event window overflow".to_string()))?;
    if from_index > local_size || end_index != header.tree_size {
        return Err(ChainCommitError::InvalidCheckpoint(format!(
            "batch window [{from_index}, {end_index}) does not align with local size {local_size} -> header {}",
            header.tree_size
        )));
    }

    let offset = (local_size - from_index) as usize;
    let new_raw_events = &events[offset..];

    let mut overlay = BatchOverlayStore::new(&rtx);
    let mut transitions = Vec::with_capacity(new_raw_events.len());
    let mut committed_txids = Vec::with_capacity(new_raw_events.len());

    for (i, raw_ev) in new_raw_events.iter().enumerate() {
        let global_idx = local_size + i as u64;
        let tx: UcoTransaction = serde_json::from_slice(raw_ev)?;
        let mirrors = match &tx {
            UcoTransaction::Mint(m) => Some((m.mrv_data_root, m.mrv_blob_mirrors.clone())),
            _ => None,
        };
        let delta = apply_uco(&overlay, &tx)?;
        committed_txids.push(delta.txid);
        overlay.record_delta(&delta);

        transitions.push(BatchTransition {
            delta,
            event_leaf_index: global_idx,
            event_raw_bytes: raw_ev.clone(),
            mrv_mirrors: mirrors,
        });
    }

    let roots = compute_roots_for_batch(&rtx, &transitions)?;

    if roots.new_events_root != header.events_root {
        return Err(ChainCommitError::InvalidCheckpoint(format!(
            "events_root mismatch: expected {}, computed {}",
            hex::encode(header.events_root),
            hex::encode(roots.new_events_root)
        )));
    }

    if local_size > 0 {
        let proof = roots
            .log_tree
            .consistency_proof(local_size as usize)
            .map_err(|_| ChainCommitError::ConsistencyFailed {
                old_size: local_size,
                new_size: header.tree_size,
            })?;
        if !verify_consistency(&proof, &roots.old_events_root, &roots.new_events_root) {
            return Err(ChainCommitError::ConsistencyFailed {
                old_size: local_size,
                new_size: header.tree_size,
            });
        }
    }

    if roots.uco_state_root != header.uco_state_root {
        return Err(ChainCommitError::InvalidCheckpoint(format!(
            "uco_state_root mismatch: expected {}, computed {}",
            hex::encode(header.uco_state_root),
            hex::encode(roots.uco_state_root)
        )));
    }

    if roots.poo_archive_root != header.poo_archive_root {
        return Err(ChainCommitError::InvalidCheckpoint(format!(
            "poo_archive_root mismatch: expected {}, computed {}",
            hex::encode(header.poo_archive_root),
            hex::encode(roots.poo_archive_root)
        )));
    }

    let note = format_checkpoint_note(header);
    drop(rtx);

    storage.commit_batch_with_sig(
        &transitions,
        Some((header, note.as_bytes())),
        None,
        Some(sequencer_sig),
    )?;

    for txid in &committed_txids {
        let broadcast_msg = serde_json::json!({
            "event": "tx_committed",
            "txid": hex::encode(txid),
            "tree_size": header.tree_size.to_string(),
        })
        .to_string();
        let _ = event_tx.send(broadcast_msg);
    }

    Ok((header.tree_size, committed_txids))
}
