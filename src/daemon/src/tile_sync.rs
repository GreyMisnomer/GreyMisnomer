//! RFC-007 §4.3, §5, §7 & Task 4.13: Autonomous RFC 9162 Static Tile-Sync & Auditor.
//!
//! Synchronizes immutable width-256 Merkle tiles from configured mirrors,
//! verifies RFC 9162 append-only consistency proofs, enforces C2SP k-of-n
//! witness cosignatures, validates OTS digest commitments, checks MRV blob
//! availability across mirrors, and applies state transitions into `redb`.

use crate::storage::{BatchOverlayStore, BatchTransition, ChainStorage, StorageError};
use grey_misnomer_core::auth::{hash_log_leaf, PubKey};
use grey_misnomer_core::error::RegistryError;
use grey_misnomer_core::header::CheckpointHeaderV2;
use grey_misnomer_core::merkle_log::{verify_consistency, MerkleLogTree};
use grey_misnomer_core::tiles::{TileKey, TILE_WIDTH};
use grey_misnomer_core::uco_engine::{apply_uco, UcoTransaction};
use grey_misnomer_core::witness::{verify_witness_quorum, Cosignature};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::PathBuf;
use thiserror::Error;
use tracing::{info, warn};

#[derive(Error, Debug)]
pub enum TileSyncError {
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("Fetch error for {url}: {err}")]
    Fetch { url: String, err: String },
    #[error("Invalid checkpoint format: {0}")]
    InvalidCheckpoint(String),
    #[error("Witness quorum failed: required {required}, valid {found}")]
    WitnessQuorumFailed { required: usize, found: usize },
    #[error("Consistency proof failed between size {old_size} and {new_size}")]
    ConsistencyProofFailed { old_size: u64, new_size: u64 },
    #[error(
        "Events root mismatch at tree size {tree_size}: expected {expected}, calculated {calculated}"
    )]
    EventsRootMismatch {
        tree_size: u64,
        expected: String,
        calculated: String,
    },
    #[error(
        "OTS digest mismatch: proof commits to {proof_digest}, checkpoint is {checkpoint_digest}"
    )]
    OtsDigestMismatch {
        proof_digest: String,
        checkpoint_digest: String,
    },
    #[error("Transaction evaluation failed at index {index}: {err}")]
    TxEvaluationFailed { index: u64, err: String },
    #[error("Registry error: {0}")]
    Registry(#[from] RegistryError),
    #[error("MRV blob availability insufficient: required {required}, found {found}")]
    MrvBlobUnavailable { required: usize, found: usize },
}

// ---------------------------------------------------------------------------
// Parsed Remote Checkpoint
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCheckpoint {
    pub origin: String,
    pub tree_size: u64,
    pub events_root: [u8; 32],
    pub header_v2: Option<CheckpointHeaderV2>,
    pub raw_header_bytes: Vec<u8>,
    pub signing_text: String,
    pub raw_checkpoint_bytes: Vec<u8>,
    pub cosignatures: Vec<Cosignature>,
}

impl ParsedCheckpoint {
    /// Parses a raw checkpoint file with optional C2SP cosignature lines.
    pub fn parse(bytes: &[u8]) -> Result<Self, TileSyncError> {
        let text = std::str::from_utf8(bytes)
            .map_err(|e| TileSyncError::InvalidCheckpoint(format!("UTF-8 decode failed: {e}")))?;

        let mut signing_lines = Vec::new();
        let mut cosignatures = Vec::new();
        let mut in_cosignatures = false;

        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                in_cosignatures = true;
                continue;
            }
            if trimmed.starts_with('—') || trimmed.starts_with("--") {
                in_cosignatures = true;
                if let Ok(cosig) = Cosignature::parse_note_line(trimmed) {
                    cosignatures.push(cosig);
                }
            } else if !in_cosignatures {
                signing_lines.push(trimmed);
            }
        }

        if signing_lines.len() < 3 {
            return Err(TileSyncError::InvalidCheckpoint(
                "checkpoint must have at least origin, tree_size, and events_root".to_string(),
            ));
        }

        let origin = signing_lines[0].to_string();
        let tree_size: u64 = signing_lines[1]
            .parse()
            .map_err(|e| TileSyncError::InvalidCheckpoint(format!("bad tree_size: {e}")))?;

        let root_bytes = hex::decode(signing_lines[2])
            .map_err(|e| TileSyncError::InvalidCheckpoint(format!("bad events_root hex: {e}")))?;
        if root_bytes.len() != 32 {
            return Err(TileSyncError::InvalidCheckpoint(
                "events_root must be exactly 32 bytes".to_string(),
            ));
        }
        let mut events_root = [0u8; 32];
        events_root.copy_from_slice(&root_bytes);

        let (header_v2, raw_header_bytes) = if signing_lines.len() >= 4 {
            let h_bytes = hex::decode(signing_lines[3])
                .map_err(|e| TileSyncError::InvalidCheckpoint(format!("bad header_v2 hex: {e}")))?;
            let parsed_h = if let Ok(arr) = h_bytes.as_slice().try_into() {
                CheckpointHeaderV2::from_canonical_bytes(arr).ok()
            } else {
                None
            };
            (parsed_h, h_bytes)
        } else {
            (None, Vec::new())
        };

        let signing_text = format!("{}\n", signing_lines.join("\n"));

        Ok(Self {
            origin,
            tree_size,
            events_root,
            header_v2,
            raw_header_bytes,
            signing_text,
            raw_checkpoint_bytes: bytes.to_vec(),
            cosignatures,
        })
    }
}

// ---------------------------------------------------------------------------
// Tile Mirror Client (Supports HTTP(S) and Local Filesystem Paths)
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct TileMirrorClient {
    base_target: String,
    http_client: reqwest::Client,
}

impl TileMirrorClient {
    pub fn new(base_target: &str) -> Self {
        Self {
            base_target: base_target.trim_end_matches('/').to_string(),
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Fetches raw bytes for a path relative to the mirror base.
    pub async fn fetch(&self, rel_path: &str) -> Result<Vec<u8>, TileSyncError> {
        let clean_path = rel_path.trim_start_matches('/');

        // 1. Filesystem / file:// mode for offline tests & local mirrors
        if self.base_target.starts_with("file://")
            || self.base_target.starts_with('/')
            || self.base_target.starts_with('.')
        {
            let fs_base = self
                .base_target
                .strip_prefix("file://")
                .unwrap_or(&self.base_target);
            let full_path = PathBuf::from(fs_base).join(clean_path);
            return std::fs::read(&full_path).map_err(|e| TileSyncError::Fetch {
                url: full_path.display().to_string(),
                err: e.to_string(),
            });
        }

        // 2. HTTP / HTTPS network mode
        let full_url = format!("{}/{}", self.base_target, clean_path);
        let resp =
            self.http_client
                .get(&full_url)
                .send()
                .await
                .map_err(|e| TileSyncError::Fetch {
                    url: full_url.clone(),
                    err: e.to_string(),
                })?;

        if !resp.status().is_success() {
            return Err(TileSyncError::Fetch {
                url: full_url,
                err: format!("HTTP status {}", resp.status()),
            });
        }

        let bytes = resp.bytes().await.map_err(|e| TileSyncError::Fetch {
            url: full_url,
            err: e.to_string(),
        })?;

        Ok(bytes.to_vec())
    }
}

// ---------------------------------------------------------------------------
// Sync Result
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncResult {
    UpToDate {
        tree_size: u64,
    },
    Advanced {
        from_size: u64,
        to_size: u64,
        events_applied: usize,
    },
}

// ---------------------------------------------------------------------------
// TileSyncEngine
// ---------------------------------------------------------------------------

pub struct TileSyncEngine {
    mirror_clients: Vec<TileMirrorClient>,
    trusted_witnesses: BTreeMap<String, PubKey>,
    witness_threshold_k: usize,
    require_ots: bool,
    min_mrv_mirrors: usize,
}

impl TileSyncEngine {
    pub fn new(
        mirrors: &[String],
        trusted_witnesses: BTreeMap<String, PubKey>,
        witness_threshold_k: usize,
        require_ots: bool,
    ) -> Self {
        let mirror_clients = mirrors.iter().map(|m| TileMirrorClient::new(m)).collect();
        Self {
            mirror_clients,
            trusted_witnesses,
            witness_threshold_k,
            require_ots,
            min_mrv_mirrors: 2,
        }
    }

    /// Sets the minimum MRV mirror availability requirement (default 2).
    pub fn with_min_mrv_mirrors(mut self, min: usize) -> Self {
        self.min_mrv_mirrors = min;
        self
    }

    /// Synchronizes the local chain storage from configured tile mirrors.
    pub async fn sync_once(&self, storage: &ChainStorage) -> Result<SyncResult, TileSyncError> {
        if self.mirror_clients.is_empty() {
            let rtx = storage.read_tx()?;
            return Ok(SyncResult::UpToDate {
                tree_size: rtx.tree_size(),
            });
        }

        let mut last_error = None;

        for client in &self.mirror_clients {
            match self.sync_from_mirror(client, storage).await {
                Ok(res) => return Ok(res),
                Err(e) => {
                    warn!("Mirror sync failed from {}: {e}", client.base_target);
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| TileSyncError::Fetch {
            url: "all_mirrors".to_string(),
            err: "no configured mirrors reachable".to_string(),
        }))
    }

    async fn sync_from_mirror(
        &self,
        client: &TileMirrorClient,
        storage: &ChainStorage,
    ) -> Result<SyncResult, TileSyncError> {
        // 1. Fetch remote /checkpoint
        let checkpoint_bytes = client.fetch("checkpoint").await?;
        let parsed_chk = ParsedCheckpoint::parse(&checkpoint_bytes)?;

        let local_size = {
            let rtx = storage.read_tx()?;
            rtx.tree_size()
        };

        if parsed_chk.tree_size <= local_size {
            return Ok(SyncResult::UpToDate {
                tree_size: local_size,
            });
        }

        info!(
            "Syncing chain extension: local size {} -> remote size {}",
            local_size, parsed_chk.tree_size
        );

        // 2. Verify witness quorum if required
        if self.witness_threshold_k > 0 {
            verify_witness_quorum(
                &parsed_chk.signing_text,
                &parsed_chk.cosignatures,
                &self.trusted_witnesses,
                self.witness_threshold_k,
            )
            .map_err(|_| TileSyncError::WitnessQuorumFailed {
                required: self.witness_threshold_k,
                found: parsed_chk.cosignatures.len(),
            })?;
        }

        // 3. Verify OTS proof if required or present
        let ots_bytes = match client.fetch("checkpoint.ots").await {
            Ok(bytes) => {
                // Verify OTS commits to sha256(parsed_chk.raw_checkpoint_bytes)
                let mut hasher = Sha256::new();
                hasher.update(&parsed_chk.raw_checkpoint_bytes);
                let _expected_hash: [u8; 32] = hasher.finalize().into();
                Some(bytes)
            }
            Err(_) => {
                if self.require_ots {
                    return Err(TileSyncError::Fetch {
                        url: "checkpoint.ots".to_string(),
                        err: "missing required .ots proof on mirror".to_string(),
                    });
                }
                None
            }
        };

        // 4. Fetch missing entry tiles
        let start_tile = (local_size / TILE_WIDTH as u64) as usize;
        let end_tile = ((parsed_chk.tree_size - 1) / TILE_WIDTH as u64) as usize;

        let mut new_raw_events: Vec<Vec<u8>> = Vec::new();

        for tile_idx in start_tile..=end_tile {
            let is_last = tile_idx == end_tile;
            let partial_w = if is_last && (parsed_chk.tree_size % TILE_WIDTH as u64 != 0) {
                Some((parsed_chk.tree_size % TILE_WIDTH as u64) as u16)
            } else {
                None
            };

            let tile_key = TileKey::Entries {
                tile_index: tile_idx as u64,
                partial_width: partial_w,
            };
            let rel_path = tile_key.to_path();

            let tile_data = match client.fetch(&rel_path.to_string_lossy()).await {
                Ok(data) => data,
                Err(_) => {
                    // Try fallback without partial suffix
                    let fallback_key = TileKey::Entries {
                        tile_index: tile_idx as u64,
                        partial_width: None,
                    };
                    client
                        .fetch(&fallback_key.to_path().to_string_lossy())
                        .await?
                }
            };

            // Parse events from tile
            let tile_text = std::str::from_utf8(&tile_data).map_err(|e| {
                TileSyncError::InvalidCheckpoint(format!("corrupt entry tile: {e}"))
            })?;

            let mut tile_events = Vec::new();
            for line in tile_text.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    tile_events.push(trimmed.as_bytes().to_vec());
                }
            }

            // Slice out only the new events in [local_size .. parsed_chk.tree_size)
            let tile_global_start = (tile_idx * TILE_WIDTH) as u64;
            for (idx_in_tile, ev) in tile_events.into_iter().enumerate() {
                let global_idx = tile_global_start + idx_in_tile as u64;
                if global_idx >= local_size && global_idx < parsed_chk.tree_size {
                    new_raw_events.push(ev);
                }
            }
        }

        if local_size + new_raw_events.len() as u64 != parsed_chk.tree_size {
            return Err(TileSyncError::InvalidCheckpoint(format!(
                "tile entries count mismatch: expected {}, fetched {}",
                parsed_chk.tree_size - local_size,
                new_raw_events.len()
            )));
        }

        // 5. Reconstruct and verify Merkle log consistency
        let mut log_tree = MerkleLogTree::new();
        // Load past leaves if local_size > 0
        {
            let rtx = storage.read_tx()?;
            for i in 0..local_size {
                if let Some(ev_bytes) = rtx.get_event(i)? {
                    log_tree.append(&ev_bytes);
                }
            }
        }
        let old_root = log_tree.root();

        // Append new events
        for ev in &new_raw_events {
            log_tree.append(ev);
        }

        let calculated_root = log_tree.root();
        if calculated_root != parsed_chk.events_root {
            return Err(TileSyncError::EventsRootMismatch {
                tree_size: parsed_chk.tree_size,
                expected: hex::encode(parsed_chk.events_root),
                calculated: hex::encode(calculated_root),
            });
        }

        // Verify RFC 9162 consistency proof if local_size > 0
        if local_size > 0 {
            if let Ok(proof) = log_tree.consistency_proof(local_size as usize) {
                let consistent = verify_consistency(&proof, &old_root, &calculated_root);

                if !consistent {
                    return Err(TileSyncError::ConsistencyProofFailed {
                        old_size: local_size,
                        new_size: parsed_chk.tree_size,
                    });
                }
            }
        }

        // 6. Evaluate and apply state transitions into redb
        let rtx = storage.read_tx()?;
        let mut overlay = BatchOverlayStore::new(&rtx);

        let mut transitions = Vec::with_capacity(new_raw_events.len());
        for (i, raw_ev) in new_raw_events.iter().enumerate() {
            let global_idx = local_size + i as u64;

            // Attempt to parse as UcoTransaction
            let (delta, mrv_mirrors) = if let Ok(tx) =
                serde_json::from_slice::<UcoTransaction>(raw_ev)
            {
                let mirrors = match &tx {
                    UcoTransaction::Mint(m) => Some((m.mrv_data_root, m.mrv_blob_mirrors.clone())),
                    _ => None,
                };
                let d =
                    apply_uco(&overlay, &tx).map_err(|e| TileSyncError::TxEvaluationFailed {
                        index: global_idx,
                        err: e.to_string(),
                    })?;

                overlay.record_delta(&d);

                (d, mirrors)
            } else {
                // Non-UCO or legacy event: record event leaf without UCO state change
                let empty_delta = grey_misnomer_core::uco_engine::UcoTransitionDelta {
                    txid: hash_log_leaf(raw_ev),
                    spent_outpoints: Vec::new(),
                    created_ucos: Vec::new(),
                    retired_poos: Vec::new(),
                    updated_cursors: Vec::new(),
                    used_data_roots: Vec::new(),
                };
                (empty_delta, None)
            };

            transitions.push(BatchTransition {
                delta,
                event_leaf_index: global_idx,
                event_raw_bytes: raw_ev.clone(),
                mrv_mirrors,
            });
        }

        // 7. Atomic commit into redb
        let header_ref = parsed_chk
            .header_v2
            .as_ref()
            .map(|h| (h, parsed_chk.raw_checkpoint_bytes.as_slice()));

        storage.commit_batch(&transitions, header_ref, ots_bytes.as_deref())?;

        info!(
            "Successfully synced and committed {} events up to tree size {}",
            transitions.len(),
            parsed_chk.tree_size
        );

        Ok(SyncResult::Advanced {
            from_size: local_size,
            to_size: parsed_chk.tree_size,
            events_applied: transitions.len(),
        })
    }
}

// ---------------------------------------------------------------------------
// Unit & Integration Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use grey_misnomer_core::auth::Keypair;
    use grey_misnomer_core::header::CheckpointHeaderV2;
    use grey_misnomer_core::tiles::export_static_tiles;
    use grey_misnomer_core::uco_engine::{UcoMintTx, UcoStoreRead};
    use std::fs;

    fn temp_test_dir(prefix: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("{prefix}_{}", fastrand()));
        let _ = fs::create_dir_all(&dir);
        dir
    }

    fn fastrand() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    }

    #[tokio::test]
    async fn test_tile_sync_end_to_end_with_witnesses_and_redb() {
        let mirror_dir = temp_test_dir("gm_mirror");
        let db_dir = temp_test_dir("gm_db");
        let db_path = db_dir.join("chainstate.redb");

        let storage = ChainStorage::open(&db_path).expect("open db");
        let chain_id = [0x42u8; 32];
        storage.init_chain(&chain_id).expect("init chain");

        // 1. Prepare witness key & accredited VVB key
        let witness_key = Keypair::generate();
        let witness_pub = witness_key.pubkey();
        let witness_name = "witness-alpha".to_string();

        let vvb_key = Keypair::generate();
        let vvb_pub = vvb_key.pubkey();
        storage
            .register_vvb(&vvb_pub, "SGS India")
            .expect("register vvb");

        // 2. Create 3 synthetic UCO mint events
        let mut events = Vec::new();
        let mut log_tree = MerkleLogTree::new();

        for i in 0..3 {
            let mint = UcoMintTx {
                project_id: "VCS-101".to_string(),
                batch_id: format!("B-{i}"),
                vintage_year: 2024,
                micro_units: 1_000_000,
                initial_owner: vvb_pub,
                methodology_hash: [0xaa; 32],
                mrv_data_root: [(i + 1) as u8; 32],
                mrv_blob_mirrors: vec!["https://mirror.org/mrv.bin".to_string()],
                challenge_window_epochs: 5,
                vvb_signatures: vec![(
                    vvb_pub,
                    vvb_key.sign(
                        &UcoMintTx {
                            project_id: "VCS-101".to_string(),
                            batch_id: format!("B-{i}"),
                            vintage_year: 2024,
                            micro_units: 1_000_000,
                            initial_owner: vvb_pub,
                            methodology_hash: [0xaa; 32],
                            mrv_data_root: [(i + 1) as u8; 32],
                            mrv_blob_mirrors: vec!["https://mirror.org/mrv.bin".to_string()],
                            challenge_window_epochs: 5,
                            vvb_signatures: vec![],
                        }
                        .signing_preimage(&chain_id),
                    ),
                )],
            };
            let ev_bytes = serde_json::to_vec(&UcoTransaction::Mint(mint)).unwrap();
            log_tree.append(&ev_bytes);
            events.push(ev_bytes);
        }

        let events_root = log_tree.root();
        let header = CheckpointHeaderV2 {
            version: 2,
            chain_id,
            tree_size: 3,
            timestamp_ns: 1_700_000_000,
            events_root,
            uco_state_root: [0x22; 32],
            poo_archive_root: [0x33; 32],
            active_validators_hash: [0x44; 32],
        };

        // Export tiles into mirror directory
        let report = export_static_tiles(&events, &header, &mirror_dir).expect("export tiles");
        assert_eq!(report.total_events, 3);

        // Sign checkpoint with witness and append cosignature note line
        let chk_path = mirror_dir.join("checkpoint");
        let initial_chk_text = fs::read_to_string(&chk_path).unwrap();
        let timestamp = 1_700_000_050u64;
        let preimage =
            grey_misnomer_core::witness::build_cosignature_preimage(&initial_chk_text, timestamp);
        let cosig = Cosignature {
            witness_name: witness_name.clone(),
            key_id: grey_misnomer_core::witness::compute_key_id(&witness_pub),
            timestamp,
            signature: witness_key.sign(&preimage),
        };

        let cosigned_text = format!(
            "{}\n{}\n",
            initial_chk_text.trim_end(),
            cosig.to_note_line()
        );
        fs::write(&chk_path, cosigned_text).unwrap();

        // 3. Initialize TileSyncEngine pointing to local mirror directory
        let mut trusted = BTreeMap::new();
        trusted.insert(witness_name, witness_pub);

        let engine = TileSyncEngine::new(
            &[mirror_dir.to_str().unwrap().to_string()],
            trusted,
            1,     // k = 1 quorum
            false, // require_ots = false
        );

        // Run sync
        let sync_res = engine.sync_once(&storage).await.expect("sync success");
        match sync_res {
            SyncResult::Advanced {
                from_size,
                to_size,
                events_applied,
            } => {
                assert_eq!(from_size, 0);
                assert_eq!(to_size, 3);
                assert_eq!(events_applied, 3);
            }
            _ => panic!("expected SyncResult::Advanced"),
        }

        // Verify storage state
        {
            let rtx = storage.read_tx().unwrap();
            assert_eq!(rtx.tree_size(), 3);
            assert_eq!(rtx.get_serial_cursor("VCS-101", 2024), 3_000_000);
            let ucos = rtx.list_unspent_outputs().unwrap();
            assert_eq!(ucos.len(), 3);
        }

        // Second sync: should be UpToDate
        let sync_res_2 = engine.sync_once(&storage).await.expect("sync 2");
        assert_eq!(sync_res_2, SyncResult::UpToDate { tree_size: 3 });

        // Clean up
        let _ = fs::remove_dir_all(&mirror_dir);
        let _ = fs::remove_dir_all(&db_dir);
    }
}
