//! RFC-007 §7 & Task 4.12: Embedded `redb` ACID Chainstate Storage Engine.
//!
//! Provides copy-on-write persistent KV storage implementing `UcoStoreRead`
//! and indexing live UCOs, serial cursors, events, checkpoints, and proofs
//! with sub-millisecond O(1) lookups and crash-safe atomic commits.

use grey_misnomer_core::auth::PubKey;
use grey_misnomer_core::header::CheckpointHeaderV2;
use grey_misnomer_core::uco::{OutPoint, ProofOfOffsetCommitment, UnretiredCreditOutput};
use grey_misnomer_core::uco_engine::{UcoStoreRead, UcoTransitionDelta};
use redb::{Database, ReadableTable, TableDefinition};
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Database error: {0}")]
    Database(#[from] Box<redb::DatabaseError>),
    #[error("Table error: {0}")]
    Table(#[from] Box<redb::TableError>),
    #[error("Transaction error: {0}")]
    Transaction(#[from] Box<redb::TransactionError>),
    #[error("Storage error: {0}")]
    Storage(#[from] Box<redb::StorageError>),
    #[error("Commit error: {0}")]
    Commit(#[from] Box<redb::CommitError>),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Chain ID mismatch: expected {expected}, found {found}")]
    ChainIdMismatch { expected: String, found: String },
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Storage corrupted: {0}")]
    Corrupted(String),
}

impl From<redb::DatabaseError> for StorageError {
    fn from(e: redb::DatabaseError) -> Self {
        Self::Database(Box::new(e))
    }
}

impl From<redb::TableError> for StorageError {
    fn from(e: redb::TableError) -> Self {
        Self::Table(Box::new(e))
    }
}

impl From<redb::TransactionError> for StorageError {
    fn from(e: redb::TransactionError) -> Self {
        Self::Transaction(Box::new(e))
    }
}

impl From<redb::StorageError> for StorageError {
    fn from(e: redb::StorageError) -> Self {
        Self::Storage(Box::new(e))
    }
}

impl From<redb::CommitError> for StorageError {
    fn from(e: redb::CommitError) -> Self {
        Self::Commit(Box::new(e))
    }
}

// ---------------------------------------------------------------------------
// Table Definitions
// ---------------------------------------------------------------------------

pub const TABLE_UNSPENT_OUTPUTS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("unspent_outputs");
pub const TABLE_SERIAL_CURSORS: TableDefinition<&str, u64> = TableDefinition::new("serial_cursors");
pub const TABLE_HISTORICAL_EVENTS: TableDefinition<u64, &[u8]> =
    TableDefinition::new("historical_events");
pub const TABLE_CHECKPOINTS: TableDefinition<u64, &[u8]> = TableDefinition::new("checkpoints");
pub const TABLE_OTS_PROOFS: TableDefinition<u64, &[u8]> = TableDefinition::new("ots_proofs");
pub const TABLE_POO_ARCHIVE: TableDefinition<u64, &[u8]> = TableDefinition::new("poo_archive");
pub const TABLE_USED_DATA_ROOTS: TableDefinition<&[u8], u8> =
    TableDefinition::new("used_data_roots");
pub const TABLE_VVBS: TableDefinition<&[u8], &str> = TableDefinition::new("vvbs");
pub const TABLE_BUFFER_POOL: TableDefinition<&str, u64> = TableDefinition::new("buffer_pool");
pub const TABLE_MRV_MIRRORS: TableDefinition<&[u8], &str> = TableDefinition::new("mrv_mirrors");
pub const TABLE_META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");

// ---------------------------------------------------------------------------
// ChainStorage Handle
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct ChainStorage {
    db: Arc<Database>,
}

impl ChainStorage {
    /// Opens or creates a `redb` database at the specified path and initializes all tables.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let db = Database::create(path)?;
        let storage = Self { db: Arc::new(db) };
        storage.init_tables()?;
        Ok(storage)
    }

    /// Initializes all tables if they do not exist.
    fn init_tables(&self) -> Result<(), StorageError> {
        let write_txn = self.db.begin_write()?;
        {
            let _ = write_txn.open_table(TABLE_UNSPENT_OUTPUTS)?;
            let _ = write_txn.open_table(TABLE_SERIAL_CURSORS)?;
            let _ = write_txn.open_table(TABLE_HISTORICAL_EVENTS)?;
            let _ = write_txn.open_table(TABLE_CHECKPOINTS)?;
            let _ = write_txn.open_table(TABLE_OTS_PROOFS)?;
            let _ = write_txn.open_table(TABLE_POO_ARCHIVE)?;
            let _ = write_txn.open_table(TABLE_USED_DATA_ROOTS)?;
            let _ = write_txn.open_table(TABLE_VVBS)?;
            let _ = write_txn.open_table(TABLE_BUFFER_POOL)?;
            let _ = write_txn.open_table(TABLE_MRV_MIRRORS)?;
            let _ = write_txn.open_table(TABLE_META)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Initializes chain metadata if not already set, verifying chain_id consistency.
    pub fn init_chain(&self, chain_id: &[u8; 32]) -> Result<(), StorageError> {
        let write_txn = self.db.begin_write()?;
        {
            let existing = {
                let meta = write_txn.open_table(TABLE_META)?;
                let res = meta.get("chain_id")?.map(|g| g.value().to_vec());
                res
            };
            let mut meta = write_txn.open_table(TABLE_META)?;
            if let Some(bytes) = existing {
                if bytes.as_slice() != chain_id {
                    return Err(StorageError::ChainIdMismatch {
                        expected: hex::encode(chain_id),
                        found: hex::encode(bytes),
                    });
                }
            } else {
                meta.insert("chain_id", &chain_id[..])?;
                meta.insert("current_epoch", &0u64.to_be_bytes()[..])?;
                meta.insert("tree_size", &0u64.to_be_bytes()[..])?;
                meta.insert("poo_count", &0u64.to_be_bytes()[..])?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Registers an accredited VVB public key.
    pub fn register_vvb(&self, pubkey: &PubKey, name: &str) -> Result<(), StorageError> {
        let write_txn = self.db.begin_write()?;
        {
            let mut vvbs = write_txn.open_table(TABLE_VVBS)?;
            vvbs.insert(&pubkey.as_bytes()[..], name)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Revokes an accredited VVB public key.
    pub fn revoke_vvb(&self, pubkey: &PubKey) -> Result<(), StorageError> {
        let write_txn = self.db.begin_write()?;
        {
            let mut vvbs = write_txn.open_table(TABLE_VVBS)?;
            vvbs.remove(&pubkey.as_bytes()[..])?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Sets or updates the collateral balance for a buffer pool category.
    pub fn set_buffer_pool_balance(&self, category: &str, amount: u64) -> Result<(), StorageError> {
        let write_txn = self.db.begin_write()?;
        {
            let mut pool = write_txn.open_table(TABLE_BUFFER_POOL)?;
            pool.insert(category, amount)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Advances the current protocol epoch.
    pub fn set_current_epoch(&self, epoch: u64) -> Result<(), StorageError> {
        let write_txn = self.db.begin_write()?;
        {
            let mut meta = write_txn.open_table(TABLE_META)?;
            meta.insert("current_epoch", &epoch.to_be_bytes()[..])?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Begins a read transaction implementing `UcoStoreRead`.
    pub fn read_tx(&self) -> Result<StorageReadTx, StorageError> {
        let read_txn = self.db.begin_read()?;
        let meta_table = read_txn.open_table(TABLE_META)?;
        let chain_id = if let Some(guard) = meta_table.get("chain_id")? {
            let bytes = guard.value();
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(bytes);
                arr
            } else {
                [0u8; 32]
            }
        } else {
            [0u8; 32]
        };
        let current_epoch = if let Some(guard) = meta_table.get("current_epoch")? {
            let bytes = guard.value();
            if bytes.len() == 8 {
                u64::from_be_bytes(bytes.try_into().unwrap_or_default())
            } else {
                0
            }
        } else {
            0
        };
        Ok(StorageReadTx {
            read_txn,
            chain_id,
            current_epoch,
        })
    }

    /// Commits a batch of transitions, new event logs, and an optional checkpoint/proof in a single atomic ACID transaction.
    pub fn commit_batch(
        &self,
        transitions: &[BatchTransition],
        new_checkpoint: Option<(&CheckpointHeaderV2, &[u8])>,
        ots_proof: Option<&[u8]>,
    ) -> Result<(), StorageError> {
        let write_txn = self.db.begin_write()?;
        {
            let mut uco_table = write_txn.open_table(TABLE_UNSPENT_OUTPUTS)?;
            let mut cursor_table = write_txn.open_table(TABLE_SERIAL_CURSORS)?;
            let mut events_table = write_txn.open_table(TABLE_HISTORICAL_EVENTS)?;
            let mut chk_table = write_txn.open_table(TABLE_CHECKPOINTS)?;
            let mut ots_table = write_txn.open_table(TABLE_OTS_PROOFS)?;
            let mut poo_table = write_txn.open_table(TABLE_POO_ARCHIVE)?;
            let mut used_roots = write_txn.open_table(TABLE_USED_DATA_ROOTS)?;
            let mut mirrors_table = write_txn.open_table(TABLE_MRV_MIRRORS)?;

            // 1. Get current poo counter and tree_size
            let (mut poo_count, mut latest_tree_size) = {
                let meta = write_txn.open_table(TABLE_META)?;
                let pc = if let Some(guard) = meta.get("poo_count")? {
                    let bytes = guard.value();
                    if bytes.len() == 8 {
                        u64::from_be_bytes(bytes.try_into().unwrap_or_default())
                    } else {
                        0
                    }
                } else {
                    0
                };
                let ts = if let Some(guard) = meta.get("tree_size")? {
                    let bytes = guard.value();
                    if bytes.len() == 8 {
                        u64::from_be_bytes(bytes.try_into().unwrap_or_default())
                    } else {
                        0
                    }
                } else {
                    0
                };
                (pc, ts)
            };

            // 2. Apply each transition delta
            for bt in transitions {
                // Remove spent outpoints
                for spent in &bt.delta.spent_outpoints {
                    let op_bytes = spent.to_bytes();
                    uco_table.remove(&op_bytes[..])?;
                }

                // Insert created UCOs
                for created in &bt.delta.created_ucos {
                    let op_bytes = created.outpoint.to_bytes();
                    let uco_json = serde_json::to_vec(created)?;
                    uco_table.insert(&op_bytes[..], uco_json.as_slice())?;
                }

                // Insert retired POOs
                for poo in &bt.delta.retired_poos {
                    let poo_json = serde_json::to_vec(poo)?;
                    poo_table.insert(poo_count, poo_json.as_slice())?;
                    poo_count += 1;
                }

                // Update serial cursors
                for ((proj, vin), cursor) in &bt.delta.updated_cursors {
                    let key = format!("{}:{}", proj, vin);
                    cursor_table.insert(key.as_str(), *cursor)?;
                }

                // Mark MRV data roots used
                for root in &bt.delta.used_data_roots {
                    used_roots.insert(&root[..], 1u8)?;
                }

                // Insert MRV mirrors if present
                if let Some((root, mirrors)) = &bt.mrv_mirrors {
                    let mirrors_csv = mirrors.join(",");
                    mirrors_table.insert(&root[..], mirrors_csv.as_str())?;
                }

                // Record event
                events_table.insert(bt.event_leaf_index, bt.event_raw_bytes.as_slice())?;
                if bt.event_leaf_index + 1 > latest_tree_size {
                    latest_tree_size = bt.event_leaf_index + 1;
                }
            }

            // 3. Update meta tree_size, poo_count, and checkpoint size
            {
                let mut meta = write_txn.open_table(TABLE_META)?;
                meta.insert("tree_size", &latest_tree_size.to_be_bytes()[..])?;
                meta.insert("poo_count", &poo_count.to_be_bytes()[..])?;
                if let Some((header, _)) = new_checkpoint {
                    meta.insert(
                        "latest_checkpoint_size",
                        &header.tree_size.to_be_bytes()[..],
                    )?;
                }
            }

            // 4. Record new checkpoint if present
            if let Some((header, note_bytes)) = new_checkpoint {
                chk_table.insert(header.tree_size, note_bytes)?;
            }

            // 5. Record OTS proof if present
            if let Some(proof_bytes) = ots_proof {
                ots_table.insert(latest_tree_size, proof_bytes)?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Single transition commit convenience wrapper.
    pub fn commit_transition(
        &self,
        delta: &UcoTransitionDelta,
        event_leaf_index: u64,
        event_raw_bytes: &[u8],
        new_checkpoint: Option<(&CheckpointHeaderV2, &[u8])>,
        ots_proof: Option<&[u8]>,
        mrv_mirrors: Option<(&[u8; 32], &[String])>,
    ) -> Result<(), StorageError> {
        let bt = BatchTransition {
            delta: delta.clone(),
            event_leaf_index,
            event_raw_bytes: event_raw_bytes.to_vec(),
            mrv_mirrors: mrv_mirrors.map(|(r, m)| (*r, m.to_vec())),
        };
        self.commit_batch(&[bt], new_checkpoint, ots_proof)
    }
}

/// Description of a single transition inside a commit batch.
#[derive(Debug, Clone)]
pub struct BatchTransition {
    pub delta: UcoTransitionDelta,
    pub event_leaf_index: u64,
    pub event_raw_bytes: Vec<u8>,
    pub mrv_mirrors: Option<([u8; 32], Vec<String>)>,
}

// ---------------------------------------------------------------------------
// StorageReadTx: Read Transaction and UcoStoreRead Implementation
// ---------------------------------------------------------------------------

pub struct StorageReadTx {
    read_txn: redb::ReadTransaction,
    chain_id: [u8; 32],
    current_epoch: u64,
}

impl StorageReadTx {
    pub fn tree_size(&self) -> u64 {
        if let Ok(meta) = self.read_txn.open_table(TABLE_META) {
            if let Ok(Some(guard)) = meta.get("tree_size") {
                let bytes = guard.value();
                if bytes.len() == 8 {
                    return u64::from_be_bytes(bytes.try_into().unwrap_or_default());
                }
            }
        }
        0
    }

    pub fn poo_count(&self) -> u64 {
        if let Ok(meta) = self.read_txn.open_table(TABLE_META) {
            if let Ok(Some(guard)) = meta.get("poo_count") {
                let bytes = guard.value();
                if bytes.len() == 8 {
                    return u64::from_be_bytes(bytes.try_into().unwrap_or_default());
                }
            }
        }
        0
    }

    pub fn get_event(&self, leaf_index: u64) -> Result<Option<Vec<u8>>, StorageError> {
        let table = self.read_txn.open_table(TABLE_HISTORICAL_EVENTS)?;
        if let Some(guard) = table.get(leaf_index)? {
            Ok(Some(guard.value().to_vec()))
        } else {
            Ok(None)
        }
    }

    pub fn get_checkpoint(&self, tree_size: u64) -> Result<Option<Vec<u8>>, StorageError> {
        let table = self.read_txn.open_table(TABLE_CHECKPOINTS)?;
        if let Some(guard) = table.get(tree_size)? {
            Ok(Some(guard.value().to_vec()))
        } else {
            Ok(None)
        }
    }

    pub fn get_latest_checkpoint(&self) -> Result<Option<Vec<u8>>, StorageError> {
        let meta = self.read_txn.open_table(TABLE_META)?;
        if let Some(guard) = meta.get("latest_checkpoint_size")? {
            let bytes = guard.value();
            if bytes.len() == 8 {
                let size = u64::from_be_bytes(bytes.try_into().unwrap_or_default());
                return self.get_checkpoint(size);
            }
        }
        Ok(None)
    }

    pub fn get_ots_proof(&self, tree_size: u64) -> Result<Option<Vec<u8>>, StorageError> {
        let table = self.read_txn.open_table(TABLE_OTS_PROOFS)?;
        if let Some(guard) = table.get(tree_size)? {
            Ok(Some(guard.value().to_vec()))
        } else {
            Ok(None)
        }
    }

    pub fn get_poo(&self, index: u64) -> Result<Option<ProofOfOffsetCommitment>, StorageError> {
        let table = self.read_txn.open_table(TABLE_POO_ARCHIVE)?;
        if let Some(guard) = table.get(index)? {
            let poo = serde_json::from_slice(guard.value())?;
            Ok(Some(poo))
        } else {
            Ok(None)
        }
    }

    pub fn list_unspent_outputs(&self) -> Result<Vec<UnretiredCreditOutput>, StorageError> {
        let table = self.read_txn.open_table(TABLE_UNSPENT_OUTPUTS)?;
        let mut ucos = Vec::new();
        for item in table.iter()? {
            let (_key, val) = item?;
            let uco: UnretiredCreditOutput = serde_json::from_slice(val.value())?;
            ucos.push(uco);
        }
        Ok(ucos)
    }

    pub fn get_buffer_pool_balance(&self, category: &str) -> Result<u64, StorageError> {
        let table = self.read_txn.open_table(TABLE_BUFFER_POOL)?;
        if let Some(guard) = table.get(category)? {
            Ok(guard.value())
        } else {
            Ok(0)
        }
    }

    pub fn get_mrv_mirrors(&self, root: &[u8; 32]) -> Result<Option<Vec<String>>, StorageError> {
        let table = self.read_txn.open_table(TABLE_MRV_MIRRORS)?;
        if let Some(guard) = table.get(&root[..])? {
            let csv = guard.value();
            let list = csv
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            Ok(Some(list))
        } else {
            Ok(None)
        }
    }
}

impl UcoStoreRead for StorageReadTx {
    fn chain_id(&self) -> [u8; 32] {
        self.chain_id
    }

    fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    fn get_uco(&self, outpoint: &OutPoint) -> Option<UnretiredCreditOutput> {
        let table = self.read_txn.open_table(TABLE_UNSPENT_OUTPUTS).ok()?;
        let op_bytes = outpoint.to_bytes();
        let guard = table.get(&op_bytes[..]).ok()??;
        serde_json::from_slice(guard.value()).ok()
    }

    fn get_serial_cursor(&self, project_id: &str, vintage_year: u16) -> u64 {
        let Ok(table) = self.read_txn.open_table(TABLE_SERIAL_CURSORS) else {
            return 0;
        };
        let key = format!("{}:{}", project_id, vintage_year);
        table
            .get(key.as_str())
            .ok()
            .flatten()
            .map(|g| g.value())
            .unwrap_or(0)
    }

    fn is_vvb_active(&self, vvb: &PubKey) -> bool {
        let Ok(table) = self.read_txn.open_table(TABLE_VVBS) else {
            return false;
        };
        table.get(&vvb.as_bytes()[..]).ok().flatten().is_some()
    }

    fn is_mrv_root_used(&self, root: &[u8; 32]) -> bool {
        let Ok(table) = self.read_txn.open_table(TABLE_USED_DATA_ROOTS) else {
            return false;
        };
        table.get(&root[..]).ok().flatten().is_some()
    }
}

// ---------------------------------------------------------------------------
// Unit & Integration Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use grey_misnomer_core::auth::Keypair;
    use grey_misnomer_core::uco_engine::{apply_uco, UcoMintTx, UcoTransaction};
    use std::fs;

    fn temp_db_path() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("gm_redb_test_{}", fastrand()));
        let _ = fs::create_dir_all(&dir);
        dir.join("chainstate.redb")
    }

    fn fastrand() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    }

    #[test]
    fn test_storage_lifecycle_and_uco_read_adapter() {
        let db_path = temp_db_path();
        let storage = ChainStorage::open(&db_path).expect("open storage");

        let chain_id = [7u8; 32];
        storage.init_chain(&chain_id).expect("init chain");

        // Verify chain_id mismatch detection
        let wrong_chain = [9u8; 32];
        assert!(storage.init_chain(&wrong_chain).is_err());

        // Register VVB
        let vvb_key = Keypair::generate();
        let vvb_pub = vvb_key.pubkey();
        storage
            .register_vvb(&vvb_pub, "DNV Climate Services")
            .expect("register vvb");

        // Verify VVB is active through UcoStoreRead
        {
            let rtx = storage.read_tx().expect("read_tx");
            assert_eq!(rtx.chain_id(), chain_id);
            assert_eq!(rtx.current_epoch(), 0);
            assert!(rtx.is_vvb_active(&vvb_pub));
            assert_eq!(rtx.get_serial_cursor("VCS-984", 2024), 0);
        }

        // Construct a valid UcoMintTx
        let owner_key = Keypair::generate();
        let owner_pub = owner_key.pubkey();
        let mrv_root = [0x55u8; 32];

        let mut mint = UcoMintTx {
            project_id: "VCS-984".to_string(),
            batch_id: "BATCH-2024-01".to_string(),
            vintage_year: 2024,
            micro_units: 5_000_000,
            initial_owner: owner_pub,
            methodology_hash: [0x11u8; 32],
            mrv_data_root: mrv_root,
            mrv_blob_mirrors: vec!["https://r2.example.com/blob1".to_string()],
            challenge_window_epochs: 10,
            vvb_signatures: Vec::new(),
        };

        // Sign with accredited VVB
        let preimage = mint.signing_preimage(&chain_id);
        let sig = vvb_key.sign(&preimage);
        mint.vvb_signatures.push((vvb_pub, sig));

        // Evaluate against redb storage read transaction!
        let delta = {
            let rtx = storage.read_tx().expect("read_tx");
            apply_uco(&rtx, &UcoTransaction::Mint(mint.clone())).expect("apply mint")
        };

        assert_eq!(delta.created_ucos.len(), 1);
        let created_uco = &delta.created_ucos[0];

        // Commit transition into redb atomically
        let event_raw = b"{\"event\":\"mint\",\"project_id\":\"VCS-984\"}";
        storage
            .commit_transition(
                &delta,
                0,
                event_raw,
                None,
                Some(b"mock_ots_proof"),
                Some((&mrv_root, &mint.mrv_blob_mirrors)),
            )
            .expect("commit transition");

        // Verify state persistence via read_tx
        {
            let rtx = storage.read_tx().expect("read_tx after commit");
            assert_eq!(rtx.tree_size(), 1);
            assert_eq!(rtx.get_serial_cursor("VCS-984", 2024), 5_000_000);
            assert!(rtx.is_mrv_root_used(&mrv_root));

            // Verify UCO can be fetched by outpoint
            let fetched = rtx.get_uco(&created_uco.outpoint).expect("fetched uco");
            assert_eq!(fetched.micro_units, 5_000_000);
            assert_eq!(fetched.start_micro_unit, 0);
            assert_eq!(fetched.end_micro_unit, 5_000_000);
            assert_eq!(fetched.owner, owner_pub);

            // Verify event log retrieval
            let ev = rtx.get_event(0).expect("get_event").expect("event exists");
            assert_eq!(ev, event_raw);

            // Verify OTS proof retrieval
            let ots = rtx.get_ots_proof(1).expect("get_ots").expect("ots exists");
            assert_eq!(ots, b"mock_ots_proof");

            // Verify MRV mirrors retrieval
            let mirrors = rtx
                .get_mrv_mirrors(&mrv_root)
                .expect("mirrors")
                .expect("exists");
            assert_eq!(mirrors, vec!["https://r2.example.com/blob1".to_string()]);

            // List active UCOs
            let all = rtx.list_unspent_outputs().expect("list");
            assert_eq!(all.len(), 1);
            assert_eq!(all[0].outpoint, created_uco.outpoint);
        }

        // Cleanup test directory
        let _ = fs::remove_dir_all(db_path.parent().unwrap());
    }
}
