// src/daemon/src/mempool.rs
// RFC-008 §4: Coinless Anti-Spam, 16-Bit BLAKE3 Hashcash & Mempool Socket Rejection

use std::collections::HashMap;
use thiserror::Error;

use grey_misnomer_core::error::RegistryError;
use grey_misnomer_core::uco::{OutPoint, MAX_TX_OUTPUTS, MAX_UCO_MICRO_UNITS};
use grey_misnomer_core::uco_engine::{apply_uco, UcoStoreRead, UcoTransaction};

pub const HASHCASH_PREFIX: &[u8] = b"GM-POW:";
pub const DEFAULT_DIFFICULTY_BITS: u32 = 16;
pub const BAN_SCORE_THRESHOLD: i32 = -100;
pub const INITIAL_PEER_SCORE: i32 = 100;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerScore {
    pub score: i32,
    pub offenses: u32,
    pub successes: u32,
}

impl Default for PeerScore {
    fn default() -> Self {
        Self {
            score: INITIAL_PEER_SCORE,
            offenses: 0,
            successes: 0,
        }
    }
}

impl PeerScore {
    pub fn is_banned(&self) -> bool {
        self.score <= BAN_SCORE_THRESHOLD
    }

    pub fn penalize(&mut self, points: i32) {
        self.score = self.score.saturating_sub(points);
        self.offenses = self.offenses.saturating_add(1);
    }

    pub fn reward(&mut self, points: i32) {
        self.score = (self.score + points).min(200);
        self.successes = self.successes.saturating_add(1);
    }
}

pub fn count_leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut total = 0;
    for &b in bytes {
        if b == 0 {
            total += 8;
        } else {
            total += b.leading_zeros();
            break;
        }
    }
    total
}

pub fn compute_hashcash(txid: &[u8; 32], difficulty_bits: u32) -> u64 {
    if difficulty_bits == 0 {
        return 0;
    }
    let mut nonce: u64 = 0;
    loop {
        let mut hasher = blake3::Hasher::new();
        hasher.update(HASHCASH_PREFIX);
        hasher.update(txid);
        hasher.update(&nonce.to_be_bytes());
        let hash = hasher.finalize();

        if count_leading_zero_bits(hash.as_bytes()) >= difficulty_bits {
            return nonce;
        }
        nonce = nonce.wrapping_add(1);
    }
}

pub fn verify_hashcash(txid: &[u8; 32], nonce: u64, difficulty_bits: u32) -> bool {
    if difficulty_bits == 0 {
        return true;
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(HASHCASH_PREFIX);
    hasher.update(txid);
    hasher.update(&nonce.to_be_bytes());
    let hash = hasher.finalize();

    count_leading_zero_bits(hash.as_bytes()) >= difficulty_bits
}

pub fn compute_txid<S: UcoStoreRead>(store: &S, tx: &UcoTransaction) -> [u8; 32] {
    let chain_id = store.chain_id();
    match tx {
        UcoTransaction::Mint(m) => m.txid(&chain_id),
        UcoTransaction::SplitTransfer(s) => {
            let op_indices: Vec<u64> = s
                .inputs
                .iter()
                .map(|inp| store.get_uco(inp).map(|u| u.op_index).unwrap_or(0))
                .collect();
            s.txid(&chain_id, &op_indices)
        }
        UcoTransaction::Burn(b) => {
            let op_index = store.get_uco(&b.input).map(|u| u.op_index).unwrap_or(0);
            b.txid(&chain_id, op_index)
        }
    }
}

pub fn get_tx_inputs(tx: &UcoTransaction) -> Vec<OutPoint> {
    match tx {
        UcoTransaction::Mint(_) => Vec::new(),
        UcoTransaction::SplitTransfer(s) => s.inputs.clone(),
        UcoTransaction::Burn(b) => vec![b.input],
    }
}

pub fn get_tx_output_count(tx: &UcoTransaction) -> usize {
    match tx {
        UcoTransaction::Mint(_) => 1,
        UcoTransaction::SplitTransfer(s) => s.outputs.len(),
        UcoTransaction::Burn(b) => {
            if b.change_owner.is_some() {
                1
            } else {
                0
            }
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MempoolError {
    #[error("Peer {0} is banned due to excessive protocol violations")]
    PeerBanned(String),
    #[error("Transaction {0} is already present in mempool")]
    DuplicateTx(String),
    #[error("Output count {count} exceeds MAX_TX_OUTPUTS limit of {max}")]
    FanoutLimitExceeded { count: usize, max: usize },
    #[error("Output micro_units exceeds MAX_UCO_MICRO_UNITS cap")]
    AmountExceedsMaxCap,
    #[error("Invalid interval bounds")]
    InvalidInterval,
    #[error("Insufficient Proof-of-Work: expected {required} zero bits")]
    InvalidProofOfWork { required: u32 },
    #[error("Mempool conflict: input {outpoint} already spent by pending tx {conflict_txid}")]
    ConflictWithPendingTx {
        outpoint: String,
        conflict_txid: String,
    },
    #[error("Transaction pre-flight simulation failed: {0}")]
    PreFlightFailed(#[from] RegistryError),
}

pub struct Mempool {
    txs: HashMap<[u8; 32], (UcoTransaction, u64, u64)>, // txid -> (tx, timestamp, nonce)
    spent_inputs: HashMap<OutPoint, [u8; 32]>,          // outpoint -> spending_txid
    peer_scores: HashMap<String, PeerScore>,
    difficulty_bits: u32,
}

impl Mempool {
    pub fn new(difficulty_bits: u32) -> Self {
        Self {
            txs: HashMap::new(),
            spent_inputs: HashMap::new(),
            peer_scores: HashMap::new(),
            difficulty_bits,
        }
    }

    pub fn set_difficulty(&mut self, difficulty_bits: u32) {
        self.difficulty_bits = difficulty_bits;
    }

    pub fn difficulty(&self) -> u32 {
        self.difficulty_bits
    }

    pub fn len(&self) -> usize {
        self.txs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }

    pub fn contains(&self, txid: &[u8; 32]) -> bool {
        self.txs.contains_key(txid)
    }

    pub fn get(&self, txid: &[u8; 32]) -> Option<&UcoTransaction> {
        self.txs.get(txid).map(|(tx, _, _)| tx)
    }

    pub fn peer_score(&self, peer_id: &str) -> i32 {
        self.peer_scores
            .get(peer_id)
            .map(|s| s.score)
            .unwrap_or(INITIAL_PEER_SCORE)
    }

    pub fn is_peer_banned(&self, peer_id: &str) -> bool {
        self.peer_scores
            .get(peer_id)
            .map(|s| s.is_banned())
            .unwrap_or(false)
    }

    pub fn submit_tx<S: UcoStoreRead>(
        &mut self,
        tx: UcoTransaction,
        peer_id: &str,
        nonce: u64,
        timestamp: u64,
        store: &S,
    ) -> Result<[u8; 32], MempoolError> {
        // 1. Check peer reputation
        let peer_entry = self.peer_scores.entry(peer_id.to_string()).or_default();
        if peer_entry.is_banned() {
            return Err(MempoolError::PeerBanned(peer_id.to_string()));
        }

        // 2. Structural Anti-Spam Invariants
        let out_count = get_tx_output_count(&tx);
        if out_count > MAX_TX_OUTPUTS {
            peer_entry.penalize(20);
            return Err(MempoolError::FanoutLimitExceeded {
                count: out_count,
                max: MAX_TX_OUTPUTS,
            });
        }

        if let UcoTransaction::Mint(ref m) = tx {
            if m.micro_units > MAX_UCO_MICRO_UNITS {
                peer_entry.penalize(20);
                return Err(MempoolError::AmountExceedsMaxCap);
            }
        } else if let UcoTransaction::SplitTransfer(ref s) = tx {
            for out in &s.outputs {
                if out.micro_units > MAX_UCO_MICRO_UNITS {
                    peer_entry.penalize(20);
                    return Err(MempoolError::AmountExceedsMaxCap);
                }
                if out.start_micro_unit >= out.end_micro_unit {
                    peer_entry.penalize(20);
                    return Err(MempoolError::InvalidInterval);
                }
            }
        }

        // 3. Compute unique TXID
        let txid = compute_txid(store, &tx);
        if self.txs.contains_key(&txid) {
            return Err(MempoolError::DuplicateTx(hex::encode(txid)));
        }

        // 4. Hashcash Proof-of-Work Verification
        if self.difficulty_bits > 0 && !verify_hashcash(&txid, nonce, self.difficulty_bits) {
            peer_entry.penalize(30);
            return Err(MempoolError::InvalidProofOfWork {
                required: self.difficulty_bits,
            });
        }

        // 5. Mempool Conflict Check (OutPoint Double-Spend)
        let inputs = get_tx_inputs(&tx);
        for inp in &inputs {
            if let Some(conflict_txid) = self.spent_inputs.get(inp) {
                peer_entry.penalize(100);
                return Err(MempoolError::ConflictWithPendingTx {
                    outpoint: inp.to_string(),
                    conflict_txid: hex::encode(conflict_txid),
                });
            }
        }

        // 6. Pre-flight Pure apply_uco Simulation against Chainstate
        if let Err(e) = apply_uco(store, &tx) {
            peer_entry.penalize(40);
            return Err(MempoolError::PreFlightFailed(e));
        }

        // 7. Accept into Mempool & Reward Peer
        for inp in inputs {
            self.spent_inputs.insert(inp, txid);
        }
        self.txs.insert(txid, (tx, timestamp, nonce));
        peer_entry.reward(5);

        Ok(txid)
    }

    pub fn remove_tx(&mut self, txid: &[u8; 32]) {
        if let Some((tx, _, _)) = self.txs.remove(txid) {
            for inp in get_tx_inputs(&tx) {
                self.spent_inputs.remove(&inp);
            }
        }
    }

    pub fn all_txids(&self) -> Vec<[u8; 32]> {
        self.txs.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use grey_misnomer_core::auth::Keypair;
    use grey_misnomer_core::uco::{OutPoint, PoOClaimType, UnretiredCreditOutput};
    use grey_misnomer_core::uco_engine::{
        UcoBurnTx, UcoSplitTransferTx, UcoState, UcoTransferOutputSpec,
    };

    fn make_test_keypair() -> Keypair {
        Keypair::generate()
    }

    #[test]
    fn test_hashcash_roundtrip() {
        let txid = [0xabu8; 32];
        let diff = 10; // small difficulty for instant unit test
        let nonce = compute_hashcash(&txid, diff);
        assert!(verify_hashcash(&txid, nonce, diff));
        assert!(!verify_hashcash(&txid, nonce.wrapping_add(1), diff + 20));
    }

    #[test]
    fn test_mempool_structural_fanout_rejection() {
        let mut mempool = Mempool::new(0);
        let store = UcoState::new([0u8; 32]);
        let key = make_test_keypair();

        let mut outputs = Vec::new();
        for i in 0..17 {
            outputs.push(UcoTransferOutputSpec {
                owner: key.pubkey(),
                start_micro_unit: (i * 1000) as u64,
                end_micro_unit: ((i + 1) * 1000) as u64,
                micro_units: 1000,
                locked_escrow_program: None,
            });
        }

        let tx = UcoTransaction::SplitTransfer(UcoSplitTransferTx {
            inputs: vec![OutPoint {
                txid: [1u8; 32],
                vout: 0,
            }],
            outputs,
            input_signatures: vec![key.sign(b"dummy")],
        });

        let res = mempool.submit_tx(tx, "peer-spam", 0, 1000, &store);
        assert!(matches!(res, Err(MempoolError::FanoutLimitExceeded { .. })));
        assert_eq!(mempool.peer_score("peer-spam"), INITIAL_PEER_SCORE - 20);
    }

    #[test]
    fn test_mempool_conflict_detection_and_peer_ban() {
        let mut mempool = Mempool::new(0);
        let key = make_test_keypair();
        let chain_id = [7u8; 32];
        let mut store = UcoState::new(chain_id);

        // Seed an unspent output in chainstate
        let uco = UnretiredCreditOutput {
            outpoint: OutPoint {
                txid: [1u8; 32],
                vout: 0,
            },
            batch_id: "B-1".to_string(),
            project_id: "PRJ-MANGROVE".to_string(),
            vintage_year: 2026,
            start_micro_unit: 1000,
            end_micro_unit: 2000,
            micro_units: 1000,
            owner: key.pubkey(),
            op_index: 1,
            methodology_hash: [2u8; 32],
            mrv_data_root: [3u8; 32],
            mrv_blob_mirrors: Vec::new(),
            challenge_until_epoch: 0,
            locked_escrow_program: None,
        };
        store.unspent_outputs.insert(uco.outpoint, uco.clone());

        // Construct valid burn transaction
        let mut burn_tx = UcoBurnTx {
            input: uco.outpoint,
            start_micro_unit: 1000,
            end_micro_unit: 2000,
            micro_units: 1000,
            beneficiary: "Corporate Buyer Ltd".to_string(),
            claim_type: PoOClaimType::Voluntary,
            owner_sig: key.sign(b"placeholder"),
            change_owner: None,
        };
        let preimage = burn_tx.signing_preimage(&chain_id, uco.op_index);
        burn_tx.owner_sig = key.sign(&preimage);

        // First submission should succeed
        let tx = UcoTransaction::Burn(burn_tx.clone());
        let txid = mempool
            .submit_tx(tx.clone(), "peer-honest", 0, 100, &store)
            .expect("first submit should succeed");
        assert_eq!(mempool.len(), 1);
        assert!(mempool.contains(&txid));

        // Duplicate spend of the same input by adversarial peer should fail with conflict
        let mut split_tx = UcoSplitTransferTx {
            inputs: vec![uco.outpoint],
            outputs: vec![UcoTransferOutputSpec {
                owner: key.pubkey(),
                start_micro_unit: 1000,
                end_micro_unit: 2000,
                micro_units: 1000,
                locked_escrow_program: None,
            }],
            input_signatures: vec![key.sign(b"placeholder")],
        };
        let split_preimage = split_tx.signing_preimage(&chain_id, &[uco.op_index]);
        split_tx.input_signatures = vec![key.sign(&split_preimage)];

        let conflict_res = mempool.submit_tx(
            UcoTransaction::SplitTransfer(split_tx.clone()),
            "peer-attacker",
            0,
            101,
            &store,
        );
        assert!(matches!(
            conflict_res,
            Err(MempoolError::ConflictWithPendingTx { .. })
        ));
        assert_eq!(
            mempool.peer_score("peer-attacker"),
            INITIAL_PEER_SCORE - 100
        );

        // Repeated conflict triggers ban
        let _ = mempool.submit_tx(
            UcoTransaction::SplitTransfer(split_tx),
            "peer-attacker",
            0,
            102,
            &store,
        );
        assert!(mempool.is_peer_banned("peer-attacker"));
    }
}
