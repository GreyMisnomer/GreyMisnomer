//! RFC-008 §9 & Stage 4.6: Sovereign v2.0 Genesis & VVB Bootstrap.
//!
//! Creates portable public `genesis_v2.json` manifests (containing `chain_id`,
//! `authority` public key, `sequencer` public key, and accredited VVBs with zero
//! secrets) alongside private CSPRNG `genesis_keys.json` bundles kept exclusively
//! by the genesis operator (`Alice`).

use crate::storage::{ChainStorage, StorageError};
use grey_misnomer_core::auth::{enc_pubkey, enc_str, enc_u64, Keypair, PubKey};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

pub const GENESIS_FILE_NAME: &str = "genesis_v2.json";
pub const GENESIS_KEYS_FILE_NAME: &str = "genesis_keys.json";

#[derive(Debug, Error)]
pub enum GenesisError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON parse/serialize error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Invalid genesis parameters: {0}")]
    Invalid(String),
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisVvb {
    pub pubkey: PubKey,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisV2 {
    pub version: u16,
    pub chain_name: String,
    #[serde(with = "grey_misnomer_core::auth::hex_bytes32")]
    pub chain_id: [u8; 32],
    pub authority: PubKey,
    pub sequencer: PubKey,
    pub accredited_vvbs: Vec<GenesisVvb>,
    pub created_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyEntry {
    pub pubkey: String,
    pub seed: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisKeyBundle {
    pub chain_name: String,
    pub chain_id: String,
    pub authority: KeyEntry,
    pub sequencer: KeyEntry,
    pub vvb: KeyEntry,
    pub alice: KeyEntry,
    pub bob: KeyEntry,
}

impl KeyEntry {
    pub fn from_keypair(kp: &Keypair) -> Self {
        Self {
            pubkey: kp.pubkey().to_hex(),
            seed: kp.secret_hex(),
        }
    }

    pub fn to_keypair(&self) -> Result<Keypair, GenesisError> {
        Keypair::from_hex(&self.seed)
            .map_err(|e| GenesisError::Invalid(format!("invalid secret key hex: {e}")))
    }
}

impl GenesisV2 {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, GenesisError> {
        let text = fs::read_to_string(path)?;
        let g: Self = serde_json::from_str(&text)?;
        if g.version != 2 {
            return Err(GenesisError::Invalid(format!(
                "unsupported genesis version {}; expected 2",
                g.version
            )));
        }
        if g.accredited_vvbs.is_empty() {
            return Err(GenesisError::Invalid(
                "genesis_v2.json must accredit at least one VVB".to_string(),
            ));
        }
        Ok(g)
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), GenesisError> {
        if let Some(parent) = path.as_ref().parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let pretty = serde_json::to_string_pretty(self)?;
        fs::write(path, format!("{pretty}\n"))?;
        Ok(())
    }
}

impl GenesisKeyBundle {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, GenesisError> {
        let text = fs::read_to_string(path)?;
        Ok(serde_json::from_str(&text)?)
    }

    pub fn save_restricted(&self, path: impl AsRef<Path>) -> Result<(), GenesisError> {
        if let Some(parent) = path.as_ref().parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let pretty = serde_json::to_string_pretty(self)?;
        fs::write(path.as_ref(), format!("{pretty}\n"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o600);
            let _ = fs::set_permissions(path.as_ref(), perms);
        }
        Ok(())
    }
}

/// Generates a fresh CSPRNG-backed `GenesisV2` + private `GenesisKeyBundle`.
pub fn generate_genesis_v2(
    chain_name: &str,
    fixed_chain_id: Option<[u8; 32]>,
) -> (GenesisV2, GenesisKeyBundle) {
    let authority_kp = Keypair::generate();
    let sequencer_kp = Keypair::generate();
    let vvb_kp = Keypair::generate();
    let alice_kp = Keypair::generate();
    let bob_kp = Keypair::generate();

    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let chain_id = fixed_chain_id.unwrap_or_else(|| {
        let mut preimage = Vec::new();
        enc_str("GM-v2-GENESIS:", &mut preimage);
        enc_str(chain_name, &mut preimage);
        enc_pubkey(&authority_kp.pubkey(), &mut preimage);
        enc_pubkey(&sequencer_kp.pubkey(), &mut preimage);
        enc_pubkey(&vvb_kp.pubkey(), &mut preimage);
        enc_u64(created_at, &mut preimage);
        *blake3::hash(&preimage).as_bytes()
    });

    let genesis = GenesisV2 {
        version: 2,
        chain_name: chain_name.to_string(),
        chain_id,
        authority: authority_kp.pubkey(),
        sequencer: sequencer_kp.pubkey(),
        accredited_vvbs: vec![GenesisVvb {
            pubkey: vvb_kp.pubkey(),
            label: format!("{chain_name} Accredited VVB #1"),
        }],
        created_at,
    };

    let bundle = GenesisKeyBundle {
        chain_name: chain_name.to_string(),
        chain_id: hex::encode(chain_id),
        authority: KeyEntry::from_keypair(&authority_kp),
        sequencer: KeyEntry::from_keypair(&sequencer_kp),
        vvb: KeyEntry::from_keypair(&vvb_kp),
        alice: KeyEntry::from_keypair(&alice_kp),
        bob: KeyEntry::from_keypair(&bob_kp),
    };

    (genesis, bundle)
}

/// Applies `GenesisV2` chain ID, sequencer key, and VVB accreditations to `ChainStorage`.
pub fn apply_genesis_to_storage(
    storage: &ChainStorage,
    genesis: &GenesisV2,
) -> Result<(), GenesisError> {
    storage.init_chain(&genesis.chain_id)?;
    storage.set_sequencer_pubkey(&genesis.sequencer)?;
    for vvb in &genesis.accredited_vvbs {
        storage.register_vvb(&vvb.pubkey, &vvb.label)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use grey_misnomer_core::uco_engine::UcoStoreRead;

    #[test]
    fn test_generate_and_apply_genesis_v2_to_storage() {
        let (genesis, keys) = generate_genesis_v2("AliceBobNet", None);
        assert_eq!(genesis.version, 2);
        assert_eq!(genesis.accredited_vvbs.len(), 1);
        assert_eq!(hex::encode(genesis.chain_id), keys.chain_id);
        assert_eq!(
            genesis.sequencer,
            keys.sequencer.to_keypair().unwrap().pubkey()
        );

        let dir = std::env::temp_dir().join(format!("gm_gen_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let gen_path = dir.join(GENESIS_FILE_NAME);
        let keys_path = dir.join(GENESIS_KEYS_FILE_NAME);
        let db_path = dir.join("chainstate.redb");

        genesis.save(&gen_path).unwrap();
        keys.save_restricted(&keys_path).unwrap();

        let reloaded = GenesisV2::load(&gen_path).unwrap();
        assert_eq!(reloaded, genesis);

        let storage = ChainStorage::open(&db_path).unwrap();
        apply_genesis_to_storage(&storage, &reloaded).unwrap();

        let rtx = storage.read_tx().unwrap();
        assert_eq!(rtx.chain_id(), genesis.chain_id);
        assert_eq!(rtx.get_sequencer_pubkey(), Some(genesis.sequencer));
        assert_eq!(rtx.list_vvbs().unwrap().len(), 1);

        let _ = fs::remove_dir_all(&dir);
    }
}
