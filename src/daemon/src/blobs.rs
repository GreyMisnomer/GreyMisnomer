// src/daemon/src/blobs.rs
// RFC-008 §6 & Task 4.29: Multi-Mirror (>=2) MRV Evidence Pinning & BLAKE3 Verification

use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BlobError {
    #[error("Insufficient independent mirror origins: verified {verified}, required {required}")]
    InsufficientMirrors { verified: usize, required: usize },
    #[error("BLAKE3 hash mismatch for MRV blob: expected {expected}, actual {actual}")]
    HashMismatch { expected: String, actual: String },
    #[error("Failed to read/write local blob store: {0}")]
    Io(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorEndpoint {
    pub name: String,
    pub base_url: String,
}

impl MirrorEndpoint {
    pub fn new(name: impl Into<String>, base_url: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            base_url: base_url.into(),
        }
    }
}

pub struct BlobStore {
    storage_dir: PathBuf,
}

impl BlobStore {
    pub fn new(storage_dir: impl AsRef<Path>) -> Result<Self, BlobError> {
        let p = storage_dir.as_ref().to_path_buf();
        if !p.exists() {
            std::fs::create_dir_all(&p).map_err(|e| BlobError::Io(e.to_string()))?;
        }
        Ok(Self { storage_dir: p })
    }

    pub fn blob_path(&self, data_root: &[u8; 32]) -> PathBuf {
        self.storage_dir
            .join(format!("{}.bin", hex::encode(data_root)))
    }

    pub fn has_blob(&self, data_root: &[u8; 32]) -> bool {
        self.blob_path(data_root).exists()
    }

    pub fn read_blob(&self, data_root: &[u8; 32]) -> Result<Vec<u8>, BlobError> {
        let path = self.blob_path(data_root);
        let data = std::fs::read(&path).map_err(|e| BlobError::Io(e.to_string()))?;
        let actual = *blake3::hash(&data).as_bytes();
        if &actual != data_root {
            return Err(BlobError::HashMismatch {
                expected: hex::encode(data_root),
                actual: hex::encode(actual),
            });
        }
        Ok(data)
    }

    pub fn save_blob(&self, data_root: &[u8; 32], bytes: &[u8]) -> Result<(), BlobError> {
        let actual = *blake3::hash(bytes).as_bytes();
        if &actual != data_root {
            return Err(BlobError::HashMismatch {
                expected: hex::encode(data_root),
                actual: hex::encode(actual),
            });
        }
        let path = self.blob_path(data_root);
        std::fs::write(path, bytes).map_err(|e| BlobError::Io(e.to_string()))?;
        Ok(())
    }
}

pub struct DualMirrorVerifier {
    blob_store: BlobStore,
    mirrors: Vec<MirrorEndpoint>,
    required_mirrors: usize,
}

impl DualMirrorVerifier {
    pub fn new(
        storage_dir: impl AsRef<Path>,
        mirrors: Vec<MirrorEndpoint>,
        required_mirrors: usize,
    ) -> Result<Self, BlobError> {
        Ok(Self {
            blob_store: BlobStore::new(storage_dir)?,
            mirrors,
            required_mirrors,
        })
    }

    pub fn mirrors(&self) -> &[MirrorEndpoint] {
        &self.mirrors
    }

    pub fn blob_store(&self) -> &BlobStore {
        &self.blob_store
    }

    pub fn verify_and_pin_evidence(
        &self,
        data_root: &[u8; 32],
        fetched_sources: &[(&str, &[u8])],
    ) -> Result<usize, BlobError> {
        let mut verified_count = 0;
        let mut valid_payload: Option<&[u8]> = None;

        for (_source_name, payload) in fetched_sources {
            let actual = *blake3::hash(payload).as_bytes();
            if &actual == data_root {
                verified_count += 1;
                if valid_payload.is_none() {
                    valid_payload = Some(payload);
                }
            }
        }

        if verified_count < self.required_mirrors {
            return Err(BlobError::InsufficientMirrors {
                verified: verified_count,
                required: self.required_mirrors,
            });
        }

        if let Some(payload) = valid_payload {
            self.blob_store.save_blob(data_root, payload)?;
        }

        Ok(verified_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(std::path::PathBuf);
    impl TempDir {
        fn new(name: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "gm_test_{}_{}_{}",
                name,
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let _ = std::fs::create_dir_all(&p);
            Self(p)
        }
        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn test_dual_mirror_verification_and_storage() {
        let temp_dir = TempDir::new("dual_mirror");
        let mirrors = vec![
            MirrorEndpoint::new("Primary-IPFS", "ipfs://bafybeidqq"),
            MirrorEndpoint::new(
                "Secondary-ArchiveOrg",
                "https://web.archive.org/web/greymisnomer",
            ),
        ];

        let verifier = DualMirrorVerifier::new(temp_dir.path(), mirrors, 2).unwrap();

        let raw_mrv = b"timestamp,temp,humidity,co2_ppm\n2026-11-24,28.5,65,418.2\n";
        let root = *blake3::hash(raw_mrv).as_bytes();

        // 1 origin only -> must fail dual mirror requirement
        let err = verifier
            .verify_and_pin_evidence(&root, &[("Primary-IPFS", raw_mrv)])
            .unwrap_err();
        assert_eq!(
            err,
            BlobError::InsufficientMirrors {
                verified: 1,
                required: 2
            }
        );
        assert!(!verifier.blob_store().has_blob(&root));

        // 2 origins with matching BLAKE3 hash -> succeeds and persists locally
        let count = verifier
            .verify_and_pin_evidence(
                &root,
                &[("Primary-IPFS", raw_mrv), ("Secondary-ArchiveOrg", raw_mrv)],
            )
            .expect("dual mirror verification should succeed");
        assert_eq!(count, 2);
        assert!(verifier.blob_store().has_blob(&root));

        let stored = verifier.blob_store().read_blob(&root).unwrap();
        assert_eq!(stored, raw_mrv);
    }

    #[test]
    fn test_blob_store_rejects_corrupted_payload() {
        let temp_dir = TempDir::new("corrupted_payload");
        let store = BlobStore::new(temp_dir.path()).unwrap();
        let root = [0x55u8; 32];
        let bad_payload = b"this does not match root 0x55";

        let err = store.save_blob(&root, bad_payload).unwrap_err();
        assert!(matches!(err, BlobError::HashMismatch { .. }));
    }
}
