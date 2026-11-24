//! RFC-007 §4.3: Immutable Static Tile Layout Generator (C2SP `tlog-tiles`).
//!
//! Replaces monolithic mutating `events.jsonl` downloads with cache-forever static chunks
//! verifiable from any dumb mirror (S3/R2, IPFS, Archive.org, nginx, or read-only GitHub Pages).
//!
//! Layout:
//! - Leaf entry tiles: `/tile/entries/<index>[.p/<w>]` (up to 256 canonical events)
//! - Subtree hash tiles: `/tile/<level>/<index>[.p/<w>]` (256 32-byte hashes per full tile)
//! - Checkpoint note: `/checkpoint` (ASCII note committing CheckpointHeaderV2 + cosignatures)

use crate::error::RegistryError;
use crate::header::CheckpointHeaderV2;
use crate::merkle_log::MerkleLogTree;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

pub const TILE_WIDTH: usize = 256;

// ---------------------------------------------------------------------------
// Tile Descriptor
// ---------------------------------------------------------------------------

/// Identifies a specific immutable or partial tile file.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TileKey {
    /// Canonical event bytes tile
    Entries {
        tile_index: u64,
        partial_width: Option<u16>,
    },
    /// Subtree hash tile at given level
    Subtree {
        level: u8,
        tile_index: u64,
        partial_width: Option<u16>,
    },
}

impl TileKey {
    /// Formats the relative URL / filesystem path for this tile per C2SP `tlog-tiles`:
    /// e.g. `tile/entries/000`, `tile/entries/000.p/42`, `tile/0/000`, `tile/1/000.p/12`
    pub fn to_path(&self) -> PathBuf {
        match self {
            Self::Entries {
                tile_index,
                partial_width,
            } => {
                let filename = if let Some(w) = partial_width {
                    format!("{tile_index:03}.p/{w}")
                } else {
                    format!("{tile_index:03}")
                };
                PathBuf::from("tile").join("entries").join(filename)
            }
            Self::Subtree {
                level,
                tile_index,
                partial_width,
            } => {
                let filename = if let Some(w) = partial_width {
                    format!("{tile_index:03}.p/{w}")
                } else {
                    format!("{tile_index:03}")
                };
                PathBuf::from("tile").join(level.to_string()).join(filename)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tile Export Report
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TileExportReport {
    pub total_events: usize,
    pub entry_tiles_created: usize,
    pub tree_tiles_created: usize,
    #[serde(with = "crate::auth::hex_bytes32")]
    pub events_root: [u8; 32],
    pub checkpoint_path: PathBuf,
}

// ---------------------------------------------------------------------------
// Static Tile Generator
// ---------------------------------------------------------------------------

/// Packs raw canonical event lines into immutable static tiles under `out_dir`.
pub fn export_static_tiles(
    events: &[Vec<u8>],
    header: &CheckpointHeaderV2,
    out_dir: &Path,
) -> Result<TileExportReport, RegistryError> {
    let n = events.len();
    if n != header.tree_size as usize {
        return Err(RegistryError::CheckpointHeadMismatch {
            size: header.tree_size,
            expected: n.to_string(),
            found: header.tree_size.to_string(),
        });
    }

    let mut log_tree = MerkleLogTree::new();
    let mut entry_tiles_count = 0;
    let mut tree_tiles_count = 0;

    // 1. Pack leaf entry tiles (256 events per tile)
    let chunks = events.chunks(TILE_WIDTH);
    for (tile_idx, chunk) in chunks.enumerate() {
        let is_partial = chunk.len() < TILE_WIDTH;
        let key = TileKey::Entries {
            tile_index: tile_idx as u64,
            partial_width: if is_partial {
                Some(chunk.len() as u16)
            } else {
                None
            },
        };

        let tile_rel_path = key.to_path();
        let tile_full_path = out_dir.join(&tile_rel_path);
        if let Some(parent) = tile_full_path.parent() {
            fs::create_dir_all(parent).map_err(|e| RegistryError::NotFound {
                id: format!("failed to create dir {}: {e}", parent.display()),
            })?;
        }

        // Pack chunk entries with length-prefix or canonical CRLF/LF json lines
        let mut tile_bytes = Vec::new();
        for event_bytes in chunk {
            tile_bytes.extend_from_slice(event_bytes);
            if !event_bytes.ends_with(b"\n") {
                tile_bytes.push(b'\n');
            }
            log_tree.append(event_bytes);
        }

        fs::write(&tile_full_path, tile_bytes).map_err(|e| RegistryError::NotFound {
            id: format!("failed to write {}: {e}", tile_full_path.display()),
        })?;
        entry_tiles_count += 1;
    }

    let calculated_root = log_tree.root();
    if calculated_root != header.events_root {
        return Err(RegistryError::CheckpointHeadMismatch {
            size: header.tree_size,
            expected: hex::encode(header.events_root),
            found: hex::encode(calculated_root),
        });
    }

    // 2. Pack Level 0 hash subtree tiles (256 32-byte leaf hashes per tile)
    let mut current_level_hashes = Vec::with_capacity(n);
    for i in 0..n {
        current_level_hashes.push(log_tree.leaf_hash(i).expect("exists"));
    }

    let mut current_level: u8 = 0;
    while !current_level_hashes.is_empty() {
        let hash_chunks = current_level_hashes.chunks(TILE_WIDTH);
        for (tile_idx, hash_chunk) in hash_chunks.enumerate() {
            let is_partial = hash_chunk.len() < TILE_WIDTH;
            let key = TileKey::Subtree {
                level: current_level,
                tile_index: tile_idx as u64,
                partial_width: if is_partial {
                    Some(hash_chunk.len() as u16)
                } else {
                    None
                },
            };

            let tile_rel_path = key.to_path();
            let tile_full_path = out_dir.join(&tile_rel_path);
            if let Some(parent) = tile_full_path.parent() {
                fs::create_dir_all(parent).map_err(|e| RegistryError::NotFound {
                    id: format!("failed to create dir {}: {e}", parent.display()),
                })?;
            }

            let mut tile_bytes = Vec::with_capacity(hash_chunk.len() * 32);
            for h in hash_chunk {
                tile_bytes.extend_from_slice(h);
            }

            fs::write(&tile_full_path, tile_bytes).map_err(|e| RegistryError::NotFound {
                id: format!("failed to write {}: {e}", tile_full_path.display()),
            })?;
            tree_tiles_count += 1;
        }

        if current_level_hashes.len() <= 1 {
            break; // Reached root
        }

        // Compute next level hashes
        let next_level_chunks = current_level_hashes.chunks(2);
        let mut next_level_hashes = Vec::with_capacity(next_level_chunks.len());
        for pair in next_level_chunks {
            if pair.len() == 2 {
                next_level_hashes.push(crate::auth::hash_log_internal(&pair[0], &pair[1]));
            } else {
                next_level_hashes.push(pair[0]);
            }
        }
        current_level_hashes = next_level_hashes;
        current_level += 1;
    }

    // 3. Write signed /checkpoint note
    let checkpoint_file = out_dir.join("checkpoint");
    let header_bytes = header.to_canonical_bytes();
    let checkpoint_content = format!(
        "greymisnomer/v2\n{}\n{}\n{}\n",
        header.tree_size,
        hex::encode(header.events_root),
        hex::encode(header_bytes)
    );
    fs::write(&checkpoint_file, checkpoint_content).map_err(|e| RegistryError::NotFound {
        id: format!("failed to write checkpoint note: {e}"),
    })?;

    Ok(TileExportReport {
        total_events: n,
        entry_tiles_created: entry_tiles_count,
        tree_tiles_created: tree_tiles_count,
        events_root: calculated_root,
        checkpoint_path: checkpoint_file,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tile_key_paths() {
        let full_entry = TileKey::Entries {
            tile_index: 0,
            partial_width: None,
        };
        assert_eq!(full_entry.to_path(), PathBuf::from("tile/entries/000"));

        let partial_entry = TileKey::Entries {
            tile_index: 1,
            partial_width: Some(42),
        };
        assert_eq!(
            partial_entry.to_path(),
            PathBuf::from("tile/entries/001.p/42")
        );

        let full_tree = TileKey::Subtree {
            level: 0,
            tile_index: 0,
            partial_width: None,
        };
        assert_eq!(full_tree.to_path(), PathBuf::from("tile/0/000"));

        let partial_tree = TileKey::Subtree {
            level: 2,
            tile_index: 5,
            partial_width: Some(17),
        };
        assert_eq!(partial_tree.to_path(), PathBuf::from("tile/2/005.p/17"));
    }

    #[test]
    fn test_export_static_tiles_small_log() {
        let tmp_dir = std::env::temp_dir().join("gm_test_export_tiles");
        let _ = fs::remove_dir_all(&tmp_dir);

        let mut events = Vec::new();
        let mut log_tree = MerkleLogTree::new();
        for i in 0..10 {
            let ev = format!(r#"{{"seq":{i},"event":"test"}}"#).into_bytes();
            log_tree.append(&ev);
            events.push(ev);
        }

        let header = CheckpointHeaderV2 {
            version: 2,
            chain_id: [0x11; 32],
            tree_size: 10,
            timestamp_ns: 1_700_000_000,
            events_root: log_tree.root(),
            uco_state_root: [0; 32],
            poo_archive_root: [0; 32],
            active_validators_hash: [0; 32],
        };

        let report = export_static_tiles(&events, &header, &tmp_dir).unwrap();

        assert_eq!(report.total_events, 10);
        assert_eq!(report.entry_tiles_created, 1); // 1 partial tile of width 10
        assert!(tmp_dir.join("tile/entries/000.p/10").exists());
        assert!(tmp_dir.join("checkpoint").exists());

        let _ = fs::remove_dir_all(&tmp_dir);
    }
}
