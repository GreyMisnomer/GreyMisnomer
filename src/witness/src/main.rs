//! C2SP `tlog-cosignature` Lightweight Witness Service.
//!
//! Stores only ~64 bytes per tracked log (`WitnessBookmark { tree_size, events_root }`).
//! Evaluates incoming checkpoint extensions via RFC 9162 consistency proofs,
//! guards against rollback and equivocation, updates the bookmark atomically,
//! and outputs canonical C2SP cosignature lines.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use grey_misnomer_core::auth::Keypair;
use grey_misnomer_core::merkle_log::ConsistencyProof;
use grey_misnomer_core::witness::{
    evaluate_cosign_request, CosignRequest, WitnessBookmark, WitnessDecision,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[command(name = "greymisnomer-witness")]
#[command(about = "C2SP tlog-cosignature witness for GreyMisnomer verifiable logs")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new witness key and empty bookmark
    Init {
        #[arg(long, default_value = "greymisnomer-witness-1")]
        name: String,
        #[arg(long, default_value = "witness.key")]
        key_path: PathBuf,
        #[arg(long, default_value = "bookmark.json")]
        bookmark_path: PathBuf,
    },
    /// Inspect the current witness bookmark
    Status {
        #[arg(long, default_value = "bookmark.json")]
        bookmark_path: PathBuf,
    },
    /// Verify an RFC 9162 extension consistency proof and emit a C2SP cosignature
    Cosign {
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "witness.key")]
        key_path: PathBuf,
        #[arg(long, default_value = "bookmark.json")]
        bookmark_path: PathBuf,
        #[arg(long)]
        note_file: PathBuf,
        #[arg(long)]
        new_size: u64,
        #[arg(long)]
        new_root: String,
        #[arg(long)]
        proof_file: PathBuf,
    },
}

fn load_or_create_bookmark(path: &Path) -> Result<WitnessBookmark> {
    if path.exists() {
        let content = fs::read_to_string(path)?;
        let bookmark: WitnessBookmark = serde_json::from_str(&content)?;
        Ok(bookmark)
    } else {
        Ok(WitnessBookmark::new(0, [0u8; 32]))
    }
}

fn save_bookmark_atomic(path: &Path, bookmark: &WitnessBookmark) -> Result<()> {
    let tmp = path.with_extension("tmp");
    let content = serde_json::to_string_pretty(bookmark)?;
    fs::write(&tmp, content)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

fn load_keypair(path: &Path) -> Result<Keypair> {
    let hex_str = fs::read_to_string(path)
        .with_context(|| format!("failed to read key file {}", path.display()))?;
    Keypair::from_hex(hex_str.trim()).map_err(|e| anyhow::anyhow!("{e}"))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init {
            name,
            key_path,
            bookmark_path,
        } => {
            if !key_path.exists() {
                let kp = Keypair::generate();
                fs::write(&key_path, kp.secret_hex())?;
                println!("Generated fresh CSPRNG witness key: {}", key_path.display());
                println!("Witness Name: {name}");
                println!("Public Key:   {}", kp.pubkey().to_hex());
            } else {
                let kp = load_keypair(&key_path)?;
                println!("Loaded existing witness key: {}", key_path.display());
                println!("Witness Name: {name}");
                println!("Public Key:   {}", kp.pubkey().to_hex());
            }

            if !bookmark_path.exists() {
                let bookmark = WitnessBookmark::new(0, [0u8; 32]);
                save_bookmark_atomic(&bookmark_path, &bookmark)?;
                println!("Initialized empty bookmark at: {}", bookmark_path.display());
            }
        }
        Commands::Status { bookmark_path } => {
            let bm = load_or_create_bookmark(&bookmark_path)?;
            println!("Witness Bookmark: {}", bookmark_path.display());
            println!("  Tree Size:   {}", bm.tree_size);
            println!("  Events Root: {}", hex::encode(bm.events_root));
        }
        Commands::Cosign {
            name,
            key_path,
            bookmark_path,
            note_file,
            new_size,
            new_root,
            proof_file,
        } => {
            let kp = load_keypair(&key_path)?;
            let bookmark = load_or_create_bookmark(&bookmark_path)?;

            let mut root_bytes = [0u8; 32];
            hex::decode_to_slice(&new_root, &mut root_bytes)
                .context("invalid new-root hex (expected 64 chars)")?;

            let note_content = fs::read_to_string(&note_file)
                .with_context(|| format!("failed to read {}", note_file.display()))?;

            let proof_json = fs::read_to_string(&proof_file)
                .with_context(|| format!("failed to read {}", proof_file.display()))?;
            let proof: ConsistencyProof = serde_json::from_str(&proof_json)
                .context("failed to parse ConsistencyProof JSON")?;

            let req = CosignRequest {
                new_size,
                new_root: &root_bytes,
                consistency_proof: &proof,
                checkpoint_note: &note_content,
                timestamp: now_secs(),
            };

            let decision = evaluate_cosign_request(&bookmark, &req, &name, &kp)
                .map_err(|e| anyhow::anyhow!("Witness rejected checkpoint: {e}"))?;

            match decision {
                WitnessDecision::Identical(cosig) => {
                    eprintln!("Checkpoint matches current bookmark. Re-emitting cosignature:");
                    println!("{}", cosig.to_note_line());
                }
                WitnessDecision::Extended {
                    new_bookmark,
                    cosignature,
                } => {
                    save_bookmark_atomic(&bookmark_path, &new_bookmark)?;
                    eprintln!(
                        "Verified RFC 9162 extension: size {} -> {}, bookmark advanced.",
                        bookmark.tree_size, new_size
                    );
                    println!("{}", cosignature.to_note_line());
                }
            }
        }
    }

    Ok(())
}
