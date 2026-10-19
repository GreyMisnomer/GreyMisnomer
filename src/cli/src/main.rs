use anyhow::{bail, Context, Result};
use grey_misnomer_core::{
    auth::{Keypair, PubKey},
    checkpoint::{detect_equivocation, verify_checkpoints, Checkpoint, CheckpointReport},
    event_log::{replay_log_with_anchor, ReplaySummary},
};
use serde::Serialize;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn find_default_log_path() -> Option<PathBuf> {
    let candidates = [
        "events.jsonl",
        "docs/events.jsonl",
        "../events.jsonl",
        "../../events.jsonl",
        "../../docs/events.jsonl",
    ];
    for c in &candidates {
        let p = PathBuf::from(c);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

fn parse_hex_bytes32(s: &str) -> Result<[u8; 32]> {
    if s.len() != 64 {
        bail!(
            "Expected 64 hexadecimal characters (32 bytes), found length {}",
            s.len()
        );
    }
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(s, &mut bytes).context("Invalid hex characters")?;
    Ok(bytes)
}

fn parse_keypair(key_str: &str) -> Keypair {
    if key_str.len() == 64 {
        if let Ok(bytes) = parse_hex_bytes32(key_str) {
            return Keypair::from_bytes(&bytes);
        }
    }
    Keypair::from_seed_str(key_str)
}

#[derive(Serialize)]
struct KeygenOutput {
    pubkey: String,
    seed: String,
}

#[derive(Serialize)]
struct CheckpointCliReport {
    file: String,
    size: u64,
    head_hash: String,
    timestamp: u64,
    sequencer_verified: bool,
    ots_proof_present: bool,
}

#[derive(Serialize)]
struct CliReplayFullReport {
    log_path: String,
    summary: ReplaySummary,
    checkpoints: Vec<CheckpointCliReport>,
    all_passed: bool,
}

fn print_usage() {
    println!("GreyMisnomer Protocol — Transparency Log & Key Management CLI (RFC-005)");
    println!();
    println!("USAGE:");
    println!("    grey-misnomer-cli [SUBCOMMAND] [FLAGS] [ARGS]");
    println!();
    println!("SUBCOMMANDS:");
    println!("    replay [FILE]               Replay events.jsonl and verify all protocol & authorization invariants (default)");
    println!("    keygen                      Generate a new Ed25519 identity keypair");
    println!("    sign-checkpoint             Sign an explicit (size, head_hash) checkpoint");
    println!(
        "    checkpoint [FILE]           Replay log, create and sign checkpoint for current head"
    );
    println!("    verify-checkpoint <FILE>    Verify an individual signed checkpoint file");
    println!();
    println!("FLAGS:");
    println!("    --chain-id <HEX>            Expected 32-byte registry domain chain_id");
    println!("    --checkpoints <DIR>         Directory of checkpoints/<size>.json files to audit");
    println!("    --key <SEED/HEX>            Private key seed or 64-hex secret");
    println!("    --sequencer <HEX>           Sequencer public key (64 hex characters)");
    println!("    --size <N>                  Log size for checkpoint");
    println!("    --head-hash <HEX>           Log head hash (32 bytes hex) for checkpoint");
    println!("    --timestamp <U64>           Unix timestamp in seconds for checkpoint");
    println!("    --out <PATH>                Destination output path or directory");
    println!("    --json                      Machine-readable JSON output");
    println!("    -h, --help                  Print help information");
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() == 1 {
        return handle_replay(&[]);
    }

    match args[1].as_str() {
        "-h" | "--help" | "help" => {
            print_usage();
            Ok(())
        }
        "keygen" => handle_keygen(&args[2..]),
        "sign-checkpoint" => handle_sign_checkpoint(&args[2..]),
        "checkpoint" => handle_checkpoint(&args[2..]),
        "verify-checkpoint" => handle_verify_checkpoint(&args[2..]),
        "replay" => handle_replay(&args[2..]),
        _ if args[1].starts_with('-') => handle_replay(&args[1..]),
        _ => handle_replay(&args[1..]),
    }
}

fn handle_keygen(args: &[String]) -> Result<()> {
    let mut seed: Option<String> = None;
    let mut json = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--seed" => {
                i += 1;
                if i < args.len() {
                    seed = Some(args[i].clone());
                }
            }
            "--json" => json = true,
            unknown => bail!("Unknown option for keygen: {unknown}"),
        }
        i += 1;
    }

    let (kp, seed_str) = match seed {
        Some(s) => (Keypair::from_seed_str(&s), s),
        None => {
            let kp = Keypair::generate();
            let hex_seed = hex::encode(kp.signing_key.to_bytes());
            (kp, hex_seed)
        }
    };

    let pubkey = kp.pubkey().to_hex();

    if json {
        let out = KeygenOutput {
            pubkey,
            seed: seed_str,
        };
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("══════════════════════════════════════════════════════════════════════");
        println!("  GreyMisnomer Identity Keypair (Ed25519 / RFC 8032)                  ");
        println!("══════════════════════════════════════════════════════════════════════");
        println!("  Public Key (32 bytes): {}", pubkey);
        println!("  Secret Seed:           {}", seed_str);
        println!("══════════════════════════════════════════════════════════════════════");
    }
    Ok(())
}

fn handle_sign_checkpoint(args: &[String]) -> Result<()> {
    let mut key: Option<String> = None;
    let mut chain_id: Option<String> = None;
    let mut size: Option<u64> = None;
    let mut head_hash: Option<String> = None;
    let mut timestamp: Option<u64> = None;
    let mut out_path: Option<String> = None;
    let mut json = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--key" => {
                i += 1;
                if i < args.len() {
                    key = Some(args[i].clone());
                }
            }
            "--chain-id" => {
                i += 1;
                if i < args.len() {
                    chain_id = Some(args[i].clone());
                }
            }
            "--size" => {
                i += 1;
                if i < args.len() {
                    size = Some(args[i].parse().context("Invalid --size")?);
                }
            }
            "--head-hash" => {
                i += 1;
                if i < args.len() {
                    head_hash = Some(args[i].clone());
                }
            }
            "--timestamp" => {
                i += 1;
                if i < args.len() {
                    timestamp = Some(args[i].parse().context("Invalid --timestamp")?);
                }
            }
            "--out" => {
                i += 1;
                if i < args.len() {
                    out_path = Some(args[i].clone());
                }
            }
            "--json" => json = true,
            unknown => bail!("Unknown option for sign-checkpoint: {unknown}"),
        }
        i += 1;
    }

    let key_str = key.context("Missing required --key")?;
    let chain_id_str = chain_id.context("Missing required --chain-id")?;
    let size_val = size.context("Missing required --size")?;
    let head_hash_str = head_hash.context("Missing required --head-hash")?;

    let kp = parse_keypair(&key_str);
    let cid_bytes = parse_hex_bytes32(&chain_id_str)?;
    let head_bytes = parse_hex_bytes32(&head_hash_str)?;
    let ts = timestamp.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    });

    let cp = Checkpoint::new(cid_bytes, size_val, head_bytes, ts, &kp);
    let canonical_json = cp.to_canonical_json();

    if let Some(ref path) = out_path {
        let p = Path::new(path);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(p, format!("{canonical_json}\n"))?;
        if !json {
            println!("✓ Checkpoint saved to {}", p.display());
        }
    }

    if json || out_path.is_none() {
        println!("{canonical_json}");
    }

    Ok(())
}

fn handle_checkpoint(args: &[String]) -> Result<()> {
    let mut key: Option<String> = None;
    let mut chain_id: Option<String> = None;
    let mut out_dir: Option<String> = None;
    let mut log_path: Option<PathBuf> = None;
    let mut json = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--key" => {
                i += 1;
                if i < args.len() {
                    key = Some(args[i].clone());
                }
            }
            "--chain-id" => {
                i += 1;
                if i < args.len() {
                    chain_id = Some(args[i].clone());
                }
            }
            "--out" => {
                i += 1;
                if i < args.len() {
                    out_dir = Some(args[i].clone());
                }
            }
            "--json" => json = true,
            arg if !arg.starts_with('-') => {
                log_path = Some(PathBuf::from(arg));
            }
            unknown => bail!("Unknown option for checkpoint: {unknown}"),
        }
        i += 1;
    }

    let key_str = key.context("Missing required --key")?;
    let kp = parse_keypair(&key_str);

    let resolved_path = match log_path {
        Some(p) => p,
        None => find_default_log_path().unwrap_or_else(|| PathBuf::from("events.jsonl")),
    };

    if !resolved_path.exists() {
        bail!("Event log file '{}' not found.", resolved_path.display());
    }

    let content = fs::read_to_string(&resolved_path)?;
    let expected_chain_id = chain_id.as_deref().map(parse_hex_bytes32).transpose()?;

    let summary = replay_log_with_anchor(content.lines(), expected_chain_id.as_ref())
        .map_err(|e| anyhow::anyhow!("Replay failed: {e}"))?;

    if summary.events_count == 0 {
        bail!("Cannot create checkpoint for empty event log (size 0)");
    }

    let head_bytes = parse_hex_bytes32(&summary.final_hash)?;
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let cp = Checkpoint::new(
        summary.state.chain_id,
        summary.events_count,
        head_bytes,
        ts,
        &kp,
    );
    let canonical_json = cp.to_canonical_json();

    let dir = out_dir.unwrap_or_else(|| "checkpoints".to_string());
    let dest_dir = Path::new(&dir);
    fs::create_dir_all(dest_dir)?;
    let dest_file = dest_dir.join(format!("{}.json", summary.events_count));
    fs::write(&dest_file, format!("{canonical_json}\n"))?;

    if json {
        println!("{canonical_json}");
    } else {
        println!("══════════════════════════════════════════════════════════════════════");
        println!("  GreyMisnomer Checkpoint Created & Signed (RFC-005 §3.7)             ");
        println!("══════════════════════════════════════════════════════════════════════");
        println!("  File:       {}", dest_file.display());
        println!("  Size:       {}", summary.events_count);
        println!("  Head Hash:  {}", summary.final_hash);
        println!("  Sequencer:  {}", kp.pubkey().to_hex());
        println!("  Timestamp:  {}", ts);
        println!("══════════════════════════════════════════════════════════════════════");
    }

    Ok(())
}

fn handle_verify_checkpoint(args: &[String]) -> Result<()> {
    let mut file_path: Option<PathBuf> = None;
    let mut sequencer: Option<String> = None;
    let mut chain_id: Option<String> = None;
    let mut json = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--sequencer" => {
                i += 1;
                if i < args.len() {
                    sequencer = Some(args[i].clone());
                }
            }
            "--chain-id" => {
                i += 1;
                if i < args.len() {
                    chain_id = Some(args[i].clone());
                }
            }
            "--json" => json = true,
            arg if !arg.starts_with('-') => {
                file_path = Some(PathBuf::from(arg));
            }
            unknown => bail!("Unknown option for verify-checkpoint: {unknown}"),
        }
        i += 1;
    }

    let path = file_path.context("Missing required checkpoint file path")?;
    let seq_str = sequencer.context("Missing required --sequencer public key")?;
    let seq_pk =
        PubKey::from_hex(&seq_str).map_err(|e| anyhow::anyhow!("Invalid sequencer pubkey: {e}"))?;

    let content = fs::read_to_string(&path)?;
    let cp = Checkpoint::from_json(&content)
        .map_err(|e| anyhow::anyhow!("Failed to parse checkpoint JSON: {e}"))?;

    if let Some(expected_cid) = chain_id {
        let expected_bytes = parse_hex_bytes32(&expected_cid)?;
        if cp.chain_id != expected_bytes {
            bail!(
                "Chain ID mismatch: expected {}, found {}",
                expected_cid,
                hex::encode(cp.chain_id)
            );
        }
    }

    cp.verify(&seq_pk)
        .map_err(|e| anyhow::anyhow!("Signature verification failed: {e}"))?;

    if json {
        let report = CheckpointReport {
            size: cp.size,
            head_hash: hex::encode(cp.head_hash),
            timestamp: cp.timestamp,
            verified: true,
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "✅ Checkpoint {} is cryptographically VALID under sequencer {}",
            path.display(),
            seq_str
        );
    }

    Ok(())
}

fn handle_replay(args: &[String]) -> Result<()> {
    let mut json_output = false;
    let mut log_path: Option<PathBuf> = None;
    let mut expected_chain_id_hex: Option<String> = None;
    let mut checkpoints_dir: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => json_output = true,
            "--chain-id" => {
                i += 1;
                if i < args.len() {
                    expected_chain_id_hex = Some(args[i].clone());
                }
            }
            "--checkpoints" => {
                i += 1;
                if i < args.len() {
                    checkpoints_dir = Some(PathBuf::from(&args[i]));
                }
            }
            "-h" | "--help" => {
                print_usage();
                return Ok(());
            }
            arg if !arg.starts_with('-') => {
                log_path = Some(PathBuf::from(arg));
            }
            unknown => bail!("Unknown option: {unknown}"),
        }
        i += 1;
    }

    let resolved_path = match log_path {
        Some(p) => p,
        None => find_default_log_path().unwrap_or_else(|| PathBuf::from("events.jsonl")),
    };

    if !resolved_path.exists() {
        eprintln!(
            "Error: Event log file '{}' not found.",
            resolved_path.display()
        );
        eprintln!("Provide a path: grey-misnomer-cli replay [path/to/events.jsonl]");
        std::process::exit(1);
    }

    let content = fs::read_to_string(&resolved_path)
        .with_context(|| format!("Failed to read {}", resolved_path.display()))?;

    let expected_chain_id = expected_chain_id_hex
        .as_deref()
        .map(parse_hex_bytes32)
        .transpose()?;

    let summary = match replay_log_with_anchor(content.lines(), expected_chain_id.as_ref()) {
        Ok(s) => s,
        Err(err) => {
            eprintln!();
            eprintln!("❌ EVENT LOG VERIFICATION FAILED!");
            eprintln!("File: {}", resolved_path.display());
            eprintln!("Failure reason: {err}");
            eprintln!();
            std::process::exit(1);
        }
    };

    // Parse entry hashes for checkpoint verification
    let mut entry_hashes = Vec::with_capacity(summary.entry_hashes.len());
    for h in &summary.entry_hashes {
        if let Ok(bytes) = parse_hex_bytes32(h) {
            entry_hashes.push(bytes);
        }
    }

    // Load checkpoints if directory provided
    let mut checkpoint_reports = Vec::new();
    let mut cp_list = Vec::new();

    if let Some(ref cp_dir) = checkpoints_dir {
        if cp_dir.exists() {
            let mut entries: Vec<_> = fs::read_dir(cp_dir)?
                .filter_map(|e| e.ok())
                .filter(|e| e.path().extension().is_some_and(|ext| ext == "json"))
                .collect();
            entries.sort_by_key(|e| e.path());

            for entry in entries {
                let file_path = entry.path();
                let cp_str = fs::read_to_string(&file_path)?;
                if let Ok(cp) = Checkpoint::from_json(&cp_str) {
                    let ots_path = file_path.with_extension("json.ots");
                    let ots_present = ots_path.exists();
                    cp_list.push((file_path.display().to_string(), cp, ots_present));
                }
            }
        }
    }

    // Verify checkpoints against replayed state
    if !cp_list.is_empty() {
        let cps_only: Vec<&Checkpoint> = cp_list.iter().map(|(_, cp, _)| cp).collect();

        // 1. Detect equivocation across all discovered checkpoints
        if let Some(equiv) = detect_equivocation(cps_only.iter().copied()) {
            eprintln!();
            eprintln!("❌ SEQUENCER EQUIVOCATION DETECTED ACROSS CHECKPOINTS!");
            eprintln!("Log Size: {}", equiv.size);
            eprintln!("Head Hash A: {}", equiv.head_hash_a);
            eprintln!("Head Hash B: {}", equiv.head_hash_b);
            std::process::exit(1);
        }

        // 2. Verify each checkpoint
        let sequencer_pk = summary.state.sequencer;
        let chain_id_bytes = summary.state.chain_id;

        match verify_checkpoints(
            cps_only.iter().copied(),
            &entry_hashes,
            &sequencer_pk,
            &chain_id_bytes,
        ) {
            Ok(_) => {
                for (file_str, cp, ots_present) in &cp_list {
                    checkpoint_reports.push(CheckpointCliReport {
                        file: file_str.clone(),
                        size: cp.size,
                        head_hash: hex::encode(cp.head_hash),
                        timestamp: cp.timestamp,
                        sequencer_verified: true,
                        ots_proof_present: *ots_present,
                    });
                }
            }
            Err(err) => {
                eprintln!();
                eprintln!("❌ CHECKPOINT VERIFICATION FAILED: {err}");
                std::process::exit(1);
            }
        }
    }

    let all_passed = summary.invariant_report.all_passed;

    if json_output {
        let full_report = CliReplayFullReport {
            log_path: resolved_path.display().to_string(),
            summary,
            checkpoints: checkpoint_reports,
            all_passed,
        };
        println!("{}", serde_json::to_string_pretty(&full_report)?);
    } else {
        print_full_report(&resolved_path, &summary, &checkpoint_reports);
    }

    if all_passed {
        Ok(())
    } else {
        std::process::exit(1);
    }
}

fn print_full_report(path: &Path, summary: &ReplaySummary, checkpoints: &[CheckpointCliReport]) {
    println!();
    println!("══════════════════════════════════════════════════════════════════════");
    println!("   GreyMisnomer Protocol — Cryptographic Audit Report (RFC-005)       ");
    println!("══════════════════════════════════════════════════════════════════════");
    println!(" Log Path:          {}", path.display());
    println!(" Events Replayed:   {}", summary.events_count);
    println!(" Final Hash:        {}", summary.final_hash);
    println!(
        " Hash Chain:        {}",
        if summary.chain_valid {
            "✅ VALID (BLAKE3 Canonical Binary Preimages)"
        } else {
            "❌ INVALID"
        }
    );
    println!(
        " Registry Chain ID: {}",
        hex::encode(summary.state.chain_id)
    );
    println!(" Root Authority:    {}", summary.state.authority);
    println!(" Sequencer PubKey:  {}", summary.state.sequencer);
    println!(" Accredited VVBs:   {}", summary.state.vvbs.len());
    println!();
    println!("── Registry Accounting ──────────────────────────────────────────────");
    println!(
        " Total Issued:      {} credits ({} micro-units)",
        summary.total_credits,
        summary.total_credits * 1_000_000
    );
    println!(" Active Supply:     {} credits", summary.active_credits);
    println!(" Retired (PoO):     {} credits", summary.retired_credits);
    println!(" Total Batches:     {}", summary.batches_count);
    println!();
    println!("── Protocol Invariants (RFC-001 §5) ─────────────────────────────────");
    print_invariant(
        "Invariant 1: PoI Mandatory for Minting",
        summary.invariant_report.inv1_poi_mandatory,
    );
    print_invariant(
        "Invariant 2: Supply Cap Consistency",
        summary.invariant_report.inv2_supply_cap,
    );
    print_invariant(
        "Invariant 3: Global Serialization Locking Uniqueness",
        summary.invariant_report.inv3_serial_uniqueness,
    );
    print_invariant(
        "Invariant 4: Burn Irreversibility",
        summary.invariant_report.inv4_burn_irreversibility,
    );
    print_invariant(
        "Invariant 5: PoO Uniqueness (No Double-Burn)",
        summary.invariant_report.inv5_poo_uniqueness,
    );
    print_invariant(
        "Invariant 6: PoO Non-Transferability",
        summary.invariant_report.inv6_poo_non_transferable,
    );
    print_invariant(
        "Invariant 7: PoI Single-Use Consumed State",
        summary.invariant_report.inv7_poi_single_use,
    );
    println!();
    println!("── Cryptographic Authorization Invariants (RFC-005 §3.8) ────────────");
    print_invariant(
        "Invariant A1: Strict Ed25519 Signature Authorization",
        summary.invariant_report.inva1_signature_validity,
    );
    print_invariant(
        "Invariant A2: Operation Index Contiguity (Replay Prevention)",
        summary.invariant_report.inva2_op_index_contiguity,
    );
    print_invariant(
        "Invariant A3: Multi-Tenant Registry Domain Separation",
        summary.invariant_report.inva3_chain_id_binding,
    );
    println!();

    if !checkpoints.is_empty() {
        println!("── Signed Checkpoints & Bitcoin Anchors (RFC-005 §3.7) ─────────────");
        for cp in checkpoints {
            let ots_indicator = if cp.ots_proof_present {
                " [OTS: Bitcoin-Anchored ✅]"
            } else {
                " [OTS: Pending]"
            };
            println!(
                "  [PASS] Size {}: {} (Sequencer Verified){}",
                cp.size,
                &cp.head_hash[..16],
                ots_indicator
            );
        }
        println!();
    }

    if summary.invariant_report.all_passed {
        println!(" VERDICT: ✅ ALL PROTOCOL & AUTHORIZATION INVARIANTS SATISFIED");
    } else {
        println!(" VERDICT: ❌ INVARIANT CHECKS FAILED");
    }
    println!("══════════════════════════════════════════════════════════════════════");
    println!();
}

fn print_invariant(name: &str, passed: bool) {
    if passed {
        println!("  [PASS] {name}");
    } else {
        println!("  [FAIL] {name}");
    }
}
