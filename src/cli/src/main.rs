use anyhow::{bail, Context, Result};
use grey_misnomer_cli::keystore::resolve_keypair;
use grey_misnomer_core::{
    auth::{
        build_authority_event_preimage, build_genesis_preimage, build_vvb_register_payload,
        Keypair, PubKey,
    },
    checkpoint::{detect_equivocation, verify_checkpoints, Checkpoint, CheckpointReport},
    event_log::{
        render_canonical_line, render_canonical_payload, replay_log_with_anchor, EventEntry,
        ReplaySummary,
    },
    manifest::{Manifest, ManifestArchiveOrg, ManifestCheckpoint, ManifestIpfs, ManifestMirrors},
    registry::{apply, RegistryEvent},
};
use serde::Serialize;
use std::env;
use std::fs;
use std::io::{self, Read, Write};
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

#[derive(Serialize)]
struct SequenceOutput {
    status: String,
    seq: u64,
    event_type: String,
    hash: String,
    prev_hash: String,
    canonical_line: String,
    checkpoint_signed: bool,
    checkpoint_size: Option<u64>,
    active_credits: u64,
    retired_credits: u64,
}

#[derive(Serialize)]
struct DryRunOutput {
    status: String,
    valid: bool,
    projected_seq: u64,
    prev_hash: String,
    projected_hash: String,
    event_type: String,
    canonical_line: String,
    active_credits: u64,
    retired_credits: u64,
}

#[derive(Serialize)]
struct InitOutput {
    chain_name: String,
    chain_id: String,
    authority: String,
    sequencer: String,
    genesis_hash: String,
    events_log: String,
    manifest: String,
    regtest_keys_file: Option<String>,
}

#[derive(Serialize)]
struct StatusOutput {
    chain_name: String,
    chain_id: String,
    log_path: String,
    log_size: u64,
    head_hash: String,
    chain_valid: bool,
    root_authority: String,
    active_sequencer: String,
    accredited_vvbs: usize,
    total_issued_credits: u64,
    active_credits: u64,
    retired_credits: u64,
    total_batches: usize,
    latest_checkpoint: Option<u64>,
    invariants_passed: bool,
}

fn print_usage() {
    println!("GreyMisnomer Protocol — Transparency Log & Key Management CLI (RFC-005/RFC-006)");
    println!();
    println!("USAGE:");
    println!("    grey-misnomer-cli [SUBCOMMAND] [FLAGS] [ARGS]");
    println!();
    println!("SUBCOMMANDS:");
    println!("    status [FILE]               Display at-a-glance ledger health, head hash, and credit metrics (like getblockchaininfo)");
    println!("    init [FLAGS]                Bootstrap a fresh ledger (use --regtest for instant local testnet)");
    println!("    replay [FILE]               Replay events.jsonl and verify all protocol & authorization invariants (default)");
    println!("    sequence-tx [FILE]          Validate candidate transaction intent, check invariants, and append to log");
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
    println!("    --keystore <FILE.gmkey>     Passphrase-protected keystore file (RFC-006)");
    println!(
        "    --passphrase <PASS>         Passphrase to decrypt keystore (or GM_PASSPHRASE env)"
    );
    println!("    --sequencer <HEX>           Sequencer public key (64 hex characters)");
    println!("    --size <N>                  Log size for checkpoint");
    println!("    --head-hash <HEX>           Log head hash (32 bytes hex) for checkpoint");
    println!("    --timestamp <U64>           Unix timestamp in seconds for checkpoint");
    println!("    --out <PATH>                Destination output path or directory");
    println!("    --checkpoint                Force checkpoint signature upon sequencing");
    println!("    --dry-run                   Validate candidate transaction without disk writes");
    println!("    --json                      Machine-readable JSON output");
    println!("    -h, --help                  Print help information");
}

fn print_init_usage() {
    println!("GreyMisnomer Init — Bootstrap Sovereign Ledger or Isolated Regtest Mode");
    println!();
    println!("USAGE:");
    println!("    grey-misnomer-cli init [FLAGS]");
    println!();
    println!("FLAGS:");
    println!("    --chain-name <NAME>         Human-readable name for the new registry chain");
    println!("    --authority-key <HEX/SEED>  Seed or private key hex for root authority (generated if omitted)");
    println!("    --sequencer-key <HEX/SEED>  Seed or private key hex for sequencer (generated if omitted)");
    println!("    --out <DIR>                 Target directory for events.jsonl and manifest.json (default: . or ./regtest)");
    println!("    --regtest                   Bootstrap an isolated regtest chain with test participants and keys");
    println!("    --json                      Machine-readable JSON output");
    println!("    -h, --help                  Print help information");
}

fn print_status_usage() {
    println!("GreyMisnomer Status — At-a-glance Ledger & Node Health Monitor");
    println!();
    println!("USAGE:");
    println!("    grey-misnomer-cli status [LOG_FILE] [FLAGS]");
    println!();
    println!("ARGS:");
    println!(
        "    [LOG_FILE]                  Path to events.jsonl (defaults to finding events.jsonl)"
    );
    println!();
    println!("FLAGS:");
    println!("    --json                      Machine-readable JSON output");
    println!("    -h, --help                  Print help information");
}

fn print_sequence_tx_usage() {
    println!("GreyMisnomer Sequencer — Atomic Transaction Ingestion & Invariant Gatekeeper");
    println!();
    println!("USAGE:");
    println!("    grey-misnomer-cli sequence-tx [INPUT_FILE] [FLAGS]");
    println!();
    println!("ARGS:");
    println!("    [INPUT_FILE]                Path to candidate transaction (.gmline, .json, or '-' for stdin)");
    println!();
    println!("FLAGS:");
    println!("    --input <PATH>              Candidate transaction file or '-' for stdin");
    println!("    --log <PATH>                Path to events.jsonl (defaults to events.jsonl)");
    println!("    --chain-id <HEX>            Expected registry domain chain_id (32 bytes hex)");
    println!("    --key <SEED/HEX>            Sequencer private key for signing checkpoints");
    println!("    --keystore <FILE.gmkey>     Passphrase-protected sequencer keystore");
    println!(
        "    --passphrase <PASS>         Passphrase to decrypt keystore (or GM_PASSPHRASE env)"
    );
    println!("    --checkpoint                Force sign a checkpoint for current block");
    println!("    --dry-run                   Simulate and validate without writing to disk");
    println!("    --json                      Output machine-readable JSON");
    println!("    -h, --help                  Print help information");
}

fn parse_input_event(input: &str) -> Result<RegistryEvent> {
    let raw = input.trim();
    let json_str = if let Some(start) = raw.find("```json") {
        let after = &raw[start + 7..];
        if let Some(end) = after.find("```") {
            after[..end].trim()
        } else {
            after.trim()
        }
    } else if let Some(start) = raw.find("```") {
        let after = &raw[start + 3..];
        if let Some(end) = after.find("```") {
            after[..end].trim()
        } else {
            after.trim()
        }
    } else {
        raw
    };

    if let Ok(ev) = serde_json::from_str::<RegistryEvent>(json_str) {
        return Ok(ev);
    }

    if let Ok(entry) = serde_json::from_str::<EventEntry>(json_str) {
        return Ok(entry.event);
    }

    if let Ok(val) = serde_json::from_str::<serde_json::Value>(json_str) {
        if let Ok(ev) = serde_json::from_value::<RegistryEvent>(val.clone()) {
            return Ok(ev);
        }
        if let Ok(entry) = serde_json::from_value::<EventEntry>(val) {
            return Ok(entry.event);
        }
    }

    bail!("Failed to parse candidate transaction as valid RegistryEvent. Ensure it contains 'type' and 'payload' per RFC-005.")
}

fn current_iso_timestamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = secs / 86400;
    let rem_secs = secs % 86400;
    let hours = rem_secs / 3600;
    let minutes = (rem_secs % 3600) / 60;
    let seconds = rem_secs % 60;
    let mut d = days as i64;
    let mut year = 1970;
    loop {
        let leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
        let days_in_year = if leap { 366 } else { 365 };
        if d < days_in_year {
            break;
        }
        d -= days_in_year;
        year += 1;
    }
    let leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    let days_in_months = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1;
    for &dim in &days_in_months {
        if d < dim {
            break;
        }
        d -= dim;
        month += 1;
    }
    let day = d + 1;
    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

fn update_single_manifest(
    p: &Path,
    log_size: u64,
    head_hash: &str,
    new_checkpoint: Option<(&Checkpoint, &str)>,
) -> Result<()> {
    if !p.exists() {
        return Ok(());
    }
    let content = fs::read_to_string(p)?;
    if let Ok(mut manifest) = Manifest::from_json(&content) {
        manifest.log_size = log_size;
        manifest.head_hash = head_hash.to_string();
        manifest.updated_at = current_iso_timestamp();

        if let Some((cp, _)) = new_checkpoint {
            manifest.latest_checkpoint = grey_misnomer_core::manifest::ManifestCheckpoint {
                size: cp.size,
                path: format!("checkpoints/{}.json", cp.size),
                signature: cp.sig.to_hex(),
            };
        }

        if let Ok(pretty) = manifest.to_json_pretty() {
            let _ = fs::write(p, format!("{pretty}\n"));
        }
    }
    Ok(())
}

fn update_manifests_and_checkpoints(
    log_size: u64,
    head_hash: &str,
    new_checkpoint: Option<(&Checkpoint, &str)>,
) -> Result<()> {
    let manifest_paths = ["manifest.json", "docs/manifest.json"];
    for mpath in &manifest_paths {
        let _ = update_single_manifest(Path::new(mpath), log_size, head_hash, new_checkpoint);
    }

    if let Some((cp, sequencer_hex)) = new_checkpoint {
        let cp_manifest_path = Path::new("docs/checkpoints/manifest.json");
        if cp_manifest_path.exists() {
            if let Ok(content) = fs::read_to_string(cp_manifest_path) {
                if let Ok(mut val) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Some(arr) = val.get_mut("checkpoints").and_then(|c| c.as_array_mut()) {
                        let new_cp_entry = serde_json::json!({
                            "size": cp.size,
                            "file": format!("checkpoints/{}.json", cp.size),
                            "head_hash": hex::encode(cp.head_hash),
                            "timestamp": cp.timestamp,
                            "sequencer": sequencer_hex,
                        });
                        if !arr.iter().any(|existing| {
                            existing.get("size").and_then(|s| s.as_u64()) == Some(cp.size)
                        }) {
                            arr.push(new_cp_entry);
                            let _ = fs::write(
                                cp_manifest_path,
                                format!("{}\n", serde_json::to_string_pretty(&val).unwrap()),
                            );
                        }
                    }
                }
            }
        }
    }

    Ok(())
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
        "init" => handle_init(&args[2..]),
        "status" => handle_status(&args[2..]),
        "sequence-tx" => handle_sequence_tx(&args[2..]),
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

fn handle_init(args: &[String]) -> Result<()> {
    let mut chain_name: Option<String> = None;
    let mut authority_key: Option<String> = None;
    let mut sequencer_key: Option<String> = None;
    let mut out_dir: Option<PathBuf> = None;
    let mut regtest = false;
    let mut json = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--chain-name" => {
                i += 1;
                if i < args.len() {
                    chain_name = Some(args[i].clone());
                }
            }
            "--authority-key" => {
                i += 1;
                if i < args.len() {
                    authority_key = Some(args[i].clone());
                }
            }
            "--sequencer-key" => {
                i += 1;
                if i < args.len() {
                    sequencer_key = Some(args[i].clone());
                }
            }
            "--out" | "--out-dir" | "--dir" => {
                i += 1;
                if i < args.len() {
                    out_dir = Some(PathBuf::from(&args[i]));
                }
            }
            "--regtest" => regtest = true,
            "--json" => json = true,
            "-h" | "--help" => {
                print_init_usage();
                return Ok(());
            }
            unknown => bail!("Unknown option for init: {unknown}"),
        }
        i += 1;
    }

    let default_out = if regtest {
        PathBuf::from("regtest")
    } else {
        PathBuf::from(".")
    };
    let dest_dir = out_dir.unwrap_or(default_out);
    fs::create_dir_all(&dest_dir)?;

    let name = chain_name.unwrap_or_else(|| {
        if regtest {
            "GreyMisnomer-Regtest".to_string()
        } else {
            "GreyMisnomer-Local".to_string()
        }
    });

    let authority = match authority_key {
        Some(k) => resolve_keypair(Some(&k), None, None)?,
        None => Keypair::generate(),
    };

    let sequencer = match sequencer_key {
        Some(k) => resolve_keypair(Some(&k), None, None)?,
        None => Keypair::generate(),
    };

    let mut nonce = [0u8; 32];
    let time_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(time_nanos.to_be_bytes());
    let hash_result = hasher.finalize();
    nonce.copy_from_slice(&hash_result);

    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let genesis_msg = build_genesis_preimage(
        &name,
        &authority.pubkey(),
        &sequencer.pubkey(),
        &nonce,
        created_at,
    );

    let genesis_event = RegistryEvent::Genesis {
        chain_name: name.clone(),
        authority: authority.pubkey(),
        sequencer: sequencer.pubkey(),
        nonce,
        created_at,
        authority_sig: authority.sign(&genesis_msg),
    };

    let entry_0 = EventEntry::new(
        0,
        "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        genesis_event.clone(),
    )?;

    let init_state = apply(
        &grey_misnomer_core::registry::RegistryState::new(),
        &genesis_event,
    )
    .map_err(|e| anyhow::anyhow!("Genesis application failed: {e}"))?;
    let chain_id_bytes = init_state.chain_id;
    let chain_id_hex = hex::encode(chain_id_bytes);

    let mut canonical_lines = vec![render_canonical_line(&entry_0)];
    let mut head_hash = entry_0.hash.clone();

    let mut regtest_keys_path: Option<PathBuf> = None;

    if regtest {
        let vvb = Keypair::generate();
        let developer = Keypair::generate();
        let buyer = Keypair::generate();

        let vvb_payload = build_vvb_register_payload(&vvb.pubkey(), "Regtest Verification Bureau");
        let vvb_msg =
            build_authority_event_preimage("vvb-register", &chain_id_bytes, 0, &vvb_payload);
        let vvb_event = RegistryEvent::VvbRegister {
            authority_index: 0,
            vvb: vvb.pubkey(),
            label: "Regtest Verification Bureau".to_string(),
            authority_sig: authority.sign(&vvb_msg),
        };
        let entry_1 = EventEntry::new(1, entry_0.hash.clone(), vvb_event)?;
        head_hash = entry_1.hash.clone();
        canonical_lines.push(render_canonical_line(&entry_1));

        let keys_file = dest_dir.join("regtest_keys.json");
        let regtest_keys = serde_json::json!({
            "chain_name": name,
            "chain_id": chain_id_hex,
            "authority": {
                "pubkey": authority.pubkey().to_hex(),
                "seed": authority.secret_hex(),
            },
            "sequencer": {
                "pubkey": sequencer.pubkey().to_hex(),
                "seed": sequencer.secret_hex(),
            },
            "vvb": {
                "pubkey": vvb.pubkey().to_hex(),
                "seed": vvb.secret_hex(),
            },
            "developer": {
                "pubkey": developer.pubkey().to_hex(),
                "seed": developer.secret_hex(),
            },
            "buyer": {
                "pubkey": buyer.pubkey().to_hex(),
                "seed": buyer.secret_hex(),
            }
        });
        fs::write(
            &keys_file,
            format!("{}\n", serde_json::to_string_pretty(&regtest_keys)?),
        )?;
        regtest_keys_path = Some(keys_file);
    }

    let log_file = dest_dir.join("events.jsonl");
    fs::write(&log_file, format!("{}\n", canonical_lines.join("\n")))?;

    let manifest_file = dest_dir.join("manifest.json");
    let manifest = Manifest {
        manifest_version: 1,
        chain_id: chain_id_hex.clone(),
        log_size: canonical_lines.len() as u64,
        head_hash: head_hash.clone(),
        updated_at: current_iso_timestamp(),
        latest_checkpoint: ManifestCheckpoint {
            size: 0,
            path: "".to_string(),
            signature: "".to_string(),
        },
        mirrors: ManifestMirrors {
            git: format!("file://{}", dest_dir.display()),
            github_pages: "".to_string(),
            ipfs: ManifestIpfs {
                events_cid: None,
                checkpoints_cid: None,
                gateways: Manifest::default_gateways(),
            },
            archive_org: ManifestArchiveOrg { snapshot_url: None },
        },
    };
    fs::write(&manifest_file, format!("{}\n", manifest.to_json_pretty()?))?;

    if json {
        let out = InitOutput {
            chain_name: name,
            chain_id: chain_id_hex,
            authority: authority.pubkey().to_hex(),
            sequencer: sequencer.pubkey().to_hex(),
            genesis_hash: entry_0.hash,
            events_log: log_file.display().to_string(),
            manifest: manifest_file.display().to_string(),
            regtest_keys_file: regtest_keys_path.map(|p| p.display().to_string()),
        };
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("══════════════════════════════════════════════════════════════════════");
        if regtest {
            println!("  GreyMisnomer Isolated Regtest Chain Bootstrapped (RFC-005/006)       ");
        } else {
            println!("  GreyMisnomer Sovereign Ledger Initialized (RFC-005 §3.1)             ");
        }
        println!("══════════════════════════════════════════════════════════════════════");
        println!("  Chain Name:     {}", name);
        println!("  Chain ID:       {}", chain_id_hex);
        println!("  Genesis Hash:   {}", entry_0.hash);
        println!("  Authority:      {}", authority.pubkey().to_hex());
        println!("  Sequencer:      {}", sequencer.pubkey().to_hex());
        println!("  Events Log:     {}", log_file.display());
        println!("  Manifest:       {}", manifest_file.display());
        if let Some(ref kf) = regtest_keys_path {
            println!(
                "  Regtest Keys:   {} (Authority, VVB, Dev, Buyer)",
                kf.display()
            );
        }
        println!("══════════════════════════════════════════════════════════════════════");
        if regtest {
            println!("  Next: Ready for instant local transactions with zero network needed!");
            println!(
                "        cargo run -p grey-misnomer-cli -- replay {}",
                log_file.display()
            );
        }
    }

    Ok(())
}

fn handle_status(args: &[String]) -> Result<()> {
    let mut log_path: Option<PathBuf> = None;
    let mut json = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => json = true,
            "--log-path" | "--log" => {
                i += 1;
                if i < args.len() {
                    log_path = Some(PathBuf::from(&args[i]));
                }
            }
            "-h" | "--help" => {
                print_status_usage();
                return Ok(());
            }
            arg if !arg.starts_with('-') && log_path.is_none() => {
                log_path = Some(PathBuf::from(arg));
            }
            unknown => bail!("Unknown option for status: {unknown}"),
        }
        i += 1;
    }

    let resolved_path = match log_path {
        Some(p) => p,
        None => find_default_log_path().unwrap_or_else(|| PathBuf::from("events.jsonl")),
    };

    if !resolved_path.exists() {
        bail!("Event log file '{}' not found.", resolved_path.display());
    }

    let content = fs::read_to_string(&resolved_path)?;
    let summary = replay_log_with_anchor(content.lines(), None)
        .map_err(|e| anyhow::anyhow!("Ledger verification error: {e}"))?;

    let (active_credits, retired_credits) = compute_state_credits(&summary.state);

    let mut latest_checkpoint: Option<u64> = None;
    let cp_dirs = [
        resolved_path.parent().map(|p| p.join("checkpoints")),
        Some(PathBuf::from("checkpoints")),
        Some(PathBuf::from("docs/checkpoints")),
    ];
    for maybe_dir in cp_dirs.into_iter().flatten() {
        if maybe_dir.exists() {
            if let Ok(entries) = fs::read_dir(maybe_dir) {
                for e in entries.flatten() {
                    if let Some(stem) = e.path().file_stem().and_then(|s| s.to_str()) {
                        if let Ok(sz) = stem.parse::<u64>() {
                            if sz <= summary.events_count
                                && latest_checkpoint.is_none_or(|c| sz > c)
                            {
                                latest_checkpoint = Some(sz);
                            }
                        }
                    }
                }
            }
        }
    }

    let chain_name = if let Some(first_line) = content.lines().next() {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(first_line) {
            val.get("payload")
                .and_then(|p| p.get("chain_name"))
                .and_then(|n| n.as_str())
                .unwrap_or("Unknown")
                .to_string()
        } else {
            "Unknown".to_string()
        }
    } else {
        "Empty".to_string()
    };

    if json {
        let out = StatusOutput {
            chain_name,
            chain_id: hex::encode(summary.state.chain_id),
            log_path: resolved_path.display().to_string(),
            log_size: summary.events_count,
            head_hash: summary.final_hash,
            chain_valid: summary.chain_valid,
            root_authority: summary.state.authority.to_string(),
            active_sequencer: summary.state.sequencer.to_string(),
            accredited_vvbs: summary.state.vvbs.len(),
            total_issued_credits: summary.total_credits,
            active_credits,
            retired_credits,
            total_batches: summary.batches_count,
            latest_checkpoint,
            invariants_passed: summary.invariant_report.all_passed,
        };
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("══════════════════════════════════════════════════════════════════════");
        println!("  GreyMisnomer Node & Ledger Status (getblockchaininfo equivalent)    ");
        println!("══════════════════════════════════════════════════════════════════════");
        println!("  Chain Name:       {}", chain_name);
        println!(
            "  Chain ID:         {}",
            hex::encode(summary.state.chain_id)
        );
        println!("  Log Path:         {}", resolved_path.display());
        println!("  Log Size:         {} events", summary.events_count);
        println!("  Head Hash (Tip):  {}", summary.final_hash);
        println!(
            "  Hash Chain Valid: {}",
            if summary.chain_valid {
                "✅ VALID"
            } else {
                "❌ INVALID"
            }
        );
        println!("  Root Authority:   {}", summary.state.authority);
        println!("  Active Sequencer: {}", summary.state.sequencer);
        println!("  Accredited VVBs:  {}", summary.state.vvbs.len());
        println!("──────────────────────────────────────────────────────────────────────");
        println!("  Total Issued:     {} credits", summary.total_credits);
        println!("  Active Supply:    {} credits", active_credits);
        println!("  Retired (PoO):    {} credits", retired_credits);
        println!("  Batches Count:    {}", summary.batches_count);
        if let Some(cp_size) = latest_checkpoint {
            println!(
                "  Checkpoint Head:  size {} (checkpoints/{}.json)",
                cp_size, cp_size
            );
        } else {
            println!("  Checkpoint Head:  [None yet]");
        }
        println!(
            "  Invariants:       {}",
            if summary.invariant_report.all_passed {
                "✅ ALL PASS (1–7 & A1–A3)"
            } else {
                "❌ INVARIANTS FAILED"
            }
        );
        println!("══════════════════════════════════════════════════════════════════════");
    }

    Ok(())
}

fn handle_sign_checkpoint(args: &[String]) -> Result<()> {
    let mut key: Option<String> = None;
    let mut keystore: Option<String> = None;
    let mut passphrase: Option<String> = None;
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
            "--keystore" => {
                i += 1;
                if i < args.len() {
                    keystore = Some(args[i].clone());
                }
            }
            "--passphrase" => {
                i += 1;
                if i < args.len() {
                    passphrase = Some(args[i].clone());
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

    let kp = resolve_keypair(key.as_deref(), keystore.as_deref(), passphrase.as_deref())?;
    let chain_id_str = chain_id.context("Missing required --chain-id")?;
    let size_val = size.context("Missing required --size")?;
    let head_hash_str = head_hash.context("Missing required --head-hash")?;

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
    let mut keystore: Option<String> = None;
    let mut passphrase: Option<String> = None;
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
            "--keystore" => {
                i += 1;
                if i < args.len() {
                    keystore = Some(args[i].clone());
                }
            }
            "--passphrase" => {
                i += 1;
                if i < args.len() {
                    passphrase = Some(args[i].clone());
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

    let kp = resolve_keypair(key.as_deref(), keystore.as_deref(), passphrase.as_deref())?;

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
            "--sequencer" | "--pubkey" => {
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
            "-h" | "--help" => {
                println!("GreyMisnomer Checkpoint Verifier\n\nUSAGE:\n    grey-misnomer-cli verify-checkpoint <CHECKPOINT_FILE> [--sequencer <PUBKEY>] [--chain-id <HEX>] [--json]");
                return Ok(());
            }
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

fn compute_state_credits(state: &grey_misnomer_core::registry::RegistryState) -> (u64, u64) {
    let mut active: u64 = 0;
    let mut retired: u64 = 0;
    for batch in &state.credits {
        for slice in &batch.slices {
            if let Ok(sz) = slice.range.size() {
                match slice.status {
                    grey_misnomer_core::credit::CreditStatus::Active => {
                        active = active.saturating_add(sz);
                    }
                    grey_misnomer_core::credit::CreditStatus::Retired => {
                        retired = retired.saturating_add(sz);
                    }
                    grey_misnomer_core::credit::CreditStatus::Expired => {}
                }
            }
        }
    }
    (active, retired)
}

fn handle_sequence_tx(args: &[String]) -> Result<()> {
    let mut input_path: Option<String> = None;
    let mut log_path: Option<PathBuf> = None;
    let mut chain_id: Option<String> = None;
    let mut key: Option<String> = None;
    let mut keystore: Option<String> = None;
    let mut passphrase: Option<String> = None;
    let mut force_checkpoint = false;
    let mut dry_run = false;
    let mut json = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--input" => {
                i += 1;
                if i < args.len() {
                    input_path = Some(args[i].clone());
                }
            }
            "--log" => {
                i += 1;
                if i < args.len() {
                    log_path = Some(PathBuf::from(&args[i]));
                }
            }
            "--chain-id" => {
                i += 1;
                if i < args.len() {
                    chain_id = Some(args[i].clone());
                }
            }
            "--key" => {
                i += 1;
                if i < args.len() {
                    key = Some(args[i].clone());
                }
            }
            "--keystore" => {
                i += 1;
                if i < args.len() {
                    keystore = Some(args[i].clone());
                }
            }
            "--passphrase" => {
                i += 1;
                if i < args.len() {
                    passphrase = Some(args[i].clone());
                }
            }
            "--checkpoint" => force_checkpoint = true,
            "--dry-run" => dry_run = true,
            "--json" => json = true,
            "-h" | "--help" => {
                print_sequence_tx_usage();
                return Ok(());
            }
            arg if !arg.starts_with('-') && input_path.is_none() => {
                input_path = Some(arg.to_string());
            }
            unknown => bail!("Unknown option for sequence-tx: {unknown}"),
        }
        i += 1;
    }

    // 1. Read input candidate transaction
    let raw_input = match input_path.as_deref() {
        Some("-") => {
            let mut buf = String::new();
            io::stdin().read_to_string(&mut buf)?;
            buf
        }
        Some(p) => {
            fs::read_to_string(p).with_context(|| format!("Failed to read input file '{p}'"))?
        }
        None => {
            use std::io::IsTerminal;
            if !io::stdin().is_terminal() {
                let mut buf = String::new();
                io::stdin().read_to_string(&mut buf)?;
                buf
            } else {
                bail!("No candidate transaction input specified. Pass file path, --input <PATH>, or pipe via STDIN.");
            }
        }
    };

    // 2. Parse candidate transaction
    let event = parse_input_event(&raw_input)?;

    // 3. Replay current event log
    let resolved_log = match log_path {
        Some(p) => p,
        None => find_default_log_path().unwrap_or_else(|| PathBuf::from("events.jsonl")),
    };

    if !resolved_log.exists() {
        bail!("Event log file '{}' not found.", resolved_log.display());
    }

    let content = fs::read_to_string(&resolved_log)?;
    let expected_chain_id = chain_id.as_deref().map(parse_hex_bytes32).transpose()?;
    let summary = replay_log_with_anchor(content.lines(), expected_chain_id.as_ref())
        .map_err(|e| anyhow::anyhow!("Existing event log verification failed: {e}"))?;

    if summary.events_count == 0 {
        bail!("Event log is empty; genesis event must exist before sequencing transactions.");
    }

    // 4. Invariant Pre-flight: apply event against state
    let new_state = apply(&summary.state, &event)
        .map_err(|e| anyhow::anyhow!("Transaction rejected under protocol state machine: {e}"))?;

    let inv_report = new_state.check_invariants();
    if !inv_report.all_passed {
        bail!("Transaction rejected: state transition violates protocol invariants (RFC-001 §5)");
    }

    let (active_credits, retired_credits) = compute_state_credits(&new_state);

    // 5. Build sequential chained EventEntry
    let next_seq = summary.events_count;
    let prev_hash = summary.final_hash.clone();
    let new_entry = EventEntry::new(next_seq, prev_hash.clone(), event)
        .map_err(|e| anyhow::anyhow!("Failed to construct event entry: {e}"))?;
    let canonical_line = render_canonical_line(&new_entry);
    let (event_type, _) = render_canonical_payload(&new_entry.event);

    // 6. Handle dry-run mode
    if dry_run {
        if json {
            let out = DryRunOutput {
                status: "simulated".to_string(),
                valid: true,
                projected_seq: next_seq,
                prev_hash,
                projected_hash: new_entry.hash.clone(),
                event_type: event_type.to_string(),
                canonical_line: canonical_line.clone(),
                active_credits,
                retired_credits,
            };
            println!("{}", serde_json::to_string_pretty(&out)?);
        } else {
            println!("══════════════════════════════════════════════════════════════════════");
            println!("  GreyMisnomer Pre-Flight Simulation — VALID (Dry Run)                 ");
            println!("══════════════════════════════════════════════════════════════════════");
            println!("  Projected Seq:  {}", next_seq);
            println!("  Event Type:     {}", event_type);
            println!("  Previous Hash:  {}", prev_hash);
            println!("  Projected Hash: {}", new_entry.hash);
            println!("  Active Credits: {}", active_credits);
            println!("  Retired:        {}", retired_credits);
            println!("  Invariants:     ✅ ALL SATISFIED (Invariants 1–7 & A1–A3)");
            println!("──────────────────────────────────────────────────────────────────────");
            println!("  Canonical Line:");
            println!("  {}", canonical_line);
            println!("══════════════════════════════════════════════════════════════════════");
        }
        return Ok(());
    }

    // 7. Atomic append to events.jsonl
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&resolved_log)
        .with_context(|| format!("Failed to open '{}' for append", resolved_log.display()))?;
    writeln!(file, "{}", canonical_line)?;

    // Mirror to docs/events.jsonl only if modifying root repository ledger
    let is_root_ledger =
        resolved_log == Path::new("events.jsonl") || resolved_log == Path::new("./events.jsonl");
    let docs_log = Path::new("docs/events.jsonl");
    if is_root_ledger && docs_log.exists() && docs_log != resolved_log.as_path() {
        if let Ok(mut docs_file) = fs::OpenOptions::new().append(true).open(docs_log) {
            let _ = writeln!(docs_file, "{}", canonical_line);
        }
    }

    let new_log_size = next_seq + 1;
    let mut checkpoint_created: Option<(Checkpoint, String)> = None;

    // 8. Checkpoint generation (every 5 events or on demand)
    let should_checkpoint = force_checkpoint || (new_log_size % 5 == 0);
    let maybe_sequencer =
        resolve_keypair(key.as_deref(), keystore.as_deref(), passphrase.as_deref()).ok();

    let cp_base_dir = if let Some(parent) = resolved_log.parent() {
        if parent.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            parent.to_path_buf()
        }
    } else {
        PathBuf::from(".")
    };

    if should_checkpoint {
        if let Some(ref seq_kp) = maybe_sequencer {
            let head_bytes = parse_hex_bytes32(&new_entry.hash)?;
            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let cp = Checkpoint::new(new_state.chain_id, new_log_size, head_bytes, ts, seq_kp);
            let cp_json = format!("{}\n", cp.to_canonical_json());

            let cp_dir = cp_base_dir.join("checkpoints");
            fs::create_dir_all(&cp_dir)?;
            fs::write(cp_dir.join(format!("{}.json", new_log_size)), &cp_json)?;

            if is_root_ledger && Path::new("docs").exists() {
                let _ = fs::create_dir_all("docs/checkpoints");
                let _ = fs::write(format!("docs/checkpoints/{}.json", new_log_size), &cp_json);
            }

            checkpoint_created = Some((cp, seq_kp.pubkey().to_hex()));
        } else if force_checkpoint {
            bail!("--checkpoint was requested but no sequencer key was provided. Specify --key, --keystore, or GM_PASSPHRASE.");
        }
    }

    // 9. Update distribution manifests
    let cp_ref = checkpoint_created
        .as_ref()
        .map(|(cp, pk)| (cp, pk.as_str()));
    if is_root_ledger {
        let _ = update_manifests_and_checkpoints(new_log_size, &new_entry.hash, cp_ref);
    } else {
        let local_manifest = cp_base_dir.join("manifest.json");
        if local_manifest.exists() {
            let _ = update_single_manifest(&local_manifest, new_log_size, &new_entry.hash, cp_ref);
        }
    }

    // 10. Output success report
    if json {
        let out = SequenceOutput {
            status: "sequenced".to_string(),
            seq: next_seq,
            event_type: event_type.to_string(),
            hash: new_entry.hash.clone(),
            prev_hash,
            canonical_line,
            checkpoint_signed: checkpoint_created.is_some(),
            checkpoint_size: checkpoint_created.as_ref().map(|(cp, _)| cp.size),
            active_credits,
            retired_credits,
        };
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("══════════════════════════════════════════════════════════════════════");
        println!("  GreyMisnomer Transaction Sequenced & Committed (RFC-005 / RFC-006)  ");
        println!("══════════════════════════════════════════════════════════════════════");
        println!("  Sequence Index: {}", next_seq);
        println!("  Event Type:     {}", event_type);
        println!("  Chained Hash:   {}", new_entry.hash);
        println!("  Previous Hash:  {}", prev_hash);
        println!("  Invariants:     ✅ ALL SATISFIED (Invariants 1–7 & A1–A3)");
        println!("  Active Credits: {}", active_credits);
        println!("  Retired:        {}", retired_credits);
        if let Some((ref cp, _)) = checkpoint_created {
            println!("  Checkpoint:     ✅ SIGNED (checkpoints/{}.json)", cp.size);
        } else {
            println!(
                "  Checkpoint:     [None / next due at size {}]",
                ((new_log_size / 5) + 1) * 5
            );
        }
        println!("══════════════════════════════════════════════════════════════════════");
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

    let mut entry_hashes = Vec::with_capacity(summary.entry_hashes.len());
    for h in &summary.entry_hashes {
        if let Ok(bytes) = parse_hex_bytes32(h) {
            entry_hashes.push(bytes);
        }
    }

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

    if !cp_list.is_empty() {
        let cps_only: Vec<&Checkpoint> = cp_list.iter().map(|(_, cp, _)| cp).collect();

        if let Some(equiv) = detect_equivocation(cps_only.iter().copied()) {
            eprintln!();
            eprintln!("❌ SEQUENCER EQUIVOCATION DETECTED ACROSS CHECKPOINTS!");
            eprintln!("Log Size: {}", equiv.size);
            eprintln!("Head Hash A: {}", equiv.head_hash_a);
            eprintln!("Head Hash B: {}", equiv.head_hash_b);
            std::process::exit(1);
        }

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
