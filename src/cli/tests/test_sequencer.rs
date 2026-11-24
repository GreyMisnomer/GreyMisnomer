use grey_misnomer_cli::keystore::{decrypt_gmkey, encrypt_gmkey, resolve_keypair};
use grey_misnomer_core::{
    auth::{build_transfer_preimage, Keypair},
    event_log::replay_log_str,
    registry::RegistryEvent,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn get_events_jsonl_path() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let candidates = [
        manifest_dir.join("../../events.jsonl"),
        manifest_dir.join("../events.jsonl"),
        manifest_dir.join("events.jsonl"),
        PathBuf::from("events.jsonl"),
    ];
    for c in &candidates {
        if c.exists() {
            return c.clone();
        }
    }
    panic!(
        "Could not find events.jsonl from {}",
        manifest_dir.display()
    );
}

fn get_cli_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_grey-misnomer-cli"))
}

#[test]
fn test_cli_keystore_encryption_and_resolution() {
    let kp = Keypair::generate();
    let pass = "MempoolPassphrase2026!";
    let envelope = encrypt_gmkey(&kp, pass, "Sequencer Node Alpha", "Sequencer")
        .expect("keystore encryption succeeds");

    assert_eq!(envelope.version, 1);
    assert_eq!(envelope.pubkey, kp.pubkey().to_hex());

    // 1. Decrypt with correct passphrase
    let unlocked = decrypt_gmkey(&envelope, pass).expect("keystore decryption succeeds");
    assert_eq!(unlocked.pubkey(), kp.pubkey());
    assert_eq!(unlocked.secret_hex(), kp.secret_hex());

    // 2. Reject wrong passphrase
    assert!(decrypt_gmkey(&envelope, "WrongPassword!").is_err());

    // 3. Save to disk and test resolve_keypair helper
    let temp_dir = std::env::temp_dir().join(format!("gm_test_ks_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).expect("create temp dir");
    let ks_path = temp_dir.join("sequencer.gmkey");
    fs::write(&ks_path, serde_json::to_string_pretty(&envelope).unwrap()).expect("write keystore");

    let resolved = resolve_keypair(None, Some(ks_path.to_str().unwrap()), Some(pass))
        .expect("resolve_keypair with keystore");
    assert_eq!(resolved.pubkey(), kp.pubkey());

    // Wrong password resolution must fail
    assert!(resolve_keypair(
        None,
        Some(ks_path.to_str().unwrap()),
        Some("WrongPassword!"),
    )
    .is_err());

    // Raw key resolution
    let resolved_raw = resolve_keypair(Some(&kp.secret_hex()), None, None)
        .expect("resolve_keypair with raw secret");
    assert_eq!(resolved_raw.pubkey(), kp.pubkey());

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_sequence_tx_lifecycle_and_invariants() {
    let cli_bin = get_cli_bin();
    let temp_dir = std::env::temp_dir().join(format!("gm_test_seq_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).expect("create temp dir");

    // Copy current events.jsonl to temporary file
    let temp_log = temp_dir.join("events.jsonl");
    let original_log_path = get_events_jsonl_path();
    let original_log = fs::read_to_string(&original_log_path).expect("read original events.jsonl");
    fs::write(&temp_log, &original_log).expect("write temp log");

    // Replay log to get current state and chain_id
    let summary = replay_log_str(&original_log).expect("replay original log");
    assert_eq!(summary.events_count, 5);
    let chain_id = summary.state.chain_id;

    // Current owner of CC-IN-SOLAR-2026-001 in committed events.jsonl is Infosys
    let infosys = resolve_keypair(
        Some("0f40aafb63d6f2157cef51206b800cc8142fd8204d0bd075d205555129bc7f3b"),
        None,
        None,
    )
    .expect("valid infosys fixture hex key");
    let batch = summary
        .state
        .get_credit("CC-IN-SOLAR-2026-001")
        .expect("batch exists");
    assert_eq!(batch.owner, infosys.pubkey());
    assert_eq!(batch.op_index, 2);

    // Create next owner
    let recipient = Keypair::generate();

    // 1. Construct valid candidate transfer event (op_index 2)
    let transfer_msg =
        build_transfer_preimage(&chain_id, "CC-IN-SOLAR-2026-001", 2, &recipient.pubkey());
    let valid_event = RegistryEvent::Transfer {
        credit_id: "CC-IN-SOLAR-2026-001".to_string(),
        op_index: 2,
        new_owner: recipient.pubkey(),
        owner_sig: infosys.sign(&transfer_msg),
    };

    let valid_event_json = serde_json::to_string(&valid_event).unwrap();
    let tx_file = temp_dir.join("candidate_transfer.gmline");
    fs::write(&tx_file, &valid_event_json).expect("write tx file");

    // 2. Test --dry-run (must validate successfully without modifying log)
    let dry_run_output = Command::new(&cli_bin)
        .arg("sequence-tx")
        .arg("--input")
        .arg(&tx_file)
        .arg("--log")
        .arg(&temp_log)
        .arg("--dry-run")
        .arg("--json")
        .output()
        .expect("execute dry-run");

    assert!(
        dry_run_output.status.success(),
        "Dry run failed: {:?}",
        String::from_utf8_lossy(&dry_run_output.stderr)
    );
    let dry_stdout = String::from_utf8_lossy(&dry_run_output.stdout);
    assert!(dry_stdout.contains("\"valid\": true"));
    assert!(dry_stdout.contains("\"projected_seq\": 5"));

    // Verify temp_log size is STILL 5 lines
    let log_after_dry_run = fs::read_to_string(&temp_log).unwrap();
    assert_eq!(log_after_dry_run.lines().count(), 5);

    // 3. Test sequencing and committing the transaction
    let seq_output = Command::new(&cli_bin)
        .arg("sequence-tx")
        .arg("--input")
        .arg(&tx_file)
        .arg("--log")
        .arg(&temp_log)
        .arg("--json")
        .output()
        .expect("execute sequence-tx");

    assert!(
        seq_output.status.success(),
        "Sequence failed: {:?}",
        String::from_utf8_lossy(&seq_output.stderr)
    );
    let seq_stdout = String::from_utf8_lossy(&seq_output.stdout);
    assert!(seq_stdout.contains("\"status\": \"sequenced\""));
    assert!(seq_stdout.contains("\"seq\": 5"));
    assert!(seq_stdout.contains("\"event_type\": \"transfer\""));

    // Verify temp_log now has 6 lines
    let log_after_sequence = fs::read_to_string(&temp_log).unwrap();
    assert_eq!(log_after_sequence.lines().count(), 6);

    // Replay updated log to confirm all invariants pass
    let new_summary = replay_log_str(&log_after_sequence).expect("replay re-sequenced log");
    assert_eq!(new_summary.events_count, 6);
    assert!(new_summary.chain_valid);
    assert!(new_summary.invariant_report.all_passed);
    assert_eq!(
        new_summary
            .state
            .get_credit("CC-IN-SOLAR-2026-001")
            .unwrap()
            .owner,
        recipient.pubkey()
    );

    // 4. Test Replay Rejection (Invariant A2): attempting to sequence same op_index 2 must fail!
    let replay_output = Command::new(&cli_bin)
        .arg("sequence-tx")
        .arg("--input")
        .arg(&tx_file)
        .arg("--log")
        .arg(&temp_log)
        .output()
        .expect("execute duplicate sequence-tx");

    assert!(!replay_output.status.success());
    let replay_err = String::from_utf8_lossy(&replay_output.stderr);
    assert!(
        replay_err.contains("operation index mismatch") || replay_err.contains("BadOpIndex"),
        "Expected replay rejection error, got: {replay_err}"
    );

    // 5. Test Forged Signature Rejection (Invariant A1):
    let impostor = Keypair::generate();
    let recipient_2 = Keypair::generate();
    let forged_msg =
        build_transfer_preimage(&chain_id, "CC-IN-SOLAR-2026-001", 3, &recipient_2.pubkey());
    let forged_event = RegistryEvent::Transfer {
        credit_id: "CC-IN-SOLAR-2026-001".to_string(),
        op_index: 3,
        new_owner: recipient_2.pubkey(),
        owner_sig: impostor.sign(&forged_msg), // signed by impostor, not recipient (current owner)
    };
    let forged_file = temp_dir.join("forged_transfer.gmline");
    fs::write(&forged_file, serde_json::to_string(&forged_event).unwrap()).unwrap();

    let forged_output = Command::new(&cli_bin)
        .arg("sequence-tx")
        .arg("--input")
        .arg(&forged_file)
        .arg("--log")
        .arg(&temp_log)
        .output()
        .expect("execute forged sequence-tx");

    assert!(!forged_output.status.success());
    let forged_err = String::from_utf8_lossy(&forged_output.stderr);
    assert!(
        forged_err.contains("BadSignature") || forged_err.contains("signature"),
        "Expected bad signature rejection, got: {forged_err}"
    );

    // 6. Test Markdown Code Block parsing (Issue mempool submission)
    let issue_markdown = format!(
        "### GreyMisnomer RFC-006 Signed Event Submission\n\n\
        ```json\n\
        {}\n\
        ```\n",
        valid_event_json
    );
    let md_file = temp_dir.join("issue_body.md");
    fs::write(&md_file, issue_markdown).unwrap();

    // Replay back to seq 5 log to test issue extraction
    fs::write(&temp_log, &original_log).unwrap();
    let md_seq_output = Command::new(&cli_bin)
        .arg("sequence-tx")
        .arg("--input")
        .arg(&md_file)
        .arg("--log")
        .arg(&temp_log)
        .arg("--json")
        .output()
        .expect("execute sequence-tx with markdown");

    assert!(
        md_seq_output.status.success(),
        "Markdown issue parsing failed: {:?}",
        String::from_utf8_lossy(&md_seq_output.stderr)
    );
    let md_stdout = String::from_utf8_lossy(&md_seq_output.stdout);
    assert!(md_stdout.contains("\"status\": \"sequenced\""));
    assert!(md_stdout.contains("\"seq\": 5"));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_sequence_tx_with_keystore_checkpoint() {
    let cli_bin = get_cli_bin();
    let temp_dir = std::env::temp_dir().join(format!("gm_test_cp_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).expect("create temp dir");

    let temp_log = temp_dir.join("events.jsonl");
    let original_log_path = get_events_jsonl_path();
    let original_log = fs::read_to_string(&original_log_path).expect("read original events.jsonl");
    fs::write(&temp_log, &original_log).expect("write temp log");

    let summary = replay_log_str(&original_log).expect("replay original log");
    let chain_id = summary.state.chain_id;

    // Encrypt committed sequencer fixture keypair into a .gmkey
    let sequencer = resolve_keypair(
        Some("5639156043909ee807959732549ed904b628d8e3deec39b741f2e933320e1f9a"),
        None,
        None,
    )
    .expect("valid sequencer fixture hex key");
    assert_eq!(summary.state.sequencer, sequencer.pubkey());

    let pass = "AutonomousSequencer2026!";
    let envelope = encrypt_gmkey(&sequencer, pass, "Sequencer Node Alpha", "Sequencer").unwrap();
    let keystore_file = temp_dir.join("sequencer.gmkey");
    fs::write(
        &keystore_file,
        serde_json::to_string_pretty(&envelope).unwrap(),
    )
    .unwrap();

    // Prepare valid candidate transaction signed by Infosys (op_index 2)
    let infosys = resolve_keypair(
        Some("0f40aafb63d6f2157cef51206b800cc8142fd8204d0bd075d205555129bc7f3b"),
        None,
        None,
    )
    .expect("valid infosys fixture hex key");
    let recipient = Keypair::generate();
    let transfer_msg =
        build_transfer_preimage(&chain_id, "CC-IN-SOLAR-2026-001", 2, &recipient.pubkey());
    let valid_event = RegistryEvent::Transfer {
        credit_id: "CC-IN-SOLAR-2026-001".to_string(),
        op_index: 2,
        new_owner: recipient.pubkey(),
        owner_sig: infosys.sign(&transfer_msg),
    };

    let tx_file = temp_dir.join("transfer.gmline");
    fs::write(&tx_file, serde_json::to_string(&valid_event).unwrap()).unwrap();

    // Run sequence-tx with --checkpoint, --keystore, and --passphrase
    let seq_output = Command::new(&cli_bin)
        .current_dir(&temp_dir)
        .arg("sequence-tx")
        .arg("--input")
        .arg(&tx_file)
        .arg("--log")
        .arg(&temp_log)
        .arg("--checkpoint")
        .arg("--keystore")
        .arg(&keystore_file)
        .arg("--passphrase")
        .arg(pass)
        .arg("--json")
        .output()
        .expect("execute sequence-tx with checkpoint");

    assert!(
        seq_output.status.success(),
        "Sequencing failed: {:?}",
        String::from_utf8_lossy(&seq_output.stderr)
    );
    let stdout = String::from_utf8_lossy(&seq_output.stdout);
    assert!(stdout.contains("\"checkpoint_signed\": true"));
    assert!(stdout.contains("\"checkpoint_size\": 6"));

    // Verify checkpoint file was generated
    let cp_file = temp_dir.join("checkpoints/6.json");
    assert!(
        cp_file.exists(),
        "Checkpoint file checkpoints/6.json was not created"
    );

    // Verify checkpoint using verify-checkpoint subcommand
    let verify_output = Command::new(&cli_bin)
        .arg("verify-checkpoint")
        .arg(&cp_file)
        .arg("--sequencer")
        .arg(sequencer.pubkey().to_hex())
        .output()
        .expect("execute verify-checkpoint");

    assert!(
        verify_output.status.success(),
        "Checkpoint verification failed: {:?}",
        String::from_utf8_lossy(&verify_output.stderr)
    );
    let verify_stdout = String::from_utf8_lossy(&verify_output.stdout);
    assert!(verify_stdout.contains("cryptographically VALID"));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_init_and_status() {
    let cli_bin = get_cli_bin();
    let temp_dir = std::env::temp_dir().join(format!("gm_test_init_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).expect("create temp dir");

    // 1. Run init --regtest --json
    let init_output = Command::new(&cli_bin)
        .arg("init")
        .arg("--regtest")
        .arg("--out")
        .arg(&temp_dir)
        .arg("--json")
        .output()
        .expect("execute init --regtest");

    assert!(
        init_output.status.success(),
        "init --regtest failed: {:?}",
        String::from_utf8_lossy(&init_output.stderr)
    );
    let stdout = String::from_utf8_lossy(&init_output.stdout);
    assert!(stdout.contains("\"chain_name\": \"GreyMisnomer-Regtest\""));
    assert!(stdout.contains("\"events_log\":"));

    let log_file = temp_dir.join("events.jsonl");
    assert!(log_file.exists());
    let manifest_file = temp_dir.join("manifest.json");
    assert!(manifest_file.exists());
    let keys_file = temp_dir.join("regtest_keys.json");
    assert!(keys_file.exists());

    // 2. Replay initialized regtest log
    let replay_output = Command::new(&cli_bin)
        .arg("replay")
        .arg(&log_file)
        .output()
        .expect("replay regtest log");

    assert!(
        replay_output.status.success(),
        "replay failed: {:?}",
        String::from_utf8_lossy(&replay_output.stderr)
    );
    let replay_stdout = String::from_utf8_lossy(&replay_output.stdout);
    assert!(replay_stdout.contains("ALL PROTOCOL & AUTHORIZATION INVARIANTS SATISFIED"));

    // 3. Test status subcommand on regtest log
    let status_output = Command::new(&cli_bin)
        .arg("status")
        .arg(&log_file)
        .arg("--json")
        .output()
        .expect("status check");

    assert!(
        status_output.status.success(),
        "status failed: {:?}",
        String::from_utf8_lossy(&status_output.stderr)
    );
    let status_stdout = String::from_utf8_lossy(&status_output.stdout);
    assert!(status_stdout.contains("\"chain_name\": \"GreyMisnomer-Regtest\""));
    assert!(status_stdout.contains("\"chain_valid\": true"));
    assert!(status_stdout.contains("\"log_size\": 2"));
    assert!(status_stdout.contains("\"invariants_passed\": true"));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_ots_digest_verification_and_require_ots_flag() {
    let cli_bin = get_cli_bin();
    let log_path = get_events_jsonl_path();

    // 1. Committed events.jsonl vs stale events.jsonl.ots must NEVER report Bitcoin-Anchored ✅
    let replay_out = Command::new(&cli_bin)
        .arg("replay")
        .arg(&log_path)
        .arg("--json")
        .output()
        .expect("run cli replay");
    assert!(replay_out.status.success());
    let json: serde_json::Value =
        serde_json::from_slice(&replay_out.stdout).expect("valid replay json");
    assert_eq!(json["log_ots"]["proof_present"], true);
    assert_eq!(json["log_ots"]["digest_matches"], false);
    assert_eq!(json["log_ots"]["status"], "digest-mismatch");

    // 2. --require-ots must exit non-zero on stale .ots proof
    let strict_fail = Command::new(&cli_bin)
        .arg("replay")
        .arg(&log_path)
        .arg("--require-ots")
        .output()
        .expect("run cli replay --require-ots");
    assert!(
        !strict_fail.status.success(),
        "--require-ots must fail on stale .ots proof"
    );

    // 3. Synthetic matching .ots proof passes --require-ots
    let temp_dir = std::env::temp_dir().join(format!("gm_test_ots_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();
    let temp_log = temp_dir.join("events.jsonl");
    let raw_events = fs::read(&log_path).unwrap();
    fs::write(&temp_log, &raw_events).unwrap();

    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(&raw_events);
    let mut synthetic_ots = Vec::new();
    synthetic_ots.extend_from_slice(&grey_misnomer_core::ots::OTS_HEADER_MAGIC);
    synthetic_ots.push(1); // version 1
    synthetic_ots.push(0x08); // OP_SHA256
    synthetic_ots.extend_from_slice(&digest);
    synthetic_ots.push(0x00); // OP_ATTESTATION
    synthetic_ots.extend_from_slice(&grey_misnomer_core::ots::BITCOIN_ATTESTATION_TAG);
    synthetic_ots.push(3); // varbytes payload len (height 972000 -> 3 bytes LEB128)
                           // 972000 = 0xED4E0 -> LEB128: [0xe0, 0xa9, 0x3b]
    synthetic_ots.extend_from_slice(&[0xe0, 0xa9, 0x3b]);
    fs::write(temp_dir.join("events.jsonl.ots"), synthetic_ots).unwrap();

    let strict_pass = Command::new(&cli_bin)
        .arg("replay")
        .arg(&temp_log)
        .arg("--require-ots")
        .arg("--json")
        .output()
        .expect("run cli replay --require-ots on valid synthetic ots");
    assert!(
        strict_pass.status.success(),
        "--require-ots failed unexpectedly: {}",
        String::from_utf8_lossy(&strict_pass.stderr)
    );
    let pass_json: serde_json::Value =
        serde_json::from_slice(&strict_pass.stdout).expect("valid json");
    assert_eq!(pass_json["log_ots"]["digest_matches"], true);
    assert_eq!(pass_json["log_ots"]["status"], "bitcoin-anchored");
    assert_eq!(pass_json["log_ots"]["bitcoin_blocks"][0], 972000);

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_export_tiles() {
    let cli_bin = get_cli_bin();
    let events_path = get_events_jsonl_path();

    let temp_dir = std::env::temp_dir().join("gm_test_cli_export_tiles");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let output_tiles = temp_dir.join("tiles");

    let status = Command::new(&cli_bin)
        .arg("export-tiles")
        .arg(&events_path)
        .arg("--out")
        .arg(&output_tiles)
        .arg("--json")
        .output()
        .expect("run cli export-tiles");

    assert!(
        status.status.success(),
        "export-tiles failed: {}",
        String::from_utf8_lossy(&status.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&status.stdout).expect("valid json output");

    assert!(report["total_events"].as_u64().unwrap() > 0);
    assert!(report["entry_tiles_created"].as_u64().unwrap() >= 1);
    assert!(output_tiles.join("checkpoint").exists());

    let _ = fs::remove_dir_all(&temp_dir);
}
