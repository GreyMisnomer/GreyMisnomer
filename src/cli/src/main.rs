use anyhow::{Context, Result};
use grey_misnomer_core::event_log::replay_log_str;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

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

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let mut json_output = false;
    let mut log_path: Option<PathBuf> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => json_output = true,
            "replay" => {}
            "-h" | "--help" => {
                println!("GreyMisnomer Protocol — Event Log Replayer (RFC-004)");
                println!();
                println!("USAGE:");
                println!("    grey-misnomer-cli [FLAGS] [FILE]");
                println!("    grey-misnomer-cli replay [FLAGS] [FILE]");
                println!();
                println!("FLAGS:");
                println!("    --json       Output raw ReplaySummary JSON");
                println!("    -h, --help   Prints help information");
                println!();
                println!("ARGS:");
                println!("    <FILE>       Path to events.jsonl [default: events.jsonl]");
                return Ok(());
            }
            arg if !arg.starts_with('-') => {
                log_path = Some(PathBuf::from(arg));
            }
            unknown => {
                eprintln!("Unknown argument: {unknown}");
                eprintln!("Run with --help for usage.");
                std::process::exit(1);
            }
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
        eprintln!("Provide a path: grey-misnomer-cli [path/to/events.jsonl]");
        std::process::exit(1);
    }

    let content = fs::read_to_string(&resolved_path)
        .with_context(|| format!("Failed to read {}", resolved_path.display()))?;

    match replay_log_str(&content) {
        Ok(summary) => {
            if json_output {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                print_report(&resolved_path, &summary);
            }
            Ok(())
        }
        Err(err) => {
            eprintln!();
            eprintln!("❌ EVENT LOG VERIFICATION FAILED!");
            eprintln!("File: {}", resolved_path.display());
            eprintln!("Failure reason: {err}");
            eprintln!();
            std::process::exit(1);
        }
    }
}

fn print_report(path: &Path, summary: &grey_misnomer_core::event_log::ReplaySummary) {
    println!();
    println!("══════════════════════════════════════════════════════════════════════");
    println!("   GreyMisnomer Protocol — Event Log Verification Report (RFC-004)    ");
    println!("══════════════════════════════════════════════════════════════════════");
    println!(" Log Path:          {}", path.display());
    println!(" Events Replayed:   {}", summary.events_count);
    println!(" Final Hash:        {}", summary.final_hash);
    println!(
        " Hash Chain:        {}",
        if summary.chain_valid {
            "✅ VALID (BLAKE3 Cryptographic Chaining)"
        } else {
            "❌ INVALID"
        }
    );
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
    if summary.invariant_report.all_passed {
        println!(" VERDICT: ✅ ALL 7 PROTOCOL INVARIANTS SATISFIED (STATE VERIFIED)");
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
