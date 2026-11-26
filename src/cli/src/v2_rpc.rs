//! RFC-008 §9 & Stage 4.6: v2 UCO Transaction Signing & Daemon Localhost RPC Helpers.
//!
//! Enables operators (`Alice` & `Bob`) to mint credits, split/transfer slices
//! across peers, retire offsets permanently, and inspect live UCOs/peers/mempool
//! on `greymisnomerd` (`127.0.0.1:9482`) using pure integer micro-unit math.

use crate::keystore::resolve_keypair;
use anyhow::{bail, Context, Result};
use grey_misnomer_core::auth::{hash_log_leaf, Keypair, PubKey, Signature};
use grey_misnomer_core::uco::{OutPoint, PoOClaimType, MAX_UCO_MICRO_UNITS};
use grey_misnomer_core::uco_engine::{
    UcoBurnTx, UcoMintTx, UcoSplitTransferTx, UcoTransaction, UcoTransferOutputSpec,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_RPC_URL: &str = "http://127.0.0.1:9482";
const MICRO_UNITS_PER_CREDIT: u64 = 1_000_000;

fn deserialize_u64_or_string<'de, D>(deserializer: D) -> std::result::Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let val = serde_json::Value::deserialize(deserializer)?;
    match val {
        serde_json::Value::Number(n) => n
            .as_u64()
            .ok_or_else(|| serde::de::Error::custom("expected unsigned integer u64")),
        serde_json::Value::String(s) => s
            .parse::<u64>()
            .map_err(|e| serde::de::Error::custom(format!("invalid u64 string: {e}"))),
        _ => Err(serde::de::Error::custom("expected u64 or numeric string")),
    }
}

fn deserialize_outpoint_or_string<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let val = serde_json::Value::deserialize(deserializer)?;
    match val {
        serde_json::Value::String(s) => Ok(s),
        serde_json::Value::Object(_) => {
            let op: OutPoint = serde_json::from_value(val).map_err(serde::de::Error::custom)?;
            Ok(op.to_string())
        }
        _ => Err(serde::de::Error::custom(
            "expected outpoint string or OutPoint object",
        )),
    }
}

#[derive(Deserialize)]
struct DaemonUcoView {
    #[serde(deserialize_with = "deserialize_outpoint_or_string")]
    pub outpoint: String,
    pub project_id: String,
    pub batch_id: String,
    pub vintage_year: u16,
    #[serde(deserialize_with = "deserialize_u64_or_string")]
    pub start_micro_unit: u64,
    #[serde(deserialize_with = "deserialize_u64_or_string")]
    pub end_micro_unit: u64,
    #[serde(deserialize_with = "deserialize_u64_or_string")]
    pub micro_units: u64,
    pub owner: String,
    #[serde(deserialize_with = "deserialize_u64_or_string")]
    pub op_index: u64,
    #[serde(default, deserialize_with = "deserialize_u64_or_string")]
    pub challenge_until_epoch: u64,
}

#[derive(Serialize)]
struct UcoDisplayView {
    pub outpoint: String,
    pub project_id: String,
    pub batch_id: String,
    pub vintage_year: u16,
    pub credits: String,
    pub micro_units: String,
    pub range: String,
    pub owner: String,
    pub op_index: String,
}

/// Parses decimal credit strings (e.g. `"10"`, `"2.5"`) into exact integer micro-units (`u64`).
/// Uses integer arithmetic exclusively (no floating point).
pub fn parse_credits_to_micro_units(s: &str) -> Result<u64> {
    let trimmed = s.trim();
    if trimmed.is_empty() || trimmed.starts_with('-') {
        bail!("Invalid credit amount '{s}': must be positive");
    }
    let parts: Vec<&str> = trimmed.split('.').collect();
    if parts.len() > 2 {
        bail!("Invalid decimal credit format '{s}'");
    }

    let whole_str = if parts[0].is_empty() { "0" } else { parts[0] };
    let whole: u64 = whole_str
        .parse()
        .with_context(|| format!("Invalid whole credit amount in '{s}'"))?;

    let frac: u64 = if parts.len() == 2 {
        let f = parts[1];
        if f.len() > 6 {
            bail!("Credit fraction '{s}' exceeds 6 decimal places (micro-unit resolution)");
        }
        if !f.chars().all(|c| c.is_ascii_digit()) {
            bail!("Invalid fractional digits in '{s}'");
        }
        let padded = format!("{f:0<6}");
        padded.parse()?
    } else {
        0
    };

    let total = whole
        .checked_mul(MICRO_UNITS_PER_CREDIT)
        .and_then(|w| w.checked_add(frac))
        .context("Credit amount overflows u64")?;

    if total == 0 || total > MAX_UCO_MICRO_UNITS {
        bail!("Credit micro-units {total} out of range (1..={MAX_UCO_MICRO_UNITS})");
    }
    Ok(total)
}

pub fn format_micro_units(micro: u64) -> String {
    let whole = micro / MICRO_UNITS_PER_CREDIT;
    let rem = micro % MICRO_UNITS_PER_CREDIT;
    if rem == 0 {
        whole.to_string()
    } else {
        let frac = format!("{rem:06}");
        format!("{whole}.{}", frac.trim_end_matches('0'))
    }
}

fn parse_32byte_hex(s: &str) -> Result<[u8; 32]> {
    let trimmed = s.trim();
    if trimmed.len() != 64 {
        bail!("Expected 64 hex chars (32 bytes), got {}", trimmed.len());
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(trimmed, &mut out).context("Invalid hex string")?;
    Ok(out)
}

fn resolve_bearer_token(cookie_arg: Option<&str>) -> Result<Option<String>> {
    let Some(raw) = cookie_arg else {
        return Ok(None);
    };
    let path = std::path::Path::new(raw);
    if path.exists() {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read cookie file {}", path.display()))?;
        let trimmed = content.trim();
        let token = trimmed.strip_prefix("__cookie__:").unwrap_or(trimmed);
        return Ok(Some(token.to_string()));
    }
    Ok(Some(raw.trim().to_string()))
}

pub fn http_rpc_request(
    rpc_url: &str,
    method: &str,
    path: &str,
    body_json: Option<&str>,
    auth_token: Option<&str>,
) -> Result<String> {
    let clean = rpc_url.trim_end_matches('/');
    let without_proto = clean
        .strip_prefix("http://")
        .or_else(|| clean.strip_prefix("https://"))
        .unwrap_or(clean);
    let mut parts = without_proto.split(':');
    let host = parts.next().unwrap_or("127.0.0.1");
    let port: u16 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(9482);

    let mut stream = TcpStream::connect((host, port))
        .with_context(|| format!("Failed to connect to greymisnomerd RPC at {host}:{port}"))?;

    let mut req =
        format!("{method} {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n");
    if let Some(tok) = auth_token {
        req.push_str(&format!("Authorization: Bearer {tok}\r\n"));
    }
    if let Some(body) = body_json {
        req.push_str("Content-Type: application/json\r\n");
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
        req.push_str("\r\n");
        req.push_str(body);
    } else {
        req.push_str("\r\n");
    }

    stream.write_all(req.as_bytes())?;
    let mut resp_bytes = Vec::new();
    stream.read_to_end(&mut resp_bytes)?;

    let resp_str = String::from_utf8_lossy(&resp_bytes);
    let (headers_part, resp_body) = match resp_str.find("\r\n\r\n") {
        Some(idx) => (&resp_str[..idx], &resp_str[idx + 4..]),
        None => ("", resp_str.as_ref()),
    };

    let status_code: u16 = headers_part
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(500);

    if !(200..300).contains(&status_code) {
        bail!("Daemon RPC {method} {path} returned HTTP {status_code}: {resp_body}");
    }

    Ok(resp_body.to_string())
}

fn read_json_file(path: &str) -> Result<serde_json::Value> {
    let txt = fs::read_to_string(path).with_context(|| format!("Failed to read {path}"))?;
    serde_json::from_str(&txt).with_context(|| format!("Invalid JSON in {path}"))
}

fn extract_actor_from_keys_bundle(
    keys_path: &str,
    role: &str,
) -> Result<(Keypair, Option<[u8; 32]>)> {
    let val = read_json_file(keys_path)?;
    let chain_id = val
        .get("chain_id")
        .and_then(|v| v.as_str())
        .and_then(|s| parse_32byte_hex(s).ok());
    let seed = val
        .get(role)
        .and_then(|a| a.get("seed"))
        .and_then(|s| s.as_str())
        .with_context(|| format!("Role '{role}' seed not found in {keys_path}"))?;
    let kp = Keypair::from_hex(seed).map_err(|e| anyhow::anyhow!("Invalid {role} key: {e}"))?;
    Ok((kp, chain_id))
}

fn extract_pubkey_from_keys_bundle(keys_path: &str, role: &str) -> Result<PubKey> {
    let val = read_json_file(keys_path)?;
    let pk_hex = val
        .get(role)
        .and_then(|a| a.get("pubkey"))
        .and_then(|s| s.as_str())
        .with_context(|| format!("Role '{role}' pubkey not found in {keys_path}"))?;
    PubKey::from_hex(pk_hex).map_err(|e| anyhow::anyhow!("Invalid {role} pubkey: {e}"))
}

fn resolve_actor_key_and_cid(
    keys_path: Option<&str>,
    actor: &str,
    key_hex: Option<&str>,
    keystore_path: Option<&str>,
    passphrase: Option<&str>,
) -> Result<(Keypair, Option<[u8; 32]>)> {
    if let Some(kp_file) = keys_path {
        if key_hex.is_none() && keystore_path.is_none() {
            return extract_actor_from_keys_bundle(kp_file, actor);
        }
    }
    let kp = resolve_keypair(key_hex, keystore_path, passphrase)?;
    Ok((kp, None))
}

fn resolve_chain_id(
    chain_id_hex: Option<&str>,
    genesis_path: Option<&str>,
    keys_chain_id: Option<[u8; 32]>,
    rpc_url: &str,
    token: Option<&str>,
) -> Result<[u8; 32]> {
    if let Some(hex) = chain_id_hex {
        return parse_32byte_hex(hex);
    }
    if let Some(g_path) = genesis_path {
        let g = read_json_file(g_path)?;
        if let Some(cid) = g.get("chain_id").and_then(|v| v.as_str()) {
            return parse_32byte_hex(cid);
        }
    }
    if let Some(cid) = keys_chain_id {
        return Ok(cid);
    }
    let body = http_rpc_request(rpc_url, "GET", "/v1/chain/status", None, token)?;
    let status: serde_json::Value = serde_json::from_str(&body)?;
    let cid_str = status
        .get("chain_id")
        .and_then(|v| v.as_str())
        .context("Daemon /v1/chain/status missing chain_id")?;
    parse_32byte_hex(cid_str)
}

pub fn handle_tx_mint(args: &[String]) -> Result<()> {
    let mut keys_path: Option<String> = None;
    let mut genesis_path: Option<String> = None;
    let mut chain_id_hex: Option<String> = None;
    let mut vvb_key_hex: Option<String> = None;
    let mut keystore_path: Option<String> = None;
    let mut passphrase: Option<String> = None;
    let mut owner_hex: Option<String> = None;
    let mut project_id = "SOLAR-ALPHA-01".to_string();
    let mut batch_id: Option<String> = None;
    let mut vintage_year: u16 = 2026;
    let mut micro_units: Option<u64> = None;
    let mut credits_str: Option<String> = None;
    let mut mrv_data: Option<String> = None;
    let mut mrv_root_hex: Option<String> = None;
    let mut mirrors: Vec<String> = Vec::new();
    let mut challenge_epochs: u64 = 0;
    let mut rpc_url = DEFAULT_RPC_URL.to_string();
    let mut cookie_arg: Option<String> = None;
    let mut dry_run = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--keys" => {
                i += 1;
                keys_path = args.get(i).cloned();
            }
            "--genesis" => {
                i += 1;
                genesis_path = args.get(i).cloned();
            }
            "--chain-id" => {
                i += 1;
                chain_id_hex = args.get(i).cloned();
            }
            "--vvb-key" | "--key" => {
                i += 1;
                vvb_key_hex = args.get(i).cloned();
            }
            "--keystore" => {
                i += 1;
                keystore_path = args.get(i).cloned();
            }
            "--passphrase" => {
                i += 1;
                passphrase = args.get(i).cloned();
            }
            "--owner" => {
                i += 1;
                owner_hex = args.get(i).cloned();
            }
            "--project" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    project_id = v.clone();
                }
            }
            "--batch" => {
                i += 1;
                batch_id = args.get(i).cloned();
            }
            "--vintage" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    vintage_year = v.parse().context("Invalid --vintage")?;
                }
            }
            "--micro-units" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    micro_units = Some(v.parse().context("Invalid --micro-units")?);
                }
            }
            "--credits" => {
                i += 1;
                credits_str = args.get(i).cloned();
            }
            "--mrv-data" => {
                i += 1;
                mrv_data = args.get(i).cloned();
            }
            "--mrv-root" => {
                i += 1;
                mrv_root_hex = args.get(i).cloned();
            }
            "--mirror" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    mirrors.push(v.clone());
                }
            }
            "--challenge-epochs" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    challenge_epochs = v.parse().context("Invalid --challenge-epochs")?;
                }
            }
            "--rpc-url" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    rpc_url = v.clone();
                }
            }
            "--cookie" => {
                i += 1;
                cookie_arg = args.get(i).cloned();
            }
            "--dry-run" => dry_run = true,
            "-h" | "--help" => {
                println!("USAGE: grey-misnomer-cli tx-mint [--keys genesis_keys.json] [--owner <PUBKEY>] [--credits <N>] [--project <ID>] [--rpc-url <URL>]");
                return Ok(());
            }
            unknown => bail!("Unknown option for tx-mint: {unknown}"),
        }
        i += 1;
    }

    let token = resolve_bearer_token(cookie_arg.as_deref())?;
    let (vvb_kp, keys_cid) = resolve_actor_key_and_cid(
        keys_path.as_deref(),
        "vvb",
        vvb_key_hex.as_deref(),
        keystore_path.as_deref(),
        passphrase.as_deref(),
    )?;

    let initial_owner = if let Some(ref o_hex) = owner_hex {
        PubKey::from_hex(o_hex).map_err(|e| anyhow::anyhow!("Invalid --owner pubkey: {e}"))?
    } else if let Some(ref kp_file) = keys_path {
        extract_pubkey_from_keys_bundle(kp_file, "alice")?
    } else {
        vvb_kp.pubkey()
    };

    let chain_id = resolve_chain_id(
        chain_id_hex.as_deref(),
        genesis_path.as_deref(),
        keys_cid,
        &rpc_url,
        token.as_deref(),
    )?;

    let units = match (micro_units, credits_str) {
        (Some(m), _) => m,
        (None, Some(c)) => parse_credits_to_micro_units(&c)?,
        (None, None) => 10 * MICRO_UNITS_PER_CREDIT,
    };

    let now_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    let mrv_data_root = if let Some(ref root_h) = mrv_root_hex {
        parse_32byte_hex(root_h)?
    } else if let Some(ref data_str) = mrv_data {
        let bytes = if std::path::Path::new(data_str).exists() {
            fs::read(data_str)?
        } else {
            data_str.as_bytes().to_vec()
        };
        hash_log_leaf(&bytes)
    } else {
        let unique = format!("mrv:{project_id}:{now_nanos}");
        hash_log_leaf(unique.as_bytes())
    };

    if mirrors.is_empty() {
        mirrors.push(format!("ipfs://mrv-{}", &hex::encode(mrv_data_root)[..16]));
    }

    let mut mint = UcoMintTx {
        project_id,
        batch_id: batch_id.unwrap_or_else(|| format!("BATCH-{}", now_nanos % 1_000_000)),
        vintage_year,
        micro_units: units,
        initial_owner,
        methodology_hash: hash_log_leaf(b"GM-METHODOLOGY-V2"),
        mrv_data_root,
        mrv_blob_mirrors: mirrors,
        challenge_window_epochs: challenge_epochs,
        vvb_signatures: Vec::new(),
    };

    let preimage = mint.signing_preimage(&chain_id);
    mint.vvb_signatures
        .push((vvb_kp.pubkey(), vvb_kp.sign(&preimage)));

    let tx = UcoTransaction::Mint(mint);
    let tx_json = serde_json::to_string_pretty(&tx)?;
    if dry_run {
        println!("{tx_json}");
        return Ok(());
    }

    let resp_str = http_rpc_request(
        &rpc_url,
        "POST",
        "/v1/tx/submit",
        Some(&tx_json),
        token.as_deref(),
    )?;
    let resp: serde_json::Value = serde_json::from_str(&resp_str)?;
    let txid = resp["txid"].as_str().unwrap_or("");
    let status = resp["status"].as_str().unwrap_or("");
    let tree_size = resp["tree_size"].as_str().unwrap_or("pending");

    println!("══════════════════════════════════════════════════════════════════════");
    println!("  v2 UCO Credit Minted & Submitted");
    println!("══════════════════════════════════════════════════════════════════════");
    println!("  Status:       {status}");
    println!("  TXID:         {txid}");
    println!("  Created UCO:  {txid}:0");
    println!("  Owner:        {}", initial_owner);
    println!(
        "  Amount:       {} credits ({units} micro-units)",
        format_micro_units(units)
    );
    println!("  Tree Size:    {tree_size}");
    println!("══════════════════════════════════════════════════════════════════════");
    Ok(())
}

pub fn handle_tx_transfer(args: &[String]) -> Result<()> {
    let mut input_str: Option<String> = None;
    let mut to_hex: Option<String> = None;
    let mut credits_str: Option<String> = None;
    let mut micro_units: Option<u64> = None;
    let mut keys_path: Option<String> = None;
    let mut actor = "alice".to_string();
    let mut key_hex: Option<String> = None;
    let mut keystore_path: Option<String> = None;
    let mut passphrase: Option<String> = None;
    let mut genesis_path: Option<String> = None;
    let mut chain_id_hex: Option<String> = None;
    let mut rpc_url = DEFAULT_RPC_URL.to_string();
    let mut cookie_arg: Option<String> = None;
    let mut dry_run = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--input" => {
                i += 1;
                input_str = args.get(i).cloned();
            }
            "--to" => {
                i += 1;
                to_hex = args.get(i).cloned();
            }
            "--credits" => {
                i += 1;
                credits_str = args.get(i).cloned();
            }
            "--micro-units" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    micro_units = Some(v.parse().context("Invalid --micro-units")?);
                }
            }
            "--keys" => {
                i += 1;
                keys_path = args.get(i).cloned();
            }
            "--actor" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    actor = v.clone();
                }
            }
            "--key" => {
                i += 1;
                key_hex = args.get(i).cloned();
            }
            "--keystore" => {
                i += 1;
                keystore_path = args.get(i).cloned();
            }
            "--passphrase" => {
                i += 1;
                passphrase = args.get(i).cloned();
            }
            "--genesis" => {
                i += 1;
                genesis_path = args.get(i).cloned();
            }
            "--chain-id" => {
                i += 1;
                chain_id_hex = args.get(i).cloned();
            }
            "--rpc-url" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    rpc_url = v.clone();
                }
            }
            "--cookie" => {
                i += 1;
                cookie_arg = args.get(i).cloned();
            }
            "--dry-run" => dry_run = true,
            "-h" | "--help" => {
                println!("USAGE: grey-misnomer-cli tx-transfer --input <TXID:VOUT> --to <PUBKEY> --credits <N> [--key <HEX> | --keys <genesis_keys.json> --actor alice] [--rpc-url <URL>]");
                return Ok(());
            }
            unknown => bail!("Unknown option for tx-transfer: {unknown}"),
        }
        i += 1;
    }

    let outpoint_str = input_str.context("Missing required --input <TXID:VOUT>")?;
    let outpoint: OutPoint = outpoint_str
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid outpoint '{outpoint_str}': {e}"))?;
    let recipient = PubKey::from_hex(&to_hex.context("Missing required --to <PUBKEY_HEX>")?)
        .map_err(|e| anyhow::anyhow!("Invalid --to pubkey: {e}"))?;

    let token = resolve_bearer_token(cookie_arg.as_deref())?;
    let (sender_kp, keys_cid) = resolve_actor_key_and_cid(
        keys_path.as_deref(),
        &actor,
        key_hex.as_deref(),
        keystore_path.as_deref(),
        passphrase.as_deref(),
    )?;

    let chain_id = resolve_chain_id(
        chain_id_hex.as_deref(),
        genesis_path.as_deref(),
        keys_cid,
        &rpc_url,
        token.as_deref(),
    )?;

    let uco_json = http_rpc_request(
        &rpc_url,
        "GET",
        &format!("/v1/uco/{outpoint}"),
        None,
        token.as_deref(),
    )?;
    let uco: DaemonUcoView = serde_json::from_str(&uco_json)?;

    let send_units = match (micro_units, credits_str) {
        (Some(m), _) => m,
        (None, Some(c)) => parse_credits_to_micro_units(&c)?,
        (None, None) => uco.micro_units,
    };

    if send_units == 0 || send_units > uco.micro_units {
        bail!(
            "Requested transfer {} exceeds input balance {} micro-units",
            send_units,
            uco.micro_units
        );
    }

    let split_end = uco
        .start_micro_unit
        .checked_add(send_units)
        .context("interval overflow")?;

    let mut outputs = vec![UcoTransferOutputSpec {
        owner: recipient,
        start_micro_unit: uco.start_micro_unit,
        end_micro_unit: split_end,
        micro_units: send_units,
        locked_escrow_program: None,
    }];

    let change_units = uco.end_micro_unit - split_end;
    if change_units > 0 {
        outputs.push(UcoTransferOutputSpec {
            owner: sender_kp.pubkey(),
            start_micro_unit: split_end,
            end_micro_unit: uco.end_micro_unit,
            micro_units: change_units,
            locked_escrow_program: None,
        });
    }

    let mut split_tx = UcoSplitTransferTx {
        inputs: vec![outpoint],
        outputs,
        input_signatures: Vec::new(),
    };
    let preimage = split_tx.signing_preimage(&chain_id, &[uco.op_index]);
    split_tx.input_signatures.push(sender_kp.sign(&preimage));

    let tx = UcoTransaction::SplitTransfer(split_tx);
    let tx_json = serde_json::to_string_pretty(&tx)?;
    if dry_run {
        println!("{tx_json}");
        return Ok(());
    }

    let resp_str = http_rpc_request(
        &rpc_url,
        "POST",
        "/v1/tx/submit",
        Some(&tx_json),
        token.as_deref(),
    )?;
    let resp: serde_json::Value = serde_json::from_str(&resp_str)?;
    let txid = resp["txid"].as_str().unwrap_or("");
    let status = resp["status"].as_str().unwrap_or("");
    let tree_size = resp["tree_size"]
        .as_str()
        .unwrap_or("pending (broadcast P2P)");

    println!("══════════════════════════════════════════════════════════════════════");
    println!("  v2 UCO SplitTransfer Submitted");
    println!("══════════════════════════════════════════════════════════════════════");
    println!("  Status:          {status}");
    println!("  TXID:            {txid}");
    println!(
        "  Recipient UCO:   {txid}:0 ({} credits -> {recipient})",
        format_micro_units(send_units)
    );
    if change_units > 0 {
        println!(
            "  Change UCO:      {txid}:1 ({} credits -> {})",
            format_micro_units(change_units),
            sender_kp.pubkey()
        );
    }
    println!("  Tree Size:       {tree_size}");
    println!("══════════════════════════════════════════════════════════════════════");
    Ok(())
}

pub fn handle_tx_burn(args: &[String]) -> Result<()> {
    let mut input_str: Option<String> = None;
    let mut credits_str: Option<String> = None;
    let mut micro_units: Option<u64> = None;
    let mut beneficiary = "Verified Offset Retirement".to_string();
    let mut claim = PoOClaimType::Voluntary;
    let mut keys_path: Option<String> = None;
    let mut actor = "bob".to_string();
    let mut key_hex: Option<String> = None;
    let mut keystore_path: Option<String> = None;
    let mut passphrase: Option<String> = None;
    let mut genesis_path: Option<String> = None;
    let mut chain_id_hex: Option<String> = None;
    let mut rpc_url = DEFAULT_RPC_URL.to_string();
    let mut cookie_arg: Option<String> = None;
    let mut dry_run = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--input" => {
                i += 1;
                input_str = args.get(i).cloned();
            }
            "--credits" => {
                i += 1;
                credits_str = args.get(i).cloned();
            }
            "--micro-units" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    micro_units = Some(v.parse().context("Invalid --micro-units")?);
                }
            }
            "--beneficiary" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    beneficiary = v.clone();
                }
            }
            "--claim" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    claim = match v.to_lowercase().as_str() {
                        "voluntary" => PoOClaimType::Voluntary,
                        "compliance" => PoOClaimType::Compliance,
                        "netzero" | "net_zero" => PoOClaimType::NetZero,
                        "cancellation" => PoOClaimType::Cancellation,
                        other => bail!("Unknown --claim '{other}' (expected voluntary|compliance|netzero|cancellation)"),
                    };
                }
            }
            "--keys" => {
                i += 1;
                keys_path = args.get(i).cloned();
            }
            "--actor" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    actor = v.clone();
                }
            }
            "--key" => {
                i += 1;
                key_hex = args.get(i).cloned();
            }
            "--keystore" => {
                i += 1;
                keystore_path = args.get(i).cloned();
            }
            "--passphrase" => {
                i += 1;
                passphrase = args.get(i).cloned();
            }
            "--genesis" => {
                i += 1;
                genesis_path = args.get(i).cloned();
            }
            "--chain-id" => {
                i += 1;
                chain_id_hex = args.get(i).cloned();
            }
            "--rpc-url" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    rpc_url = v.clone();
                }
            }
            "--cookie" => {
                i += 1;
                cookie_arg = args.get(i).cloned();
            }
            "--dry-run" => dry_run = true,
            "-h" | "--help" => {
                println!("USAGE: grey-misnomer-cli tx-burn --input <TXID:VOUT> [--credits <N>] [--beneficiary <ORG>] [--key <HEX>] [--rpc-url <URL>]");
                return Ok(());
            }
            unknown => bail!("Unknown option for tx-burn: {unknown}"),
        }
        i += 1;
    }

    let outpoint_str = input_str.context("Missing required --input <TXID:VOUT>")?;
    let outpoint: OutPoint = outpoint_str
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid outpoint '{outpoint_str}': {e}"))?;
    let token = resolve_bearer_token(cookie_arg.as_deref())?;

    let (owner_kp, keys_cid) = resolve_actor_key_and_cid(
        keys_path.as_deref(),
        &actor,
        key_hex.as_deref(),
        keystore_path.as_deref(),
        passphrase.as_deref(),
    )?;

    let chain_id = resolve_chain_id(
        chain_id_hex.as_deref(),
        genesis_path.as_deref(),
        keys_cid,
        &rpc_url,
        token.as_deref(),
    )?;

    let uco_json = http_rpc_request(
        &rpc_url,
        "GET",
        &format!("/v1/uco/{outpoint}"),
        None,
        token.as_deref(),
    )?;
    let uco: DaemonUcoView = serde_json::from_str(&uco_json)?;

    let burn_units = match (micro_units, credits_str) {
        (Some(m), _) => m,
        (None, Some(c)) => parse_credits_to_micro_units(&c)?,
        (None, None) => uco.micro_units,
    };

    if burn_units == 0 || burn_units > uco.micro_units {
        bail!(
            "Burn units {burn_units} exceeds input balance {}",
            uco.micro_units
        );
    }

    let burn_end = uco
        .start_micro_unit
        .checked_add(burn_units)
        .context("interval overflow")?;
    let change_owner = if burn_units < uco.micro_units {
        Some(owner_kp.pubkey())
    } else {
        None
    };

    let mut burn_tx = UcoBurnTx {
        input: outpoint,
        start_micro_unit: uco.start_micro_unit,
        end_micro_unit: burn_end,
        micro_units: burn_units,
        beneficiary: beneficiary.clone(),
        claim_type: claim,
        owner_sig: Signature::default(),
        change_owner,
    };
    let preimage = burn_tx.signing_preimage(&chain_id, uco.op_index);
    burn_tx.owner_sig = owner_kp.sign(&preimage);

    let tx = UcoTransaction::Burn(burn_tx);
    let tx_json = serde_json::to_string_pretty(&tx)?;
    if dry_run {
        println!("{tx_json}");
        return Ok(());
    }

    let resp_str = http_rpc_request(
        &rpc_url,
        "POST",
        "/v1/tx/submit",
        Some(&tx_json),
        token.as_deref(),
    )?;
    let resp: serde_json::Value = serde_json::from_str(&resp_str)?;
    println!("══════════════════════════════════════════════════════════════════════");
    println!("  v2 Proof-of-Offset Retirement Submitted (BurnPoO)");
    println!("══════════════════════════════════════════════════════════════════════");
    println!("  Status:       {}", resp["status"].as_str().unwrap_or(""));
    println!("  TXID:         {}", resp["txid"].as_str().unwrap_or(""));
    println!(
        "  Retired:      {} credits ({burn_units} micro-units)",
        format_micro_units(burn_units)
    );
    println!("  Beneficiary:  {beneficiary}");
    println!("══════════════════════════════════════════════════════════════════════");
    Ok(())
}

fn parse_rpc_query_flags(args: &[String]) -> Result<(String, Option<String>, bool)> {
    let mut rpc_url = DEFAULT_RPC_URL.to_string();
    let mut cookie_arg: Option<String> = None;
    let mut json = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--rpc-url" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    rpc_url = v.clone();
                }
            }
            arg if arg.starts_with("--rpc-url=") => {
                rpc_url = arg.strip_prefix("--rpc-url=").unwrap().to_string();
            }
            "--cookie" => {
                i += 1;
                cookie_arg = args.get(i).cloned();
            }
            "--json" => json = true,
            unknown => bail!("Unknown option: {unknown}"),
        }
        i += 1;
    }
    let token = resolve_bearer_token(cookie_arg.as_deref())?;
    Ok((rpc_url, token, json))
}

pub fn handle_rpc_ucos(args: &[String]) -> Result<()> {
    let (rpc_url, token, json) = parse_rpc_query_flags(args)?;
    let body = http_rpc_request(&rpc_url, "GET", "/v1/ucos", None, token.as_deref())?;
    if json {
        println!("{body}");
        return Ok(());
    }
    let items: Vec<DaemonUcoView> = serde_json::from_str(&body)?;
    println!("══════════════════════════════════════════════════════════════════════");
    println!("  Active Unretired Credit Outputs ({} total)", items.len());
    println!("══════════════════════════════════════════════════════════════════════");
    for item in items {
        let view = UcoDisplayView {
            outpoint: item.outpoint,
            project_id: item.project_id,
            batch_id: item.batch_id,
            vintage_year: item.vintage_year,
            credits: format_micro_units(item.micro_units),
            micro_units: item.micro_units.to_string(),
            range: format!("[{}, {})", item.start_micro_unit, item.end_micro_unit),
            owner: item.owner,
            op_index: item.op_index.to_string(),
        };
        println!(
            "  OutPoint: {}  ({} credits, range {}, lock_epoch: {})",
            view.outpoint, view.credits, view.range, item.challenge_until_epoch
        );
        println!(
            "    Project: {} ({}) | Owner: {} | op_index: {}",
            view.project_id, view.vintage_year, view.owner, view.op_index
        );
    }
    println!("══════════════════════════════════════════════════════════════════════");
    Ok(())
}

pub fn handle_rpc_peers(args: &[String]) -> Result<()> {
    let (rpc_url, token, json) = parse_rpc_query_flags(args)?;
    let body = http_rpc_request(&rpc_url, "GET", "/v1/network/peers", None, token.as_deref())?;
    if json {
        println!("{body}");
        return Ok(());
    }
    let val: serde_json::Value = serde_json::from_str(&body)?;
    println!("══════════════════════════════════════════════════════════════════════");
    println!(
        "  P2P Network Peers (Node: {}, Port: {})",
        val["node_id"].as_str().unwrap_or(""),
        val["p2p_port"].as_u64().unwrap_or(0)
    );
    println!("══════════════════════════════════════════════════════════════════════");
    println!(
        "  Connected Peers: {}",
        val["peer_count"].as_u64().unwrap_or(0)
    );
    if let Some(arr) = val["peers"].as_array() {
        for p in arr {
            println!(
                "  • {}  [addr: {}, relay: {}]",
                p["node_id"].as_str().unwrap_or(""),
                p["address"].as_str().unwrap_or(""),
                p["is_relay"].as_bool().unwrap_or(false)
            );
        }
    }
    println!("══════════════════════════════════════════════════════════════════════");
    Ok(())
}

pub fn handle_rpc_mempool(args: &[String]) -> Result<()> {
    let (rpc_url, token, json) = parse_rpc_query_flags(args)?;
    let body = http_rpc_request(&rpc_url, "GET", "/v1/mempool", None, token.as_deref())?;
    if json {
        println!("{body}");
        return Ok(());
    }
    let val: serde_json::Value = serde_json::from_str(&body)?;
    println!("══════════════════════════════════════════════════════════════════════");
    println!(
        "  Node P2P Mempool ({} pending)",
        val["count"].as_u64().unwrap_or(0)
    );
    println!("══════════════════════════════════════════════════════════════════════");
    if let Some(arr) = val["transactions"].as_array() {
        for t in arr {
            println!(
                "  • {}  [kind: {}, ts: {}]",
                t["txid"].as_str().unwrap_or(""),
                t["kind"].as_str().unwrap_or(""),
                t["timestamp"].as_str().unwrap_or("")
            );
        }
    }
    println!("══════════════════════════════════════════════════════════════════════");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_integer_credit_parsing_and_formatting() {
        assert_eq!(parse_credits_to_micro_units("1").unwrap(), 1_000_000);
        assert_eq!(parse_credits_to_micro_units("10.5").unwrap(), 10_500_000);
        assert_eq!(parse_credits_to_micro_units("0.000001").unwrap(), 1);
        assert_eq!(format_micro_units(10_500_000), "10.5");
        assert_eq!(format_micro_units(10_000_000), "10");
        assert!(parse_credits_to_micro_units("0").is_err());
        assert!(parse_credits_to_micro_units("-5").is_err());
        assert!(parse_credits_to_micro_units("1.1234567").is_err());
    }

    #[test]
    fn test_daemon_uco_view_parses_both_numeric_and_string_u64() {
        let json_str = r#"{
            "outpoint": "0101010101010101010101010101010101010101010101010101010101010101:0",
            "project_id": "SOLAR-01",
            "batch_id": "B1",
            "vintage_year": 2026,
            "start_micro_unit": "0",
            "end_micro_unit": "10000000",
            "micro_units": "10000000",
            "owner": "aabb",
            "op_index": "0",
            "challenge_until_epoch": "0"
        }"#;
        let view: DaemonUcoView = serde_json::from_str(json_str).unwrap();
        assert_eq!(view.micro_units, 10_000_000);

        let uco = grey_misnomer_core::uco::UnretiredCreditOutput {
            outpoint: OutPoint::new([0x22; 32], 1),
            batch_id: "B2".to_string(),
            project_id: "SOLAR-02".to_string(),
            vintage_year: 2026,
            start_micro_unit: 0,
            end_micro_unit: 4_000_000,
            micro_units: 4_000_000,
            owner: Keypair::generate().pubkey(),
            op_index: 0,
            methodology_hash: [0x11; 32],
            mrv_data_root: [0x33; 32],
            mrv_blob_mirrors: vec![],
            challenge_until_epoch: 0,
            locked_escrow_program: None,
        };
        let raw_uco_json = serde_json::to_string(&uco).unwrap();
        let parsed_raw: DaemonUcoView = serde_json::from_str(&raw_uco_json).unwrap();
        assert_eq!(parsed_raw.outpoint, uco.outpoint.to_string());
        assert_eq!(parsed_raw.micro_units, 4_000_000);
    }
}
