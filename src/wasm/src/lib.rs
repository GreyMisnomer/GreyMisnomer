// src/wasm/src/lib.rs
//
// This crate is the bridge between grey-misnomer-core (pure Rust) and the browser.
// Every public function here is decorated with #[wasm_bindgen] which makes it
// callable from JavaScript as if it were a normal JS function.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

// Pull in everything we need from the core crate
use grey_misnomer_core::{
    auth::{
        build_authority_event_preimage, build_burn_preimage, build_genesis_preimage,
        build_mint_preimage, build_transfer_preimage, build_vvb_register_payload, Keypair,
        MintAttestationParams, PubKey,
    },
    credit::CreditStatus,
    mrv::{self, MRVCommitment, MRVRecord},
    poo::ClaimType,
    registry::{Registry, RegistryEvent},
    serial::SerialRange,
};

// ── Helper: convert any Rust error into a JS Error ───────────────────────────
fn js_err(msg: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&msg.to_string())
}

// ── Input shapes (what JS sends us as JSON strings) ──────────────────────────

#[derive(Deserialize)]
struct MrvInput {
    timestamp: u64,
    #[serde(deserialize_with = "deserialize_micro_units")]
    value: u64,
    unit: String,
    source: String,
}

fn deserialize_micro_units<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct MicroUnitsVisitor;

    impl<'de> serde::de::Visitor<'de> for MicroUnitsVisitor {
        type Value = u64;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("an integer micro-unit or a floating-point value")
        }

        fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(v)
        }

        fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if v < 0 {
                return Err(E::custom("micro-unit value cannot be negative"));
            }
            Ok(v as u64)
        }

        fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if v < 0.0 {
                return Err(E::custom("micro-unit value cannot be negative"));
            }
            let micro = (v * 1_000_000.0).round();
            if micro > u64::MAX as f64 {
                return Err(E::custom("value overflow"));
            }
            Ok(micro as u64)
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if let Ok(u) = v.parse::<u64>() {
                Ok(u)
            } else if let Ok(f) = v.parse::<f64>() {
                self.visit_f64(f)
            } else {
                Err(E::custom(format!("invalid numeric string: {v}")))
            }
        }
    }

    deserializer.deserialize_any(MicroUnitsVisitor)
}

fn default_true() -> bool {
    true
}

#[derive(Deserialize)]
struct PoiInput {
    project_id: String,
    credit_id: String,
    serial_start: u64,
    serial_end: u64,
    cc_mint_amount: u64,
    jurisdiction: String,
    methodology_hash: String,
    #[allow(dead_code)]
    vvb_signature: String,
    owner: String,
    #[serde(default = "default_true")]
    poi_valid: bool,
}

#[derive(Deserialize)]
struct BurnInput {
    credit_id: String,
    burn_start: u64,
    burn_end: u64,
    beneficiary: String,
    claim_type: String, // "CorporateNetZero" | "Payg" | "Compliance"
}

// ── Output shapes (what we send back as JSON strings) ────────────────────────

#[derive(Serialize)]
struct CommitmentOutput {
    merkle_root_hex: String,
    algorithm: String,
    leaf_count: u64,
    timestamp: u64,
}

#[derive(Serialize)]
struct MintOutput {
    credit_id: String,
    project_id: String,
    owner: String,
    original_start: u64,
    original_end: u64,
    total_credits: u64,
    poi_status: String,
}

#[derive(Serialize)]
struct SliceOutput {
    start: u64,
    end: u64,
    size: u64,
    status: String,
}

#[derive(Serialize)]
struct BatchStateOutput {
    credit_id: String,
    owner: String,
    original_start: u64,
    original_end: u64,
    slices: Vec<SliceOutput>,
    active_total: u64,
    retired_total: u64,
}

#[derive(Serialize)]
struct PooOutput {
    project_id: String,
    credit_id: String,
    beneficiary: String,
    claim_type: String,
    serial_start: u64,
    serial_end: u64,
    cc_amount: u64,
    amount_tco2e: u64,
    burn_tx_hash: String,
    status: String,
    amounts_consistent: bool,
}

// ── Free functions (stateless) ────────────────────────────────────────────────

/// Build a BLAKE3 Merkle commitment from a JSON array of MRV records.
#[wasm_bindgen]
pub fn build_commitment(records_json: &str, timestamp: u64) -> Result<String, JsValue> {
    let inputs: Vec<MrvInput> = serde_json::from_str(records_json)
        .map_err(|e| js_err(format!("Invalid MRV records JSON: {e}")))?;

    if inputs.is_empty() {
        return Err(js_err("Cannot build commitment from empty MRV dataset"));
    }

    let records: Vec<MRVRecord> = inputs
        .into_iter()
        .map(|r| MRVRecord {
            timestamp: r.timestamp,
            value: r.value,
            unit: r.unit,
            source: r.source,
        })
        .collect();

    let commitment = mrv::commit(&records, timestamp);

    let root_hex = commitment
        .merkle_root
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();

    let out = CommitmentOutput {
        merkle_root_hex: root_hex,
        algorithm: commitment.hash_algorithm.clone(),
        leaf_count: commitment.leaf_count,
        timestamp: commitment.timestamp,
    };

    serde_json::to_string(&out).map_err(js_err)
}

/// Verify that a specific MRV record is included in a commitment.
#[wasm_bindgen]
pub fn verify_inclusion(
    records_json: &str,
    index: usize,
    root_hex: &str,
) -> Result<String, JsValue> {
    let inputs: Vec<MrvInput> = serde_json::from_str(records_json)
        .map_err(|e| js_err(format!("Invalid records JSON: {e}")))?;

    let records: Vec<MRVRecord> = inputs
        .into_iter()
        .map(|r| MRVRecord {
            timestamp: r.timestamp,
            value: r.value,
            unit: r.unit,
            source: r.source,
        })
        .collect();

    if root_hex.len() != 64 {
        return Err(js_err("Root hex must be 64 characters (32 bytes)"));
    }
    let mut root = [0u8; 32];
    for i in 0..32 {
        root[i] = u8::from_str_radix(&root_hex[i * 2..i * 2 + 2], 16)
            .map_err(|e| js_err(format!("Invalid hex: {e}")))?;
    }

    let proof = mrv::generate_inclusion_proof(&records, index)
        .ok_or_else(|| js_err("Index out of range"))?;

    let ok = mrv::verify_inclusion_proof(&records[index], &proof, &root);
    Ok(if ok {
        "verified".to_string()
    } else {
        "failed".to_string()
    })
}

// ── WasmRegistry — stateful JS class ─────────────────────────────────────────

#[wasm_bindgen]
pub struct WasmRegistry {
    inner: Registry,
    commitments: HashMap<String, MRVCommitment>,
    last_commitment: Option<MRVCommitment>,
    #[allow(dead_code)]
    authority_key: Keypair,
    #[allow(dead_code)]
    sequencer_key: Keypair,
    vvb_key: Keypair,
    owner_keys: HashMap<PubKey, Keypair>,
    wallet_aliases: HashMap<String, PubKey>,
    pubkey_aliases: HashMap<PubKey, String>,
}

impl WasmRegistry {
    fn resolve_owner(&mut self, owner_str: &str) -> (PubKey, Keypair) {
        if let Some(pk) = self.wallet_aliases.get(owner_str) {
            if let Some(kp) = self.owner_keys.get(pk) {
                return (*pk, kp.clone());
            }
        }
        if let Ok(pk) = PubKey::from_hex(owner_str) {
            if let Some(kp) = self.owner_keys.get(&pk) {
                self.wallet_aliases.insert(owner_str.to_string(), pk);
                self.pubkey_aliases.insert(pk, owner_str.to_string());
                return (pk, kp.clone());
            }
        }
        let kp = Keypair::from_seed_str(owner_str);
        let pk = kp.pubkey();
        self.owner_keys.insert(pk, kp.clone());
        self.wallet_aliases.insert(owner_str.to_string(), pk);
        self.pubkey_aliases.insert(pk, owner_str.to_string());
        (pk, kp)
    }

    fn owner_display_str(&self, pk: &PubKey) -> String {
        self.pubkey_aliases
            .get(pk)
            .cloned()
            .unwrap_or_else(|| pk.to_hex())
    }
}

#[wasm_bindgen]
impl WasmRegistry {
    #[wasm_bindgen(constructor)]
    pub fn new() -> WasmRegistry {
        let authority_key = Keypair::from_seed_str("wasm-demo-authority-seed-00000000");
        let sequencer_key = Keypair::from_seed_str("wasm-demo-sequencer-seed-00000000");
        let vvb_key = Keypair::from_seed_str("wasm-demo-vvb-seed-000000000000");

        let mut inner = Registry::new();
        let nonce = [42u8; 32];
        let created_at = 1_700_000_000;
        let genesis_msg = build_genesis_preimage(
            "GreyMisnomer-Wasm",
            &authority_key.pubkey(),
            &sequencer_key.pubkey(),
            &nonce,
            created_at,
        );
        let genesis_event = RegistryEvent::Genesis {
            chain_name: "GreyMisnomer-Wasm".to_string(),
            authority: authority_key.pubkey(),
            sequencer: sequencer_key.pubkey(),
            nonce,
            created_at,
            authority_sig: authority_key.sign(&genesis_msg),
        };
        inner
            .apply_event(&genesis_event)
            .expect("genesis must succeed");

        let vvb_payload = build_vvb_register_payload(&vvb_key.pubkey(), "Wasm-Default-VVB");
        let vvb_msg =
            build_authority_event_preimage("vvb-register", &inner.chain_id, 0, &vvb_payload);
        let vvb_event = RegistryEvent::VvbRegister {
            authority_index: 0,
            vvb: vvb_key.pubkey(),
            label: "Wasm-Default-VVB".to_string(),
            authority_sig: authority_key.sign(&vvb_msg),
        };
        inner
            .apply_event(&vvb_event)
            .expect("vvb register must succeed");

        let mut owner_keys = HashMap::new();
        owner_keys.insert(authority_key.pubkey(), authority_key.clone());
        owner_keys.insert(sequencer_key.pubkey(), sequencer_key.clone());
        owner_keys.insert(vvb_key.pubkey(), vvb_key.clone());

        WasmRegistry {
            inner,
            commitments: HashMap::new(),
            last_commitment: None,
            authority_key,
            sequencer_key,
            vvb_key,
            owner_keys,
            wallet_aliases: HashMap::new(),
            pubkey_aliases: HashMap::new(),
        }
    }

    #[wasm_bindgen]
    pub fn store_commitment(
        &mut self,
        records_json: &str,
        timestamp: u64,
        project_id: Option<String>,
    ) -> Result<(), JsValue> {
        let inputs: Vec<MrvInput> = serde_json::from_str(records_json)
            .map_err(|e| js_err(format!("Invalid records JSON: {e}")))?;

        let records: Vec<MRVRecord> = inputs
            .into_iter()
            .map(|r| MRVRecord {
                timestamp: r.timestamp,
                value: r.value,
                unit: r.unit,
                source: r.source,
            })
            .collect();

        let comm = mrv::commit(&records, timestamp);
        if let Some(pid) = &project_id {
            if !pid.is_empty() {
                self.commitments.insert(pid.clone(), comm.clone());
            }
        }
        self.last_commitment = Some(comm);
        Ok(())
    }

    #[wasm_bindgen]
    pub fn store_project_commitment(
        &mut self,
        project_id: &str,
        records_json: &str,
        timestamp: u64,
    ) -> Result<(), JsValue> {
        self.store_commitment(records_json, timestamp, Some(project_id.to_string()))
    }

    #[wasm_bindgen]
    pub fn mint(&mut self, poi_json: &str) -> Result<String, JsValue> {
        let input: PoiInput =
            serde_json::from_str(poi_json).map_err(|e| js_err(format!("Invalid PoI JSON: {e}")))?;

        if !input.poi_valid {
            return Err(js_err("PoI is marked invalid or not issued"));
        }

        let commitment = self
            .commitments
            .get(&input.project_id)
            .cloned()
            .or_else(|| self.last_commitment.clone())
            .ok_or_else(|| {
                js_err(format!(
                    "No MRV commitment found for project '{}'. Call store_commitment() first.",
                    input.project_id
                ))
            })?;

        let range = SerialRange::new(input.serial_start, input.serial_end).map_err(js_err)?;
        let range_sz = range.size().map_err(js_err)?;

        if input.cc_mint_amount != range_sz {
            return Err(js_err(format!(
                "cc_mint_amount ({}) must equal serial range size ({})",
                input.cc_mint_amount, range_sz
            )));
        }

        let (owner_pk, _) = self.resolve_owner(&input.owner);

        let mint_params = MintAttestationParams {
            chain_id: &self.inner.chain_id,
            project_id: &input.project_id,
            credit_id: &input.credit_id,
            range_start: input.serial_start,
            range_end: input.serial_end,
            cc_mint_amount: input.cc_mint_amount,
            merkle_root: &commitment.merkle_root,
            leaf_count: commitment.leaf_count,
            mrv_timestamp: commitment.timestamp,
            methodology_hash: &input.methodology_hash,
            jurisdiction: &input.jurisdiction,
            market_scope: "Vcm",
            valid_from: 0,
            valid_until: 9_999_999_999,
            initial_owner: &owner_pk,
        };
        let mint_msg = build_mint_preimage(&mint_params);
        let vvb_sig = self.vvb_key.sign(&mint_msg);

        let event = RegistryEvent::Mint {
            project_id: input.project_id.clone(),
            credit_id: input.credit_id.clone(),
            range_start: input.serial_start,
            range_end: input.serial_end,
            cc_mint_amount: input.cc_mint_amount,
            merkle_root: commitment.merkle_root,
            leaf_count: commitment.leaf_count,
            mrv_timestamp: commitment.timestamp,
            methodology_hash: input.methodology_hash,
            jurisdiction: input.jurisdiction,
            market_scope: "Vcm".to_string(),
            valid_from: 0,
            valid_until: 9_999_999_999,
            initial_owner: owner_pk,
            vvb: self.vvb_key.pubkey(),
            vvb_sig,
        };

        let batch = self.inner.mint(&event).map_err(js_err)?;

        let out = MintOutput {
            credit_id: batch.credit_id.clone(),
            project_id: batch.project_id.clone(),
            owner: self.owner_display_str(&batch.owner),
            original_start: batch.original_range.start,
            original_end: batch.original_range.end,
            total_credits: batch.original_range.size().map_err(js_err)?,
            poi_status: "USED".to_string(),
        };

        serde_json::to_string(&out).map_err(js_err)
    }

    #[wasm_bindgen]
    pub fn transfer(&mut self, credit_id: &str, new_owner: &str) -> Result<String, JsValue> {
        let batch = self
            .inner
            .credits
            .iter()
            .find(|b| b.credit_id == credit_id)
            .ok_or_else(|| js_err(format!("Credit not found: {credit_id}")))?
            .clone();

        let (new_pk, _) = self.resolve_owner(new_owner);
        let owner_kp = self.owner_keys.get(&batch.owner).cloned().ok_or_else(|| {
            js_err(format!(
                "No private key found for owner {}",
                batch.owner.to_hex()
            ))
        })?;

        let op_index = batch.op_index;
        let transfer_msg =
            build_transfer_preimage(&self.inner.chain_id, credit_id, op_index, &new_pk);
        let owner_sig = owner_kp.sign(&transfer_msg);

        let event = RegistryEvent::Transfer {
            credit_id: credit_id.to_string(),
            op_index,
            new_owner: new_pk,
            owner_sig,
        };

        self.inner.transfer(&event).map_err(js_err)?;
        self.batch_state(credit_id)
    }

    #[wasm_bindgen]
    pub fn burn(&mut self, burn_json: &str) -> Result<String, JsValue> {
        let input: BurnInput = serde_json::from_str(burn_json)
            .map_err(|e| js_err(format!("Invalid burn JSON: {e}")))?;

        let batch = self
            .inner
            .credits
            .iter()
            .find(|b| b.credit_id == input.credit_id)
            .ok_or_else(|| js_err(format!("Credit not found: {}", input.credit_id)))?
            .clone();

        let claim_type = match input.claim_type.as_str() {
            "CorporateNetZero" => ClaimType::CorporateNetZero,
            "Payg" => ClaimType::Payg,
            "Compliance" => ClaimType::Compliance,
            other => return Err(js_err(format!("Unknown claim type: {other}"))),
        };

        let owner_kp = self.owner_keys.get(&batch.owner).cloned().ok_or_else(|| {
            js_err(format!(
                "No private key found for owner {}",
                batch.owner.to_hex()
            ))
        })?;

        let op_index = batch.op_index;
        let burn_msg = build_burn_preimage(
            &self.inner.chain_id,
            &input.credit_id,
            op_index,
            input.burn_start,
            input.burn_end,
            &input.beneficiary,
            claim_type.as_str(),
        );
        let owner_sig = owner_kp.sign(&burn_msg);

        let event = RegistryEvent::Burn {
            credit_id: input.credit_id.clone(),
            op_index,
            range_start: input.burn_start,
            range_end: input.burn_end,
            beneficiary: input.beneficiary.clone(),
            claim_type,
            owner_sig,
        };

        let poo = self.inner.burn(&event).map_err(js_err)?;

        let claim_str = match poo.claim_type {
            ClaimType::CorporateNetZero => "CorporateNetZero",
            ClaimType::Payg => "Payg",
            ClaimType::Compliance => "Compliance",
        };

        let amounts_consistent = poo.amounts_are_consistent();
        let out = PooOutput {
            project_id: poo.project_id,
            credit_id: poo.credit_id,
            beneficiary: poo.beneficiary,
            claim_type: claim_str.to_string(),
            serial_start: poo.serialization_range.start,
            serial_end: poo.serialization_range.end,
            cc_amount: poo.cc_amount,
            amount_tco2e: poo.amount_tco2e,
            burn_tx_hash: poo.burn_tx_hash,
            status: "FINALIZED".to_string(),
            amounts_consistent,
        };

        serde_json::to_string(&out).map_err(js_err)
    }

    #[wasm_bindgen]
    pub fn batch_state(&self, credit_id: &str) -> Result<String, JsValue> {
        let batch = self
            .inner
            .credits
            .iter()
            .find(|b| b.credit_id == credit_id)
            .ok_or_else(|| js_err(format!("Credit not found: {credit_id}")))?;

        let mut slices = Vec::with_capacity(batch.slices.len());
        let mut active_total: u64 = 0;
        let mut retired_total: u64 = 0;

        for s in &batch.slices {
            let sz = s.range.size().map_err(js_err)?;
            if s.status == CreditStatus::Active {
                active_total = active_total
                    .checked_add(sz)
                    .ok_or_else(|| js_err("active_total overflow"))?;
            } else if s.status == CreditStatus::Retired {
                retired_total = retired_total
                    .checked_add(sz)
                    .ok_or_else(|| js_err("retired_total overflow"))?;
            }
            slices.push(SliceOutput {
                start: s.range.start,
                end: s.range.end,
                size: sz,
                status: match s.status {
                    CreditStatus::Active => "Active".to_string(),
                    CreditStatus::Retired => "Retired".to_string(),
                    CreditStatus::Expired => "Expired".to_string(),
                },
            });
        }

        let out = BatchStateOutput {
            credit_id: batch.credit_id.clone(),
            owner: self.owner_display_str(&batch.owner),
            original_start: batch.original_range.start,
            original_end: batch.original_range.end,
            slices,
            active_total,
            retired_total,
        };

        serde_json::to_string(&out).map_err(js_err)
    }

    #[wasm_bindgen]
    pub fn full_state(&self) -> Result<String, JsValue> {
        #[derive(Serialize)]
        struct FullState {
            credit_count: usize,
            burned_range_count: usize,
            credits: Vec<BatchStateOutput>,
        }

        let mut credits = Vec::with_capacity(self.inner.credits.len());
        for b in &self.inner.credits {
            let mut slices = Vec::with_capacity(b.slices.len());
            let mut active_total: u64 = 0;
            let mut retired_total: u64 = 0;

            for s in &b.slices {
                let sz = s.range.size().map_err(js_err)?;
                if s.status == CreditStatus::Active {
                    active_total = active_total
                        .checked_add(sz)
                        .ok_or_else(|| js_err("active_total overflow"))?;
                } else if s.status == CreditStatus::Retired {
                    retired_total = retired_total
                        .checked_add(sz)
                        .ok_or_else(|| js_err("retired_total overflow"))?;
                }
                slices.push(SliceOutput {
                    start: s.range.start,
                    end: s.range.end,
                    size: sz,
                    status: match s.status {
                        CreditStatus::Active => "Active".to_string(),
                        CreditStatus::Retired => "Retired".to_string(),
                        CreditStatus::Expired => "Expired".to_string(),
                    },
                });
            }

            credits.push(BatchStateOutput {
                credit_id: b.credit_id.clone(),
                owner: self.owner_display_str(&b.owner),
                original_start: b.original_range.start,
                original_end: b.original_range.end,
                slices,
                active_total,
                retired_total,
            });
        }

        let state = FullState {
            credit_count: self.inner.credits.len(),
            burned_range_count: self.inner.burned_ranges.len(),
            credits,
        };

        serde_json::to_string(&state).map_err(js_err)
    }

    #[wasm_bindgen]
    pub fn chain_id(&self) -> String {
        hex::encode(self.inner.chain_id)
    }

    #[wasm_bindgen]
    pub fn authority(&self) -> String {
        self.inner.authority.to_hex()
    }

    #[wasm_bindgen]
    pub fn sequencer(&self) -> String {
        self.inner.sequencer.to_hex()
    }

    /// Evaluates all protocol invariants (RFC-001 + RFC-005) and returns a JSON InvariantReport.
    #[wasm_bindgen]
    pub fn check_invariants(&self) -> Result<String, JsValue> {
        let report = self.inner.check_invariants();
        serde_json::to_string(&report).map_err(js_err)
    }

    /// Invariant 1: PoI is Mandatory for Minting.
    #[wasm_bindgen]
    pub fn check_invariant_1(&self) -> bool {
        self.inner.check_invariant_1()
    }

    /// Invariant 2: Supply Authorized Cap Limit & Conservation.
    #[wasm_bindgen]
    pub fn check_invariant_2(&self) -> bool {
        self.inner.check_invariant_2()
    }

    /// Invariant 3: Global Serialization Locking Uniqueness.
    #[wasm_bindgen]
    pub fn check_invariant_3(&self) -> bool {
        self.inner.check_invariant_3()
    }

    /// Invariant 4: Burn Irreversibility.
    #[wasm_bindgen]
    pub fn check_invariant_4(&self) -> bool {
        self.inner.check_invariant_4()
    }

    /// Invariant 5: PoO Uniqueness (Double-spending prevented).
    #[wasm_bindgen]
    pub fn check_invariant_5(&self) -> bool {
        self.inner.check_invariant_5()
    }

    /// Invariant 6: PoO Non-Transferability.
    #[wasm_bindgen]
    pub fn check_invariant_6(&self) -> bool {
        self.inner.check_invariant_6()
    }

    /// Invariant 7: PoI Single-use Consumed State.
    #[wasm_bindgen]
    pub fn check_invariant_7(&self) -> bool {
        self.inner.check_invariant_7()
    }

    /// Invariant A1: Cryptographic Authorization Validity.
    #[wasm_bindgen]
    pub fn check_invariant_a1(&self) -> bool {
        self.inner.check_invariant_a1()
    }

    /// Invariant A2: Operation Index Contiguity (Replay Prevention).
    #[wasm_bindgen]
    pub fn check_invariant_a2(&self) -> bool {
        self.inner.check_invariant_a2()
    }

    /// Invariant A3: Multi-Tenant Registry Domain Separation.
    #[wasm_bindgen]
    pub fn check_invariant_a3(&self) -> bool {
        self.inner.check_invariant_a3()
    }
}

impl Default for WasmRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// In-browser event log replayer (RFC-004 / Stage 1):
/// Parses `events.jsonl`, validates the cryptographic hash chain,
/// replays every state transition through pure `apply()`, and verifies all 7 invariants.
#[wasm_bindgen]
pub fn replay_event_log(events_jsonl: &str) -> Result<String, JsValue> {
    match grey_misnomer_core::event_log::replay_log_str(events_jsonl) {
        Ok(summary) => serde_json::to_string(&summary).map_err(js_err),
        Err(err) => Err(js_err(format!("Replay verification failed: {err}"))),
    }
}
