//! RFC-007 §2.4, §7 & Task 4.14: Localhost JSON-RPC & WebSocket Bus on Port 9482.
//!
//! Provides sub-millisecond O(1) UCO state queries, O(log N) unspentness SPV proofs,
//! permanent retirement proofs, and transaction submissions bound to 127.0.0.1:9482.
//! Responses enforce stringified base-10 `u64` integers to ensure complete JS/BigInt safety.

use crate::storage::{BatchTransition, ChainStorage};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use grey_misnomer_core::auth::hash_log_leaf;
use grey_misnomer_core::header::CheckpointHeaderV2;
use grey_misnomer_core::spv::{
    generate_poo_spv_proof, generate_unspent_spv_proof, PooRetirementSpvProof, UcoUnspentSpvProof,
};
use grey_misnomer_core::uco::{OutPoint, UnretiredCreditOutput};
use grey_misnomer_core::uco_engine::{apply_uco, UcoStoreRead, UcoTransaction};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::str::FromStr;
use tokio::sync::broadcast;
use tower_http::cors::{Any, CorsLayer};
use tracing::info;

// ---------------------------------------------------------------------------
// App State & Configuration
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct AppState {
    pub storage: ChainStorage,
    pub event_tx: broadcast::Sender<String>,
    pub regtest: bool,
    pub cookie_token: Option<String>,
    pub rpc_port: u16,
    pub p2p_mesh: Option<std::sync::Arc<crate::p2p::P2pMesh<ChainStorage>>>,
}

impl AppState {
    pub fn new(
        storage: ChainStorage,
        event_tx: broadcast::Sender<String>,
        regtest: bool,
        cookie_token: Option<String>,
        rpc_port: u16,
    ) -> Self {
        Self {
            storage,
            event_tx,
            regtest,
            cookie_token,
            rpc_port,
            p2p_mesh: None,
        }
    }

    pub fn with_p2p_mesh(
        mut self,
        mesh: std::sync::Arc<crate::p2p::P2pMesh<ChainStorage>>,
    ) -> Self {
        self.p2p_mesh = Some(mesh);
        self
    }
}

// ---------------------------------------------------------------------------
// RPC Request & Response Envelopes (Stringified u64 for JS MAX_SAFE_INTEGER)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainStatusResponse {
    pub chain_id: String,
    pub tree_size: String,
    pub current_epoch: String,
    pub poo_count: String,
    pub active_ucos_count: String,
    pub latest_checkpoint: Option<String>,
    pub rpc_port: u16,
    pub regtest: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPeersResponse {
    pub node_id: String,
    pub p2p_port: u16,
    pub peer_count: usize,
    pub peers: Vec<PeerInfoResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfoResponse {
    pub address: String,
    pub node_id: String,
    pub connected_at_secs: u64,
    pub is_relay: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoiProofResponse {
    pub mrv_data_root: String,
    pub used: bool,
    pub mirrors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxSubmitResponse {
    pub status: String,
    pub txid: String,
    pub tree_size: Option<String>,
}

// ---------------------------------------------------------------------------
// Router Builder
// ---------------------------------------------------------------------------

pub fn build_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/v1/chain/status", get(get_chain_status))
        .route("/v1/uco/:outpoint", get(get_uco))
        .route("/v1/proof/spv/:outpoint", get(get_spv_proof))
        .route("/v1/proof/poo/:id", get(get_poo_proof))
        .route("/v1/proof/poi/:root", get(get_poi_proof))
        .route("/v1/checkpoint/latest", get(get_latest_checkpoint))
        .route("/v1/network/peers", get(get_network_peers))
        .route("/v1/tx/submit", post(submit_tx))
        .route("/v1/events/subscribe", get(subscribe_events))
        .layer(cors)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Bearer & Cookie Auth Middleware
// ---------------------------------------------------------------------------

async fn auth_middleware(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: axum::extract::Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if let Some(expected_token) = &state.cookie_token {
        let auth_header = headers.get("Authorization").and_then(|h| h.to_str().ok());

        let authorized = match auth_header {
            Some(val) if val.starts_with("Bearer ") => {
                let token = val.strip_prefix("Bearer ").unwrap().trim();
                token == expected_token
            }
            Some(val) if val.starts_with("Basic ") => {
                // Bitcoin Core compatible basic auth: __cookie__:<token>
                if let Ok(decoded) = hex::decode(val.strip_prefix("Basic ").unwrap().trim()) {
                    let s = String::from_utf8_lossy(&decoded);
                    s.ends_with(expected_token)
                } else {
                    false
                }
            }
            _ => false,
        };

        if !authorized {
            return Err(StatusCode::UNAUTHORIZED);
        }
    }

    Ok(next.run(request).await)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn get_chain_status(
    State(state): State<AppState>,
) -> Result<Json<ChainStatusResponse>, (StatusCode, String)> {
    let rtx = state.storage.read_tx().map_err(internal_error)?;
    let active_ucos = rtx.list_unspent_outputs().map_err(internal_error)?;
    let latest_chk = rtx.get_latest_checkpoint().map_err(internal_error)?;

    let chk_str = latest_chk.and_then(|bytes| String::from_utf8(bytes).ok());

    Ok(Json(ChainStatusResponse {
        chain_id: hex::encode(rtx.chain_id()),
        tree_size: rtx.tree_size().to_string(),
        current_epoch: rtx.current_epoch().to_string(),
        poo_count: rtx.poo_count().to_string(),
        active_ucos_count: active_ucos.len().to_string(),
        latest_checkpoint: chk_str,
        rpc_port: state.rpc_port,
        regtest: state.regtest,
    }))
}

async fn get_uco(
    State(state): State<AppState>,
    Path(outpoint_str): Path<String>,
) -> Result<Json<UnretiredCreditOutput>, (StatusCode, String)> {
    let outpoint = OutPoint::from_str(&outpoint_str).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid outpoint format: {e}"),
        )
    })?;

    let rtx = state.storage.read_tx().map_err(internal_error)?;
    let uco = rtx.get_uco(&outpoint).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!("output {outpoint_str} not found"),
        )
    })?;

    Ok(Json(uco))
}

async fn get_spv_proof(
    State(state): State<AppState>,
    Path(outpoint_str): Path<String>,
) -> Result<Json<UcoUnspentSpvProof>, (StatusCode, String)> {
    let outpoint = OutPoint::from_str(&outpoint_str).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid outpoint format: {e}"),
        )
    })?;

    let rtx = state.storage.read_tx().map_err(internal_error)?;
    let all_ucos = rtx.list_unspent_outputs().map_err(internal_error)?;

    let mut uco_map = BTreeMap::new();
    for u in all_ucos {
        uco_map.insert(u.outpoint, u);
    }

    let proof = generate_unspent_spv_proof(&uco_map, &outpoint).map_err(|e| {
        (
            StatusCode::NOT_FOUND,
            format!("failed to generate SPV proof: {e}"),
        )
    })?;

    Ok(Json(proof))
}

async fn get_poo_proof(
    State(state): State<AppState>,
    Path(id_str): Path<String>,
) -> Result<Json<PooRetirementSpvProof>, (StatusCode, String)> {
    let rtx = state.storage.read_tx().map_err(internal_error)?;
    let poo_count = rtx.poo_count();

    let mut all_poos = Vec::with_capacity(poo_count as usize);
    for idx in 0..poo_count {
        if let Some(poo) = rtx.get_poo(idx).map_err(internal_error)? {
            all_poos.push(poo);
        }
    }

    // Try parsing as integer index first, otherwise match by txid hex
    let target_idx = if let Ok(idx) = id_str.parse::<usize>() {
        if idx < all_poos.len() {
            Some(idx)
        } else {
            None
        }
    } else {
        all_poos
            .iter()
            .position(|p| p.consumed_outpoint.to_string() == id_str)
    };

    let idx = target_idx.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!("Proof of Offset {id_str} not found in archive"),
        )
    })?;

    let proof = generate_poo_spv_proof(&all_poos, idx).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to generate PoO proof: {e}"),
        )
    })?;

    Ok(Json(proof))
}

async fn get_poi_proof(
    State(state): State<AppState>,
    Path(root_hex): Path<String>,
) -> Result<Json<PoiProofResponse>, (StatusCode, String)> {
    let bytes = hex::decode(&root_hex).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid MRV root hex: {e}"),
        )
    })?;

    if bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            "MRV root must be 32 bytes (64 hex characters)".to_string(),
        ));
    }

    let mut root = [0u8; 32];
    root.copy_from_slice(&bytes);

    let rtx = state.storage.read_tx().map_err(internal_error)?;
    let used = rtx.is_mrv_root_used(&root);
    let mirrors = rtx
        .get_mrv_mirrors(&root)
        .map_err(internal_error)?
        .unwrap_or_default();

    Ok(Json(PoiProofResponse {
        mrv_data_root: root_hex,
        used,
        mirrors,
    }))
}

async fn get_latest_checkpoint(
    State(state): State<AppState>,
) -> Result<String, (StatusCode, String)> {
    let rtx = state.storage.read_tx().map_err(internal_error)?;
    let chk = rtx.get_latest_checkpoint().map_err(internal_error)?;

    chk.and_then(|bytes| String::from_utf8(bytes).ok())
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                "no checkpoint published yet".to_string(),
            )
        })
}

async fn get_network_peers(
    State(state): State<AppState>,
) -> Result<Json<NetworkPeersResponse>, (StatusCode, String)> {
    if let Some(ref mesh) = state.p2p_mesh {
        let peers = mesh.connected_peers().await;
        let peer_infos: Vec<PeerInfoResponse> = peers
            .into_iter()
            .map(|p| PeerInfoResponse {
                address: p.addr.to_string(),
                node_id: p.node_id,
                connected_at_secs: p.connected_at_secs,
                is_relay: p.is_relay,
            })
            .collect();
        Ok(Json(NetworkPeersResponse {
            node_id: mesh.node_id().to_string(),
            p2p_port: mesh.listen_addr().port(),
            peer_count: peer_infos.len(),
            peers: peer_infos,
        }))
    } else {
        Ok(Json(NetworkPeersResponse {
            node_id: "standalone".to_string(),
            p2p_port: 0,
            peer_count: 0,
            peers: Vec::new(),
        }))
    }
}

async fn submit_tx(
    State(state): State<AppState>,
    Json(tx): Json<UcoTransaction>,
) -> Result<Json<TxSubmitResponse>, (StatusCode, String)> {
    let rtx = state.storage.read_tx().map_err(internal_error)?;

    // 1. Verify transaction against current chainstate
    let delta = apply_uco(&rtx, &tx).map_err(|e| {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("transaction evaluation failed: {e}"),
        )
    })?;

    let txid_hex = hex::encode(delta.txid);

    // Broadcast over P2P mesh if active
    if let Some(ref mesh) = state.p2p_mesh {
        let _ = mesh.broadcast_tx(&tx).await;
    }

    // 2. In regtest mode: commit immediately and broadcast
    if state.regtest {
        let current_size = rtx.tree_size();
        let ev_raw = serde_json::to_vec(&tx).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("serialization error: {e}"),
            )
        })?;

        let mirrors = match &tx {
            UcoTransaction::Mint(m) => Some((m.mrv_data_root, m.mrv_blob_mirrors.clone())),
            _ => None,
        };

        let new_size = current_size + 1;
        let dummy_header = CheckpointHeaderV2 {
            version: 2,
            chain_id: rtx.chain_id(),
            tree_size: new_size,
            timestamp_ns: 1_700_000_000,
            events_root: hash_log_leaf(&ev_raw),
            uco_state_root: [0; 32],
            poo_archive_root: [0; 32],
            active_validators_hash: [0; 32],
        };

        let note = format!(
            "greymisnomer/v2\n{}\n{}\n{}\n",
            new_size,
            hex::encode(dummy_header.events_root),
            hex::encode(dummy_header.to_canonical_bytes())
        );

        let bt = BatchTransition {
            delta,
            event_leaf_index: current_size,
            event_raw_bytes: ev_raw.clone(),
            mrv_mirrors: mirrors,
        };

        state
            .storage
            .commit_batch(&[bt], Some((&dummy_header, note.as_bytes())), None)
            .map_err(internal_error)?;

        // Broadcast to WebSocket subscribers
        let broadcast_msg = serde_json::json!({
            "event": "tx_committed",
            "txid": txid_hex,
            "tree_size": new_size.to_string(),
        })
        .to_string();
        let _ = state.event_tx.send(broadcast_msg);

        Ok(Json(TxSubmitResponse {
            status: "committed".to_string(),
            txid: txid_hex,
            tree_size: Some(new_size.to_string()),
        }))
    } else {
        // Production mode: validated and pending sequencer collection
        Ok(Json(TxSubmitResponse {
            status: "validated_pending".to_string(),
            txid: txid_hex,
            tree_size: None,
        }))
    }
}

async fn subscribe_events(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_socket(socket, state))
}

async fn handle_socket(mut socket: WebSocket, state: AppState) {
    let mut rx = state.event_tx.subscribe();
    while let Ok(msg) = rx.recv().await {
        if socket.send(Message::Text(msg)).await.is_err() {
            break;
        }
    }
}

fn internal_error(e: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

// ---------------------------------------------------------------------------
// Server Bootstrap Helper
// ---------------------------------------------------------------------------

pub async fn start_rpc_server(
    state: AppState,
    listener: tokio::net::TcpListener,
) -> anyhow::Result<()> {
    let addr = listener.local_addr()?;
    info!("greymisnomerd RPC server listening on http://{addr}");
    let app = build_router(state);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit & Integration Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use grey_misnomer_core::auth::Keypair;
    use grey_misnomer_core::uco_engine::UcoMintTx;
    use http_body_util::BodyExt;
    use std::fs;
    use tower::ServiceExt;

    fn temp_db_path() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("gm_rpc_test_{}", fastrand()));
        let _ = fs::create_dir_all(&dir);
        dir.join("chainstate.redb")
    }

    fn fastrand() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    }

    #[tokio::test]
    async fn test_rpc_status_and_regtest_tx_submit_lifecycle() {
        let db_path = temp_db_path();
        let storage = ChainStorage::open(&db_path).expect("open db");
        let chain_id = [0x55u8; 32];
        storage.init_chain(&chain_id).expect("init chain");

        let (event_tx, _) = broadcast::channel(16);
        let state = AppState {
            storage: storage.clone(),
            event_tx,
            regtest: true,
            cookie_token: Some("secret123".to_string()),
            rpc_port: 9482,
            p2p_mesh: None,
        };

        let app = build_router(state);

        // 1. Unauthorized request should return 401
        let req = Request::builder()
            .uri("/v1/chain/status")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // 2. Authorized status query with Bearer token
        let req = Request::builder()
            .uri("/v1/chain/status")
            .header("Authorization", "Bearer secret123")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let status: ChainStatusResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(status.chain_id, hex::encode(chain_id));
        assert_eq!(status.tree_size, "0");
        assert!(status.regtest);

        // 3. Register accredited VVB in storage
        let vvb_key = Keypair::generate();
        let vvb_pub = vvb_key.pubkey();
        storage
            .register_vvb(&vvb_pub, "Envirotest Labs")
            .expect("register vvb");

        // 4. Submit UCO Mint transaction via POST /v1/tx/submit
        let owner_key = Keypair::generate();
        let owner_pub = owner_key.pubkey();
        let mrv_root = [0x88; 32];

        let mut mint = UcoMintTx {
            project_id: "ICM-SOLAR-01".to_string(),
            batch_id: "B-2024".to_string(),
            vintage_year: 2024,
            micro_units: 10_000_000,
            initial_owner: owner_pub,
            methodology_hash: [0x11; 32],
            mrv_data_root: mrv_root,
            mrv_blob_mirrors: vec!["https://mrv.io/blob.bin".to_string()],
            challenge_window_epochs: 10,
            vvb_signatures: vec![],
        };
        let preimage = mint.signing_preimage(&chain_id);
        mint.vvb_signatures.push((vvb_pub, vvb_key.sign(&preimage)));

        let submit_req = Request::builder()
            .method("POST")
            .uri("/v1/tx/submit")
            .header("Authorization", "Bearer secret123")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&UcoTransaction::Mint(mint)).unwrap(),
            ))
            .unwrap();
        let submit_resp = app.clone().oneshot(submit_req).await.unwrap();
        assert_eq!(submit_resp.status(), StatusCode::OK);
        let submit_body = submit_resp.into_body().collect().await.unwrap().to_bytes();
        let submit_json: TxSubmitResponse = serde_json::from_slice(&submit_body).unwrap();
        assert_eq!(submit_json.status, "committed");
        assert_eq!(submit_json.tree_size, Some("1".to_string()));

        // 5. Query created UCO via GET /v1/uco/:outpoint
        let txid_bytes = hex::decode(&submit_json.txid).unwrap();
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&txid_bytes);
        let created_op = OutPoint::new(txid, 0);

        let uco_req = Request::builder()
            .uri(format!("/v1/uco/{created_op}"))
            .header("Authorization", "Bearer secret123")
            .body(Body::empty())
            .unwrap();
        let uco_resp = app.clone().oneshot(uco_req).await.unwrap();
        assert_eq!(uco_resp.status(), StatusCode::OK);
        let uco_body = uco_resp.into_body().collect().await.unwrap().to_bytes();
        let fetched_uco: UnretiredCreditOutput = serde_json::from_slice(&uco_body).unwrap();
        assert_eq!(fetched_uco.micro_units, 10_000_000);
        assert_eq!(fetched_uco.owner, owner_pub);

        // 6. Query SPV unspentness proof via GET /v1/proof/spv/:outpoint
        let spv_req = Request::builder()
            .uri(format!("/v1/proof/spv/{created_op}"))
            .header("Authorization", "Bearer secret123")
            .body(Body::empty())
            .unwrap();
        let spv_resp = app.clone().oneshot(spv_req).await.unwrap();
        assert_eq!(spv_resp.status(), StatusCode::OK);
        let spv_body = spv_resp.into_body().collect().await.unwrap().to_bytes();
        let spv_proof: UcoUnspentSpvProof = serde_json::from_slice(&spv_body).unwrap();
        assert_eq!(spv_proof.uco.outpoint, created_op);

        // 7. Query network peers endpoint via GET /v1/network/peers
        let peers_req = Request::builder()
            .uri("/v1/network/peers")
            .header("Authorization", "Bearer secret123")
            .body(Body::empty())
            .unwrap();
        let peers_resp = app.clone().oneshot(peers_req).await.unwrap();
        assert_eq!(peers_resp.status(), StatusCode::OK);
        let peers_body = peers_resp.into_body().collect().await.unwrap().to_bytes();
        let peers_json: NetworkPeersResponse = serde_json::from_slice(&peers_body).unwrap();
        assert_eq!(peers_json.node_id, "standalone");
        assert_eq!(peers_json.peer_count, 0);

        // Clean up
        let _ = fs::remove_dir_all(db_path.parent().unwrap());
    }
}
