// src/daemon/src/p2p.rs
// RFC-008 §2, §5, §9 & Stages 4.5–4.6: Sovereign P2P Node on Port 9483, Buffered WAN Framing & Ledger Sync

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, Mutex, RwLock};
use tracing::{debug, info, warn};

use crate::chain_commit::{
    apply_verified_p2p_sync, parse_header_from_checkpoint_note, sequence_and_commit_tx,
};
use crate::mempool::Mempool;
use crate::p2p_wire::{MessageType, WireFrame, CHECKSUM_LEN, HEADER_LEN, MAX_PAYLOAD_SIZE};
use crate::storage::ChainStorage;
use grey_misnomer_core::auth::{Keypair, Signature};
use grey_misnomer_core::header::CheckpointHeaderV2;
use grey_misnomer_core::uco_engine::{UcoStoreRead, UcoTransaction};

pub const DEFAULT_P2P_PORT: u16 = 9483;
const MAX_READ_BUFFER_BYTES: usize = HEADER_LEN + MAX_PAYLOAD_SIZE + (CHECKSUM_LEN * 2);

#[derive(Debug, Clone)]
pub struct P2pConfig {
    pub listen_addr: SocketAddr,
    pub node_id: String,
    pub bootstrap_peers: Vec<SocketAddr>,
    pub enable_relay: bool,
}

impl Default for P2pConfig {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([0, 0, 0, 0], DEFAULT_P2P_PORT)),
            node_id: format!(
                "gm-node-{}",
                hex::encode(&blake3::hash(b"default-node").as_bytes()[..8])
            ),
            bootstrap_peers: Vec::new(),
            enable_relay: false,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PeerInfo {
    pub addr: String,
    pub node_id: String,
    pub connected_at_secs: u64,
    pub is_relay: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PeerPingPayload {
    pub node_id: String,
    #[serde(with = "grey_misnomer_core::auth::hex_bytes32")]
    pub chain_id: [u8; 32],
    pub tree_size: u64,
    pub is_relay: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CheckpointAnnouncementPayload {
    #[serde(with = "grey_misnomer_core::auth::hex_bytes32")]
    pub chain_id: [u8; 32],
    pub tree_size: u64,
    #[serde(with = "grey_misnomer_core::auth::hex_bytes32")]
    pub events_root: [u8; 32],
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TileRequestPayload {
    #[serde(with = "grey_misnomer_core::auth::hex_bytes32")]
    pub chain_id: [u8; 32],
    pub from_index: u64,
    pub max_count: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TileResponsePayload {
    #[serde(with = "grey_misnomer_core::auth::hex_bytes32")]
    pub chain_id: [u8; 32],
    pub from_index: u64,
    pub events: Vec<Vec<u8>>,
    pub header: CheckpointHeaderV2,
    pub sequencer_sig: Signature,
    pub peer_tip_size: u64,
}

#[derive(Debug, Clone)]
struct BroadcastEnvelope {
    origin: Option<SocketAddr>,
    frame: WireFrame,
}

pub struct P2pMesh<S: UcoStoreRead + Send + Sync + 'static> {
    config: P2pConfig,
    peers: Arc<RwLock<HashMap<SocketAddr, PeerInfo>>>,
    mempool: Arc<Mutex<Mempool>>,
    store: Arc<S>,
    sync_storage: Option<ChainStorage>,
    event_tx: Option<broadcast::Sender<String>>,
    sequencer_key: Option<Arc<Keypair>>,
    tx_broadcast: broadcast::Sender<BroadcastEnvelope>,
    shutdown_notify: Arc<tokio::sync::Notify>,
}

impl<S: UcoStoreRead + Send + Sync + 'static> P2pMesh<S> {
    pub fn new(config: P2pConfig, mempool: Arc<Mutex<Mempool>>, store: Arc<S>) -> Self {
        let (tx_broadcast, _) = broadcast::channel(128);
        Self {
            config,
            peers: Arc::new(RwLock::new(HashMap::new())),
            mempool,
            store,
            sync_storage: None,
            event_tx: None,
            sequencer_key: None,
            tx_broadcast,
            shutdown_notify: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// Attaches persistent `redb` storage and WebSocket broadcast bus for full P2P ledger catch-up.
    pub fn with_chain_sync(
        mut self,
        storage: ChainStorage,
        event_tx: broadcast::Sender<String>,
    ) -> Self {
        self.sync_storage = Some(storage);
        self.event_tx = Some(event_tx);
        self
    }

    /// Authorizes this P2P node to auto-sequence valid incoming P2P `TxIntent`s and sign checkpoints.
    pub fn with_sequencer_key(mut self, keypair: Arc<Keypair>) -> Self {
        self.sequencer_key = Some(keypair);
        self
    }

    pub fn node_id(&self) -> &str {
        &self.config.node_id
    }

    pub fn listen_addr(&self) -> SocketAddr {
        self.config.listen_addr
    }

    pub fn mempool(&self) -> Arc<Mutex<Mempool>> {
        Arc::clone(&self.mempool)
    }

    pub fn is_relay_enabled(&self) -> bool {
        self.config.enable_relay
    }

    pub async fn connected_peers(&self) -> Vec<PeerInfo> {
        self.peers.read().await.values().cloned().collect()
    }

    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }

    fn current_unix_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn local_chain_tip(&self) -> ([u8; 32], u64) {
        if let Some(ref storage) = self.sync_storage {
            if let Ok(rtx) = storage.read_tx() {
                return (rtx.chain_id(), rtx.tree_size());
            }
        }
        (self.store.chain_id(), 0)
    }

    fn build_ping_frame(&self) -> WireFrame {
        let (chain_id, tree_size) = self.local_chain_tip();
        let payload_obj = PeerPingPayload {
            node_id: self.config.node_id.clone(),
            chain_id,
            tree_size,
            is_relay: self.config.enable_relay,
        };
        let payload = serde_json::to_vec(&payload_obj)
            .unwrap_or_else(|_| self.config.node_id.as_bytes().to_vec());
        WireFrame::new(MessageType::PeerPing, Self::current_unix_secs(), payload)
    }

    pub fn broadcast(&self, frame: WireFrame) -> Result<usize, String> {
        if self.tx_broadcast.receiver_count() == 0 {
            return Ok(0);
        }
        self.tx_broadcast
            .send(BroadcastEnvelope {
                origin: None,
                frame,
            })
            .map_err(|e| format!("Broadcast channel error: {e}"))
    }

    fn forward_except(&self, origin: SocketAddr, frame: WireFrame) {
        if self.tx_broadcast.receiver_count() > 0 {
            let _ = self.tx_broadcast.send(BroadcastEnvelope {
                origin: Some(origin),
                frame,
            });
        }
    }

    pub async fn broadcast_tx(&self, tx: &UcoTransaction) -> Result<usize, String> {
        let payload = serde_json::to_vec(tx).map_err(|e| e.to_string())?;
        let frame = WireFrame::new(MessageType::TxIntent, Self::current_unix_secs(), payload);
        self.broadcast(frame)
    }

    pub async fn broadcast_checkpoint(&self, checkpoint_json: &[u8]) -> Result<usize, String> {
        let frame = WireFrame::new(
            MessageType::CheckpointAnnouncement,
            Self::current_unix_secs(),
            checkpoint_json.to_vec(),
        );
        self.broadcast(frame)
    }

    pub async fn broadcast_checkpoint_announcement(
        &self,
        chain_id: [u8; 32],
        tree_size: u64,
        events_root: [u8; 32],
    ) -> Result<usize, String> {
        let ann = CheckpointAnnouncementPayload {
            chain_id,
            tree_size,
            events_root,
        };
        let payload = serde_json::to_vec(&ann).map_err(|e| e.to_string())?;
        self.broadcast_checkpoint(&payload).await
    }

    pub async fn start(self: Arc<Self>) -> Result<SocketAddr, String> {
        let listener = TcpListener::bind(self.config.listen_addr)
            .await
            .map_err(|e| {
                format!(
                    "Failed to bind P2P listener on {}: {e}",
                    self.config.listen_addr
                )
            })?;
        let bound_addr = listener.local_addr().map_err(|e| e.to_string())?;

        info!(
            "[P2P Wire Mesh] Listening on {} (Node ID: {})",
            bound_addr, self.config.node_id
        );

        // Connect to initial bootstrap peers
        for peer_addr in &self.config.bootstrap_peers {
            let self_clone = Arc::clone(&self);
            let addr = *peer_addr;
            tokio::spawn(async move {
                if let Err(e) = self_clone.connect_to_peer(addr).await {
                    debug!("[P2P Wire Mesh] Could not connect to bootstrap peer {addr}: {e}");
                }
            });
        }

        let self_listener = Arc::clone(&self);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    accept_res = listener.accept() => {
                        match accept_res {
                            Ok((stream, remote_addr)) => {
                                let self_peer = Arc::clone(&self_listener);
                                tokio::spawn(async move {
                                    self_peer.handle_connection(stream, remote_addr, true).await;
                                });
                            }
                            Err(e) => {
                                warn!("[P2P Wire Mesh] Accept error: {e}");
                            }
                        }
                    }
                    _ = self_listener.shutdown_notify.notified() => {
                        info!("[P2P Wire Mesh] Shutting down listener");
                        break;
                    }
                }
            }
        });

        Ok(bound_addr)
    }

    pub async fn connect_to_peer(self: &Arc<Self>, addr: SocketAddr) -> Result<(), String> {
        let mut stream = TcpStream::connect(addr)
            .await
            .map_err(|e| format!("Connection to {addr} failed: {e}"))?;

        let now = Self::current_unix_secs();
        let ping_frame = self.build_ping_frame();
        let encoded = ping_frame.encode().map_err(|e| e.to_string())?;
        stream
            .write_all(&encoded)
            .await
            .map_err(|e| e.to_string())?;

        let peer_info = PeerInfo {
            addr: addr.to_string(),
            node_id: format!("remote-{}", addr.port()),
            connected_at_secs: now,
            is_relay: false,
        };

        self.peers.write().await.insert(addr, peer_info);

        let self_clone = Arc::clone(self);
        tokio::spawn(async move {
            self_clone.handle_connection(stream, addr, false).await;
        });

        Ok(())
    }

    async fn handle_connection(
        &self,
        mut stream: TcpStream,
        remote_addr: SocketAddr,
        send_initial_ping: bool,
    ) {
        let now = Self::current_unix_secs();

        // Register connection entry without clobbering pre-seeded outbound info
        {
            let mut peers = self.peers.write().await;
            peers.entry(remote_addr).or_insert_with(|| PeerInfo {
                addr: remote_addr.to_string(),
                node_id: format!("peer-{}", remote_addr.port()),
                connected_at_secs: now,
                is_relay: false,
            });
        }

        if send_initial_ping {
            if let Ok(encoded) = self.build_ping_frame().encode() {
                if let Err(e) = stream.write_all(&encoded).await {
                    debug!("[P2P Wire Mesh] Initial ping write error to {remote_addr}: {e}");
                    self.peers.write().await.remove(&remote_addr);
                    return;
                }
            }
        }

        let mut buf = vec![0u8; 65536];
        let mut read_acc: Vec<u8> = Vec::with_capacity(4096);
        let mut bcast_rx = self.tx_broadcast.subscribe();

        loop {
            tokio::select! {
                _ = self.shutdown_notify.notified() => {
                    break;
                }
                read_res = stream.read(&mut buf) => {
                    match read_res {
                        Ok(0) => {
                            debug!("[P2P Wire Mesh] Peer {remote_addr} disconnected");
                            break;
                        }
                        Ok(n) => {
                            read_acc.extend_from_slice(&buf[..n]);
                            if read_acc.len() > MAX_READ_BUFFER_BYTES {
                                warn!("[P2P Wire Mesh] Read buffer overflow from {remote_addr}; disconnecting");
                                self.mempool.lock().await.penalize_peer(&remote_addr.to_string(), 50);
                                break;
                            }

                            let mut stream_bad = false;
                            loop {
                                match WireFrame::decode_from_buffer(&read_acc) {
                                    Ok(Some((frame, consumed))) => {
                                        read_acc.drain(..consumed);
                                        self.process_incoming_frame(frame, remote_addr, &mut stream).await;
                                    }
                                    Ok(None) => break,
                                    Err(e) => {
                                        warn!("[P2P Wire Mesh] Malformed frame from {remote_addr}: {e}");
                                        self.mempool.lock().await.penalize_peer(&remote_addr.to_string(), 20);
                                        stream_bad = true;
                                        break;
                                    }
                                }
                            }
                            if stream_bad {
                                break;
                            }
                        }
                        Err(e) => {
                            debug!("[P2P Wire Mesh] Connection read error from {remote_addr}: {e}");
                            break;
                        }
                    }
                }
                bcast_msg = bcast_rx.recv() => {
                    match bcast_msg {
                        Ok(env) => {
                            if env.origin == Some(remote_addr) {
                                continue;
                            }
                            if let Ok(encoded) = env.frame.encode() {
                                if let Err(e) = stream.write_all(&encoded).await {
                                    debug!("[P2P Wire Mesh] Write error to {remote_addr}: {e}");
                                    break;
                                }
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            debug!("[P2P Wire Mesh] Broadcast receiver lagged by {skipped} frames for {remote_addr}");
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
            }
        }

        self.peers.write().await.remove(&remote_addr);
    }

    async fn send_tile_request(&self, stream: &mut TcpStream, chain_id: [u8; 32], from_index: u64) {
        let req = TileRequestPayload {
            chain_id,
            from_index,
            max_count: 32,
        };
        if let Ok(payload) = serde_json::to_vec(&req) {
            let frame =
                WireFrame::new(MessageType::TileRequest, Self::current_unix_secs(), payload);
            if let Ok(encoded) = frame.encode() {
                let _ = stream.write_all(&encoded).await;
            }
        }
    }

    async fn process_incoming_frame(
        &self,
        frame: WireFrame,
        remote_addr: SocketAddr,
        stream: &mut TcpStream,
    ) {
        match frame.msg_type {
            MessageType::PeerPing => {
                if let Ok(ping) = serde_json::from_slice::<PeerPingPayload>(&frame.payload) {
                    {
                        let mut peers = self.peers.write().await;
                        if let Some(peer_info) = peers.get_mut(&remote_addr) {
                            if !ping.node_id.is_empty() {
                                peer_info.node_id = ping.node_id;
                            }
                            peer_info.is_relay = ping.is_relay;
                        }
                    }

                    if self.sync_storage.is_some() {
                        let (local_chain, local_size) = self.local_chain_tip();
                        if ping.chain_id != local_chain {
                            warn!(
                                "[P2P Sync] Peer {remote_addr} has mismatched chain_id {} != local {}",
                                hex::encode(ping.chain_id),
                                hex::encode(local_chain)
                            );
                        } else if ping.tree_size > local_size {
                            info!(
                                "[P2P Sync] Peer {remote_addr} leads ({} > {local_size}); requesting tiles",
                                ping.tree_size
                            );
                            self.send_tile_request(stream, local_chain, local_size)
                                .await;
                        }
                    }
                } else {
                    // Fallback plain UTF-8 ping payload
                    let remote_node_id = String::from_utf8_lossy(&frame.payload).to_string();
                    if !remote_node_id.is_empty() {
                        let mut peers = self.peers.write().await;
                        if let Some(peer_info) = peers.get_mut(&remote_addr) {
                            peer_info.node_id = remote_node_id;
                        }
                    }
                }
            }
            MessageType::TxIntent => {
                if let Ok(tx) = serde_json::from_slice::<UcoTransaction>(&frame.payload) {
                    let submit_res = {
                        let mut mp = self.mempool.lock().await;
                        let peer_id_str = remote_addr.to_string();
                        mp.submit_tx(
                            tx.clone(),
                            &peer_id_str,
                            0,
                            frame.timestamp,
                            self.store.as_ref(),
                        )
                    };

                    match submit_res {
                        Ok(txid) => {
                            info!(
                                "[P2P Mempool] Accepted transaction {} from {remote_addr}",
                                hex::encode(txid)
                            );

                            if let (Some(ref seq_kp), Some(ref storage)) =
                                (&self.sequencer_key, &self.sync_storage)
                            {
                                let evt_tx = self.event_tx.clone().unwrap_or_else(|| {
                                    let (tx_chan, _) = broadcast::channel(8);
                                    tx_chan
                                });
                                match sequence_and_commit_tx(
                                    storage,
                                    &evt_tx,
                                    &tx,
                                    Some(seq_kp.as_ref()),
                                ) {
                                    Ok((_, header, _)) => {
                                        self.mempool.lock().await.remove_tx(&txid);
                                        info!(
                                            "[P2P Sequencer] Auto-committed peer tx {} -> tree_size {}",
                                            hex::encode(txid),
                                            header.tree_size
                                        );
                                        let _ = self
                                            .broadcast_checkpoint_announcement(
                                                header.chain_id,
                                                header.tree_size,
                                                header.events_root,
                                            )
                                            .await;
                                    }
                                    Err(e) => {
                                        warn!(
                                            "[P2P Sequencer] Failed to sequence tx {}: {e}",
                                            hex::encode(txid)
                                        );
                                    }
                                }
                            } else {
                                // Relay / non-sequencer peer forwards valid intent to other peers
                                self.forward_except(remote_addr, frame);
                            }
                        }
                        Err(e) => {
                            warn!("[P2P Mempool] Rejected transaction from {remote_addr}: {e}");
                        }
                    }
                }
            }
            MessageType::CheckpointAnnouncement => {
                if let Ok(ann) =
                    serde_json::from_slice::<CheckpointAnnouncementPayload>(&frame.payload)
                {
                    if self.sync_storage.is_some() {
                        let (local_chain, local_size) = self.local_chain_tip();
                        if ann.chain_id != local_chain {
                            warn!(
                                "[P2P Checkpoint] Ignoring checkpoint for foreign chain {}",
                                hex::encode(ann.chain_id)
                            );
                        } else if ann.tree_size > local_size {
                            info!(
                                "[P2P Checkpoint] Announcement height {} > local {}; requesting sync from {remote_addr}",
                                ann.tree_size, local_size
                            );
                            self.send_tile_request(stream, local_chain, local_size)
                                .await;
                        }
                    } else {
                        self.forward_except(remote_addr, frame);
                    }
                } else {
                    info!("[P2P Checkpoint] Received checkpoint announcement from {remote_addr}");
                    self.forward_except(remote_addr, frame);
                }
            }
            MessageType::TileRequest => {
                let Some(ref storage) = self.sync_storage else {
                    return;
                };
                let Ok(req) = serde_json::from_slice::<TileRequestPayload>(&frame.payload) else {
                    return;
                };
                let Ok(rtx) = storage.read_tx() else {
                    return;
                };
                if req.chain_id != rtx.chain_id() {
                    return;
                }
                let local_tip = rtx.tree_size();
                if req.from_index >= local_tip {
                    return;
                }

                let max_count = req.max_count.clamp(1, 32);
                let target_end = (req.from_index.saturating_add(max_count)).min(local_tip);

                // Pick the highest checkpointed index inside (req.from_index..=target_end] bounded by size
                let mut collected = Vec::new();
                let mut approx_bytes = 0usize;
                let mut best_end: Option<(u64, usize, CheckpointHeaderV2, Signature)> = None;

                for idx in req.from_index..target_end {
                    let Ok(Some(ev)) = rtx.get_event(idx) else {
                        break;
                    };
                    approx_bytes = approx_bytes.saturating_add(ev.len());
                    collected.push(ev);

                    let next_size = idx + 1;
                    if let (Ok(Some(chk_bytes)), Ok(Some(sig))) = (
                        rtx.get_checkpoint(next_size),
                        rtx.get_sequencer_sig(next_size),
                    ) {
                        if let Ok(hdr) = parse_header_from_checkpoint_note(&chk_bytes) {
                            best_end = Some((next_size, collected.len(), hdr, sig));
                        }
                    }
                    if approx_bytes >= 512_000 && best_end.is_some() {
                        break;
                    }
                }

                if let Some((_end_size, count, header, sequencer_sig)) = best_end {
                    collected.truncate(count);
                    let resp = TileResponsePayload {
                        chain_id: req.chain_id,
                        from_index: req.from_index,
                        events: collected,
                        header,
                        sequencer_sig,
                        peer_tip_size: local_tip,
                    };
                    if let Ok(payload) = serde_json::to_vec(&resp) {
                        let resp_frame = WireFrame::new(
                            MessageType::TileResponse,
                            Self::current_unix_secs(),
                            payload,
                        );
                        if let Ok(encoded) = resp_frame.encode() {
                            let _ = stream.write_all(&encoded).await;
                        }
                    }
                }
            }
            MessageType::TileResponse => {
                let Some(ref storage) = self.sync_storage else {
                    return;
                };
                let Ok(resp) = serde_json::from_slice::<TileResponsePayload>(&frame.payload) else {
                    return;
                };
                let evt_tx = self.event_tx.clone().unwrap_or_else(|| {
                    let (tx_chan, _) = broadcast::channel(8);
                    tx_chan
                });

                match apply_verified_p2p_sync(
                    storage,
                    &evt_tx,
                    resp.from_index,
                    &resp.events,
                    &resp.header,
                    &resp.sequencer_sig,
                ) {
                    Ok((new_local_size, committed_txids)) => {
                        if !committed_txids.is_empty() {
                            {
                                let mut mp = self.mempool.lock().await;
                                for txid in &committed_txids {
                                    mp.remove_tx(txid);
                                }
                            }
                            info!(
                                "[P2P Sync] Verified & committed {} event(s) up to tree_size {}",
                                committed_txids.len(),
                                new_local_size
                            );

                            // Forward verified checkpoint announcement to remaining peers (relay/gossip)
                            if let Ok(ann_payload) =
                                serde_json::to_vec(&CheckpointAnnouncementPayload {
                                    chain_id: resp.chain_id,
                                    tree_size: new_local_size,
                                    events_root: resp.header.events_root,
                                })
                            {
                                let ann_frame = WireFrame::new(
                                    MessageType::CheckpointAnnouncement,
                                    Self::current_unix_secs(),
                                    ann_payload,
                                );
                                self.forward_except(remote_addr, ann_frame);
                            }
                        }

                        if new_local_size < resp.peer_tip_size {
                            self.send_tile_request(stream, resp.chain_id, new_local_size)
                                .await;
                        }
                    }
                    Err(e) => {
                        warn!("[P2P Sync] Rejected TileResponse from {remote_addr}: {e}");
                        self.mempool
                            .lock()
                            .await
                            .penalize_peer(&remote_addr.to_string(), 50);
                    }
                }
            }
            _ => {
                debug!(
                    "[P2P Frame] Received unhandled message type {:?}",
                    frame.msg_type
                );
            }
        }
    }

    pub fn shutdown(&self) {
        self.shutdown_notify.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use grey_misnomer_core::uco_engine::UcoState;

    #[tokio::test]
    async fn test_p2p_mesh_lifecycle_and_peer_registry() {
        let store = Arc::new(UcoState::new([0x33u8; 32]));
        let mempool = Arc::new(Mutex::new(Mempool::new(0)));

        let cfg = P2pConfig {
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)), // OS assigns ephemeral port
            node_id: "test-node-1".to_string(),
            bootstrap_peers: Vec::new(),
            enable_relay: true,
        };

        let mesh = Arc::new(P2pMesh::new(cfg, mempool, store));
        assert_eq!(mesh.node_id(), "test-node-1");
        assert!(mesh.is_relay_enabled());
        assert_eq!(mesh.peer_count().await, 0);

        // Test broadcasting without connected peers returns 0
        let frame = WireFrame::new(MessageType::PeerPing, 100, b"ping".to_vec());
        let res = mesh.broadcast(frame);
        assert!(res.is_ok());
    }
}
