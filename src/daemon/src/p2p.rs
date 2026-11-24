// src/daemon/src/p2p.rs
// RFC-008 §2, §5 & Task 4.26-4.27: Sovereign P2P Node on Port 9483 & Self-Hosted Relays

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, Mutex, RwLock};
use tracing::{debug, info, warn};

use crate::mempool::Mempool;
use crate::p2p_wire::{MessageType, WireFrame};
use grey_misnomer_core::uco_engine::{UcoStoreRead, UcoTransaction};

pub const DEFAULT_P2P_PORT: u16 = 9483;

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

pub struct P2pMesh<S: UcoStoreRead + Send + Sync + 'static> {
    config: P2pConfig,
    peers: Arc<RwLock<HashMap<SocketAddr, PeerInfo>>>,
    mempool: Arc<Mutex<Mempool>>,
    store: Arc<S>,
    tx_broadcast: broadcast::Sender<WireFrame>,
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
            tx_broadcast,
            shutdown_notify: Arc::new(tokio::sync::Notify::new()),
        }
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

    pub fn broadcast(&self, frame: WireFrame) -> Result<usize, String> {
        if self.tx_broadcast.receiver_count() == 0 {
            return Ok(0);
        }
        self.tx_broadcast
            .send(frame)
            .map_err(|e| format!("Broadcast channel error: {e}"))
    }

    pub async fn broadcast_tx(&self, tx: &UcoTransaction) -> Result<usize, String> {
        let payload = serde_json::to_vec(tx).map_err(|e| e.to_string())?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let frame = WireFrame::new(MessageType::TxIntent, now, payload);
        self.broadcast(frame)
    }

    pub async fn broadcast_checkpoint(&self, checkpoint_json: &[u8]) -> Result<usize, String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let frame = WireFrame::new(
            MessageType::CheckpointAnnouncement,
            now,
            checkpoint_json.to_vec(),
        );
        self.broadcast(frame)
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
                                    self_peer.handle_connection(stream, remote_addr).await;
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

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Send handshake Ping with our node_id
        let ping_frame = WireFrame::new(
            MessageType::PeerPing,
            now,
            self.config.node_id.as_bytes().to_vec(),
        );
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
            self_clone.handle_connection(stream, addr).await;
        });

        Ok(())
    }

    async fn handle_connection(&self, mut stream: TcpStream, remote_addr: SocketAddr) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut buf = vec![0u8; 65536];
        let mut bcast_rx = self.tx_broadcast.subscribe();

        let peer_info = PeerInfo {
            addr: remote_addr.to_string(),
            node_id: format!("peer-{}", remote_addr.port()),
            connected_at_secs: now,
            is_relay: false,
        };
        self.peers.write().await.insert(remote_addr, peer_info);

        loop {
            tokio::select! {
                read_res = stream.read(&mut buf) => {
                    match read_res {
                        Ok(0) => {
                            debug!("[P2P Wire Mesh] Peer {remote_addr} disconnected");
                            break;
                        }
                        Ok(n) => {
                            match WireFrame::decode(&buf[..n]) {
                                Ok(frame) => {
                                    self.process_incoming_frame(frame, remote_addr, &mut stream).await;
                                }
                                Err(e) => {
                                    warn!("[P2P Wire Mesh] Malformed frame from {remote_addr}: {e}");
                                    let mut mp = self.mempool.lock().await;
                                    mp.penalize_peer(&remote_addr.to_string(), 20);
                                }
                            }
                        }
                        Err(e) => {
                            debug!("[P2P Wire Mesh] Connection read error from {remote_addr}: {e}");
                            break;
                        }
                    }
                }
                bcast_msg = bcast_rx.recv() => {
                    if let Ok(frame) = bcast_msg {
                        if let Ok(encoded) = frame.encode() {
                            let _ = stream.write_all(&encoded).await;
                        }
                    }
                }
            }
        }

        self.peers.write().await.remove(&remote_addr);
    }

    async fn process_incoming_frame(
        &self,
        frame: WireFrame,
        remote_addr: SocketAddr,
        _stream: &mut TcpStream,
    ) {
        match frame.msg_type {
            MessageType::PeerPing => {
                let remote_node_id = String::from_utf8_lossy(&frame.payload).to_string();
                if !remote_node_id.is_empty() {
                    let mut peers = self.peers.write().await;
                    if let Some(peer_info) = peers.get_mut(&remote_addr) {
                        peer_info.node_id = remote_node_id;
                    }
                }
            }
            MessageType::TxIntent => {
                if let Ok(tx) = serde_json::from_slice::<UcoTransaction>(&frame.payload) {
                    let mut mp = self.mempool.lock().await;
                    let peer_id_str = remote_addr.to_string();
                    match mp.submit_tx(
                        tx.clone(),
                        &peer_id_str,
                        0,
                        frame.timestamp,
                        self.store.as_ref(),
                    ) {
                        Ok(txid) => {
                            info!(
                                "[P2P Mempool] Accepted transaction {} from {remote_addr}",
                                hex::encode(txid)
                            );
                            // Forward valid tx to other peers in mesh
                            let _ = self.tx_broadcast.send(frame);
                        }
                        Err(e) => {
                            warn!("[P2P Mempool] Rejected transaction from {remote_addr}: {e}");
                        }
                    }
                }
            }
            MessageType::CheckpointAnnouncement => {
                info!("[P2P Checkpoint] Received checkpoint announcement from {remote_addr}");
                let _ = self.tx_broadcast.send(frame);
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
