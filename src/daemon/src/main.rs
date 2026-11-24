//! `greymisnomerd`: GreyMisnomer Autonomous Tile-Sync, Verification and Local Daemon.
//!
//! Binds strictly to 127.0.0.1:9482 for authenticated localhost RPC & WebSockets,
//! while syncing immutable RFC 9162 Merkle tiles from mirrors in the background.

use anyhow::Result;
use clap::Parser;
use greymisnomerd::config::DaemonConfig;
use greymisnomerd::rpc::{start_rpc_server, AppState};
use greymisnomerd::storage::ChainStorage;
use greymisnomerd::tile_sync;
use std::collections::BTreeMap;
use std::fs;
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let config = DaemonConfig::parse();

    info!(
        "Starting greymisnomerd on unclaimed RPC port {} (P2P port {})",
        config.rpc_port, config.p2p_port
    );
    info!("Data directory: {}", config.data_dir.display());
    fs::create_dir_all(&config.data_dir)?;

    let db_path = config.data_dir.join("chainstate.redb");
    let storage = ChainStorage::open(&db_path)?;

    // In regtest mode, initialize a local sandbox chain if not already done
    if config.regtest {
        info!("Running in REGTEST sandbox mode");
        let regtest_chain = [0x55u8; 32];
        let _ = storage.init_chain(&regtest_chain);
    }

    let (event_tx, _) = broadcast::channel(128);

    // Optional cookie generation for authenticated RPC
    let cookie_token = if config.regtest {
        None
    } else {
        let cookie_file = config.data_dir.join(".cookie");
        let token = hex::encode(fastrand_bytes());
        fs::write(&cookie_file, format!("__cookie__:{token}\n"))?;
        Some(token)
    };

    // Initialize P2P wire mesh
    let node_id = config
        .node_id
        .clone()
        .unwrap_or_else(|| format!("node-{}", &hex::encode(fastrand_bytes())[..8]));

    let mut bootstrap_addrs = Vec::new();
    for p in &config.peers {
        if let Ok(addr) = p.parse() {
            bootstrap_addrs.push(addr);
        }
    }

    let p2p_cfg = greymisnomerd::p2p::P2pConfig {
        listen_addr: format!("0.0.0.0:{}", config.p2p_port)
            .parse()
            .unwrap_or_else(|_| std::net::SocketAddr::from(([0, 0, 0, 0], config.p2p_port))),
        node_id,
        bootstrap_peers: bootstrap_addrs,
        enable_relay: config.enable_relay,
    };

    let mempool = std::sync::Arc::new(tokio::sync::Mutex::new(
        greymisnomerd::mempool::Mempool::new(0),
    ));
    let p2p_mesh = std::sync::Arc::new(greymisnomerd::p2p::P2pMesh::new(
        p2p_cfg,
        mempool,
        std::sync::Arc::new(storage.clone()),
    ));

    let p2p_runner = std::sync::Arc::clone(&p2p_mesh);
    tokio::spawn(async move {
        if let Err(e) = p2p_runner.start().await {
            tracing::warn!("P2P mesh error: {e}");
        }
    });

    let app_state = AppState {
        storage: storage.clone(),
        event_tx: event_tx.clone(),
        regtest: config.regtest,
        cookie_token,
        rpc_port: config.rpc_port,
        p2p_mesh: Some(p2p_mesh),
    };

    // Spawn tile mirror sync loop if mirrors configured
    if !config.tile_mirrors.is_empty() {
        let mirrors = config.tile_mirrors.clone();
        let sync_storage = storage.clone();
        tokio::spawn(async move {
            let sync_engine = tile_sync::TileSyncEngine::new(&mirrors, BTreeMap::new(), 0, false);
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
            loop {
                interval.tick().await;
                if let Err(e) = sync_engine.sync_once(&sync_storage).await {
                    tracing::debug!("Tile sync tick: {e}");
                }
            }
        });
    }

    let bind_addr = format!("127.0.0.1:{}", config.rpc_port);
    let listener = TcpListener::bind(&bind_addr).await?;

    tokio::select! {
        res = start_rpc_server(app_state, listener) => {
            if let Err(e) = res {
                tracing::error!("RPC server error: {e}");
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Received SIGINT/Ctrl+C. Shutting down greymisnomerd gracefully...");
        }
    }

    Ok(())
}

fn fastrand_bytes() -> [u8; 32] {
    let mut b = [0u8; 32];
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    b[..16].copy_from_slice(&time.to_be_bytes());
    b[16..].copy_from_slice(&time.to_le_bytes());
    b
}
