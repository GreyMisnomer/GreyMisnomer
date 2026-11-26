//! `greymisnomerd`: GreyMisnomer Autonomous Tile-Sync, P2P Mesh & Local RPC Daemon.
//!
//! Binds strictly to 127.0.0.1:9482 for localhost JSON-RPC & WebSockets,
//! binds to 0.0.0.0:9483 for P2P wire protocol & ledger sync (`RFC-008`),
//! and optionally syncs immutable RFC 9162 Merkle tiles from mirrors.

use anyhow::{bail, Result};
use clap::Parser;
use greymisnomerd::config::DaemonConfig;
use greymisnomerd::genesis::{
    apply_genesis_to_storage, generate_genesis_v2, GenesisKeyBundle, GenesisV2, GENESIS_FILE_NAME,
    GENESIS_KEYS_FILE_NAME,
};
use greymisnomerd::rpc::{start_rpc_server, AppState};
use greymisnomerd::storage::ChainStorage;
use greymisnomerd::tile_sync;
use std::collections::BTreeMap;
use std::fs;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let config = DaemonConfig::parse();
    fs::create_dir_all(&config.data_dir)?;

    let db_path = config.data_dir.join("chainstate.redb");
    let storage = ChainStorage::open(&db_path)?;

    // Dedicated genesis bootstrap command (`--init-genesis`)
    if config.init_genesis {
        let gen_path = config
            .genesis_file
            .clone()
            .unwrap_or_else(|| config.data_dir.join(GENESIS_FILE_NAME));
        let keys_path = config.data_dir.join(GENESIS_KEYS_FILE_NAME);

        if gen_path.exists() {
            bail!(
                "Genesis file already exists at {}. Remove or use another --data-dir.",
                gen_path.display()
            );
        }

        let (genesis, bundle) = generate_genesis_v2(&config.chain_name, None);
        genesis.save(&gen_path)?;
        bundle.save_restricted(&keys_path)?;
        apply_genesis_to_storage(&storage, &genesis)?;

        println!("══════════════════════════════════════════════════════════════════════");
        println!("  GreyMisnomer v2.0 Sovereign Genesis Bootstrapped (RFC-007 / RFC-008) ");
        println!("══════════════════════════════════════════════════════════════════════");
        println!("  Chain Name:      {}", genesis.chain_name);
        println!("  Chain ID:        {}", hex::encode(genesis.chain_id));
        println!("  Sequencer Pub:   {}", genesis.sequencer);
        println!("  VVB PubKey:      {}", bundle.vvb.pubkey);
        println!("  Alice PubKey:    {}", bundle.alice.pubkey);
        println!("  Bob PubKey:      {}", bundle.bob.pubkey);
        println!(
            "  Public Genesis:  {} (Share this file with peers)",
            gen_path.display()
        );
        println!(
            "  Private Keys:    {} (KEEP PRIVATE on host node)",
            keys_path.display()
        );
        println!("══════════════════════════════════════════════════════════════════════");
        return Ok(());
    }

    info!(
        "Starting greymisnomerd on unclaimed RPC port {} (P2P port {})",
        config.rpc_port, config.p2p_port
    );
    info!("Data directory: {}", config.data_dir.display());

    // Load or auto-bootstrap GenesisV2
    let local_genesis_path = config.data_dir.join(GENESIS_FILE_NAME);
    let local_keys_path = config.data_dir.join(GENESIS_KEYS_FILE_NAME);

    let loaded_genesis = if let Some(ref custom_path) = config.genesis_file {
        let g = GenesisV2::load(custom_path)?;
        apply_genesis_to_storage(&storage, &g)?;
        Some(g)
    } else if local_genesis_path.exists() {
        let g = GenesisV2::load(&local_genesis_path)?;
        apply_genesis_to_storage(&storage, &g)?;
        Some(g)
    } else if config.regtest {
        info!(
            "Bootstrapping fresh CSPRNG regtest genesis in {}",
            config.data_dir.display()
        );
        let (g, bundle) = generate_genesis_v2(&config.chain_name, None);
        g.save(&local_genesis_path)?;
        bundle.save_restricted(&local_keys_path)?;
        apply_genesis_to_storage(&storage, &g)?;
        info!(
            "Shareable genesis written to {} (chain_id: {})",
            local_genesis_path.display(),
            hex::encode(g.chain_id)
        );
        Some(g)
    } else {
        None
    };

    // Load optional sequencer signing keypair (authorizes checkpoint signing & auto-sequencing)
    let sequencer_key = if let Some(ref seq_keys_path) = config.sequencer_keys_file {
        let bundle = GenesisKeyBundle::load(seq_keys_path)?;
        let kp = bundle.sequencer.to_keypair()?;
        if let Some(ref g) = loaded_genesis {
            if kp.pubkey() != g.sequencer {
                bail!(
                    "Sequencer keypair in {} ({}) does not match genesis sequencer ({})",
                    seq_keys_path.display(),
                    kp.pubkey(),
                    g.sequencer
                );
            }
        }
        Some(Arc::new(kp))
    } else if config.genesis_file.is_none() && local_keys_path.exists() {
        // Local genesis host running from its own data-dir loads its own sequencer keys
        let bundle = GenesisKeyBundle::load(&local_keys_path)?;
        let kp = bundle.sequencer.to_keypair()?;
        Some(Arc::new(kp))
    } else {
        None
    };

    if sequencer_key.is_some() {
        info!("Active role: Genesis Sequencer & Validator (signing checkpoints + P2P sync)");
    } else {
        info!("Active role: Verifier & P2P Peer Node (verifies signatures + syncs P2P)");
    }

    let (event_tx, _) = broadcast::channel(128);

    // Optional cookie generation for authenticated RPC
    let cookie_token = if config.regtest || config.no_rpc_auth {
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
        if let Ok(resolved) = p.to_socket_addrs() {
            for addr in resolved {
                if addr.is_ipv4() || bootstrap_addrs.is_empty() {
                    bootstrap_addrs.push(addr);
                    break;
                }
            }
        } else {
            tracing::warn!("Could not resolve bootstrap peer address: {p}");
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

    let mempool = Arc::new(tokio::sync::Mutex::new(
        greymisnomerd::mempool::Mempool::new(0),
    ));
    let mut mesh_builder =
        greymisnomerd::p2p::P2pMesh::new(p2p_cfg, mempool, Arc::new(storage.clone()))
            .with_chain_sync(storage.clone(), event_tx.clone());

    if let Some(ref seq_kp) = sequencer_key {
        mesh_builder = mesh_builder.with_sequencer_key(Arc::clone(seq_kp));
    }

    let p2p_mesh = Arc::new(mesh_builder);
    let p2p_runner = Arc::clone(&p2p_mesh);
    tokio::spawn(async move {
        if let Err(e) = p2p_runner.start().await {
            tracing::warn!("P2P mesh error: {e}");
        }
    });

    let mut app_state = AppState::new(
        storage.clone(),
        event_tx.clone(),
        config.regtest,
        cookie_token,
        config.rpc_port,
    )
    .with_p2p_mesh(Arc::clone(&p2p_mesh));

    if let Some(ref seq_kp) = sequencer_key {
        app_state = app_state.with_sequencer_key(Arc::clone(seq_kp));
    }

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
            p2p_mesh.shutdown();
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
