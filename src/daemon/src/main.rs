//! `greymisnomerd`: GreyMisnomer Autonomous Tile-Sync, Verification and Local Daemon.
//!
//! Binds strictly to 127.0.0.1:9482 for authenticated localhost RPC & WebSockets,
//! while syncing immutable RFC 9162 Merkle tiles from mirrors in the background.

pub mod config;
pub mod storage;

use anyhow::Result;
use clap::Parser;
use config::DaemonConfig;
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
    if config.regtest {
        info!("Running in REGTEST sandbox mode");
    }

    // Scaffold shutdown listener
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Received SIGINT/Ctrl+C. Shutting down greymisnomerd gracefully...");
        }
    }

    Ok(())
}
