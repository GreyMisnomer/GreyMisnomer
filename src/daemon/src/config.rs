//! Daemon Configuration & Unclaimed Port Allocations.
//!
//! Enforces RFC-007 §2.4 unclaimed default ports:
//! - Local JSON-RPC / WebSocket API: Port 9482 (bound to 127.0.0.1)
//! - P2P Wire Protocol (future Stage 4.5): Port 9483
//!
//! (Explicitly avoids Litecoin's 9332 / 9333 conflict).

use clap::Parser;
use std::path::PathBuf;

pub const DEFAULT_RPC_PORT: u16 = 9482;
pub const DEFAULT_P2P_PORT: u16 = 9483;

#[derive(Parser, Debug, Clone)]
#[command(name = "greymisnomerd")]
#[command(
    about = "GreyMisnomer autonomous tile-sync, verification and local RPC daemon (Port 9482)"
)]
pub struct DaemonConfig {
    /// Local JSON-RPC / WebSocket listen port (default unclaimed 9482)
    #[arg(long, default_value_t = DEFAULT_RPC_PORT, env = "GM_RPC_PORT")]
    pub rpc_port: u16,

    /// P2P wire listen port (default unclaimed 9483)
    #[arg(long, default_value_t = DEFAULT_P2P_PORT, env = "GM_P2P_PORT")]
    pub p2p_port: u16,

    /// Data directory for redb database and tile cache
    #[arg(long, default_value = ".greymisnomer", env = "GM_DATA_DIR")]
    pub data_dir: PathBuf,

    /// Tile mirror URLs to sync from (can be specified multiple times)
    #[arg(long = "tile-mirror", env = "GM_TILE_MIRRORS")]
    pub tile_mirrors: Vec<String>,

    /// Path to file containing trusted witness public keys (one per line)
    #[arg(long = "witness-keys", env = "GM_WITNESS_KEYS")]
    pub witness_keys_file: Option<PathBuf>,

    /// Run in isolated local regtest mode
    #[arg(long, default_value_t = false)]
    pub regtest: bool,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            rpc_port: DEFAULT_RPC_PORT,
            p2p_port: DEFAULT_P2P_PORT,
            data_dir: PathBuf::from(".greymisnomer"),
            tile_mirrors: Vec::new(),
            witness_keys_file: None,
            regtest: false,
        }
    }
}
