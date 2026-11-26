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

    /// Bootstrap peers for P2P wire mesh (can be specified multiple times)
    #[arg(long = "peer", env = "GM_PEERS")]
    pub peers: Vec<String>,

    /// Node ID identifier for P2P wire mesh
    #[arg(long, env = "GM_NODE_ID")]
    pub node_id: Option<String>,

    /// Enable P2P relay mode
    #[arg(long, default_value_t = false, env = "GM_RELAY")]
    pub enable_relay: bool,

    /// Initialize fresh CSPRNG v2 Genesis (genesis_v2.json + genesis_keys.json) and exit
    #[arg(long, default_value_t = false)]
    pub init_genesis: bool,

    /// Human-readable chain name used during --init-genesis or first --regtest boot
    #[arg(long, default_value = "GreyMisnomer-Local", env = "GM_CHAIN_NAME")]
    pub chain_name: String,

    /// Path to public genesis_v2.json file shared with peers
    #[arg(long = "genesis", env = "GM_GENESIS")]
    pub genesis_file: Option<PathBuf>,

    /// Path to private genesis_keys.json file authorizing checkpoint signing / auto-sequencing
    #[arg(long = "sequencer-keys", env = "GM_SEQUENCER_KEYS")]
    pub sequencer_keys_file: Option<PathBuf>,

    /// Disable .cookie bearer auth on localhost RPC port 9482
    #[arg(long, default_value_t = false, env = "GM_NO_RPC_AUTH")]
    pub no_rpc_auth: bool,

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
            peers: Vec::new(),
            node_id: None,
            enable_relay: false,
            init_genesis: false,
            chain_name: "GreyMisnomer-Local".to_string(),
            genesis_file: None,
            sequencer_keys_file: None,
            no_rpc_auth: false,
            regtest: false,
        }
    }
}
