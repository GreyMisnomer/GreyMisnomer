// src/desktop/src-tauri/src/main.rs
// RFC-007 §7 & Task 4.17: GreyMisnomer Desktop Sovereign Node Wrapper

pub mod sidecar;

use sidecar::{SidecarConfig, SidecarManager};

#[cfg(feature = "gui")]
fn main() {
    let sidecar_mgr = SidecarManager::new(SidecarConfig::default());
    if let Err(e) = sidecar_mgr.start() {
        eprintln!("[Desktop Wrapper] Sidecar startup notice: {e}");
    }

    tauri::Builder::default()
        .setup(|_app| {
            println!("[Desktop Wrapper] Tauri v2 initialized on port 9482");
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(not(feature = "gui"))]
fn main() {
    println!("GreyMisnomer Sovereign Desktop Node (Tauri v2 Wrapper)");
    println!("Version: {}", env!("CARGO_PKG_VERSION"));
    let cfg = SidecarConfig::default();
    println!("Target RPC Port: {}", cfg.rpc_port);
    println!("Target P2P Port: {}", cfg.p2p_port);
    println!("Data Directory : {:?}", cfg.data_dir);

    let mgr = SidecarManager::new(cfg);
    println!("Sidecar active : {}", mgr.is_running());
    if let Some(bin) = sidecar::locate_daemon_binary(None) {
        println!("Located daemon binary at: {:?}", bin);
    } else {
        println!("Note: greymisnomerd binary not yet built in local target. Run `cargo build -p greymisnomerd` to bundle.");
    }
}
