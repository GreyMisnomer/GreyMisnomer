// src/desktop/src-tauri/src/sidecar.rs
// RFC-007 §7 & Task 4.17: Native Desktop Sidecar Lifecycle for greymisnomerd

use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};

pub const DEFAULT_RPC_PORT: u16 = 9482;
pub const DEFAULT_P2P_PORT: u16 = 9483;
pub const DEFAULT_CHAIN_ID: &str = "gm-regtest-1";

#[derive(Debug, Clone)]
pub struct SidecarConfig {
    pub daemon_path: Option<PathBuf>,
    pub data_dir: PathBuf,
    pub rpc_port: u16,
    pub p2p_port: u16,
    pub chain_id: String,
    pub regtest: bool,
}

impl Default for SidecarConfig {
    fn default() -> Self {
        Self {
            daemon_path: None,
            data_dir: default_desktop_data_dir(),
            rpc_port: DEFAULT_RPC_PORT,
            p2p_port: DEFAULT_P2P_PORT,
            chain_id: DEFAULT_CHAIN_ID.to_string(),
            regtest: true,
        }
    }
}

pub fn default_desktop_data_dir() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        #[cfg(target_os = "macos")]
        {
            return PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("GreyMisnomer")
                .join("daemon");
        }
        #[cfg(not(target_os = "macos"))]
        {
            return PathBuf::from(home)
                .join(".local")
                .join("share")
                .join("greymisnomer")
                .join("daemon");
        }
    }
    if let Ok(appdata) = std::env::var("APPDATA") {
        return PathBuf::from(appdata).join("GreyMisnomer").join("daemon");
    }
    PathBuf::from(".greymisnomer-desktop-data")
}

pub fn locate_daemon_binary(custom_path: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = custom_path {
        if p.exists() {
            return Some(p.to_path_buf());
        }
    }

    // Check adjacent to running executable
    if let Ok(mut current_exe) = std::env::current_exe() {
        current_exe.pop();
        let candidate = current_exe.join("greymisnomerd");
        if candidate.exists() {
            return Some(candidate);
        }
        let candidate_exe = current_exe.join("greymisnomerd.exe");
        if candidate_exe.exists() {
            return Some(candidate_exe);
        }
    }

    // Check cargo target debug/release dirs
    for profile in &["release", "debug"] {
        let candidate = PathBuf::from("target").join(profile).join("greymisnomerd");
        if candidate.exists() {
            return Some(candidate);
        }
        let candidate_exe = PathBuf::from("target")
            .join(profile)
            .join("greymisnomerd.exe");
        if candidate_exe.exists() {
            return Some(candidate_exe);
        }
    }

    // Check standard cargo bin
    if let Ok(home) = std::env::var("HOME") {
        let cargo_bin = PathBuf::from(home)
            .join(".cargo")
            .join("bin")
            .join("greymisnomerd");
        if cargo_bin.exists() {
            return Some(cargo_bin);
        }
    }

    None
}

pub struct SidecarManager {
    config: SidecarConfig,
    child: Arc<Mutex<Option<Child>>>,
}

impl SidecarManager {
    pub fn new(config: SidecarConfig) -> Self {
        Self {
            config,
            child: Arc::new(Mutex::new(None)),
        }
    }

    pub fn build_command(&self, binary_path: &Path) -> Command {
        let mut cmd = Command::new(binary_path);
        cmd.arg("--data-dir").arg(&self.config.data_dir);
        cmd.arg("--rpc-port").arg(self.config.rpc_port.to_string());
        cmd.arg("--p2p-port").arg(self.config.p2p_port.to_string());
        cmd.arg("--chain-id").arg(&self.config.chain_id);
        if self.config.regtest {
            cmd.arg("--regtest");
        }
        cmd
    }

    pub fn start(&self) -> Result<(), String> {
        let bin = locate_daemon_binary(self.config.daemon_path.as_deref()).ok_or_else(|| {
            "Could not locate greymisnomerd binary on system or bundle path".to_string()
        })?;

        // Ensure directory exists
        if !self.config.data_dir.exists() {
            std::fs::create_dir_all(&self.config.data_dir)
                .map_err(|e| format!("Failed to create daemon data dir: {e}"))?;
        }

        let mut cmd = self.build_command(&bin);
        let child = cmd
            .spawn()
            .map_err(|e| format!("Failed to spawn greymisnomerd sidecar: {e}"))?;

        let mut lock = self.child.lock().unwrap();
        *lock = Some(child);
        Ok(())
    }

    pub fn is_running(&self) -> bool {
        let mut lock = self.child.lock().unwrap();
        if let Some(ref mut child) = *lock {
            matches!(child.try_wait(), Ok(None))
        } else {
            false
        }
    }

    pub fn shutdown(&self) -> Result<(), String> {
        let mut lock = self.child.lock().unwrap();
        if let Some(mut child) = lock.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        Ok(())
    }
}

impl Drop for SidecarManager {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_ports() {
        let cfg = SidecarConfig::default();
        assert_eq!(cfg.rpc_port, 9482);
        assert_eq!(cfg.p2p_port, 9483);
        assert_eq!(cfg.chain_id, "gm-regtest-1");
        assert!(cfg.regtest);
    }

    #[test]
    fn test_build_command_arguments() {
        let cfg = SidecarConfig {
            daemon_path: None,
            data_dir: PathBuf::from("/tmp/greymisnomer_test_dir"),
            rpc_port: 9482,
            p2p_port: 9483,
            chain_id: "gm-test-chain".to_string(),
            regtest: true,
        };
        let mgr = SidecarManager::new(cfg);
        let cmd = mgr.build_command(Path::new("/usr/local/bin/greymisnomerd"));

        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();

        assert_eq!(
            args,
            vec![
                "--data-dir",
                "/tmp/greymisnomer_test_dir",
                "--rpc-port",
                "9482",
                "--p2p-port",
                "9483",
                "--chain-id",
                "gm-test-chain",
                "--regtest"
            ]
        );
    }

    #[test]
    fn test_locate_binary_custom_missing() {
        let res = locate_daemon_binary(Some(Path::new("/nonexistent/greymisnomerd")));
        assert!(res.is_none());
    }
}
