use serde::{Deserialize, Serialize};

/// Canonical Distribution Manifest (RFC-006 §5.2)
/// Commits log size, head hash, checkpoint, and decentralized mirror addresses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub manifest_version: u32,
    pub chain_id: String,
    pub log_size: u64,
    pub head_hash: String,
    pub updated_at: String,
    pub latest_checkpoint: ManifestCheckpoint,
    pub mirrors: ManifestMirrors,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestCheckpoint {
    pub size: u64,
    pub path: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestMirrors {
    pub git: String,
    pub github_pages: String,
    pub ipfs: ManifestIpfs,
    pub archive_org: ManifestArchiveOrg,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestIpfs {
    pub events_cid: Option<String>,
    pub checkpoints_cid: Option<String>,
    pub gateways: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestArchiveOrg {
    pub snapshot_url: Option<String>,
}

impl Manifest {
    pub fn default_gateways() -> Vec<String> {
        vec![
            "https://dweb.link/ipfs/".to_string(),
            "https://ipfs.io/ipfs/".to_string(),
            "https://cloudflare-ipfs.com/ipfs/".to_string(),
        ]
    }

    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manifest_roundtrip() {
        let manifest = Manifest {
            manifest_version: 1,
            chain_id: "6713110c8ac6ba73638381f2ec9bde8eb236e894b1a34b4293a9f69933069e95".to_string(),
            log_size: 5,
            head_hash: "6aee877e18f2327eeb730ee01b29568ed18ae17280850a15b9e23d34176054b4".to_string(),
            updated_at: "2026-10-19T08:24:11Z".to_string(),
            latest_checkpoint: ManifestCheckpoint {
                size: 5,
                path: "checkpoints/5.json".to_string(),
                signature: "3c0b11a43a0d3f829584d412".to_string(),
            },
            mirrors: ManifestMirrors {
                git: "https://github.com/GreyMisnomer/GreyMisnomer".to_string(),
                github_pages: "https://greymisnomer.github.io/GreyMisnomer".to_string(),
                ipfs: ManifestIpfs {
                    events_cid: Some("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi".to_string()),
                    checkpoints_cid: Some("bafybeihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku".to_string()),
                    gateways: Manifest::default_gateways(),
                },
                archive_org: ManifestArchiveOrg {
                    snapshot_url: Some("https://web.archive.org/web/20261019082411/https://greymisnomer.github.io/GreyMisnomer/events.jsonl".to_string()),
                },
            },
        };

        let json = manifest.to_json_pretty().expect("serialize");
        let parsed: Manifest = Manifest::from_json(&json).expect("deserialize");
        assert_eq!(manifest, parsed);
        assert_eq!(parsed.manifest_version, 1);
        assert_eq!(parsed.mirrors.ipfs.gateways.len(), 3);
    }
}
