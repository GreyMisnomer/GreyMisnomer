use serde::{Deserialize, Serialize};

// ProjectStatus represents where a project is in its lifecycle.
// Active <-> Suspended is reversible; everything else is one-way.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProjectStatus {
    Registered,
    Active,
    Suspended,
    Terminated,
}

// MrvMode describes how a project reports measurement data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MrvMode {
    Continuous,
    Periodic,
    EventBased,
}

// MarketScope defines which carbon market a credit belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MarketScope {
    Vcm,
    Ets,
}

// The Project struct is the registry record for a carbon project.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub project_id: String,
    pub owner: String,
    pub name: String,
    pub sector: String,
    pub methodology_id: String,
    pub geography: String,
    pub market_scope: MarketScope,
    pub mrv_mode: MrvMode,
    pub baseline_hash: String,
    pub status: ProjectStatus,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_project(status: ProjectStatus) -> Project {
        Project {
            project_id: "PRJ-001".to_string(),
            owner: "0xOwnerWallet".to_string(),
            name: "Test Solar Project".to_string(),
            sector: "Renewable_Energy".to_string(),
            methodology_id: "VM0042".to_string(),
            geography: "IN-MH".to_string(),
            market_scope: MarketScope::Vcm,
            mrv_mode: MrvMode::Continuous,
            baseline_hash: "0xabc123".to_string(),
            status,
        }
    }

    #[test]
    fn test_project_status() {
        let p = make_project(ProjectStatus::Registered);
        assert_ne!(p.status, ProjectStatus::Active);
    }
}
