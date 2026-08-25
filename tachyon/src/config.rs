// Copyright 2026 Google LLC
//
// SPDX-License-Identifier: Apache-2.0

pub mod tachyon_config {
    include!(concat!(env!("OUT_DIR"), "/tachyon_config.rs"));
}

pub use tachyon_config::*;

impl VmOptions {
    /// Return all configured VFIO group IDs across all NUMA nodes.
    pub fn vfio_groups(&self) -> Vec<u64> {
        let mut groups = Vec::new();
        for node in &self.nodes {
            for dev in &node.vfio_devices {
                if let Some(group) = dev.group {
                    groups.push(group);
                }
            }
        }
        groups
    }

    /// Parse configuration from a JSON string.
    pub fn parse_from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str::<VmOptions>(s)
    }

    /// Load and decode a config from bytes (tries JSON, then binary protobuf).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        // Try JSON format first
        if let Ok(cfg) = serde_json::from_slice::<VmOptions>(bytes) {
            return Ok(cfg);
        }

        // Try binary protobuf format
        use prost::Message;
        if let Ok(cfg) = VmOptions::decode(bytes) {
            return Ok(cfg);
        }

        Err("Failed to parse config: unrecognized binary or JSON format".to_string())
    }

    /// Load config from a file path.
    pub fn from_file(path: &str) -> std::io::Result<Self> {
        let bytes = std::fs::read(path)?;
        Self::from_bytes(&bytes).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to parse config file {path}: {e}"),
            )
        })
    }
}

pub type Config = VmOptions;
