use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Error, Debug)]
pub enum EvidenceError {
    #[error("Integrity check failed at index {0}: expected {1}, found {2}")]
    ChainBroken(usize, String, String),
    #[error("HMAC signature verification failed")]
    InvalidSignature,
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvidenceRecord {
    pub evidence_id: String,
    pub host: String,
    pub timestamp: DateTime<Utc>,
    pub artifact_type: String,
    pub raw_sha256: String,
    pub byte_count: usize,
    pub previous_hash: String,
    pub record_hash: String,
    pub collector_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceStore {
    pub case_id: String,
    pub records: Vec<EvidenceRecord>,
    pub chain_head: String,
}

impl EvidenceStore {
    pub fn new(case_id: impl Into<String>) -> Self {
        Self {
            case_id: case_id.into(),
            records: Vec::new(),
            chain_head: GENESIS_HASH.to_string(),
        }
    }

    pub fn record_artifact(
        &mut self,
        host: &str,
        artifact_type: &str,
        data: &[u8],
    ) -> Result<&EvidenceRecord, EvidenceError> {
        let index = self.records.len() + 1;
        let evidence_id = format!("EV-{:05}", index);
        let timestamp = Utc::now();

        let mut hasher = Sha256::new();
        hasher.update(data);
        let raw_sha256 = hex::encode(hasher.finalize());

        let previous_hash = self.chain_head.clone();

        // Calculate hash of the chain step
        let mut step_hasher = Sha256::new();
        step_hasher.update(previous_hash.as_bytes());
        step_hasher.update(evidence_id.as_bytes());
        step_hasher.update(raw_sha256.as_bytes());
        step_hasher.update(timestamp.to_rfc3339().as_bytes());
        let record_hash = hex::encode(step_hasher.finalize());

        self.chain_head = record_hash.clone();

        let record = EvidenceRecord {
            evidence_id,
            host: host.to_string(),
            timestamp,
            artifact_type: artifact_type.to_string(),
            raw_sha256,
            byte_count: data.len(),
            previous_hash,
            record_hash,
            collector_version: "2.0.0".to_string(),
        };

        self.records.push(record);
        Ok(self.records.last().unwrap())
    }

    pub fn verify_integrity(&self) -> Result<bool, EvidenceError> {
        let mut prev = GENESIS_HASH.to_string();

        for (i, rec) in self.records.iter().enumerate() {
            if rec.previous_hash != prev {
                return Err(EvidenceError::ChainBroken(i, prev, rec.previous_hash.clone()));
            }

            let mut step_hasher = Sha256::new();
            step_hasher.update(rec.previous_hash.as_bytes());
            step_hasher.update(rec.evidence_id.as_bytes());
            step_hasher.update(rec.raw_sha256.as_bytes());
            step_hasher.update(rec.timestamp.to_rfc3339().as_bytes());
            let computed = hex::encode(step_hasher.finalize());

            if computed != rec.record_hash {
                return Err(EvidenceError::ChainBroken(i, computed, rec.record_hash.clone()));
            }

            prev = rec.record_hash.clone();
        }

        Ok(true)
    }

    pub fn sign_manifest(&self, secret_key: &[u8]) -> Result<String, EvidenceError> {
        let mut mac = HmacSha256::new_from_slice(secret_key).map_err(|_| EvidenceError::InvalidSignature)?;
        mac.update(self.case_id.as_bytes());
        mac.update(self.chain_head.as_bytes());
        mac.update(self.records.len().to_string().as_bytes());
        let result = mac.finalize();
        Ok(hex::encode(result.into_bytes()))
    }
}
