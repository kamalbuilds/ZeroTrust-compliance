//! ZeroTrust Compliance Backend
//! 
//! A privacy-preserving compliance infrastructure built on Miden for Web3 businesses.
//! This library provides KYC/AML verification, sanctions screening, and compliance attestation
//! while maintaining user privacy through zero-knowledge proofs.

pub mod error;
pub mod config;
pub mod miden_client;
pub mod compliance;
pub mod api;
pub mod database;
pub mod crypto;
pub mod webhooks;

pub use error::{ComplianceError, Result};
pub use config::Config;

/// Core compliance types and utilities
pub mod types {
    use serde::{Deserialize, Serialize};
    use uuid::Uuid;
    use chrono::{DateTime, Utc};
    
    /// Represents a KYC verification status
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum KycStatus {
        Pending,
        Verified,
        Rejected,
        Expired,
    }
    
    /// Represents an AML risk level
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum AmlRiskLevel {
        Low,
        Medium,
        High,
        Critical,
    }
    
    /// Compliance attestation
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ComplianceAttestation {
        pub id: Uuid,
        pub account_id: String,
        pub kyc_status: KycStatus,
        pub aml_risk_level: AmlRiskLevel,
        pub sanctions_cleared: bool,
        pub created_at: DateTime<Utc>,
        pub expires_at: DateTime<Utc>,
        pub proof_hash: String,
    }
    
    /// Business client configuration
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct BusinessClient {
        pub id: Uuid,
        pub name: String,
        pub api_key: String,
        pub webhook_url: Option<String>,
        pub compliance_level: ComplianceLevel,
        pub created_at: DateTime<Utc>,
    }
    
    /// Compliance level requirements
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum ComplianceLevel {
        Basic,
        Standard,
        Enhanced,
        InstitutionalGrade,
    }
} 