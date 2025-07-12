//! Core compliance modules for ZeroTrust Compliance Backend

pub mod kyc;
pub mod aml;
pub mod sanctions;
pub mod attestation;
pub mod account_components;
pub mod note_scripts;

use crate::{Result, types::*};
use miden_client::Client;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Main compliance service that coordinates all compliance operations
pub struct ComplianceService {
    /// KYC service
    pub kyc: Arc<kyc::KycService>,
    
    /// AML service
    pub aml: Arc<aml::AmlService>,
    
    /// Sanctions screening service
    pub sanctions: Arc<sanctions::SanctionsService>,
    
    /// Attestation service
    pub attestation: Arc<attestation::AttestationService>,
    
    /// Miden client
    pub miden_client: Arc<RwLock<Client>>,
}

impl ComplianceService {
    /// Create a new compliance service
    pub fn new(
        kyc: Arc<kyc::KycService>,
        aml: Arc<aml::AmlService>,
        sanctions: Arc<sanctions::SanctionsService>,
        attestation: Arc<attestation::AttestationService>,
        miden_client: Arc<RwLock<Client>>,
    ) -> Self {
        Self {
            kyc,
            aml,
            sanctions,
            attestation,
            miden_client,
        }
    }
    
    /// Perform comprehensive compliance check
    pub async fn comprehensive_check(&self, account_id: &str) -> Result<ComplianceAttestation> {
        // Run all compliance checks in parallel
        let (kyc_result, aml_result, sanctions_result) = tokio::try_join!(
            self.kyc.verify_account(account_id),
            self.aml.assess_risk(account_id),
            self.sanctions.screen_account(account_id)
        )?;
        
        // Generate compliance attestation
        let attestation = self.attestation.generate_attestation(
            account_id,
            kyc_result,
            aml_result,
            sanctions_result,
        ).await?;
        
        Ok(attestation)
    }
    
    /// Create a privacy-preserving compliance proof
    pub async fn create_compliance_proof(&self, account_id: &str) -> Result<String> {
        // Get the compliance attestation
        let attestation = self.comprehensive_check(account_id).await?;
        
        // Generate zero-knowledge proof using Miden
        let proof = self.attestation.generate_zk_proof(&attestation).await?;
        
        Ok(proof)
    }
    
    /// Verify a compliance proof
    pub async fn verify_compliance_proof(&self, proof: &str, account_id: &str) -> Result<bool> {
        self.attestation.verify_zk_proof(proof, account_id).await
    }
    
    /// Update compliance status for an account
    pub async fn update_compliance_status(&self, account_id: &str) -> Result<ComplianceAttestation> {
        // Re-run compliance checks
        let attestation = self.comprehensive_check(account_id).await?;
        
        // Store updated attestation
        self.attestation.store_attestation(&attestation).await?;
        
        Ok(attestation)
    }
    
    /// Get compliance status for an account
    pub async fn get_compliance_status(&self, account_id: &str) -> Result<Option<ComplianceAttestation>> {
        self.attestation.get_attestation(account_id).await
    }
    
    /// Check if account meets compliance level requirements
    pub async fn check_compliance_level(&self, account_id: &str, required_level: ComplianceLevel) -> Result<bool> {
        let attestation = self.get_compliance_status(account_id).await?;
        
        match attestation {
            Some(att) => Ok(self.meets_compliance_level(&att, required_level)),
            None => Ok(false),
        }
    }
    
    /// Helper function to check if attestation meets compliance level
    fn meets_compliance_level(&self, attestation: &ComplianceAttestation, required_level: ComplianceLevel) -> bool {
        match required_level {
            ComplianceLevel::Basic => {
                attestation.kyc_status == KycStatus::Verified && 
                attestation.sanctions_cleared
            },
            ComplianceLevel::Standard => {
                attestation.kyc_status == KycStatus::Verified &&
                attestation.sanctions_cleared &&
                matches!(attestation.aml_risk_level, AmlRiskLevel::Low | AmlRiskLevel::Medium)
            },
            ComplianceLevel::Enhanced => {
                attestation.kyc_status == KycStatus::Verified &&
                attestation.sanctions_cleared &&
                attestation.aml_risk_level == AmlRiskLevel::Low
            },
            ComplianceLevel::InstitutionalGrade => {
                attestation.kyc_status == KycStatus::Verified &&
                attestation.sanctions_cleared &&
                attestation.aml_risk_level == AmlRiskLevel::Low &&
                !attestation.expires_at.le(&chrono::Utc::now())
            },
        }
    }
} 